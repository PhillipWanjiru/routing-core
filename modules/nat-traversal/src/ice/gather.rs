//! ICE candidate gathering (RFC 8445 §5.1.1).
//!
//! # Scope of this module, stated plainly
//!
//! Full ICE also includes candidate pairing, connectivity checks (STUN
//! Binding requests exchanged over each candidate pair, carrying
//! PRIORITY and ICE-CONTROLLING/ICE-CONTROLLED attributes), and
//! nomination of the winning pair. None of that exists yet — this
//! module only gathers candidates. That is a deliberate, documented
//! scope boundary for this milestone, not an oversight: connectivity
//! checking is a large enough state machine (RFC 8445 §7) to deserve its
//! own verified slice rather than being rushed in alongside gathering.
//!
//! # Host candidate gathering is simplified, also deliberately
//!
//! RFC 8445 §5.1.1.1 gathers host candidates by enumerating every local
//! network interface. Rust's standard library has no cross-platform way
//! to do that without either an FFI call to `getifaddrs` or a crate
//! dependency — and this project's crates.io access has been unreliable
//! this session (container resets blocking egress entirely at times).
//! `gather_host_candidates` here takes the local addresses as a
//! parameter instead of discovering them, deferring real OS-level
//! interface enumeration to when it's actually needed. This is an
//! explicit, named gap — not something to assume is "basically done."

use super::candidate::{Candidate, CandidateType};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    builder::build_message,
    parser::{parse_message, MessageClass, Method},
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Errors from candidate gathering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatherError {
    /// Binding the local UDP socket failed (e.g. address already in use).
    BindFailed(String),
    /// Sending the STUN request failed.
    SendFailed(String),
    /// No response arrived within the timeout — typically means the
    /// STUN server is unreachable, or a firewall is silently dropping
    /// the request.
    Timeout,
    /// A response arrived but did not parse as a valid STUN message.
    InvalidResponse,
    /// The response parsed but was not a Binding Success Response (e.g.
    /// the server returned an error), or contained no XOR-MAPPED-ADDRESS.
    NoMappedAddress,
}

/// Wrap caller-supplied local addresses as host candidates.
///
/// See this module's doc comment — this does not enumerate interfaces
/// itself. `component_id` is applied to every address produced; call
/// this once per component (1 for RTP, 2 for RTCP) if both are needed
/// unmultiplexed.
pub fn gather_host_candidates(
    local_addrs: &[SocketAddr],
    component_id: u8,
) -> Vec<Candidate> {
    local_addrs
        .iter()
        .map(|&addr| Candidate::new(CandidateType::Host, addr, addr, DEFAULT_LOCAL_PREFERENCE, component_id))
        .collect()
}

/// Default local preference used when a caller has no reason to rank
/// one candidate above another of the same type (RFC 8445 §5.1.2.2
/// permits any value 0-65535; the maximum is a reasonable default for a
/// single-interface deployment where there is nothing to rank against).
pub const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// Gather a server-reflexive candidate: bind a local UDP socket, send a
/// real STUN Binding request to `stun_server_addr`, and parse the
/// XOR-MAPPED-ADDRESS out of the response.
///
/// This performs a genuine network round trip — it is not a mock. On
/// success, the returned candidate's `transport_addr` is this
/// endpoint's public mapping as observed by the STUN server, and its
/// `base_addr` is the local socket's own bound address (RFC 8445's
/// distinction between a candidate's externally-visible address and its
/// base — see `Candidate::base_addr`'s doc comment for why that
/// distinction matters for foundation grouping).
pub async fn gather_server_reflexive_candidate(
    stun_server_addr: SocketAddr,
    bind_addr: SocketAddr,
    component_id: u8,
    response_timeout: Duration,
) -> Result<Candidate, GatherError> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| GatherError::BindFailed(e.to_string()))?;

    let base_addr = socket
        .local_addr()
        .map_err(|e| GatherError::BindFailed(e.to_string()))?;

    let txn_id = generate_transaction_id();
    let request = build_message(MessageClass::Request, Method::Binding, &txn_id, &[]);

    socket
        .send_to(&request, stun_server_addr)
        .await
        .map_err(|e| GatherError::SendFailed(e.to_string()))?;

    let mut buf = vec![0u8; 2048];
    let n = match timeout(response_timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _peer))) => n,
        Ok(Err(e)) => return Err(GatherError::SendFailed(e.to_string())),
        Err(_elapsed) => return Err(GatherError::Timeout),
    };

    let response = parse_message(&buf[..n]).map_err(|_| GatherError::InvalidResponse)?;

    if response.class != MessageClass::SuccessResponse || response.method != Method::Binding {
        return Err(GatherError::NoMappedAddress);
    }

    let attrs = decode_attributes(&response.attributes_raw, &response.transaction_id);
    let mapped = attrs.iter().find_map(|a| match a {
        Attribute::XorMappedAddress(addr) => Some(*addr),
        _ => None,
    }).ok_or(GatherError::NoMappedAddress)?;

    let transport_addr = SocketAddr::new(mapped.ip, mapped.port);

    Ok(Candidate::new(
        CandidateType::ServerReflexive,
        transport_addr,
        base_addr,
        DEFAULT_LOCAL_PREFERENCE,
        component_id,
    ))
}

/// Same nanosecond-time-mixed-with-counter approach used for STUN
/// transaction IDs and SIP branch parameters elsewhere in this project —
/// unique per process, not cryptographically unguessable, which is fine
/// for a transaction correlation ID.
fn generate_transaction_id() -> [u8; 12] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = (ns ^ c).wrapping_mul(0x9e3779b97f4a7c15);

    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&mixed.to_be_bytes());
    id[8..12].copy_from_slice(&(c as u32).to_be_bytes());
    id
}
