//! STUN Binding request handler (RFC 5389 §7.3.1).
//!
//! The server's entire job for this milestone: receive a Binding
//! Request, take the request's source address (for UDP this is simply
//! the `recv_from()` peer address — no separate address-discovery step
//! needed), and respond with that address wrapped in XOR-MAPPED-ADDRESS.
//!
//! This is the mechanism that lets a client behind NAT learn its own
//! public IP:port — the server tells the client exactly what address
//! the request appeared to come from, which is the client's NAT mapping,
//! not its private address.
//!
//! `handle_datagram` is deliberately synchronous and side-effect-free —
//! same shape as `voip_sip::sip::uas::UasEngine::handle_datagram` — so it
//! is testable without a real socket. The async UDP loop in `main.rs` is
//! just the I/O shell around it.

use super::{
    attributes::SocketAddrAttr,
    builder::build_binding_success_response,
    parser::parse_message,
};
use std::net::SocketAddr;

/// Process one inbound UDP datagram addressed to the STUN server.
///
/// Returns `Some(response_bytes)` if a response should be sent back to
/// `peer`, or `None` if the datagram should be silently dropped.
///
/// Drop cases:
/// - The datagram doesn't parse as a STUN message at all (RFC 5389 §7.3
///   permits silent discard here — a message that fails to parse often
///   has no reliable transaction ID to respond to in the first place).
/// - The message parses but isn't a Binding Request (no other STUN
///   methods are implemented yet; responding with an error for methods
///   we've never advertised support for is unnecessary complexity this
///   milestone doesn't need).
pub fn handle_datagram(raw: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;

    if !msg.is_binding_request() {
        return None;
    }

    let observed = SocketAddrAttr {
        ip:   peer.ip(),
        port: peer.port(),
    };

    Some(build_binding_success_response(&msg.transaction_id, observed))
}
