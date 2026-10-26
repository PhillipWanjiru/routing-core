//! TURN relay data path (RFC 5766 §10-11).
//!
//! This is the module that makes TURN functionally a relay rather than
//! bookkeeping: it decides whether a given piece of data is allowed to
//! cross between a client and a peer, and in which direction.
//!
//! # Two transport mechanisms, same forwarding decision
//!
//! RFC 5766 offers two ways to move data through an allocation:
//!
//! - **Send/Data indications** (§10) — STUN-formatted messages carrying
//!   XOR-PEER-ADDRESS + DATA attributes. Self-describing but costly:
//!   36+ bytes of overhead per packet.
//! - **ChannelData messages** (§11) — a 4-byte header (channel number +
//!   length) wrapping the payload directly. A channel number is bound
//!   once to a peer address, after which every packet costs 4 bytes
//!   instead of 36. For a 20ms G.711 stream at 50 packets/second, that
//!   difference is ~1.6 kbps per direction — meaningful on constrained
//!   links, which is exactly where a relay is most likely to be needed.
//!
//! Both mechanisms reach the same permission check. Only the framing
//! differs.
//!
//! # Indications are NOT authenticated per-packet
//!
//! Send and Data are Indications, not Requests: no response, no
//! transaction, and deliberately no MESSAGE-INTEGRITY. RFC 5766 §10.1
//! is explicit about this — per-packet HMAC over a media stream would be
//! prohibitively expensive, so authentication happens once, at Allocate
//! time. The allocation table and the permission table *are* the
//! security model for the data path. That makes the permission check
//! below security-critical rather than merely procedural: it is the only
//! thing standing between an allocation and an open forwarder.
//!
//! # Demultiplexing on a shared port
//!
//! The first two bits of the first byte distinguish all three things
//! that can arrive on a TURN port:
//!
//! ```text
//! 00xxxxxx  → STUN message      (Allocate, Refresh, CreatePermission, Send)
//! 01xxxxxx  → ChannelData       (RFC 5766 §11.4, channel 0x4000-0x7FFF)
//! 10xxxxxx  → RTP/RTCP          (version 2 — not TURN traffic)
//! ```
//!
//! This is the same top-two-bits rule the STUN parser already enforces
//! (`stun::parser` rejects anything where those bits are set), now used
//! constructively rather than defensively.

use super::{allocation::AllocationTable, permission::PermissionTable};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Channel numbers valid for ChannelBind (RFC 5766 §11).
/// Values outside this range are reserved and must be rejected.
pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;
pub const CHANNEL_NUMBER_MAX: u16 = 0x7FFF;

/// Channel binding lifetime (RFC 5766 §11). Deliberately longer than a
/// permission's 300s, because rebinding a channel is more disruptive
/// than refreshing a permission — but note that a channel binding does
/// *not* imply a permission: RFC 5766 §11.2 requires ChannelBind to
/// also install/refresh a permission for the peer, since the two expire
/// on independent clocks and a channel outliving its permission must
/// still be gated by that permission check.
pub const CHANNEL_LIFETIME_SECS: u64 = 600;

/// Fixed ChannelData header size: 2 bytes channel number + 2 bytes length.
pub const CHANNELDATA_HEADER_LEN: usize = 4;

// ─── Wire-format demultiplexing ──────────────────────────────────

/// What kind of datagram arrived on the TURN port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    /// Top bits 00 — a STUN-formatted message (request, response, or indication).
    Stun,
    /// Top bits 01 — a ChannelData message.
    ChannelData,
    /// Top bits 10 or 11 — RTP/RTCP or unrecognised; not TURN traffic.
    Other,
}

/// Classify a datagram by its first two bits (RFC 5766 §11.4).
pub fn classify_datagram(raw: &[u8]) -> DatagramKind {
    match raw.first() {
        None => DatagramKind::Other,
        Some(&b) => match b >> 6 {
            0b00 => DatagramKind::Stun,
            0b01 => DatagramKind::ChannelData,
            _    => DatagramKind::Other,
        },
    }
}

// ─── ChannelData framing ─────────────────────────────────────────

/// A parsed ChannelData message (RFC 5766 §11.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDataMessage {
    pub channel_number: u16,
    pub payload: Vec<u8>,
}

/// Errors from ChannelData parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelDataError {
    /// Fewer than 4 bytes — cannot even read the header.
    TooShort,
    /// The declared length exceeds the bytes actually present. Like the
    /// STUN parser's equivalent case, this is `Malformed` rather than
    /// "incomplete": UDP datagrams arrive whole, so a length field that
    /// overruns its own datagram is corrupt, not partial.
    DeclaredLengthExceedsDatagram { declared: usize, available: usize },
    /// Channel number outside the 0x4000-0x7FFF range.
    InvalidChannelNumber(u16),
}

/// Parse a ChannelData message.
///
/// RFC 5766 §11.4 requires padding to a 4-byte boundary over TCP but
/// explicitly *not* over UDP; this implementation reads exactly the
/// declared length and tolerates trailing padding bytes if present,
/// which is correct for both transports.
pub fn parse_channel_data(raw: &[u8]) -> Result<ChannelDataMessage, ChannelDataError> {
    if raw.len() < CHANNELDATA_HEADER_LEN {
        return Err(ChannelDataError::TooShort);
    }

    let channel_number = u16::from_be_bytes([raw[0], raw[1]]);
    if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel_number) {
        return Err(ChannelDataError::InvalidChannelNumber(channel_number));
    }

    let declared = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let available = raw.len() - CHANNELDATA_HEADER_LEN;
    if declared > available {
        return Err(ChannelDataError::DeclaredLengthExceedsDatagram { declared, available });
    }

    Ok(ChannelDataMessage {
        channel_number,
        payload: raw[CHANNELDATA_HEADER_LEN..CHANNELDATA_HEADER_LEN + declared].to_vec(),
    })
}

/// Build a ChannelData message wrapping `payload`.
pub fn build_channel_data(channel_number: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHANNELDATA_HEADER_LEN + payload.len());
    out.extend_from_slice(&channel_number.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ─── Channel bindings ────────────────────────────────────────────

/// Tracks channel-number ↔ peer-address bindings per client.
///
/// RFC 5766 §11.2 imposes two uniqueness rules that this table enforces,
/// both of which exist to keep the binding unambiguously reversible in
/// each direction:
///   - one channel number maps to at most one peer, and
///   - one peer maps to at most one channel number,
/// for a given allocation.
pub struct ChannelTable {
    /// client -> channel number -> (peer address, expiry)
    by_channel: HashMap<SocketAddr, HashMap<u16, (SocketAddr, Instant)>>,
    /// client -> peer address -> channel number (reverse index for the
    /// peer→client direction, which arrives knowing only the peer)
    by_peer: HashMap<SocketAddr, HashMap<SocketAddr, u16>>,
}

/// Why a ChannelBind was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelBindError {
    InvalidChannelNumber(u16),
    /// This channel number is already bound to a *different* peer.
    ChannelAlreadyBoundToDifferentPeer,
    /// This peer is already reachable via a *different* channel number.
    PeerAlreadyBoundToDifferentChannel,
}

impl ChannelTable {
    pub fn new() -> Self {
        ChannelTable {
            by_channel: HashMap::new(),
            by_peer: HashMap::new(),
        }
    }

    /// Bind `channel_number` to `peer_addr` for `client_addr`, or
    /// refresh an existing identical binding.
    ///
    /// Rebinding the same (channel, peer) pair is a refresh, not an
    /// error — that is how a client keeps a long-lived channel alive.
    /// Binding that would violate either uniqueness rule is rejected.
    pub fn bind(
        &mut self,
        client_addr: SocketAddr,
        channel_number: u16,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), ChannelBindError> {
        if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel_number) {
            return Err(ChannelBindError::InvalidChannelNumber(channel_number));
        }

        // Uniqueness rule 1: this channel must not already point elsewhere.
        if let Some(existing) = self.by_channel.get(&client_addr).and_then(|m| m.get(&channel_number)) {
            if existing.0 != peer_addr {
                return Err(ChannelBindError::ChannelAlreadyBoundToDifferentPeer);
            }
        }
        // Uniqueness rule 2: this peer must not already have another channel.
        if let Some(&existing_channel) = self.by_peer.get(&client_addr).and_then(|m| m.get(&peer_addr)) {
            if existing_channel != channel_number {
                return Err(ChannelBindError::PeerAlreadyBoundToDifferentChannel);
            }
        }

        let expiry = now + Duration::from_secs(CHANNEL_LIFETIME_SECS);
        self.by_channel.entry(client_addr).or_default().insert(channel_number, (peer_addr, expiry));
        self.by_peer.entry(client_addr).or_default().insert(peer_addr, channel_number);
        Ok(())
    }

    /// Resolve a channel number to its bound peer, if the binding exists
    /// and has not expired.
    pub fn peer_for_channel(&self, client_addr: &SocketAddr, channel_number: u16, now: Instant) -> Option<SocketAddr> {
        self.by_channel
            .get(client_addr)
            .and_then(|m| m.get(&channel_number))
            .filter(|(_, expiry)| now < *expiry)
            .map(|(peer, _)| *peer)
    }

    /// Resolve a peer address to its bound channel number, if any and
    /// unexpired. Used in the peer→client direction to decide whether
    /// to deliver as ChannelData (cheap) or a Data indication (fallback).
    pub fn channel_for_peer(&self, client_addr: &SocketAddr, peer_addr: &SocketAddr, now: Instant) -> Option<u16> {
        let channel = *self.by_peer.get(client_addr)?.get(peer_addr)?;
        // Validate against the authoritative forward map so an expired
        // binding is not resolvable from either direction.
        self.peer_for_channel(client_addr, channel, now).map(|_| channel)
    }

    /// Drop every channel binding for one client (allocation released).
    pub fn clear_for_client(&mut self, client_addr: &SocketAddr) {
        self.by_channel.remove(client_addr);
        self.by_peer.remove(client_addr);
    }

    /// Remove expired bindings, keeping both indexes consistent.
    /// Returns how many bindings were removed.
    pub fn sweep_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        for (client, channels) in self.by_channel.iter_mut() {
            let expired: Vec<(u16, SocketAddr)> = channels
                .iter()
                .filter(|(_, (_, expiry))| now >= *expiry)
                .map(|(ch, (peer, _))| (*ch, *peer))
                .collect();

            for (ch, peer) in expired {
                channels.remove(&ch);
                if let Some(peers) = self.by_peer.get_mut(client) {
                    peers.remove(&peer);
                }
                removed += 1;
            }
        }
        self.by_channel.retain(|_, m| !m.is_empty());
        self.by_peer.retain(|_, m| !m.is_empty());
        removed
    }

    pub fn binding_count_for(&self, client_addr: &SocketAddr) -> usize {
        self.by_channel.get(client_addr).map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for ChannelTable {
    fn default() -> Self { ChannelTable::new() }
}

// ─── Forwarding decisions ────────────────────────────────────────

/// What the relay should do with a piece of data.
///
/// Returning a decision rather than performing the I/O keeps this
/// module synchronous and testable without sockets — the same shape as
/// every other handler in this project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    /// Forward `payload` to this destination.
    Forward { to: SocketAddr, payload: Vec<u8> },
    /// Drop silently, with a reason for logging/metrics.
    Drop(DropReason),
}

/// Why a datagram was not relayed. Distinguished rather than collapsed
/// into a bool because these have genuinely different operational
/// meanings: `NoPermission` may indicate an attack, while
/// `NoAllocation` usually just means an allocation expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// No allocation exists for this client.
    NoAllocation,
    /// No valid permission exists for this peer IP.
    NoPermission,
    /// Channel number is not bound (or the binding expired).
    UnboundChannel,
    /// Data arrived on a relay port owned by no current allocation.
    UnknownRelayPort,
}

/// Decide what to do with data a **client** wants sent to a **peer**
/// (Send indication or ChannelData from the client).
///
/// Requires both an allocation and a permission for the peer's IP.
pub fn decide_client_to_peer(
    client_addr: SocketAddr,
    peer_addr: SocketAddr,
    payload: Vec<u8>,
    allocations: &AllocationTable,
    permissions: &PermissionTable,
    now: Instant,
) -> RelayDecision {
    if allocations.get(&client_addr).is_none() {
        return RelayDecision::Drop(DropReason::NoAllocation);
    }
    if !permissions.has_permission(&client_addr, &peer_addr.ip(), now) {
        return RelayDecision::Drop(DropReason::NoPermission);
    }
    RelayDecision::Forward { to: peer_addr, payload }
}

/// Decide what to do with data arriving from a **peer** on a relay port,
/// destined for the **client** that owns that allocation.
///
/// This direction is the security-critical one: without the permission
/// check, anyone who discovered a relay port could inject traffic
/// straight at the client. The client address is not taken on trust —
/// it is resolved from the relay port the data actually arrived on.
pub fn decide_peer_to_client(
    relay_port: u16,
    peer_addr: SocketAddr,
    payload: Vec<u8>,
    allocations: &AllocationTable,
    permissions: &PermissionTable,
    channels: &ChannelTable,
    now: Instant,
) -> RelayDecision {
    let Some(client_addr) = find_client_by_relay_port(allocations, relay_port) else {
        return RelayDecision::Drop(DropReason::UnknownRelayPort);
    };
    if !permissions.has_permission(&client_addr, &peer_addr.ip(), now) {
        return RelayDecision::Drop(DropReason::NoPermission);
    }

    // Prefer ChannelData framing when a channel is bound — 4 bytes of
    // overhead instead of a full Data indication. With no channel the peer's
    // identity has to travel with the data, so it goes in a Data indication:
    // a bare payload would leave the client unable to tell who sent it.
    let framed = match channels.channel_for_peer(&client_addr, &peer_addr, now) {
        Some(channel) => build_channel_data(channel, &payload),
        None => crate::stun::builder::build_data_indication(
            &crate::ice::random::random_bytes::<12>(), peer_addr, &payload,
        ),
    };

    RelayDecision::Forward { to: client_addr, payload: framed }
}

/// Resolve which client owns a given relay port.
///
/// `AllocationTable` intentionally exposes no reverse port→client index
/// (its internal one is private), so this is a linear scan. At the scale
/// this server targets — a single node with at most a few thousand
/// concurrent allocations — that is acceptable; a production deployment
/// would push this lookup into the allocation table itself rather than
/// scanning per packet, since this runs on the media hot path.
fn find_client_by_relay_port(allocations: &AllocationTable, relay_port: u16) -> Option<SocketAddr> {
    allocations
        .iter()
        .find(|(_, alloc)| alloc.relay_port == relay_port)
        .map(|(addr, _)| *addr)
}

/// Whether a peer IP is permitted for a client — thin wrapper making the
/// gate explicit at call sites that only need the boolean.
pub fn is_peer_permitted(
    client_addr: &SocketAddr,
    peer_ip: &IpAddr,
    permissions: &PermissionTable,
    now: Instant,
) -> bool {
    permissions.has_permission(client_addr, peer_ip, now)
}
