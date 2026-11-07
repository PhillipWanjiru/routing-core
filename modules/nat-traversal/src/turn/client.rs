//! A sans-IO TURN client (RFC 5766): the counterpart of [`TurnServer`](super::TurnServer).
//!
//! Like the server and the ICE agent it owns no socket and reads no clock.
//! Every call takes `now`; every call returns a [`TurnClientStep`] saying what
//! to send to the TURN server and what happened. A driver supplies the I/O.
//!
//! # What it does
//!
//! * **Allocate** with the long-term-credential challenge: an unauthenticated
//!   request, a 401 carrying the realm and a nonce, then an authenticated retry.
//!   A stale nonce (438) is adopted and retried, a bounded number of times.
//! * **Refresh** the allocation before it expires, and **deallocate** on request.
//! * Install **permissions** and keep them alive, **bind channels** and keep
//!   those alive, and **send and receive peer data** — as Send/Data indications,
//!   or as 4-byte-overhead ChannelData once a channel is bound.
//! * Retransmit unanswered requests with exponential backoff, and give up.
//!
//! # It only believes a signed success
//!
//! The server signs its success responses (RFC 5766). This client treats a
//! success with a missing or wrong MESSAGE-INTEGRITY as if it had never
//! arrived: the transaction runs on. Without this check an off-path attacker
//! who could guess a transaction ID could answer an Allocate with a forged
//! "success" and point the client at a relay of their choosing. The 401 and 438
//! challenges that start authentication cannot be signed (the client has no
//! key yet), so they are accepted on the strength of the 96-bit random
//! transaction ID, the matching method, and the datagram coming from the
//! server's address.
//!
//! Datagrams from any address other than the configured server are dropped.
//!
//! # Not covered
//!
//! TURN over TCP/TLS, IPv6 allocations (REQUESTED-ADDRESS-FAMILY), and
//! DONT-FRAGMENT.

use super::{
    auth::{build_authenticated_request_with, long_term_key},
    relay::{build_channel_data, classify_datagram, parse_channel_data, DatagramKind},
};
use crate::ice::random::random_bytes;
use crate::stun::{
    attributes::{
        decode_attributes, encode_xor_mapped_address, Attribute, ATTR_CHANNEL_NUMBER,
        ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT, ATTR_XOR_PEER_ADDRESS,
    },
    builder::{
        build_attribute, build_message, build_send_indication, encode_channel_number,
        encode_requested_transport, IP_PROTOCOL_UDP,
    },
    integrity::verify_integrity,
    parser::{parse_message, MessageClass, Method},
    SocketAddrAttr,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// RFC 5766 §8: permissions last 5 minutes; refresh a minute early.
const PERMISSION_REFRESH: Duration = Duration::from_secs(240);
/// RFC 5766 §11: channel bindings last 10 minutes; refresh at half.
const CHANNEL_REFRESH: Duration = Duration::from_secs(300);
/// First channel number (RFC 5766 §11: 0x4000..=0x7FFF).
const FIRST_CHANNEL: u16 = 0x4000;
const LAST_CHANNEL: u16 = 0x7FFF;
/// Stale-nonce (438) retries per request before giving up.
const MAX_NONCE_RETRIES: u8 = 2;
/// Lifetime requested on refresh when the caller did not choose one.
const DEFAULT_LIFETIME_SECS: u32 = 600;

#[derive(Debug, Clone)]
pub struct TurnClientConfig {
    /// The TURN server's address; the only source datagrams are accepted from.
    pub server: SocketAddr,
    pub username: String,
    pub password: String,
    /// Lifetime to ask for; `None` lets the server choose its default.
    pub requested_lifetime: Option<u32>,
    /// Initial retransmission timeout (RFC 5389 §7.2.1 default: 500 ms).
    pub rto: Duration,
    /// Rc: total transmissions of one request, including the first.
    pub max_transmissions: u32,
    /// Rm: after the last transmission, wait `rto * final_wait_multiplier`.
    pub final_wait_multiplier: u32,
}

impl TurnClientConfig {
    pub fn new(server: SocketAddr, username: impl Into<String>, password: impl Into<String>) -> Self {
        TurnClientConfig {
            server,
            username: username.into(),
            password: password.into(),
            requested_lifetime: None,
            rto: Duration::from_millis(500),
            max_transmissions: 7,
            final_wait_multiplier: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnClientPhase {
    Idle,
    /// An Allocate is in flight (including the authentication round trip).
    Allocating,
    Allocated,
    /// Allocation failed, or an established allocation was lost.
    Failed,
    /// Deallocated on request.
    Closed,
}

/// What the caller must do on the client's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnClientAction {
    /// Send `data` to the TURN server.
    Send { to: SocketAddr, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnClientEvent {
    /// The allocation exists. `relayed` is the address peers send to; `mapped`
    /// is this client's server-reflexive address as the server saw it.
    Allocated { relayed: SocketAddr, mapped: SocketAddr, lifetime_secs: u32 },
    /// Allocation did not happen: an error `code`, or `None` for a timeout.
    AllocationFailed { code: Option<u16> },
    Refreshed { lifetime_secs: u32 },
    /// An established allocation is gone (a refresh failed, or the server no
    /// longer knows it, e.g. after a restart). Allocate again.
    AllocationLost,
    PermissionInstalled { peer_ips: Vec<IpAddr> },
    PermissionFailed { code: Option<u16> },
    ChannelBound { channel: u16, peer: SocketAddr },
    ChannelBindFailed { peer: SocketAddr, code: Option<u16> },
    /// Data from `peer`, relayed by the server.
    Data { peer: SocketAddr, payload: Vec<u8> },
    /// Deallocated on request.
    Closed,
}

#[derive(Debug, Default)]
pub struct TurnClientStep {
    pub actions: Vec<TurnClientAction>,
    pub events: Vec<TurnClientEvent>,
}

#[derive(Debug, Clone)]
enum Kind {
    Allocate { authenticated: bool },
    /// `lifetime` 0 deallocates.
    Refresh { lifetime: u32 },
    Permission { ips: Vec<IpAddr> },
    ChannelBind { channel: u16, peer: SocketAddr },
}

impl Kind {
    fn method(&self) -> Method {
        match self {
            Kind::Allocate { .. } => Method::Allocate,
            Kind::Refresh { .. } => Method::Refresh,
            Kind::Permission { .. } => Method::CreatePermission,
            Kind::ChannelBind { .. } => Method::ChannelBind,
        }
    }
}

/// One request awaiting its response.
struct Pending {
    kind: Kind,
    txn: [u8; 12],
    /// The exact bytes sent: retransmissions are byte-identical.
    bytes: Vec<u8>,
    sent: u32,
    next_send_at: Option<Instant>,
    deadline: Option<Instant>,
    rto: Duration,
    nonce_retries: u8,
}

pub struct TurnClient {
    cfg: TurnClientConfig,
    phase: TurnClientPhase,
    realm: Option<String>,
    nonce: Option<String>,
    pending: Vec<Pending>,
    relayed: Option<SocketAddr>,
    mapped: Option<SocketAddr>,
    refresh_at: Option<Instant>,
    permissions: Vec<IpAddr>,
    permission_refresh_at: Option<Instant>,
    channels: HashMap<u16, SocketAddr>,
    by_peer: HashMap<SocketAddr, u16>,
    channel_refresh_at: Option<Instant>,
    next_channel: u16,
}

fn peer_attr(addr: SocketAddr, txn: &[u8; 12]) -> Vec<u8> {
    let value = encode_xor_mapped_address(&SocketAddrAttr { ip: addr.ip(), port: addr.port() }, txn);
    build_attribute(ATTR_XOR_PEER_ADDRESS, &value)
}

fn error_code(attrs: &[Attribute]) -> Option<u16> {
    attrs.iter().find_map(|a| if let Attribute::ErrorCode { code, .. } = a { Some(*code) } else { None })
}

impl TurnClient {
    pub fn new(cfg: TurnClientConfig) -> Self {
        TurnClient {
            cfg,
            phase: TurnClientPhase::Idle,
            realm: None,
            nonce: None,
            pending: Vec::new(),
            relayed: None,
            mapped: None,
            refresh_at: None,
            permissions: Vec::new(),
            permission_refresh_at: None,
            channels: HashMap::new(),
            by_peer: HashMap::new(),
            channel_refresh_at: None,
            next_channel: FIRST_CHANNEL,
        }
    }

    pub fn phase(&self) -> TurnClientPhase {
        self.phase
    }

    /// The relayed transport address, once allocated.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed
    }

    /// This client's server-reflexive address, once allocated.
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// The channel bound to `peer`, if any.
    pub fn channel_for(&self, peer: &SocketAddr) -> Option<u16> {
        self.by_peer.get(peer).copied()
    }

    // ─── Starting, and the requests the caller can make ─────────

    /// Begin allocating. Sends an unauthenticated Allocate; the server's 401
    /// supplies the realm and nonce for the authenticated retry.
    pub fn start(&mut self, now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        if self.phase != TurnClientPhase::Idle {
            return step;
        }
        self.phase = TurnClientPhase::Allocating;
        self.submit(Kind::Allocate { authenticated: false }, 0, now, &mut step);
        step
    }

    /// Install permissions for these peer IPs (RFC 5766 §9). Only an installed
    /// permission lets the server relay to, or accept data from, a peer.
    pub fn create_permission(&mut self, ips: &[IpAddr], now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        if self.phase == TurnClientPhase::Allocated && !ips.is_empty() {
            self.submit(Kind::Permission { ips: ips.to_vec() }, 0, now, &mut step);
        }
        step
    }

    /// Bind the next free channel number to `peer` (RFC 5766 §11). Once bound,
    /// data to and from the peer uses ChannelData framing.
    pub fn channel_bind(&mut self, peer: SocketAddr, now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        if self.phase != TurnClientPhase::Allocated
            || self.by_peer.contains_key(&peer)
            || self.next_channel > LAST_CHANNEL
        {
            return step;
        }
        let channel = self.next_channel;
        self.next_channel += 1;
        self.submit(Kind::ChannelBind { channel, peer }, 0, now, &mut step);
        step
    }

    /// Release the allocation (a Refresh with lifetime 0).
    pub fn deallocate(&mut self, now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        if self.phase == TurnClientPhase::Allocated {
            self.submit(Kind::Refresh { lifetime: 0 }, 0, now, &mut step);
        }
        step
    }

    /// Wrap `payload` for relay to `peer`: ChannelData if a channel is bound,
    /// otherwise a Send indication. `None` unless allocated. The server relays
    /// only to peers that have a permission, so install one first.
    pub fn send_to_peer(&self, peer: SocketAddr, payload: &[u8]) -> Option<TurnClientAction> {
        if self.phase != TurnClientPhase::Allocated {
            return None;
        }
        let data = match self.by_peer.get(&peer) {
            Some(&channel) => build_channel_data(channel, payload),
            None => build_send_indication(&random_bytes::<12>(), peer, payload),
        };
        Some(TurnClientAction::Send { to: self.cfg.server, data })
    }

    // ─── Time ────────────────────────────────────────────────────

    /// Retransmit what is due, expire what has timed out, and fire any refresh
    /// that has come due.
    pub fn poll(&mut self, now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        let (max_tx, mult, server) = (self.cfg.max_transmissions, self.cfg.final_wait_multiplier, self.cfg.server);

        let mut timed_out = Vec::new();
        for (i, p) in self.pending.iter_mut().enumerate() {
            if p.deadline.is_some_and(|d| now >= d) {
                timed_out.push(i);
                continue;
            }
            if p.next_send_at.is_some_and(|n| now >= n) {
                p.sent += 1;
                step.actions.push(TurnClientAction::Send { to: server, data: p.bytes.clone() });
                if p.sent >= max_tx {
                    p.next_send_at = None;
                    p.deadline = Some(now + p.rto.saturating_mul(mult));
                } else {
                    p.next_send_at = Some(now + p.rto.saturating_mul(1u32 << (p.sent - 1).min(20)));
                }
            }
        }
        for i in timed_out.into_iter().rev() {
            let p = self.pending.remove(i);
            self.on_failure(p.kind, None, &mut step);
        }

        if self.phase == TurnClientPhase::Allocated {
            self.fire_refreshes(now, &mut step);
        }
        step
    }

    fn fire_refreshes(&mut self, now: Instant, step: &mut TurnClientStep) {
        let in_flight = |pending: &[Pending], f: fn(&Kind) -> bool| pending.iter().any(|p| f(&p.kind));

        if self.refresh_at.is_some_and(|t| now >= t)
            && !in_flight(&self.pending, |k| matches!(k, Kind::Refresh { .. }))
        {
            let lifetime = self.cfg.requested_lifetime.unwrap_or(DEFAULT_LIFETIME_SECS);
            self.submit(Kind::Refresh { lifetime }, 0, now, step);
        }
        if self.permission_refresh_at.is_some_and(|t| now >= t)
            && !self.permissions.is_empty()
            && !in_flight(&self.pending, |k| matches!(k, Kind::Permission { .. }))
        {
            self.permission_refresh_at = Some(now + PERMISSION_REFRESH);
            self.submit(Kind::Permission { ips: self.permissions.clone() }, 0, now, step);
        }
        if self.channel_refresh_at.is_some_and(|t| now >= t) {
            self.channel_refresh_at = Some(now + CHANNEL_REFRESH);
            let bound: Vec<(u16, SocketAddr)> = self.channels.iter().map(|(c, p)| (*c, *p)).collect();
            for (channel, peer) in bound {
                self.submit(Kind::ChannelBind { channel, peer }, 0, now, step);
            }
        }
    }

    /// The earliest instant at which `poll` has something to do.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| earliest = Some(earliest.map_or(t, |e| e.min(t)));
        for p in &self.pending {
            p.next_send_at.into_iter().for_each(&mut consider);
            p.deadline.into_iter().for_each(&mut consider);
        }
        if self.phase == TurnClientPhase::Allocated {
            self.refresh_at.into_iter().for_each(&mut consider);
            if !self.permissions.is_empty() {
                self.permission_refresh_at.into_iter().for_each(&mut consider);
            }
            if !self.channels.is_empty() {
                self.channel_refresh_at.into_iter().for_each(&mut consider);
            }
        }
        earliest
    }

    // ─── Receiving ───────────────────────────────────────────────

    /// Feed in a datagram received from `from`.
    pub fn handle_datagram(&mut self, from: SocketAddr, raw: &[u8], now: Instant) -> TurnClientStep {
        let mut step = TurnClientStep::default();
        if from != self.cfg.server {
            return step; // not our server: never act on it
        }
        match classify_datagram(raw) {
            DatagramKind::ChannelData => {
                if self.phase == TurnClientPhase::Allocated {
                    if let Ok(m) = parse_channel_data(raw) {
                        if let Some(&peer) = self.channels.get(&m.channel_number) {
                            step.events.push(TurnClientEvent::Data { peer, payload: m.payload });
                        }
                    }
                }
            }
            DatagramKind::Stun => self.handle_stun(raw, now, &mut step),
            DatagramKind::Other => {}
        }
        step
    }

    fn handle_stun(&mut self, raw: &[u8], now: Instant, step: &mut TurnClientStep) {
        let Ok(msg) = parse_message(raw) else {
            return;
        };
        let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
        match (msg.class, msg.method) {
            (MessageClass::Indication, Method::Data) => {
                if self.phase != TurnClientPhase::Allocated {
                    return;
                }
                let peer = attrs.iter().find_map(|a| {
                    if let Attribute::XorPeerAddress(p) = a { Some(SocketAddr::new(p.ip, p.port)) } else { None }
                });
                let payload = attrs.iter().find_map(|a| if let Attribute::Data(d) = a { Some(d.clone()) } else { None });
                if let (Some(peer), Some(payload)) = (peer, payload) {
                    step.events.push(TurnClientEvent::Data { peer, payload });
                }
            }
            (MessageClass::SuccessResponse, _) | (MessageClass::ErrorResponse, _) => {
                self.handle_response(&msg.transaction_id, msg.method, msg.class, raw, &attrs, now, step);
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_response(
        &mut self,
        txn: &[u8; 12],
        method: Method,
        class: MessageClass,
        raw: &[u8],
        attrs: &[Attribute],
        now: Instant,
        step: &mut TurnClientStep,
    ) {
        let Some(idx) = self.pending.iter().position(|p| &p.txn == txn) else {
            return;
        };
        if self.pending[idx].kind.method() != method {
            return;
        }

        if class == MessageClass::SuccessResponse {
            // Only a signed success counts. A missing or wrong signature is
            // treated as if the datagram never arrived: the transaction runs on.
            let Some(key) = self.key() else {
                return;
            };
            if !verify_integrity(raw, &key) {
                return;
            }
            let p = self.pending.remove(idx);
            self.on_success(p.kind, attrs, now, step);
        } else {
            let code = error_code(attrs);
            let p = self.pending.remove(idx);
            self.on_error(p, code, attrs, now, step);
        }
    }

    fn key(&self) -> Option<[u8; 16]> {
        self.realm.as_ref().map(|realm| long_term_key(&self.cfg.username, realm, &self.cfg.password))
    }

    // ─── Outcomes ────────────────────────────────────────────────

    fn on_success(&mut self, kind: Kind, attrs: &[Attribute], now: Instant, step: &mut TurnClientStep) {
        let lifetime = attrs.iter().find_map(|a| if let Attribute::Lifetime(l) = a { Some(*l) } else { None });
        match kind {
            Kind::Allocate { .. } => {
                let addr = |pick: fn(&Attribute) -> Option<&SocketAddrAttr>| {
                    attrs.iter().find_map(pick).map(|a| SocketAddr::new(a.ip, a.port))
                };
                let relayed = addr(|a| if let Attribute::XorRelayedAddress(v) = a { Some(v) } else { None });
                let mapped = addr(|a| if let Attribute::XorMappedAddress(v) = a { Some(v) } else { None });
                let (Some(relayed), Some(mapped), Some(lifetime)) = (relayed, mapped, lifetime) else {
                    // A signed success that omits what an Allocate must return:
                    // the server is not speaking TURN as we understand it.
                    self.phase = TurnClientPhase::Failed;
                    step.events.push(TurnClientEvent::AllocationFailed { code: None });
                    return;
                };
                self.phase = TurnClientPhase::Allocated;
                self.relayed = Some(relayed);
                self.mapped = Some(mapped);
                self.refresh_at = Some(now + Duration::from_secs(u64::from((lifetime / 2).max(1))));
                step.events.push(TurnClientEvent::Allocated { relayed, mapped, lifetime_secs: lifetime });
            }
            Kind::Refresh { lifetime: 0 } => {
                self.phase = TurnClientPhase::Closed;
                self.refresh_at = None;
                step.events.push(TurnClientEvent::Closed);
            }
            Kind::Refresh { .. } => {
                let granted = lifetime.unwrap_or(DEFAULT_LIFETIME_SECS);
                self.refresh_at = Some(now + Duration::from_secs(u64::from((granted / 2).max(1))));
                step.events.push(TurnClientEvent::Refreshed { lifetime_secs: granted });
            }
            Kind::Permission { ips } => {
                for ip in &ips {
                    if !self.permissions.contains(ip) {
                        self.permissions.push(*ip);
                    }
                }
                self.permission_refresh_at = Some(now + PERMISSION_REFRESH);
                step.events.push(TurnClientEvent::PermissionInstalled { peer_ips: ips });
            }
            Kind::ChannelBind { channel, peer } => {
                let fresh = !self.channels.contains_key(&channel);
                self.channels.insert(channel, peer);
                self.by_peer.insert(peer, channel);
                self.channel_refresh_at.get_or_insert(now + CHANNEL_REFRESH);
                if fresh {
                    step.events.push(TurnClientEvent::ChannelBound { channel, peer });
                }
            }
        }
    }

    fn on_error(&mut self, p: Pending, code: Option<u16>, attrs: &[Attribute], now: Instant, step: &mut TurnClientStep) {
        let realm = attrs.iter().find_map(|a| if let Attribute::Realm(r) = a { Some(r.clone()) } else { None });
        let nonce = attrs.iter().find_map(|a| if let Attribute::Nonce(n) = a { Some(n.clone()) } else { None });

        match (&p.kind, code) {
            // The first round trip of long-term authentication: learn the realm
            // and nonce, then retry with credentials. Only ever from the
            // *unauthenticated* attempt: a 401 to an authenticated one means the
            // credentials are wrong, and retrying would loop forever.
            (Kind::Allocate { authenticated: false }, Some(401)) => match (realm, nonce) {
                (Some(r), Some(n)) => {
                    self.realm = Some(r);
                    self.nonce = Some(n);
                    self.submit(Kind::Allocate { authenticated: true }, 0, now, step);
                }
                _ => self.on_failure(p.kind, code, step),
            },
            // Stale nonce: adopt the fresh one and retry, a bounded number of times.
            (_, Some(438)) if p.nonce_retries < MAX_NONCE_RETRIES && nonce.is_some() => {
                self.nonce = nonce;
                self.submit(p.kind, p.nonce_retries + 1, now, step);
            }
            _ => self.on_failure(p.kind, code, step),
        }
    }

    fn on_failure(&mut self, kind: Kind, code: Option<u16>, step: &mut TurnClientStep) {
        // 437: the server does not know our allocation (it restarted, or it
        // expired). Whatever we were doing, the allocation is gone.
        if code == Some(437) && self.phase == TurnClientPhase::Allocated {
            self.lose_allocation(step);
            return;
        }
        match kind {
            Kind::Allocate { .. } => {
                self.phase = TurnClientPhase::Failed;
                step.events.push(TurnClientEvent::AllocationFailed { code });
            }
            Kind::Refresh { lifetime: 0 } => {
                // Could not confirm a deallocation: treat the allocation as gone locally.
                self.phase = TurnClientPhase::Closed;
                step.events.push(TurnClientEvent::Closed);
            }
            Kind::Refresh { .. } => self.lose_allocation(step),
            Kind::Permission { .. } => step.events.push(TurnClientEvent::PermissionFailed { code }),
            Kind::ChannelBind { peer, .. } => step.events.push(TurnClientEvent::ChannelBindFailed { peer, code }),
        }
    }

    fn lose_allocation(&mut self, step: &mut TurnClientStep) {
        if self.phase == TurnClientPhase::Allocated {
            self.phase = TurnClientPhase::Failed;
            self.refresh_at = None;
            step.events.push(TurnClientEvent::AllocationLost);
        }
    }

    // ─── Building and sending requests ───────────────────────────

    fn extras(&self, kind: &Kind, txn: &[u8; 12]) -> Vec<u8> {
        match kind {
            Kind::Allocate { .. } => {
                let mut e = build_attribute(ATTR_REQUESTED_TRANSPORT, &encode_requested_transport(IP_PROTOCOL_UDP));
                if let Some(l) = self.cfg.requested_lifetime {
                    e.extend_from_slice(&build_attribute(ATTR_LIFETIME, &l.to_be_bytes()));
                }
                e
            }
            Kind::Refresh { lifetime } => build_attribute(ATTR_LIFETIME, &lifetime.to_be_bytes()),
            // A permission names an IP only; the port is meaningless and sent as 0.
            Kind::Permission { ips } => ips.iter().flat_map(|ip| peer_attr(SocketAddr::new(*ip, 0), txn)).collect(),
            Kind::ChannelBind { channel, peer } => {
                let mut e = build_attribute(ATTR_CHANNEL_NUMBER, &encode_channel_number(*channel));
                e.extend_from_slice(&peer_attr(*peer, txn));
                e
            }
        }
    }

    /// Build, send and track one request. The very first Allocate goes out
    /// without credentials; everything else is authenticated. If credentials are
    /// not yet known there is nothing honest to send.
    fn submit(&mut self, kind: Kind, nonce_retries: u8, now: Instant, step: &mut TurnClientStep) {
        let txn: [u8; 12] = random_bytes();
        let extras = self.extras(&kind, &txn);
        let bytes = match (&kind, &self.realm, &self.nonce) {
            (Kind::Allocate { authenticated: false }, _, _) => {
                build_message(MessageClass::Request, Method::Allocate, &txn, &extras)
            }
            (_, Some(realm), Some(nonce)) => build_authenticated_request_with(
                kind.method(), &txn, &extras, &self.cfg.username, realm, nonce, &self.cfg.password,
            ),
            _ => return,
        };

        let rto = self.cfg.rto;
        let (next_send_at, deadline) = if self.cfg.max_transmissions <= 1 {
            (None, Some(now + rto.saturating_mul(self.cfg.final_wait_multiplier)))
        } else {
            (Some(now + rto), None)
        };
        step.actions.push(TurnClientAction::Send { to: self.cfg.server, data: bytes.clone() });
        self.pending.push(Pending { kind, txn, bytes, sent: 1, next_send_at, deadline, rto, nonce_retries });
    }
}
