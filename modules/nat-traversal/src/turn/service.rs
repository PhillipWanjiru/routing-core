//! A complete, sans-IO TURN server (RFC 5766), composed from the handlers.
//!
//! The pieces already existed — allocation, permissions, the relay decision
//! functions — but as separate handlers. This composes them into one server
//! with the same shape as the ICE agent: no sockets, no clock. Every call
//! takes `now` and returns [`TurnOutput`]s describing what to send and which
//! relay sockets to open or close; a thin driver supplies the real I/O.
//!
//! # Two kinds of socket
//!
//! A TURN server listens on one *control* address that clients talk to, and
//! holds one *relay* socket per allocation, whose address is what the client's
//! peers send to. Traffic therefore arrives by two different doors:
//! [`TurnServer::handle_from_client`] for the control socket and
//! [`TurnServer::handle_from_peer`] for a relay socket (identified by its
//! port). [`TurnOutput`] likewise says which socket a reply leaves from.
//!
//! # Where the security lives
//!
//! Allocate, Refresh, CreatePermission and ChannelBind are authenticated
//! (long-term credentials) and their successes are signed. Send indications and
//! ChannelData carry no per-packet authentication — by design, they are tied to
//! the allocation by the client's address — which makes the **permission
//! table the only barrier** between the relay and an open proxy. Every relayed
//! packet in either direction passes `decide_client_to_peer` or
//! `decide_peer_to_client`, which enforce it.
//!
//! # State that must die with an allocation
//!
//! When an allocation ends — by a Refresh with lifetime 0 or by expiry — its
//! permissions and channel bindings must go too. Otherwise a later allocation
//! from the same client address would silently inherit them: permissions the
//! new allocation never asked for.

use super::{
    allocation::{Allocation, AllocationTable, PortPool},
    auth::CredentialStore,
    channel_server::handle_channel_bind_datagram,
    permission::PermissionTable,
    permission_server::handle_create_permission_datagram,
    relay::{
        classify_datagram, decide_client_to_peer, decide_peer_to_client, parse_channel_data,
        ChannelTable, DatagramKind, RelayDecision,
    },
    server::{handle_allocate_datagram, handle_refresh_datagram},
};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    parser::{parse_message, MessageClass, Method, StunMessage},
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// What the caller must do on the server's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnOutput {
    /// Send `data` to `to` from the server's control socket.
    ToClient { to: SocketAddr, data: Vec<u8> },
    /// Send `data` to `to` from the relay socket bound to `relay_port`.
    ToPeer { relay_port: u16, to: SocketAddr, data: Vec<u8> },
    /// An allocation was created: open a socket on `relay_port`. Emitted before
    /// the Allocate response, so a driver handling outputs in order is ready
    /// before the client can pass the address on.
    RelayOpened { relay_port: u16 },
    /// An allocation ended: close the socket on `relay_port`.
    RelayClosed { relay_port: u16 },
}

pub struct TurnServer {
    realm: String,
    /// The address relayed transport addresses are advertised on.
    relay_ip: IpAddr,
    max_nonce_age_secs: u64,
    credentials: CredentialStore,
    allocations: AllocationTable,
    permissions: PermissionTable,
    channels: ChannelTable,
}

fn reply(to: SocketAddr, data: Option<Vec<u8>>) -> Vec<TurnOutput> {
    data.map(|data| vec![TurnOutput::ToClient { to, data }]).unwrap_or_default()
}

impl TurnServer {
    pub fn new(realm: impl Into<String>, relay_ip: IpAddr, credentials: CredentialStore, pool: PortPool) -> Self {
        TurnServer {
            realm: realm.into(),
            relay_ip,
            max_nonce_age_secs: 3600,
            credentials,
            allocations: AllocationTable::new(pool),
            permissions: PermissionTable::new(),
            channels: ChannelTable::new(),
        }
    }

    // ─── Inspection (for tests and metrics) ──────────────────────

    pub fn allocation_for(&self, client: &SocketAddr) -> Option<&Allocation> {
        self.allocations.get(client)
    }

    pub fn has_permission(&self, client: &SocketAddr, peer_ip: IpAddr, now: Instant) -> bool {
        self.permissions.has_permission(client, &peer_ip, now)
    }

    pub fn channel_peer(&self, client: &SocketAddr, channel: u16, now: Instant) -> Option<SocketAddr> {
        self.channels.peer_for_channel(client, channel, now)
    }

    // ─── Client → server ─────────────────────────────────────────

    /// Handle a datagram that arrived on the control socket from `client`.
    pub fn handle_from_client(&mut self, client: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        match classify_datagram(data) {
            DatagramKind::Stun => self.client_stun(client, data, now),
            DatagramKind::ChannelData => self.client_channel_data(client, data, now),
            DatagramKind::Other => Vec::new(),
        }
    }

    fn client_stun(&mut self, client: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        let Ok(msg) = parse_message(data) else {
            return Vec::new();
        };
        match (msg.class, msg.method) {
            // A TURN server doubles as a STUN server: clients gather their
            // server-reflexive address from the same port.
            (MessageClass::Request, Method::Binding) => reply(client, crate::stun::handle_datagram(data, client)),
            (MessageClass::Request, Method::Allocate) => self.allocate(client, data, now),
            (MessageClass::Request, Method::Refresh) => self.refresh(client, data, now),
            (MessageClass::Request, Method::CreatePermission) => reply(
                client,
                handle_create_permission_datagram(
                    data, client, &self.realm, &self.credentials, &self.allocations,
                    &mut self.permissions, self.max_nonce_age_secs, now,
                ),
            ),
            (MessageClass::Request, Method::ChannelBind) => reply(
                client,
                handle_channel_bind_datagram(
                    data, client, &self.realm, &self.credentials, &self.allocations,
                    &mut self.permissions, &mut self.channels, self.max_nonce_age_secs, now,
                ),
            ),
            (MessageClass::Indication, Method::Send) => self.send_indication(client, &msg, now),
            _ => Vec::new(),
        }
    }

    fn allocate(&mut self, client: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        let had_allocation = self.allocations.get(&client).is_some();
        let response = handle_allocate_datagram(
            data, client, self.relay_ip, &self.realm, &self.credentials, &mut self.allocations,
            self.max_nonce_age_secs, now,
        );
        let mut out = Vec::new();
        if !had_allocation {
            if let Some(a) = self.allocations.get(&client) {
                out.push(TurnOutput::RelayOpened { relay_port: a.relay_port });
            }
        }
        out.extend(reply(client, response));
        out
    }

    fn refresh(&mut self, client: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        let before = self.allocations.get(&client).map(|a| a.relay_port);
        let response = handle_refresh_datagram(
            data, client, &self.realm, &self.credentials, &mut self.allocations,
            self.max_nonce_age_secs, now,
        );
        let mut out = reply(client, response);
        if let Some(relay_port) = before {
            if self.allocations.get(&client).is_none() {
                self.forget(&client);
                out.push(TurnOutput::RelayClosed { relay_port });
            }
        }
        out
    }

    /// Drop everything tied to a client whose allocation has ended.
    fn forget(&mut self, client: &SocketAddr) {
        self.permissions.clear_for_client(client);
        self.channels.clear_for_client(client);
    }

    /// A Send indication (RFC 5766 §10.1): relay the DATA to the named peer —
    /// if, and only if, the client has an allocation and a permission for that
    /// peer's IP. Indications never get an error response, so a refusal is
    /// silent.
    fn send_indication(&mut self, client: SocketAddr, msg: &StunMessage, now: Instant) -> Vec<TurnOutput> {
        let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
        let peer = attrs.iter().find_map(|a| {
            if let Attribute::XorPeerAddress(p) = a { Some(SocketAddr::new(p.ip, p.port)) } else { None }
        });
        let payload = attrs.iter().find_map(|a| if let Attribute::Data(d) = a { Some(d.clone()) } else { None });
        let (Some(peer), Some(payload)) = (peer, payload) else {
            return Vec::new();
        };
        self.forward_to_peer(client, peer, payload, now)
    }

    /// ChannelData from the client: resolve the channel to its peer, then relay.
    fn client_channel_data(&mut self, client: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        let Ok(message) = parse_channel_data(data) else {
            return Vec::new();
        };
        let Some(peer) = self.channels.peer_for_channel(&client, message.channel_number, now) else {
            return Vec::new();
        };
        self.forward_to_peer(client, peer, message.payload, now)
    }

    fn forward_to_peer(&self, client: SocketAddr, peer: SocketAddr, payload: Vec<u8>, now: Instant) -> Vec<TurnOutput> {
        match decide_client_to_peer(client, peer, payload, &self.allocations, &self.permissions, now) {
            RelayDecision::Forward { to, payload } => match self.allocations.get(&client) {
                Some(allocation) => vec![TurnOutput::ToPeer { relay_port: allocation.relay_port, to, data: payload }],
                None => Vec::new(),
            },
            RelayDecision::Drop(_) => Vec::new(),
        }
    }

    // ─── Peer → server ───────────────────────────────────────────

    /// Handle a datagram that arrived at the relay socket on `relay_port` from
    /// `peer`. It is delivered to the allocation's owner — as ChannelData if a
    /// channel is bound, otherwise as a Data indication — only if the owner has
    /// a permission for `peer`'s IP; anything else is dropped.
    pub fn handle_from_peer(&self, relay_port: u16, peer: SocketAddr, data: &[u8], now: Instant) -> Vec<TurnOutput> {
        match decide_peer_to_client(
            relay_port, peer, data.to_vec(), &self.allocations, &self.permissions, &self.channels, now,
        ) {
            RelayDecision::Forward { to, payload } => vec![TurnOutput::ToClient { to, data: payload }],
            RelayDecision::Drop(_) => Vec::new(),
        }
    }

    // ─── Housekeeping ────────────────────────────────────────────

    /// Expire allocations, permissions and channel bindings whose lifetimes have
    /// passed, reporting each relay socket that should now be closed.
    pub fn sweep(&mut self, now: Instant) -> Vec<TurnOutput> {
        let ports: HashMap<SocketAddr, u16> =
            self.allocations.iter().map(|(client, a)| (*client, a.relay_port)).collect();
        let mut out = Vec::new();
        for client in self.allocations.sweep_expired(now) {
            self.forget(&client);
            if let Some(&relay_port) = ports.get(&client) {
                out.push(TurnOutput::RelayClosed { relay_port });
            }
        }
        self.permissions.sweep_expired(now);
        self.channels.sweep_expired(now);
        out
    }
}
