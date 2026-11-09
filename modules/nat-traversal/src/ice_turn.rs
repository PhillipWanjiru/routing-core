//! ICE over a TURN relay: the glue between a [`TurnClient`] and an [`IceAgent`].
//!
//! Neither side knows about the other. The agent names its local candidates by
//! address (`IceAction::Send { from, to, .. }`, `handle_datagram(from, to, ..)`),
//! and a relayed candidate is simply an address that is not a real socket. This
//! module is what makes it one:
//!
//! * **Outgoing.** An action sent *from* the relayed address is wrapped for the
//!   TURN server (a Send indication) rather than put on a socket as it stands.
//!   If the allocation is gone the action is **dropped, never sent from the host
//!   socket instead**: that would bypass the relay and reveal the client's own
//!   address, which is exactly what a relay is used to avoid.
//! * **Incoming.** A Data indication or ChannelData from the server is unwrapped.
//!   STUN payloads (the peer's connectivity checks) go to the agent as arriving
//!   at the relayed address from the peer; anything else (media) is handed back
//!   to the caller.
//! * **Permissions.** The server relays only for peers it holds a permission for,
//!   in both directions, so every IP the peer might send from needs one before the
//!   checks start. [`TurnBridge::sync_permissions`] asks for each remote candidate's
//!   IP once, and again whenever the peer's candidate list grows.
//!
//! Sans-IO, like both halves: it owns no socket and reads no clock. A driver
//! gathers the relayed candidate, calls `sync_permissions` after each agent call,
//! routes the agent's actions through [`TurnBridge::route`], and feeds datagrams
//! that arrive from the TURN server to [`TurnBridge::handle_server_datagram`].
//!
//! # Not covered
//!
//! Binding a channel for the selected pair (ChannelData's smaller overhead).

use crate::ice::{Candidate, IceAction, IceAgent};
use crate::turn::relay::{classify_datagram, DatagramKind};
use crate::turn::{TurnClient, TurnClientAction, TurnClientConfig, TurnClientEvent, TurnClientStep};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

pub struct TurnBridge {
    client: TurnClient,
    /// Peer IPs a permission has been requested for.
    requested: HashSet<IpAddr>,
}

/// What came out of a datagram from the TURN server.
#[derive(Debug, Default)]
pub struct Inbound {
    /// Datagrams for the TURN server, and the TURN events (allocation,
    /// permissions, ...). Peer data is consumed here and never appears.
    pub turn: TurnClientStep,
    /// What the agent wants to send in answer to checks that arrived over the relay.
    pub ice: Vec<IceAction>,
    /// Payloads from peers that are not ICE (media), with the peer that sent each.
    pub app: Vec<(SocketAddr, Vec<u8>)>,
}

/// An agent's actions, split by how each must leave.
#[derive(Debug, Default)]
pub struct Routed {
    /// Sends from the relayed address, already wrapped for the TURN server.
    pub via_turn: Vec<TurnClientAction>,
    /// Everything else: send from the socket bound to `from`.
    pub direct: Vec<IceAction>,
}

impl TurnBridge {
    pub fn new(cfg: TurnClientConfig) -> Self {
        TurnBridge { client: TurnClient::new(cfg), requested: HashSet::new() }
    }

    pub fn client(&self) -> &TurnClient {
        &self.client
    }

    /// Begin allocating.
    pub fn start(&mut self, now: Instant) -> TurnClientStep {
        self.client.start(now)
    }

    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.client.relayed_addr()
    }

    /// Release the allocation. Afterwards nothing sent from the relayed address
    /// is put on the wire at all.
    pub fn deallocate(&mut self, now: Instant) -> TurnClientStep {
        self.client.deallocate(now)
    }

    /// The relayed candidate to offer, once the allocation exists.
    pub fn relayed_candidate(&self, local_preference: u16, component_id: u8) -> Option<Candidate> {
        self.client.relayed_addr().map(|a| Candidate::relayed(a, local_preference, component_id))
    }

    /// Ask the server to permit every remote candidate's IP not yet asked for.
    /// Call after every agent call: a peer-reflexive candidate learned from a
    /// check adds to the list. Before the allocation exists nothing is asked
    /// and nothing is remembered, so the next call tries again.
    pub fn sync_permissions(&mut self, remote: &[Candidate], now: Instant) -> TurnClientStep {
        let mut fresh: Vec<IpAddr> = Vec::new();
        for c in remote {
            let ip = c.transport_addr.ip();
            if !self.requested.contains(&ip) && !fresh.contains(&ip) {
                fresh.push(ip);
            }
        }
        if fresh.is_empty() {
            return TurnClientStep::default();
        }
        let step = self.client.create_permission(&fresh, now);
        if !step.actions.is_empty() {
            self.requested.extend(fresh);
        }
        step
    }

    /// Split the agent's actions into those that must go through the relay and
    /// those that leave a socket directly.
    pub fn route(&self, actions: Vec<IceAction>) -> Routed {
        let relayed = self.client.relayed_addr();
        let mut routed = Routed::default();
        for action in actions {
            let IceAction::Send { from, to, data } = &action;
            if Some(*from) == relayed {
                // Not allocated: the send is dropped. It must not fall through
                // to a real socket.
                if let Some(wrapped) = self.client.send_to_peer(*to, data) {
                    routed.via_turn.push(wrapped);
                }
            } else {
                routed.direct.push(action);
            }
        }
        routed
    }

    /// Wrap a media payload for `peer` (over the selected pair's relay).
    pub fn send_app(&self, peer: SocketAddr, payload: &[u8]) -> Option<TurnClientAction> {
        self.client.send_to_peer(peer, payload)
    }

    /// A datagram arrived from the TURN server. `agent` is `None` before ICE
    /// has started, in which case peer checks that arrive are dropped.
    pub fn handle_server_datagram(
        &mut self,
        mut agent: Option<&mut IceAgent>,
        from: SocketAddr,
        raw: &[u8],
        now: Instant,
    ) -> Inbound {
        let mut turn = self.client.handle_datagram(from, raw, now);
        let relayed = self.client.relayed_addr();
        let mut inbound = Inbound::default();

        for event in std::mem::take(&mut turn.events) {
            match event {
                TurnClientEvent::Data { peer, payload } => {
                    if classify_datagram(&payload) == DatagramKind::Stun {
                        if let (Some(agent), Some(relayed)) = (agent.as_deref_mut(), relayed) {
                            inbound.ice.extend(agent.handle_datagram(peer, relayed, &payload, now));
                        }
                    } else {
                        inbound.app.push((peer, payload));
                    }
                }
                other => turn.events.push(other),
            }
        }
        self.forget_failed_permissions(&turn);
        inbound.turn = turn;
        inbound
    }

    /// Retransmissions, refreshes and timeouts.
    pub fn poll(&mut self, now: Instant) -> TurnClientStep {
        let step = self.client.poll(now);
        self.forget_failed_permissions(&step);
        step
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        self.client.next_wakeup()
    }

    /// A refused or timed-out permission request must be asked for again: forget
    /// what was requested so the next `sync_permissions` retries.
    fn forget_failed_permissions(&mut self, step: &TurnClientStep) {
        if step.events.iter().any(|e| matches!(e, TurnClientEvent::PermissionFailed { .. })) {
            self.requested.clear();
        }
    }
}
