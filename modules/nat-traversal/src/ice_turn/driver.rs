//! Real-socket helpers for ICE over TURN: the two steps that happen *before* ICE
//! starts. While ICE is in progress the agent is run by [`run_agent_relayed`]
//! (with a [`TurnRelay`]); these report TURN's own outcomes, which that does not.
//!
//! The usual order, for each client:
//!
//! 1. [`allocate_relay`] on the socket that will carry the agent's traffic, and
//!    offer the returned candidate to the peer alongside the host candidates.
//! 2. Once the peer's candidates arrive, [`install_permissions`] for them, so the
//!    peer's first checks are not dropped by the relay while the permission is
//!    still being set up.
//! 3. Build the agent and run it.
//!
//! Both helpers use the socket the TURN client will keep using, and read only
//! datagrams from the TURN server; anything else that arrives meanwhile is
//! consumed and dropped, which is safe only because ICE has not started.
//!
//! [`run_agent_relayed`]: crate::ice::run_agent_relayed
//! [`TurnRelay`]: super::TurnRelay

use super::TurnBridge;
use crate::ice::Candidate;
use crate::turn::{TurnClientAction, TurnClientEvent, TurnClientStep};
use std::fmt;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The server refused to allocate: its error code, or `None` if the allocation
    /// completed without the addresses an Allocate must return.
    AllocationFailed(Option<u16>),
    /// The server refused the permission request: its error code, or `None` for a
    /// timeout inside the TURN client.
    PermissionFailed(Option<u16>),
    /// Nothing conclusive happened within the time allowed.
    Timeout,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::AllocationFailed(Some(code)) => write!(f, "the TURN server refused the allocation (error {code})"),
            RelayError::AllocationFailed(None) => write!(f, "the TURN allocation did not complete"),
            RelayError::PermissionFailed(Some(code)) => write!(f, "the TURN server refused the permission (error {code})"),
            RelayError::PermissionFailed(None) => write!(f, "the TURN permission request timed out"),
            RelayError::Timeout => write!(f, "timed out waiting for the TURN server"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Allocate a relay through `bridge` over `socket`, and return the relayed
/// candidate to offer the peer.
pub async fn allocate_relay(bridge: &mut TurnBridge, socket: &UdpSocket, timeout: Duration) -> Result<Candidate, RelayError> {
    let step = bridge.start(Instant::now());
    send_step(socket, &step).await;
    pump(bridge, socket, timeout, |e| match e {
        TurnClientEvent::Allocated { .. } => Some(Ok(())),
        TurnClientEvent::AllocationFailed { code } => Some(Err(RelayError::AllocationFailed(*code))),
        _ => None,
    })
    .await?;
    bridge.relayed_candidate(65535, 1).ok_or(RelayError::AllocationFailed(None))
}

/// Install a permission on the relay for each remote candidate's IP not yet
/// asked for, and wait for the server's answer. Returns at once if there is
/// nothing new to ask, and an error if there is no allocation to hold them.
pub async fn install_permissions(
    bridge: &mut TurnBridge,
    socket: &UdpSocket,
    remote: &[Candidate],
    timeout: Duration,
) -> Result<(), RelayError> {
    if bridge.relayed_addr().is_none() {
        // A permission lives on an allocation. Reporting success here would hide that
        // nothing could be asked at all.
        return Err(RelayError::AllocationFailed(None));
    }
    let step = bridge.sync_permissions(remote, Instant::now());
    if step.actions.is_empty() {
        return Ok(());
    }
    send_step(socket, &step).await;
    pump(bridge, socket, timeout, |e| match e {
        TurnClientEvent::PermissionInstalled { .. } => Some(Ok(())),
        TurnClientEvent::PermissionFailed { code } => Some(Err(RelayError::PermissionFailed(*code))),
        _ => None,
    })
    .await
}

async fn send_step(socket: &UdpSocket, step: &TurnClientStep) {
    for TurnClientAction::Send { to, data } in &step.actions {
        let _ = socket.send_to(data, to).await;
    }
}

/// Drive the bridge, retransmitting as it asks, until `decide` returns a verdict
/// on some event, or `limit` passes.
async fn pump(
    bridge: &mut TurnBridge,
    socket: &UdpSocket,
    limit: Duration,
    decide: impl Fn(&TurnClientEvent) -> Option<Result<(), RelayError>>,
) -> Result<(), RelayError> {
    let server = bridge.server_addr();
    let deadline = Instant::now() + limit;
    let mut buf = vec![0u8; 65535];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RelayError::Timeout);
        }
        let step = bridge.poll(now);
        send_step(socket, &step).await;
        if let Some(verdict) = step.events.iter().find_map(&decide) {
            return verdict;
        }

        let wake = bridge.next_wakeup().map_or(deadline, |w| w.min(deadline));
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = received {
                    if from == server {
                        let inbound = bridge.handle_server_datagram(None, from, &buf[..n], Instant::now());
                        send_step(socket, &inbound.turn).await;
                        if let Some(verdict) = inbound.turn.events.iter().find_map(&decide) {
                            return verdict;
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
        }
    }
}
