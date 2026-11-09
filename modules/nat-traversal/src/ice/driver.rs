//! Running an [`IceAgent`] over real UDP sockets and the real clock.
//!
//! The agent itself is a sans-IO state machine: it owns no socket and reads no
//! clock. This is the thin layer that supplies both — receive a datagram, hand
//! it to the agent with the current time, send whatever the agent returns, and
//! sleep until the agent says it next needs attention.
//!
//! # A finished agent must keep answering
//!
//! When an agent reaches `Completed` (or `Failed`) the *peer* may not have.
//! The controlled side completes only after its own check succeeds, and that
//! check needs the controlling side to answer it. A driver that stopped the
//! moment its agent finished would strand the peer. So [`run_agent`] keeps
//! serving for `linger` after the agent settles — the agent still answers
//! requests in that state; it just starts none of its own.
//!
//! # Sockets
//!
//! Bind each socket to the specific address of the candidate it carries, not a
//! wildcard: the agent matches a datagram's destination address against its
//! candidates, and a wildcard-bound socket reports `0.0.0.0` as its local
//! address.
//!
//! # Running through a relay
//!
//! [`run_agent_relayed`] is the same loop with a [`RelayPath`] plugged in. The
//! driver knows nothing about TURN: the relay path says which sends must be
//! wrapped for a relay server and which datagrams from that server belong to it,
//! and the driver does the I/O. The relay client shares one of the driver's
//! sockets, so that socket carries both direct ICE traffic and traffic to the
//! relay server; the server's address tells them apart.

use super::agent::{ChecklistState, IceAction, IceAgent};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How long to sleep when the agent reports nothing pending. It will wake
/// sooner for any datagram; this only bounds how stale the loop can get.
const IDLE_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy)]
pub struct DriveOptions {
    /// Stop after this long no matter what state the agent is in.
    pub timeout: Duration,
    /// After the agent leaves `Running`, keep answering the peer this long.
    pub linger: Duration,
}

impl Default for DriveOptions {
    fn default() -> Self {
        DriveOptions { timeout: Duration::from_secs(60), linger: Duration::from_secs(1) }
    }
}

/// Carries part of an agent's traffic through a relay, for [`run_agent_relayed`].
///
/// Anything that can wrap the agent's sends from a relayed address into datagrams
/// for a relay server, and unwrap what comes back, can plug in. It must be `Send`,
/// since the driver future is typically spawned onto a multi-threaded runtime. `ice_turn::TurnRelay`
/// is the TURN implementation. Sans-IO: every method takes the time and returns
/// datagrams; none touches a socket.
pub trait RelayPath: Send {
    /// The driver socket the relay client talks from. It must be one of the
    /// sockets given to the driver.
    fn local_addr(&self) -> SocketAddr;
    /// The relay server's address: a datagram from it belongs to the relay, not
    /// to the agent.
    fn server_addr(&self) -> SocketAddr;
    /// Split the agent's actions into datagrams for the relay server and the
    /// actions that leave ordinary sockets. An action from a relayed address
    /// whose relay is gone must be dropped, never handed back as a direct send.
    fn route(&mut self, actions: Vec<IceAction>) -> (Vec<Vec<u8>>, Vec<IceAction>);
    /// A datagram arrived from the relay server. Returns datagrams for the server
    /// and the agent's resulting actions, which are not yet routed.
    fn on_server_datagram(&mut self, agent: &mut IceAgent, raw: &[u8], now: Instant) -> (Vec<Vec<u8>>, Vec<IceAction>);
    /// Retransmissions, refreshes and upkeep. Returns datagrams for the server.
    fn poll(&mut self, agent: &IceAgent, now: Instant) -> Vec<Vec<u8>>;
    /// The earliest instant at which `poll` has something to do.
    fn next_wakeup(&self) -> Option<Instant>;
}

/// Run `agent` over `sockets` until it has settled and lingered, or `timeout`
/// elapses. Returns the agent's final state; the caller keeps the agent and can
/// read its selected pair.
pub async fn run_agent(agent: &mut IceAgent, sockets: &[Arc<UdpSocket>], opts: DriveOptions) -> ChecklistState {
    drive(agent, sockets, None, opts).await
}

/// [`run_agent`], with some of the agent's traffic carried through `relay`.
pub async fn run_agent_relayed(
    agent: &mut IceAgent,
    sockets: &[Arc<UdpSocket>],
    relay: &mut (dyn RelayPath + '_),
    opts: DriveOptions,
) -> ChecklistState {
    drive(agent, sockets, Some(relay), opts).await
}

async fn drive(
    agent: &mut IceAgent,
    sockets: &[Arc<UdpSocket>],
    mut relay: Option<&mut (dyn RelayPath + '_)>,
    opts: DriveOptions,
) -> ChecklistState {
    let mut by_addr: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<(SocketAddr, SocketAddr, Vec<u8>)>();
    let mut readers = Vec::new();

    for sock in sockets {
        let Ok(local) = sock.local_addr() else {
            continue;
        };
        by_addr.insert(local, Arc::clone(sock));
        let (sock, tx) = (Arc::clone(sock), tx.clone());
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if tx.send((local, from, buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);

    let start = Instant::now();
    let mut settled_at: Option<Instant> = None;

    loop {
        let now = Instant::now();
        dispatch(&by_addr, relay.as_deref_mut(), agent.poll(now)).await;
        if let Some(r) = relay.as_deref_mut() {
            let datagrams = r.poll(agent, now);
            send_to_relay(&by_addr, (r.local_addr(), r.server_addr()), datagrams).await;
        }

        if agent.state() != ChecklistState::Running {
            settled_at.get_or_insert(now);
        }
        if now >= start + opts.timeout || settled_at.is_some_and(|s| now >= s + opts.linger) {
            break;
        }

        let mut wake = agent.next_wakeup().unwrap_or(now + IDLE_POLL).min(start + opts.timeout);
        if let Some(w) = relay.as_deref().and_then(|r| r.next_wakeup()) {
            wake = wake.min(w);
        }
        if let Some(s) = settled_at {
            wake = wake.min(s + opts.linger);
        }

        tokio::select! {
            incoming = rx.recv() => match incoming {
                Some((local, from, data)) => {
                    let now = Instant::now();
                    match relay.as_deref_mut() {
                        Some(r) if local == r.local_addr() && from == r.server_addr() => {
                            let (to_server, actions) = r.on_server_datagram(agent, &data, now);
                            send_to_relay(&by_addr, (r.local_addr(), r.server_addr()), to_server).await;
                            dispatch(&by_addr, Some(r), actions).await;
                        }
                        other => {
                            let actions = agent.handle_datagram(from, local, &data, now);
                            dispatch(&by_addr, other, actions).await;
                        }
                    }
                }
                None => break, // every reader has stopped: nothing more can arrive
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
        }
    }

    for r in readers {
        r.abort();
    }
    agent.state()
}

/// Send the agent's actions: through the relay where they are from a relayed
/// address, from the socket they name otherwise.
async fn dispatch(by_addr: &HashMap<SocketAddr, Arc<UdpSocket>>, relay: Option<&mut (dyn RelayPath + '_)>, actions: Vec<IceAction>) {
    match relay {
        Some(r) => {
            let (to_server, direct) = r.route(actions);
            send_to_relay(by_addr, (r.local_addr(), r.server_addr()), to_server).await;
            send_all(by_addr, direct).await;
        }
        None => send_all(by_addr, actions).await,
    }
}

/// Send datagrams to the relay server, from the socket the relay client uses.
/// `link` is that socket's address and the server's, taken by value so no
/// reference to the relay is held across an await point.
async fn send_to_relay(by_addr: &HashMap<SocketAddr, Arc<UdpSocket>>, link: (SocketAddr, SocketAddr), datagrams: Vec<Vec<u8>>) {
    let (local, server) = link;
    if let Some(sock) = by_addr.get(&local) {
        for data in datagrams {
            let _ = sock.send_to(&data, server).await;
        }
    }
}

/// Send each action from the socket it names. UDP is best-effort and the
/// protocol retransmits, so a failed send is not an error; an action naming a
/// socket we do not hold is dropped.
async fn send_all(by_addr: &HashMap<SocketAddr, Arc<UdpSocket>>, actions: Vec<IceAction>) {
    for action in actions {
        let IceAction::Send { from, to, data } = action;
        if let Some(sock) = by_addr.get(&from) {
            let _ = sock.send_to(&data, to).await;
        }
    }
}
