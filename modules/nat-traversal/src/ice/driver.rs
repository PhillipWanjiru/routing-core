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

/// Run `agent` over `sockets` until it has settled and lingered, or `timeout`
/// elapses. Returns the agent's final state; the caller keeps the agent and can
/// read its selected pair.
pub async fn run_agent(agent: &mut IceAgent, sockets: &[Arc<UdpSocket>], opts: DriveOptions) -> ChecklistState {
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
        send_all(&by_addr, agent.poll(now)).await;

        if agent.state() != ChecklistState::Running {
            settled_at.get_or_insert(now);
        }
        if now >= start + opts.timeout || settled_at.is_some_and(|s| now >= s + opts.linger) {
            break;
        }

        let mut wake = agent.next_wakeup().unwrap_or(now + IDLE_POLL).min(start + opts.timeout);
        if let Some(s) = settled_at {
            wake = wake.min(s + opts.linger);
        }

        tokio::select! {
            incoming = rx.recv() => match incoming {
                Some((local, from, data)) => {
                    let actions = agent.handle_datagram(from, local, &data, Instant::now());
                    send_all(&by_addr, actions).await;
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
