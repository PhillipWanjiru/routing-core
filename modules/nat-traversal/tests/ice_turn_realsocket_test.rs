//! ICE over a TURN relay on real sockets: real agents, real TURN clients, and a
//! real `TurnServer` on loopback.
//!
//! Loopback has no NAT to defeat the direct path, so the main scenario uses a
//! relay-only policy: each agent offers just its relayed candidate. That is a real
//! configuration (what a browser's `iceTransportPolicy: "relay"` does), and it
//! proves the relay path end to end over real UDP. `ice_turn_test` covers the
//! symmetric-NAT cases themselves, in simulation.

mod common;

use common::*;
use nat_traversal::ice::{
    run_agent_relayed, Candidate, CandidateType, ChecklistState, DriveOptions, IceAgent, IceConfig,
    IceCredentials, IceRole, Nomination, RelayPath,
};
use nat_traversal::ice_turn::driver::{allocate_relay, install_permissions, RelayError};
use nat_traversal::ice_turn::{TurnBridge, TurnRelay};
use nat_traversal::turn::{TurnClientAction, TurnClientConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn creds(tag: &str) -> IceCredentials {
    IceCredentials { ufrag: format!("{tag}frg"), password: format!("{tag}-password-0123456789abcd") }
}
fn config() -> IceConfig {
    IceConfig {
        ta: ms(20), min_rto: ms(100), max_transmissions: 7, final_wait_multiplier: 16,
        nomination: Nomination::Regular { delay: ms(100) },
    }
}
fn opts() -> DriveOptions {
    DriveOptions { timeout: Duration::from_secs(20), linger: Duration::from_secs(1) }
}
fn host_cand(addr: SocketAddr) -> Candidate {
    Candidate::new(CandidateType::Host, addr, addr, 65535, 1)
}

/// One client: a socket shared by the agent's direct traffic and the TURN client,
/// with its allocation already made.
struct Side {
    sock: Arc<UdpSocket>,
    relay: TurnRelay,
    host: Candidate,
    relayed: Candidate,
}

async fn side(server: SocketAddr) -> Side {
    let sock = Arc::new(UdpSocket::bind((LOOPBACK, 0)).await.unwrap());
    let addr = sock.local_addr().unwrap();
    let mut bridge = TurnBridge::new(TurnClientConfig::new(server, USER, PASS));
    let relayed = allocate_relay(&mut bridge, &sock, Duration::from_secs(5)).await.expect("allocation");
    Side { sock, relay: TurnRelay::new(bridge, addr), host: host_cand(addr), relayed }
}

fn agent(controlling: bool, local: Vec<Candidate>, remote: Vec<Candidate>) -> IceAgent {
    let (role, tie, me, peer) =
        if controlling { (IceRole::Controlling, 100, "a", "b") } else { (IceRole::Controlled, 50, "b", "a") };
    IceAgent::new(config(), role, tie, creds(me), creds(peer), local, remote, Instant::now())
}

fn uses_relay(agent: &IceAgent) -> bool {
    agent
        .selected_pair()
        .map(|v| v.pair.local.candidate_type == CandidateType::Relayed || v.pair.remote.candidate_type == CandidateType::Relayed)
        .unwrap_or(false)
}

/// Two relay-only clients that have completed ICE through a real TURN server.
struct Connected {
    server: Server,
    a: Side,
    b: Side,
    agent_a: IceAgent,
    agent_b: IceAgent,
}

async fn connect_relay_only() -> Connected {
    let server = start(10, Duration::from_secs(1)).await;
    let (mut a, mut b) = (side(server.addr).await, side(server.addr).await);
    install_permissions(a.relay.bridge_mut(), &a.sock, &[b.relayed.clone()], Duration::from_secs(5)).await.expect("A permits B");
    install_permissions(b.relay.bridge_mut(), &b.sock, &[a.relayed.clone()], Duration::from_secs(5)).await.expect("B permits A");

    let mut agent_a = agent(true, vec![a.relayed.clone()], vec![b.relayed.clone()]);
    let mut agent_b = agent(false, vec![b.relayed.clone()], vec![a.relayed.clone()]);
    let (socks_a, socks_b) = (vec![Arc::clone(&a.sock)], vec![Arc::clone(&b.sock)]);
    let (ra, rb) = tokio::join!(
        run_agent_relayed(&mut agent_a, &socks_a, &mut a.relay, opts()),
        run_agent_relayed(&mut agent_b, &socks_b, &mut b.relay, opts()),
    );
    assert_eq!((ra, rb), (ChecklistState::Completed, ChecklistState::Completed), "relay-only ICE must complete");
    Connected { server, a, b, agent_a, agent_b }
}

// ─── The relay path over real UDP ──────────────────────────────────

#[tokio::test]
async fn two_agents_complete_through_a_real_turn_server() {
    let c = connect_relay_only().await;
    assert!(uses_relay(&c.agent_a) && uses_relay(&c.agent_b), "with only relayed candidates, the path can only be the relay");
}

#[tokio::test]
async fn media_flows_both_ways_over_the_nominated_relay_path() {
    let mut c = connect_relay_only().await;
    let (relayed_a, relayed_b) = (c.a.relayed.transport_addr, c.b.relayed.transport_addr);

    // A to B.
    let TurnClientAction::Send { to, data } = c.a.relay.bridge().send_app(relayed_b, b"A to B: media").expect("allocated");
    c.a.sock.send_to(&data, to).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), c.b.sock.recv_from(&mut buf)).await.expect("B received").unwrap();
    assert_eq!(from, c.server.addr, "it arrives from the TURN server, wrapped");
    c.b.relay.on_server_datagram(&mut c.agent_b, &buf[..n], Instant::now());
    assert_eq!(c.b.relay.take_media(), vec![(relayed_a, b"A to B: media".to_vec())], "unwrapped, and attributed to A's relayed address");

    // And back.
    let TurnClientAction::Send { to, data } = c.b.relay.bridge().send_app(relayed_a, b"B to A: media").expect("allocated");
    c.b.sock.send_to(&data, to).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), c.a.sock.recv_from(&mut buf)).await.expect("A received").unwrap();
    c.a.relay.on_server_datagram(&mut c.agent_a, &buf[..n], Instant::now());
    assert_eq!(c.a.relay.take_media(), vec![(relayed_b, b"B to A: media".to_vec())]);
}

#[tokio::test]
async fn permissions_are_installed_during_the_run_when_they_were_not_before() {
    // No install_permissions call: the driver itself must ask the server for the
    // peer's IPs, by polling the relay. The first checks may be dropped by the
    // relay until the permission exists; ICE retransmits, and completes.
    let server = start(10, Duration::from_secs(1)).await;
    let (mut a, mut b) = (side(server.addr).await, side(server.addr).await);
    let mut agent_a = agent(true, vec![a.relayed.clone()], vec![b.relayed.clone()]);
    let mut agent_b = agent(false, vec![b.relayed.clone()], vec![a.relayed.clone()]);
    let (socks_a, socks_b) = (vec![Arc::clone(&a.sock)], vec![Arc::clone(&b.sock)]);
    let (ra, rb) = tokio::join!(
        run_agent_relayed(&mut agent_a, &socks_a, &mut a.relay, opts()),
        run_agent_relayed(&mut agent_b, &socks_b, &mut b.relay, opts()),
    );
    assert_eq!((ra, rb), (ChecklistState::Completed, ChecklistState::Completed));
}

#[tokio::test]
async fn the_direct_path_still_wins_when_a_relay_is_also_available() {
    // Each agent offers a host and a relayed candidate on ONE socket, which carries
    // both the direct traffic and the traffic to the TURN server. Direct works on
    // loopback, so the relay must not be chosen.
    let server = start(10, Duration::from_secs(1)).await;
    let (mut a, mut b) = (side(server.addr).await, side(server.addr).await);
    install_permissions(a.relay.bridge_mut(), &a.sock, &[b.host.clone(), b.relayed.clone()], Duration::from_secs(5)).await.unwrap();
    install_permissions(b.relay.bridge_mut(), &b.sock, &[a.host.clone(), a.relayed.clone()], Duration::from_secs(5)).await.unwrap();

    let mut agent_a = agent(true, vec![a.host.clone(), a.relayed.clone()], vec![b.host.clone(), b.relayed.clone()]);
    let mut agent_b = agent(false, vec![b.host.clone(), b.relayed.clone()], vec![a.host.clone(), a.relayed.clone()]);
    let (socks_a, socks_b) = (vec![Arc::clone(&a.sock)], vec![Arc::clone(&b.sock)]);
    let (ra, rb) = tokio::join!(
        run_agent_relayed(&mut agent_a, &socks_a, &mut a.relay, opts()),
        run_agent_relayed(&mut agent_b, &socks_b, &mut b.relay, opts()),
    );
    assert_eq!((ra, rb), (ChecklistState::Completed, ChecklistState::Completed));
    assert!(!uses_relay(&agent_a) && !uses_relay(&agent_b), "a direct path exists, so the relay stays a last resort");
}

// ─── Allocation and permission failures ────────────────────────────

#[tokio::test]
async fn allocation_with_the_wrong_password_is_refused_with_401() {
    let server = start(5, Duration::from_secs(1)).await;
    let sock = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let mut bridge = TurnBridge::new(TurnClientConfig::new(server.addr, USER, "not-the-password"));
    assert_eq!(
        allocate_relay(&mut bridge, &sock, Duration::from_secs(5)).await.unwrap_err(),
        RelayError::AllocationFailed(Some(401))
    );
}

#[tokio::test]
async fn allocation_against_a_server_that_is_not_there_times_out() {
    let gone = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let nowhere = gone.local_addr().unwrap();
    drop(gone);

    let sock = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let mut bridge = TurnBridge::new(TurnClientConfig::new(nowhere, USER, PASS));
    assert_eq!(allocate_relay(&mut bridge, &sock, ms(700)).await.unwrap_err(), RelayError::Timeout);
}

#[tokio::test]
async fn permissions_cannot_be_installed_without_an_allocation() {
    let sock = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let mut bridge = TurnBridge::new(TurnClientConfig::new("127.0.0.1:9".parse().unwrap(), USER, PASS));
    let peer = host_cand("127.0.0.1:5555".parse().unwrap());
    assert_eq!(
        install_permissions(&mut bridge, &sock, &[peer], ms(300)).await.unwrap_err(),
        RelayError::AllocationFailed(None),
        "success here would hide that nothing could be asked"
    );
}

#[tokio::test]
async fn installing_permissions_that_are_already_in_place_returns_at_once() {
    let server = start(5, Duration::from_secs(1)).await;
    let mut a = side(server.addr).await;
    let peer = host_cand("127.0.0.1:5555".parse().unwrap());
    install_permissions(a.relay.bridge_mut(), &a.sock, &[peer.clone()], Duration::from_secs(5)).await.unwrap();

    let started = Instant::now();
    install_permissions(a.relay.bridge_mut(), &a.sock, &[peer], Duration::from_secs(5)).await.unwrap();
    assert!(started.elapsed() < ms(50), "nothing new to ask means no round trip");
}

// ─── The relay path's addresses ────────────────────────────────────

#[tokio::test]
async fn the_relay_client_speaks_from_the_shared_socket_to_the_server() {
    let server = start(5, Duration::from_secs(1)).await;
    let a = side(server.addr).await;
    assert_eq!(a.relay.local_addr(), a.sock.local_addr().unwrap(), "the relay client speaks from the shared socket");
    assert_eq!(a.relay.server_addr(), server.addr);
}
