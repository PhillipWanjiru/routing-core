//! ICE candidate gathering tests.
//!
//! `gather_server_reflexive_candidate_over_real_stun_round_trip` is the
//! test that matters most here: it runs the actual gathering function
//! against a real UDP socket, with the real STUN Binding request the
//! function sends answered by `stun::server::handle_datagram` — the
//! same server implementation already independently verified earlier in
//! this project, not a mock built for this test alone. If the wire
//! format between `ice::gather` and `stun::server` ever drifted apart,
//! this is the test that would catch it.

use nat_traversal::ice::{
    gather_host_candidates, gather_server_reflexive_candidate, CandidateType, GatherError,
};
use nat_traversal::stun::handle_datagram as stun_handle_datagram;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

// ─── Host candidates ───────────────────────────────────────────────

#[test]
fn gather_host_candidates_wraps_given_addresses() {
    let addrs = vec![local_addr(5000), local_addr(5001)];
    let candidates = gather_host_candidates(&addrs, 1);

    assert_eq!(candidates.len(), 2);
    for (c, expected_addr) in candidates.iter().zip(addrs.iter()) {
        assert_eq!(c.candidate_type, CandidateType::Host);
        assert_eq!(c.transport_addr, *expected_addr);
        assert_eq!(c.base_addr, *expected_addr, "host candidate's base must equal its own address");
        assert_eq!(c.component_id, 1);
    }
}

#[test]
fn gather_host_candidates_empty_input_returns_empty() {
    let candidates = gather_host_candidates(&[], 1);
    assert!(candidates.is_empty());
}

#[test]
fn gather_host_candidates_applies_given_component_id_to_all() {
    let addrs = vec![local_addr(5000), local_addr(5001), local_addr(5002)];
    let candidates = gather_host_candidates(&addrs, 2);
    assert!(candidates.iter().all(|c| c.component_id == 2));
}

// ─── Server-reflexive: the real round trip ─────────────────────────

/// Spawn a real STUN server on `bind_addr`, using the exact same
/// `handle_datagram` implementation this project already verified for
/// the STUN Binding milestone. Returns a handle to abort it.
async fn spawn_stun_server(bind_addr: SocketAddr) -> tokio::task::JoinHandle<()> {
    let socket = UdpSocket::bind(bind_addr).await.expect("bind test STUN server");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Some(resp) = stun_handle_datagram(&buf[..n], peer) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    })
}

#[tokio::test]
async fn gather_server_reflexive_real_round_trip_against_real_stun_server() {
    let server_addr = local_addr(38000);
    let server_task = spawn_stun_server(server_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await; // let the server start listening

    let bind_addr = local_addr(0); // OS-assigned ephemeral port
    let result = gather_server_reflexive_candidate(
        server_addr, bind_addr, 1, Duration::from_secs(2),
    ).await;

    server_task.abort();

    let candidate = result.expect("gathering against a real, live STUN server must succeed");

    assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
    assert_eq!(
        candidate.transport_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "on loopback there is no NAT, so the server-observed address must be loopback too"
    );
    // On loopback, the server observes exactly the socket's own local
    // address -- no translation occurs. This is the same structural
    // check the original STUN Binding milestone used to prove the
    // server told the truth about what it saw.
    assert_eq!(
        candidate.transport_addr, candidate.base_addr,
        "on loopback (no real NAT), the observed address must equal the local bind address"
    );
    assert_eq!(candidate.component_id, 1);
}

#[tokio::test]
async fn gather_server_reflexive_candidate_has_correct_foundation() {
    let server_addr = local_addr(38001);
    let server_task = spawn_stun_server(server_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let candidate = gather_server_reflexive_candidate(
        server_addr, local_addr(0), 1, Duration::from_secs(2),
    ).await.expect("should succeed");

    server_task.abort();

    let expected = format!("{:?}-{}", CandidateType::ServerReflexive, candidate.base_addr.ip());
    assert_eq!(candidate.foundation, expected);
}

#[tokio::test]
async fn gather_server_reflexive_times_out_when_nothing_answers() {
    // Bind a "server" address that nothing is listening on -- no server
    // task spawned at all, so no response will ever arrive.
    let unanswered_addr = local_addr(38002);

    let result = gather_server_reflexive_candidate(
        unanswered_addr, local_addr(0), 1, Duration::from_millis(200),
    ).await;

    assert_eq!(result, Err(GatherError::Timeout));
}

#[tokio::test]
async fn gather_server_reflexive_invalid_response_does_not_panic() {
    // A "server" that immediately replies with garbage instead of a
    // valid STUN message.
    let garbage_server_addr = local_addr(38003);
    let socket = UdpSocket::bind(garbage_server_addr).await.expect("bind garbage server");
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&[0xFF, 0xFF, 0xFF], peer).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = gather_server_reflexive_candidate(
        garbage_server_addr, local_addr(0), 1, Duration::from_secs(1),
    ).await;

    server_task.abort();
    assert_eq!(result, Err(GatherError::InvalidResponse));
}

#[tokio::test]
async fn gather_server_reflexive_multiple_concurrent_gathers_get_distinct_ports() {
    // Two simultaneous gathers against the same server must not collide
    // on the local ephemeral port (each uses bind_addr with port 0, so
    // the OS assigns distinct ports) or on the STUN transaction ID.
    let server_addr = local_addr(38004);
    let server_task = spawn_stun_server(server_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (r1, r2) = tokio::join!(
        gather_server_reflexive_candidate(server_addr, local_addr(0), 1, Duration::from_secs(2)),
        gather_server_reflexive_candidate(server_addr, local_addr(0), 1, Duration::from_secs(2)),
    );

    server_task.abort();

    let c1 = r1.expect("first gather should succeed");
    let c2 = r2.expect("second gather should succeed");
    assert_ne!(
        c1.transport_addr.port(), c2.transport_addr.port(),
        "two concurrent gathers must resolve to two distinct local ports"
    );
}
