//! Two ICE agents over *real* UDP sockets on loopback, with the real clock.
//!
//! Everything else in the ICE test suite runs on a virtual clock and an
//! in-memory network. These tests exist to show that the same state machine,
//! unchanged, also works against the kernel's UDP stack and wall-clock time —
//! which is what the driver adds. The timers are short so the tests are quick,
//! but nothing is simulated.

use nat_traversal::ice::{
    random_tie_breaker, run_agent, Candidate, CandidateType, ChecklistState, DriveOptions, IceAgent,
    IceConfig, IceCredentials, IceRole, Nomination,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
fn fast() -> IceConfig {
    IceConfig {
        ta: ms(20), min_rto: ms(100), max_transmissions: 7, final_wait_multiplier: 16,
        nomination: Nomination::Regular { delay: ms(100) },
    }
}
fn creds(tag: &str) -> IceCredentials {
    IceCredentials { ufrag: format!("{tag}frg"), password: format!("{tag}-password-0123456789abcd") }
}
fn host(addr: SocketAddr, pref: u16) -> Candidate {
    Candidate::new(CandidateType::Host, addr, addr, pref, 1)
}
async fn bound() -> (Arc<UdpSocket>, SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = s.local_addr().unwrap();
    (Arc::new(s), addr)
}
/// An address nobody is listening on: bind, note the port, close.
async fn dead_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
}
fn opts() -> DriveOptions {
    DriveOptions { timeout: Duration::from_secs(5), linger: ms(300) }
}

/// Run an agent to completion on a task; hand the agent back for inspection.
fn spawn_agent(mut agent: IceAgent, sockets: Vec<Arc<UdpSocket>>, opts: DriveOptions) -> tokio::task::JoinHandle<IceAgent> {
    tokio::spawn(async move {
        run_agent(&mut agent, &sockets, opts).await;
        agent
    })
}

#[tokio::test]
async fn two_agents_complete_over_real_loopback_udp() {
    let (sock_a, addr_a) = bound().await;
    let (sock_b, addr_b) = bound().await;
    let t0 = Instant::now();
    let agent_a = IceAgent::new(fast(), IceRole::Controlling, random_tie_breaker(), creds("a"), creds("b"),
        vec![host(addr_a, 65535)], vec![host(addr_b, 65535)], t0);
    let agent_b = IceAgent::new(fast(), IceRole::Controlled, random_tie_breaker(), creds("b"), creds("a"),
        vec![host(addr_b, 65535)], vec![host(addr_a, 65535)], t0);

    let (ra, rb) = tokio::join!(
        spawn_agent(agent_a, vec![sock_a], opts()),
        spawn_agent(agent_b, vec![sock_b], opts()),
    );
    let (a, b) = (ra.unwrap(), rb.unwrap());

    assert_eq!(a.state(), ChecklistState::Completed);
    assert_eq!(b.state(), ChecklistState::Completed);
    let (pa, pb) = (&a.selected_pair().unwrap().pair, &b.selected_pair().unwrap().pair);
    assert_eq!((pa.local.transport_addr, pa.remote.transport_addr), (addr_a, addr_b));
    assert_eq!((pb.local.transport_addr, pb.remote.transport_addr), (addr_b, addr_a));
}

#[tokio::test]
async fn a_role_conflict_resolves_over_real_sockets_with_random_tie_breakers() {
    let (sock_a, addr_a) = bound().await;
    let (sock_b, addr_b) = bound().await;
    let (tie_a, tie_b) = loop {
        let (x, y) = (random_tie_breaker(), random_tie_breaker());
        if x != y {
            break (x, y);
        }
    };
    let t0 = Instant::now();
    // Both believe they are controlling.
    let agent_a = IceAgent::new(fast(), IceRole::Controlling, tie_a, creds("a"), creds("b"),
        vec![host(addr_a, 65535)], vec![host(addr_b, 65535)], t0);
    let agent_b = IceAgent::new(fast(), IceRole::Controlling, tie_b, creds("b"), creds("a"),
        vec![host(addr_b, 65535)], vec![host(addr_a, 65535)], t0);

    let (ra, rb) = tokio::join!(
        spawn_agent(agent_a, vec![sock_a], opts()),
        spawn_agent(agent_b, vec![sock_b], opts()),
    );
    let (a, b) = (ra.unwrap(), rb.unwrap());

    assert_eq!(a.state(), ChecklistState::Completed);
    assert_eq!(b.state(), ChecklistState::Completed);
    assert_ne!(a.role(), b.role(), "exactly one side may end up controlling");
    assert_eq!(a.role() == IceRole::Controlling, tie_a > tie_b, "and it must be the one with the larger tie-breaker");
}

#[tokio::test]
async fn a_dead_higher_priority_candidate_does_not_delay_completion_on_real_sockets() {
    let (sock_a, addr_a) = bound().await;
    let (sock_b, addr_b) = bound().await;
    let dead = dead_addr().await;
    let t0 = Instant::now();
    // A is told about a candidate that outranks the real one and goes nowhere.
    // (On loopback both share an IP, hence a foundation: the dead pair is the
    // Waiting one and the real pair starts Frozen, released by the rule that
    // an idle Frozen pair is checked anyway.)
    let agent_a = IceAgent::new(fast(), IceRole::Controlling, random_tie_breaker(), creds("a"), creds("b"),
        vec![host(addr_a, 65535)], vec![host(dead, 65535), host(addr_b, 100)], t0);
    let agent_b = IceAgent::new(fast(), IceRole::Controlled, random_tie_breaker(), creds("b"), creds("a"),
        vec![host(addr_b, 65535)], vec![host(addr_a, 65535)], t0);

    let started = Instant::now();
    let (ra, rb) = tokio::join!(
        spawn_agent(agent_a, vec![sock_a], opts()),
        spawn_agent(agent_b, vec![sock_b], opts()),
    );
    let elapsed = started.elapsed();
    let (a, b) = (ra.unwrap(), rb.unwrap());

    assert_eq!(a.state(), ChecklistState::Completed);
    assert_eq!(b.state(), ChecklistState::Completed);
    assert_eq!(a.selected_pair().unwrap().pair.remote.transport_addr, addr_b, "the live path, not the dead one");
    // The dead pair alone would take ~8 s to time out with these timers. Two
    // seconds is a very generous bound on the real work (about 0.4 s: the
    // nomination delay plus the 300 ms linger).
    assert!(elapsed < Duration::from_secs(2), "completion took {elapsed:?}: the dead pair held it up");
}

#[tokio::test]
async fn an_agent_with_several_local_sockets_uses_the_best_one() {
    let (sock_a1, addr_a1) = bound().await;
    let (sock_a2, addr_a2) = bound().await;
    let (sock_b, addr_b) = bound().await;
    let t0 = Instant::now();
    let agent_a = IceAgent::new(fast(), IceRole::Controlling, random_tie_breaker(), creds("a"), creds("b"),
        vec![host(addr_a1, 65535), host(addr_a2, 100)], vec![host(addr_b, 65535)], t0);
    let agent_b = IceAgent::new(fast(), IceRole::Controlled, random_tie_breaker(), creds("b"), creds("a"),
        vec![host(addr_b, 65535)], vec![host(addr_a1, 65535), host(addr_a2, 100)], t0);

    let (ra, rb) = tokio::join!(
        spawn_agent(agent_a, vec![sock_a1, sock_a2], opts()),
        spawn_agent(agent_b, vec![sock_b], opts()),
    );
    let (a, b) = (ra.unwrap(), rb.unwrap());

    assert_eq!(a.state(), ChecklistState::Completed);
    assert_eq!(b.state(), ChecklistState::Completed);
    assert_eq!(a.selected_pair().unwrap().pair.local.transport_addr, addr_a1, "A's higher-preference socket wins");
    assert_eq!(b.selected_pair().unwrap().pair.remote.transport_addr, addr_a1, "and B agrees");
}

#[tokio::test]
async fn an_agent_reports_failure_when_nobody_answers() {
    let (sock_a, addr_a) = bound().await;
    let nobody = dead_addr().await;
    let t0 = Instant::now();
    // Rc=2, Rm=2, RTO=50ms: the only pair fails after about 150 ms.
    let config = IceConfig {
        ta: ms(20), min_rto: ms(50), max_transmissions: 2, final_wait_multiplier: 2,
        nomination: Nomination::Regular { delay: ms(100) },
    };
    let agent_a = IceAgent::new(config, IceRole::Controlling, random_tie_breaker(), creds("a"), creds("b"),
        vec![host(addr_a, 65535)], vec![host(nobody, 65535)], t0);

    let started = Instant::now();
    let a = spawn_agent(agent_a, vec![sock_a], DriveOptions { timeout: Duration::from_secs(5), linger: ms(50) })
        .await
        .unwrap();

    assert_eq!(a.state(), ChecklistState::Failed);
    assert!(a.selected_pair().is_none());
    assert!(started.elapsed() < Duration::from_secs(2), "the driver must notice failure, not wait out its timeout");
}
