//! The TURN server over real UDP sockets on loopback.
//!
//! The sans-IO server is thoroughly tested already; these tests are about what
//! only real sockets can show: that a relay port really opens, really forwards
//! in both directions, and really closes again, and that the loop survives
//! rubbish and shuts down cleanly. Clients are the sans-IO `TurnClient` driven
//! by a real socket, so the server is exercised the way a real client would.

mod common;

use common::*;
use nat_traversal::turn::{TurnClient, TurnClientAction, TurnClientConfig, TurnClientEvent, TurnClientStep};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

// ─── A client: the sans-IO TurnClient on a real socket ─────────────

struct Client {
    sock: UdpSocket,
    turn: TurnClient,
}

impl Client {
    async fn new(server: SocketAddr, tweak: impl FnOnce(&mut TurnClientConfig)) -> Client {
        let sock = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
        let mut cfg = TurnClientConfig::new(server, USER, PASS);
        tweak(&mut cfg);
        Client { sock, turn: TurnClient::new(cfg) }
    }
    fn addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap()
    }
    async fn send(&self, step: &TurnClientStep) {
        for TurnClientAction::Send { to, data } in &step.actions {
            self.sock.send_to(data, to).await.unwrap();
        }
    }

    /// Drive the client until an event satisfies `want`, or `limit` passes.
    async fn until(&mut self, limit: Duration, want: impl Fn(&TurnClientEvent) -> bool) -> Option<TurnClientEvent> {
        let deadline = Instant::now() + limit;
        let mut buf = vec![0u8; 65535];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let step = self.turn.poll(now);
            self.send(&step).await;
            if let Some(e) = step.events.into_iter().find(|e| want(e)) {
                return Some(e);
            }
            let wake = self.turn.next_wakeup().map_or(deadline, |w| w.min(deadline));
            tokio::select! {
                r = self.sock.recv_from(&mut buf) => {
                    let (n, from) = r.unwrap();
                    let step = self.turn.handle_datagram(from, &buf[..n], Instant::now());
                    self.send(&step).await;
                    if let Some(e) = step.events.into_iter().find(|e| want(e)) {
                        return Some(e);
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
            }
        }
    }

    /// Allocate, returning the relayed address.
    async fn allocate(&mut self) -> SocketAddr {
        let step = self.turn.start(Instant::now());
        self.send(&step).await;
        match self.until(Duration::from_secs(5), |e| matches!(e, TurnClientEvent::Allocated { .. } | TurnClientEvent::AllocationFailed { .. })).await {
            Some(TurnClientEvent::Allocated { relayed, .. }) => relayed,
            other => panic!("allocation did not succeed: {other:?}"),
        }
    }

    async fn permit(&mut self, ip: IpAddr) {
        let step = self.turn.create_permission(&[ip], Instant::now());
        self.send(&step).await;
        let ev = self.until(Duration::from_secs(5), |e| matches!(e, TurnClientEvent::PermissionInstalled { .. })).await;
        assert!(ev.is_some(), "the permission must be installed");
    }
}

// ─── Allocation and the relay data path ────────────────────────────

#[tokio::test]
async fn a_client_allocates_over_real_udp() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let step = c.turn.start(Instant::now());
    c.send(&step).await;

    let ev = c.until(Duration::from_secs(5), |e| matches!(e, TurnClientEvent::Allocated { .. })).await.expect("allocated");
    let TurnClientEvent::Allocated { relayed, mapped, lifetime_secs } = ev else { unreachable!() };
    assert_eq!(relayed.ip(), loopback(), "the relay is on the address the server was told to advertise");
    assert!((srv.lo..srv.lo + 5).contains(&relayed.port()), "from the server's own port pool");
    assert_eq!(mapped, c.addr(), "the server saw the client's real source address");
    assert_eq!(lifetime_secs, 600);
}

#[tokio::test]
async fn a_peers_datagram_reaches_the_client_through_a_real_relay_socket() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;
    c.permit(loopback()).await;

    let peer = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    peer.send_to(b"hello through the relay", relayed).await.unwrap();

    let ev = c.until(Duration::from_secs(3), |e| matches!(e, TurnClientEvent::Data { .. })).await.expect("data");
    assert_eq!(ev, TurnClientEvent::Data { peer: peer.local_addr().unwrap(), payload: b"hello through the relay".to_vec() });
}

#[tokio::test]
async fn a_clients_datagram_reaches_the_peer_from_the_relay_address() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;
    let peer = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    c.permit(loopback()).await;

    let TurnClientAction::Send { to, data } = c.turn.send_to_peer(peer.local_addr().unwrap(), b"media").unwrap();
    c.sock.send_to(&data, to).await.unwrap();

    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf)).await.expect("peer got it").unwrap();
    assert_eq!(&buf[..n], b"media");
    assert_eq!(from, relayed, "it must come from the relay socket, not from the server's control port or the client");
}

#[tokio::test]
async fn without_a_permission_the_peer_is_ignored() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;

    let peer = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    peer.send_to(b"unwelcome", relayed).await.unwrap();
    assert!(
        c.until(ms(400), |e| matches!(e, TurnClientEvent::Data { .. })).await.is_none(),
        "a relay with no permission installed must not be an open proxy"
    );
}

// ─── The relay socket's lifetime ───────────────────────────────────

#[tokio::test]
async fn deallocation_closes_the_relay_socket() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;
    assert!(!becomes_free(relayed.port(), ms(100)).await, "setup: the relay socket is open while allocated");

    let step = c.turn.deallocate(Instant::now());
    c.send(&step).await;
    assert!(c.until(Duration::from_secs(3), |e| matches!(e, TurnClientEvent::Closed)).await.is_some());
    assert!(becomes_free(relayed.port(), Duration::from_secs(2)).await, "the relay socket must close");
}

#[tokio::test]
async fn an_expired_allocation_is_closed_by_the_sweep() {
    let srv = start(5, ms(100)).await;
    let mut c = Client::new(srv.addr, |cfg| cfg.requested_lifetime = Some(1)).await;
    let relayed = c.allocate().await;

    // Nothing refreshes it: the client is not being driven while this waits.
    assert!(becomes_free(relayed.port(), Duration::from_secs(4)).await, "the sweep must close an expired relay socket");
}

#[tokio::test]
async fn shutdown_returns_the_server_and_closes_every_relay() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;
    let client_addr = c.addr();

    let server = srv.stop().await;
    assert!(server.allocation_for(&client_addr).is_some(), "the final state comes back for inspection");
    assert!(becomes_free(relayed.port(), Duration::from_secs(2)).await, "and no relay socket is left open");
}

// ─── Robustness ────────────────────────────────────────────────────

#[tokio::test]
async fn several_clients_get_distinct_relays_at_once() {
    let srv = start(8, Duration::from_secs(1)).await;
    let mut clients = Vec::new();
    for _ in 0..4 {
        clients.push(Client::new(srv.addr, |_| {}).await);
    }
    let relays = allocate_all(&mut clients).await;
    let mut ports: Vec<u16> = relays.iter().map(|a| a.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 4, "four clients, four different relay ports");
}

/// Allocate every client concurrently, one task each.
async fn allocate_all(clients: &mut Vec<Client>) -> Vec<SocketAddr> {
    let mut handles = Vec::new();
    for mut c in clients.drain(..) {
        handles.push(tokio::spawn(async move { c.allocate().await }));
    }
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test]
async fn garbage_on_either_socket_does_not_disturb_the_server() {
    let srv = start(5, Duration::from_secs(1)).await;
    let mut c = Client::new(srv.addr, |_| {}).await;
    let relayed = c.allocate().await;
    c.permit(loopback()).await;

    let noise = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    for junk in [&b""[..], &[0xFF; 7][..], &[0u8; 64][..], &[0x40, 0x00, 0xFF, 0xFF][..]] {
        noise.send_to(junk, srv.addr).await.unwrap();
        noise.send_to(junk, relayed).await.unwrap();
    }

    // Still serving: a new client allocates, and the first one's data path works.
    let mut second = Client::new(srv.addr, |_| {}).await;
    second.allocate().await;
    let peer = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    peer.send_to(b"still alive", relayed).await.unwrap();
    assert!(c.until(Duration::from_secs(3), |e| matches!(e, TurnClientEvent::Data { .. })).await.is_some());
}

#[tokio::test]
async fn a_relay_socket_that_cannot_be_opened_is_abandoned_and_the_client_gets_no_false_success() {
    // A pool of one port, with something else already holding that port.
    let srv = start(1, Duration::from_secs(1)).await;
    let blocker = UdpSocket::bind((LOOPBACK, srv.lo)).await.expect("setup: take the server's only port");

    let mut c = Client::new(srv.addr, |cfg| {
        cfg.rto = ms(50);
        cfg.max_transmissions = 3;
        cfg.final_wait_multiplier = 4;
    })
    .await;
    let step = c.turn.start(Instant::now());
    c.send(&step).await;
    let ev = c.until(Duration::from_secs(5), |e| matches!(e, TurnClientEvent::Allocated { .. } | TurnClientEvent::AllocationFailed { .. })).await;
    assert_eq!(ev, Some(TurnClientEvent::AllocationFailed { code: None }), "no success may be sent for a relay that does not exist");

    drop(blocker);
    let server = srv.stop().await;
    assert!(server.allocation_for(&c.addr()).is_none(), "and the server must not keep the dead allocation");
}
