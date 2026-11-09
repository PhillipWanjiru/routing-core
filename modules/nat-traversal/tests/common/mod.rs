//! Helpers shared by the real-socket integration tests: a TURN server running on
//! loopback, and a way to tell when one of its relay ports has closed.

#![allow(dead_code)] // each test crate uses a different subset

use nat_traversal::turn::driver::{run_turn_server, TurnDriveOptions};
use nat_traversal::turn::{CredentialStore, PortPool, TurnServer};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub const REALM: &str = "routing-core.local";
pub const USER: &str = "alice";
pub const PASS: &str = "correcthorsebatterystaple";
pub const LOOPBACK: &str = "127.0.0.1";

/// Each test gets its own block of relay ports, so tests running in parallel in
/// one process never fight over a port.
static NEXT_PORT: AtomicU16 = AtomicU16::new(42000);

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
pub fn loopback() -> IpAddr {
    LOOPBACK.parse().unwrap()
}

/// A TURN server on a real socket.
pub struct Server {
    pub addr: SocketAddr,
    /// The first relay port of this server's pool.
    pub lo: u16,
    stop: oneshot::Sender<()>,
    task: JoinHandle<TurnServer>,
}

pub async fn start(ports: u16, sweep: Duration) -> Server {
    let lo = NEXT_PORT.fetch_add(ports, Ordering::SeqCst);
    let hi = lo + ports - 1;
    let mut creds = CredentialStore::new();
    creds.add_user(USER, PASS);
    let server = TurnServer::new(REALM, loopback(), creds, PortPool::new(lo, hi));

    let control = Arc::new(UdpSocket::bind((LOOPBACK, 0)).await.unwrap());
    let addr = control.local_addr().unwrap();
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(run_turn_server(server, control, loopback(), TurnDriveOptions { sweep_interval: sweep }, shutdown));
    Server { addr, lo, stop, task }
}

impl Server {
    /// Stop serving and hand back the server's final state.
    pub async fn stop(self) -> TurnServer {
        let _ = self.stop.send(());
        self.task.await.unwrap()
    }
}

/// True once nothing holds `port` any more, i.e. the relay socket has closed.
pub async fn becomes_free(port: u16, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if UdpSocket::bind((LOOPBACK, port)).await.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(ms(20)).await;
    }
}
