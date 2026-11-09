//! Running a [`TurnServer`] over real UDP sockets and the real clock.
//!
//! The server is a sans-IO state machine. This is the thin layer that supplies
//! the sockets and the clock: it reads the control socket, opens and closes one
//! relay socket per allocation as the server directs, sends each output from the
//! socket it names, and calls `sweep` on a timer so expired allocations close.
//!
//! # Sockets
//!
//! The control socket is the caller's to bind (so the caller learns its address,
//! including when it asks for port 0). Relay sockets are bound here, on
//! `relay_bind_ip` at the port the server chose. That address must be the one the
//! server was built to advertise (`TurnServer::new`'s `relay_ip`), or peers will
//! be told to send somewhere nothing is listening.
//!
//! # A relay socket that cannot be opened
//!
//! The server emits `RelayOpened` *before* the Allocate success response, so the
//! failure is seen before the client has been told anything. The driver then
//! abandons the allocation and drops the rest of that batch, so the client is not
//! sent a success for a relay that does not exist. It gets silence, retransmits,
//! and eventually gives up.
//!
//! # Stopping
//!
//! The server runs until `shutdown` resolves (a message, or its sender being
//! dropped). It returns the server so the caller can inspect what it held, and
//! closes every relay socket.

use super::service::{TurnOutput, TurnServer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Datagrams waiting between the relay readers and the server loop. Bounded, so
/// a flood at a relay port is dropped by the kernel rather than queued here.
const RELAY_QUEUE: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct TurnDriveOptions {
    /// How often to expire allocations, permissions and channel bindings.
    pub sweep_interval: Duration,
}

impl Default for TurnDriveOptions {
    fn default() -> Self {
        TurnDriveOptions { sweep_interval: Duration::from_secs(1) }
    }
}

struct RelaySocket {
    socket: Arc<UdpSocket>,
    reader: JoinHandle<()>,
}

struct Relays {
    bind_ip: IpAddr,
    sockets: HashMap<u16, RelaySocket>,
    /// Datagrams read from relay sockets: (relay port, sender, payload).
    tx: mpsc::Sender<(u16, SocketAddr, Vec<u8>)>,
}

impl Relays {
    async fn open(&mut self, port: u16) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(SocketAddr::new(self.bind_ip, port)).await?);
        let (reader_socket, tx) = (Arc::clone(&socket), self.tx.clone());
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = reader_socket.recv_from(&mut buf).await {
                if tx.send((port, from, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        });
        self.sockets.insert(port, RelaySocket { socket, reader });
        Ok(())
    }

    fn close(&mut self, port: u16) {
        if let Some(r) = self.sockets.remove(&port) {
            r.reader.abort();
        }
    }

    fn close_all(&mut self) {
        for (_, r) in self.sockets.drain() {
            r.reader.abort();
        }
    }

    /// Carry out the server's outputs in order. `from_client` is the sender of the
    /// datagram that produced them, if it came from a client: it names the
    /// allocation to abandon if a relay socket cannot be opened.
    async fn dispatch(
        &mut self,
        server: &mut TurnServer,
        control: &UdpSocket,
        from_client: Option<SocketAddr>,
        outputs: Vec<TurnOutput>,
    ) {
        for out in outputs {
            match out {
                TurnOutput::ToClient { to, data } => {
                    let _ = control.send_to(&data, to).await;
                }
                TurnOutput::ToPeer { relay_port, to, data } => {
                    if let Some(r) = self.sockets.get(&relay_port) {
                        let _ = r.socket.send_to(&data, to).await;
                    }
                }
                TurnOutput::RelayOpened { relay_port } => {
                    if let Err(e) = self.open(relay_port).await {
                        tracing::warn!(relay_port, error = %e, "cannot open relay socket; abandoning the allocation");
                        if let Some(client) = from_client {
                            for closed in server.abandon(&client, Instant::now()) {
                                if let TurnOutput::RelayClosed { relay_port } = closed {
                                    self.close(relay_port);
                                }
                            }
                        }
                        // The rest of this batch assumes the relay exists, including
                        // the Allocate success. Withhold it.
                        return;
                    }
                }
                TurnOutput::RelayClosed { relay_port } => self.close(relay_port),
            }
        }
    }
}

/// Serve `server` on `control` until `shutdown` resolves, then return it.
pub async fn run_turn_server(
    mut server: TurnServer,
    control: Arc<UdpSocket>,
    relay_bind_ip: IpAddr,
    opts: TurnDriveOptions,
    mut shutdown: oneshot::Receiver<()>,
) -> TurnServer {
    let (tx, mut rx) = mpsc::channel(RELAY_QUEUE);
    let mut relays = Relays { bind_ip: relay_bind_ip, sockets: HashMap::new(), tx };
    let mut sweep = tokio::time::interval(opts.sweep_interval);
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            received = control.recv_from(&mut buf) => {
                if let Ok((n, from)) = received {
                    let outs = server.handle_from_client(from, &buf[..n], Instant::now());
                    relays.dispatch(&mut server, &control, Some(from), outs).await;
                }
            }
            Some((port, from, data)) = rx.recv() => {
                let outs = server.handle_from_peer(port, from, &data, Instant::now());
                relays.dispatch(&mut server, &control, None, outs).await;
            }
            _ = sweep.tick() => {
                let outs = server.sweep(Instant::now());
                relays.dispatch(&mut server, &control, None, outs).await;
            }
        }
    }

    relays.close_all();
    server
}
