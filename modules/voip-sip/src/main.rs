//! voip-sip module — Phase 3 milestone: live UDP signaling.
//!
//! Binds a SIP UDP socket, dispatches inbound datagrams through the UAS
//! engine (parser → transaction FSM → dialog → builder), and sends
//! responses back. No RTP yet — that is the next Phase 3 step once this
//! signaling exchange is verified in a pcap.

pub mod sip;

use sip::uas::UasEngine;
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let local_addr = "127.0.0.1:5060";
    let local_uri  = format!("sip:uas@{}", local_addr);
    let local_host = "127.0.0.1:5060";

    let socket = UdpSocket::bind(local_addr)
        .expect("cannot bind SIP socket on 127.0.0.1:5060");
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();

    tracing::info!(addr = local_addr, "SIP/UDP listening");

    let engine = UasEngine::new(local_uri, local_host);
    let mut buf = [0u8; 65535];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                tracing::info!(bytes = len, from = %peer, "← received datagram");
                let data = &buf[..len];
                let responses = engine.handle_datagram(data);
                for resp in responses {
                    tracing::info!(bytes = resp.len(), to = %peer, "→ sending response");
                    if let Err(e) = socket.send_to(resp.as_bytes(), peer) {
                        tracing::warn!("send error: {e}");
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                tracing::info!("read timeout — no traffic for 30s, exiting");
                break;
            }
            Err(e) => {
                tracing::error!("recv error: {e}");
                break;
            }
        }
    }

    tracing::info!(
        active = engine.active_call_count(),
        "UAS engine shut down"
    );
}
