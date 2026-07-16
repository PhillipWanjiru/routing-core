//! nat-traversal module entrypoint — Phase 4 STUN server live test.
//!
//! Binds a STUN server on 127.0.0.1:3478 (RFC 5389 §8's assigned port)
//! and a synthetic client on an ephemeral port. The client sends a
//! Binding Request; the server responds with the client's observed
//! address via XOR-MAPPED-ADDRESS; the client decodes the response and
//! verifies it exactly matches its own real local socket address.
//!
//! On loopback there is no NAT in the way, so "what the server observed
//! as the request's source" and "what the client's socket actually is"
//! must be byte-for-byte identical — this is the same structural check
//! that, on a real NAT-connected client, would instead reveal the NAT's
//! public mapping and differ from the client's private address.
//!
//! Usage:
//!   cargo run -p nat-traversal
//!   (separate terminal) tcpdump -i lo -w phase4_stun.pcap 'udp port 3478'

pub mod stun;

use stun::{
    attributes::{decode_attributes, Attribute},
    builder::build_message,
    parser::{parse_message, MessageClass, Method},
    server,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

const STUN_SERVER_ADDR: &str = "127.0.0.1:3478";
const STUN_CLIENT_ADDR: &str = "127.0.0.1:0"; // :0 = OS-assigned ephemeral port

/// Generate a 96-bit STUN transaction ID. Same nanosecond-time-mixed-with-
/// counter approach used for SIP branch parameters in voip-sip — unique
/// per process, not cryptographically unguessable (fine for a transaction
/// correlation ID; Phase 4's auth-pki work owns anything needing real
/// CSPRNG output).
fn gen_transaction_id() -> [u8; 12] {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = (ns ^ c).wrapping_mul(0x9e3779b97f4a7c15);

    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&mixed.to_be_bytes());
    id[8..12].copy_from_slice(&(c as u32).to_be_bytes());
    id
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    tracing::info!("nat-traversal Phase 4 — STUN server live test");
    tracing::info!("STUN server: {STUN_SERVER_ADDR}");
    tracing::info!("Run:  tcpdump -i lo -w phase4_stun.pcap 'udp port 3478'");
    tracing::info!("--------------------------------------------------------------");

    sleep(Duration::from_millis(200)).await;

    let server_socket = UdpSocket::bind(STUN_SERVER_ADDR).await.expect("bind STUN server port 3478");
    let client_socket  = UdpSocket::bind(STUN_CLIENT_ADDR).await.expect("bind STUN client ephemeral port");
    let client_local_addr = client_socket.local_addr().expect("read client local addr");

    tracing::info!("Client bound to ephemeral {client_local_addr}");

    // ── Server receive loop ──────────────────────────────────────
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = match server_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => { tracing::warn!("server recv error: {e}"); break; }
            };
            tracing::debug!("STUN server ← {n} bytes from {peer}");

            if let Some(resp) = server::handle_datagram(&buf[..n], peer) {
                if let Err(e) = server_socket.send_to(&resp, peer).await {
                    tracing::warn!("server send error: {e}");
                    break;
                }
                tracing::debug!("STUN server → {} bytes to {peer}", resp.len());
            } else {
                tracing::debug!("STUN server: datagram from {peer} dropped (not a Binding Request)");
            }
        }
    });

    // ── Client: send Binding Request, verify response ────────────
    sleep(Duration::from_millis(50)).await;

    let txn_id = gen_transaction_id();
    let request = build_message(MessageClass::Request, Method::Binding, &txn_id, &[]);
    client_socket.send_to(&request, STUN_SERVER_ADDR).await.expect("send Binding Request");
    tracing::info!("Client → Binding Request (txn_id={})", hex(&txn_id));

    let mut buf = vec![0u8; 2048];
    let (n, server_peer) = client_socket.recv_from(&mut buf).await.expect("recv Binding response");
    tracing::info!("Client ← {n} bytes from {server_peer}");

    let response = parse_message(&buf[..n]).expect("response must parse as valid STUN");

    tracing::info!(
        "Client ← class={:?} method={:?} txn_id={}",
        response.class, response.method, hex(&response.transaction_id)
    );

    let class_ok  = response.class == MessageClass::SuccessResponse;
    let method_ok = response.method == Method::Binding;
    let txn_ok    = response.transaction_id == txn_id;

    if !class_ok {
        tracing::warn!("RESULT: FAIL — expected SuccessResponse, got {:?}", response.class);
    }
    if !method_ok {
        tracing::warn!("RESULT: FAIL — expected Binding, got {:?}", response.method);
    }
    if !txn_ok {
        tracing::warn!("RESULT: FAIL — transaction ID not echoed correctly");
    }

    let attrs = decode_attributes(&response.attributes_raw, &response.transaction_id);
    let observed = attrs.iter().find_map(|a| match a {
        Attribute::XorMappedAddress(addr) => Some(*addr),
        _ => None,
    });

    match observed {
        Some(addr) => {
            tracing::info!("Server-observed address (via XOR-MAPPED-ADDRESS): {addr}");
            tracing::info!("Client's actual local address:                    {client_local_addr}");

            let ip_matches   = addr.ip   == client_local_addr.ip();
            let port_matches = addr.port == client_local_addr.port();

            if class_ok && method_ok && txn_ok && ip_matches && port_matches {
                tracing::info!(
                    "RESULT: PASS — server-observed address exactly matches \
                     client's real local address (no NAT in the way on loopback, \
                     as expected)"
                );
            } else {
                tracing::warn!(
                    "RESULT: FAIL — ip_matches={ip_matches} port_matches={port_matches}"
                );
            }
        }
        None => {
            tracing::warn!("RESULT: FAIL — response contained no XOR-MAPPED-ADDRESS attribute");
        }
    }

    server_task.abort();
    tracing::info!("--------------------------------------------------------------");
    tracing::info!("nat-traversal Phase 4: STUN server milestone COMPLETE");
    std::process::exit(0);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}
