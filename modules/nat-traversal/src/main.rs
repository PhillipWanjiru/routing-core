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

pub mod ice;
pub mod stun;
pub mod turn;

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
    tracing::info!("STUN Binding milestone COMPLETE — starting TURN Allocate auth demo");
    tracing::info!("--------------------------------------------------------------");

    run_turn_auth_demo().await;

    tracing::info!("--------------------------------------------------------------");
    tracing::info!("nat-traversal Phase 4: STUN server + TURN auth milestones COMPLETE");
    std::process::exit(0);
}

/// Demonstrates the full TURN long-term credential challenge-response
/// cycle over real sockets:
///   1. Unauthenticated Allocate -> server responds 401 with REALM+NONCE
///   2. Client resends with correct credentials -> Success (placeholder)
///   3. A separate attempt with WRONG credentials -> rejected with a
///      fresh 401, not silently accepted
async fn run_turn_auth_demo() {
    use turn::{authenticate_request, build_authenticated_request, handle_allocate_datagram};
    use turn::{AuthResult, CredentialAttempt, CredentialStore};

    const TURN_SERVER_ADDR: &str = "127.0.0.1:3479";
    const TURN_CLIENT_ADDR: &str = "127.0.0.1:0";
    const REALM: &str = "routing-core.local";
    const USERNAME: &str = "alice";
    const CORRECT_PASSWORD: &str = "correcthorsebatterystaple";
    const WRONG_PASSWORD: &str = "definitely-not-the-password";

    let mut credentials = CredentialStore::new();
    credentials.add_user(USERNAME, CORRECT_PASSWORD);

    let mut allocations = turn::AllocationTable::new(turn::PortPool::default_range());

    let server_socket = UdpSocket::bind(TURN_SERVER_ADDR).await.expect("bind TURN server 3479");
    let client_socket  = UdpSocket::bind(TURN_CLIENT_ADDR).await.expect("bind TURN client ephemeral");

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = match server_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Some(resp) = handle_allocate_datagram(&buf[..n], peer, REALM, &credentials, &mut allocations, 3600) {
                let _ = server_socket.send_to(&resp, peer).await;
            }
        }
    });

    sleep(Duration::from_millis(50)).await;

    // ── Step 1: unauthenticated Allocate -> expect 401 with REALM+NONCE ──
    let txn_id_1 = gen_transaction_id();
    let bare_request = build_message(MessageClass::Request, Method::Allocate, &txn_id_1, &[]);
    client_socket.send_to(&bare_request, TURN_SERVER_ADDR).await.expect("send bare Allocate");
    tracing::info!("Client → Allocate (no credentials)");

    let mut buf = vec![0u8; 2048];
    let (n, _) = client_socket.recv_from(&mut buf).await.expect("recv 401 challenge");
    let challenge = parse_message(&buf[..n]).expect("401 response must parse");
    let challenge_attrs = decode_attributes(&challenge.attributes_raw, &challenge.transaction_id);

    let realm_from_server = challenge_attrs.iter().find_map(|a| match a {
        Attribute::Realm(r) => Some(r.clone()),
        _ => None,
    });
    let nonce_from_server = challenge_attrs.iter().find_map(|a| match a {
        Attribute::Nonce(n) => Some(n.clone()),
        _ => None,
    });
    let error_code = challenge_attrs.iter().find_map(|a| match a {
        Attribute::ErrorCode { code, .. } => Some(*code),
        _ => None,
    });

    tracing::info!(
        "Client ← class={:?} error_code={:?} realm={:?} nonce={:?}",
        challenge.class, error_code, realm_from_server, nonce_from_server
    );

    let step1_ok = challenge.class == MessageClass::ErrorResponse
        && error_code == Some(401)
        && realm_from_server.as_deref() == Some(REALM);

    if step1_ok {
        tracing::info!("Step 1 PASS — unauthenticated request correctly challenged with 401");
    } else {
        tracing::warn!("Step 1 FAIL — expected 401/REALM, got class={:?} code={:?}", challenge.class, error_code);
    }

    let (Some(realm), Some(nonce)) = (realm_from_server, nonce_from_server) else {
        tracing::warn!("Cannot continue demo without REALM+NONCE from server");
        server_task.abort();
        return;
    };

    // ── Step 2: resend with CORRECT credentials -> expect Success ──────
    let txn_id_2 = gen_transaction_id();
    let authed_request = build_authenticated_request(
        Method::Allocate, &txn_id_2, USERNAME, &realm, &nonce, CORRECT_PASSWORD,
    );
    client_socket.send_to(&authed_request, TURN_SERVER_ADDR).await.expect("send authenticated Allocate");
    tracing::info!("Client → Allocate (USERNAME={USERNAME}, correct password, MESSAGE-INTEGRITY attached)");

    let (n, _) = client_socket.recv_from(&mut buf).await.expect("recv auth response");
    let auth_response = parse_message(&buf[..n]).expect("auth response must parse");
    tracing::info!("Client ← class={:?} method={:?}", auth_response.class, auth_response.method);

    let auth_attrs = decode_attributes(&auth_response.attributes_raw, &auth_response.transaction_id);
    let relayed_addr = auth_attrs.iter().find_map(|a| match a {
        Attribute::XorRelayedAddress(addr) => Some(*addr),
        _ => None,
    });
    let granted_lifetime = auth_attrs.iter().find_map(|a| match a {
        Attribute::Lifetime(secs) => Some(*secs),
        _ => None,
    });

    if let (Some(addr), Some(lifetime)) = (relayed_addr, granted_lifetime) {
        tracing::info!("Client ← relay port allocated: {addr}, lifetime={lifetime}s");
    } else {
        tracing::warn!("Client ← Success Response missing XOR-RELAYED-ADDRESS or LIFETIME");
    }

    let step2_ok = auth_response.class == MessageClass::SuccessResponse
        && auth_response.method == Method::Allocate
        && auth_response.transaction_id == txn_id_2
        && relayed_addr.is_some()
        && granted_lifetime.is_some();

    if step2_ok {
        tracing::info!(
            "Step 2 PASS — correct credentials authenticated, real relay port {} granted for {}s",
            relayed_addr.unwrap(), granted_lifetime.unwrap()
        );
    } else {
        tracing::warn!("Step 2 FAIL — expected SuccessResponse/Allocate with a real relay allocation, got {:?}/{:?}", auth_response.class, auth_response.method);
    }

    // ── Step 3: resend with WRONG credentials -> expect a fresh 401, not success ──
    let txn_id_3 = gen_transaction_id();
    let wrong_request = build_authenticated_request(
        Method::Allocate, &txn_id_3, USERNAME, &realm, &nonce, WRONG_PASSWORD,
    );
    client_socket.send_to(&wrong_request, TURN_SERVER_ADDR).await.expect("send wrong-credential Allocate");
    tracing::info!("Client → Allocate (USERNAME={USERNAME}, WRONG password)");

    let (n, _) = client_socket.recv_from(&mut buf).await.expect("recv rejection response");
    let reject_response = parse_message(&buf[..n]).expect("rejection response must parse");
    let reject_attrs = decode_attributes(&reject_response.attributes_raw, &reject_response.transaction_id);
    let reject_code = reject_attrs.iter().find_map(|a| match a {
        Attribute::ErrorCode { code, .. } => Some(*code),
        _ => None,
    });

    tracing::info!("Client ← class={:?} error_code={:?}", reject_response.class, reject_code);

    let step3_ok = reject_response.class == MessageClass::ErrorResponse && reject_code == Some(401);

    if step3_ok {
        tracing::info!("Step 3 PASS — wrong credentials correctly rejected (not silently accepted)");
    } else {
        tracing::warn!("Step 3 FAIL — wrong credentials were NOT rejected as expected");
    }

    server_task.abort();

    // ── Also verify authenticate_request directly, independent of the
    // socket round trip, using the same locally-known-good message —
    // belt-and-suspenders check that the gate itself (not just the
    // demo's happy path) behaves correctly. ──
    let mut store2 = CredentialStore::new();
    store2.add_user(USERNAME, CORRECT_PASSWORD);
    let direct_check = authenticate_request(
        &CredentialAttempt {
            username: Some(USERNAME),
            realm: Some(&realm),
            nonce: Some(&nonce),
            mi_value_offset: find_mi_offset_for_demo(&authed_request),
        },
        &authed_request,
        &realm,
        &store2,
        3600,
    );
    let direct_ok = matches!(direct_check, AuthResult::Authenticated { .. });

    tracing::info!(
        "--------------------------------------------------------------"
    );
    if step1_ok && step2_ok && step3_ok && direct_ok {
        tracing::info!("TURN AUTH DEMO RESULT: PASS — full challenge-response cycle verified over real sockets");
    } else {
        tracing::warn!(
            "TURN AUTH DEMO RESULT: FAIL — step1={step1_ok} step2={step2_ok} step3={step3_ok} direct={direct_ok}"
        );
    }
}

/// Small helper for the demo's belt-and-suspenders direct check: scans a
/// message this same process just built for the MESSAGE-INTEGRITY
/// attribute's value offset, mirroring what a real server would do by
/// scanning received bytes. Not part of the public API — this is demo
/// plumbing, not production logic (the real version lives in
/// `turn::server::find_message_integrity_value_offset`, private to that
/// module).
fn find_mi_offset_for_demo(message: &[u8]) -> Option<usize> {
    const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
    let attrs_start = 20; // stun::parser::HEADER_LEN
    let mut offset = attrs_start;
    while offset + 4 <= message.len() {
        let attr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attr_len  = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
        let value_start = offset + 4;
        if attr_type == ATTR_MESSAGE_INTEGRITY {
            return Some(value_start);
        }
        if value_start + attr_len > message.len() { break; }
        let padded_len = (attr_len + 3) & !3;
        offset = value_start + padded_len;
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}
