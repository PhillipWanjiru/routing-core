//! voip-sip module — Phase 3 entrypoint.
//!
//! Runs two concurrent tasks on loopback:
//!   • UAS on 127.0.0.1:5060 — the server under test
//!   • UAC on 127.0.0.1:5080 — synthetic test client
//!
//! The UAC drives a complete INVITE → 100 → 180 → 200 → ACK → BYE → 200
//! exchange, then exits.  tcpdump captures everything on lo for pcap
//! verification.
//!
//! Usage:
//!   cargo run -p voip-sip
//!   (separate terminal) tcpdump -i lo -w phase3_call.pcap port 5060

pub mod sip;

use sip::{
    builder::{self, gen_branch, gen_call_id, gen_tag, RequestParts},
    parser::parse_message,
    uas::UasEngine,
};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

const UAS_ADDR: &str = "127.0.0.1:5060";
const UAC_ADDR: &str = "127.0.0.1:5080";
const UAS_URI:  &str = "sip:uas@127.0.0.1";
const UAC_URI:  &str = "sip:uac@127.0.0.1:5080";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    tracing::info!("voip-sip Phase 3 — signaling plane live test");
    tracing::info!("UAS: {UAS_ADDR}  UAC: {UAC_ADDR}");
    tracing::info!("Run:  tcpdump -i lo -w phase3_call.pcap 'port 5060 or port 5080'");
    tracing::info!("--------------------------------------------------------------");

    // Give any existing tcpdump process a moment to start capturing.
    sleep(Duration::from_millis(200)).await;

    let uas_engine = UasEngine::new(UAS_URI, "127.0.0.1");

    let uas_socket = UdpSocket::bind(UAS_ADDR).await.expect("bind UAS 5060");
    let uac_socket = UdpSocket::bind(UAC_ADDR).await.expect("bind UAC 5080");

    // Share the UAS socket between the receiver task and the response sender.
    let uas_socket = Arc::new(uas_socket);
    let uac_socket = Arc::new(uac_socket);

    let uas_socket_rx  = Arc::clone(&uas_socket);
    let uas_engine_ref = Arc::clone(&uas_engine);

    // ── UAS receive loop ──────────────────────────────────────────
    let uas_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let (n, peer) = uas_socket_rx.recv_from(&mut buf).await
                .expect("UAS recv_from");
            let raw = &buf[..n];

            tracing::debug!("UAS ← {} bytes from {peer}", n);

            let responses = uas_engine_ref.handle_datagram(raw);
            for resp in responses {
                // Small delay between provisional responses so each
                // appears as a distinct packet in the pcap — easier to
                // read than two packets with identical timestamps.
                sleep(Duration::from_millis(5)).await;
                uas_socket_rx.send_to(resp.as_bytes(), &peer).await
                    .expect("UAS send_to");
                tracing::debug!("UAS → {} bytes to {peer}", resp.len());
            }
        }
    });

    // ── UAC (synthetic test client) ───────────────────────────────
    // Runs the full INVITE/ACK/BYE cycle then signals completion.
    let uac_socket_ref = Arc::clone(&uac_socket);
    let uac_task: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        // Short delay to ensure UAS task is listening before we send.
        sleep(Duration::from_millis(50)).await;

        let call_id   = gen_call_id("127.0.0.1");
        let from_tag  = gen_tag();
        let via_branch_invite = gen_branch();

        let invite_parts = RequestParts {
            from_uri: UAC_URI,
            from_tag: &from_tag,
            to_uri:   UAS_URI,
            to_tag:   None,
            call_id:  &call_id,
            cseq:     1,
            local_contact: UAC_URI,
            via_branch: &via_branch_invite,
            via_host:   "127.0.0.1:5080",
        };

        // ─ Send INVITE ──────────────────────────────────────────
        let invite = builder::build_invite(&invite_parts, UAS_URI, 40000);
        uac_socket_ref.send_to(invite.as_bytes(), UAS_ADDR).await
            .expect("UAC send INVITE");
        tracing::info!("UAC → INVITE  (branch={})", &via_branch_invite[7..]);

        // ─ Receive responses until 200 ──────────────────────────
        let mut buf = vec![0u8; 8192];
        let mut to_tag_opt: Option<String> = None;
        let mut remote_contact = UAS_URI.to_string();

        loop {
            let (n, _peer) = uac_socket_ref.recv_from(&mut buf).await
                .expect("UAC recv_from");
            let raw = &buf[..n];

            let msg = match parse_message(raw) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("UAC: unparseable response: {e}");
                    continue;
                }
            };

            let code = match msg.status_code() {
                Some(c) => c,
                None    => { tracing::warn!("UAC: expected response, got request"); continue; }
            };

            // Extract To-tag from any response that carries one — the
            // first provisional with a tag is what creates the early dialog.
            if to_tag_opt.is_none() {
                if let Some(to) = msg.header("To") {
                    if let Some(tag) = to.split(';')
                        .find_map(|p| p.trim().strip_prefix("tag="))
                    {
                        to_tag_opt = Some(tag.to_owned());
                        tracing::info!("UAC ← {code} (To-tag={})", tag);
                    } else {
                        tracing::info!("UAC ← {code}");
                    }
                }
            } else {
                tracing::info!("UAC ← {code}");
            }

            if let Some(contact) = msg.header("Contact") {
                // Strip angle brackets for use as the request-URI in ACK/BYE.
                let c = contact.trim();
                let c = if let (Some(s), Some(e)) = (c.find('<'), c.find('>')) {
                    c[s+1..e].to_owned()
                } else { c.to_owned() };
                remote_contact = c;
            }

            if code >= 200 { break; }
        }

        let to_tag = to_tag_opt.unwrap_or_default();

        // ─ Send ACK for 200 ────────────────────────────────────
        // ACK for a 2xx is a new transaction (new branch), per RFC 3261
        // §17.1.1.3. We do not reuse via_branch_invite.
        let ack_branch = gen_branch();
        let ack_parts = RequestParts {
            from_uri: UAC_URI,
            from_tag: &from_tag,
            to_uri:   UAS_URI,
            to_tag:   Some(&to_tag),
            call_id:  &call_id,
            cseq:     1,              // Same CSeq number as INVITE per RFC 3261 §13.2.2.4
            local_contact: UAC_URI,
            via_branch: &ack_branch,
            via_host:   "127.0.0.1:5080",
        };
        let ack = builder::build_ack(&ack_parts, &remote_contact);
        uac_socket_ref.send_to(ack.as_bytes(), UAS_ADDR).await
            .expect("UAC send ACK");
        tracing::info!("UAC → ACK");

        // ─ Hold for 1 second to represent call duration ─────────
        tracing::info!("UAC   (call active — 1 second hold)");
        sleep(Duration::from_secs(1)).await;

        // ─ Send BYE ─────────────────────────────────────────────
        let bye_branch = gen_branch();
        let bye_parts = RequestParts {
            from_uri: UAC_URI,
            from_tag: &from_tag,
            to_uri:   UAS_URI,
            to_tag:   Some(&to_tag),
            call_id:  &call_id,
            cseq:     2,              // Incremented CSeq for in-dialog request
            local_contact: UAC_URI,
            via_branch: &bye_branch,
            via_host:   "127.0.0.1:5080",
        };
        let bye = builder::build_bye(&bye_parts, &remote_contact);
        uac_socket_ref.send_to(bye.as_bytes(), UAS_ADDR).await
            .expect("UAC send BYE");
        tracing::info!("UAC → BYE");

        // ─ Receive 200 OK for BYE ────────────────────────────────
        let (n, _peer) = uac_socket_ref.recv_from(&mut buf).await
            .expect("UAC recv_from BYE 200");
        let bye_resp = parse_message(&buf[..n]).ok();
        let bye_code = bye_resp.and_then(|m| m.status_code()).unwrap_or(0);
        tracing::info!("UAC ← {bye_code} (BYE response)");

        tracing::info!("--------------------------------------------------------------");
        tracing::info!("Phase 3 milestone: signaling exchange complete.");
        tracing::info!("Expected pcap sequence:");
        tracing::info!("  1. INVITE   (UAC → UAS)");
        tracing::info!("  2. 100 Trying  (UAS → UAC)");
        tracing::info!("  3. 180 Ringing (UAS → UAC)");
        tracing::info!("  4. 200 OK INVITE (UAS → UAC)");
        tracing::info!("  5. ACK      (UAC → UAS)");
        tracing::info!("  6. BYE      (UAC → UAS)");
        tracing::info!("  7. 200 OK BYE (UAS → UAC)");
        tracing::info!("Verify with: tshark -r phase3_call.pcap -Y sip -T fields -e sip.Status-Line -e sip.Request-Line");
    });

    // Wait for UAC to finish, then cancel the UAS loop.
    uac_task.await.expect("UAC task panicked");
    uas_task.abort();

    tracing::info!("voip-sip Phase 3: signaling milestone COMPLETE");
    std::process::exit(0);
}
