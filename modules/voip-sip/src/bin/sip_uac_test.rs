//! UAC (User Agent Client) test driver — Phase 3 signaling milestone.
//!
//! Drives the full RFC 3261 §17 exchange against the live UAS:
//!
//!   UAC                              UAS
//!    │──────── INVITE ───────────────►│
//!    │◄──────── 100 Trying ───────────│
//!    │◄──────── 180 Ringing ──────────│
//!    │◄──────── 200 OK ───────────────│
//!    │──────── ACK ──────────────────►│
//!    │         (5-second call hold)
//!    │──────── BYE ──────────────────►│
//!    │◄──────── 200 OK ───────────────│
//!
//! Verifies the exact response sequence, prints every message, and exits
//! 0 on success or 1 on failure. Run alongside a tcpdump capture to produce
//! the Phase 3 pcap artifact.

use voip_sip::sip::{
    builder::{gen_branch, gen_call_id, gen_tag, RequestParts},
    builder::{build_ack, build_bye, build_invite},
    parser::parse_message,
};
use std::{
    net::UdpSocket,
    time::Duration,
};

const UAS_ADDR: &str = "127.0.0.1:5060";
const UAC_ADDR: &str = "127.0.0.1:5070";
const LOCAL_URI:   &str = "sip:uac@127.0.0.1:5070";
const REMOTE_URI:  &str = "sip:uas@127.0.0.1:5060";
const LOCAL_HOST:  &str = "127.0.0.1:5070";
const LOCAL_RTP_PORT: u16 = 40000;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let socket = UdpSocket::bind(UAC_ADDR).expect("cannot bind UAC socket");
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let call_id    = gen_call_id("127.0.0.1");
    let from_tag   = gen_tag();
    let invite_branch = gen_branch();

    // ─── INVITE ─────────────────────────────────────────────────
    let invite_parts = RequestParts {
        from_uri:      LOCAL_URI,
        from_tag:      &from_tag,
        to_uri:        REMOTE_URI,
        to_tag:        None,
        call_id:       &call_id,
        cseq:          1,
        local_contact: LOCAL_URI,
        via_branch:    &invite_branch,
        via_host:      LOCAL_HOST,
    };

    let invite_msg = build_invite(&invite_parts, REMOTE_URI, LOCAL_RTP_PORT);
    println!("\n── INVITE ──────────────────────────────────────\n{invite_msg}");
    socket.send_to(invite_msg.as_bytes(), UAS_ADDR).unwrap();

    // ─── Receive 100 Trying ─────────────────────────────────────
    let mut to_tag = String::new();
    let mut uas_contact = REMOTE_URI.to_string();
    let mut buf = [0u8; 65535];

    let mut received_100 = false;
    let mut received_180 = false;
    let mut received_200 = false;

    for _ in 0..10 {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let raw = &buf[..len];
                let msg = parse_message(raw).expect("UAS sent malformed message");
                let code = msg.status_code().expect("expected response, got request");
                println!("\n── {code} ───────────────────────────────────────\n{}",
                    std::str::from_utf8(raw).unwrap_or("(binary)"));

                // Extract To-tag from first tagged response (180 or 200).
                if code >= 180 && to_tag.is_empty() {
                    if let Some(to_hdr) = msg.header("To") {
                        to_tag = to_hdr
                            .split(';')
                            .find_map(|p| p.trim().strip_prefix("tag="))
                            .unwrap_or("")
                            .to_owned();
                    }
                }

                // Extract UAS Contact for request-URI of subsequent requests.
                if code == 200 {
                    if let Some(contact) = msg.header("Contact") {
                        let c = contact.trim();
                        uas_contact = if let (Some(s), Some(e)) = (c.find('<'), c.find('>')) {
                            c[s+1..e].to_owned()
                        } else {
                            c.to_owned()
                        };
                    }
                }

                match code {
                    100 => received_100 = true,
                    180 => received_180 = true,
                    200 => { received_200 = true; break; }
                    _   => {}
                }
            }
            Err(e) => { eprintln!("recv error: {e}"); std::process::exit(1); }
        }
    }

    assert!(received_100, "did not receive 100 Trying");
    assert!(received_180, "did not receive 180 Ringing");
    assert!(received_200, "did not receive 200 OK for INVITE");
    assert!(!to_tag.is_empty(), "200 OK missing To-tag — dialog not established");

    // ─── ACK ────────────────────────────────────────────────────
    // ACK for a 2xx INVITE is a new transaction (RFC 3261 §17.1.1.3):
    // fresh branch, same CSeq number as the INVITE.
    let ack_branch = gen_branch();
    let ack_parts = RequestParts {
        from_uri:      LOCAL_URI,
        from_tag:      &from_tag,
        to_uri:        REMOTE_URI,
        to_tag:        Some(&to_tag),
        call_id:       &call_id,
        cseq:          1,           // Same CSeq number as INVITE
        local_contact: LOCAL_URI,
        via_branch:    &ack_branch,
        via_host:      LOCAL_HOST,
    };
    let ack_msg = build_ack(&ack_parts, &uas_contact);
    println!("\n── ACK ─────────────────────────────────────────\n{ack_msg}");
    socket.send_to(ack_msg.as_bytes(), UAS_ADDR).unwrap();

    // Simulate a 3-second call.
    println!("\n── [call active for 3 seconds] ─────────────────");
    std::thread::sleep(Duration::from_secs(3));

    // ─── BYE ────────────────────────────────────────────────────
    // BYE is a new, independent transaction: fresh branch, incremented CSeq.
    let bye_branch = gen_branch();
    let bye_parts = RequestParts {
        from_uri:      LOCAL_URI,
        from_tag:      &from_tag,
        to_uri:        REMOTE_URI,
        to_tag:        Some(&to_tag),
        call_id:       &call_id,
        cseq:          2,           // Incremented from INVITE's CSeq=1
        local_contact: LOCAL_URI,
        via_branch:    &bye_branch,
        via_host:      LOCAL_HOST,
    };
    let bye_msg = build_bye(&bye_parts, &uas_contact);
    println!("\n── BYE ─────────────────────────────────────────\n{bye_msg}");
    socket.send_to(bye_msg.as_bytes(), UAS_ADDR).unwrap();

    // ─── Receive 200 OK for BYE ─────────────────────────────────
    let mut received_bye_200 = false;
    for _ in 0..5 {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let raw = &buf[..len];
                let msg = parse_message(raw).expect("malformed BYE response");
                let code = msg.status_code().expect("expected response");
                println!("\n── {code} (BYE response) ────────────────────────\n{}",
                    std::str::from_utf8(raw).unwrap_or("(binary)"));
                if code == 200 { received_bye_200 = true; break; }
            }
            Err(e) => { eprintln!("recv error: {e}"); std::process::exit(1); }
        }
    }

    assert!(received_bye_200, "did not receive 200 OK for BYE");

    println!("\n════════════════════════════════════════════════");
    println!("  RFC 3261 §17 exchange: COMPLETE");
    println!("  100 Trying  : ✓");
    println!("  180 Ringing : ✓");
    println!("  200 OK      : ✓ (dialog established, to_tag = {to_tag})");
    println!("  ACK         : ✓ (sent)");
    println!("  BYE         : ✓ (sent)");
    println!("  200 OK (BYE): ✓");
    println!("════════════════════════════════════════════════\n");
}
