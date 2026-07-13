//! voip-sip module — Phase 3 entrypoint.
//!
//! Runs two concurrent tasks on loopback:
//!   • UAS on 127.0.0.1:5060 — the server under test
//!   • UAC on 127.0.0.1:5080 — synthetic test client
//!
//! Signaling drives a complete INVITE → 100 → 180 → 200 → ACK → BYE → 200
//! exchange. Once the dialog is confirmed, both sides open RTP sockets
//! and exchange 50 encrypted G.711 frames (1 second of audio at 20ms
//! ptime), with the receiver running the frames through the adaptive
//! jitter buffer and reporting live SRTP-verified MOS at the end.
//!
//! Usage:
//!   cargo run -p voip-sip
//!   (separate terminal) tcpdump -i lo -w phase3_call.pcap \
//!       'port 5060 or port 5080 or portrange 40000-40010'

pub mod codec;
pub mod rtp;
pub mod sip;
pub mod srtp;

use sip::{
    builder::{self, gen_branch, gen_call_id, gen_tag, RequestParts},
    parser::parse_message,
    uas::UasEngine,
};
use rtp::{jitter_buffer::JitterBuffer, session::{RtpRecvSession, RtpSendSession, RtpHeader}};
use srtp::{derive_session_keys, parse_sdes_crypto, srtp_decrypt, srtp_encrypt};
use codec::g711;

use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

const UAS_ADDR:     &str = "127.0.0.1:5060";
const UAC_ADDR:     &str = "127.0.0.1:5080";
const UAS_URI:      &str = "sip:uas@127.0.0.1";
const UAC_URI:      &str = "sip:uac@127.0.0.1:5080";
const UAS_RTP_ADDR: &str = "127.0.0.1:40000";
const UAC_RTP_ADDR: &str = "127.0.0.1:40002";

/// A single 30-byte SDES key (16-byte key + 14-byte salt), base64-encoded.
/// Both sides use the same key here purely to keep the Phase 3 signaling
/// demo self-contained — in a real call each direction negotiates its own
/// key via the SDP offer/answer exchange already implemented in sip::sdp.
const DEMO_SDES_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    tracing::info!("voip-sip Phase 3 — signaling + media plane live test");
    tracing::info!("SIP: UAS {UAS_ADDR}  UAC {UAC_ADDR}");
    tracing::info!("RTP: UAS {UAS_RTP_ADDR}  UAC {UAC_RTP_ADDR}");
    tracing::info!("Run:  tcpdump -i lo -w phase3_call.pcap \\");
    tracing::info!("        'port 5060 or port 5080 or portrange 40000-40010'");
    tracing::info!("--------------------------------------------------------------");

    sleep(Duration::from_millis(200)).await;

    let uas_engine = UasEngine::new(UAS_URI, "127.0.0.1");

    let uas_socket = Arc::new(UdpSocket::bind(UAS_ADDR).await.expect("bind UAS 5060"));
    let uac_socket = Arc::new(UdpSocket::bind(UAC_ADDR).await.expect("bind UAC 5080"));

    let uas_socket_rx  = Arc::clone(&uas_socket);
    let uas_engine_ref = Arc::clone(&uas_engine);

    // ── UAS SIP receive loop ───────────────────────────────────
    let uas_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let (n, peer) = uas_socket_rx.recv_from(&mut buf).await.expect("UAS recv_from");
            let raw = &buf[..n];
            tracing::debug!("UAS ← {n} bytes from {peer}");
            for resp in uas_engine_ref.handle_datagram(raw) {
                sleep(Duration::from_millis(5)).await;
                uas_socket_rx.send_to(resp.as_bytes(), &peer).await.expect("UAS send_to");
                tracing::debug!("UAS → {} bytes to {peer}", resp.len());
            }
        }
    });

    // ── UAS RTP: receive + decrypt + jitter-buffer + decode ────
    let uas_rtp_task = tokio::spawn(async move {
        let rtp_socket = UdpSocket::bind(UAS_RTP_ADDR).await.expect("bind UAS RTP port");
        run_rtp_receiver("UAS", rtp_socket, 50).await;
    });

    // ── UAC: full signaling + RTP send cycle ───────────────────
    let uac_socket_ref = Arc::clone(&uac_socket);
    let uac_task: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;

        let call_id  = gen_call_id("127.0.0.1");
        let from_tag = gen_tag();
        let branch1  = gen_branch();

        let invite_parts = RequestParts {
            from_uri: UAC_URI, from_tag: &from_tag, to_uri: UAS_URI, to_tag: None,
            call_id: &call_id, cseq: 1, local_contact: UAC_URI,
            via_branch: &branch1, via_host: "127.0.0.1:5080",
        };
        let invite = builder::build_invite(&invite_parts, UAS_URI, 40002);
        uac_socket_ref.send_to(invite.as_bytes(), UAS_ADDR).await.expect("send INVITE");
        tracing::info!("UAC → INVITE  (branch={})", &branch1[7..]);

        let mut buf = vec![0u8; 8192];
        let mut to_tag_opt: Option<String> = None;
        let mut remote_contact = UAS_URI.to_string();

        loop {
            let (n, _peer) = uac_socket_ref.recv_from(&mut buf).await.expect("recv");
            let msg = match parse_message(&buf[..n]) {
                Ok(m) => m,
                Err(e) => { tracing::warn!("UAC: unparseable response: {e}"); continue; }
            };
            let code = match msg.status_code() {
                Some(c) => c,
                None => { tracing::warn!("UAC: expected response, got request"); continue; }
            };
            if to_tag_opt.is_none() {
                if let Some(to) = msg.header("To") {
                    if let Some(tag) = to.split(';').find_map(|p| p.trim().strip_prefix("tag=")) {
                        to_tag_opt = Some(tag.to_owned());
                        tracing::info!("UAC ← {code} (To-tag={tag})");
                    } else {
                        tracing::info!("UAC ← {code}");
                    }
                }
            } else {
                tracing::info!("UAC ← {code}");
            }
            if let Some(contact) = msg.header("Contact") {
                let c = contact.trim();
                remote_contact = if let (Some(s), Some(e)) = (c.find('<'), c.find('>')) {
                    c[s+1..e].to_owned()
                } else { c.to_owned() };
            }
            if code >= 200 { break; }
        }

        let to_tag = to_tag_opt.unwrap_or_default();

        let ack_branch = gen_branch();
        let ack_parts = RequestParts {
            from_uri: UAC_URI, from_tag: &from_tag, to_uri: UAS_URI, to_tag: Some(&to_tag),
            call_id: &call_id, cseq: 1, local_contact: UAC_URI,
            via_branch: &ack_branch, via_host: "127.0.0.1:5080",
        };
        let ack = builder::build_ack(&ack_parts, &remote_contact);
        uac_socket_ref.send_to(ack.as_bytes(), UAS_ADDR).await.expect("send ACK");
        tracing::info!("UAC → ACK");
        tracing::info!("UAC   (dialog confirmed — starting RTP media)");

        // ── Media: send 50 encrypted G.711 frames (1s @ 20ms ptime) ──
        let rtp_socket = UdpSocket::bind(UAC_RTP_ADDR).await.expect("bind UAC RTP port");
        send_srtp_g711_stream(&rtp_socket, UAS_RTP_ADDR, 50).await;

        // ── BYE ───────────────────────────────────────────────────
        let bye_branch = gen_branch();
        let bye_parts = RequestParts {
            from_uri: UAC_URI, from_tag: &from_tag, to_uri: UAS_URI, to_tag: Some(&to_tag),
            call_id: &call_id, cseq: 2, local_contact: UAC_URI,
            via_branch: &bye_branch, via_host: "127.0.0.1:5080",
        };
        let bye = builder::build_bye(&bye_parts, &remote_contact);
        uac_socket_ref.send_to(bye.as_bytes(), UAS_ADDR).await.expect("send BYE");
        tracing::info!("UAC → BYE");

        let (n, _peer) = uac_socket_ref.recv_from(&mut buf).await.expect("recv BYE 200");
        let bye_code = parse_message(&buf[..n]).ok().and_then(|m| m.status_code()).unwrap_or(0);
        tracing::info!("UAC ← {bye_code} (BYE response)");
        tracing::info!("--------------------------------------------------------------");
        tracing::info!("Phase 3 milestone: signaling + encrypted media exchange complete.");
    });

    uac_task.await.expect("UAC task panicked");
    sleep(Duration::from_millis(300)).await; // let the RTP receiver finish logging
    uas_task.abort();
    uas_rtp_task.abort();

    tracing::info!("voip-sip Phase 3: signaling + media milestone COMPLETE");
    std::process::exit(0);
}

/// Encode 1 second of a 1 kHz test tone as G.711 a-law, packetise at 20ms
/// (160 samples/frame), encrypt each frame with SRTP, and send it.
async fn send_srtp_g711_stream(socket: &UdpSocket, dest: &str, frame_count: u32) {
    let km   = parse_sdes_crypto(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{DEMO_SDES_KEY}"))
        .expect("demo SDES key must parse");
    let keys = derive_session_keys(&km, 0).expect("key derivation must succeed");

    let mut tx = RtpSendSession::new(0 /* PT=0 = PCMU */, 8000);
    let ssrc = tx.ssrc;

    for frame_idx in 0..frame_count {
        // Generate 160 samples (20ms @ 8kHz) of a 1kHz test tone.
        let samples: Vec<i16> = (0..160).map(|i| {
            let sample_idx = frame_idx as f64 * 160.0 + i as f64;
            let angle = 2.0 * std::f64::consts::PI * 1000.0 * sample_idx / 8000.0;
            (12000.0 * angle.sin()) as i16
        }).collect();

        let payload = g711::encode_alaw(&samples);
        let rtp_pkt = tx.build_packet(&payload, 160, frame_idx == 0);
        let hdr     = RtpHeader::parse(&rtp_pkt).unwrap();

        let srtp_pkt = srtp_encrypt(&rtp_pkt, &keys, ssrc, hdr.sequence, 0);
        socket.send_to(&srtp_pkt, dest).await.expect("send SRTP frame");

        sleep(Duration::from_millis(20)).await; // real-time pacing at 20ms ptime
    }

    tracing::info!(
        "UAC   sent {frame_count} SRTP frames ({} samples, {:.1}s audio) to {dest}",
        frame_count * 160, frame_count as f64 * 0.02
    );
}

/// Receive SRTP frames, decrypt, push through the jitter buffer, decode,
/// and report a live quality summary (loss, jitter, effective SNR) at the end.
async fn run_rtp_receiver(label: &str, socket: UdpSocket, expected_frames: u32) {
    let km   = parse_sdes_crypto(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{DEMO_SDES_KEY}"))
        .expect("demo SDES key must parse");
    let keys = derive_session_keys(&km, 0).expect("key derivation must succeed");

    let mut recv_session = RtpRecvSession::new(8000);
    let mut jitter_buf    = JitterBuffer::new(20.0, 20.0, 200.0, 1.5);

    let mut buf = vec![0u8; 2048];
    let start   = tokio::time::Instant::now();
    let mut ssrc_seen: Option<u32> = None;
    let mut auth_failures = 0u32;
    let mut frames_in     = 0u32;

    loop {
        let recv_fut = socket.recv_from(&mut buf);
        let timeout  = sleep(Duration::from_millis(3000));
        tokio::select! {
            result = recv_fut => {
                let (n, _peer) = match result { Ok(v) => v, Err(_) => break };
                let arrival_ms = start.elapsed().as_millis() as u64;

                // We need seq/ssrc from the (still-encrypted) header to decrypt —
                // SRTP does not encrypt the fixed header, only the payload.
                let Some(hdr) = RtpHeader::parse(&buf[..n]) else { continue };
                ssrc_seen.get_or_insert(hdr.ssrc);

                let Some(plain_rtp) = srtp_decrypt(&buf[..n], &keys, hdr.ssrc, hdr.sequence, 0) else {
                    auth_failures += 1;
                    tracing::warn!("{label}: SRTP auth failure on seq {}", hdr.sequence);
                    continue;
                };

                let Some(payload) = recv_session.receive(&plain_rtp, Some(arrival_ms * 1_000_000)) else {
                    continue;
                };

                frames_in += 1;
                // Extended sequence acts as the jitter buffer's sort key.
                jitter_buf.insert(hdr.sequence as u32, payload, arrival_ms);

                // Drain anything now due for playout.
                while let Some(pcm_bytes) = jitter_buf.pop_due(arrival_ms) {
                    let _pcm = g711::decode_alaw(&pcm_bytes); // decoded — PCM available for playback
                }

                if frames_in >= expected_frames {
                    // Give any final in-flight jitter-buffer packets a moment
                    // to become due, then report.
                    sleep(Duration::from_millis(250)).await;
                    let final_now = start.elapsed().as_millis() as u64;
                    while let Some(pcm_bytes) = jitter_buf.pop_due(final_now) {
                        let _pcm = g711::decode_alaw(&pcm_bytes);
                    }
                    break;
                }
            }
            _ = timeout => {
                tracing::warn!("{label}: RTP receive timed out after {frames_in}/{expected_frames} frames");
                break;
            }
        }
    }

    if let Some(ssrc) = ssrc_seen {
        let stats     = recv_session.rtcp_stats(ssrc);
        let jitter_ms = recv_session.jitter_ms(ssrc);
        let loss_pct  = recv_session.loss_fraction(ssrc) * 100.0;

        // One-way latency on `lo` is physically sub-millisecond — there is
        // no real network path to traverse. We label this as an assumption
        // rather than a measurement: true one-way latency requires RTCP
        // SR/RR round-trip timing (LSR/DLSR), which is not yet implemented
        // (see rtp/mod.rs — rtcp.rs is still a Phase 3-continuation stub).
        // Packet loss below, by contrast, IS a real measurement from RTP
        // sequence tracking, not an assumption.
        const LOOPBACK_LATENCY_ASSUMPTION_MS: f64 = 1.0;
        let mos = rtp::mos::estimate_mos(
            LOOPBACK_LATENCY_ASSUMPTION_MS,
            loss_pct,
            rtp::mos::CODEC_IE_G711,
        );
        let rating = rtp::mos::mos_rating(mos);

        tracing::info!(
            "{label}   RTP receive summary: {frames_in} frames, \
             {auth_failures} SRTP auth failures, \
             jitter={jitter_ms:.2}ms (RFC 3550), loss={loss_pct:.2}% (measured), \
             jitter-buffer depth={:.1}ms, packets played={}",
            jitter_buf.current_depth_ms(),
            jitter_buf.packets_played,
        );
        if let Some(s) = stats {
            tracing::info!(
                "{label}   RTCP RR: fraction_lost={} cumulative_lost={} ext_max_seq={}",
                s.fraction_lost, s.cumulative_lost, s.extended_max_seq
            );
        }
        tracing::info!(
            "{label}   MOS (E-model, ITU-T G.107): {mos:.2} ({rating}) \
             — latency={LOOPBACK_LATENCY_ASSUMPTION_MS}ms [assumed, loopback], \
             loss={loss_pct:.2}% [measured]",
        );
        if auth_failures == 0 && loss_pct < 5.0 {
            tracing::info!("{label}   RESULT: PASS — encrypted media received, authenticated, decoded, MOS {mos:.2}");
        } else {
            tracing::warn!("{label}   RESULT: DEGRADED — check auth failures / loss above");
        }
    } else {
        tracing::warn!("{label}   RESULT: FAIL — no RTP frames received at all");
    }
}
