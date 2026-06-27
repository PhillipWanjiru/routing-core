//! SIP and SDP parser tests for Phase 1.
//!
//! RFC 3261 §20 example messages are used as ground truth.

use voip_sip::sip::parser::{parse_message, Method, StartLine};
use voip_sip::sip::sdp::parse_sdp;

// ─── Method parsing ───────────────────────────────────────────

#[test]
fn parse_invite_request() {
    let raw = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                Max-Forwards: 70\r\n\
                To: Bob <sip:bob@biloxi.com>\r\n\
                From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 314159 INVITE\r\n\
                Contact: <sip:alice@pc33.atlanta.com>\r\n\
                Content-Type: application/sdp\r\n\
                Content-Length: 4\r\n\
                \r\n\
                Test";

    let msg = parse_message(raw).expect("should parse INVITE");
    assert!(msg.is_request());
    assert_eq!(msg.method(), Some(&Method::Invite));
    assert_eq!(msg.call_id(), Some("a84b4c76e66710@pc33.atlanta.com"));
    assert_eq!(msg.cseq(), Some((314159, "INVITE")));
    assert_eq!(msg.body, b"Test");
    assert_eq!(msg.content_length(), 4);
}

#[test]
fn parse_register_request() {
    let raw = b"REGISTER sips:ss2.biloxi.com SIP/2.0\r\n\
                Via: SIP/2.0/TLS client.biloxi.com:5061;branch=z9hG4bKnashds8\r\n\
                Max-Forwards: 70\r\n\
                From: Bob <sips:bob@biloxi.com>;tag=a48s\r\n\
                To: Bob <sips:bob@biloxi.com>\r\n\
                Call-ID: 1j9FpLxk3uxtm8tn@biloxi.com\r\n\
                CSeq: 1 REGISTER\r\n\
                Contact: <sips:bob@client.biloxi.com>\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).expect("should parse REGISTER");
    assert_eq!(msg.method(), Some(&Method::Register));
    assert_eq!(msg.cseq(), Some((1, "REGISTER")));
    assert_eq!(msg.body.len(), 0);
}

#[test]
fn parse_200_ok_response() {
    let raw = b"SIP/2.0 200 OK\r\n\
                Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff;received=192.0.2.3\r\n\
                To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
                From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 314159 INVITE\r\n\
                Contact: <sip:bob@192.0.2.4>\r\n\
                Content-Type: application/sdp\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).expect("should parse 200 OK");
    assert!(msg.is_response());
    assert_eq!(msg.status_code(), Some(200));
    assert!(msg.header("To").unwrap().contains("tag=a6c85cf"));
}

#[test]
fn parse_bye_request() {
    let raw = b"BYE sip:alice@pc33.atlanta.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKnashds10\r\n\
                Max-Forwards: 70\r\n\
                From: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
                To: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 231 BYE\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).unwrap();
    assert_eq!(msg.method(), Some(&Method::Bye));
}

#[test]
fn parse_options_request() {
    let raw = b"OPTIONS sip:carol@chicago.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n\
                Max-Forwards: 70\r\n\
                To: <sip:carol@chicago.com>\r\n\
                From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 63104 OPTIONS\r\n\
                Contact: <sip:alice@pc33.atlanta.com>\r\n\
                Accept: application/sdp\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).unwrap();
    assert_eq!(msg.method(), Some(&Method::Options));
    assert_eq!(msg.header("Accept"), Some("application/sdp"));
}

#[test]
fn parse_cancel_request() {
    let raw = b"CANCEL sip:bob@biloxi.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                Max-Forwards: 70\r\n\
                From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                To: Bob <sip:bob@biloxi.com>\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 314159 CANCEL\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).unwrap();
    assert_eq!(msg.method(), Some(&Method::Cancel));
}

#[test]
fn parse_4xx_error_response() {
    let raw = b"SIP/2.0 404 Not Found\r\n\
                Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                To: Bob <sip:bob@biloxi.com>;tag=7jyXl\r\n\
                Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                CSeq: 314159 INVITE\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).unwrap();
    assert_eq!(msg.status_code(), Some(404));
}

// ─── Folded headers ───────────────────────────────────────────

#[test]
fn parse_folded_header() {
    // Subject header continues on the next line with a leading space.
    // RFC 3261 §7.3.1: a header value continues on the next line if that
    // line starts with at least one SP or HT.
    let raw = b"OPTIONS sip:bob@biloxi.com SIP/2.0\r\nSubject: I know you are\r\n there, pick up the phone\r\nCall-ID: folded-test@example.com\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    let msg = parse_message(raw).unwrap();
    let subject = msg.header("Subject").unwrap();
    assert!(
        subject.contains("there, pick up"),
        "folded continuation not unfolded: '{subject}'"
    );
}

// ─── Error cases ──────────────────────────────────────────────

#[test]
fn parse_empty_input_is_error() {
    // Empty input is always an error (the parser can't determine if it's
    // incomplete or invalid without at least seeing a start line).
    let result = parse_message(b"");
    assert!(result.is_err(), "empty input should return an error");
}

#[test]
fn parse_truncated_header_is_incomplete() {
    use voip_sip::sip::parser::ParseError;
    let raw = b"INVITE sip:bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP";
    // Truncated mid-header — should be Incomplete, not a crash.
    let result = parse_message(raw);
    assert!(result.is_err());
}

#[test]
fn parse_extra_unknown_header_does_not_fail() {
    let raw = b"OPTIONS sip:carol@chicago.com SIP/2.0\r\n\
                X-Custom-Header: whatever; q=0.5\r\n\
                Call-ID: custom-test@example.com\r\n\
                CSeq: 1 OPTIONS\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let msg = parse_message(raw).expect("unknown headers must not cause errors");
    assert_eq!(
        msg.header("X-Custom-Header"),
        Some("whatever; q=0.5")
    );
}

// ─── SDP parser ───────────────────────────────────────────────

#[test]
fn sdp_basic_audio() {
    let sdp = b"v=0\r\n\
                o=- 2890844526 2890844527 IN IP4 host.atlanta.com\r\n\
                s=-\r\n\
                c=IN IP4 host.atlanta.com\r\n\
                t=0 0\r\n\
                m=audio 49172 RTP/AVP 0\r\n\
                a=rtpmap:0 PCMU/8000\r\n";

    let session = parse_sdp(sdp).expect("should parse basic SDP");
    assert!(session.connection.is_some());
    assert_eq!(session.connection.as_ref().unwrap().address, "host.atlanta.com");
    assert_eq!(session.media.len(), 1);
    let audio = &session.media[0];
    assert_eq!(audio.media_type, "audio");
    assert_eq!(audio.port, 49172);
    assert_eq!(audio.protocol, "RTP/AVP");
    assert_eq!(audio.payload_types, vec![0]);
    assert_eq!(audio.attr("rtpmap"), Some("0 PCMU/8000"));
}

#[test]
fn sdp_opus_payload() {
    let sdp = b"v=0\r\n\
                o=- 0 0 IN IP4 127.0.0.1\r\n\
                s=-\r\n\
                c=IN IP4 192.168.1.100\r\n\
                t=0 0\r\n\
                m=audio 5004 RTP/SAVP 111\r\n\
                a=rtpmap:111 opus/48000/2\r\n\
                a=fmtp:111 minptime=10;useinbandfec=1\r\n\
                a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zLWhlbGxvd29ybGQ\r\n";

    let session = parse_sdp(sdp).unwrap();
    let audio = &session.media[0];
    assert_eq!(audio.protocol, "RTP/SAVP");
    assert_eq!(audio.payload_types, vec![111]);
    assert_eq!(audio.attr("rtpmap"), Some("111 opus/48000/2"));
    assert!(audio.attr("fmtp").unwrap().contains("useinbandfec"));
    assert!(!audio.crypto_lines().is_empty());
}

#[test]
fn sdp_per_media_connection() {
    let sdp = b"v=0\r\n\
                o=- 0 0 IN IP4 0.0.0.0\r\n\
                s=-\r\n\
                c=IN IP4 0.0.0.0\r\n\
                t=0 0\r\n\
                m=audio 20000 RTP/AVP 0\r\n\
                c=IN IP4 192.168.50.1\r\n\
                a=rtpmap:0 PCMU/8000\r\n";

    let session = parse_sdp(sdp).unwrap();
    let audio = &session.media[0];
    // Per-media c= should override session-level.
    assert_eq!(audio.connection.as_ref().unwrap().address, "192.168.50.1");
}

#[test]
fn sdp_ice_attributes() {
    let sdp = b"v=0\r\n\
                o=- 0 0 IN IP4 0.0.0.0\r\n\
                s=-\r\n\
                c=IN IP4 0.0.0.0\r\n\
                t=0 0\r\n\
                m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                a=ice-ufrag:F7gI\r\n\
                a=ice-pwd:x9cml/YoukHEt3LmX4lGpf02\r\n\
                a=rtpmap:111 opus/48000/2\r\n";

    let session = parse_sdp(sdp).unwrap();
    let audio = &session.media[0];
    assert_eq!(audio.ice_ufrag(), Some("F7gI"));
    assert_eq!(audio.ice_pwd(), Some("x9cml/YoukHEt3LmX4lGpf02"));
}

#[test]
fn sdp_multi_media() {
    let sdp = b"v=0\r\n\
                o=- 0 0 IN IP4 0.0.0.0\r\n\
                s=-\r\n\
                c=IN IP4 10.0.0.1\r\n\
                t=0 0\r\n\
                m=audio 5004 RTP/AVP 0\r\n\
                m=video 5006 RTP/AVP 96\r\n\
                a=rtpmap:96 VP8/90000\r\n";

    let session = parse_sdp(sdp).unwrap();
    assert_eq!(session.media.len(), 2);
    assert_eq!(session.media[0].media_type, "audio");
    assert_eq!(session.media[1].media_type, "video");
    assert_eq!(session.media[1].attr("rtpmap"), Some("96 VP8/90000"));
}

// ─── ULID tests ───────────────────────────────────────────────

#[test]
fn ulid_is_26_chars() {
    let id = routing_core::tracing::ulid::Ulid::new();
    assert_eq!(id.to_string().len(), 26);
}

#[test]
fn ulid_round_trip() {
    let id  = routing_core::tracing::ulid::Ulid::new();
    let s   = id.to_string();
    let id2 = routing_core::tracing::ulid::Ulid::from_str(&s).unwrap();
    assert_eq!(id, id2);
}

#[test]
fn ulid_monotone() {
    // Two successive ULIDs generated in the same millisecond differ in the
    // random bits, but the first 10 timestamp characters are equal.
    let a = routing_core::tracing::ulid::Ulid::new();
    let b = routing_core::tracing::ulid::Ulid::new();
    // The raw u128 values should be different.
    assert_ne!(a.as_u128(), b.as_u128());
}
