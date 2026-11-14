//! ICE in the SIP offer/answer exchange: reading it from an SDP, writing it into one, and the
//! role and default-candidate rules that go with it.
//!
//! The realistic SDP bodies below are written from memory of what browsers and SIP stacks send
//! (not captured from them), so they are evidence for the parsing rules, not an interop test.

use nat_traversal::ice::sdp::{decode_candidate, EncodeError, EncodeOptions, IceDescription, SdpError, Skip};
use nat_traversal::ice::{Candidate, CandidateType, IceRole};
use nat_traversal::ice::interfaces::{gather_host_sockets, HostPolicy, HostSocket};
use nat_traversal::ice::{run_agent, ChecklistState, DriveOptions, IceAgent, IceConfig, Nomination};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use voip_sip::nat::ice::{check_remote, default_candidate, role_for, IceCredentials, NegotiationError};
use voip_sip::sip::sdp::{parse_sdp, IceSdpError, SdpSession};
use voip_sip::sip::sdp_builder::{build_sdp, BuildError, Format, MediaSection, Origin};

const PWD: &str = "asd88fgpdd777uzjYhagZg";

fn cand(line: &str) -> Candidate {
    decode_candidate(line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
}
fn sdp(lines: &[&str]) -> String {
    lines.join("\r\n") + "\r\n"
}
fn parse(text: &str) -> SdpSession {
    parse_sdp(text.as_bytes()).unwrap_or_else(|e| panic!("{e:?}\n{text}"))
}
const HOST1: &str = "a=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host";
const SRFLX1: &str = "a=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.1.1 rport 8998";

// ─── Reading ICE from an SDP ───────────────────────────────────────

#[test]
fn media_level_ice_attributes_are_read() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0", "c=IN IP4 10.0.1.1",
        "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"), HOST1, SRFLX1]));
    let d = s.ice_description(0).unwrap();
    assert_eq!((d.ufrag.as_deref(), d.pwd.as_deref()), (Some("8hhy"), Some(PWD)));
    assert_eq!(d.candidates.len(), 2);
    assert!(!d.lite && !d.trickle && !d.end_of_candidates);
}

#[test]
fn session_level_credentials_apply_to_every_media_section_that_does_not_set_its_own() {
    // RFC 8839 allows ice-ufrag and ice-pwd at session level. The parser used to drop
    // everything before the first m= line, so a legal offer looked like it had no credentials.
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "a=ice-ufrag:sess", &format!("a=ice-pwd:{PWD}"),
        "m=audio 8998 RTP/AVP 0", HOST1, "m=video 9000 RTP/AVP 96", "a=candidate:3 1 UDP 2130706431 10.0.1.1 9000 typ host"]));
    for i in 0..2 {
        let d = s.ice_description(i).unwrap();
        assert_eq!((d.ufrag.as_deref(), d.pwd.as_deref()), (Some("sess"), Some(PWD)), "media {i}");
        assert_eq!(d.candidates.len(), 1, "candidates stay with their own section");
    }
}

#[test]
fn a_media_level_credential_overrides_the_session_level_one_independently_per_field() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "a=ice-ufrag:sess", &format!("a=ice-pwd:{PWD}"),
        "m=audio 8998 RTP/AVP 0", "a=ice-ufrag:aud1", HOST1,
        "m=video 9000 RTP/AVP 96", "a=ice-pwd:vvvvvvvvvvvvvvvvvvvvvvvv", "a=candidate:3 1 UDP 2130706431 10.0.1.1 9000 typ host"]));
    let (a, v) = (s.ice_description(0).unwrap(), s.ice_description(1).unwrap());
    assert_eq!((a.ufrag.as_deref(), a.pwd.as_deref()), (Some("aud1"), Some(PWD)), "audio overrides the ufrag only");
    assert_eq!((v.ufrag.as_deref(), v.pwd.as_deref()), (Some("sess"), Some("vvvvvvvvvvvvvvvvvvvvvvvv")), "video overrides the password only");
}

#[test]
fn ice_lite_is_detected_at_session_level_and_tolerated_at_media_level() {
    let session_level = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "a=ice-lite", "m=audio 8998 RTP/AVP 0",
        "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"), HOST1]));
    assert!(session_level.ice_description(0).unwrap().lite);
    // A stack that puts it on the m= line is read as lite too, which only makes us controlling.
    let media_level = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0", "a=ice-lite",
        "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"), HOST1]));
    assert!(media_level.ice_description(0).unwrap().lite);
}

#[test]
fn trickle_and_end_of_candidates_are_read_from_either_level() {
    // Each flag is tested at each level, so that a bug that ignored one of the four places
    // cannot hide behind the other.
    let pwd_line = format!("a=ice-pwd:{PWD}");
    let flags = |session: &[&str], media: &[&str]| {
        let mut lines = vec!["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0"];
        lines.extend_from_slice(session);
        lines.extend(["m=audio 8998 RTP/AVP 0", "a=ice-ufrag:8hhy", pwd_line.as_str(), HOST1]);
        lines.extend_from_slice(media);
        let d = parse(&sdp(&lines)).ice_description(0).unwrap();
        (d.trickle, d.end_of_candidates)
    };
    assert_eq!(flags(&["a=ice-options:trickle"], &[]), (true, false), "trickle at session level");
    assert_eq!(flags(&[], &["a=ice-options:trickle"]), (true, false), "trickle at media level");
    assert_eq!(flags(&["a=end-of-candidates"], &[]), (false, true), "end-of-candidates at session level");
    assert_eq!(flags(&[], &["a=end-of-candidates"]), (false, true), "end-of-candidates at media level");
    assert_eq!(flags(&[], &[]), (false, false));
    assert_eq!(flags(&["a=ice-options:ice2 trickle"], &[]), (true, false), "among several options");
}

#[test]
fn a_candidate_at_session_level_is_refused() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", HOST1, "m=audio 8998 RTP/AVP 0", "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}")]));
    assert_eq!(s.ice_description(0), Err(IceSdpError::CandidateAtSessionLevel));
}

#[test]
fn a_malformed_candidate_fails_its_own_section_only() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"),
        "m=audio 8998 RTP/AVP 0", "a=candidate:1 1 UDP 0 10.0.1.1 8998 typ host",
        "m=video 9000 RTP/AVP 96", "a=candidate:3 1 UDP 2130706431 10.0.1.1 9000 typ host"]));
    assert!(matches!(s.ice_description(0), Err(IceSdpError::Ice(SdpError::Candidate { .. }))));
    assert_eq!(s.ice_description(1).unwrap().candidates.len(), 1, "one bad section must not poison the others");
}

#[test]
fn unsupported_candidates_are_skipped_and_counted() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0", "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"), HOST1,
        "a=candidate:9 1 tcp 1518280447 10.0.1.1 9 typ host tcptype active",
        "a=candidate:8 1 UDP 2113937151 9f3a1c2e-1111-4222-8333-444455556666.local 54321 typ host"]));
    let d = s.ice_description(0).unwrap();
    assert_eq!(d.candidates.len(), 1);
    assert_eq!(d.skipped, vec![Skip::Transport("tcp".into()), Skip::Hostname("9f3a1c2e-1111-4222-8333-444455556666.local".into())]);
}

#[test]
fn a_section_without_ice_has_no_credentials_and_an_out_of_range_index_is_an_error() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0", "a=rtpmap:0 PCMU/8000"]));
    let d = s.ice_description(0).unwrap();
    assert_eq!((d.ufrag, d.pwd, d.candidates.len()), (None, None, 0));
    assert_eq!(s.ice_description(1), Err(IceSdpError::NoSuchMedia(1)));
}

#[test]
fn unrelated_attributes_cannot_be_mistaken_for_ice_and_the_old_accessors_still_work() {
    let s = parse(&sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0",
        "a=fmtp:0 note=ice-ufrag:evil", "a=ICE-UFRAG:8hhy", &format!("a=ice-pwd:{PWD}"), HOST1]));
    let d = s.ice_description(0).unwrap();
    assert_eq!(d.ufrag.as_deref(), Some("8hhy"), "attribute names are matched case-insensitively, values not guessed at");
    assert_eq!((s.media[0].ice_ufrag(), s.media[0].ice_pwd()), (Some("8hhy"), Some(PWD)), "the existing accessors are untouched");
}

// ─── Realistic bodies ──────────────────────────────────────────────

#[test]
fn a_browser_style_offer_with_everything_a_browser_sends() {
    let offer = sdp(&["v=0", "o=- 4611731400430051336 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0", "a=msid-semantic: WMS",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8", "c=IN IP4 0.0.0.0", "a=rtcp:9 IN IP4 0.0.0.0",
        "a=candidate:842163049 1 udp 1677729535 203.0.113.5 46052 typ srflx raddr 10.0.0.5 rport 46052 generation 0 ufrag Xy7z network-cost 999",
        "a=candidate:1467250027 1 udp 2122260223 192.168.0.196 46243 typ host generation 0 network-id 1",
        "a=candidate:3 1 tcp 1518280447 192.168.0.196 9 typ host tcptype active generation 0 network-id 1",
        "a=candidate:2 1 udp 2113937151 9f3a1c2e-1111-4222-8333-444455556666.local 54321 typ host generation 0 network-id 2",
        "a=ice-ufrag:Xy7z", &format!("a=ice-pwd:{PWD}"), "a=ice-options:trickle", "a=fingerprint:sha-256 AB:CD", "a=setup:actpass", "a=mid:0",
        "a=sendrecv", "a=rtcp-mux", "a=rtpmap:111 opus/48000/2", "a=rtpmap:0 PCMU/8000"]);
    let d = parse(&offer).ice_description(0).unwrap();
    assert_eq!(d.candidates.len(), 2, "the srflx and the host; the TCP and mDNS ones are skipped");
    assert_eq!(d.skipped.len(), 2);
    assert!(d.trickle);
    assert_eq!(d.candidates[0].base_addr, "10.0.0.5:46052".parse().unwrap(), "the related address is the base");
    check_remote(&d).unwrap();
}

#[test]
fn a_firefox_style_offer_with_credentials_at_session_level() {
    let offer = sdp(&["v=0", "o=mozilla...THIS_IS_SDPARTA-99.0 6258418273108795021 0 IN IP4 0.0.0.0", "s=-", "t=0 0", "a=sendrecv",
        "a=fingerprint:sha-256 AB:CD", "a=group:BUNDLE 0", "a=ice-options:trickle", "a=msid-semantic:WMS *",
        "m=audio 9 UDP/TLS/RTP/SAVPF 109 9 0 8 101", "c=IN IP4 0.0.0.0", "a=candidate:0 1 UDP 2122252543 192.168.1.5 54000 typ host",
        "a=ice-pwd:0123456789abcdefghijklmn", "a=ice-ufrag:abcd1234", "a=mid:0"]);
    let d = parse(&offer).ice_description(0).unwrap();
    assert_eq!((d.ufrag.as_deref(), d.candidates.len()), (Some("abcd1234"), 1));
}

#[test]
fn a_sip_stack_style_offer_with_one_host_candidate() {
    let offer = sdp(&["v=0", "o=- 3815411482 3815411482 IN IP4 192.168.1.100", "s=pjmedia", "b=AS:84", "t=0 0", "a=X-nat:0",
        "m=audio 4000 RTP/AVP 0 101", "c=IN IP4 192.168.1.100", "b=TIAS:64000", "a=rtcp:4001 IN IP4 192.168.1.100", "a=sendrecv",
        "a=rtpmap:0 PCMU/8000", "a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16", "a=ice-ufrag:5b7c3f1d", "a=ice-pwd:9a8b7c6d5e4f3a2b1c0d9e8f",
        "a=candidate:Hc0a80164 1 UDP 2130706431 192.168.1.100 4000 typ host", "a=candidate:Hc0a80164 2 UDP 2130706430 192.168.1.100 4001 typ host"]);
    let d = parse(&offer).ice_description(0).unwrap();
    assert_eq!(d.candidates.len(), 2, "both components are read; only component 1 can be the default");
    check_remote(&d).unwrap();
}

// ─── Roles and the default candidate ───────────────────────────────

#[test]
fn the_offerer_controls_unless_the_peer_is_lite_in_which_case_we_do() {
    assert_eq!(role_for(true, false), IceRole::Controlling, "full offerer");
    assert_eq!(role_for(false, false), IceRole::Controlled, "full answerer");
    assert_eq!(role_for(true, true), IceRole::Controlling, "full offerer, lite answerer");
    assert_eq!(role_for(false, true), IceRole::Controlling, "full answerer facing a lite offerer: someone has to drive");
}

fn host(addr: &str, pref: u16) -> Candidate {
    Candidate::new(CandidateType::Host, addr.parse().unwrap(), addr.parse().unwrap(), pref, 1)
}
fn srflx(addr: &str, base: &str, pref: u16) -> Candidate {
    Candidate::new(CandidateType::ServerReflexive, addr.parse().unwrap(), base.parse().unwrap(), pref, 1)
}

#[test]
fn the_default_candidate_is_relayed_then_reflexive_then_host() {
    let relay = Candidate::relayed("203.0.113.10:50001".parse().unwrap(), 100, 1);
    let all = [host("10.0.1.1:5000", 65535), srflx("192.0.2.3:4000", "10.0.1.1:5000", 65535), relay.clone()];
    assert_eq!(default_candidate(&all), Some(&relay), "even though its priority is the lowest");
    assert_eq!(default_candidate(&all[..2]).unwrap().candidate_type, CandidateType::ServerReflexive);
    assert_eq!(default_candidate(&all[..1]).unwrap().candidate_type, CandidateType::Host);
}

#[test]
fn within_a_type_the_highest_priority_wins_and_ties_go_to_the_first() {
    let all = [host("10.0.1.1:5000", 100), host("10.0.2.1:5000", 65535), host("10.0.3.1:5000", 200)];
    assert_eq!(default_candidate(&all).unwrap().transport_addr, "10.0.2.1:5000".parse().unwrap());
    let tied = [host("10.0.1.1:5000", 500), host("10.0.2.1:5000", 500)];
    assert_eq!(default_candidate(&tied).unwrap().transport_addr, "10.0.1.1:5000".parse().unwrap(), "deterministic");
}

#[test]
fn only_component_one_can_be_the_default_and_no_candidates_means_none() {
    let rtcp = Candidate::new(CandidateType::Relayed, "203.0.113.10:50002".parse().unwrap(), "203.0.113.10:50002".parse().unwrap(), 65535, 2);
    assert_eq!(default_candidate(&[rtcp.clone()]), None, "an RTCP candidate is never what the m= line points at");
    assert_eq!(default_candidate(&[rtcp, host("10.0.1.1:5000", 1)]).unwrap().transport_addr, "10.0.1.1:5000".parse().unwrap());
    assert_eq!(default_candidate(&[]), None);
}

#[test]
fn a_description_is_negotiable_only_with_credentials_and_a_usable_candidate() {
    let full = IceDescription { ufrag: Some("8hhy".into()), pwd: Some(PWD.into()), candidates: vec![host("10.0.1.1:5000", 1)], ..Default::default() };
    assert_eq!(check_remote(&full), Ok(()));
    assert_eq!(check_remote(&IceDescription { ufrag: None, ..full.clone() }), Err(NegotiationError::MissingCredentials));
    assert_eq!(check_remote(&IceDescription { pwd: None, ..full.clone() }), Err(NegotiationError::MissingCredentials));
    let skipped_only = IceDescription { candidates: vec![], skipped: vec![Skip::Transport("tcp".into()), Skip::Hostname("a.local".into())], ..full.clone() };
    assert_eq!(check_remote(&skipped_only), Err(NegotiationError::NoUsableCandidates { skipped: 2 }));
    assert_eq!(check_remote(&IceDescription { trickle: true, candidates: vec![], ..full }), Err(NegotiationError::NoUsableCandidates { skipped: 0 }), "this agent does not trickle");
}

// ─── Writing ───────────────────────────────────────────────────────

fn origin() -> Origin {
    Origin { username: "-".into(), session_id: 1, session_version: 1, address: "10.0.1.1".parse().unwrap() }
}
fn pcmu() -> Vec<Format> {
    vec![Format { payload_type: 0, rtpmap: Some("PCMU/8000".into()) }, Format { payload_type: 101, rtpmap: Some("telephone-event/8000".into()) }]
}
fn section(ice: Option<IceDescription>) -> MediaSection {
    MediaSection { media_type: "audio".into(), protocol: "RTP/AVP".into(), formats: pcmu(), fallback: "198.51.100.9:7000".parse().unwrap(), ice, attributes: vec!["sendrecv".into()] }
}
fn ice(candidates: Vec<Candidate>) -> IceDescription {
    IceDescription { ufrag: Some("8hhy".into()), pwd: Some(PWD.into()), candidates, ..Default::default() }
}

#[test]
fn an_offer_with_ice_has_exactly_the_expected_text() {
    let text = build_sdp(&origin(), &[section(Some(ice(vec![cand("candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host")])))], EncodeOptions::default()).unwrap();
    let expected = sdp(&["v=0", "o=- 1 1 IN IP4 10.0.1.1", "s=-", "t=0 0", "m=audio 8998 RTP/AVP 0 101", "c=IN IP4 10.0.1.1",
        "a=rtpmap:0 PCMU/8000", "a=rtpmap:101 telephone-event/8000", "a=sendrecv", "a=ice-ufrag:8hhy", &format!("a=ice-pwd:{PWD}"),
        "a=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host"]);
    assert_eq!(text, expected);
}

#[test]
fn the_m_and_c_lines_carry_the_default_candidate() {
    let relay = Candidate::relayed("203.0.113.10:50001".parse().unwrap(), 100, 1);
    let text = build_sdp(&origin(), &[section(Some(ice(vec![host("10.0.1.1:5000", 65535), relay])))], EncodeOptions::default()).unwrap();
    let s = parse(&text);
    assert_eq!(s.media[0].port, 50001, "the relayed candidate is the default");
    assert_eq!(s.media[0].connection.as_ref().unwrap().address, "203.0.113.10");
}

#[test]
fn ice_with_no_candidates_yet_uses_the_conventional_placeholder() {
    let s = parse(&build_sdp(&origin(), &[section(Some(ice(vec![])))], EncodeOptions::default()).unwrap());
    assert_eq!((s.media[0].port, s.media[0].connection.as_ref().unwrap().address.as_str()), (9, "0.0.0.0"));
}

#[test]
fn without_ice_the_fallback_address_is_used() {
    let s = parse(&build_sdp(&origin(), &[section(None)], EncodeOptions::default()).unwrap());
    assert_eq!((s.media[0].port, s.media[0].connection.as_ref().unwrap().address.as_str()), (7000, "198.51.100.9"));
    assert!(s.ice_description(0).unwrap().ufrag.is_none());
}

#[test]
fn an_ipv6_default_candidate_gets_an_ip6_connection_line() {
    let text = build_sdp(&origin(), &[section(Some(ice(vec![host("[2001:db8::1]:6000", 65535)])))], EncodeOptions::default()).unwrap();
    assert!(text.contains("c=IN IP6 2001:db8::1\r\n") && text.contains("m=audio 6000 "), "{text}");
}

#[test]
fn each_media_section_gets_its_own_default() {
    let mut video = section(Some(ice(vec![host("10.0.1.1:9000", 65535)])));
    video.media_type = "video".into();
    video.formats = vec![Format { payload_type: 96, rtpmap: Some("VP8/90000".into()) }];
    let s = parse(&build_sdp(&origin(), &[section(Some(ice(vec![host("10.0.1.1:8998", 65535)]))), video], EncodeOptions::default()).unwrap());
    assert_eq!((s.media[0].port, s.media[1].port), (8998, 9000));
    assert_eq!((s.media[0].media_type.as_str(), s.media[1].media_type.as_str()), ("audio", "video"));
}

#[test]
fn nothing_that_could_add_a_line_is_written() {
    let bad_section = |f: &dyn Fn(&mut MediaSection)| {
        let mut s = section(None);
        f(&mut s);
        build_sdp(&origin(), &[s], EncodeOptions::default())
    };
    let invalid = |r: Result<String, BuildError>| matches!(r, Err(BuildError::Invalid(_)));
    assert!(invalid(bad_section(&|s| s.media_type = "audio\r\nm=video 9 RTP/AVP 0".into())));
    assert!(invalid(bad_section(&|s| s.media_type = "au dio".into())));
    assert!(invalid(bad_section(&|s| s.protocol = "RTP/AVP\r\na=evil".into())));
    assert!(invalid(bad_section(&|s| s.formats[0].rtpmap = Some("PCMU/8000\r\na=evil".into()))));
    assert!(invalid(bad_section(&|s| s.formats[0].rtpmap = Some("PCMU 8000".into()))));
    assert!(invalid(bad_section(&|s| s.attributes = vec!["sendrecv\r\na=evil".into()])));
    assert!(invalid(bad_section(&|s| s.attributes = vec!["sendrecv\u{0}".into()])));
    assert!(invalid(bad_section(&|s| s.attributes = vec![String::new()])));
    let mut o = origin();
    o.username = "evil\r\nm=video".into();
    assert!(matches!(build_sdp(&o, &[section(None)], EncodeOptions::default()), Err(BuildError::Invalid(_))));
    o.username = "two words".into();
    assert!(matches!(build_sdp(&o, &[section(None)], EncodeOptions::default()), Err(BuildError::Invalid(_))));
}

#[test]
fn ice_attributes_cannot_be_smuggled_in_as_plain_attributes() {
    for name in ["ice-ufrag:evil", "ICE-PWD:evil", "candidate:1 1 UDP 1 1.2.3.4 5 typ host", "ice-lite", "end-of-candidates", "ice-options:trickle"] {
        let mut s = section(None);
        s.attributes = vec![name.into()];
        assert!(matches!(build_sdp(&origin(), &[s], EncodeOptions::default()), Err(BuildError::Invalid(_))), "{name}");
    }
}

#[test]
fn structural_mistakes_are_refused() {
    let invalid = |r: Result<String, BuildError>| matches!(r, Err(BuildError::Invalid(_)));
    assert!(invalid(build_sdp(&origin(), &[], EncodeOptions::default())), "no media sections");
    let mut s = section(None);
    s.formats.clear();
    assert!(invalid(build_sdp(&origin(), &[s], EncodeOptions::default())), "no formats");
    let mut s = section(None);
    s.formats[0].payload_type = 128;
    assert!(invalid(build_sdp(&origin(), &[s], EncodeOptions::default())), "payload type above 127");
    let mut s = section(None);
    s.fallback = "198.51.100.9:0".parse().unwrap();
    assert!(invalid(build_sdp(&origin(), &[s], EncodeOptions::default())), "port 0 would silently reject the stream");
}

#[test]
fn a_bad_ice_attribute_surfaces_as_an_ice_error() {
    let mut d = ice(vec![host("10.0.1.1:5000", 1)]);
    d.ufrag = Some("abc\r\na=evil".into());
    assert_eq!(build_sdp(&origin(), &[section(Some(d))], EncodeOptions::default()), Err(BuildError::Ice(EncodeError::Credential("ice-ufrag"))));
}

// ─── Round trips ───────────────────────────────────────────────────

#[test]
fn a_built_description_reads_back_as_what_was_put_in() {
    let relay = Candidate::relayed("203.0.113.10:50001".parse().unwrap(), 100, 1);
    let put_in = ice(vec![host("10.0.1.1:5000", 65535), srflx("192.0.2.3:4000", "10.0.1.1:5000", 65534), relay]);
    let text = build_sdp(&origin(), &[section(Some(put_in.clone()))], EncodeOptions::default()).unwrap();
    let s = parse(&text);
    assert_eq!((s.media[0].payload_types.clone(), s.media[0].protocol.as_str()), (vec![0, 101], "RTP/AVP"));
    assert_eq!(s.media[0].attrs_all("rtpmap"), vec!["0 PCMU/8000", "101 telephone-event/8000"]);

    let back = s.ice_description(0).unwrap();
    assert_eq!((back.ufrag.clone(), back.pwd.clone()), (put_in.ufrag.clone(), put_in.pwd.clone()));
    assert_eq!(back.candidates.len(), 3);
    for (a, b) in put_in.candidates.iter().zip(&back.candidates) {
        assert_eq!((a.candidate_type, a.transport_addr, a.component_id, a.priority()), (b.candidate_type, b.transport_addr, b.component_id, b.priority()));
    }
}

#[test]
fn credentials_can_be_generated_and_survive_the_round_trip() {
    let c = IceCredentials::generate().expect("OS randomness");
    let text = build_sdp(&origin(), &[section(Some(IceDescription { ufrag: Some(c.ufrag.clone()), pwd: Some(c.password.clone()), candidates: vec![host("10.0.1.1:5000", 1)], ..Default::default() }))], EncodeOptions::default()).unwrap();
    assert_eq!(parse(&text).ice_description(0).unwrap().credentials(), Some(c));
}

// ─── The whole exchange, over real sockets ─────────────────────────

fn audio_section(sockets: &[HostSocket], creds: &IceCredentials) -> MediaSection {
    section(Some(IceDescription {
        ufrag: Some(creds.ufrag.clone()),
        pwd: Some(creds.password.clone()),
        candidates: sockets.iter().map(|h| h.candidate.clone()).collect(),
        ..Default::default()
    }))
}

#[tokio::test]
async fn two_endpoints_negotiate_ice_through_sdp_written_and_read_by_voip_sip() {
    // Each side discovers its own addresses, binds sockets and generates credentials. The
    // caller offers; the callee reads the offer, checks it, picks its role and answers; the
    // caller reads the answer. Then both run ICE, knowing each other only through that text.
    let policy = HostPolicy { include_loopback: true, ..HostPolicy::default() };
    let (caller, callee) = (gather_host_sockets(&policy).await.unwrap(), gather_host_sockets(&policy).await.unwrap());
    let (creds_caller, creds_callee) = (IceCredentials::generate().unwrap(), IceCredentials::generate().unwrap());

    let offer = build_sdp(&origin(), &[audio_section(&caller, &creds_caller)], EncodeOptions::default()).unwrap();
    let offer_ice = parse(&offer).ice_description(0).unwrap();
    check_remote(&offer_ice).unwrap();
    let callee_role = role_for(false, offer_ice.lite);

    let answer = build_sdp(&origin(), &[audio_section(&callee, &creds_callee)], EncodeOptions::default()).unwrap();
    let answer_sdp = parse(&answer);
    let answer_ice = answer_sdp.ice_description(0).unwrap();
    check_remote(&answer_ice).unwrap();
    let caller_role = role_for(true, answer_ice.lite);
    assert_eq!((caller_role, callee_role), (IceRole::Controlling, IceRole::Controlled));

    // The m= and c= lines of the answer name the callee's default candidate.
    let default = default_candidate_of(&callee);
    assert_eq!(answer_sdp.media[0].port, default.port());
    assert_eq!(answer_sdp.media[0].connection.as_ref().unwrap().address, default.ip().to_string());

    let config = || IceConfig {
        ta: Duration::from_millis(20), min_rto: Duration::from_millis(100), max_transmissions: 7, final_wait_multiplier: 16,
        nomination: Nomination::Regular { delay: Duration::from_millis(100) },
    };
    let locals = |g: &[HostSocket]| -> Vec<Candidate> { g.iter().map(|h| h.candidate.clone()).collect() };
    let mut agent_caller = IceAgent::new(config(), caller_role, 100, creds_caller, answer_ice.credentials().unwrap(), locals(&caller), answer_ice.candidates.clone(), Instant::now());
    let mut agent_callee = IceAgent::new(config(), callee_role, 50, creds_callee, offer_ice.credentials().unwrap(), locals(&callee), offer_ice.candidates.clone(), Instant::now());

    let socks = |g: &[HostSocket]| -> Vec<Arc<UdpSocket>> { g.iter().map(|h| Arc::clone(&h.socket)).collect() };
    let (socks_caller, socks_callee) = (socks(&caller), socks(&callee));
    let opts = DriveOptions { timeout: Duration::from_secs(20), linger: Duration::from_secs(1) };
    let (a, b) = tokio::join!(
        run_agent(&mut agent_caller, &socks_caller, opts),
        run_agent(&mut agent_callee, &socks_callee, opts),
    );
    assert_eq!((a, b), (ChecklistState::Completed, ChecklistState::Completed));
    assert!(agent_caller.selected_pair().is_some() && agent_callee.selected_pair().is_some());
}

/// The address the default candidate of these sockets names.
fn default_candidate_of(g: &[HostSocket]) -> std::net::SocketAddr {
    let c: Vec<Candidate> = g.iter().map(|h| h.candidate.clone()).collect();
    default_candidate(&c).expect("at least one candidate").transport_addr
}
