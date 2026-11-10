//! SDP candidate attributes (RFC 8839 §5).
//!
//! The decoder reads hostile text, and the encoder writes text a peer will trust,
//! so both are tested for what they refuse as much as for what they accept.
//!
//! The tables at the bottom were produced by an independent implementation of the
//! grammar (a separate program with its own IP parsing, whitespace rules and
//! encoding rules). The same oracle was also run against about 21,000 generated
//! decode cases and 4,000 encoder specs with no disagreement. The oracle and this
//! codec share one author's reading of the RFC, so that is evidence against
//! slips, not against a shared misreading; the real-world strings below are the
//! check on that.

use nat_traversal::ice::sdp::{
    decode_candidate, encode_candidate, format_ice_attributes, parse_ice_attributes, wire_foundation,
    DecodeError, EncodeError, EncodeOptions, IceDescription, SdpError, Skip, MAX_CANDIDATES, MAX_INPUT, MAX_LINE,
};
use nat_traversal::ice::{
    run_agent, Candidate, CandidateType, ChecklistState, DriveOptions, IceAgent, IceConfig, IceCredentials, IceRole, Nomination,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn ok(line: &str) -> Candidate {
    decode_candidate(line).unwrap_or_else(|e| panic!("{line:?} should decode: {e}"))
}
fn is_malformed(line: &str) -> bool {
    matches!(decode_candidate(line), Err(DecodeError::Malformed(_)))
}
fn skipped(line: &str) -> Skip {
    match decode_candidate(line) {
        Err(DecodeError::Unsupported(s)) => s,
        other => panic!("{line:?} should be skipped, got {other:?}"),
    }
}
const HOST: &str = "candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host";

// ─── Real-world candidate lines ────────────────────────────────────

#[test]
fn the_rfc_host_example_decodes() {
    let c = ok(HOST);
    assert_eq!(c.candidate_type, CandidateType::Host);
    assert_eq!(c.transport_addr, a("10.0.1.1:8998"));
    assert_eq!((c.component_id, c.priority(), c.foundation.as_str()), (1, 2130706431, "1"));
    assert_eq!(c.base_addr, c.transport_addr, "a host candidate is its own base");
    assert_eq!(c.local_preference, 65535, "recovered from the priority");
}

#[test]
fn the_rfc_server_reflexive_example_decodes_with_its_base() {
    let c = ok("candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.1.1 rport 8998");
    assert_eq!(c.candidate_type, CandidateType::ServerReflexive);
    assert_eq!(c.transport_addr, a("192.0.2.3:45664"));
    assert_eq!(c.base_addr, a("10.0.1.1:8998"), "the related address is the base");
}

#[test]
fn a_hidden_related_address_leaves_the_base_as_the_transport_address() {
    // Browsers send 0.0.0.0 / 0 for raddr / rport to avoid disclosing the host's own address.
    let c = ok("candidate:3 1 udp 41885439 203.0.113.9 56789 typ relay raddr 0.0.0.0 rport 0 generation 0");
    assert_eq!(c.candidate_type, CandidateType::Relayed);
    assert_eq!(c.base_addr, c.transport_addr);
    let c = ok("candidate:4 1 udp 1677729535 203.0.113.5 46052 typ srflx raddr 0.0.0.0 rport 0");
    assert_eq!(c.base_addr, c.transport_addr, "and a hidden one must not become a base of 0.0.0.0:0");
}

#[test]
fn a_browser_line_with_extensions_decodes_and_the_extensions_are_ignored() {
    let c = ok("candidate:842163049 1 udp 1677729535 203.0.113.5 46052 typ srflx raddr 10.0.0.5 rport 46052 generation 0 ufrag abcd network-cost 999");
    assert_eq!(c.transport_addr, a("203.0.113.5:46052"));
    assert_eq!(c.base_addr, a("10.0.0.5:46052"));
    assert_eq!(c.foundation, "842163049");
}

#[test]
fn the_a_prefix_whitespace_line_endings_and_repeated_spaces_are_tolerated() {
    let expected = ok(HOST);
    for line in [
        "a=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host",
        "  candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host\r\n",
        "candidate:1  1   UDP 2130706431 10.0.1.1  8998 typ host",
        "\ta=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host \n",
        "candidate:1 1 udp 2130706431 10.0.1.1 8998 typ host",
        "candidate:1 1 Udp 2130706431 10.0.1.1 8998 typ host",
    ] {
        assert_eq!(ok(line), expected, "{line:?}");
    }
}

#[test]
fn ipv6_and_peer_reflexive_candidates_decode() {
    let c = ok("candidate:5 1 UDP 2130706175 2001:db8::1 6000 typ host");
    assert_eq!(c.transport_addr, a("[2001:db8::1]:6000"));
    let c = ok("candidate:6 1 UDP 1862270975 198.51.100.7 7000 typ prflx raddr 10.9.9.9 rport 7000");
    assert_eq!(c.candidate_type, CandidateType::PeerReflexive);
    assert_eq!(c.base_addr, a("10.9.9.9:7000"));
}

#[test]
fn a_decoded_candidate_keeps_the_exact_priority_the_peer_advertised() {
    // 5 is nowhere near what the formula would give for a host candidate. The agent
    // must use the peer's number, or the two ends compute different pair priorities.
    let c = ok("candidate:7 1 UDP 5 10.0.1.1 8998 typ host");
    assert_eq!(c.priority(), 5);
}

// ─── Well-formed but unusable: skipped, not failed ─────────────────

#[test]
fn tcp_candidates_are_skipped() {
    assert_eq!(skipped("candidate:2 1 tcp 1518280447 192.168.0.196 9 typ host tcptype active generation 0"), Skip::Transport("tcp".into()));
}

#[test]
fn unknown_candidate_types_are_skipped() {
    assert_eq!(skipped("candidate:2 1 UDP 1 10.0.1.1 8998 typ future-type"), Skip::CandidateType("future-type".into()));
}

#[test]
fn mdns_hostnames_are_skipped_and_never_resolved() {
    let name = "9f3a1c2e-1111-4222-8333-444455556666.local";
    assert_eq!(skipped(&format!("candidate:2 1 UDP 2113937151 {name} 54321 typ host generation 0")), Skip::Hostname(name.into()));
}

#[test]
fn component_256_is_skipped() {
    assert_eq!(skipped("candidate:2 256 UDP 1 10.0.1.1 8998 typ host"), Skip::Component(256));
}

#[test]
fn a_malformed_line_is_never_downgraded_to_a_skip() {
    // TCP is a skip, but this line is also broken: it must be an error.
    assert!(is_malformed("candidate:2 1 tcp 0 192.168.0.196 9 typ host"), "priority 0");
    assert!(is_malformed("candidate:2 1 UDP 1 not_a_host.local 8998 typ future-type"), "an invalid name");
    assert!(is_malformed("candidate:2 1 UDP 1 abc.local 0 typ host"), "port 0 on a hostname candidate");
}

// ─── Malformed: refused, field by field ────────────────────────────

const TEMPLATE: [&str; 8] = ["1", "1", "UDP", "2130706431", "10.0.1.1", "8998", "typ", "host"];

#[test]
fn every_field_rejects_its_bad_values() {
    let bad: [(usize, &[&str]); 8] = [
        (0, &["!", "a-b", "a.b", "a:b", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "é"]),
        (1, &["0", "257", "1000", "abc", "-1", "+1", "1.5"]),
        (2, &["(", "\"", "<", "\u{1}", "é", ","]),
        (3, &["0", "2147483648", "4294967295", "abc", "12345678901", "-5", "1e3", "0x10"]),
        (4, &["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "2001:db8::g", "fe80::1%eth0", "::1::", "a_b.local", "-a.local", "a..b", "1.2.3.4%x", ".local", "a.", "[::1]"]),
        (5, &["0", "65536", "abc", "-1", "123456", "1.5", "+80"]),
        (6, &["Typ", "TYP", "type", "typ2", "host"]),
        (7, &["(x)", "\u{1}", "é"]),
    ];
    for (index, values) in bad {
        for value in values {
            let mut t = TEMPLATE;
            t[index] = value;
            let line = format!("candidate:{}", t.join(" "));
            assert!(is_malformed(&line), "field {index} = {value:?} must be refused: {line:?}");
        }
    }
}

#[test]
fn structural_damage_is_refused() {
    for line in [
        "", " ", "\t\t", "candidate:", "a=", "a=candidate:", "candidate:1 1 UDP",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ", "Candidate:1 1 UDP 1 10.0.1.1 8998 typ host",
        "candidat:1 1 UDP 1 10.0.1.1 8998 typ host", "candidate 1 1 UDP 1 10.0.1.1 8998 typ host",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ host lonely",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ srflx raddr 1.2.3.4 raddr 1.2.3.5",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ srflx raddr 1.2.3.4 rport 65536",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ srflx raddr 1.2.3.4 rport abc",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{0}", "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{e9}",
        "candidate:1\u{a0}1 UDP 1 10.0.1.1 8998 typ host", "CANDIDATE:1 1 UDP 1 10.0.1.1 8998 typ host",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{2028}",
        // Unicode whitespace is not padding: it is a line break to some parsers.
        "\u{a0}candidate:1 1 UDP 1 10.0.1.1 8998 typ host", "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{a0}",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{85}", "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{3000}",
        "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{b}", "candidate:1 1 UDP 1 10.0.1.1 8998 typ host\u{c}",
    ] {
        assert!(is_malformed(line), "{line:?}");
    }
}

#[test]
fn junk_hidden_in_an_extension_value_is_still_refused() {
    // An extension's value is the one field nothing else validates, so the blanket
    // "printable ASCII only" rule is all that stops a control character, a NUL, or a
    // text-direction override reaching a log line or a UI through it.
    for junk in ["\u{1}", "\u{0}", "\u{7f}", "\u{e9}", "\u{202e}", "a\u{200b}b", "\u{1b}[31m"] {
        let line = format!("candidate:1 1 UDP 1 10.0.1.1 8998 typ host generation {junk}");
        assert!(is_malformed(&line), "{line:?}");
    }
    assert!(decode_candidate("candidate:1 1 UDP 1 10.0.1.1 8998 typ host generation 0 network-cost 999").is_ok(), "ordinary extension values are fine");
}

#[test]
fn an_overlong_line_is_refused() {
    let line = format!("{HOST} {}", "g ".repeat(MAX_LINE));
    assert!(is_malformed(&line));
}

// ─── Encoding ──────────────────────────────────────────────────────

fn cand(t: CandidateType, addr: &str, base: &str, pref: u16) -> Candidate {
    Candidate::new(t, a(addr), a(base), pref, 1)
}
fn tokens(line: &str) -> Vec<String> {
    line.split(' ').map(String::from).collect()
}

#[test]
fn a_host_candidate_encodes_to_the_rfc_example_numbers() {
    let line = encode_candidate(&cand(CandidateType::Host, "10.0.1.1:8998", "10.0.1.1:8998", 65535), EncodeOptions::default()).unwrap();
    let t = tokens(&line);
    assert_eq!(&t[1..], ["1", "UDP", "2130706431", "10.0.1.1", "8998", "typ", "host"], "{line}");
    assert!(t[0].starts_with("candidate:"));
}

#[test]
fn a_server_reflexive_candidate_matches_the_rfc_priority_and_hides_its_base_by_default() {
    let c = cand(CandidateType::ServerReflexive, "192.0.2.3:45664", "10.0.1.1:8998", 65535);
    let t = tokens(&encode_candidate(&c, EncodeOptions::default()).unwrap());
    assert_eq!(t[3], "1694498815", "the RFC's own example priority");
    assert_eq!(&t[7..], ["srflx", "raddr", "0.0.0.0", "rport", "0"], "the host's address is not disclosed unless asked");
}

#[test]
fn the_base_is_written_only_when_asked_for() {
    let c = cand(CandidateType::ServerReflexive, "192.0.2.3:45664", "10.0.1.1:8998", 65535);
    let t = tokens(&encode_candidate(&c, EncodeOptions { expose_base: true }).unwrap());
    assert_eq!(&t[7..], ["srflx", "raddr", "10.0.1.1", "rport", "8998"]);
}

#[test]
fn a_relayed_candidate_never_discloses_a_base() {
    // Its base is itself, and the mapped address that RFC 8839 asks for is not known here.
    let c = Candidate::relayed(a("203.0.113.10:50001"), 65535, 1);
    let t = tokens(&encode_candidate(&c, EncodeOptions { expose_base: true }).unwrap());
    assert_eq!(&t[7..], ["relay", "raddr", "0.0.0.0", "rport", "0"]);
}

#[test]
fn a_hidden_related_address_matches_the_candidates_address_family() {
    let c = cand(CandidateType::ServerReflexive, "[2001:db8::7]:4000", "[2001:db8::1]:5000", 65535);
    let t = tokens(&encode_candidate(&c, EncodeOptions::default()).unwrap());
    assert_eq!(&t[7..], ["srflx", "raddr", "::", "rport", "0"]);
}

#[test]
fn the_foundations_this_crate_computes_are_not_valid_sdp_so_they_are_hashed() {
    let readable = cand(CandidateType::Host, "10.0.1.1:8998", "10.0.1.1:8998", 65535).foundation;
    assert_eq!(readable, "Host-10.0.1.1", "setup: the readable internal form");
    let wire = wire_foundation(&readable);
    assert_eq!(wire.len(), 16);
    assert!(wire.chars().all(|c| c.is_ascii_hexdigit()), "{wire}");
    assert_eq!(wire, wire_foundation(&readable), "stable: the same foundation always maps to the same token");
}

#[test]
fn a_foundation_that_is_already_valid_passes_through_unchanged() {
    for f in ["1", "842163049", "abcXYZ019+/", &"a".repeat(32)] {
        assert_eq!(wire_foundation(f), f);
    }
    for f in ["", "has space", "a-b", "x:y", &"a".repeat(33), "é"] {
        assert_ne!(wire_foundation(f), f, "{f:?} is not valid SDP and must not be written as it stands");
    }
}

#[test]
fn distinct_foundations_stay_distinct_on_the_wire() {
    // A peer compares foundations for equality; a collision would merge two groups.
    let mut seen = std::collections::HashMap::new();
    for i in 0..4000u32 {
        let ip = IpAddr::from([10, (i >> 8) as u8, i as u8, 1]);
        for t in [CandidateType::Host, CandidateType::ServerReflexive, CandidateType::PeerReflexive, CandidateType::Relayed] {
            let f = Candidate::new(t, SocketAddr::new(ip, 5000), SocketAddr::new(ip, 5000), 65535, 1).foundation;
            let w = wire_foundation(&f);
            if let Some(prev) = seen.insert(w.clone(), f.clone()) {
                assert_eq!(prev, f, "two different foundations mapped to {w}");
            }
        }
    }
}

#[test]
fn encoding_refuses_what_sdp_cannot_say() {
    let ok = cand(CandidateType::Host, "10.0.1.1:8998", "10.0.1.1:8998", 65535);
    let with = |f: &dyn Fn(&mut Candidate)| {
        let mut c = ok.clone();
        f(&mut c);
        encode_candidate(&c, EncodeOptions::default())
    };
    assert_eq!(with(&|c| c.transport_addr.set_port(0)), Err(EncodeError::Port));
    assert_eq!(with(&|c| c.component_id = 0), Err(EncodeError::Component(0)));
    assert_eq!(with(&|c| c.priority_override = Some(0)), Err(EncodeError::Priority(0)));
    assert_eq!(with(&|c| c.priority_override = Some(1 << 31)), Err(EncodeError::Priority(1 << 31)));
    assert_eq!(with(&|c| c.priority_override = Some(u32::MAX)), Err(EncodeError::Priority(u32::MAX)));
    assert!(with(&|c| c.priority_override = Some((1 << 31) - 1)).is_ok(), "the largest legal priority");
}

// ─── The output cannot be used to inject lines ─────────────────────

#[test]
fn a_hostile_foundation_cannot_add_lines_to_the_description() {
    let mut c = cand(CandidateType::Host, "10.0.1.1:8998", "10.0.1.1:8998", 65535);
    c.foundation = "x\r\na=evil\r\nm=video 9 RTP/AVP 0".into();
    let line = encode_candidate(&c, EncodeOptions::default()).unwrap();
    assert!(!line.contains('\r') && !line.contains('\n'), "{line:?}");
    assert_eq!(line.split(' ').count(), 8, "no extra fields either: {line:?}");
    assert!(decode_candidate(&line).is_ok());
}

#[test]
fn hostile_credentials_are_refused_not_written() {
    for (ufrag, pwd) in [("abcd\r\na=evil", "p".repeat(22)), ("abcd", "pass word pass word 1234".to_string()), ("abc", "p".repeat(22)), ("abcd", "p".repeat(21)), ("a b c d", "p".repeat(22))] {
        let d = IceDescription { ufrag: Some(ufrag.into()), pwd: Some(pwd.clone()), ..Default::default() };
        assert!(matches!(format_ice_attributes(&d, EncodeOptions::default()), Err(EncodeError::Credential(_))), "{ufrag:?} / {pwd:?}");
    }
}

// ─── Round trips ───────────────────────────────────────────────────

/// A small deterministic generator, so the property tests are repeatable.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_candidate(r: &mut Rng) -> Candidate {
    let ip = |r: &mut Rng| -> IpAddr {
        if r.below(3) == 0 {
            IpAddr::V6(Ipv6Addr::from((r.next() as u128) << 64 | r.next() as u128))
        } else {
            IpAddr::V4(Ipv4Addr::from(r.next() as u32))
        }
    };
    let t = [CandidateType::Host, CandidateType::ServerReflexive, CandidateType::PeerReflexive, CandidateType::Relayed][r.below(4) as usize];
    let ip1 = ip(r);
    let base_ip = if ip1.is_ipv4() { IpAddr::V4(Ipv4Addr::from(r.next() as u32)) } else { ip(r) };
    let port = |r: &mut Rng| 1 + r.below(65535) as u16;
    Candidate::new(t, SocketAddr::new(ip1, port(r)), SocketAddr::new(base_ip, port(r)), r.below(65536) as u16, 1 + r.below(255) as u8)
}

#[test]
fn encoding_then_decoding_preserves_what_a_peer_needs() {
    let mut r = Rng(0x8839_5245);
    for _ in 0..3000 {
        let c = random_candidate(&mut r);
        for expose_base in [false, true] {
            let line = encode_candidate(&c, EncodeOptions { expose_base }).unwrap();
            let d = ok(&line);
            assert_eq!(d.candidate_type, c.candidate_type, "{line}");
            assert_eq!(d.transport_addr, c.transport_addr, "{line}");
            assert_eq!(d.component_id, c.component_id, "{line}");
            assert_eq!(d.priority(), c.priority(), "{line}");
            assert_eq!(d.foundation, wire_foundation(&c.foundation), "{line}");
            let exposes = expose_base && matches!(c.candidate_type, CandidateType::ServerReflexive | CandidateType::PeerReflexive);
            assert_eq!(d.base_addr, if exposes { c.base_addr } else { c.transport_addr }, "{line}");
        }
    }
}

#[test]
fn a_decoded_candidate_encodes_back_to_the_same_line() {
    // So a B2BUA that relays a description does not change it.
    let mut r = Rng(0xC0FFEE);
    for _ in 0..1000 {
        let c = random_candidate(&mut r);
        let line = encode_candidate(&c, EncodeOptions { expose_base: true }).unwrap();
        assert_eq!(encode_candidate(&ok(&line), EncodeOptions { expose_base: true }).unwrap(), line);
    }
}

// ─── Robustness ────────────────────────────────────────────────────

#[test]
fn mutated_lines_never_panic_and_anything_accepted_is_sane() {
    let mut r = Rng(0xDEAD_BEEF);
    let mut accepted = 0;
    for _ in 0..4000 {
        let c = random_candidate(&mut r);
        let mut bytes = encode_candidate(&c, EncodeOptions { expose_base: r.below(2) == 0 }).unwrap().into_bytes();
        for _ in 0..1 + r.below(3) {
            if bytes.is_empty() { break; }
            let i = r.below(bytes.len() as u64) as usize;
            match r.below(5) {
                0 => { bytes.remove(i); }
                1 => bytes.insert(i, [b' ', b':', b'.', b'0', 0xC3, 0x01, b'-', b'%'][r.below(8) as usize]),
                2 => bytes[i] = b"0123456789abcdef: ."[r.below(18) as usize],
                3 => bytes.truncate(i),
                _ => { let dup = bytes[i..bytes.len().min(i + 6)].to_vec(); bytes.extend(dup); }
            }
        }
        let Ok(line) = String::from_utf8(bytes) else { continue };
        if let Ok(d) = decode_candidate(&line) {
            accepted += 1;
            assert!((1..=(1 << 31) - 1).contains(&d.priority()), "{line:?}");
            assert!(d.transport_addr.port() != 0 && d.component_id != 0, "{line:?}");
            let again = ok(&encode_candidate(&d, EncodeOptions { expose_base: true }).unwrap());
            assert_eq!((again.transport_addr, again.priority(), again.candidate_type), (d.transport_addr, d.priority(), d.candidate_type), "{line:?}");
        }
    }
    assert!(accepted > 100, "the mutations must leave some lines valid, or this tests nothing ({accepted})");
}

// ─── A whole description ───────────────────────────────────────────

const OFFER: &str = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=ice-ufrag:8hhy\r\n\
a=ice-pwd:asd88fgpdd777uzjYhagZg\r\n\
a=ice-options:trickle\r\n\
a=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host\r\n\
a=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.1.1 rport 8998\r\n\
a=candidate:3 1 tcp 1518280447 10.0.1.1 9 typ host tcptype active\r\n\
a=candidate:4 1 UDP 2113937151 9f3a1c2e-1111-4222-8333-444455556666.local 54321 typ host\r\n\
a=end-of-candidates\r\n";

#[test]
fn a_description_is_parsed_and_unusable_candidates_are_skipped_and_counted() {
    let d = parse_ice_attributes(OFFER).unwrap();
    assert_eq!(d.ufrag.as_deref(), Some("8hhy"));
    assert_eq!(d.pwd.as_deref(), Some("asd88fgpdd777uzjYhagZg"));
    assert!(d.trickle && d.end_of_candidates && !d.lite);
    assert_eq!(d.candidates.len(), 2);
    assert_eq!(d.skipped, vec![Skip::Transport("tcp".into()), Skip::Hostname("9f3a1c2e-1111-4222-8333-444455556666.local".into())]);
    let creds = d.credentials().unwrap();
    assert_eq!((creds.ufrag.as_str(), creds.password.len()), ("8hhy", 22));
}

#[test]
fn line_endings_may_be_lf_or_crlf_and_other_lines_are_ignored() {
    let lf = OFFER.replace("\r\n", "\n");
    assert_eq!(parse_ice_attributes(&lf).unwrap(), parse_ice_attributes(OFFER).unwrap());
}

#[test]
fn a_description_survives_being_formatted_and_parsed_again() {
    let mut d = parse_ice_attributes(OFFER).unwrap();
    d.lite = true;
    let text = format_ice_attributes(&d, EncodeOptions { expose_base: true }).unwrap();
    assert!(text.ends_with("a=end-of-candidates\r\n") && text.lines().all(|l| l.starts_with("a=")));
    let back = parse_ice_attributes(&text).unwrap();
    assert!(back.lite && back.trickle && back.end_of_candidates);
    assert_eq!((back.ufrag, back.pwd), (d.ufrag, d.pwd));
    assert_eq!(back.candidates.len(), d.candidates.len());
    assert!(back.skipped.is_empty(), "what was skipped on the way in is simply not written back");
}

#[test]
fn credentials_are_held_to_the_rfc_lengths_and_characters() {
    let line = |name: &str, v: &str| format!("a={name}:{v}\r\n");
    for (name, v) in [("ice-ufrag", "abc"), ("ice-ufrag", "ab cd"), ("ice-ufrag", "ab-cd"), ("ice-pwd", "p21p21p21p21p21p21p21"), ("ice-pwd", "pass-word-pass-word-1234")] {
        assert!(matches!(parse_ice_attributes(&line(name, v)), Err(SdpError::Credential(_))), "{name}={v}");
    }
    assert!(parse_ice_attributes(&line("ice-ufrag", "abcd")).is_ok());
    assert!(parse_ice_attributes(&line("ice-ufrag", &"u".repeat(256))).is_ok());
    assert!(parse_ice_attributes(&line("ice-ufrag", &"u".repeat(257))).is_err());
    assert!(parse_ice_attributes(&line("ice-pwd", &"p".repeat(22))).is_ok());
}

#[test]
fn a_second_ufrag_or_password_is_an_error() {
    let two = "a=ice-ufrag:abcd\r\na=ice-ufrag:efgh\r\n";
    assert_eq!(parse_ice_attributes(two), Err(SdpError::Duplicate("ice-ufrag")));
    let two = format!("a=ice-pwd:{0}\r\na=ice-pwd:{0}\r\n", "p".repeat(22));
    assert_eq!(parse_ice_attributes(&two), Err(SdpError::Duplicate("ice-pwd")));
}

#[test]
fn a_malformed_candidate_fails_the_description_and_names_its_line() {
    let sdp = "a=ice-ufrag:abcd\r\na=candidate:1 1 UDP 1 10.0.1.1 8998 typ host\r\na=candidate:2 1 UDP 0 10.0.1.2 8998 typ host\r\n";
    assert_eq!(parse_ice_attributes(sdp), Err(SdpError::Candidate { line: 3, why: "priority range" }));
}

#[test]
fn the_size_limits_hold() {
    let many: String = (0..MAX_CANDIDATES + 1).map(|i| format!("a=candidate:{i} 1 UDP 1 10.0.{}.{} 5000 typ host\r\n", i / 250, i % 250 + 1)).collect();
    assert_eq!(parse_ice_attributes(&many), Err(SdpError::TooManyCandidates));
    assert_eq!(parse_ice_attributes(&format!("a=ice-ufrag:{}\r\n", "u".repeat(MAX_LINE))), Err(SdpError::LineTooLong(1)));
    assert_eq!(parse_ice_attributes(&"x".repeat(MAX_INPUT + 1)), Err(SdpError::InputTooLarge));
    let at_limit: String = (0..MAX_CANDIDATES).map(|i| format!("a=candidate:{i} 1 UDP 1 10.0.{}.{} 5000 typ host\n", i / 250, i % 250 + 1)).collect();
    assert_eq!(parse_ice_attributes(&at_limit).unwrap().candidates.len(), MAX_CANDIDATES);
}

#[test]
fn long_lines_that_are_not_ice_attributes_are_not_our_business() {
    let sdp = format!("a=fmtp:111 {}\r\na=ice-ufrag:abcd\r\n", "x=1;".repeat(2000));
    assert_eq!(parse_ice_attributes(&sdp).unwrap().ufrag.as_deref(), Some("abcd"));
}

// ─── Two agents that know each other only through SDP text ─────────

#[tokio::test]
async fn two_agents_complete_ice_knowing_each_other_only_through_sdp_text() {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
    let host = |addr| Candidate::new(CandidateType::Host, addr, addr, 65535, 1);
    let describe = |addr, ufrag: &str, pwd: &str| IceDescription {
        ufrag: Some(ufrag.into()), pwd: Some(pwd.into()), candidates: vec![host(addr)], ..Default::default()
    };
    let (pwd_a, pwd_b) = ("aPasswordaPassword0123456789", "bPasswordbPassword0123456789");

    // The offer, and an answer that also carries what a browser would send: a TCP
    // candidate and an mDNS hostname, neither of which can be used here.
    let offer = format_ice_attributes(&describe(addr_a, "aaaa", pwd_a), EncodeOptions::default()).unwrap();
    let answer = format_ice_attributes(&describe(addr_b, "bbbb", pwd_b), EncodeOptions::default()).unwrap()
        + "a=candidate:99 1 tcp 1518280447 192.0.2.99 9 typ host tcptype active\r\n"
        + "a=candidate:98 1 UDP 2113937151 9f3a1c2e-1111-4222-8333-444455556666.local 54321 typ host\r\n";

    // Each side knows its own candidates and learns the peer's from text alone.
    let (seen_by_b, seen_by_a) = (parse_ice_attributes(&offer).unwrap(), parse_ice_attributes(&answer).unwrap());
    assert_eq!((seen_by_a.candidates.len(), seen_by_a.skipped.len()), (1, 2), "the unusable candidates are skipped, not fatal");

    let config = || IceConfig {
        ta: Duration::from_millis(20), min_rto: Duration::from_millis(100), max_transmissions: 7,
        final_wait_multiplier: 16, nomination: Nomination::Regular { delay: Duration::from_millis(100) },
    };
    let mine = |ufrag: &str, pwd: &str| IceCredentials { ufrag: ufrag.into(), password: pwd.into() };
    let mut agent_a = IceAgent::new(config(), IceRole::Controlling, 100, mine("aaaa", pwd_a), seen_by_a.credentials().unwrap(), vec![host(addr_a)], seen_by_a.candidates.clone(), Instant::now());
    let mut agent_b = IceAgent::new(config(), IceRole::Controlled, 50, mine("bbbb", pwd_b), seen_by_b.credentials().unwrap(), vec![host(addr_b)], seen_by_b.candidates.clone(), Instant::now());

    let opts = DriveOptions { timeout: Duration::from_secs(20), linger: Duration::from_secs(1) };
    let (socks_a, socks_b) = ([Arc::clone(&sock_a)], [Arc::clone(&sock_b)]);
    let (ra, rb) = tokio::join!(
        run_agent(&mut agent_a, &socks_a, opts),
        run_agent(&mut agent_b, &socks_b, opts),
    );
    assert_eq!((ra, rb), (ChecklistState::Completed, ChecklistState::Completed));
    assert_eq!(agent_a.selected_pair().unwrap().pair.remote.transport_addr, addr_b, "A's checks went to the address B's SDP gave");
    assert_eq!(agent_b.selected_pair().unwrap().pair.remote.transport_addr, addr_a);
}

// ─── Fixtures from the independent oracle ──────────────────────────
//
// Generated by a separate implementation of the grammar; do not edit by hand.
// Each decode case is (input, the oracle's verdict).

const DECODE_FIXTURES: &[(&str, &str)] = &[
    ("  a=candidate:E2+ 96 Udp 1604904414 754f:947a:4595:36e2:899a:3327:95e:1cfa 46898 typ host ", "OK Host v6:754f947a459536e2899a3327095e1cfa 46898 96 1604904414 E2+ v6:754f947a459536e2899a3327095e1cfa:46898 43237"),
    ("\tcandidate:aC1bxd 95 Udp 1165838174 cae9:8712:a5ad:cb93:1773:a74a:bbf:bfc0 62835 typ host tcptype active", "OK Host v6:cae98712a5adcb931773a74a0bbfbfc0 62835 95 1165838174 aC1bxd v6:cae98712a5adcb931773a74a0bbfbfc0:62835 32071"),
    ("candidate:5  171  UDP  1940155593  dc12:dc10:7e4f:172e:7728:7045:df05:c3a5  59533  typ  host  generation  0  network-cost  999\n", "OK Host v6:dc12dc107e4f172e77287045df05c3a5 59533 171 1940155593 5 v6:dc12dc107e4f172e77287045df05c3a5:59533 42092"),
    ("candidate:e20aBcC453B9efay 57 Udp 1342123392 2868:2c8f:44ed:60d7:8fd4:31bd:86a1:1aa0 721 typ host ufrag abcd tcptype active", "OK Host v6:28682c8f44ed60d78fd431bd86a11aa0 721 57 1342123392 e20aBcC453B9efay v6:28682c8f44ed60d78fd431bd86a11aa0:721 65325"),
    ("\ta=candidate:a5E3adaA2B3d8AdC7ce2aC 193 Udp 932804030 90ba:20d3:9024:b983:79c7:5bc:a28e:5291 59201 typ host\r\n", "OK Host v6:90ba20d39024b98379c705bca28e5291 59201 193 932804030 a5E3adaA2B3d8AdC7ce2aC v6:90ba20d39024b98379c705bca28e5291:59201 39285"),
    ("candidate:FDF 190 UDP 535128189 43.246.206.252 5658 typ host", "OK Host v4:2bf6cefc 5658 190 535128189 FDF v4:2bf6cefc:5658 58728"),
    (" candidate:7aA7BDaz5x74cx/yzEy2f1A33/fbC0+ 98 uDP 1259273189 204.86.28.105 48216 typ host", "OK Host v4:cc561c69 48216 98 1259273189 7aA7BDaz5x74cx/yzEy2f1A33/fbC0+ v4:cc561c69:48216 3835"),
    ("candidate:CA192d4y83cc+648Fa29B/F9409/ 57 udp 63990535 197.108.166.80 6062 typ host network-id 3 network-cost 999", "OK Host v4:c56ca650 6062 57 63990535 CA192d4y83cc+648Fa29B/F9409/ v4:c56ca650:6062 53355"),
    ("candidate:2c779+Dz91c14cBe7d1E5Eb+cc441 11 Udp 582077182 210.193.56.68 44615 typ srflx raddr 85.63.117.230 rport 46236 network-id 3\r\n", "OK ServerReflexive v4:d2c13844 44615 11 582077182 2c779+Dz91c14cBe7d1E5Eb+cc441 v4:553f75e6:46236 45514"),
    ("\tcandidate:C3fCcED7 233 Udp 886937699 9b1:7c57:8ea9:9bb2:1b9c:12d7:9c63:c3b2 36485 typ srflx raddr 0.0.0.0 rport 0\r\n", "OK ServerReflexive v6:09b17c578ea99bb21b9c12d79c63c3b2 36485 233 886937699 C3fCcED7 v6:09b17c578ea99bb21b9c12d79c63c3b2:36485 56728"),
    ("\r\na=candidate:C5e+y 54 udp 1411748364 115.89.97.66 8958 typ srflx raddr 0.0.0.0 rport 0 network-id 3 generation 0 tcptype active\n", "OK ServerReflexive v4:73596142 8958 54 1411748364 C5e+y v4:73596142:8958 9618"),
    ("\tcandidate:z7c590+D3eczF++6 245 udp 1996000775 250.72.70.101 59828 typ srflx raddr 78.215.151.11 rport 23315 network-id 3 ufrag abcd network-id 3", "OK ServerReflexive v4:fa484665 59828 245 1996000775 z7c590+D3eczF++6 v4:4ed7970b:23315 63630"),
    ("\r\ncandidate:Fbf0Ad 51 uDP 884596365 238.159.226.23 52548 typ srflx raddr 0.0.0.0 rport 0", "OK ServerReflexive v4:ee9fe217 52548 51 884596365 Fbf0Ad v4:ee9fe217:52548 47582"),
    (" candidate:803cB5y2BF077c  70  Udp  365262443  a55d:cf8:d980:f5ee:df17:66d2:a188:ebe9  20565  typ  srflx  raddr  36.43.138.82  rport  43387  x-foo  bar  generation  0  network-cost  999", "OK ServerReflexive v6:a55d0cf8d980f5eedf1766d2a188ebe9 20565 70 365262443 803cB5y2BF077c v4:242b8a52:43387 50550"),
    ("\r\ncandidate:710/49 43 udp 1857831617 f6d9:3105:522d:e8e1:beac:ea7:e401:b4cd 53399 typ srflx x-foo bar\r\n", "OK ServerReflexive v6:f6d93105522de8e1beac0ea7e401b4cd 53399 43 1857831617 710/49 v6:f6d93105522de8e1beac0ea7e401b4cd:53399 48194"),
    ("\tcandidate:5/yb2 185 Udp 1913857136 b225:8a60:ebae:2d49:fc69:e9c0:af95:9e45 6864 typ srflx raddr 0.0.0.0 rport 0", "OK ServerReflexive v6:b2258a60ebae2d49fc69e9c0af959e45 6864 185 1913857136 5/yb2 v6:b2258a60ebae2d49fc69e9c0af959e45:6864 4900"),
    ("  a=candidate:Ce9cA66cDfyb9EFeA586bBae4b8 127 UDP 357610224 86.114.109.128 14252 typ prflx raddr 220.7.19.34 rport 27685 network-cost 999\n", "OK PeerReflexive v4:56726d80 14252 127 357610224 Ce9cA66cDfyb9EFeA586bBae4b8 v4:dc071322:27685 20658"),
    (" a=candidate:c2Adc3ca10Bz6ax9305y+ae1F9exaDFe 220 udp 496277290 65.238.191.206 39216 typ prflx raddr 0.0.0.0 rport 0 x-foo bar generation 0\r\n", "OK PeerReflexive v4:41eebfce 39216 220 496277290 c2Adc3ca10Bz6ax9305y+ae1F9exaDFe v4:41eebfce:39216 38039"),
    ("a=candidate:60+E+f49f5F83xxd1aA/20zC  173  UDP  1158784099  78d5:cbc2:eb5f:bf1a:f8c6:6c5a:e300:13e9  36448  typ  prflx  raddr  5df2:d67c:cf77:bb0e:def4:3565:642d:96fd  rport  43013\n", "OK PeerReflexive v6:78d5cbc2eb5fbf1af8c66c5ae30013e9 36448 173 1158784099 60+E+f49f5F83xxd1aA/20zC v6:5df2d67ccf77bb0edef43565642d96fd:43013 4516"),
    ("candidate:C+3y 9 Udp 81236814 213.116.93.225 54145 typ prflx x-foo bar generation 0 network-cost 999", "OK PeerReflexive v4:d5745de1 54145 9 81236814 C+3y v4:d5745de1:54145 55187"),
    (" candidate:axDEC 144 uDP 893259379 89d2:509d:88d:4b03:3401:b07f:b60:e3fe 27457 typ prflx raddr 0.0.0.0 rport 0 x-foo bar tcptype active x-foo bar\n", "OK PeerReflexive v6:89d2509d088d4b033401b07f0b60e3fe 27457 144 893259379 axDEC v6:89d2509d088d4b033401b07f0b60e3fe:27457 15886"),
    ("  candidate:Cdx 165 Udp 388555483 67.150.9.7 48578 typ prflx raddr 138.211.214.46 rport 19499\r\n", "OK PeerReflexive v4:43960907 48578 165 388555483 Cdx v4:8ad3d62e:19499 10466"),
    (" candidate:y8  121  UDP  1196491441  125.168.101.34  40964  typ  prflx  raddr  39.166.193.23  rport  42077  tcptype  active  network-id  3  ufrag  abcd", "OK PeerReflexive v4:7da86522 40964 121 1196491441 y8 v4:27a6c117:42077 20738"),
    ("a=candidate:dBaDCdEy+c3FcC3zFec93AD5A8d// 248 udp 1835509916 59.246.166.71 12359 typ prflx raddr 84.170.114.170 rport 59470", "OK PeerReflexive v4:3bf6a647 12359 248 1835509916 dBaDCdEy+c3FcC3zFec93AD5A8d// v4:54aa72aa:59470 26536"),
    ("a=candidate:d83CCe4+7bEzcF44/957aAyEEBzD1C 34 UDP 207798677 255.15.216.139 30033 typ relay raddr 0.0.0.0 rport 0 ufrag abcd\r\n", "OK Relayed v4:ff0fd88b 30033 34 207798677 d83CCe4+7bEzcF44/957aAyEEBzD1C v4:ff0fd88b:30033 25281"),
    ("candidate:y9c9cdzde0D7 197 uDP 1836742320 80.85.81.103 43811 typ relay raddr 22.64.202.160 rport 64575 tcptype active network-id 3", "OK Relayed v4:50555167 43811 197 1836742320 y9c9cdzde0D7 v4:50555167:43811 31350"),
    (" candidate:fb6aDy0/00 100 udp 2001047131 116.170.8.139 42752 typ relay raddr 0.0.0.0 rport 0\r\n", "OK Relayed v4:74aa088b 42752 100 2001047131 fb6aDy0/00 v4:74aa088b:42752 17806"),
    ("  candidate:CDbAa4c2xc2 43 UDP 922234304 161.244.78.97 29059 typ relay raddr dba9:a738:6b3c:3aac:e73e:8ed5:6a1e:8494 rport 58590 generation 0 tcptype active\n", "OK Relayed v4:a1f44e61 29059 43 922234304 CDbAa4c2xc2 v4:a1f44e61:29059 63533"),
    ("candidate:+d1FB+a/c/8a/38bABC5Dy8044x6 235 udp 1337186452 67.248.248.163 1583 typ relay raddr ae2f:4aab:1732:bff:4312:70fb:84d3:e1db rport 36962 network-cost 999 network-id 3\n", "OK Relayed v4:43f8f8a3 1583 235 1337186452 +d1FB+a/c/8a/38bABC5Dy8044x6 v4:43f8f8a3:1583 46040"),
    ("  candidate:3cF5fB7Ayd/b/aB6 241 Udp 1524629309 27.209.42.138 52383 typ relay raddr 146.151.93.24 rport 46284 x-foo bar x-foo bar network-cost 999", "OK Relayed v4:1bd12a8a 52383 241 1524629309 3cF5fB7Ayd/b/aB6 v4:1bd12a8a:52383 57343"),
    ("  candidate:AzxxD4E86EBb+F4bd9/C/FCEE709E 21 uDP 1401865585 37.77.135.68 17732 typ relay raddr 0.0.0.0 rport 0 tcptype active ", "OK Relayed v4:254d8744 17732 21 1401865585 AzxxD4E86EBb+F4bd9/C/FCEE709E v4:254d8744:17732 36549"),
    ("candidate:/bxFzD9C5  103  udp  807254303  234.113.20.68  24088  typ  relay  raddr  0.0.0.0  rport  0  x-foo  bar  tcptype  active", "OK Relayed v4:ea711444 24088 103 807254303 /bxFzD9C5 v4:ea711444:24088 7609"),
    ("candidate:czbbD 38 TCP 1157672444 65.207.242.217 24824 typ host generation 0 tcptype active", "UNSUPPORTED transport"),
    ("candidate:z2/fB45d8/+d 200 tcp 570840383 181.225.231.42 13191 typ relay raddr d09f:b040:8b3a:651f:5c92:15b2:7bce:c8a6 rport 20200 generation 0 ufrag abcd", "UNSUPPORTED transport"),
    ("candidate:/Dxf 221 dccp 1888587988 1.191.184.244 59091 typ host", "UNSUPPORTED transport"),
    ("candidate:eAEaD4aD54/fCxAy6B/y9ac4 244 uDP 1147960819 230.30.226.29 33405 typ foo x-foo bar ufrag abcd network-id 3", "UNSUPPORTED type"),
    ("candidate:e/Dc7E5CF75A/8B+2xd2 92 udp 1381895131 232.99.246.46 12550 typ x-new network-cost 999 x-foo bar x-foo bar", "UNSUPPORTED type"),
    ("candidate:f+8E 213 Udp 1306831269 110.105.94.145 10852 typ foo raddr e8d5:5cad:7bb8:dd85:f60b:a5c8:d955:1fd4 rport 34388", "UNSUPPORTED type"),
    ("candidate:75 200 udp 615461593 9f3a1c2e-1111-4222-8333-444455556666.local 35283 typ srflx raddr 0.0.0.0 rport 0 tcptype active generation 0", "UNSUPPORTED hostname"),
    ("candidate:84e34EDcEC3E9AFD 103 UDP 715475851 9f3a1c2e-1111-4222-8333-444455556666.local 21071 typ host x-foo bar generation 0 network-cost 999", "UNSUPPORTED hostname"),
    ("candidate:dBD+5FcbA6+x7EF+6 91 Udp 1874134496 a-b.example.com 33701 typ prflx raddr 144.92.206.23 rport 22992 generation 0", "UNSUPPORTED hostname"),
    ("candidate:C14Fb1yf 256 UDP 1118347925 42.72.81.53 26884 typ relay raddr 24e:e2be:117f:4d73:a7ac:1c69:b3f4:f4b0 rport 25410 tcptype active", "UNSUPPORTED component"),
    ("candidate:69A0Fbyyb19FA77F/x218yByfzcC4 256 uDP 300009504 240.229.231.198 58835 typ prflx raddr 145.238.61.91 rport 28064 generation 0 tcptype active ufrag abcd", "UNSUPPORTED component"),
    ("candidate:2cCdB/ 256 Udp 131646876 214.184.155.215 38824 typ relay raddr 12.127.143.234 rport 63525 tcptype active", "UNSUPPORTED component"),
    ("candidate:AACB6x16y/+ 6 UDP 511573835 109.220.103.233 46103 typ (x) raddr 541d:9343:86bc:e73f:acd6:3f3a:ac23:ef74 rport 35397", "MALFORMED"),
    ("zb+8z 86 udp 1464267736 7940:44b8:d1ae:cc94:7752:ee0f:faf6:4422 38520 typ srflx raddr 0.0.0.0 rport 0 x-foo bar generation 0 ufrag abcd lonely", "MALFORMED"),
    ("candidat:6A7fA8A18F18azDd2d61+xcCF8 103 udp 1400009113 234.192.231.169 -1 typ relay x-foo bar network-cost 999", "MALFORMED"),
    ("candidate:/+7xa50A1yaa5 66 uDP 4294967295 192.233.249.82 58006 typ srflx raddr 70.113.63.173 rport 38868 tcptype active tcptype active", "MALFORMED"),
    ("candidate:5E/yzE+f3e 70 UDP 1888963439 50.12.152.116 abc typ host generation 0 network-cost 999 ufrag abcd", "MALFORMED"),
    ("candidat:edA472ydC//7 129 UDP 567482653 18.72.51.108 +80 typ srflx raddr 0.0.0.0 rport 0 generation 0 x-foo bar", "MALFORMED"),
    ("candidate:19 0 UDP 233302142 202.116.200.154 48201 typ relay raddr 0.0.0.0 rport 0 x-foo bar ufrag abcd", "MALFORMED"),
    ("candidat:! 140 Udp 1301163995 3d3d:930c:9a40:708f:af50:324b:20a1:84fd 48803 typ host network-id 3 network-id 3", "MALFORMED"),
    ("Candidate:dBaaEA5db1z9fdE/Axfx8c20A+Eca 252 uDP 1694360707 51.225.39.111 45822 typ relay raddr 0.0.0.0 rport 0 raddr 82.97.172.233 raddr 160.217.98.147", "MALFORMED"),
    ("candidate:udp 147 rport 9482 50.165.175.233 typ 6dy1y2xCAC25 prflx 632767107 20426 raddr 29a1:fd:25da:95fa:6057:bc3:acb2:18de", "MALFORMED"),
    ("candidate:/y+0x45zx 210 uDP 894151827 34d1:79ba:97e8:5fee:a096:4a88:fc03:ee40 25783 typ host x-foo bar network-cost 999 x-foo bar raddr 1.2.3.4 rport 1.5", "MALFORMED"),
    ("1783b+Acf840D5087FcC/FxB 192 udp 1001345996 217.138.150.141 50980 typ srflx raddr 249.198.28.132 rport 27040 lonely", "MALFORMED"),
    ("candidate:FFaC2aBy9CE3zbA8Ce7x49zA 78 udp 540793417 67.129.104.206", "MALFORMED"),
    ("8/0F2be+fd8/CBCF 107 Udp 1544944248 69.37.89.12 6008 typ relay raddr 255.105.134.181 rport 2574 raddr 181.239.23.105 raddr c5a4:4716:3787:fd6b:a8a9:5cee:edcd:e7e9", "MALFORMED"),
    ("candidate:a b 116 Udp 1046902409 51.213.12.190 13329 typ prflx raddr 48.54.35.171 rport 35719 network-id 3 tcptype active", "MALFORMED"),
    ("Candidate:7x41edxD++aFc6DB650370b9 201 UDP 827864068 219.26.115.114 10075 typ \u{e9} raddr 1cc2:e876:9655:256a:c46d:7f34:f709:12e2 rport 30912 network-cost 999", "MALFORMED"),
    ("", "MALFORMED"),
    ("Candidate:fCc3eCb6d4CbzDx6Ax+9E61Bez24 83 Udp 1820849785 0.88.53.154 50193 typ prflx raddr 6451:7059:b5a0:4ef:fcf5:380c:a2e1:88f2 rport 16130 tcptype active ufrag abcd raddr 1.2.3.4 rport 1.5", "MALFORMED"),
    ("a=candidate:Cy790cx79bDfae0/Ed 98 < 415474393 1225:23fc:4510:1522:b543:7a4c:b5ff:18bc 7890 typ prflx", "MALFORMED"),
    ("candidate:d32BeC8/e6d42y9E12x3b 215 udp 1351740805 a..b 38584 typ srflx raddr 0.0.0.0 rport 0", "MALFORMED"),
    ("candidat:byaf42 18 udp 613237472 145.203.14.111 55770 typ host network-cost 999 raddr 49.254.234.194 raddr d5db:6d70:da:fe39:3cc8:7f03:f0c9:c268", "MALFORMED"),
    ("candidate 1bdEc1ayFe44zC74f 32 uDP abc eb77:4496:7649:9ed7:ca1b:d39:cc9:f3c5 2862 typ prflx raddr 0.0.0.0 rport 0 x-foo bar tcptype active", "MALFORMED"),
    ("candidate:1\u{a0}1 UDP 1 1.2.3.4 5 typ host", "MALFORMED"),
    ("\u{a0}candidate:1 1 UDP 1 1.2.3.4 5 typ host\u{a0}", "MALFORMED"),
    (" ", "MALFORMED"),
    ("candidate:1 1 UDP 1 1.2.3.4 5 typ host\u{2028}", "MALFORMED"),
    ("CANDIDATE:1 1 UDP 1 1.2.3.4 5 typ host", "MALFORMED"),
    ("candidate:", "MALFORMED"),
    ("\t\t", "MALFORMED"),
    ("candidate:1 1 UDP 1 1.2.3.4 5 typ host\x00", "MALFORMED"),
    ("candidate:1 1 UDP 1 1.2.3.4 5 typ host\u{e9}", "MALFORMED"),
    ("a=", "MALFORMED"),
];

/// (type, ip, port, component, local preference, priority override, foundation override,
///  base ip, base port, expose the base, the oracle's encoding or error)
type EncodeFixture = (&'static str, &'static str, u16, u8, u16, Option<u32>, Option<&'static str>, &'static str, u16, bool, &'static str);
const ENCODE_FIXTURES: &[EncodeFixture] = &[
    ("prflx", "e3d7:905e:eb57:3a4a:2a20:6d05:4b7a:fc7b", 1, 1, 1673, Some(4294967295), Some("\u{e9}"), "fa38:9fd8:c810:40d9:ace9:d31b:b4da:8832", 0, true, "ERR Priority(4294967295)"),
    ("srflx", "70df:25b6:499f:1684:6f63:5851:86f3:32ee", 43761, 0, 0, None, None, "7a7d:54c1:de03:c4ca:3ad5:dc0:d2e3:6e16", 13643, true, "ERR Component(0)"),
    ("srflx", "245.128.121.241", 1, 2, 0, None, None, "9957:cb79:f4e4:70b6:7287:2ddd:a618:958a", 0, true, "candidate:6c04e136a42cf139 2 UDP 1677721854 245.128.121.241 1 typ srflx raddr 9957:cb79:f4e4:70b6:7287:2ddd:a618:958a rport 0"),
    ("srflx", "104.141.209.200", 65535, 255, 3889, None, None, "218.133.80.70", 0, true, "candidate:c7937ce472c4cb68 255 UDP 1678717185 104.141.209.200 65535 typ srflx raddr 218.133.80.70 rport 0"),
    ("relay", "218.67.171.134", 0, 2, 65535, Some(1807497421), Some("\u{e9}"), "bee:62c0:7660:fee6:bd73:12d1:5d3b:c07d", 41156, false, "ERR Port"),
    ("prflx", "44.153.155.77", 1, 1, 65535, Some(0), Some("5A0C/7Cxed8C6/yf12f92B+bbE1A"), "17.155.164.173", 3006, false, "ERR Priority(0)"),
    ("host", "116.148.182.50", 65535, 116, 21381, None, Some("x"), "79.138.169.190", 34325, true, "candidate:x 116 UDP 2119402892 116.148.182.50 65535 typ host"),
    ("prflx", "215.119.43.180", 26202, 2, 23149, None, Some("BzAzAAfybcD1/e"), "13.127.43.33", 0, false, "candidate:BzAzAAfybcD1/e 2 UDP 1851420158 215.119.43.180 26202 typ prflx raddr 0.0.0.0 rport 0"),
    ("prflx", "98eb:d755:8917:f4ea:85d1:18b0:bf3b:de3", 65535, 2, 23988, None, Some("x"), "9329:5552:14e2:5b8f:4bbf:bc2b:736a:80f6", 20949, true, "candidate:x 2 UDP 1851634942 98eb:d755:8917:f4ea:85d1:18b0:bf3b:de3 65535 typ prflx raddr 9329:5552:14e2:5b8f:4bbf:bc2b:736a:80f6 rport 20949"),
    ("relay", "164.199.235.9", 41282, 1, 0, None, Some("y/33974C6"), "194.98.35.138", 65535, true, "candidate:y/33974C6 1 UDP 255 164.199.235.9 41282 typ relay raddr 0.0.0.0 rport 0"),
    ("srflx", "e816:a83a:18fe:792d:1a5f:553f:6a21:d098", 65535, 1, 0, None, None, "e379:46d7:9430:5f9a:a29:900d:ce4b:8922", 31566, true, "candidate:6e1196677442ff2d 1 UDP 1677721855 e816:a83a:18fe:792d:1a5f:553f:6a21:d098 65535 typ srflx raddr e379:46d7:9430:5f9a:a29:900d:ce4b:8922 rport 31566"),
    ("srflx", "ae4a:c3a7:1f3f:3385:1309:9eb8:5076:9770", 65535, 255, 65535, None, Some("x"), "d603:2eea:f980:fe8d:9307:bcca:d54:a197", 65535, true, "candidate:x 255 UDP 1694498561 ae4a:c3a7:1f3f:3385:1309:9eb8:5076:9770 65535 typ srflx raddr d603:2eea:f980:fe8d:9307:bcca:d54:a197 rport 65535"),
    ("prflx", "143.175.218.21", 1, 1, 65535, None, Some("\u{e9}"), "d791:b0d7:e15a:1e77:89bd:9715:1b01:1454", 50286, true, "candidate:0ac21707b7181e01 1 UDP 1862270975 143.175.218.21 1 typ prflx raddr d791:b0d7:e15a:1e77:89bd:9715:1b01:1454 rport 50286"),
    ("prflx", "796e:3248:d3e6:2851:fd70:a7e9:9131:f288", 1, 2, 36876, None, Some("bad-found.ation"), "ed2f:d34:aa38:943c:72a2:db98:3c7e:8ba0", 0, true, "candidate:98a198491bf97cd6 2 UDP 1854934270 796e:3248:d3e6:2851:fd70:a7e9:9131:f288 1 typ prflx raddr ed2f:d34:aa38:943c:72a2:db98:3c7e:8ba0 rport 0"),
    ("srflx", "200.205.133.204", 64596, 1, 37526, None, Some("\u{e9}"), "106.193.125.4", 26166, false, "candidate:0ac21707b7181e01 1 UDP 1687328511 200.205.133.204 64596 typ srflx raddr 0.0.0.0 rport 0"),
    ("host", "148.146.204.15", 52459, 1, 0, None, Some("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"), "9af2:60d6:6393:25ec:e1a3:9e36:a70c:4386", 0, false, "candidate:909839184804b9dd 1 UDP 2113929471 148.146.204.15 52459 typ host"),
    ("prflx", "171.229.245.229", 32511, 1, 65535, None, Some("\u{e9}"), "66.95.231.154", 65535, false, "candidate:0ac21707b7181e01 1 UDP 1862270975 171.229.245.229 32511 typ prflx raddr 0.0.0.0 rport 0"),
    ("relay", "243.64.146.225", 40773, 255, 0, None, Some("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"), "42c8:e34e:21bc:d6c9:4e3d:2ba7:359e:64f6", 57446, true, "candidate:909839184804b9dd 255 UDP 1 243.64.146.225 40773 typ relay raddr 0.0.0.0 rport 0"),
    ("prflx", "853c:d27b:dfca:86a7:cf06:7f57:4d2f:55c2", 1588, 255, 0, None, Some("x"), "5cd5:545d:ffac:e765:f65e:656c:9c57:ac59", 0, false, "candidate:x 255 UDP 1845493761 853c:d27b:dfca:86a7:cf06:7f57:4d2f:55c2 1588 typ prflx raddr :: rport 0"),
    ("prflx", "6d36:c9a1:5c4f:3797:7227:193b:6c6b:37d9", 1, 95, 65535, None, Some("f7Ec2c06/BCxebDx7BA8E8a8"), "3133:cc71:c716:549:837a:5f03:3299:724", 28055, true, "candidate:f7Ec2c06/BCxebDx7BA8E8a8 95 UDP 1862270881 6d36:c9a1:5c4f:3797:7227:193b:6c6b:37d9 1 typ prflx raddr 3133:cc71:c716:549:837a:5f03:3299:724 rport 28055"),
    ("host", "144.1.51.182", 1, 1, 65535, None, Some("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"), "102.34.147.67", 51302, false, "candidate:909839184804b9dd 1 UDP 2130706431 144.1.51.182 1 typ host"),
    ("relay", "83.255.52.30", 1, 119, 42949, None, Some("x"), "8bca:ba81:b95:b345:c3f0:2942:32b2:8dc4", 21435, true, "candidate:x 119 UDP 10995081 83.255.52.30 1 typ relay raddr 0.0.0.0 rport 0"),
    ("prflx", "96.126.158.118", 51577, 1, 0, Some(1091802831), None, "206.44.114.138", 0, false, "candidate:e410b95cb97f51b6 1 UDP 1091802831 96.126.158.118 51577 typ prflx raddr 0.0.0.0 rport 0"),
    ("host", "6e8d:f835:f456:f48c:53c:dfcf:8490:a6f9", 1, 255, 47988, None, None, "25.236.216.67", 61650, false, "candidate:bae096305e246dfa 255 UDP 2126214145 6e8d:f835:f456:f48c:53c:dfcf:8490:a6f9 1 typ host"),
    ("host", "2e47:d2e3:5ce0:3adb:f679:f336:d9c5:9c91", 1, 255, 0, None, None, "9617:5f5e:1950:40c7:c751:965:5851:9a5c", 65535, false, "candidate:b32314c23a055fb8 255 UDP 2113929217 2e47:d2e3:5ce0:3adb:f679:f336:d9c5:9c91 1 typ host"),
    ("relay", "7817:9655:a7f7:6d7e:773f:9b0c:7206:a60", 31203, 124, 0, Some(934579373), Some("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"), "3238:a410:8a28:7d2d:8e97:482c:78ca:91a9", 0, true, "candidate:909839184804b9dd 124 UDP 934579373 7817:9655:a7f7:6d7e:773f:9b0c:7206:a60 31203 typ relay raddr :: rport 0"),
    ("relay", "209.234.138.116", 56541, 1, 13573, Some(2147483648), Some("x"), "55.244.175.56", 291, false, "ERR Priority(2147483648)"),
];

/// The verdict in the oracle's format, so a fixture can be compared as text.
fn verdict(line: &str) -> String {
    let hex = |ip: IpAddr| match ip {
        IpAddr::V4(a) => format!("v4:{}", a.octets().iter().map(|b| format!("{b:02x}")).collect::<String>()),
        IpAddr::V6(a) => format!("v6:{}", a.octets().iter().map(|b| format!("{b:02x}")).collect::<String>()),
    };
    match decode_candidate(line) {
        Ok(c) => format!(
            "OK {:?} {} {} {} {} {} {}:{} {}",
            c.candidate_type, hex(c.transport_addr.ip()), c.transport_addr.port(), c.component_id, c.priority(),
            c.foundation, hex(c.base_addr.ip()), c.base_addr.port(), c.local_preference,
        ),
        Err(DecodeError::Unsupported(Skip::Transport(_))) => "UNSUPPORTED transport".into(),
        Err(DecodeError::Unsupported(Skip::CandidateType(_))) => "UNSUPPORTED type".into(),
        Err(DecodeError::Unsupported(Skip::Hostname(_))) => "UNSUPPORTED hostname".into(),
        Err(DecodeError::Unsupported(Skip::Component(_))) => "UNSUPPORTED component".into(),
        Err(DecodeError::Malformed(_)) => "MALFORMED".into(),
    }
}

#[test]
fn decoding_agrees_with_the_independent_oracle_on_every_fixture() {
    for (input, expected) in DECODE_FIXTURES {
        assert_eq!(&verdict(input), expected, "input {input:?}");
    }
    assert!(DECODE_FIXTURES.len() >= 76, "the fixture table must not shrink silently");
}

#[test]
fn encoding_agrees_with_the_independent_oracle_on_every_fixture() {
    for (t, ip, port, comp, pref, ov, fnd, bip, bport, expose, expected) in ENCODE_FIXTURES {
        let kind = match *t {
            "host" => CandidateType::Host, "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive, _ => CandidateType::Relayed,
        };
        let mut c = Candidate::new(kind, SocketAddr::new(ip.parse().unwrap(), *port), SocketAddr::new(bip.parse().unwrap(), *bport), *pref, *comp);
        c.priority_override = *ov;
        if let Some(f) = fnd { c.foundation = f.to_string(); }
        let got = match encode_candidate(&c, EncodeOptions { expose_base: *expose }) {
            Ok(s) => s,
            Err(e) => format!("ERR {e:?}"),
        };
        assert_eq!(&got, expected, "spec {t} {ip}:{port} comp {comp} pref {pref} override {ov:?} foundation {fnd:?}");
    }
    assert!(ENCODE_FIXTURES.len() >= 27);
}
