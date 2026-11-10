//! Discovering the host's addresses and turning them into host candidates.
//!
//! The decisions (what is a candidate, in what order, with what preference) are pure
//! and are tested with synthetic interface lists, so they behave the same on every
//! machine. The few tests that ask the real operating system assert only what must be
//! true anywhere. One test checks that `unsafe` really is confined to the one module
//! that needs it.

use nat_traversal::ice::interfaces::{
    bind_host_sockets, enumerate_interfaces, gather_host_sockets, select_host_addresses, HostAddress, HostPolicy, InterfaceAddr,
};
use nat_traversal::ice::sdp::{format_ice_attributes, parse_ice_attributes, EncodeOptions, IceDescription};
use nat_traversal::ice::{run_agent, CandidateType, ChecklistState, DriveOptions, IceAgent, IceConfig, IceCredentials, IceRole, Nomination};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
fn iface(name: &str, addr: &str, up: bool, running: bool, loopback: bool) -> InterfaceAddr {
    InterfaceAddr { name: name.into(), ip: ip(addr), is_up: up, is_running: running, is_loopback: loopback }
}
fn eth(name: &str, addr: &str) -> InterfaceAddr {
    iface(name, addr, true, true, false)
}
fn lo(addr: &str) -> InterfaceAddr {
    iface("lo", addr, true, true, true)
}
fn ips(selected: &[nat_traversal::ice::interfaces::HostAddress]) -> Vec<IpAddr> {
    selected.iter().map(|h| h.ip).collect()
}
fn all_on() -> HostPolicy {
    HostPolicy { include_loopback: true, include_link_local: true, ..HostPolicy::default() }
}

// ─── What is, and is not, a candidate ──────────────────────────────

#[test]
fn loopback_is_excluded_unless_asked() {
    let all = [lo("127.0.0.1"), lo("::1"), eth("eth0", "192.168.1.10")];
    assert_eq!(ips(&select_host_addresses(&all, &HostPolicy::default())), vec![ip("192.168.1.10")]);
    let with = HostPolicy { include_loopback: true, ..HostPolicy::default() };
    assert_eq!(select_host_addresses(&all, &with).len(), 3);
}

#[test]
fn a_loopback_interface_is_loopback_whatever_address_it_carries() {
    // A VIP or anycast address configured on `lo` is still only reachable locally.
    let all = [lo("10.1.1.1"), eth("eth0", "192.168.1.10")];
    assert_eq!(ips(&select_host_addresses(&all, &HostPolicy::default())), vec![ip("192.168.1.10")]);
}

#[test]
fn an_interface_that_is_down_or_has_no_link_offers_nothing() {
    let all = [
        iface("eth0", "192.168.1.10", true, false, false), // up, no carrier
        iface("eth1", "192.168.2.10", false, true, false), // administratively down
        eth("eth2", "192.168.3.10"),
    ];
    assert_eq!(ips(&select_host_addresses(&all, &all_on())), vec![ip("192.168.3.10")]);
}

#[test]
fn link_local_addresses_are_excluded_unless_asked() {
    // fe80::/10 covers fe80:: through febf::; fec0:: (site-local) is outside it.
    let all = [eth("eth0", "169.254.7.7"), eth("eth0", "fe80::1"), eth("eth0", "febf::1"), eth("eth0", "fec0::1"), eth("eth0", "192.168.1.10")];
    assert_eq!(ips(&select_host_addresses(&all, &HostPolicy::default())), vec![ip("fec0::1"), ip("192.168.1.10")]);
    assert_eq!(select_host_addresses(&all, &all_on()).len(), 5);
}

#[test]
fn unspecified_multicast_broadcast_and_mapped_addresses_are_never_candidates() {
    let all = [
        eth("eth0", "0.0.0.0"), eth("eth0", "224.0.0.1"), eth("eth0", "255.255.255.255"),
        eth("eth0", "::"), eth("eth0", "ff02::1"), eth("eth0", "::ffff:192.0.2.1"),
    ];
    assert!(select_host_addresses(&all, &all_on()).is_empty(), "not even with every permissive flag on");
}

#[test]
fn private_and_unique_local_addresses_are_kept() {
    let all = [eth("eth0", "10.0.0.1"), eth("eth0", "172.16.0.1"), eth("eth0", "192.168.0.1"), eth("eth0", "fd00::1")];
    assert_eq!(select_host_addresses(&all, &HostPolicy::default()).len(), 4, "a LAN address is exactly what a LAN peer needs");
}

#[test]
fn an_address_held_by_several_interfaces_is_offered_once() {
    let all = [eth("eth0", "192.168.1.10"), eth("br0", "192.168.1.10")];
    let s = select_host_addresses(&all, &HostPolicy::default());
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].interface, "eth0", "the first interface to report it wins");
}

#[test]
fn one_interface_with_two_addresses_offers_both() {
    let all = [eth("eth0", "192.168.1.10"), eth("eth0", "192.168.1.11")];
    assert_eq!(select_host_addresses(&all, &HostPolicy::default()).len(), 2);
}

#[test]
fn address_families_can_be_switched_off() {
    let all = [eth("eth0", "192.168.1.10"), eth("eth0", "fd00::1")];
    assert_eq!(ips(&select_host_addresses(&all, &HostPolicy { ipv6: false, ..HostPolicy::default() })), vec![ip("192.168.1.10")]);
    assert_eq!(ips(&select_host_addresses(&all, &HostPolicy { ipv4: false, ..HostPolicy::default() })), vec![ip("fd00::1")]);
}

#[test]
fn an_empty_interface_list_offers_nothing() {
    assert!(select_host_addresses(&[], &all_on()).is_empty());
}

// ─── Order and preference ──────────────────────────────────────────

#[test]
fn ipv6_comes_first_by_default_and_ipv4_when_asked_with_the_os_order_kept_within_a_family() {
    let all = [eth("eth0", "192.168.1.10"), eth("eth0", "fd00::1"), eth("eth1", "192.168.2.10"), eth("eth1", "fd00::2")];
    assert_eq!(
        ips(&select_host_addresses(&all, &HostPolicy::default())),
        vec![ip("fd00::1"), ip("fd00::2"), ip("192.168.1.10"), ip("192.168.2.10")]
    );
    assert_eq!(
        ips(&select_host_addresses(&all, &HostPolicy { prefer_ipv6: false, ..HostPolicy::default() })),
        vec![ip("192.168.1.10"), ip("192.168.2.10"), ip("fd00::1"), ip("fd00::2")]
    );
}

#[test]
fn local_preferences_are_distinct_and_count_down_from_65535() {
    let all = [eth("eth0", "192.168.1.10"), eth("eth0", "fd00::1"), eth("eth1", "192.168.2.10")];
    let prefs: Vec<u16> = select_host_addresses(&all, &HostPolicy::default()).iter().map(|h| h.local_preference).collect();
    assert_eq!(prefs, vec![65535, 65534, 65533], "RFC 8445 asks for distinct preferences so check order is deterministic");
}

#[test]
fn preferences_never_reach_zero_even_for_an_absurd_number_of_addresses() {
    let all: Vec<InterfaceAddr> = (0..70_000u32).map(|i| eth("eth0", &format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255))).collect();
    let s = select_host_addresses(&all, &HostPolicy::default());
    assert_eq!(s.len(), 70_000);
    assert!(s.iter().all(|h| h.local_preference >= 1), "a zero preference would collapse into the type preference");
    let distinct: HashSet<u16> = s.iter().take(65_535).map(|h| h.local_preference).collect();
    assert_eq!(distinct.len(), 65_535, "distinct for as long as that is possible");
}

// ─── The real operating system ─────────────────────────────────────

#[cfg(unix)]
#[test]
fn the_os_reports_a_loopback_interface_with_the_right_flags() {
    let all = enumerate_interfaces().expect("getifaddrs");
    let lo4 = all.iter().find(|a| a.ip == ip("127.0.0.1")).unwrap_or_else(|| panic!("no 127.0.0.1 in {all:?}"));
    assert!(lo4.is_loopback && lo4.is_up && lo4.is_running, "{lo4:?}");
    assert!(!lo4.name.is_empty());
    // Everything the OS reports for a loopback interface must be flagged as such, and
    // nothing that is not 127/8 or ::1 should be flagged by accident.
    for a in all.iter().filter(|a| a.ip.is_loopback()) {
        assert!(a.is_loopback, "{a:?}");
    }
}

#[cfg(unix)]
#[test]
fn enumeration_is_repeatable() {
    let first: HashSet<IpAddr> = enumerate_interfaces().unwrap().iter().map(|a| a.ip).collect();
    for _ in 0..200 {
        let again: HashSet<IpAddr> = enumerate_interfaces().unwrap().iter().map(|a| a.ip).collect();
        assert_eq!(again, first);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn gathered_sockets_are_bound_to_the_address_their_candidate_names() {
    let policy = HostPolicy { include_loopback: true, ..HostPolicy::default() };
    let gathered = gather_host_sockets(&policy).await.unwrap();
    assert!(!gathered.is_empty(), "with loopback included there is always something to bind");
    for g in &gathered {
        let bound = g.socket.local_addr().unwrap();
        assert_eq!(g.candidate.transport_addr, bound);
        assert_eq!(g.candidate.base_addr, bound, "a host candidate is its own base");
        assert_eq!(g.candidate.candidate_type, CandidateType::Host);
        assert_ne!(bound.port(), 0, "the ephemeral port the OS chose, not the 0 that was asked for");
        assert!(!g.interface.is_empty());
    }
    let prefs: HashSet<u16> = gathered.iter().map(|g| g.candidate.local_preference).collect();
    assert_eq!(prefs.len(), gathered.len(), "distinct local preferences");
}

#[cfg(unix)]
#[tokio::test]
async fn a_gathered_socket_really_receives_datagrams() {
    let gathered = gather_host_sockets(&HostPolicy { include_loopback: true, ..HostPolicy::default() }).await.unwrap();
    let g = gathered.iter().find(|g| g.candidate.transport_addr.ip() == ip("127.0.0.1")).expect("an IPv4 loopback socket");
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"hello", g.candidate.transport_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), g.socket.recv_from(&mut buf)).await.expect("received").unwrap();
    assert_eq!((&buf[..n], from), (&b"hello"[..], sender.local_addr().unwrap()));
}

#[cfg(unix)]
#[tokio::test]
async fn the_default_policy_gathers_without_error_and_never_offers_loopback() {
    // On a machine with no network at all this is legitimately empty.
    let gathered = gather_host_sockets(&HostPolicy::default()).await.unwrap();
    for g in &gathered {
        assert!(!g.candidate.transport_addr.ip().is_loopback(), "{:?}", g.candidate);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn two_agents_that_discover_their_own_addresses_and_exchange_sdp_complete_ice() {
    // The whole chain, with nothing hand-built: each side finds its addresses from the
    // OS, binds sockets, describes itself in SDP, learns about the other from SDP text
    // alone, and runs ICE.
    let policy = HostPolicy { include_loopback: true, ..HostPolicy::default() };
    let (ga, gb) = (gather_host_sockets(&policy).await.unwrap(), gather_host_sockets(&policy).await.unwrap());
    let describe = |g: &[nat_traversal::ice::interfaces::HostSocket], ufrag: &str, pwd: &str| IceDescription {
        ufrag: Some(ufrag.into()), pwd: Some(pwd.into()), candidates: g.iter().map(|h| h.candidate.clone()).collect(), ..Default::default()
    };
    let (pwd_a, pwd_b) = ("aPasswordaPassword0123456789", "bPasswordbPassword0123456789");
    let offer = format_ice_attributes(&describe(&ga, "aaaa", pwd_a), EncodeOptions::default()).unwrap();
    let answer = format_ice_attributes(&describe(&gb, "bbbb", pwd_b), EncodeOptions::default()).unwrap();
    let (seen_by_b, seen_by_a) = (parse_ice_attributes(&offer).unwrap(), parse_ice_attributes(&answer).unwrap());
    assert_eq!(seen_by_a.candidates.len(), gb.len(), "every address B discovered reached A through the text");

    let config = || IceConfig {
        ta: Duration::from_millis(20), min_rto: Duration::from_millis(100), max_transmissions: 7,
        final_wait_multiplier: 16, nomination: Nomination::Regular { delay: Duration::from_millis(100) },
    };
    let mine = |u: &str, p: &str| IceCredentials { ufrag: u.into(), password: p.into() };
    let mut agent_a = IceAgent::new(config(), IceRole::Controlling, 100, mine("aaaa", pwd_a), seen_by_a.credentials().unwrap(), ga.iter().map(|h| h.candidate.clone()).collect(), seen_by_a.candidates.clone(), Instant::now());
    let mut agent_b = IceAgent::new(config(), IceRole::Controlled, 50, mine("bbbb", pwd_b), seen_by_b.credentials().unwrap(), gb.iter().map(|h| h.candidate.clone()).collect(), seen_by_b.candidates.clone(), Instant::now());

    let (socks_a, socks_b): (Vec<Arc<UdpSocket>>, Vec<Arc<UdpSocket>>) =
        (ga.iter().map(|h| Arc::clone(&h.socket)).collect(), gb.iter().map(|h| Arc::clone(&h.socket)).collect());
    let opts = DriveOptions { timeout: Duration::from_secs(20), linger: Duration::from_secs(1) };
    let (ra, rb) = tokio::join!(run_agent(&mut agent_a, &socks_a, opts), run_agent(&mut agent_b, &socks_b, opts));
    assert_eq!((ra, rb), (ChecklistState::Completed, ChecklistState::Completed));
    assert!(agent_a.selected_pair().is_some() && agent_b.selected_pair().is_some());
}

#[cfg(unix)]
#[tokio::test]
async fn an_address_that_cannot_be_bound_is_skipped_not_fatal() {
    // 203.0.113.250 is not assigned to any interface here, so binding it fails; the
    // addresses either side of it must still be offered.
    let host = |addr: &str, pref: u16| HostAddress { ip: ip(addr), interface: "test".into(), local_preference: pref };
    let sockets = bind_host_sockets(&[host("127.0.0.1", 65535), host("203.0.113.250", 65534), host("127.0.0.1", 65533)]).await;
    assert_eq!(sockets.len(), 2, "one failure must not cost the others");
    assert_eq!(sockets.iter().map(|s| s.candidate.local_preference).collect::<Vec<_>>(), vec![65535, 65533], "and each keeps its own preference");
}

// ─── `unsafe` stays where it belongs ───────────────────────────────

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// True if a line of code (not a comment) uses `unsafe` or switches the lint off.
fn uses_unsafe(line: &str) -> bool {
    let code = line.trim_start();
    !code.starts_with("//") && ["unsafe {", "unsafe fn", "unsafe impl", "unsafe trait", "allow(unsafe_code)"].iter().any(|p| code.contains(p))
}

#[test]
fn unsafe_code_is_confined_to_the_interfaces_module() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 20, "the scan must actually find the source tree, or it checks nothing");

    let offenders: Vec<String> = files
        .iter()
        .filter(|f| !f.ends_with("ice/interfaces.rs"))
        .filter(|f| std::fs::read_to_string(f).unwrap().lines().any(uses_unsafe))
        .map(|f| f.display().to_string())
        .collect();
    assert!(offenders.is_empty(), "unsafe outside ice/interfaces.rs: {offenders:?}");

    for root in ["lib.rs", "main.rs"] {
        let text = std::fs::read_to_string(src.join(root)).unwrap();
        assert!(text.contains("#![deny(unsafe_code)]"), "{root} must deny unsafe so the compiler enforces this");
    }
}

#[test]
fn the_unsafe_scan_recognises_what_it_is_looking_for() {
    // A guard that matches nothing guards nothing.
    for bad in ["    unsafe { libc::free(p) };", "unsafe fn f() {}", "#![allow(unsafe_code)]", "unsafe impl Send for X {}"] {
        assert!(uses_unsafe(bad), "{bad:?}");
    }
    for fine in ["// no unsafe { blocks here }", "    //! `unsafe` is denied across the crate.", "let unsafely = 1;", "fn safe() {}"] {
        assert!(!uses_unsafe(fine), "{fine:?}");
    }
}
