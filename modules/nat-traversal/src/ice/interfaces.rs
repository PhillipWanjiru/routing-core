//! Discovering the host's own addresses, and turning them into host candidates.
//!
//! Two halves, kept apart on purpose:
//!
//! * **Selection is pure.** [`select_host_addresses`] takes a list of interface
//!   addresses and a [`HostPolicy`] and decides which become candidates, in what
//!   order and with what local preference. It does no I/O, so every rule is tested
//!   with synthetic data on any machine.
//! * **Enumeration is the operating system's.** [`enumerate_interfaces`] asks the OS
//!   (`getifaddrs`). That is the only place in this crate that uses `unsafe`; the crate
//!   denies it everywhere else, and a test checks that.
//!
//! [`gather_host_sockets`] puts them together: it binds one UDP socket per selected
//! address and returns each with its host candidate.
//!
//! # What is, and is not, a candidate
//!
//! By default an address is offered only if its interface is up and running and it is
//! neither loopback nor link-local. Loopback addresses are useless to a peer on another
//! machine and disclose nothing useful; link-local IPv6 addresses cannot be used without
//! a scope id, which a candidate does not carry. Unspecified, multicast, broadcast and
//! IPv4-mapped IPv6 addresses are never candidates. An address held by several
//! interfaces is offered once.
//!
//! # Ordering
//!
//! RFC 8445 §5.1.2.2 asks that an agent with several addresses give them distinct local
//! preferences, so that candidate priorities, and hence the order of checks, are
//! deterministic. Preferences count down from 65535 in the order the addresses are
//! selected: native IPv6 first by default (RFC 6724's precedence), then IPv4, each family
//! in the order the OS reported. That is a simplification of RFC 6724's full rules.

use super::candidate::{Candidate, CandidateType};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// One address on one interface, as the operating system reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddr {
    pub name: String,
    pub ip: IpAddr,
    /// The interface is administratively up (`IFF_UP`).
    pub is_up: bool,
    /// The interface has a working link (`IFF_RUNNING`).
    pub is_running: bool,
    /// It is a loopback interface (`IFF_LOOPBACK`), whatever address it carries.
    pub is_loopback: bool,
}

/// Which addresses to offer, and in what order of preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicy {
    pub include_loopback: bool,
    /// Offer link-local addresses. An IPv6 link-local address cannot be bound without
    /// a scope id, so [`gather_host_sockets`] skips those even when this is set.
    pub include_link_local: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Give IPv6 addresses the higher local preferences.
    pub prefer_ipv6: bool,
}

impl Default for HostPolicy {
    fn default() -> Self {
        HostPolicy { include_loopback: false, include_link_local: false, ipv4: true, ipv6: true, prefer_ipv6: true }
    }
}

/// An address selected to become a host candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    pub ip: IpAddr,
    pub interface: String,
    pub local_preference: u16,
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// An address that is never a usable host candidate whatever the policy.
fn is_never_a_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast() || a.to_ipv4_mapped().is_some(),
    }
}

/// Decide which of `all` become host candidates, and with what local preference.
pub fn select_host_addresses(all: &[InterfaceAddr], policy: &HostPolicy) -> Vec<HostAddress> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut chosen: Vec<&InterfaceAddr> = Vec::new();
    for a in all {
        let family_ok = if a.ip.is_ipv4() { policy.ipv4 } else { policy.ipv6 };
        let loopback = a.is_loopback || a.ip.is_loopback();
        let usable = a.is_up
            && a.is_running
            && family_ok
            && !is_never_a_candidate(a.ip)
            && (policy.include_loopback || !loopback)
            && (policy.include_link_local || !is_link_local(a.ip));
        if usable && seen.insert(a.ip) {
            chosen.push(a);
        }
    }

    // Stable: within a family, the order the OS reported.
    let first_family_is_v6 = policy.prefer_ipv6;
    chosen.sort_by_key(|a| a.ip.is_ipv6() != first_family_is_v6);

    chosen
        .into_iter()
        .enumerate()
        .map(|(i, a)| HostAddress {
            ip: a.ip,
            interface: a.name.clone(),
            // Distinct and descending from 65535; clamped at 1 only for an absurd number of addresses.
            local_preference: 65535u32.saturating_sub(i as u32).max(1) as u16,
        })
        .collect()
}

/// Ask the operating system for every address on every interface.
///
/// Unix only (`getifaddrs`); elsewhere it returns an [`io::ErrorKind::Unsupported`] error.
pub fn enumerate_interfaces() -> io::Result<Vec<InterfaceAddr>> {
    os::enumerate()
}

#[cfg(unix)]
mod os {
    //! The only `unsafe` in the crate. It is a thin wrapper that turns the C list into
    //! owned Rust values and frees the list on every path out.
    #![allow(unsafe_code)]

    use super::InterfaceAddr;
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Owns the list `getifaddrs` allocated, and frees it when dropped, so that every
    /// return path (including an early one) releases it exactly once.
    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a successful `getifaddrs` and is freed
                // only here, once, because `IfAddrs` is not `Clone` and is never copied.
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    pub(super) fn enumerate() -> io::Result<Vec<InterfaceAddr>> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid place to write one pointer. On success `getifaddrs`
        // stores a pointer to a list it allocated; on failure it stores nothing and we
        // return before using it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let list = IfAddrs(head);

        let mut out = Vec::new();
        let mut cursor = list.0;
        while !cursor.is_null() {
            // SAFETY: `cursor` is non-null and points at a node of the list that `list`
            // owns and keeps alive until this function returns. Nothing mutates the list.
            let node = unsafe { &*cursor };
            // SAFETY: `ifa_addr` is null or points at a valid `sockaddr` of the family it
            // declares, which is exactly what `ip_of` requires.
            if let Some(ip) = unsafe { ip_of(node.ifa_addr) } {
                if !node.ifa_name.is_null() {
                    // SAFETY: `ifa_name` is a NUL-terminated C string owned by the node.
                    let name = unsafe { CStr::from_ptr(node.ifa_name) }.to_string_lossy().into_owned();
                    let (is_up, is_running, is_loopback) = decode_flags(node.ifa_flags);
                    out.push(InterfaceAddr { name, ip, is_up, is_running, is_loopback });
                }
            }
            cursor = node.ifa_next;
        }
        Ok(out)
    }

    /// `(up, running, loopback)` from an interface's `IFF_*` flags. Pure, so every
    /// combination can be tested whatever interfaces the machine happens to have.
    pub(super) fn decode_flags(flags: libc::c_uint) -> (bool, bool, bool) {
        let has = |flag: libc::c_int| flags & (flag as libc::c_uint) != 0;
        (has(libc::IFF_UP), has(libc::IFF_RUNNING), has(libc::IFF_LOOPBACK))
    }

    /// The IP address in `sa`, for the two families we use; `None` for anything else
    /// (the link-layer entries Linux also reports) or for a null pointer.
    ///
    /// # Safety
    ///
    /// `sa` must be null, or valid for reads of the structure its `sa_family` names
    /// (`sockaddr_in` for `AF_INET`, `sockaddr_in6` for `AF_INET6`, and at least a
    /// `sockaddr` for anything else). It need not be aligned: every read below is an
    /// unaligned one, including the family, which `(*sa).sa_family` would not be.
    unsafe fn ip_of(sa: *const libc::sockaddr) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // `addr_of!` takes the field's address without creating a reference, and the read
        // makes no assumption about alignment.
        let family = std::ptr::read_unaligned(std::ptr::addr_of!((*sa).sa_family));
        match family as libc::c_int {
            libc::AF_INET => {
                let sin = std::ptr::read_unaligned(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let sin6 = std::ptr::read_unaligned(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        //! `ip_of` is tested with hand-built `sockaddr` structures rather than a real
        //! interface, so the IPv6 branch is exercised on a machine that has no IPv6, and
        //! each byte-order decision is checked against an independently built input.
        use super::*;
        use std::mem::{size_of, zeroed};

        fn sockaddr_in(octets: [u8; 4]) -> libc::sockaddr_in {
            // SAFETY: `sockaddr_in` is plain old data; all-zero is a valid value.
            let mut sin: libc::sockaddr_in = unsafe { zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            // The kernel stores the four octets in memory order: this builds that
            // representation directly, without the conversion `ip_of` is being checked on.
            sin.sin_addr.s_addr = u32::from_ne_bytes(octets);
            sin
        }

        fn sockaddr_in6(octets: [u8; 16]) -> libc::sockaddr_in6 {
            // SAFETY: `sockaddr_in6` is plain old data; all-zero is a valid value.
            let mut sin6: libc::sockaddr_in6 = unsafe { zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = octets;
            sin6
        }

        fn read<T>(sa: &T) -> Option<IpAddr> {
            // SAFETY: every caller passes a fully initialised `sockaddr_in` or `sockaddr_in6`.
            unsafe { ip_of(sa as *const T as *const libc::sockaddr) }
        }

        #[test]
        fn ipv4_is_read_in_network_byte_order() {
            assert_eq!(read(&sockaddr_in([192, 0, 2, 2])), Some("192.0.2.2".parse().unwrap()));
            assert_eq!(read(&sockaddr_in([1, 2, 3, 4])), Some("1.2.3.4".parse().unwrap()), "not 4.3.2.1");
            assert_eq!(read(&sockaddr_in([127, 0, 0, 1])), Some("127.0.0.1".parse().unwrap()));
        }

        #[test]
        fn ipv6_is_read_byte_for_byte() {
            let doc = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!(read(&sockaddr_in6(doc)), Some("2001:db8::1".parse().unwrap()));
            let ascending: [u8; 16] = std::array::from_fn(|i| i as u8);
            assert_eq!(read(&sockaddr_in6(ascending)), Some("1:203:405:607:809:a0b:c0d:e0f".parse().unwrap()), "no byte or group reversed");
            let mut link_local = [0u8; 16];
            link_local[0] = 0xfe;
            link_local[1] = 0x80;
            link_local[15] = 1;
            assert_eq!(read(&sockaddr_in6(link_local)), Some("fe80::1".parse().unwrap()));
        }

        #[test]
        fn each_interface_flag_maps_to_its_own_field_and_no_other() {
            let bit = |f: libc::c_int| f as libc::c_uint;
            assert_eq!(decode_flags(0), (false, false, false));
            assert_eq!(decode_flags(bit(libc::IFF_UP)), (true, false, false));
            assert_eq!(decode_flags(bit(libc::IFF_RUNNING)), (false, true, false));
            assert_eq!(decode_flags(bit(libc::IFF_LOOPBACK)), (false, false, true));
            assert_eq!(decode_flags(bit(libc::IFF_UP) | bit(libc::IFF_RUNNING)), (true, true, false), "an ordinary live interface");
            assert_eq!(decode_flags(bit(libc::IFF_UP) | bit(libc::IFF_RUNNING) | bit(libc::IFF_LOOPBACK)), (true, true, true), "lo");
            // Flags the OS sets that we do not read must not leak into the three we do.
            assert_eq!(decode_flags(bit(libc::IFF_BROADCAST) | bit(libc::IFF_MULTICAST) | bit(libc::IFF_POINTOPOINT)), (false, false, false));
        }

        #[test]
        fn other_address_families_and_null_are_ignored() {
            // SAFETY: `sockaddr` is plain old data; all-zero is a valid value.
            let mut other: libc::sockaddr = unsafe { zeroed() };
            other.sa_family = libc::AF_UNIX as libc::sa_family_t;
            assert_eq!(read(&other), None);
            #[cfg(target_os = "linux")]
            {
                other.sa_family = libc::AF_PACKET as libc::sa_family_t;
                assert_eq!(read(&other), None, "the link-layer entries Linux also reports");
            }
            // SAFETY: null is explicitly allowed by `ip_of`'s contract.
            assert_eq!(unsafe { ip_of(std::ptr::null()) }, None);
        }

        #[test]
        fn a_misaligned_sockaddr_is_read_correctly() {
            // Read through an odd address, as `read_unaligned` exists to allow.
            let sin6 = sockaddr_in6(std::array::from_fn(|i| 0xa0 + i as u8));
            let mut buf = vec![0u8; size_of::<libc::sockaddr_in6>() + 8];
            // SAFETY: the destination has room for the struct at offset 1, and the two
            // buffers do not overlap.
            let ptr = unsafe {
                std::ptr::copy_nonoverlapping(&sin6 as *const _ as *const u8, buf.as_mut_ptr().add(1), size_of::<libc::sockaddr_in6>());
                buf.as_ptr().add(1) as *const libc::sockaddr
            };
            // SAFETY: `ptr` points at a complete, initialised `sockaddr_in6`.
            assert_eq!(unsafe { ip_of(ptr) }, Some("a0a1:a2a3:a4a5:a6a7:a8a9:aaab:acad:aeaf".parse().unwrap()));
        }
    }
}

#[cfg(not(unix))]
mod os {
    use super::InterfaceAddr;
    use std::io;

    pub(super) fn enumerate() -> io::Result<Vec<InterfaceAddr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "interface enumeration is implemented for unix only"))
    }
}

/// A bound socket and the host candidate that names it.
#[derive(Debug, Clone)]
pub struct HostSocket {
    pub socket: Arc<UdpSocket>,
    pub candidate: Candidate,
    /// The interface the address came from.
    pub interface: String,
}

/// Bind one UDP socket per selected address, on an ephemeral port, and return each with
/// its host candidate (component 1).
///
/// An address that cannot be bound (an IPv6 address still tentative, one that has since
/// been removed, or a link-local one with no scope id) is skipped rather than failing the
/// whole gather: the remaining addresses are still worth offering.
pub async fn bind_host_sockets(selected: &[HostAddress]) -> Vec<HostSocket> {
    let mut out = Vec::new();
    for h in selected {
        let socket = match UdpSocket::bind(SocketAddr::new(h.ip, 0)).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::debug!(ip = %h.ip, interface = %h.interface, error = %e, "cannot bind a host candidate; skipping it");
                continue;
            }
        };
        let Ok(addr) = socket.local_addr() else {
            continue;
        };
        out.push(HostSocket {
            socket: Arc::new(socket),
            candidate: Candidate::new(CandidateType::Host, addr, addr, h.local_preference, 1),
            interface: h.interface.clone(),
        });
    }
    out
}

/// Discover the host's addresses, select the ones to offer under `policy`, and bind a
/// socket for each: [`enumerate_interfaces`], [`select_host_addresses`] and
/// [`bind_host_sockets`] in turn.
pub async fn gather_host_sockets(policy: &HostPolicy) -> io::Result<Vec<HostSocket>> {
    Ok(bind_host_sockets(&select_host_addresses(&enumerate_interfaces()?, policy)).await)
}
