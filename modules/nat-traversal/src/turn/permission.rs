//! TURN permission management (RFC 5766 §8).
//!
//! An allocation alone does not let any peer send data through the
//! relay — the client must explicitly install a permission for each
//! peer IP address it wants to exchange data with. Without this, anyone
//! who learns or guesses a client's relay port could inject arbitrary
//! traffic; permissions are what make TURN's relay a client-controlled
//! allowlist rather than an open forwarder.
//!
//! # Keyed by IP address only, not IP:port
//!
//! This is the detail most likely to be gotten wrong by copying the
//! shape of `AllocationTable` (which keys on a full `SocketAddr`): a
//! permission is per **peer IP address**, not per socket address. A
//! permission means "accept traffic from this peer's address, on
//! whatever port they send from." RFC 5766 §8 is explicit that the port
//! is deliberately excluded from the permission key, since a peer may
//! legitimately use different source ports across the lifetime of one
//! media session.
//!
//! # Lifetime is fixed, not negotiable
//!
//! Unlike an allocation's LIFETIME (client-requestable, server-capped),
//! a permission's lifetime is a flat 300 seconds (RFC 5766 §8) with no
//! attribute for a client to request otherwise. It refreshes to a full
//! 300 seconds on an explicit CreatePermission request, and — once the
//! relay data path exists — implicitly whenever a valid Send indication
//! or ChannelData message is sent to that peer. That implicit-refresh-
//! on-use call site does not exist yet in this codebase, since the
//! Send/Data relay path is the module after this one.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Fixed permission lifetime (RFC 5766 §8) — not client-negotiable,
/// unlike allocation LIFETIME.
pub const PERMISSION_LIFETIME_SECS: u64 = 300;

/// Tracks, per client allocation, which peer IP addresses that client
/// currently has permission to exchange data with.
///
/// Keyed `client_addr -> (peer_ip -> expiry)`. The outer key is the
/// client's full `SocketAddr` (matching how `AllocationTable` identifies
/// a client); the inner key is deliberately just `IpAddr`, per the
/// module-level note above.
pub struct PermissionTable {
    permissions: HashMap<SocketAddr, HashMap<IpAddr, Instant>>,
}

impl PermissionTable {
    pub fn new() -> Self {
        PermissionTable { permissions: HashMap::new() }
    }

    /// Install a permission for `peer_ip` under `client_addr`'s
    /// allocation, or refresh it to a fresh 300-second lifetime if one
    /// already exists.
    ///
    /// RFC 5766 §8 does not distinguish "create" from "refresh" here — a
    /// CreatePermission request naming an already-permitted peer simply
    /// extends it, which is exactly what this function does.
    pub fn create_or_refresh(&mut self, client_addr: SocketAddr, peer_ip: IpAddr, now: Instant) {
        let expiry = now + Duration::from_secs(PERMISSION_LIFETIME_SECS);
        self.permissions.entry(client_addr).or_default().insert(peer_ip, expiry);
    }

    /// Whether `client_addr` currently holds a valid (non-expired)
    /// permission for `peer_ip`.
    ///
    /// This is the check the future relay data path performs before
    /// forwarding a Data indication to the client, or before accepting a
    /// Send indication naming this peer.
    pub fn has_permission(&self, client_addr: &SocketAddr, peer_ip: &IpAddr, now: Instant) -> bool {
        self.permissions
            .get(client_addr)
            .and_then(|peers| peers.get(peer_ip))
            .map(|&expiry| now < expiry)
            .unwrap_or(false)
    }

    /// Remove every permission belonging to one client — called when
    /// that client's allocation is deallocated or swept as expired,
    /// since a permission without a backing allocation is meaningless
    /// (RFC 5766 §8: permissions exist only in the context of an
    /// allocation).
    pub fn clear_for_client(&mut self, client_addr: &SocketAddr) {
        self.permissions.remove(client_addr);
    }

    /// Remove only the individual peer entries whose lifetime has
    /// elapsed, leaving that client's still-valid permissions untouched.
    ///
    /// Finer granularity than `clear_for_client`, which removes
    /// everything for a client unconditionally regardless of individual
    /// peer expiry. Returns the number of individual (client, peer)
    /// entries removed.
    pub fn sweep_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        for peers in self.permissions.values_mut() {
            let before = peers.len();
            peers.retain(|_, &mut expiry| now < expiry);
            removed += before - peers.len();
        }
        // Drop client entries left with zero permissions, so empty inner
        // maps don't accumulate as dead weight over time.
        self.permissions.retain(|_, peers| !peers.is_empty());
        removed
    }

    /// Number of peer permissions currently tracked for one client.
    ///
    /// This is a raw count including not-yet-swept expired entries — it
    /// is not a "currently valid" count. Callers wanting validity should
    /// use `has_permission` per peer, or call `sweep_expired` first.
    pub fn permission_count_for(&self, client_addr: &SocketAddr) -> usize {
        self.permissions.get(client_addr).map(|p| p.len()).unwrap_or(0)
    }

    /// Number of clients with at least one tracked permission entry.
    pub fn client_count(&self) -> usize {
        self.permissions.len()
    }
}

impl Default for PermissionTable {
    fn default() -> Self {
        PermissionTable::new()
    }
}
