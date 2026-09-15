//! TURN allocation lifecycle (RFC 5766 §6-7).
//!
//! An allocation reserves a relay port on this server for one
//! authenticated client, valid for a limited lifetime that the client
//! must periodically refresh or the allocation is released back to the
//! pool. This is the mechanism that actually solves the symmetric-NAT
//! problem: once allocated, the relay port becomes a stable rendezvous
//! address that any peer can send media to, forwarded on to the client
//! regardless of what NAT sits in front of either side.
//!
//! # Lifetime model (RFC 5766 §2.2, §7)
//!
//! - Default lifetime if the client doesn't request one: 600 seconds.
//! - A client may request a specific lifetime via the LIFETIME
//!   attribute; the server may grant it as-is or cap it — this
//!   implementation caps at `MAX_LIFETIME_SECS` (3600s) to bound how
//!   long an abandoned allocation can hold a port before a sweep clears
//!   it, even if a client crashes without ever sending a Refresh.
//! - A Refresh request with LIFETIME=0 is an explicit deallocation
//!   request, not an error — RFC 5766 §7 requires a Success Response
//!   confirming it, same as any other refresh.
//!
//! # Why this is a separate module from `turn::auth`
//!
//! Authentication answers "is this request from who it claims to be."
//! Allocation answers "does this authenticated client get a relay port,
//! and for how long." Keeping them separate means allocation logic never
//! has to know anything about MD5/HMAC/nonces, and auth logic never has
//! to know anything about port pools — the same separation of concerns
//! this project has held since `sip::transaction` and `sip::dialog` were
//! split apart in Phase 2.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Default allocation lifetime when a client doesn't request one
/// (RFC 5766 §2.2).
pub const DEFAULT_LIFETIME_SECS: u32 = 600;

/// Server-side cap on any requested lifetime. RFC 5766 permits a server
/// to grant less than requested; this bounds how long a port can be
/// held by an allocation whose owner never sends a Refresh (e.g. crashed
/// or lost network) before a sweep reclaims it.
pub const MAX_LIFETIME_SECS: u32 = 3600;

/// A lifetime of exactly zero is a Refresh request's way of saying
/// "deallocate me now" (RFC 5766 §7), not "give me a zero-second
/// allocation."
const DEALLOCATE_LIFETIME: u32 = 0;

// ─── Relay port pool ───────────────────────────────────────────

/// Manages a contiguous range of relay ports as a free/in-use set.
///
/// A `Vec<bool>` bitset indexed by `port - range_start` is deliberately
/// simple here: for the default range (49152-65535, ~16K ports) this is
/// 16KB of memory and O(n) worst-case allocation — entirely adequate for
/// a single-node server. A production deployment handling thousands of
/// concurrent allocations would want a free-list instead of a linear
/// scan; that optimisation is not this milestone's concern.
pub struct PortPool {
    range_start: u16,
    in_use: Vec<bool>,
}

impl PortPool {
    /// Create a pool over `[range_start, range_end]` inclusive.
    pub fn new(range_start: u16, range_end: u16) -> Self {
        let size = (range_end as usize).saturating_sub(range_start as usize) + 1;
        PortPool {
            range_start,
            in_use: vec![false; size],
        }
    }

    /// The IANA-recommended default ephemeral/dynamic port range, also
    /// what most TURN deployments use for relay ports.
    pub fn default_range() -> Self {
        PortPool::new(49152, 65535)
    }

    /// Reserve the first free port. Returns `None` if the pool is
    /// exhausted — callers must handle this cleanly (RFC 5766 §6.2:
    /// respond with error code 508 Insufficient Capacity), not panic.
    pub fn allocate(&mut self) -> Option<u16> {
        let idx = self.in_use.iter().position(|&used| !used)?;
        self.in_use[idx] = true;
        Some(self.range_start.wrapping_add(idx as u16))
    }

    /// Release a previously-allocated port back to the pool. A port
    /// outside this pool's range, or already free, is silently ignored —
    /// callers should not be able to cause a panic by double-releasing.
    pub fn release(&mut self, port: u16) {
        if let Some(idx) = self.index_of(port) {
            self.in_use[idx] = false;
        }
    }

    /// Number of ports currently in use.
    pub fn in_use_count(&self) -> usize {
        self.in_use.iter().filter(|&&used| used).count()
    }

    /// Total pool capacity.
    pub fn capacity(&self) -> usize {
        self.in_use.len()
    }

    fn index_of(&self, port: u16) -> Option<usize> {
        let idx = port.checked_sub(self.range_start)? as usize;
        if idx < self.in_use.len() { Some(idx) } else { None }
    }
}

// ─── Allocation ──────────────────────────────────────────────────

/// One active TURN allocation.
#[derive(Debug, Clone)]
pub struct Allocation {
    pub client_addr:  SocketAddr,
    pub relay_port:   u16,
    pub created_at:   Instant,
    pub last_refresh: Instant,
    pub lifetime_secs: u32,
}

impl Allocation {
    /// Whether this allocation's lifetime has elapsed since it was last
    /// refreshed (or created, if never refreshed).
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_refresh) >= Duration::from_secs(self.lifetime_secs as u64)
    }

    /// Seconds remaining before expiry, or 0 if already expired.
    pub fn remaining_secs(&self, now: Instant) -> u32 {
        let elapsed = now.duration_since(self.last_refresh).as_secs();
        (self.lifetime_secs as u64).saturating_sub(elapsed) as u32
    }
}

/// Errors from allocation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocationError {
    /// The relay port pool has no free ports (RFC 5766 §6.2: respond
    /// with 508 Insufficient Capacity).
    PoolExhausted,
    /// A Refresh (or implicit re-Allocate) was received for a client
    /// address that has no existing allocation.
    NoSuchAllocation,
}

/// Tracks all active allocations, keyed by client address.
///
/// RFC 5766 §5 actually keys allocations by the 5-tuple (client IP,
/// client port, server IP, server port, transport) — this
/// implementation simplifies to client `SocketAddr` alone, since this
/// server only listens on one address/port for TURN and only supports
/// UDP transport for this milestone. A client requesting a second
/// allocation from a different local port would be indistinguishable
/// from the RFC's perspective anyway (different 5-tuple), so this
/// simplification does not change observable behaviour for the UDP-only
/// case this project currently supports.
pub struct AllocationTable {
    pool: PortPool,
    allocations: HashMap<SocketAddr, Allocation>,
    /// Reverse index so `sweep_expired` and capacity accounting don't
    /// need to scan the pool independently of the table.
    port_owner: HashMap<u16, SocketAddr>,
}

impl AllocationTable {
    pub fn new(pool: PortPool) -> Self {
        AllocationTable {
            pool,
            allocations: HashMap::new(),
            port_owner: HashMap::new(),
        }
    }

    /// Create a new allocation for `client_addr`.
    ///
    /// `requested_lifetime_secs` is the client's LIFETIME attribute
    /// value if present. The granted lifetime is
    /// `min(requested, MAX_LIFETIME_SECS)`, or `DEFAULT_LIFETIME_SECS`
    /// if the client didn't request one at all.
    ///
    /// If `client_addr` already has an active allocation, RFC 5766 §6.2
    /// treats a repeated Allocate as refreshing the existing one rather
    /// than creating a second — this implementation does the same,
    /// returning the existing allocation with its lifetime extended.
    pub fn create_or_refresh(
        &mut self,
        client_addr: SocketAddr,
        requested_lifetime_secs: Option<u32>,
        now: Instant,
    ) -> Result<Allocation, AllocationError> {
        let granted_lifetime = requested_lifetime_secs
            .map(|r| r.min(MAX_LIFETIME_SECS))
            .unwrap_or(DEFAULT_LIFETIME_SECS)
            .max(1); // A brand-new allocation always gets at least 1 second, even if
                     // the client's request was nonsensically low — 0 means deallocate,
                     // which only applies to Refresh on an *existing* allocation, not
                     // to first-time Allocate.

        if let Some(existing) = self.allocations.get_mut(&client_addr) {
            existing.last_refresh = now;
            existing.lifetime_secs = granted_lifetime;
            return Ok(existing.clone());
        }

        let relay_port = self.pool.allocate().ok_or(AllocationError::PoolExhausted)?;

        let allocation = Allocation {
            client_addr,
            relay_port,
            created_at: now,
            last_refresh: now,
            lifetime_secs: granted_lifetime,
        };

        self.allocations.insert(client_addr, allocation.clone());
        self.port_owner.insert(relay_port, client_addr);

        Ok(allocation)
    }

    /// Refresh an existing allocation. `requested_lifetime_secs = Some(0)`
    /// explicitly deallocates (RFC 5766 §7) — the port is released
    /// immediately and this returns `Ok` with the resulting granted
    /// lifetime of 0, not an error; the caller uses that 0 to build a
    /// Success Response confirming the deallocation, exactly as a
    /// non-zero refresh would confirm an extension.
    pub fn refresh(
        &mut self,
        client_addr: SocketAddr,
        requested_lifetime_secs: Option<u32>,
        now: Instant,
    ) -> Result<u32, AllocationError> {
        let Some(existing) = self.allocations.get_mut(&client_addr) else {
            return Err(AllocationError::NoSuchAllocation);
        };

        match requested_lifetime_secs {
            Some(DEALLOCATE_LIFETIME) => {
                let port = existing.relay_port;
                self.allocations.remove(&client_addr);
                self.port_owner.remove(&port);
                self.pool.release(port);
                Ok(DEALLOCATE_LIFETIME)
            }
            other => {
                let granted = other.map(|r| r.min(MAX_LIFETIME_SECS)).unwrap_or(DEFAULT_LIFETIME_SECS).max(1);
                existing.last_refresh = now;
                existing.lifetime_secs = granted;
                Ok(granted)
            }
        }
    }

    /// Look up the active allocation for a client, if any.
    pub fn get(&self, client_addr: &SocketAddr) -> Option<&Allocation> {
        self.allocations.get(client_addr)
    }

    /// Iterate over every active allocation as `(client_addr, allocation)`.
    ///
    /// Added for the relay data path, which receives data on a relay
    /// port and must resolve backwards to the owning client. The
    /// internal `port_owner` reverse index would serve this directly and
    /// in O(1), but is deliberately kept private — exposing it would
    /// leak an implementation detail that callers could come to depend
    /// on. If this linear scan ever shows up in profiling on the media
    /// hot path, the right fix is a dedicated `client_for_relay_port`
    /// method here, not widening access to the index.
    pub fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &Allocation)> {
        self.allocations.iter()
    }

    /// Release every allocation whose lifetime has elapsed as of `now`.
    /// Returns the client addresses that were swept, so a caller can log
    /// or otherwise react to them. Intended to be called periodically
    /// from a background task — this function itself has no timing
    /// logic, it is a single synchronous pass so it stays trivially
    /// testable without needing real elapsed wall-clock time.
    pub fn sweep_expired(&mut self, now: Instant) -> Vec<SocketAddr> {
        let expired: Vec<SocketAddr> = self.allocations
            .iter()
            .filter(|(_, a)| a.is_expired(now))
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &expired {
            if let Some(a) = self.allocations.remove(addr) {
                self.port_owner.remove(&a.relay_port);
                self.pool.release(a.relay_port);
            }
        }

        expired
    }

    /// Number of currently active (not-yet-expired-by-sweep) allocations.
    pub fn active_count(&self) -> usize {
        self.allocations.len()
    }

    /// Pool utilisation, for capacity monitoring.
    pub fn pool_in_use(&self) -> usize {
        self.pool.in_use_count()
    }

    pub fn pool_capacity(&self) -> usize {
        self.pool.capacity()
    }
}
