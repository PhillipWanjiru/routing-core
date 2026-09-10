//! TURN allocation lifecycle tests.
//!
//! Expiry/lifetime tests use caller-controlled `Instant` values rather
//! than real `sleep()` calls — `AllocationTable::create_or_refresh` and
//! `::refresh` both take `now: Instant` as an explicit parameter rather
//! than fetching it internally, specifically so expiry can be tested
//! deterministically: compute a "later" Instant via `Instant + Duration`
//! directly, no waiting required. Same pattern this project used for the
//! RTP jitter buffer tests (explicit `arrival_ms` values, not real time).

use nat_traversal::turn::{
    Allocation, AllocationError, AllocationTable, PortPool,
    DEFAULT_LIFETIME_SECS, MAX_LIFETIME_SECS,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

// ─── PortPool ──────────────────────────────────────────────────

#[test]
fn port_pool_allocates_distinct_ports() {
    let mut pool = PortPool::new(50000, 50010);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..5 {
        let p = pool.allocate().expect("pool should not be exhausted yet");
        assert!(seen.insert(p), "port {p} was allocated twice");
        assert!((50000..=50010).contains(&p), "port {p} out of range");
    }
}

#[test]
fn port_pool_exhausts_cleanly_not_panic() {
    let mut pool = PortPool::new(50000, 50001); // exactly 2 ports
    assert!(pool.allocate().is_some());
    assert!(pool.allocate().is_some());
    assert_eq!(pool.allocate(), None, "pool must return None, not panic, when exhausted");
    assert_eq!(pool.allocate(), None);
}

#[test]
fn port_pool_release_makes_port_available_again() {
    let mut pool = PortPool::new(50000, 50000); // exactly 1 port
    let p1 = pool.allocate().expect("first allocation should succeed");
    assert_eq!(pool.allocate(), None, "pool should be exhausted with 1 port taken");
    pool.release(p1);
    let p2 = pool.allocate().expect("port should be available again after release");
    assert_eq!(p1, p2, "the only port in this pool must be the one reused");
}

#[test]
fn port_pool_release_of_unowned_or_out_of_range_port_is_noop() {
    let mut pool = PortPool::new(50000, 50010);
    pool.release(50005);
    pool.release(9999);
    pool.release(60000);
    let mut count = 0;
    while pool.allocate().is_some() { count += 1; }
    assert_eq!(count, 11, "pool capacity must be unaffected by no-op releases");
}

#[test]
fn port_pool_in_use_count_tracks_allocations() {
    let mut pool = PortPool::new(50000, 50010);
    assert_eq!(pool.in_use_count(), 0);
    let p1 = pool.allocate().unwrap();
    assert_eq!(pool.in_use_count(), 1);
    let _p2 = pool.allocate().unwrap();
    assert_eq!(pool.in_use_count(), 2);
    pool.release(p1);
    assert_eq!(pool.in_use_count(), 1);
}

// ─── Allocation (direct struct tests) ─────────────────────────────

#[test]
fn allocation_is_expired_false_before_lifetime_elapses() {
    let now = Instant::now();
    let a = Allocation {
        client_addr: addr(1234), relay_port: 50000,
        created_at: now, last_refresh: now, lifetime_secs: 10,
    };
    let check_at = now + Duration::from_secs(5);
    assert!(!a.is_expired(check_at), "5s into a 10s lifetime must not be expired");
}

#[test]
fn allocation_is_expired_true_at_and_after_lifetime_boundary() {
    let now = Instant::now();
    let a = Allocation {
        client_addr: addr(1234), relay_port: 50000,
        created_at: now, last_refresh: now, lifetime_secs: 10,
    };
    let at_boundary = now + Duration::from_secs(10);
    let past_boundary = now + Duration::from_secs(11);
    assert!(a.is_expired(at_boundary), "exactly at the lifetime boundary must count as expired");
    assert!(a.is_expired(past_boundary));
}

#[test]
fn allocation_remaining_secs_saturates_at_zero_not_negative() {
    let now = Instant::now();
    let a = Allocation {
        client_addr: addr(1234), relay_port: 50000,
        created_at: now, last_refresh: now, lifetime_secs: 10,
    };
    let long_after = now + Duration::from_secs(1000);
    assert_eq!(a.remaining_secs(long_after), 0, "remaining_secs must saturate at 0, not underflow");
}

#[test]
fn allocation_remaining_secs_counts_down_correctly() {
    let now = Instant::now();
    let a = Allocation {
        client_addr: addr(1234), relay_port: 50000,
        created_at: now, last_refresh: now, lifetime_secs: 10,
    };
    let three_in = now + Duration::from_secs(3);
    assert_eq!(a.remaining_secs(three_in), 7);
}

// ─── AllocationTable: create / lifetime negotiation ────────────────

#[test]
fn create_grants_default_lifetime_when_none_requested() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let a = table.create_or_refresh(addr(1000), None, now).expect("should succeed");
    assert_eq!(a.lifetime_secs, DEFAULT_LIFETIME_SECS);
}

#[test]
fn create_honors_requested_lifetime_under_cap() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let a = table.create_or_refresh(addr(1000), Some(120), now).expect("should succeed");
    assert_eq!(a.lifetime_secs, 120);
}

#[test]
fn create_caps_requested_lifetime_at_max() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let a = table.create_or_refresh(addr(1000), Some(999_999), now).expect("should succeed");
    assert_eq!(a.lifetime_secs, MAX_LIFETIME_SECS, "a wildly excessive request must be capped");
}

#[test]
fn create_grants_at_least_one_second_for_absurdly_low_request() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let a = table.create_or_refresh(addr(1000), Some(0), now).expect("should succeed");
    assert!(a.lifetime_secs >= 1, "first-time Allocate must never grant a 0-second lifetime");
}

#[test]
fn create_again_for_same_client_refreshes_rather_than_double_allocates() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let client = addr(1000);

    let first = table.create_or_refresh(client, None, now).unwrap();
    let second = table.create_or_refresh(client, Some(300), now).unwrap();

    assert_eq!(first.relay_port, second.relay_port, "a repeated Allocate must refresh, not double-allocate");
    assert_eq!(second.lifetime_secs, 300);
    assert_eq!(table.active_count(), 1);
    assert_eq!(table.pool_in_use(), 1);
}

// ─── AllocationTable: pool exhaustion ──────────────────────────────

#[test]
fn create_returns_pool_exhausted_error_not_panic() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50001)); // 2 ports
    let now = Instant::now();
    table.create_or_refresh(addr(1000), None, now).expect("1st should succeed");
    table.create_or_refresh(addr(1001), None, now).expect("2nd should succeed");

    let result = table.create_or_refresh(addr(1002), None, now);
    assert!(matches!(result, Err(AllocationError::PoolExhausted)));
}

#[test]
fn refresh_after_release_frees_a_slot_for_a_new_client() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50000)); // exactly 1 port
    let now = Instant::now();
    let client_a = addr(1000);
    let client_b = addr(1001);

    table.create_or_refresh(client_a, None, now).expect("client A should get the only port");
    assert!(matches!(table.create_or_refresh(client_b, None, now), Err(AllocationError::PoolExhausted)));

    table.refresh(client_a, Some(0), now).expect("deallocation should succeed");

    let b_alloc = table.create_or_refresh(client_b, None, now)
        .expect("client B should now succeed after A released");
    assert_eq!(b_alloc.relay_port, 50000);
}

// ─── AllocationTable: refresh ──────────────────────────────────────

#[test]
fn refresh_extends_lifetime_and_advances_last_refresh() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let t0 = Instant::now();
    let client = addr(1000);

    table.create_or_refresh(client, Some(60), t0).unwrap();

    let t1 = t0 + Duration::from_secs(30);
    let granted = table.refresh(client, Some(120), t1).expect("refresh should succeed");
    assert_eq!(granted, 120);

    let allocation = table.get(&client).expect("allocation should still exist");
    assert_eq!(allocation.lifetime_secs, 120);
    assert_eq!(allocation.last_refresh, t1);

    let original_boundary = t0 + Duration::from_secs(61);
    assert!(!allocation.is_expired(original_boundary), "refreshing must actually extend expiry");
}

#[test]
fn refresh_with_none_grants_default_lifetime() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let client = addr(1000);
    table.create_or_refresh(client, Some(60), now).unwrap();

    let granted = table.refresh(client, None, now).expect("refresh should succeed");
    assert_eq!(granted, DEFAULT_LIFETIME_SECS);
}

#[test]
fn refresh_caps_at_max_lifetime() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let client = addr(1000);
    table.create_or_refresh(client, None, now).unwrap();

    let granted = table.refresh(client, Some(999_999), now).expect("refresh should succeed");
    assert_eq!(granted, MAX_LIFETIME_SECS);
}

#[test]
fn refresh_zero_deallocates_and_releases_the_port() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let client = addr(1000);
    let allocation = table.create_or_refresh(client, None, now).unwrap();
    let port = allocation.relay_port;

    assert_eq!(table.pool_in_use(), 1);

    let granted = table.refresh(client, Some(0), now).expect("explicit deallocation must succeed");
    assert_eq!(granted, 0);

    assert!(table.get(&client).is_none());
    assert_eq!(table.pool_in_use(), 0);
    assert_eq!(table.active_count(), 0);

    let new_alloc = table.create_or_refresh(addr(2000), None, now).unwrap();
    assert_eq!(new_alloc.relay_port, port, "the deallocated port must be reusable");
}

#[test]
fn refresh_unknown_client_returns_no_such_allocation() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let result = table.refresh(addr(9999), Some(60), now);
    assert!(matches!(result, Err(AllocationError::NoSuchAllocation)));
}

#[test]
fn refresh_zero_for_unknown_client_also_returns_no_such_allocation() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let now = Instant::now();
    let result = table.refresh(addr(9999), Some(0), now);
    assert!(matches!(result, Err(AllocationError::NoSuchAllocation)));
}

// ─── AllocationTable: expiry sweep ──────────────────────────────────

#[test]
fn sweep_releases_only_truly_expired_allocations() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let t0 = Instant::now();

    let short_lived = addr(1000);
    let long_lived  = addr(1001);

    table.create_or_refresh(short_lived, Some(5), t0).unwrap();
    table.create_or_refresh(long_lived,  Some(500), t0).unwrap();

    let t1 = t0 + Duration::from_secs(10);
    let swept = table.sweep_expired(t1);

    assert_eq!(swept, vec![short_lived]);
    assert!(table.get(&short_lived).is_none());
    assert!(table.get(&long_lived).is_some());
    assert_eq!(table.active_count(), 1);
    assert_eq!(table.pool_in_use(), 1);
}

#[test]
fn sweep_returns_empty_and_changes_nothing_when_none_expired() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let t0 = Instant::now();
    table.create_or_refresh(addr(1000), Some(600), t0).unwrap();
    table.create_or_refresh(addr(1001), Some(600), t0).unwrap();

    let t1 = t0 + Duration::from_secs(10);
    let swept = table.sweep_expired(t1);

    assert!(swept.is_empty());
    assert_eq!(table.active_count(), 2);
    assert_eq!(table.pool_in_use(), 2);
}

#[test]
fn sweep_releases_pool_capacity_for_reuse() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50000)); // exactly 1 port
    let t0 = Instant::now();
    let client = addr(1000);

    let original = table.create_or_refresh(client, Some(5), t0).unwrap();

    let t1 = t0 + Duration::from_secs(100);
    let swept = table.sweep_expired(t1);
    assert_eq!(swept, vec![client]);

    let new_client = addr(2000);
    let new_alloc = table.create_or_refresh(new_client, None, t1)
        .expect("port must be available for a new client after sweep");
    assert_eq!(new_alloc.relay_port, original.relay_port);
}

#[test]
fn sweep_on_empty_table_is_a_safe_noop() {
    let mut table = AllocationTable::new(PortPool::new(50000, 50010));
    let swept = table.sweep_expired(Instant::now());
    assert!(swept.is_empty());
}
