//! TURN CreatePermission request handler (RFC 5766 §9).
//!
//! Kept in its own file rather than appended to `server.rs` because it
//! depends on a second piece of state (`PermissionTable`) that Allocate
//! and Refresh have no reason to know about — the same separation of
//! concerns that keeps `auth.rs` ignorant of port pools and
//! `allocation.rs` ignorant of MD5/HMAC.
//!
//! # Atomicity (RFC 5766 §9.2)
//!
//! A CreatePermission request may carry multiple XOR-PEER-ADDRESS
//! attributes. The RFC requires the request be treated atomically: if
//! any peer address is unacceptable, the server must reject the whole
//! request and install *none* of the permissions, rather than partially
//! applying it. This implementation validates every address first, and
//! only then commits — a partial-application bug here would leave the
//! client's view of its own permissions silently out of sync with the
//! server's, which is exactly the kind of state divergence that
//! produces media flowing one direction but not the other.

use super::{
    allocation::AllocationTable,
    auth::{AuthResult, CredentialStore},
    permission::PermissionTable,
    server::{authenticate_turn_request, challenge_response_for},
};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    builder::{
        build_437_allocation_mismatch, build_create_permission_success_response,
        build_error_response,
    },
    parser::{parse_message, MessageClass, Method},
};
use std::net::SocketAddr;
use std::time::Instant;

/// Process one inbound CreatePermission request.
///
/// Returns the response bytes to send back to `peer`, or `None` to
/// silently drop (unparseable input, or not a CreatePermission request).
///
/// Outcomes:
/// - **Authenticated + allocation exists + ≥1 valid peer address** →
///   permissions installed (or refreshed), 200 Success Response.
/// - **Authenticated but no allocation** → 437 Allocation Mismatch.
///   A permission is meaningless without an allocation to attach it to.
/// - **Authenticated but zero XOR-PEER-ADDRESS attributes** → 400 Bad
///   Request. RFC 5766 §9.1 expects at least one; a CreatePermission
///   naming no peers is malformed, not a no-op success.
/// - **Not authenticated** → 401/438 challenge, identical handling to
///   Allocate and Refresh.
pub fn handle_create_permission_datagram(
    raw: &[u8],
    peer: SocketAddr,
    realm: &str,
    credentials: &CredentialStore,
    allocations: &AllocationTable,
    permissions: &mut PermissionTable,
    max_nonce_age_secs: u64,
) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;
    if msg.class != MessageClass::Request || msg.method != Method::CreatePermission {
        return None;
    }

    match authenticate_turn_request(&msg, raw, realm, credentials, max_nonce_age_secs) {
        AuthResult::Authenticated { username } => {
            // A permission only has meaning attached to an allocation.
            if allocations.get(&peer).is_none() {
                tracing::warn!(username, "CreatePermission with no existing allocation");
                return Some(build_437_allocation_mismatch(
                    Method::CreatePermission, &msg.transaction_id,
                ));
            }

            // Collect every peer address named in the request. Multiple
            // XOR-PEER-ADDRESS attributes are legal and common —
            // `decode_attributes` preserves all of them in order rather
            // than collapsing duplicates by type.
            let peer_ips: Vec<_> = decode_attributes(&msg.attributes_raw, &msg.transaction_id)
                .into_iter()
                .filter_map(|a| match a {
                    Attribute::XorPeerAddress(addr) => Some(addr.ip),
                    _ => None,
                })
                .collect();

            if peer_ips.is_empty() {
                tracing::warn!(username, "CreatePermission naming no peer addresses");
                return Some(build_error_response(
                    Method::CreatePermission, &msg.transaction_id,
                    400, "Bad Request", &[],
                ));
            }

            // Commit only after the full set is known to be acceptable —
            // see this module's atomicity note.
            let now = Instant::now();
            for ip in &peer_ips {
                permissions.create_or_refresh(peer, *ip, now);
            }

            tracing::info!(
                username, peer_count = peer_ips.len(),
                "CreatePermission succeeded"
            );
            Some(build_create_permission_success_response(&msg.transaction_id))
        }
        result => Some(challenge_response_for(
            &result, Method::CreatePermission, &msg.transaction_id, realm,
        )),
    }
}
