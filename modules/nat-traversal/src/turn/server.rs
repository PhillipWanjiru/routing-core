//! TURN Allocate and Refresh request handlers.
//!
//! Both handlers share the same authentication gate (`authenticate_turn_request`)
//! and differ only in what they do once a request is authenticated:
//! Allocate creates or extends a relay port assignment, Refresh extends
//! or explicitly releases an existing one. Neither function is async —
//! both are synchronous, side-effect-isolated (aside from mutating the
//! `AllocationTable` passed in), and testable without a real socket,
//! matching the shape of every other datagram handler in this project
//! (`voip_sip::sip::uas::UasEngine::handle_datagram`, `stun::server::handle_datagram`).

use super::{
    allocation::{AllocationError, AllocationTable},
    auth::{authenticate_request, AuthResult, CredentialAttempt, CredentialStore},
};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    builder::{
        build_401_challenge, build_438_stale_nonce, build_allocate_success_response,
        build_error_response, build_refresh_success_response,
    },
    parser::{parse_message, MessageClass, Method, StunMessage},
};
use std::net::SocketAddr;
use std::time::Instant;

const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

/// Find the byte offset of the MESSAGE-INTEGRITY attribute's *value*
/// within a raw attributes section, if present. Offset is relative to
/// the start of `attrs_raw` — callers add `parser::HEADER_LEN` to get an
/// offset relative to the full message.
fn find_message_integrity_value_offset(attrs_raw: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 4 <= attrs_raw.len() {
        let attr_type = u16::from_be_bytes([attrs_raw[offset], attrs_raw[offset + 1]]);
        let attr_len  = u16::from_be_bytes([attrs_raw[offset + 2], attrs_raw[offset + 3]]) as usize;
        let value_start = offset + 4;

        if attr_type == ATTR_MESSAGE_INTEGRITY {
            return Some(value_start);
        }
        if value_start + attr_len > attrs_raw.len() {
            break;
        }
        let padded_len = (attr_len + 3) & !3;
        offset = value_start + padded_len;
    }
    None
}

/// Shared authentication step for Allocate/Refresh/CreatePermission:
/// extract USERNAME/REALM/NONCE/MESSAGE-INTEGRITY from the decoded
/// message and run them through the long-term credential gate.
pub(super) fn authenticate_turn_request(
    msg: &StunMessage,
    raw: &[u8],
    realm: &str,
    credentials: &CredentialStore,
    max_nonce_age_secs: u64,
) -> AuthResult {
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);

    let username = attrs.iter().find_map(|a| match a {
        Attribute::Username(s) => Some(s.as_str()),
        _ => None,
    });
    let req_realm = attrs.iter().find_map(|a| match a {
        Attribute::Realm(s) => Some(s.as_str()),
        _ => None,
    });
    let nonce = attrs.iter().find_map(|a| match a {
        Attribute::Nonce(s) => Some(s.as_str()),
        _ => None,
    });
    let mi_value_offset = find_message_integrity_value_offset(&msg.attributes_raw)
        .map(|rel| rel + crate::stun::parser::HEADER_LEN);

    let attempt = CredentialAttempt {
        username, realm: req_realm, nonce, mi_value_offset,
    };

    authenticate_request(&attempt, raw, realm, credentials, max_nonce_age_secs)
}

/// Extract a client-requested LIFETIME attribute value, if present.
fn extract_requested_lifetime(msg: &StunMessage) -> Option<u32> {
    decode_attributes(&msg.attributes_raw, &msg.transaction_id)
        .iter()
        .find_map(|a| match a {
            Attribute::Lifetime(secs) => Some(*secs),
            _ => None,
        })
}

/// Build the 401/438 challenge appropriate to an `AuthResult` that isn't
/// `Authenticated` — shared by every handler so the challenge-building
/// logic isn't duplicated.
pub(super) fn challenge_response_for(result: &AuthResult, method: Method, transaction_id: &[u8; 12], realm: &str) -> Vec<u8> {
    let fresh_nonce = super::auth::generate_nonce();
    match result {
        AuthResult::Rejected { stale_nonce: true } => {
            build_438_stale_nonce(method, transaction_id, realm, &fresh_nonce)
        }
        _ => build_401_challenge(method, transaction_id, realm, &fresh_nonce),
    }
}

/// Process one inbound Allocate request.
///
/// On success: creates a new allocation (or extends an existing one for
/// the same client, per RFC 5766 §6.2) and returns a Success Response
/// carrying the real relay port via XOR-RELAYED-ADDRESS and the granted
/// LIFETIME. On pool exhaustion: 508 Insufficient Capacity. On
/// authentication failure: 401/438, same as before allocation existed.
pub fn handle_allocate_datagram(
    raw: &[u8],
    peer: SocketAddr,
    realm: &str,
    credentials: &CredentialStore,
    allocations: &mut AllocationTable,
    max_nonce_age_secs: u64,
) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;
    if msg.class != MessageClass::Request || msg.method != Method::Allocate {
        return None;
    }

    match authenticate_turn_request(&msg, raw, realm, credentials, max_nonce_age_secs) {
        AuthResult::Authenticated { username } => {
            let requested_lifetime = extract_requested_lifetime(&msg);

            match allocations.create_or_refresh(peer, requested_lifetime, Instant::now()) {
                Ok(allocation) => {
                    tracing::info!(
                        username, relay_port = allocation.relay_port, lifetime = allocation.lifetime_secs,
                        "Allocate succeeded"
                    );
                    let relayed_addr = crate::stun::SocketAddrAttr {
                        ip:   peer.ip(),
                        port: allocation.relay_port,
                    };
                    Some(build_allocate_success_response(
                        &msg.transaction_id, relayed_addr, allocation.lifetime_secs,
                    ))
                }
                Err(AllocationError::PoolExhausted) => {
                    tracing::warn!(username, "Allocate failed: relay port pool exhausted");
                    Some(build_error_response(
                        Method::Allocate, &msg.transaction_id, 508, "Insufficient Capacity", &[],
                    ))
                }
                Err(AllocationError::NoSuchAllocation) => unreachable!(
                    "create_or_refresh never returns NoSuchAllocation"
                ),
            }
        }
        result => Some(challenge_response_for(&result, Method::Allocate, &msg.transaction_id, realm)),
    }
}

/// Process one inbound Refresh request.
///
/// A LIFETIME of 0 explicitly deallocates (RFC 5766 §7) — this still
/// returns a Success Response with LIFETIME=0 confirming the
/// deallocation, not an error. A Refresh for a client with no existing
/// allocation is silently dropped rather than fabricating a response for
/// a case that shouldn't occur in normal operation.
pub fn handle_refresh_datagram(
    raw: &[u8],
    peer: SocketAddr,
    realm: &str,
    credentials: &CredentialStore,
    allocations: &mut AllocationTable,
    max_nonce_age_secs: u64,
) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;
    if msg.class != MessageClass::Request || msg.method != Method::Refresh {
        return None;
    }

    match authenticate_turn_request(&msg, raw, realm, credentials, max_nonce_age_secs) {
        AuthResult::Authenticated { username } => {
            let requested_lifetime = extract_requested_lifetime(&msg);

            match allocations.refresh(peer, requested_lifetime, Instant::now()) {
                Ok(granted) => {
                    tracing::info!(username, granted_lifetime = granted, "Refresh succeeded");
                    Some(build_refresh_success_response(&msg.transaction_id, granted))
                }
                Err(AllocationError::NoSuchAllocation) => {
                    tracing::warn!(username, "Refresh for unknown allocation, dropping");
                    None
                }
                Err(AllocationError::PoolExhausted) => unreachable!(
                    "refresh never allocates a new port, so pool exhaustion cannot occur here"
                ),
            }
        }
        result => Some(challenge_response_for(&result, Method::Refresh, &msg.transaction_id, realm)),
    }
}
