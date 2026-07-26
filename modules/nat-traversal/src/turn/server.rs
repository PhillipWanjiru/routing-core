//! Minimal TURN Allocate handler — proves the authentication gate wired
//! to real requests over the full challenge-response cycle.
//!
//! # Scope boundary (read this before extending)
//!
//! This handler authenticates an Allocate request and, once
//! authenticated, returns a *placeholder* Success Response containing no
//! real allocation (no relay port, no XOR-RELAYED-ADDRESS, no LIFETIME
//! attribute). That is deliberate: this milestone's job was building and
//! verifying the authentication mechanism itself, not the allocation
//! pool. The next milestone (`turn::allocation`) replaces the
//! placeholder success path with a real one; the authentication gate
//! below does not change when that happens.

use super::auth::{authenticate_request, AuthResult, CredentialAttempt, CredentialStore};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    builder::{build_401_challenge, build_438_stale_nonce, build_message},
    parser::{parse_message, MessageClass, Method},
};
use std::net::SocketAddr;

/// Duplicated here from `stun::attributes` rather than imported, since
/// only MESSAGE-INTEGRITY's *position* (not its decoded value) is
/// needed, and scanning for it directly is simpler than extending the
/// general-purpose decoder to also report offsets it has no other
/// reason to track.
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

/// Find the byte offset of the MESSAGE-INTEGRITY attribute's *value*
/// within a raw attributes section, if present. Offset is relative to
/// the start of `attrs_raw` — the caller adds `parser::HEADER_LEN` to
/// get an offset relative to the full message.
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

/// Process one inbound Allocate request. Returns the response bytes to
/// send back to `peer`, or `None` to silently drop.
pub fn handle_allocate_datagram(
    raw: &[u8],
    _peer: SocketAddr,
    realm: &str,
    credentials: &CredentialStore,
    max_nonce_age_secs: u64,
) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;

    if msg.class != MessageClass::Request || msg.method != Method::Allocate {
        return None;
    }

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
        username,
        realm: req_realm,
        nonce,
        mi_value_offset,
    };

    match authenticate_request(&attempt, raw, realm, credentials, max_nonce_age_secs) {
        AuthResult::Authenticated { username } => {
            tracing::info!(username, "Allocate request authenticated");
            // Placeholder success — see this module's doc comment.
            Some(build_message(
                MessageClass::SuccessResponse,
                Method::Allocate,
                &msg.transaction_id,
                &[],
            ))
        }
        AuthResult::ChallengeRequired => {
            let fresh_nonce = super::auth::generate_nonce();
            tracing::info!("Allocate request has no credentials, sending 401 challenge");
            Some(build_401_challenge(Method::Allocate, &msg.transaction_id, realm, &fresh_nonce))
        }
        AuthResult::Rejected { stale_nonce: true } => {
            let fresh_nonce = super::auth::generate_nonce();
            tracing::info!("Allocate request nonce is stale, sending 438 with fresh nonce");
            Some(build_438_stale_nonce(Method::Allocate, &msg.transaction_id, realm, &fresh_nonce))
        }
        AuthResult::Rejected { stale_nonce: false } => {
            let fresh_nonce = super::auth::generate_nonce();
            tracing::info!("Allocate request credentials invalid, sending fresh 401 challenge");
            Some(build_401_challenge(Method::Allocate, &msg.transaction_id, realm, &fresh_nonce))
        }
    }
}
