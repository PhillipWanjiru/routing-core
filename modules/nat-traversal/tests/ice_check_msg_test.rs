//! ICE check-message codec tests (RFC 8445 §7).
//!
//! Byte-exactness of the builders and acceptance by the validators are both
//! checked against messages built by an independent Python implementation,
//! not merely against each other.

include!("ice_check_fixtures.rs");

use nat_traversal::ice::{
    build_check_error_response, build_check_request, build_check_success_response,
    parse_check_request, parse_check_response, CheckRequestError, CheckRequestParams,
    CheckResponse, CheckResponseError, IceRole, ParsedCheckRequest,
};
use nat_traversal::stun::{
    attributes::{
        ATTR_ERROR_CODE, ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY,
        ATTR_USERNAME, ATTR_USE_CANDIDATE,
    },
    builder::{build_attribute, build_message, encode_priority, encode_tie_breaker},
    fingerprint::append_fingerprint,
    integrity::append_integrity,
    parser::{MessageClass, Method},
    scan::locate_attribute,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn mapped_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(RESP_MAPPED_IP)), RESP_MAPPED_PORT)
}

fn params(role: IceRole, tie_breaker: u64, use_candidate: bool, txn: [u8; 12]) -> CheckRequestParams<'static> {
    CheckRequestParams {
        txn_id: txn,
        username: CHECK_USERNAME,
        password: CHECK_PASSWORD,
        priority: CHECK_PRIORITY,
        role,
        tie_breaker,
        use_candidate,
    }
}

fn username_attr() -> Vec<u8> { build_attribute(ATTR_USERNAME, CHECK_USERNAME.as_bytes()) }
fn priority_attr() -> Vec<u8> { build_attribute(ATTR_PRIORITY, &encode_priority(CHECK_PRIORITY)) }
fn controlling_attr(tb: u64) -> Vec<u8> { build_attribute(ATTR_ICE_CONTROLLING, &encode_tie_breaker(tb)) }
fn controlled_attr(tb: u64) -> Vec<u8> { build_attribute(ATTR_ICE_CONTROLLED, &encode_tie_breaker(tb)) }

fn cat(parts: &[Vec<u8>]) -> Vec<u8> { parts.concat() }

/// A fully signed Binding request carrying exactly `attrs`.
fn signed_request(attrs: &[u8], password: &[u8]) -> Vec<u8> {
    let mut m = build_message(MessageClass::Request, Method::Binding, &REQ_CONTROLLING_TXN, attrs);
    append_integrity(&mut m, password);
    append_fingerprint(&mut m);
    m
}

fn signed_response(class: MessageClass, attrs: &[u8]) -> Vec<u8> {
    let mut m = build_message(class, Method::Binding, &REQ_CONTROLLING_TXN, attrs);
    append_integrity(&mut m, CHECK_PASSWORD);
    append_fingerprint(&mut m);
    m
}

fn strip_fingerprint(msg: &[u8]) -> Vec<u8> {
    let mut m = msg[..msg.len() - 8].to_vec();
    let len = (m.len() - 20) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    m
}

fn parse(raw: &[u8]) -> Result<ParsedCheckRequest, CheckRequestError> {
    parse_check_request(raw, CHECK_RECEIVER_UFRAG, CHECK_PASSWORD)
}

// ─── Building requests: byte-exact against the oracle ───────────────

#[test]
fn build_request_controlling_with_use_candidate_matches_oracle() {
    let built = build_check_request(&params(IceRole::Controlling, REQ_CONTROLLING_TIEBREAKER, true, REQ_CONTROLLING_TXN));
    assert_eq!(built, REQ_CONTROLLING);
}

#[test]
fn build_request_controlled_matches_oracle() {
    let built = build_check_request(&params(IceRole::Controlled, REQ_CONTROLLED_TIEBREAKER, false, REQ_CONTROLLED_TXN));
    assert_eq!(built, REQ_CONTROLLED);
}

#[test]
fn controlled_builder_never_emits_use_candidate() {
    let with = build_check_request(&params(IceRole::Controlled, 5, true, [1; 12]));
    let without = build_check_request(&params(IceRole::Controlled, 5, false, [1; 12]));
    assert_eq!(with, without, "USE-CANDIDATE is controlling-only; the flag must be ignored");
    assert!(locate_attribute(&with, ATTR_USE_CANDIDATE).is_none());
}

// ─── Parsing requests ───────────────────────────────────────────────

#[test]
fn parse_oracle_controlling_request() {
    assert_eq!(
        parse(REQ_CONTROLLING),
        Ok(ParsedCheckRequest {
            txn_id: REQ_CONTROLLING_TXN,
            remote_ufrag: CHECK_SENDER_UFRAG.to_owned(),
            priority: CHECK_PRIORITY,
            sender_role: IceRole::Controlling,
            tie_breaker: REQ_CONTROLLING_TIEBREAKER,
            use_candidate: true,
        })
    );
}

#[test]
fn parse_oracle_controlled_request() {
    assert_eq!(
        parse(REQ_CONTROLLED),
        Ok(ParsedCheckRequest {
            txn_id: REQ_CONTROLLED_TXN,
            remote_ufrag: CHECK_SENDER_UFRAG.to_owned(),
            priority: CHECK_PRIORITY,
            sender_role: IceRole::Controlled,
            tie_breaker: REQ_CONTROLLED_TIEBREAKER,
            use_candidate: false,
        })
    );
}

#[test]
fn round_trip_preserves_every_field_including_boundary_tie_breakers() {
    for role in [IceRole::Controlling, IceRole::Controlled] {
        for tb in [0u64, 1, u64::MAX, 0x8000_0000_0000_0000] {
            let raw = build_check_request(&params(role, tb, role == IceRole::Controlling, [0xAB; 12]));
            let got = parse(&raw).expect("own output must validate");
            assert_eq!(got.sender_role, role);
            assert_eq!(got.tie_breaker, tb);
            assert_eq!(got.priority, CHECK_PRIORITY);
            assert_eq!(got.txn_id, [0xAB; 12]);
            assert_eq!(got.use_candidate, role == IceRole::Controlling);
        }
    }
}

#[test]
fn use_candidate_from_a_controlled_sender_is_ignored() {
    let attrs = cat(&[username_attr(), priority_attr(), controlled_attr(9), build_attribute(ATTR_USE_CANDIDATE, &[])]);
    let got = parse(&signed_request(&attrs, CHECK_PASSWORD)).expect("valid otherwise");
    assert!(!got.use_candidate, "only a controlling agent may nominate");
}

// ─── Rejecting requests: authentication ─────────────────────────────

#[test]
fn wrong_password_is_unauthorized() {
    assert_eq!(parse_check_request(REQ_CONTROLLING, CHECK_RECEIVER_UFRAG, b"some-other-password-xyz"),
               Err(CheckRequestError::Unauthorized));
}

#[test]
fn request_addressed_to_a_different_ufrag_is_unauthorized() {
    assert_eq!(parse_check_request(REQ_CONTROLLING, "other", CHECK_PASSWORD),
               Err(CheckRequestError::Unauthorized));
}

#[test]
fn username_without_a_colon_is_unauthorized() {
    let attrs = cat(&[build_attribute(ATTR_USERNAME, b"nocolon"), priority_attr(), controlling_attr(1)]);
    assert_eq!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::Unauthorized));
}

#[test]
fn missing_username_is_unauthorized() {
    let attrs = cat(&[priority_attr(), controlling_attr(1)]);
    assert_eq!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::Unauthorized));
}

#[test]
fn missing_message_integrity_is_unauthorized() {
    let attrs = cat(&[username_attr(), priority_attr(), controlling_attr(1)]);
    let mut m = build_message(MessageClass::Request, Method::Binding, &[3; 12], &attrs);
    append_fingerprint(&mut m); // valid fingerprint, no MI at all
    assert_eq!(parse(&m), Err(CheckRequestError::Unauthorized));
}

// ─── Rejecting requests: fingerprint ────────────────────────────────

#[test]
fn missing_fingerprint_is_bad_fingerprint() {
    assert_eq!(parse(&strip_fingerprint(REQ_CONTROLLING)), Err(CheckRequestError::BadFingerprint));
}

#[test]
fn a_flipped_bit_is_caught_by_the_fingerprint_first() {
    let mut m = REQ_CONTROLLING.to_vec();
    m[24] ^= 0x01; // inside USERNAME
    assert_eq!(parse(&m), Err(CheckRequestError::BadFingerprint));
}

#[test]
fn forged_fingerprint_over_tampered_content_is_still_unauthorized() {
    let mut m = REQ_CONTROLLING.to_vec();
    let p = locate_attribute(&m, ATTR_PRIORITY).unwrap();
    m[p.value_start] ^= 0x01;
    let mut m = strip_fingerprint(&m);
    append_fingerprint(&mut m); // attacker recomputes the checksum
    assert_eq!(parse(&m), Err(CheckRequestError::Unauthorized),
               "the fingerprint is not a security boundary; MESSAGE-INTEGRITY is");
}

// ─── Rejecting requests: semantics (only after authentication) ──────

#[test]
fn missing_priority_is_bad_request() {
    let attrs = cat(&[username_attr(), controlling_attr(1)]);
    assert_eq!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::BadRequest("missing PRIORITY")));
}

#[test]
fn malformed_priority_is_treated_as_missing() {
    let attrs = cat(&[username_attr(), build_attribute(ATTR_PRIORITY, &[1, 2, 3]), controlling_attr(1)]);
    assert_eq!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::BadRequest("missing PRIORITY")));
}

#[test]
fn both_role_attributes_is_bad_request() {
    let attrs = cat(&[username_attr(), priority_attr(), controlling_attr(1), controlled_attr(2)]);
    assert!(matches!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::BadRequest(_))));
}

#[test]
fn no_role_attribute_is_bad_request() {
    let attrs = cat(&[username_attr(), priority_attr()]);
    assert!(matches!(parse(&signed_request(&attrs, CHECK_PASSWORD)), Err(CheckRequestError::BadRequest(_))));
}

#[test]
fn semantic_errors_are_hidden_from_unauthenticated_senders() {
    // Contradictory roles AND the wrong password: the sender must learn
    // "unauthorized", not which attribute was wrong.
    let attrs = cat(&[username_attr(), priority_attr(), controlling_attr(1), controlled_attr(2)]);
    assert_eq!(parse(&signed_request(&attrs, b"not-the-password-at-all-xx")), Err(CheckRequestError::Unauthorized));
}

// ─── Rejecting non-requests ─────────────────────────────────────────

#[test]
fn a_non_binding_request_is_not_a_check() {
    let m = build_message(MessageClass::Request, Method::Allocate, &[1; 12], &[]);
    assert_eq!(parse(&m), Err(CheckRequestError::NotBindingRequest));
}

#[test]
fn a_response_is_not_a_check_request() {
    assert_eq!(parse(RESP_SUCCESS), Err(CheckRequestError::NotBindingRequest));
}

#[test]
fn garbage_is_not_a_check_request() {
    assert_eq!(parse(&[0xFF; 3]), Err(CheckRequestError::NotBindingRequest));
    assert_eq!(parse(&[]), Err(CheckRequestError::NotBindingRequest));
}

// ─── Success responses ──────────────────────────────────────────────

#[test]
fn build_success_response_matches_oracle() {
    assert_eq!(build_check_success_response(&REQ_CONTROLLING_TXN, mapped_addr(), CHECK_PASSWORD), RESP_SUCCESS);
}

#[test]
fn parse_oracle_success_response() {
    assert_eq!(
        parse_check_response(RESP_SUCCESS, &REQ_CONTROLLING_TXN, CHECK_PASSWORD),
        Ok(CheckResponse::Success { mapped: mapped_addr() })
    );
}

#[test]
fn success_response_round_trips_ipv6() {
    let src: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
    let raw = build_check_success_response(&[0x55; 12], src, CHECK_PASSWORD);
    assert_eq!(parse_check_response(&raw, &[0x55; 12], CHECK_PASSWORD), Ok(CheckResponse::Success { mapped: src }));
}

#[test]
fn success_with_the_wrong_password_is_bad_integrity() {
    assert_eq!(parse_check_response(RESP_SUCCESS, &REQ_CONTROLLING_TXN, b"wrong-password-0123456789"),
               Err(CheckResponseError::BadIntegrity));
}

#[test]
fn response_for_a_different_transaction_is_rejected() {
    assert_eq!(parse_check_response(RESP_SUCCESS, &REQ_CONTROLLED_TXN, CHECK_PASSWORD),
               Err(CheckResponseError::TransactionMismatch));
}

#[test]
fn tampered_success_response_is_bad_fingerprint() {
    let mut m = RESP_SUCCESS.to_vec();
    m[26] ^= 0x01; // inside XOR-MAPPED-ADDRESS
    assert_eq!(parse_check_response(&m, &REQ_CONTROLLING_TXN, CHECK_PASSWORD), Err(CheckResponseError::BadFingerprint));
}

#[test]
fn success_without_a_fingerprint_is_bad_fingerprint() {
    assert_eq!(parse_check_response(&strip_fingerprint(RESP_SUCCESS), &REQ_CONTROLLING_TXN, CHECK_PASSWORD),
               Err(CheckResponseError::BadFingerprint));
}

#[test]
fn success_without_a_mapped_address_is_malformed() {
    let m = signed_response(MessageClass::SuccessResponse, &build_attribute(0x8022, b"x"));
    assert_eq!(parse_check_response(&m, &REQ_CONTROLLING_TXN, CHECK_PASSWORD), Err(CheckResponseError::Malformed));
}

// ─── Error responses ────────────────────────────────────────────────

#[test]
fn build_role_conflict_matches_oracle() {
    assert_eq!(build_check_error_response(&REQ_CONTROLLING_TXN, 487, "Role Conflict", Some(CHECK_PASSWORD)),
               RESP_ROLE_CONFLICT);
}

#[test]
fn authenticated_role_conflict_is_reported_as_authenticated() {
    assert_eq!(parse_check_response(RESP_ROLE_CONFLICT, &REQ_CONTROLLING_TXN, CHECK_PASSWORD),
               Ok(CheckResponse::Error { code: 487, authenticated: true }));
}

#[test]
fn forged_role_conflict_is_reported_as_unauthenticated_not_rejected() {
    // The codec reports the facts; the engine must refuse to flip roles on an
    // unauthenticated 487. Returning Ok(authenticated:false) — rather than an
    // error — keeps that decision, and its reason, visible to the engine.
    assert_eq!(parse_check_response(RESP_ROLE_CONFLICT, &REQ_CONTROLLING_TXN, b"attacker-guess-0123456789"),
               Ok(CheckResponse::Error { code: 487, authenticated: false }));
}

#[test]
fn build_401_without_integrity_matches_oracle() {
    assert_eq!(build_check_error_response(&REQ_CONTROLLING_TXN, 401, "Unauthorized", None), RESP_UNAUTHORIZED_NO_MI);
}

#[test]
fn unsigned_401_parses_as_an_unauthenticated_error() {
    assert_eq!(parse_check_response(RESP_UNAUTHORIZED_NO_MI, &REQ_CONTROLLING_TXN, CHECK_PASSWORD),
               Ok(CheckResponse::Error { code: 401, authenticated: false }));
}

#[test]
fn error_response_without_an_error_code_is_malformed() {
    let m = signed_response(MessageClass::ErrorResponse, &build_attribute(0x8022, b"x"));
    assert_eq!(parse_check_response(&m, &REQ_CONTROLLING_TXN, CHECK_PASSWORD), Err(CheckResponseError::Malformed));
    let _ = ATTR_ERROR_CODE; // referenced so the import documents which attribute is missing
}

// ─── Responses that aren't ──────────────────────────────────────────

#[test]
fn a_request_is_not_a_response() {
    assert_eq!(parse_check_response(REQ_CONTROLLING, &REQ_CONTROLLING_TXN, CHECK_PASSWORD),
               Err(CheckResponseError::NotBindingResponse));
}

#[test]
fn garbage_is_not_a_response() {
    assert_eq!(parse_check_response(&[0xFF; 5], &REQ_CONTROLLING_TXN, CHECK_PASSWORD), Err(CheckResponseError::NotBindingResponse));
    assert_eq!(parse_check_response(&[], &REQ_CONTROLLING_TXN, CHECK_PASSWORD), Err(CheckResponseError::NotBindingResponse));
}
