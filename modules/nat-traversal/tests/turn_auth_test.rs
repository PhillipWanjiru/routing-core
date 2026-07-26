//! TURN long-term credential authentication tests.
//!
//! Reference values come from `turn_auth_fixtures.rs`, which is generated
//! (not hand-transcribed) by an independent Python script using
//! `hashlib`/`hmac` as the oracle — see that file's header comment for
//! why this project stopped hand-copying hex byte arrays after an
//! earlier transcription mistake in the STUN test vectors.

include!("turn_auth_fixtures.rs");

use nat_traversal::turn::{
    authenticate_request, generate_nonce, hmac_sha1, long_term_key, md5,
    nonce_is_stale, verify_message_integrity, AuthResult, CredentialAttempt,
    CredentialStore,
};

// ─── MD5 against independent reference vectors ───────────────────

#[test]
fn md5_matches_reference_vectors() {
    for (input, expected_hex) in MD5_VECTORS {
        let digest = md5(input);
        let got_hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(&got_hex, expected_hex, "MD5({input:?}) mismatch");
    }
}

// ─── SHA-1 against independent reference vectors ─────────────────

#[test]
fn sha1_matches_reference_vectors() {
    for (input, expected_hex) in SHA1_VECTORS {
        let digest = nat_traversal::turn::sha1(input);
        let got_hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(&got_hex, expected_hex, "SHA1({input:?}) mismatch");
    }
}

// ─── HMAC-SHA1 against RFC 2202 test case 1 (20-byte key, distinct from
// the 16-byte MD5-derived key used internally for message integrity) ───

#[test]
fn hmac_sha1_matches_rfc2202_test_case_1() {
    let digest = hmac_sha1(HMAC_SHA1_KEY, HMAC_SHA1_DATA);
    let got_hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(&got_hex, HMAC_SHA1_EXPECTED);
}

// ─── Long-term credential key derivation ──────────────────────────

#[test]
fn long_term_key_matches_independent_computation() {
    let key = long_term_key(LTK_USERNAME, LTK_REALM, LTK_PASSWORD);
    assert_eq!(&key, LTK_EXPECTED_KEY);
}

#[test]
fn long_term_key_differs_for_wrong_password() {
    let correct = long_term_key(LTK_USERNAME, LTK_REALM, LTK_PASSWORD);
    let wrong   = long_term_key(LTK_USERNAME, LTK_REALM, WRONG_PASSWORD);
    assert_ne!(&correct[..], &wrong[..]);
    assert_eq!(&wrong, WRONG_KEY);
}

// ─── MESSAGE-INTEGRITY: the full worked example ───────────────────

#[test]
fn message_integrity_verifies_against_full_worked_example() {
    // This is the single most important test in this file: it proves the
    // "adjusted length field" construction (RFC 5389 §15.4) is byte-exact
    // against an independently-computed worked example, not just
    // internally self-consistent.
    assert_eq!(AUTH_REQUEST_FULL_MESSAGE.len(), AUTH_REQUEST_MSG_LEN);

    let key = long_term_key(LTK_USERNAME, LTK_REALM, LTK_PASSWORD);
    let verified = verify_message_integrity(
        AUTH_REQUEST_FULL_MESSAGE,
        AUTH_REQUEST_MI_VALUE_OFFSET,
        &key,
    );
    assert!(verified, "MESSAGE-INTEGRITY must verify against the correct key");

    let actual_mi_bytes = &AUTH_REQUEST_FULL_MESSAGE[AUTH_REQUEST_MI_VALUE_OFFSET..AUTH_REQUEST_MI_VALUE_OFFSET + 20];
    assert_eq!(actual_mi_bytes, AUTH_REQUEST_MI_VALUE);
}

#[test]
fn build_authenticated_request_matches_worked_example_byte_for_byte() {
    // The build direction, checked against the SAME independent Python
    // oracle as the verify direction above -- not against our own
    // verify_message_integrity, which would only prove the two sides of
    // this crate agree with each other, not that either is actually
    // correct. A bug shared by both build and verify would pass that
    // weaker check; it cannot pass this one, since AUTH_REQUEST_FULL_MESSAGE
    // was computed by a completely separate implementation (Python's
    // hmac/hashlib) before any of this Rust existed.
    let built = nat_traversal::turn::build_authenticated_request(
        nat_traversal::stun::Method::Allocate,
        AUTH_REQUEST_TXN_ID,
        LTK_USERNAME,
        LTK_REALM,
        AUTH_REQUEST_NONCE,
        LTK_PASSWORD,
    );
    assert_eq!(built.len(), AUTH_REQUEST_FULL_MESSAGE.len());
    assert_eq!(&built[..], AUTH_REQUEST_FULL_MESSAGE);
}

#[test]
fn message_integrity_fails_with_wrong_key() {
    let wrong_key = long_term_key(LTK_USERNAME, LTK_REALM, WRONG_PASSWORD);
    let verified = verify_message_integrity(
        AUTH_REQUEST_FULL_MESSAGE,
        AUTH_REQUEST_MI_VALUE_OFFSET,
        &wrong_key,
    );
    assert!(!verified, "MESSAGE-INTEGRITY must NOT verify with the wrong key");
}

#[test]
fn message_integrity_fails_if_message_tampered() {
    let key = long_term_key(LTK_USERNAME, LTK_REALM, LTK_PASSWORD);
    let mut tampered = AUTH_REQUEST_FULL_MESSAGE.to_vec();
    tampered[24] ^= 0x01;
    let verified = verify_message_integrity(&tampered, AUTH_REQUEST_MI_VALUE_OFFSET, &key);
    assert!(!verified, "tampering any byte before MESSAGE-INTEGRITY must invalidate it");
}

#[test]
fn message_integrity_rejects_out_of_bounds_offset() {
    let key = long_term_key(LTK_USERNAME, LTK_REALM, LTK_PASSWORD);
    let short_message = &AUTH_REQUEST_FULL_MESSAGE[..10];
    let verified = verify_message_integrity(short_message, 88, &key);
    assert!(!verified);
}

// ─── Nonce staleness ────────────────────────────────────────────

#[test]
fn freshly_generated_nonce_is_not_stale() {
    let nonce = generate_nonce();
    assert!(!nonce_is_stale(&nonce, 3600));
}

#[test]
fn nonce_shorter_than_timestamp_field_is_treated_as_stale() {
    assert!(nonce_is_stale("short", 3600));
}

#[test]
fn manually_aged_nonce_is_detected_as_stale() {
    let old_ts: u64 = 1_000_000_000;
    let fake_nonce = format!("{old_ts:016x}deadbeefcafe0000");
    assert!(nonce_is_stale(&fake_nonce, 3600));
}

// ─── Full authentication gate ──────────────────────────────────────

fn make_store() -> CredentialStore {
    let mut store = CredentialStore::new();
    store.add_user(LTK_USERNAME, LTK_PASSWORD);
    store
}

#[test]
fn authenticate_request_succeeds_with_correct_credentials() {
    let store = make_store();
    let attempt = CredentialAttempt {
        username: Some(LTK_USERNAME),
        realm:    Some(LTK_REALM),
        nonce:    Some(AUTH_REQUEST_NONCE),
        mi_value_offset: Some(AUTH_REQUEST_MI_VALUE_OFFSET),
    };
    let result = authenticate_request(&attempt, AUTH_REQUEST_FULL_MESSAGE, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::Authenticated { username: LTK_USERNAME.to_owned() });
}

#[test]
fn authenticate_request_requires_challenge_when_no_credentials_present() {
    let store = make_store();
    let attempt = CredentialAttempt {
        username: None,
        realm:    None,
        nonce:    None,
        mi_value_offset: None,
    };
    let result = authenticate_request(&attempt, AUTH_REQUEST_FULL_MESSAGE, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::ChallengeRequired);
}

#[test]
fn authenticate_request_rejects_unknown_username() {
    let store = make_store();
    let attempt = CredentialAttempt {
        username: Some("bob"),
        realm:    Some(LTK_REALM),
        nonce:    Some(AUTH_REQUEST_NONCE),
        mi_value_offset: Some(AUTH_REQUEST_MI_VALUE_OFFSET),
    };
    let result = authenticate_request(&attempt, AUTH_REQUEST_FULL_MESSAGE, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::Rejected { stale_nonce: false });
}

#[test]
fn authenticate_request_rejects_wrong_realm() {
    let store = make_store();
    let attempt = CredentialAttempt {
        username: Some(LTK_USERNAME),
        realm:    Some("some-other-realm.example"),
        nonce:    Some(AUTH_REQUEST_NONCE),
        mi_value_offset: Some(AUTH_REQUEST_MI_VALUE_OFFSET),
    };
    let result = authenticate_request(&attempt, AUTH_REQUEST_FULL_MESSAGE, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::Rejected { stale_nonce: false });
}

#[test]
fn authenticate_request_reports_stale_nonce_distinctly() {
    let store = make_store();
    let old_ts: u64 = 1_000_000_000;
    let stale_nonce = format!("{old_ts:016x}deadbeefcafe0000");

    let attempt = CredentialAttempt {
        username: Some(LTK_USERNAME),
        realm:    Some(LTK_REALM),
        nonce:    Some(&stale_nonce),
        mi_value_offset: Some(AUTH_REQUEST_MI_VALUE_OFFSET),
    };
    let result = authenticate_request(&attempt, AUTH_REQUEST_FULL_MESSAGE, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::Rejected { stale_nonce: true });
}

#[test]
fn authenticate_request_rejects_when_message_integrity_wrong() {
    let store = make_store();
    let mut tampered = AUTH_REQUEST_FULL_MESSAGE.to_vec();
    tampered[30] ^= 0x01;

    let attempt = CredentialAttempt {
        username: Some(LTK_USERNAME),
        realm:    Some(LTK_REALM),
        nonce:    Some(AUTH_REQUEST_NONCE),
        mi_value_offset: Some(AUTH_REQUEST_MI_VALUE_OFFSET),
    };
    let result = authenticate_request(&attempt, &tampered, LTK_REALM, &store, 3600);
    assert_eq!(result, AuthResult::Rejected { stale_nonce: false });
}

// ─── 401 challenge fixture sanity check ───────────────────────────

#[test]
fn challenge_401_fixture_has_expected_length() {
    assert_eq!(CHALLENGE_401_FULL_MESSAGE.len(), CHALLENGE_401_MSG_LEN);
    assert_eq!(CHALLENGE_401_MSG_LEN, 92);
}
