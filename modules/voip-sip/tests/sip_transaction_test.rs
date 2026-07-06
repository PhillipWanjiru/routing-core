//! SIP transaction state machine tests.

use voip_sip::sip::transaction::*;

// ─── INVITE client FSM ────────────────────────────────────────

#[test]
fn invite_client_calling_to_proceeding() {
    let s = invite_client_step(
        InviteClientState::Calling,
        TxEvent::MessageReceived { code: 180 },
    );
    assert_eq!(s, InviteClientState::Proceeding);
}

#[test]
fn invite_client_calling_to_accepted_on_200() {
    let s = invite_client_step(
        InviteClientState::Calling,
        TxEvent::MessageReceived { code: 200 },
    );
    assert_eq!(s, InviteClientState::Accepted);
}

#[test]
fn invite_client_calling_to_completed_on_4xx() {
    let s = invite_client_step(
        InviteClientState::Calling,
        TxEvent::MessageReceived { code: 486 },
    );
    assert_eq!(s, InviteClientState::Completed);
}

#[test]
fn invite_client_completed_to_terminated_on_timer_d() {
    let s = invite_client_step(
        InviteClientState::Completed,
        TxEvent::TimerD,
    );
    assert_eq!(s, InviteClientState::Terminated);
}

#[test]
fn invite_client_timer_b_terminates() {
    let s = invite_client_step(
        InviteClientState::Calling,
        TxEvent::TimerTimeout,
    );
    assert_eq!(s, InviteClientState::Terminated);
}

#[test]
fn invite_client_retransmit_stays_calling() {
    let s = invite_client_step(
        InviteClientState::Calling,
        TxEvent::Retransmit,
    );
    assert_eq!(s, InviteClientState::Calling);
}

#[test]
fn invite_client_terminated_absorbs_all_events() {
    for event in [
        TxEvent::MessageReceived { code: 200 },
        TxEvent::TimerTimeout,
        TxEvent::Retransmit,
        TxEvent::TimerD,
    ] {
        let s = invite_client_step(InviteClientState::Terminated, event);
        assert_eq!(s, InviteClientState::Terminated);
    }
}

// ─── INVITE server FSM ────────────────────────────────────────

#[test]
fn invite_server_proceeding_to_completed_on_reject() {
    let s = invite_server_step(
        InviteServerState::Proceeding,
        TxEvent::TuResponse { code: 486 },
    );
    assert_eq!(s, InviteServerState::Completed);
}

#[test]
fn invite_server_proceeding_to_accepted_on_200() {
    let s = invite_server_step(
        InviteServerState::Proceeding,
        TxEvent::TuResponse { code: 200 },
    );
    assert_eq!(s, InviteServerState::Accepted);
}

#[test]
fn invite_server_completed_to_confirmed_on_ack() {
    let s = invite_server_step(
        InviteServerState::Completed,
        TxEvent::AckReceived,
    );
    assert_eq!(s, InviteServerState::Confirmed);
}

#[test]
fn invite_server_timer_h_terminates() {
    let s = invite_server_step(
        InviteServerState::Completed,
        TxEvent::TimerTimeout,
    );
    assert_eq!(s, InviteServerState::Terminated);
}

// ─── Non-INVITE client FSM ────────────────────────────────────

#[test]
fn non_invite_client_trying_to_proceeding() {
    let s = non_invite_client_step(
        NonInviteClientState::Trying,
        TxEvent::MessageReceived { code: 100 },
    );
    assert_eq!(s, NonInviteClientState::Proceeding);
}

#[test]
fn non_invite_client_trying_to_completed_on_200() {
    let s = non_invite_client_step(
        NonInviteClientState::Trying,
        TxEvent::MessageReceived { code: 200 },
    );
    assert_eq!(s, NonInviteClientState::Completed);
}

#[test]
fn non_invite_client_timer_f_terminates() {
    let s = non_invite_client_step(
        NonInviteClientState::Trying,
        TxEvent::TimerTimeout,
    );
    assert_eq!(s, NonInviteClientState::Terminated);
}

// ─── SHA-256 (used by Digest auth) ────────────────────────────

#[test]
fn sha256_empty_string() {
    use voip_sip::sip::auth::sha256_hex;
    // FIPS 180-4 known answer test.
    let h = sha256_hex("");
    assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn sha256_abc() {
    use voip_sip::sip::auth::sha256_hex;
    let h = sha256_hex("abc");
    assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn sha256_long_message() {
    use voip_sip::sip::auth::sha256_hex;
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" — FIPS 180-4 §B.1
    let h = sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

// ─── Registrar ────────────────────────────────────────────────

#[test]
fn registrar_basic_register_and_lookup() {
    use voip_sip::sip::registrar::{Registrar, RegisterResult};
    let reg = Registrar::new(3600, 7200, 60);
    let result = reg.register(
        "sip:alice@example.com",
        "sip:alice@192.168.1.5:5060",
        "192.168.1.5",
        Some(600),
        "abc-123",
        1,
    );
    assert_eq!(result, RegisterResult::Ok { granted_expires: 600 });
    assert!(reg.is_registered("sip:alice@example.com"));
    let bindings = reg.lookup("sip:alice@example.com");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].contact, "sip:alice@192.168.1.5:5060");
}

#[test]
fn registrar_expire_zero_removes_binding() {
    use voip_sip::sip::registrar::Registrar;
    let reg = Registrar::new(3600, 7200, 60);
    reg.register("sip:bob@example.com", "sip:bob@10.0.0.1", "10.0.0.1", Some(600), "id1", 1);
    assert!(reg.is_registered("sip:bob@example.com"));
    reg.register("sip:bob@example.com", "sip:bob@10.0.0.1", "10.0.0.1", Some(0), "id1", 2);
    assert!(!reg.is_registered("sip:bob@example.com"));
}

#[test]
fn registrar_interval_too_brief() {
    use voip_sip::sip::registrar::{Registrar, RegisterResult};
    let reg = Registrar::new(3600, 7200, 300);
    let result = reg.register(
        "sip:carol@example.com",
        "sip:carol@10.0.0.2",
        "10.0.0.2",
        Some(60), // Below min_expires=300
        "id1",
        1,
    );
    assert_eq!(result, RegisterResult::IntervalTooBrief { min_expires: 300 });
}

#[test]
fn registrar_grants_max_expires_when_requested_more() {
    use voip_sip::sip::registrar::{Registrar, RegisterResult};
    let reg = Registrar::new(3600, 7200, 60);
    let result = reg.register(
        "sip:dave@example.com",
        "sip:dave@10.0.0.3",
        "10.0.0.3",
        Some(86400), // Requesting 24h; max is 7200
        "id1",
        1,
    );
    assert_eq!(result, RegisterResult::Ok { granted_expires: 7200 });
}
