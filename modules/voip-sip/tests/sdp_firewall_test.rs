//! SRTP key management and encrypt/decrypt tests.
//! (File named sdp_firewall_test.rs — was a stub, now repurposed for SRTP.)

use voip_sip::srtp::{
    derive_session_keys, parse_sdes_crypto, srtp_decrypt, srtp_encrypt, srtp_index,
};
use voip_sip::rtp::session::RtpSendSession;

// ─── Key parsing ───────────────────────────────────────────────

#[test]
fn sdes_parse_valid_crypto_line() {
    // RFC 4568 §6.1 example attribute value (tag stripped, just the value).
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    let km = parse_sdes_crypto(attr).expect("should parse valid a=crypto line");
    assert_eq!(km.suite, "AES_CM_128_HMAC_SHA1_80");
    assert_eq!(km.master_key.len(),  16, "AES-128 key must be 16 bytes");
    assert_eq!(km.master_salt.len(), 14, "CM salt must be 14 bytes");
}

#[test]
fn sdes_parse_rejects_short_line() {
    assert!(parse_sdes_crypto("1 AES_CM_128_HMAC_SHA1_80").is_none());
}

#[test]
fn sdes_parse_rejects_unknown_suite() {
    let attr = "1 UNKNOWN_SUITE inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    assert!(parse_sdes_crypto(attr).is_none());
}

#[test]
fn sdes_parse_handles_lifetime_suffix() {
    // Key params may include a key lifetime: inline:<key>|2^48|1:1
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd|2^48|1:1";
    let km = parse_sdes_crypto(attr).expect("should ignore lifetime suffix");
    assert_eq!(km.master_key.len(), 16);
}

// ─── Key derivation ────────────────────────────────────────────

#[test]
fn derive_keys_produces_correct_lengths() {
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    let km   = parse_sdes_crypto(attr).unwrap();
    let keys = derive_session_keys(&km, 0).expect("should derive session keys");
    assert_eq!(keys.k_e.len(), 16, "AES-128 session key must be 16 bytes");
    assert_eq!(keys.k_s.len(), 14, "session salt must be 14 bytes");
    assert_eq!(keys.k_a.len(), 20, "HMAC-SHA1 auth key must be 20 bytes");
}

#[test]
fn derive_keys_are_non_zero() {
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    let km   = parse_sdes_crypto(attr).unwrap();
    let keys = derive_session_keys(&km, 0).unwrap();
    // The derived keys must not be all-zero (would indicate a broken PRF).
    assert!(keys.k_e.iter().any(|&b| b != 0), "session key must not be all-zero");
    assert!(keys.k_s.iter().any(|&b| b != 0), "session salt must not be all-zero");
    assert!(keys.k_a.iter().any(|&b| b != 0), "auth key must not be all-zero");
}

#[test]
fn derive_keys_differ_from_master() {
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    let km   = parse_sdes_crypto(attr).unwrap();
    let keys = derive_session_keys(&km, 0).unwrap();
    // Session keys must be different from the master key.
    assert_ne!(keys.k_e, km.master_key, "session key must differ from master key");
}

// ─── SRTP packet index ─────────────────────────────────────────

#[test]
fn srtp_index_zero_roc() {
    assert_eq!(srtp_index(0,     0), 0);
    assert_eq!(srtp_index(1,     0), 1);
    assert_eq!(srtp_index(65535, 0), 65535);
}

#[test]
fn srtp_index_with_roc() {
    // ROC=1, SEQ=0: index = 2^16 = 65536
    assert_eq!(srtp_index(0, 1), 65536);
    // ROC=1, SEQ=1: index = 65537
    assert_eq!(srtp_index(1, 1), 65537);
}

// ─── Encrypt / Decrypt round-trip ──────────────────────────────

fn test_keys() -> voip_sip::srtp::SrtpSessionKeys {
    let attr = "1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
    let km   = parse_sdes_crypto(attr).unwrap();
    derive_session_keys(&km, 0).unwrap()
}

#[test]
fn srtp_encrypt_decrypt_round_trip() {
    let keys   = test_keys();
    let mut tx = RtpSendSession::new(0, 8000);
    let payload = vec![0x42u8; 160];     // synthetic G.711 payload
    let pkt     = tx.build_packet(&payload, 160, false);

    let ssrc = tx.ssrc;
    let seq  = voip_sip::rtp::session::RtpHeader::parse(&pkt).unwrap().sequence;

    let encrypted = srtp_encrypt(&pkt, &keys, ssrc, seq, 0);

    // SRTP packet must be longer than RTP by exactly 10 bytes (HMAC tag).
    assert_eq!(encrypted.len(), pkt.len() + 10,
        "SRTP packet must be RTP + 10-byte tag");

    // Payload region must be different (encrypted).
    assert_ne!(&encrypted[12..pkt.len()], payload.as_slice(),
        "ciphertext must differ from plaintext");

    let decrypted = srtp_decrypt(&encrypted, &keys, ssrc, seq, 0)
        .expect("decryption must succeed with correct keys");

    assert_eq!(decrypted, pkt, "decrypted packet must equal original RTP");
}

#[test]
fn srtp_decrypt_fails_on_tampered_tag() {
    let keys   = test_keys();
    let mut tx = RtpSendSession::new(0, 8000);
    let pkt    = tx.build_packet(&vec![0u8; 160], 160, false);
    let ssrc   = tx.ssrc;
    let seq    = voip_sip::rtp::session::RtpHeader::parse(&pkt).unwrap().sequence;

    let mut encrypted = srtp_encrypt(&pkt, &keys, ssrc, seq, 0);
    // Flip a bit in the authentication tag (last 10 bytes).
    let tag_pos = encrypted.len() - 5;
    encrypted[tag_pos] ^= 0xFF;

    let result = srtp_decrypt(&encrypted, &keys, ssrc, seq, 0);
    assert!(result.is_none(), "tampered tag must cause decryption failure");
}

#[test]
fn srtp_decrypt_fails_on_wrong_keys() {
    let keys1  = test_keys();
    let attr2  = "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let keys2  = derive_session_keys(&parse_sdes_crypto(attr2).unwrap(), 0).unwrap();

    let mut tx = RtpSendSession::new(0, 8000);
    let pkt    = tx.build_packet(&vec![1u8; 160], 160, false);
    let ssrc   = tx.ssrc;
    let seq    = voip_sip::rtp::session::RtpHeader::parse(&pkt).unwrap().sequence;

    let encrypted = srtp_encrypt(&pkt, &keys1, ssrc, seq, 0);
    let result    = srtp_decrypt(&encrypted, &keys2, ssrc, seq, 0);
    assert!(result.is_none(), "wrong keys must cause decryption failure");
}

#[test]
fn srtp_different_packets_produce_different_ciphertexts() {
    let keys   = test_keys();
    let mut tx = RtpSendSession::new(0, 8000);
    let p1     = tx.build_packet(&vec![0xAAu8; 160], 160, false);
    let p2     = tx.build_packet(&vec![0xAAu8; 160], 160, false);
    let seq1   = voip_sip::rtp::session::RtpHeader::parse(&p1).unwrap().sequence;
    let seq2   = voip_sip::rtp::session::RtpHeader::parse(&p2).unwrap().sequence;
    let ssrc   = tx.ssrc;
    let e1     = srtp_encrypt(&p1, &keys, ssrc, seq1, 0);
    let e2     = srtp_encrypt(&p2, &keys, ssrc, seq2, 0);
    // Different sequence numbers → different IV → different ciphertext.
    assert_ne!(&e1[12..e1.len()-10], &e2[12..e2.len()-10],
        "same plaintext at different sequence numbers must produce different ciphertexts");
}
