//! ICE connectivity-check message codec (RFC 8445 §7).
//!
//! Pure functions over bytes — no sockets, no timers, no state. The
//! connectivity-check engine (next module) owns *when* to send and *what to
//! do with the result*; this module owns *what a valid check looks like on
//! the wire* and *whether a received message is one*. Keeping that split
//! means every validation rule here is testable against fixed byte vectors,
//! the same way `turn::server`'s handlers and `stun::server::handle_datagram`
//! are.
//!
//! # What an ICE check carries
//!
//! A check request is a STUN Binding request with: USERNAME (`remote_ufrag:
//! local_ufrag`), PRIORITY, exactly one of ICE-CONTROLLING / ICE-CONTROLLED
//! (carrying a 64-bit tie-breaker), optionally USE-CANDIDATE (controlling
//! agent only), then MESSAGE-INTEGRITY keyed by the *short-term credential* —
//! the ICE password — and finally FINGERPRINT. A success response carries
//! XOR-MAPPED-ADDRESS (the request's observed source) plus the same
//! MESSAGE-INTEGRITY and FINGERPRINT.
//!
//! # Verification discipline
//!
//! Byte-exactness of the builders and acceptance by the validators are both
//! checked against messages built by an independent Python implementation
//! (hmac/hashlib/zlib) from the RFC construction rules — not merely against
//! each other. That oracle is still *my* reading of the rules, not RFC 5769's
//! published vectors, so interoperability with a real ICE stack remains
//! unproven until tested against one.
//!
//! # Constants flagged as recalled
//!
//! Attribute type numbers (PRIORITY, USE-CANDIDATE, ICE-CONTROLLING/
//! CONTROLLED), error code 487 (Role Conflict), and the FINGERPRINT XOR
//! constant are recalled registry values, not derivable; confirm against
//! the RFCs before real-world interop.

use super::pair::IceRole;
use crate::stun::{
    attributes::{
        decode_attributes, encode_xor_mapped_address, Attribute, ATTR_ERROR_CODE,
        ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY, ATTR_USERNAME,
        ATTR_USE_CANDIDATE, ATTR_XOR_MAPPED_ADDRESS,
    },
    builder::{
        build_attribute, build_message, encode_error_code, encode_priority, encode_tie_breaker,
    },
    fingerprint::{append_fingerprint, verify_fingerprint},
    integrity::{append_integrity, verify_integrity},
    parser::{parse_message, MessageClass, Method},
    SocketAddrAttr,
};
use std::net::SocketAddr;

// ─── Building ────────────────────────────────────────────────────

/// Everything needed to build one outgoing check request.
pub struct CheckRequestParams<'a> {
    pub txn_id: [u8; 12],
    /// `"REMOTE_UFRAG:LOCAL_UFRAG"` — the receiver's ufrag first.
    pub username: &'a str,
    /// The *remote* agent's ICE password: the short-term credential key.
    pub password: &'a [u8],
    /// Priority this agent's candidate would have if it became
    /// peer-reflexive (RFC 8445 §7.1.1).
    pub priority: u32,
    pub role: IceRole,
    pub tie_breaker: u64,
    /// Request nomination of this pair. Honoured only for the controlling
    /// agent: a controlled agent never sets USE-CANDIDATE (RFC 8445 §7.1.2),
    /// so the flag is ignored rather than allowing a malformed message.
    pub use_candidate: bool,
}

/// Build a signed check request: attributes, then MESSAGE-INTEGRITY, then
/// FINGERPRINT (that order is mandatory — FINGERPRINT is always last).
pub fn build_check_request(p: &CheckRequestParams<'_>) -> Vec<u8> {
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&build_attribute(ATTR_USERNAME, p.username.as_bytes()));
    attrs.extend_from_slice(&build_attribute(ATTR_PRIORITY, &encode_priority(p.priority)));
    match p.role {
        IceRole::Controlling => attrs.extend_from_slice(&build_attribute(
            ATTR_ICE_CONTROLLING,
            &encode_tie_breaker(p.tie_breaker),
        )),
        IceRole::Controlled => attrs.extend_from_slice(&build_attribute(
            ATTR_ICE_CONTROLLED,
            &encode_tie_breaker(p.tie_breaker),
        )),
    }
    if p.use_candidate && p.role == IceRole::Controlling {
        attrs.extend_from_slice(&build_attribute(ATTR_USE_CANDIDATE, &[]));
    }

    let mut msg = build_message(MessageClass::Request, Method::Binding, &p.txn_id, &attrs);
    append_integrity(&mut msg, p.password);
    append_fingerprint(&mut msg);
    msg
}

/// Build a signed success response reporting `source`, the address the
/// request was observed arriving from. `password` is the responder's own ICE
/// password — the same key the requester used to sign the request.
pub fn build_check_success_response(txn_id: &[u8; 12], source: SocketAddr, password: &[u8]) -> Vec<u8> {
    let value = encode_xor_mapped_address(
        &SocketAddrAttr { ip: source.ip(), port: source.port() },
        txn_id,
    );
    let attrs = build_attribute(ATTR_XOR_MAPPED_ADDRESS, &value);
    let mut msg = build_message(MessageClass::SuccessResponse, Method::Binding, txn_id, &attrs);
    append_integrity(&mut msg, password);
    append_fingerprint(&mut msg);
    msg
}

/// Build an error response. Pass `Some(password)` when the request itself
/// authenticated (e.g. 487 Role Conflict — the requester must be able to
/// trust it, or an attacker could force role flips); pass `None` for errors
/// to requests that failed authentication (400/401), which cannot be signed
/// meaningfully. FINGERPRINT is always appended.
pub fn build_check_error_response(
    txn_id: &[u8; 12],
    code: u16,
    reason: &str,
    password: Option<&[u8]>,
) -> Vec<u8> {
    let attrs = build_attribute(ATTR_ERROR_CODE, &encode_error_code(code, reason));
    let mut msg = build_message(MessageClass::ErrorResponse, Method::Binding, txn_id, &attrs);
    if let Some(pw) = password {
        append_integrity(&mut msg, pw);
    }
    append_fingerprint(&mut msg);
    msg
}

// ─── Parsing / validating a received request ─────────────────────

/// A received check request that passed every validation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCheckRequest {
    pub txn_id: [u8; 12],
    /// The sender's ufrag (the part of USERNAME after the colon).
    pub remote_ufrag: String,
    pub priority: u32,
    /// The *sender's* role, inferred from which tie-breaker attribute it used.
    pub sender_role: IceRole,
    pub tie_breaker: u64,
    /// True only if the sender is controlling *and* set USE-CANDIDATE.
    pub use_candidate: bool,
}

/// Why a received message was not accepted as a check request. The engine
/// maps these to actions: the first two are silent drops, `Unauthorized`
/// warrants a 401, `BadRequest` a 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckRequestError {
    /// Not a parseable STUN Binding *request*.
    NotBindingRequest,
    /// FINGERPRINT missing or wrong — this is not STUN-for-ICE.
    BadFingerprint,
    /// USERNAME missing or not addressed to us, or MESSAGE-INTEGRITY missing
    /// or wrong.
    Unauthorized,
    /// Authenticated, but a required attribute is missing or contradictory.
    BadRequest(&'static str),
}

/// Validate a received datagram as an ICE check request addressed to the
/// agent holding `local_ufrag` / `local_password`.
///
/// Order matters: FINGERPRINT first (cheap, filters non-STUN), then USERNAME
/// and MESSAGE-INTEGRITY (authentication), and only *then* the semantic
/// attributes — so an unauthenticated sender learns nothing about which
/// attribute it got wrong.
pub fn parse_check_request(
    raw: &[u8],
    local_ufrag: &str,
    local_password: &[u8],
) -> Result<ParsedCheckRequest, CheckRequestError> {
    let msg = parse_message(raw).map_err(|_| CheckRequestError::NotBindingRequest)?;
    if msg.class != MessageClass::Request || msg.method != Method::Binding {
        return Err(CheckRequestError::NotBindingRequest);
    }
    if !verify_fingerprint(raw) {
        return Err(CheckRequestError::BadFingerprint);
    }

    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);

    let username = attrs
        .iter()
        .find_map(|a| if let Attribute::Username(u) = a { Some(u.as_str()) } else { None })
        .ok_or(CheckRequestError::Unauthorized)?;
    let (addressed_to, remote_ufrag) =
        username.split_once(':').ok_or(CheckRequestError::Unauthorized)?;
    if addressed_to != local_ufrag {
        return Err(CheckRequestError::Unauthorized);
    }
    if !verify_integrity(raw, local_password) {
        return Err(CheckRequestError::Unauthorized);
    }

    let priority = attrs
        .iter()
        .find_map(|a| if let Attribute::Priority(p) = a { Some(*p) } else { None })
        .ok_or(CheckRequestError::BadRequest("missing PRIORITY"))?;

    let controlling = attrs
        .iter()
        .find_map(|a| if let Attribute::IceControlling(t) = a { Some(*t) } else { None });
    let controlled = attrs
        .iter()
        .find_map(|a| if let Attribute::IceControlled(t) = a { Some(*t) } else { None });
    let (sender_role, tie_breaker) = match (controlling, controlled) {
        (Some(t), None) => (IceRole::Controlling, t),
        (None, Some(t)) => (IceRole::Controlled, t),
        (Some(_), Some(_)) => {
            return Err(CheckRequestError::BadRequest("both ICE-CONTROLLING and ICE-CONTROLLED"))
        }
        (None, None) => {
            return Err(CheckRequestError::BadRequest("missing ICE-CONTROLLING/ICE-CONTROLLED"))
        }
    };

    let use_candidate = sender_role == IceRole::Controlling
        && attrs.iter().any(|a| matches!(a, Attribute::UseCandidate));

    Ok(ParsedCheckRequest {
        txn_id: msg.transaction_id,
        remote_ufrag: remote_ufrag.to_owned(),
        priority,
        sender_role,
        tie_breaker,
        use_candidate,
    })
}

// ─── Parsing / validating a received response ────────────────────

/// A response that matched our outstanding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResponse {
    /// Authenticated success; `mapped` is where the peer saw our request
    /// come from — a possible new peer-reflexive candidate.
    Success { mapped: SocketAddr },
    /// An error response. `authenticated` says whether its MESSAGE-INTEGRITY
    /// verified: the engine must only act on a 487 Role Conflict if it is
    /// authenticated, since an off-path attacker could otherwise forge one to
    /// flip our role.
    Error { code: u16, authenticated: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResponseError {
    /// Unparseable, or not a Binding success/error response.
    NotBindingResponse,
    /// Transaction ID does not match the request we sent.
    TransactionMismatch,
    BadFingerprint,
    /// A success response whose MESSAGE-INTEGRITY is missing or wrong.
    BadIntegrity,
    /// Success response with no usable XOR-MAPPED-ADDRESS, or an error
    /// response with no ERROR-CODE.
    Malformed,
}

/// Validate a received datagram as the response to the request identified by
/// `expected_txn`, signed with `remote_password` (the password the request
/// was keyed with).
pub fn parse_check_response(
    raw: &[u8],
    expected_txn: &[u8; 12],
    remote_password: &[u8],
) -> Result<CheckResponse, CheckResponseError> {
    let msg = parse_message(raw).map_err(|_| CheckResponseError::NotBindingResponse)?;
    if msg.method != Method::Binding
        || !matches!(msg.class, MessageClass::SuccessResponse | MessageClass::ErrorResponse)
    {
        return Err(CheckResponseError::NotBindingResponse);
    }
    if msg.transaction_id != *expected_txn {
        return Err(CheckResponseError::TransactionMismatch);
    }
    if !verify_fingerprint(raw) {
        return Err(CheckResponseError::BadFingerprint);
    }

    let authenticated = verify_integrity(raw, remote_password);
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);

    match msg.class {
        MessageClass::SuccessResponse => {
            if !authenticated {
                return Err(CheckResponseError::BadIntegrity);
            }
            let mapped = attrs
                .iter()
                .find_map(|a| if let Attribute::XorMappedAddress(m) = a { Some(*m) } else { None })
                .ok_or(CheckResponseError::Malformed)?;
            Ok(CheckResponse::Success { mapped: SocketAddr::new(mapped.ip, mapped.port) })
        }
        _ => {
            let code = attrs
                .iter()
                .find_map(|a| if let Attribute::ErrorCode { code, .. } = a { Some(*code) } else { None })
                .ok_or(CheckResponseError::Malformed)?;
            Ok(CheckResponse::Error { code, authenticated })
        }
    }
}
