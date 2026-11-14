//! The decisions the SIP side makes about ICE in an offer/answer exchange
//! (RFC 8839 §4, RFC 8445 §6.1.1 and §5.1.4). The agent that acts on them is in
//! `nat-traversal`; this is what to tell it, and what to put in the SDP.

use nat_traversal::ice::sdp::IceDescription;
use nat_traversal::ice::{Candidate, CandidateType, IceRole};

pub use nat_traversal::ice::IceCredentials;

/// The role this agent takes (RFC 8445 §6.1.1).
///
/// A full agent facing a lite peer is always controlling: a lite agent only answers
/// checks, so someone has to drive. Between two full agents the one that made the offer
/// is controlling. Roles can still collide afterwards (both ends believing they control),
/// which the agent resolves with its tie-breaker; this only gets the common case right
/// from the start.
pub fn role_for(we_are_the_offerer: bool, peer_is_lite: bool) -> IceRole {
    if peer_is_lite || we_are_the_offerer {
        IceRole::Controlling
    } else {
        IceRole::Controlled
    }
}

/// How likely a candidate type is to work, for choosing the default candidate: a relayed
/// candidate works whenever the relay is reachable, a server-reflexive one when the NAT
/// cooperates, a host one only on the same network.
fn likelihood(t: CandidateType) -> u8 {
    match t {
        CandidateType::Relayed => 3,
        CandidateType::ServerReflexive => 2,
        CandidateType::PeerReflexive => 1,
        CandidateType::Host => 0,
    }
}

/// The default candidate: the one whose address goes in the `m=` and `c=` lines, which an
/// endpoint that does not do ICE will use. RFC 8445 §5.1.4 recommends the candidate most
/// likely to work: relayed, then server-reflexive, then host (recalled, not checked against
/// the text); within a type, the highest priority; then the first listed, so the choice is
/// deterministic. Only component 1 (RTP) is considered.
pub fn default_candidate(candidates: &[Candidate]) -> Option<&Candidate> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.component_id == 1)
        .max_by_key(|(i, c)| (likelihood(c.candidate_type), c.priority(), std::cmp::Reverse(*i)))
        .map(|(_, c)| c)
}

/// Why the peer's ICE description cannot be negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    /// No `ice-ufrag` or no `ice-pwd`: the peer is not offering ICE, or not usably.
    MissingCredentials,
    /// No candidate this agent can use. `skipped` counts those that were well-formed but
    /// unsupported (TCP, hostnames). This agent does not trickle, so a description with
    /// no candidates now will not get any later.
    NoUsableCandidates { skipped: usize },
}

impl std::fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NegotiationError::MissingCredentials => write!(f, "the peer's ICE description has no ufrag or password"),
            NegotiationError::NoUsableCandidates { skipped } => {
                write!(f, "the peer offered no usable candidate ({skipped} skipped as unsupported)")
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Check that the peer's description is something ICE can be run against.
pub fn check_remote(description: &IceDescription) -> Result<(), NegotiationError> {
    if description.ufrag.is_none() || description.pwd.is_none() {
        return Err(NegotiationError::MissingCredentials);
    }
    if description.candidates.is_empty() {
        return Err(NegotiationError::NoUsableCandidates { skipped: description.skipped.len() });
    }
    Ok(())
}
