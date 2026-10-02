//! ICE candidate pairing (RFC 8445 §6.1.2).
//!
//! Once both sides have gathered candidates and exchanged them (via SDP
//! — the encoding for that exchange does not exist yet in this project;
//! see the note in `gather.rs` about scope boundaries applying equally
//! here), each local candidate is paired with each compatible remote
//! candidate. The resulting list, sorted by pair priority, is the check
//! list a connectivity-check state machine (not yet built — the next
//! module after this one) will work through from highest to lowest
//! priority.
//!
//! # Role determines which side is G and which is D
//!
//! RFC 8445 §6.1.2.3's pair priority formula treats the two agents
//! asymmetrically: G is always the *controlling* agent's candidate
//! priority, D is always the *controlled* agent's, regardless of which
//! side (local or remote) happens to be controlling for this session.
//! Getting G/D backwards doesn't crash anything — the formula still
//! produces *a* number — it just produces the wrong number, silently,
//! which is a worse failure mode than a crash. This is why
//! `CandidatePair::priority` takes `IceRole` as an explicit parameter
//! rather than assuming local-is-always-controlling.
//!
//! # Address-family filtering is a deliberate implementation choice, not
//! a quoted RFC requirement
//!
//! RFC 8445 §6.1.2.2 pairs candidates that share a component ID; it does
//! not explicitly forbid pairing an IPv4 candidate with an IPv6 one.
//! This implementation excludes cross-family pairs anyway: such a pair
//! could never succeed a connectivity check regardless of priority, so
//! including it only wastes check-list positions on a pair guaranteed
//! to fail. Flagged here as a choice, not a citation, since — like the
//! TURN/STUN registry constants elsewhere in this project — I'm not
//! certain enough of the RFC's exact wording on this point to present it
//! as a quoted requirement.

use super::candidate::Candidate;
use std::net::IpAddr;

/// Which side of the ICE session this agent is playing for the purpose
/// of the pair-priority formula (RFC 8445 §6.1.2.3, §8.1.1). Determined
/// by out-of-band negotiation (conventionally: the offerer controls)
/// that this module does not implement — a caller supplies the already-
/// decided role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

/// One local×remote candidate combination, with its RFC 8445 §6.1.2.3
/// priority already computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    /// A 64-bit value — wider than an individual candidate's 32-bit
    /// priority, per RFC 8445's own specification of this field's width.
    pub priority: u64,
    /// RFC 8445 §6.1.2.4: `{local foundation}:{remote foundation}` —
    /// pairs sharing a pair foundation are expected to behave alike,
    /// the same pruning rationale as individual candidate foundations.
    pub foundation: String,
}

impl CandidatePair {
    /// Compute RFC 8445 §6.1.2.3 pair priority for `local` and `remote`,
    /// given which side `this_agent_role` occupies.
    ///
    /// Verified independently in Python before this function was
    /// written: the formula's bit width (fits u64 with room to spare),
    /// the tie-bit's role in distinguishing G>D from G<D for the same
    /// two raw priorities, monotonicity in both inputs, and the G==D
    /// edge case — four properties, all confirmed, none of them
    /// re-derived from this Rust and asserted against itself.
    fn compute_priority(local: &Candidate, remote: &Candidate, this_agent_role: IceRole) -> u64 {
        // "This agent" here means the LOCAL side of this pairing
        // operation — the agent doing the pairing, which by construction
        // owns `local`. G is always the controlling agent's priority.
        let (g, d) = match this_agent_role {
            IceRole::Controlling => (local.priority(), remote.priority()),
            IceRole::Controlled  => (remote.priority(), local.priority()),
        };
        let lo = g.min(d) as u64;
        let hi = g.max(d) as u64;
        let tie_bit: u64 = if g > d { 1 } else { 0 };
        (1u64 << 32) * lo + 2 * hi + tie_bit
    }

    fn new(local: Candidate, remote: Candidate, role: IceRole) -> Self {
        let priority = Self::compute_priority(&local, &remote, role);
        let foundation = format!("{}:{}", local.foundation, remote.foundation);
        CandidatePair { local, remote, priority, foundation }
    }
}

/// Whether two candidates are eligible to be paired at all: same
/// component ID (RFC 8445 §6.1.2.2), and — this implementation's own
/// choice, see this module's doc comment — same IP address family.
fn compatible(local: &Candidate, remote: &Candidate) -> bool {
    if local.component_id != remote.component_id {
        return false;
    }
    matches!(
        (local.transport_addr.ip(), remote.transport_addr.ip()),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// Form the full check list: every compatible local×remote combination,
/// sorted by pair priority descending (RFC 8445 §6.1.2.5 — checks
/// proceed from the highest-priority pair down).
///
/// This does not deduplicate pairs sharing a foundation (RFC 8445 permits
/// an implementation to prune "frozen" redundant pairs as an
/// optimisation — that pruning is check-list *scheduling* behaviour,
/// which belongs with the connectivity-check state machine, not with
/// pair formation itself).
pub fn form_candidate_pairs(
    local_candidates: &[Candidate],
    remote_candidates: &[Candidate],
    role: IceRole,
) -> Vec<CandidatePair> {
    let mut pairs: Vec<CandidatePair> = local_candidates
        .iter()
        .flat_map(|local| {
            remote_candidates
                .iter()
                .filter(move |remote| compatible(local, remote))
                .map(move |remote| CandidatePair::new(local.clone(), remote.clone(), role))
        })
        .collect();

    // Descending by priority; RFC 8445 does not mandate a specific
    // tiebreak for equal priorities, so ties keep their original
    // (local-candidate-major, remote-candidate-minor) relative order —
    // Rust's sort_by is stable, which is what makes that guarantee hold.
    pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
    pairs
}
