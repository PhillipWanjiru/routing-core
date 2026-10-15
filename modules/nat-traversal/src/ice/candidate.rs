//! ICE candidate model (RFC 8445 §5.1).
//!
//! An ICE candidate is one possible transport address a peer could use
//! to reach this endpoint. Gathering produces several of them (host,
//! server-reflexive via STUN, relayed via TURN); connectivity checks
//! (not yet built — see this module's sibling `gather.rs` doc comment)
//! determine which pair of candidates, one from each side, actually
//! works, and ICE nominates the best working pair.
//!
//! # The priority formula is structural math; the type-preference
//! constants are not
//!
//! RFC 8445 §5.1.2.1:
//! ```text
//! priority = (2^24) * type_preference + (2^8) * local_preference
//!          + (2^0) * (256 - component_id)
//! ```
//! This project verified the formula's *ordering properties* — type
//! always dominates local_preference and component_id regardless of
//! their values, higher local_preference wins within a type, lower
//! component_id wins within a type+local_preference, the maximum
//! possible value fits in u32 — independently in Python before writing
//! this file (five properties, all confirmed). That verification is
//! checking arithmetic, which is derivable.
//!
//! The specific type-preference *constants* (host=126, peer-reflexive=110,
//! server-reflexive=100, relayed=0) are different in kind: they are IANA/
//! RFC registry-style values, recalled from training data the same way
//! every other TURN method number, attribute type, and error code in
//! this project has been — not independently derivable, and flagged with
//! the same caveat: confirm against RFC 8445's text before real-world
//! interop.

use std::net::SocketAddr;

/// Candidate type, in RFC 8445's preference order (host is preferred
/// most, relayed least — see `type_preference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// A local interface address, gathered directly with no network
    /// round-trip.
    Host,
    /// Discovered via a STUN Binding request during a connectivity
    /// check that revealed a NAT mapping not seen during gathering.
    /// Not producible by this module yet — connectivity checks don't
    /// exist yet — included so the type space is complete from day one
    /// rather than needing a breaking enum change later.
    PeerReflexive,
    /// This endpoint's public mapping as observed by a STUN server
    /// (RFC 5389 Binding request/response) — see `gather.rs`.
    ServerReflexive,
    /// A relay port allocated on a TURN server (RFC 5766 Allocate) —
    /// gathering support not yet built in this module; the allocation
    /// and relay mechanics themselves already exist in `turn::allocation`
    /// and `turn::relay`.
    Relayed,
}

impl CandidateType {
    /// RFC 8445 §5.1.2.1 type preference. Recalled registry values —
    /// see this module's doc comment.
    fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relayed => 0,
        }
    }
}

/// One gathered ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub candidate_type: CandidateType,
    /// The transport address a peer would actually send to.
    pub transport_addr: SocketAddr,
    /// For host candidates, the same as `transport_addr`. For
    /// server-reflexive/relayed candidates, the *local* address the
    /// gathering socket was bound to before NAT/relay translation —
    /// RFC 8445 calls this the candidate's "base," and it matters for
    /// foundation grouping (§5.1.1.3): two server-reflexive candidates
    /// discovered from the same local socket share a foundation even
    /// though their public-facing `transport_addr` is identical, because
    /// what actually determines "these behave the same way" is the base,
    /// not the externally-visible address.
    pub base_addr: SocketAddr,
    /// RFC 8445 §5.1.1.3 grouping string — same type + same base address
    /// + same protocol (this project is UDP-only so far) yields the same
    /// foundation. Used to prune candidates that would behave identically
    /// during connectivity checks; not itself a correctness requirement.
    pub foundation: String,
    /// Local preference, used to break ties among same-type candidates
    /// on a multi-homed host (RFC 8445 §5.1.2.2). A single-interface
    /// deployment can leave this at its default; documented as a
    /// parameter rather than hardcoded so a future multi-interface
    /// gathering pass has somewhere to plug in real interface ranking.
    pub local_preference: u16,
    /// 1 for RTP, 2 for RTCP when not multiplexed (RFC 8445 §4.1.1).
    /// This project multiplexes RTP/RTCP on one port in practice, so
    /// component 1 is the only value actually produced today; the field
    /// exists so the type is RFC-complete rather than assuming that
    /// will always remain true.
    pub component_id: u8,
    /// Set only for a *remote peer-reflexive* candidate learned from an
    /// incoming check (RFC 8445 §7.3.1.3). Its priority is whatever the
    /// peer's PRIORITY attribute said, and that exact value must be kept: it
    /// cannot be reconstructed from a type and a local preference, because a
    /// peer is free to advertise any 32-bit value. `None` for every candidate
    /// built through `Candidate::new`.
    pub priority_override: Option<u32>,
}

impl Candidate {
    /// Construct a candidate, computing its priority and foundation from
    /// the fields given — callers never set priority or foundation
    /// directly, so those two can never drift out of sync with the
    /// values that produced them.
    pub fn new(
        candidate_type: CandidateType,
        transport_addr: SocketAddr,
        base_addr: SocketAddr,
        local_preference: u16,
        component_id: u8,
    ) -> Self {
        let foundation = compute_foundation(candidate_type, base_addr);
        Candidate {
            candidate_type,
            transport_addr,
            base_addr,
            foundation,
            local_preference,
            component_id,
            priority_override: None,
        }
    }

    /// A remote peer-reflexive candidate: an address the peer's check came
    /// from that it never signalled to us (typically a symmetric NAT's
    /// per-destination mapping). Its base is unknown, so it is its own base,
    /// and its priority is the exact PRIORITY the check advertised.
    pub fn remote_peer_reflexive(transport_addr: SocketAddr, priority: u32, component_id: u8) -> Self {
        let mut c = Candidate::new(CandidateType::PeerReflexive, transport_addr, transport_addr, 0, component_id);
        c.priority_override = Some(priority);
        c
    }

    /// RFC 8445 §5.1.2.1 priority. Computed on demand rather than cached,
    /// since it is cheap arithmetic and this avoids any risk of a cached
    /// value going stale if a candidate's fields were ever mutated after
    /// construction (they currently aren't, but computing fresh costs
    /// nothing and removes the possibility by construction).
    pub fn priority(&self) -> u32 {
        self.priority_override
            .unwrap_or_else(|| compute_priority(self.candidate_type, self.local_preference, self.component_id))
    }

    /// RFC 8445 §7.1.1: the priority a check sent from this candidate
    /// advertises in its PRIORITY attribute — what a *peer-reflexive*
    /// candidate learned from that check would have. It takes the
    /// peer-reflexive type preference but this candidate's own local
    /// preference and component, so a NAT-discovered address inherits the
    /// ranking of the interface it was discovered through.
    pub fn peer_reflexive_priority(&self) -> u32 {
        compute_priority(CandidateType::PeerReflexive, self.local_preference, self.component_id)
    }
}

/// RFC 8445 §5.1.1.3 foundation: a grouping key shared by candidates that
/// would behave identically during connectivity checks. This
/// implementation groups by (candidate type, base IP address) — the base
/// port is deliberately excluded, matching the RFC's intent that
/// foundation identifies "the same underlying path," not "the exact same
/// socket." Two server-reflexive candidates gathered from two different
/// local ports on the *same* interface still share a foundation here,
/// which is the RFC-correct behaviour for pruning purposes.
fn compute_foundation(candidate_type: CandidateType, base_addr: SocketAddr) -> String {
    format!("{:?}-{}", candidate_type, base_addr.ip())
}

/// The one place the RFC 8445 §5.1.2.1 formula lives, shared by `priority`
/// and `peer_reflexive_priority` so the two can never drift apart.
fn compute_priority(candidate_type: CandidateType, local_preference: u16, component_id: u8) -> u32 {
    let component_term = 256u32.saturating_sub(component_id as u32);
    (1 << 24) * candidate_type.type_preference() + (1 << 8) * (local_preference as u32) + component_term
}
