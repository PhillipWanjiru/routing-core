//! The ICE check list (RFC 8445 §6.1.2): which pairs to probe, in what
//! order, and the state each is in.
//!
//! Pure data and rules — no timers, no I/O. The agent drives it; keeping the
//! rules here means pruning, freezing and re-prioritisation are testable
//! without a clock.
//!
//! # Pruning (RFC 8445 §6.1.2.4)
//!
//! A server-reflexive local candidate is never used as the *source* of a
//! check — the packet leaves from its **base** (the host socket that learned
//! the mapping). So a host candidate H and its server-reflexive candidate S
//! paired with the same remote R produce the *same* packet, from H to R. The
//! check list keeps only one of them (the higher-priority, i.e. the host).
//! The key is therefore `(local base, remote address, component)`. Remote
//! server-reflexive candidates are not collapsed: their base is not known
//! to us.
//!
//! # Freezing (RFC 8445 §6.1.2.6)
//!
//! Pairs sharing a foundation are expected to behave alike, so only one per
//! foundation starts `Waiting`; the rest start `Frozen` and are released
//! when that one succeeds. This avoids sending the same doomed probe down a
//! dozen equivalent paths.
//!
//! RFC section numbers here and in `agent.rs` are cited from memory —
//! verify against the RFC text.

use super::pair::{CandidatePair, IceRole};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Waiting for another pair with the same foundation to succeed first.
    Frozen,
    /// Eligible to be checked at the next pacing tick.
    Waiting,
    /// A check has been sent and no final result is known.
    InProgress,
    /// A check on this pair got a valid success response.
    Succeeded,
    /// The check timed out, was answered with an error, or its response was
    /// not symmetric with the request.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckListEntry {
    /// Stable identifier, assigned in original priority order. Unlike a
    /// vector index it survives re-sorting after a role switch, which is why
    /// the agent's triggered-check queue and transactions refer to entries by
    /// `id`.
    pub id: usize,
    pub pair: CandidatePair,
    pub state: PairState,
}

#[derive(Debug, Clone)]
pub struct CheckList {
    /// Kept sorted by pair priority, highest first.
    entries: Vec<CheckListEntry>,
}

impl CheckList {
    /// Prune redundant pairs, order by priority, and apply initial freezing.
    pub fn build(mut pairs: Vec<CandidatePair>) -> Self {
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut seen = HashSet::new();
        let kept: Vec<CandidatePair> = pairs
            .into_iter()
            .filter(|p| seen.insert((p.local.base_addr, p.remote.transport_addr, p.local.component_id)))
            .collect();

        let mut entries: Vec<CheckListEntry> = kept
            .into_iter()
            .enumerate()
            .map(|(id, pair)| CheckListEntry { id, pair, state: PairState::Frozen })
            .collect();

        // Per foundation, the pair with the lowest component id — and among
        // those the highest priority, which is first in this ordering —
        // starts Waiting.
        let mut lowest_component: HashMap<String, u8> = HashMap::new();
        for e in &entries {
            lowest_component
                .entry(e.pair.foundation.clone())
                .and_modify(|c| *c = (*c).min(e.pair.local.component_id))
                .or_insert(e.pair.local.component_id);
        }
        let mut released: HashSet<String> = HashSet::new();
        for e in &mut entries {
            if e.pair.local.component_id == lowest_component[&e.pair.foundation]
                && released.insert(e.pair.foundation.clone())
            {
                e.state = PairState::Waiting;
            }
        }

        CheckList { entries }
    }

    /// Add a pair formed after construction — e.g. from a check that arrived
    /// from a remote candidate we were never told about. The list stays
    /// sorted; the sort is stable, so an equal-priority newcomer goes after
    /// the existing ones. Returns the new entry's stable id (one past the
    /// largest in use, so ids are never reused).
    pub fn add_pair(&mut self, pair: CandidatePair, state: PairState) -> usize {
        let id = self.entries.iter().map(|e| e.id).max().map_or(0, |m| m + 1);
        self.entries.push(CheckListEntry { id, pair, state });
        self.entries.sort_by(|a, b| b.pair.priority.cmp(&a.pair.priority));
        id
    }

    /// The entry whose check leaves `local_base` for `remote` on `component`:
    /// the same key pruning uses, so a pruned list holds at most one.
    pub fn find_entry(&self, local_base: SocketAddr, remote: SocketAddr, component: u8) -> Option<usize> {
        self.entries
            .iter()
            .find(|e| {
                e.pair.local.base_addr == local_base
                    && e.pair.remote.transport_addr == remote
                    && e.pair.local.component_id == component
            })
            .map(|e| e.id)
    }

    pub fn entries(&self) -> &[CheckListEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, id: usize) -> Option<&CheckListEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn entry_mut(&mut self, id: usize) -> Option<&mut CheckListEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    pub fn count(&self, state: PairState) -> usize {
        self.entries.iter().filter(|e| e.state == state).count()
    }

    /// Any pair still able to produce a result: Frozen, Waiting or InProgress.
    pub fn has_pending(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.state, PairState::Frozen | PairState::Waiting | PairState::InProgress))
    }

    /// Highest-priority Waiting pair.
    pub fn next_waiting(&self) -> Option<usize> {
        self.entries.iter().find(|e| e.state == PairState::Waiting).map(|e| e.id)
    }

    /// RFC 8445 §6.1.4.2: when nothing is Waiting, the highest-priority
    /// Frozen pair is released so the check list always makes progress even
    /// if no foundation ever succeeds.
    pub fn unfreeze_highest(&mut self) -> Option<usize> {
        let e = self.entries.iter_mut().find(|e| e.state == PairState::Frozen)?;
        e.state = PairState::Waiting;
        Some(e.id)
    }

    /// RFC 8445 §7.2.5.3.3: a success releases every Frozen pair sharing its
    /// foundation. Pairs in any other state are untouched.
    pub fn unfreeze_foundation(&mut self, foundation: &str) {
        for e in &mut self.entries {
            if e.state == PairState::Frozen && e.pair.foundation == foundation {
                e.state = PairState::Waiting;
            }
        }
    }

    /// Re-prioritise every pair for `role` and restore priority order. The
    /// sort is stable, so equal-priority pairs keep their relative order.
    pub fn recompute_priorities(&mut self, role: IceRole) {
        for e in &mut self.entries {
            e.pair.recompute_priority(role);
        }
        self.entries.sort_by(|a, b| b.pair.priority.cmp(&a.pair.priority));
    }
}
