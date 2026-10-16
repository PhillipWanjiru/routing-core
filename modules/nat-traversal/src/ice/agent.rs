//! ICE connectivity-check agent, initiator side (RFC 8445 §6–7).
//!
//! A deterministic state machine: it owns no socket and reads no clock. The
//! caller passes the current `Instant` into every call and receives
//! [`IceAction`]s describing what to send. That is the same shape as every
//! other protocol handler in this project (`turn::server`, the allocation
//! tables), for the same reason: time and I/O are the hard things to test, so
//! they are kept outside, and the logic inside is exercised with a virtual
//! clock — no `sleep`, no flakiness, and two agents can be wired together in
//! memory.
//!
//! # What this slice implements
//!
//! * Check scheduling: one new check per pacing interval `Ta`, highest-priority
//!   Waiting pair first, releasing the best Frozen pair when none is Waiting.
//! * Transactions: STUN retransmission with exponential backoff and a final
//!   wait, with the initial RTO scaled by how many pairs are pending (RFC 8445
//!   §14.3), so a large check list cannot flood the network.
//! * Response handling: authenticated success → valid pair (learning a
//!   peer-reflexive local candidate when the NAT mapping differs from every
//!   known one); symmetric-address enforcement; error responses; and
//!   **role-conflict (487)** handling, including the subtle case of several
//!   checks in flight all being answered 487.
//!
//! # Responder side (RFC 8445 §7.3)
//!
//! Incoming check requests are validated by the codec whose tests proved it
//! byte-exact, and then:
//!
//! * **Role conflicts** are resolved by tie-breaker, arranged so the larger
//!   tie-breaker ends up controlling at both ends. The loser either switches
//!   role or answers 487 (signed, so it cannot be forged).
//! * **Triggered checks**: a valid request moves its pair to the front of the
//!   queue so the reverse path is probed at once. This is what makes hole
//!   punching work through address-restricted NATs: each side's first check
//!   is dropped, but it opens the permission the other side's check needs.
//! * **Remote peer-reflexive candidates**: a request from an address we were
//!   never told about — a symmetric NAT's per-destination mapping — becomes a
//!   new remote candidate with its own pair.
//! * A request that fails authentication creates nothing: no pair, no
//!   candidate, no triggered check.
//!
//! # Nomination and completion (RFC 8445 §8)
//!
//! *Regular* nomination only (aggressive nomination is deprecated by RFC
//! 8445). The controlling agent waits a short, configurable time after its
//! first valid pair for a better one — nominating at once if nothing better can
//! still arrive — then sends a check carrying USE-CANDIDATE on the best valid
//! pair; when that succeeds, the pair is nominated. The controlled agent
//! nominates a pair only when it has received USE-CANDIDATE on it *and* its own
//! check on that pair has succeeded, so a nominated path has been verified in
//! both directions. ICE completes when every component has a nominated pair;
//! the agent then stops checking but keeps answering the peer.
//!
//! # Not implemented yet
//!
//! Relayed-candidate sending, keepalives, ICE restart.
//!
//! # A response that fails validation is discarded, and the transaction runs on
//!
//! An off-path attacker can send anything to our port. If a bad response
//! could end a transaction, forging one would be a cheap denial of service.
//! So a response with a bad fingerprint or integrity is dropped silently and
//! the pair keeps retransmitting until the real answer or the timeout.

use super::{
    candidate::{Candidate, CandidateType},
    check_msg::{
        build_check_error_response, build_check_request, build_check_success_response,
        parse_check_request, parse_check_response, CheckRequestError, CheckRequestParams,
        CheckResponse,
    },
    checklist::{CheckList, PairState},
    pair::{form_candidate_pairs, CandidatePair, IceRole},
    random::{random_bytes, random_u64},
};
use crate::stun::parser::{parse_message, MessageClass};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How the controlling agent picks the pair that media will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nomination {
    /// RFC 8445 §8.1.1.1 regular nomination. After the first valid pair, wait
    /// up to `delay` for a better one; nominate at once if no higher-priority
    /// pair is still being checked. The wait matters: the highest-priority
    /// pair is often a dead one (an unreachable private address), which would
    /// otherwise hold up a working path for the full transaction timeout.
    Regular { delay: Duration },
    /// Never nominate automatically. For tests of the checking machinery in
    /// isolation, and for callers who pick the path themselves with
    /// [`IceAgent::nominate_now`].
    Never,
}

/// Timer configuration. Defaults follow the RFCs: `Ta` 50 ms for a single
/// audio stream (RFC 8445 §14.2), and STUN's Rc = 7 transmissions with
/// Rm = 16 (RFC 5389 §7.2.1).
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// Pacing: at most one new check is started per `ta`.
    pub ta: Duration,
    /// Floor for a transaction's initial retransmission timeout.
    pub min_rto: Duration,
    /// Rc — total transmissions of one request, including the first.
    pub max_transmissions: u32,
    /// Rm — after the last transmission, wait `rto * final_wait_multiplier`
    /// before giving up.
    pub final_wait_multiplier: u32,
    /// How the controlling agent nominates. Ignored by a controlled agent.
    pub nomination: Nomination,
}

impl Default for IceConfig {
    fn default() -> Self {
        IceConfig {
            ta: Duration::from_millis(50),
            min_rto: Duration::from_millis(500),
            max_transmissions: 7,
            final_wait_multiplier: 16,
            // 100 ms: long enough for checks already in flight to return,
            // short enough not to be felt in call setup. A policy choice,
            // not an RFC value.
            nomination: Nomination::Regular { delay: Duration::from_millis(100) },
        }
    }
}

/// An ICE username fragment and password (RFC 8839 `a=ice-ufrag`/`a=ice-pwd`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    pub ufrag: String,
    pub password: String,
}

/// What the caller must do on the agent's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IceAction {
    /// Send `data` from the socket bound to `from` to `to`.
    Send { from: SocketAddr, to: SocketAddr, data: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecklistState {
    Running,
    /// A nominated valid pair exists for every component. The agent stops
    /// checking but keeps answering the peer's checks.
    Completed,
    /// Every pair is settled and none produced a valid pair.
    Failed,
}

/// A pair that a check has verified as working. Distinct from the check-list
/// entry that generated the check: when the NAT maps differently than any
/// candidate we knew, the valid pair's local side is a *new* peer-reflexive
/// candidate that was never in the check list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidPair {
    pub pair: CandidatePair,
    /// Set once this pair has been nominated (RFC 8445 §8): the controlling
    /// agent's USE-CANDIDATE check on it succeeded, or the controlled agent
    /// received one on a pair whose own check had also succeeded.
    pub nominated: bool,
    /// Ids of the check-list entries whose successful checks produced this
    /// pair — usually one, several when different entries lead to the same
    /// path (e.g. two sockets mapped to one peer-reflexive address). The
    /// controlled agent needs this: a nomination names an entry's pair, and
    /// the valid pair *that entry generated* is what gets nominated.
    pub generated_by: Vec<usize>,
}

/// One outstanding check request.
struct Transaction {
    entry_id: usize,
    txn_id: [u8; 12],
    /// The exact bytes sent — retransmissions are byte-identical.
    request: Vec<u8>,
    from: SocketAddr,
    to: SocketAddr,
    sent_count: u32,
    next_send_at: Option<Instant>,
    /// Set once the final transmission has gone out.
    deadline: Option<Instant>,
    rto: Duration,
    /// The role this request was sent under. A 487 only means "switch" if our
    /// role has not already changed since — see `on_role_conflict`.
    role: IceRole,
    /// Set when a triggered check supersedes this transaction (RFC 8445
    /// §7.3.1.4): it stops retransmitting and its timeout no longer counts as
    /// a failure, but a *success* answering it is still honoured — the packet
    /// may simply have been slow.
    cancelled: bool,
    /// A USE-CANDIDATE check on an already-Succeeded pair. It must not change
    /// the entry's state, and at most one is in flight at a time.
    nominating: bool,
}

pub struct IceAgent {
    config: IceConfig,
    role: IceRole,
    tie_breaker: u64,
    local: IceCredentials,
    remote: IceCredentials,
    local_candidates: Vec<Candidate>,
    /// The peer's candidates, including peer-reflexive ones learned from
    /// incoming checks.
    remote_candidates: Vec<Candidate>,
    /// Transaction IDs of requests already acted on, so a retransmitted
    /// request is answered again but does not re-trigger a check each time.
    seen_requests: VecDeque<[u8; 12]>,
    /// When the first valid pair appeared: the start of the nomination wait.
    first_valid_at: Option<Instant>,
    /// Entries the peer nominated before our own check on them succeeded; they
    /// are nominated when it does.
    pending_nomination: Vec<usize>,
    checklist: CheckList,
    valid: Vec<ValidPair>,
    transactions: Vec<Transaction>,
    /// Entries queued for an immediate re-check, ahead of ordinary ones.
    triggered: VecDeque<usize>,
    next_check_at: Instant,
    state: ChecklistState,
}

/// A fresh random 64-bit tie-breaker (RFC 8445 §5.2).
pub fn random_tie_breaker() -> u64 {
    random_u64()
}

impl IceAgent {
    /// Form pairs from the two candidate lists, prune and freeze them, and
    /// start in `Running` (or `Failed` if there is nothing to check).
    /// `now` is the clock origin: the first check is due immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: IceConfig,
        role: IceRole,
        tie_breaker: u64,
        local: IceCredentials,
        remote: IceCredentials,
        local_candidates: Vec<Candidate>,
        remote_candidates: Vec<Candidate>,
        now: Instant,
    ) -> Self {
        let pairs = form_candidate_pairs(&local_candidates, &remote_candidates, role);
        let checklist = CheckList::build(pairs);
        let state = if checklist.is_empty() { ChecklistState::Failed } else { ChecklistState::Running };
        IceAgent {
            config,
            role,
            tie_breaker,
            local,
            remote,
            local_candidates,
            remote_candidates,
            seen_requests: VecDeque::new(),
            first_valid_at: None,
            pending_nomination: Vec::new(),
            checklist,
            valid: Vec::new(),
            transactions: Vec::new(),
            triggered: VecDeque::new(),
            next_check_at: now,
            state,
        }
    }

    pub fn role(&self) -> IceRole {
        self.role
    }

    pub fn state(&self) -> ChecklistState {
        self.state
    }

    pub fn checklist(&self) -> &CheckList {
        &self.checklist
    }

    /// Verified pairs, highest priority first.
    pub fn valid_pairs(&self) -> &[ValidPair] {
        &self.valid
    }

    /// The original local candidates plus any peer-reflexive ones learned.
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    /// The peer's candidates as signalled, plus any peer-reflexive ones
    /// learned from the source of an incoming check.
    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    /// The best nominated valid pair — the path media should use — once ICE has
    /// nominated one. For a multi-component session see
    /// [`selected_pair_for`](Self::selected_pair_for).
    pub fn selected_pair(&self) -> Option<&ValidPair> {
        self.valid.iter().find(|v| v.nominated)
    }

    /// The best nominated valid pair for `component`.
    pub fn selected_pair_for(&self, component: u8) -> Option<&ValidPair> {
        self.valid.iter().find(|v| v.nominated && v.pair.local.component_id == component)
    }

    /// Advance time: retransmit or expire transactions, and start the next
    /// check if the pacing interval has elapsed. At most one new check is
    /// started per call, and each transaction retransmits at most once per
    /// call — a late caller does not get a burst of catch-up traffic.
    pub fn poll(&mut self, now: Instant) -> Vec<IceAction> {
        let mut actions = Vec::new();
        self.service_transactions(now, &mut actions);
        self.maybe_nominate(now, &mut actions);

        if self.state == ChecklistState::Running && now >= self.next_check_at {
            if let Some(id) = self.pick_next_check() {
                if let Some(action) = self.start_check(id, now, false) {
                    actions.push(action);
                    self.next_check_at = now + self.config.ta;
                }
            }
        }

        self.refresh_state();
        actions
    }

    /// The earliest instant at which `poll` has something to do, or `None`
    /// if the agent is idle. A driver sleeps until this.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for t in &self.transactions {
            if let Some(n) = t.next_send_at {
                consider(n);
            }
            if let Some(d) = t.deadline {
                consider(d);
            }
        }
        let has_unstarted = self.checklist.count(PairState::Waiting) > 0
            || self.checklist.count(PairState::Frozen) > 0
            || !self.triggered.is_empty();
        if self.state == ChecklistState::Running && has_unstarted {
            consider(self.next_check_at);
        }
        // Nomination falls due `delay` after the first valid pair — or at once
        // if nothing better can still arrive.
        if self.nomination_waiting() {
            if let (Nomination::Regular { delay }, Some(first)) = (self.config.nomination, self.first_valid_at) {
                consider(if self.better_pair_pending() { first + delay } else { first });
            }
        }
        earliest
    }

    /// Feed in a received datagram. `from` is its source; `to` is the local
    /// address it arrived at. Returns anything that must now be sent.
    pub fn handle_datagram(&mut self, from: SocketAddr, to: SocketAddr, raw: &[u8], now: Instant) -> Vec<IceAction> {
        let Ok(msg) = parse_message(raw) else {
            return Vec::new();
        };
        match msg.class {
            MessageClass::SuccessResponse | MessageClass::ErrorResponse => {
                self.handle_response(from, to, raw, msg.transaction_id, now)
            }
            MessageClass::Request => self.handle_request(from, to, raw),
            _ => Vec::new(),
        }
    }

    // ─── Scheduling ──────────────────────────────────────────────

    /// Triggered checks first, then the best Waiting pair, then — if nothing
    /// is Waiting — release and take the best Frozen pair (RFC 8445 §6.1.4.2).
    fn pick_next_check(&mut self) -> Option<usize> {
        while let Some(id) = self.triggered.pop_front() {
            if self.checklist.entry(id).is_some_and(|e| e.state == PairState::Waiting) {
                return Some(id);
            }
        }
        self.checklist.next_waiting().or_else(|| self.checklist.unfreeze_highest())
    }

    /// Send a check for entry `id`. A nomination check (`nominate`) goes out on
    /// an entry that has already Succeeded and must leave its state alone; an
    /// ordinary one marks the entry InProgress.
    fn start_check(&mut self, id: usize, now: Instant, nominate: bool) -> Option<IceAction> {
        let (from, to, priority) = {
            let e = self.checklist.entry_mut(id)?;
            if !nominate {
                e.state = PairState::InProgress;
            }
            (e.pair.local.base_addr, e.pair.remote.transport_addr, e.pair.local.peer_reflexive_priority())
        };

        // RFC 8445 §14.3: RTO = max(floor, Ta * (Waiting + InProgress)). With
        // many pairs pending, each transaction backs off longer so the
        // aggregate retransmission rate stays bounded.
        let pending = self.checklist.count(PairState::Waiting) + self.checklist.count(PairState::InProgress);
        let rto = self.config.min_rto.max(self.config.ta.saturating_mul(pending as u32));

        let txn_id: [u8; 12] = random_bytes();
        let username = format!("{}:{}", self.remote.ufrag, self.local.ufrag);
        let request = build_check_request(&CheckRequestParams {
            txn_id,
            username: &username,
            password: self.remote.password.as_bytes(),
            priority,
            role: self.role,
            tie_breaker: self.tie_breaker,
            use_candidate: nominate,
        });

        let (next_send_at, deadline) = if self.config.max_transmissions <= 1 {
            (None, Some(now + rto.saturating_mul(self.config.final_wait_multiplier)))
        } else {
            (Some(now + rto), None)
        };

        self.transactions.push(Transaction {
            entry_id: id,
            txn_id,
            request: request.clone(),
            from,
            to,
            sent_count: 1,
            next_send_at,
            deadline,
            rto,
            role: self.role,
            cancelled: false,
            nominating: nominate,
        });
        Some(IceAction::Send { from, to, data: request })
    }

    // ─── Timers ──────────────────────────────────────────────────

    /// Retransmit what is due and expire what has timed out.
    ///
    /// After the n-th transmission the next waits `rto * 2^(n-1)`; after the
    /// last of Rc transmissions the transaction waits `rto * Rm` and fails.
    /// With RFC 5389's defaults that is sends at 0, 0.5, 1.5, 3.5, 7.5, 15.5,
    /// 31.5 s and failure at 39.5 s — derived independently in Python and
    /// asserted in the tests.
    fn service_transactions(&mut self, now: Instant, actions: &mut Vec<IceAction>) {
        let max_tx = self.config.max_transmissions;
        let final_mult = self.config.final_wait_multiplier;
        let mut timed_out: Vec<usize> = Vec::new();

        for (i, t) in self.transactions.iter_mut().enumerate() {
            // A superseded transaction stops retransmitting but is kept for
            // one final wait, in case its answer is merely slow.
            if t.cancelled {
                t.next_send_at = None;
                if t.deadline.is_none() {
                    t.deadline = Some(now + t.rto.saturating_mul(final_mult));
                }
            }
            if t.deadline.is_some_and(|d| now >= d) {
                timed_out.push(i);
                continue;
            }
            if t.next_send_at.is_some_and(|n| now >= n) {
                t.sent_count += 1;
                actions.push(IceAction::Send { from: t.from, to: t.to, data: t.request.clone() });
                if t.sent_count >= max_tx {
                    t.next_send_at = None;
                    t.deadline = Some(now + t.rto.saturating_mul(final_mult));
                } else {
                    // Shift capped so a pathological Rc cannot overflow it.
                    let factor = 1u32 << (t.sent_count - 1).min(20);
                    t.next_send_at = Some(now + t.rto.saturating_mul(factor));
                }
            }
        }

        for &i in timed_out.iter().rev() {
            let t = self.transactions.remove(i);
            // A cancelled transaction timing out is not a failure: its pair has
            // been re-queued and may already have a newer check in flight.
            if !t.cancelled {
                self.fail_entry(t.entry_id);
            }
        }
    }

    // ─── Responses ───────────────────────────────────────────────

    fn handle_response(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        raw: &[u8],
        txn_id: [u8; 12],
        now: Instant,
    ) -> Vec<IceAction> {
        let Some(idx) = self.transactions.iter().position(|t| t.txn_id == txn_id) else {
            return Vec::new();
        };

        // Anything failing fingerprint/integrity/format is discarded and the
        // transaction runs on — see the module comment.
        let Ok(response) = parse_check_response(raw, &txn_id, self.remote.password.as_bytes()) else {
            return Vec::new();
        };

        // RFC 8445 §7.2.5.2.1: the response must come back from the address we
        // sent to, to the address we sent from. Anything else is a failed check
        // (a NAT or attacker answering from somewhere unexpected).
        let (sent_from, sent_to, entry_id, role_sent, cancelled, nominating) = {
            let t = &self.transactions[idx];
            (t.from, t.to, t.entry_id, t.role, t.cancelled, t.nominating)
        };
        if from != sent_to || to != sent_from {
            self.transactions.remove(idx);
            if !cancelled {
                self.fail_entry(entry_id);
            }
            self.refresh_state();
            return Vec::new();
        }

        match response {
            CheckResponse::Success { mapped } => {
                let t = self.transactions.remove(idx);
                self.on_success(t.entry_id, mapped, nominating, now);
            }
            // An error answering a superseded transaction is not acted on: the
            // pair's current check will get its own answer.
            _ if cancelled => {
                self.transactions.remove(idx);
            }
            // Only an authenticated 487 may flip our role: an unauthenticated
            // one could be forged to make us flap. Ignored, the transaction
            // continues.
            CheckResponse::Error { code: 487, authenticated: true } => {
                self.transactions.remove(idx);
                self.on_role_conflict(entry_id, role_sent);
            }
            CheckResponse::Error { code: 487, authenticated: false } => {}
            CheckResponse::Error { .. } => {
                self.transactions.remove(idx);
                self.fail_entry(entry_id);
            }
        }
        self.refresh_state();
        Vec::new()
    }

    /// RFC 8445 §7.2.5.3: record the pair as Succeeded, build the valid pair,
    /// and release same-foundation Frozen pairs.
    fn on_success(&mut self, entry_id: usize, mapped: SocketAddr, nominating: bool, now: Instant) {
        let (local, remote, foundation) = {
            let Some(e) = self.checklist.entry(entry_id) else {
                return;
            };
            (e.pair.local.clone(), e.pair.remote.clone(), e.pair.foundation.clone())
        };

        // Which local candidate does the valid pair use? The response's
        // XOR-MAPPED-ADDRESS is how the peer saw us, so:
        let local_valid = if mapped == local.transport_addr {
            local.clone()
        } else if let Some(known) = self
            .local_candidates
            .iter()
            .find(|c| c.transport_addr == mapped && c.component_id == local.component_id)
        {
            // The mapping matches a different candidate we already hold
            // (typically our server-reflexive one).
            known.clone()
        } else {
            // A mapping we have never seen — e.g. a symmetric NAT that gave
            // this destination a fresh port. It becomes a peer-reflexive
            // candidate, based on the socket the check left from and ranked
            // by that interface's local preference.
            let prflx = Candidate::new(
                CandidateType::PeerReflexive,
                mapped,
                local.base_addr,
                local.local_preference,
                local.component_id,
            );
            self.local_candidates.push(prflx.clone());
            prflx
        };

        if let Some(e) = self.checklist.entry_mut(entry_id) {
            e.state = PairState::Succeeded;
        }

        let pair = CandidatePair::new(local_valid, remote, self.role);
        let probe = pair.clone();
        match self.valid.iter_mut().find(|v| same_endpoints(&v.pair, &probe)) {
            Some(existing) => {
                if !existing.generated_by.contains(&entry_id) {
                    existing.generated_by.push(entry_id);
                }
            }
            None => {
                self.valid.push(ValidPair { pair, nominated: false, generated_by: vec![entry_id] });
                self.valid.sort_by(|a, b| b.pair.priority.cmp(&a.pair.priority));
            }
        }
        if self.first_valid_at.is_none() {
            self.first_valid_at = Some(now);
        }

        // This success nominates the pair if it answered our USE-CANDIDATE
        // check, or if the peer had already nominated this pair while it was
        // still unverified here.
        let nominate = nominating || self.pending_nomination.contains(&entry_id);
        self.pending_nomination.retain(|&id| id != entry_id);
        if nominate {
            if let Some(v) = self.valid.iter_mut().find(|v| same_endpoints(&v.pair, &probe)) {
                v.nominated = true;
            }
        }

        self.checklist.unfreeze_foundation(&foundation);
        self.check_completion();
    }

    /// RFC 8445 §7.2.5.1: a 487 says the roles collided.
    ///
    /// Several checks can be in flight when the collision happens, and the
    /// peer answers each with 487. Switching on every one would flip the role
    /// back and forth; only the first should switch. So the switch happens
    /// only if our role is still the one this request was sent under — if it
    /// has already changed, the collision is already resolved and we merely
    /// retry the pair under the new role.
    fn on_role_conflict(&mut self, entry_id: usize, role_sent: IceRole) {
        if role_sent == self.role {
            self.switch_role();
        }
        if let Some(e) = self.checklist.entry_mut(entry_id) {
            e.state = PairState::Waiting;
        }
        self.triggered.push_back(entry_id);
    }

    /// Flip role and re-prioritise everything that depends on it: pair
    /// priority is computed from which side is controlling, so every check-list
    /// entry and valid pair held under the old role is now stale. The
    /// tie-breaker is unchanged.
    fn switch_role(&mut self) {
        self.role = match self.role {
            IceRole::Controlling => IceRole::Controlled,
            IceRole::Controlled => IceRole::Controlling,
        };
        self.checklist.recompute_priorities(self.role);
        for v in &mut self.valid {
            v.pair.recompute_priority(self.role);
        }
        self.valid.sort_by(|a, b| b.pair.priority.cmp(&a.pair.priority));
    }

    // ─── Incoming check requests (RFC 8445 §7.3) ─────────────────

    fn handle_request(&mut self, from: SocketAddr, to: SocketAddr, raw: &[u8]) -> Vec<IceAction> {
        let parsed = match parse_check_request(raw, &self.local.ufrag, self.local.password.as_bytes()) {
            Ok(p) => p,
            // We cannot verify the sender. Say so (401) and do nothing else:
            // an unauthenticated request must never create a pair, a
            // candidate or a triggered check, or anyone could steer our list.
            Err(CheckRequestError::Unauthorized) => {
                return self.reply_error(raw, to, from, 401, "Unauthorized", false);
            }
            // Authenticated but malformed, so the sender can trust the reply.
            Err(CheckRequestError::BadRequest(_)) => {
                return self.reply_error(raw, to, from, 400, "Bad Request", true);
            }
            // Not STUN-for-ICE at all: not ours to answer.
            Err(_) => return Vec::new(),
        };

        // RFC 8445 §7.3.1.1 — both sides claim the same role. The two rules
        // are mirror images, arranged so the *larger* tie-breaker ends up
        // controlling at both ends: a controlling agent keeps its role only if
        // its tie-breaker is >= the peer's; a controlled agent takes over only
        // if its tie-breaker is >=. Otherwise the agent yields — by switching
        // (controlling side) or by answering 487 (controlled side), and the
        // peer, holding the larger value, switches or keeps its role to match.
        // Equal tie-breakers make both sides flip forever; with 64 random bits
        // that is a 2^-64 event, which is why the RFC tolerates it.
        match (self.role, parsed.sender_role) {
            (IceRole::Controlling, IceRole::Controlling) => {
                if self.tie_breaker >= parsed.tie_breaker {
                    return self.reply_error(raw, to, from, 487, "Role Conflict", true);
                }
                self.switch_role();
            }
            (IceRole::Controlled, IceRole::Controlled) => {
                if self.tie_breaker >= parsed.tie_breaker {
                    self.switch_role();
                } else {
                    return self.reply_error(raw, to, from, 487, "Role Conflict", true);
                }
            }
            _ => {}
        }

        // The response goes back from the address the request arrived on, to
        // the address it came from — and reports that source as the mapping.
        let reply = IceAction::Send {
            from: to,
            to: from,
            data: build_check_success_response(&parsed.txn_id, from, self.local.password.as_bytes()),
        };
        if self.note_request(parsed.txn_id) {
            let entry = self.trigger_for_request(from, to, parsed.priority);
            // Only a controlling peer can nominate, and the codec already
            // refuses USE-CANDIDATE from a controlled one.
            if parsed.use_candidate && self.role == IceRole::Controlled {
                if let Some(id) = entry {
                    self.on_nomination_request(id);
                }
            }
        }
        vec![reply]
    }

    /// An error response, signed only when the request itself authenticated
    /// (an unsigned 401 is all we can honestly say to a stranger).
    fn reply_error(
        &self,
        raw: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        code: u16,
        reason: &str,
        sign: bool,
    ) -> Vec<IceAction> {
        let Ok(msg) = parse_message(raw) else {
            return Vec::new();
        };
        let key = if sign { Some(self.local.password.as_bytes()) } else { None };
        vec![IceAction::Send {
            from: local,
            to: peer,
            data: build_check_error_response(&msg.transaction_id, code, reason, key),
        }]
    }

    /// Remember a request's transaction ID. Returns `false` if it was already
    /// acted on, i.e. this is a retransmission.
    fn note_request(&mut self, txn_id: [u8; 12]) -> bool {
        if self.seen_requests.contains(&txn_id) {
            return false;
        }
        self.seen_requests.push_back(txn_id);
        if self.seen_requests.len() > 128 {
            self.seen_requests.pop_front();
        }
        true
    }

    /// The local candidate a datagram arrived on: the one whose transport
    /// address is the destination, or failing that one sharing its base
    /// (a server-reflexive candidate arrives at its host base).
    fn local_candidate_for(&self, addr: SocketAddr) -> Option<Candidate> {
        self.local_candidates
            .iter()
            .find(|c| c.transport_addr == addr)
            .or_else(|| self.local_candidates.iter().find(|c| c.base_addr == addr))
            .cloned()
    }

    /// RFC 8445 §7.3.1.3–4: work out the pair this request implies — learning
    /// a remote peer-reflexive candidate if its source is new — and queue a
    /// triggered check on it.
    fn trigger_for_request(&mut self, from: SocketAddr, to: SocketAddr, priority: u32) -> Option<usize> {
        // Once ICE has completed there is nothing left to probe or learn.
        if self.state == ChecklistState::Completed {
            return None;
        }
        let local = self.local_candidate_for(to)?;
        let component = local.component_id;

        let remote = match self
            .remote_candidates
            .iter()
            .find(|c| c.transport_addr == from && c.component_id == component)
        {
            Some(known) => known.clone(),
            None => {
                let learned = Candidate::remote_peer_reflexive(from, priority, component);
                self.remote_candidates.push(learned.clone());
                learned
            }
        };

        let id = match self.checklist.find_entry(local.base_addr, remote.transport_addr, component) {
            Some(id) => id,
            None => {
                let pair = CandidatePair::new(local, remote, self.role);
                self.checklist.add_pair(pair, PairState::Waiting)
            }
        };
        self.queue_triggered(id);
        Some(id)
    }

    /// RFC 8445 §7.3.1.4, by the pair's current state: a Succeeded pair is
    /// left alone; an In-Progress one has its transaction cancelled and is
    /// re-checked; Frozen, Waiting and Failed ones are simply queued. A check
    /// list that had Failed is revived — a peer that is actively checking us
    /// proves connectivity is still possible.
    fn queue_triggered(&mut self, id: usize) {
        let Some(state) = self.checklist.entry(id).map(|e| e.state) else {
            return;
        };
        match state {
            PairState::Succeeded => return,
            PairState::InProgress => {
                for t in self.transactions.iter_mut().filter(|t| t.entry_id == id) {
                    t.cancelled = true;
                }
            }
            PairState::Frozen | PairState::Waiting | PairState::Failed => {}
        }
        if let Some(e) = self.checklist.entry_mut(id) {
            e.state = PairState::Waiting;
        }
        if !self.triggered.contains(&id) {
            self.triggered.push_back(id);
        }
        if self.state == ChecklistState::Failed {
            self.state = ChecklistState::Running;
        }
    }

    // ─── Nomination and completion (RFC 8445 §8) ─────────────────

    /// Nominate the best valid pair now, if this agent is controlling and holds
    /// one that is not yet nominated. Returns the nomination check to send.
    /// Under [`Nomination::Regular`] `poll` does this by itself; this is for
    /// callers who chose [`Nomination::Never`] and decide for themselves when a
    /// path is good enough.
    pub fn nominate_now(&mut self, now: Instant) -> Vec<IceAction> {
        if !self.nomination_waiting() {
            return Vec::new();
        }
        let Some(&entry_id) = self.valid[0].generated_by.first() else {
            return Vec::new();
        };
        self.start_check(entry_id, now, true).into_iter().collect()
    }

    /// Is this agent in a position to start a nomination: controlling, still
    /// checking, holding a valid pair, none nominated, and no nomination check
    /// already in flight?
    fn nomination_waiting(&self) -> bool {
        self.role == IceRole::Controlling
            && self.state == ChecklistState::Running
            && !self.valid.is_empty()
            && !self.valid.iter().any(|v| v.nominated)
            && !self.transactions.iter().any(|t| t.nominating)
    }

    /// Could a pair outranking the best valid one still turn up? True while
    /// any higher-priority entry is unsettled.
    fn better_pair_pending(&self) -> bool {
        let best = self.valid.first().map_or(0, |v| v.pair.priority);
        self.checklist.entries().iter().any(|e| {
            matches!(e.state, PairState::Frozen | PairState::Waiting | PairState::InProgress)
                && e.pair.priority > best
        })
    }

    /// Regular nomination (RFC 8445 §8.1.1.1): nominate once the wait since the
    /// first valid pair has elapsed, or immediately if nothing better is still
    /// being checked.
    fn maybe_nominate(&mut self, now: Instant, actions: &mut Vec<IceAction>) {
        let Nomination::Regular { delay } = self.config.nomination else {
            return;
        };
        if !self.nomination_waiting() {
            return;
        }
        let waited_enough = self.first_valid_at.is_some_and(|t| now >= t + delay);
        if waited_enough || !self.better_pair_pending() {
            actions.extend(self.nominate_now(now));
        }
    }

    /// The controlled agent's side (RFC 8445 §7.3.1.5): the peer sent
    /// USE-CANDIDATE on entry `id`'s pair. If our own check there has already
    /// succeeded the pair is nominated now; otherwise the nomination is held
    /// until it does — a controlled agent nominates only what it has verified
    /// in both directions.
    fn on_nomination_request(&mut self, id: usize) {
        match self.checklist.entry(id).map(|e| e.state) {
            Some(PairState::Succeeded) => {
                for v in &mut self.valid {
                    if v.generated_by.contains(&id) {
                        v.nominated = true;
                    }
                }
                self.check_completion();
            }
            Some(_) => {
                if !self.pending_nomination.contains(&id) {
                    self.pending_nomination.push(id);
                }
            }
            None => {}
        }
    }

    /// ICE completes once every component in the check list has a nominated
    /// valid pair. The agent then abandons its remaining checks — they can no
    /// longer improve anything — but still answers the peer's.
    fn check_completion(&mut self) {
        if self.state != ChecklistState::Running {
            return;
        }
        let components: HashSet<u8> =
            self.checklist.entries().iter().map(|e| e.pair.local.component_id).collect();
        let done = !components.is_empty()
            && components.iter().all(|c| {
                self.valid.iter().any(|v| v.nominated && v.pair.local.component_id == *c)
            });
        if done {
            self.state = ChecklistState::Completed;
            self.transactions.clear();
            self.triggered.clear();
            self.pending_nomination.clear();
        }
    }

    fn fail_entry(&mut self, entry_id: usize) {
        if let Some(e) = self.checklist.entry_mut(entry_id) {
            if e.state == PairState::InProgress {
                e.state = PairState::Failed;
            }
        }
    }

    /// The list has failed once nothing can still produce a result and no pair
    /// ever verified.
    fn refresh_state(&mut self) {
        if self.state == ChecklistState::Running && self.valid.is_empty() && !self.checklist.has_pending() {
            self.state = ChecklistState::Failed;
        }
    }
}

/// Two pairs are the same path if they connect the same two transport
/// addresses for the same component.
fn same_endpoints(a: &CandidatePair, b: &CandidatePair) -> bool {
    a.local.transport_addr == b.local.transport_addr
        && a.remote.transport_addr == b.remote.transport_addr
        && a.local.component_id == b.local.component_id
}
