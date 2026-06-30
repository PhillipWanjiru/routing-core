//! Back-to-Back User Agent.
//!
//! The B2BUA terminates every call leg and re-originates it. This gives:
//! - Full control over codec negotiation between legs.
//! - Topology hiding (remote party never sees internal addressing).
//! - Hooks for recording, monitoring, and mid-call rerouting.
//! - The ability to change the outbound route without the caller knowing.
//!
//! # Call leg model
//!
//! Every call has two legs:
//! - **Leg A** — the originating side (the caller). The B2BUA acts as UAS.
//! - **Leg B** — the terminating side (the callee). The B2BUA acts as UAC.
//!
//! The B2BUA owns both dialog states independently. A failure on leg B
//! can be retried on a different path without leg A noticing.

use crate::sip::{
    dialog::{Dialog, DialogId, DialogStore},
    transaction::{InviteClientState, InviteServerState},
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The state of one bridged call.
#[derive(Debug, Clone)]
pub struct BridgedCall {
    pub call_id:         String,
    /// Leg-A dialog ID (B2BUA is UAS).
    pub leg_a_id:        DialogId,
    /// Leg-B dialog ID (B2BUA is UAC). None until leg-B INVITE is sent.
    pub leg_b_id:        Option<DialogId>,
    /// Current leg-A transaction state.
    pub leg_a_tx:        InviteServerState,
    /// Current leg-B transaction state.
    pub leg_b_tx:        InviteClientState,
    /// The path ID chosen by the routing engine for this call.
    pub route_path_id:   Option<String>,
    pub state:           BridgedCallState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgedCallState {
    /// Leg-A INVITE received, leg-B INVITE not yet sent.
    Setup,
    /// Leg-B INVITE sent, awaiting response.
    Ringing,
    /// Both legs confirmed (ACK exchanged).
    Active,
    /// BYE received or sent; tearing down.
    Terminating,
    /// Both legs torn down.
    Terminated,
}

/// The B2BUA call table.
pub struct B2bua {
    calls:   RwLock<HashMap<String, BridgedCall>>,
    dialogs: Arc<DialogStore>,
}

impl B2bua {
    pub fn new(dialogs: Arc<DialogStore>) -> Arc<Self> {
        Arc::new(B2bua {
            calls:   RwLock::new(HashMap::new()),
            dialogs,
        })
    }

    /// Handle an incoming INVITE from leg A.
    ///
    /// Returns the new `BridgedCall` record. The caller is responsible for:
    /// 1. Querying the routing engine for a path.
    /// 2. Calling `originate_leg_b` with the selected path.
    pub fn incoming_invite(
        &self,
        call_id:   &str,
        from_party: &str,
        to_party:   &str,
        from_tag:   &str,
        local_tag:  &str,
        remote_contact: &str,
        route_set:  Vec<String>,
        cseq:       u32,
    ) -> BridgedCall {
        let leg_a_id = DialogId::new(call_id, from_tag, local_tag);

        let dialog = Dialog::new_early_uas(
            call_id,
            from_tag,
            local_tag,
            to_party,
            from_party,
            remote_contact,
            route_set,
            cseq,
        );
        self.dialogs.upsert(dialog);

        let call = BridgedCall {
            call_id:       call_id.to_owned(),
            leg_a_id:      leg_a_id.clone(),
            leg_b_id:      None,
            leg_a_tx:      InviteServerState::Proceeding,
            leg_b_tx:      InviteClientState::Calling, // not yet
            route_path_id: None,
            state:         BridgedCallState::Setup,
        };

        self.calls.write().unwrap()
            .insert(call_id.to_owned(), call.clone());

        tracing::info!(
            call_id,
            from = from_party,
            to   = to_party,
            "B2BUA: incoming INVITE, leg-A dialog created"
        );

        call
    }

    /// Record that leg-B INVITE has been sent.
    pub fn originate_leg_b(
        &self,
        call_id:    &str,
        b_call_id:  &str,
        _local_tag: &str,
        path_id:    &str,
    ) {
        let mut calls = self.calls.write().unwrap();
        if let Some(call) = calls.get_mut(call_id) {
            // leg_b_id will be updated when we receive the 200 OK (To-tag arrives then).
            call.route_path_id = Some(path_id.to_owned());
            call.state         = BridgedCallState::Ringing;
            call.leg_b_tx      = InviteClientState::Calling;
            tracing::info!(
                call_id,
                b_call_id,
                path = path_id,
                "B2BUA: leg-B INVITE sent"
            );
        }
    }

    /// Handle 200 OK on leg B — confirm both legs.
    pub fn leg_b_accepted(
        &self,
        call_id:     &str,
        b_from_tag:  &str,
        b_to_tag:    &str,
        b_call_id:   &str,
        remote_contact: &str,
    ) {
        let leg_b_id = DialogId::new(b_call_id, b_from_tag, b_to_tag);
        let mut calls = self.calls.write().unwrap();
        if let Some(call) = calls.get_mut(call_id) {
            call.leg_b_id  = Some(leg_b_id.clone());
            call.leg_b_tx  = InviteClientState::Accepted;
            call.leg_a_tx  = InviteServerState::Accepted;
            call.state     = BridgedCallState::Active;
        }
        // Update leg-B dialog.
        if let Some(mut d) = self.dialogs.get(&leg_b_id) {
            d.confirm(remote_contact);
            self.dialogs.upsert(d);
        }
        tracing::info!(call_id, "B2BUA: call active, both legs confirmed");
    }

    /// Handle BYE on either leg.
    pub fn handle_bye(&self, call_id: &str, from_leg: &str) {
        let mut calls = self.calls.write().unwrap();
        if let Some(call) = calls.get_mut(call_id) {
            call.state = BridgedCallState::Terminating;
            tracing::info!(call_id, from_leg, "B2BUA: BYE received, terminating");
        }
    }

    /// Mark call as fully terminated.
    pub fn terminate(&self, call_id: &str) {
        let mut calls = self.calls.write().unwrap();
        if let Some(call) = calls.get_mut(call_id) {
            call.state = BridgedCallState::Terminated;
            // Evict dialogs.
            self.dialogs.terminate(&call.leg_a_id);
            if let Some(ref id) = call.leg_b_id {
                self.dialogs.terminate(id);
            }
        }
        tracing::info!(call_id, "B2BUA: call terminated");
    }

    /// Active call count.
    pub fn active_count(&self) -> usize {
        self.calls.read().unwrap()
            .values()
            .filter(|c| c.state == BridgedCallState::Active)
            .count()
    }

    /// Evict terminated calls from memory.
    pub fn evict_terminated(&self) {
        self.calls.write().unwrap()
            .retain(|_, v| v.state != BridgedCallState::Terminated);
    }
}
