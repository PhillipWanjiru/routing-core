//! RFC 3261 §12 SIP dialog.
//!
//! A dialog is a peer-to-peer SIP relationship established by a transaction.
//! It is identified by the three-tuple (Call-ID, From-tag, To-tag).
//! The dialog tracks the route set and remote target for subsequent
//! in-dialog requests (re-INVITE, BYE, etc.).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The three-tuple that uniquely identifies a SIP dialog.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id:  String,
    pub from_tag: String,
    pub to_tag:   String,
}

impl DialogId {
    pub fn new(call_id: &str, from_tag: &str, to_tag: &str) -> Self {
        DialogId {
            call_id:  call_id.to_owned(),
            from_tag: from_tag.to_owned(),
            to_tag:   to_tag.to_owned(),
        }
    }
}

/// Dialog state as defined in RFC 3261 §12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogState {
    /// INVITE sent / received; 1xx with To-tag received (early dialog).
    Early,
    /// 2xx received/sent; ACK sent/received.
    Confirmed,
    /// BYE sent or received.
    Terminated,
}

/// A SIP dialog.
#[derive(Debug, Clone)]
pub struct Dialog {
    pub id:            DialogId,
    pub state:         DialogState,
    /// Local sequence number (CSeq for requests we send).
    pub local_seq:     u32,
    /// Remote sequence number (CSeq for requests we receive).
    pub remote_seq:    u32,
    /// Local URI.
    pub local_uri:     String,
    /// Remote URI.
    pub remote_uri:    String,
    /// Remote target (from Contact header of last message).
    pub remote_target: String,
    /// Route set (from Record-Route headers, reversed for UAC).
    pub route_set:     Vec<String>,
    /// Whether we are the UAC (true) or UAS (false) for this dialog.
    pub is_uac:        bool,
}

impl Dialog {
    /// Create a new early dialog from a received 1xx response (UAC side).
    pub fn new_early_uac(
        call_id:      &str,
        from_tag:     &str,
        to_tag:       &str,
        local_uri:    &str,
        remote_uri:   &str,
        remote_target: &str,
        route_set:    Vec<String>,
        initial_seq:  u32,
    ) -> Self {
        Dialog {
            id:            DialogId::new(call_id, from_tag, to_tag),
            state:         DialogState::Early,
            local_seq:     initial_seq,
            remote_seq:    0,
            local_uri:     local_uri.to_owned(),
            remote_uri:    remote_uri.to_owned(),
            remote_target: remote_target.to_owned(),
            route_set,
            is_uac:        true,
        }
    }

    /// Create a new early dialog from an incoming INVITE (UAS side).
    pub fn new_early_uas(
        call_id:      &str,
        from_tag:     &str,
        to_tag:       &str,
        local_uri:    &str,
        remote_uri:   &str,
        remote_target: &str,
        route_set:    Vec<String>,
        remote_seq:   u32,
    ) -> Self {
        Dialog {
            id:            DialogId::new(call_id, from_tag, to_tag),
            state:         DialogState::Early,
            local_seq:     0,
            remote_seq,
            local_uri:     local_uri.to_owned(),
            remote_uri:    remote_uri.to_owned(),
            remote_target: remote_target.to_owned(),
            route_set,
            is_uac:        false,
        }
    }

    /// Advance to Confirmed state.
    pub fn confirm(&mut self, remote_target: &str) {
        self.remote_target = remote_target.to_owned();
        self.state = DialogState::Confirmed;
    }

    /// Advance to Terminated state.
    pub fn terminate(&mut self) {
        self.state = DialogState::Terminated;
    }

    /// Return true if the dialog is active (not terminated).
    pub fn is_active(&self) -> bool {
        self.state != DialogState::Terminated
    }

    /// Increment local CSeq and return the new value.
    pub fn next_local_seq(&mut self) -> u32 {
        self.local_seq += 1;
        self.local_seq
    }
}

/// Thread-safe dialog store.
pub struct DialogStore {
    inner: RwLock<HashMap<DialogId, Dialog>>,
}

impl DialogStore {
    pub fn new() -> Arc<Self> {
        Arc::new(DialogStore {
            inner: RwLock::new(HashMap::new()),
        })
    }

    /// Insert or update a dialog.
    pub fn upsert(&self, dialog: Dialog) {
        self.inner.write().unwrap()
            .insert(dialog.id.clone(), dialog);
    }

    /// Get a dialog by its ID.
    pub fn get(&self, id: &DialogId) -> Option<Dialog> {
        self.inner.read().unwrap()
            .get(id).cloned()
    }

    /// Terminate a dialog.
    pub fn terminate(&self, id: &DialogId) {
        if let Some(d) = self.inner.write().unwrap().get_mut(id) {
            d.terminate();
        }
    }

    /// Remove terminated dialogs (called periodically).
    pub fn evict_terminated(&self) {
        self.inner.write().unwrap()
            .retain(|_, v| v.is_active());
    }

    /// Active dialog count.
    pub fn active_count(&self) -> usize {
        self.inner.read().unwrap()
            .values()
            .filter(|d| d.is_active())
            .count()
    }
}

impl Default for DialogStore {
    fn default() -> Self {
        DialogStore { inner: RwLock::new(HashMap::new()) }
    }
}
