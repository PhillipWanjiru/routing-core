//! SIP registrar.
//!
//! Maintains the binding table: AoR → [Contact, Expires, Received-IP].
//! Responds to REGISTER requests per RFC 3261 §10.
//!
//! Bindings expire on schedule. The store-forward-queue subscribes to
//! presence events from here to know when to flush queued calls.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// One registered contact binding.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The Contact URI the endpoint registered.
    pub contact:     String,
    /// The IP address the REGISTER was received from.
    pub received_ip: String,
    /// Absolute expiry time.
    pub expires_at:  Instant,
    /// The Call-ID of the REGISTER that created this binding.
    pub call_id:     String,
    /// The CSeq of the REGISTER that created this binding.
    pub cseq:        u32,
}

impl Binding {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn remaining_secs(&self) -> u32 {
        self.expires_at
            .checked_duration_since(Instant::now())
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }
}

/// The SIP registrar binding table.
pub struct Registrar {
    /// aor → list of active bindings
    bindings: RwLock<HashMap<String, Vec<Binding>>>,
    /// Default expiry in seconds when the client doesn't specify.
    default_expires: u32,
    /// Maximum expiry we will grant.
    max_expires: u32,
    /// Minimum expiry we will grant (RFC 3261 recommends 3600).
    min_expires: u32,
}

impl Registrar {
    pub fn new(default_expires: u32, max_expires: u32, min_expires: u32) -> Arc<Self> {
        Arc::new(Registrar {
            bindings: RwLock::new(HashMap::new()),
            default_expires,
            max_expires,
            min_expires,
        })
    }

    /// Register a contact for an AoR. Returns the granted expiry.
    ///
    /// Rules (RFC 3261 §10.3):
    /// - Expiry 0 removes the binding.
    /// - Expiry < min_expires returns 423 Interval Too Brief (caller handles).
    /// - Expiry > max_expires is clamped to max_expires.
    pub fn register(
        &self,
        aor:         &str,
        contact:     &str,
        received_ip: &str,
        requested_expires: Option<u32>,
        call_id:     &str,
        cseq:        u32,
    ) -> RegisterResult {
        let expires = requested_expires.unwrap_or(self.default_expires);

        if expires == 0 {
            self.remove_binding(aor, contact);
            return RegisterResult::Ok { granted_expires: 0 };
        }

        if expires < self.min_expires {
            return RegisterResult::IntervalTooBrief {
                min_expires: self.min_expires,
            };
        }

        let granted = expires.min(self.max_expires);

        let binding = Binding {
            contact:     contact.to_owned(),
            received_ip: received_ip.to_owned(),
            expires_at:  Instant::now() + Duration::from_secs(granted as u64),
            call_id:     call_id.to_owned(),
            cseq,
        };

        let mut db = self.bindings.write().unwrap();
        let list = db.entry(aor.to_owned()).or_default();

        // RFC 3261: update if same Call-ID and CSeq > existing.
        if let Some(existing) = list.iter_mut().find(|b| b.contact == contact) {
            if call_id == existing.call_id && cseq <= existing.cseq {
                return RegisterResult::OutOfOrder;
            }
            *existing = binding;
        } else {
            list.push(binding);
        }

        RegisterResult::Ok { granted_expires: granted }
    }

    /// Look up all active bindings for an AoR.
    pub fn lookup(&self, aor: &str) -> Vec<Binding> {
        self.bindings.read().unwrap()
            .get(aor)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|b| !b.is_expired())
            .collect()
    }

    /// True if the AoR has at least one unexpired binding.
    pub fn is_registered(&self, aor: &str) -> bool {
        !self.lookup(aor).is_empty()
    }

    /// Remove all bindings for an AoR (de-register everything).
    pub fn deregister_all(&self, aor: &str) {
        self.bindings.write().unwrap().remove(aor);
    }

    /// Remove expired bindings from all AoRs.
    pub fn evict_expired(&self) {
        let mut db = self.bindings.write().unwrap();
        for list in db.values_mut() {
            list.retain(|b| !b.is_expired());
        }
        db.retain(|_, v| !v.is_empty());
    }

    fn remove_binding(&self, aor: &str, contact: &str) {
        let mut db = self.bindings.write().unwrap();
        if let Some(list) = db.get_mut(aor) {
            list.retain(|b| b.contact != contact);
        }
    }

    /// Total registered endpoint count.
    pub fn endpoint_count(&self) -> usize {
        self.bindings.read().unwrap()
            .values()
            .map(|v| v.iter().filter(|b| !b.is_expired()).count())
            .sum()
    }
}

/// Result of a REGISTER attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterResult {
    Ok { granted_expires: u32 },
    IntervalTooBrief { min_expires: u32 },
    OutOfOrder,
}
