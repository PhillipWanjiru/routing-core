//! Live UAS (User Agent Server) call engine.
//!
//! This is the first place the parser (`sip::parser`), the transaction
//! state machine (`sip::transaction`), the dialog store (`sip::dialog`),
//! and the message builder (`sip::builder`) are wired together against
//! real network input rather than exercised independently in unit tests.
//!
//! Scope for this milestone: signaling only. A full INVITE/ACK/BYE cycle,
//! with a real SDP offer/answer exchanged in the bodies, but no RTP yet —
//! that is the next piece of Phase 3. The point of building this first,
//! in isolation from RTP, is to prove the signaling stack is correct
//! against a live socket and a captured pcap before adding media
//! complexity on top of it.

use crate::sip::{
    builder::{self, ResponseParts},
    dialog::{Dialog, DialogId, DialogStore},
    parser::{parse_message, Method, SipMessage},
    sdp::parse_sdp,
    transaction::{invite_server_step, InviteServerState, TxEvent},
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Per-call-id transaction bookkeeping. Distinct from `Dialog`, which is
/// keyed by the full (Call-ID, From-tag, To-tag) triple — a transaction
/// exists from the moment the INVITE arrives, before the dialog's To-tag
/// is even assigned.
#[allow(dead_code)] // fields used in Phase 3 RTP wiring
struct CallState {
    tx_state:   InviteServerState,
    to_tag:     String,
    /// The audio port we told the caller to send RTP to (from our SDP answer).
    /// Recorded here so Phase 3's media wiring has somewhere to read it from.
    local_rtp_port: u16,
}

/// The live UAS engine. One instance serves all calls received on this
/// module's SIP socket.
#[allow(dead_code)] // fields used in Phase 3 RTP wiring
pub struct UasEngine {
    dialogs:    Arc<DialogStore>,
    calls:      RwLock<HashMap<String, CallState>>,
    local_uri:  String,
    local_host: String,
    /// Fixed for this milestone — Phase 3's RTP work replaces this with a
    /// real port allocator once jitter buffer and codec wiring exist.
    next_rtp_port: RwLock<u16>,
}

/// Outcome of handling one inbound datagram: zero or more response
/// messages to send back to the peer, in order.
pub type Responses = Vec<String>;

impl UasEngine {
    pub fn new(local_uri: impl Into<String>, local_host: impl Into<String>) -> Arc<Self> {
        Arc::new(UasEngine {
            dialogs:    DialogStore::new(),
            calls:      RwLock::new(HashMap::new()),
            local_uri:  local_uri.into(),
            local_host: local_host.into(),
            next_rtp_port: RwLock::new(30000),
        })
    }

    /// Parse and dispatch one inbound datagram. Returns the response
    /// message(s) to send back, if any.
    ///
    /// This is the single entry point the UDP receive loop calls — it is
    /// deliberately synchronous and side-effect-isolated (dialog/call-state
    /// mutation only) so it can be unit tested without a socket.
    pub fn handle_datagram(&self, raw: &[u8]) -> Responses {
        let msg = match parse_message(raw) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("dropping unparseable datagram: {e}");
                return vec![];
            }
        };

        let Some(method) = msg.method() else {
            // Responses arriving here would mean we're acting as a UAC
            // for this dialog — not this milestone's scope (the test
            // client plays that role). Log and ignore.
            tracing::debug!("UAS received a response, not a request — ignoring");
            return vec![];
        };

        match method {
            Method::Invite => self.handle_invite(&msg),
            Method::Ack    => { self.handle_ack(&msg); vec![] }
            Method::Bye    => self.handle_bye(&msg),
            other => {
                tracing::debug!("UAS: no handler for method {other}, ignoring");
                vec![]
            }
        }
    }

    fn handle_invite(&self, msg: &SipMessage) -> Responses {
        let Some(call_id) = msg.call_id() else {
            tracing::warn!("INVITE missing Call-ID, dropping");
            return vec![];
        };
        let Some(via)  = msg.header("Via")  else { return vec![] };
        let Some(from) = msg.header("From") else { return vec![] };
        let Some(to)   = msg.header("To")   else { return vec![] };
        let Some((cseq_num, _)) = msg.cseq() else { return vec![] };

        let from_tag = extract_tag(from).unwrap_or_default();
        let to_uri   = strip_uri(to);

        // Parse the offered SDP, if present, to learn where the caller
        // wants RTP sent. This exercises the SDP parser in the same live
        // path as the SIP parser, on real (if loopback) network input.
        if !msg.body.is_empty() {
            match parse_sdp(&msg.body) {
                Ok(sdp) => {
                    if let Some(m) = sdp.media.first() {
                        tracing::info!(
                            call_id,
                            offered_port = m.port,
                            codec = ?m.payload_types,
                            "parsed SDP offer"
                        );
                    }
                }
                Err(e) => tracing::warn!(call_id, "SDP parse error: {e}"),
            }
        }

        let to_tag = builder::gen_tag();
        let local_rtp_port = self.allocate_rtp_port();

        // Transaction starts in Proceeding the moment the TU decides to
        // process it (RFC 3261 §17.2.1) — there is no separate "received"
        // state before that for the INVITE server transaction.
        let tx_state = invite_server_step(
            InviteServerState::Proceeding,
            TxEvent::TuResponse { code: 100 },
        );

        // Create the early dialog now — RFC 3261 §12.1.1: a dialog is
        // constructed when a UAS sends a reliable response with a tag in
        // the To header (180 in our case; 100 is hop-by-hop and dialog-less).
        let dialog = Dialog::new_early_uas(
            &call_id,
            &from_tag,
            &to_tag,
            &self.local_uri,
            &strip_uri(from),
            &strip_uri(from), // remote target — refined once we see Contact
            vec![],
            cseq_num,
        );
        self.dialogs.upsert(dialog);

        self.calls.write().unwrap().insert(
            call_id.to_owned(),
            CallState { tx_state, to_tag: to_tag.clone(), local_rtp_port },
        );

        let resp = ResponseParts {
            via, from, to_uri: &to_uri, to_tag: &to_tag,
            call_id: &call_id, cseq: &format!("{cseq_num} INVITE"),
            local_contact: &self.local_uri,
        };

        tracing::info!(call_id, from_tag, to_tag, "INVITE accepted, sending 100/180/200");

        // 100 Trying, 180 Ringing, 200 OK — the full provisional sequence,
        // not a shortcut straight to 200, because the Phase 2 deliverable
        // this closes out explicitly calls for verifying the complete
        // RFC 3261 §17 message sequence in a pcap, not just the happy-path
        // final response.
        let mut out = vec![
            builder::build_100_trying(&resp),
            builder::build_180_ringing(&resp),
        ];

        self.advance_to_accepted(&call_id);
        out.push(builder::build_200_ok_invite(&resp, local_rtp_port));
        out
    }

    fn advance_to_accepted(&self, call_id: &str) {
        if let Some(call) = self.calls.write().unwrap().get_mut(call_id) {
            call.tx_state = invite_server_step(
                call.tx_state.clone(),
                TxEvent::TuResponse { code: 200 },
            );
        }
    }

    fn handle_ack(&self, msg: &SipMessage) {
        let Some(call_id) = msg.call_id() else { return };

        let mut calls = self.calls.write().unwrap();
        let Some(call) = calls.get_mut(call_id) else {
            tracing::warn!(call_id, "ACK for unknown call, ignoring");
            return;
        };

        // The INVITE server transaction is Accepted, not Completed, because
        // our TU sent a 2xx (see invite_server_step: TuResponse{200} → 
        // Accepted, which absorbs further events). The ACK confirms the
        // *dialog*, not this transaction — 2xx ACKs are end-to-end and
        // handled at the dialog layer per RFC 3261 §13.2.2.4, not by the
        // INVITE server transaction itself.
        let _ = &call.tx_state;

        if let Some(from) = msg.header("From") {
            if let Some(to) = msg.header("To") {
                let from_tag = extract_tag(from).unwrap_or_default();
                let to_tag   = extract_tag(to).unwrap_or_else(|| call.to_tag.clone());
                let id = DialogId::new(&call_id, &from_tag, &to_tag);
                if let Some(mut d) = self.dialogs.get(&id) {
                    d.confirm(&self.local_uri);
                    self.dialogs.upsert(d);
                    tracing::info!(call_id, "ACK received, dialog confirmed — call active");
                }
            }
        }
    }

    fn handle_bye(&self, msg: &SipMessage) -> Responses {
        let Some(call_id) = msg.call_id() else { return vec![] };
        let Some(via)  = msg.header("Via")  else { return vec![] };
        let Some(from) = msg.header("From") else { return vec![] };
        let Some(to)   = msg.header("To")   else { return vec![] };
        let Some((cseq_num, _)) = msg.cseq() else { return vec![] };

        let mut calls = self.calls.write().unwrap();
        let Some(call) = calls.remove(call_id) else {
            tracing::warn!(call_id, "BYE for unknown call, ignoring");
            return vec![];
        };
        drop(calls);

        let from_tag = extract_tag(from).unwrap_or_default();
        let id = DialogId::new(&call_id, &from_tag, &call.to_tag);
        self.dialogs.terminate(&id);

        tracing::info!(call_id, "BYE received, call terminated");

        let resp = ResponseParts {
            via, from,
            to_uri: &strip_uri(to), to_tag: &call.to_tag,
            call_id: &call_id, cseq: &format!("{cseq_num} BYE"),
            local_contact: &self.local_uri,
        };
        vec![builder::build_200_ok_bye(&resp)]
    }

    fn allocate_rtp_port(&self) -> u16 {
        let mut p = self.next_rtp_port.write().unwrap();
        let port = *p;
        *p = p.wrapping_add(2).max(30000); // even ports by RTP convention
        port
    }

    /// Number of dialogs currently in Confirmed state — used by the
    /// test harness and, later, the dashboard's "active calls" metric.
    pub fn active_call_count(&self) -> usize {
        self.dialogs.active_count()
    }
}

// ─── Header-value helpers ───────────────────────────────────────
//
// These operate on already-parsed header *values* (the parser hands us
// the raw value string for a header; SIP doesn't break down From/To/Via
// internal structure for us, since that structure differs per header).

/// Extract the `tag=` parameter from a From/To header value, if present.
fn extract_tag(header_value: &str) -> Option<String> {
    header_value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("tag="))
        .map(|s| s.trim().to_owned())
}

/// Strip a `<...>` wrapper and any `;tag=...` suffix from a From/To value,
/// leaving just the bare URI — what we need when building a *new* To/From
/// header for an outbound message in a different role.
fn strip_uri(header_value: &str) -> String {
    let v = header_value.trim();
    let v = v.split(';').next().unwrap_or(v).trim();
    if let (Some(start), Some(end)) = (v.find('<'), v.find('>')) {
        v[start + 1..end].to_owned()
    } else {
        v.to_owned()
    }
}
