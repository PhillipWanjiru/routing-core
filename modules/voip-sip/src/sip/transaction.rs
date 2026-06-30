//! RFC 3261 §17 SIP transaction state machine.
//!
//! A transaction is the fundamental unit of SIP reliability. It wraps one
//! request and all responses to it, handling retransmission so the dialog
//! layer does not have to.
//!
//! # Transaction types
//!
//! - **INVITE client** — sends INVITE, receives provisional and final responses.
//! - **INVITE server** — receives INVITE, sends provisional and final responses.
//! - **Non-INVITE client** — sends any non-INVITE request, receives final response.
//! - **Non-INVITE server** — receives any non-INVITE request, sends final response.
//!
//! # Timer values (RFC 3261 §17.1.1)
//!
//! | Timer | Value             | Meaning                                |
//! |-------|-------------------|----------------------------------------|
//! | T1    | 500 ms (default)  | RTT estimate, retransmit base          |
//! | T2    | 4 s               | Max retransmit interval (non-INVITE)   |
//! | T4    | 5 s               | Max duration a message will remain in net |
//! | B     | 64 × T1 = 32 s   | INVITE client timeout                  |
//! | F     | 64 × T1 = 32 s   | Non-INVITE client timeout              |
//! | H     | 64 × T1 = 32 s   | INVITE server wait for ACK             |

use std::time::Duration;

pub const T1: Duration = Duration::from_millis(500);
pub const T2: Duration = Duration::from_secs(4);
pub const T4: Duration = Duration::from_secs(5);
pub const TIMER_B: Duration = Duration::from_millis(500 * 64); // 64 × T1
pub const TIMER_F: Duration = Duration::from_millis(500 * 64);
pub const TIMER_H: Duration = Duration::from_millis(500 * 64);

// ─── States ───────────────────────────────────────────────────

/// INVITE client transaction states (RFC 3261 §17.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteClientState {
    /// INVITE sent, awaiting any response.
    Calling,
    /// 1xx received; awaiting final response.
    Proceeding,
    /// 2xx received — success (terminate immediately, dialog layer takes over).
    Accepted,
    /// 3xx–6xx received; awaiting ACK to be sent by TU.
    Completed,
    /// ACK sent; waiting for Timer D before termination.
    Terminated,
}

/// INVITE server transaction states (RFC 3261 §17.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteServerState {
    /// INVITE received; TU is processing (may send 1xx).
    Proceeding,
    /// 2xx sent — success.
    Accepted,
    /// Final non-2xx sent; awaiting ACK.
    Completed,
    /// ACK received.
    Confirmed,
    /// Transaction ended.
    Terminated,
}

/// Non-INVITE client transaction states (RFC 3261 §17.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonInviteClientState {
    /// Request sent.
    Trying,
    /// 1xx received.
    Proceeding,
    /// Final response received.
    Completed,
    /// Transaction ended.
    Terminated,
}

/// Non-INVITE server transaction states (RFC 3261 §17.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonInviteServerState {
    /// Request received; TU processing.
    Trying,
    /// 1xx sent.
    Proceeding,
    /// Final response sent; retransmitting on retransmit.
    Completed,
    /// Transaction ended.
    Terminated,
}

// ─── Events ───────────────────────────────────────────────────

/// Events that drive transaction state machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxEvent {
    /// A SIP message was received from the network.
    MessageReceived {
        /// SIP status code for responses; 0 for requests.
        code: u16,
    },
    /// The TU (transaction user) wants to send a response.
    TuResponse { code: u16 },
    /// Timer B / F / H fired.
    TimerTimeout,
    /// Timer D fired (INVITE client: wait after ACK).
    TimerD,
    /// Retransmit timer fired — resend last message.
    Retransmit,
    /// ACK received (INVITE server only).
    AckReceived,
}

// ─── INVITE client FSM ────────────────────────────────────────

/// Process one event for an INVITE client transaction.
///
/// Returns the new state. Caller is responsible for any I/O
/// (resending the INVITE, sending ACK for 3xx-6xx, etc.).
pub fn invite_client_step(
    state: InviteClientState,
    event: TxEvent,
) -> InviteClientState {
    use InviteClientState::*;
    match (&state, &event) {
        // Retransmit INVITE while Calling.
        (Calling, TxEvent::Retransmit) => Calling,

        // 1xx → Proceeding.
        (Calling | Proceeding, TxEvent::MessageReceived { code: 100..=199 }) => Proceeding,

        // 2xx → Accepted (dialog layer takes over).
        (Calling | Proceeding, TxEvent::MessageReceived { code: 200..=299 }) => Accepted,

        // 3xx–6xx → Completed; caller must send ACK.
        (Calling | Proceeding, TxEvent::MessageReceived { code: 300..=699 }) => Completed,

        // ACK sent (Completed) → Terminated after Timer D.
        (Completed, TxEvent::Retransmit) => Completed, // Retransmit ACK.
        (Completed, TxEvent::TimerD)     => Terminated,

        // Timer B: no final response before timeout.
        (Calling | Proceeding, TxEvent::TimerTimeout) => Terminated,

        // Already terminated — absorb any late messages.
        (Terminated, _) => Terminated,
        (Accepted, _)   => Accepted,

        _ => state, // All other combinations are no-ops.
    }
}

// ─── INVITE server FSM ────────────────────────────────────────

/// Process one event for an INVITE server transaction.
pub fn invite_server_step(
    state: InviteServerState,
    event: TxEvent,
) -> InviteServerState {
    use InviteServerState::*;
    match (&state, &event) {
        // TU sends 1xx.
        (Proceeding, TxEvent::TuResponse { code: 100..=199 }) => Proceeding,

        // TU sends 2xx → Accepted.
        (Proceeding, TxEvent::TuResponse { code: 200..=299 }) => Accepted,

        // TU sends final non-2xx → Completed; retransmit on retransmit events.
        (Proceeding, TxEvent::TuResponse { code: 300..=699 }) => Completed,

        // ACK received while Completed → Confirmed.
        (Completed, TxEvent::AckReceived) => Confirmed,

        // Retransmit INVITE while Proceeding/Completed.
        (Proceeding, TxEvent::Retransmit) => Proceeding,
        (Completed,  TxEvent::Retransmit) => Completed,

        // Timer H: no ACK received → terminate.
        (Completed, TxEvent::TimerTimeout) => Terminated,

        // Timer I: absorb any late ACKs.
        (Confirmed, TxEvent::TimerTimeout) => Terminated,

        (Terminated, _) => Terminated,
        (Accepted, _)   => Accepted,

        _ => state,
    }
}

// ─── Non-INVITE client FSM ────────────────────────────────────

/// Process one event for a non-INVITE client transaction.
pub fn non_invite_client_step(
    state: NonInviteClientState,
    event: TxEvent,
) -> NonInviteClientState {
    use NonInviteClientState::*;
    match (&state, &event) {
        // Retransmit request while Trying/Proceeding.
        (Trying | Proceeding, TxEvent::Retransmit) => state,

        // 1xx → Proceeding.
        (Trying | Proceeding, TxEvent::MessageReceived { code: 100..=199 }) => Proceeding,

        // Final response → Completed.
        (Trying | Proceeding, TxEvent::MessageReceived { code: 200..=699 }) => Completed,

        // Timer K (= T4) fires after Completed → Terminated.
        (Completed, TxEvent::TimerD) => Terminated,

        // Timer F: no response before timeout.
        (Trying | Proceeding, TxEvent::TimerTimeout) => Terminated,

        (Terminated, _) => Terminated,

        _ => state,
    }
}
