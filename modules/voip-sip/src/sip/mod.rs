//! SIP and SDP parsers.
//!
//! Phase 1 — only the parsers exist.  The transaction state machine,
//! dialog tracker, registrar, and B2BUA come in Phase 2.

pub mod parser;
pub mod sdp;

pub use parser::{parse_message, Method, SipHeader, SipMessage, StartLine};
pub use sdp::{parse_sdp, MediaDescription, SdpSession};
