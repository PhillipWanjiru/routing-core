//! IPC envelope encode / decode using JSON for Phase 1.
//! Phase 5: replace JSON with protobuf via prost.

use crate::proto::{Envelope};
use anyhow::{Context, Result};

/// Encode an Envelope to bytes for framing.
pub fn encode_envelope(env: &Envelope) -> Result<Vec<u8>> {
    env.encode().context("failed to encode Envelope")
}

/// Decode a byte slice back into an Envelope.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope> {
    Envelope::decode(bytes).context("failed to decode Envelope")
}
