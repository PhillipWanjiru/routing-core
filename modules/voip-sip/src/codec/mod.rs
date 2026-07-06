//! Codec sub-modules.

pub mod g711;

// Phase 3 continuation: opus.rs, g722.rs
pub use g711::{
    alaw_encode, alaw_decode, ulaw_encode, ulaw_decode,
    encode_alaw, decode_alaw, encode_ulaw, decode_ulaw,
    snr_db,
};
