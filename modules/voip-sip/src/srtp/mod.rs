//! SRTP sub-modules.

pub mod encrypt;
pub mod key_mgmt;

pub use key_mgmt::{parse_sdes_crypto, derive_session_keys, SrtpKeyMaterial, SrtpSessionKeys};
pub use encrypt::{srtp_encrypt, srtp_decrypt, srtp_index};
