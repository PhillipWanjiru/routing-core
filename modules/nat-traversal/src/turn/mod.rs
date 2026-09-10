//! TURN (RFC 5766) sub-modules.

pub mod allocation;
pub mod auth;
pub mod server;

pub use allocation::{
    Allocation, AllocationError, AllocationTable, PortPool,
    DEFAULT_LIFETIME_SECS, MAX_LIFETIME_SECS,
};
pub use auth::{
    authenticate_request, build_authenticated_request, generate_nonce,
    hmac_sha1, long_term_key, md5, nonce_is_stale, sha1,
    verify_message_integrity, AuthResult, CredentialAttempt, CredentialStore,
};
pub use server::{handle_allocate_datagram, handle_refresh_datagram};
