//! TURN (RFC 5766) sub-modules.

pub mod allocation;
pub mod auth;
pub mod channel_server;
pub mod client;
pub mod permission;
pub mod permission_server;
pub mod relay;
pub mod server;
pub mod service;

pub use allocation::{
    Allocation, AllocationError, AllocationTable, PortPool,
    DEFAULT_LIFETIME_SECS, MAX_LIFETIME_SECS,
};
pub use permission::{PermissionTable, PERMISSION_LIFETIME_SECS};
pub use relay::{
    build_channel_data, classify_datagram, decide_client_to_peer, decide_peer_to_client,
    is_peer_permitted, parse_channel_data, ChannelBindError, ChannelDataError,
    ChannelDataMessage, ChannelTable, DatagramKind, DropReason, RelayDecision,
    CHANNELDATA_HEADER_LEN, CHANNEL_LIFETIME_SECS, CHANNEL_NUMBER_MAX, CHANNEL_NUMBER_MIN,
};
pub use auth::{
    authenticate_request, build_authenticated_request, build_authenticated_request_with, generate_nonce,
    hmac_sha1, long_term_key, md5, nonce_is_stale, sha1,
    verify_message_integrity, AuthResult, CredentialAttempt, CredentialStore,
};
pub use channel_server::handle_channel_bind_datagram;
pub use permission_server::handle_create_permission_datagram;
pub use service::{TurnOutput, TurnServer};
pub use client::{
    TurnClient, TurnClientAction, TurnClientConfig, TurnClientEvent, TurnClientPhase, TurnClientStep,
};
pub use server::{handle_allocate_datagram, handle_refresh_datagram};
