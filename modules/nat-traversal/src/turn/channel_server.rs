//! TURN ChannelBind request handler (RFC 5766 §11).
//!
//! A channel binding trades the 36+ bytes of a Send/Data indication for the 4
//! bytes of a ChannelData header, by agreeing once on "channel N means peer P".
//! That agreement changes how data is routed, so it is authenticated like
//! Allocate and CreatePermission.
//!
//! A successful bind also installs (or refreshes) the permission for the peer's
//! IP (RFC 5766 §11.2) — a client that binds a channel has plainly expressed
//! the intent to exchange data with that peer, and making it send a separate
//! CreatePermission first would be pointless ceremony.
//!
//! Atomic like the permission handler: the binding is validated and committed
//! first, and the permission installed only if it succeeded, so a rejected
//! request leaves no trace.

use super::{
    allocation::AllocationTable,
    auth::{AuthResult, CredentialStore},
    permission::PermissionTable,
    relay::ChannelTable,
    server::{authenticate_turn_request, challenge_response_for, sign_response},
};
use crate::stun::{
    attributes::{decode_attributes, Attribute},
    builder::{build_437_allocation_mismatch, build_channel_bind_success_response, build_error_response},
    parser::{parse_message, MessageClass, Method},
};
use std::net::SocketAddr;
use std::time::Instant;

/// Process one inbound ChannelBind request from `client`.
///
/// Returns the response to send back, or `None` to drop silently (unparseable,
/// or not a ChannelBind request).
///
/// * **Authenticated, allocation exists, valid attributes** → binding made,
///   permission installed, signed 200.
/// * **No allocation** → 437.
/// * **Missing CHANNEL-NUMBER or XOR-PEER-ADDRESS, an out-of-range channel
///   number, or a binding that conflicts with an existing one** → 400.
/// * **Not authenticated** → 401/438 challenge.
#[allow(clippy::too_many_arguments)]
pub fn handle_channel_bind_datagram(
    raw: &[u8],
    client: SocketAddr,
    realm: &str,
    credentials: &CredentialStore,
    allocations: &AllocationTable,
    permissions: &mut PermissionTable,
    channels: &mut ChannelTable,
    max_nonce_age_secs: u64,
    now: Instant,
) -> Option<Vec<u8>> {
    let msg = parse_message(raw).ok()?;
    if msg.class != MessageClass::Request || msg.method != Method::ChannelBind {
        return None;
    }

    match authenticate_turn_request(&msg, raw, realm, credentials, max_nonce_age_secs) {
        AuthResult::Authenticated { username } => {
            if allocations.get(&client).is_none() {
                tracing::warn!(username, "ChannelBind with no existing allocation");
                return Some(build_437_allocation_mismatch(Method::ChannelBind, &msg.transaction_id));
            }

            let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
            let channel = attrs
                .iter()
                .find_map(|a| if let Attribute::ChannelNumber(n) = a { Some(*n) } else { None });
            let peer = attrs.iter().find_map(|a| {
                if let Attribute::XorPeerAddress(p) = a { Some(SocketAddr::new(p.ip, p.port)) } else { None }
            });
            let bad_request = || {
                build_error_response(Method::ChannelBind, &msg.transaction_id, 400, "Bad Request", &[])
            };
            let (Some(channel), Some(peer)) = (channel, peer) else {
                tracing::warn!(username, "ChannelBind missing CHANNEL-NUMBER or XOR-PEER-ADDRESS");
                return Some(bad_request());
            };

            if let Err(error) = channels.bind(client, channel, peer, now) {
                tracing::warn!(username, ?error, "ChannelBind rejected");
                return Some(bad_request());
            }
            permissions.create_or_refresh(client, peer.ip(), now);

            tracing::info!(username, channel, "ChannelBind succeeded");
            let mut response = build_channel_bind_success_response(&msg.transaction_id);
            sign_response(&mut response, &username, realm, credentials);
            Some(response)
        }
        result => Some(challenge_response_for(&result, Method::ChannelBind, &msg.transaction_id, realm)),
    }
}
