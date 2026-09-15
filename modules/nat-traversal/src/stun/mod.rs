//! STUN (RFC 5389) sub-modules.

pub mod attributes;
pub mod builder;
pub mod parser;
pub mod server;

pub use attributes::{decode_attributes, Attribute, SocketAddrAttr};
pub use builder::{
    build_attribute, build_allocate_success_response, build_binding_success_response,
    build_create_permission_success_response, build_message, build_refresh_success_response,
    build_437_allocation_mismatch, encode_lifetime,
};
pub use parser::{parse_message, MessageClass, Method, ParseError, StunMessage, MAGIC_COOKIE};
pub use server::handle_datagram;
