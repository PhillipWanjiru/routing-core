//! STUN (RFC 5389) sub-modules.

pub mod attributes;
pub mod parser;

pub use attributes::{decode_attributes, Attribute, SocketAddrAttr};
pub use parser::{parse_message, MessageClass, Method, ParseError, StunMessage, MAGIC_COOKIE};
