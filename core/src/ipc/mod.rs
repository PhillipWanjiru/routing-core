//! IPC bus: Unix domain socket transport with protobuf framing.

pub mod bus;
pub mod codec;
pub mod framing;

pub use bus::{Bus, ModuleConn};
pub use codec::{decode_envelope, encode_envelope};
pub use framing::{read_frame, write_frame};
