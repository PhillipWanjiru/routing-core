//! NAT traversal as the SIP module uses it.
//!
//! The STUN and TURN *servers* are network services and live in the `nat-traversal`
//! process. The client side (the ICE agent, the TURN client, the SDP codec and interface
//! discovery) is the logic of a media endpoint, so it is linked into whatever terminates
//! the call: this module is where the SIP side meets it. ICE traffic never crosses the IPC
//! bus, which carries control-plane messages between processes.
//!
//! The other files in this directory are placeholders for features that are not built yet
//! and are not compiled.

pub mod ice;
