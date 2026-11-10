//! nat-traversal module library root.
//!
//! `unsafe` is denied across the crate. The one exception is the operating-system call
//! that lists network interfaces, in `ice::interfaces`, which opts back in for that
//! single function; a test checks that nothing else does.

#![deny(unsafe_code)]

pub mod ice;
pub mod ice_turn;
pub mod stun;
pub mod turn;
