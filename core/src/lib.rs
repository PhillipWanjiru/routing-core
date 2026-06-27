//! Routing Core library crate.

pub mod config;
pub mod ipc;
pub mod module_registry;
pub mod routing;
pub mod tracing;
pub mod proto;

pub use anyhow::{anyhow, bail, Context, Result};
