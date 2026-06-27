//! Configuration loading.
//! Phase 1: defaults only, loaded from env vars.
//! Phase 2: TOML file support.

pub mod schema;
pub use schema::Config;

use std::sync::Arc;

/// Return default configuration wrapped in Arc.
/// Phase 2 will add TOML file loading here.
pub fn load_or_default() -> Arc<Config> {
    Arc::new(Config::default())
}
