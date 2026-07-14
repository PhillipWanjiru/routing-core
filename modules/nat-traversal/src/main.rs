//! nat-traversal module entrypoint.
//! Phase 4: STUN parser + attributes exist; server wiring is next.

pub mod stun;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("nat-traversal module starting (Phase 4 — STUN parser milestone)");
    tracing::info!("nat-traversal module halted — server wiring not yet implemented");
}
