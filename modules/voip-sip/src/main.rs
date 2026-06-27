//! voip-sip module entrypoint.
//! Phase 1: parses command-line args, connects to the IPC bus.
//! Phase 2: starts the SIP listener, RTP multiplexer.

pub mod sip;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("voip-sip module starting (Phase 1 — parser + IPC stub)");
    // Phase 2: connect to IPC bus and start SIP listener.
    tracing::info!("voip-sip module halted — nothing to do in Phase 1");
}
