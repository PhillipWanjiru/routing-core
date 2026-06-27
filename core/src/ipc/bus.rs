//! IPC bus: accepts Unix domain socket connections from protocol adapter modules.

use crate::{
    ipc::{codec, framing},
    module_registry::{health::ModuleStatus, registry::ModuleRegistry},
    proto::{Envelope, Payload, HealthPing},
};
use anyhow::{Context, Result};
use std::{path::PathBuf, sync::Arc};
use tokio::net::{UnixListener, UnixStream};

/// The central IPC bus.
pub struct Bus {
    socket_dir: PathBuf,
    registry:   Arc<ModuleRegistry>,
    max_frame:  usize,
}

/// A placeholder for a module connection handle (Phase 2 will use mpsc channels).
pub struct ModuleConn {
    pub module_name: String,
}

impl Bus {
    pub fn new(
        socket_dir: impl Into<PathBuf>,
        registry: Arc<ModuleRegistry>,
        max_frame: usize,
    ) -> Self {
        Bus {
            socket_dir: socket_dir.into(),
            registry,
            max_frame,
        }
    }

    /// Bind the bus socket and accept connections indefinitely.
    pub async fn run(&self) -> Result<()> {
        let path = self.socket_dir.join("bus.sock");
        let _ = std::fs::remove_file(&path);

        std::fs::create_dir_all(&self.socket_dir)
            .with_context(|| format!("cannot create socket dir: {}", self.socket_dir.display()))?;

        let listener = UnixListener::bind(&path)
            .with_context(|| format!("cannot bind bus socket: {}", path.display()))?;

        tracing::info!("IPC bus listening on {}", path.display());

        loop {
            let (stream, _addr) = listener
                .accept()
                .await
                .context("bus accept failed")?;

            let registry  = Arc::clone(&self.registry);
            let max_frame = self.max_frame;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, registry, max_frame).await {
                    tracing::warn!("IPC connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    registry: Arc<ModuleRegistry>,
    max_frame: usize,
) -> Result<()> {
    let (mut reader, mut _writer) = stream.split();

    // First frame must be a HealthPing for module identification.
    let Some(raw) = framing::read_frame(&mut reader, max_frame).await? else {
        return Ok(());
    };

    let env = codec::decode_envelope(&raw)?;
    let module_name = env.src_module.clone();

    let Payload::HealthPing(ping) = env.payload else {
        anyhow::bail!("first IPC frame from {module_name} must be HealthPing");
    };

    tracing::info!("module connected: {module_name} (status={})", ping.status);
    registry.register(module_name.clone(), ModuleStatus::Online);

    // Read loop.
    loop {
        let Some(raw) = framing::read_frame(&mut reader, max_frame).await? else {
            break;
        };

        let env = codec::decode_envelope(&raw)?;

        if let Payload::HealthPing(p) = &env.payload {
            if let Ok(status) = parse_status(&p.status) {
                registry.update_status(&module_name, status);
            }
            registry.heartbeat(&module_name, p.seq);
        }
        // Phase 2: route other payload types to the routing engine.
    }

    tracing::info!("module disconnected: {module_name}");
    registry.deregister(&module_name);
    Ok(())
}

fn parse_status(s: &str) -> Result<ModuleStatus> {
    match s {
        "online"      => Ok(ModuleStatus::Online),
        "draining"    => Ok(ModuleStatus::Draining),
        "maintenance" => Ok(ModuleStatus::Maintenance { reason: String::new() }),
        "degraded"    => Ok(ModuleStatus::Degraded),
        other         => anyhow::bail!("unknown module status: {other}"),
    }
}
