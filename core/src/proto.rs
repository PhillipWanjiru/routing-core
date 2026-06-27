//! IPC message types — hand-written for Phase 1.
//!
//! Phase 5 replaces these with prost-generated types from core/proto/ipc.proto
//! once the Kafka tracing pipeline is added and prost-build is available.
//! All call sites use these types identically either way.

use serde::{Deserialize, Serialize};

// ─── Envelope ─────────────────────────────────────────────────

/// Every IPC message is wrapped in an Envelope so the trace_id travels
/// with the payload regardless of type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// ULID — assigned once at ingress, shared across all hops for one call.
    pub trace_id:    String,
    /// Module that produced this message.
    pub src_module:  String,
    /// Nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// The actual payload.
    pub payload:     Payload,
}

/// All possible IPC payload types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Payload {
    HealthPing(HealthPing),
    CallSetupRequest(CallSetupRequest),
    CallTeardown(CallTeardown),
    RouteQuery(RouteQuery),
    RouteResponse(RouteResponse),
    FirewallPunchCmd(FirewallPunchCmd),
    Span(Span),
    PresenceUpdate(PresenceUpdate),
    QueueItem(QueueItem),
}

// ─── Payload structs ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPing {
    pub module:  String,
    /// "online" | "draining" | "maintenance" | "degraded"
    pub status:  String,
    pub seq:     u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSetupRequest {
    pub from_party:       String,
    pub to_party:         String,
    pub preferred_codec:  String,
    pub srtp_required:    bool,
    pub sdp_offer:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTeardown {
    pub call_id:         String,
    pub reason:          String,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteQuery {
    pub to_party:  String,
    pub exclude:   Vec<String>,
    pub max_paths: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteResponse {
    pub path_id: String,
    pub score:   f64,
    pub hops:    Vec<String>,
}

/// Tells the firewall to punch or close an RTP port pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPunchCmd {
    /// "open" | "close"
    pub action:       String,
    pub src_ip:       String,
    pub src_rtp_port: u16,
    pub dst_rtp_port: u16,
    pub call_id:      String,
}

/// One hop in the distributed trace of a call or message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub span_id:       String,
    pub parent_span_id: Option<String>,
    pub module:        String,
    pub start_ns:      u64,
    pub end_ns:        u64,
    pub outcome:       String,
    pub attrs:         std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceUpdate {
    pub party:   String,
    /// "online" | "offline" | "busy"
    pub status:  String,
    pub ttl_s:   i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub item_id:  String,
    pub target:   String,
    pub channel:  String,
    pub payload:  Vec<u8>,
    pub attempt:  u32,
}

// ─── Serialization helpers ────────────────────────────────────

impl Envelope {
    /// Encode to JSON bytes.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Decode from JSON bytes.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}
