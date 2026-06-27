//! Distributed tracing span emission.
//!
//! Phase 1: spans are written to stderr as structured JSON lines.
//! Phase 5: the emitter is replaced with an async Kafka producer.
//! All call sites are unchanged — only this file changes.

use super::Ulid;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Types ────────────────────────────────────────────────────

/// A single hop in the distributed trace of a call or message.
#[derive(Debug, Clone)]
pub struct Span {
    /// Shared across all hops for one call/message.
    pub trace_id: Ulid,
    /// Unique ID of this hop.
    pub span_id: Ulid,
    /// Parent span, if any (None for the ingress hop).
    pub parent_id: Option<Ulid>,
    /// Module that produced this span.
    pub module: String,
    /// Nanoseconds since Unix epoch when this hop started.
    pub start_ns: u64,
    /// Nanoseconds since Unix epoch when this hop finished.
    pub end_ns: u64,
    /// "ok" | "error" | "timeout" or any module-specific label.
    pub outcome: String,
    /// Arbitrary key-value metadata attached to this hop.
    pub attrs: HashMap<String, String>,
}

impl Span {
    /// Serialise to a compact JSON line for Phase 1 stderr logging.
    fn to_json_line(&self) -> String {
        let mut attrs = String::from("{");
        for (i, (k, v)) in self.attrs.iter().enumerate() {
            if i > 0 { attrs.push(','); }
            attrs.push_str(&format!("\"{}\":\"{}\"", k, v));
        }
        attrs.push('}');

        let parent = self.parent_id
            .map(|p| format!("\"{}\"", p))
            .unwrap_or_else(|| "null".into());

        format!(
            "{{\"trace\":\"{}\",\"span\":\"{}\",\
             \"parent\":{},\"module\":\"{}\",             \"start_ns\":{},\"end_ns\":{},             \"outcome\":\"{}\",\"attrs\":{}}}",
            self.trace_id,
            self.span_id,
            parent,
            self.module,
            self.start_ns,
            self.end_ns,
            self.outcome,
            attrs,
        )
    }
}

// ─── Builder ──────────────────────────────────────────────────

/// Builds and emits a span.
///
/// # Example
///
/// ```rust
/// use routing_core::tracing::{ulid::Ulid, span::SpanEmitter};
///
/// let trace_id   = Ulid::new();
/// let parent_id  = Ulid::new();
/// let span = SpanEmitter::start(trace_id, "voip-sip")
///     .parent(parent_id)
///     .attr("call_id", "abc-123")
///     .finish("ok");
/// assert_eq!(span.outcome, "ok");
/// assert_eq!(span.module,  "voip-sip");
/// ```
pub struct SpanEmitter {
    trace_id:  Ulid,
    span_id:   Ulid,
    parent_id: Option<Ulid>,
    module:    String,
    start_ns:  u64,
    attrs:     HashMap<String, String>,
}

impl SpanEmitter {
    /// Begin a span.  Records the current wall-clock time as `start_ns`.
    pub fn start(trace_id: Ulid, module: impl Into<String>) -> Self {
        SpanEmitter {
            trace_id,
            span_id:   Ulid::new(),
            parent_id: None,
            module:    module.into(),
            start_ns:  now_ns(),
            attrs:     HashMap::new(),
        }
    }

    /// Attach a parent span id (all hops except the first ingress hop).
    pub fn parent(mut self, parent: Ulid) -> Self {
        self.parent_id = Some(parent);
        self
    }

    /// Attach a key-value attribute.
    pub fn attr(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attrs.insert(k.into(), v.into());
        self
    }

    /// Finish the span with an outcome label and emit it.
    ///
    /// Phase 1: emits to stderr.
    /// Phase 5: sends to Kafka topic `spans.<module>`.
    pub fn finish(self, outcome: impl Into<String>) -> Span {
        let span = Span {
            trace_id:  self.trace_id,
            span_id:   self.span_id,
            parent_id: self.parent_id,
            module:    self.module,
            start_ns:  self.start_ns,
            end_ns:    now_ns(),
            outcome:   outcome.into(),
            attrs:     self.attrs,
        };
        emit(&span);
        span
    }
}

/// Emit a span to the configured backend.
///
/// Phase 1: writes a JSON line to stderr.
fn emit(span: &Span) {
    eprintln!("[span] {}", span.to_json_line());
}

/// Current wall-clock time in nanoseconds since Unix epoch.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
