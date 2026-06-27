//! Distributed tracing: ULID generation and span emission.

pub mod span;
pub mod ulid;

pub use span::{Span, SpanEmitter};
pub use ulid::Ulid;
