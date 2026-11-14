//! Writing SDP offers and answers, with ICE.
//!
//! Every value is validated before it is written, so nothing a caller (or a caller's
//! peer, whose text may have been copied in) controls can add lines to a description.
//! That is the same rule the ICE codec applies to the attributes it writes, and it is
//! applied here to everything else.
//!
//! # The `m=` and `c=` lines
//!
//! With ICE they carry the *default candidate* (RFC 8839 §4.2): the address an endpoint
//! that does not understand ICE will send to, chosen by
//! [`default_candidate`](crate::nat::ice::default_candidate). With ICE but no candidates
//! yet, they carry the conventional placeholder, port 9 and `0.0.0.0`. Without ICE they
//! carry the caller's `fallback` address. Each media section gets its own `c=` line,
//! because each can have a different default.
//!
//! # Not covered
//!
//! A rejected stream (port 0), session-level attributes, and bundling.

use crate::nat::ice::default_candidate;
use nat_traversal::ice::sdp::{format_ice_attributes, EncodeError, EncodeOptions, IceDescription};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// The `o=` line: who made the description, and which version of it this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub address: IpAddr,
}

/// One payload type, with its `a=rtpmap` encoding (`PCMU/8000`) if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    pub payload_type: u8,
    pub rtpmap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSection {
    /// `audio` or `video`.
    pub media_type: String,
    /// `RTP/AVP`, `UDP/TLS/RTP/SAVPF`, ...
    pub protocol: String,
    pub formats: Vec<Format>,
    /// Where media goes when there is no ICE.
    pub fallback: SocketAddr,
    pub ice: Option<IceDescription>,
    /// Extra `a=` lines, without the `a=`. ICE attributes must go in `ice`.
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    Invalid(&'static str),
    Ice(EncodeError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Invalid(why) => write!(f, "cannot write SDP: {why}"),
            BuildError::Ice(e) => write!(f, "cannot write the ICE attributes: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

fn invalid<T>(why: &'static str) -> Result<T, BuildError> {
    Err(BuildError::Invalid(why))
}

/// Printable ASCII only: no control characters, so no line breaks.
fn printable(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn word(s: &str, extra: &[u8]) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

const RESERVED: [&str; 6] = ["ice-ufrag", "ice-pwd", "ice-options", "ice-lite", "end-of-candidates", "candidate"];

fn ip_version(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "IP4" } else { "IP6" }
}

fn write_section(out: &mut String, s: &MediaSection, opts: EncodeOptions) -> Result<(), BuildError> {
    if !word(&s.media_type, b"") {
        return invalid("media type");
    }
    if !word(&s.protocol, b"/_.-") {
        return invalid("transport protocol");
    }
    if s.formats.is_empty() {
        return invalid("a media section needs at least one format");
    }
    for f in &s.formats {
        if f.payload_type > 127 {
            return invalid("payload type above 127");
        }
        if let Some(map) = &f.rtpmap {
            if !word(map, b"/_.-") {
                return invalid("rtpmap");
            }
        }
    }
    for a in &s.attributes {
        if !printable(a) {
            return invalid("attribute with a control character, or empty");
        }
        let name = a.split(':').next().unwrap_or("");
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name)) {
            return invalid("ICE attributes belong in `ice`");
        }
    }

    let (ip, port) = match &s.ice {
        Some(d) => match default_candidate(&d.candidates) {
            Some(c) => (c.transport_addr.ip(), c.transport_addr.port()),
            None => (IpAddr::from([0, 0, 0, 0]), 9),
        },
        None => {
            if s.fallback.port() == 0 {
                return invalid("port 0 would reject the stream");
            }
            (s.fallback.ip(), s.fallback.port())
        }
    };

    let pts: Vec<String> = s.formats.iter().map(|f| f.payload_type.to_string()).collect();
    out.push_str(&format!("m={} {} {} {}\r\n", s.media_type, port, s.protocol, pts.join(" ")));
    out.push_str(&format!("c=IN {} {}\r\n", ip_version(ip), ip));
    for f in &s.formats {
        if let Some(map) = &f.rtpmap {
            out.push_str(&format!("a=rtpmap:{} {}\r\n", f.payload_type, map));
        }
    }
    for a in &s.attributes {
        out.push_str(&format!("a={a}\r\n"));
    }
    if let Some(d) = &s.ice {
        out.push_str(&format_ice_attributes(d, opts).map_err(BuildError::Ice)?);
    }
    Ok(())
}

/// Write a complete SDP description: an offer, or an answer.
pub fn build_sdp(origin: &Origin, sections: &[MediaSection], opts: EncodeOptions) -> Result<String, BuildError> {
    if !word(&origin.username, b"._-") {
        return invalid("origin username");
    }
    if sections.is_empty() {
        return invalid("a description needs at least one media section");
    }
    let mut out = String::new();
    out.push_str("v=0\r\n");
    out.push_str(&format!(
        "o={} {} {} IN {} {}\r\n",
        origin.username, origin.session_id, origin.session_version, ip_version(origin.address), origin.address
    ));
    out.push_str("s=-\r\n");
    out.push_str("t=0 0\r\n");
    for s in sections {
        write_section(&mut out, s, opts)?;
    }
    Ok(out)
}
