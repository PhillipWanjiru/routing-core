//! RFC 4566 SDP (Session Description Protocol) parser.
//!
//! Extracts the information the VoIP module needs from an SDP body:
//! - Connection address (c= line) — where to send RTP
//! - Media descriptions (m= lines) — port, protocol, payload types
//! - Attributes (a= lines) — rtpmap, fmtp, crypto, ICE candidates
//!
//! The parser is line-oriented (one type=value per line, CRLF or LF).
//! Unknown line types are silently skipped, per RFC 4566 §5.

/// A complete SDP session.
#[derive(Debug, Clone, Default)]
pub struct SdpSession {
    /// Session-level connection address (overridden by per-media c= lines).
    pub connection: Option<ConnectionData>,
    /// Zero or more media descriptions.
    pub media: Vec<MediaDescription>,
}

/// SDP connection data (c= line).
#[derive(Debug, Clone)]
pub struct ConnectionData {
    /// Network type — almost always "IN".
    pub net_type:   String,
    /// Address type — "IP4" or "IP6".
    pub addr_type:  String,
    /// The IP address as a string.
    pub address:    String,
}

/// One m= block and its associated attributes.
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// "audio", "video", "application", etc.
    pub media_type:    String,
    /// RTP port.
    pub port:          u16,
    /// Number of ports (almost always 1).
    pub num_ports:     u16,
    /// Protocol: "RTP/AVP", "RTP/SAVP", etc.
    pub protocol:      String,
    /// Payload type numbers in preference order.
    pub payload_types: Vec<u8>,
    /// Per-media connection address (overrides session-level).
    pub connection:    Option<ConnectionData>,
    /// Raw a= attributes for this media block.
    pub attributes:    Vec<(String, Option<String>)>,
}

impl MediaDescription {
    /// Look up an attribute by name (case-insensitive).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_deref())
    }

    /// All attributes matching `name`.
    pub fn attrs_all(&self, name: &str) -> Vec<&str> {
        self.attributes
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }

    /// Crypto key lines for SDES (a=crypto).
    pub fn crypto_lines(&self) -> Vec<&str> {
        self.attrs_all("crypto")
    }

    /// ICE ufrag (a=ice-ufrag).
    pub fn ice_ufrag(&self) -> Option<&str> {
        self.attr("ice-ufrag")
    }

    /// ICE password (a=ice-pwd).
    pub fn ice_pwd(&self) -> Option<&str> {
        self.attr("ice-pwd")
    }
}

// ─── Parser ───────────────────────────────────────────────────

/// Parse an SDP body (bytes) into an SdpSession.
///
/// Lines are split on CRLF or bare LF for robustness.
/// Unknown line types are skipped without error.
pub fn parse_sdp(input: &[u8]) -> Result<SdpSession, SdpError> {
    let text = std::str::from_utf8(input)
        .map_err(|e| SdpError::InvalidUtf8(e.valid_up_to()))?;

    let mut session = SdpSession::default();
    let mut current_media: Option<MediaDescription> = None;

    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end();
        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            // Lines shorter than "x=" or without '=' at position 1 are skipped.
            continue;
        }

        let kind  = line.as_bytes()[0] as char;
        let value = &line[2..];

        match kind {
            'v' => { /* version — ignore */ }

            'c' => {
                let conn = parse_connection(value)
                    .map_err(|e| SdpError::InvalidLine { lineno, detail: e })?;
                match current_media {
                    Some(ref mut m) => m.connection = Some(conn),
                    None            => session.connection = Some(conn),
                }
            }

            'm' => {
                // Flush previous media block.
                if let Some(m) = current_media.take() {
                    session.media.push(m);
                }
                let m = parse_media(value)
                    .map_err(|e| SdpError::InvalidLine { lineno, detail: e })?;
                current_media = Some(m);
            }

            'a' => {
                let (name, val) = parse_attribute(value);
                match current_media {
                    Some(ref mut m) => m.attributes.push((name, val)),
                    None            => { /* session-level attr — ignore for now */ }
                }
            }

            _ => { /* skip o= s= t= b= k= z= r= */ }
        }
    }

    // Flush the last media block.
    if let Some(m) = current_media {
        session.media.push(m);
    }

    Ok(session)
}

// ─── Line parsers ─────────────────────────────────────────────

/// Parse a c= line: `<nettype> <addrtype> <address>`
fn parse_connection(value: &str) -> Result<ConnectionData, String> {
    let mut parts = value.splitn(3, ' ');
    let net_type  = parts.next().unwrap_or("").trim().to_owned();
    let addr_type = parts.next().ok_or("c= missing addrtype")?.trim().to_owned();
    let address   = parts.next().ok_or("c= missing address")?.trim().to_owned();
    if net_type.is_empty() || addr_type.is_empty() || address.is_empty() {
        return Err(format!("malformed c= line: '{value}'"));
    }
    Ok(ConnectionData { net_type, addr_type, address })
}

/// Parse an m= line: `<media> <port>[/<num_ports>] <protocol> <payload_types...>`
fn parse_media(value: &str) -> Result<MediaDescription, String> {
    let mut parts = value.split_whitespace();

    let media_type = parts.next().unwrap_or("").to_owned();
    let port_str   = parts.next().ok_or("m= missing port")?;
    let protocol   = parts.next().ok_or("m= missing protocol")?.to_owned();

    // Port may be "port" or "port/num_ports".
    let (port, num_ports) = if let Some(idx) = port_str.find('/') {
        let p = port_str[..idx].parse::<u16>()
            .map_err(|_| format!("m= invalid port: '{}'", &port_str[..idx]))?;
        let n = port_str[idx+1..].parse::<u16>()
            .map_err(|_| format!("m= invalid num_ports: '{}'", &port_str[idx+1..]))?;
        (p, n)
    } else {
        let p = port_str.parse::<u16>()
            .map_err(|_| format!("m= invalid port: '{port_str}'"))?;
        (p, 1)
    };

    let payload_types: Vec<u8> = parts
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();

    if media_type.is_empty() {
        return Err(format!("m= empty media type: '{value}'"));
    }

    Ok(MediaDescription {
        media_type,
        port,
        num_ports,
        protocol,
        payload_types,
        connection:  None,
        attributes:  Vec::new(),
    })
}

/// Parse an a= line: either `<name>` or `<name>:<value>`.
fn parse_attribute(value: &str) -> (String, Option<String>) {
    if let Some(idx) = value.find(':') {
        (value[..idx].trim().to_owned(),
         Some(value[idx+1..].trim().to_owned()))
    } else {
        (value.trim().to_owned(), None)
    }
}

// ─── Error type ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpError {
    InvalidUtf8(usize),
    InvalidLine { lineno: usize, detail: String },
}

impl std::fmt::Display for SdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdpError::InvalidUtf8(pos) =>
                write!(f, "SDP body is not valid UTF-8 at byte {pos}"),
            SdpError::InvalidLine { lineno, detail } =>
                write!(f, "SDP line {lineno}: {detail}"),
        }
    }
}

impl std::error::Error for SdpError {}
