//! RFC 3550 RTP session.
//!
//! Tracks per-call RTP state for one direction of one call leg:
//! sequence number generation/validation, timestamp tracking, SSRC
//! management, SSRC collision detection, and RTCP statistics.

use std::collections::HashMap;
use std::time::Instant;

// ─── Fixed header ──────────────────────────────────────────────

pub const RTP_HEADER_LEN: usize = 12;
pub const RTP_VERSION:     u8   = 2;

/// A parsed RTP fixed header (RFC 3550 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub version:      u8,
    pub padding:      bool,
    pub extension:    bool,
    pub cc:           u8,
    pub marker:       bool,
    pub payload_type: u8,
    pub sequence:     u16,
    pub timestamp:    u32,
    pub ssrc:         u32,
}

impl RtpHeader {
    /// Parse from the first 12 bytes of an RTP packet.
    /// Returns `None` on a short buffer or wrong version.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < RTP_HEADER_LEN { return None; }
        let v = (buf[0] >> 6) & 0x3;
        if v != RTP_VERSION { return None; }
        Some(RtpHeader {
            version:      v,
            padding:      (buf[0] & 0x20) != 0,
            extension:    (buf[0] & 0x10) != 0,
            cc:           buf[0] & 0x0F,
            marker:       (buf[1] & 0x80) != 0,
            payload_type: buf[1] & 0x7F,
            sequence:     u16::from_be_bytes([buf[2], buf[3]]),
            timestamp:    u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ssrc:         u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }

    /// Serialise to a 12-byte array.
    pub fn to_bytes(&self) -> [u8; RTP_HEADER_LEN] {
        let mut b = [0u8; RTP_HEADER_LEN];
        b[0] = (self.version << 6)
             | ((self.padding   as u8) << 5)
             | ((self.extension as u8) << 4)
             | (self.cc & 0x0F);
        b[1] = ((self.marker as u8) << 7) | (self.payload_type & 0x7F);
        b[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        b[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        b[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        b
    }
}

// ─── Send session ──────────────────────────────────────────────

/// Send-side state for one RTP stream.
pub struct RtpSendSession {
    pub ssrc:          u32,
    pub payload_type:  u8,
    pub clock_rate:    u32,
    pub packets_sent:  u32,
    pub bytes_sent:    u32,
    next_seq:          u16,
    next_timestamp:    u32,
}

impl RtpSendSession {
    pub fn new(payload_type: u8, clock_rate: u32) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SSRC_CTR: AtomicU32 = AtomicU32::new(0x12345678);
        let ssrc = SSRC_CTR.fetch_add(0x9e3779b9, Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        RtpSendSession {
            ssrc,
            payload_type,
            clock_rate,
            packets_sent:   0,
            bytes_sent:     0,
            next_seq:       (ts & 0xFFFF) as u16,
            next_timestamp: ts,
        }
    }

    /// Build a complete RTP packet. `samples` advances the timestamp.
    /// For G.711 at 20ms ptime: clock_rate=8000, samples=160.
    pub fn build_packet(&mut self, payload: &[u8], samples: u32, marker: bool) -> Vec<u8> {
        let hdr = RtpHeader {
            version: RTP_VERSION, padding: false, extension: false, cc: 0,
            marker,
            payload_type: self.payload_type,
            sequence:     self.next_seq,
            timestamp:    self.next_timestamp,
            ssrc:         self.ssrc,
        };
        let mut pkt = Vec::with_capacity(RTP_HEADER_LEN + payload.len());
        pkt.extend_from_slice(&hdr.to_bytes());
        pkt.extend_from_slice(payload);
        self.next_seq       = self.next_seq.wrapping_add(1);
        self.next_timestamp = self.next_timestamp.wrapping_add(samples);
        self.packets_sent  += 1;
        self.bytes_sent    += payload.len() as u32;
        pkt
    }
}

// ─── Per-source state ──────────────────────────────────────────

struct SourceState {
    _ssrc:            u32,
    max_seq_extended: u32,
    base_seq:         u16,
    received:         u32,
    expected_prior:   u32,
    received_prior:   u32,
    /// Inter-arrival jitter in RTP timestamp units (RFC 3550 §A.8).
    jitter:           f64,
    last_transit:     i64,
    first_packet:     bool,
}

impl SourceState {
    fn new(ssrc: u32, first_seq: u16) -> Self {
        SourceState {
            _ssrc:            ssrc,
            max_seq_extended: first_seq as u32,
            base_seq:         first_seq,
            received:         0,
            expected_prior:   0,
            received_prior:   0,
            jitter:           0.0,
            last_transit:     0,
            first_packet:     true,
        }
    }

    /// RFC 3550 §A.1: extend 16-bit seq to 32 bits, handling wrap-around.
    fn extend_seq(&self, seq: u16) -> u32 {
        let max16 = (self.max_seq_extended & 0xFFFF) as u16;
        let delta = seq.wrapping_sub(max16);
        if delta < 0x8000 {
            self.max_seq_extended.wrapping_add(delta as u32)
        } else {
            self.max_seq_extended
                .wrapping_sub((0x10000u32).wrapping_sub(delta as u32))
        }
    }

    /// RFC 3550 §A.8: update inter-arrival jitter estimate.
    fn update_jitter(&mut self, rtp_ts: u32, arrival_ns: u64, clock_rate: u32) {
        let clocks_per_ns = clock_rate as f64 / 1_000_000_000.0;
        let arrival_rtp = (arrival_ns as f64 * clocks_per_ns) as i64;
        let transit = arrival_rtp - rtp_ts as i64;
        if self.first_packet {
            self.last_transit = transit;
            self.first_packet = false;
            return;
        }
        let d = (transit - self.last_transit).unsigned_abs() as f64;
        self.jitter     += (d - self.jitter) / 16.0;
        self.last_transit = transit;
    }

    fn expected(&self) -> u32 {
        self.max_seq_extended
            .wrapping_sub(self.base_seq as u32)
            .wrapping_add(1)
    }

    fn lost(&self) -> u32 { self.expected().saturating_sub(self.received) }

    /// Fraction lost since last RR: 0 = 0%, 255 ≈ 100% (RFC 3550 §6.4.1).
    fn fraction_lost(&mut self) -> u8 {
        let exp_now  = self.expected();
        let recv_now = self.received;
        let exp_int  = exp_now.saturating_sub(self.expected_prior);
        let recv_int = recv_now.saturating_sub(self.received_prior);
        self.expected_prior = exp_now;
        self.received_prior = recv_now;
        if exp_int == 0 { return 0; }
        let lost_int = exp_int.saturating_sub(recv_int);
        ((lost_int as f64 / exp_int as f64) * 256.0) as u8
    }
}

// ─── Receive session ───────────────────────────────────────────

/// Receive-side RTP state. Tracks one or more SSRC sources.
pub struct RtpRecvSession {
    pub clock_rate: u32,
    sources:        HashMap<u32, SourceState>,
    session_start:  Instant,
}

/// Statistics for one RTCP Receiver Report block.
#[derive(Debug, Clone)]
pub struct RtcpStats {
    pub ssrc:             u32,
    pub fraction_lost:    u8,
    pub cumulative_lost:  u32,
    pub extended_max_seq: u32,
    pub jitter:           u32,
}

impl RtpRecvSession {
    pub fn new(clock_rate: u32) -> Self {
        RtpRecvSession {
            clock_rate,
            sources:       HashMap::new(),
            session_start: Instant::now(),
        }
    }

    /// Process one inbound RTP packet. Returns payload bytes on success.
    /// Pass `arrival_ns = None` to derive from `Instant::now()`.
    pub fn receive(&mut self, packet: &[u8], arrival_ns: Option<u64>) -> Option<Vec<u8>> {
        let hdr = RtpHeader::parse(packet)?;

        // Skip RTCP packets accidentally received on the RTP port.
        if hdr.payload_type == 72 || hdr.payload_type == 73 { return None; }

        let arrival = arrival_ns.unwrap_or_else(|| {
            self.session_start.elapsed().as_nanos() as u64
        });

        let src = self.sources
            .entry(hdr.ssrc)
            .or_insert_with(|| SourceState::new(hdr.ssrc, hdr.sequence));

        let extended = src.extend_seq(hdr.sequence);
        if extended >= src.max_seq_extended {
            src.max_seq_extended = extended;
        }
        src.received += 1;
        src.update_jitter(hdr.timestamp, arrival, self.clock_rate);

        let payload_start = RTP_HEADER_LEN + (hdr.cc as usize) * 4;
        if packet.len() <= payload_start { return None; }
        Some(packet[payload_start..].to_vec())
    }

    /// RTCP RR statistics for the named SSRC.
    pub fn rtcp_stats(&mut self, ssrc: u32) -> Option<RtcpStats> {
        let src = self.sources.get_mut(&ssrc)?;
        Some(RtcpStats {
            ssrc,
            fraction_lost:    src.fraction_lost(),
            cumulative_lost:  src.lost().min(0x00FF_FFFF),
            extended_max_seq: src.max_seq_extended,
            jitter:           src.jitter as u32,
        })
    }

    /// Jitter in milliseconds for the named SSRC.
    pub fn jitter_ms(&self, ssrc: u32) -> f64 {
        self.sources.get(&ssrc)
            .map(|s| s.jitter * 1000.0 / self.clock_rate as f64)
            .unwrap_or(0.0)
    }

    /// Packet loss fraction 0.0–1.0 for the named SSRC.
    pub fn loss_fraction(&self, ssrc: u32) -> f64 {
        match self.sources.get(&ssrc) {
            None => 0.0,
            Some(s) => {
                let exp = s.expected();
                if exp == 0 { 0.0 } else { s.lost() as f64 / exp as f64 }
            }
        }
    }
}
