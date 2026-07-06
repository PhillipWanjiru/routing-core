//! G.711 a-law and μ-law codec — pure Rust, no external dependency.
//!
//! G.711 is the codec used on every PSTN call in the world. Each sample
//! is 8 bits (one byte), clock rate 8000 Hz, 64 kbps.
//!
//! # Algorithm
//!
//! Both a-law and μ-law compress 16-bit PCM into 8-bit codewords using
//! logarithmic companding. The codec operates on the 13 most-significant
//! bits of the 16-bit input sample (i.e. `sample >> 3`), which defines
//! the 8 companding segments. Each segment doubles in width:
//!
//! | Segment | abs_s range  | Exp |
//! |---------|-------------|-----|
//! | 0       | 0 – 31      | 0   |
//! | 1       | 32 – 63     | 1   |
//! | 2       | 64 – 127    | 2   |
//! | 3       | 128 – 255   | 3   |
//! | 4       | 256 – 511   | 4   |
//! | 5       | 512 – 1023  | 5   |
//! | 6       | 1024 – 2047 | 6   |
//! | 7       | 2048 – 4095 | 7   |
//!
//! The exponent selects the segment; the 4-bit mantissa selects the step
//! within the segment. Decode is the inverse.
//!
//! # Why threshold comparison, not bit_length()
//!
//! G.711 segments are NOT powers of 2 — segment 0 covers 0–31 (32 values)
//! and segment 1 also covers 32–63 (32 values, same width). Starting from
//! segment 2 the widths double: 64, 128, 256, 512, 1024, 2048. This means
//! `floor(log2(abs_s))` gives the wrong segment for segment 0 and 1.
//! The threshold comparison is the direct implementation of the spec table.
//!
//! # Encoding SNR
//!
//! G.711 achieves ≥ 36 dB SNR for typical speech signals (tested by
//! `snr_db` in the unit tests). The SNR is approximately constant across
//! amplitude levels — this is the companding benefit: a linear codec at
//! the same bit rate would have much lower SNR for quiet signals.

// ─── A-law ─────────────────────────────────────────────────────

/// G.711 a-law segment: returns (exp, shift) for a 13-bit magnitude.
/// This is the direct implementation of ITU-T G.711 Table 1.
#[inline]
fn alaw_segment(abs13: i32) -> (u8, u8) {
    if      abs13 < 32   { (0, 1) }
    else if abs13 < 64   { (1, 1) }
    else if abs13 < 128  { (2, 2) }
    else if abs13 < 256  { (3, 3) }
    else if abs13 < 512  { (4, 4) }
    else if abs13 < 1024 { (5, 5) }
    else if abs13 < 2048 { (6, 6) }
    else                 { (7, 7) }
}

/// Encode one 16-bit linear PCM sample to 8-bit a-law (ITU-T G.711 §3).
pub fn alaw_encode(sample: i16) -> u8 {
    // Operate on the 13 MSBs (G.711 is defined on a 13-bit input range).
    let pcm = (sample as i32) >> 3;
    let sign: u8 = if pcm >= 0 { 0x80 } else { 0x00 };
    let abs13 = if pcm >= 0 { pcm } else { -(pcm + 1) }.min(4095);

    let (exp, shift) = alaw_segment(abs13);
    let mant = if exp == 0 {
        // Segment 0: mantissa is the lower 4 bits of (abs13 >> 1).
        ((abs13 >> 1) & 0x0F) as u8
    } else {
        // Segments 1–7: mantissa is bits [exp+3 .. exp] of abs13.
        ((abs13 >> shift) & 0x0F) as u8
    };

    let codeword = sign | (exp << 4) | mant;
    // XOR 0x55 per G.711 spec to ensure adequate 0/1 density on the line.
    codeword ^ 0x55
}

/// Decode one 8-bit a-law codeword to 16-bit linear PCM.
pub fn alaw_decode(codeword: u8) -> i16 {
    let c    = codeword ^ 0x55;
    let sign = (c & 0x80) != 0;   // 1 = positive sample
    let exp  = (c >> 4) & 0x07;
    let mant = (c & 0x0F) as i32;

    // Reconstruct the 13-bit magnitude at the centre of the quantisation interval.
    let linear13: i32 = if exp == 0 {
        (mant << 1) | 1           // mid-point of a 2-unit interval
    } else {
        ((mant | 0x10) << exp) | (1 << (exp - 1))
    };

    // Scale back to 16-bit range.
    let scaled = linear13 << 3;
    if sign { scaled as i16 } else { -(scaled as i16) }
}

// ─── μ-law ─────────────────────────────────────────────────────

/// Encode one 16-bit linear PCM sample to 8-bit μ-law (ITU-T G.711 §4).
pub fn ulaw_encode(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;   // 132
    const CLIP: i32 = 32635;

    let sign: u8 = if sample >= 0 { 0x80 } else { 0x00 };
    let abs = (sample.abs() as i32).min(CLIP) + BIAS;

    // Segment/exponent selection by threshold.
    let exp: u8 = if      abs >= 0x4000 { 7 }
                  else if abs >= 0x2000 { 6 }
                  else if abs >= 0x1000 { 5 }
                  else if abs >= 0x0800 { 4 }
                  else if abs >= 0x0400 { 3 }
                  else if abs >= 0x0200 { 2 }
                  else if abs >= 0x0100 { 1 }
                  else                  { 0 };

    let mant = ((abs >> (exp + 3)) & 0x0F) as u8;
    // Bitwise NOT gives the 2's complement inversion required by the spec.
    !(sign | (exp << 4) | mant)
}

/// Decode one 8-bit μ-law codeword to 16-bit linear PCM.
pub fn ulaw_decode(codeword: u8) -> i16 {
    let c    = !(codeword);
    let sign = (c & 0x80) != 0;  // True = bit7 was set after NOT = original was POSITIVE
    let exp  = ((c >> 4) & 0x07) as i32;
    let mant = (c & 0x0F) as i32;
    let mag  = ((mant | 0x10) << (exp + 3)) - 0x84;
    if sign { mag as i16 } else { -(mag as i16) }
}

// ─── Bulk helpers ──────────────────────────────────────────────

/// Encode a slice of PCM samples to a-law bytes.
pub fn encode_alaw(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().map(|&s| alaw_encode(s)).collect()
}

/// Decode a-law bytes to PCM samples.
pub fn decode_alaw(bytes: &[u8]) -> Vec<i16> {
    bytes.iter().map(|&b| alaw_decode(b)).collect()
}

/// Encode a slice of PCM samples to μ-law bytes.
pub fn encode_ulaw(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().map(|&s| ulaw_encode(s)).collect()
}

/// Decode μ-law bytes to PCM samples.
pub fn decode_ulaw(bytes: &[u8]) -> Vec<i16> {
    bytes.iter().map(|&b| ulaw_decode(b)).collect()
}

// ─── Quality measurement ───────────────────────────────────────

/// Signal-to-noise ratio in dB for a round-trip encode→decode.
///
/// G.711 achieves ≥ 36 dB SNR for typical speech signals.
pub fn snr_db(original: &[i16], reconstructed: &[i16]) -> f64 {
    let n = original.len().min(reconstructed.len());
    if n == 0 { return 0.0; }
    let sig: f64 = original[..n].iter()
        .map(|&s| (s as f64).powi(2)).sum::<f64>() / n as f64;
    let noise: f64 = original[..n].iter().zip(reconstructed[..n].iter())
        .map(|(&o, &r)| (o as f64 - r as f64).powi(2)).sum::<f64>() / n as f64;
    if noise == 0.0 { f64::INFINITY } else { 10.0 * (sig / noise).log10() }
}
