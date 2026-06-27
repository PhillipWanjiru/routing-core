//! Length-prefixed frame protocol.
//!
//! Wire format:
//!   [u32 big-endian length][<length> bytes of protobuf data]
//!
//! Design decisions:
//! - u32 gives a 4 GiB maximum frame.  We enforce a much lower limit
//!   (Config::max_frame_bytes, default 1 MiB) so a malformed length
//!   field cannot cause a gigabyte allocation.
//! - Big-endian is the network byte order convention.
//! - We read the length header and the body in two separate `read_exact`
//!   calls rather than allocating based on the header first.  The header
//!   read is bounded (4 bytes), and the body read is bounded by the limit.

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum permissible frame body size in bytes.
/// Override at runtime via Config::max_frame_bytes.
pub const DEFAULT_MAX_FRAME: usize = 1_048_576; // 1 MiB

/// Write one length-prefixed frame.
///
/// Writes `[u32-BE length][data bytes]` atomically into `writer`.
pub async fn write_frame<W>(writer: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > u32::MAX as usize {
        bail!("frame too large: {} bytes", data.len());
    }
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Read one length-prefixed frame.
///
/// Reads the 4-byte header, validates against `max_bytes`, then reads the
/// body.  Returns `None` on a clean EOF at the start of a frame boundary
/// (the peer closed the connection).  Returns `Err` on a mid-frame EOF.
pub async fn read_frame<R>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    // Read the 4-byte length header.
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Clean close at frame boundary.
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }

    let frame_len = u32::from_be_bytes(len_buf) as usize;

    if frame_len > max_bytes {
        bail!(
            "frame length {frame_len} exceeds limit {max_bytes} —              possible framing attack or corrupt stream"
        );
    }

    let mut body = vec![0u8; frame_len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|e| anyhow::anyhow!("mid-frame EOF after {frame_len}-byte header: {e}"))?;

    Ok(Some(body))
}
