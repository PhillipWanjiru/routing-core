//! IPC framing and codec tests.

use routing_core::ipc::framing::{read_frame, write_frame};
use std::io::Cursor;

// ─── Framing ──────────────────────────────────────────────────

#[tokio::test]
async fn framing_round_trip_empty() {
    let data: &[u8] = &[];
    let mut buf = Vec::new();
    write_frame(&mut buf, data).await.unwrap();
    // buf should be: [0,0,0,0] (4-byte length = 0)
    assert_eq!(buf, [0u8, 0, 0, 0]);

    let mut cursor = Cursor::new(buf);
    let result = read_frame(&mut cursor, 1024).await.unwrap();
    assert_eq!(result, Some(vec![]));
}

#[tokio::test]
async fn framing_round_trip_payload() {
    let data = b"hello, routing core";
    let mut buf = Vec::new();
    write_frame(&mut buf, data).await.unwrap();

    // First 4 bytes are the big-endian length.
    let expected_len = (data.len() as u32).to_be_bytes();
    assert_eq!(&buf[..4], &expected_len);
    assert_eq!(&buf[4..], data);

    let mut cursor = Cursor::new(buf);
    let result = read_frame(&mut cursor, 1024).await.unwrap();
    assert_eq!(result, Some(data.to_vec()));
}

#[tokio::test]
async fn framing_multiple_frames() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"frame one").await.unwrap();
    write_frame(&mut buf, b"frame two").await.unwrap();
    write_frame(&mut buf, b"frame three").await.unwrap();

    let mut cursor = Cursor::new(buf);
    let f1 = read_frame(&mut cursor, 1024).await.unwrap();
    let f2 = read_frame(&mut cursor, 1024).await.unwrap();
    let f3 = read_frame(&mut cursor, 1024).await.unwrap();
    let f4 = read_frame(&mut cursor, 1024).await.unwrap();

    assert_eq!(f1, Some(b"frame one".to_vec()));
    assert_eq!(f2, Some(b"frame two".to_vec()));
    assert_eq!(f3, Some(b"frame three".to_vec()));
    assert_eq!(f4, None); // clean EOF
}

#[tokio::test]
async fn framing_rejects_oversized_frame() {
    let limit = 16usize;
    let mut buf = Vec::new();
    // Write a frame that claims to be 1000 bytes.
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(&[0u8; 20]); // less than claimed — doesn't matter

    let mut cursor = Cursor::new(buf);
    let result = read_frame(&mut cursor, limit).await;
    assert!(result.is_err(), "should have rejected oversized frame");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("exceeds limit"), "unexpected error: {msg}");
}

#[tokio::test]
async fn framing_clean_eof_at_boundary() {
    // An empty reader should return None (clean EOF), not an error.
    let mut cursor = Cursor::new(Vec::<u8>::new());
    let result = read_frame(&mut cursor, 1024).await.unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn framing_length_is_big_endian() {
    // Verify byte order explicitly for a known payload length.
    let data = vec![42u8; 256];
    let mut buf = Vec::new();
    write_frame(&mut buf, &data).await.unwrap();
    // 256 in big-endian u32 = [0, 0, 1, 0]
    assert_eq!(&buf[..4], &[0u8, 0, 1, 0]);
}
