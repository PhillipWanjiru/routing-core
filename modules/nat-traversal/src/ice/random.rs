//! Randomness for ICE: transaction IDs, tie-breakers and credentials.
//!
//! This matters more than it looks. A check *response* is protected by
//! MESSAGE-INTEGRITY, but an *error* response to a rejected check cannot be
//! (the rejecting side has nothing to sign with), so the transaction ID is
//! the only thing standing between an off-path attacker and a forged error
//! that fails a working pair. RFC 5389 §6 therefore requires transaction IDs
//! to be uniformly random — a predictable counter would not do. ICE passwords,
//! which key every connectivity check, need the same.
//!
//! The source is the kernel's CSPRNG, read from `/dev/urandom`.
//!
//! # There is no fallback
//!
//! An earlier version dropped to a time-and-counter mixer whenever the read
//! failed, and documented that a deployment reaching it "should be treated as
//! degraded". Nothing told anyone it had happened, and the failure it was most
//! likely to be triggered by is the process running out of file descriptors
//! (every call opened the device afresh), which is what a flooded server
//! experiences, at exactly the moment predictable IDs do the most harm. A
//! guarantee that silently stops holding under load is not a guarantee.
//!
//! So now:
//!
//! * The device is opened **once** and the handle kept for the life of the
//!   process, so running out of descriptors later cannot take the source away.
//! * [`try_random_bytes`] reports a failure as an error, for callers that can
//!   refuse the work (rejecting a call, say).
//! * [`random_bytes`] refuses to continue: it panics rather than hand out
//!   predictable values, as the standard library does when it cannot seed a hash
//!   map.

use std::fs::File;
use std::io::{self, Read};
use std::sync::OnceLock;

const SOURCE: &str = "/dev/urandom";

/// The open device, kept for the life of the process. Only a success is stored,
/// so a failed first attempt (a transient descriptor shortage) is retried.
static HANDLE: OnceLock<File> = OnceLock::new();

fn handle() -> io::Result<&'static File> {
    if let Some(f) = HANDLE.get() {
        return Ok(f);
    }
    let f = File::open(SOURCE)?;
    // If another thread won the race, its handle is kept and this one is dropped.
    Ok(HANDLE.get_or_init(|| f))
}

/// `N` bytes read in full from `source`. A source that fails or runs dry is an
/// error: never a short read padded with zeros, and never a substitute.
fn try_bytes_from<const N: usize>(mut source: impl Read) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    source.read_exact(&mut buf)?;
    Ok(buf)
}

/// `N` random bytes from the operating system's CSPRNG, or the error that
/// prevented it.
pub fn try_random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    try_bytes_from(handle()?)
}

/// Turn a failure to obtain randomness into a refusal to go on.
fn or_refuse<const N: usize>(result: io::Result<[u8; N]>) -> [u8; N] {
    result.unwrap_or_else(|e| {
        panic!("the operating system's random source ({SOURCE}) is unavailable: {e}; refusing to generate predictable values")
    })
}

/// `N` random bytes from the operating system's CSPRNG.
///
/// # Panics
///
/// If the source cannot be read. There is no weaker substitute; see the module
/// documentation. Use [`try_random_bytes`] where the work can be refused instead.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    or_refuse(try_random_bytes())
}

/// A uniformly random `u64`, e.g. an ICE tie-breaker (RFC 8445 §5.2).
pub fn random_u64() -> u64 {
    u64::from_be_bytes(random_bytes::<8>())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that always fails, as a device that cannot be read would.
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "no entropy for you"))
        }
    }

    /// A reader that supplies a fixed number of bytes and then reports end of file.
    struct Dries(usize);
    impl Read for Dries {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0);
            buf[..n].fill(0xAB);
            self.0 -= n;
            Ok(n)
        }
    }

    #[test]
    fn a_source_that_fails_is_an_error_not_a_substitute() {
        assert_eq!(try_bytes_from::<12>(Broken).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_source_that_runs_dry_is_an_error_not_a_zero_padded_success() {
        assert_eq!(try_bytes_from::<12>(Dries(5)).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(try_bytes_from::<12>(Dries(0)).is_err());
    }

    #[test]
    fn what_the_source_supplies_is_returned_verbatim_for_any_length() {
        // Not mixed, not transformed: the bytes are the device's.
        assert_eq!(try_bytes_from::<1>(Dries(1)).unwrap(), [0xAB]);
        assert_eq!(try_bytes_from::<9>(Dries(9)).unwrap(), [0xAB; 9]);
        assert_eq!(try_bytes_from::<33>(Dries(100)).unwrap(), [0xAB; 33], "extra bytes are simply left unread");
        assert_eq!(try_bytes_from::<0>(Dries(0)).unwrap(), [0u8; 0]);
    }

    #[test]
    #[should_panic(expected = "refusing to generate predictable values")]
    fn a_failure_to_obtain_randomness_stops_the_process_rather_than_continuing() {
        or_refuse::<12>(Err(io::Error::new(io::ErrorKind::NotFound, "gone")));
    }

    #[test]
    fn success_is_passed_through_untouched() {
        assert_eq!(or_refuse(Ok([1u8, 2, 3])), [1, 2, 3]);
    }
}
