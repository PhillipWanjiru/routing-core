# voip-sip

Rust. Internet-facing SIP parsing and RTP media handling.

The SIP parser (src/sip/parser.rs) is the historically most-attacked surface
in any SIP stack. Rust's nom combinators eliminate the buffer-overflow and
use-after-free CVE classes that account for the majority of published SIP
stack CVEs. Fuzz targets run continuously in CI against the live parser.

This module runs as a B2BUA (Back-to-Back User Agent). It terminates every
call leg and re-originates it, giving full control over codec negotiation,
topology hiding, recording hooks, and the firewall punch interface.
