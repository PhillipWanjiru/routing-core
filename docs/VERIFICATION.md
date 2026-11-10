# Verification

A passing test suite proves little if the tests share the code's
misunderstanding. This project layers several kinds of check so that no single
one can quietly agree with a wrong implementation.

## Layers

1. **Reference vectors.** Hash and checksum primitives are checked against
   published values: MD5, SHA-1, HMAC-SHA1 (RFC 2202 case 1) and the standard
   CRC-32 check value.
2. **An independent oracle.** Messages are built by a separate Python
   implementation (`hmac`, `hashlib`, `zlib`) from the RFC's construction
   rules, and the oracle re-parses its own output to confirm the HMAC and CRC
   before writing a fixture. Fixtures are *generated*, never hand-copied. The
   Rust builders must reproduce them byte-for-byte and the validators must
   accept them. This is how the MESSAGE-INTEGRITY "adjusted length" trap — the
   most common STUN/TURN interoperability bug — was checked in both the build
   and verify directions. The SDP codec got a stricter form of this: a separate
   Python implementation of the RFC 8839 grammar was run against about 25,000
   generated lines (valid, unsupported, malformed and byte-mutated) and 4,000
   encoder specs with no disagreement, and its verdicts on 76 decode cases and
   27 encode cases are embedded as fixtures. One limit worth knowing: for its
   whitespace rule the oracle was at first aligned with Rust's own `trim`, so it
   could not have caught the decision that Unicode line separators count as
   padding. A hand-written test did, and the oracle now states the intended
   ASCII-only policy independently.
3. **Exhaustive properties.** Every single-bit flip is detected by CRC-32 and by
   the HMAC, over every bit of every byte of a message; every role and
   tie-breaker combination ends with exactly one controlling agent.
4. **Virtual-time simulation.** State machines run on an explicit clock. Two
   agents negotiate through an in-memory network with injectable loss, latency
   and NAT models (address-restricted cone and symmetric), including the
   *negative* case: two symmetric NATs must fail, and the agents must conclude
   so rather than hang.
5. **Real sockets.** The same state machine is driven over UDP on loopback with
   the wall clock, and the TURN server and the relay path run over real UDP
   against each other. Each real-socket suite was run 25 times in a row to look
   for timing flakiness; none.
6. **Mutation testing.** For each security- or timing-critical rule, the rule is
   broken on purpose and the test written for it must fail.
7. **Smoke fuzzing.** Parsers are fed randomised and mutated inputs and must
   never panic.

## Mutation results

| Area | Rules broken | Caught by their intended test |
|---|---|---|
| ICE connectivity-check agent, initiator | 8 | 8 |
| ICE responder, triggered checks, role conflicts | 15 | 15 |
| ICE nomination and completion | 14 | 14 |
| TURN server core | 16 | 16 |
| TURN client | 12 | 12 |
| ICE over TURN: bridge rules and relayed priority | 8 | 8 |
| TURN server UDP driver | 7 | 7 |
| Relay-aware ICE driver and `TurnRelay` | 8 | 8 |
| SDP codec (`ice::sdp`) | 17 | 17 |

Each count is *after* the test fixes described below; the first pass found
weak tests in three of the four areas.

## What mutation testing caught

Tests that could not fail, found because breaking the rule left them green:

- A NAT test named "through triggered checks" still passed with triggered
  checks disabled, because ordinary retransmission eventually connected. Fixed
  with a timing bound only a triggered check can meet.
- "Expiry clears permissions" passed vacuously: a 300 s permission is already
  dead when a 600 s allocation expires. Rewritten to refresh the permission
  late, so only the sweep can remove it.
- "A controlled agent never nominates" missed a controlled agent nominating
  itself, because the message builder strips USE-CANDIDATE for that role and
  the mutant sent a plain-looking check. The assertion became "sends nothing".
- A guard preventing a completed agent from learning new candidates had no test
  at all.

A harness artifact is recorded too: one "missed" mutation was only cargo
stopping at the first failing test binary; `--no-fail-fast` showed the intended
test did fail.

Reading code, not only testing it, found five defects in the TURN relay that
its tests had been written around: the relayed address advertised the client's
IP; handlers read the system clock; peer data reached the client with no
indication of which peer sent it; deallocation left permissions behind; and a
Refresh for an unknown allocation got silence rather than 437. One existing test
had enshrined the missing Data indication as expected behaviour.

Reading the ICE candidate documentation found a further error before any relay
code was written: it gave a relayed candidate the local socket as its base, which
would have sent its checks around the relay and pruned the relayed pair as a
duplicate of the host pair. A regression test reproduces the pruning.

Writing the SDP encoder found another: the foundations the ICE layer computes
(`Host-192.168.1.10`, and for IPv6 up to 55 characters) are not valid SDP, which
allows only letters, digits, `+` and `/`, at most 32. Encoding them as they stood
would have produced descriptions a browser rejects.

## What is not verified

- **Interoperability.** The oracle is this project's own reading of the RFCs,
  not an independent stack. Testing against a third-party ICE/TURN/SIP
  implementation is still to do.
- **Real NATs.** The models are simplifications.
- **Coverage-guided fuzzing**, which needs a nightly toolchain.
- **Recalled constants.** Attribute and error-code numbers recalled from memory
  rather than checked against the RFC text are flagged where they are defined.
