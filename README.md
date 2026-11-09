# routing-core

[![CI](https://github.com/PhillipWanjiru/routing-core/actions/workflows/ci.yml/badge.svg)](https://github.com/PhillipWanjiru/routing-core/actions/workflows/ci.yml)

A multi-protocol telecom routing core built from the RFCs up — no Asterisk, no
Twilio. SIP signalling, RTP/SRTP media and NAT traversal (STUN, TURN, ICE) are
implemented directly in Rust, and each protocol adapter is designed to run as
an independent, supervised OS process so that one failing adapter cannot take
the others down.

## What is distinctive

- **Protocol logic is sans-IO.** The ICE agent and the TURN server own no
  sockets and read no clock: every call takes `now` and returns the actions to
  perform. Timers and NAT behaviour are therefore tested exactly, on a virtual
  clock, with two agents negotiating through simulated NATs in memory.
- **Correctness is checked against independent sources, then attacked.**
  Wire formats are compared byte-for-byte with messages built by a separate
  implementation, and security rules are *mutation-tested*: break the rule on
  purpose, and the test written for it must fail. See
  [docs/VERIFICATION.md](docs/VERIFICATION.md).
- **Honest about gaps.** Constants recalled from memory are flagged in the
  source, and the limits of the verification are written down.

## Status

| Area | State |
|---|---|
| Core: IPC framing, link-state routing (Dijkstra, Yen), Erlang B/C capacity maths | Implemented |
| SIP: parser, SDP, transactions, registrar, UDP user-agent server | Implemented. Dialog, proxy and B2BUA are present but not yet tested |
| Media: RTP, adaptive jitter buffer, G.711, SRTP with SDES, MOS (E-model) | Implemented (G.711 only; Opus and G.722 planned) |
| STUN: message codec, Binding server | Implemented |
| TURN server: authentication, allocation, permissions, ChannelBind, relay | Implemented: a sans-IO core and a UDP driver with one relay socket per allocation |
| TURN client | Implemented (sans-IO); signed-response verification, refresh, permissions, channels |
| ICE: gathering, pairing, checks, triggered checks, role conflicts, nomination, real-socket driver | Implemented |
| ICE over TURN: relayed candidates, permission management, routing agent traffic through an allocation | Implemented (sans-IO); proven in simulation, including two symmetric NATs; not yet in the real-socket driver |
| QoS (DSCP, admission control), dynamic firewall, XDP flood mitigation, fraud detection | Planned |
| CDR pipeline, WebRTC gateway, dashboard | Planned |

Two agents behind two **symmetric** NATs cannot connect directly — the test
suite asserts this. Through a TURN relay they do: an end-to-end test runs two
real ICE agents, two real TURN clients and a real TURN server over simulated
symmetric NATs, in virtual time, and checks that media flows both ways.

## Repository layout

| Path | Contents |
|---|---|
| `core/` | IPC framing, routing engine, capacity maths, tracing |
| `modules/voip-sip/` | SIP stack, RTP/SRTP media plane, call-quality scoring |
| `modules/nat-traversal/` | STUN, TURN, ICE |
| `docs/` | [Architecture](docs/ARCHITECTURE.md) and [verification](docs/VERIFICATION.md) |

## Build and test

Rust 1.75 (stable) on Linux.

```bash
cargo build --workspace
cargo test --workspace
```

The tree builds without warnings, and CI enforces it (`-D warnings`). A few
tests open real UDP sockets on loopback and use the wall clock; everything else
runs on a virtual clock.

## Known gaps

- Coverage-guided fuzzing has not been run (it needs a nightly toolchain); the
  parsers are exercised by a randomised smoke-fuzz harness instead.
- The IPC bus has not yet been exercised between two live processes.
- Interoperability with third-party SIP/ICE/TURN stacks is untested: the
  oracle used to check wire formats is this project's own reading of the RFCs,
  not the RFCs' published vectors.
- NAT behaviour is modelled (address-restricted cone and symmetric), not
  measured on real devices.
- The TURN server runs over real sockets, but ICE over TURN is proven in
  simulation only, and nothing has run against a third-party TURN server or
  client.

## Roadmap

1. Relayed candidates in the real-socket ICE driver, so the relay path runs over
   real sockets rather than only in simulation.
2. QoS: DSCP marking, Erlang-B admission control, dynamic firewall rules.
3. Flood mitigation and fraud detection.
4. Observability, CDR pipeline and a WebRTC gateway.

## Development

Developed collaboratively with an AI assistant (Claude, by Anthropic). Every
change is held to the verification standard above — an automated test suite
plus deliberate rule-breaking — rather than to review by eye. Contribution and
commit conventions are in [CONTRIBUTING.md](CONTRIBUTING.md); history by
version is in [CHANGELOG.md](CHANGELOG.md).

The history up to v0.5.0 was reconstructed from milestone snapshots taken while
the project was built: one commit per milestone, dated from when that snapshot
was created (June to October 2026), and each tagged release builds and passes
its recorded test count. From there on, changes are committed as they are made.

## License

No license has been chosen yet; until one is added, all rights are reserved.
