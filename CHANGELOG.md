# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/); while the major version is 0, a
minor release may change interfaces.

## [Unreleased]

### Added
- `TurnClient`: a sans-IO TURN client. Allocates through the long-term-credential
  challenge, believes only signed success responses, refreshes the allocation,
  permissions and channel bindings, and sends and receives peer data as
  indications or ChannelData.

- `ice_turn::TurnBridge`: joins an ICE agent to a TURN client. Gathers the
  relayed candidate, routes the agent's sends from it through the allocation,
  unwraps what comes back (STUN to the agent, media to the caller), and keeps
  TURN permissions in step with the peer's candidate list.
- `Candidate::relayed`.
- An end-to-end test: two symmetric NATs, which ICE alone cannot connect, now
  connect through a relay, with media flowing both ways.

### Fixed
- The `Candidate` documentation gave a relayed candidate the local socket as its
  base. A relayed candidate is its own base (RFC 8445), or its checks bypass the
  relay and its pair is pruned as a duplicate of the host pair.

### Planned
- UDP driver for the TURN server.
- Relayed candidates in the real-socket ICE driver.

## [0.5.0] - 2026-10-26

### Added
- `TurnServer`: a sans-IO TURN server core composing allocation, permissions,
  channels and relay decisions, with relay-socket open/close events.
- ChannelBind handler; DATA, CHANNEL-NUMBER and REQUESTED-TRANSPORT
  attributes; Send and Data indication builders.
- Signed TURN success responses, so a client can reject a forged one.

### Changed
- TURN handlers take `now` and the relay IP explicitly rather than reading the
  system clock and assuming the client's address.

### Fixed
- Allocate advertised the client's IP as the relayed address.
- Peer data reached the client as a bare payload; it now arrives as a Data
  indication naming the peer.
- Deallocation left permissions and channel bindings behind, so a new
  allocation from the same address inherited them.
- Refresh for an unknown allocation returned nothing instead of 437.

## [0.4.0] - 2026-10-17

### Added
- ICE agent: gathering, pairing, connectivity checks, triggered checks,
  role-conflict resolution, regular nomination and completion.
- Short-term-credential MESSAGE-INTEGRITY that tolerates a trailing
  FINGERPRINT; CRC-32 and FINGERPRINT.
- `ice::run_agent`: a driver over real UDP sockets.

## [0.3.0] - 2026-09-15

### Added
- STUN message codec and Binding server.
- TURN: long-term authentication, allocation lifecycle, permissions,
  ChannelData framing and the relay forwarding decisions.

## [0.2.0] - 2026-07-13

### Added
- Media plane: RTP, adaptive jitter buffer, G.711, SRTP with SDES key exchange,
  E-model call-quality scoring.
- SIP user-agent server and a loopback call flow.

## [0.1.0] - 2026-06-30

### Added
- Workspace, IPC framing, Erlang B/C capacity maths, link-state routing with
  Dijkstra and Yen's k-shortest paths.
- SIP and SDP parsers, transaction state machines, registrar.

[Unreleased]: https://github.com/PhillipWanjiru/routing-core/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/PhillipWanjiru/routing-core/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/PhillipWanjiru/routing-core/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/PhillipWanjiru/routing-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/PhillipWanjiru/routing-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PhillipWanjiru/routing-core/releases/tag/v0.1.0
