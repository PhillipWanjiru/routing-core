# Security policy

This project implements network protocols (SIP, STUN, TURN, ICE) that parse
attacker-controlled input, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's
private reporting instead: the **Security** tab, then **Report a vulnerability**.

Useful details: the affected module and commit, a minimal reproducing input
(a hex dump of the datagram is ideal), and the behaviour you expected.

## Scope

In scope: memory-safety or panic-on-input bugs in any parser, authentication
or integrity bypasses, and the relay barrier (anything that lets traffic cross a
TURN relay without an allocation and a matching permission).

## Known gaps

Coverage-guided fuzzing has not yet been run (it needs a nightly toolchain);
parsers are currently exercised by a randomised smoke-fuzz harness instead.
See [docs/VERIFICATION.md](docs/VERIFICATION.md).
