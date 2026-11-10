# Contributing

## Workflow

1. Branch from `main`: `feat/<topic>`, `fix/<topic>` or `docs/<topic>`.
2. Make the change **with its tests in the same commit**.
3. `cargo test --workspace` must pass and the build must stay warning-free
   (CI runs with `-D warnings`).
4. Open a pull request; CI must be green before merging.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, imperative, no trailing full stop, 72 characters or
fewer. Types used here: `feat`, `fix`, `test`, `docs`, `ci`, `chore`,
`refactor`. Scopes follow the code: `core`, `routing`, `sip`, `media`,
`srtp`, `stun`, `turn`, `ice`.

The body explains **why** — the constraint, the trap avoided, the decision and
what it costs — not a restatement of the diff. State how the change was
verified, and any known gap it leaves.

## Testing standards

- **Protocol bytes are checked against an independent source**: a published
  vector, or a message built by a separate implementation. A test that only
  compares the code with itself proves agreement, not correctness.
- **Security rules need a test that can fail.** After writing the test, break
  the rule on purpose and confirm the test goes red. Several tests in this
  repository passed vacuously the first time; this is how they were found.
  See [docs/VERIFICATION.md](docs/VERIFICATION.md).
- **State machines are tested on a virtual clock.** Time and I/O are passed in,
  never read, so tests are exact and never sleep.
- Cite the RFC section for protocol rules, and flag any constant recalled from
  memory rather than checked against the text.

## Unsafe code

`unsafe` is denied across the `nat-traversal` crate (`#![deny(unsafe_code)]`). The one
exception is the `getifaddrs` wrapper in `ice/interfaces.rs`, which opts back in for that
single function. A test fails if any other file uses `unsafe` or turns the lint off, because
the compiler alone would not stop the second. If you need `unsafe` elsewhere, raise it
first: the answer is almost always a different design. Where it is justified, keep it to the
smallest function that can hold it, write a `# Safety` section stating exactly what the
caller must guarantee, put a `SAFETY:` comment on every block saying why it holds, and test
it with inputs built by hand, since the real operating system only ever hands back
well-formed data.

## Changelog

User-visible changes go under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
