# ADR-013: Async Runtime — Tokio in Core, Proto Pure-Serde

**Status:** Accepted

## Context
Core must spawn N plugin subprocesses concurrently, feed each a `ScanRequest` on stdin, collect
a `ScanResult` from stdout with per-plugin timeouts, and (for feed-using modules) perform HTTP
fetches. Concurrent subprocess management with timeouts and cancellation is the textbook case
where `std::process` + manual thread juggling becomes unwieldy.

## Decision
Use **tokio**, confined to `wardend-core`. Its `process`, `time::timeout`, and `JoinSet` make
the runner small and the timeout/cancellation logic clean. Later feed fetching uses an async HTTP
client (`reqwest`).

Discipline:
- `wardend-proto` stays **pure serde with zero async dependencies** — it is the contract a
  community plugin in any language must be able to mirror from the struct definitions alone.
- `wardend-cli` is **synchronous** — it shells out to the privileged core and renders JSON.
- Plugins themselves may be sync or async; the protocol is line-oriented JSON, runtime-agnostic.

## Consequences
- Clean, ~40-line runner instead of a hand-rolled thread/timeout scheme.
- Same runtime the future realtime phase will need — no later migration.
- The contract crate stays dependency-light and language-portable.
