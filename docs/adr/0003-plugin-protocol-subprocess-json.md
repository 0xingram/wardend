# ADR-003: Plugin Protocol — Subprocess JSON stdin/stdout

**Status:** Accepted

## Context
Plugin system must be language-agnostic so the community can contribute in any language. Rust
ABI instability makes `.so` dynamic loading impractical.

## Decision
Plugins are spawned as subprocesses. Communication via JSON over stdin/stdout. Protocol defined
in `wardend-proto` (versioned serde structs). Long-running/realtime plugins will graduate to
Unix domain socket transport in a future phase when realtime protection is added.

## Consequences
Any language can implement a wardend plugin. No ABI issues. Easy to test plugins in isolation.
Slight subprocess spawn overhead, acceptable for on-demand scans. Refined by ADR-012
(`--describe` handshake, proto-version negotiation) and ADR-015 (the wire `ScanResult` carries
no status — core derives it).
