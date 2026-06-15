# ADR-011: First-Party Modules Dogfood the Subprocess Protocol

**Status:** Accepted

## Context
ADR-002 (feature-flagged crates per module) reads as in-process; ADR-003 (subprocess JSON
protocol) is out-of-process. Both cannot be the default execution path for the same code without
a decision. The temptation is to run first-party modules in-process (fast, simple) and reserve
the subprocess protocol for third-party plugins only.

## Decision
First-party modules **dogfood the subprocess protocol**. Each is a separate binary
(`wardend-plugin-*`), spawned by core exactly as a community plugin would be — JSON over
stdin/stdout. There is **no in-process fast path** for first-party modules.

## Consequences
- The plugin boundary — which *is* the security model (ADR-004) — sits on the path we exercise
  daily. There is no second, divergent path that rots from disuse.
- Building `setuid-audit` (Slice 1) proves the protocol end-to-end before the hard modules exist.
- Per-module subprocesses can drop to minimal privileges (a benefit in-process can't give).
- Feature flags and subprocess **compose**: the flag controls *whether a plugin binary is built*;
  subprocess is *how it's invoked*.
- Cost: subprocess spawn overhead per scan — negligible for on-demand use.
