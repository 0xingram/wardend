# ADR-002: Cargo Workspace + Feature Flags

**Status:** Accepted

## Context
Modular architecture required. Users should only build/install modules they need to keep
wardend lightweight. Plugin modules must be independently compilable.

## Decision
Cargo workspace with crates: `wardend-core`, `wardend-cli`, `wardend-proto`, `wardend-plugin-*`.
Each plugin module gated behind a cargo feature flag. Packagers and users can select the feature
set at build time.

## Consequences
Changes to one plugin crate don't recompile the core. Clean dependency boundaries. Community
plugins live in separate crates within the workspace. See ADR-011 for how feature flags compose
with the subprocess model (flag = whether the binary is built; subprocess = how it's invoked).
