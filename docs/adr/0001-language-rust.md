# ADR-001: Language — Rust

**Status:** Accepted

## Context
Need a lightweight, performant security daemon for desktop Linux. Tool must be native (no
sandbox) to access kernel interfaces, capabilities, and system files.

## Decision
Rust. Memory-safety properties are particularly appropriate for a security tool. Single native
binary. Strong cargo ecosystem. Existing AUR security tools trending Rust (ks-aur-scanner, Traur).

## Consequences
Slower initial build times mitigated by: cargo workspace crate splitting, feature flags (only
build needed modules), `mold` linker, `cargo-watch` for dev iteration, `CARGO_TARGET_DIR` on
tmpfs. Incremental builds after first compile are fast (5–30s).
