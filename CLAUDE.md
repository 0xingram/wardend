# CLAUDE.md — wardend

> Canonical, session-agnostic context for any agent working on `wardend`.
> Read this first, every session. If a fact here conflicts with your memory or
> an old summary, **this file wins**. Keep it current.

## What wardend is

`wardend` is a **modular, GPL v3, Rust, desktop-first Linux security tool**. It answers
one question for a non-technical Linux user — *"is my computer safe?"* — while staying
extensible enough for power users and community contributors.

It runs an **on-demand health scan** (`wardend scan`) that fans out across pluggable
security **modules** and renders a **traffic-light + plain-English** report (PASS / WARN /
FAIL), with `--verbose` for technical detail and `--json` for scripting.

Origin & motivation: built on CachyOS/Arch in the wake of the **Atomic Arch** AUR supply
chain attack (June 2026). Catching attacks like that *before install* is the flagship use case.

## Canonical glossary (do not drift)

These terms are load-bearing. Use them precisely. Full definitions in [GLOSSARY.md](GLOSSARY.md).

- **Module** — a *security capability* / unit of "what gets checked". User-facing.
  ("The cve-check module flagged 3 packages.")
- **Plugin** — the *implementation mechanism*: a subprocess binary speaking the JSON
  protocol. Contributor-facing. A module is realized **by** a plugin. (MVP: 1 plugin = 1 module.)
- **Scan** — one `wardend scan` invocation; fans out to N modules → N `ScanResult`s.
- **Finding** — a single issue inside a `ScanResult` (severity/title/detail/remediation).
- **Status** — a module's verdict: `pass`/`warn`/`fail`/`error`. **Core-derived, not plugin-asserted.**
- **Severity** — a finding's seriousness: `info`/`low`/`medium`/`high`/`critical`.
  *Status ≠ severity — different axes, different layers.*
- **Core** — the privileged scan engine (`wardend-core`). **Not** "the daemon" — there is no
  resident daemon in the MVP.
- **Feed** — locally-cached threat intel (ClamAV CVD, NVD JSON, …) under `/var/lib/wardend/feeds/`.
- **Manifest** — a plugin's self-description, emitted on `--describe`.

## Architecture (MVP)

**On-demand, no resident daemon.** Despite the `-d` name (a destination, not a current state),
nothing in Phase 1 needs a 24/7 process. A long-lived privileged daemon is pure attack
surface with no MVP payoff — that contradicts wardend's own mission. The resident daemon +
Unix-socket IPC graduate in the future **realtime** phase.

**Two binaries, polkit between them:**

- `wardend` — **unprivileged CLI**. Parses args, renders output. Installs to `/usr/bin/`.
- `wardend-core` — **privileged scan engine**. Installs to `/usr/lib/wardend/` (not on `$PATH`).
- `wardend scan` invokes `pkexec /usr/lib/wardend/wardend-core scan …` against the polkit
  action **`dev.wardend.scan`**. Core runs the scan, spawns plugin subprocesses, emits
  `Vec<ScanResult>` JSON on stdout. CLI captures and renders it.
- ADR-005 split holds: **core speaks JSON, CLI renders.**

**Plugins are subprocesses (first-party included).** First-party modules **dogfood** the same
JSON-over-stdin/stdout protocol a community plugin uses — they are separate binaries, not
in-process. This keeps the plugin boundary (the security model, ADR-004) on the path we test
daily. No divergent in-process fast path.

**Plugin lifecycle:**
1. Core discovers plugins in `/usr/lib/wardend/plugins/` (dev override: `WARDEND_PLUGIN_DIR`).
2. Core invokes each with `--describe` → plugin emits a **Manifest** JSON
   (`{ name, proto_version, required_capabilities, summary, signature? }`).
3. Core checks `proto_version` compatibility; incompatible plugins are refused.
4. Core sends a `ScanRequest` on the plugin's stdin; plugin emits a `ScanResult` on stdout.
5. Core **derives** the module `Status` from finding severities (ladder below) and aggregates.

**Trust (MVP):** the anchor is **filesystem ownership** — plugins live in a root-owned,
package-manager-managed dir. Cryptographic signing (ADR-004's end state) is *designed for but
deferred* to when the external plugin ecosystem opens; the `signature` wire field is reserved now.

## Crates (cargo workspace)

| Crate | Role | Key deps |
|---|---|---|
| `wardend-proto` | Shared JSON protocol types (the contract). **Pure serde, zero async.** | serde |
| `wardend-core` | Privileged engine: discovery, plugin runner, status derivation, aggregation, feeds | tokio, reqwest (later) |
| `wardend-cli` | Unprivileged CLI: arg parsing, output rendering (traffic-light/verbose/json). **Sync.** | clap |
| `wardend-plugin-*` | One crate per module, **feature-flag-gated**, separate binary | (per module) |

Feature flags gate *whether a plugin binary is built*; subprocess is *how it's invoked* — the
two ideas compose. Packagers build only the modules they want.

## Severity → Status ladder (core-derived)

Core computes a module's `Status` from the **highest-severity finding** in its `ScanResult`.
Plugins emit findings only — **the wire `ScanResult` has no `status` field.**

| Highest severity present | Status |
|---|---|
| `critical` or `high` | `FAIL` |
| `medium` | `WARN` |
| `low` / `info` only | `PASS` (with notes) |
| none | `PASS` |
| crash / timeout / bad protocol | `ERROR` |

**Overall narrative** (bottom of report), from module-status counts:
- any `FAIL` → "X issues need your attention." (red)
- else any `WARN` → "X things worth a look." (amber)
- else all `PASS` → "Your system looks healthy." (green)
- `ERROR` is always called out separately — a broken module must never masquerade as PASS.

## Wire protocol (lives in `wardend-proto`, versioned)

```jsonc
// ScanRequest  (core → plugin stdin)
{ "scan_id": "uuid", "module": "name", "config": { /* module-specific */ }, "offline": false }

// ScanResult   (plugin → core stdout)   — NOTE: no top-level status; core derives it
{ "scan_id": "uuid", "module": "name",
  "summary": "Plain English one-liner",
  "findings": [ { "severity": "high", "title": "…", "detail": "…", "remediation": "…" } ],
  "metadata": { /* module-specific */ } }

// Manifest     (plugin --describe → stdout)
{ "name": "setuid-audit", "proto_version": 1,
  "required_capabilities": [], "summary": "…", "signature": null }
```

`Status = pass | warn | fail | error` · `Severity = info | low | medium | high | critical`

## Threat intel (ADR-008)

Local pull only; **hash-only outbound** (SHA256, never file contents or system inventory).
`--offline` disables all network. Sources: ClamAV CVD, YARA (Florian Roth signature-base),
NVD CVE JSON, abuse.ch (URLhaus/MalwareBazaar/ThreatFox), AlienVault OTX, AUR RPC.
Feeds under `/var/lib/wardend/feeds/`, updated by a **systemd timer** (daily). The tool itself
updates **only via the distro package manager** — self-update is prohibited (ADR-007).

## Conventions

- **Edition 2024.** MSRV pinned via `rust-toolchain.toml` (reproducible across sessions).
- **SPDX header on every source file:** `// SPDX-License-Identifier: GPL-3.0-or-later`
  (`-or-later` keeps the AGPL/SaaS door openable — ADR-009).
- **Workspace lints:** `unsafe_code = "forbid"` in `proto`/`cli`; `"deny"`-with-justification
  only inside plugin crates that genuinely need it (eBPF/ptrace, later). clippy pedantic on.
- **`mold` linker** + `CARGO_TARGET_DIR` on tmpfs are recommended for fast iteration but are a
  *commented opt-in* in `.cargo/config.toml` — never force contributors to install mold.
- **CI from commit one:** `fmt --check`, `clippy -D warnings`, `test` on every PR.
- **TDD** for `wardend-proto` types and every module (red-green-refactor). Tests assert
  **external behaviour** (JSON in → JSON out, PASS/FAIL classification), not internal structure.
- **Reverse-DNS namespace: `dev.wardend.*`** (project owns `wardend.dev`). Never a personal
  namespace. Used for polkit actions, future AppStream/D-Bus IDs, installed paths.

## Common commands

```bash
cargo build --workspace                 # build everything
cargo test  --workspace                 # run all tests
cargo clippy --workspace -- -D warnings # lint as CI does
cargo fmt --all -- --check              # format check as CI does
# Dev: run a plugin against the runner without root, pointing at target/:
WARDEND_PLUGIN_DIR=target/debug cargo run -p wardend-cli -- scan
```

## Where things live

- [GLOSSARY.md](GLOSSARY.md) — canonical terms (extends the glossary above).
- [docs/BUILD-PLAN.md](docs/BUILD-PLAN.md) — the slice-by-slice build plan + acceptance criteria.
- [docs/adr/](docs/adr/) — Architecture Decision Records (one file per decision). Read the
  index at [docs/adr/README.md](docs/adr/README.md).
- Out of scope (do not build): GUI, realtime/continuous monitoring, network IDS, AI-analysis
  module, Unix-socket plugin transport, `.deb`/`.rpm` (after AUR), self-update. See PRD §Out of Scope.

## Session & contribution workflow

Every working session follows this loop — it is mandatory, not optional:

1. **Branch** off `main` (never commit a slice directly to `main`).
2. Implement **one slice** from [docs/BUILD-PLAN.md](docs/BUILD-PLAN.md), TDD where the plan says so.
3. **Open a PR** so CI runs (`fmt --check`, `clippy -D warnings`, `test`).
4. **Drive CI to green** — watch the run, fix failures, do not hand off or call a slice done
   until CI passes on the PR. A red PR is an unfinished slice.
5. Update the slice's status in BUILD-PLAN.md and any affected ADR/CLAUDE.md/memory **in the
   same PR**, so the next cold session inherits an accurate map.

## Working agreement

- Marcus has IT-support / enterprise-software background, daily CachyOS/KDE user, strong
  Linux/terminal familiarity — **do not over-explain Linux concepts.**
- This project is **session-agnostic by design.** When you make or change a load-bearing
  decision, update the relevant ADR + this file + memory in the same turn, so the next cold
  session stays aligned.
