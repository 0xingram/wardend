# wardend — Glossary

Canonical project vocabulary. These terms are load-bearing and must be used precisely across
code, docs, output, and agent sessions. If you find a term used loosely, fix it. The short
form of this glossary is mirrored in [CLAUDE.md](CLAUDE.md); this is the authoritative copy.

## Core concepts

### Module
A **security capability** — a unit of *what gets checked*. User-facing noun; this is what
appears in scan output, `--help`, and user docs. A non-technical user meets *modules*, never
*plugins*.
> "The cve-check module flagged 3 packages."

MVP modules: `setuid-audit`, `pkgbuild-audit`, `cve-check`, `file-hash-check`, `rkhunter-wrapper`.

### Plugin
The **implementation mechanism** behind a module: a subprocess binary that speaks the JSON
protocol over stdin/stdout. Contributor-facing noun; this is what the protocol, discovery, and
signing decisions (ADR-003/004) talk about.

A module is realized **by** a plugin. In the MVP the relationship is 1:1 (one binary per
module). The distinction is kept deliberately so that later we can have a plugin that provides
multiple modules, or a module backed differently, without renaming everything.

### Scan
One invocation of `wardend scan`. A scan fans out to N enabled modules and produces N
`ScanResult`s, which core aggregates into a single report.

### Finding
A single discrete issue within a `ScanResult`. Carries `severity`, `title` (plain English),
`detail` (technical, shown only with `--verbose`), and `remediation` (plain-English action).

### Status
A **module's verdict**: `pass` | `warn` | `fail` | `error`. Module-level axis.
**Core derives status** from the severities of a result's findings (see the ladder in
CLAUDE.md / ADR-015). Plugins do **not** assert their own status — the wire `ScanResult` has
no `status` field.

### Severity
A **finding's seriousness**: `info` | `low` | `medium` | `high` | `critical`. Finding-level axis.

> **Status ≠ Severity.** Different layers (module vs finding), different axes. Do not conflate.

## Components

### Core (`wardend-core`)
The **privileged scan engine**. Runs under polkit elevation, discovers and spawns plugins,
sends `ScanRequest`s, collects `ScanResult`s, derives statuses, aggregates, manages feeds,
emits the aggregated JSON. **Not** "the daemon" — there is no resident daemon in the MVP.

### CLI (`wardend`)
The **unprivileged client**. Parses arguments, invokes core under polkit, renders the returned
JSON as traffic-light / verbose / json output. Holds no privileges; does the human-facing work.

### Proto (`wardend-proto`)
The shared, versioned **JSON protocol contract**: `ScanRequest`, `ScanResult`, `Finding`,
`Manifest`, and the `Status`/`Severity` enums. Pure serde, zero async — so a community plugin
in any language can mirror it from the struct definitions alone.

### Daemon
The future resident process for the **realtime** phase (continuous monitoring over Unix-socket
IPC). **Does not exist in the MVP.** When you see "daemon" in older docs describing MVP
behaviour, read it as *core*.

## Data & infrastructure

### Manifest
A plugin's self-description, emitted when core invokes it with `--describe`:
`{ name, proto_version, required_capabilities, summary, signature? }`. The binary is the source
of truth for its own metadata — there is no sidecar manifest file to drift out of sync.

### Feed
Locally-cached threat-intel data (ClamAV CVD, NVD CVE JSON, YARA rules, abuse.ch sets, …)
stored under `/var/lib/wardend/feeds/`. Pulled locally; updated by a systemd timer (daily).
Outbound lookups send **hashes only**, never file contents.

### Plugin directory
`/usr/lib/wardend/plugins/` — the root-owned, package-manager-managed directory core discovers
plugins in. Filesystem ownership is the MVP trust anchor. Dev override: `WARDEND_PLUGIN_DIR`.

## Naming & identifiers

### `dev.wardend.*`
The project's reverse-DNS namespace (project owns `wardend.dev`). Used for the polkit action
(`dev.wardend.scan`), and future AppStream / D-Bus identifiers. Never a personal namespace.

## Output vocabulary (user-facing)

- **PASS / WARN / FAIL / ERROR** — the rendered traffic-light form of a module's `Status`.
- **Narrative** — the single plain-English summary line at the bottom of a report
  ("Your system looks healthy." / "2 issues need your attention.").
- **`--verbose`** — expands each finding with its `detail` and `remediation`.
- **`--json`** — emits the raw aggregated `Vec<ScanResult>`-with-derived-status for scripting.
- **`--offline`** — disables all network activity; cached feeds only.
