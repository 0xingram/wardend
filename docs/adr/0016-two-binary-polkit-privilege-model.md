# ADR-016: Two-Binary + Polkit Privilege Model; `dev.wardend.*` Namespace

**Status:** Accepted

## Context
Given ADR-010 (on-demand, no resident daemon) and ADR-005 (core speaks JSON, CLI renders), an
unprivileged `wardend scan` must become a privileged scan without a long-held capability set and
without running the whole CLI as root.

## Decision
**Two binaries, polkit between them:**

- `wardend` — the **unprivileged CLI**. Parses args, renders output. Installs to `/usr/bin/`.
- `wardend-core` — the **privileged scan engine**. Installs to `/usr/lib/wardend/` (not on
  `$PATH`; not meant to be run directly by users).
- `wardend scan` invokes `pkexec /usr/lib/wardend/wardend-core scan …` against the packaged
  polkit action **`dev.wardend.scan`**. Core runs the scan, spawns plugin subprocesses (which can
  drop privileges per-module), and emits `Vec<ScanResult>`-with-derived-status JSON on stdout.
  The CLI captures that JSON and renders it. This preserves the ADR-005 split.
- Flags: `--verbose`/`--json` are CLI-only (rendering); `--offline` is forwarded into the
  elevated call and into each `ScanRequest`.

**Config:** TOML at `/etc/wardend/config.toml` — top-level keys (enabled modules, plugin dir,
feed dir, timeouts) plus `[modules.<name>]` sections passed through as the `config` object of
that module's `ScanRequest`. Core reads config (it is the privileged side that needs the paths);
the CLI stays config-light.

**Namespace:** all reverse-DNS identifiers use **`dev.wardend.*`** (the project owns
`wardend.dev`) — polkit action, future AppStream / D-Bus IDs, installed paths. Never a personal
namespace: a personal identifier is a liability once the project gains co-maintainers or transfers.

## Consequences
- No privileged process between scans; elevation is per-invocation and user-consented via polkit.
- Clean separation of concerns mirrors the crate boundaries (`wardend-cli` / `wardend-core`).
- Packaging (Slice 5) ships: `/usr/bin/wardend`, `/usr/lib/wardend/wardend-core`,
  `/usr/lib/wardend/plugins/`, the `dev.wardend.scan` polkit action, `/etc/wardend/config.toml`,
  `/var/lib/wardend/feeds/`.
