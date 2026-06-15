<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# wardend

**Is my computer safe?** — answered for desktop Linux, in plain English.

`wardend` is a modular, GPL v3, Rust security tool for desktop Linux. It runs an on-demand
**health scan** across pluggable security **modules** and reports back with a traffic-light
summary (PASS / WARN / FAIL) any user can understand — with `--verbose` for the full technical
detail and `--json` for scripting.

It's built for non-technical users migrating from Windows who are used to something like Windows
Security Center, while staying extensible enough for power users and community contributors. It
was started in the wake of the **Atomic Arch** AUR supply-chain attack (June 2026); catching that
class of attack *before install* is the flagship use case.

> **Status: early development.** The architecture is resolved and documented; implementation is
> proceeding slice by slice. Not yet ready for use.

## How it works

- An unprivileged CLI (`wardend`) renders results; a privileged engine (`wardend-core`), elevated
  per-invocation via polkit, runs the scan. There is no resident daemon in the current scope.
- Each scan **module** is realized by a **plugin** — a subprocess speaking a small, versioned
  JSON protocol over stdin/stdout, so plugins can be written in any language.
- Threat-intel feeds are pulled locally and updated on a systemd timer; outbound lookups send
  **hashes only**, never file contents. `--offline` disables all network activity.

## Documentation

- [CLAUDE.md](CLAUDE.md) — architecture, glossary, conventions (the canonical project context)
- [GLOSSARY.md](GLOSSARY.md) — project vocabulary
- [docs/adr/](docs/adr/) — Architecture Decision Records
- [docs/BUILD-PLAN.md](docs/BUILD-PLAN.md) — the slice-by-slice build plan

## Licence

[GPL-3.0-or-later](LICENSE).
