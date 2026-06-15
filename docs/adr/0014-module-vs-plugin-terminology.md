# ADR-014: Terminology — Module (Capability) vs Plugin (Mechanism)

**Status:** Accepted

## Context
The design docs use "module" and "plugin" interchangeably. For a session-agnostic project where
many cold agent sessions and community contributors must stay aligned, ambiguous core vocabulary
causes drift across code, docs, and output.

## Decision
"Module" and "plugin" are **not synonyms**; they name different layers.

- **Module** — a *security capability* / unit of "what gets checked". User-facing. Appears in
  output, `--help`, and user docs. ("The cve-check module flagged 3 packages.")
- **Plugin** — the *implementation mechanism*: a subprocess binary speaking the JSON protocol.
  Contributor-facing. This is what ADR-003/004 (protocol, signing) refer to.

A module is realized **by** a plugin. In the MVP the relationship is 1:1, but the distinction is
preserved so a plugin could later provide multiple modules without renaming everything.

The full canonical vocabulary lives in [GLOSSARY.md](../../GLOSSARY.md) (status vs severity,
core vs daemon, scan, finding, feed, manifest, the `dev.wardend.*` namespace).

## Consequences
- Output and user docs speak of *modules*; protocol and contributor docs speak of *plugins*.
- The glossary is authoritative; loose usage is treated as a bug to fix.
