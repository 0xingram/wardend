# ADR-004: Plugin Curation — PR-gated, Signed

**Status:** Accepted

## Context
wardend plugins run with elevated system privileges. An uncurated plugin ecosystem is itself an
attack surface — directly contradicting wardend's security mission.

## Decision
All community plugin modules are submitted as PRs to the wardend repository. Maintainer review
required before merge. Merged plugins are cryptographically signed by maintainers. The wardend
core only loads signed plugins.

## Consequences
Slower plugin-ecosystem growth vs. an open marketplace, but the trust model is sound. Community
contributes via PRs; maintainers are the trust anchor.

**MVP refinement (see ADR-012):** until the external plugin ecosystem opens, the trust anchor is
**filesystem ownership** — first-party plugins live in a root-owned, package-manager-managed
directory. Cryptographic signature *verification* is designed for but deferred to the phase where
third-party plugins are actually accepted; the `signature` wire field is reserved in the Manifest now.
