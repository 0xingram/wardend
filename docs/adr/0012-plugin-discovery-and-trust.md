# ADR-012: Plugin Discovery & Trust — Root-Owned Dir, `--describe`, Signing Deferred

**Status:** Accepted

## Context
Core must find plugins, learn their capabilities and required privileges, negotiate protocol
version, and decide whether to trust them. ADR-004 says core "only loads signed plugins," but
first-party binaries can't be cryptographically signed during dev without grinding development to
a halt, and third-party plugins (PR-gated) don't exist until post-MVP.

## Decision
**Discovery:** core finds plugins in the root-owned directory `/usr/lib/wardend/plugins/`, with a
dev override via the `WARDEND_PLUGIN_DIR` environment variable (pointing at `target/`).

**Self-description:** plugins are self-describing. Core invokes each with `--describe`; the plugin
emits a `Manifest` JSON — `{ name, proto_version, required_capabilities, summary, signature? }`.
The binary is the source of truth for its own metadata; there is no sidecar manifest file to
drift out of sync. Core refuses a plugin whose `proto_version` it does not support.

**Trust (MVP):** the trust anchor is **filesystem ownership** — plugins live in a root-owned,
package-manager-managed directory only the package manager writes to. Cryptographic signature
*verification* (ADR-004's end state) is **designed for but deferred** to the phase where the
external plugin ecosystem opens. The `signature` field is reserved in the Manifest wire format
now so it can be populated later without a breaking change.

## Consequences
- Frictionless dev: no signing step in the inner loop.
- An honest security story for the MVP: a root-owned directory is a real boundary.
- No dead crypto code shipped that we can't yet exercise.
- The protocol-version handshake has a home from day one.
