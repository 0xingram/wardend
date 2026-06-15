# ADR-008: Threat Intel — Local Pull Only, Hash-Only Outbound

**Status:** Accepted

## Context
Privacy-conscious Linux desktop users are a core audience. Sending file contents or system
inventory to external services would be a hard blocker for adoption.

## Decision
- All feeds pulled to the local machine; no system data sent outbound.
- Remote lookups (MalwareBazaar, OTX) send only SHA256 hashes, never file contents.
- `--offline` disables all network activity entirely.
- Sources: ClamAV CVD, YARA (Florian Roth signature-base), NVD CVE JSON, abuse.ch
  (URLhaus, MalwareBazaar, ThreatFox), AlienVault OTX, AUR RPC API.

## Consequences
Strong privacy posture. Hash-only lookups still provide a meaningful reputation signal.
`--offline` enables air-gapped usage. The feed manager (built in Slice 3) enforces the
`--offline` suppression of all network calls.
