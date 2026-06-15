# Architecture Decision Records

One file per decision. ADRs are immutable once Accepted — to change a decision, add a new ADR
that supersedes the old one (and mark the old one Superseded), don't edit history.

ADRs 0001–0009 are the **product-level** decisions from the design phase. ADRs 0010+ are the
**build-level** decisions resolved in the design→build grilling session, which refine how the
product decisions are realized in code.

| # | Title | Status |
|---|---|---|
| [0001](0001-language-rust.md) | Language — Rust | Accepted |
| [0002](0002-cargo-workspace-feature-flags.md) | Cargo workspace + feature flags | Accepted |
| [0003](0003-plugin-protocol-subprocess-json.md) | Plugin protocol — subprocess JSON stdin/stdout | Accepted |
| [0004](0004-plugin-curation-pr-gated-signed.md) | Plugin curation — PR-gated, signed | Accepted |
| [0005](0005-output-traffic-light-plain-english.md) | Output — traffic light + plain English + `--verbose` | Accepted |
| [0006](0006-distribution-native-packages.md) | Distribution — native packages only for the privileged component | Accepted |
| [0007](0007-update-model.md) | Update model — feeds via timer, tool via package manager | Accepted |
| [0008](0008-threat-intel-local-pull-hash-only.md) | Threat intel — local pull, hash-only outbound | Accepted |
| [0009](0009-licence-gpl-v3.md) | Licence — GPL v3 | Accepted |
| [0010](0010-mvp-process-model-on-demand.md) | MVP process model — on-demand, no resident daemon | Accepted |
| [0011](0011-first-party-modules-dogfood-subprocess.md) | First-party modules dogfood the subprocess protocol | Accepted |
| [0012](0012-plugin-discovery-and-trust.md) | Plugin discovery & trust — root-owned dir, `--describe`, signing deferred | Accepted |
| [0013](0013-async-runtime-tokio-in-core.md) | Async runtime — tokio in core, proto pure-serde | Accepted |
| [0014](0014-module-vs-plugin-terminology.md) | Terminology — module (capability) vs plugin (mechanism) | Accepted |
| [0015](0015-core-derived-status-severity-ladder.md) | Core-derived status via severity ladder | Accepted |
| [0016](0016-two-binary-polkit-privilege-model.md) | Two-binary + polkit privilege model; `dev.wardend.*` namespace | Accepted |
