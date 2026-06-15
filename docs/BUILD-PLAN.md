# wardend — Build Plan

Slice-by-slice plan. Each slice is a **vertical tracer bullet** that ends in something runnable
and committed, not a horizontal layer. Build the *walking skeleton* first, then thicken it.

> Ordering principle (locked, supersedes HANDOFF.md's phase order): **prove the architecture
> with the simplest real module first; build the hardest module second.** pkgbuild-audit is the
> *flagship* but not the *first thing built* — building it before a working runner means building
> it untested.

Status legend: ☐ not started · ◑ in progress · ☑ done

---

## Slice 0 — Scaffold + CI  ◑

Goal: an empty-but-correct workspace that compiles and passes CI.

- Workspace `Cargo.toml` with members: `wardend-proto`, `wardend-core`, `wardend-cli`.
  (Plugin crates added in their slices.)
- `rust-toolchain.toml` pinning a current stable + edition 2024.
- `[workspace.lints]`: clippy pedantic; `unsafe_code = "forbid"` for proto/cli.
- `.cargo/config.toml` with a **commented** mold opt-in.
- SPDX `GPL-3.0-or-later` header in every source file; `LICENSE` already present (GPLv3).
- GitHub Actions: `fmt --check`, `clippy -D warnings`, `test` on PRs.
- `.gitignore` (`/target`, etc.).

**Acceptance:** `cargo build --workspace` green; CI green on a PR.

---

## Slice 1 — Walking skeleton (end-to-end, `setuid-audit`)  ☐

Goal: prove the **entire architecture** — protocol, subprocess, `--describe` handshake, status
derivation, rendering — with the least possible module logic. Everything after this is "add
another module," a now-solved repeatable shape.

**`wardend-proto`** (TDD, round-trip serde tests):
- `ScanRequest { scan_id, module, config, offline }`
- `ScanResult { scan_id, module, summary, findings, metadata }` — **no `status` field**
- `Finding { severity, title, detail, remediation }`
- `Manifest { name, proto_version, required_capabilities, summary, signature }`
- `enum Status { Pass, Warn, Fail, Error }`, `enum Severity { Info, Low, Medium, High, Critical }`
- `PROTO_VERSION` constant.

**`wardend-plugin-setuid-audit`** (the trivial-but-real module — filesystem walk, no feeds, no net):
- `--describe` → emits its `Manifest`.
- scan mode → reads `ScanRequest` on stdin, walks for unexpected setuid/setgid binaries
  (compare against a baseline allowlist), emits `ScanResult` with findings on stdout.

**`wardend-core`** (tokio):
- discover plugins in `WARDEND_PLUGIN_DIR` (fallback `/usr/lib/wardend/plugins/`).
- `--describe` handshake + `proto_version` compatibility check.
- spawn plugin, write `ScanRequest`, read `ScanResult`, per-plugin **timeout**.
- **derive `Status`** via the severity ladder; aggregate into `Vec<(module, Status, ScanResult)>`.
- emit aggregated JSON on stdout. (polkit wiring stubbed/dev-bypassed; real pkexec in packaging slice.)

**`wardend-cli`** (clap, sync):
- `wardend scan [--verbose] [--json] [--offline]`.
- invoke core, render: traffic-light per module + plain-English summary lines + overall
  **narrative**; `--verbose` expands detail/remediation; `--json` passes through.

**Acceptance:** `WARDEND_PLUGIN_DIR=target/debug cargo run -p wardend-cli -- scan` runs
setuid-audit end-to-end and prints a correct traffic-light report. Runner tests use a mock
plugin asserting JSON exchange + timeout + error propagation. Renderer tests assert output for
default/verbose/json given fixed `ScanResult`s.

---

## Slice 2 — pkgbuild-audit (flagship)  ☐

Goal: the module the project exists for. Built against a runner that already works, TDD against
fixtures.

`wardend-plugin-pkgbuild-audit`:
- fetch PKGBUILD via AUR RPC API (package name outbound only; respects `--offline`).
- static analysis → findings: `npm`/`pip`/`gem`/`bun` calls (esp. in `install()`),
  curl-pipe-shell, `base64 -d` decode, `eval`, unexpected domains, weak/missing checksums.
- **must detect the Atomic Arch pattern**: `npm install atomic-lockfile` / `js-digest` in
  `install()` → `critical`/`high` finding.
- TDD against **known-malicious** and **known-clean** PKGBUILD fixtures → correct PASS/FAIL.

Prior art to mine: `ks-aur-scanner`, `aur-scanner` (Kief Studio, 50+ rules), `aur_scanner`.

**Acceptance:** malicious fixtures → FAIL with the right findings; clean fixtures → PASS.

---

## Slice 3 — cve-check + file-hash-check (introduce the feed manager)  ☐

Goal: the first modules needing **local feeds + hash-only outbound**. Build the feed manager
here (it wasn't needed by the skeleton or flagship).

**`wardend-core` feed manager:** fetch (mockable HTTP), local cache read/write under
`/var/lib/wardend/feeds/`, `--offline` suppresses all network. Tested with mocked HTTP.

- `wardend-plugin-cve-check` — cross-ref installed packages against NVD CVE feed; TDD with a
  mock NVD feed + installed-package list → correct CVE matches.
- `wardend-plugin-file-hash-check` — hash configured paths, look up SHA256 against
  MalwareBazaar (hash only); `--offline` → cache only.

**Acceptance:** feed manager respects `--offline`; cve-check matches against a mock feed.

---

## Slice 4 — rkhunter-wrapper  ☐

Goal: low-architectural-risk output-parsing shim; slots in any time after Slice 1.

`wardend-plugin-rkhunter-wrapper` — shell out to rkhunter, parse output → `ScanResult`.

**Acceptance:** given captured rkhunter output fixtures, emits correct findings/severities.

---

## Slice 5 — Packaging & privilege (AUR)  ☐

Goal: make the two-binary + polkit model real for install.

- polkit action `dev.wardend.scan`; `wardend scan` → `pkexec /usr/lib/wardend/wardend-core …`.
- systemd **timer** for daily feed updates.
- file layout: `/usr/bin/wardend`, `/usr/lib/wardend/wardend-core`,
  `/usr/lib/wardend/plugins/`, `/etc/wardend/config.toml`, `/var/lib/wardend/feeds/`.
- AUR `PKGBUILD` (`wardend`, `wardend-git`). `.deb`/`.rpm` deferred.

**Acceptance:** installs on CachyOS; `wardend scan` elevates via polkit and runs the full set.

---

## Integration tests (ongoing)

Full flow: CLI → elevated core → plugin subprocesses → aggregated render, against a controlled
test environment. Add as slices land.

## Deferred (do NOT build — see PRD §Out of Scope)

GUI · realtime/continuous monitoring · network IDS · AI-analysis module · Unix-socket plugin
transport · `.deb`/`.rpm` (after AUR) · AppImage CLI · self-update.
