// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Result, bail};
use wardend_proto::{ModuleReport, Severity, Status};

// ── Core binary discovery ─────────────────────────────────────────────────────

/// How to invoke `wardend-core`.
///
/// - `Dev` — invoke the binary directly (no pkexec). Used when running from a build tree
///   or when `WARDEND_CORE_BIN` overrides the path.
/// - `Production` — invoke via `pkexec` so polkit handles privilege elevation.
pub enum CoreMode {
    Dev(PathBuf),
    Production(PathBuf),
}

/// Locate `wardend-core` and decide whether to use pkexec.
///
/// Precedence:
/// 1. `WARDEND_CORE_BIN` env var → dev mode (direct invocation, no pkexec).
/// 2. Binary adjacent to the CLI exe (covers `cargo run`) → dev mode.
/// 3. Installed path `/usr/lib/wardend/wardend-core` → production mode (pkexec).
///
/// # Errors
/// Returns an error if `wardend-core` cannot be found by any of the above methods.
pub fn find_core() -> Result<CoreMode> {
    find_core_inner(std::env::var("WARDEND_CORE_BIN").ok().as_deref())
}

/// Inner implementation, accepting an optional `WARDEND_CORE_BIN` override.
/// Extracted for testability without `unsafe` env-var mutation.
///
/// # Errors
/// Returns an error if `wardend-core` cannot be found by any of the lookup methods.
pub fn find_core_inner(core_bin_override: Option<&str>) -> Result<CoreMode> {
    if let Some(path) = core_bin_override {
        return Ok(CoreMode::Dev(PathBuf::from(path)));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("wardend-core");
        if candidate.exists() {
            return Ok(CoreMode::Dev(candidate));
        }
    }
    let installed = PathBuf::from("/usr/lib/wardend/wardend-core");
    if installed.exists() {
        return Ok(CoreMode::Production(installed));
    }
    bail!(
        "wardend-core not found — run 'cargo build --workspace' first, \
         or set WARDEND_CORE_BIN to its path"
    )
}

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn esc(colour: bool, code: &str) -> &str {
    if colour { code } else { "" }
}

fn status_badge(status: &Status, colour: bool) -> String {
    let red = esc(colour, RED);
    let yel = esc(colour, YELLOW);
    let grn = esc(colour, GREEN);
    let bld = esc(colour, BOLD);
    let rst = esc(colour, RESET);
    match status {
        Status::Pass => format!("{grn}{bld}[PASS]{rst}"),
        Status::Warn => format!("{yel}{bld}[WARN]{rst}"),
        Status::Fail => format!("{red}{bld}[FAIL]{rst}"),
        Status::Error => format!("{red}{bld}[ERROR]{rst}"),
    }
}

fn severity_badge(severity: &Severity, colour: bool) -> String {
    let red = esc(colour, RED);
    let yel = esc(colour, YELLOW);
    let cyn = esc(colour, CYAN);
    let bld = esc(colour, BOLD);
    let dim = esc(colour, DIM);
    let rst = esc(colour, RESET);
    match severity {
        Severity::Critical => format!("{red}{bld}[CRITICAL]{rst}"),
        Severity::High => format!("{red}[HIGH]{rst}"),
        Severity::Medium => format!("{yel}[MEDIUM]{rst}"),
        Severity::Low => format!("{cyn}[LOW]{rst}"),
        Severity::Info => format!("{dim}[INFO]{rst}"),
    }
}

// ── Renderers ─────────────────────────────────────────────────────────────────

/// Render in default (non-verbose) mode: one traffic-light line per module + narrative.
/// Pass `colour: true` when stdout is a TTY, `false` when piped/redirected.
#[must_use]
pub fn render_default(reports: &[ModuleReport], colour: bool) -> String {
    let mut out = String::new();
    out.push('\n');
    for r in reports {
        let _ = writeln!(
            out,
            "  {} {} \u{2014} {}",
            status_badge(&r.status, colour),
            r.result.module,
            r.result.summary,
        );
    }
    out.push('\n');
    out.push_str(&narrative(reports, colour));
    out.push('\n');
    out
}

/// Render in verbose mode: traffic-light + finding details with severity, detail, remediation.
/// Pass `colour: true` when stdout is a TTY, `false` when piped/redirected.
#[must_use]
pub fn render_verbose(reports: &[ModuleReport], colour: bool) -> String {
    let mut out = String::new();
    out.push('\n');
    for r in reports {
        let _ = writeln!(
            out,
            "  {} {} \u{2014} {}",
            status_badge(&r.status, colour),
            r.result.module,
            r.result.summary,
        );
        for f in &r.result.findings {
            let _ = writeln!(
                out,
                "\n    {}  {}",
                severity_badge(&f.severity, colour),
                f.title
            );
            let _ = writeln!(out, "           {}", f.detail);
            let _ = writeln!(out, "           {}", f.remediation);
        }
        if !r.result.findings.is_empty() {
            out.push('\n');
        }
    }
    out.push('\n');
    out.push_str(&narrative(reports, colour));
    out.push('\n');
    out
}

/// Render in JSON mode: emit the raw aggregated JSON as-is.
#[must_use]
pub fn render_json(reports: &[ModuleReport]) -> String {
    serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".to_string())
}

/// Build the overall narrative line (ADR-015 summary rules).
#[must_use]
pub fn narrative(reports: &[ModuleReport], colour: bool) -> String {
    let red = esc(colour, RED);
    let yel = esc(colour, YELLOW);
    let grn = esc(colour, GREEN);
    let bld = esc(colour, BOLD);
    let dim = esc(colour, DIM);
    let rst = esc(colour, RESET);

    if reports.is_empty() {
        return format!("{dim}No modules were run.{rst}");
    }

    let fail_count = reports.iter().filter(|r| r.status == Status::Fail).count();
    let warn_count = reports.iter().filter(|r| r.status == Status::Warn).count();
    let error_count = reports.iter().filter(|r| r.status == Status::Error).count();

    let mut parts: Vec<String> = Vec::new();

    if fail_count > 0 {
        if fail_count == 1 {
            parts.push(format!("{red}{bld}1 issue needs your attention.{rst}"));
        } else {
            parts.push(format!(
                "{red}{bld}{fail_count} issues need your attention.{rst}"
            ));
        }
    } else if warn_count > 0 {
        parts.push(format!(
            "{yel}{bld}{warn_count} {} worth a look.{rst}",
            if warn_count == 1 { "thing" } else { "things" }
        ));
    } else {
        parts.push(format!("{grn}{bld}Your system looks healthy.{rst}"));
    }

    if error_count > 0 {
        parts.push(format!(
            "{red}{error_count} module{} could not be scanned — see above.{rst}",
            if error_count == 1 { "" } else { "s" }
        ));
    }

    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;
    use wardend_proto::{Finding, ScanResult};

    use super::*;

    fn make_result(module: &str, summary: &str, findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            scan_id: "test".to_string(),
            module: module.to_string(),
            summary: summary.to_string(),
            findings,
            metadata: serde_json::Value::Null,
        }
    }

    fn make_finding(sev: Severity, title: &str) -> Finding {
        Finding {
            severity: sev,
            title: title.to_string(),
            detail: "Some detail".to_string(),
            remediation: "Fix it".to_string(),
        }
    }

    fn pass_report() -> ModuleReport {
        ModuleReport {
            status: Status::Pass,
            result: make_result(
                "setuid-audit",
                "No unexpected setuid binaries found",
                vec![],
            ),
        }
    }

    fn fail_report() -> ModuleReport {
        ModuleReport {
            status: Status::Fail,
            result: make_result(
                "setuid-audit",
                "Found 1 unexpected setuid binary",
                vec![make_finding(
                    Severity::High,
                    "Unexpected setuid binary: /opt/evil",
                )],
            ),
        }
    }

    fn warn_report() -> ModuleReport {
        ModuleReport {
            status: Status::Warn,
            result: make_result(
                "pkg-check",
                "Found 1 suspicious package",
                vec![make_finding(
                    Severity::Medium,
                    "Suspicious package: evil-pkg",
                )],
            ),
        }
    }

    fn error_report() -> ModuleReport {
        ModuleReport {
            status: Status::Error,
            result: make_result("broken-module", "Plugin error: timeout", vec![]),
        }
    }

    // ── render_default ─────────────────────────────────────────────────────────

    #[test]
    fn default_pass_contains_pass_badge_and_module_name() {
        let out = render_default(&[pass_report()], true);
        assert!(out.contains("PASS"), "expected PASS in: {out:?}");
        assert!(
            out.contains("setuid-audit"),
            "expected module name in: {out:?}"
        );
        assert!(
            out.contains("No unexpected"),
            "expected summary in: {out:?}"
        );
    }

    #[test]
    fn default_fail_contains_fail_badge() {
        let out = render_default(&[fail_report()], true);
        assert!(out.contains("FAIL"), "expected FAIL in: {out:?}");
    }

    #[test]
    fn default_warn_contains_warn_badge() {
        let out = render_default(&[warn_report()], true);
        assert!(out.contains("WARN"), "expected WARN in: {out:?}");
    }

    #[test]
    fn default_error_contains_error_badge() {
        let out = render_default(&[error_report()], true);
        assert!(out.contains("ERROR"), "expected ERROR in: {out:?}");
    }

    #[test]
    fn default_no_ansi_when_colour_disabled() {
        let out = render_default(&[pass_report(), fail_report(), error_report()], false);
        assert!(
            !out.contains('\x1b'),
            "expected no ANSI escape codes when colour=false, got: {out:?}"
        );
        // Content must still be present
        assert!(out.contains("PASS"), "expected PASS text: {out:?}");
        assert!(out.contains("FAIL"), "expected FAIL text: {out:?}");
    }

    // ── narrative ──────────────────────────────────────────────────────────────

    #[test]
    fn narrative_all_pass_is_healthy() {
        let out = narrative(&[pass_report()], true);
        assert!(
            out.contains("looks healthy"),
            "expected healthy narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_any_fail_shows_issues() {
        let out = narrative(&[pass_report(), fail_report()], true);
        assert!(
            out.contains("your attention"),
            "expected attention narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_warn_no_fail_shows_look() {
        let out = narrative(&[pass_report(), warn_report()], true);
        assert!(
            out.contains("worth a look"),
            "expected look narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_error_always_called_out() {
        let out = narrative(&[pass_report(), error_report()], true);
        assert!(
            out.contains("could not be scanned"),
            "expected error call-out, got: {out:?}"
        );
    }

    #[test]
    fn narrative_fail_and_error_both_present() {
        let out = narrative(&[fail_report(), error_report()], true);
        assert!(out.contains("your attention"), "missing fail text: {out:?}");
        assert!(
            out.contains("could not be scanned"),
            "missing error text: {out:?}"
        );
    }

    #[test]
    fn narrative_empty_no_modules() {
        let out = narrative(&[], true);
        assert!(
            out.contains("No modules"),
            "expected no-modules message, got: {out:?}"
        );
    }

    // ── render_verbose ────────────────────────────────────────────────────────

    #[test]
    fn verbose_shows_finding_title_and_severity() {
        let out = render_verbose(&[fail_report()], true);
        assert!(out.contains("HIGH"), "expected HIGH badge: {out:?}");
        assert!(
            out.contains("Unexpected setuid binary"),
            "expected finding title: {out:?}"
        );
    }

    #[test]
    fn verbose_shows_detail_and_remediation() {
        let out = render_verbose(&[fail_report()], true);
        assert!(out.contains("Some detail"), "expected detail: {out:?}");
        assert!(out.contains("Fix it"), "expected remediation: {out:?}");
    }

    #[test]
    fn verbose_pass_shows_no_findings_section() {
        let out = render_verbose(&[pass_report()], true);
        assert!(out.contains("PASS"), "expected PASS: {out:?}");
        // No finding blocks for a PASS module with no findings
        assert!(!out.contains("HIGH"), "unexpected HIGH badge: {out:?}");
    }

    // ── render_json ───────────────────────────────────────────────────────────

    #[test]
    fn json_output_is_valid_json_array() {
        let out = render_json(&[pass_report(), fail_report()]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn json_output_contains_status_field() {
        let out = render_json(&[pass_report()]);
        assert!(out.contains("\"status\""), "expected status field: {out:?}");
        assert!(out.contains("\"pass\""), "expected pass value: {out:?}");
    }

    #[test]
    fn json_output_result_has_no_top_level_status_in_result_object() {
        // The result sub-object (ScanResult) must NOT have a status field per ADR-015.
        let out = render_json(&[pass_report()]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        let result_obj = &parsed[0]["result"];
        assert!(
            result_obj.get("status").is_none(),
            "ScanResult sub-object must not have a status field; got: {result_obj}"
        );
    }

    // ── find_core / dev-bypass ────────────────────────────────────────────────

    /// `WARDEND_CORE_BIN` must produce `CoreMode::Dev` so the CLI invokes the binary
    /// directly without pkexec — exercisable in development without polkit installed.
    ///
    /// Uses `find_core_inner` to avoid `unsafe` env-var mutation; the public
    /// `find_core()` reads `WARDEND_CORE_BIN` and delegates here.
    #[test]
    fn dev_bypass_via_wardend_core_bin_env_var() {
        let tmp = TempDir::new().unwrap();
        let fake_core = tmp.path().join("wardend-core");

        // A real executable in a TempDir, mimicking what cargo build produces.
        std::fs::write(&fake_core, b"#!/bin/sh\nexec true\n").unwrap();
        std::fs::set_permissions(&fake_core, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path_str = fake_core.to_str().unwrap();
        match super::find_core_inner(Some(path_str)).unwrap() {
            super::CoreMode::Dev(p) => {
                assert_eq!(p, fake_core, "dev path must match the override value")
            }
            super::CoreMode::Production(_) => {
                panic!("expected Dev mode when WARDEND_CORE_BIN is set, got Production")
            }
        }
    }

    #[test]
    fn production_mode_when_no_override_and_no_adjacent_binary() {
        // When neither override nor an adjacent binary is present and the installed
        // path does not exist, find_core_inner must return an error.
        // (If /usr/lib/wardend/wardend-core is actually installed on this machine
        //  this test would see Production — that's still the correct behaviour.)
        let result = super::find_core_inner(None);
        // Either Production (installed) or an error (not installed) — never Dev.
        if let Ok(mode) = result {
            assert!(
                matches!(mode, super::CoreMode::Production(_)),
                "without override or adjacent binary, must be Production or error"
            );
        }
        // Error case (wardend-core not installed) is also valid — just verify no panic.
    }
}
