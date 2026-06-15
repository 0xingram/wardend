// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Write as _;

use wardend_proto::{ModuleReport, Severity, Status};

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn status_badge(status: &Status) -> String {
    match status {
        Status::Pass => format!("{GREEN}{BOLD}[PASS]{RESET}"),
        Status::Warn => format!("{YELLOW}{BOLD}[WARN]{RESET}"),
        Status::Fail => format!("{RED}{BOLD}[FAIL]{RESET}"),
        Status::Error => format!("{RED}{BOLD}[ERROR]{RESET}"),
    }
}

fn severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Critical => format!("{RED}{BOLD}[CRITICAL]{RESET}"),
        Severity::High => format!("{RED}[HIGH]{RESET}"),
        Severity::Medium => format!("{YELLOW}[MEDIUM]{RESET}"),
        Severity::Low => format!("{CYAN}[LOW]{RESET}"),
        Severity::Info => format!("{DIM}[INFO]{RESET}"),
    }
}

// ── Renderers ─────────────────────────────────────────────────────────────────

/// Render in default (non-verbose) mode: one traffic-light line per module + narrative.
#[must_use]
pub fn render_default(reports: &[ModuleReport]) -> String {
    let mut out = String::new();
    out.push('\n');
    for r in reports {
        let _ = writeln!(
            out,
            "  {} {} \u{2014} {}",
            status_badge(&r.status),
            r.result.module,
            r.result.summary,
        );
    }
    out.push('\n');
    out.push_str(&narrative(reports));
    out.push('\n');
    out
}

/// Render in verbose mode: traffic-light + finding details with severity, detail, remediation.
#[must_use]
pub fn render_verbose(reports: &[ModuleReport]) -> String {
    let mut out = String::new();
    out.push('\n');
    for r in reports {
        let _ = writeln!(
            out,
            "  {} {} \u{2014} {}",
            status_badge(&r.status),
            r.result.module,
            r.result.summary,
        );
        for f in &r.result.findings {
            let _ = writeln!(out, "\n    {}  {}", severity_badge(&f.severity), f.title);
            let _ = writeln!(out, "           {}", f.detail);
            let _ = writeln!(out, "           {}", f.remediation);
        }
        if !r.result.findings.is_empty() {
            out.push('\n');
        }
    }
    out.push('\n');
    out.push_str(&narrative(reports));
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
pub fn narrative(reports: &[ModuleReport]) -> String {
    if reports.is_empty() {
        return format!("{DIM}No modules were run.{RESET}");
    }

    let fail_count = reports.iter().filter(|r| r.status == Status::Fail).count();
    let warn_count = reports.iter().filter(|r| r.status == Status::Warn).count();
    let error_count = reports.iter().filter(|r| r.status == Status::Error).count();

    let mut parts: Vec<String> = Vec::new();

    if fail_count > 0 {
        if fail_count == 1 {
            parts.push(format!("{RED}{BOLD}1 issue needs your attention.{RESET}"));
        } else {
            parts.push(format!(
                "{RED}{BOLD}{fail_count} issues need your attention.{RESET}"
            ));
        }
    } else if warn_count > 0 {
        parts.push(format!(
            "{YELLOW}{BOLD}{warn_count} {} worth a look.{RESET}",
            if warn_count == 1 { "thing" } else { "things" }
        ));
    } else {
        parts.push(format!("{GREEN}{BOLD}Your system looks healthy.{RESET}"));
    }

    if error_count > 0 {
        parts.push(format!(
            "{RED}{error_count} module{} could not be scanned — see above.{RESET}",
            if error_count == 1 { "" } else { "s" }
        ));
    }

    parts.join("\n")
}

#[cfg(test)]
mod tests {
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
        let out = render_default(&[pass_report()]);
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
        let out = render_default(&[fail_report()]);
        assert!(out.contains("FAIL"), "expected FAIL in: {out:?}");
    }

    #[test]
    fn default_warn_contains_warn_badge() {
        let out = render_default(&[warn_report()]);
        assert!(out.contains("WARN"), "expected WARN in: {out:?}");
    }

    #[test]
    fn default_error_contains_error_badge() {
        let out = render_default(&[error_report()]);
        assert!(out.contains("ERROR"), "expected ERROR in: {out:?}");
    }

    // ── narrative ──────────────────────────────────────────────────────────────

    #[test]
    fn narrative_all_pass_is_healthy() {
        let out = narrative(&[pass_report()]);
        assert!(
            out.contains("looks healthy"),
            "expected healthy narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_any_fail_shows_issues() {
        let out = narrative(&[pass_report(), fail_report()]);
        assert!(
            out.contains("your attention"),
            "expected attention narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_warn_no_fail_shows_look() {
        let out = narrative(&[pass_report(), warn_report()]);
        assert!(
            out.contains("worth a look"),
            "expected look narrative, got: {out:?}"
        );
    }

    #[test]
    fn narrative_error_always_called_out() {
        let out = narrative(&[pass_report(), error_report()]);
        assert!(
            out.contains("could not be scanned"),
            "expected error call-out, got: {out:?}"
        );
    }

    #[test]
    fn narrative_fail_and_error_both_present() {
        let out = narrative(&[fail_report(), error_report()]);
        assert!(out.contains("your attention"), "missing fail text: {out:?}");
        assert!(
            out.contains("could not be scanned"),
            "missing error text: {out:?}"
        );
    }

    #[test]
    fn narrative_empty_no_modules() {
        let out = narrative(&[]);
        assert!(
            out.contains("No modules"),
            "expected no-modules message, got: {out:?}"
        );
    }

    // ── render_verbose ────────────────────────────────────────────────────────

    #[test]
    fn verbose_shows_finding_title_and_severity() {
        let out = render_verbose(&[fail_report()]);
        assert!(out.contains("HIGH"), "expected HIGH badge: {out:?}");
        assert!(
            out.contains("Unexpected setuid binary"),
            "expected finding title: {out:?}"
        );
    }

    #[test]
    fn verbose_shows_detail_and_remediation() {
        let out = render_verbose(&[fail_report()]);
        assert!(out.contains("Some detail"), "expected detail: {out:?}");
        assert!(out.contains("Fix it"), "expected remediation: {out:?}");
    }

    #[test]
    fn verbose_pass_shows_no_findings_section() {
        let out = render_verbose(&[pass_report()]);
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
}
