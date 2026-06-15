// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::Command;

use anyhow::{Context as _, Result};
use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

const MODULE_NAME: &str = "rkhunter-wrapper";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--describe") {
        describe()
    } else {
        scan()
    }
}

fn describe() -> Result<()> {
    let manifest = Manifest {
        name: MODULE_NAME.to_string(),
        proto_version: PROTO_VERSION,
        required_capabilities: vec![],
        summary: "Scans for rootkits and suspicious files using rkhunter".to_string(),
        signature: None,
    };
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}

fn scan() -> Result<()> {
    let line = {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading ScanRequest from stdin")?;
        buf
    };
    let request: ScanRequest =
        serde_json::from_str(line.trim()).context("parsing ScanRequest JSON")?;

    let findings = if let Some(fixture) = request.config.get("_fixture").and_then(|v| v.as_str()) {
        parse_rkhunter_output(fixture)
    } else {
        match invoke_rkhunter()? {
            RkhunterOutput::Output(output) => parse_rkhunter_output(&output),
            RkhunterOutput::NotInstalled => vec![not_installed_finding()],
        }
    };

    let summary = build_summary(&findings);

    let result = ScanResult {
        scan_id: request.scan_id,
        module: MODULE_NAME.to_string(),
        summary,
        findings,
        metadata: serde_json::Value::Null,
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

enum RkhunterOutput {
    Output(String),
    NotInstalled,
}

fn invoke_rkhunter() -> Result<RkhunterOutput> {
    match Command::new("rkhunter")
        .args(["--check", "--skip-keypress", "--report-mode"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            Ok(RkhunterOutput::Output(format!("{stdout}{stderr}")))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RkhunterOutput::NotInstalled),
        Err(e) => Err(anyhow::Error::new(e).context("running rkhunter")),
    }
}

fn not_installed_finding() -> Finding {
    Finding {
        severity: Severity::Info,
        title: "rkhunter is not installed".to_string(),
        detail: "The rkhunter rootkit scanner is not available on this system. \
                 Without it, this module cannot check for rootkits or suspicious \
                 system file modifications."
            .to_string(),
        remediation: "Install rkhunter: `sudo pacman -S rkhunter`. \
                      After installation, initialise the baseline with \
                      `sudo rkhunter --propupd`."
            .to_string(),
    }
}

// Parse rkhunter output, extracting [ Found ] and [ Warning ] lines as findings.
// Lines ending with [ Found ] map to Critical (rootkit component detected).
// Lines ending with [ Warning ] map to High (suspicious file or condition).
fn parse_rkhunter_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if let Some((item, _)) = trimmed.rsplit_once("[ Found ]") {
            let name = item.trim().to_string();
            if name.is_empty() {
                continue;
            }
            findings.push(Finding {
                severity: Severity::Critical,
                title: format!("Rootkit component found: {name}"),
                detail: format!(
                    "rkhunter detected a known rootkit component: {name}. \
                     This is a strong indicator of system compromise."
                ),
                remediation: "Your system may be compromised. Review \
                              `/var/log/rkhunter.log` immediately and consider \
                              reinstalling from a trusted clean state."
                    .to_string(),
            });
        } else if let Some((item, _)) = trimmed.rsplit_once("[ Warning ]") {
            let name = item.trim().to_string();
            if name.is_empty() {
                continue;
            }
            findings.push(Finding {
                severity: Severity::High,
                title: format!("rkhunter warning: {name}"),
                detail: format!(
                    "rkhunter reported a warning for: {name}. \
                     This may indicate system file tampering or a misconfiguration."
                ),
                remediation: format!(
                    "Review `/var/log/rkhunter.log` for details. \
                     Verify the flagged item with `pacman -Qo {name}`."
                ),
            });
        }
    }

    findings
}

fn build_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "rkhunter found no warnings or rootkit indicators.".to_string();
    }

    let is_not_installed = findings.len() == 1
        && findings[0].severity == Severity::Info
        && findings[0].title.contains("not installed");
    if is_not_installed {
        return "rkhunter is not installed; rootkit scanning skipped.".to_string();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();

    if critical > 0 {
        format!("rkhunter detected {critical} rootkit component(s) — immediate action required")
    } else {
        format!("rkhunter reported {high} warning(s) — review recommended")
    }
}

#[cfg(test)]
mod tests {
    use wardend_proto::{Manifest, PROTO_VERSION, ScanResult, Severity};

    use super::{MODULE_NAME, build_summary, not_installed_finding, parse_rkhunter_output};

    // Fixture: a clean rkhunter run — no warnings, no rootkits found.
    const FIXTURE_CLEAN: &str = r"
[ Rootkit Hunter version 1.4.6 ]

Checking system commands...

  Performing 'strings' command checks
    Checking 'strings' command                               [ OK ]

  Performing 'shared libraries' checks
    Checking for preloading variables                        [ None found ]
    Checking for preloaded libraries                        [ None found ]

  Performing file properties checks
    /usr/bin/awk                                             [ OK ]
    /usr/bin/bash                                            [ OK ]
    /usr/bin/cat                                             [ OK ]

Checking for rootkits...

  Performing check of known rootkit files and directories
    55808 Trojan - Variant A                                 [ Not found ]
    ADM Worm                                                 [ Not found ]
    AjaKit Rootkit                                           [ Not found ]

Checking the network...

  Performing checks on the network ports
    Checking for backdoor ports                              [ None found ]

No warnings were found whilst checking the system.
";

    // Fixture: file integrity warning — a system binary has been replaced.
    const FIXTURE_WARNING: &str = r"
[ Rootkit Hunter version 1.4.6 ]

Checking system commands...

  Performing file properties checks
    /usr/bin/awk                                             [ Warning ]
    /usr/bin/bash                                            [ OK ]
    /usr/bin/cat                                             [ OK ]

Checking for rootkits...

  Performing check of known rootkit files and directories
    55808 Trojan - Variant A                                 [ Not found ]
    ADM Worm                                                 [ Not found ]
";

    // Fixture: actual rootkit component found.
    const FIXTURE_ROOTKIT: &str = r"
[ Rootkit Hunter version 1.4.6 ]

Checking system commands...

  Performing file properties checks
    /usr/bin/awk                                             [ Warning ]
    /usr/bin/bash                                            [ OK ]

Checking for rootkits...

  Performing check of known rootkit files and directories
    55808 Trojan - Variant A                                 [ Found ]
    ADM Worm                                                 [ Not found ]
    Adore Rootkit                                            [ Not found ]
";

    // ── describe ──────────────────────────────────────────────────────────────

    #[test]
    fn describe_emits_valid_manifest() {
        let manifest = Manifest {
            name: MODULE_NAME.to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Scans for rootkits and suspicious files using rkhunter".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, MODULE_NAME);
        assert_eq!(back.proto_version, PROTO_VERSION);
    }

    // ── ADR-015: no status field on the wire ──────────────────────────────────

    #[test]
    fn scan_result_wire_has_no_status_field() {
        let result = ScanResult {
            scan_id: "adr015".to_string(),
            module: MODULE_NAME.to_string(),
            summary: "test".to_string(),
            findings: vec![],
            metadata: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("\"status\""),
            "ScanResult wire must not contain a status field; got: {json}"
        );
    }

    // ── clean run ─────────────────────────────────────────────────────────────

    #[test]
    fn clean_output_produces_no_findings() {
        let findings = parse_rkhunter_output(FIXTURE_CLEAN);
        assert!(
            findings.is_empty(),
            "clean rkhunter output must yield zero findings; got: {findings:?}"
        );
    }

    #[test]
    fn clean_summary_is_reassuring() {
        let findings = parse_rkhunter_output(FIXTURE_CLEAN);
        let summary = build_summary(&findings);
        assert!(
            summary.contains("no warnings"),
            "clean summary must say 'no warnings'; got: {summary}"
        );
    }

    // ── warning (suspicious file) ─────────────────────────────────────────────

    #[test]
    fn warning_line_produces_high_finding() {
        let findings = parse_rkhunter_output(FIXTURE_WARNING);
        assert_eq!(findings.len(), 1, "one [ Warning ] line → one finding");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn warning_finding_names_the_flagged_item() {
        let findings = parse_rkhunter_output(FIXTURE_WARNING);
        assert!(
            findings[0].title.contains("/usr/bin/awk"),
            "finding title must include the flagged path; got: {}",
            findings[0].title
        );
    }

    #[test]
    fn warning_summary_mentions_count() {
        let findings = parse_rkhunter_output(FIXTURE_WARNING);
        let summary = build_summary(&findings);
        assert!(
            summary.contains('1'),
            "summary must mention the warning count; got: {summary}"
        );
    }

    // ── rootkit found ─────────────────────────────────────────────────────────

    #[test]
    fn found_line_produces_critical_finding() {
        let findings = parse_rkhunter_output(FIXTURE_ROOTKIT);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert_eq!(
            critical.len(),
            1,
            "one [ Found ] line → one Critical finding"
        );
    }

    #[test]
    fn rootkit_finding_names_the_rootkit() {
        let findings = parse_rkhunter_output(FIXTURE_ROOTKIT);
        let crit = findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .expect("must have a critical finding");
        assert!(
            crit.title.contains("55808 Trojan - Variant A"),
            "critical finding must name the rootkit; got: {}",
            crit.title
        );
    }

    #[test]
    fn rootkit_fixture_also_has_warning_finding() {
        let findings = parse_rkhunter_output(FIXTURE_ROOTKIT);
        let high: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert_eq!(
            high.len(),
            1,
            "fixture has one [ Warning ] line alongside the rootkit"
        );
    }

    #[test]
    fn rootkit_summary_mentions_rootkit_count() {
        let findings = parse_rkhunter_output(FIXTURE_ROOTKIT);
        let summary = build_summary(&findings);
        assert!(
            summary.contains("rootkit"),
            "summary for rootkit finding must mention 'rootkit'; got: {summary}"
        );
    }

    // ── not installed ─────────────────────────────────────────────────────────

    #[test]
    fn not_installed_finding_has_info_severity() {
        let finding = not_installed_finding();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn not_installed_finding_has_install_instructions() {
        let finding = not_installed_finding();
        assert!(
            finding.remediation.contains("pacman"),
            "remediation must include pacman install command; got: {}",
            finding.remediation
        );
    }

    #[test]
    fn not_installed_summary_is_informative() {
        let findings = vec![not_installed_finding()];
        let summary = build_summary(&findings);
        assert!(
            summary.contains("not installed"),
            "summary must say rkhunter is not installed; got: {summary}"
        );
    }

    // ── severity mapping ──────────────────────────────────────────────────────

    #[test]
    fn not_found_lines_do_not_produce_findings() {
        let output = "    55808 Trojan - Variant A                                 [ Not found ]\n\
                          ADM Worm                                                 [ Not found ]";
        let findings = parse_rkhunter_output(output);
        assert!(
            findings.is_empty(),
            "[ Not found ] lines must not produce findings; got: {findings:?}"
        );
    }

    #[test]
    fn ok_lines_do_not_produce_findings() {
        let output = "    /usr/bin/awk                                             [ OK ]\n\
                          /usr/bin/bash                                            [ OK ]";
        let findings = parse_rkhunter_output(output);
        assert!(
            findings.is_empty(),
            "[ OK ] lines must not produce findings; got: {findings:?}"
        );
    }

    #[test]
    fn multiple_found_lines_produce_multiple_critical_findings() {
        let output = "    Rootkit A                                                [ Found ]\n\
                          Rootkit B                                                [ Found ]";
        let findings = parse_rkhunter_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn multiple_warning_lines_produce_multiple_high_findings() {
        let output = "    /usr/bin/awk                                             [ Warning ]\n\
                          /usr/bin/ls                                              [ Warning ]";
        let findings = parse_rkhunter_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }
}
