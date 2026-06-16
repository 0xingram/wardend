// SPDX-License-Identifier: GPL-3.0-or-later

mod analyzer;

use anyhow::{Context as _, Result};
use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

const MODULE_NAME: &str = "pkgbuild-audit";
/// Only the package name travels outbound (as a URL path segment). No system
/// inventory, no file contents, no hashes — ADR-008.
const AUR_PKGBUILD_URL_PREFIX: &str = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=";

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
        summary: "Statically analyses PKGBUILDs for supply-chain attack patterns (AUR)".to_string(),
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

    let package = request.config.get("package").and_then(|v| v.as_str());

    let mut findings: Vec<Finding> = Vec::new();

    let pkgbuild_text: Option<String> = if let Some(pkg) = package {
        if request.offline {
            findings.push(Finding {
                severity: Severity::Info,
                title: format!("pkgbuild-audit skipped for '{pkg}': offline mode"),
                detail: format!(
                    "Cannot fetch the PKGBUILD for '{pkg}' because --offline is set. \
                     No analysis was performed."
                ),
                remediation: "Re-run without --offline to analyse the PKGBUILD.".to_string(),
            });
            None
        } else {
            match fetch_pkgbuild(pkg) {
                Ok(text) => Some(text),
                Err(err) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        title: format!("Failed to fetch PKGBUILD for '{pkg}'"),
                        detail: format!("AUR fetch error: {err:#}"),
                        remediation:
                            "Verify the package name and check AUR connectivity. \
                             Try: curl https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=<pkg>"
                                .to_string(),
                    });
                    None
                }
            }
        }
    } else {
        findings.push(Finding {
            severity: Severity::Info,
            title: "No package specified for pkgbuild-audit".to_string(),
            detail: "pkgbuild-audit requires a 'package' key in the scan config JSON.".to_string(),
            remediation: "Pass {\"package\": \"<aur-pkg-name>\"} in the scan configuration."
                .to_string(),
        });
        None
    };

    if let Some(text) = pkgbuild_text {
        findings.extend(analyzer::analyze(&text));
    }

    let summary = build_summary(package, &findings);

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

fn fetch_pkgbuild(pkgname: &str) -> Result<String> {
    let url = format!("{AUR_PKGBUILD_URL_PREFIX}{pkgname}");
    let connector = ureq::native_tls::TlsConnector::new().context("creating TLS connector")?;
    let agent = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(connector))
        .build();
    let response = agent.get(&url).call().context("HTTP request to AUR cgit")?;
    let body = response
        .into_string()
        .context("reading AUR response body")?;
    Ok(body)
}

fn build_summary(package: Option<&str>, findings: &[Finding]) -> String {
    let pkg_label = package.unwrap_or("<unspecified>");

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();

    if critical_count > 0 {
        format!("PKGBUILD '{pkg_label}': {critical_count} critical finding(s) — do not install")
    } else if high_count > 0 {
        format!(
            "PKGBUILD '{pkg_label}': {high_count} high-severity finding(s) — review before installing"
        )
    } else if medium_count > 0 {
        format!(
            "PKGBUILD '{pkg_label}': {medium_count} medium-severity finding(s) — review recommended"
        )
    } else if findings.is_empty() {
        format!("PKGBUILD '{pkg_label}': no suspicious patterns found")
    } else {
        format!("PKGBUILD '{pkg_label}': informational notes only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardend_proto::{Manifest, PROTO_VERSION};

    #[test]
    fn describe_emits_valid_manifest() {
        let manifest = Manifest {
            name: MODULE_NAME.to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Statically analyses PKGBUILDs for supply-chain attack patterns (AUR)"
                .to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, MODULE_NAME);
        assert_eq!(back.proto_version, PROTO_VERSION);
        assert!(back.signature.is_none());
    }

    #[test]
    fn scan_result_wire_has_no_status_field() {
        // ADR-015: plugins never assert status; core derives it.
        let result = ScanResult {
            scan_id: "test-001".to_string(),
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

    #[test]
    fn build_summary_critical() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            title: "IOC".to_string(),
            detail: "d".to_string(),
            remediation: "r".to_string(),
        }];
        let s = build_summary(Some("evil-pkg"), &findings);
        assert!(
            s.contains("critical"),
            "summary must mention critical; got: {s}"
        );
    }

    #[test]
    fn build_summary_clean() {
        let s = build_summary(Some("hello-world"), &[]);
        assert!(s.contains("no suspicious"), "clean summary wrong; got: {s}");
    }

    #[test]
    fn build_summary_no_package() {
        let findings = vec![Finding {
            severity: Severity::Info,
            title: "No package".to_string(),
            detail: "d".to_string(),
            remediation: "r".to_string(),
        }];
        let s = build_summary(None, &findings);
        assert!(
            s.contains("<unspecified>"),
            "should show unspecified; got: {s}"
        );
    }
}
