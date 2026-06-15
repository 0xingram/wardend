// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

pub const PROTO_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub scan_id: String,
    pub module: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub offline: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub remediation: String,
}

/// Wire format for plugin output. Has NO `status` field — core derives status from findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub module: String,
    pub summary: String,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub proto_version: u32,
    pub required_capabilities: Vec<String>,
    pub summary: String,
    pub signature: Option<String>,
}

/// Finding severity. Variants must be declared in ascending order — `derive(Ord)` uses
/// declaration order, and the status ladder depends on `max()` returning the highest severity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Module-level verdict. Core-derived — plugins never assert this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Error,
}

/// Core-to-CLI wire format: a `ScanResult` plus the status core derived from its findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleReport {
    pub status: Status,
    pub result: ScanResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ScanRequest {
        ScanRequest {
            scan_id: "scan-001".to_string(),
            module: "setuid-audit".to_string(),
            config: serde_json::Value::Null,
            offline: false,
        }
    }

    fn sample_finding(severity: Severity) -> Finding {
        Finding {
            severity,
            title: "Test finding".to_string(),
            detail: "Detail text".to_string(),
            remediation: "Fix it".to_string(),
        }
    }

    fn sample_result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            scan_id: "scan-001".to_string(),
            module: "setuid-audit".to_string(),
            summary: "Scan complete".to_string(),
            findings,
            metadata: serde_json::Value::Null,
        }
    }

    // ── ScanRequest ───────────────────────────────────────────────────────────

    #[test]
    fn scan_request_round_trip() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: ScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn scan_request_with_config_round_trip() {
        let req = ScanRequest {
            config: serde_json::json!({ "paths": ["/usr/bin"] }),
            ..sample_request()
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // ── ScanResult ────────────────────────────────────────────────────────────

    #[test]
    fn scan_result_round_trip() {
        let result = sample_result(vec![sample_finding(Severity::High)]);
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    /// ADR-015: the wire ScanResult must have no "status" field.
    #[test]
    fn scan_result_wire_has_no_status_field() {
        let result = sample_result(vec![]);
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("\"status\""),
            "ScanResult JSON must not contain a status field; got: {json}"
        );
    }

    // ── Finding ───────────────────────────────────────────────────────────────

    #[test]
    fn finding_round_trip() {
        let finding = sample_finding(Severity::Critical);
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    // ── Manifest ──────────────────────────────────────────────────────────────

    #[test]
    fn manifest_round_trip() {
        let manifest = Manifest {
            name: "setuid-audit".to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Checks for unexpected setuid binaries".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn manifest_with_signature_round_trip() {
        let manifest = Manifest {
            name: "setuid-audit".to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec!["read_filesystem".to_string()],
            summary: "Checks for unexpected setuid binaries".to_string(),
            signature: Some("sha256:abc123".to_string()),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // ── Severity ──────────────────────────────────────────────────────────────

    #[test]
    fn severity_all_variants_round_trip() {
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn severity_ordering_ascending() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_max_works() {
        let severities = vec![Severity::Low, Severity::High, Severity::Medium];
        assert_eq!(severities.iter().max(), Some(&Severity::High));
    }

    // ── Status ────────────────────────────────────────────────────────────────

    #[test]
    fn status_all_variants_round_trip() {
        for status in [Status::Pass, Status::Warn, Status::Fail, Status::Error] {
            let json = serde_json::to_string(&status).unwrap();
            let back: Status = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    // ── ModuleReport ──────────────────────────────────────────────────────────

    #[test]
    fn module_report_round_trip() {
        let report = ModuleReport {
            status: Status::Fail,
            result: sample_result(vec![sample_finding(Severity::High)]),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ModuleReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
