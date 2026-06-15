// SPDX-License-Identifier: GPL-3.0-or-later

use wardend_proto::{Finding, Severity, Status};

/// Derive a module `Status` from the highest-severity finding present (ADR-015 ladder).
#[must_use]
pub fn derive_status(findings: &[Finding]) -> Status {
    match findings.iter().map(|f| &f.severity).max() {
        Some(Severity::Critical | Severity::High) => Status::Fail,
        Some(Severity::Medium) => Status::Warn,
        None | Some(Severity::Low | Severity::Info) => Status::Pass,
    }
}

#[cfg(test)]
mod tests {
    use wardend_proto::Finding;

    use super::*;

    fn finding(sev: Severity) -> Finding {
        Finding {
            severity: sev,
            title: "t".to_string(),
            detail: "d".to_string(),
            remediation: "r".to_string(),
        }
    }

    #[test]
    fn no_findings_is_pass() {
        assert_eq!(derive_status(&[]), Status::Pass);
    }

    #[test]
    fn info_only_is_pass() {
        assert_eq!(derive_status(&[finding(Severity::Info)]), Status::Pass);
    }

    #[test]
    fn low_only_is_pass() {
        assert_eq!(derive_status(&[finding(Severity::Low)]), Status::Pass);
    }

    #[test]
    fn medium_is_warn() {
        assert_eq!(derive_status(&[finding(Severity::Medium)]), Status::Warn);
    }

    #[test]
    fn high_is_fail() {
        assert_eq!(derive_status(&[finding(Severity::High)]), Status::Fail);
    }

    #[test]
    fn critical_is_fail() {
        assert_eq!(derive_status(&[finding(Severity::Critical)]), Status::Fail);
    }

    #[test]
    fn mixed_severities_uses_highest() {
        let findings = vec![
            finding(Severity::Info),
            finding(Severity::Medium),
            finding(Severity::High),
            finding(Severity::Low),
        ];
        assert_eq!(derive_status(&findings), Status::Fail);
    }

    #[test]
    fn critical_plus_low_is_fail() {
        assert_eq!(
            derive_status(&[finding(Severity::Low), finding(Severity::Critical)]),
            Status::Fail
        );
    }

    #[test]
    fn medium_plus_low_is_warn() {
        assert_eq!(
            derive_status(&[finding(Severity::Low), finding(Severity::Medium)]),
            Status::Warn
        );
    }
}
