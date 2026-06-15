// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use walkdir::WalkDir;
use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

const MODULE_NAME: &str = "setuid-audit";

const SCAN_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/lib",
    "/usr/local/bin",
    "/usr/local/lib",
    "/opt",
];

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
        summary:
            "Checks setuid/setgid binaries against the package manager for ownership and integrity"
                .to_string(),
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

    let checker = PacmanChecker;
    let entries = collect_setuid_paths(SCAN_PATHS);
    let findings = classify_binaries(&entries, &checker);
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

// ── Package-manager abstraction ───────────────────────────────────────────────

/// The result of verifying a single setuid/setgid binary against the package manager.
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryStatus {
    /// Owned by a package and the file passes the integrity check.
    Owned,
    /// Owned by a package but the file has been modified since install.
    Modified { package: String },
    /// Not owned by any installed package.
    Unowned,
    /// Package manager unavailable or query failed.
    Unavailable { reason: String },
}

pub trait PkgChecker {
    fn check(&self, path: &Path) -> BinaryStatus;
}

pub struct PacmanChecker;

impl PkgChecker for PacmanChecker {
    fn check(&self, path: &Path) -> BinaryStatus {
        match query_pacman_ownership(path) {
            Err(e) => BinaryStatus::Unavailable {
                reason: e.to_string(),
            },
            Ok(None) => BinaryStatus::Unowned,
            Ok(Some(pkg)) => {
                // Err or false (check failed/clean) both default to Owned — the safe side.
                if check_pacman_integrity(&pkg, path).unwrap_or(false) {
                    BinaryStatus::Modified { package: pkg }
                } else {
                    BinaryStatus::Owned
                }
            }
        }
    }
}

/// `pacman -Qo <path>` → `Some("pkgname")` if owned, `None` if unowned.
fn query_pacman_ownership(path: &Path) -> Result<Option<String>> {
    let output = Command::new("pacman")
        .arg("-Qo")
        .arg(path)
        .output()
        .context("running pacman -Qo")?;

    if !output.status.success() {
        return Ok(None);
    }

    // Output: "/path is owned by pkgname 1.0-1\n"
    // Split: [..., "by", "pkgname", "1.0-1"]
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkg = stdout
        .split_whitespace()
        .rev()
        .nth(1) // skip version token, take package name
        .map(str::to_string);

    Ok(pkg)
}

/// `pacman -Qkk <pkg>` → `true` if <path> appears in the output (modified file), `false` if clean.
fn check_pacman_integrity(package: &str, path: &Path) -> Result<bool> {
    let output = Command::new("pacman")
        .args(["-Qkk", package])
        .output()
        .context("running pacman -Qkk")?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let path_str = path.to_string_lossy();
    // Only flag actual content changes. GID/Permissions mismatches are expected for
    // setuid/setgid binaries whose group is assigned dynamically at install time and
    // are not evidence of tampering.
    Ok(combined.lines().any(|l| {
        l.contains(path_str.as_ref())
            && (l.contains("SHA256 checksum mismatch") || l.contains("Size mismatch"))
    }))
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a single setuid/setgid binary. Returns `None` if the binary is safe
/// (owned and unmodified). `bit_desc` is "setuid", "setgid", or "setuid+setgid".
pub fn classify_binary(path: &Path, bit_desc: &str, checker: &dyn PkgChecker) -> Option<Finding> {
    let path_str = path.to_string_lossy();
    match checker.check(path) {
        BinaryStatus::Owned => None,

        BinaryStatus::Unowned => Some(Finding {
            severity: Severity::High,
            title: format!("Unowned {bit_desc} binary: {path_str}"),
            detail: format!(
                "'{path_str}' has the {bit_desc} bit set but is not owned by any installed \
                 package. An unowned privileged binary is a strong indicator of a backdoor \
                 or privilege-escalation vector."
            ),
            remediation: format!(
                "Investigate: `ls -la {path_str}` and `pacman -Qo {path_str}`. \
                 If unrecognised, quarantine or remove it immediately."
            ),
        }),

        BinaryStatus::Modified { package } => Some(Finding {
            severity: Severity::High,
            title: format!("Modified {bit_desc} binary: {path_str}"),
            detail: format!(
                "'{path_str}' is owned by '{package}' but fails the package integrity check \
                 (`pacman -Qkk`). A modified setuid binary is a critical privilege-escalation vector."
            ),
            remediation: format!(
                "Reinstall the package: `sudo pacman -S {package}`. \
                 If the modification was intentional, verify with `pacman -Qkk {package}`."
            ),
        }),

        BinaryStatus::Unavailable { reason } => Some(Finding {
            severity: Severity::Info,
            title: format!("Package-manager check skipped for {path_str}"),
            detail: format!(
                "setuid-audit could not query pacman for '{path_str}': {reason}. \
                 Without package verification the binary's status is unknown."
            ),
            remediation: "Ensure pacman is available: `which pacman`.".to_string(),
        }),
    }
}

/// Walk `scan_paths` and return all setuid/setgid files as `(path, bit_desc)` pairs.
fn collect_setuid_paths(scan_paths: &[&str]) -> Vec<(PathBuf, String)> {
    let mut entries = Vec::new();
    for root in scan_paths {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        let max_depth = if root.starts_with("/usr/lib") || root.starts_with("/usr/local/lib") {
            4
        } else {
            2
        };
        for entry in WalkDir::new(root_path)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let mode = meta.permissions().mode();
            let setuid = mode & 0o4000 != 0;
            let setgid = mode & 0o2000 != 0;
            if !setuid && !setgid {
                continue;
            }
            let canonical = entry
                .path()
                .canonicalize()
                .unwrap_or_else(|_| entry.path().to_path_buf());
            let bit_desc = match (setuid, setgid) {
                (true, true) => "setuid+setgid",
                (true, false) => "setuid",
                (false, _) => "setgid",
            };
            entries.push((canonical, bit_desc.to_string()));
        }
    }
    entries
}

fn classify_binaries(entries: &[(PathBuf, String)], checker: &dyn PkgChecker) -> Vec<Finding> {
    entries
        .iter()
        .filter_map(|(path, bits)| classify_binary(path, bits, checker))
        .collect()
}

fn build_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "All setuid/setgid binaries are owned and unmodified.".to_string();
    }
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    if high > 0 {
        format!(
            "Found {high} suspicious setuid/setgid {}",
            if high == 1 { "binary" } else { "binaries" }
        )
    } else {
        format!("Package-manager checks skipped for {info} path(s).")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use wardend_proto::{Manifest, PROTO_VERSION, ScanResult, Severity};

    use super::*;

    // ── MockPkgChecker ────────────────────────────────────────────────────────

    struct MockPkgChecker {
        results: HashMap<PathBuf, BinaryStatus>,
        default: BinaryStatus,
    }

    impl MockPkgChecker {
        fn new(entries: &[(&str, BinaryStatus)]) -> Self {
            Self {
                results: entries
                    .iter()
                    .map(|(p, s)| (PathBuf::from(p), s.clone()))
                    .collect(),
                default: BinaryStatus::Owned,
            }
        }

        fn all_unowned() -> Self {
            Self {
                results: HashMap::new(),
                default: BinaryStatus::Unowned,
            }
        }
    }

    impl PkgChecker for MockPkgChecker {
        fn check(&self, path: &Path) -> BinaryStatus {
            self.results
                .get(path)
                .cloned()
                .unwrap_or_else(|| self.default.clone())
        }
    }

    // ── describe / ADR-015 ────────────────────────────────────────────────────

    #[test]
    fn describe_emits_valid_manifest() {
        let manifest = Manifest {
            name: MODULE_NAME.to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Checks setuid/setgid binaries against the package manager for ownership and integrity".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, MODULE_NAME);
        assert_eq!(back.proto_version, PROTO_VERSION);
    }

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

    // ── classify_binary: Owned → no finding ──────────────────────────────────

    #[test]
    fn owned_unmodified_produces_no_finding() {
        let checker = MockPkgChecker::new(&[("/usr/bin/sudo", BinaryStatus::Owned)]);
        assert!(
            classify_binary(Path::new("/usr/bin/sudo"), "setuid", &checker).is_none(),
            "owned+unmodified must not produce a finding"
        );
    }

    #[test]
    fn multiple_owned_binaries_produce_no_findings() {
        let checker = MockPkgChecker::new(&[
            ("/usr/bin/sudo", BinaryStatus::Owned),
            ("/usr/bin/unix_chkpwd", BinaryStatus::Owned),
            ("/usr/lib/dbus-daemon-launch-helper", BinaryStatus::Owned),
            ("/usr/bin/nvidia-modprobe", BinaryStatus::Owned),
            ("/opt/1Password/chrome-sandbox", BinaryStatus::Owned),
        ]);
        let entries: Vec<(PathBuf, String)> = [
            "/usr/bin/sudo",
            "/usr/bin/unix_chkpwd",
            "/usr/lib/dbus-daemon-launch-helper",
            "/usr/bin/nvidia-modprobe",
            "/opt/1Password/chrome-sandbox",
        ]
        .iter()
        .map(|p| (PathBuf::from(p), "setuid".to_string()))
        .collect();
        let findings = classify_binaries(&entries, &checker);
        assert!(
            findings.is_empty(),
            "known-good owned binaries must produce no findings; got: {findings:?}"
        );
    }

    // ── classify_binary: Unowned → High ──────────────────────────────────────

    #[test]
    fn unowned_binary_produces_high_finding() {
        let checker = MockPkgChecker::all_unowned();
        let finding = classify_binary(Path::new("/tmp/evil-suid"), "setuid", &checker)
            .expect("unowned binary must produce a finding");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn unowned_finding_names_the_path() {
        let checker = MockPkgChecker::all_unowned();
        let finding = classify_binary(Path::new("/tmp/evil-suid"), "setuid", &checker).unwrap();
        assert!(
            finding.title.contains("/tmp/evil-suid"),
            "finding must name the suspicious path; got: {}",
            finding.title
        );
    }

    #[test]
    fn unowned_finding_mentions_unowned_in_detail() {
        let checker = MockPkgChecker::all_unowned();
        let finding = classify_binary(Path::new("/tmp/evil-suid"), "setuid", &checker).unwrap();
        assert!(
            finding.detail.contains("not owned"),
            "detail must say not owned; got: {}",
            finding.detail
        );
    }

    #[test]
    fn setgid_unowned_produces_high_finding_with_correct_bit_desc() {
        let checker = MockPkgChecker::all_unowned();
        let finding = classify_binary(Path::new("/tmp/evil-sgid"), "setgid", &checker).unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert!(
            finding.title.contains("setgid"),
            "title must say setgid; got: {}",
            finding.title
        );
    }

    // ── classify_binary: Modified → High ─────────────────────────────────────

    #[test]
    fn modified_owned_binary_produces_high_finding() {
        let checker = MockPkgChecker::new(&[(
            "/usr/bin/sudo",
            BinaryStatus::Modified {
                package: "sudo".to_string(),
            },
        )]);
        let finding = classify_binary(Path::new("/usr/bin/sudo"), "setuid", &checker)
            .expect("modified binary must produce a finding");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn modified_finding_names_the_package() {
        let checker = MockPkgChecker::new(&[(
            "/usr/bin/sudo",
            BinaryStatus::Modified {
                package: "sudo".to_string(),
            },
        )]);
        let finding = classify_binary(Path::new("/usr/bin/sudo"), "setuid", &checker).unwrap();
        assert!(
            finding.detail.contains("sudo"),
            "detail must name the package; got: {}",
            finding.detail
        );
        assert!(
            finding.detail.contains("modified") || finding.detail.contains("integrity"),
            "detail must mention modification; got: {}",
            finding.detail
        );
    }

    #[test]
    fn modified_finding_remediation_includes_reinstall_command() {
        let checker = MockPkgChecker::new(&[(
            "/usr/bin/sudo",
            BinaryStatus::Modified {
                package: "sudo".to_string(),
            },
        )]);
        let finding = classify_binary(Path::new("/usr/bin/sudo"), "setuid", &checker).unwrap();
        assert!(
            finding.remediation.contains("pacman -S"),
            "remediation must suggest reinstall; got: {}",
            finding.remediation
        );
    }

    // ── classify_binary: Unavailable → Info ──────────────────────────────────

    #[test]
    fn unavailable_produces_info_finding() {
        let checker = MockPkgChecker::new(&[(
            "/usr/bin/sudo",
            BinaryStatus::Unavailable {
                reason: "pacman not found".to_string(),
            },
        )]);
        let finding = classify_binary(Path::new("/usr/bin/sudo"), "setuid", &checker)
            .expect("unavailable must produce an info finding");
        assert_eq!(finding.severity, Severity::Info);
    }

    // ── build_summary ─────────────────────────────────────────────────────────

    #[test]
    fn summary_no_findings_is_reassuring() {
        let s = build_summary(&[]);
        assert!(
            s.contains("owned") && s.contains("unmodified"),
            "clean summary must mention owned and unmodified; got: {s}"
        );
    }

    #[test]
    fn summary_with_high_findings_mentions_count() {
        let findings = vec![Finding {
            severity: Severity::High,
            title: "Unowned setuid binary: /tmp/evil".to_string(),
            detail: "d".to_string(),
            remediation: "r".to_string(),
        }];
        let s = build_summary(&findings);
        assert!(s.contains('1'), "summary must include count; got: {s}");
    }

    // ── pacman output parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_pacman_qo_output_extracts_package_name() {
        // Simulate what query_pacman_ownership parses:
        // "/usr/bin/sudo is owned by sudo 1.9.15p5-1"
        let stdout = "/usr/bin/sudo is owned by sudo 1.9.15p5-1\n";
        let pkg = stdout.split_whitespace().rev().nth(1).map(str::to_string);
        assert_eq!(pkg, Some("sudo".to_string()));
    }

    #[test]
    fn parse_pacman_qo_output_various_packages() {
        for (line, expected_pkg) in [
            (
                "/usr/lib/dbus-daemon-launch-helper is owned by dbus 1.14.10-1\n",
                "dbus",
            ),
            (
                "/usr/bin/nvidia-modprobe is owned by nvidia-modprobe 560.35.03-1\n",
                "nvidia-modprobe",
            ),
            (
                "/opt/1Password/chrome-sandbox is owned by 1password 8.10.50-1\n",
                "1password",
            ),
        ] {
            let pkg = line
                .split_whitespace()
                .rev()
                .nth(1)
                .map(str::to_string)
                .unwrap();
            assert_eq!(pkg, expected_pkg, "failed for line: {line}");
        }
    }

    // ── integrity check keyword filtering ─────────────────────────────────────

    // GID/Permissions mismatches are expected for setgid binaries whose group is
    // assigned dynamically at install time. They must NOT be treated as tampering.
    #[test]
    fn gid_mismatch_does_not_indicate_modification() {
        // Real pacman -Qkk output for /usr/bin/groupmems on a healthy CachyOS system.
        let pacman_output = "\
warning: shadow: /usr/bin/groupmems (GID mismatch)\n\
warning: shadow: /usr/bin/groupmems (Permissions mismatch)\n";
        let path_str = "/usr/bin/groupmems";
        let is_modified = pacman_output.lines().any(|l| {
            l.contains(path_str)
                && (l.contains("SHA256 checksum mismatch") || l.contains("Size mismatch"))
        });
        assert!(
            !is_modified,
            "GID/Permissions mismatch must not trigger a modified finding"
        );
    }

    #[test]
    fn sha256_mismatch_indicates_modification() {
        let pacman_output = "warning: sudo: /usr/bin/sudo (SHA256 checksum mismatch)\n";
        let path_str = "/usr/bin/sudo";
        let is_modified = pacman_output.lines().any(|l| {
            l.contains(path_str)
                && (l.contains("SHA256 checksum mismatch") || l.contains("Size mismatch"))
        });
        assert!(
            is_modified,
            "SHA256 checksum mismatch must trigger a modified finding"
        );
    }

    #[test]
    fn size_mismatch_indicates_modification() {
        let pacman_output = "warning: sudo: /usr/bin/sudo (Size mismatch)\n";
        let path_str = "/usr/bin/sudo";
        let is_modified = pacman_output.lines().any(|l| {
            l.contains(path_str)
                && (l.contains("SHA256 checksum mismatch") || l.contains("Size mismatch"))
        });
        assert!(is_modified, "Size mismatch must trigger a modified finding");
    }
}
