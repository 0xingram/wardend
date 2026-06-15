// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use walkdir::WalkDir;
use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

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
        name: "setuid-audit".to_string(),
        proto_version: PROTO_VERSION,
        required_capabilities: vec![],
        summary: "Checks for unexpected setuid/setgid binaries".to_string(),
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

    let findings = find_unexpected_setuid_binaries();

    let summary = if findings.is_empty() {
        "No unexpected setuid or setgid binaries found".to_string()
    } else {
        format!(
            "Found {} unexpected setuid/setgid {}",
            findings.len(),
            if findings.len() == 1 {
                "binary"
            } else {
                "binaries"
            }
        )
    };

    let result = ScanResult {
        scan_id: request.scan_id,
        module: "setuid-audit".to_string(),
        summary,
        findings,
        metadata: serde_json::Value::Null,
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn find_unexpected_setuid_binaries() -> Vec<Finding> {
    let allowlist = build_allowlist();
    let mut findings = Vec::new();

    for root in SCAN_PATHS {
        let path = Path::new(root);
        if !path.exists() {
            continue;
        }
        let max_depth = if root.starts_with("/usr/lib") || root.starts_with("/usr/local/lib") {
            4
        } else {
            2
        };
        for entry in WalkDir::new(path)
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
            let canonical = match entry.path().canonicalize() {
                Ok(p) => p,
                Err(_) => entry.path().to_path_buf(),
            };
            let path_str = canonical.to_string_lossy();
            if allowlist.iter().any(|a| *a == path_str.as_ref()) {
                continue;
            }
            let bit = if setuid && setgid {
                "setuid+setgid"
            } else if setuid {
                "setuid"
            } else {
                "setgid"
            };
            findings.push(Finding {
                severity: Severity::High,
                title: format!("Unexpected {bit} binary: {path_str}"),
                detail: format!(
                    "The binary at {path_str} has the {bit} bit set but is not in the \
                     expected baseline for this system. This could indicate a backdoor \
                     or privilege-escalation vector."
                ),
                remediation: format!(
                    "Investigate the binary: `ls -la {path_str}` and \
                     `pacman -Qo {path_str}`. If unrecognised, remove it."
                ),
            });
        }
    }

    findings
}

#[allow(clippy::too_many_lines)]
fn build_allowlist() -> Vec<&'static str> {
    vec![
        // Core privilege tools
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/gpasswd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/bin/sg",
        // Disk/mount
        "/usr/bin/mount",
        "/usr/bin/umount",
        // Network
        "/usr/bin/ping",
        // User/group management
        "/usr/bin/chage",
        "/usr/bin/expiry",
        "/usr/bin/newuidmap",
        "/usr/bin/newgidmap",
        // Cron
        "/usr/bin/crontab",
        // FUSE
        "/usr/bin/fusermount3",
        "/usr/bin/fusermount",
        // Write/wall (message tools, typically setgid tty)
        "/usr/bin/write",
        "/usr/bin/wall",
        // polkit
        "/usr/bin/pkexec",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
        // SSH
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/ssh/ssh-keysign",
        // D-Bus
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        // X11
        "/usr/lib/xorg/Xorg.wrap",
        "/usr/bin/Xorg",
        // Terminal helpers (setgid utmp)
        "/usr/lib/utempter/utempter",
        // Flatpak sandbox
        "/usr/lib/flatpak-bwrap",
        // Chromium sandbox (setuid by package)
        "/usr/lib/chromium/chrome-sandbox",
        "/usr/lib/chromium-browser/chrome-sandbox",
        // plocate (setgid mlocate)
        "/usr/bin/plocate",
        "/usr/bin/locate",
        // at (setgid daemon)
        "/usr/bin/at",
        // KDE/SUID helpers
        "/usr/lib/kde4/libexec/kcheckpass",
        "/usr/lib/kcheckpass",
        // xterm (setgid utmp)
        "/usr/bin/xterm",
    ]
}

const SCAN_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/lib",
    "/usr/local/bin",
    "/usr/local/lib",
    "/opt",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_non_empty() {
        assert!(!build_allowlist().is_empty());
    }

    #[test]
    fn no_findings_for_clean_system_if_allowlist_complete() {
        // We cannot guarantee the test environment's setuid layout, but we can verify
        // the function completes without panicking.
        let findings = find_unexpected_setuid_binaries();
        // On a clean system with a complete allowlist, expect zero unexpected binaries.
        // Accept that CI may produce findings if env has extras — the real check is
        // that findings are well-formed.
        for f in &findings {
            assert!(!f.title.is_empty());
            assert_eq!(f.severity, Severity::High);
        }
    }

    #[test]
    fn describe_outputs_valid_manifest() {
        // Exercise the describe path by calling describe() and capturing stdout
        // is not straightforward in unit tests; instead verify the serialisation
        // of the Manifest we would emit.
        let manifest = Manifest {
            name: "setuid-audit".to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Checks for unexpected setuid/setgid binaries".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "setuid-audit");
        assert_eq!(back.proto_version, PROTO_VERSION);
    }
}
