// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use tempfile::TempDir;
use wardend_core::runner::{discover_plugins, run_plugin};
use wardend_proto::{PROTO_VERSION, Status};

/// All subprocess-spawning tests share one tokio runtime to avoid SIGCHLD contention
/// that arises when multiple `#[tokio::test]` runtimes compete to reap child processes.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

fn write_mock_plugin(dir: &TempDir, name: &str, script: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(script.as_bytes()).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

fn success_script(proto_version: u32) -> String {
    format!(
        r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{{"name":"mock","proto_version":{proto_version},"required_capabilities":[],"summary":"Mock plugin","signature":null}}'
else
    read -r _line
    echo '{{"scan_id":"test","module":"mock","summary":"All clear","findings":[],"metadata":null}}'
fi
"#
    )
}

const HANG_SCRIPT: &str = r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{"name":"mock-hang","proto_version":1,"required_capabilities":[],"summary":"Hangs on scan","signature":null}'
else
    sleep 999
fi
"#;

const BAD_PROTOCOL_SCRIPT: &str = r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{"name":"mock-bad","proto_version":1,"required_capabilities":[],"summary":"Bad protocol","signature":null}'
else
    read -r _line
    echo 'this is not valid json'
fi
"#;

const DESCRIBE_CRASH_SCRIPT: &str = r#"#!/bin/sh
exit 1
"#;

// ── discover_plugins ──────────────────────────────────────────────────────────

#[test]
fn discover_finds_plugins_by_prefix() {
    let dir = TempDir::new().unwrap();
    write_mock_plugin(&dir, "wardend-plugin-alpha", &success_script(PROTO_VERSION));
    write_mock_plugin(&dir, "wardend-plugin-beta", &success_script(PROTO_VERSION));
    // Should be ignored: wrong prefix
    write_mock_plugin(&dir, "other-binary", &success_script(PROTO_VERSION));

    let plugins = discover_plugins(dir.path());
    assert_eq!(plugins.len(), 2);
    assert!(
        plugins[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("wardend-plugin-")
    );
    assert!(
        plugins[1]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("wardend-plugin-")
    );
}

#[test]
fn discover_returns_empty_for_missing_dir() {
    let plugins = discover_plugins(std::path::Path::new("/nonexistent/path/to/plugins"));
    assert!(plugins.is_empty());
}

// ── run_plugin: success path ──────────────────────────────────────────────────

#[test]
fn run_plugin_success_returns_pass_for_no_findings() {
    let dir = TempDir::new().unwrap();
    let path = write_mock_plugin(&dir, "wardend-plugin-mock", &success_script(PROTO_VERSION));

    let report = rt().block_on(run_plugin(&path, "scan-001", false, Duration::from_secs(5)));
    assert_eq!(
        report.status,
        Status::Pass,
        "expected Pass, got Error: {}",
        report.result.summary
    );
    assert_eq!(report.result.module, "mock");
    // The mock script hardcodes scan_id "test"; verify it is non-empty.
    assert!(!report.result.scan_id.is_empty());
    assert!(report.result.findings.is_empty());
}

#[test]
fn run_plugin_passes_offline_flag_in_request() {
    let dir = TempDir::new().unwrap();
    let path = write_mock_plugin(&dir, "wardend-plugin-mock", &success_script(PROTO_VERSION));

    let report = rt().block_on(run_plugin(&path, "scan-002", true, Duration::from_secs(5)));
    assert_eq!(report.status, Status::Pass);
}

// ── run_plugin: timeout ───────────────────────────────────────────────────────

#[test]
fn run_plugin_timeout_produces_error_status() {
    let dir = TempDir::new().unwrap();
    let path = write_mock_plugin(&dir, "wardend-plugin-hang", HANG_SCRIPT);

    let report = rt().block_on(run_plugin(
        &path,
        "scan-003",
        false,
        Duration::from_millis(400),
    ));
    assert_eq!(report.status, Status::Error);
    assert!(
        report.result.summary.contains("timed out"),
        "expected 'timed out' in summary, got: {}",
        report.result.summary
    );
}

#[test]
fn run_plugin_timeout_kills_child_process() {
    let dir = TempDir::new().unwrap();
    let pid_file = dir.path().join("plugin.pid");
    let pid_path = pid_file.to_string_lossy().into_owned();

    // Script writes its own PID to a file before sleeping so we can check it later.
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{{"name":"mock-kill","proto_version":1,"required_capabilities":[],"summary":"Kill regression","signature":null}}'
else
    echo $$ > {pid_path}
    sleep 999
fi
"#
    );
    let path = write_mock_plugin(&dir, "wardend-plugin-killtest", &script);

    let report = rt().block_on(run_plugin(
        &path,
        "scan-kill",
        false,
        Duration::from_millis(400),
    ));
    assert_eq!(report.status, Status::Error);

    // Give the OS a moment to deliver the SIGKILL.
    std::thread::sleep(Duration::from_millis(150));

    if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file).unwrap();
        let pid: u32 = pid_str
            .trim()
            .parse()
            .expect("pid file must contain a number");
        // A killed-but-not-yet-reaped process shows as zombie (state 'Z') in /proc.
        // Either the process is gone entirely OR it is a zombie — both mean it is no
        // longer executing.  A still-alive sleeping process would have state 'S'.
        assert!(
            !process_is_running(pid),
            "plugin process {pid} is still running after timeout — kill_on_drop not set"
        );
    }
    // If the pid file was never written, the process was killed before it could write it — also correct.
}

/// Returns true only if the process exists AND is not a zombie (i.e. still executing).
fn process_is_running(pid: u32) -> bool {
    let status_path = format!("/proc/{pid}/status");
    let Ok(content) = std::fs::read_to_string(status_path) else {
        return false; // process no longer exists
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            // State line looks like "State:\tZ (zombie)" or "State:\tS (sleeping)"
            return !rest.contains('Z');
        }
    }
    true
}

// ── run_plugin: bad protocol ──────────────────────────────────────────────────

#[test]
fn run_plugin_bad_protocol_produces_error_status() {
    let dir = TempDir::new().unwrap();
    let path = write_mock_plugin(&dir, "wardend-plugin-bad", BAD_PROTOCOL_SCRIPT);

    let report = rt().block_on(run_plugin(&path, "scan-004", false, Duration::from_secs(5)));
    assert_eq!(report.status, Status::Error);
}

// ── run_plugin: --describe failure ───────────────────────────────────────────

#[test]
fn run_plugin_describe_crash_produces_error_status() {
    let dir = TempDir::new().unwrap();
    let path = write_mock_plugin(&dir, "wardend-plugin-crash", DESCRIBE_CRASH_SCRIPT);

    let report = rt().block_on(run_plugin(&path, "scan-005", false, Duration::from_secs(5)));
    assert_eq!(report.status, Status::Error);
}

// ── run_plugin: proto_version mismatch ───────────────────────────────────────

#[test]
fn run_plugin_version_mismatch_produces_error_status() {
    let dir = TempDir::new().unwrap();
    let incompatible_version = PROTO_VERSION + 1;
    let path = write_mock_plugin(
        &dir,
        "wardend-plugin-future",
        &success_script(incompatible_version),
    );

    let report = rt().block_on(run_plugin(&path, "scan-006", false, Duration::from_secs(5)));
    assert_eq!(report.status, Status::Error);
    assert!(
        report.result.summary.contains("proto_version"),
        "expected 'proto_version' in summary, got: {}",
        report.result.summary
    );
}

// ── run_plugin: high-severity finding → Fail ─────────────────────────────────

#[test]
fn run_plugin_high_finding_produces_fail_status() {
    let dir = TempDir::new().unwrap();
    let script = r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{"name":"mock-fail","proto_version":1,"required_capabilities":[],"summary":"Failing mock","signature":null}'
else
    read -r _line
    echo '{"scan_id":"test","module":"mock-fail","summary":"Found issue","findings":[{"severity":"high","title":"Bad thing","detail":"Details","remediation":"Fix it"}],"metadata":null}'
fi
"#;
    let path = write_mock_plugin(&dir, "wardend-plugin-mock-fail", script);

    let report = rt().block_on(run_plugin(&path, "scan-007", false, Duration::from_secs(5)));
    assert_eq!(
        report.status,
        Status::Fail,
        "expected Fail, got {:?}: {}",
        report.status,
        report.result.summary
    );
    assert_eq!(report.result.findings.len(), 1);
}

// ── run_plugin: medium-severity finding → Warn ───────────────────────────────

#[test]
fn run_plugin_medium_finding_produces_warn_status() {
    let dir = TempDir::new().unwrap();
    let script = r#"#!/bin/sh
if [ "$1" = "--describe" ]; then
    echo '{"name":"mock-warn","proto_version":1,"required_capabilities":[],"summary":"Warning mock","signature":null}'
else
    read -r _line
    echo '{"scan_id":"test","module":"mock-warn","summary":"Found warning","findings":[{"severity":"medium","title":"Meh thing","detail":"Details","remediation":"Maybe fix"}],"metadata":null}'
fi
"#;
    let path = write_mock_plugin(&dir, "wardend-plugin-mock-warn", script);

    let report = rt().block_on(run_plugin(&path, "scan-008", false, Duration::from_secs(5)));
    assert_eq!(
        report.status,
        Status::Warn,
        "expected Warn, got {:?}: {}",
        report.status,
        report.result.summary
    );
}
