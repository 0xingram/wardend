// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use wardend_proto::{Manifest, ModuleReport, PROTO_VERSION, ScanRequest, ScanResult, Status};

use crate::{derive_status, error_result};

/// Discover plugin binaries in `dir`. A plugin binary is any executable file
/// whose name starts with `wardend-plugin-`.
#[must_use]
pub fn discover_plugins(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut plugins: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("wardend-plugin-") {
                return false;
            }
            let Ok(meta) = e.metadata() else {
                return false;
            };
            if !meta.is_file() {
                return false;
            }
            meta.permissions().mode() & 0o111 != 0
        })
        .map(|e| e.path())
        .collect();
    plugins.sort();
    plugins
}

/// Run a single plugin end-to-end: `--describe` handshake, send `ScanRequest`, read `ScanResult`.
/// On any error (timeout, bad protocol, version mismatch) returns an `Error`-status report.
pub async fn run_plugin(
    plugin_path: &Path,
    scan_id: &str,
    offline: bool,
    timeout: Duration,
) -> ModuleReport {
    match run_plugin_inner(plugin_path, scan_id, offline, timeout).await {
        Ok(result) => {
            let status = derive_status(&result.findings);
            ModuleReport { status, result }
        }
        Err(e) => {
            let module = plugin_path.file_name().map_or_else(
                || "unknown".to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            ModuleReport {
                status: Status::Error,
                result: error_result(&module, scan_id, &e.to_string()),
            }
        }
    }
}

async fn run_plugin_inner(
    plugin_path: &Path,
    scan_id: &str,
    offline: bool,
    timeout: Duration,
) -> Result<ScanResult> {
    let manifest = describe_plugin(plugin_path, timeout).await?;

    if manifest.proto_version != PROTO_VERSION {
        bail!(
            "plugin '{}' has proto_version {} but core requires {}",
            manifest.name,
            manifest.proto_version,
            PROTO_VERSION
        );
    }

    let request = ScanRequest {
        scan_id: scan_id.to_string(),
        module: manifest.name.clone(),
        config: serde_json::Value::Null,
        offline,
    };
    let request_json = serde_json::to_string(&request).context("serialising ScanRequest")?;

    let output = tokio::time::timeout(timeout, spawn_plugin_scan(plugin_path, &request_json)).await;

    match output {
        Err(_elapsed) => bail!("plugin '{}' timed out", manifest.name),
        Ok(Err(e)) => Err(e),
        Ok(Ok(stdout)) => {
            let result: ScanResult = serde_json::from_str(stdout.trim())
                .with_context(|| format!("parsing ScanResult from plugin '{}'", manifest.name))?;
            Ok(result)
        }
    }
}

async fn describe_plugin(plugin_path: &Path, timeout: Duration) -> Result<Manifest> {
    let output = tokio::time::timeout(timeout, async {
        Command::new(plugin_path)
            .arg("--describe")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .context("spawning plugin --describe")
    })
    .await;

    let out = match output {
        Err(_) => bail!("plugin --describe timed out"),
        Ok(r) => r?,
    };

    if !out.status.success() {
        bail!(
            "plugin --describe exited with status {}",
            out.status.code().unwrap_or(-1)
        );
    }

    let json = std::str::from_utf8(&out.stdout).context("plugin --describe output is not UTF-8")?;
    serde_json::from_str(json.trim()).context("parsing Manifest from plugin --describe")
}

async fn spawn_plugin_scan(plugin_path: &Path, request_json: &str) -> Result<String> {
    let mut child = Command::new(plugin_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning plugin for scan")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{request_json}\n").as_bytes())
            .await
            .context("writing ScanRequest to plugin stdin")?;
    }

    let out = child
        .wait_with_output()
        .await
        .context("waiting for plugin output")?;

    if !out.status.success() {
        bail!(
            "plugin exited with status {}",
            out.status.code().unwrap_or(-1)
        );
    }

    String::from_utf8(out.stdout).context("plugin stdout is not UTF-8")
}
