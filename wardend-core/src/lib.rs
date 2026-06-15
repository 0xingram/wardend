// SPDX-License-Identifier: GPL-3.0-or-later

pub mod runner;
pub mod status;

pub use runner::{discover_plugins, run_plugin};
pub use status::derive_status;
use wardend_proto::{ModuleReport, ScanResult, Status};

/// Run every discovered plugin and return one `ModuleReport` per module.
pub async fn run_scan(plugin_dir: &std::path::Path, offline: bool) -> Vec<ModuleReport> {
    use std::time::Duration;
    use tokio::task::JoinSet;
    use uuid::Uuid;

    let scan_id = Uuid::new_v4().to_string();
    let plugins = discover_plugins(plugin_dir);

    if plugins.is_empty() {
        return vec![];
    }

    let mut set: JoinSet<ModuleReport> = JoinSet::new();

    for plugin_path in plugins {
        let id = scan_id.clone();
        set.spawn(async move {
            runner::run_plugin(&plugin_path, &id, offline, Duration::from_secs(30)).await
        });
    }

    let mut reports = Vec::new();
    while let Some(result) = set.join_next().await {
        match result {
            Ok(report) => reports.push(report),
            Err(e) => {
                reports.push(ModuleReport {
                    status: Status::Error,
                    result: error_result("unknown", &scan_id, &e.to_string()),
                });
            }
        }
    }
    reports
}

pub(crate) fn error_result(module: &str, scan_id: &str, message: &str) -> ScanResult {
    ScanResult {
        scan_id: scan_id.to_string(),
        module: module.to_string(),
        summary: format!("Plugin error: {message}"),
        findings: vec![],
        metadata: serde_json::Value::Null,
    }
}
