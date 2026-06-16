// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PLUGIN_DIR: &str = "/usr/lib/wardend/plugins";
pub const DEFAULT_FEED_DIR: &str = "/var/lib/wardend/feeds";
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_CONFIG_PATH: &str = "/etc/wardend/config.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub plugin_dir: PathBuf,
    pub feed_dir: PathBuf,
    pub scan_timeout_secs: u64,
    /// Per-module config tables, keyed by module name.
    pub modules: HashMap<String, toml::Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            plugin_dir: PathBuf::from(DEFAULT_PLUGIN_DIR),
            feed_dir: PathBuf::from(DEFAULT_FEED_DIR),
            scan_timeout_secs: DEFAULT_SCAN_TIMEOUT_SECS,
            modules: HashMap::new(),
        }
    }
}

impl Config {
    /// Load config from `WARDEND_CONFIG` env var or `/etc/wardend/config.toml`.
    /// Missing file → silently use defaults.
    #[must_use]
    pub fn load() -> Self {
        let path = std::env::var("WARDEND_CONFIG")
            .map_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from);
        Self::from_file(&path)
    }

    /// Parse config from `path`. Missing file returns defaults; parse errors print a warning
    /// to stderr and return defaults.
    #[must_use]
    pub fn from_file(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: could not read config {}: {e}", path.display());
                return Self::default();
            }
        };
        match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("warning: config parse error in {}: {e}", path.display());
                Self::default()
            }
        }
    }

    /// Return the per-module config table as a `serde_json::Value` (for `ScanRequest.config`).
    /// Returns an empty object if the module is not configured.
    #[must_use]
    pub fn module_config(&self, module: &str) -> serde_json::Value {
        self.modules
            .get(module)
            .and_then(|v| serde_json::to_value(v).ok())
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn write_config(dir: &TempDir, content: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn missing_file_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("no-such.toml");
        let cfg = Config::from_file(&path);
        assert_eq!(cfg.plugin_dir, PathBuf::from(DEFAULT_PLUGIN_DIR));
        assert_eq!(cfg.feed_dir, PathBuf::from(DEFAULT_FEED_DIR));
        assert_eq!(cfg.scan_timeout_secs, DEFAULT_SCAN_TIMEOUT_SECS);
        assert!(cfg.modules.is_empty());
    }

    #[test]
    fn values_override_defaults() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
plugin_dir = "/tmp/plugins"
feed_dir   = "/tmp/feeds"
scan_timeout_secs = 60
"#,
        );
        let cfg = Config::from_file(&path);
        assert_eq!(cfg.plugin_dir, PathBuf::from("/tmp/plugins"));
        assert_eq!(cfg.feed_dir, PathBuf::from("/tmp/feeds"));
        assert_eq!(cfg.scan_timeout_secs, 60);
    }

    #[test]
    fn partial_override_keeps_defaults_for_missing_keys() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"scan_timeout_secs = 90"#);
        let cfg = Config::from_file(&path);
        assert_eq!(cfg.scan_timeout_secs, 90);
        assert_eq!(cfg.plugin_dir, PathBuf::from(DEFAULT_PLUGIN_DIR));
    }

    #[test]
    fn module_table_passes_through_to_json() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[modules.pkgbuild-audit]
max_findings = 10
allow_npm = false

[modules.cve-check]
min_score = 7.0
"#,
        );
        let cfg = Config::from_file(&path);

        let audit_cfg = cfg.module_config("pkgbuild-audit");
        assert_eq!(
            audit_cfg["max_findings"].as_i64(),
            Some(10),
            "module config should pass max_findings through"
        );
        assert_eq!(
            audit_cfg["allow_npm"].as_bool(),
            Some(false),
            "module config should pass allow_npm through"
        );

        let cve_cfg = cfg.module_config("cve-check");
        let min_score = cve_cfg["min_score"].as_f64().unwrap();
        assert!((min_score - 7.0).abs() < 0.001);
    }

    #[test]
    fn unconfigured_module_returns_empty_object() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "");
        let cfg = Config::from_file(&path);
        let v = cfg.module_config("not-a-module");
        assert!(
            v.is_object() && v.as_object().unwrap().is_empty(),
            "unconfigured module should return empty JSON object"
        );
    }

    #[test]
    fn invalid_toml_falls_back_to_defaults() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "this is not toml = = garbage");
        let cfg = Config::from_file(&path);
        assert_eq!(cfg.plugin_dir, PathBuf::from(DEFAULT_PLUGIN_DIR));
    }
}
