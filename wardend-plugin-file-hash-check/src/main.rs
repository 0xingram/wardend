// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

const MODULE_NAME: &str = "file-hash-check";
const MB_API_URL: &str = "https://mb-api.abuse.ch/api/v1/";
const MB_CACHE_FILE: &str = "mb-hashes.json";

// Local mirror of `wardend_core::feeds::MalwareHashInfo` — keep in sync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MalwareHashInfo {
    sha256: String,
    malware_name: String,
}

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
            "Hashes configured paths and checks SHA-256 against MalwareBazaar (hash-only outbound)"
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

    let feed_dir = resolve_feed_dir(&request);
    let paths = collect_paths(&request);

    let mut findings = Vec::new();
    let mut hashed_count: usize = 0;

    for path in &paths {
        let p = Path::new(path);

        if !p.exists() {
            findings.push(Finding {
                severity: Severity::Info,
                title: format!("file-hash-check: path not found — {path}"),
                detail: format!("The configured path '{path}' does not exist on this system."),
                remediation: "Remove it from the scan configuration if it is no longer relevant."
                    .to_string(),
            });
            continue;
        }

        let sha256 = match sha256_hex(p) {
            Ok(h) => h,
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Info,
                    title: format!("file-hash-check: could not hash '{path}'"),
                    detail: format!("Hash failed: {e:#}"),
                    remediation: "Check file permissions.".to_string(),
                });
                continue;
            }
        };

        hashed_count += 1;

        match lookup_hash(&sha256, &feed_dir, request.offline) {
            Ok(Some(hit)) => {
                findings.push(Finding {
                    severity: Severity::Critical,
                    title: format!(
                        "Known malware detected: {} ({sha256:.16}…)",
                        hit.malware_name
                    ),
                    detail: format!(
                        "The file '{path}' has SHA-256 {sha256} which matches \
                         MalwareBazaar entry '{}'. This file is a known malicious sample.",
                        hit.malware_name
                    ),
                    remediation: format!(
                        "Quarantine or delete '{path}' immediately and investigate how it arrived \
                         on this system."
                    ),
                });
            }
            Ok(None) => {}
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Info,
                    title: format!("file-hash-check: lookup failed for '{path}'"),
                    detail: format!("MalwareBazaar lookup error: {e:#}"),
                    remediation:
                        "Check network connectivity or run with --offline to skip lookups."
                            .to_string(),
                });
            }
        }
    }

    let summary = build_summary(hashed_count, &findings);

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

// config["feed_dir"] → WARDEND_FEED_DIR env → default
fn resolve_feed_dir(request: &ScanRequest) -> PathBuf {
    if let Some(dir) = request.config.get("feed_dir").and_then(|v| v.as_str()) {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("WARDEND_FEED_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("/var/lib/wardend/feeds")
}

fn collect_paths(request: &ScanRequest) -> Vec<String> {
    request
        .config
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn sha256_hex(path: &Path) -> Result<String> {
    use std::fmt::Write as _;
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536].into_boxed_slice();
    loop {
        let n = file.read(&mut buf).context("reading file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in &hash {
        write!(hex, "{b:02x}").expect("write to String is infallible");
    }
    Ok(hex)
}

// Check the local cache first. If not cached and not offline, query the MB API
// (hash only outbound — ADR-008) and cache positive hits.
fn lookup_hash(sha256: &str, feed_dir: &Path, offline: bool) -> Result<Option<MalwareHashInfo>> {
    let mut cached = load_mb_cache(feed_dir).unwrap_or_default();

    if let Some(hit) = cached.iter().find(|e| e.sha256 == sha256) {
        return Ok(Some(hit.clone()));
    }

    if offline {
        return Ok(None);
    }

    let body = serde_json::json!({"query": "get_info", "hash": sha256}).to_string();
    let response_bytes = ureq::post(MB_API_URL)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .with_context(|| format!("POST to MalwareBazaar for hash {sha256:.16}…"))?;

    let mut bytes = Vec::new();
    response_bytes
        .into_reader()
        .read_to_end(&mut bytes)
        .context("reading MalwareBazaar response")?;

    let json: serde_json::Value =
        serde_json::from_slice(&bytes).context("parsing MalwareBazaar response")?;

    if let Some(hit) = parse_mb_hit(&json, sha256) {
        cached.push(hit.clone());
        let _ = write_mb_cache(feed_dir, &cached);
        return Ok(Some(hit));
    }

    Ok(None)
}

fn load_mb_cache(feed_dir: &Path) -> Result<Vec<MalwareHashInfo>> {
    let path = feed_dir.join(MB_CACHE_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read(&path).context("reading MB cache")?;
    serde_json::from_slice(&data).context("parsing MB cache")
}

fn write_mb_cache(feed_dir: &Path, hits: &[MalwareHashInfo]) -> Result<()> {
    std::fs::create_dir_all(feed_dir)
        .with_context(|| format!("creating {}", feed_dir.display()))?;
    let path = feed_dir.join(MB_CACHE_FILE);
    let json = serde_json::to_vec(hits).context("serialising MB cache")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
}

fn parse_mb_hit(response: &serde_json::Value, sha256: &str) -> Option<MalwareHashInfo> {
    let status = response["query_status"].as_str()?;
    if matches!(status, "hash_not_found" | "no_results") {
        return None;
    }

    let data = response["data"].as_array()?.first()?;
    let malware_name = data["signature"].as_str().unwrap_or("unknown").to_string();

    Some(MalwareHashInfo {
        sha256: sha256.to_string(),
        malware_name,
    })
}

fn build_summary(hashed_count: usize, findings: &[Finding]) -> String {
    let malware_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();

    if malware_count > 0 {
        format!(
            "Hashed {hashed_count} file(s): {malware_count} known malware hit(s) — immediate action required"
        )
    } else if hashed_count == 0 {
        "No paths configured for file-hash-check.".to_string()
    } else {
        format!("Hashed {hashed_count} file(s): no known malware detected.")
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use wardend_proto::{Finding, Manifest, PROTO_VERSION, ScanRequest, ScanResult, Severity};

    use super::{
        MB_CACHE_FILE, MODULE_NAME, MalwareHashInfo, build_summary, collect_paths, lookup_hash,
        sha256_hex,
    };

    // ── describe ──────────────────────────────────────────────────────────────

    #[test]
    fn describe_emits_valid_manifest() {
        let manifest = Manifest {
            name: MODULE_NAME.to_string(),
            proto_version: PROTO_VERSION,
            required_capabilities: vec![],
            summary: "Hashes configured paths and checks SHA-256 against MalwareBazaar (hash-only outbound)".to_string(),
            signature: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, MODULE_NAME);
        assert_eq!(back.proto_version, PROTO_VERSION);
    }

    // ── ADR-015 ───────────────────────────────────────────────────────────────

    #[test]
    fn scan_result_wire_has_no_status_field() {
        let result = ScanResult {
            scan_id: "t1".to_string(),
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

    // ── sha256_hex ────────────────────────────────────────────────────────────

    #[test]
    fn sha256_of_known_content() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let hex = sha256_hex(&path).unwrap();
        assert_eq!(
            hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // ── lookup_hash (cache path) ──────────────────────────────────────────────

    #[test]
    fn cached_hit_is_returned_offline() {
        let dir = TempDir::new().unwrap();
        let sha256 = "cafebabe0000";

        let hits = vec![MalwareHashInfo {
            sha256: sha256.to_string(),
            malware_name: "Trojan.Test".to_string(),
        }];
        std::fs::write(
            dir.path().join(MB_CACHE_FILE),
            serde_json::to_vec(&hits).unwrap(),
        )
        .unwrap();

        let result = lookup_hash(sha256, dir.path(), true).unwrap();
        assert!(result.is_some(), "cached hit must be returned even offline");
        assert_eq!(result.unwrap().malware_name, "Trojan.Test");
    }

    #[test]
    fn offline_unknown_hash_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = lookup_hash("unknown_sha256", dir.path(), true).unwrap();
        assert!(result.is_none(), "unknown hash offline must return None");
    }

    // ── collect_paths ─────────────────────────────────────────────────────────

    #[test]
    fn collect_paths_from_config() {
        let request = ScanRequest {
            scan_id: "t".to_string(),
            module: MODULE_NAME.to_string(),
            config: serde_json::json!({"paths": ["/etc/passwd", "/usr/bin/ls"]}),
            offline: false,
        };
        let paths = collect_paths(&request);
        assert_eq!(paths, vec!["/etc/passwd", "/usr/bin/ls"]);
    }

    #[test]
    fn collect_paths_empty_when_not_configured() {
        let request = ScanRequest {
            scan_id: "t".to_string(),
            module: MODULE_NAME.to_string(),
            config: serde_json::Value::Null,
            offline: false,
        };
        let paths = collect_paths(&request);
        assert!(paths.is_empty());
    }

    // ── build_summary ─────────────────────────────────────────────────────────

    #[test]
    fn summary_no_paths() {
        let s = build_summary(0, &[]);
        assert!(s.contains("No paths"), "got: {s}");
    }

    #[test]
    fn summary_clean() {
        let s = build_summary(3, &[]);
        assert!(s.contains("3"), "count must appear; got: {s}");
        assert!(s.contains("no known malware"), "got: {s}");
    }

    #[test]
    fn summary_malware_hit() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            title: "malware".to_string(),
            detail: "d".to_string(),
            remediation: "r".to_string(),
        }];
        let s = build_summary(1, &findings);
        assert!(s.contains("malware"), "got: {s}");
    }

    // ── full pipeline: file + cached hit ─────────────────────────────────────

    #[test]
    fn malicious_file_produces_critical_finding() {
        let dir = TempDir::new().unwrap();

        // Write a "malicious" file.
        let file_path = dir.path().join("suspicious.bin");
        std::fs::write(&file_path, b"evil payload").unwrap();
        let sha = sha256_hex(&file_path).unwrap();

        // Pre-populate MB cache with that hash.
        let hits = vec![MalwareHashInfo {
            sha256: sha.clone(),
            malware_name: "Evil.Payload".to_string(),
        }];
        let feed_dir = dir.path().join("feeds");
        std::fs::create_dir_all(&feed_dir).unwrap();
        std::fs::write(
            feed_dir.join(MB_CACHE_FILE),
            serde_json::to_vec(&hits).unwrap(),
        )
        .unwrap();

        let result = lookup_hash(&sha, &feed_dir, true).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().malware_name, "Evil.Payload");
    }
}
