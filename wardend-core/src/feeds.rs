// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use wardend_proto::Severity;

pub const NVD_CACHE_FILE: &str = "nvd-cve.json";
pub const MB_CACHE_FILE: &str = "mb-hashes.json";
pub const NVD_FEED_URL: &str =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=0";
pub const MB_API_URL: &str = "https://mb-api.abuse.ch/api/v1/";

/// A single CVE entry in the local feed cache.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    /// Affected package names (Arch/CPE product names).
    pub packages: Vec<String>,
    pub severity: Severity,
    pub score: f64,
    pub description: String,
}

/// A positive `MalwareBazaar` hash hit, stored in the local cache.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MalwareHashInfo {
    pub sha256: String,
    pub malware_name: String,
}

// Trait for fetching remote resources — inject a mock in tests.
pub trait FeedFetcher: Send + Sync {
    /// # Errors
    /// Returns an error if the HTTP request fails or the response body can't be read.
    fn get_bytes(&self, url: &str) -> Result<Vec<u8>>;
    /// # Errors
    /// Returns an error if the HTTP request fails or the response body can't be read.
    fn post_bytes(&self, url: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// Production HTTP fetcher backed by ureq.
pub struct UreqFetcher;

impl FeedFetcher for UreqFetcher {
    fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = ureq::get(url)
            .call()
            .with_context(|| format!("GET {url}"))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading body for {url}"))?;
        Ok(bytes)
    }

    fn post_bytes(&self, url: &str, body: &[u8]) -> Result<Vec<u8>> {
        let response = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_bytes(body)
            .with_context(|| format!("POST {url}"))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading body for {url}"))?;
        Ok(bytes)
    }
}

// Manages local feed caches and network fetching.
// In tests, construct with `with_fetcher` to inject a mock.
pub struct FeedManager {
    cache_dir: PathBuf,
    offline: bool,
    fetcher: Box<dyn FeedFetcher>,
}

impl FeedManager {
    #[must_use]
    pub fn new(cache_dir: PathBuf, offline: bool) -> Self {
        Self {
            cache_dir,
            offline,
            fetcher: Box::new(UreqFetcher),
        }
    }

    #[must_use]
    pub fn with_fetcher(cache_dir: PathBuf, offline: bool, fetcher: Box<dyn FeedFetcher>) -> Self {
        Self {
            cache_dir,
            offline,
            fetcher,
        }
    }

    #[must_use]
    pub fn nvd_cache_path(&self) -> PathBuf {
        self.cache_dir.join(NVD_CACHE_FILE)
    }

    #[must_use]
    pub fn mb_cache_path(&self) -> PathBuf {
        self.cache_dir.join(MB_CACHE_FILE)
    }

    /// # Errors
    /// Returns an error if the cache is missing and `--offline` is set, or if I/O fails.
    pub fn load_nvd_feed(&self) -> Result<Vec<CveEntry>> {
        let cache = self.nvd_cache_path();
        if cache.exists() {
            let data =
                std::fs::read(&cache).with_context(|| format!("reading {}", cache.display()))?;
            return serde_json::from_slice(&data).context("parsing NVD cache");
        }

        if self.offline {
            bail!(
                "NVD feed not cached at {}; run without --offline to fetch it",
                cache.display()
            );
        }

        self.fetch_and_cache_nvd()
    }

    /// # Errors
    /// Returns an error if `--offline` is set, the HTTP fetch fails, or caching fails.
    pub fn fetch_and_cache_nvd(&self) -> Result<Vec<CveEntry>> {
        if self.offline {
            bail!("--offline: cannot fetch NVD feed");
        }

        let bytes = self
            .fetcher
            .get_bytes(NVD_FEED_URL)
            .context("fetching NVD CVE feed")?;

        let entries = parse_nvd_response(&bytes).context("parsing NVD response")?;
        write_json_cache(&self.nvd_cache_path(), &entries)?;
        Ok(entries)
    }

    /// # Errors
    /// Returns an error if the HTTP request fails or the response can't be parsed.
    // Returns `None` if the hash is unknown or `--offline` and not cached.
    pub fn malwarebazaar_lookup(&self, sha256: &str) -> Result<Option<MalwareHashInfo>> {
        // Check local cache first (available offline too).
        let mut cached_hits = self.load_mb_cache().unwrap_or_default();
        if let Some(hit) = cached_hits.iter().find(|e| e.sha256 == sha256) {
            return Ok(Some(hit.clone()));
        }

        if self.offline {
            return Ok(None);
        }

        let body = serde_json::json!({"query": "get_info", "hash": sha256}).to_string();
        let bytes = self
            .fetcher
            .post_bytes(MB_API_URL, body.as_bytes())
            .context("MalwareBazaar hash lookup")?;

        let response: serde_json::Value =
            serde_json::from_slice(&bytes).context("parsing MalwareBazaar response")?;

        if let Some(hit) = parse_mb_response(&response, sha256) {
            cached_hits.push(hit.clone());
            let _ = write_json_cache(&self.mb_cache_path(), &cached_hits);
            return Ok(Some(hit));
        }

        Ok(None)
    }

    /// Fetch all feeds, printing progress to stderr. Returns any errors encountered.
    /// Called by `wardend-core feeds update` (run as root by the systemd timer).
    #[must_use]
    pub fn update_all(&self) -> Vec<anyhow::Error> {
        let mut errors = Vec::new();

        eprintln!("Updating NVD CVE feed...");
        match self.fetch_and_cache_nvd() {
            Ok(entries) => eprintln!("  NVD: {} entries cached.", entries.len()),
            Err(e) => {
                eprintln!("  NVD update failed: {e}");
                errors.push(e);
            }
        }

        errors
    }

    fn load_mb_cache(&self) -> Result<Vec<MalwareHashInfo>> {
        let path = self.mb_cache_path();
        if !path.exists() {
            return Ok(vec![]);
        }
        let data = std::fs::read(&path).context("reading MB cache")?;
        serde_json::from_slice(&data).context("parsing MB cache")
    }
}

fn write_json_cache<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_vec(data).context("serialising cache")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

/// # Errors
/// Returns an error if the JSON is malformed or missing the `vulnerabilities` array.
// Entries without any CPE product matches are skipped.
pub fn parse_nvd_response(bytes: &[u8]) -> Result<Vec<CveEntry>> {
    let response: serde_json::Value = serde_json::from_slice(bytes).context("parsing NVD JSON")?;

    let vulnerabilities = response["vulnerabilities"]
        .as_array()
        .context("NVD response missing 'vulnerabilities' array")?;

    let mut entries = Vec::new();

    for vuln in vulnerabilities {
        let cve = &vuln["cve"];

        let id = match cve["id"].as_str().filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        let description = cve["descriptions"]
            .as_array()
            .and_then(|arr| arr.iter().find(|d| d["lang"].as_str() == Some("en")))
            .and_then(|d| d["value"].as_str())
            .unwrap_or("")
            .to_string();

        let (severity, score) = extract_cvss(cve);
        let packages = extract_cpe_products(cve);

        if packages.is_empty() {
            continue;
        }

        entries.push(CveEntry {
            id,
            packages,
            severity,
            score,
            description,
        });
    }

    Ok(entries)
}

fn extract_cvss(cve: &serde_json::Value) -> (Severity, f64) {
    let metrics = &cve["metrics"];

    for key in ["cvssMetricV31", "cvssMetricV30"] {
        if let Some(arr) = metrics[key].as_array()
            && let Some(score) = arr
                .first()
                .and_then(|e| e["cvssData"]["baseScore"].as_f64())
        {
            return (score_to_severity(score), score);
        }
    }

    if let Some(score) = metrics["cvssMetricV2"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["cvssData"]["baseScore"].as_f64())
    {
        return (score_to_severity(score), score);
    }

    (Severity::Info, 0.0)
}

fn score_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn extract_cpe_products(cve: &serde_json::Value) -> Vec<String> {
    let mut products = Vec::new();

    let Some(configs) = cve["configurations"].as_array() else {
        return products;
    };

    for config in configs {
        let Some(nodes) = config["nodes"].as_array() else {
            continue;
        };
        for node in nodes {
            let Some(matches) = node["cpeMatch"].as_array() else {
                continue;
            };
            for m in matches {
                if let Some(product) = m["criteria"].as_str().and_then(cpe_product)
                    && !products.contains(&product)
                {
                    products.push(product);
                }
            }
        }
    }

    products
}

/// Extract the product name from a CPE 2.3 string.
/// `cpe:2.3:a:vendor:product:version:...` → `product`
fn cpe_product(cpe: &str) -> Option<String> {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 5 {
        let product = parts[4];
        if product != "*" && product != "-" {
            return Some(product.to_string());
        }
    }
    None
}

fn parse_mb_response(response: &serde_json::Value, sha256: &str) -> Option<MalwareHashInfo> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use super::*;

    // ── Mock fetcher ──────────────────────────────────────────────────────────

    struct MockFetcher {
        call_count: Arc<AtomicUsize>,
        get_response: Vec<u8>,
        post_response: Vec<u8>,
    }

    impl FeedFetcher for MockFetcher {
        fn get_bytes(&self, _url: &str) -> Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.get_response.clone())
        }

        fn post_bytes(&self, _url: &str, _body: &[u8]) -> Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.post_response.clone())
        }
    }

    /// Minimal valid NVD 2.0 API JSON — one CVE for openssl, CVSS 8.8.
    fn nvd_api_response_bytes() -> Vec<u8> {
        serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "OpenSSL heap overflow"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]
                    },
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "criteria": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
                            }]
                        }]
                    }]
                }
            }]
        })
        .to_string()
        .into_bytes()
    }

    fn mb_hit_response(_sha256: &str) -> Vec<u8> {
        serde_json::json!({
            "query_status": "ok",
            "data": [{"signature": "TestMalware.A", "file_type": "exe"}]
        })
        .to_string()
        .into_bytes()
    }

    // ── NVD feed manager tests ────────────────────────────────────────────────

    #[test]
    fn offline_with_cache_does_not_call_fetcher() {
        let dir = TempDir::new().unwrap();

        // Pre-populate cache.
        let cached: Vec<CveEntry> = vec![CveEntry {
            id: "CVE-2024-0001".to_string(),
            packages: vec!["cached-pkg".to_string()],
            severity: Severity::Low,
            score: 2.0,
            description: "cached".to_string(),
        }];
        std::fs::write(
            dir.path().join(NVD_CACHE_FILE),
            serde_json::to_vec(&cached).unwrap(),
        )
        .unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            true, // --offline
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: vec![],
                post_response: vec![],
            }),
        );

        let entries = mgr.load_nvd_feed().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "fetcher must not be called when --offline and cache exists"
        );
    }

    #[test]
    fn offline_without_cache_returns_error() {
        let dir = TempDir::new().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            true, // --offline
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: vec![],
                post_response: vec![],
            }),
        );

        let result = mgr.load_nvd_feed();
        assert!(result.is_err(), "should error: offline + no cache");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "fetcher must never be called in offline mode"
        );
    }

    #[test]
    fn online_fetch_parses_and_caches() {
        let dir = TempDir::new().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            false, // online
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: nvd_api_response_bytes(),
                post_response: vec![],
            }),
        );

        let entries = mgr.fetch_and_cache_nvd().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "CVE-2024-1234");
        assert_eq!(entries[0].severity, Severity::High);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert!(
            dir.path().join(NVD_CACHE_FILE).exists(),
            "cache file must be written"
        );
    }

    #[test]
    fn second_load_uses_cache_not_fetcher() {
        let dir = TempDir::new().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            false,
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: nvd_api_response_bytes(),
                post_response: vec![],
            }),
        );

        mgr.fetch_and_cache_nvd().unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second load — should hit cache, not fetcher.
        mgr.load_nvd_feed().unwrap();
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "second load must use cache"
        );
    }

    // ── MalwareBazaar tests ───────────────────────────────────────────────────

    #[test]
    fn mb_offline_returns_none_when_not_cached() {
        let dir = TempDir::new().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            true, // offline
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: vec![],
                post_response: vec![],
            }),
        );

        let result = mgr.malwarebazaar_lookup("deadbeef").unwrap();
        assert!(result.is_none());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "no network in offline mode"
        );
    }

    #[test]
    fn mb_lookup_caches_positive_hit() {
        let dir = TempDir::new().unwrap();
        let sha256 = "badc0ffee0ddf00d";
        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            false,
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: vec![],
                post_response: mb_hit_response(sha256),
            }),
        );

        let result = mgr.malwarebazaar_lookup(sha256).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().malware_name, "TestMalware.A");
        assert!(
            dir.path().join(MB_CACHE_FILE).exists(),
            "positive hit must be cached"
        );
    }

    #[test]
    fn mb_offline_returns_cached_hit() {
        let dir = TempDir::new().unwrap();
        let sha256 = "cafef00d";

        let hits = vec![MalwareHashInfo {
            sha256: sha256.to_string(),
            malware_name: "CachedMalware".to_string(),
        }];
        std::fs::write(
            dir.path().join(MB_CACHE_FILE),
            serde_json::to_vec(&hits).unwrap(),
        )
        .unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let mgr = FeedManager::with_fetcher(
            dir.path().to_owned(),
            true, // offline
            Box::new(MockFetcher {
                call_count: Arc::clone(&call_count),
                get_response: vec![],
                post_response: vec![],
            }),
        );

        let result = mgr.malwarebazaar_lookup(sha256).unwrap();
        assert_eq!(result.unwrap().malware_name, "CachedMalware");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "cache hit must not trigger network"
        );
    }

    // ── parse_nvd_response unit tests ─────────────────────────────────────────

    #[test]
    fn parse_nvd_extracts_cve_entry() {
        let entries = parse_nvd_response(&nvd_api_response_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.id, "CVE-2024-1234");
        assert!(e.packages.contains(&"openssl".to_string()));
        assert_eq!(e.severity, Severity::High);
        assert!((e.score - 8.8).abs() < 0.01);
    }

    #[test]
    fn parse_nvd_skips_entry_without_cpe() {
        let bytes = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "no cpe"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                    "configurations": []
                }
            }]
        })
        .to_string()
        .into_bytes();

        let entries = parse_nvd_response(&bytes).unwrap();
        assert!(entries.is_empty(), "entry without CPE must be skipped");
    }

    // ── score → severity ladder ───────────────────────────────────────────────

    #[test]
    fn score_to_severity_ladder() {
        assert_eq!(score_to_severity(9.5), Severity::Critical);
        assert_eq!(score_to_severity(9.0), Severity::Critical);
        assert_eq!(score_to_severity(8.9), Severity::High);
        assert_eq!(score_to_severity(7.0), Severity::High);
        assert_eq!(score_to_severity(6.9), Severity::Medium);
        assert_eq!(score_to_severity(4.0), Severity::Medium);
        assert_eq!(score_to_severity(3.9), Severity::Low);
        assert_eq!(score_to_severity(0.1), Severity::Low);
        assert_eq!(score_to_severity(0.0), Severity::Info);
    }

    // ── cpe_product ───────────────────────────────────────────────────────────

    #[test]
    fn cpe_product_extracts_product_name() {
        assert_eq!(
            cpe_product("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"),
            Some("openssl".to_string())
        );
    }

    #[test]
    fn cpe_product_skips_wildcard() {
        assert_eq!(cpe_product("cpe:2.3:a:vendor:*:1.0:*:*:*:*:*:*:*"), None);
    }
}
