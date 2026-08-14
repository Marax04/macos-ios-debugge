// rustre-plugin-api/src/plugin_marketplace.rs
//! Plugin Marketplace — search, fetch metadata, install, update, and uninstall plugins.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::{PluginError, PluginManifest, PluginResult, Version};

// ─── MarketplaceEntry ─────────────────────────────────────────────────────────

/// A single entry in the plugin marketplace.
#[derive(Debug, Clone)]
pub struct MarketplaceEntry {
    /// Unique name of the plugin.
    pub name: String,
    /// Current published version.
    pub version: Version,
    /// Author or organisation.
    pub author: String,
    /// Short description.
    pub description: String,
    /// Total number of downloads.
    pub downloads: u64,
    /// Average user rating in [0.0, 5.0].
    pub rating: f32,
    /// Searchable tags.
    pub tags: Vec<String>,
    /// URL of the plugin package.
    pub download_url: String,
    /// SHA-256 hex digest of the package.
    pub sha256: String,
    /// Minimum `RustRE` version required.
    pub min_rustre_version: Version,
    /// License identifier.
    pub license: String,
    /// Whether the entry is verified/trusted.
    pub verified: bool,
}

impl MarketplaceEntry {
    /// Create a minimal entry.
    #[must_use]
    pub fn new(name: &str, version: Version, author: &str) -> Self {
        Self {
            name: name.to_string(),
            version,
            author: author.to_string(),
            description: String::new(),
            downloads: 0,
            rating: 0.0,
            tags: Vec::new(),
            download_url: String::new(),
            sha256: String::new(),
            min_rustre_version: Version::new(0, 1, 0),
            license: "MIT".to_string(),
            verified: false,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, d: &str) -> Self {
        self.description = d.to_string();
        self
    }

    /// Set the download URL and hash.
    #[must_use]
    pub fn with_download(mut self, url: &str, sha256: &str) -> Self {
        self.download_url = url.to_string();
        self.sha256 = sha256.to_string();
        self
    }

    /// Add tags.
    #[must_use]
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(std::string::ToString::to_string).collect();
        self
    }

    /// Set rating and downloads.
    #[must_use]
    pub const fn with_stats(mut self, rating: f32, downloads: u64) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. Note the bounds are 0..=5 here — this is a
        // star rating, not a 0..=1 score.
        self.rating = if rating >= 5.0 {
            5.0
        } else if rating > 0.0 {
            rating
        } else {
            0.0
        };
        self.downloads = downloads;
        self
    }

    /// Mark as verified.
    #[must_use]
    pub const fn verified(mut self) -> Self {
        self.verified = true;
        self
    }

    /// Whether this entry has all the fields required for installation.
    #[must_use]
    pub const fn is_installable(&self) -> bool {
        !self.download_url.is_empty() && !self.sha256.is_empty()
    }
}

// ─── MarketplaceFilter ────────────────────────────────────────────────────────

/// Criteria to filter the marketplace index.
#[derive(Debug, Clone, Default)]
pub struct MarketplaceFilter {
    /// Only return entries containing this substring (case-insensitive) in name or description.
    pub query: Option<String>,
    /// Only return entries that have ALL of these tags.
    pub tags: Vec<String>,
    /// Minimum average rating (inclusive).
    pub min_rating: Option<f32>,
    /// Minimum downloads (inclusive).
    pub min_downloads: Option<u64>,
    /// Only return verified entries.
    pub verified_only: bool,
    /// Only return entries compatible with the given `RustRE` version.
    pub compatible_with: Option<Version>,
}

impl MarketplaceFilter {
    /// Create a filter that matches everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_query(mut self, q: &str) -> Self {
        self.query = Some(q.to_lowercase());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    #[must_use]
    pub const fn with_min_rating(mut self, r: f32) -> Self {
        self.min_rating = Some(r);
        self
    }

    #[must_use]
    pub const fn with_min_downloads(mut self, d: u64) -> Self {
        self.min_downloads = Some(d);
        self
    }

    #[must_use]
    pub const fn verified_only(mut self) -> Self {
        self.verified_only = true;
        self
    }

    #[must_use]
    pub const fn compatible_with(mut self, v: Version) -> Self {
        self.compatible_with = Some(v);
        self
    }

    /// Test whether `entry` satisfies all criteria in this filter.
    #[must_use]
    pub fn matches(&self, entry: &MarketplaceEntry) -> bool {
        if let Some(ref q) = self.query {
            let name_lc = entry.name.to_lowercase();
            let desc_lc = entry.description.to_lowercase();
            if !name_lc.contains(q.as_str()) && !desc_lc.contains(q.as_str()) {
                return false;
            }
        }
        for tag in &self.tags {
            if !entry.tags.iter().any(|t| t == tag) {
                return false;
            }
        }
        if let Some(min_r) = self.min_rating
            && entry.rating < min_r
        {
            return false;
        }
        if let Some(min_d) = self.min_downloads
            && entry.downloads < min_d
        {
            return false;
        }
        if self.verified_only && !entry.verified {
            return false;
        }
        if let Some(ref v) = self.compatible_with
            && !v.is_compatible_with(&entry.min_rustre_version)
        {
            return false;
        }
        true
    }
}

// ─── PluginManifestValidator ──────────────────────────────────────────────────

/// Validates a `PluginManifest` against marketplace requirements.
#[derive(Debug, Clone, Default)]
pub struct PluginManifestValidator;

/// A single validation issue.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// The field or aspect that is invalid.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether this is fatal (error) or advisory (warning).
    pub is_error: bool,
}

/// Result of manifest validation.
#[derive(Debug, Clone)]
pub struct ManifestValidationResult {
    /// All issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ManifestValidationResult {
    /// True if there are no errors (warnings are acceptable).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.issues.iter().any(|i| i.is_error)
    }

    /// Number of errors.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_error).count()
    }

    /// Number of warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| !i.is_error).count()
    }
}

impl PluginManifestValidator {
    /// Create a new validator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validate `manifest` and return all discovered issues.
    #[must_use]
    pub fn validate(&self, manifest: &PluginManifest) -> ManifestValidationResult {
        let mut issues = Vec::new();

        // Name checks
        if manifest.name.is_empty() {
            issues.push(ValidationIssue {
                field: "name".to_string(),
                message: "Plugin name must not be empty".to_string(),
                is_error: true,
            });
        } else if manifest.name.len() > 64 {
            issues.push(ValidationIssue {
                field: "name".to_string(),
                message: "Plugin name exceeds 64 characters".to_string(),
                is_error: false,
            });
        }
        if !manifest
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            issues.push(ValidationIssue {
                field: "name".to_string(),
                message: "Plugin name should contain only alphanumeric, '-', '_' characters"
                    .to_string(),
                is_error: false,
            });
        }

        // Author
        if manifest.author.is_empty() {
            issues.push(ValidationIssue {
                field: "author".to_string(),
                message: "Plugin author must not be empty".to_string(),
                is_error: false,
            });
        }

        // Description
        if manifest.description.is_empty() {
            issues.push(ValidationIssue {
                field: "description".to_string(),
                message: "Plugin description is missing".to_string(),
                is_error: false,
            });
        } else if manifest.description.len() < 10 {
            issues.push(ValidationIssue {
                field: "description".to_string(),
                message: "Plugin description is too short (< 10 chars)".to_string(),
                is_error: false,
            });
        }

        // Capabilities
        if manifest.capabilities.is_empty() {
            issues.push(ValidationIssue {
                field: "capabilities".to_string(),
                message: "Plugin declares no capabilities".to_string(),
                is_error: false,
            });
        }

        // License
        let known_licenses = [
            "MIT",
            "Apache-2.0",
            "GPL-2.0",
            "GPL-3.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "MPL-2.0",
        ];
        if !known_licenses.contains(&manifest.license.as_str()) {
            issues.push(ValidationIssue {
                field: "license".to_string(),
                message: format!("Unknown SPDX license identifier: '{}'", manifest.license),
                is_error: false,
            });
        }

        // Version sanity
        if manifest.version == Version::new(0, 0, 0) {
            issues.push(ValidationIssue {
                field: "version".to_string(),
                message: "Plugin version 0.0.0 is not a valid release version".to_string(),
                is_error: false,
            });
        }

        ManifestValidationResult { issues }
    }
}

// ─── Mock HTTP Client ─────────────────────────────────────────────────────────

/// Simulates HTTP interactions for marketplace tests without real network access.
#[derive(Debug, Clone)]
pub struct MockHttpClient {
    responses: HashMap<String, Result<Vec<u8>, String>>,
    /// Log of URLs that were requested.
    pub request_log: Vec<String>,
}

impl MockHttpClient {
    /// Create an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            request_log: Vec::new(),
        }
    }

    /// Register a successful response for `url`.
    pub fn add_response(&mut self, url: &str, body: Vec<u8>) {
        self.responses.insert(url.to_string(), Ok(body));
    }

    /// Register an error for `url`.
    pub fn add_error(&mut self, url: &str, msg: &str) {
        self.responses.insert(url.to_string(), Err(msg.to_string()));
    }

    ///
    /// # Errors
    ///
    /// Returns an error message when the URL is not in the cache.
    pub fn get(&mut self, url: &str) -> Result<Vec<u8>, String> {
        self.request_log.push(url.to_string());
        self.responses
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(format!("No mock response for {url}")))
    }

    /// Number of requests made so far.
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_log.len()
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── InstallRecord ────────────────────────────────────────────────────────────

/// Tracks a plugin that has been installed locally.
#[derive(Debug, Clone)]
pub struct InstallRecord {
    pub name: String,
    pub version: Version,
    pub installed_at: SystemTime,
    pub install_path: String,
}

// ─── PluginMarketplace ────────────────────────────────────────────────────────

/// Central hub for marketplace operations.
pub struct PluginMarketplace {
    index: Vec<MarketplaceEntry>,
    installed: HashMap<String, InstallRecord>,
    http: MockHttpClient,
    validator: PluginManifestValidator,
    /// Base URL for the marketplace API.
    pub base_url: String,
    /// Maximum number of results per query.
    pub max_results: usize,
    /// Timeout applied to any single HTTP request.
    pub request_timeout: Duration,
}

impl PluginMarketplace {
    /// Create a marketplace pointing at `base_url`.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            index: Vec::new(),
            installed: HashMap::new(),
            http: MockHttpClient::new(),
            validator: PluginManifestValidator::new(),
            base_url: base_url.to_string(),
            max_results: 50,
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Configure the HTTP request timeout used by network operations.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Attach a mock HTTP client (useful in tests).
    #[must_use]
    pub fn with_http(mut self, http: MockHttpClient) -> Self {
        self.http = http;
        self
    }

    /// Add an entry directly to the local index (useful for testing).
    pub fn add_to_index(&mut self, entry: MarketplaceEntry) {
        self.index.push(entry);
    }

    /// Number of entries in the local cache.
    #[must_use]
    pub const fn index_len(&self) -> usize {
        self.index.len()
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Search plugins using `filter`. Returns matching entries sorted by downloads descending.
    #[must_use]
    pub fn search_plugins(&self, filter: &MarketplaceFilter) -> Vec<&MarketplaceEntry> {
        let mut results: Vec<&MarketplaceEntry> = self
            .index
            .iter()
            .filter(|e| filter.matches(e))
            .take(self.max_results)
            .collect();
        results.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        results
    }

    ///
    /// # Errors
    ///
    /// Returns an error if metadata cannot be fetched or parsed.
    pub fn fetch_plugin_metadata(&mut self, name: &str) -> PluginResult<MarketplaceEntry> {
        // Try local index first.
        if let Some(e) = self.index.iter().find(|e| e.name == name) {
            return Ok(e.clone());
        }
        // Otherwise request from "server".
        let url = format!("{}/api/v1/plugins/{}", self.base_url, name);
        let body = self.http.get(&url).map_err(PluginError::ApiError)?;
        // Parse a trivial JSON-like payload: just deserialize name/version.
        let text = String::from_utf8_lossy(&body).to_string();
        if text.contains("\"name\"") {
            // Minimal parse: return a stub entry.
            Ok(MarketplaceEntry::new(
                name,
                Version::new(0, 1, 0),
                "unknown",
            ))
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if installation fails (network, validation, etc.).
    pub fn install_plugin(&mut self, name: &str) -> PluginResult<InstallRecord> {
        if self.installed.contains_key(name) {
            return Err(PluginError::AlreadyRegistered(name.to_string()));
        }
        let entry = self
            .index
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        if !entry.is_installable() {
            return Err(PluginError::LoadError(format!(
                "{name} has no download URL"
            )));
        }

        let url = entry.download_url.clone();
        let _bytes = self.http.get(&url).map_err(PluginError::LoadError)?;

        let record = InstallRecord {
            name: entry.name.clone(),
            version: entry.version.clone(),
            installed_at: SystemTime::now(),
            install_path: format!("~/.rustre/plugins/{}.so", entry.name),
        };
        self.installed.insert(name.to_string(), record.clone());
        Ok(record)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the update fails.
    pub fn update_plugin(&mut self, name: &str) -> PluginResult<InstallRecord> {
        if !self.installed.contains_key(name) {
            return Err(PluginError::NotFound(format!("{name} is not installed")));
        }
        self.installed.remove(name);
        self.install_plugin(name)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is not installed.
    pub fn uninstall_plugin(&mut self, name: &str) -> PluginResult<()> {
        self.installed
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| PluginError::NotFound(format!("{name} is not installed")))
    }

    /// List all installed plugins.
    #[must_use]
    pub fn list_installed(&self) -> Vec<&InstallRecord> {
        self.installed.values().collect()
    }

    /// Check whether a plugin is currently installed.
    #[must_use]
    pub fn is_installed(&self, name: &str) -> bool {
        self.installed.contains_key(name)
    }

    /// Validate a manifest before publishing.
    #[must_use]
    pub fn validate_manifest(&self, manifest: &PluginManifest) -> ManifestValidationResult {
        self.validator.validate(manifest)
    }

    /// Number of HTTP requests made (for test assertions).
    #[must_use]
    pub const fn http_request_count(&self) -> usize {
        self.http.request_count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PluginCapability, PluginManifest, Version};

    fn sample_entry(name: &str) -> MarketplaceEntry {
        MarketplaceEntry::new(name, Version::new(1, 0, 0), "alice")
            .with_description("A test plugin for unit testing")
            .with_download(&format!("https://example.com/{name}.so"), "deadbeef")
            .with_tags(&["test", "analysis"])
            .with_stats(4.5, 1000)
            .verified()
    }

    fn make_marketplace() -> PluginMarketplace {
        let mp = PluginMarketplace::new("https://plugins.rustre.io");
        let mut http = MockHttpClient::new();
        http.add_response(
            "https://example.com/my_plugin.so",
            b"PLUGIN_BINARY_DATA".to_vec(),
        );

        mp.with_http(http)
    }

    // ── MarketplaceEntry ──────────────────────────────────────────────────────

    #[test]
    fn test_entry_new() {
        let e = MarketplaceEntry::new("my_plugin", Version::new(1, 2, 3), "Bob");
        assert_eq!(e.name, "my_plugin");
        assert_eq!(e.version, Version::new(1, 2, 3));
        assert_eq!(e.author, "Bob");
        assert!(!e.verified);
    }

    #[test]
    fn test_entry_builder_chain() {
        let e = sample_entry("alpha");
        assert!((e.rating - 4.5).abs() < f32::EPSILON);
        assert_eq!(e.downloads, 1000);
        assert!(e.tags.contains(&"test".to_string()));
        assert!(e.verified);
    }

    #[test]
    fn test_entry_is_installable_with_url() {
        let e = sample_entry("beta");
        assert!(e.is_installable());
    }

    #[test]
    fn test_entry_is_not_installable_without_url() {
        let e = MarketplaceEntry::new("gamma", Version::new(1, 0, 0), "carol");
        assert!(!e.is_installable());
    }

    #[test]
    fn test_entry_rating_clamped() {
        let e = MarketplaceEntry::new("x", Version::new(1, 0, 0), "d").with_stats(10.0, 0);
        assert!(e.rating <= 5.0);
    }

    // ── MarketplaceFilter ─────────────────────────────────────────────────────

    #[test]
    fn test_filter_query_match() {
        let f = MarketplaceFilter::new().with_query("test");
        let e = sample_entry("test_plugin");
        assert!(f.matches(&e));
    }

    #[test]
    fn test_filter_query_no_match() {
        let f = MarketplaceFilter::new().with_query("xyz_nope");
        let e = sample_entry("alpha");
        assert!(!f.matches(&e));
    }

    #[test]
    fn test_filter_tag_match() {
        let f = MarketplaceFilter::new().with_tag("analysis");
        let e = sample_entry("plug_a");
        assert!(f.matches(&e));
    }

    #[test]
    fn test_filter_tag_no_match() {
        let f = MarketplaceFilter::new().with_tag("missing_tag");
        let e = sample_entry("plug_b");
        assert!(!f.matches(&e));
    }

    #[test]
    fn test_filter_min_rating() {
        let f = MarketplaceFilter::new().with_min_rating(4.0);
        let e = sample_entry("high_rated"); // 4.5
        assert!(f.matches(&e));
        let f2 = MarketplaceFilter::new().with_min_rating(5.0);
        assert!(!f2.matches(&e));
    }

    #[test]
    fn test_filter_min_downloads() {
        let f = MarketplaceFilter::new().with_min_downloads(500);
        let e = sample_entry("popular"); // 1000
        assert!(f.matches(&e));
        let f2 = MarketplaceFilter::new().with_min_downloads(5000);
        assert!(!f2.matches(&e));
    }

    #[test]
    fn test_filter_verified_only() {
        let f = MarketplaceFilter::new().verified_only();
        let verified = sample_entry("vp");
        let not_verified =
            MarketplaceEntry::new("np", Version::new(1, 0, 0), "e").with_stats(4.0, 100);
        assert!(f.matches(&verified));
        assert!(!f.matches(&not_verified));
    }

    #[test]
    fn test_filter_empty_matches_all() {
        let f = MarketplaceFilter::new();
        let e = sample_entry("anything");
        assert!(f.matches(&e));
    }

    // ── PluginManifestValidator ───────────────────────────────────────────────

    #[test]
    fn test_validator_valid_manifest() {
        let m = PluginManifest::new("my-plugin", Version::new(1, 0, 0))
            .with_description("A properly described plugin")
            .with_author("Charlie")
            .with_capability(PluginCapability::Loader);
        let v = PluginManifestValidator::new();
        let r = v.validate(&m);
        assert!(r.is_valid(), "Expected valid, got errors: {:?}", r.issues);
    }

    #[test]
    fn test_validator_empty_name() {
        let m = PluginManifest::new("", Version::new(1, 0, 0));
        let v = PluginManifestValidator::new();
        let r = v.validate(&m);
        assert!(r.error_count() > 0);
    }

    #[test]
    fn test_validator_missing_description() {
        let m = PluginManifest::new("myplugin", Version::new(1, 0, 0)).with_author("Dave");
        let v = PluginManifestValidator::new();
        let r = v.validate(&m);
        assert!(r.warning_count() > 0);
    }

    #[test]
    fn test_validator_unknown_license() {
        let mut m = PluginManifest::new("myplugin", Version::new(1, 0, 0))
            .with_author("Eve")
            .with_description("A plugin with a weird license");
        m.license = "PROPRIETARY".to_string();
        let v = PluginManifestValidator::new();
        let r = v.validate(&m);
        let has_license_warn = r.issues.iter().any(|i| !i.is_error && i.field == "license");
        assert!(has_license_warn);
    }

    #[test]
    fn test_validator_version_zero() {
        let m = PluginManifest::new("myplugin", Version::new(0, 0, 0))
            .with_author("Frank")
            .with_description("Version zero plugin");
        let v = PluginManifestValidator::new();
        let r = v.validate(&m);
        let has_version_warn = r.issues.iter().any(|i| !i.is_error && i.field == "version");
        assert!(has_version_warn);
    }

    // ── MockHttpClient ────────────────────────────────────────────────────────

    #[test]
    fn test_mock_http_success() {
        let mut http = MockHttpClient::new();
        http.add_response("https://example.com/file", b"data".to_vec());
        let r = http.get("https://example.com/file").unwrap();
        assert_eq!(r, b"data");
        assert_eq!(http.request_count(), 1);
    }

    #[test]
    fn test_mock_http_error() {
        let mut http = MockHttpClient::new();
        http.add_error("https://example.com/bad", "404 Not Found");
        let r = http.get("https://example.com/bad");
        assert!(r.is_err());
    }

    #[test]
    fn test_mock_http_unknown_url() {
        let mut http = MockHttpClient::new();
        let r = http.get("https://example.com/unknown");
        assert!(r.is_err());
    }

    #[test]
    fn test_mock_http_request_log() {
        let mut http = MockHttpClient::new();
        http.add_response("https://a.com/1", vec![]);
        http.add_response("https://a.com/2", vec![]);
        let _ = http.get("https://a.com/1");
        let _ = http.get("https://a.com/2");
        assert_eq!(http.request_log, ["https://a.com/1", "https://a.com/2"]);
    }

    // ── PluginMarketplace ──────────────────────────────────────────────────────

    #[test]
    fn test_marketplace_search_all() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("plugin_a"));
        mp.add_to_index(sample_entry("plugin_b"));
        let results = mp.search_plugins(&MarketplaceFilter::new());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_marketplace_search_filter() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("filter_test"));
        mp.add_to_index(MarketplaceEntry::new("other", Version::new(1, 0, 0), "x"));
        let f = MarketplaceFilter::new().with_query("filter");
        let results = mp.search_plugins(&f);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "filter_test");
    }

    #[test]
    fn test_marketplace_fetch_metadata_from_index() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        let meta = mp.fetch_plugin_metadata("my_plugin").unwrap();
        assert_eq!(meta.name, "my_plugin");
    }

    #[test]
    fn test_marketplace_fetch_metadata_not_found() {
        let mut mp = make_marketplace();
        let r = mp.fetch_plugin_metadata("nonexistent");
        assert!(r.is_err());
    }

    #[test]
    fn test_marketplace_install_success() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        let record = mp.install_plugin("my_plugin").unwrap();
        assert_eq!(record.name, "my_plugin");
        assert!(mp.is_installed("my_plugin"));
    }

    #[test]
    fn test_marketplace_install_duplicate_fails() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        mp.install_plugin("my_plugin").unwrap();
        let r = mp.install_plugin("my_plugin");
        assert!(r.is_err());
    }

    #[test]
    fn test_marketplace_install_not_in_index_fails() {
        let mut mp = make_marketplace();
        let r = mp.install_plugin("ghost_plugin");
        assert!(r.is_err());
    }

    #[test]
    fn test_marketplace_uninstall_success() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        mp.install_plugin("my_plugin").unwrap();
        mp.uninstall_plugin("my_plugin").unwrap();
        assert!(!mp.is_installed("my_plugin"));
    }

    #[test]
    fn test_marketplace_uninstall_not_installed_fails() {
        let mut mp = make_marketplace();
        let r = mp.uninstall_plugin("ghost");
        assert!(r.is_err());
    }

    #[test]
    fn test_marketplace_update_success() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        mp.install_plugin("my_plugin").unwrap();
        let record = mp.update_plugin("my_plugin").unwrap();
        assert_eq!(record.name, "my_plugin");
        assert!(mp.is_installed("my_plugin"));
    }

    #[test]
    fn test_marketplace_update_not_installed_fails() {
        let mut mp = make_marketplace();
        let r = mp.update_plugin("not_installed");
        assert!(r.is_err());
    }

    #[test]
    fn test_marketplace_list_installed() {
        let mut mp = make_marketplace();
        mp.add_to_index(sample_entry("my_plugin"));
        assert_eq!(mp.list_installed().len(), 0);
        mp.install_plugin("my_plugin").unwrap();
        assert_eq!(mp.list_installed().len(), 1);
    }

    #[test]
    fn test_marketplace_sorted_by_downloads() {
        let mut mp = make_marketplace();
        mp.add_to_index(
            MarketplaceEntry::new("low", Version::new(1, 0, 0), "a")
                .with_description("Low downloads plugin ok")
                .with_stats(3.0, 10),
        );
        mp.add_to_index(
            MarketplaceEntry::new("high", Version::new(1, 0, 0), "b")
                .with_description("High downloads plugin ok")
                .with_stats(4.0, 9999),
        );
        let results = mp.search_plugins(&MarketplaceFilter::new());
        assert_eq!(results[0].name, "high");
    }
}
