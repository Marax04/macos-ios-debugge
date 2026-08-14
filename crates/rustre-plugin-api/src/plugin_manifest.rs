//! Plugin manifest: structured description of a plugin's identity, requirements,
//! and capabilities.  Provides [`PluginManifest`], [`ManifestEntry`],
//! [`ApiVersion`] and the [`parse_manifest`] top-level function.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

// ── ApiVersion ────────────────────────────────────────────────────────────────

/// A semantic API version triplet (major.minor.patch).
///
/// Two versions are *compatible* when they share the same major number and the
/// candidate is greater-or-equal to the required version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ApiVersion {
    /// Construct a new version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// The version used by the current `RustRE` plugin API.
    pub const CURRENT: Self = Self::new(0, 1, 0);

    /// Return `true` when `self` satisfies the requirement expressed by `req`.
    ///
    /// Compatibility is defined as: same major, and `self >= req`.
    #[must_use]
    pub fn satisfies(&self, req: &Self) -> bool {
        self.major == req.major && self >= req
    }

    /// Parse a `"major.minor.patch"` string.
    ///
    /// # Errors
    ///
    /// Returns an error string if the format is wrong or any component cannot
    /// be parsed as `u32`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 {
            return Err(format!("expected 'major.minor.patch', got '{s}'"));
        }
        let major = parts[0].parse::<u32>().map_err(|e| e.to_string())?;
        let minor = parts[1].parse::<u32>().map_err(|e| e.to_string())?;
        let patch = parts[2].parse::<u32>().map_err(|e| e.to_string())?;
        Ok(Self { major, minor, patch })
    }

    /// Bump the patch component and return the new version.
    /// Saturates at `u32::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch.saturating_add(1))
    }

    /// Bump the minor component (resets patch to 0) and return the new version.
    /// Saturates at `u32::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor.saturating_add(1), 0)
    }

    /// Bump the major component (resets minor and patch) and return the new version.
    /// Saturates at `u32::MAX` to avoid overflow panics in debug builds.
    #[must_use]
    pub const fn bump_major(&self) -> Self {
        Self::new(self.major.saturating_add(1), 0, 0)
    }

    /// Return `true` when this is a pre-release (patch == 0 and minor == 0).
    #[must_use]
    pub const fn is_initial(&self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for ApiVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ── ManifestEntry ─────────────────────────────────────────────────────────────

/// A single key-value entry in the manifest's metadata section.
///
/// Keys must be non-empty ASCII identifiers; values may be arbitrary UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub key: String,
    pub value: String,
}

impl ManifestEntry {
    /// Create a new entry.
    ///
    /// # Errors
    ///
    /// Returns an error string if `key` is empty or contains non-ASCII
    /// alphanumeric / underscore characters.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, String> {
        let key = key.into();
        if key.is_empty() {
            return Err("manifest entry key must not be empty".into());
        }
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "manifest entry key '{key}' contains invalid characters"
            ));
        }
        Ok(Self { key, value: value.into() })
    }

    /// Create an entry without validating the key (for trusted internal use).
    #[must_use]
    pub fn unchecked(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into() }
    }

    /// Return `true` if the value looks like a boolean true.
    #[must_use]
    pub fn is_true(&self) -> bool {
        matches!(self.value.as_str(), "true" | "1" | "yes")
    }

    /// Return `true` if the value looks like a boolean false.
    #[must_use]
    pub fn is_false(&self) -> bool {
        matches!(self.value.as_str(), "false" | "0" | "no")
    }

    /// Try to parse the value as `u64`.
    ///
    /// # Errors
    ///
    /// Returns a parse error string on failure.
    pub fn as_u64(&self) -> Result<u64, String> {
        self.value.parse::<u64>().map_err(|e| e.to_string())
    }
}

impl fmt::Display for ManifestEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

// ── ManifestSection ───────────────────────────────────────────────────────────

/// A named section within a manifest, holding a collection of entries.
#[derive(Debug, Clone, Default)]
pub struct ManifestSection {
    pub name: String,
    pub entries: Vec<ManifestEntry>,
}

impl ManifestSection {
    /// Create an empty section.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), entries: Vec::new() }
    }

    /// Add an entry to this section.
    pub fn push(&mut self, entry: ManifestEntry) {
        self.entries.push(entry);
    }

    /// Find the first entry with the given key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// Return the value for `key`, or `default` if absent.
    #[must_use]
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).map_or(default, |e| e.value.as_str())
    }

    /// Return all values for a given key (multi-valued keys).
    #[must_use]
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.key == key)
            .map(|e| e.value.as_str())
            .collect()
    }

    /// Build a `HashMap` from all entries; later entries shadow earlier ones.
    #[must_use]
    pub fn as_map(&self) -> HashMap<&str, &str> {
        self.entries.iter().map(|e| (e.key.as_str(), e.value.as_str())).collect()
    }

    /// Number of entries in this section.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if this section has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for ManifestSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}]", self.name)?;
        for e in &self.entries {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

// ── PluginManifest ────────────────────────────────────────────────────────────

/// Full plugin manifest: identity metadata, API version requirements,
/// capabilities declared, dependencies, and arbitrary key-value metadata.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    /// Unique plugin identifier (reverse-DNS style recommended).
    pub id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Plugin version.
    pub version: ApiVersion,
    /// Minimum host API version required.
    pub min_api: ApiVersion,
    /// Maximum host API version known to work with (exclusive, `None` = unbounded).
    pub max_api: Option<ApiVersion>,
    /// Short description.
    pub description: String,
    /// Author name or organisation.
    pub author: String,
    /// License identifier (SPDX).
    pub license: String,
    /// Homepage URL.
    pub homepage: Option<String>,
    /// Repository URL.
    pub repository: Option<String>,
    /// Capability tags declared by the plugin.
    pub capabilities: Vec<String>,
    /// Plugin IDs this plugin depends on.
    pub dependencies: Vec<PluginDependency>,
    /// Arbitrary extension metadata sections.
    pub sections: Vec<ManifestSection>,
}

/// A single dependency declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDependency {
    /// Dependency plugin ID.
    pub id: String,
    /// Minimum version required.
    pub min_version: ApiVersion,
    /// Whether this dependency is optional.
    pub optional: bool,
}

impl PluginDependency {
    /// Create a required dependency.
    #[must_use]
    pub fn required(id: impl Into<String>, min_version: ApiVersion) -> Self {
        Self { id: id.into(), min_version, optional: false }
    }

    /// Create an optional dependency.
    #[must_use]
    pub fn optional(id: impl Into<String>, min_version: ApiVersion) -> Self {
        Self { id: id.into(), min_version, optional: true }
    }
}

impl fmt::Display for PluginDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} >= {}{}",
            self.id,
            self.min_version,
            if self.optional { " (optional)" } else { "" }
        )
    }
}

impl PluginManifest {
    /// Create a minimal manifest with sensible defaults.
    #[must_use]
    pub fn new(id: impl Into<String>, version: ApiVersion) -> Self {
        Self {
            id: id.into(),
            display_name: String::new(),
            version,
            min_api: ApiVersion::CURRENT,
            max_api: None,
            description: String::new(),
            author: String::new(),
            license: "MIT".into(),
            homepage: None,
            repository: None,
            capabilities: Vec::new(),
            dependencies: Vec::new(),
            sections: Vec::new(),
        }
    }

    /// Builder: set the display name.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Builder: set the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set the author.
    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Builder: set the license.
    #[must_use]
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = license.into();
        self
    }

    /// Builder: set the minimum API version.
    #[must_use]
    pub const fn with_min_api(mut self, v: ApiVersion) -> Self {
        self.min_api = v;
        self
    }

    /// Builder: declare a capability.
    #[must_use]
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Builder: add a dependency.
    #[must_use]
    pub fn with_dependency(mut self, dep: PluginDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Return `true` when the given host API version satisfies this manifest's
    /// `min_api` requirement (and does not exceed `max_api` if set).
    #[must_use]
    pub fn is_compatible_with(&self, host_api: &ApiVersion) -> bool {
        if !host_api.satisfies(&self.min_api) {
            return false;
        }
        if let Some(ref max) = self.max_api
            && host_api >= max {
                return false;
            }
        true
    }

    /// Find or create a section by name, returning a mutable reference.
    pub fn section_mut(&mut self, name: &str) -> &mut ManifestSection {
        if let Some(pos) = self.sections.iter().position(|s| s.name == name) {
            &mut self.sections[pos]
        } else {
            self.sections.push(ManifestSection::new(name));
            self.sections.last_mut().unwrap()
        }
    }

    /// Look up the first section with the given name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&ManifestSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Return an iterator over all capabilities as string slices.
    pub fn capability_iter(&self) -> impl Iterator<Item = &str> {
        self.capabilities.iter().map(String::as_str)
    }

    /// Return `true` when the manifest declares the named capability.
    #[must_use]
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// Validate the manifest, returning a list of error strings.
    ///
    /// The manifest is considered valid when the returned `Vec` is empty.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        if self.id.is_empty() {
            errors.push("manifest id must not be empty".into());
        }
        if !self.id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            errors.push(format!("manifest id '{}' contains invalid characters", self.id));
        }
        if self.version.is_initial() && self.version.patch == 0 {
            // 0.0.0 is allowed but unusual — just a warning-level hint, not recorded.
        }
        if self.author.is_empty() {
            errors.push("manifest author must not be empty".into());
        }
        if self.license.is_empty() {
            errors.push("manifest license must not be empty".into());
        }
        for dep in &self.dependencies {
            if dep.id.is_empty() {
                errors.push("dependency id must not be empty".into());
            }
        }
        errors
    }

    /// Serialise this manifest to a simple INI-like text format.
    #[must_use]
    pub fn to_ini(&self) -> String {
        let mut out = String::new();
        out.push_str("[plugin]\n");
        out.push_str(&format!("id={}\n", self.id));
        out.push_str(&format!("display_name={}\n", self.display_name));
        out.push_str(&format!("version={}\n", self.version));
        out.push_str(&format!("min_api={}\n", self.min_api));
        out.push_str(&format!("description={}\n", self.description));
        out.push_str(&format!("author={}\n", self.author));
        out.push_str(&format!("license={}\n", self.license));
        if let Some(ref url) = self.homepage {
            out.push_str(&format!("homepage={url}\n"));
        }
        if let Some(ref url) = self.repository {
            out.push_str(&format!("repository={url}\n"));
        }
        if !self.capabilities.is_empty() {
            out.push_str("\n[capabilities]\n");
            for cap in &self.capabilities {
                out.push_str(&format!("{cap}=true\n"));
            }
        }
        if !self.dependencies.is_empty() {
            out.push_str("\n[dependencies]\n");
            for dep in &self.dependencies {
                out.push_str(&format!("{}={}", dep.id, dep.min_version));
                if dep.optional {
                    out.push_str(",optional");
                }
                out.push('\n');
            }
        }
        for sec in &self.sections {
            out.push_str(&format!("\n[{}]\n", sec.name));
            for e in &sec.entries {
                out.push_str(&format!("{}={}\n", e.key, e.value));
            }
        }
        out
    }
}

impl fmt::Display for PluginManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Plugin '{}' v{} (api>={}) by {}",
            self.id, self.version, self.min_api, self.author
        )
    }
}

// ── parse_manifest ────────────────────────────────────────────────────────────

/// Parse a manifest from its INI-like text representation.
///
/// Format:
/// ```text
/// [plugin]
/// id=my.plugin
/// version=1.0.0
/// min_api=0.1.0
/// description=My plugin
/// author=Alice
/// license=MIT
///
/// [capabilities]
/// loader=true
///
/// [dependencies]
/// other.plugin=0.1.0
/// optional.plugin=0.1.0,optional
/// ```
///
/// # Errors
///
/// Returns an error string if required fields are missing or versions cannot
/// be parsed.
pub fn parse_manifest(input: &str) -> Result<PluginManifest, String> {
    let mut current_section = String::new();
    let mut sections: HashMap<String, Vec<ManifestEntry>> = HashMap::new();

    for (lineno, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let end = line
                .find(']')
                .ok_or_else(|| format!("line {}: unclosed '[' in section header", lineno + 1))?;
            current_section = line[1..end].trim().to_string();
            sections.entry(current_section.clone()).or_default();
        } else if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_string();
            let value = v.trim().to_string();
            sections
                .entry(current_section.clone())
                .or_default()
                .push(ManifestEntry::unchecked(key, value));
        } else {
            return Err(format!("line {}: cannot parse '{line}'", lineno + 1));
        }
    }

    // Extract [plugin] section.
    let plugin_entries = sections.get("plugin").cloned().unwrap_or_default();
    let get = |key: &str| -> Option<String> {
        plugin_entries.iter().find(|e| e.key == key).map(|e| e.value.clone())
    };

    let id = get("id").ok_or("missing 'id' in [plugin] section")?;
    let version_str = get("version").ok_or("missing 'version' in [plugin] section")?;
    let version = ApiVersion::parse(&version_str)?;

    let min_api_str = get("min_api").unwrap_or_else(|| "0.1.0".into());
    let min_api = ApiVersion::parse(&min_api_str)?;

    let max_api = if let Some(s) = get("max_api") {
        Some(ApiVersion::parse(&s)?)
    } else {
        None
    };

    let mut manifest = PluginManifest::new(id, version);
    manifest.min_api = min_api;
    manifest.max_api = max_api;
    manifest.display_name = get("display_name").unwrap_or_default();
    manifest.description = get("description").unwrap_or_default();
    manifest.author = get("author").unwrap_or_default();
    manifest.license = get("license").unwrap_or_else(|| "MIT".into());
    manifest.homepage = get("homepage");
    manifest.repository = get("repository");

    // [capabilities]
    if let Some(caps) = sections.get("capabilities") {
        for e in caps {
            if e.is_true() {
                manifest.capabilities.push(e.key.clone());
            }
        }
    }

    // [dependencies]
    if let Some(deps) = sections.get("dependencies") {
        for e in deps {
            let mut parts = e.value.splitn(2, ',');
            let ver_str = parts.next().unwrap_or("0.0.0");
            let flags = parts.next().unwrap_or("").trim();
            let min_v = ApiVersion::parse(ver_str)?;
            let optional = flags == "optional";
            manifest.dependencies.push(if optional {
                PluginDependency::optional(e.key.clone(), min_v)
            } else {
                PluginDependency::required(e.key.clone(), min_v)
            });
        }
    }

    // Remaining sections become extension sections.
    for (sec_name, entries) in &sections {
        if matches!(sec_name.as_str(), "plugin" | "capabilities" | "dependencies") {
            continue;
        }
        let mut sec = ManifestSection::new(sec_name.clone());
        for e in entries {
            sec.push(e.clone());
        }
        manifest.sections.push(sec);
    }

    Ok(manifest)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ApiVersion ─────────────────────────────────────────────────────────────

    #[test]
    fn test_api_version_display() {
        assert_eq!(ApiVersion::new(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn test_api_version_parse_ok() {
        let v = ApiVersion::parse("2.5.11").unwrap();
        assert_eq!(v, ApiVersion::new(2, 5, 11));
    }

    #[test]
    fn test_api_version_parse_short_fails() {
        assert!(ApiVersion::parse("1.2").is_err());
    }

    #[test]
    fn test_api_version_satisfies_same() {
        let v = ApiVersion::new(1, 0, 0);
        assert!(v.satisfies(&v));
    }

    #[test]
    fn test_api_version_satisfies_newer() {
        assert!(ApiVersion::new(1, 2, 0).satisfies(&ApiVersion::new(1, 1, 0)));
    }

    #[test]
    fn test_api_version_major_mismatch() {
        assert!(!ApiVersion::new(2, 0, 0).satisfies(&ApiVersion::new(1, 0, 0)));
    }

    #[test]
    fn test_api_version_bump_patch() {
        assert_eq!(ApiVersion::new(1, 2, 3).bump_patch(), ApiVersion::new(1, 2, 4));
    }

    #[test]
    fn test_api_version_bump_minor() {
        assert_eq!(ApiVersion::new(1, 2, 3).bump_minor(), ApiVersion::new(1, 3, 0));
    }

    #[test]
    fn test_api_version_bump_major() {
        assert_eq!(ApiVersion::new(1, 2, 3).bump_major(), ApiVersion::new(2, 0, 0));
    }

    #[test]
    fn test_api_version_ordering() {
        assert!(ApiVersion::new(0, 2, 0) > ApiVersion::new(0, 1, 9));
        assert!(ApiVersion::new(1, 0, 0) > ApiVersion::new(0, 9, 9));
    }

    // ── ManifestEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_entry_valid() {
        let e = ManifestEntry::new("foo_bar", "hello").unwrap();
        assert_eq!(e.key, "foo_bar");
        assert_eq!(e.value, "hello");
    }

    #[test]
    fn test_manifest_entry_empty_key_fails() {
        assert!(ManifestEntry::new("", "v").is_err());
    }

    #[test]
    fn test_manifest_entry_invalid_key_fails() {
        assert!(ManifestEntry::new("foo bar", "v").is_err());
    }

    #[test]
    fn test_manifest_entry_is_true() {
        assert!(ManifestEntry::unchecked("k", "true").is_true());
        assert!(ManifestEntry::unchecked("k", "1").is_true());
        assert!(!ManifestEntry::unchecked("k", "false").is_true());
    }

    #[test]
    fn test_manifest_entry_as_u64() {
        assert_eq!(ManifestEntry::unchecked("k", "42").as_u64().unwrap(), 42);
        assert!(ManifestEntry::unchecked("k", "not_a_num").as_u64().is_err());
    }

    // ── ManifestSection ────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_section_get() {
        let mut sec = ManifestSection::new("test");
        sec.push(ManifestEntry::unchecked("a", "1"));
        sec.push(ManifestEntry::unchecked("b", "2"));
        assert_eq!(sec.get("a").unwrap().value, "1");
        assert!(sec.get("c").is_none());
    }

    #[test]
    fn test_manifest_section_get_all() {
        let mut sec = ManifestSection::new("test");
        sec.push(ManifestEntry::unchecked("x", "v1"));
        sec.push(ManifestEntry::unchecked("x", "v2"));
        let all = sec.get_all("x");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_manifest_section_as_map() {
        let mut sec = ManifestSection::new("test");
        sec.push(ManifestEntry::unchecked("k", "v"));
        let map = sec.as_map();
        assert_eq!(map.get("k"), Some(&"v"));
    }

    // ── PluginManifest ────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_manifest_new() {
        let m = PluginManifest::new("test.plugin", ApiVersion::new(1, 0, 0));
        assert_eq!(m.id, "test.plugin");
        assert_eq!(m.version, ApiVersion::new(1, 0, 0));
        assert!(m.capabilities.is_empty());
    }

    #[test]
    fn test_plugin_manifest_builder() {
        let m = PluginManifest::new("p", ApiVersion::new(1, 0, 0))
            .with_description("desc")
            .with_author("Alice")
            .with_capability("loader");
        assert_eq!(m.description, "desc");
        assert_eq!(m.author, "Alice");
        assert!(m.has_capability("loader"));
    }

    #[test]
    fn test_plugin_manifest_compat_ok() {
        let m = PluginManifest::new("p", ApiVersion::new(1, 0, 0))
            .with_min_api(ApiVersion::new(0, 1, 0));
        assert!(m.is_compatible_with(&ApiVersion::CURRENT));
    }

    #[test]
    fn test_plugin_manifest_compat_too_old() {
        let m = PluginManifest::new("p", ApiVersion::new(1, 0, 0))
            .with_min_api(ApiVersion::new(1, 0, 0));
        assert!(!m.is_compatible_with(&ApiVersion::new(0, 9, 9)));
    }

    #[test]
    fn test_plugin_manifest_validate_ok() {
        let m = PluginManifest::new("my.plugin", ApiVersion::new(0, 1, 0))
            .with_author("Bob")
            .with_license("MIT");
        assert!(m.validate().is_empty());
    }

    #[test]
    fn test_plugin_manifest_validate_missing_author() {
        let m = PluginManifest::new("my.plugin", ApiVersion::new(0, 1, 0));
        let errors = m.validate();
        assert!(errors.iter().any(|e| e.contains("author")));
    }

    #[test]
    fn test_plugin_manifest_to_ini_roundtrip() {
        let m = PluginManifest::new("round.trip", ApiVersion::new(1, 2, 3))
            .with_author("Alice")
            .with_description("A round-trip test")
            .with_capability("loader");
        let ini = m.to_ini();
        assert!(ini.contains("id=round.trip"));
        assert!(ini.contains("version=1.2.3"));
        assert!(ini.contains("author=Alice"));
        assert!(ini.contains("loader=true"));
    }

    // ── parse_manifest ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_manifest_minimal() {
        let input = "[plugin]\nid=test.plug\nversion=0.1.0\nauthor=Alice\n";
        let m = parse_manifest(input).unwrap();
        assert_eq!(m.id, "test.plug");
        assert_eq!(m.version, ApiVersion::new(0, 1, 0));
        assert_eq!(m.author, "Alice");
    }

    #[test]
    fn test_parse_manifest_full() {
        let input = r#"
[plugin]
id=full.plugin
version=1.2.3
min_api=0.1.0
description=Full manifest
author=Bob
license=Apache-2.0
homepage=https://example.com
repository=https://github.com/example

[capabilities]
loader=true
decompiler=true

[dependencies]
core.plugin=0.1.0
optional.plugin=0.1.0,optional

[metadata]
custom_key=custom_val
"#;
        let m = parse_manifest(input).unwrap();
        assert_eq!(m.id, "full.plugin");
        assert_eq!(m.version, ApiVersion::new(1, 2, 3));
        assert!(m.has_capability("loader"));
        assert!(m.has_capability("decompiler"));
        assert_eq!(m.dependencies.len(), 2);
        assert!(m.dependencies[1].optional);
        assert!(m.section("metadata").is_some());
    }

    #[test]
    fn test_parse_manifest_missing_id_fails() {
        let input = "[plugin]\nversion=0.1.0\nauthor=A\n";
        assert!(parse_manifest(input).is_err());
    }

    #[test]
    fn test_parse_manifest_bad_version_fails() {
        let input = "[plugin]\nid=x\nversion=not.a.version\nauthor=A\n";
        assert!(parse_manifest(input).is_err());
    }

    #[test]
    fn test_parse_manifest_comments_ignored() {
        let input = "# comment\n[plugin]\nid=c\nversion=0.1.0\nauthor=A\n; also a comment\n";
        let m = parse_manifest(input).unwrap();
        assert_eq!(m.id, "c");
    }
}
