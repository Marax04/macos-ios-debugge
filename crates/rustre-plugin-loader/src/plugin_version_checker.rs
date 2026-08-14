// rustre-plugin-loader/src/plugin_version_checker.rs
//
// Plugin version compatibility checking for RustRE.
// Validates that a plugin's declared requirements are satisfied by the running
// host, compares plugin versions against each other, and reports structured
// compatibility results.

use std::cmp::Ordering;
use std::fmt;

// ── SemanticVersion ───────────────────────────────────────────────────────────

/// A parsed semantic version `(major, minor, patch)` with optional pre-release
/// label and build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Optional pre-release label, e.g. `"alpha"`, `"beta.1"`.
    pub pre: Option<String>,
    /// Optional build metadata, e.g. `"20250101"`.
    pub build: Option<String>,
}

impl SemanticVersion {
    /// Construct a release version (no pre-release or metadata).
    #[must_use]
    pub const fn release(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
            build: None,
        }
    }

    /// Parse a version string such as `"1.2.3"`, `"1.2.3-alpha"`, or
    /// `"1.2.3-beta.1+build.42"`.
    ///
    /// Returns `None` if the string cannot be parsed.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        // Strip optional leading 'v'.
        let s = s.strip_prefix('v').unwrap_or(s);

        // Split off build metadata (+...).
        let (core_and_pre, build) = if let Some((c, b)) = s.split_once('+') {
            (c, Some(b.to_string()))
        } else {
            (s, None)
        };

        // Split off pre-release label (-...).
        let (core, pre) = if let Some((c, p)) = core_and_pre.split_once('-') {
            (c, Some(p.to_string()))
        } else {
            (core_and_pre, None)
        };

        let parts: Vec<&str> = core.split('.').collect();
        // Require exactly 3 numeric components; more components (e.g.
        // "1.2.3.4") are rejected so that malformed version strings from
        // untrusted manifests do not silently parse as a valid version.
        if parts.len() != 3 {
            return None;
        }

        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
            pre,
            build,
        })
    }

    /// Whether this is a stable (non-pre-release) version.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        self.pre.is_none()
    }

    /// Whether this version is backward-compatible with `other` under semver
    /// rules (same major, this >= other).
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && *self >= *other
    }

    /// The numeric triple `(major, minor, patch)`.
    #[must_use]
    pub const fn as_triple(&self) -> (u32, u32, u32) {
        (self.major, self.minor, self.patch)
    }

    /// Increment the patch component (returns a new version).
    ///
    /// Returns `None` if patch would overflow `u32::MAX`.
    #[must_use]
    pub fn next_patch(&self) -> Option<Self> {
        self.patch
            .checked_add(1)
            .map(|p| Self::release(self.major, self.minor, p))
    }

    /// Increment the minor component and reset patch (returns a new version).
    ///
    /// Returns `None` if minor would overflow `u32::MAX`.
    #[must_use]
    pub fn next_minor(&self) -> Option<Self> {
        self.minor
            .checked_add(1)
            .map(|m| Self::release(self.major, m, 0))
    }

    /// Increment the major component and reset minor/patch.
    ///
    /// Returns `None` if major would overflow `u32::MAX`.
    #[must_use]
    pub fn next_major(&self) -> Option<Self> {
        self.major
            .checked_add(1)
            .map(|mj| Self::release(mj, 0, 0))
    }
}

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Pre-release versions have lower precedence than releases.
        let triple_cmp = self.as_triple().cmp(&other.as_triple());
        if triple_cmp != Ordering::Equal {
            return triple_cmp;
        }
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater, // release > pre-release
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        if let Some(build) = &self.build {
            write!(f, "+{build}")?;
        }
        Ok(())
    }
}

// ── VersionSpec ───────────────────────────────────────────────────────────────

/// A version requirement specification as declared in a plugin manifest.
///
/// Supports the same operators as Cargo.toml: `>=`, `>`, `<=`, `<`, `^`, `~`,
/// exact (`=`), and wildcard (`*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    /// The version must exactly equal the specified value.
    Exact(SemanticVersion),
    /// `>=` — the version must be greater than or equal.
    AtLeast(SemanticVersion),
    /// `>` — the version must be strictly greater.
    GreaterThan(SemanticVersion),
    /// `<=` — the version must be less than or equal.
    AtMost(SemanticVersion),
    /// `<` — the version must be strictly less.
    LessThan(SemanticVersion),
    /// `^` — compatible release (same major, >= minor.patch).
    Compatible(SemanticVersion),
    /// `~` — approximately equal (same major.minor, >= patch).
    Approximately(SemanticVersion),
    /// `*` — any version is acceptable.
    Any,
}

impl VersionSpec {
    /// Parse a version spec string.
    ///
    /// Returns `None` if the string cannot be parsed.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "*" || s.is_empty() {
            return Some(Self::Any);
        }
        if let Some(rest) = s.strip_prefix(">=") {
            return SemanticVersion::parse(rest.trim()).map(Self::AtLeast);
        }
        if let Some(rest) = s.strip_prefix('>') {
            return SemanticVersion::parse(rest.trim()).map(Self::GreaterThan);
        }
        if let Some(rest) = s.strip_prefix("<=") {
            return SemanticVersion::parse(rest.trim()).map(Self::AtMost);
        }
        if let Some(rest) = s.strip_prefix('<') {
            return SemanticVersion::parse(rest.trim()).map(Self::LessThan);
        }
        if let Some(rest) = s.strip_prefix('^') {
            return SemanticVersion::parse(rest.trim()).map(Self::Compatible);
        }
        if let Some(rest) = s.strip_prefix('~') {
            return SemanticVersion::parse(rest.trim()).map(Self::Approximately);
        }
        if let Some(rest) = s.strip_prefix('=') {
            return SemanticVersion::parse(rest.trim()).map(Self::Exact);
        }
        // Bare version — treat as AtLeast.
        SemanticVersion::parse(s).map(Self::AtLeast)
    }

    /// Check whether `candidate` satisfies this spec.
    #[must_use]
    pub fn matches(&self, candidate: &SemanticVersion) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(req) => candidate == req,
            Self::AtLeast(req) => candidate >= req,
            Self::GreaterThan(req) => candidate > req,
            Self::AtMost(req) => candidate <= req,
            Self::LessThan(req) => candidate < req,
            Self::Compatible(req) => {
                candidate.major == req.major && candidate >= req
            }
            Self::Approximately(req) => {
                candidate.major == req.major
                    && candidate.minor == req.minor
                    && candidate >= req
            }
        }
    }

    /// Human-readable name for this spec variant.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Exact(_) => "exact",
            Self::AtLeast(_) => "at_least",
            Self::GreaterThan(_) => "greater_than",
            Self::AtMost(_) => "at_most",
            Self::LessThan(_) => "less_than",
            Self::Compatible(_) => "compatible",
            Self::Approximately(_) => "approximately",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for VersionSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Exact(v) => write!(f, "={v}"),
            Self::AtLeast(v) => write!(f, ">={v}"),
            Self::GreaterThan(v) => write!(f, ">{v}"),
            Self::AtMost(v) => write!(f, "<={v}"),
            Self::LessThan(v) => write!(f, "<{v}"),
            Self::Compatible(v) => write!(f, "^{v}"),
            Self::Approximately(v) => write!(f, "~{v}"),
        }
    }
}

// ── CompatResult ──────────────────────────────────────────────────────────────

/// The result of a compatibility check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatResult {
    /// The plugin is fully compatible with the running host.
    Compatible,
    /// The plugin is compatible but an upgrade is recommended.
    CompatibleWithWarning { reason: String },
    /// The plugin requires a higher host version.
    HostTooOld {
        required: SemanticVersion,
        found: SemanticVersion,
    },
    /// The host is newer than the plugin was tested against (may still work).
    HostTooNew {
        tested_up_to: SemanticVersion,
        found: SemanticVersion,
    },
    /// The major versions differ — ABI incompatibility guaranteed.
    MajorMismatch {
        plugin_requires: u32,
        host_has: u32,
    },
    /// A plugin dependency version requirement is not met.
    DependencyNotMet {
        dep_name: String,
        required: VersionSpec,
        found: SemanticVersion,
    },
    /// Version string could not be parsed.
    ParseError { raw: String },
}

impl CompatResult {
    /// Whether this result allows the plugin to be loaded.
    #[must_use]
    pub fn is_loadable(&self) -> bool {
        matches!(
            self,
            Self::Compatible | Self::CompatibleWithWarning { .. } | Self::HostTooNew { .. }
        )
    }

    /// Whether this result is a hard failure.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !self.is_loadable()
    }
}

impl fmt::Display for CompatResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatible => write!(f, "compatible"),
            Self::CompatibleWithWarning { reason } => {
                write!(f, "compatible (warning: {reason})")
            }
            Self::HostTooOld { required, found } => {
                write!(f, "host too old: need >={required}, have {found}")
            }
            Self::HostTooNew { tested_up_to, found } => {
                write!(
                    f,
                    "host newer than tested ({tested_up_to}), running {found}"
                )
            }
            Self::MajorMismatch {
                plugin_requires,
                host_has,
            } => {
                write!(
                    f,
                    "major version mismatch: plugin needs major {plugin_requires}, host is {host_has}"
                )
            }
            Self::DependencyNotMet {
                dep_name,
                required,
                found,
            } => {
                write!(
                    f,
                    "dependency '{dep_name}' not met: need {required}, found {found}"
                )
            }
            Self::ParseError { raw } => write!(f, "cannot parse version '{raw}'"),
        }
    }
}

// ── PluginVersionChecker ──────────────────────────────────────────────────────

/// Checks plugin versions for compatibility with the running RustRE host.
///
/// # Usage
///
/// ```
/// use rustre_plugin_loader::plugin_version_checker::{
///     PluginVersionChecker, SemanticVersion, VersionSpec, CompatResult,
/// };
///
/// let host_version = SemanticVersion::release(1, 2, 0);
/// let checker = PluginVersionChecker::new(host_version);
///
/// let result = checker.check_compat(">=1.0.0");
/// assert!(result.is_loadable());
/// ```
#[derive(Debug, Clone)]
pub struct PluginVersionChecker {
    /// The version of the running RustRE host.
    pub host_version: SemanticVersion,
    /// When `true`, plugins tested against an older minor release produce
    /// a `CompatibleWithWarning` instead of `HostTooNew`.
    pub warn_on_host_newer: bool,
}

impl PluginVersionChecker {
    /// Create a new checker with the given host version.
    #[must_use]
    pub fn new(host_version: SemanticVersion) -> Self {
        Self {
            host_version,
            warn_on_host_newer: true,
        }
    }

    /// Check whether the host satisfies `version_req` (a raw version-spec string).
    ///
    /// This is the primary entry point for plugin manifests: call with the
    /// `min_host_version` string declared in the manifest.
    #[must_use]
    pub fn check_compat(&self, version_req: &str) -> CompatResult {
        let Some(spec) = VersionSpec::parse(version_req) else {
            return CompatResult::ParseError {
                raw: version_req.to_string(),
            };
        };
        self.check_compat_with_spec(&spec)
    }

    /// Check compatibility given a parsed [`VersionSpec`].
    #[must_use]
    pub fn check_compat_with_spec(&self, spec: &VersionSpec) -> CompatResult {
        if spec == &VersionSpec::Any {
            return CompatResult::Compatible;
        }

        // Extract the required version for major-mismatch fast path.
        let req_version = match spec {
            VersionSpec::Exact(v)
            | VersionSpec::AtLeast(v)
            | VersionSpec::GreaterThan(v)
            | VersionSpec::AtMost(v)
            | VersionSpec::LessThan(v)
            | VersionSpec::Compatible(v)
            | VersionSpec::Approximately(v) => v.clone(),
            VersionSpec::Any => unreachable!(),
        };

        // Hard fail on major version mismatch, but only for lower-bound and
        // exact specs.  For upper-bound specs (`AtMost`, `LessThan`) a major
        // difference means the host is too new, not an ABI mismatch.
        let is_upper_bound = matches!(spec, VersionSpec::AtMost(_) | VersionSpec::LessThan(_));
        if req_version.major != self.host_version.major && !is_upper_bound {
            return CompatResult::MajorMismatch {
                plugin_requires: req_version.major,
                host_has: self.host_version.major,
            };
        }

        if spec.matches(&self.host_version) {
            // The host satisfies the spec — but check if host is too new.
            if self.warn_on_host_newer && self.host_version > req_version {
                if let VersionSpec::AtMost(_) | VersionSpec::LessThan(_) = spec {
                    return CompatResult::HostTooNew {
                        tested_up_to: req_version,
                        found: self.host_version.clone(),
                    };
                }
            }
            CompatResult::Compatible
        } else {
            // Spec not satisfied — figure out direction.
            match spec {
                VersionSpec::AtMost(_) | VersionSpec::LessThan(_) => CompatResult::HostTooNew {
                    tested_up_to: req_version,
                    found: self.host_version.clone(),
                },
                _ => CompatResult::HostTooOld {
                    required: req_version,
                    found: self.host_version.clone(),
                },
            }
        }
    }

    /// Check that a specific plugin dependency version satisfies a spec.
    #[must_use]
    pub fn check_dep_compat(
        &self,
        dep_name: &str,
        dep_version: &str,
        required_spec: &str,
    ) -> CompatResult {
        let Some(candidate) = SemanticVersion::parse(dep_version) else {
            return CompatResult::ParseError {
                raw: dep_version.to_string(),
            };
        };
        let Some(spec) = VersionSpec::parse(required_spec) else {
            return CompatResult::ParseError {
                raw: required_spec.to_string(),
            };
        };
        if spec.matches(&candidate) {
            CompatResult::Compatible
        } else {
            CompatResult::DependencyNotMet {
                dep_name: dep_name.to_string(),
                required: spec,
                found: candidate,
            }
        }
    }

    /// Check a batch of (plugin_name, min_host_version_req) pairs.
    ///
    /// Returns a `Vec` aligned with the input: each element is the result for
    /// the corresponding plugin.
    #[must_use]
    pub fn check_batch<'a>(
        &self,
        requirements: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<(&'a str, CompatResult)> {
        requirements
            .into_iter()
            .map(|(name, req)| (name, self.check_compat(req)))
            .collect()
    }

    /// Filter a list of plugins, returning only those that are loadable.
    #[must_use]
    pub fn filter_loadable<'a>(
        &self,
        plugins: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<&'a str> {
        plugins
            .into_iter()
            .filter(|(_, req)| self.check_compat(req).is_loadable())
            .map(|(name, _)| name)
            .collect()
    }

    /// Check that `candidate` is newer than or equal to `baseline`.
    ///
    /// Useful for upgrade checks: returns `true` when `candidate` is an
    /// acceptable upgrade from `baseline`.
    #[must_use]
    pub fn is_upgrade(baseline: &SemanticVersion, candidate: &SemanticVersion) -> bool {
        candidate > baseline
    }

    /// Compare two version strings and return their ordering.
    ///
    /// Returns `None` if either string cannot be parsed.
    #[must_use]
    pub fn compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
        let va = SemanticVersion::parse(a)?;
        let vb = SemanticVersion::parse(b)?;
        Some(va.cmp(&vb))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn host(major: u32, minor: u32, patch: u32) -> PluginVersionChecker {
        PluginVersionChecker::new(SemanticVersion::release(major, minor, patch))
    }

    // ── SemanticVersion ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_simple() {
        let v = SemanticVersion::parse("1.2.3").unwrap();
        assert_eq!(v.as_triple(), (1, 2, 3));
        assert!(v.pre.is_none());
    }

    #[test]
    fn test_parse_pre_release() {
        let v = SemanticVersion::parse("2.0.0-alpha").unwrap();
        assert_eq!(v.pre.as_deref(), Some("alpha"));
    }

    #[test]
    fn test_parse_with_v_prefix() {
        let v = SemanticVersion::parse("v3.1.4").unwrap();
        assert_eq!(v.major, 3);
    }

    #[test]
    fn test_parse_build_metadata() {
        let v = SemanticVersion::parse("1.0.0+build.42").unwrap();
        assert!(v.build.is_some());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(SemanticVersion::parse("not-a-version").is_none());
        assert!(SemanticVersion::parse("1.2").is_none());
    }

    #[test]
    fn test_ordering() {
        let a = SemanticVersion::release(1, 0, 0);
        let b = SemanticVersion::release(1, 0, 1);
        let c = SemanticVersion::release(2, 0, 0);
        assert!(b > a);
        assert!(c > b);
    }

    #[test]
    fn test_pre_release_lower_than_release() {
        let pre = SemanticVersion::parse("1.0.0-alpha").unwrap();
        let rel = SemanticVersion::release(1, 0, 0);
        assert!(pre < rel);
    }

    #[test]
    fn test_is_compatible_with() {
        let host_v = SemanticVersion::release(1, 5, 0);
        let req = SemanticVersion::release(1, 2, 0);
        assert!(host_v.is_compatible_with(&req));
        let major_mismatch = SemanticVersion::release(2, 0, 0);
        assert!(!host_v.is_compatible_with(&major_mismatch));
    }

    // ── VersionSpec ───────────────────────────────────────────────────────────

    #[test]
    fn test_spec_at_least() {
        let spec = VersionSpec::parse(">=1.0.0").unwrap();
        assert!(spec.matches(&SemanticVersion::release(1, 0, 0)));
        assert!(spec.matches(&SemanticVersion::release(1, 5, 0)));
        assert!(!spec.matches(&SemanticVersion::release(0, 9, 9)));
    }

    #[test]
    fn test_spec_caret() {
        let spec = VersionSpec::parse("^1.2.0").unwrap();
        assert!(spec.matches(&SemanticVersion::release(1, 2, 0)));
        assert!(spec.matches(&SemanticVersion::release(1, 9, 9)));
        assert!(!spec.matches(&SemanticVersion::release(2, 0, 0)));
    }

    #[test]
    fn test_spec_tilde() {
        let spec = VersionSpec::parse("~1.2.0").unwrap();
        assert!(spec.matches(&SemanticVersion::release(1, 2, 5)));
        assert!(!spec.matches(&SemanticVersion::release(1, 3, 0)));
    }

    #[test]
    fn test_spec_any() {
        let spec = VersionSpec::parse("*").unwrap();
        assert!(spec.matches(&SemanticVersion::release(99, 0, 0)));
    }

    #[test]
    fn test_spec_exact() {
        let spec = VersionSpec::parse("=1.0.0").unwrap();
        assert!(spec.matches(&SemanticVersion::release(1, 0, 0)));
        assert!(!spec.matches(&SemanticVersion::release(1, 0, 1)));
    }

    #[test]
    fn test_spec_display() {
        let spec = VersionSpec::parse("^2.1.0").unwrap();
        assert_eq!(spec.to_string(), "^2.1.0");
    }

    // ── PluginVersionChecker ──────────────────────────────────────────────────

    #[test]
    fn test_check_compat_satisfied() {
        let checker = host(1, 5, 0);
        let r = checker.check_compat(">=1.0.0");
        assert!(r.is_loadable());
        assert_eq!(r, CompatResult::Compatible);
    }

    #[test]
    fn test_check_compat_host_too_old() {
        let checker = host(1, 0, 0);
        let r = checker.check_compat(">=1.2.0");
        assert!(r.is_failure());
        assert!(matches!(r, CompatResult::HostTooOld { .. }));
    }

    #[test]
    fn test_check_compat_major_mismatch() {
        let checker = host(2, 0, 0);
        let r = checker.check_compat(">=1.0.0");
        assert!(matches!(r, CompatResult::MajorMismatch { .. }));
    }

    #[test]
    fn test_check_compat_any() {
        let checker = host(5, 0, 0);
        let r = checker.check_compat("*");
        assert_eq!(r, CompatResult::Compatible);
    }

    #[test]
    fn test_check_compat_parse_error() {
        let checker = host(1, 0, 0);
        let r = checker.check_compat("garbage!!");
        assert!(matches!(r, CompatResult::ParseError { .. }));
    }

    #[test]
    fn test_check_dep_compat() {
        let checker = host(1, 0, 0);
        let r = checker.check_dep_compat("core", "1.2.0", ">=1.0.0");
        assert_eq!(r, CompatResult::Compatible);
        let r2 = checker.check_dep_compat("core", "0.9.0", ">=1.0.0");
        assert!(matches!(r2, CompatResult::DependencyNotMet { .. }));
    }

    #[test]
    fn test_batch_check() {
        let checker = host(1, 5, 0);
        let results = checker.check_batch([("plugA", ">=1.0.0"), ("plugB", ">=2.0.0")]);
        assert_eq!(results.len(), 2);
        assert!(results[0].1.is_loadable());
        assert!(results[1].1.is_failure());
    }

    #[test]
    fn test_filter_loadable() {
        let checker = host(1, 5, 0);
        let loadable = checker.filter_loadable([("ok", ">=1.0.0"), ("bad", ">=2.0.0")]);
        assert_eq!(loadable, vec!["ok"]);
    }

    #[test]
    fn test_is_upgrade() {
        let a = SemanticVersion::release(1, 0, 0);
        let b = SemanticVersion::release(1, 1, 0);
        assert!(PluginVersionChecker::is_upgrade(&a, &b));
        assert!(!PluginVersionChecker::is_upgrade(&b, &a));
    }

    #[test]
    fn test_compare() {
        assert_eq!(
            PluginVersionChecker::compare("1.0.0", "1.0.1"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            PluginVersionChecker::compare("2.0.0", "2.0.0"),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn test_compat_result_display() {
        let r = CompatResult::HostTooOld {
            required: SemanticVersion::release(2, 0, 0),
            found: SemanticVersion::release(1, 9, 9),
        };
        assert!(r.to_string().contains("2.0.0"));
    }

    #[test]
    fn test_next_patch_minor_major() {
        let v = SemanticVersion::release(1, 2, 3);
        assert_eq!(v.next_patch().unwrap().as_triple(), (1, 2, 4));
        assert_eq!(v.next_minor().unwrap().as_triple(), (1, 3, 0));
        assert_eq!(v.next_major().unwrap().as_triple(), (2, 0, 0));
    }

    #[test]
    fn test_next_patch_overflow() {
        let v = SemanticVersion::release(1, 2, u32::MAX);
        assert!(v.next_patch().is_none());
    }

    #[test]
    fn test_next_minor_overflow() {
        let v = SemanticVersion::release(1, u32::MAX, 0);
        assert!(v.next_minor().is_none());
    }

    #[test]
    fn test_next_major_overflow() {
        let v = SemanticVersion::release(u32::MAX, 0, 0);
        assert!(v.next_major().is_none());
    }
}
