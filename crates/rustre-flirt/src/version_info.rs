//! `version_info` — FLIRT engine version and capability introspection.
//!
//! Provides:
//!
//! * [`FlirtVersion`] — the current crate version and FLIRT schema version.
//! * [`FlirtCapabilities`] — the set of formats and sizes supported by this build.
//! * [`compatibility_check`] — compare a required capability set against what
//!   is available.

use std::fmt;

// ---------------------------------------------------------------------------
// FlirtVersion
// ---------------------------------------------------------------------------

/// Version information for the FLIRT engine embedded in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlirtVersion {
    /// Crate semver (major.minor.patch).
    pub crate_version: &'static str,
    /// FLIRT binary-file schema version supported by this build.
    pub schema_version: u32,
    /// Minimum FLIRT schema version this build can read.
    pub min_schema_version: u32,
    /// Maximum FLIRT schema version this build can read.
    pub max_schema_version: u32,
}

impl FlirtVersion {
    /// Return the statically-compiled version for the current build.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            crate_version: env!("CARGO_PKG_VERSION"),
            schema_version: 9,
            min_schema_version: 5,
            max_schema_version: 10,
        }
    }

    /// Return `true` if `schema` is within the supported schema range.
    #[must_use]
    pub const fn supports_schema(&self, schema: u32) -> bool {
        schema >= self.min_schema_version && schema <= self.max_schema_version
    }

    /// Return the [semver](https://semver.org/) major component.
    #[must_use]
    pub fn major(&self) -> u32 {
        self.crate_version
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Return a human-readable version string.
    #[must_use]
    pub fn display_string(&self) -> String {
        format!(
            "rustre-flirt {} (FLIRT schema {}-{})",
            self.crate_version, self.min_schema_version, self.max_schema_version
        )
    }
}

impl fmt::Display for FlirtVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_string())
    }
}

// ---------------------------------------------------------------------------
// FlirtCapabilities
// ---------------------------------------------------------------------------

/// Bitfield tracking which FLIRT file-format features are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlirtSupportFlags(u8);

impl FlirtSupportFlags {
    const SIG_BIT: u8 = 0b0001;
    const PAT_BIT: u8 = 0b0010;
    const CRC16_BIT: u8 = 0b0100;
    const TAIL_BIT: u8 = 0b1000;

    /// All features enabled.
    pub const ALL: Self = Self(0b1111);

    /// Returns `true` if `.sig` file loading is supported.
    #[must_use]
    pub const fn sig_files(self) -> bool { self.0 & Self::SIG_BIT != 0 }
    /// Returns `true` if `.pat` file loading is supported.
    #[must_use]
    pub const fn pat_files(self) -> bool { self.0 & Self::PAT_BIT != 0 }
    /// Returns `true` if CRC-16 disambiguation is supported.
    #[must_use]
    pub const fn crc16(self) -> bool { self.0 & Self::CRC16_BIT != 0 }
    /// Returns `true` if tail-byte disambiguation is supported.
    #[must_use]
    pub const fn tail_bytes(self) -> bool { self.0 & Self::TAIL_BIT != 0 }
}

/// The set of capabilities supported by this build of the FLIRT engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlirtCapabilities {
    /// File formats that can be parsed.
    pub supported_formats: Vec<&'static str>,
    /// Maximum supported pattern initial-byte count.
    pub max_pattern_bytes: usize,
    /// Maximum supported CRC region length.
    pub max_sig_size: usize,
    /// Which file-format features are supported.
    pub support: FlirtSupportFlags,
}

impl FlirtCapabilities {
    /// Return the capabilities of the current build.
    #[must_use]
    pub fn current() -> Self {
        Self {
            supported_formats: vec!["sig", "pat"],
            max_pattern_bytes: 32,
            max_sig_size: 256,
            support: FlirtSupportFlags::ALL,
        }
    }

    /// Return `true` if the format (e.g. `"sig"` or `"pat"`) is supported.
    #[must_use]
    pub fn supports_format(&self, format: &str) -> bool {
        self.supported_formats.contains(&format)
    }

    /// Return `true` if a pattern of `n` bytes fits within the supported range.
    #[must_use]
    pub const fn supports_pattern_size(&self, n: usize) -> bool {
        n > 0 && n <= self.max_pattern_bytes
    }
}

impl fmt::Display for FlirtCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlirtCapabilities(formats=[{}], max_pat={}, max_sig={})",
            self.supported_formats.join(","),
            self.max_pattern_bytes,
            self.max_sig_size,
        )
    }
}

// ---------------------------------------------------------------------------
// CompatibilityCheck
// ---------------------------------------------------------------------------

/// Result of a compatibility check between required and available capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityCheckResult {
    /// `true` when all requirements are satisfied.
    pub is_compatible: bool,
    /// Any requirements that are not met.
    pub unsatisfied: Vec<String>,
}

impl CompatibilityCheckResult {
    /// Return `true` if all requirements are met.
    #[must_use]
    pub const fn compatible(&self) -> bool {
        self.is_compatible
    }
}

impl fmt::Display for CompatibilityCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_compatible {
            write!(f, "compatible")
        } else {
            write!(f, "incompatible: {}", self.unsatisfied.join("; "))
        }
    }
}

/// Check whether the current engine capabilities satisfy the requirements
/// expressed by `required_schema`, `required_format`, and
/// `required_max_pattern`.
///
/// Returns a [`CompatibilityCheckResult`] describing any unsatisfied needs.
#[must_use]
pub fn compatibility_check(
    required_schema: u32,
    required_format: &str,
    required_max_pattern: usize,
) -> CompatibilityCheckResult {
    let ver = FlirtVersion::current();
    let caps = FlirtCapabilities::current();
    let mut unsatisfied = Vec::new();

    if !ver.supports_schema(required_schema) {
        unsatisfied.push(format!(
            "schema {} not in [{}, {}]",
            required_schema, ver.min_schema_version, ver.max_schema_version
        ));
    }
    if !caps.supports_format(required_format) {
        unsatisfied.push(format!("format '{required_format}' not supported"));
    }
    if required_max_pattern > caps.max_pattern_bytes {
        unsatisfied.push(format!(
            "pattern size {required_max_pattern} > max {}",
            caps.max_pattern_bytes
        ));
    }

    CompatibilityCheckResult {
        is_compatible: unsatisfied.is_empty(),
        unsatisfied,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flirt_version_current_non_empty() {
        let v = FlirtVersion::current();
        assert!(!v.crate_version.is_empty());
        assert!(v.schema_version > 0);
        assert!(v.max_schema_version >= v.min_schema_version);
    }

    #[test]
    fn test_flirt_version_supports_schema_in_range() {
        let v = FlirtVersion::current();
        assert!(v.supports_schema(v.schema_version));
        assert!(v.supports_schema(v.min_schema_version));
        assert!(v.supports_schema(v.max_schema_version));
    }

    #[test]
    fn test_flirt_version_rejects_out_of_range_schema() {
        let v = FlirtVersion::current();
        assert!(!v.supports_schema(0));
        assert!(!v.supports_schema(v.max_schema_version + 1));
    }

    #[test]
    fn test_flirt_version_display() {
        let v = FlirtVersion::current();
        let s = v.to_string();
        assert!(s.contains("rustre-flirt"), "unexpected: {s}");
    }

    #[test]
    fn test_flirt_capabilities_current_non_empty() {
        let c = FlirtCapabilities::current();
        assert!(!c.supported_formats.is_empty());
        assert!(c.max_pattern_bytes > 0);
        assert!(c.max_sig_size > 0);
    }

    #[test]
    fn test_flirt_capabilities_supports_known_formats() {
        let c = FlirtCapabilities::current();
        assert!(c.supports_format("sig"));
        assert!(c.supports_format("pat"));
        assert!(!c.supports_format("elf"));
    }

    #[test]
    fn test_flirt_capabilities_pattern_size_bounds() {
        let c = FlirtCapabilities::current();
        assert!(c.supports_pattern_size(1));
        assert!(c.supports_pattern_size(c.max_pattern_bytes));
        assert!(!c.supports_pattern_size(0));
        assert!(!c.supports_pattern_size(c.max_pattern_bytes + 1));
    }

    #[test]
    fn test_compatibility_check_valid() {
        let result = compatibility_check(9, "sig", 32);
        assert!(result.is_compatible, "{result}");
        assert!(result.unsatisfied.is_empty());
    }

    #[test]
    fn test_compatibility_check_bad_schema() {
        let result = compatibility_check(0, "sig", 32);
        assert!(!result.is_compatible);
        assert!(result.unsatisfied.iter().any(|s| s.contains("schema")));
    }

    #[test]
    fn test_compatibility_check_unknown_format() {
        let result = compatibility_check(9, "xyz", 32);
        assert!(!result.is_compatible);
        assert!(result.unsatisfied.iter().any(|s| s.contains("format")));
    }

    #[test]
    fn test_compatibility_check_pattern_too_large() {
        let result = compatibility_check(9, "sig", 9999);
        assert!(!result.is_compatible);
        assert!(
            result
                .unsatisfied
                .iter()
                .any(|s| s.contains("pattern size"))
        );
    }

    #[test]
    fn test_compatibility_check_result_display_compatible() {
        let r = CompatibilityCheckResult {
            is_compatible: true,
            unsatisfied: vec![],
        };
        assert_eq!(r.to_string(), "compatible");
    }
}
