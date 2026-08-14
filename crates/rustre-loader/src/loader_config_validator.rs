//! Loader configuration validator.
//!
//! Validates `LoaderOptions` and related configuration structures before they
//! are applied to a loading session, surfacing actionable diagnostics rather
//! than opaque panics.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// ValidationError
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational note; does not prevent loading.
    Info,
    /// Non-fatal warning; loading may still proceed.
    Warning,
    /// Fatal error; loading must not proceed.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A single validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Severity level.
    pub severity: Severity,
    /// Field path within the configuration (e.g. `"options.base_address"`).
    pub field: String,
    /// Human-readable description.
    pub message: String,
    /// Optional suggested fix.
    pub suggestion: Option<String>,
}

impl ValidationError {
    /// Construct an error-level finding.
    #[must_use]
    pub fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            field: field.into(),
            message: message.into(),
            suggestion: None,
        }
    }

    /// Construct a warning-level finding.
    #[must_use]
    pub fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            field: field.into(),
            message: message.into(),
            suggestion: None,
        }
    }

    /// Construct an info-level finding.
    #[must_use]
    pub fn info(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            field: field.into(),
            message: message.into(),
            suggestion: None,
        }
    }

    /// Attach a suggestion string.
    #[must_use]
    pub fn with_suggestion(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.field, self.message)?;
        if let Some(s) = &self.suggestion {
            write!(f, " (hint: {s})")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateResult
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result from a validation run.
#[derive(Debug, Clone, Default)]
pub struct ValidateResult {
    /// All findings collected during validation.
    pub findings: Vec<ValidationError>,
}

impl ValidateResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a finding.
    pub fn push(&mut self, e: ValidationError) {
        self.findings.push(e);
    }

    /// Return `true` if there are any error-severity findings.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    /// Return `true` if there are any warning-severity findings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Warning)
    }

    /// Return `true` if all findings are at info level or there are none.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        !self.has_errors()
    }

    /// Return only error-level findings.
    #[must_use]
    pub fn errors(&self) -> Vec<&ValidationError> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect()
    }

    /// Return only warning-level findings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationError> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect()
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: Self) {
        self.findings.extend(other.findings);
    }

    /// Return the highest severity level present, or `None` if empty.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Format all findings as a multi-line string.
    #[must_use]
    pub fn report(&self) -> String {
        self.findings
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl fmt::Display for ValidateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.report())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderConfigSpec — the configuration structure to be validated
// ─────────────────────────────────────────────────────────────────────────────

/// A validated representation of loader options.
///
/// This mirrors the fields used by the loader crate but is self-contained so
/// the validator has no dependency on the loader runtime.
#[derive(Debug, Clone)]
pub struct LoaderConfigSpec {
    /// Optional explicit base address (overrides the binary's own preference).
    pub base_address: Option<u64>,
    /// Whether to apply relocations.
    pub apply_relocations: bool,
    /// Whether to resolve imports (may require a filesystem or symbol server).
    pub resolve_imports: bool,
    /// Forced architecture override (e.g. "`x86_64`").
    pub arch_override: Option<String>,
    /// Forced endianness override ("little" or "big").
    pub endian_override: Option<String>,
    /// Maximum image size in bytes; 0 = unlimited.
    pub max_image_size: u64,
    /// Section name allowlist; empty = allow all.
    pub section_allowlist: Vec<String>,
    /// Section name denylist.
    pub section_denylist: Vec<String>,
    /// Optional file path of the binary (for path-based heuristics).
    pub file_path: Option<String>,
    /// Loader-specific extension map: key → value.
    pub extensions: HashMap<String, String>,
    /// Number of parallel loading threads; 0 = auto.
    pub parallelism: usize,
    /// Cache capacity in number of entries; 0 = disabled.
    pub cache_capacity: usize,
    /// Maximum number of nested loaders (for recursive formats like ZIP).
    pub max_nesting_depth: u32,
    /// Whether to emit verbose trace logs.
    pub verbose: bool,
}

impl Default for LoaderConfigSpec {
    fn default() -> Self {
        Self {
            base_address: None,
            apply_relocations: true,
            resolve_imports: false,
            arch_override: None,
            endian_override: None,
            max_image_size: 0,
            section_allowlist: Vec::new(),
            section_denylist: Vec::new(),
            file_path: None,
            extensions: HashMap::new(),
            parallelism: 0,
            cache_capacity: 1024,
            max_nesting_depth: 4,
            verbose: false,
        }
    }
}

impl LoaderConfigSpec {
    /// Create a default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the base address.
    #[must_use]
    pub const fn with_base_address(mut self, addr: u64) -> Self {
        self.base_address = Some(addr);
        self
    }

    /// Builder: set the architecture override.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch_override = Some(arch.into());
        self
    }

    /// Builder: set the endianness override.
    #[must_use]
    pub fn with_endian(mut self, endian: impl Into<String>) -> Self {
        self.endian_override = Some(endian.into());
        self
    }

    /// Builder: set maximum image size.
    #[must_use]
    pub const fn with_max_image_size(mut self, max: u64) -> Self {
        self.max_image_size = max;
        self
    }

    /// Builder: set parallelism.
    #[must_use]
    pub const fn with_parallelism(mut self, n: usize) -> Self {
        self.parallelism = n;
        self
    }

    /// Builder: set cache capacity.
    #[must_use]
    pub const fn with_cache_capacity(mut self, cap: usize) -> Self {
        self.cache_capacity = cap;
        self
    }

    /// Builder: add an extension key/value pair.
    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extensions.insert(key.into(), value.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual validators
// ─────────────────────────────────────────────────────────────────────────────

fn validate_base_address(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if let Some(addr) = spec.base_address {
        if addr % 0x1000 != 0 {
            result.push(
                ValidationError::warning(
                    "base_address",
                    format!("base address {addr:#x} is not page-aligned (0x1000)"),
                )
                .with_suggestion("use a multiple of 0x1000 to avoid mapping issues"),
            );
        }
        if addr == 0 {
            result.push(ValidationError::warning(
                "base_address",
                "explicit base address of 0 may conflict with null-pointer checks",
            ));
        }
        if addr >= 0xFFFF_0000_0000_0000 {
            result.push(ValidationError::error(
                "base_address",
                format!("base address {addr:#x} is in kernel space on most architectures"),
            ));
        }
    }
}

fn validate_arch(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    const KNOWN_ARCHES: &[&str] = &[
        "x86", "x86_64", "aarch64", "arm", "mips", "mips64",
        "ppc", "ppc64", "riscv32", "riscv64", "s390x", "wasm32", "wasm64",
    ];
    if let Some(arch) = &spec.arch_override {
        if arch.is_empty() {
            result.push(ValidationError::error(
                "arch_override",
                "arch_override must not be an empty string",
            ));
        } else if !KNOWN_ARCHES.contains(&arch.as_str()) {
            result.push(
                ValidationError::warning(
                    "arch_override",
                    format!("unrecognised architecture '{arch}'"),
                )
                .with_suggestion(
                    format!("known values: {}", KNOWN_ARCHES.join(", ")),
                ),
            );
        }
    }
}

fn validate_endian(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if let Some(endian) = &spec.endian_override
        && !matches!(endian.as_str(), "little" | "big" | "le" | "be") {
            result.push(
                ValidationError::error(
                    "endian_override",
                    format!("invalid endianness value '{endian}'"),
                )
                .with_suggestion("use 'little' or 'big'"),
            );
        }
}

fn validate_image_size(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    const MAX_SANE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
    if spec.max_image_size > 0 && spec.max_image_size < 512 {
        result.push(
            ValidationError::error(
                "max_image_size",
                format!("max_image_size {} is unreasonably small (< 512 bytes)", spec.max_image_size),
            ),
        );
    }
    if spec.max_image_size > MAX_SANE {
        result.push(
            ValidationError::warning(
                "max_image_size",
                format!(
                    "max_image_size {} ({:.1} GiB) is very large",
                    spec.max_image_size,
                    f64::from(u32::try_from(spec.max_image_size).unwrap_or(u32::MAX)) / 1024.0 / 1024.0 / 1024.0
                ),
            )
            .with_suggestion("consider reducing to avoid excessive memory usage"),
        );
    }
}

fn validate_section_lists(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    // Check for duplicates within allowlist.
    let allow_set: HashSet<&str> = spec.section_allowlist.iter().map(std::string::String::as_str).collect();
    if allow_set.len() < spec.section_allowlist.len() {
        result.push(ValidationError::warning(
            "section_allowlist",
            "section_allowlist contains duplicate entries",
        ));
    }

    // Check for overlap between allowlist and denylist.
    for name in &spec.section_denylist {
        if allow_set.contains(name.as_str()) {
            result.push(
                ValidationError::error(
                    "section_denylist",
                    format!("section '{name}' appears in both allowlist and denylist"),
                )
                .with_suggestion("remove it from one of the two lists"),
            );
        }
    }

    // Warn about empty section names.
    for name in spec.section_allowlist.iter().chain(spec.section_denylist.iter()) {
        if name.is_empty() {
            result.push(ValidationError::warning(
                "section_list",
                "empty string in section list matches no section name",
            ));
        }
    }
}

fn validate_file_path(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if let Some(path) = &spec.file_path {
        if path.is_empty() {
            result.push(ValidationError::warning(
                "file_path",
                "file_path is an empty string; omit it if no file path is known",
            ));
        } else {
            let p = Path::new(path);
            if p.extension().is_none() {
                result.push(ValidationError::info(
                    "file_path",
                    format!("file '{path}' has no extension; format auto-detection may be imprecise"),
                ));
            }
        }
    }
}

fn validate_parallelism(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if spec.parallelism > 512 {
        result.push(
            ValidationError::warning(
                "parallelism",
                format!("parallelism={} is unusually high", spec.parallelism),
            )
            .with_suggestion("values above the CPU thread count rarely improve throughput"),
        );
    }
}

fn validate_nesting_depth(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if spec.max_nesting_depth > 32 {
        result.push(
            ValidationError::warning(
                "max_nesting_depth",
                format!("max_nesting_depth={} may allow deep recursion with malicious inputs", spec.max_nesting_depth),
            )
            .with_suggestion("values above 8 are rarely needed"),
        );
    }
    if spec.max_nesting_depth == 0 {
        result.push(ValidationError::error(
            "max_nesting_depth",
            "max_nesting_depth=0 disables recursive loading entirely",
        ));
    }
}

fn validate_extension_keys(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    for key in spec.extensions.keys() {
        if key.is_empty() {
            result.push(ValidationError::error(
                "extensions",
                "extension map contains an empty key",
            ));
        }
        if key.contains(' ') {
            result.push(ValidationError::warning(
                "extensions",
                format!("extension key '{key}' contains whitespace; this may not be portable"),
            ));
        }
    }
}

fn validate_import_relocation_consistency(spec: &LoaderConfigSpec, result: &mut ValidateResult) {
    if spec.resolve_imports && !spec.apply_relocations {
        result.push(
            ValidationError::warning(
                "resolve_imports",
                "resolve_imports=true with apply_relocations=false may produce incorrect addresses",
            )
            .with_suggestion("enable apply_relocations when resolve_imports is active"),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderConfigValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates a [`LoaderConfigSpec`] and returns a [`ValidateResult`].
#[derive(Debug, Default)]
pub struct LoaderConfigValidator {
    /// Extra extension keys that are known-valid (loader-specific).
    known_extension_keys: HashSet<String>,
    /// Strict mode: treat all warnings as errors.
    strict: bool,
}

impl LoaderConfigValidator {
    /// Create a new validator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable strict mode: all warnings are promoted to errors.
    #[must_use]
    pub const fn with_strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Register an extension key as known-valid (suppresses unknown-key warnings).
    pub fn register_extension_key(&mut self, key: impl Into<String>) {
        self.known_extension_keys.insert(key.into());
    }

    /// Validate `spec` and return a [`ValidateResult`].
    ///
    /// If `strict` mode is enabled, any warning-level findings are upgraded to
    /// errors in the returned result.
    #[must_use]
    pub fn validate(&self, spec: &LoaderConfigSpec) -> ValidateResult {
        let mut result = ValidateResult::new();

        validate_base_address(spec, &mut result);
        validate_arch(spec, &mut result);
        validate_endian(spec, &mut result);
        validate_image_size(spec, &mut result);
        validate_section_lists(spec, &mut result);
        validate_file_path(spec, &mut result);
        validate_parallelism(spec, &mut result);
        validate_nesting_depth(spec, &mut result);
        validate_extension_keys(spec, &mut result);
        validate_import_relocation_consistency(spec, &mut result);

        // Check for unknown extension keys.
        if !self.known_extension_keys.is_empty() {
            for key in spec.extensions.keys() {
                if !self.known_extension_keys.contains(key.as_str()) {
                    result.push(ValidationError::info(
                        "extensions",
                        format!("unregistered extension key '{key}'"),
                    ));
                }
            }
        }

        // Apply strict mode: promote warnings to errors.
        if self.strict {
            for finding in &mut result.findings {
                if finding.severity == Severity::Warning {
                    finding.severity = Severity::Error;
                }
            }
        }

        result
    }

    /// Convenience: validate and return `Ok(())` on success or `Err(report)`.
    ///
    /// # Errors
    /// Returns `Err(String)` with the full diagnostic report if any error-level
    /// findings exist.
    pub fn validate_ok(&self, spec: &LoaderConfigSpec) -> Result<ValidateResult, String> {
        let result = self.validate(spec);
        if result.has_errors() {
            Err(result.report())
        } else {
            Ok(result)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates_cleanly() {
        let spec = LoaderConfigSpec::default();
        let v = LoaderConfigValidator::new();
        let result = v.validate(&spec);
        assert!(result.is_ok(), "unexpected errors: {}", result.report());
        assert!(!result.has_warnings());
    }

    #[test]
    fn unaligned_base_address_is_warning() {
        let spec = LoaderConfigSpec::new().with_base_address(0x1001);
        let result = LoaderConfigValidator::new().validate(&spec);
        assert!(result.has_warnings());
        assert!(!result.has_errors());
    }

    #[test]
    fn kernel_space_base_address_is_error() {
        let spec = LoaderConfigSpec::new().with_base_address(0xFFFF_8000_0000_0000);
        let result = LoaderConfigValidator::new().validate(&spec);
        assert!(result.has_errors());
    }

    #[test]
    fn bad_endian_override() {
        let spec = LoaderConfigSpec::new().with_endian("middle");
        let result = LoaderConfigValidator::new().validate(&spec);
        assert!(result.has_errors());
    }

    #[test]
    fn section_overlap_is_error() {
        let mut spec = LoaderConfigSpec::new();
        spec.section_allowlist = vec![".text".into()];
        spec.section_denylist = vec![".text".into()];
        let result = LoaderConfigValidator::new().validate(&spec);
        assert!(result.has_errors());
    }

    #[test]
    fn strict_mode_upgrades_warnings_to_errors() {
        let spec = LoaderConfigSpec::new().with_base_address(0x1001);
        let v = LoaderConfigValidator::new().with_strict();
        let result = v.validate(&spec);
        assert!(result.has_errors());
    }

    #[test]
    fn zero_nesting_depth_is_error() {
        let mut spec = LoaderConfigSpec::new();
        spec.max_nesting_depth = 0;
        let result = LoaderConfigValidator::new().validate(&spec);
        assert!(result.has_errors());
    }

    #[test]
    fn validate_ok_returns_err_on_errors() {
        let spec = LoaderConfigSpec::new().with_endian("sideways");
        let result = LoaderConfigValidator::new().validate_ok(&spec);
        assert!(result.is_err());
    }
}
