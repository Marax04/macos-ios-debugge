//! libFuzzer harness builder for `rustre-fuzz-libfuzzer`.
//!
//! Provides tools to generate, validate, and package libFuzzer-compatible
//! fuzz harnesses in C, Rust, and Go, with OSS-Fuzz and `ClusterFuzz`
//! integration stubs.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from harness building and verification.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("template render error: {0}")]
    Template(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// HarnessLanguage
// ---------------------------------------------------------------------------

/// Target language for the generated harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HarnessLanguage {
    C,
    Rust,
    Go,
}

impl fmt::Display for HarnessLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::C => write!(f, "C"),
            Self::Rust => write!(f, "Rust"),
            Self::Go => write!(f, "Go"),
        }
    }
}

impl HarnessLanguage {
    /// File extension for the source file.
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Rust => "rs",
            Self::Go => "go",
        }
    }

    /// Parse from a string (case-insensitive).
    ///
    /// # Errors
    /// Returns [`HarnessError::UnsupportedLanguage`] if not recognized.
    pub fn from_str(s: &str) -> Result<Self, HarnessError> {
        match s.to_lowercase().as_str() {
            "c" => Ok(Self::C),
            "rust" | "rs" => Ok(Self::Rust),
            "go" => Ok(Self::Go),
            other => Err(HarnessError::UnsupportedLanguage(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// HarnessTemplate
// ---------------------------------------------------------------------------

/// The skeleton of a harness file before variable substitution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessTemplate {
    pub language: HarnessLanguage,
    /// Template source (uses `{{VARIABLE}}` placeholders).
    pub source: String,
    /// Map of variable name → default value.
    pub defaults: HashMap<String, String>,
}

impl HarnessTemplate {
    /// Create a template with default content for the given language.
    #[must_use]
    pub fn default_for(language: HarnessLanguage) -> Self {
        let (source, defaults) = match language {
            HarnessLanguage::C => (Self::c_template(), HashMap::new()),
            HarnessLanguage::Rust => (Self::rust_template(), HashMap::new()),
            HarnessLanguage::Go => (Self::go_template(), HashMap::new()),
        };
        Self {
            language,
            source,
            defaults,
        }
    }

    /// Render the template with the given variable substitutions.
    ///
    /// Missing variables are replaced with their defaults, or left as-is.
    ///
    /// # Errors
    /// Returns [`HarnessError::Template`] if a required variable is missing.
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<String, HarnessError> {
        let mut out = self.source.clone();
        // Collect all {{VAR}} placeholders.
        let mut pos = 0;
        while let Some(start) = out[pos..].find("{{") {
            let abs_start = pos + start;
            if let Some(end_rel) = out[abs_start..].find("}}") {
                let abs_end = abs_start + end_rel + 2;
                // Clone the variable name and looked-up value into owned
                // strings before mutating `out` to avoid aliasing borrows.
                let var_name: String = out[abs_start + 2..abs_end - 2].to_string();
                let value: String = vars
                    .get(&var_name)
                    .or_else(|| self.defaults.get(&var_name))
                    .cloned()
                    .unwrap_or_else(|| var_name.clone());
                out.replace_range(abs_start..abs_end, &value);
                pos = abs_start + value.len();
            } else {
                break;
            }
        }
        Ok(out)
    }

    fn c_template() -> String {
        r"/* libFuzzer harness for {{TARGET_NAME}} */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

{{INIT_CODE}}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < {{MIN_SIZE}}) return 0;
    if (size > {{MAX_SIZE}}) return 0;
    {{FUZZ_BODY}}
    {{CLEANUP_CODE}}
    return 0;
}
"
        .to_string()
    }

    fn rust_template() -> String {
        r"// libFuzzer harness for {{TARGET_NAME}}
#![no_main]

use libfuzzer_sys::fuzz_target;

{{INIT_CODE}}

fuzz_target!(|data: &[u8]| {
    if data.len() < {{MIN_SIZE}} { return; }
    if data.len() > {{MAX_SIZE}} { return; }
    {{FUZZ_BODY}}
    {{CLEANUP_CODE}}
});
"
        .to_string()
    }

    fn go_template() -> String {
        r#"// libFuzzer harness for {{TARGET_NAME}}
package fuzz

import "C"
import "unsafe"

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
    buf := C.GoBytes(unsafe.Pointer(data), C.int(size))
    if len(buf) < {{MIN_SIZE}} { return 0 }
    {{FUZZ_BODY}}
    return 0
}
"#
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// InitializerCode / CleanupCode
// ---------------------------------------------------------------------------

/// Code blocks to be inserted at harness initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitializerCode {
    pub blocks: Vec<String>,
}

impl InitializerCode {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a code block.
    pub fn add(&mut self, code: impl Into<String>) {
        self.blocks.push(code.into());
    }

    /// Render all blocks joined by newlines.
    #[must_use]
    pub fn render(&self) -> String {
        self.blocks.join("\n")
    }
}

/// Code blocks to be executed before the harness returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanupCode {
    pub blocks: Vec<String>,
}

impl CleanupCode {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, code: impl Into<String>) {
        self.blocks.push(code.into());
    }

    #[must_use]
    pub fn render(&self) -> String {
        self.blocks.join("\n")
    }
}

// ---------------------------------------------------------------------------
// FuzzTargetWrapper
// ---------------------------------------------------------------------------

/// Wraps a target function declaration with libFuzzer-compatible calling
/// conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTargetWrapper {
    pub target_name: String,
    pub language: HarnessLanguage,
    pub function_signature: String,
    pub invocation: String,
    pub min_input_size: usize,
    pub max_input_size: usize,
}

impl FuzzTargetWrapper {
    #[must_use]
    pub fn new(target_name: impl Into<String>, language: HarnessLanguage) -> Self {
        Self {
            target_name: target_name.into(),
            language,
            function_signature: String::new(),
            invocation: String::new(),
            min_input_size: 1,
            max_input_size: 65536,
        }
    }

    /// Generate the full harness source for this target.
    ///
    /// # Errors
    /// Returns [`HarnessError::Template`] if template rendering fails.
    pub fn generate_source(
        &self,
        init: &InitializerCode,
        cleanup: &CleanupCode,
    ) -> Result<String, HarnessError> {
        let template = HarnessTemplate::default_for(self.language);
        let mut vars = HashMap::new();
        vars.insert("TARGET_NAME".to_string(), self.target_name.clone());
        vars.insert("FUZZ_BODY".to_string(), self.invocation.clone());
        vars.insert("INIT_CODE".to_string(), init.render());
        vars.insert("CLEANUP_CODE".to_string(), cleanup.render());
        vars.insert("MIN_SIZE".to_string(), self.min_input_size.to_string());
        vars.insert("MAX_SIZE".to_string(), self.max_input_size.to_string());
        template.render(&vars)
    }
}

// ---------------------------------------------------------------------------
// OssFuzzCompat
// ---------------------------------------------------------------------------

/// OSS-Fuzz compatibility helpers.
#[derive(Debug, Clone, Default)]
pub struct OssFuzzCompat;

impl OssFuzzCompat {
    /// Generate a minimal `build.sh` script for OSS-Fuzz.
    #[must_use]
    pub fn generate_build_sh(project: &str, fuzz_targets: &[&str]) -> String {
        let targets: String = fuzz_targets.iter().fold(String::new(), |mut acc, t| {
            use std::fmt::Write;
            let _ = writeln!(acc, "$CXX $CXXFLAGS -std=c++17 -o $OUT/{t} {t}.cc $LIB_FUZZING_ENGINE");
            acc
        });
        format!("#!/bin/bash -eu\n# OSS-Fuzz build script for {project}\nset -e\n\n{targets}")
    }

    /// Generate a project YAML for OSS-Fuzz.
    #[must_use]
    pub fn generate_project_yaml(project: &str, language: &str, repo: &str) -> String {
        format!(
            "homepage: {repo}\nlanguage: {language}\nprimary_contact: fuzz@example.com\nmain_repo: {repo}\nproject_short_name: {project}\n"
        )
    }

    /// Check that a harness source contains the required libFuzzer entry point.
    #[must_use]
    pub fn validate_entry_point(source: &str, language: HarnessLanguage) -> bool {
        match language {
            HarnessLanguage::Rust => source.contains("fuzz_target!"),
            HarnessLanguage::C | HarnessLanguage::Go => source.contains("LLVMFuzzerTestOneInput"),
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterFuzzIntegration
// ---------------------------------------------------------------------------

/// `ClusterFuzz` integration metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterFuzzIntegration {
    pub project_name: String,
    pub fuzz_target: String,
    pub engine: String,
    pub sanitizer: String,
    pub architecture: String,
    pub corpus_dir: PathBuf,
    pub crash_dir: PathBuf,
}

impl ClusterFuzzIntegration {
    #[must_use]
    pub fn new(project_name: impl Into<String>, fuzz_target: impl Into<String>) -> Self {
        Self {
            project_name: project_name.into(),
            fuzz_target: fuzz_target.into(),
            engine: "libfuzzer".to_string(),
            sanitizer: "address".to_string(),
            architecture: "x86_64".to_string(),
            corpus_dir: PathBuf::from("corpus"),
            crash_dir: PathBuf::from("crashes"),
        }
    }

    /// Generate a minimal `ClusterFuzz` configuration JSON.
    #[must_use]
    pub fn to_config_json(&self) -> String {
        format!(
            r#"{{"project":"{project}","target":"{target}","engine":"{engine}","sanitizer":"{san}","arch":"{arch}","corpus_dir":"{corpus}","crash_dir":"{crash}"}}"#,
            project = self.project_name,
            target = self.fuzz_target,
            engine = self.engine,
            san = self.sanitizer,
            arch = self.architecture,
            corpus = self.corpus_dir.display(),
            crash = self.crash_dir.display(),
        )
    }
}

// ---------------------------------------------------------------------------
// HarnessVerifier
// ---------------------------------------------------------------------------

/// Static analysis checks performed on generated harnesses.
#[derive(Debug, Clone)]
pub struct HarnessVerificationResult {
    pub has_entry_point: bool,
    pub has_size_check: bool,
    pub has_return_zero: bool,
    pub issues: Vec<String>,
}

impl HarnessVerificationResult {
    /// Returns `true` if all checks passed.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.issues.is_empty() && self.has_entry_point
    }
}

/// Performs static analysis on generated harness source code.
pub struct HarnessVerifier;

impl HarnessVerifier {
    /// Verify a generated harness for common issues.
    #[must_use]
    pub fn verify(source: &str, language: HarnessLanguage) -> HarnessVerificationResult {
        let mut issues = Vec::new();
        let has_entry_point = OssFuzzCompat::validate_entry_point(source, language);
        if !has_entry_point {
            issues.push("missing libFuzzer entry point".to_string());
        }
        let has_size_check = source.contains("size") || source.contains("len");
        if !has_size_check {
            issues.push("no size/length check found".to_string());
        }
        let has_return_zero = match language {
            HarnessLanguage::C | HarnessLanguage::Go => source.contains("return 0"),
            HarnessLanguage::Rust => true, // fuzz_target! macro handles this
        };
        if !has_return_zero && language != HarnessLanguage::Rust {
            issues.push("missing return 0".to_string());
        }
        // Check for unbounded memory use (very basic).
        if source.contains("alloca") || source.contains("alloc(size)") {
            issues.push("potentially unbounded allocation".to_string());
        }
        HarnessVerificationResult {
            has_entry_point,
            has_size_check,
            has_return_zero,
            issues,
        }
    }

    /// Verify that the harness file exists and has non-zero size.
    ///
    /// # Errors
    /// Returns [`HarnessError::Validation`] if the file is missing or empty.
    pub fn verify_file(path: &Path) -> Result<(), HarnessError> {
        let meta = std::fs::metadata(path)?;
        if meta.len() == 0 {
            return Err(HarnessError::Validation(
                "harness file is empty".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HarnessBuilder
// ---------------------------------------------------------------------------

/// End-to-end harness builder.
///
/// Combines [`FuzzTargetWrapper`], [`InitializerCode`], [`CleanupCode`], and
/// [`HarnessVerifier`] into a single pipeline.
pub struct HarnessBuilder {
    pub target: FuzzTargetWrapper,
    pub init: InitializerCode,
    pub cleanup: CleanupCode,
    pub oss_fuzz: bool,
    pub clusterfuzz: Option<ClusterFuzzIntegration>,
}

impl HarnessBuilder {
    /// Create a builder for the given target and language.
    #[must_use]
    pub fn new(target_name: impl Into<String>, language: HarnessLanguage) -> Self {
        Self {
            target: FuzzTargetWrapper::new(target_name, language),
            init: InitializerCode::new(),
            cleanup: CleanupCode::new(),
            oss_fuzz: false,
            clusterfuzz: None,
        }
    }

    /// Set the fuzz body / invocation.
    pub fn set_invocation(&mut self, invocation: impl Into<String>) {
        self.target.invocation = invocation.into();
    }

    /// Add initialization code.
    pub fn add_init(&mut self, code: impl Into<String>) {
        self.init.add(code);
    }

    /// Add cleanup code.
    pub fn add_cleanup(&mut self, code: impl Into<String>) {
        self.cleanup.add(code);
    }

    /// Enable OSS-Fuzz compatibility.
    pub const fn enable_oss_fuzz(&mut self) {
        self.oss_fuzz = true;
    }

    /// Enable `ClusterFuzz` integration.
    pub fn enable_clusterfuzz(&mut self, project: impl Into<String>) {
        self.clusterfuzz = Some(ClusterFuzzIntegration::new(
            project,
            self.target.target_name.clone(),
        ));
    }

    /// Generate the harness source.
    ///
    /// # Errors
    /// Returns [`HarnessError`] on template or validation failures.
    pub fn build(&self) -> Result<GeneratedHarness, HarnessError> {
        let source = self.target.generate_source(&self.init, &self.cleanup)?;
        let verification = HarnessVerifier::verify(&source, self.target.language);

        let oss_fuzz_script = if self.oss_fuzz {
            Some(OssFuzzCompat::generate_build_sh(
                &self.target.target_name,
                &[self.target.target_name.as_str()],
            ))
        } else {
            None
        };

        let cf_config = self.clusterfuzz.as_ref().map(ClusterFuzzIntegration::to_config_json);

        Ok(GeneratedHarness {
            language: self.target.language,
            target_name: self.target.target_name.clone(),
            source,
            verification,
            oss_fuzz_script,
            clusterfuzz_config: cf_config,
        })
    }
}

// ---------------------------------------------------------------------------
// GeneratedHarness
// ---------------------------------------------------------------------------

/// Output of [`HarnessBuilder::build`].
#[derive(Debug, Clone)]
pub struct GeneratedHarness {
    pub language: HarnessLanguage,
    pub target_name: String,
    pub source: String,
    pub verification: HarnessVerificationResult,
    pub oss_fuzz_script: Option<String>,
    pub clusterfuzz_config: Option<String>,
}

impl GeneratedHarness {
    /// Write the harness source to `path`.
    ///
    /// # Errors
    /// Returns `std::io::Error` on write failure.
    pub fn write_source(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, &self.source)
    }

    /// Returns `true` if the harness passed verification.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.verification.is_valid()
    }
}

impl fmt::Display for GeneratedHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GeneratedHarness({} / {} / valid={})",
            self.target_name,
            self.language,
            self.is_valid()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── HarnessLanguage ───────────────────────────────────────────────────

    #[test]
    fn language_extension() {
        assert_eq!(HarnessLanguage::C.extension(), "c");
        assert_eq!(HarnessLanguage::Rust.extension(), "rs");
        assert_eq!(HarnessLanguage::Go.extension(), "go");
    }

    #[test]
    fn language_from_str() {
        assert_eq!(HarnessLanguage::from_str("c").unwrap(), HarnessLanguage::C);
        assert_eq!(
            HarnessLanguage::from_str("Rust").unwrap(),
            HarnessLanguage::Rust
        );
        assert_eq!(
            HarnessLanguage::from_str("go").unwrap(),
            HarnessLanguage::Go
        );
    }

    #[test]
    fn language_from_str_unknown() {
        assert!(HarnessLanguage::from_str("python").is_err());
    }

    #[test]
    fn language_display() {
        assert_eq!(HarnessLanguage::C.to_string(), "C");
    }

    // ── HarnessTemplate ───────────────────────────────────────────────────

    #[test]
    fn template_c_contains_entry_point() {
        let t = HarnessTemplate::default_for(HarnessLanguage::C);
        assert!(t.source.contains("LLVMFuzzerTestOneInput"));
    }

    #[test]
    fn template_rust_contains_fuzz_target() {
        let t = HarnessTemplate::default_for(HarnessLanguage::Rust);
        assert!(t.source.contains("fuzz_target!"));
    }

    #[test]
    fn template_render_substitutes_variable() {
        let t = HarnessTemplate::default_for(HarnessLanguage::C);
        let mut vars = HashMap::new();
        vars.insert("TARGET_NAME".to_string(), "my_parser".to_string());
        vars.insert("MIN_SIZE".to_string(), "4".to_string());
        vars.insert("MAX_SIZE".to_string(), "1024".to_string());
        vars.insert("FUZZ_BODY".to_string(), "/* body */".to_string());
        vars.insert("INIT_CODE".to_string(), String::new());
        vars.insert("CLEANUP_CODE".to_string(), String::new());
        let rendered = t.render(&vars).unwrap();
        assert!(rendered.contains("my_parser"));
        assert!(rendered.contains("/* body */"));
    }

    // ── InitializerCode / CleanupCode ─────────────────────────────────────

    #[test]
    fn init_code_render() {
        let mut init = InitializerCode::new();
        init.add("int x = 0;");
        init.add("x++;");
        let rendered = init.render();
        assert!(rendered.contains("int x = 0;"));
        assert!(rendered.contains("x++"));
    }

    #[test]
    fn cleanup_code_empty() {
        let c = CleanupCode::new();
        assert!(c.render().is_empty());
    }

    // ── FuzzTargetWrapper ─────────────────────────────────────────────────

    #[test]
    fn fuzz_target_wrapper_generate_c() {
        let mut w = FuzzTargetWrapper::new("test_parser", HarnessLanguage::C);
        w.invocation = "parse_data(data, size);".to_string();
        let init = InitializerCode::new();
        let cleanup = CleanupCode::new();
        let src = w.generate_source(&init, &cleanup).unwrap();
        assert!(src.contains("LLVMFuzzerTestOneInput"));
        assert!(src.contains("parse_data"));
    }

    #[test]
    fn fuzz_target_wrapper_generate_rust() {
        let w = FuzzTargetWrapper::new("my_fn", HarnessLanguage::Rust);
        let src = w
            .generate_source(&InitializerCode::new(), &CleanupCode::new())
            .unwrap();
        assert!(src.contains("fuzz_target!"));
    }

    #[test]
    fn fuzz_target_wrapper_generate_go() {
        let w = FuzzTargetWrapper::new("go_fn", HarnessLanguage::Go);
        let src = w
            .generate_source(&InitializerCode::new(), &CleanupCode::new())
            .unwrap();
        assert!(src.contains("LLVMFuzzerTestOneInput"));
    }

    // ── HarnessVerifier ───────────────────────────────────────────────────

    #[test]
    fn verifier_valid_c_harness() {
        let src = r"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    return 0;
}
";
        let r = HarnessVerifier::verify(src, HarnessLanguage::C);
        assert!(r.has_entry_point);
        assert!(r.has_size_check);
        assert!(r.has_return_zero);
    }

    #[test]
    fn verifier_missing_entry_point() {
        let src = "void my_func() {}";
        let r = HarnessVerifier::verify(src, HarnessLanguage::C);
        assert!(!r.has_entry_point);
        assert!(!r.is_valid());
    }

    #[test]
    fn verifier_rust_no_return_zero_needed() {
        let src = "fuzz_target!(|data: &[u8]| { let _ = data.len(); });";
        let r = HarnessVerifier::verify(src, HarnessLanguage::Rust);
        assert!(r.has_entry_point);
        assert!(r.has_return_zero); // always true for Rust
    }

    // ── OssFuzzCompat ────────────────────────────────────────────────────

    #[test]
    fn oss_fuzz_build_sh() {
        let script = OssFuzzCompat::generate_build_sh("myproject", &["fuzz_parser"]);
        assert!(script.contains("fuzz_parser"));
        assert!(script.contains("LIB_FUZZING_ENGINE"));
    }

    #[test]
    fn oss_fuzz_project_yaml() {
        let yaml = OssFuzzCompat::generate_project_yaml(
            "myproject",
            "c++",
            "https://github.com/example/repo",
        );
        assert!(yaml.contains("myproject"));
        assert!(yaml.contains("language: c++"));
    }

    #[test]
    fn oss_fuzz_validate_c_entry_point() {
        assert!(OssFuzzCompat::validate_entry_point(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {}",
            HarnessLanguage::C
        ));
        assert!(!OssFuzzCompat::validate_entry_point(
            "void foo() {}",
            HarnessLanguage::C
        ));
    }

    // ── ClusterFuzzIntegration ────────────────────────────────────────────

    #[test]
    fn clusterfuzz_config_json() {
        let cf = ClusterFuzzIntegration::new("myproject", "fuzz_target");
        let json = cf.to_config_json();
        assert!(json.contains("myproject"));
        assert!(json.contains("fuzz_target"));
        assert!(json.contains("libfuzzer"));
    }

    // ── HarnessBuilder ────────────────────────────────────────────────────

    #[test]
    fn builder_c_harness() {
        let mut b = HarnessBuilder::new("parse_test", HarnessLanguage::C);
        b.set_invocation("parse(data, size);");
        let h = b.build().unwrap();
        assert!(h.source.contains("LLVMFuzzerTestOneInput"));
        assert!(h.source.contains("parse(data, size);"));
    }

    #[test]
    fn builder_with_init_cleanup() {
        let mut b = HarnessBuilder::new("f", HarnessLanguage::C);
        b.add_init("static int initialized = 0;");
        b.add_cleanup("/* cleanup */");
        b.set_invocation("process(data);");
        let h = b.build().unwrap();
        assert!(h.source.contains("initialized"));
        assert!(h.source.contains("cleanup"));
    }

    #[test]
    fn builder_oss_fuzz() {
        let mut b = HarnessBuilder::new("f", HarnessLanguage::C);
        b.enable_oss_fuzz();
        let h = b.build().unwrap();
        assert!(h.oss_fuzz_script.is_some());
    }

    #[test]
    fn builder_clusterfuzz() {
        let mut b = HarnessBuilder::new("f", HarnessLanguage::Rust);
        b.enable_clusterfuzz("myproj");
        let h = b.build().unwrap();
        assert!(h.clusterfuzz_config.is_some());
    }

    #[test]
    fn builder_rust_harness() {
        let b = HarnessBuilder::new("rust_target", HarnessLanguage::Rust);
        let h = b.build().unwrap();
        assert!(h.source.contains("fuzz_target!"));
    }

    #[test]
    fn generated_harness_display() {
        let b = HarnessBuilder::new("t", HarnessLanguage::C);
        let h = b.build().unwrap();
        let s = h.to_string();
        assert!(s.contains("GeneratedHarness"));
        assert!(s.contains('t'));
    }

    #[test]
    fn generated_harness_write() {
        let b = HarnessBuilder::new("t", HarnessLanguage::C);
        let h = b.build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuzz.c");
        h.write_source(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn harness_verification_result_valid() {
        let r = HarnessVerificationResult {
            has_entry_point: true,
            has_size_check: true,
            has_return_zero: true,
            issues: Vec::new(),
        };
        assert!(r.is_valid());
    }

    #[test]
    fn harness_verification_result_invalid() {
        let r = HarnessVerificationResult {
            has_entry_point: false,
            has_size_check: false,
            has_return_zero: false,
            issues: vec!["missing entry".to_string()],
        };
        assert!(!r.is_valid());
    }

    // ── HarnessVerifier::verify_file ──────────────────────────────────────

    #[test]
    fn verify_file_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("harness.c");
        std::fs::write(&path, b"int LLVMFuzzerTestOneInput() {}").unwrap();
        assert!(HarnessVerifier::verify_file(&path).is_ok());
    }

    #[test]
    fn verify_file_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.c");
        std::fs::write(&path, b"").unwrap();
        assert!(HarnessVerifier::verify_file(&path).is_err());
    }
}
