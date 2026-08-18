//! `rustre-mobile-apktool` —  Apktool wrapper types.

pub mod apk_analyzer;
pub mod apk_rebuilder;
pub mod apk_signing;
pub mod arsc_parser;
pub mod manifest;
/// Android binary XML (AXML) manifest parser.
pub mod android_manifest_parser;
/// Backward-compat alias — prefer [`android_manifest_parser`].
pub use android_manifest_parser as manifest_parser;
pub mod res_decompiler;
pub mod res_rebuilder;
pub mod dex_parser;
pub mod dex_analyzer;
pub mod apk_threat_model;
pub mod dalvik_disasm;
pub mod resource_decoder;
pub mod cert_analyzer;
pub mod res_table_parser;
pub mod arsc_value_decoder;
pub mod apk_signature_verifier;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum ApktoolError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("build error: {0}")]
    Build(String),
    #[error("io error: {0}")]
    Io(String),
}

// â"€â"€â"€ ApktoolConfig â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApktoolConfig {
    pub apktool_path: String,
    pub output_dir: String,
    pub no_src: bool,
    pub no_res: bool,
    pub force: bool,
}

impl ApktoolConfig {
    /// Create a new config with default flags.
    #[must_use]
    pub fn new(path: impl Into<String>, out: impl Into<String>) -> Self {
        Self {
            apktool_path: path.into(),
            output_dir: out.into(),
            no_src: false,
            no_res: false,
            force: false,
        }
    }

    /// Disable source decoding.
    #[must_use]
    pub const fn with_no_src(mut self) -> Self {
        self.no_src = true;
        self
    }

    /// Disable resource decoding.
    #[must_use]
    pub const fn with_no_res(mut self) -> Self {
        self.no_res = true;
        self
    }

    /// Force overwrite of output directory.
    #[must_use]
    pub const fn with_force(mut self) -> Self {
        self.force = true;
        self
    }
}

// â"€â"€â"€ DecodeResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeResult {
    pub output_dir: String,
    pub smali_dirs: Vec<String>,
    pub res_dir: Option<String>,
    pub success: bool,
    pub log: String,
}

impl DecodeResult {
    /// Returns the number of smali directories.
    #[must_use]
    pub const fn smali_count(&self) -> usize {
        self.smali_dirs.len()
    }
}

// â"€â"€â"€ BuildResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildResult {
    pub apk_path: String,
    pub success: bool,
    pub log: String,
}

// â"€â"€â"€ Trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub trait ApktoolRunner: Send + Sync {
    /// # Errors
    /// Returns an [`ApktoolError`] if decoding fails.
    fn decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError>;
    /// # Errors
    /// Returns an [`ApktoolError`] if building fails.
    fn build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError>;
}

// â"€â"€â"€ MockApktoolRunner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct MockApktoolRunner {
    pub decode_ok: bool,
    pub build_ok: bool,
    pub smali_dirs: Vec<String>,
}

impl MockApktoolRunner {
    /// Create a runner that succeeds.
    #[must_use]
    pub fn success() -> Self {
        Self {
            decode_ok: true,
            build_ok: true,
            smali_dirs: vec!["smali".to_string(), "smali_classes2".to_string()],
        }
    }

    /// Create a runner that fails.
    #[must_use]
    pub const fn failure() -> Self {
        Self {
            decode_ok: false,
            build_ok: false,
            smali_dirs: vec![],
        }
    }
}

impl ApktoolRunner for MockApktoolRunner {
    /// Decode `apk` by actually running the external apktool.
    ///
    /// This runner never synthesises an outcome. `decode_ok == false` means
    /// "configured to refuse", and is reported as such; otherwise the APK must
    /// exist on disk and a real apktool must be locatable, or a typed error is
    /// returned naming exactly what is missing.
    fn decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError> {
        if !self.decode_ok {
            return Err(ApktoolError::Decode(format!(
                "runner configured with decode_ok = false; refusing to decode {apk}"
            )));
        }
        if !std::path::Path::new(apk).is_file() {
            return Err(ApktoolError::NotFound(format!(
                "input APK not found on disk: {apk}"
            )));
        }
        let cli = CliApktoolRunner::new()?;
        let mut result = cli.decode(apk, cfg)?;
        // Honour an explicit smali-dir filter, but only for directories the
        // real decode actually produced.
        if !self.smali_dirs.is_empty() {
            result.smali_dirs.retain(|d| {
                self.smali_dirs
                    .iter()
                    .any(|want| d == want || d.ends_with(want.as_str()))
            });
        }
        Ok(result)
    }

    /// Build `dir` by actually running the external apktool.
    ///
    /// Same contract as [`MockApktoolRunner::decode`]: no outcome is invented.
    fn build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError> {
        if !self.build_ok {
            return Err(ApktoolError::Build(format!(
                "runner configured with build_ok = false; refusing to build {dir}"
            )));
        }
        if !std::path::Path::new(dir).is_dir() {
            return Err(ApktoolError::NotFound(format!(
                "decoded project directory not found on disk: {dir}"
            )));
        }
        let cli = CliApktoolRunner::new()?;
        cli.build(dir, cfg)
    }
}

// â"€â"€â"€ ApkDecodeResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Result of a successful `apktool d` decode operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkDecodeResult {
    /// Directory where the decoded APK was written.
    pub output_dir: String,
    /// List of smali source directories found.
    pub smali_dirs: Vec<String>,
    /// Path to the `res/` directory, if resources were decoded.
    pub res_dir: Option<String>,
    /// Path to the decoded `AndroidManifest.xml`, if available.
    pub manifest_path: Option<String>,
    /// Non-fatal warnings emitted during decoding.
    pub warnings: Vec<String>,
}

impl ApkDecodeResult {
    /// Number of smali directories.
    #[must_use]
    pub const fn smali_count(&self) -> usize {
        self.smali_dirs.len()
    }

    /// `true` if no warnings were emitted.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

// â"€â"€â"€ ApkBuildResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Result of a successful `apktool b` build operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkBuildResult {
    /// Path to the rebuilt APK file.
    pub apk_path: String,
    /// `true` if the APK has not been signed.
    pub unsigned: bool,
    /// Size of the output APK in bytes.
    pub size_bytes: u64,
}

// â"€â"€â"€ CliApktoolRunner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Locates the real `apktool` binary on `PATH` and spawns subprocesses for
/// decode and build operations.
///
/// # Discovery
/// The binary is looked up in three ways, in order:
/// 1. `APKTOOL_PATH` environment variable (exact path to the binary / script).
/// 2. `apktool` on `PATH` (confirmed runnable via `--version`).
/// 3. `apktool.bat` on `PATH` (Windows wrapper script distributed with
///    the official release).
#[derive(Debug, Clone)]
pub struct CliApktoolRunner {
    /// Resolved path to the `apktool` binary (or `.bat` wrapper on Windows).
    pub apktool_path: std::path::PathBuf,
}

impl CliApktoolRunner {
    /// Build a runner by auto-locating `apktool`.
    ///
    /// # Errors
    /// Returns `Err(ApktoolError::NotFound)` when the binary cannot be found.
    pub fn new() -> Result<Self, ApktoolError> {
        let path = Self::find_apktool().ok_or_else(|| {
            ApktoolError::NotFound(
                "apktool not found. Install apktool and ensure it is on PATH, \
                 or set the APKTOOL_PATH environment variable."
                    .to_owned(),
            )
        })?;
        Ok(Self { apktool_path: path })
    }

    /// Build a runner from an explicit binary path.
    #[must_use]
    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            apktool_path: path.into(),
        }
    }

    /// Locate the `apktool` binary using three strategies (see struct docs).
    #[must_use]
    pub fn find_apktool() -> Option<std::path::PathBuf> {
        // Strategy 1: explicit env var.
        if let Ok(val) = std::env::var("APKTOOL_PATH") {
            let p = std::path::PathBuf::from(val);
            if p.exists() {
                return Some(p);
            }
        }

        // Strategy 2 + 3: probe candidates on PATH.
        let candidates: &[&str] = if cfg!(windows) {
            &["apktool", "apktool.bat"]
        } else {
            &["apktool"]
        };

        for candidate in candidates {
            let ok = std::process::Command::new(candidate)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());

            if ok {
                if let Some(abs) = apktool_which(candidate) {
                    return Some(abs);
                }
                return Some(std::path::PathBuf::from(candidate));
            }
        }
        None
    }

    /// Run `apktool d <apk> -o <output_dir>` and return a `DecodeResult`.
    ///
    /// Extra flags from `cfg` (`--no-src`, `--no-res`, `-f`) are passed
    /// through.  The subprocess's combined stdout+stderr is captured and
    /// included in `DecodeResult::log`.  A non-zero exit code or any line
    /// containing `"ERROR"` is treated as a failure.
    ///
    /// # Errors
    /// Returns an [`ApktoolError`] if the subprocess fails or apktool reports an error.
    pub fn decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError> {
        let mut cmd = std::process::Command::new(&self.apktool_path);
        cmd.arg("d").arg(apk).arg("-o").arg(&cfg.output_dir);

        if cfg.no_src {
            cmd.arg("--no-src");
        }
        if cfg.no_res {
            cmd.arg("--no-res");
        }
        if cfg.force {
            cmd.arg("-f");
        }

        let output = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| ApktoolError::Io(format!("failed to spawn apktool: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let log = format!("{stdout}{stderr}");

        let apktool_error = log.lines().any(|l| l.starts_with("I: E:") || l.starts_with("E: ") || l.starts_with("brut."));
        if !output.status.success() || apktool_error {
            return Err(ApktoolError::Decode(format!(
                "apktool d failed (exit {}): {}",
                output.status,
                log.trim()
            )));
        }

        // Discover smali directories written into output_dir.
        let smali_dirs = discover_smali_dirs(&cfg.output_dir);

        let res_dir = if cfg.no_res {
            None
        } else {
            Some(format!("{}/res", cfg.output_dir))
        };

        Ok(DecodeResult {
            output_dir: cfg.output_dir.clone(),
            smali_dirs,
            res_dir,
            success: true,
            log,
        })
    }

    /// Run `apktool b <dir> -o <rebuilt_apk>` and return a `BuildResult`.
    ///
    /// The rebuilt APK is written to `<cfg.output_dir>/dist/<basename>.apk`.
    ///
    /// # Errors
    /// Returns an [`ApktoolError`] if the subprocess fails or apktool reports an error.
    pub fn build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError> {
        if dir.is_empty() {
            return Err(ApktoolError::Build(
                "source directory must not be empty".to_owned(),
            ));
        }

        let apk_name = dir.rsplit(['/', '\\']).next().unwrap_or("output");
        let apk_path = format!("{}/dist/{apk_name}.apk", cfg.output_dir);

        let mut cmd = std::process::Command::new(&self.apktool_path);
        cmd.arg("b").arg(dir).arg("-o").arg(&apk_path);

        if cfg.force {
            cmd.arg("-f");
        }

        let output = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| ApktoolError::Io(format!("failed to spawn apktool: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let log = format!("{stdout}{stderr}");

        let apktool_error = log.lines().any(|l| l.starts_with("I: E:") || l.starts_with("E: ") || l.starts_with("brut."));
        if !output.status.success() || apktool_error {
            return Err(ApktoolError::Build(format!(
                "apktool b failed (exit {}): {}",
                output.status,
                log.trim()
            )));
        }

        if !std::path::Path::new(&apk_path).is_file() {
            return Err(ApktoolError::Build(format!(
                "apktool b exited 0 but produced no file at {apk_path}: {}",
                log.trim()
            )));
        }

        Ok(BuildResult {
            apk_path,
            success: true,
            log,
        })
    }

    /// Run `apktool if <apk>` to install a framework resource.
    ///
    /// # Errors
    /// Returns [`ApktoolError::Io`] if the subprocess cannot be spawned and
    /// [`ApktoolError::Build`] if apktool reports failure.
    pub fn install_framework(&self, apk_path: &str) -> Result<(), ApktoolError> {
        let output = std::process::Command::new(&self.apktool_path)
            .arg("if")
            .arg(apk_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| ApktoolError::Io(format!("failed to spawn apktool: {e}")))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(ApktoolError::Build(format!(
                "apktool if failed (exit {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

/// Portable PATH lookup for a CLI tool, exposed for callers that need to know
/// whether an external tool is installed before offering to run it.
#[must_use]
pub fn cli_find_in_path(name: &str) -> Option<std::path::PathBuf> {
    apktool_which(name)
}

/// Locate a usable apktool, or `None` when none is installed.
#[must_use]
pub fn apktool_find() -> Option<std::path::PathBuf> {
    CliApktoolRunner::find_apktool()
}

impl ApktoolRunner for CliApktoolRunner {
    fn decode(&self, apk: &str, cfg: &ApktoolConfig) -> Result<DecodeResult, ApktoolError> {
        self.decode(apk, cfg)
    }

    fn build(&self, dir: &str, cfg: &ApktoolConfig) -> Result<BuildResult, ApktoolError> {
        self.build(dir, cfg)
    }
}

// â"€â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Portable PATH lookup for `name`.  Returns the first matching file, checking
/// `.exe` on Windows.
fn apktool_which(name: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let with_exe = dir.join(format!("{name}.exe"));
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
    }
    None
}

/// Walk `output_dir` for directories whose names start with `"smali"`.
fn discover_smali_dirs(output_dir: &str) -> Vec<String> {
    let base = std::path::Path::new(output_dir);
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("smali")
            {
                dirs.push(path.to_string_lossy().into_owned());
            }
        }
    }
    dirs.sort();
    dirs
}

// â"€â"€â"€ ApktoolRunnerImpl â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A concrete implementation of the apktool runner that wraps an
/// [`ApktoolConfig`] and provides high-level decode/build operations.
#[derive(Debug, Clone)]
pub struct ApktoolRunnerImpl {
    /// Configuration for this runner.
    pub config: ApktoolConfig,
}

impl ApktoolRunnerImpl {
    /// Create a new runner with the given config.
    #[must_use]
    pub const fn new(config: ApktoolConfig) -> Self {
        Self { config }
    }

    /// The directory a decode of `apk_path` would be written to.
    ///
    /// Pure path arithmetic, separated out so it can be reasoned about (and
    /// tested) without pretending a decode happened.
    #[must_use]
    pub fn output_dir_for(&self, apk_path: &str) -> String {
        let base_name = apk_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(apk_path)
            .trim_end_matches(".apk")
            .trim_end_matches(".APK");
        format!("{}/{base_name}", self.config.output_dir)
    }

    /// Decode `apk_path` by running the external apktool, and report only
    /// what the decode actually wrote to disk.
    ///
    /// Nothing here is synthesised: the APK must exist, an apktool must be
    /// locatable, the subprocess must succeed, and every path in the returned
    /// [`ApkDecodeResult`] is verified to exist before it is reported.
    ///
    /// # Errors
    /// Returns an [`ApktoolError`] if the path is invalid, the APK or the
    /// apktool binary is missing, or the decode subprocess fails.
    pub fn decode(&self, apk_path: &str) -> Result<ApkDecodeResult, ApktoolError> {
        if !std::path::Path::new(&apk_path.to_lowercase()).extension().is_some_and(|e| e.eq_ignore_ascii_case("apk")) {
            return Err(ApktoolError::Decode(format!(
                "{apk_path} does not have an .apk extension"
            )));
        }

        if !std::path::Path::new(apk_path).is_file() {
            return Err(ApktoolError::NotFound(format!(
                "input APK not found on disk: {apk_path}"
            )));
        }

        let output_dir = self.output_dir_for(apk_path);

        let cli = CliApktoolRunner::new()?;
        let mut sub_cfg = self.config.clone();
        sub_cfg.output_dir = output_dir.clone();
        let decoded = cli.decode(apk_path, &sub_cfg)?;

        // Report only paths that really exist after the decode.
        let smali_dirs: Vec<String> = decoded
            .smali_dirs
            .into_iter()
            .filter(|d| std::path::Path::new(d).is_dir())
            .collect();

        let res_dir = decoded
            .res_dir
            .filter(|d| std::path::Path::new(d).is_dir());

        let manifest_candidate = format!("{output_dir}/AndroidManifest.xml");
        let manifest_path = if std::path::Path::new(&manifest_candidate).is_file() {
            Some(manifest_candidate)
        } else {
            None
        };

        let mut warnings = Vec::new();
        if self.config.no_src {
            warnings.push("Source decoding skipped (--no-src)".to_string());
        }
        if smali_dirs.is_empty() && !self.config.no_src {
            warnings.push("apktool produced no smali directory".to_string());
        }
        if manifest_path.is_none() {
            warnings.push("apktool produced no AndroidManifest.xml".to_string());
        }

        Ok(ApkDecodeResult {
            output_dir,
            smali_dirs,
            res_dir,
            manifest_path,
            warnings,
        })
    }

    /// Build the decoded project at `dir` by running the external apktool.
    ///
    /// The reported `size_bytes` is the real size of the produced file; if no
    /// file was produced, that is an error rather than a zero-size success.
    ///
    /// # Errors
    /// Returns an [`ApktoolError`] if the directory path is empty or missing,
    /// apktool cannot be located, or the build subprocess fails.
    pub fn build(&self, dir: &str) -> Result<ApkBuildResult, ApktoolError> {
        if dir.is_empty() {
            return Err(ApktoolError::Build("directory path is empty".to_string()));
        }
        if !std::path::Path::new(dir).is_dir() {
            return Err(ApktoolError::NotFound(format!(
                "decoded project directory not found on disk: {dir}"
            )));
        }

        let cli = CliApktoolRunner::new()?;
        let built = cli.build(dir, &self.config)?;

        let meta = std::fs::metadata(&built.apk_path).map_err(|e| {
            ApktoolError::Build(format!(
                "apktool reported success but {} is not readable: {e}",
                built.apk_path
            ))
        })?;

        Ok(ApkBuildResult {
            apk_path: built.apk_path,
            unsigned: true,
            size_bytes: meta.len(),
        })
    }

    /// Install an APK as an apktool framework resource by running
    /// `apktool if <apk>` for real.
    ///
    /// # Errors
    /// Returns an [`ApktoolError::NotFound`] if the path is not an existing
    /// APK file or apktool cannot be located, and [`ApktoolError::Build`] if
    /// the subprocess reports failure.
    pub fn install_framework(&self, apk_path: &str) -> Result<(), ApktoolError> {
        if !std::path::Path::new(&apk_path.to_lowercase()).extension().is_some_and(|e| e.eq_ignore_ascii_case("apk")) {
            return Err(ApktoolError::NotFound(format!(
                "{apk_path}: not an APK file"
            )));
        }
        if !std::path::Path::new(apk_path).is_file() {
            return Err(ApktoolError::NotFound(format!(
                "framework APK not found on disk: {apk_path}"
            )));
        }
        let cli = CliApktoolRunner::new()?;
        cli.install_framework(apk_path)
    }
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let cfg = ApktoolConfig::new("/usr/bin/apktool", "/tmp/out");
        assert_eq!(cfg.apktool_path, "/usr/bin/apktool");
        assert_eq!(cfg.output_dir, "/tmp/out");
        assert!(!cfg.no_src);
        assert!(!cfg.no_res);
        assert!(!cfg.force);
    }

    #[test]
    fn test_config_with_no_src() {
        let cfg = ApktoolConfig::new("apktool", "out").with_no_src();
        assert!(cfg.no_src);
        assert!(!cfg.no_res);
    }

    #[test]
    fn test_config_with_no_res() {
        let cfg = ApktoolConfig::new("apktool", "out").with_no_res();
        assert!(cfg.no_res);
    }

    #[test]
    fn test_config_with_force() {
        let cfg = ApktoolConfig::new("apktool", "out").with_force();
        assert!(cfg.force);
    }

    #[test]
    fn test_config_builder_chain() {
        let cfg = ApktoolConfig::new("apktool", "out")
            .with_no_src()
            .with_force();
        assert!(cfg.no_src);
        assert!(cfg.force);
        assert!(!cfg.no_res);
    }

    #[test]
    fn test_decode_result_smali_count() {
        let r = DecodeResult {
            output_dir: "/tmp/out".to_string(),
            smali_dirs: vec!["smali".to_string(), "smali_classes2".to_string()],
            res_dir: Some("/tmp/out/res".to_string()),
            success: true,
            log: String::new(),
        };
        assert_eq!(r.smali_count(), 2);
    }

    #[test]
    fn test_decode_result_smali_count_empty() {
        let r = DecodeResult {
            output_dir: "/tmp/out".to_string(),
            smali_dirs: vec![],
            res_dir: None,
            success: false,
            log: "error".to_string(),
        };
        assert_eq!(r.smali_count(), 0);
    }

    /// A runner configured to run must never invent a decode: with a
    /// nonexistent APK it has to fail, and name why.
    #[test]
    fn test_runner_never_invents_decode() {
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        match runner.decode("definitely-not-here.apk", &cfg) {
            Err(ApktoolError::NotFound(m)) => assert!(m.contains("definitely-not-here.apk")),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("decoded an APK that does not exist"),
        }
    }

    /// Same contract for build: no directory, no result.
    #[test]
    fn test_runner_never_invents_build() {
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        match runner.build("definitely-not-a-directory", &cfg) {
            Err(ApktoolError::NotFound(m)) => assert!(m.contains("definitely-not-a-directory")),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("built a directory that does not exist"),
        }
    }

    #[test]
    fn test_mock_runner_failure_decode() {
        let runner = MockApktoolRunner::failure();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let err = runner.decode("app.apk", &cfg).unwrap_err();
        assert!(matches!(err, ApktoolError::Decode(_)));
    }

    #[test]
    fn test_mock_runner_failure_build() {
        let runner = MockApktoolRunner::failure();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let err = runner.build("/tmp/out", &cfg).unwrap_err();
        assert!(matches!(err, ApktoolError::Build(_)));
    }

    /// `--no-res` cannot turn a missing APK into a result either.
    #[test]
    fn test_runner_no_res_still_requires_real_input() {
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out").with_no_res();
        assert!(matches!(
            runner.decode("app-not-present.apk", &cfg),
            Err(ApktoolError::NotFound(_))
        ));
    }

    /// A real, empty file is not a real APK: apktool must be consulted, and
    /// when it is absent the error must say so rather than reporting success.
    #[test]
    fn test_runner_reports_missing_apktool() {
        let dir = std::env::temp_dir().join("rustre_apktool_probe");
        let _ = std::fs::create_dir_all(&dir);
        let apk = dir.join("probe.apk");
        std::fs::write(&apk, b"not really an apk").unwrap();
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", dir.join("out").to_string_lossy().as_ref());
        match runner.decode(apk.to_string_lossy().as_ref(), &cfg) {
            Err(ApktoolError::NotFound(m)) => assert!(m.contains("apktool")),
            // apktool really is installed here: it must reject the fake APK.
            Err(ApktoolError::Decode(_) | ApktoolError::Io(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("decoded 17 bytes of garbage as an APK"),
        }
        let _ = std::fs::remove_file(&apk);
    }

    #[test]
    fn test_apktool_error_not_found() {
        let e = ApktoolError::NotFound("apktool".to_string());
        assert!(e.to_string().contains("apktool"));
    }

    #[test]
    fn test_apktool_error_decode() {
        let e = ApktoolError::Decode("bad apk".to_string());
        assert!(e.to_string().contains("bad apk"));
    }

    #[test]
    fn test_apktool_error_build() {
        let e = ApktoolError::Build("missing resource".to_string());
        assert!(e.to_string().contains("missing resource"));
    }

    #[test]
    fn test_apktool_error_io() {
        let e = ApktoolError::Io("permission denied".to_string());
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn test_config_serialization() {
        let cfg = ApktoolConfig::new("apktool", "out").with_force();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: ApktoolConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.apktool_path, cfg.apktool_path);
        assert!(decoded.force);
    }

    #[test]
    fn test_build_result_serialization() {
        let r = BuildResult {
            apk_path: "/tmp/app.apk".to_string(),
            success: true,
            log: "ok".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: BuildResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.apk_path, r.apk_path);
    }

    #[test]
    fn test_decode_error_names_the_input() {
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let err = runner.decode("test.apk", &cfg).unwrap_err();
        assert!(err.to_string().contains("test.apk"));
    }

    #[test]
    fn test_custom_smali_dirs_do_not_conjure_a_decode() {
        let runner = MockApktoolRunner {
            decode_ok: true,
            build_ok: true,
            smali_dirs: vec![
                "smali".to_string(),
                "smali2".to_string(),
                "smali3".to_string(),
            ],
        };
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        assert!(matches!(
            runner.decode("app.apk", &cfg),
            Err(ApktoolError::NotFound(_))
        ));
    }

    #[test]
    fn test_decode_result_success_flag() {
        let r = DecodeResult {
            output_dir: "/out".to_string(),
            smali_dirs: vec![],
            res_dir: None,
            success: true,
            log: String::new(),
        };
        assert!(r.success);
    }

    #[test]
    fn test_decode_result_failure_flag() {
        let r = DecodeResult {
            output_dir: "/out".to_string(),
            smali_dirs: vec![],
            res_dir: None,
            success: false,
            log: "error".to_string(),
        };
        assert!(!r.success);
    }

    #[test]
    fn test_build_error_names_the_directory() {
        let runner = MockApktoolRunner::success();
        let cfg = ApktoolConfig::new("apktool", "/build");
        let err = runner.build("/build-does-not-exist", &cfg).unwrap_err();
        assert!(err.to_string().contains("/build-does-not-exist"));
    }

    #[test]
    fn test_runner_failure_struct() {
        let runner = MockApktoolRunner::failure();
        assert!(!runner.decode_ok);
        assert!(!runner.build_ok);
        assert!(runner.smali_dirs.is_empty());
    }

    #[test]
    fn test_runner_success_struct() {
        let runner = MockApktoolRunner::success();
        assert!(runner.decode_ok);
        assert!(runner.build_ok);
        assert!(!runner.smali_dirs.is_empty());
    }

    // â"€â"€â"€ ApktoolRunnerImpl â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn runner_impl_decode_requires_a_real_apk() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        match runner.decode("app.apk") {
            Err(ApktoolError::NotFound(m)) => assert!(m.contains("app.apk")),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("decoded an APK that does not exist"),
        }
    }

    #[test]
    fn runner_impl_decode_wrong_extension() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        let err = runner.decode("app.zip").unwrap_err();
        assert!(matches!(err, ApktoolError::Decode(_)));
    }

    #[test]
    fn runner_impl_reports_missing_input_not_smali_dirs() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        assert!(matches!(
            runner.decode("myapp.apk"),
            Err(ApktoolError::NotFound(_))
        ));
    }

    #[test]
    fn runner_impl_no_src_still_requires_a_real_apk() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out").with_no_src();
        let runner = ApktoolRunnerImpl::new(cfg);
        assert!(matches!(
            runner.decode("myapp.apk"),
            Err(ApktoolError::NotFound(_))
        ));
    }

    #[test]
    fn runner_impl_no_res_still_requires_a_real_apk() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out").with_no_res();
        let runner = ApktoolRunnerImpl::new(cfg);
        assert!(matches!(
            runner.decode("myapp.apk"),
            Err(ApktoolError::NotFound(_))
        ));
    }

    #[test]
    fn runner_impl_never_claims_a_manifest_it_did_not_see() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        let err = runner.decode("myapp.apk").unwrap_err();
        assert!(err.to_string().contains("myapp.apk"));
    }

    #[test]
    fn runner_impl_build_requires_a_real_directory() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        assert!(matches!(
            runner.build("/tmp/out/myapp-does-not-exist"),
            Err(ApktoolError::NotFound(_))
        ));
    }

    #[test]
    fn runner_impl_build_empty_dir_errors() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        let err = runner.build("").unwrap_err();
        assert!(matches!(err, ApktoolError::Build(_)));
    }

    #[test]
    fn runner_impl_install_framework_requires_a_real_file() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        match runner.install_framework("framework.apk") {
            Err(ApktoolError::NotFound(m)) => assert!(m.contains("framework.apk")),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(()) => panic!("installed a framework APK that does not exist"),
        }
    }

    #[test]
    fn runner_impl_install_framework_bad_ext() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        let err = runner.install_framework("framework.jar").unwrap_err();
        assert!(matches!(err, ApktoolError::NotFound(_)));
    }

    // â"€â"€â"€ ApkDecodeResult helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn apk_decode_result_smali_count() {
        let r = ApkDecodeResult {
            output_dir: "/out".into(),
            smali_dirs: vec!["smali".into(), "smali_classes2".into()],
            res_dir: Some("/out/res".into()),
            manifest_path: Some("/out/AndroidManifest.xml".into()),
            warnings: vec![],
        };
        assert_eq!(r.smali_count(), 2);
        assert!(r.is_clean());
    }

    #[test]
    fn apk_decode_result_not_clean() {
        let r = ApkDecodeResult {
            output_dir: "/out".into(),
            smali_dirs: vec![],
            res_dir: None,
            manifest_path: None,
            warnings: vec!["warning".into()],
        };
        assert!(!r.is_clean());
    }

    #[test]
    fn apk_build_result_is_not_produced_without_a_project() {
        let cfg = ApktoolConfig::new("apktool", "/tmp/out");
        let runner = ApktoolRunnerImpl::new(cfg);
        assert!(runner.build("/myapp").is_err());
    }
}


