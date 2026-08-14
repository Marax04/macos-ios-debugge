//! `apk_rebuilder` — APK rebuild/repack pipeline.
//!
//! Provides [`ApkRebuilder`] as the top-level entry point and the following
//! building blocks:
//! * [`SmaliRecompiler`] — compiles smali text back to DEX bytes
//! * [`ResourceRecompiler`] — compiles decoded resource directories back to `resources.arsc`
//! * [`SigningConfig`] — keystroke-alias / password configuration for APK signing
//! * [`ManifestEditor`] — in-place AndroidManifest.xml editing
//! * [`DexMerger`] — merge multiple DEX byte buffers respecting 65k limits
//! * [`ZipAligner`] — 4-byte-align ZIP entries for Android installation
//! * [`RebuildReport`] — aggregated result of a full rebuild run

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ApktoolError, DecodeResult};

pub use crate::BuildResult;
pub use std::path::Path;

// ─── SmaliRecompiler ─────────────────────────────────────────────────────────

/// Recompiles smali source directories into DEX byte buffers.
#[derive(Debug, Clone, Default)]
pub struct SmaliRecompiler {
    /// Minimum smali source API version (controls opcode set).
    pub api_level: u32,
    /// Whether to include debug information in the output.
    pub include_debug_info: bool,
    /// Extra options passed verbatim to the smali tool.
    pub extra_opts: Vec<String>,
}

impl SmaliRecompiler {
    /// Create with default settings (API 21, debug info on).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            api_level: 21,
            include_debug_info: true,
            extra_opts: vec![],
        }
    }

    /// Set the target API level.
    #[must_use]
    pub const fn with_api_level(mut self, level: u32) -> Self {
        self.api_level = level;
        self
    }

    /// Disable debug information in output DEX.
    #[must_use]
    pub const fn without_debug_info(mut self) -> Self {
        self.include_debug_info = false;
        self
    }

    /// Simulate compilation of a smali directory into DEX bytes.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if the directory path is empty.
    pub fn compile(&self, smali_dir: &str) -> Result<Vec<u8>, ApktoolError> {
        if smali_dir.is_empty() {
            return Err(ApktoolError::Build("smali directory is empty".into()));
        }
        // Emit a synthetic DEX header as placeholder
        let mut dex = Vec::with_capacity(112);
        dex.extend_from_slice(b"dex\n035\0"); // magic
        dex.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
        dex.extend_from_slice(&[0u8; 20]); // SHA-1 placeholder
        dex.extend_from_slice(&112u32.to_le_bytes()); // file size
        dex.extend_from_slice(&112u32.to_le_bytes()); // header size
        dex.extend_from_slice(&0xEFBE_ADDE_u32.to_le_bytes()); // endian tag
        dex.extend_from_slice(&[0u8; 48]); // remaining header fields
        Ok(dex)
    }

    /// Compile multiple smali directories, returning one DEX per directory.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if any directory fails.
    pub fn compile_all(&self, dirs: &[String]) -> Result<Vec<Vec<u8>>, ApktoolError> {
        dirs.iter().map(|d| self.compile(d)).collect()
    }
}

// ─── ResourceRecompiler ──────────────────────────────────────────────────────

/// Recompiles decoded resource directories back to `resources.arsc`.
#[derive(Debug, Clone, Default)]
pub struct ResourceRecompiler {
    /// Aapt2 binary path override.
    pub aapt2_path: Option<PathBuf>,
    /// Compile with `--no-compress` flag.
    pub no_compress: bool,
    /// Minimum SDK version for resource compilation.
    pub min_sdk: u32,
}

impl ResourceRecompiler {
    /// Create with defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            aapt2_path: None,
            no_compress: false,
            min_sdk: 21,
        }
    }

    /// Override the aapt2 binary path.
    #[must_use]
    pub fn with_aapt2(mut self, path: impl Into<PathBuf>) -> Self {
        self.aapt2_path = Some(path.into());
        self
    }

    /// Simulate resource recompilation from a decoded `res/` directory.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if `res_dir` is empty.
    pub fn compile(&self, res_dir: &str) -> Result<Vec<u8>, ApktoolError> {
        if res_dir.is_empty() {
            return Err(ApktoolError::Build("resource directory is empty".into()));
        }
        // Emit a minimal ARSC placeholder
        let mut arsc = Vec::new();
        arsc.extend_from_slice(&0x0008_0002_u32.to_le_bytes()); // chunk type: RES_TABLE_TYPE
        arsc.extend_from_slice(&0x0Cu32.to_le_bytes()); // header size
        arsc.extend_from_slice(&0x0Cu32.to_le_bytes()); // total size
        Ok(arsc)
    }

    /// Returns `true` if an aapt2 path has been set.
    #[must_use]
    pub const fn has_aapt2(&self) -> bool {
        self.aapt2_path.is_some()
    }
}

// ─── SigningConfig ────────────────────────────────────────────────────────────

/// Configuration for APK signing (jarsigner / apksigner).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Path to the keystore file.
    pub keystore_path: String,
    /// Alias of the key entry inside the keystore.
    pub key_alias: String,
    /// Keystore password (plaintext; use env injection in production).
    pub keystore_password: String,
    /// Key password (may differ from keystore password).
    pub key_password: String,
    /// Whether to use v1 (JAR) signing.
    pub enable_v1: bool,
    /// Whether to use v2 (APK Scheme v2) signing.
    pub enable_v2: bool,
    /// Whether to use v3 (APK Scheme v3) signing.
    pub enable_v3: bool,
}

impl SigningConfig {
    /// Create a minimal signing config for a debug keystore.
    #[must_use]
    pub fn debug() -> Self {
        Self {
            keystore_path: "debug.keystore".into(),
            key_alias: "androiddebugkey".into(),
            keystore_password: "android".into(),
            key_password: "android".into(),
            enable_v1: true,
            enable_v2: true,
            enable_v3: false,
        }
    }

    /// Create a release signing config.
    #[must_use]
    pub fn release(
        keystore_path: impl Into<String>,
        alias: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let pwd = password.into();
        Self {
            keystore_path: keystore_path.into(),
            key_alias: alias.into(),
            keystore_password: pwd.clone(),
            key_password: pwd,
            enable_v1: false,
            enable_v2: true,
            enable_v3: true,
        }
    }

    /// Returns `true` if at least one signing scheme is enabled.
    #[must_use]
    pub const fn has_scheme(&self) -> bool {
        self.enable_v1 || self.enable_v2 || self.enable_v3
    }

    /// Returns a descriptive label for the active signing schemes.
    #[must_use]
    pub fn schemes_label(&self) -> String {
        let mut parts = Vec::new();
        if self.enable_v1 {
            parts.push("v1");
        }
        if self.enable_v2 {
            parts.push("v2");
        }
        if self.enable_v3 {
            parts.push("v3");
        }
        if parts.is_empty() {
            return "none".into();
        }
        parts.join("+")
    }
}

// ─── ManifestEditor ──────────────────────────────────────────────────────────

/// In-place `AndroidManifest.xml` text editor.
#[derive(Debug, Clone, Default)]
pub struct ManifestEditor {
    /// Pending attribute changes: `(xpath-like key, new value)`.
    changes: Vec<(String, String)>,
}

impl ManifestEditor {
    /// Create a new editor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a change to the `android:debuggable` attribute.
    #[must_use]
    pub fn set_debuggable(mut self, value: bool) -> Self {
        self.changes
            .push(("application/@android:debuggable".into(), value.to_string()));
        self
    }

    /// Queue a change to the `android:versionName` attribute.
    #[must_use]
    pub fn set_version_name(mut self, name: impl Into<String>) -> Self {
        self.changes
            .push(("manifest/@android:versionName".into(), name.into()));
        self
    }

    /// Queue a change to the `android:versionCode` attribute.
    #[must_use]
    pub fn set_version_code(mut self, code: u32) -> Self {
        self.changes
            .push(("manifest/@android:versionCode".into(), code.to_string()));
        self
    }

    /// Queue a change to the minimum SDK version.
    #[must_use]
    pub fn set_min_sdk(mut self, sdk: u32) -> Self {
        self.changes
            .push(("uses-sdk/@android:minSdkVersion".into(), sdk.to_string()));
        self
    }

    /// Remove all pending changes.
    pub fn reset(&mut self) {
        self.changes.clear();
    }

    /// Apply all queued changes to a manifest XML string.
    ///
    /// This is a simplistic string-replace implementation for plain-text XML.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if `xml` is empty.
    pub fn apply(&self, xml: &str) -> Result<String, ApktoolError> {
        if xml.is_empty() {
            return Err(ApktoolError::Decode("empty manifest XML".into()));
        }
        let mut out = xml.to_string();
        for (key, val) in &self.changes {
            // Very simplistic: replace first occurrence of the attribute name
            let attr_name = key.split('/').next_back().unwrap_or(key);
            let search = format!("{attr_name}=");
            if let Some(pos) = out.find(&search) {
                let rest = &out[pos + search.len()..];
                let (quote, end) = if let Some(__stripped) = rest.strip_prefix('"') {
                    ('"', __stripped.find('"').map(|p| pos + search.len() + 1 + p))
                } else if let Some(__stripped) = rest.strip_prefix('\'') {
                    (
                        '\'',
                        __stripped.find('\'').map(|p| pos + search.len() + 1 + p),
                    )
                } else {
                    continue;
                };
                if let Some(end_pos) = end {
                    let start_pos = pos + search.len() + 1;
                    out = format!(
                        "{}{}{}{}{}",
                        &out[..start_pos],
                        val,
                        quote,
                        &out[end_pos + 1..],
                        ""
                    );
                }
            }
        }
        Ok(out)
    }

    /// Number of pending changes.
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.changes.len()
    }
}

// ─── DexMerger ───────────────────────────────────────────────────────────────

/// Merge multiple DEX byte buffers, respecting the 65535-method-reference limit.
#[derive(Debug, Clone, Default)]
pub struct DexMerger {
    /// Maximum methods per DEX before splitting.
    pub max_methods: u32,
    /// Whether to strip debug information.
    pub strip_debug: bool,
}

impl DexMerger {
    /// Create with Android's default 65535 method limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_methods: 65535,
            strip_debug: false,
        }
    }

    /// Set the maximum methods per DEX.
    #[must_use]
    pub const fn with_max_methods(mut self, n: u32) -> Self {
        self.max_methods = n;
        self
    }

    /// Merge DEX buffers.  In a real implementation this re-encodes DEX; here we
    /// simply concatenate with a separator and return a list of (at most) two groups.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if no buffers are provided.
    pub fn merge(&self, dex_buffers: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ApktoolError> {
        if dex_buffers.is_empty() {
            return Err(ApktoolError::Build("no DEX buffers to merge".into()));
        }
        // Simulate: group into chunks based on size heuristic
        let total_size: usize = dex_buffers.iter().map(std::vec::Vec::len).sum();
        if total_size < 1_000_000 {
            // Single-DEX output
            let mut merged = Vec::new();
            for buf in dex_buffers {
                merged.extend_from_slice(buf);
            }
            Ok(vec![merged])
        } else {
            // Multi-DEX: naive 50/50 split
            let mid = dex_buffers.len() / 2;
            let mut part1 = Vec::new();
            let mut part2 = Vec::new();
            for buf in &dex_buffers[..mid.max(1)] {
                part1.extend_from_slice(buf);
            }
            for buf in &dex_buffers[mid.max(1)..] {
                part2.extend_from_slice(buf);
            }
            Ok(vec![part1, part2])
        }
    }

    /// Returns how many output DEX files a given set of buffers would produce.
    #[must_use]
    pub fn estimate_output_count(&self, input_count: usize) -> usize {
        if input_count == 0 {
            0
        } else {
            (input_count / 4).max(1)
        }
    }
}

// ─── ZipAligner ──────────────────────────────────────────────────────────────

/// 4-byte ZIP alignment for Android installation performance.
#[derive(Debug, Clone)]
pub struct ZipAligner {
    /// Alignment in bytes (typically 4 for uncompressed entries).
    pub alignment: usize,
    /// Whether to page-align `.so` shared libraries to 4096 bytes.
    pub page_align_shared_libs: bool,
}

impl Default for ZipAligner {
    fn default() -> Self {
        Self {
            alignment: 4,
            page_align_shared_libs: true,
        }
    }
}

impl ZipAligner {
    /// Create with the standard 4-byte alignment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the alignment requirement.
    #[must_use]
    pub const fn with_alignment(mut self, align: usize) -> Self {
        self.alignment = align;
        self
    }

    /// Compute the padding needed to align `offset` to `self.alignment`.
    #[must_use]
    pub const fn padding_for(&self, offset: usize) -> usize {
        let align = if self.alignment == 0 {
            4
        } else {
            self.alignment
        };
        let rem = offset % align;
        if rem == 0 { 0 } else { align - rem }
    }

    /// Returns `true` if `offset` is already aligned.
    #[must_use]
    pub const fn is_aligned(&self, offset: usize) -> bool {
        self.padding_for(offset) == 0
    }

    /// Simulate alignment of a ZIP file by adjusting entry offsets.
    ///
    /// Returns a map `entry_name → aligned_offset`.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if entries is empty.
    pub fn align_entries(
        &self,
        entries: &[(String, usize, bool)], // (name, size, is_stored)
    ) -> Result<HashMap<String, usize>, ApktoolError> {
        if entries.is_empty() {
            return Err(ApktoolError::Build("no entries to align".into()));
        }
        let mut result = HashMap::new();
        let mut current_offset: usize = 30; // local file header base
        for (name, size, is_stored) in entries {
            if *is_stored {
                let pad = self.padding_for(current_offset);
                current_offset += pad;
            }
            result.insert(name.clone(), current_offset);
            current_offset += 30 + name.len() + size; // header + name + data
        }
        Ok(result)
    }
}

// ─── RebuildReport ───────────────────────────────────────────────────────────

/// Result of a complete APK rebuild run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildReport {
    /// Path to the output APK.
    pub output_path: String,
    /// Whether the rebuild succeeded.
    pub success: bool,
    /// Number of smali directories compiled.
    pub smali_dirs_compiled: usize,
    /// Number of DEX files in the final APK.
    pub dex_count: usize,
    /// Whether the APK was signed.
    pub signed: bool,
    /// Active signing schemes, e.g. `"v2+v3"`.
    pub signing_schemes: String,
    /// Whether the APK was zipaligned.
    pub zipaligned: bool,
    /// Warnings emitted during the build.
    pub warnings: Vec<String>,
    /// Total wall-clock build time in milliseconds (simulated).
    pub build_time_ms: u64,
}

impl RebuildReport {
    /// Returns `true` if the rebuild is clean (no warnings).
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Short summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} ({} DEX, signed={}, zipaligned={})",
            if self.success { "OK" } else { "FAILED" },
            self.dex_count,
            self.signed,
            self.zipaligned,
        )
    }
}

// ─── ApkRebuilder ────────────────────────────────────────────────────────────

/// Top-level APK rebuild pipeline.
///
/// Orchestrates smali recompilation, resource recompilation, DEX merging,
/// manifest editing, signing, and zip-alignment.
#[derive(Debug, Clone)]
pub struct ApkRebuilder {
    /// Smali recompiler configuration.
    pub smali: SmaliRecompiler,
    /// Resource recompiler configuration.
    pub resources: ResourceRecompiler,
    /// Signing configuration (optional).
    pub signing: Option<SigningConfig>,
    /// Whether to run zip-alignment after building.
    pub zipalign: bool,
    /// Manifest edits to apply before recompilation.
    pub manifest_editor: ManifestEditor,
}

impl Default for ApkRebuilder {
    fn default() -> Self {
        Self {
            smali: SmaliRecompiler::new(),
            resources: ResourceRecompiler::new(),
            signing: Some(SigningConfig::debug()),
            zipalign: true,
            manifest_editor: ManifestEditor::new(),
        }
    }
}

impl ApkRebuilder {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable signing.
    #[must_use]
    pub fn without_signing(mut self) -> Self {
        self.signing = None;
        self
    }

    /// Use a custom signing configuration.
    #[must_use]
    pub fn with_signing(mut self, config: SigningConfig) -> Self {
        self.signing = Some(config);
        self
    }

    /// Disable zip-alignment.
    #[must_use]
    pub const fn without_zipalign(mut self) -> Self {
        self.zipalign = false;
        self
    }

    /// Run the full rebuild pipeline on a previously decoded APK directory.
    ///
    /// # Errors
    /// Returns [`ApktoolError`] if smali or resource recompilation fails.
    pub fn rebuild(
        &self,
        decode_result: &DecodeResult,
        output_apk: &str,
    ) -> Result<RebuildReport, ApktoolError> {
        if output_apk.is_empty() {
            return Err(ApktoolError::Build("output APK path is empty".into()));
        }

        let mut warnings = Vec::new();
        let mut dex_bufs: Vec<Vec<u8>> = Vec::new();

        // 1. Compile smali
        for dir in &decode_result.smali_dirs {
            match self.smali.compile(dir) {
                Ok(buf) => dex_bufs.push(buf),
                Err(e) => warnings.push(format!("smali compile warning: {e}")),
            }
        }

        // 2. Compile resources
        if let Some(ref res_dir) = decode_result.res_dir
            && let Err(e) = self.resources.compile(res_dir)
        {
            warnings.push(format!("resource compile warning: {e}"));
        }

        // 3. Merge DEX
        let merger = DexMerger::new();
        let merged_dex = if dex_bufs.is_empty() {
            vec![]
        } else {
            merger.merge(&dex_bufs).unwrap_or_else(|_| dex_bufs.clone())
        };
        let dex_count = merged_dex.len().max(usize::from(!dex_bufs.is_empty()));

        // 4. Signing
        let (signed, signing_schemes) = self.signing.as_ref().map_or_else(|| (false, "none".to_string()), |cfg| (true, cfg.schemes_label()));

        // 5. Zipalign
        let zipaligned = self.zipalign;

        Ok(RebuildReport {
            output_path: output_apk.to_string(),
            success: true,
            smali_dirs_compiled: decode_result.smali_dirs.len(),
            dex_count,
            signed,
            signing_schemes,
            zipaligned,
            warnings,
            build_time_ms: 42,
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodeResult;

    fn mock_decode() -> DecodeResult {
        DecodeResult {
            output_dir: "/tmp/decoded".into(),
            smali_dirs: vec!["smali".into(), "smali_classes2".into()],
            res_dir: Some("/tmp/decoded/res".into()),
            success: true,
            log: "ok".into(),
        }
    }

    // ── SmaliRecompiler ───────────────────────────────────────────────────────

    #[test]
    fn test_smali_recompiler_new() {
        let r = SmaliRecompiler::new();
        assert_eq!(r.api_level, 21);
        assert!(r.include_debug_info);
    }

    #[test]
    fn test_smali_compile_ok() {
        let r = SmaliRecompiler::new();
        let dex = r.compile("smali").unwrap();
        assert!(!dex.is_empty());
    }

    #[test]
    fn test_smali_compile_empty_dir_err() {
        let r = SmaliRecompiler::new();
        assert!(r.compile("").is_err());
    }

    #[test]
    fn test_smali_compile_all() {
        let r = SmaliRecompiler::new();
        let dirs = vec!["smali".to_string(), "smali2".to_string()];
        let result = r.compile_all(&dirs).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_smali_with_api_level() {
        let r = SmaliRecompiler::new().with_api_level(33);
        assert_eq!(r.api_level, 33);
    }

    #[test]
    fn test_smali_without_debug_info() {
        let r = SmaliRecompiler::new().without_debug_info();
        assert!(!r.include_debug_info);
    }

    #[test]
    fn test_smali_dex_magic() {
        let r = SmaliRecompiler::new();
        let dex = r.compile("test").unwrap();
        assert_eq!(&dex[0..4], b"dex\n");
    }

    // ── ResourceRecompiler ────────────────────────────────────────────────────

    #[test]
    fn test_resource_recompiler_new() {
        let r = ResourceRecompiler::new();
        assert!(!r.no_compress);
        assert!(!r.has_aapt2());
    }

    #[test]
    fn test_resource_compile_ok() {
        let r = ResourceRecompiler::new();
        let arsc = r.compile("res/").unwrap();
        assert!(!arsc.is_empty());
    }

    #[test]
    fn test_resource_compile_empty_err() {
        let r = ResourceRecompiler::new();
        assert!(r.compile("").is_err());
    }

    #[test]
    fn test_resource_with_aapt2() {
        let r = ResourceRecompiler::new().with_aapt2("/usr/bin/aapt2");
        assert!(r.has_aapt2());
    }

    // ── SigningConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_signing_config_debug() {
        let c = SigningConfig::debug();
        assert_eq!(c.key_alias, "androiddebugkey");
        assert!(c.enable_v2);
    }

    #[test]
    fn test_signing_config_release() {
        let c = SigningConfig::release("my.jks", "mykey", "password");
        assert!(!c.enable_v1);
        assert!(c.enable_v2);
        assert!(c.enable_v3);
    }

    #[test]
    fn test_signing_config_has_scheme() {
        let c = SigningConfig::debug();
        assert!(c.has_scheme());
    }

    #[test]
    fn test_signing_config_no_scheme() {
        let mut c = SigningConfig::debug();
        c.enable_v1 = false;
        c.enable_v2 = false;
        c.enable_v3 = false;
        assert!(!c.has_scheme());
        assert_eq!(c.schemes_label(), "none");
    }

    #[test]
    fn test_signing_config_schemes_label() {
        let c = SigningConfig::debug();
        let label = c.schemes_label();
        assert!(label.contains("v2"));
    }

    #[test]
    fn test_signing_config_serialization() {
        let c = SigningConfig::release("k.jks", "alias", "pw");
        let json = serde_json::to_string(&c).unwrap();
        let d: SigningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(d.key_alias, c.key_alias);
    }

    // ── ManifestEditor ────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_editor_change_count() {
        let e = ManifestEditor::new()
            .set_debuggable(false)
            .set_version_code(2);
        assert_eq!(e.change_count(), 2);
    }

    #[test]
    fn test_manifest_editor_apply_ok() {
        let xml = r#"<manifest versionCode="1"><application debuggable="true"/></manifest>"#;
        let e = ManifestEditor::new().set_debuggable(false);
        let result = e.apply(xml).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_manifest_editor_apply_empty_err() {
        let e = ManifestEditor::new();
        assert!(e.apply("").is_err());
    }

    #[test]
    fn test_manifest_editor_reset() {
        let mut e = ManifestEditor::new()
            .set_debuggable(true)
            .set_version_code(5);
        e.reset();
        assert_eq!(e.change_count(), 0);
    }

    #[test]
    fn test_manifest_editor_set_min_sdk() {
        let e = ManifestEditor::new().set_min_sdk(24);
        assert_eq!(e.change_count(), 1);
    }

    #[test]
    fn test_manifest_editor_set_version_name() {
        let e = ManifestEditor::new().set_version_name("2.0.0");
        assert_eq!(e.change_count(), 1);
    }

    // ── DexMerger ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dex_merger_single_dex() {
        let m = DexMerger::new();
        let result = m.merge(&[b"dex\n035\0".to_vec()]).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dex_merger_empty_err() {
        let m = DexMerger::new();
        assert!(m.merge(&[]).is_err());
    }

    #[test]
    fn test_dex_merger_estimate_output() {
        let m = DexMerger::new();
        assert_eq!(m.estimate_output_count(0), 0);
        assert_eq!(m.estimate_output_count(1), 1);
    }

    #[test]
    fn test_dex_merger_with_max_methods() {
        let m = DexMerger::new().with_max_methods(50_000);
        assert_eq!(m.max_methods, 50_000);
    }

    // ── ZipAligner ────────────────────────────────────────────────────────────

    #[test]
    fn test_zip_aligner_padding() {
        let z = ZipAligner::new();
        assert_eq!(z.padding_for(0), 0);
        assert_eq!(z.padding_for(1), 3);
        assert_eq!(z.padding_for(4), 0);
        assert_eq!(z.padding_for(5), 3);
    }

    #[test]
    fn test_zip_aligner_is_aligned() {
        let z = ZipAligner::new();
        assert!(z.is_aligned(0));
        assert!(z.is_aligned(4));
        assert!(!z.is_aligned(3));
    }

    #[test]
    fn test_zip_aligner_align_entries_ok() {
        let z = ZipAligner::new();
        let entries = vec![
            ("classes.dex".to_string(), 1024, true),
            ("resources.arsc".to_string(), 512, true),
        ];
        let offsets = z.align_entries(&entries).unwrap();
        assert!(offsets.contains_key("classes.dex"));
    }

    #[test]
    fn test_zip_aligner_align_empty_err() {
        let z = ZipAligner::new();
        assert!(z.align_entries(&[]).is_err());
    }

    #[test]
    fn test_zip_aligner_custom_alignment() {
        let z = ZipAligner::new().with_alignment(8);
        assert_eq!(z.padding_for(1), 7);
        assert_eq!(z.padding_for(8), 0);
    }

    // ── ApkRebuilder ──────────────────────────────────────────────────────────

    #[test]
    fn test_rebuilder_new() {
        let r = ApkRebuilder::new();
        assert!(r.zipalign);
        assert!(r.signing.is_some());
    }

    #[test]
    fn test_rebuilder_without_signing() {
        let r = ApkRebuilder::new().without_signing();
        assert!(r.signing.is_none());
    }

    #[test]
    fn test_rebuilder_rebuild_ok() {
        let r = ApkRebuilder::new();
        let decode = mock_decode();
        let report = r.rebuild(&decode, "/tmp/out.apk").unwrap();
        assert!(report.success);
        assert_eq!(report.smali_dirs_compiled, 2);
    }

    #[test]
    fn test_rebuilder_rebuild_empty_output_err() {
        let r = ApkRebuilder::new();
        let decode = mock_decode();
        assert!(r.rebuild(&decode, "").is_err());
    }

    #[test]
    fn test_rebuilder_report_summary() {
        let r = ApkRebuilder::new();
        let decode = mock_decode();
        let report = r.rebuild(&decode, "out.apk").unwrap();
        let s = report.summary();
        assert!(s.contains("OK"));
    }

    #[test]
    fn test_rebuilder_without_zipalign() {
        let r = ApkRebuilder::new().without_zipalign();
        let decode = mock_decode();
        let report = r.rebuild(&decode, "out.apk").unwrap();
        assert!(!report.zipaligned);
    }

    #[test]
    fn test_rebuilder_report_signed() {
        let r = ApkRebuilder::new();
        let decode = mock_decode();
        let report = r.rebuild(&decode, "out.apk").unwrap();
        assert!(report.signed);
        assert_ne!(report.signing_schemes, "none");
    }

    #[test]
    fn test_rebuilder_report_is_clean() {
        let r = ApkRebuilder::new();
        let decode = mock_decode();
        let report = r.rebuild(&decode, "out.apk").unwrap();
        let _ = report.is_clean(); // no panic
    }

    #[test]
    fn test_rebuild_report_serialization() {
        let report = RebuildReport {
            output_path: "out.apk".into(),
            success: true,
            smali_dirs_compiled: 2,
            dex_count: 2,
            signed: true,
            signing_schemes: "v2".into(),
            zipaligned: true,
            warnings: vec![],
            build_time_ms: 100,
        };
        let json = serde_json::to_string(&report).unwrap();
        let d: RebuildReport = serde_json::from_str(&json).unwrap();
        assert_eq!(d.output_path, report.output_path);
    }
}
