//! Smali patching: method modification (insert/remove instructions), change return values,
//! insert log calls, bypass security checks, recompile DEX, sign APK after patch.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("method not found: {class}->{method}")]
    MethodNotFound { class: String, method: String },
    #[error("instruction index {0} out of bounds (len={1})")]
    IndexOutOfBounds(usize, usize),
    #[error("recompile failed: {0}")]
    RecompileFailed(String),
    #[error("sign failed: {0}")]
    SignFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("patch target {0} is immutable")]
    Immutable(String),
}

pub type PatchResult<T> = Result<T, PatchError>;

// ── Smali instruction (patch-level) ──────────────────────────────────────────

/// A single smali instruction as a raw text line (for patching purposes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmaliLine {
    pub text: String,
    pub label: Option<String>,
}

impl SmaliLine {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into(), label: None }
    }

    pub fn with_label(text: impl Into<String>, label: impl Into<String>) -> Self {
        Self { text: text.into(), label: Some(label.into()) }
    }

    #[must_use] 
    pub fn is_return(&self) -> bool {
        let t = self.text.trim();
        t.starts_with("return") && !t.starts_with("return-void-no-barrier")
    }

    #[must_use] 
    pub fn is_invoke(&self) -> bool {
        self.text.trim().starts_with("invoke-")
    }
}

// ── Patch operation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchOp {
    /// Insert lines before instruction at index.
    InsertBefore { index: usize, lines: Vec<SmaliLine> },
    /// Insert lines after instruction at index.
    InsertAfter { index: usize, lines: Vec<SmaliLine> },
    /// Replace instruction at index with new lines.
    Replace { index: usize, lines: Vec<SmaliLine> },
    /// Remove instruction at index.
    Remove { index: usize },
    /// Prepend lines at the start of the method body (after .locals).
    Prepend { lines: Vec<SmaliLine> },
    /// Append lines before the first return.
    AppendBeforeReturn { lines: Vec<SmaliLine> },
    /// Replace all return instructions with return-void (void method bypass).
    ForceReturnVoid,
    /// Replace all return-* with a constant value return.
    ForceReturnConst { value: i32 },
    /// Increase .locals count by n.
    IncreaseLocals { by: usize },
}

// ── Method patcher ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodPatcher {
    pub class_descriptor: String,
    pub method_name: String,
    pub method_proto: String,
    pub original_lines: Vec<SmaliLine>,
    pub ops: Vec<PatchOp>,
}

impl MethodPatcher {
    pub fn new(
        class_descriptor: impl Into<String>,
        method_name: impl Into<String>,
        method_proto: impl Into<String>,
        original_lines: Vec<SmaliLine>,
    ) -> Self {
        Self {
            class_descriptor: class_descriptor.into(),
            method_name: method_name.into(),
            method_proto: method_proto.into(),
            original_lines,
            ops: Vec::new(),
        }
    }

    pub fn add_op(&mut self, op: PatchOp) -> &mut Self {
        self.ops.push(op);
        self
    }

    /// Apply a single instruction at index.
    pub fn insert_before(&mut self, index: usize, lines: Vec<SmaliLine>) -> &mut Self {
        self.ops.push(PatchOp::InsertBefore { index, lines });
        self
    }

    pub fn insert_after(&mut self, index: usize, lines: Vec<SmaliLine>) -> &mut Self {
        self.ops.push(PatchOp::InsertAfter { index, lines });
        self
    }

    pub fn replace_at(&mut self, index: usize, lines: Vec<SmaliLine>) -> &mut Self {
        self.ops.push(PatchOp::Replace { index, lines });
        self
    }

    pub fn remove_at(&mut self, index: usize) -> &mut Self {
        self.ops.push(PatchOp::Remove { index });
        self
    }

    pub fn force_return_void(&mut self) -> &mut Self {
        self.ops.push(PatchOp::ForceReturnVoid);
        self
    }

    pub fn force_return_const(&mut self, value: i32) -> &mut Self {
        self.ops.push(PatchOp::ForceReturnConst { value });
        self
    }

    /// Insert an Android Log.d call at the start of the method.
    pub fn inject_log(&mut self, tag: &str, message: &str) -> &mut Self {
        let log_lines = vec![
            SmaliLine::new(format!("const-string v0, \"{tag}\"")),
            SmaliLine::new(format!("const-string v1, \"{message}\"")),
            SmaliLine::new("invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"),
        ];
        self.ops.push(PatchOp::Prepend { lines: log_lines });
        self.ops.push(PatchOp::IncreaseLocals { by: 2 });
        self
    }

    /// Apply all ops and return the patched smali lines.
    ///
    /// Index-based ops (`InsertBefore`, `InsertAfter`, Replace, Remove) use the
    /// *original* instruction indices recorded at queue-time.  A running
    /// `offset` tracks how many lines have been inserted or removed by
    /// preceding ops so that each original index is translated to the correct
    /// current position in the mutating vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn apply(&self) -> PatchResult<Vec<SmaliLine>> {
        let mut lines = self.original_lines.clone();
        // Running delta: number of lines added (+) or removed (-) by index ops
        // applied so far.  Applied in order, earlier ops shift later indices.
        let mut offset: isize = 0;

        for op in &self.ops {
            match op {
                PatchOp::InsertBefore { index, lines: new } => {
                    // Validate against the original length (before any mutations).
                    if *index > self.original_lines.len() {
                        return Err(PatchError::IndexOutOfBounds(*index, self.original_lines.len()));
                    }
                    let current_idx = (*index).cast_signed().checked_add(offset)
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or(PatchError::IndexOutOfBounds(*index, self.original_lines.len()))?;
                    for (i, l) in new.iter().enumerate() {
                        lines.insert(current_idx + i, l.clone());
                    }
                    offset += new.len().cast_signed();
                }
                PatchOp::InsertAfter { index, lines: new } => {
                    // Use checked_add to avoid overflow; validate original bounds.
                    let insert_orig = index
                        .checked_add(1)
                        .ok_or(PatchError::IndexOutOfBounds(*index, self.original_lines.len()))?;
                    if insert_orig > self.original_lines.len() {
                        return Err(PatchError::IndexOutOfBounds(*index, self.original_lines.len()));
                    }
                    let current_idx = insert_orig.cast_signed().checked_add(offset)
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or(PatchError::IndexOutOfBounds(*index, self.original_lines.len()))?;
                    for (i, l) in new.iter().enumerate() {
                        lines.insert(current_idx + i, l.clone());
                    }
                    offset += new.len().cast_signed();
                }
                PatchOp::Replace { index, lines: new } => {
                    if *index >= self.original_lines.len() {
                        return Err(PatchError::IndexOutOfBounds(*index, self.original_lines.len()));
                    }
                    let current_idx = (*index).cast_signed().checked_add(offset)
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or(PatchError::IndexOutOfBounds(*index, self.original_lines.len()))?;
                    lines.remove(current_idx);
                    for (i, l) in new.iter().enumerate() {
                        lines.insert(current_idx + i, l.clone());
                    }
                    // net change: new.len() inserted, 1 removed
                    offset += new.len().cast_signed() - 1;
                }
                PatchOp::Remove { index } => {
                    if *index >= self.original_lines.len() {
                        return Err(PatchError::IndexOutOfBounds(*index, self.original_lines.len()));
                    }
                    let current_idx = (*index).cast_signed().checked_add(offset)
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or(PatchError::IndexOutOfBounds(*index, self.original_lines.len()))?;
                    lines.remove(current_idx);
                    offset -= 1;
                }
                PatchOp::Prepend { lines: new } => {
                    let mut prepended = new.clone();
                    prepended.append(&mut lines);
                    lines = prepended;
                }
                PatchOp::AppendBeforeReturn { lines: new } => {
                    // Find first return instruction
                    if let Some(pos) = lines.iter().position(SmaliLine::is_return) {
                        for (i, l) in new.iter().enumerate() {
                            lines.insert(pos + i, l.clone());
                        }
                    } else {
                        lines.extend(new.iter().cloned());
                    }
                }
                PatchOp::ForceReturnVoid => {
                    for line in &mut lines {
                        if line.is_return() {
                            "return-void".clone_into(&mut line.text);
                        }
                    }
                }
                PatchOp::ForceReturnConst { value } => {
                    // Insert const/4 v0, #value before each return; change return to return v0
                    let mut i = 0;
                    while i < lines.len() {
                        if lines[i].is_return() {
                            let ret_type = &lines[i].text.trim().to_owned();
                            let is_wide = ret_type.contains("-wide");
                            let reg = "v0";
                            let const_line = if is_wide {
                                SmaliLine::new(format!("const-wide/16 {reg}, #{value}"))
                            } else if *value >= -8 && *value <= 7 {
                                SmaliLine::new(format!("const/4 {reg}, #{value}"))
                            } else {
                                SmaliLine::new(format!("const/16 {reg}, #{value}"))
                            };
                            lines[i] = SmaliLine::new(format!("return {reg}"));
                            lines.insert(i, const_line);
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                }
                PatchOp::IncreaseLocals { by } => {
                    // Update either .locals or .registers depending on which
                    // the method uses.  Both directives must be incremented to
                    // keep the scratch registers allocated by inject_log valid.
                    for line in &mut lines {
                        let trimmed = line.text.trim();
                        if let Some(rest) = trimmed.strip_prefix(".locals ") {
                            if let Ok(n) = rest.trim().parse::<usize>() {
                                // Use saturating_add to prevent integer overflow when
                                // `by` is large; Dalvik caps registers at 65535.
                                line.text = format!("    .locals {}", n.saturating_add(*by).min(65535));
                            }
                        } else if let Some(rest) = trimmed.strip_prefix(".registers ")
                            && let Ok(n) = rest.trim().parse::<usize>() {
                                line.text = format!("    .registers {}", n.saturating_add(*by).min(65535));
                            }
                    }
                }
            }
        }

        Ok(lines)
    }

    /// Render patched method back to smali text.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn render(&self) -> PatchResult<String> {
        use std::fmt::Write as _;
        let lines = self.apply()?;
        let mut out = String::new();
        let _ = writeln!(out, ".method public {}{}", self.method_name, self.method_proto);
        for line in &lines {
            out.push_str("    ");
            out.push_str(&line.text);
            out.push('\n');
        }
        out.push_str(".end method\n");
        Ok(out)
    }
}

// ── Security bypass helpers ───────────────────────────────────────────────────

/// Common security bypass patches.
pub struct SecurityBypass;

impl SecurityBypass {
    /// Bypass a boolean method (return true / return 1).
    pub fn bypass_boolean_true(patcher: &mut MethodPatcher) -> &mut MethodPatcher {
        patcher.force_return_const(1)
    }

    /// Bypass a boolean method (return false / return 0).
    pub fn bypass_boolean_false(patcher: &mut MethodPatcher) -> &mut MethodPatcher {
        patcher.force_return_const(0)
    }

    /// Bypass a void method (return-void immediately).
    pub fn bypass_void(patcher: &mut MethodPatcher) -> &mut MethodPatcher {
        patcher.force_return_void()
    }

    /// Bypass root/jailbreak check that returns boolean.
    pub fn bypass_root_check(patcher: &mut MethodPatcher) {
        patcher.force_return_const(0); // return false = not rooted
    }

    /// Bypass certificate pinning: make the check method return-void.
    pub fn bypass_cert_pinning(patcher: &mut MethodPatcher) {
        patcher.force_return_void();
    }

    /// Bypass SSL validation by forcing onReceivedSslError to proceed.
    pub fn bypass_ssl_error(patcher: &mut MethodPatcher) {
        // WebViewClient.onReceivedSslError calls handler.proceed()
        let proceed_call = vec![
            SmaliLine::new("invoke-virtual {p1}, Landroid/webkit/SslErrorHandler;->proceed()V"),
            SmaliLine::new("return-void"),
        ];
        patcher.ops.push(PatchOp::Replace { index: 0, lines: proceed_call });
    }

    /// Add an "allow all" hostname verifier stub.
    pub fn bypass_hostname_verifier(patcher: &mut MethodPatcher) {
        // HostnameVerifier.verify(String, SSLSession) should return true
        patcher.force_return_const(1);
    }
}

// ── APK patcher ───────────────────────────────────────────────────────────────

/// Configuration for recompiling and re-signing a patched APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkPatchConfig {
    /// Path to the input APK.
    pub input_apk: PathBuf,
    /// Path where the patched APK will be written.
    pub output_apk: PathBuf,
    /// Path to baksmali/smali jars (or None to skip recompile).
    pub smali_jar: Option<PathBuf>,
    /// Path to apksigner or jarsigner.
    pub signer_tool: Option<PathBuf>,
    /// Keystore for signing (path, alias, store-pass, key-pass).
    pub keystore: Option<KeystoreConfig>,
    /// Whether to zipalign the output APK.
    pub zipalign: bool,
    /// Path to zipalign binary.
    pub zipalign_bin: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    pub path: PathBuf,
    pub alias: String,
    pub store_password: String,
    pub key_password: String,
}

/// Result of an APK patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkPatchResult {
    pub patched_apk: PathBuf,
    pub patches_applied: Vec<String>,
    pub recompiled: bool,
    pub signed: bool,
    pub aligned: bool,
    pub warnings: Vec<String>,
}

/// High-level APK patcher (orchestrates smali editing + rebuild + sign).
pub struct ApkPatcher {
    config: ApkPatchConfig,
    method_patches: Vec<(String, String, String, Vec<PatchOp>)>,
}

impl ApkPatcher {
    #[must_use] 
    pub const fn new(config: ApkPatchConfig) -> Self {
        Self { config, method_patches: Vec::new() }
    }

    /// Queue a patch for a specific class/method.
    pub fn queue_patch(
        &mut self,
        class_descriptor: impl Into<String>,
        method_name: impl Into<String>,
        method_proto: impl Into<String>,
        ops: Vec<PatchOp>,
    ) {
        self.method_patches.push((
            class_descriptor.into(),
            method_name.into(),
            method_proto.into(),
            ops,
        ));
    }

    /// Simulate the patch application and return what would be done.
    #[must_use] 
    pub fn dry_run(&self) -> Vec<String> {
        self.method_patches
            .iter()
            .map(|(cls, meth, proto, ops)| {
                format!(
                    "patch {}->{}{}: {} op(s)",
                    cls, meth, proto, ops.len()
                )
            })
            .collect()
    }

    /// Apply patches, rebuild DEX, and sign the APK.
    /// This is a stub implementation showing the intended workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn apply(&self) -> PatchResult<ApkPatchResult> {
        let mut warnings = Vec::new();
        let patches_applied = self.dry_run();

        // In a real implementation this would:
        // 1. Unzip the APK
        // 2. Run baksmali on classes.dex
        // 3. Apply patches to .smali files
        // 4. Run smali to recompile to DEX
        // 5. Repack the APK
        // 6. Sign with apksigner/jarsigner
        // 7. Optionally zipalign

        if self.config.smali_jar.is_none() {
            warnings.push("smali_jar not set: skipping actual recompile".into());
        }
        if self.config.keystore.is_none() {
            warnings.push("keystore not set: output will be unsigned".into());
        }

        Ok(ApkPatchResult {
            patched_apk: self.config.output_apk.clone(),
            patches_applied,
            recompiled: self.config.smali_jar.is_some(),
            signed: self.config.keystore.is_some(),
            aligned: self.config.zipalign,
            warnings,
        })
    }
}

// ── Smali file patcher ────────────────────────────────────────────────────────

/// Parse smali text into a list of `SmaliLine` for patching.
#[must_use] 
pub fn parse_method_body(smali_method_text: &str) -> Vec<SmaliLine> {
    smali_method_text
        .lines()
        .filter(|l| !l.trim().starts_with(".method") && !l.trim().starts_with(".end method"))
        .map(|l| SmaliLine::new(l.trim_start()))
        .collect()
}

/// Find all method definitions in a smali file and return their byte ranges.
#[must_use] 
pub fn find_methods_in_smali(smali: &str) -> Vec<(String, usize, usize)> {
    let mut methods = Vec::new();
    let mut start = 0;
    let mut method_name = String::new();
    let mut in_method = false;

    for (i, line) in smali.lines().enumerate() {
        let byte_off = smali
            .lines()
            .take(i)
            .map(|l| l.len() + 1)
            .sum::<usize>();

        if line.trim().starts_with(".method ") {
            in_method = true;
            start = byte_off;
            line.trim().clone_into(&mut method_name);
        } else if line.trim() == ".end method" && in_method {
            let end = byte_off + line.len() + 1;
            methods.push((method_name.clone(), start, end));
            in_method = false;
        }
    }

    methods
}

/// Apply a `MethodPatcher` to a smali file string and return the modified file.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn patch_smali_file(
    smali_content: &str,
    class_descriptor: &str,
    method_name: &str,
    method_proto: &str,
    ops: Vec<PatchOp>,
) -> PatchResult<String> {
    let methods = find_methods_in_smali(smali_content);
    let _target_sig = format!(".method {method_name}{method_proto}");

    for (sig, start, end) in &methods {
        if sig.contains(method_name) && (method_proto.is_empty() || sig.contains(method_proto)) {
            let method_body_text = &smali_content[*start..*end];
            let lines = parse_method_body(method_body_text);
            let mut patcher = MethodPatcher::new(class_descriptor, method_name, method_proto, lines);
            for op in ops {
                patcher.add_op(op);
            }
            let patched_method = patcher.render()?;
            let new_content = format!(
                "{}{}{}",
                &smali_content[..*start],
                patched_method,
                &smali_content[*end..]
            );
            return Ok(new_content);
        }
    }

    Err(PatchError::MethodNotFound {
        class: class_descriptor.to_owned(),
        method: format!("{method_name}{method_proto}"),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_patcher(lines: &[&str]) -> MethodPatcher {
        let body = lines.iter().map(|&l| SmaliLine::new(l)).collect();
        MethodPatcher::new("Lcom/example/Foo;", "isRooted", "()Z", body)
    }

    #[test]
    fn test_force_return_void() {
        let mut p = make_patcher(&[
            ".locals 1",
            "const/4 v0, #1",
            "return v0",
        ]);
        p.force_return_void();
        let result = p.apply().unwrap();
        assert!(result.iter().any(|l| l.text == "return-void"));
    }

    #[test]
    fn test_force_return_const() {
        let mut p = make_patcher(&[
            ".locals 1",
            "const/4 v0, #1",
            "return v0",
        ]);
        p.force_return_const(0);
        let result = p.apply().unwrap();
        assert!(result.iter().any(|l| l.text.contains("const/4") && l.text.contains("#0")));
    }

    #[test]
    fn test_inject_log() {
        let mut p = make_patcher(&[
            ".locals 2",
            "return-void",
        ]);
        p.inject_log("MyTag", "method called");
        let result = p.apply().unwrap();
        assert!(result.iter().any(|l| l.text.contains("Log;")));
    }

    #[test]
    fn test_insert_before() {
        let mut p = make_patcher(&[".locals 0", "return-void"]);
        p.insert_before(1, vec![SmaliLine::new("nop")]);
        let result = p.apply().unwrap();
        assert_eq!(result[1].text, "nop");
        assert_eq!(result[2].text, "return-void");
    }

    #[test]
    fn test_remove_at() {
        let mut p = make_patcher(&[".locals 0", "nop", "return-void"]);
        p.remove_at(1);
        let result = p.apply().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].text, "return-void");
    }

    #[test]
    fn test_render() {
        let p = make_patcher(&[".locals 0", "return-void"]);
        let text = p.render().unwrap();
        assert!(text.contains(".method public isRooted"));
        assert!(text.contains(".end method"));
    }

    #[test]
    fn test_parse_method_body() {
        let smali = ".method public foo()V\n    .locals 0\n    return-void\n.end method\n";
        let lines = parse_method_body(smali);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_find_methods() {
        let smali = ".method public foo()V\n    return-void\n.end method\n\
                     .method public bar()I\n    const/4 v0, #1\n    return v0\n.end method\n";
        let methods = find_methods_in_smali(smali);
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn test_dry_run() {
        let config = ApkPatchConfig {
            input_apk: PathBuf::from("/tmp/in.apk"),
            output_apk: PathBuf::from("/tmp/out.apk"),
            smali_jar: None,
            signer_tool: None,
            keystore: None,
            zipalign: false,
            zipalign_bin: None,
        };
        let mut patcher = ApkPatcher::new(config);
        patcher.queue_patch("Lcom/example/A;", "isRooted", "()Z", vec![PatchOp::ForceReturnVoid]);
        let dry = patcher.dry_run();
        assert_eq!(dry.len(), 1);
        assert!(dry[0].contains("isRooted"));
    }
}
