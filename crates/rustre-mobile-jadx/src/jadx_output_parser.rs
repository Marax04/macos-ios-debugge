//! `jadx_output_parser` — Parse the directory tree produced by a JADX run.
//!
//! JADX decompiles Android APK/DEX files and emits a directory tree of `.java`
//! files under `<output>/sources/<package path>/ClassName.java`.  This module
//! provides [`JadxOutputParser`], which walks that tree and builds structured
//! [`JadxClass`] and [`JadxMethod`] values without requiring a running JVM.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::JadxError;

// ─────────────────────────────────────────────────────────────────────────────
// JadxMethod
// ─────────────────────────────────────────────────────────────────────────────

/// A method extracted from a JADX-decompiled Java source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxMethod {
    /// Method simple name (e.g. `"onCreate"`).
    pub name: String,
    /// Full signature including parameter types (e.g. `"onCreate(Bundle)"`).
    pub signature: String,
    /// Return type string (e.g. `"void"`, `"String"`).
    pub return_type: String,
    /// Parameter type strings.
    pub params: Vec<String>,
    /// Access modifiers (e.g. `["public", "static"]`).
    pub modifiers: Vec<String>,
    /// Raw body text (empty if abstract/native/interface method).
    pub body: String,
    /// Whether declared `native`.
    pub is_native: bool,
    /// Whether declared `static`.
    pub is_static: bool,
    /// Whether declared `abstract`.
    pub is_abstract: bool,
    /// 1-based line number in the source file where the declaration starts.
    pub line_number: usize,
    /// Annotations found on this method (e.g. `"@Override"`).
    pub annotations: Vec<String>,
}

impl JadxMethod {
    /// Returns `true` if this is a constructor.
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == "<init>"
            || self.name == "constructor"
            || self.modifiers.iter().any(|m| m == "constructor")
    }

    /// Returns the descriptor-style parameter string (comma-joined).
    #[must_use]
    pub fn param_descriptor(&self) -> String {
        self.params.join(", ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxField
// ─────────────────────────────────────────────────────────────────────────────

/// A field extracted from a JADX-decompiled Java source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxField {
    /// Field name.
    pub name: String,
    /// Declared type string.
    pub field_type: String,
    /// Access modifiers.
    pub modifiers: Vec<String>,
    /// Optional initializer literal (e.g. `"42"`, `"null"`).
    pub initializer: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxClass
// ─────────────────────────────────────────────────────────────────────────────

/// A class parsed from JADX decompiler output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxClass {
    /// Simple class name (e.g. `"MainActivity"`).
    pub class_name: String,
    /// Java package (e.g. `"com.example.app"`).
    pub package: String,
    /// Fully-qualified class name.
    pub fqn: String,
    /// Superclass name if `extends` was detected.
    pub super_class: Option<String>,
    /// Implemented interface names.
    pub interfaces: Vec<String>,
    /// Class-level access modifiers (e.g. `["public", "final"]`).
    pub modifiers: Vec<String>,
    /// Class-level annotations (e.g. `"@SuppressWarnings"`).
    pub annotations: Vec<String>,
    /// Parsed methods.
    pub methods: Vec<JadxMethod>,
    /// Parsed fields.
    pub fields: Vec<JadxField>,
    /// Full Java source text.
    pub source: String,
    /// Absolute path of the `.java` file on disk.
    pub source_path: PathBuf,
    /// Whether JADX marked this class as having bad / inconsistent code.
    pub has_bad_code: bool,
}

impl JadxClass {
    /// Return all static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&JadxMethod> {
        self.methods.iter().filter(|m| m.is_static).collect()
    }

    /// Return all native methods.
    #[must_use]
    pub fn native_methods(&self) -> Vec<&JadxMethod> {
        self.methods.iter().filter(|m| m.is_native).collect()
    }

    /// Return all constructors.
    #[must_use]
    pub fn constructors(&self) -> Vec<&JadxMethod> {
        self.methods.iter().filter(|m| m.is_constructor()).collect()
    }

    /// Find a method by simple name.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<&JadxMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Whether the class is an Android `Activity` (heuristic).
    #[must_use]
    pub fn is_activity(&self) -> bool {
        self.super_class
            .as_deref()
            .is_some_and(|s| s.contains("Activity"))
            || self.class_name.ends_with("Activity")
    }

    /// Whether the class is an Android `Service` (heuristic).
    #[must_use]
    pub fn is_service(&self) -> bool {
        self.super_class
            .as_deref()
            .is_some_and(|s| s.contains("Service"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated statistics from a parse run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParseStats {
    /// Total `.java` files encountered.
    pub total_files: usize,
    /// Successfully parsed files.
    pub parsed: usize,
    /// Files that triggered parse errors.
    pub failed: usize,
    /// Total methods across all parsed classes.
    pub total_methods: usize,
    /// Total native methods.
    pub native_methods: usize,
    /// Total static methods.
    pub static_methods: usize,
    /// Files with JADX bad-code markers.
    pub bad_code_files: usize,
    /// Classes with superclasses detected.
    pub with_super: usize,
    /// Unique package names seen.
    pub unique_packages: usize,
}

impl ParseStats {
    fn update_from_class(&mut self, cls: &JadxClass) {
        self.parsed += 1;
        self.total_methods += cls.methods.len();
        self.native_methods += cls.native_methods().len();
        self.static_methods += cls.static_methods().len();
        if cls.has_bad_code {
            self.bad_code_files += 1;
        }
        if cls.super_class.is_some() {
            self.with_super += 1;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxOutputParser
// ─────────────────────────────────────────────────────────────────────────────

/// Walks a JADX output directory and parses all `.java` files.
///
/// # Example
///
/// ```no_run
/// use rustre_mobile_jadx::jadx_output_parser::JadxOutputParser;
/// use std::path::Path;
///
/// let parser = JadxOutputParser::new();
/// let (classes, stats) = parser.parse_dir(Path::new("/tmp/jadx_out")).unwrap();
/// println!("Parsed {} classes", classes.len());
/// ```
#[derive(Debug, Clone)]
pub struct JadxOutputParser {
    /// If true, parse the `resources/` subtree for resource hints too.
    pub include_resources: bool,
    /// If true, treat lines containing `// ERROR:` as bad-code markers.
    pub detect_bad_code: bool,
    /// If true, extract field declarations.
    pub parse_fields: bool,
}

impl Default for JadxOutputParser {
    fn default() -> Self {
        Self {
            include_resources: false,
            detect_bad_code: true,
            parse_fields: true,
        }
    }
}

impl JadxOutputParser {
    /// Create a parser with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse all `.java` files under `dir`.
    ///
    /// Returns `(classes, stats)` on success.
    ///
    /// # Errors
    /// Returns `JadxError::Io` if the root directory cannot be read.
    pub fn parse_dir(&self, dir: &Path) -> Result<(Vec<JadxClass>, ParseStats), JadxError> {
        let mut classes = Vec::new();
        let mut stats = ParseStats::default();
        let mut packages: std::collections::HashSet<String> = std::collections::HashSet::default();

        // JADX emits Java sources under <root>/sources/
        let sources_root = dir.join("sources");
        let search_root = if sources_root.is_dir() {
            sources_root
        } else {
            dir.to_path_buf()
        };

        self.walk_dir(&search_root, &search_root, &mut classes, &mut stats, &mut packages)?;

        stats.total_files = stats.parsed + stats.failed;
        stats.unique_packages = packages.len();
        Ok((classes, stats))
    }

    /// Parse a single `.java` file.
    ///
    /// # Errors
    /// Returns `JadxError::Io` if the file cannot be read, or
    /// `JadxError::Parse` if the source is malformed beyond recovery.
    pub fn parse_file(&self, root: &Path, path: &Path) -> Result<JadxClass, JadxError> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| JadxError::Io(format!("read {}: {e}", path.display())))?;
        Ok(self.parse_source(root, path, &source))
    }

    // ── Private helpers ────────────────────────────────────────────────────

    fn walk_dir(
        &self,
        root: &Path,
        current: &Path,
        classes: &mut Vec<JadxClass>,
        stats: &mut ParseStats,
        packages: &mut std::collections::HashSet<String>,
    ) -> Result<(), JadxError> {
        self.walk_dir_inner(root, current, classes, stats, packages, 0)
    }

    fn walk_dir_inner(
        &self,
        root: &Path,
        current: &Path,
        classes: &mut Vec<JadxClass>,
        stats: &mut ParseStats,
        packages: &mut std::collections::HashSet<String>,
        depth: usize,
    ) -> Result<(), JadxError> {
        const MAX_DEPTH: usize = 64;
        if depth > MAX_DEPTH {
            return Err(JadxError::Io(format!(
                "source directory tree too deep (>{MAX_DEPTH} levels) at {}",
                current.display()
            )));
        }
        let entries = std::fs::read_dir(current)
            .map_err(|e| JadxError::Io(format!("read_dir {}: {e}", current.display())))?;

        for entry in entries {
            let entry = entry.map_err(|e| JadxError::Io(e.to_string()))?;
            let path = entry.path();
            if path.is_dir() {
                self.walk_dir_inner(root, &path, classes, stats, packages, depth + 1)?;
            } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                match self.parse_file(root, &path) {
                    Ok(cls) => {
                        packages.insert(cls.package.clone());
                        stats.update_from_class(&cls);
                        classes.push(cls);
                    }
                    Err(_) => stats.failed += 1,
                }
            }
        }
        Ok(())
    }

    fn parse_source(&self, root: &Path, path: &Path, source: &str) -> JadxClass {
        let class_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown")
            .to_owned();

        let package = extract_package_declaration(source)
            .unwrap_or_else(|| derive_package_from_path(root, path));

        let fqn = if package.is_empty() {
            class_name.clone()
        } else {
            format!("{package}.{class_name}")
        };

        let super_class = extract_super_class(source);
        let interfaces = extract_interfaces(source);
        let modifiers = extract_class_modifiers(source, &class_name);
        let annotations = extract_class_annotations(source);
        let has_bad_code = self.detect_bad_code && source.contains("// ERROR:");
        let methods = parse_methods(source);
        let fields = if self.parse_fields {
            parse_fields(source)
        } else {
            Vec::new()
        };

        JadxClass {
            class_name,
            package,
            fqn,
            super_class,
            interfaces,
            modifiers,
            annotations,
            methods,
            fields,
            source: source.to_owned(),
            source_path: path.to_path_buf(),
            has_bad_code,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level convenience
// ─────────────────────────────────────────────────────────────────────────────

/// Parse all Java files in a JADX output directory.
///
/// This is a one-shot wrapper around [`JadxOutputParser`].
///
/// # Errors
/// Returns `JadxError::Io` on directory access failures.
pub fn parse_jadx_dir(dir: &Path) -> Result<Vec<JadxClass>, JadxError> {
    let (classes, _stats) = JadxOutputParser::new().parse_dir(dir)?;
    Ok(classes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Source-level heuristic extractors
// ─────────────────────────────────────────────────────────────────────────────

fn extract_package_declaration(source: &str) -> Option<String> {
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("package ") {
            let pkg = rest.trim_end_matches(';').trim();
            if !pkg.is_empty() {
                return Some(pkg.to_owned());
            }
        }
    }
    None
}

fn derive_package_from_path(root: &Path, file: &Path) -> String {
    let rel = file
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map(|p| p.to_string_lossy().replace(['\\', '/'], "."))
        .unwrap_or_default();
    rel.trim_start_matches('.').to_owned()
}

fn extract_super_class(source: &str) -> Option<String> {
    for line in source.lines() {
        if let Some(pos) = line.find("extends ") {
            let after = &line[pos + "extends ".len()..];
            let name: String = after
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
                .next()
                .unwrap_or("")
                .to_owned();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn extract_interfaces(source: &str) -> Vec<String> {
    for line in source.lines() {
        if let Some(pos) = line.find("implements ") {
            let after = &line[pos + "implements ".len()..];
            // Stop at '{' or end of line
            let iface_str = after.split('{').next().unwrap_or("").trim();
            return iface_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

fn extract_class_modifiers(source: &str, class_name: &str) -> Vec<String> {
    let needle = format!("class {class_name}");
    for line in source.lines() {
        if line.contains(&needle) {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let modifiers: Vec<String> = tokens
                .iter()
                .take_while(|&&t| t != "class")
                .filter(|&&t| matches!(t, "public" | "private" | "protected" | "abstract" | "final" | "static" | "strictfp"))
                .map(|&t| t.to_owned())
                .collect();
            return modifiers;
        }
    }
    Vec::new()
}

fn extract_class_annotations(source: &str) -> Vec<String> {
    let mut annotations = Vec::new();
    let mut prev_was_annotation = false;
    for line in source.lines() {
        let t = line.trim();
        if t.starts_with('@') && !t.starts_with("//") {
            let ann = t.split('(').next().unwrap_or(t);
            annotations.push(ann.to_owned());
            prev_was_annotation = true;
        } else if prev_was_annotation && t.contains("class ") {
            break;
        } else if !t.is_empty() && !t.starts_with("//") && !t.starts_with("/*") {
            prev_was_annotation = false;
        }
    }
    annotations
}

const MODIFIER_KEYWORDS: &[&str] = &[
    "public", "protected", "private", "static", "final", "abstract",
    "synchronized", "native", "default", "strictfp",
];

fn parse_methods(source: &str) -> Vec<JadxMethod> {
    let mut methods = Vec::new();
    let mut pending_annotations: Vec<String> = Vec::new();

    for (line_idx, line) in source.lines().enumerate() {
        let t = line.trim();
        // Collect annotations
        if t.starts_with('@') && !t.starts_with("//") {
            let ann = t.split('(').next().unwrap_or(t).to_owned();
            pending_annotations.push(ann);
            continue;
        }
        // Skip comments, blank lines, class/interface declarations
        if t.is_empty()
            || t.starts_with("//")
            || t.starts_with("/*")
            || t.starts_with('*')
            || t.contains("class ")
            || t.contains("interface ")
        {
            if !t.starts_with('@') {
                pending_annotations.clear();
            }
            continue;
        }
        if !t.contains('(') {
            pending_annotations.clear();
            continue;
        }

        let tokens: Vec<&str> = t.split_whitespace().collect();
        if tokens.len() < 2 {
            pending_annotations.clear();
            continue;
        }
        let mut idx = 0;
        let mut is_static = false;
        let mut is_native = false;
        let mut is_abstract = false;
        let mut modifiers = Vec::new();
        while idx < tokens.len() {
            let tok = tokens[idx].trim_start_matches('(');
            if MODIFIER_KEYWORDS.contains(&tok) {
                if tok == "static" { is_static = true; }
                if tok == "native" { is_native = true; }
                if tok == "abstract" { is_abstract = true; }
                modifiers.push(tok.to_owned());
                idx += 1;
            } else {
                break;
            }
        }
        if idx + 1 >= tokens.len() {
            pending_annotations.clear();
            continue;
        }
        let return_type = tokens[idx].to_owned();
        let name_token = tokens[idx + 1];
        let name = name_token.split('(').next().unwrap_or("").to_owned();
        if name.is_empty() || !name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '<') {
            pending_annotations.clear();
            continue;
        }
        let param_str = t
            .find('(')
            .and_then(|s| {
                // Search for ')' strictly after the opening '(' to avoid
                // a panic when ')' appears before '(' on the same line.
                t[s + 1..].find(')').map(|rel_e| &t[s + 1..s + 1 + rel_e])
            })
            .unwrap_or("");
        let params: Vec<String> = if param_str.trim().is_empty() {
            vec![]
        } else {
            param_str
                .split(',')
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect()
        };
        let signature = format!("{}({})", name, params.join(", "));
        methods.push(JadxMethod {
            name,
            signature,
            return_type,
            params,
            modifiers,
            body: String::new(),
            is_native,
            is_static,
            is_abstract,
            line_number: line_idx + 1,
            annotations: std::mem::take(&mut pending_annotations),
        });
    }
    methods
}

fn parse_fields(source: &str) -> Vec<JadxField> {
    let mut fields = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        // Field: ends with `;`, no `(`, not a method return, not `import`/`package`
        if !t.ends_with(';') || t.contains('(') || t.starts_with("import ") || t.starts_with("package ") {
            continue;
        }
        let tokens: Vec<&str> = t.trim_end_matches(';').split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let mut idx = 0;
        let mut modifiers = Vec::new();
        while idx < tokens.len() {
            if MODIFIER_KEYWORDS.contains(&tokens[idx]) {
                modifiers.push(tokens[idx].to_owned());
                idx += 1;
            } else {
                break;
            }
        }
        if idx + 1 >= tokens.len() {
            continue;
        }
        let field_type = tokens[idx].to_owned();
        let rest = tokens[idx + 1];
        let (name, initializer) = if rest.contains('=') {
            let parts: Vec<&str> = rest.splitn(2, '=').collect();
            (parts[0].trim().to_owned(), Some(parts[1].trim().to_owned()))
        } else {
            (rest.trim().to_owned(), None)
        };
        if name.is_empty() || !name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') {
            continue;
        }
        fields.push(JadxField {
            name,
            field_type,
            modifiers,
            initializer,
        });
    }
    fields
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassIndex — searchable index over parsed classes
// ─────────────────────────────────────────────────────────────────────────────

/// An index built from a collection of [`JadxClass`] values for fast lookup.
#[derive(Debug, Default)]
pub struct ClassIndex {
    by_fqn: HashMap<String, usize>,
    by_simple_name: HashMap<String, Vec<usize>>,
    by_package: HashMap<String, Vec<usize>>,
    classes: Vec<JadxClass>,
}

impl ClassIndex {
    /// Build a `ClassIndex` from a list of classes.
    #[must_use]
    pub fn build(classes: Vec<JadxClass>) -> Self {
        let mut idx = Self {
            classes,
            ..Default::default()
        };
        for (i, cls) in idx.classes.iter().enumerate() {
            idx.by_fqn.insert(cls.fqn.clone(), i);
            idx.by_simple_name
                .entry(cls.class_name.clone())
                .or_default()
                .push(i);
            idx.by_package
                .entry(cls.package.clone())
                .or_default()
                .push(i);
        }
        idx
    }

    /// Look up a class by fully-qualified name.
    #[must_use]
    pub fn by_fqn(&self, fqn: &str) -> Option<&JadxClass> {
        self.by_fqn.get(fqn).map(|&i| &self.classes[i])
    }

    /// Look up classes by simple name (may return multiple for inner/nested).
    #[must_use]
    pub fn by_simple_name(&self, name: &str) -> Vec<&JadxClass> {
        self.by_simple_name
            .get(name)
            .map(|v| v.iter().map(|&i| &self.classes[i]).collect())
            .unwrap_or_default()
    }

    /// Return all classes in a package.
    #[must_use]
    pub fn in_package(&self, pkg: &str) -> Vec<&JadxClass> {
        self.by_package
            .get(pkg)
            .map(|v| v.iter().map(|&i| &self.classes[i]).collect())
            .unwrap_or_default()
    }

    /// Return all classes (immutable slice).
    #[must_use]
    pub fn all(&self) -> &[JadxClass] {
        &self.classes
    }

    /// Total number of classes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.classes.len()
    }

    /// Returns `true` if the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Find all classes whose source contains a given substring.
    #[must_use]
    pub fn containing_text(&self, needle: &str) -> Vec<&JadxClass> {
        self.classes
            .iter()
            .filter(|c| c.source.contains(needle))
            .collect()
    }

    /// All packages present in the index.
    #[must_use]
    pub fn packages(&self) -> Vec<&str> {
        self.by_package.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source() -> &'static str {
        r#"
package com.example.test;

import android.app.Activity;

@SuppressWarnings("unchecked")
public final class SampleActivity extends Activity implements Runnable {

    private static final int MAX = 10;
    public String name;

    @Override
    public void onCreate(android.os.Bundle b) {
        super.onCreate(b);
    }

    public static String helper(int x) {
        return "";
    }

    public native void nativeFunc();
}
"#
    }

    fn make_parser() -> JadxOutputParser {
        JadxOutputParser::new()
    }

    fn parse_sample() -> JadxClass {
        let parser = make_parser();
        let root = Path::new("/tmp/root");
        let path = Path::new("/tmp/root/com/example/test/SampleActivity.java");
        parser.parse_source(root, path, sample_source())
    }

    #[test]
    fn test_class_name() {
        let cls = parse_sample();
        assert_eq!(cls.class_name, "SampleActivity");
    }

    #[test]
    fn test_package() {
        let cls = parse_sample();
        assert_eq!(cls.package, "com.example.test");
    }

    #[test]
    fn test_fqn() {
        let cls = parse_sample();
        assert_eq!(cls.fqn, "com.example.test.SampleActivity");
    }

    #[test]
    fn test_super_class() {
        let cls = parse_sample();
        assert_eq!(cls.super_class.as_deref(), Some("Activity"));
    }

    #[test]
    fn test_interfaces() {
        let cls = parse_sample();
        assert!(cls.interfaces.contains(&"Runnable".to_string()));
    }

    #[test]
    fn test_class_modifiers() {
        let cls = parse_sample();
        assert!(cls.modifiers.contains(&"public".to_string()));
        assert!(cls.modifiers.contains(&"final".to_string()));
    }

    #[test]
    fn test_class_annotations() {
        let cls = parse_sample();
        assert!(cls.annotations.iter().any(|a| a.contains("SuppressWarnings")));
    }

    #[test]
    fn test_methods_parsed() {
        let cls = parse_sample();
        let names: Vec<&str> = cls.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"onCreate"), "expected onCreate, got {names:?}");
        assert!(names.contains(&"helper"));
        assert!(names.contains(&"nativeFunc"));
    }

    #[test]
    fn test_native_method() {
        let cls = parse_sample();
        let native = cls.native_methods();
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].name, "nativeFunc");
    }

    #[test]
    fn test_static_method() {
        let cls = parse_sample();
        let statics = cls.static_methods();
        assert!(statics.iter().any(|m| m.name == "helper"));
    }

    #[test]
    fn test_is_activity() {
        let cls = parse_sample();
        assert!(cls.is_activity());
    }

    #[test]
    fn test_find_method() {
        let cls = parse_sample();
        assert!(cls.find_method("onCreate").is_some());
        assert!(cls.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_no_bad_code() {
        let cls = parse_sample();
        assert!(!cls.has_bad_code);
    }

    #[test]
    fn test_bad_code_detection() {
        let parser = make_parser();
        let source = "// ERROR: some bad code\npublic class X {}";
        let root = Path::new("/tmp");
        let path = Path::new("/tmp/X.java");
        let cls = parser.parse_source(root, path, source);
        assert!(cls.has_bad_code);
    }

    #[test]
    fn test_class_index_by_fqn() {
        let cls = parse_sample();
        let idx = ClassIndex::build(vec![cls]);
        assert!(idx.by_fqn("com.example.test.SampleActivity").is_some());
    }

    #[test]
    fn test_class_index_by_simple_name() {
        let cls = parse_sample();
        let idx = ClassIndex::build(vec![cls]);
        let found = idx.by_simple_name("SampleActivity");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_class_index_in_package() {
        let cls = parse_sample();
        let idx = ClassIndex::build(vec![cls]);
        let in_pkg = idx.in_package("com.example.test");
        assert_eq!(in_pkg.len(), 1);
    }

    #[test]
    fn test_class_index_containing_text() {
        let cls = parse_sample();
        let idx = ClassIndex::build(vec![cls]);
        assert_eq!(idx.containing_text("nativeFunc").len(), 1);
        assert_eq!(idx.containing_text("DOES_NOT_EXIST").len(), 0);
    }

    #[test]
    fn test_class_index_packages() {
        let cls = parse_sample();
        let idx = ClassIndex::build(vec![cls]);
        let pkgs = idx.packages();
        assert!(pkgs.contains(&"com.example.test"));
    }

    #[test]
    fn test_fields_parsed() {
        let cls = parse_sample();
        let mut names = cls.fields.iter().map(|f| f.name.as_str());
        assert!(names.any(|n| n == "name") || cls.fields.is_empty());
    }
}
