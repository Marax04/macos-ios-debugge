//! `c_annotation` — annotation system for decompiled C pseudocode.
//!
//! Supports three kinds of annotations that are injected into the emitted
//! C source:
//!
//! 1. **Data-type hints**: force a variable or expression to a specific C type.
//! 2. **Function signature annotations**: override the inferred signature with
//!    a user-provided one.
//! 3. **Custom inline annotations**: arbitrary text comments placed at a
//!    specific line or at a named site.
//!
//! Annotations are stored separately from the AST and applied as a final
//! pass over the emitted source text.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Annotation types
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies where an annotation is anchored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotationSite {
    /// 1-based line number in the emitted source.
    Line(usize),
    /// Variable name — annotation applies wherever the variable is declared.
    Variable(String),
    /// Function name — annotation applies to the function signature.
    Function(String),
    /// A named bookmark (e.g. set by the user via a UI).
    Named(String),
}

/// A single annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub site: AnnotationSite,
    pub kind: AnnotationKind,
    /// Whether the annotation is active (can be disabled without deleting).
    pub enabled: bool,
    /// Optional author tag.
    pub author: Option<String>,
    /// Optional timestamp (Unix seconds).
    pub timestamp: Option<u64>,
}

impl Annotation {
    #[must_use]
    pub const fn new(site: AnnotationSite, kind: AnnotationKind) -> Self {
        Self {
            site,
            kind,
            enabled: true,
            author: None,
            timestamp: None,
        }
    }

    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// The content of an annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationKind {
    /// Override the type of a variable/expression.
    TypeHint { new_type: String },
    /// Replace the inferred function signature.
    SignatureOverride { signature: String },
    /// Rename a variable or function.
    Rename { new_name: String },
    /// A free-form comment placed at the site.
    Comment { text: String, placement: CommentPlacement },
    /// Mark the site as a known function call.
    KnownCall { func_name: String, description: String },
    /// Propagate a colour tag (for UI highlighting — stored in output as `#pragma` comment).
    ColorTag { color: String, label: String },
    /// Mark as a potential vulnerability.
    VulnerabilityHint { cve: Option<String>, description: String },
}

/// Where to place a comment annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentPlacement {
    /// Before the annotated line.
    Before,
    /// At end of the annotated line.
    EndOfLine,
    /// After the annotated line.
    After,
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationStore
// ─────────────────────────────────────────────────────────────────────────────

/// Stores all annotations for one function.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnnotationStore {
    /// Indexed by site for fast lookup.
    annotations: Vec<Annotation>,
    /// Quick index: variable name → annotation indices.
    var_index: HashMap<String, Vec<usize>>,
    /// Quick index: function name → annotation indices.
    func_index: HashMap<String, Vec<usize>>,
}

impl AnnotationStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation. Returns its index.
    pub fn add(&mut self, ann: Annotation) -> usize {
        let idx = self.annotations.len();

        // Update indices.
        match &ann.site {
            AnnotationSite::Variable(v) => {
                self.var_index.entry(v.clone()).or_default().push(idx);
            }
            AnnotationSite::Function(f) => {
                self.func_index.entry(f.clone()).or_default().push(idx);
            }
            _ => {}
        }

        self.annotations.push(ann);
        idx
    }

    /// Get all enabled annotations for a given site.
    #[must_use]
    pub fn get_for_site(&self, site: &AnnotationSite) -> Vec<&Annotation> {
        self.annotations
            .iter()
            .filter(|a| a.enabled && &a.site == site)
            .collect()
    }

    /// Get all enabled annotations for a line number.
    #[must_use]
    pub fn get_for_line(&self, line: usize) -> Vec<&Annotation> {
        self.get_for_site(&AnnotationSite::Line(line))
    }

    /// Get all annotations for a variable name.
    #[must_use]
    pub fn get_for_variable(&self, name: &str) -> Vec<&Annotation> {
        self.get_for_site(&AnnotationSite::Variable(name.to_string()))
    }

    /// Get all annotations for a function.
    #[must_use]
    pub fn get_for_function(&self, name: &str) -> Vec<&Annotation> {
        self.get_for_site(&AnnotationSite::Function(name.to_string()))
    }

    /// Total annotations (including disabled).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.annotations.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Disable an annotation by index.
    pub fn disable(&mut self, idx: usize) {
        if let Some(a) = self.annotations.get_mut(idx) {
            a.enabled = false;
        }
    }

    /// Enable an annotation by index.
    pub fn enable(&mut self, idx: usize) {
        if let Some(a) = self.annotations.get_mut(idx) {
            a.enabled = true;
        }
    }

    /// Merge another store into this one.
    pub fn merge(&mut self, other: Self) {
        for ann in other.annotations {
            self.add(ann);
        }
    }

    /// Find the type hint for a variable, if any.
    #[must_use]
    pub fn type_hint_for(&self, var: &str) -> Option<&str> {
        for ann in self.get_for_variable(var) {
            if let AnnotationKind::TypeHint { ref new_type } = ann.kind {
                return Some(new_type.as_str());
            }
        }
        None
    }

    /// Find the rename for a variable, if any.
    #[must_use]
    pub fn rename_for(&self, var: &str) -> Option<&str> {
        for ann in self.get_for_variable(var) {
            if let AnnotationKind::Rename { ref new_name } = ann.kind {
                return Some(new_name.as_str());
            }
        }
        None
    }

    /// Find the signature override for a function, if any.
    #[must_use]
    pub fn signature_override_for(&self, func: &str) -> Option<&str> {
        for ann in self.get_for_function(func) {
            if let AnnotationKind::SignatureOverride { ref signature } = ann.kind {
                return Some(signature.as_str());
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationApplier
// ─────────────────────────────────────────────────────────────────────────────

/// Applies annotations from an [`AnnotationStore`] to source text.
pub struct AnnotationApplier<'a> {
    store: &'a AnnotationStore,
}

impl<'a> AnnotationApplier<'a> {
    #[must_use]
    pub const fn new(store: &'a AnnotationStore) -> Self {
        Self { store }
    }

    /// Apply all applicable annotations to the source, returning the annotated text.
    pub fn apply(&self, source: &str) -> String {
        let mut lines: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();

        // ── Apply line-based comment annotations ──────────────────────────
        // Collect before/after/eol comments keyed by line.
        let mut before_comments: HashMap<usize, Vec<String>> = HashMap::new();
        let mut after_comments: HashMap<usize, Vec<String>> = HashMap::new();
        let mut eol_comments: HashMap<usize, Vec<String>> = HashMap::new();

        for ann in &self.store.annotations {
            if !ann.enabled {
                continue;
            }
            if let AnnotationSite::Line(lineno) = ann.site {
                let lineno_0 = lineno.saturating_sub(1); // 0-based for vector
                let _ = lineno_0;
                match &ann.kind {
                    AnnotationKind::Comment { text, placement } => {
                        match placement {
                            CommentPlacement::Before => {
                                before_comments.entry(lineno).or_default().push(text.clone());
                            }
                            CommentPlacement::After => {
                                after_comments.entry(lineno).or_default().push(text.clone());
                            }
                            CommentPlacement::EndOfLine => {
                                eol_comments.entry(lineno).or_default().push(text.clone());
                            }
                        }
                    }
                    AnnotationKind::VulnerabilityHint { cve, description } => {
                        let cve_str = cve.as_deref().map(|c| format!(" [{c}]")).unwrap_or_default();
                        before_comments.entry(lineno).or_default()
                            .push(format!("VULNERABILITY{cve_str}: {description}"));
                    }
                    AnnotationKind::ColorTag { label, color } => {
                        eol_comments.entry(lineno).or_default()
                            .push(format!("#tag:{color}:{label}"));
                    }
                    _ => {}
                }
            }
        }

        // ── Apply variable renames ─────────────────────────────────────────
        // Collect all rename annotations.
        let mut renames: Vec<(String, String)> = Vec::new();
        for ann in &self.store.annotations {
            if !ann.enabled { continue; }
            if let AnnotationKind::Rename { ref new_name } = ann.kind
                && let AnnotationSite::Variable(ref old_name) = ann.site {
                    renames.push((old_name.clone(), new_name.clone()));
                }
        }

        // Apply renames to all lines.
        if !renames.is_empty() {
            for line in &mut lines {
                for (old, new) in &renames {
                    *line = rename_identifier(line, old, new);
                }
            }
        }

        // ── Apply type hints to variable declarations ──────────────────────
        for ann in &self.store.annotations {
            if !ann.enabled { continue; }
            if let AnnotationKind::TypeHint { ref new_type } = ann.kind
                && let AnnotationSite::Variable(ref var_name) = ann.site {
                    // Find and patch the declaration line.
                    for line in &mut lines {
                        if let Some(new_line) = patch_var_type(line, var_name, new_type) {
                            *line = new_line;
                        }
                    }
                }
        }

        // ── Apply signature overrides ─────────────────────────────────────
        for ann in &self.store.annotations {
            if !ann.enabled { continue; }
            if let AnnotationKind::SignatureOverride { ref signature } = ann.kind
                && let AnnotationSite::Function(ref func_name) = ann.site {
                    // Replace the first line that contains `func_name(`.
                    for line in &mut lines {
                        if line.contains(&format!("{func_name}("))
                            && !line.trim().starts_with("//")
                            && !line.trim().starts_with("/*")
                        {
                            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                            *line = format!("{indent}{signature}");
                            break;
                        }
                    }
                }
        }

        // ── Reconstruct with before/after/eol comments ────────────────────
        let mut out: Vec<String> = Vec::with_capacity(lines.len() + before_comments.len() + after_comments.len());

        for (i, line) in lines.iter().enumerate() {
            let lineno = i + 1;

            // Before comments.
            if let Some(comments) = before_comments.get(&lineno) {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                for c in comments {
                    out.push(format!("{indent}/* {c} */"));
                }
            }

            // EOL comments.
            if let Some(comments) = eol_comments.get(&lineno) {
                let joined = comments.join("; ");
                out.push(format!("{line} /* {joined} */"));
            } else {
                out.push(line.clone());
            }

            // After comments.
            if let Some(comments) = after_comments.get(&lineno) {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                for c in comments {
                    out.push(format!("{indent}/* {c} */"));
                }
            }
        }

        out.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Replace all whole-word occurrences of `old` with `new` in `source`.
fn rename_identifier(source: &str, old: &str, new_name: &str) -> String {
    let mut result = String::new();
    let mut remaining = source;

    loop {
        if let Some(pos) = remaining.find(old) {
            let before_ok = pos == 0
                || remaining[..pos]
                    .chars()
                    .last()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_');
            let after_pos = pos + old.len();
            let after_ok = after_pos >= remaining.len()
                || remaining[after_pos..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_');

            if before_ok && after_ok {
                result.push_str(&remaining[..pos]);
                result.push_str(new_name);
                remaining = &remaining[after_pos..];
            } else {
                result.push_str(&remaining[..=pos]);
                remaining = &remaining[pos + 1..];
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }

    result
}

/// Patch the type of a variable declaration line.
/// E.g. `int var1 = 0;` with type hint `uint32_t` → `uint32_t var1 = 0;`
fn patch_var_type(line: &str, var_name: &str, new_type: &str) -> Option<String> {
    let t = line.trim();
    // Check if this looks like a declaration containing `var_name`.
    if !t.contains(var_name) {
        return None;
    }
    if !t.ends_with(';') {
        return None;
    }

    // Simple pattern: `old_type var_name ...;`
    // Find the position of `var_name` as whole word.
    let pos = t.find(var_name)?;
    let before_ok = pos == 0
        || t[..pos].chars().last().is_none_or(|c| !c.is_alphanumeric() && c != '_');
    let after_ok = pos + var_name.len() >= t.len()
        || t[pos + var_name.len()..].chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');

    if !before_ok || !after_ok {
        return None;
    }

    // The type is everything before `var_name`, stripped of pointers.
    let old_type_region = t[..pos].trim();
    if old_type_region.is_empty() {
        return None;
    }

    // Build the new line.
    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let rest = &t[pos..]; // `var_name ...;`
    Some(format!("{indent}{new_type} {rest}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationSerializer — JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

/// Serialise/deserialise annotation stores to/from JSON.
pub struct AnnotationSerializer;

impl AnnotationSerializer {
    /// Serialise an annotation store to a JSON string.
    ///
    /// # Errors
    /// Returns `Err` if serialisation fails.
    pub fn to_json(store: &AnnotationStore) -> Result<String, String> {
        serde_json::to_string_pretty(store).map_err(|e| e.to_string())
    }

    /// Deserialise an annotation store from a JSON string.
    ///
    /// # Errors
    /// Returns `Err` if deserialisation fails.
    pub fn from_json(json: &str) -> Result<AnnotationStore, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnnotationMerger — merge stores from multiple sources
// ─────────────────────────────────────────────────────────────────────────────

/// Merges annotation stores from multiple sources (e.g. multiple analysts).
pub struct AnnotationMerger;

impl AnnotationMerger {
    /// Merge all stores into a new combined store.
    #[must_use]
    pub fn merge(stores: Vec<AnnotationStore>) -> AnnotationStore {
        let mut combined = AnnotationStore::new();
        for store in stores {
            combined.merge(store);
        }
        combined
    }

    /// Merge two stores, keeping both sets of annotations and deduplicating
    /// exact duplicates (same site + same type hint text).
    #[must_use]
    pub fn merge_dedup(a: AnnotationStore, b: AnnotationStore) -> AnnotationStore {
        let mut combined = a;
        'outer: for ann in b.annotations {
            // Check for duplicates.
            for existing in &combined.annotations {
                if existing.site == ann.site {
                    // Compare kind by discriminant.
                    if kind_equivalent(&existing.kind, &ann.kind) {
                        continue 'outer;
                    }
                }
            }
            combined.add(ann);
        }
        combined
    }
}

fn kind_equivalent(a: &AnnotationKind, b: &AnnotationKind) -> bool {
    match (a, b) {
        (AnnotationKind::TypeHint { new_type: t1 }, AnnotationKind::TypeHint { new_type: t2 }) => t1 == t2,
        (AnnotationKind::Rename { new_name: n1 }, AnnotationKind::Rename { new_name: n2 }) => n1 == n2,
        (AnnotationKind::Comment { text: t1, placement: p1 }, AnnotationKind::Comment { text: t2, placement: p2 }) => t1 == t2 && p1 == p2,
        (AnnotationKind::SignatureOverride { signature: s1 }, AnnotationKind::SignatureOverride { signature: s2 }) => s1 == s2,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in annotation presets
// ─────────────────────────────────────────────────────────────────────────────

/// Provides factory methods for common annotation patterns.
pub struct AnnotationPresets;

impl AnnotationPresets {
    /// Annotate a call site as a format-string vulnerability.
    #[must_use]
    pub fn format_string_vuln(line: usize) -> Annotation {
        Annotation::new(
            AnnotationSite::Line(line),
            AnnotationKind::VulnerabilityHint {
                cve: None,
                description: "Format-string vulnerability — user-controlled format arg".to_string(),
            },
        )
    }

    /// Annotate a buffer copy as an unchecked overflow.
    #[must_use]
    pub fn buffer_overflow(line: usize, func_name: &str) -> Annotation {
        Annotation::new(
            AnnotationSite::Line(line),
            AnnotationKind::VulnerabilityHint {
                cve: None,
                description: format!("{func_name}: no bounds check — possible buffer overflow"),
            },
        )
    }

    /// Rename `var1` to `buffer_size` with a type hint.
    #[must_use]
    pub fn typed_var(var: &str, new_name: &str, ty: &str) -> Vec<Annotation> {
        vec![
            Annotation::new(
                AnnotationSite::Variable(var.to_string()),
                AnnotationKind::Rename { new_name: new_name.to_string() },
            ),
            Annotation::new(
                AnnotationSite::Variable(var.to_string()),
                AnnotationKind::TypeHint { new_type: ty.to_string() },
            ),
        ]
    }

    /// Mark a function as a known API wrapper.
    #[must_use]
    pub fn known_wrapper(func: &str, real_name: &str, description: &str) -> Annotation {
        Annotation::new(
            AnnotationSite::Function(func.to_string()),
            AnnotationKind::Comment {
                text: format!("Wrapper for {real_name}: {description}"),
                placement: CommentPlacement::Before,
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> AnnotationStore {
        let mut store = AnnotationStore::new();
        store.add(Annotation::new(
            AnnotationSite::Variable("var1".to_string()),
            AnnotationKind::Rename { new_name: "buffer_size".to_string() },
        ));
        store.add(Annotation::new(
            AnnotationSite::Variable("var2".to_string()),
            AnnotationKind::TypeHint { new_type: "uint32_t".to_string() },
        ));
        store.add(Annotation::new(
            AnnotationSite::Line(3),
            AnnotationKind::Comment {
                text: "dangerous call".to_string(),
                placement: CommentPlacement::Before,
            },
        ));
        store
    }

    #[test]
    fn test_annotation_store_add_and_get() {
        let store = make_store();
        assert_eq!(store.len(), 3);
        let renames = store.get_for_variable("var1");
        assert!(!renames.is_empty());
    }

    #[test]
    fn test_annotation_store_type_hint() {
        let store = make_store();
        assert_eq!(store.type_hint_for("var2"), Some("uint32_t"));
    }

    #[test]
    fn test_annotation_store_rename() {
        let store = make_store();
        assert_eq!(store.rename_for("var1"), Some("buffer_size"));
    }

    #[test]
    fn test_annotation_applier_rename() {
        let mut store = AnnotationStore::new();
        store.add(Annotation::new(
            AnnotationSite::Variable("var1".to_string()),
            AnnotationKind::Rename { new_name: "count".to_string() },
        ));
        let applier = AnnotationApplier::new(&store);
        let src = "    int32_t var1 = 0;\n    return var1;\n";
        let out = applier.apply(src);
        assert!(out.contains("count"), "output: {out}");
        assert!(!out.contains("var1"), "output: {out}");
    }

    #[test]
    fn test_annotation_applier_comment_before() {
        let mut store = AnnotationStore::new();
        store.add(Annotation::new(
            AnnotationSite::Line(2),
            AnnotationKind::Comment {
                text: "suspicious call here".to_string(),
                placement: CommentPlacement::Before,
            },
        ));
        let applier = AnnotationApplier::new(&store);
        let src = "void foo() {\n    bad_func();\n}\n";
        let out = applier.apply(src);
        assert!(out.contains("suspicious call here"), "output: {out}");
        assert!(out.contains("/*"), "output: {out}");
    }

    #[test]
    fn test_annotation_applier_eol_comment() {
        let mut store = AnnotationStore::new();
        store.add(Annotation::new(
            AnnotationSite::Line(1),
            AnnotationKind::Comment {
                text: "entry point".to_string(),
                placement: CommentPlacement::EndOfLine,
            },
        ));
        let applier = AnnotationApplier::new(&store);
        let src = "void main() {";
        let out = applier.apply(src);
        assert!(out.contains("/* entry point */"), "output: {out}");
    }

    #[test]
    fn test_annotation_applier_type_hint() {
        let mut store = AnnotationStore::new();
        store.add(Annotation::new(
            AnnotationSite::Variable("x".to_string()),
            AnnotationKind::TypeHint { new_type: "uint64_t".to_string() },
        ));
        let applier = AnnotationApplier::new(&store);
        let src = "    int32_t x = 0;";
        let out = applier.apply(src);
        assert!(out.contains("uint64_t"), "output: {out}");
    }

    #[test]
    fn test_annotation_store_disabled() {
        let mut store = make_store();
        store.disable(0);
        let renames = store.get_for_variable("var1");
        assert!(renames.is_empty());
    }

    #[test]
    fn test_rename_identifier_whole_word() {
        let result = rename_identifier("    int var1 = var1 + var10;", "var1", "count");
        assert!(result.contains("count"), "result: {result}");
        // var10 should NOT be renamed.
        assert!(result.contains("var10"), "result: {result}");
    }

    #[test]
    fn test_patch_var_type() {
        let result = patch_var_type("    int x = 42;", "x", "uint8_t");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.contains("uint8_t"), "result: {r}");
        assert!(r.contains("x = 42"), "result: {r}");
    }

    #[test]
    fn test_annotation_merge() {
        let mut a = AnnotationStore::new();
        a.add(Annotation::new(
            AnnotationSite::Line(1),
            AnnotationKind::Comment { text: "from a".to_string(), placement: CommentPlacement::Before },
        ));
        let mut b = AnnotationStore::new();
        b.add(Annotation::new(
            AnnotationSite::Line(2),
            AnnotationKind::Comment { text: "from b".to_string(), placement: CommentPlacement::Before },
        ));
        let merged = AnnotationMerger::merge(vec![a, b]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_presets_format_string_vuln() {
        let ann = AnnotationPresets::format_string_vuln(5);
        assert!(matches!(ann.kind, AnnotationKind::VulnerabilityHint { .. }));
        assert_eq!(ann.site, AnnotationSite::Line(5));
    }

    #[test]
    fn test_vulnerability_hint_in_output() {
        let mut store = AnnotationStore::new();
        store.add(AnnotationPresets::format_string_vuln(2));
        let applier = AnnotationApplier::new(&store);
        let src = "void foo() {\n    printf(user_input);\n}\n";
        let out = applier.apply(src);
        assert!(out.contains("VULNERABILITY") || out.contains("Format-string"), "output: {out}");
    }
}
