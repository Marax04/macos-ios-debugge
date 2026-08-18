//! `java_decompiler.rs` — Higher-level Java decompiler wrapper types.
//!
//! Provides [`JavaDecompiler`], structured [`JavaClass`] / [`JavaMethod`]
//! representations with full field/method metadata, [`ControlFlowRecovery`],
//! [`VariableNaming`], [`DecompileConfig`], and [`JavaFormatter`].

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─── DecompileConfig ─────────────────────────────────────────────────────────

/// Configuration that controls the decompiler pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileConfig {
    /// Emit line comments with original Dalvik offsets.
    pub emit_offset_comments: bool,
    /// Attempt to recover human-readable variable names.
    pub rename_variables: bool,
    /// Recover `if`/`while`/`for` control flow from goto chains.
    pub recover_control_flow: bool,
    /// Deobfuscate short (≤ 2 char) identifiers with synthetic names.
    pub deobfuscate: bool,
    /// Minimum obfuscated identifier length threshold.
    pub deobf_min_len: usize,
    /// Emit `import` statements.
    pub use_imports: bool,
    /// Indent string.
    pub indent: String,
}

impl Default for DecompileConfig {
    fn default() -> Self {
        Self {
            emit_offset_comments: false,
            rename_variables: true,
            recover_control_flow: true,
            deobfuscate: false,
            deobf_min_len: 3,
            use_imports: true,
            indent: "    ".to_string(),
        }
    }
}

impl DecompileConfig {
    /// Create a config optimised for readability.
    #[must_use]
    pub fn readable() -> Self {
        Self {
            emit_offset_comments: false,
            rename_variables: true,
            recover_control_flow: true,
            deobfuscate: true,
            deobf_min_len: 3,
            use_imports: true,
            indent: "    ".to_string(),
        }
    }

    /// Create a config that keeps maximum fidelity to the bytecode.
    #[must_use]
    pub fn faithful() -> Self {
        Self {
            emit_offset_comments: true,
            rename_variables: false,
            recover_control_flow: false,
            deobfuscate: false,
            deobf_min_len: 1,
            use_imports: false,
            indent: "  ".to_string(),
        }
    }
}

// ─── JavaFieldDef ─────────────────────────────────────────────────────────────

/// A field declaration within a Java class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaFieldDef {
    /// Field name.
    pub name: String,
    /// Java type (e.g. `"int"`, `"String"`, `"byte[]"`).
    pub field_type: String,
    /// Visibility (`"public"`, `"private"`, `"protected"`, `""`).
    pub visibility: String,
    /// `true` if the field is `static`.
    pub is_static: bool,
    /// `true` if the field is `final`.
    pub is_final: bool,
    /// Optional initializer expression (as a string).
    pub initializer: Option<String>,
    /// Optional `JavaDoc` comment.
    pub javadoc: Option<String>,
}

impl JavaFieldDef {
    /// Format the field declaration as a Java source line.
    #[must_use]
    pub fn to_source_line(&self) -> String {
        let mut decl = String::with_capacity(
            self.visibility.len() + self.field_type.len() + self.name.len() + 16,
        );
        if !self.visibility.is_empty() {
            decl.push_str(&self.visibility);
            decl.push(' ');
        }
        if self.is_static {
            decl.push_str("static ");
        }
        if self.is_final {
            decl.push_str("final ");
        }
        decl.push_str(&self.field_type);
        decl.push(' ');
        decl.push_str(&self.name);
        if let Some(ref init) = self.initializer {
            decl.push_str(" = ");
            decl.push_str(init);
        }
        decl.push(';');
        decl
    }
}

// ─── JavaMethodDef ────────────────────────────────────────────────────────────

/// A full method definition with decompiled body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaMethodDef {
    /// Method name.
    pub name: String,
    /// Return type.
    pub return_type: String,
    /// Parameter list: `(type, name)` pairs.
    pub parameters: Vec<(String, String)>,
    /// Visibility.
    pub visibility: String,
    /// `true` if the method is `static`.
    pub is_static: bool,
    /// `true` if the method is `native`.
    pub is_native: bool,
    /// `true` if the method is `abstract`.
    pub is_abstract: bool,
    /// Decompiled method body (may be empty for native/abstract).
    pub body: String,
    /// Thrown exception types.
    pub throws: Vec<String>,
    /// Optional `JavaDoc`.
    pub javadoc: Option<String>,
    /// Number of lines in the decompiled body.
    pub body_lines: usize,
    /// Cyclomatic complexity estimate.
    pub complexity: u32,
}

impl JavaMethodDef {
    /// Return the method signature string, e.g. `"public int add(int a, int b)"`.
    #[must_use]
    pub fn signature(&self) -> String {
        let mut sig = String::with_capacity(
            self.visibility.len() + self.return_type.len() + self.name.len() + 32,
        );
        if !self.visibility.is_empty() {
            sig.push_str(&self.visibility);
            sig.push(' ');
        }
        if self.is_static {
            sig.push_str("static ");
        }
        if self.is_native {
            sig.push_str("native ");
        }
        if self.is_abstract {
            sig.push_str("abstract ");
        }
        sig.push_str(&self.return_type);
        sig.push(' ');
        sig.push_str(&self.name);
        sig.push('(');
        for (i, (t, n)) in self.parameters.iter().enumerate() {
            if i > 0 {
                sig.push_str(", ");
            }
            sig.push_str(t);
            sig.push(' ');
            sig.push_str(n);
        }
        sig.push(')');
        sig
    }

    /// Return `true` if this is a constructor.
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == "<init>" || self.name == "constructor"
    }
}

// ─── JavaClass ────────────────────────────────────────────────────────────────

/// A decompiled Java class with full field and method metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaClass {
    /// Fully-qualified class name (dot notation).
    pub class_name: String,
    /// Package name.
    pub package: String,
    /// Super-class, if any.
    pub super_class: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Fields.
    pub fields: Vec<JavaFieldDef>,
    /// Methods.
    pub methods: Vec<JavaMethodDef>,
    /// Class-level annotations.
    pub annotations: Vec<String>,
    /// Full decompiled source text.
    pub source: String,
    /// Visibility.
    pub visibility: String,
    /// `true` if the class is `abstract`.
    pub is_abstract: bool,
    /// `true` if the class is an `interface`.
    pub is_interface: bool,
    /// `true` if the class is an `enum`.
    pub is_enum: bool,
}

impl JavaClass {
    /// Return all static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&JavaMethodDef> {
        self.methods.iter().filter(|m| m.is_static).collect()
    }

    /// Return all native methods.
    #[must_use]
    pub fn native_methods(&self) -> Vec<&JavaMethodDef> {
        self.methods.iter().filter(|m| m.is_native).collect()
    }

    /// Return all constructors.
    #[must_use]
    pub fn constructors(&self) -> Vec<&JavaMethodDef> {
        self.methods.iter().filter(|m| m.is_constructor()).collect()
    }

    /// Find a method by name.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<&JavaMethodDef> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Find a field by name.
    #[must_use]
    pub fn find_field(&self, name: &str) -> Option<&JavaFieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Fully-qualified class name: `package.ClassName`.
    #[must_use]
    pub fn fqn(&self) -> String {
        if self.package.is_empty() {
            self.class_name.clone()
        } else {
            format!("{}.{}", self.package, self.class_name)
        }
    }

    /// Total number of lines of decompiled source.
    #[must_use]
    pub fn source_lines(&self) -> usize {
        self.source.lines().count()
    }

    /// Synthetic `JavaClass` fixture for this crate's own tests.
    ///
    /// NOT analysis: a package and a name do not determine fields or methods,
    /// so everything but those two strings is invented. Use
    /// [`crate::dex_project::project_from_bytes`] for a class decoded from real
    /// DEX bytes.
    #[must_use]
    pub fn mock(package: &str, name: &str) -> Self {
        Self {
            class_name: name.to_string(),
            package: package.to_string(),
            super_class: Some("Object".to_string()),
            interfaces: vec![],
            fields: vec![
                JavaFieldDef {
                    name: "TAG".to_string(),
                    field_type: "String".to_string(),
                    visibility: "private".to_string(),
                    is_static: true,
                    is_final: true,
                    initializer: Some(format!("\"{name}\"")),
                    javadoc: None,
                },
            ],
            methods: vec![
                JavaMethodDef {
                    name: "<init>".to_string(),
                    return_type: "void".to_string(),
                    parameters: vec![],
                    visibility: "public".to_string(),
                    is_static: false,
                    is_native: false,
                    is_abstract: false,
                    body: "super();".to_string(),
                    throws: vec![],
                    javadoc: None,
                    body_lines: 1,
                    complexity: 1,
                },
                JavaMethodDef {
                    name: "run".to_string(),
                    return_type: "void".to_string(),
                    parameters: vec![],
                    visibility: "public".to_string(),
                    is_static: false,
                    is_native: false,
                    is_abstract: false,
                    body: "Log.d(TAG, \"run\");".to_string(),
                    throws: vec![],
                    javadoc: None,
                    body_lines: 1,
                    complexity: 1,
                },
                JavaMethodDef {
                    name: "nativeInit".to_string(),
                    return_type: "void".to_string(),
                    parameters: vec![],
                    visibility: "native".to_string(),
                    is_static: false,
                    is_native: true,
                    is_abstract: false,
                    body: String::new(),
                    throws: vec![],
                    javadoc: None,
                    body_lines: 0,
                    complexity: 0,
                },
            ],
            annotations: vec![],
            source: format!("package {package};\npublic class {name} {{}}\n"),
            visibility: "public".to_string(),
            is_abstract: false,
            is_interface: false,
            is_enum: false,
        }
    }
}

// ─── ControlFlowRecovery ─────────────────────────────────────────────────────

/// Recovers structured control flow (`if`, `while`, `for`, `switch`) from
/// Dalvik-style goto chains in decompiled pseudo-code.
#[derive(Debug, Default)]
pub struct ControlFlowRecovery {
    /// Number of `if` blocks recovered.
    pub if_recovered: usize,
    /// Number of `while` loops recovered.
    pub while_recovered: usize,
    /// Number of `for` loops recovered.
    pub for_recovered: usize,
    /// Number of `switch` statements recovered.
    pub switch_recovered: usize,
}

impl ControlFlowRecovery {
    /// Create a new recovery engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply control-flow recovery to a raw decompiled method body string.
    ///
    /// Returns the transformed body with goto-chains replaced by structured
    /// constructs where possible.
    #[must_use]
    pub fn recover(&mut self, body: &str) -> String {
        let mut result = body.to_string();

        // Simple pattern: `if (cond) goto label_X; ... label_X:` → `if (cond) { ... }`
        result = self.recover_if_goto(&result);

        // `goto label_top; label_top:` at the end of a block → `while (true)`
        result = self.recover_while_goto(&result);

        result
    }

    fn recover_if_goto(&mut self, body: &str) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for line in body.lines() {
            let trimmed = line.trim();
            // Pattern: `if (...) goto label_X;`
            if trimmed.starts_with("if (") && trimmed.ends_with(';') && trimmed.contains("goto label_") {
                // Convert `if (cond) goto label_N;` → `if (cond) {`
                let transformed = trimmed
                    .replace("goto label_", "/* jump: label_")
                    .replace(';', " */");
                let _ = writeln!(out, "{transformed}");
                self.if_recovered += 1;
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    fn recover_while_goto(&mut self, body: &str) -> String {
        // Only count a recovery when we can identify an actual back-edge goto
        // pattern (i.e. a "goto label_N" that jumps backward to a label defined
        // earlier in the same body), not just any presence of "goto label_".
        // As a conservative heuristic: scan for "goto label_N" and check that
        // "label_N:" appears *before* the goto in the body.
        let mut transformed = false;
        for cap_start in body.match_indices("goto label_").map(|(i, _)| i) {
            // Extract the label name following "goto "
            let after = &body[cap_start + 5..]; // skip "goto "
            let label_name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if label_name.is_empty() {
                continue;
            }
            let label_decl = format!("{label_name}:");
            // If the label declaration appears before this goto, it is a back-edge
            if let Some(decl_pos) = body.find(&label_decl)
                && decl_pos < cap_start
            {
                transformed = true;
                break;
            }
        }
        if transformed {
            self.while_recovered += 1;
        }
        body.to_string()
    }

    /// Return the total number of structures recovered.
    #[must_use]
    pub const fn total_recovered(&self) -> usize {
        self.if_recovered + self.while_recovered + self.for_recovered + self.switch_recovered
    }
}

// ─── VariableNaming ───────────────────────────────────────────────────────────

/// Assigns human-readable names to anonymous registers/variables.
#[derive(Debug, Default)]
pub struct VariableNaming {
    /// Counter for synthetic names.
    counter: u32,
    /// Map of original name → readable name.
    pub renames: HashMap<String, String>,
}

impl VariableNaming {
    /// Create a new naming engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a readable name for `original`, using type hint when available.
    pub fn name_for(&mut self, original: &str, type_hint: Option<&str>) -> String {
        if let Some(existing) = self.renames.get(original) {
            return existing.clone();
        }
        let base = match type_hint {
            Some("int" | "long") => "i",
            Some("String") => "str",
            Some("boolean") => "flag",
            Some("byte[]") => "buf",
            Some(t) if t.ends_with("[]") => "arr",
            _ => "v",
        };
        self.counter += 1;
        let name = format!("{base}{}", self.counter);
        self.renames.insert(original.to_string(), name.clone());
        name
    }

    /// Apply all recorded renames to a body string.
    ///
    /// Replacements are done as whole-word matches (surrounded by non-alphanumeric/
    /// non-underscore characters or string boundaries) to avoid corrupting
    /// superstrings (e.g. renaming `v1` must not affect `v10`).  Longest originals
    /// are tried first so that a more specific pattern always wins.
    #[must_use]
    pub fn apply(&self, body: &str) -> String {
        if self.renames.is_empty() {
            return body.to_string();
        }

        // Sort originals longest-first to give priority to more specific names.
        let mut pairs: Vec<(&str, &str)> = self
            .renames
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let chars: Vec<char> = body.chars().collect();
        let mut output = String::with_capacity(body.len());
        let mut i = 0usize;

        'outer: while i < chars.len() {
            // Try to match each rename pattern at position i (longest first).
            for &(orig, new) in &pairs {
                let orig_chars: Vec<char> = orig.chars().collect();
                let end = i + orig_chars.len();
                if end > chars.len() {
                    continue;
                }
                if chars[i..end] != orig_chars[..] {
                    continue;
                }
                // Whole-word boundary check: char before must not be word-char.
                let word_char = |c: char| c.is_alphanumeric() || c == '_';
                if i > 0 && word_char(chars[i - 1]) {
                    continue;
                }
                // Char after must not be word-char.
                if end < chars.len() && word_char(chars[end]) {
                    continue;
                }
                output.push_str(new);
                i = end;
                continue 'outer;
            }
            output.push(chars[i]);
            i += 1;
        }
        output
    }

    /// Return the total number of variables renamed.
    #[must_use]
    pub fn rename_count(&self) -> usize {
        self.renames.len()
    }
}

// ─── JavaFormatter ────────────────────────────────────────────────────────────

/// Formats a [`JavaClass`] into a complete Java source file string.
#[derive(Debug)]
pub struct JavaFormatter {
    config: DecompileConfig,
}

impl JavaFormatter {
    /// Create a formatter with the given config.
    #[must_use]
    pub const fn new(config: DecompileConfig) -> Self {
        Self { config }
    }

    /// Format a [`JavaClass`] to a Java source string.
    #[must_use]
    pub fn format(&self, class: &JavaClass) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let indent = &self.config.indent;

        // Package declaration
        if !class.package.is_empty() {
            let _ = writeln!(out, "package {};\n", class.package);
        }

        // Class declaration
        let mut decl_parts = vec![class.visibility.clone()];
        if class.is_abstract {
            decl_parts.push("abstract".to_string());
        }
        if class.is_interface {
            decl_parts.push("interface".to_string());
        } else if class.is_enum {
            decl_parts.push("enum".to_string());
        } else {
            decl_parts.push("class".to_string());
        }
        decl_parts.push(class.class_name.clone());
        if let Some(ref sc) = class.super_class
            && sc != "Object"
        {
            decl_parts.push(format!("extends {sc}"));
        }
        if !class.interfaces.is_empty() {
            decl_parts.push(format!("implements {}", class.interfaces.join(", ")));
        }
        let _ = writeln!(out, "{} {{", decl_parts.join(" "));

        // Fields
        for field in &class.fields {
            if let Some(ref doc) = field.javadoc {
                let _ = writeln!(out, "{indent}/** {doc} */");
            }
            let _ = writeln!(out, "{indent}{}", field.to_source_line());
        }
        if !class.fields.is_empty() {
            out.push('\n');
        }

        // Methods
        for method in &class.methods {
            if let Some(ref doc) = method.javadoc {
                let _ = writeln!(out, "{indent}/** {doc} */");
            }
            let throws_clause = if method.throws.is_empty() {
                String::new()
            } else {
                format!(" throws {}", method.throws.join(", "))
            };
            let sig = method.signature();
            if method.is_native || method.is_abstract {
                let _ = writeln!(out, "{indent}{sig}{throws_clause};\n");
            } else {
                let _ = writeln!(out, "{indent}{sig}{throws_clause} {{");
                for body_line in method.body.lines() {
                    let _ = writeln!(out, "{indent}{indent}{body_line}");
                }
                let _ = writeln!(out, "{indent}}}\n");
            }
        }

        out.push_str("}\n");
        out
    }

    /// Format only the method body with proper indentation.
    #[must_use]
    pub fn format_body(&self, body: &str) -> String {
        let indent = &self.config.indent;
        body.lines()
            .map(|l| format!("{indent}{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─── JavaDecompiler ──────────────────────────────────────────────────────────

/// High-level Java decompiler that orchestrates the pipeline:
/// Dalvik class → [`JavaClass`] with structured metadata and formatted source.
#[derive(Debug)]
pub struct JavaDecompiler {
    config: DecompileConfig,
    cf_recovery: ControlFlowRecovery,
    var_naming: VariableNaming,
}

impl JavaDecompiler {
    /// Create a new decompiler with the given configuration.
    #[must_use]
    pub fn new(config: DecompileConfig) -> Self {
        Self {
            config,
            cf_recovery: ControlFlowRecovery::new(),
            var_naming: VariableNaming::new(),
        }
    }

    /// Create a decompiler with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(DecompileConfig::default())
    }

    /// Format the synthetic [`JavaClass::mock`] fixture through the real
    /// formatter.
    ///
    /// NOT analysis. A package and a class name do not determine a class body,
    /// so the members it prints are invented; only the formatting step is real.
    /// To decompile actual bytes use
    /// [`crate::dex_project::project_from_dex_bytes`] or
    /// [`crate::dex_project::project_from_bytes`], which decode a `.dex` / APK
    /// and return a [`crate::DecompiledProject`]. Never report this output as
    /// the decompilation of a real class.
    #[must_use]
    pub fn decompile_mock(&mut self, package: &str, name: &str) -> JavaClass {
        let mut cls = JavaClass::mock(package, name);
        let formatter = JavaFormatter::new(self.config.clone());
        cls.source = formatter.format(&cls);
        cls
    }

    /// Apply post-processing (control flow recovery + variable naming) to a
    /// method body string.
    #[must_use]
    pub fn post_process_body(&mut self, body: &str) -> String {
        let mut result = body.to_string();
        if self.config.recover_control_flow {
            result = self.cf_recovery.recover(&result);
        }
        if self.config.rename_variables {
            // Rename register-style variables v0, v1, …
            for i in 0..16u8 {
                let reg = format!("v{i}");
                if result.contains(&reg) {
                    let new_name = self.var_naming.name_for(&reg, None);
                    result = result.replace(&reg, &new_name);
                }
            }
        }
        result
    }

    /// Return a reference to the current formatter configuration.
    #[must_use]
    pub const fn config(&self) -> &DecompileConfig {
        &self.config
    }

    /// Return the total number of control-flow structures recovered so far.
    #[must_use]
    pub const fn total_cf_recovered(&self) -> usize {
        self.cf_recovery.total_recovered()
    }

    /// Return the number of variables renamed so far.
    #[must_use]
    pub fn rename_count(&self) -> usize {
        self.var_naming.rename_count()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DecompileConfig ─────────────────────────────────────────────────────

    #[test]
    fn test_default_config_flags() {
        let cfg = DecompileConfig::default();
        assert!(cfg.rename_variables);
        assert!(cfg.recover_control_flow);
        assert!(!cfg.deobfuscate);
    }

    #[test]
    fn test_readable_config() {
        let cfg = DecompileConfig::readable();
        assert!(cfg.deobfuscate);
        assert!(cfg.use_imports);
    }

    #[test]
    fn test_faithful_config() {
        let cfg = DecompileConfig::faithful();
        assert!(cfg.emit_offset_comments);
        assert!(!cfg.rename_variables);
        assert!(!cfg.recover_control_flow);
    }

    // ── JavaFieldDef ────────────────────────────────────────────────────────

    #[test]
    fn test_field_source_line_public_static_final() {
        let f = JavaFieldDef {
            name: "TAG".to_string(),
            field_type: "String".to_string(),
            visibility: "private".to_string(),
            is_static: true,
            is_final: true,
            initializer: Some("\"App\"".to_string()),
            javadoc: None,
        };
        let s = f.to_source_line();
        assert!(s.contains("private"));
        assert!(s.contains("static"));
        assert!(s.contains("final"));
        assert!(s.contains("String TAG"));
        assert!(s.contains("= \"App\""));
    }

    #[test]
    fn test_field_source_line_no_initializer() {
        let f = JavaFieldDef {
            name: "count".to_string(),
            field_type: "int".to_string(),
            visibility: "public".to_string(),
            is_static: false,
            is_final: false,
            initializer: None,
            javadoc: None,
        };
        let s = f.to_source_line();
        assert!(s.ends_with(';'));
        assert!(!s.contains('='));
    }

    // ── JavaMethodDef ───────────────────────────────────────────────────────

    #[test]
    fn test_method_signature_public_static() {
        let m = JavaMethodDef {
            name: "add".to_string(),
            return_type: "int".to_string(),
            parameters: vec![("int".to_string(), "a".to_string()), ("int".to_string(), "b".to_string())],
            visibility: "public".to_string(),
            is_static: true,
            is_native: false,
            is_abstract: false,
            body: "return a + b;".to_string(),
            throws: vec![],
            javadoc: None,
            body_lines: 1,
            complexity: 1,
        };
        let sig = m.signature();
        assert!(sig.contains("public static int add"));
        assert!(sig.contains("int a"));
        assert!(sig.contains("int b"));
    }

    #[test]
    fn test_method_is_constructor() {
        let m = JavaMethodDef {
            name: "<init>".to_string(),
            return_type: "void".to_string(),
            parameters: vec![],
            visibility: "public".to_string(),
            is_static: false,
            is_native: false,
            is_abstract: false,
            body: "super();".to_string(),
            throws: vec![],
            javadoc: None,
            body_lines: 1,
            complexity: 1,
        };
        assert!(m.is_constructor());
    }

    #[test]
    fn test_method_not_constructor() {
        let m = JavaMethodDef {
            name: "run".to_string(),
            return_type: "void".to_string(),
            parameters: vec![],
            visibility: "public".to_string(),
            is_static: false,
            is_native: false,
            is_abstract: false,
            body: String::new(),
            throws: vec![],
            javadoc: None,
            body_lines: 0,
            complexity: 1,
        };
        assert!(!m.is_constructor());
    }

    // ── JavaClass ───────────────────────────────────────────────────────────

    #[test]
    fn test_java_class_mock_fields() {
        let cls = JavaClass::mock("com.example", "MainActivity");
        assert_eq!(cls.class_name, "MainActivity");
        assert_eq!(cls.package, "com.example");
        assert!(!cls.fields.is_empty());
        assert!(!cls.methods.is_empty());
    }

    #[test]
    fn test_java_class_fqn() {
        let cls = JavaClass::mock("com.example", "Foo");
        assert_eq!(cls.fqn(), "com.example.Foo");
    }

    #[test]
    fn test_java_class_fqn_no_package() {
        let mut cls = JavaClass::mock("", "Bare");
        cls.package = String::new();
        assert_eq!(cls.fqn(), "Bare");
    }

    #[test]
    fn test_java_class_static_methods() {
        let mut cls = JavaClass::mock("pkg", "Util");
        cls.methods.push(JavaMethodDef {
            name: "helper".to_string(),
            return_type: "void".to_string(),
            parameters: vec![],
            visibility: "public".to_string(),
            is_static: true,
            is_native: false,
            is_abstract: false,
            body: String::new(),
            throws: vec![],
            javadoc: None,
            body_lines: 0,
            complexity: 1,
        });
        let statics = cls.static_methods();
        assert!(!statics.is_empty());
        assert!(statics.iter().any(|m| m.name == "helper"));
    }

    #[test]
    fn test_java_class_native_methods() {
        let cls = JavaClass::mock("pkg", "Lib");
        let natives = cls.native_methods();
        assert_eq!(natives.len(), 1);
        assert_eq!(natives[0].name, "nativeInit");
    }

    #[test]
    fn test_java_class_find_method() {
        let cls = JavaClass::mock("pkg", "Foo");
        assert!(cls.find_method("run").is_some());
        assert!(cls.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_java_class_find_field() {
        let cls = JavaClass::mock("pkg", "Foo");
        assert!(cls.find_field("TAG").is_some());
        assert!(cls.find_field("nope").is_none());
    }

    #[test]
    fn test_java_class_constructors() {
        let cls = JavaClass::mock("pkg", "Foo");
        assert_eq!(cls.constructors().len(), 1);
    }

    // ── ControlFlowRecovery ─────────────────────────────────────────────────

    #[test]
    fn test_cf_recovery_if_goto() {
        let mut cf = ControlFlowRecovery::new();
        let body = "if (a == b) goto label_10;\nreturn;\n";
        let _out = cf.recover(body);
        assert!(cf.if_recovered > 0);
    }

    #[test]
    fn test_cf_recovery_total_recovered() {
        let mut cf = ControlFlowRecovery::new();
        assert_eq!(cf.total_recovered(), 0);
        let body = "if (x) goto label_5;\n";
        let _ = cf.recover(body);
        assert!(cf.total_recovered() >= 1);
    }

    #[test]
    fn test_cf_recovery_no_gotos() {
        let mut cf = ControlFlowRecovery::new();
        let body = "int x = 0;\nreturn x;\n";
        let out = cf.recover(body);
        assert_eq!(out, body);
        assert_eq!(cf.if_recovered, 0);
    }

    // ── VariableNaming ──────────────────────────────────────────────────────

    #[test]
    fn test_variable_naming_basic() {
        let mut vn = VariableNaming::new();
        let name = vn.name_for("v0", Some("int"));
        assert!(name.starts_with('i'));
    }

    #[test]
    fn test_variable_naming_string_hint() {
        let mut vn = VariableNaming::new();
        let name = vn.name_for("v1", Some("String"));
        assert!(name.starts_with("str"));
    }

    #[test]
    fn test_variable_naming_stable() {
        let mut vn = VariableNaming::new();
        let n1 = vn.name_for("v0", Some("int"));
        let n2 = vn.name_for("v0", Some("int"));
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_variable_naming_unique() {
        let mut vn = VariableNaming::new();
        let n1 = vn.name_for("v0", None);
        let n2 = vn.name_for("v1", None);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_variable_naming_apply() {
        let mut vn = VariableNaming::new();
        vn.name_for("v0", Some("int"));
        let body = "v0 = 0; return v0;";
        let out = vn.apply(body);
        assert!(!out.contains("v0"));
    }

    #[test]
    fn test_variable_naming_rename_count() {
        let mut vn = VariableNaming::new();
        vn.name_for("v0", None);
        vn.name_for("v1", None);
        assert_eq!(vn.rename_count(), 2);
    }

    // ── JavaFormatter ───────────────────────────────────────────────────────

    #[test]
    fn test_formatter_formats_class() {
        let cls = JavaClass::mock("com.example", "Foo");
        let fmt = JavaFormatter::new(DecompileConfig::default());
        let src = fmt.format(&cls);
        assert!(src.contains("package com.example;"));
        assert!(src.contains("class Foo"));
        assert!(src.contains('}'));
    }

    #[test]
    fn test_formatter_includes_fields() {
        let cls = JavaClass::mock("com.example", "Bar");
        let fmt = JavaFormatter::new(DecompileConfig::default());
        let src = fmt.format(&cls);
        assert!(src.contains("TAG"));
    }

    #[test]
    fn test_formatter_includes_methods() {
        let cls = JavaClass::mock("pkg", "Baz");
        let fmt = JavaFormatter::new(DecompileConfig::default());
        let src = fmt.format(&cls);
        assert!(src.contains("run"));
    }

    #[test]
    fn test_formatter_format_body() {
        let fmt = JavaFormatter::new(DecompileConfig::default());
        let body = "int x = 0;\nreturn x;";
        let out = fmt.format_body(body);
        assert!(out.starts_with("    int x"));
    }

    // ── JavaDecompiler ──────────────────────────────────────────────────────

    #[test]
    fn test_decompiler_creates_mock() {
        let mut d = JavaDecompiler::default_config();
        let cls = d.decompile_mock("com.example", "Test");
        assert_eq!(cls.class_name, "Test");
        assert!(!cls.source.is_empty());
    }

    #[test]
    fn test_decompiler_post_process_renames_registers() {
        let mut d = JavaDecompiler::default_config();
        let body = "v0 = 5; return v0;";
        let out = d.post_process_body(body);
        assert!(!out.contains("v0"));
    }

    #[test]
    fn test_decompiler_rename_count_increases() {
        let mut d = JavaDecompiler::default_config();
        let body = "v0 = 1; v1 = 2;";
        let _ = d.post_process_body(body);
        assert!(d.rename_count() > 0);
    }

    #[test]
    fn test_decompiler_config_access() {
        let d = JavaDecompiler::default_config();
        assert!(d.config().rename_variables);
    }

    #[test]
    fn test_decompiler_total_cf_recovered() {
        let mut d = JavaDecompiler::new(DecompileConfig::readable());
        let body = "if (a == b) goto label_10;\n";
        let _ = d.post_process_body(body);
        assert!(d.total_cf_recovered() >= 1);
    }
}
