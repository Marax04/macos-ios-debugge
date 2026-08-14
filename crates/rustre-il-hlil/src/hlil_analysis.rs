//! HLIL-level analysis suite for `rustre-il-hlil`.
//!
//! Provides type recovery, variable naming, auto-comment generation,
//! refactoring passes, and C pseudocode generation over HLIL functions.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

pub use rustre_core::address::Address;
pub use rustre_il_mlil::{MlilFunction, Size};

// ---------------------------------------------------------------------------
// HlilError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HlilError {
    #[error("unsupported construct: {0}")]
    Unsupported(String),
    #[error("type error: {0}")]
    TypeError(String),
    #[error("missing function")]
    MissingFunction,
}

// ---------------------------------------------------------------------------
// HlilVariable
// ---------------------------------------------------------------------------

/// A high-level variable with an optional inferred type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlilVariable {
    pub name: String,
    pub inferred_type: Option<HlilType>,
    pub is_parameter: bool,
    pub is_local: bool,
    pub usage_count: usize,
}

impl HlilVariable {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inferred_type: None,
            is_parameter: false,
            is_local: true,
            usage_count: 0,
        }
    }

    #[must_use]
    pub fn parameter(name: impl Into<String>, ty: HlilType) -> Self {
        Self {
            name: name.into(),
            inferred_type: Some(ty),
            is_parameter: true,
            is_local: false,
            usage_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// HlilType
// ---------------------------------------------------------------------------

/// A high-level type inferred by the HLIL type recovery pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HlilType {
    Void,
    Bool,
    Int(u8), // byte width: 1, 2, 4, 8
    Uint(u8),
    Float32,
    Float64,
    Pointer(Box<Self>),
    Array {
        elem: Box<Self>,
        count: usize,
    },
    Struct(String),
    Function {
        ret: Box<Self>,
        params: Vec<Self>,
    },
    Unknown,
}

impl HlilType {
    #[must_use]
    pub fn int32() -> Self {
        Self::Int(4)
    }
    #[must_use]
    pub fn int64() -> Self {
        Self::Int(8)
    }
    #[must_use]
    pub fn uint8() -> Self {
        Self::Uint(1)
    }
    #[must_use]
    pub fn char_ptr() -> Self {
        Self::Pointer(Box::new(Self::Int(1)))
    }

    #[must_use]
    pub fn size_bytes(&self) -> usize {
        match self {
            Self::Int(n) | Self::Uint(n) => *n as usize,
            Self::Float32 => 4,
            Self::Float64 | Self::Pointer(_) => 8,
            _ => 0,
        }
    }

    /// C-like type string.
    #[must_use]
    pub fn c_name(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Bool => "bool".to_string(),
            Self::Int(1) => "int8_t".to_string(),
            Self::Int(2) => "int16_t".to_string(),
            Self::Int(4) => "int32_t".to_string(),
            Self::Int(8) => "int64_t".to_string(),
            Self::Uint(1) => "uint8_t".to_string(),
            Self::Uint(2) => "uint16_t".to_string(),
            Self::Uint(4) => "uint32_t".to_string(),
            Self::Uint(8) => "uint64_t".to_string(),
            Self::Float32 => "float".to_string(),
            Self::Float64 => "double".to_string(),
            Self::Pointer(inner) => format!("{}*", inner.c_name()),
            Self::Array { elem, count } => format!("{}[{count}]", elem.c_name()),
            Self::Struct(name) => format!("struct {name}"),
            Self::Function { ret, params } => {
                let params_str: Vec<String> = params.iter().map(HlilType::c_name).collect();
                format!("{} (*)({})", ret.c_name(), params_str.join(", "))
            }
            _ => "unknown_t".to_string(),
        }
    }
}

impl fmt::Display for HlilType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.c_name())
    }
}

// ---------------------------------------------------------------------------
// HlilTypeRecovery
// ---------------------------------------------------------------------------

/// Infers types for HLIL variables based on usage context.
#[derive(Debug, Default)]
pub struct HlilTypeRecovery {
    /// Inferred types: variable_name → type.
    pub types: HashMap<String, HlilType>,
    pub inference_log: Vec<String>,
}

impl HlilTypeRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply heuristics to infer types.
    pub fn infer(&mut self, variables: &[HlilVariable]) {
        for var in variables {
            let ty = if var.name.starts_with("arg") || var.name.starts_with("param") {
                HlilType::int64()
            } else if var.name.starts_with("buf") || var.name.contains("buf") {
                HlilType::char_ptr()
            } else if var.name.starts_with("sz")
                || var.name.contains("size")
                || var.name.contains("len")
            {
                HlilType::Uint(8)
            } else if var.name.starts_with('p') && var.name.len() > 1 {
                HlilType::Pointer(Box::new(HlilType::int32()))
            } else if var.name.starts_with('b') || var.name.starts_with("flag") {
                HlilType::Bool
            } else {
                HlilType::int32()
            };
            self.inference_log
                .push(format!("infer {} → {}", var.name, ty));
            self.types.insert(var.name.clone(), ty);
        }
    }

    /// Get the inferred type for a variable.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&HlilType> {
        self.types.get(name)
    }
}

// ---------------------------------------------------------------------------
// HlilVariableNaming
// ---------------------------------------------------------------------------

/// Suggests human-readable names for HLIL variables.
#[derive(Debug, Default)]
pub struct HlilVariableNaming {
    pub renames: HashMap<String, String>,
}

impl HlilVariableNaming {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Suggest names based on type and usage heuristics.
    pub fn suggest(&mut self, vars: &[HlilVariable], types: &HashMap<String, HlilType>) {
        let mut counter: HashMap<String, usize> = HashMap::new();
        for var in vars {
            let base = types.get(&var.name).map_or_else(|| "var".to_string(), |ty| match ty {
                    HlilType::Pointer(inner) => {
                        format!("p_{}", inner.c_name().replace('*', "ptr").replace(' ', "_"))
                    }
                    HlilType::Uint(8) => "size".to_string(),
                    HlilType::Bool => "flag".to_string(),
                    HlilType::Int(4) => "value".to_string(),
                    HlilType::Struct(n) => n.to_lowercase(),
                    _ => "var".to_string(),
                });
            let idx = counter.entry(base.clone()).or_insert(0);
            let name = if *idx == 0 {
                base.clone()
            } else {
                format!("{base}{idx}")
            };
            *idx += 1;
            if name != var.name {
                self.renames.insert(var.name.clone(), name);
            }
        }
    }

    /// Maximum number of rename substitutions applied in a single
    /// [`apply_to_code`] call.  Limits O(N × |code|) work when a malicious
    /// binary contributes an unbounded number of symbol names.
    pub const MAX_RENAMES_APPLIED: usize = 4096;

    /// Apply renames to a pseudocode string.
    ///
    /// At most [`MAX_RENAMES_APPLIED`] substitutions are performed to prevent
    /// O(N × |code|) memory exhaustion when the rename table is attacker-sized.
    #[must_use]
    pub fn apply_to_code(&self, code: &str) -> String {
        self.apply_to_code_capped(code, Self::MAX_RENAMES_APPLIED)
    }

    /// `apply_to_code`, with the truncation cap as a parameter so it is
    /// unit-testable without building a real [`MAX_RENAMES_APPLIED`]-entry
    /// table. `renames` is a `HashMap`, whose iteration order is randomised
    /// per process — truncating a raw `.iter()` would make WHICH renames
    /// survive the cap (and which are silently dropped) depend on
    /// per-process hash order instead of program content, for any function
    /// with more locals than the cap. Sorting by the old name first makes
    /// the truncation deterministic and reproducible.
    fn apply_to_code_capped(&self, code: &str, cap: usize) -> String {
        let mut result = code.to_string();
        let mut sorted: Vec<(&String, &String)> = self.renames.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (old, new) in sorted.into_iter().take(cap) {
            result = result.replace(old.as_str(), new.as_str());
        }
        result
    }
}

// ---------------------------------------------------------------------------
// HlilCommentGenerator
// ---------------------------------------------------------------------------

/// Generates auto-comments for HLIL constructs.
#[derive(Debug, Default)]
pub struct HlilCommentGenerator {
    pub comments: HashMap<u64, String>,
}

impl HlilCommentGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a comment at the given address.
    pub fn add(&mut self, addr: u64, comment: impl Into<String>) {
        self.comments.insert(addr, comment.into());
    }

    /// Generate a comment for a function entry.
    pub fn comment_function_entry(&mut self, addr: u64, name: &str, param_count: usize) {
        self.add(
            addr,
            format!("Function '{name}' with {param_count} parameter(s)"),
        );
    }

    /// Generate comments for loop constructs.
    pub fn comment_loop(&mut self, addr: u64, loop_var: &str) {
        self.add(addr, format!("Loop with variable '{loop_var}'"));
    }

    /// Comment for a call site.
    pub fn comment_call(&mut self, addr: u64, callee: &str, arg_count: usize) {
        self.add(addr, format!("Call to '{callee}' with {arg_count} arg(s)"));
    }

    /// Get the comment at an address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&str> {
        self.comments.get(&addr).map(std::string::String::as_str)
    }

    /// Number of comments generated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.comments.len()
    }
}

// ---------------------------------------------------------------------------
// HlilRefactoring
// ---------------------------------------------------------------------------

/// Simplifies common HLIL idioms.
#[derive(Debug, Default)]
pub struct HlilRefactoring {
    pub transformations: Vec<String>,
}

impl HlilRefactoring {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simplify `if (cond == 0)` to `if (!cond)`.
    pub fn simplify_zero_comparison(&mut self, code: &str) -> String {
        let result = code.replace(" == 0)", ")").replace(" != 0)", " != 0)");
        if result != code {
            self.transformations
                .push("simplified zero comparison".to_string());
        }
        result
    }

    /// Simplify `x = x + 1` to `x++`.
    pub fn simplify_increment(&mut self, code: &str) -> String {
        // Very simplified heuristic.
        let result = code.replace("x = x + 1;", "x++;");
        if result != code {
            self.transformations
                .push("simplified increment".to_string());
        }
        result
    }

    /// Remove redundant double negations `!!x` → `x`.
    pub fn remove_double_negation(&mut self, code: &str) -> String {
        let result = code.replace("!!", "");
        if result != code {
            self.transformations
                .push("removed double negation".to_string());
        }
        result
    }

    /// Apply all refactoring passes.
    #[must_use]
    pub fn apply_all(&mut self, code: &str) -> String {
        let code = self.simplify_zero_comparison(code);
        let code = self.simplify_increment(&code);
        self.remove_double_negation(&code)
    }
}

// ---------------------------------------------------------------------------
// HlilToC
// ---------------------------------------------------------------------------

/// Generates C pseudocode from HLIL.
#[derive(Debug, Default)]
pub struct HlilToC {
    pub indent: usize,
    pub output: String,
}

impl HlilToC {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn write_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
    }

    /// Generate a function prototype.
    pub fn emit_prototype(
        &mut self,
        name: &str,
        ret_type: &HlilType,
        params: &[(String, HlilType)],
    ) {
        let _ = write!(self.output, "{} {name}(", ret_type.c_name());
        for (i, (n, t)) in params.iter().enumerate() {
            if i > 0 {
                self.output.push_str(", ");
            }
            let _ = write!(self.output, "{} {n}", t.c_name());
        }
        self.output.push_str(") {\n");
        self.indent += 1;
    }

    /// Emit a variable declaration.
    pub fn emit_local(&mut self, name: &str, ty: &HlilType) {
        self.write_indent();
        let _ = writeln!(self.output, "{} {name};", ty.c_name());
    }

    /// Emit an assignment.
    pub fn emit_assign(&mut self, lhs: &str, rhs: &str) {
        self.write_indent();
        let _ = writeln!(self.output, "{lhs} = {rhs};");
    }

    /// Emit a function call.
    pub fn emit_call(&mut self, func: &str, args: &[&str]) {
        self.write_indent();
        let _ = write!(self.output, "{func}(");
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                self.output.push_str(", ");
            }
            self.output.push_str(a);
        }
        self.output.push_str(");\n");
    }

    /// Emit a return statement.
    pub fn emit_return(&mut self, value: Option<&str>) {
        self.write_indent();
        match value {
            Some(v) => {
                let _ = writeln!(self.output, "return {v};");
            }
            None => self.output.push_str("return;\n"),
        }
    }

    /// Emit an if-else block.
    pub fn emit_if(&mut self, cond: &str, then_body: &str, else_body: Option<&str>) {
        self.write_indent();
        let _ = writeln!(self.output, "if ({cond}) {{");
        self.indent += 1;
        self.write_indent();
        self.output.push_str(then_body);
        self.output.push('\n');
        self.indent -= 1;
        self.write_indent();
        self.output.push_str("}\n");
        if let Some(else_b) = else_body {
            self.write_indent();
            self.output.push_str("else {\n");
            self.indent += 1;
            self.write_indent();
            self.output.push_str(else_b);
            self.output.push('\n');
            self.indent -= 1;
            self.write_indent();
            self.output.push_str("}\n");
        }
    }

    /// Emit a for loop.
    pub fn emit_for(&mut self, init: &str, cond: &str, inc: &str, body: &str) {
        self.write_indent();
        let _ = writeln!(self.output, "for ({init}; {cond}; {inc}) {{");
        self.indent += 1;
        self.write_indent();
        self.output.push_str(body);
        self.output.push('\n');
        self.indent -= 1;
        self.write_indent();
        self.output.push_str("}\n");
    }

    /// Close the current function.
    pub fn emit_function_end(&mut self) {
        if self.indent > 0 {
            self.indent -= 1;
        }
        self.output.push_str("}\n");
    }

    /// Return the generated pseudocode.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.output
    }
}

// ---------------------------------------------------------------------------
// HlilReport
// ---------------------------------------------------------------------------

/// Summary report from the HLIL analysis pass.
#[derive(Debug, Clone, Default)]
pub struct HlilReport {
    pub function_name: String,
    pub variable_count: usize,
    pub inferred_types: usize,
    pub suggested_renames: usize,
    pub auto_comments: usize,
    pub transformations_applied: usize,
    pub pseudocode_lines: usize,
    pub issues: Vec<String>,
}

impl HlilReport {
    #[must_use]
    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }
}

impl fmt::Display for HlilReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HlilReport({}): {} vars, {} types, {} renames, {} comments, {} transforms",
            self.function_name,
            self.variable_count,
            self.inferred_types,
            self.suggested_renames,
            self.auto_comments,
            self.transformations_applied,
        )
    }
}

// ---------------------------------------------------------------------------
// HlilAnalyzer
// ---------------------------------------------------------------------------

/// Orchestrates the full HLIL analysis pipeline.
pub struct HlilAnalyzer {
    pub type_recovery: HlilTypeRecovery,
    pub naming: HlilVariableNaming,
    pub comments: HlilCommentGenerator,
    pub refactoring: HlilRefactoring,
    pub to_c: HlilToC,
}

impl HlilAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_recovery: HlilTypeRecovery::new(),
            naming: HlilVariableNaming::new(),
            comments: HlilCommentGenerator::new(),
            refactoring: HlilRefactoring::new(),
            to_c: HlilToC::new(),
        }
    }

    /// Run all passes on a list of variables.
    pub fn analyze(
        &mut self,
        func_name: &str,
        func_addr: u64,
        variables: Vec<HlilVariable>,
    ) -> HlilReport {
        self.type_recovery.infer(&variables);
        self.naming.suggest(&variables, &self.type_recovery.types);
        self.comments.comment_function_entry(
            func_addr,
            func_name,
            variables.iter().filter(|v| v.is_parameter).count(),
        );

        HlilReport {
            function_name: func_name.to_string(),
            variable_count: variables.len(),
            inferred_types: self.type_recovery.types.len(),
            suggested_renames: self.naming.renames.len(),
            auto_comments: self.comments.comments.len(),
            transformations_applied: self.refactoring.transformations.len(),
            pseudocode_lines: 0,
            issues: Vec::new(),
        }
    }

    /// Generate C pseudocode for a simple function skeleton.
    pub fn generate_pseudocode(&mut self, func_name: &str, variables: &[HlilVariable]) -> String {
        let ret_type = HlilType::Void;
        let params: Vec<(String, HlilType)> = variables
            .iter()
            .filter(|v| v.is_parameter)
            .map(|v| {
                (
                    v.name.clone(),
                    v.inferred_type.clone().unwrap_or(HlilType::int64()),
                )
            })
            .collect();
        self.to_c = HlilToC::new();
        self.to_c.emit_prototype(func_name, &ret_type, &params);
        for var in variables.iter().filter(|v| v.is_local) {
            let ty = self
                .type_recovery
                .get(&var.name)
                .cloned()
                .unwrap_or(HlilType::int32());
            let renamed = self
                .naming
                .renames
                .get(&var.name)
                .map(String::as_str)
                .unwrap_or(&var.name);
            self.to_c.emit_local(renamed, &ty);
        }
        self.to_c.emit_function_end();
        self.to_c.code().to_string()
    }
}

impl Default for HlilAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vars() -> Vec<HlilVariable> {
        vec![
            HlilVariable::parameter("arg0", HlilType::int64()),
            HlilVariable::parameter("arg1", HlilType::char_ptr()),
            HlilVariable {
                name: "buf".to_string(),
                inferred_type: None,
                is_parameter: false,
                is_local: true,
                usage_count: 5,
            },
            HlilVariable {
                name: "szLen".to_string(),
                inferred_type: None,
                is_parameter: false,
                is_local: true,
                usage_count: 3,
            },
        ]
    }

    // ── HlilType ──────────────────────────────────────────────────────────

    #[test]
    fn type_c_name_int32() {
        assert_eq!(HlilType::int32().c_name(), "int32_t");
    }

    #[test]
    fn type_c_name_pointer() {
        assert_eq!(HlilType::char_ptr().c_name(), "int8_t*");
    }

    #[test]
    fn type_size_bytes() {
        assert_eq!(HlilType::int64().size_bytes(), 8);
        assert_eq!(HlilType::Uint(1).size_bytes(), 1);
    }

    #[test]
    fn type_display() {
        assert_eq!(HlilType::Void.to_string(), "void");
        assert_eq!(HlilType::Bool.to_string(), "bool");
    }

    // ── HlilTypeRecovery ──────────────────────────────────────────────────

    #[test]
    fn type_recovery_infers_size_type() {
        let mut tr = HlilTypeRecovery::new();
        let vars = vec![HlilVariable::new("szBuffer")];
        tr.infer(&vars);
        assert!(matches!(tr.get("szBuffer"), Some(HlilType::Uint(8))));
    }

    #[test]
    fn type_recovery_infers_bool() {
        let mut tr = HlilTypeRecovery::new();
        let vars = vec![HlilVariable::new("flag_done")];
        tr.infer(&vars);
        assert!(matches!(tr.get("flag_done"), Some(HlilType::Bool)));
    }

    #[test]
    fn type_recovery_infers_pointer() {
        let mut tr = HlilTypeRecovery::new();
        let vars = vec![HlilVariable::new("pData")];
        tr.infer(&vars);
        assert!(matches!(tr.get("pData"), Some(HlilType::Pointer(_))));
    }

    #[test]
    fn type_recovery_log_not_empty() {
        let mut tr = HlilTypeRecovery::new();
        tr.infer(&[HlilVariable::new("x")]);
        assert!(!tr.inference_log.is_empty());
    }

    // ── HlilVariableNaming ────────────────────────────────────────────────

    #[test]
    fn naming_suggests_renames() {
        let mut naming = HlilVariableNaming::new();
        let vars = vec![HlilVariable::new("var_0")];
        let mut types = HashMap::new();
        types.insert("var_0".to_string(), HlilType::Uint(8));
        naming.suggest(&vars, &types);
        assert!(!naming.renames.is_empty());
    }

    #[test]
    fn naming_apply_to_code() {
        let mut naming = HlilVariableNaming::new();
        naming
            .renames
            .insert("var_0".to_string(), "size".to_string());
        let code = "int var_0 = 10;";
        let result = naming.apply_to_code(code);
        assert!(result.contains("size"));
    }

    #[test]
    fn naming_apply_to_code_truncation_is_deterministic() {
        // `renames` is a `HashMap`, whose iteration order is randomised per
        // process. `apply_to_code` truncates to `MAX_RENAMES_APPLIED` via
        // `.iter().take(N)` — if that truncation follows raw HashMap
        // iteration, WHICH renames survive the cap (and which are silently
        // dropped) would differ between two runs over the identical binary,
        // for any function with more locals than the cap. Force that case
        // with a tiny cap-sized table (cheaper than 4096 real entries) by
        // building the table directly and checking the result is stable
        // across repeated calls on the SAME `HlilVariableNaming` — a
        // random-order bug would still be internally consistent per `self`
        // (same HashMap, same iteration each call), so the real regression
        // test is: two DIFFERENT `HlilVariableNaming` instances built from
        // the same rename set, in different insertion orders, must apply the
        // exact same subset when truncated to a size smaller than the table.
        let build = |order: &[usize]| {
            let mut naming = HlilVariableNaming::new();
            for &i in order {
                naming.renames.insert(format!("var_{i}"), format!("named_{i}"));
            }
            naming
        };
        let forward: Vec<usize> = (0..20).collect();
        let reversed: Vec<usize> = (0..20).rev().collect();
        let a = build(&forward);
        let b = build(&reversed);
        let code: String =
            (0..20).map(|i| format!("int var_{i} = 0;\n")).collect();

        // Cap smaller than the table forces truncation to matter. Exercises
        // the REAL production method (`apply_to_code_capped`, which
        // `apply_to_code` itself calls with `MAX_RENAMES_APPLIED`), not a
        // test-only mirror.
        let capped_a = a.apply_to_code_capped(&code, 5);
        let capped_b = b.apply_to_code_capped(&code, 5);
        assert_eq!(
            capped_a, capped_b,
            "truncating to a cap smaller than the rename table must pick the \
             SAME subset regardless of HashMap insertion/iteration order — \
             a random pick means the same binary decompiles differently \
             between runs once a function has more locals than the cap"
        );
    }

    // ── HlilCommentGenerator ──────────────────────────────────────────────

    #[test]
    fn comment_generator_add_and_get() {
        let mut cg = HlilCommentGenerator::new();
        cg.add(0x1000, "This is the entry point");
        assert_eq!(cg.get(0x1000), Some("This is the entry point"));
        assert_eq!(cg.len(), 1);
    }

    #[test]
    fn comment_generator_function_entry() {
        let mut cg = HlilCommentGenerator::new();
        cg.comment_function_entry(0x1000, "malloc", 1);
        let comment = cg.get(0x1000).unwrap();
        assert!(comment.contains("malloc"));
        assert!(comment.contains('1'));
    }

    #[test]
    fn comment_generator_call() {
        let mut cg = HlilCommentGenerator::new();
        cg.comment_call(0x2000, "memcpy", 3);
        let c = cg.get(0x2000).unwrap();
        assert!(c.contains("memcpy"));
        assert!(c.contains('3'));
    }

    // ── HlilRefactoring ───────────────────────────────────────────────────

    #[test]
    fn refactoring_simplify_zero_cmp() {
        let mut r = HlilRefactoring::new();
        let code = "if (x == 0) {";
        let result = r.simplify_zero_comparison(code);
        assert!(result.contains("x)"));
    }

    #[test]
    fn refactoring_increment() {
        let mut r = HlilRefactoring::new();
        let code = "x = x + 1;";
        let result = r.simplify_increment(code);
        assert!(result.contains("x++"));
    }

    #[test]
    fn refactoring_double_negation() {
        let mut r = HlilRefactoring::new();
        let result = r.remove_double_negation("!!flag");
        assert_eq!(result, "flag");
    }

    #[test]
    fn refactoring_apply_all_no_panic() {
        let mut r = HlilRefactoring::new();
        let result = r.apply_all("x = x + 1; if (!!y == 0) {}");
        assert!(!result.is_empty());
    }

    // ── HlilToC ───────────────────────────────────────────────────────────

    #[test]
    fn to_c_prototype() {
        let mut c = HlilToC::new();
        c.emit_prototype(
            "my_fn",
            &HlilType::int32(),
            &[("arg0".to_string(), HlilType::int64())],
        );
        assert!(c.code().contains("my_fn"));
        assert!(c.code().contains("int32_t"));
    }

    #[test]
    fn to_c_local() {
        let mut c = HlilToC::new();
        c.emit_local("count", &HlilType::int32());
        assert!(c.code().contains("count"));
    }

    #[test]
    fn to_c_assign() {
        let mut c = HlilToC::new();
        c.emit_assign("x", "42");
        assert!(c.code().contains("x = 42;"));
    }

    #[test]
    fn to_c_return() {
        let mut c = HlilToC::new();
        c.emit_return(Some("0"));
        assert!(c.code().contains("return 0;"));
    }

    #[test]
    fn to_c_if() {
        let mut c = HlilToC::new();
        c.indent = 1;
        c.emit_if("x > 0", "x--;", None);
        assert!(c.code().contains("if (x > 0)"));
    }

    #[test]
    fn to_c_for() {
        let mut c = HlilToC::new();
        c.emit_for("int i = 0", "i < 10", "i++", "do_work(i);");
        assert!(c.code().contains("for (int i = 0; i < 10; i++)"));
    }

    // ── HlilAnalyzer ─────────────────────────────────────────────────────

    #[test]
    fn analyzer_analyze_basic() {
        let mut a = HlilAnalyzer::new();
        let report = a.analyze("my_func", 0x1000, make_vars());
        assert_eq!(report.function_name, "my_func");
        assert_eq!(report.variable_count, 4);
        assert!(report.inferred_types > 0);
    }

    #[test]
    fn analyzer_generate_pseudocode() {
        let mut a = HlilAnalyzer::new();
        let vars = vec![HlilVariable::parameter("argc", HlilType::int32())];
        let code = a.generate_pseudocode("main", &vars);
        assert!(code.contains("main"));
    }

    #[test]
    fn hlil_report_display() {
        let r = HlilReport {
            function_name: "foo".to_string(),
            variable_count: 3,
            inferred_types: 2,
            ..Default::default()
        };
        let s = r.to_string();
        assert!(s.contains("foo"));
    }

    #[test]
    fn hlil_variable_parameter() {
        let v = HlilVariable::parameter("x", HlilType::int64());
        assert!(v.is_parameter);
        assert!(!v.is_local);
    }

    #[test]
    fn hlil_variable_new() {
        let v = HlilVariable::new("local_var");
        assert!(!v.is_parameter);
        assert!(v.is_local);
    }

    #[test]
    fn analyzer_default() {
        let a = HlilAnalyzer::default();
        assert_eq!(a.type_recovery.types.len(), 0);
    }
}
