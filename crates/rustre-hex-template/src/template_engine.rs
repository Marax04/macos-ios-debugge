//! 010 Editor-style template engine for `rustre-hex-template`.
//!
//! Parses and evaluates binary templates producing a [`TemplateResult`] tree.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("parse error at line {line}: {msg}")]
    Parse { line: usize, msg: String },
    #[error("type error: {0}")]
    TypeError(String),
    #[error("undefined type: {0}")]
    UndefinedType(String),
    #[error("undefined variable: {0}")]
    UndefinedVariable(String),
    #[error("assertion failed at offset {offset}: {msg}")]
    AssertionFailed { offset: u64, msg: String },
    #[error("end of data at offset {0}")]
    EndOfData(u64),
    #[error("loop limit exceeded")]
    LoopLimitExceeded,
}

// ---------------------------------------------------------------------------
// TypeDef
// ---------------------------------------------------------------------------

/// A type defined in a template (struct, typedef, or local).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeDef {
    /// A primitive type.
    Primitive { name: String, size: usize },
    /// A struct type.
    Struct {
        name: String,
        fields: Vec<StructField>,
    },
    /// A typedef alias.
    Typedef { name: String, target: String },
    /// A local variable (not a type, but stored in the same namespace).
    Local { name: String, type_name: String },
}

/// A field within a struct typedef.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub type_name: String,
    pub array_count: Option<usize>,
    pub comment: String,
}

/// Split on the first top-level comma, ignoring commas inside string literals or nested parens/brackets.
fn split_top_level_comma(s: &str) -> Option<(String, String)> {
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in s.char_indices() {
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                return Some((s[..i].to_string(), s[i + 1..].to_string()));
            }
            _ => {}
        }
    }
    None
}

/// Built-in primitive types.
fn builtin_primitives() -> HashMap<String, usize> {
    let mut m = HashMap::new();
    m.insert("byte".to_string(), 1);
    m.insert("char".to_string(), 1);
    m.insert("uchar".to_string(), 1);
    m.insert("short".to_string(), 2);
    m.insert("ushort".to_string(), 2);
    m.insert("uint16".to_string(), 2);
    m.insert("int".to_string(), 4);
    m.insert("uint".to_string(), 4);
    m.insert("uint32".to_string(), 4);
    m.insert("int32".to_string(), 4);
    m.insert("int64".to_string(), 8);
    m.insert("uint64".to_string(), 8);
    m.insert("float".to_string(), 4);
    m.insert("double".to_string(), 8);
    m.insert("DWORD".to_string(), 4);
    m.insert("WORD".to_string(), 2);
    m.insert("BYTE".to_string(), 1);
    m.insert("QWORD".to_string(), 8);
    m
}

// ---------------------------------------------------------------------------
// ControlFlow
// ---------------------------------------------------------------------------

/// Control flow instructions in a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlFlow {
    If {
        condition: String,
        then_body: Vec<TemplateStatement>,
        else_body: Vec<TemplateStatement>,
    },
    While {
        condition: String,
        body: Vec<TemplateStatement>,
    },
    For {
        init: String,
        condition: String,
        increment: String,
        body: Vec<TemplateStatement>,
    },
    Local {
        type_name: String,
        var_name: String,
        value: Option<String>,
    },
}

/// A single statement in a template script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateStatement {
    /// Declare a variable of `type_name` named `var_name`.
    Declare {
        type_name: String,
        var_name: String,
        comment: String,
    },
    /// Array declaration.
    DeclareArray {
        type_name: String,
        var_name: String,
        count: usize,
        comment: String,
    },
    /// Control flow.
    Control(ControlFlow),
    /// Printf (informational message).
    Printf { format: String, args: Vec<String> },
    /// Assert.
    Assert { condition: String, message: String },
    /// Typedef definition.
    DefineTypedef(TypeDef),
}

// ---------------------------------------------------------------------------
// TemplateScript
// ---------------------------------------------------------------------------

/// A parsed 010 Editor-style template.
#[derive(Debug, Clone, Default)]
pub struct TemplateScript {
    pub name: String,
    pub statements: Vec<TemplateStatement>,
    pub source: String,
}

impl TemplateScript {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn add_statement(&mut self, stmt: TemplateStatement) {
        self.statements.push(stmt);
    }

    /// Simplified parser for a 010-style template.
    /// Recognizes: `type_name var_name;`, `typedef struct { ... } Name;`,
    /// `local type var = value;`, `Printf(...)`, `Assert(...)`.
    ///
    /// # Errors
    /// Returns [`TemplateError::Parse`] on syntax errors.
    pub fn parse(source: &str, name: impl Into<String>) -> Result<Self, TemplateError> {
        let mut script = Self::new(name);
        script.source = source.to_string();
        for (lineno, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if let Some(stmt) = Self::try_parse_line(trimmed, lineno + 1)? {
                script.statements.push(stmt);
            }
        }
        Ok(script)
    }

    fn try_parse_line(
        line: &str,
        lineno: usize,
    ) -> Result<Option<TemplateStatement>, TemplateError> {
        let line = line.trim_end_matches(';').trim();
        if line.is_empty() {
            return Ok(None);
        }

        // Printf(...)
        if line.starts_with("Printf(") || line.starts_with("printf(") {
            let inner = line
                .trim_start_matches("Printf(")
                .trim_start_matches("printf(")
                .trim_end_matches(')');
            let mut format = inner.trim().to_string();
            let mut args: Vec<String> = Vec::new();
            let s = inner.trim_start();
            if s.starts_with('"') {
                let bytes = s.as_bytes();
                let mut end_quote: Option<usize> = None;
                let mut i = 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'"' {
                        end_quote = Some(i);
                        break;
                    }
                    i += 1;
                }
                if let Some(eq) = end_quote {
                    format = s[..=eq].to_string();
                    let rest = s[eq + 1..].trim_start();
                    if let Some(rest) = rest.strip_prefix(',') {
                        args = rest
                            .split(',')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect();
                    }
                }
            }
            return Ok(Some(TemplateStatement::Printf { format, args }));
        }

        // Assert(cond, msg)
        if line.starts_with("Assert(") || line.starts_with("assert(") {
            let inner = line
                .trim_start_matches("Assert(")
                .trim_start_matches("assert(")
                .trim_end_matches(')');
            let (cond, msg) = split_top_level_comma(inner)
                .unwrap_or((inner.to_string(), "\"assertion failed\"".to_string()));
            let (cond, msg) = (cond.as_str(), msg.as_str());
            return Ok(Some(TemplateStatement::Assert {
                condition: cond.trim().to_string(),
                message: msg.trim().to_string(),
            }));
        }

        // local type var = value
        if let Some(rest) = line.strip_prefix("local ") {
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                let type_name = parts[0].to_string();
                let rest_after_type = rest[parts[0].len()..].trim_start();
                let (var_name, value) = if let Some((n, v)) = rest_after_type.split_once('=') {
                    (n.trim().to_string(), Some(v.trim().to_string()))
                } else {
                    (rest_after_type.trim().to_string(), None)
                };
                return Ok(Some(TemplateStatement::Control(ControlFlow::Local {
                    type_name,
                    var_name,
                    value,
                })));
            }
        }

        // type_name var_name [array_count]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let type_name = parts[0].to_string();
            let var_name = parts[1].trim_end_matches(';').to_string();
            // Check for array: `int arr[4]`
            if let Some((base_name, count_str)) = var_name.split_once('[') {
                let count_str = count_str.trim_end_matches(']');
                let count = count_str.parse::<usize>().unwrap_or(1);
                return Ok(Some(TemplateStatement::DeclareArray {
                    type_name,
                    var_name: base_name.to_string(),
                    count,
                    comment: String::new(),
                }));
            }
            return Ok(Some(TemplateStatement::Declare {
                type_name,
                var_name,
                comment: String::new(),
            }));
        }

        Err(TemplateError::Parse {
            line: lineno,
            msg: format!("unrecognized statement: {line}"),
        })
    }
}

// ---------------------------------------------------------------------------
// TemplateValue
// ---------------------------------------------------------------------------

/// A value parsed from the data by the template engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedField {
    pub name: String,
    pub type_name: String,
    pub offset: u64,
    pub size: usize,
    pub raw_bytes: Vec<u8>,
    pub display_value: String,
    pub comment: String,
    pub children: Vec<ParsedField>,
}

impl ParsedField {
    fn from_primitive(
        name: String,
        type_name: String,
        offset: u64,
        data: &[u8],
        size: usize,
    ) -> Self {
        let raw_bytes = data
            .get(offset as usize..(offset as usize + size).min(data.len()))
            .unwrap_or(&[])
            .to_vec();
        let display_value = match size {
            1 => format!(
                "0x{:02X} ({})",
                raw_bytes.first().copied().unwrap_or(0),
                raw_bytes.first().copied().unwrap_or(0)
            ),
            2 => {
                let v = u16::from_le_bytes([
                    raw_bytes.first().copied().unwrap_or(0),
                    raw_bytes.get(1).copied().unwrap_or(0),
                ]);
                format!("0x{v:04X} ({v})")
            }
            4 => {
                if raw_bytes.len() >= 4 {
                    let v = u32::from_le_bytes(raw_bytes[0..4].try_into().unwrap());
                    format!("0x{v:08X} ({v})")
                } else {
                    String::new()
                }
            }
            8 => {
                if raw_bytes.len() >= 8 {
                    let v = u64::from_le_bytes(raw_bytes[0..8].try_into().unwrap());
                    format!("0x{v:016X} ({v})")
                } else {
                    String::new()
                }
            }
            _ => format!("{raw_bytes:02X?}"),
        };
        ParsedField {
            name,
            type_name,
            offset,
            size,
            raw_bytes,
            display_value,
            comment: String::new(),
            children: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// TemplateResult
// ---------------------------------------------------------------------------

/// The result of applying a template to binary data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateResult {
    pub template_name: String,
    pub fields: Vec<ParsedField>,
    pub messages: Vec<String>,
    pub assertion_errors: Vec<String>,
    pub bytes_consumed: u64,
}

impl TemplateResult {
    #[must_use]
    pub fn field_by_name(&self, name: &str) -> Option<&ParsedField> {
        self.fields.iter().find(|f| f.name == name)
    }

    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.bytes_consumed
    }
}

impl fmt::Display for TemplateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TemplateResult({}: {} fields, {} bytes)",
            self.template_name,
            self.fields.len(),
            self.bytes_consumed
        )
    }
}

// ---------------------------------------------------------------------------
// TemplateInterpreter
// ---------------------------------------------------------------------------

/// Evaluates a [`TemplateScript`] against binary data.
pub struct TemplateInterpreter {
    pub data: Vec<u8>,
    pub offset: u64,
    primitives: HashMap<String, usize>,
    typedefs: HashMap<String, TypeDef>,
    vars: HashMap<String, i64>,
    pub loop_limit: usize,
}

impl TemplateInterpreter {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            offset: 0,
            primitives: builtin_primitives(),
            typedefs: HashMap::new(),
            vars: HashMap::new(),
            loop_limit: 10_000,
        }
    }

    /// Run the template and return a [`TemplateResult`].
    ///
    /// # Errors
    /// Returns [`TemplateError`] on parse/evaluation failures.
    pub fn run(&mut self, script: &TemplateScript) -> Result<TemplateResult, TemplateError> {
        let mut result = TemplateResult {
            template_name: script.name.clone(),
            ..Default::default()
        };
        for stmt in &script.statements {
            self.exec_stmt(stmt, &mut result)?;
        }
        result.bytes_consumed = self.offset;
        Ok(result)
    }

    fn exec_stmt(
        &mut self,
        stmt: &TemplateStatement,
        result: &mut TemplateResult,
    ) -> Result<(), TemplateError> {
        match stmt {
            TemplateStatement::Declare {
                type_name,
                var_name,
                comment,
            } => {
                let field = self.read_primitive_or_struct(var_name, type_name, comment)?;
                result.fields.push(field);
            }
            TemplateStatement::DeclareArray {
                type_name,
                var_name,
                count,
                comment,
            } => {
                for i in 0..*count {
                    let name = format!("{var_name}[{i}]");
                    let field = self.read_primitive_or_struct(&name, type_name, comment)?;
                    result.fields.push(field);
                }
            }
            TemplateStatement::Printf { format, .. } => {
                result.messages.push(format.clone());
            }
            TemplateStatement::Assert { condition, message } => {
                let passed = self.eval_condition(condition);
                if !passed {
                    result
                        .assertion_errors
                        .push(format!("{message} (at offset {})", self.offset));
                }
            }
            TemplateStatement::Control(ctrl) => {
                self.exec_control(ctrl, result)?;
            }
            TemplateStatement::DefineTypedef(td) => {
                self.typedefs.insert(td_name(td).to_string(), td.clone());
            }
        }
        Ok(())
    }

    fn exec_control(
        &mut self,
        ctrl: &ControlFlow,
        result: &mut TemplateResult,
    ) -> Result<(), TemplateError> {
        match ctrl {
            ControlFlow::Local {
                type_name,
                var_name,
                value,
            } => {
                let v = value
                    .as_deref()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let _ = type_name;
                self.vars.insert(var_name.clone(), v);
            }
            ControlFlow::If {
                condition,
                then_body,
                else_body,
            } => {
                let body = if self.eval_condition(condition) {
                    then_body
                } else {
                    else_body
                };
                for stmt in body.iter() {
                    self.exec_stmt(stmt, result)?;
                }
            }
            ControlFlow::While { condition, body } => {
                let mut iters = 0;
                while self.eval_condition(condition) {
                    if iters >= self.loop_limit {
                        return Err(TemplateError::LoopLimitExceeded);
                    }
                    for stmt in body {
                        self.exec_stmt(stmt, result)?;
                    }
                    iters += 1;
                }
            }
            ControlFlow::For {
                init,
                condition,
                increment,
                body,
            } => {
                // Very simplified: parse `i = 0` → set var.
                if let Some((name, val)) = init.split_once('=') {
                    let v = val.trim().parse::<i64>().unwrap_or(0);
                    self.vars.insert(name.trim().to_string(), v);
                }
                let mut iters = 0;
                while self.eval_condition(condition) {
                    if iters >= self.loop_limit {
                        return Err(TemplateError::LoopLimitExceeded);
                    }
                    for stmt in body {
                        self.exec_stmt(stmt, result)?;
                    }
                    // Increment: parse `i++` or `i += 1`.
                    self.eval_increment(increment);
                    iters += 1;
                }
            }
        }
        Ok(())
    }

    fn read_primitive_or_struct(
        &mut self,
        name: &str,
        type_name: &str,
        comment: &str,
    ) -> Result<ParsedField, TemplateError> {
        if let Some(&size) = self.primitives.get(type_name) {
            let end = (self.offset as usize).checked_add(size)
                .ok_or(TemplateError::EndOfData(self.offset))?;
            if end > self.data.len() {
                return Err(TemplateError::EndOfData(self.offset));
            }
            let mut field = ParsedField::from_primitive(
                name.to_string(),
                type_name.to_string(),
                self.offset,
                &self.data,
                size,
            );
            field.comment = comment.to_string();
            self.offset += size as u64;
            Ok(field)
        } else {
            Err(TemplateError::UndefinedType(type_name.to_string()))
        }
    }

    fn eval_condition(&self, cond: &str) -> bool {
        let cond = cond.trim();
        // Simple: `varname < value`, `varname == value`, etc.
        for op in &["<=", ">=", "!=", "==", "<", ">"] {
            if let Some((lhs, rhs)) = cond.split_once(op) {
                let l = self.eval_expr_int(lhs.trim());
                let r = self.eval_expr_int(rhs.trim());
                return match *op {
                    "<" => l < r,
                    "<=" => l <= r,
                    ">" => l > r,
                    ">=" => l >= r,
                    "==" => l == r,
                    "!=" => l != r,
                    _ => false,
                };
            }
        }
        // Try as bool var.
        if let Ok(v) = cond.parse::<i64>() {
            return v != 0;
        }
        self.vars.get(cond).copied().unwrap_or(0) != 0
    }

    fn eval_expr_int(&self, expr: &str) -> i64 {
        if let Ok(v) = expr.parse::<i64>() {
            return v;
        }
        if let Some(v) = self.vars.get(expr) {
            return *v;
        }
        0
    }

    fn eval_increment(&mut self, inc: &str) {
        let inc = inc.trim();
        if let Some(name) = inc.strip_suffix("++") {
            let v = self.vars.entry(name.trim().to_string()).or_insert(0);
            *v += 1;
        } else if let Some(rest) = inc.strip_suffix("--") {
            let v = self.vars.entry(rest.trim().to_string()).or_insert(0);
            *v -= 1;
        } else if let Some((name, val)) = inc.split_once("+=") {
            let delta = val.trim().parse::<i64>().unwrap_or(1);
            let v = self.vars.entry(name.trim().to_string()).or_insert(0);
            *v += delta;
        }
    }
}

fn td_name(td: &TypeDef) -> &str {
    match td {
        TypeDef::Primitive { name, .. }
        | TypeDef::Struct { name, .. }
        | TypeDef::Typedef { name, .. }
        | TypeDef::Local { name, .. } => name,
    }
}

// ---------------------------------------------------------------------------
// TemplateEngine (high-level)
// ---------------------------------------------------------------------------

/// High-level template engine combining parsing and interpretation.
pub struct TemplateEngine {
    pub data: Vec<u8>,
}

impl TemplateEngine {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Apply a template source string to the data.
    ///
    /// # Errors
    /// Returns [`TemplateError`] on syntax or evaluation errors.
    pub fn apply(
        &self,
        template_source: &str,
        name: &str,
    ) -> Result<TemplateResult, TemplateError> {
        let script = TemplateScript::parse(template_source, name)?;
        let mut interpreter = TemplateInterpreter::new(self.data.clone());
        interpreter.run(&script)
    }

    /// Apply a pre-parsed template script.
    ///
    /// # Errors
    /// Returns [`TemplateError`] on evaluation errors.
    pub fn apply_script(&self, script: &TemplateScript) -> Result<TemplateResult, TemplateError> {
        let mut interpreter = TemplateInterpreter::new(self.data.clone());
        interpreter.run(script)
    }
}

// ---------------------------------------------------------------------------
// Printf / Assert helpers
// ---------------------------------------------------------------------------

/// Simple printf-style message formatter.
#[must_use]
pub fn format_printf(fmt: &str, args: &[&str]) -> String {
    let mut result = fmt.to_string();
    for arg in args {
        if let Some(pos) = result.find("%s") {
            result.replace_range(pos..pos + 2, arg);
        } else if let Some(pos) = result.find("%d") {
            result.replace_range(pos..pos + 2, arg);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    // ── TemplateScript::parse ─────────────────────────────────────────────

    #[test]
    fn parse_simple_declare() {
        let src = "uint magic;\nbyte version;";
        let s = TemplateScript::parse(src, "test").unwrap();
        assert_eq!(s.statements.len(), 2);
    }

    #[test]
    fn parse_printf() {
        let src = "Printf(\"hello\");";
        let s = TemplateScript::parse(src, "t").unwrap();
        assert_eq!(s.statements.len(), 1);
        assert!(matches!(s.statements[0], TemplateStatement::Printf { .. }));
    }

    #[test]
    fn parse_assert() {
        let src = "Assert(magic == 0xDEAD, \"bad magic\");";
        let s = TemplateScript::parse(src, "t").unwrap();
        assert!(matches!(s.statements[0], TemplateStatement::Assert { .. }));
    }

    #[test]
    fn parse_local() {
        let src = "local int i = 0;";
        let s = TemplateScript::parse(src, "t").unwrap();
        assert!(matches!(
            s.statements[0],
            TemplateStatement::Control(ControlFlow::Local { .. })
        ));
    }

    #[test]
    fn parse_array() {
        let src = "byte header[4];";
        let s = TemplateScript::parse(src, "t").unwrap();
        assert!(matches!(
            s.statements[0],
            TemplateStatement::DeclareArray { count: 4, .. }
        ));
    }

    // ── TemplateInterpreter ───────────────────────────────────────────────

    #[test]
    fn interpret_uint() {
        let data = make_data(&[0x01, 0x00, 0x00, 0x00]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("uint value;", "t").unwrap();
        assert_eq!(result.fields.len(), 1);
        assert_eq!(result.fields[0].name, "value");
        assert_eq!(result.fields[0].size, 4);
        assert_eq!(result.bytes_consumed, 4);
    }

    #[test]
    fn interpret_byte() {
        let data = make_data(&[0xAB, 0xCD]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("byte b1;\nbyte b2;", "t").unwrap();
        assert_eq!(result.fields.len(), 2);
        assert_eq!(result.bytes_consumed, 2);
    }

    #[test]
    fn interpret_array() {
        let data = make_data(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("byte header[4];", "t").unwrap();
        assert_eq!(result.fields.len(), 4);
    }

    #[test]
    fn interpret_printf_adds_message() {
        let data = make_data(&[]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("Printf(\"hello world\");", "t").unwrap();
        assert!(result.messages.contains(&"\"hello world\"".to_string()));
    }

    #[test]
    fn interpret_end_of_data_error() {
        let data = make_data(&[0x01]); // only 1 byte
        let engine = TemplateEngine::new(data);
        let err = engine.apply("uint too_big;", "t"); // needs 4 bytes
        assert!(matches!(err, Err(TemplateError::EndOfData(_))));
    }

    #[test]
    fn interpret_undefined_type_error() {
        let data = make_data(&[1, 2, 3, 4]);
        let engine = TemplateEngine::new(data);
        let err = engine.apply("MyCustomType x;", "t");
        assert!(matches!(err, Err(TemplateError::UndefinedType(_))));
    }

    #[test]
    fn interpret_local_variable() {
        let data = make_data(&[0x01]);
        let engine = TemplateEngine::new(data);
        // local doesn't consume data
        let result = engine.apply("local int i = 5;\nbyte b;", "t").unwrap();
        assert_eq!(result.fields.len(), 1);
        assert_eq!(result.bytes_consumed, 1);
    }

    #[test]
    fn interpret_ushort() {
        let data = make_data(&[0xFF, 0x00]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("ushort v;", "t").unwrap();
        assert_eq!(result.fields[0].size, 2);
    }

    #[test]
    fn interpret_result_field_by_name() {
        let data = make_data(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let engine = TemplateEngine::new(data);
        let result = engine.apply("uint magic;", "t").unwrap();
        let f = result.field_by_name("magic");
        assert!(f.is_some());
    }

    #[test]
    fn result_display() {
        let r = TemplateResult {
            template_name: "pe".to_string(),
            ..Default::default()
        };
        let s = r.to_string();
        assert!(s.contains("pe"));
    }

    // ── TypeDef ───────────────────────────────────────────────────────────

    #[test]
    fn typedef_primitive() {
        let td = TypeDef::Primitive {
            name: "DWORD".to_string(),
            size: 4,
        };
        assert_eq!(td_name(&td), "DWORD");
    }

    // ── format_printf ─────────────────────────────────────────────────────

    #[test]
    fn printf_substitution() {
        let s = format_printf("Hello %s!", &["world"]);
        assert_eq!(s, "Hello world!");
    }

    #[test]
    fn printf_no_args() {
        let s = format_printf("Hello!", &[]);
        assert_eq!(s, "Hello!");
    }

    // ── ControlFlow: if ───────────────────────────────────────────────────

    #[test]
    fn interpret_if_taken() {
        let data = make_data(&[1, 2, 3, 4, 5]);
        let mut interp = TemplateInterpreter::new(data);
        interp.vars.insert("flag".to_string(), 1);
        let mut result = TemplateResult::default();
        let ctrl = ControlFlow::If {
            condition: "flag == 1".to_string(),
            then_body: vec![TemplateStatement::Declare {
                type_name: "byte".to_string(),
                var_name: "x".to_string(),
                comment: String::new(),
            }],
            else_body: vec![],
        };
        interp.exec_control(&ctrl, &mut result).unwrap();
        assert_eq!(result.fields.len(), 1);
    }

    #[test]
    fn interpret_if_not_taken() {
        let data = make_data(&[1, 2]);
        let mut interp = TemplateInterpreter::new(data);
        interp.vars.insert("flag".to_string(), 0);
        let mut result = TemplateResult::default();
        let ctrl = ControlFlow::If {
            condition: "flag == 1".to_string(),
            then_body: vec![TemplateStatement::Declare {
                type_name: "byte".to_string(),
                var_name: "x".to_string(),
                comment: String::new(),
            }],
            else_body: vec![TemplateStatement::Declare {
                type_name: "byte".to_string(),
                var_name: "y".to_string(),
                comment: String::new(),
            }],
        };
        interp.exec_control(&ctrl, &mut result).unwrap();
        assert_eq!(result.fields.len(), 1);
        assert_eq!(result.fields[0].name, "y");
    }

    // ── ParsedField display ───────────────────────────────────────────────

    #[test]
    fn parsed_field_display_value_byte() {
        let f = ParsedField::from_primitive("b".to_string(), "byte".to_string(), 0, &[0xAB], 1);
        assert!(f.display_value.contains("0xAB"));
    }

    #[test]
    fn builtin_primitives_have_dword() {
        assert!(builtin_primitives().contains_key("DWORD"));
        assert_eq!(builtin_primitives()["DWORD"], 4);
    }
}
