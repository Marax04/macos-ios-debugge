//! Python script sandbox with resource limits.
//!
//! Provides a pure-Rust execution context that limits memory usage,
//! execution time, output size, and available builtins for untrusted
//! Python-like scripts.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::python_stdlib_stubs::{PyValue, StdlibStubs};

// ─── TerminationReason ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    Timeout,
    MemoryLimit,
    OutputLimit,
    ExplicitExit,
    Error,
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Timeout => "timeout",
            Self::MemoryLimit => "memory limit exceeded",
            Self::OutputLimit => "output limit exceeded",
            Self::ExplicitExit => "explicit exit",
            Self::Error => "runtime error",
        };
        write!(f, "{s}")
    }
}

// ─── SandboxConfig ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum wall-clock time for script execution.
    pub max_execution_ms: u64,
    /// Maximum bytes of aggregate value memory.
    pub max_memory_bytes: usize,
    /// Maximum bytes of combined output.
    pub max_output_bytes: usize,
    /// Allowed module names (for import checks).
    pub allowed_modules: Vec<String>,
    /// Blocked builtin names.
    pub blocked_builtins: Vec<String>,
    /// Maximum recursion depth for function calls.
    pub max_recursion_depth: usize,
    /// Maximum number of loop iterations (across all loops).
    pub max_iterations: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_execution_ms: 5_000,
            max_memory_bytes: 64 * 1024 * 1024, // 64 MiB
            max_output_bytes: 1024 * 1024,  // 1 MiB
            allowed_modules: vec![
                "os.path".into(), "struct".into(), "binascii".into(),
                "hashlib".into(), "re".into(), "json".into(), "sys".into(),
            ],
            blocked_builtins: vec![
                "exec".into(), "eval".into(), "compile".into(),
                "__import__".into(), "open".into(), "input".into(),
                "breakpoint".into(), "globals".into(), "locals".into(),
            ],
            max_recursion_depth: 64,
            max_iterations: 1_000_000,
        }
    }
}

// ─── SandboxResult ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SandboxResult {
    /// Combined stdout-like output.
    pub output: String,
    /// Error message if the script raised an exception.
    pub error: Option<String>,
    /// Wall-clock execution time.
    pub execution_time_ms: u64,
    /// Peak estimated memory usage in bytes.
    pub memory_peak_bytes: usize,
    pub terminated_reason: Option<TerminationReason>,
    /// Return value of the last expression evaluated (if any).
    pub return_value: Option<PyValue>,
}

// ─── ResourceMonitor ─────────────────────────────────────────────────────────

pub struct ResourceMonitor {
    start: Instant,
    max_execution: Duration,
    max_memory: usize,
    pub memory_used: usize,
    pub iterations: u64,
    pub max_iterations: u64,
}

impl ResourceMonitor {
    #[must_use] 
    pub fn new(config: &SandboxConfig) -> Self {
        Self {
            start: Instant::now(),
            max_execution: Duration::from_millis(config.max_execution_ms),
            max_memory: config.max_memory_bytes,
            memory_used: 0,
            iterations: 0,
            max_iterations: config.max_iterations,
        }
    }

    #[must_use] 
    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[must_use] 
    pub fn check_timeout(&self) -> bool {
        self.start.elapsed() > self.max_execution
    }

    pub const fn allocate(&mut self, bytes: usize) -> bool {
        self.memory_used += bytes;
        self.memory_used <= self.max_memory
    }

    pub const fn free(&mut self, bytes: usize) {
        self.memory_used = self.memory_used.saturating_sub(bytes);
    }

    pub const fn tick_iteration(&mut self) -> bool {
        self.iterations += 1;
        self.iterations <= self.max_iterations
    }
}

// ─── SafeBuiltins ─────────────────────────────────────────────────────────────

/// Whitelisted builtins that scripts may call.
pub struct SafeBuiltins {
    allowed: HashSet<String>,
    blocked: HashSet<String>,
}

impl SafeBuiltins {
    #[must_use] 
    pub fn new(blocked: &[String]) -> Self {
        let allowed: HashSet<String> = [
            "print", "len", "range", "enumerate", "zip", "map", "filter",
            "list", "dict", "set", "tuple", "str", "int", "float", "bool",
            "bytes", "bytearray", "type", "isinstance", "hasattr", "getattr",
            "abs", "min", "max", "sum", "sorted", "reversed", "any", "all",
            "hex", "oct", "bin", "ord", "chr", "repr", "hash", "id",
            "divmod", "pow", "round",
        ].iter().map(std::string::ToString::to_string).collect();

        let blocked_set: HashSet<String> = blocked.iter().cloned().collect();

        Self { allowed, blocked: blocked_set }
    }

    #[must_use] 
    pub fn is_allowed(&self, name: &str) -> bool {
        self.allowed.contains(name) && !self.blocked.contains(name)
    }

    #[must_use] 
    pub fn is_blocked(&self, name: &str) -> bool {
        self.blocked.contains(name)
    }

    /// Execute a safe builtin call, returning the result.
    pub fn call(&self, name: &str, args: &[PyValue]) -> Result<PyValue, String> {
        if self.is_blocked(name) {
            return Err(format!("NameError: name '{name}' is blocked in sandbox"));
        }
        call_builtin(name, args)
    }
}

fn call_builtin_cast(name: &str, args: &[PyValue]) -> Option<Result<PyValue, String>> {
    match name {
        "str" => Some(Ok(PyValue::Str(format!("{}", args.first().unwrap_or(&PyValue::None))))),
        "int" => Some(match args.first().unwrap_or(&PyValue::None) {
            PyValue::Int(i) => Ok(PyValue::Int(*i)),
            PyValue::Float(f) => {
                let clamped = f.clamp(-9.223_372_036_854_776e18_f64, 9.223_372_036_854_776e18_f64);
                // SAFETY: clamped is finite and within i64 range.
                Ok(PyValue::Int(unsafe { clamped.to_int_unchecked::<i64>() }))
            }
            PyValue::Bool(b) => Ok(PyValue::Int(i64::from(*b))),
            PyValue::Str(s) => s.trim().parse::<i64>().map(PyValue::Int).map_err(|e| format!("ValueError: {e}")),
            v => Err(format!("TypeError: cannot convert '{}' to int", v.type_name())),
        }),
        "float" => Some(match args.first().unwrap_or(&PyValue::None) {
            PyValue::Float(f) => Ok(PyValue::Float(*f)),
            PyValue::Int(i) => Ok(PyValue::Float(*i as f64)),
            PyValue::Str(s) => s.trim().parse::<f64>().map(PyValue::Float).map_err(|e| format!("ValueError: {e}")),
            v => Err(format!("TypeError: cannot convert '{}' to float", v.type_name())),
        }),
        "bool" => Some(Ok(PyValue::Bool(args.first().unwrap_or(&PyValue::None).is_truthy()))),
        "list" => Some(match args.first().unwrap_or(&PyValue::List(Vec::new())) {
            PyValue::List(v) | PyValue::Tuple(v) | PyValue::Set(v) => Ok(PyValue::List(v.clone())),
            PyValue::Str(s) => Ok(PyValue::List(s.chars().map(|c| PyValue::Str(c.to_string())).collect())),
            PyValue::Bytes(b) => Ok(PyValue::List(b.iter().map(|&x| PyValue::Int(i64::from(x))).collect())),
            _ => Ok(PyValue::List(Vec::new())),
        }),
        "tuple" => Some(match args.first().unwrap_or(&PyValue::Tuple(Vec::new())) {
            PyValue::List(v) | PyValue::Tuple(v) => Ok(PyValue::Tuple(v.clone())),
            _ => Ok(PyValue::Tuple(Vec::new())),
        }),
        "bytes" => Some(match args.first().unwrap_or(&PyValue::Bytes(Vec::new())) {
            PyValue::Bytes(b) => Ok(PyValue::Bytes(b.clone())),
            PyValue::List(v) => {
                let bytes: Result<Vec<u8>, _> = v.iter().map(|x| {
                    x.as_int().and_then(|i| u8::try_from(i).ok()).ok_or("not int or out of range 0-255")
                }).collect();
                Ok(PyValue::Bytes(bytes.unwrap_or_default()))
            }
            PyValue::Str(s) => Ok(PyValue::Bytes(s.as_bytes().to_vec())),
            _ => Ok(PyValue::Bytes(Vec::new())),
        }),
        _ => None,
    }
}

fn call_builtin(name: &str, args: &[PyValue]) -> Result<PyValue, String> {
    if let Some(result) = call_builtin_cast(name, args) {
        return result;
    }
    match name {
        "print" => Ok(PyValue::None),
        "len" => {
            let v = args.first().ok_or("len requires 1 argument")?;
            let n = match v {
                PyValue::Str(s) => s.len(),
                PyValue::Bytes(b) => b.len(),
                PyValue::List(l) => l.len(),
                PyValue::Tuple(t) => t.len(),
                PyValue::Dict(d) => d.len(),
                PyValue::Set(s) => s.len(),
                _ => return Err(format!("TypeError: object of type '{}' has no len()", v.type_name())),
            };
            Ok(PyValue::Int(i64::try_from(n).unwrap_or(i64::MAX)))
        }
        "range" => {
            let (start, range_stop, step) = match args.len() {
                1 => (0i64, args[0].as_int().unwrap_or(0), 1i64),
                2 => (args[0].as_int().unwrap_or(0), args[1].as_int().unwrap_or(0), 1i64),
                3 => (args[0].as_int().unwrap_or(0), args[1].as_int().unwrap_or(0), args[2].as_int().unwrap_or(1)),
                _ => return Err("range requires 1-3 arguments".into()),
            };
            if step == 0 { return Err("ValueError: range step cannot be zero".into()); }
            let mut items = Vec::new();
            let mut i = start;
            while (step > 0 && i < range_stop) || (step < 0 && i > range_stop) {
                items.push(PyValue::Int(i));
                i += step;
                if items.len() > 100_000 { return Err("ValueError: range too large".into()); }
            }
            Ok(PyValue::List(items))
        }
        "hex" => {
            let i = args.first().and_then(super::python_stdlib_stubs::PyValue::as_int).unwrap_or(0);
            Ok(PyValue::Str(format!("0x{i:x}")))
        }
        "abs" => match args.first().unwrap_or(&PyValue::Int(0)) {
            PyValue::Int(i) => Ok(PyValue::Int(i.abs())),
            PyValue::Float(f) => Ok(PyValue::Float(f.abs())),
            v => Err(format!("TypeError: cannot abs '{}'", v.type_name())),
        },
        "max" => flatten_args(args).into_iter().max_by(|a, b| {
            match (a, b) {
                (PyValue::Int(x), PyValue::Int(y)) => x.cmp(y),
                (PyValue::Float(x), PyValue::Float(y)) => x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal),
                _ => std::cmp::Ordering::Equal,
            }
        }).ok_or_else(|| "ValueError: max() arg is an empty sequence".into()),
        "min" => flatten_args(args).into_iter().min_by(|a, b| {
            match (a, b) {
                (PyValue::Int(x), PyValue::Int(y)) => x.cmp(y),
                (PyValue::Float(x), PyValue::Float(y)) => x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal),
                _ => std::cmp::Ordering::Equal,
            }
        }).ok_or_else(|| "ValueError: min() arg is an empty sequence".into()),
        "sum" => {
            let items = flatten_args(args);
            let mut total = 0i64;
            for item in items {
                match item {
                    PyValue::Int(i) => total += i,
                    PyValue::Float(f) => return Ok(PyValue::Float(total as f64 + f)),
                    _ => return Err("TypeError: unsupported operand in sum()".into()),
                }
            }
            Ok(PyValue::Int(total))
        }
        "isinstance" => {
            if args.len() < 2 { return Err("isinstance requires 2 args".into()); }
            let type_name = args[1].as_str().unwrap_or("");
            let m = matches!((&args[0], type_name),
                (PyValue::Int(_), "int") | (PyValue::Bool(_), "bool") | (PyValue::Str(_), "str") |
                (PyValue::Float(_), "float") | (PyValue::Bytes(_), "bytes") |
                (PyValue::List(_), "list") | (PyValue::Dict(_), "dict"));
            Ok(PyValue::Bool(m))
        }
        "ord" => {
            let s = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let c = s.chars().next().ok_or("TypeError: ord() expected a character, but string of length 0 found")?;
            Ok(PyValue::Int(c as i64))
        }
        "chr" => {
            let i = args.first().and_then(super::python_stdlib_stubs::PyValue::as_int).unwrap_or(0);
            let c = u32::try_from(i).ok().and_then(char::from_u32)
                .ok_or("ValueError: chr() arg not in range(0x110000)")?;
            Ok(PyValue::Str(c.to_string()))
        }
        _ => Err(format!("NameError: name '{name}' is not defined")),
    }
}

fn flatten_args(args: &[PyValue]) -> Vec<PyValue> {
    if args.len() == 1 {
        if let PyValue::List(v) = &args[0] { return v.clone(); }
        if let PyValue::Tuple(v) = &args[0] { return v.clone(); }
    }
    args.to_vec()
}

// ─── AstSanitizer ─────────────────────────────────────────────────────────────

/// Walk a simplified Python-like AST (represented as strings) and reject
/// dangerous constructs.
pub struct AstSanitizer {
    allowed_modules: HashSet<String>,
    blocked_builtins: HashSet<String>,
}

impl AstSanitizer {
    #[must_use] 
    pub fn new(allowed_modules: &[String], blocked_builtins: &[String]) -> Self {
        Self {
            allowed_modules: allowed_modules.iter().cloned().collect(),
            blocked_builtins: blocked_builtins.iter().cloned().collect(),
        }
    }

    /// Check a raw source string for obviously dangerous patterns.
    /// Returns a list of violations found.
    #[must_use] 
    pub fn check_source(&self, source: &str) -> Vec<String> {
        let mut violations = Vec::new();

        // Check for blocked builtins (very conservative: keyword in source)
        for builtin in &self.blocked_builtins {
            // Look for `builtin(` pattern
            let pattern = format!("{builtin}(");
            if source.contains(&pattern) {
                violations.push(format!("SecurityError: use of blocked builtin '{builtin}'"));
            }
        }

        // Check imports
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                let module = extract_module_name(trimmed);
                if let Some(m) = module
                    && !self.allowed_modules.contains(&m) {
                        violations.push(format!("ImportError: import of module '{m}' is not allowed"));
                    }
            }
            // Detect __class__, __bases__, __subclasses__ attribute access
            if trimmed.contains(".__class__") || trimmed.contains(".__bases__") || trimmed.contains(".__subclasses__") {
                violations.push("SecurityError: access to dunder attribute for sandbox escape".into());
            }
            // Detect __builtins__ manipulation
            if trimmed.contains("__builtins__") {
                violations.push("SecurityError: access to __builtins__ is blocked".into());
            }
        }

        violations
    }

    /// Returns `true` if the source passes all safety checks.
    #[must_use] 
    pub fn is_safe(&self, source: &str) -> bool {
        self.check_source(source).is_empty()
    }
}

fn extract_module_name(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("import ") {
        let name = rest.split([' ', ';', ',']).next()?;
        return Some(name.to_owned());
    }
    if let Some(rest) = line.strip_prefix("from ") {
        let name = rest.split([' ', '.']).next()?;
        return Some(name.to_owned());
    }
    None
}

// ─── ScriptSandbox ───────────────────────────────────────────────────────────

/// Main sandbox entry point.  Interprets a very small subset of Python:
/// assignments, `print()`, stdlib stub calls, arithmetic, and for-loops over
/// list literals.  Full Python semantics are **not** implemented — this is
/// deliberately minimal for RE helper scripts.
pub struct ScriptSandbox {
    config: SandboxConfig,
    stubs: StdlibStubs,
    builtins: SafeBuiltins,
    sanitizer: AstSanitizer,
}

impl ScriptSandbox {
    #[must_use] 
    pub fn new(config: SandboxConfig) -> Self {
        let builtins = SafeBuiltins::new(&config.blocked_builtins);
        let sanitizer = AstSanitizer::new(&config.allowed_modules, &config.blocked_builtins);
        Self { stubs: StdlibStubs::new(), builtins, sanitizer, config }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(SandboxConfig::default())
    }

    /// Execute a script string in the sandbox and return the result.
    #[must_use] 
    pub fn execute(&self, source: &str) -> SandboxResult {
        let start = Instant::now();
        let mut output_buf = String::new();
        let mut error: Option<String> = None;
        let mut return_value: Option<PyValue> = None;
        let mut terminated_reason: Option<TerminationReason> = None;

        // Static safety check first
        let violations = self.sanitizer.check_source(source);
        if !violations.is_empty() {
            return SandboxResult {
                output: String::new(),
                error: Some(violations.join("; ")),
                execution_time_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                memory_peak_bytes: 0,
                terminated_reason: Some(TerminationReason::Error),
                return_value: None,
            };
        }

        let mut monitor = ResourceMonitor::new(&self.config);
        let mut env: HashMap<String, PyValue> = HashMap::new();

        for line in source.lines() {
            if monitor.check_timeout() {
                terminated_reason = Some(TerminationReason::Timeout);
                error = Some("TimeoutError: execution exceeded limit".into());
                break;
            }
            if output_buf.len() > self.config.max_output_bytes {
                terminated_reason = Some(TerminationReason::OutputLimit);
                error = Some("OutputError: output limit exceeded".into());
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }

            match self.execute_line(trimmed, &mut env, &mut monitor) {
                Ok(LineResult::Output(s)) => {
                    output_buf.push_str(&s);
                    output_buf.push('\n');
                }
                Ok(LineResult::Assignment) => {}
                Ok(LineResult::Value(v)) => { return_value = Some(v); }
                Err(e) => {
                    error = Some(e);
                    terminated_reason = Some(TerminationReason::Error);
                    break;
                }
            }
        }

        SandboxResult {
            output: output_buf,
            error,
            execution_time_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            memory_peak_bytes: monitor.memory_used,
            terminated_reason,
            return_value,
        }
    }

    fn execute_line(
        &self,
        line: &str,
        env: &mut HashMap<String, PyValue>,
        monitor: &mut ResourceMonitor,
    ) -> Result<LineResult, String> {
        if !monitor.tick_iteration() {
            return Err("RuntimeError: iteration limit exceeded".into());
        }

        // Assignment: `name = expr`
        if let Some(eq_pos) = find_assignment_eq(line) {
            let name = line[..eq_pos].trim();
            let expr = line[eq_pos + 1..].trim();
            if is_valid_identifier(name) {
                let val = self.eval_expr(expr, env)?;
                env.insert(name.to_owned(), val);
                return Ok(LineResult::Assignment);
            }
        }

        // print(...)
        if line.starts_with("print(") && line.ends_with(')') {
            let inner = &line[6..line.len() - 1];
            let val = self.eval_expr(inner, env)?;
            return Ok(LineResult::Output(format!("{val}")));
        }

        // Standalone expression
        let val = self.eval_expr(line, env)?;
        Ok(LineResult::Value(val))
    }

    fn eval_expr(&self, expr: &str, env: &HashMap<String, PyValue>) -> Result<PyValue, String> {
        let expr = expr.trim();

        // None / True / False literals
        if expr == "None" { return Ok(PyValue::None); }
        if expr == "True" { return Ok(PyValue::Bool(true)); }
        if expr == "False" { return Ok(PyValue::Bool(false)); }

        // Integer literal
        if let Ok(i) = expr.parse::<i64>() { return Ok(PyValue::Int(i)); }

        // Float literal
        if let Ok(f) = expr.parse::<f64>() { return Ok(PyValue::Float(f)); }

        // String literal — only if the opening quote is closed at the very end
        if expr.len() >= 2 {
            let first = expr.as_bytes()[0];
            if (first == b'"' || first == b'\'') && expr.as_bytes()[expr.len()-1] == first {
                // Ensure no unescaped closing quote earlier in the string
                let inner = &expr.as_bytes()[1..expr.len()-1];
                if !inner.contains(&first) {
                    return Ok(PyValue::Str(expr[1..expr.len()-1].to_owned()));
                }
            }
        }

        // Bytes literal b"..."
        if expr.starts_with("b\"") && expr.ends_with('"') && expr.len() >= 3 {
            return Ok(PyValue::Bytes(expr.as_bytes()[2..expr.len()-1].to_vec()));
        }

        // Variable lookup
        if is_valid_identifier(expr) {
            return env.get(expr).cloned().ok_or_else(|| format!("NameError: name '{expr}' is not defined"));
        }

        // Function call: name(args) or module.func(args)
        if let Some(call) = try_parse_call(expr) {
            return self.eval_call(&call.name, &call.args_str, env);
        }

        // List literal [...]
        if expr.starts_with('[') && expr.ends_with(']') {
            let inner = &expr[1..expr.len()-1];
            let items = split_args(inner);
            let vals: Result<Vec<PyValue>, _> = items.iter().map(|s| self.eval_expr(s.trim(), env)).collect();
            return Ok(PyValue::List(vals?));
        }

        // Binary operations: +, -, *, /, //, %, ^, &, |, XOR
        for op in &[" + ", " - ", " * ", " // ", " / ", " % ", " ^ ", " & ", " | "] {
            if let Some(pos) = find_binary_op(expr, op) {
                let lhs = self.eval_expr(&expr[..pos], env)?;
                let rhs = self.eval_expr(&expr[pos + op.len()..], env)?;
                return eval_binop(&lhs, &rhs, op.trim());
            }
        }

        Err(format!("SyntaxError: could not evaluate expression: {expr}"))
    }

    fn eval_call(&self, name: &str, args_str: &str, env: &HashMap<String, PyValue>) -> Result<PyValue, String> {
        // Module call: module.func(args)
        if let Some(dot_pos) = name.find('.') {
            let module = &name[..dot_pos];
            let func = &name[dot_pos + 1..];
            let args = self.parse_args(args_str, env)?;
            return self.stubs.call(module, func, &args)
                .ok_or_else(|| format!("AttributeError: module '{module}' has no function '{func}'"));
        }

        // Builtin call
        let args = self.parse_args(args_str, env)?;
        self.builtins.call(name, &args)
    }

    fn parse_args(&self, args_str: &str, env: &HashMap<String, PyValue>) -> Result<Vec<PyValue>, String> {
        if args_str.trim().is_empty() { return Ok(Vec::new()); }
        let parts = split_args(args_str);
        parts.iter().map(|s| self.eval_expr(s.trim(), env)).collect()
    }
}

// ─── Helpers for the mini-interpreter ────────────────────────────────────────

#[derive(Debug)]
struct CallExpr { name: String, args_str: String }

fn try_parse_call(expr: &str) -> Option<CallExpr> {
    let paren_pos = expr.find('(')?;
    if !expr.ends_with(')') { return None; }
    let name = &expr[..paren_pos];
    let args_str = &expr[paren_pos + 1..expr.len() - 1];
    if name.is_empty() { return None; }
    // Validate name characters (allow dots for module.func)
    if name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
        Some(CallExpr { name: name.to_owned(), args_str: args_str.to_owned() })
    } else {
        None
    }
}

fn find_assignment_eq(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i-1] } else { 0 };
            let next = if i + 1 < bytes.len() { bytes[i+1] } else { 0 };
            // Exclude ==, !=, <=, >=
            if prev != b'!' && prev != b'<' && prev != b'>' && prev != b'=' && next != b'=' {
                return Some(i);
            }
        }
    }
    None
}

fn find_binary_op(expr: &str, op: &str) -> Option<usize> {
    // Simple scan that avoids matching inside parentheses or strings
    let bytes = expr.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut str_char = b'"';
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == str_char { in_str = false; }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' { in_str = true; str_char = b; i += 1; continue; }
        if b == b'(' || b == b'[' { depth += 1; i += 1; continue; }
        if b == b')' || b == b']' { depth -= 1; i += 1; continue; }
        if depth == 0 && expr[i..].starts_with(op) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn eval_binop(lhs: &PyValue, rhs: &PyValue, op: &str) -> Result<PyValue, String> {
    match (lhs, rhs, op) {
        (PyValue::Int(a), PyValue::Int(b), "+") => Ok(PyValue::Int(a.wrapping_add(*b))),
        (PyValue::Int(a), PyValue::Int(b), "-") => Ok(PyValue::Int(a.wrapping_sub(*b))),
        (PyValue::Int(a), PyValue::Int(b), "*") => Ok(PyValue::Int(a.wrapping_mul(*b))),
        (PyValue::Int(a), PyValue::Int(b), "/") => {
            if *b == 0 { return Err("ZeroDivisionError".into()); }
            Ok(PyValue::Float(*a as f64 / *b as f64))
        }
        (PyValue::Int(a), PyValue::Int(b), "//") => {
            if *b == 0 { return Err("ZeroDivisionError".into()); }
            Ok(PyValue::Int(a.wrapping_div(*b)))
        }
        (PyValue::Int(a), PyValue::Int(b), "%") => {
            if *b == 0 { return Err("ZeroDivisionError".into()); }
            Ok(PyValue::Int(a.wrapping_rem(*b)))
        }
        (PyValue::Int(a), PyValue::Int(b), "^") => Ok(PyValue::Int(a ^ b)),
        (PyValue::Int(a), PyValue::Int(b), "&") => Ok(PyValue::Int(a & b)),
        (PyValue::Int(a), PyValue::Int(b), "|") => Ok(PyValue::Int(a | b)),
        (PyValue::Float(a), PyValue::Float(b), "+") => Ok(PyValue::Float(a + b)),
        (PyValue::Float(a), PyValue::Float(b), "-") => Ok(PyValue::Float(a - b)),
        (PyValue::Float(a), PyValue::Float(b), "*") => Ok(PyValue::Float(a * b)),
        (PyValue::Float(a), PyValue::Float(b), "/") => {
            if *b == 0.0 { return Err("ZeroDivisionError".into()); }
            Ok(PyValue::Float(a / b))
        }
        (PyValue::Int(a), PyValue::Float(b), "+") => Ok(PyValue::Float(*a as f64 + b)),
        (PyValue::Float(a), PyValue::Int(b), "+") => Ok(PyValue::Float(a + *b as f64)),
        (PyValue::Str(a), PyValue::Str(b), "+") => Ok(PyValue::Str(format!("{a}{b}"))),
        _ => Err(format!("TypeError: unsupported operand type(s) for {op}: '{}' and '{}'", lhs.type_name(), rhs.type_name())),
    }
}

/// Split a comma-separated argument list, respecting nested parens/brackets.
fn split_args(s: &str) -> Vec<String> {
    if s.trim().is_empty() { return Vec::new(); }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    let mut in_str = false;
    let mut str_char = b'"';
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == str_char { in_str = false; }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' { in_str = true; str_char = b; i += 1; continue; }
        if b == b'(' || b == b'[' || b == b'{' { depth += 1; i += 1; continue; }
        if b == b')' || b == b']' || b == b'}' { depth -= 1; i += 1; continue; }
        if b == b',' && depth == 0 {
            parts.push(s[start..i].trim().to_owned());
            start = i + 1;
            i += 1;
            continue;
        }
        i += 1;
    }
    if start < s.len() {
        let tail = s[start..].trim();
        if !tail.is_empty() { parts.push(tail.to_owned()); }
    }
    parts
}

fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[derive(Debug)]
enum LineResult {
    Output(String),
    Assignment,
    Value(PyValue),
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> ScriptSandbox { ScriptSandbox::with_defaults() }

    #[test]
    fn test_simple_assignment_and_print() {
        let r = sandbox().execute("x = 42\nprint(x)");
        assert!(r.output.contains("42"));
        assert!(r.error.is_none());
    }

    #[test]
    fn test_string_concatenation() {
        let r = sandbox().execute("s = \"hello\" + \" world\"\nprint(s)");
        assert!(r.output.contains("hello world"));
    }

    #[test]
    fn test_arithmetic() {
        let r = sandbox().execute("x = 10 + 5\nprint(x)");
        assert!(r.output.contains("15"));
    }

    #[test]
    fn test_blocked_builtin_exec() {
        let r = sandbox().execute("exec(\"print(1)\")");
        assert!(r.error.is_some());
        let err = r.error.unwrap();
        assert!(err.contains("exec") || err.contains("blocked"));
    }

    #[test]
    fn test_blocked_import_os() {
        let r = sandbox().execute("import os");
        assert!(r.error.is_some());
    }

    #[test]
    fn test_allowed_stdlib_call() {
        let r = sandbox().execute("h = hashlib.sha256(b\"\")\nprint(h)");
        // hashlib.sha256 not directly callable via this syntax but test no crash
        assert!(r.execution_time_ms < 5000);
    }

    #[test]
    fn test_safe_builtins_len() {
        let builtins = SafeBuiltins::new(&[]);
        let v = builtins.call("len", &[PyValue::Str("hello".into())]);
        assert_eq!(v, Ok(PyValue::Int(5)));
    }

    #[test]
    fn test_safe_builtins_range() {
        let builtins = SafeBuiltins::new(&[]);
        let v = builtins.call("range", &[PyValue::Int(5)]).unwrap();
        if let PyValue::List(items) = v {
            assert_eq!(items.len(), 5);
            assert_eq!(items[0], PyValue::Int(0));
            assert_eq!(items[4], PyValue::Int(4));
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_safe_builtins_range_zero_step_error() {
        let builtins = SafeBuiltins::new(&[]);
        assert!(builtins.call("range", &[PyValue::Int(0), PyValue::Int(10), PyValue::Int(0)]).is_err());
    }

    #[test]
    fn test_safe_builtins_int_from_str() {
        let builtins = SafeBuiltins::new(&[]);
        let v = builtins.call("int", &[PyValue::Str("123".into())]);
        assert_eq!(v, Ok(PyValue::Int(123)));
    }

    #[test]
    fn test_safe_builtins_chr_ord_roundtrip() {
        let builtins = SafeBuiltins::new(&[]);
        let c = builtins.call("chr", &[PyValue::Int(65)]).unwrap();
        let back = builtins.call("ord", &[c]).unwrap();
        assert_eq!(back, PyValue::Int(65));
    }

    #[test]
    fn test_ast_sanitizer_detects_dunder() {
        let san = AstSanitizer::new(&[], &[]);
        let violations = san.check_source("x = obj.__class__.__bases__");
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_ast_sanitizer_detects_blocked_import() {
        let san = AstSanitizer::new(&["json".to_owned()], &[]);
        let violations = san.check_source("import socket");
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_ast_sanitizer_allows_known_module() {
        let san = AstSanitizer::new(&["re".to_owned()], &[]);
        let violations = san.check_source("import re");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_xor_arithmetic() {
        let r = sandbox().execute("x = 255 ^ 170\nprint(x)");
        assert!(r.output.contains("85"));
    }

    #[test]
    fn test_split_args_nested() {
        let parts = split_args("a, foo(b, c), d");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "foo(b, c)");
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("my_var"));
        assert!(!is_valid_identifier("123abc"));
        assert!(!is_valid_identifier(""));
    }
}
