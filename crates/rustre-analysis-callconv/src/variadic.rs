//! Variadic function detection and type-checking.
//!
//! This module is the single consolidated home for variadic-function
//! analysis in this crate. It merges three previously independent,
//! non-interoperating modules (`vararg_detector`, `variadic_detection`,
//! `variadic_analyzer`) that had grown ~2200 lines and ~77 tests between
//! them with real duplication (two separate `PrintfFamily` types, two
//! separate format-string parsers). None of the three had any callers
//! outside their own unit tests and none were wired into this crate's
//! detection pipeline (`lib.rs::CallingConventionDetector`) or into
//! `rustre-decompiler`.
//!
//! The API is split into three complementary pieces that are kept
//! (deliberately) rather than merged into one god-type, because they serve
//! different call patterns:
//!
//! * **Format-string parsing** ([`FormatSpecifier`] / [`parse_format_specifiers`]):
//!   the single canonical printf-style format parser. [`FmtArgType`] /
//!   [`parse_fmt_arg_types`] (used by the type-checker) is now derived from
//!   this parser instead of re-implementing it.
//! * **Printf/scanf family tables** ([`PrintfFamily`] / [`ScanfFamily`]):
//!   name → (format-arg-index, fixed-arg-count, stream-arg) lookup. There is
//!   now exactly one `PrintfFamily` type (previously `variadic_detection`
//!   and `variadic_analyzer` each had their own).
//! * **Detection** — two independent strategies, both retained because they
//!   consume different evidence:
//!   - [`VarargDetector`]: streaming evidence accumulator fed by
//!     instruction-level observations (`observe_va_list_access`,
//!     `observe_al_read`, ...), producing a weighted confidence score. Best
//!     suited to a single-pass decompiler walk over one function.
//!   - [`VariadicDetection`]: one-shot batch driver over `(address, name,
//!     body-bytes)` tuples using name matching and byte-pattern matching.
//!     Best suited to a bulk pre-pass over many functions.
//! * **Type-checking** ([`VariadicAnalyzer`] / [`typecheck_varargs`]): given a
//!   statically-recovered format string and the argument values observed at
//!   a call site, checks the arguments against what the specifiers expect.
//!
//! None of this is wired into `CallingConventionDetector` yet; that is
//! tracked as follow-up work (see the crate-level integration notes in
//! `lib.rs`).

use rustc_hash::FxHashMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// Format-string parsing (canonical)
// ═══════════════════════════════════════════════════════════════════════════

/// A single `%...` specifier parsed from a printf/scanf format string.
#[derive(Debug, Clone)]
pub struct FormatSpecifier {
    /// The raw specifier text (e.g. `%d`, `%08.2f`, `%*s`).
    pub raw: String,
    /// Conversion character (e.g. `d`, `s`, `f`, `x`).
    pub conv: char,
    /// Whether this specifier is a `%%` literal percent.
    pub is_literal: bool,
    /// Whether the width is taken from an argument (`%*d`).
    pub width_from_arg: bool,
    /// Whether the precision is taken from an argument (`%.*f`).
    pub precision_from_arg: bool,
    /// The length modifier (e.g. `l`, `ll`, `h`, `z`).
    pub length_mod: Option<String>,
}

impl FormatSpecifier {
    /// Whether this specifier consumes a 64-bit (`long long`) argument.
    #[must_use]
    pub fn is_64bit_arg(&self) -> bool {
        matches!(self.length_mod.as_deref(), Some("ll" | "L" | "q"))
    }
}

/// Parse format specifiers from a printf-style format string.
///
/// This is a best-effort parser — it handles the most common cases and
/// ignores malformed or non-standard extensions.
#[must_use]
pub fn parse_format_specifiers(fmt: &str) -> Vec<FormatSpecifier> {
    let mut specs = Vec::new();
    let chars: Vec<char> = fmt.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '%' {
            i += 1;
            continue;
        }
        // Start of a specifier.
        let start = i;
        i += 1;
        if i >= chars.len() {
            break;
        }

        // %% → literal percent.
        if chars[i] == '%' {
            specs.push(FormatSpecifier {
                raw: "%%".into(),
                conv: '%',
                is_literal: true,
                width_from_arg: false,
                precision_from_arg: false,
                length_mod: None,
            });
            i += 1;
            continue;
        }

        // Flags: -, +, space, 0, #
        while i < chars.len() && "-+ #0".contains(chars[i]) {
            i += 1;
        }

        // Width
        let mut width_from_arg = false;
        if i < chars.len() && chars[i] == '*' {
            width_from_arg = true;
            i += 1;
        } else {
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        }

        // Precision
        let mut precision_from_arg = false;
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            if i < chars.len() && chars[i] == '*' {
                precision_from_arg = true;
                i += 1;
            } else {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
        }

        // Length modifier
        let mut length_mod = None;
        if i < chars.len() {
            let lm: String = match chars[i] {
                'h' => {
                    i += 1;
                    if i < chars.len() && chars[i] == 'h' {
                        i += 1;
                        "hh".into()
                    } else {
                        "h".into()
                    }
                }
                'l' => {
                    i += 1;
                    if i < chars.len() && chars[i] == 'l' {
                        i += 1;
                        "ll".into()
                    } else {
                        "l".into()
                    }
                }
                'L' | 'q' | 'j' | 'z' | 't' | 'Z' => {
                    let c = chars[i].to_string();
                    i += 1;
                    c
                }
                _ => String::new(),
            };
            if !lm.is_empty() {
                length_mod = Some(lm);
            }
        }

        // Conversion character.
        if i >= chars.len() {
            break;
        }
        let conv = chars[i];
        i += 1;

        let raw: String = chars[start..i].iter().collect();
        specs.push(FormatSpecifier {
            raw,
            conv,
            is_literal: false,
            width_from_arg,
            precision_from_arg,
            length_mod,
        });
    }

    specs
}

/// A format-string argument site detected in a function call.
#[derive(Debug, Clone)]
pub struct FormatStringArg {
    /// Byte offset of the call/load instruction that references the format string.
    pub instr_offset: u64,
    /// The format string literal, if recoverable.
    pub literal: Option<String>,
    /// Format specifiers parsed from `literal` (e.g. `%d`, `%s`, `%f`).
    pub specifiers: Vec<FormatSpecifier>,
    /// The argument position that carries this format string (0-based).
    pub arg_position: u32,
}

impl FormatStringArg {
    /// Create from a format string literal.
    #[must_use]
    pub fn from_literal(instr_offset: u64, literal: String, arg_position: u32) -> Self {
        let specifiers = parse_format_specifiers(&literal);
        Self {
            instr_offset,
            literal: Some(literal),
            specifiers,
            arg_position,
        }
    }

    /// Create without a literal (address-only reference).
    #[must_use]
    pub const fn from_address(instr_offset: u64, arg_position: u32) -> Self {
        Self {
            instr_offset,
            literal: None,
            specifiers: Vec::new(),
            arg_position,
        }
    }

    /// Minimum number of additional arguments required by the format specifiers.
    ///
    /// Each non-literal specifier consumes its value argument, PLUS one extra
    /// argument for a dynamic `*` width and another for a dynamic `.*`
    /// precision — e.g. `printf("%*d", w, v)` requires 2 args and
    /// `printf("%*.*f", w, p, v)` requires 3. (The previous version counted one
    /// arg per specifier and ignored the `*`/`.*` args entirely, under-reporting
    /// the requirement so an under-supplied call site was falsely accepted.)
    ///
    /// PRINTF SEMANTICS ONLY. This counts `*`/`.*` as consuming an extra
    /// argument, which is correct for printf-family functions. It is WRONG for
    /// scanf-family functions, where `%*` means *suppress assignment* and
    /// consumes ZERO arguments (no output pointer). Do not call this on a scanf
    /// format string — it would over-count. (scanf detection currently uses
    /// name matching + `ScanfFamily::format_arg_index`, not this method.)
    #[must_use]
    pub fn min_arg_count(&self) -> u32 {
        let mut count: u32 = 0;
        for s in &self.specifiers {
            if s.is_literal {
                continue;
            }
            count = count.saturating_add(1); // the value argument itself
            if s.width_from_arg {
                count = count.saturating_add(1); // dynamic `*` width
            }
            if s.precision_from_arg {
                count = count.saturating_add(1); // dynamic `.*` precision
            }
        }
        count
    }

    /// Whether any wildcard (`%*`) specifier was found (requires extra arg for width).
    #[must_use]
    pub fn has_wildcard_width(&self) -> bool {
        self.specifiers
            .iter()
            .any(|s| s.width_from_arg || s.precision_from_arg)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type-checking format-arg types
// ═══════════════════════════════════════════════════════════════════════════

/// The broad type class expected by a single format specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FmtArgType {
    /// A signed or unsigned integer.
    Integer,
    /// A floating-point value.
    Float,
    /// A pointer to a char array (string).
    StringPtr,
    /// A generic pointer.
    Pointer,
    /// A single character.
    Char,
    /// A write-back pointer (`%n`).
    WriteBack,
    /// Unknown / cannot be determined.
    Unknown,
}

impl FmtArgType {
    /// Parse from a format specifier character.
    #[must_use]
    pub const fn from_spec_char(ch: char) -> Self {
        match ch {
            'd' | 'i' | 'u' | 'o' | 'x' | 'X' => Self::Integer,
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => Self::Float,
            's' | 'S' => Self::StringPtr,
            'p' | 'P' => Self::Pointer,
            'c' | 'C' => Self::Char,
            'n' => Self::WriteBack,
            _ => Self::Unknown,
        }
    }
}

/// Parse all `%`-specifiers from a format string and return a list of
/// expected argument types in order.
///
/// Built on top of [`parse_format_specifiers`] (the canonical parser) rather
/// than re-implementing specifier scanning.
#[must_use]
pub fn parse_fmt_arg_types(fmt: &str) -> Vec<FmtArgType> {
    let mut types = Vec::new();
    for spec in parse_format_specifiers(fmt) {
        if spec.is_literal {
            continue;
        }
        if spec.width_from_arg {
            types.push(FmtArgType::Integer);
        }
        if spec.precision_from_arg {
            types.push(FmtArgType::Integer);
        }
        types.push(FmtArgType::from_spec_char(spec.conv));
    }
    types
}

// ═══════════════════════════════════════════════════════════════════════════
// Printf / scanf family tables (canonical — single PrintfFamily type)
// ═══════════════════════════════════════════════════════════════════════════

/// A printf-family function's calling shape.
#[derive(Debug, Clone, Copy)]
pub struct PrintfFamily {
    /// The canonical function name.
    pub name: &'static str,
    /// Zero-based index of the format string in the fixed argument list.
    pub fmt_arg_index: usize,
    /// Whether the function writes to a file descriptor / stream (first
    /// arg(s) before the format string are a `FILE*`/fd).
    pub has_stream_arg: bool,
    /// Whether the function is genuinely VARIADIC.
    ///
    /// The `v*` members (`vprintf`, `vfprintf`, …) take a `va_list` and have a
    /// fixed arity; `OutputDebugStringA` takes a single string. They belong in
    /// this table because callers use it to locate the format string, but
    /// reporting them as variadic — which is what happened before this flag
    /// existed — is wrong on both the variadic claim and the argument count.
    pub is_variadic: bool,
}

impl PrintfFamily {
    /// Number of fixed (non-variadic) arguments, including the format string
    /// itself.
    #[must_use]
    pub const fn fixed_arg_count(&self) -> usize {
        self.fmt_arg_index + 1
    }
}

/// Built-in printf-family table.
#[must_use]
pub fn printf_family_table() -> Vec<PrintfFamily> {
    vec![
        PrintfFamily { name: "printf",    fmt_arg_index: 0, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "fprintf",   fmt_arg_index: 1, has_stream_arg: true  , is_variadic: true },
        PrintfFamily { name: "sprintf",   fmt_arg_index: 1, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "snprintf",  fmt_arg_index: 2, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "vprintf",   fmt_arg_index: 0, has_stream_arg: false , is_variadic: false },
        PrintfFamily { name: "vfprintf",  fmt_arg_index: 1, has_stream_arg: true  , is_variadic: false },
        PrintfFamily { name: "vsprintf",  fmt_arg_index: 1, has_stream_arg: false , is_variadic: false },
        PrintfFamily { name: "vsnprintf", fmt_arg_index: 2, has_stream_arg: false , is_variadic: false },
        PrintfFamily { name: "wprintf",   fmt_arg_index: 0, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "fwprintf",  fmt_arg_index: 1, has_stream_arg: true  , is_variadic: true },
        PrintfFamily { name: "swprintf",  fmt_arg_index: 1, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "dprintf",   fmt_arg_index: 1, has_stream_arg: true  , is_variadic: true },
        PrintfFamily { name: "asprintf",  fmt_arg_index: 1, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "DbgPrint",  fmt_arg_index: 0, has_stream_arg: false , is_variadic: true },
        PrintfFamily { name: "OutputDebugStringA", fmt_arg_index: 0, has_stream_arg: false , is_variadic: false },
    ]
}

/// Return the printf-family entry for `name` (case-insensitive).
#[must_use]
pub fn lookup_printf_family(name: &str) -> Option<PrintfFamily> {
    let lower = name.to_lowercase();
    printf_family_table()
        .into_iter()
        .find(|f| f.name.to_lowercase() == lower)
}

/// Whether `name` is a known printf-family function.
#[must_use]
pub fn is_printf_family(name: &str) -> bool {
    lookup_printf_family(name).is_some()
}

/// Recognises scanf-family functions.
pub struct ScanfFamily;

impl ScanfFamily {
    pub const NAMES: &'static [&'static str] =
        &["scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"];

    #[must_use]
    pub fn is_scanf_family(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        Self::NAMES.iter().any(|&n| lower == n)
    }

    /// Whether this scanf-family member is genuinely VARIADIC.
    ///
    /// Same distinction as [`PrintfFamily::is_variadic`]: `vscanf`, `vfscanf`
    /// and `vsscanf` take a `va_list` and have a fixed arity. They stay in
    /// [`Self::NAMES`] because the format-string index is still useful.
    #[must_use]
    pub fn is_variadic(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        Self::is_scanf_family(&lower) && !lower.starts_with('v')
    }

    #[must_use]
    pub fn format_arg_index(name: &str) -> Option<usize> {
        match name.to_ascii_lowercase().as_str() {
            "scanf" | "vscanf" => Some(0),
            "fscanf" | "vfscanf" => Some(1),
            "sscanf" | "vsscanf" => Some(1),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VarargDetector: streaming evidence accumulator
// ═══════════════════════════════════════════════════════════════════════════

/// A pattern that indicates a function might be variadic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarargPattern {
    /// The function uses `va_start` / `va_list` — definitive indicator.
    VaListUsage,
    /// The first argument register is used as a format string (printf-family).
    FormatStringArg,
    /// The `al` register (x86-64 `SysV`: counts XMM args) is read before write.
    AlRegisterRead,
    /// More argument registers are read than any fixed-arity convention supports.
    ExcessiveArgRegs,
    /// A variadic helper function (`vsnprintf`, `vprintf`, etc.) is called.
    VariadicHelperCall,
    /// The function accesses `[rbp + N]` for large N — stack arg sweep.
    StackArgSweep,
    /// The function copies `rsp + N` into a register and then iterates — `va_list` materialisation.
    VaListMaterialise,
    /// A format-string verb `%*` (width from arg) was detected in a literal string.
    FormatVerbWildcard,
    /// Heuristic: function name contains "printf", "scanf", "log", etc.
    NameHeuristic,
}

impl fmt::Display for VarargPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::VaListUsage => "VaListUsage",
            Self::FormatStringArg => "FormatStringArg",
            Self::AlRegisterRead => "AlRegisterRead",
            Self::ExcessiveArgRegs => "ExcessiveArgRegs",
            Self::VariadicHelperCall => "VariadicHelperCall",
            Self::StackArgSweep => "StackArgSweep",
            Self::VaListMaterialise => "VaListMaterialise",
            Self::FormatVerbWildcard => "FormatVerbWildcard",
            Self::NameHeuristic => "NameHeuristic",
        };
        write!(f, "{s}")
    }
}

/// A single `va_list` access site observed in the function body.
#[derive(Debug, Clone)]
pub struct VaListAccess {
    /// Byte offset of the access instruction within the function.
    pub instr_offset: u64,
    /// Kind of `va_list` operation.
    pub kind: VaListAccessKind,
    /// The register used to hold the `va_list` pointer, if applicable.
    pub reg: Option<String>,
    /// SP-relative offset where the `va_list` was constructed, if known.
    pub sp_offset: Option<i32>,
}

/// The kind of `va_list` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaListAccessKind {
    /// `va_start` initialisation.
    Start,
    /// `va_arg` fetch.
    Arg,
    /// `va_end` teardown.
    End,
    /// `va_copy` copy.
    Copy,
    /// Unidentified `va_list` access.
    Unknown,
}

impl fmt::Display for VaListAccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Start => "va_start",
            Self::Arg => "va_arg",
            Self::End => "va_end",
            Self::Copy => "va_copy",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Detects whether a function is variadic by accumulating evidence.
pub struct VarargDetector {
    /// Architecture pointer size (4 or 8).
    _pointer_size: u32,
    /// Maximum number of register arguments in any known fixed CC.
    max_fixed_reg_args: u32,
    /// Patterns observed so far.
    patterns: Vec<(VarargPattern, u32)>, // (kind, weight)
    /// `va_list` access sites.
    va_accesses: Vec<VaListAccess>,
    /// Format-string argument sites.
    fmt_args: Vec<FormatStringArg>,
    /// Call targets identified as variadic helpers.
    helper_calls: Vec<String>,
    /// Number of distinct argument registers read before write.
    reg_arg_count: u32,
    /// Function name heuristic result.
    name_heuristic: bool,
}

impl VarargDetector {
    /// Create a new detector for the given architecture.
    ///
    /// `max_fixed_reg_args` is the maximum number of integer argument registers
    /// any calling convention on this architecture uses (e.g. 6 for `SysV` AMD64).
    #[must_use]
    pub const fn new(pointer_size: u32, max_fixed_reg_args: u32) -> Self {
        Self {
            _pointer_size: pointer_size,
            max_fixed_reg_args,
            patterns: Vec::new(),
            va_accesses: Vec::new(),
            fmt_args: Vec::new(),
            helper_calls: Vec::new(),
            reg_arg_count: 0,
            name_heuristic: false,
        }
    }

    /// Record a `va_list` access at `offset`.
    pub fn observe_va_list_access(&mut self, access: VaListAccess) {
        self.add_pattern(VarargPattern::VaListUsage, 30);
        self.va_accesses.push(access);
    }

    /// Record a format-string argument.
    pub fn observe_format_string(&mut self, arg: FormatStringArg) {
        let wildcard = arg.has_wildcard_width();
        self.add_pattern(VarargPattern::FormatStringArg, 20);
        if wildcard {
            self.add_pattern(VarargPattern::FormatVerbWildcard, 10);
        }
        self.fmt_args.push(arg);
    }

    /// Record a read of the `al` register (`SysV` AMD64 XMM count convention).
    pub fn observe_al_read(&mut self) {
        self.add_pattern(VarargPattern::AlRegisterRead, 15);
    }

    /// Record the number of distinct argument registers read before write.
    pub fn observe_arg_reg_count(&mut self, count: u32) {
        self.reg_arg_count = count;
        if count > self.max_fixed_reg_args {
            self.add_pattern(VarargPattern::ExcessiveArgRegs, 15);
        }
    }

    /// Record a call to a variadic helper function.
    pub fn observe_helper_call(&mut self, name: impl Into<String>) {
        let n = name.into();
        self.add_pattern(VarargPattern::VariadicHelperCall, 25);
        self.helper_calls.push(n);
    }

    /// Record a stack argument sweep (loading successive sp+N values in a loop).
    pub fn observe_stack_sweep(&mut self) {
        self.add_pattern(VarargPattern::StackArgSweep, 12);
    }

    /// Record materialisation of the `va_list` onto the stack.
    pub fn observe_va_materialise(&mut self) {
        self.add_pattern(VarargPattern::VaListMaterialise, 20);
    }

    /// Apply a function-name heuristic: does the name suggest a variadic function?
    pub fn apply_name_heuristic(&mut self, name: &str) {
        let lower = name.to_lowercase();
        let is_variadic = VARIADIC_NAME_HINTS.iter().any(|h| lower.contains(h));
        if is_variadic {
            self.name_heuristic = true;
            self.add_pattern(VarargPattern::NameHeuristic, 8);
        }
    }

    /// Compute the total evidence score.
    #[must_use]
    pub fn total_score(&self) -> u32 {
        self.patterns.iter().map(|(_, w)| w).sum()
    }

    /// Confidence that the function is variadic (0.0 – 1.0).
    #[must_use]
    pub fn confidence(&self) -> f64 {
        let score = self.total_score();
        // Use a logistic-like mapping: score 30 → ~0.8, 15 → ~0.5.
        let x = f64::from(score);
        1.0 / (1.0 + (-0.1 * (x - 15.0)).exp())
    }

    /// Whether the function is almost certainly variadic (confidence >= 0.7).
    #[must_use]
    pub fn is_variadic(&self) -> bool {
        self.confidence() >= 0.7
    }

    /// Return all distinct observed patterns.
    #[must_use]
    pub fn patterns(&self) -> Vec<&VarargPattern> {
        self.patterns.iter().map(|(p, _)| p).collect()
    }

    /// Produce a full detection result.
    #[must_use]
    pub fn result(&self) -> VarargResult {
        VarargResult {
            is_variadic: self.is_variadic(),
            confidence: self.confidence(),
            total_score: self.total_score(),
            patterns: self.patterns.clone(),
            va_accesses: self.va_accesses.clone(),
            fmt_args: self.fmt_args.clone(),
            helper_calls: self.helper_calls.clone(),
            reg_arg_count: self.reg_arg_count,
            name_heuristic: self.name_heuristic,
        }
    }

    // Internal helper.
    fn add_pattern(&mut self, kind: VarargPattern, weight: u32) {
        if let Some((_, w)) = self.patterns.iter_mut().find(|(p, _)| *p == kind) {
            // Accumulate weight but cap to avoid overflow.
            *w = w.saturating_add(weight);
        } else {
            self.patterns.push((kind, weight));
        }
    }
}

/// Substrings in a function name that strongly suggest variadicity.
static VARIADIC_NAME_HINTS: &[&str] = &[
    "printf", "scanf", "sprintf", "snprintf", "fprintf",
    "sscanf", "vprintf", "vscanf", "vfprintf", "vsnprintf",
    "log_fmt", "logf", "dbgprintf", "wprintf", "swprintf",
    "format", "emit",
];

/// Complete result produced by `VarargDetector`.
#[derive(Debug, Clone)]
pub struct VarargResult {
    /// Whether the function is most likely variadic.
    pub is_variadic: bool,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f64,
    /// Raw total evidence weight.
    pub total_score: u32,
    /// All evidence patterns and their accumulated weights.
    pub patterns: Vec<(VarargPattern, u32)>,
    /// `va_list` access sites.
    pub va_accesses: Vec<VaListAccess>,
    /// Format-string argument sites.
    pub fmt_args: Vec<FormatStringArg>,
    /// Variadic helper call targets.
    pub helper_calls: Vec<String>,
    /// Number of distinct argument registers.
    pub reg_arg_count: u32,
    /// Whether the name heuristic fired.
    pub name_heuristic: bool,
}

impl VarargResult {
    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "variadic={} conf={:.0}% score={} patterns={}",
            self.is_variadic,
            self.confidence * 100.0,
            self.total_score,
            self.patterns.len(),
        )
    }

    /// The strongest pattern observed (highest weight).
    #[must_use]
    pub fn strongest_pattern(&self) -> Option<&VarargPattern> {
        self.patterns.iter().max_by_key(|(_, w)| w).map(|(p, _)| p)
    }
}

/// Convenience wrapper for analysing multiple functions at once.
pub struct BatchVarargAnalyzer {
    pointer_size: u32,
    max_fixed_reg_args: u32,
}

impl BatchVarargAnalyzer {
    /// Create a batch analyser.
    #[must_use]
    pub const fn new(pointer_size: u32, max_fixed_reg_args: u32) -> Self {
        Self {
            pointer_size,
            max_fixed_reg_args,
        }
    }

    /// Analyse a slice of `(function_name, per-function observations)` pairs.
    ///
    /// `observations` is a closure called with a `&mut VarargDetector` to feed
    /// data for one function.
    #[must_use]
    pub fn analyse<F>(&self, function_name: &str, observe: F) -> VarargResult
    where
        F: FnOnce(&mut VarargDetector),
    {
        let mut det = VarargDetector::new(self.pointer_size, self.max_fixed_reg_args);
        det.apply_name_heuristic(function_name);
        observe(&mut det);
        det.result()
    }

    /// Return aggregate statistics over a slice of results.
    #[must_use]
    pub fn stats(results: &[VarargResult]) -> VarargStats {
        VarargStats::compute(results)
    }
}

/// Aggregate statistics over a batch of variadic detection results.
#[derive(Debug, Clone, Default)]
pub struct VarargStats {
    pub total: usize,
    pub variadic: usize,
    pub avg_confidence: f64,
    /// Keyed by pattern names from binary analysis — `FxHashMap` to prevent `DoS`.
    pub pattern_frequency: FxHashMap<String, usize>,
}

impl VarargStats {
    /// Compute from a slice of results.
    #[must_use]
    pub fn compute(results: &[VarargResult]) -> Self {
        if results.is_empty() {
            return Self::default();
        }
        let mut variadic = 0usize;
        let mut conf_sum = 0.0f64;
        let mut pattern_frequency: FxHashMap<String, usize> = FxHashMap::default();
        for r in results {
            if r.is_variadic {
                variadic += 1;
            }
            conf_sum += r.confidence;
            for (p, _) in &r.patterns {
                *pattern_frequency.entry(p.to_string()).or_insert(0) += 1;
            }
        }
        Self {
            total: results.len(),
            variadic,
            avg_confidence: conf_sum / results.len() as f64,
            pattern_frequency,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VariadicDetection: batch byte-pattern / name driver
// ═══════════════════════════════════════════════════════════════════════════

/// The category of a detected variadic function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VariadicKind {
    PrintfFamily,
    ScanfFamily,
    VaList,
    CustomVariadic,
}

impl fmt::Display for VariadicKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PrintfFamily => "printf_family",
            Self::ScanfFamily => "scanf_family",
            Self::VaList => "va_list",
            Self::CustomVariadic => "custom_variadic",
        };
        f.write_str(s)
    }
}

/// Function batch entry: `(address, optional name, optional body bytes)`.
pub type VariadicFunctionEntry = (u64, Option<String>, Option<Vec<u8>>);

/// Summary result for one function.
#[derive(Debug, Clone)]
pub struct VariadicReport {
    /// Function address.
    pub address: u64,
    /// Whether this function is variadic.
    pub is_variadic: bool,
    /// The detected kind (if any).
    pub kind: Option<VariadicKind>,
    /// Evidence patterns that led to this conclusion.
    pub evidence: Vec<String>,
    /// Confidence 0–100.
    pub confidence: u8,
    /// Format string argument index (for printf/scanf families).
    pub format_arg_index: Option<usize>,
    /// Fixed argument count before variadic arguments.
    pub fixed_arg_count: usize,
}

impl VariadicReport {
    #[must_use]
    pub const fn not_variadic(address: u64) -> Self {
        Self {
            address,
            is_variadic: false,
            kind: None,
            evidence: Vec::new(),
            confidence: 90,
            format_arg_index: None,
            fixed_arg_count: 0,
        }
    }

    #[must_use]
    pub const fn variadic(address: u64, kind: VariadicKind, confidence: u8, fixed_args: usize) -> Self {
        Self {
            address,
            is_variadic: true,
            kind: Some(kind),
            evidence: Vec::new(),
            confidence,
            format_arg_index: None,
            fixed_arg_count: fixed_args,
        }
    }

    /// Add an evidence string.
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }

    /// Set the format argument index.
    #[must_use]
    pub const fn with_format_arg(mut self, idx: usize) -> Self {
        self.format_arg_index = Some(idx);
        self
    }
}

/// A byte pattern that indicates `va_list` manipulation.
#[derive(Debug, Clone)]
pub struct VaListPattern {
    /// Short description of what this pattern detects.
    pub description: String,
    /// Byte sequence to search for (may contain wildcards as `None`).
    pub pattern: Vec<Option<u8>>,
}

impl VaListPattern {
    #[must_use]
    pub fn new(description: impl Into<String>, pattern: Vec<Option<u8>>) -> Self {
        Self {
            description: description.into(),
            pattern,
        }
    }

    /// Check whether `data` contains this pattern starting at any offset.
    #[must_use]
    pub fn matches_in(&self, data: &[u8]) -> Option<usize> {
        let pat = &self.pattern;
        if pat.is_empty() {
            return None;
        }
        'outer: for start in 0..data.len().saturating_sub(pat.len() - 1) {
            for (i, p) in pat.iter().enumerate() {
                if let Some(byte) = p
                    && data[start + i] != *byte
                {
                    continue 'outer;
                }
            }
            return Some(start);
        }
        None
    }

    /// Length of the pattern.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pattern.len()
    }

    /// Whether the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

/// Recognises the `va_arg` access pattern in a function body.
///
/// On x86-64 `SysV` ABI this often manifests as an `al` = number-of-FP-args
/// pattern combined with `test al, al` before a jump.
#[derive(Debug, Clone)]
pub struct VaArgPattern {
    pub pattern_bytes: Vec<u8>,
    pub mask_bytes: Vec<u8>,
}

impl VaArgPattern {
    /// x86-64: `test al, al` followed by `jz` (FP arg count check).
    #[must_use]
    pub fn x86_64_fp_check() -> Self {
        Self {
            pattern_bytes: vec![0x84, 0xC0, 0x74], // test al,al; jz
            mask_bytes: vec![0xFF, 0xFF, 0xFF],
        }
    }

    /// Apply mask and match.
    ///
    /// `pattern_bytes`/`mask_bytes` are public fields, so a struct literal
    /// (as opposed to [`Self::x86_64_fp_check`]) can construct an instance
    /// where they have mismatched lengths; guard against that here rather
    /// than indexing `mask_bytes` out of bounds.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let n = self.pattern_bytes.len();
        if self.mask_bytes.len() != n || offset + n > data.len() {
            return false;
        }
        for i in 0..n {
            let mask_i = self.mask_bytes[i];
            if data[offset + i] & mask_i != self.pattern_bytes[i] & mask_i {
                return false;
            }
        }
        true
    }

    /// Find all offsets in `data` where this pattern matches.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        (0..data.len()).filter(|&i| self.matches_at(data, i)).collect()
    }
}

/// A user-defined variadic detection rule.
#[derive(Debug, Clone)]
pub struct CustomVariadic {
    /// Name of the custom pattern.
    pub name: String,
    /// Va-list patterns to match in the function body.
    pub va_patterns: Vec<VaListPattern>,
    /// Fixed argument count before `...`.
    pub fixed_args: usize,
}

impl CustomVariadic {
    #[must_use]
    pub fn new(name: impl Into<String>, fixed_args: usize) -> Self {
        Self {
            name: name.into(),
            va_patterns: Vec::new(),
            fixed_args,
        }
    }

    pub fn add_pattern(&mut self, p: VaListPattern) {
        self.va_patterns.push(p);
    }

    /// Detect if `data` (function body bytes) matches this custom variadic pattern.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Option<Vec<String>> {
        let mut evidence = Vec::new();
        for pat in &self.va_patterns {
            if let Some(offset) = pat.matches_in(data) {
                evidence.push(format!("'{}' at offset {offset:#x}", pat.description));
            }
        }
        if evidence.is_empty() {
            None
        } else {
            Some(evidence)
        }
    }
}

/// Configuration for variadic detection.
#[derive(Debug, Clone, Default)]
pub struct VariadicDetectionConfig {
    /// Also detect by symbol name matching.
    pub use_name_matching: bool,
    /// Also detect by byte pattern matching in function body.
    pub use_pattern_matching: bool,
    /// Minimum function body size for pattern matching.
    pub min_function_size: usize,
}

impl VariadicDetectionConfig {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            use_name_matching: true,
            use_pattern_matching: true,
            min_function_size: 8,
        }
    }
}

/// Main driver for batch variadic detection over `(address, name, body)`
/// tuples, using name matching and byte-pattern matching.
pub struct VariadicDetection {
    pub config: VariadicDetectionConfig,
    custom_patterns: Vec<CustomVariadic>,
    va_list_patterns: Vec<VaListPattern>,
    va_arg_patterns: Vec<VaArgPattern>,
}

impl Default for VariadicDetection {
    fn default() -> Self {
        Self::new()
    }
}

impl VariadicDetection {
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self {
            config: VariadicDetectionConfig::new(),
            custom_patterns: Vec::new(),
            va_list_patterns: Vec::new(),
            va_arg_patterns: Vec::new(),
        };
        // Add default va_list patterns
        // x86-64: lea rcx, [rbp - N] (often used for va_list)
        s.va_list_patterns.push(VaListPattern::new(
            "va_start stack prep",
            vec![Some(0x48), Some(0x8D), None, None, None], // lea r64, [rbp±N]
        ));
        s.va_arg_patterns.push(VaArgPattern::x86_64_fp_check());
        s
    }

    pub fn add_custom(&mut self, c: CustomVariadic) {
        self.custom_patterns.push(c);
    }

    /// Analyse a function by its symbol name (if known).
    #[must_use]
    pub fn detect_by_name(&self, address: u64, name: &str) -> VariadicReport {
        if let Some(pf) = lookup_printf_family(name) {
            // A printf-family NAME is not the same thing as a variadic
            // function: the `v*` members take a `va_list` and
            // `OutputDebugStringA` takes a single string.
            if !pf.is_variadic {
                return VariadicReport::not_variadic(address);
            }
            let mut r = VariadicReport::variadic(
                address,
                VariadicKind::PrintfFamily,
                99,
                pf.fixed_arg_count(),
            )
            .with_evidence(format!("name '{name}' matches printf family"));
            r.format_arg_index = Some(pf.fmt_arg_index);
            return r;
        }
        if ScanfFamily::is_scanf_family(name) {
            if !ScanfFamily::is_variadic(name) {
                return VariadicReport::not_variadic(address);
            }
            let fmt_idx = ScanfFamily::format_arg_index(name);
            let mut r = VariadicReport::variadic(address, VariadicKind::ScanfFamily, 99, 1)
                .with_evidence(format!("name '{name}' matches scanf family"));
            r.format_arg_index = fmt_idx;
            return r;
        }
        VariadicReport::not_variadic(address)
    }

    /// Analyse a function by scanning its body bytes.
    #[must_use]
    pub fn detect_by_body(&self, address: u64, body: &[u8]) -> VariadicReport {
        if body.len() < self.config.min_function_size {
            return VariadicReport::not_variadic(address);
        }

        let mut evidence = Vec::new();

        // Check va_list patterns
        for pat in &self.va_list_patterns {
            if let Some(off) = pat.matches_in(body) {
                evidence.push(format!("'{}' at offset {off:#x}", pat.description));
            }
        }

        // Check va_arg patterns
        for pat in &self.va_arg_patterns {
            let hits = pat.find_all(body);
            if !hits.is_empty() {
                evidence.push(format!("va_arg pattern at {} offset(s)", hits.len()));
            }
        }

        // Check custom patterns
        for custom in &self.custom_patterns {
            if let Some(ev) = custom.detect(body) {
                evidence.extend(ev);
            }
        }

        if evidence.is_empty() {
            VariadicReport::not_variadic(address)
        } else {
            let confidence = (50 + evidence.len() * 10).min(95) as u8;
            let mut r = VariadicReport::variadic(address, VariadicKind::VaList, confidence, 0);
            r.evidence = evidence;
            r
        }
    }

    /// Analyse multiple functions, keyed by address with optional name and body.
    ///
    /// Returns an `FxHashMap` (randomised seed) to prevent hash-collision `DoS`
    /// from maliciously crafted function-address distributions in binary input.
    #[must_use]
    pub fn analyse_batch(&self, functions: &[VariadicFunctionEntry]) -> FxHashMap<u64, VariadicReport> {
        let mut results = FxHashMap::default();
        for (addr, name, body) in functions {
            let report = if self.config.use_name_matching {
                if let Some(n) = name {
                    let r = self.detect_by_name(*addr, n);
                    if r.is_variadic {
                        r
                    } else if let Some(b) = body {
                        self.detect_by_body(*addr, b)
                    } else {
                        r
                    }
                } else if let Some(b) = body {
                    self.detect_by_body(*addr, b)
                } else {
                    VariadicReport::not_variadic(*addr)
                }
            } else if let Some(b) = body {
                self.detect_by_body(*addr, b)
            } else {
                VariadicReport::not_variadic(*addr)
            };
            results.insert(*addr, report);
        }
        results
    }

    /// Collect only the variadic functions from a batch result.
    #[must_use]
    pub fn variadic_functions(reports: &FxHashMap<u64, VariadicReport>) -> Vec<u64> {
        let mut addrs: Vec<u64> = reports
            .iter()
            .filter(|(_, r)| r.is_variadic)
            .map(|(a, _)| *a)
            .collect();
        addrs.sort_unstable();
        addrs
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type-checking: variadic call-site argument verification
// ═══════════════════════════════════════════════════════════════════════════

/// The static type hint associated with an argument at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgTypeHint {
    /// Argument is a small integer (register width ≤ 32 bits).
    SmallInt,
    /// Argument is a 64-bit integer.
    Int64,
    /// Argument is a floating-point value (XMM / double).
    Float,
    /// Argument is a pointer (non-null).
    Pointer,
    /// Argument is a literal zero (could be NULL or 0).
    Zero,
    /// Cannot determine.
    Unknown,
}

/// One argument at a variadic call site.
#[derive(Debug, Clone)]
pub struct VariadicCallArg {
    /// Zero-based position after the fixed arguments.
    pub variadic_index: usize,
    /// Register or stack slot name.
    pub location: String,
    /// Static type hint.
    pub type_hint: ArgTypeHint,
    /// Immediate value if statically known.
    pub immediate: Option<u64>,
}

/// The result of comparing a format specifier with the actual argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeCheckResult {
    /// The argument matches the specifier.
    Ok,
    /// The argument type conflicts with the specifier (possible format bug).
    Mismatch {
        /// The specifier that was expected.
        expected: FmtArgType,
        /// The actual type hint.
        actual: ArgTypeHint,
    },
    /// The argument is missing (fewer args than specifiers).
    Missing,
    /// The format string could not be obtained statically.
    FormatUnknown,
}

/// Type-check the variadic arguments at a call site against a parsed format
/// string.
#[must_use]
pub fn typecheck_varargs(fmt: &str, args: &[VariadicCallArg]) -> Vec<TypeCheckResult> {
    let expected = parse_fmt_arg_types(fmt);
    let mut results = Vec::new();

    for (i, exp_type) in expected.iter().enumerate() {
        if let Some(arg) = args.get(i) {
            let ok = match (exp_type, arg.type_hint) {
                (FmtArgType::Integer, ArgTypeHint::SmallInt | ArgTypeHint::Int64 | ArgTypeHint::Zero) => true,
                (FmtArgType::Float, ArgTypeHint::Float) => true,
                (FmtArgType::StringPtr, ArgTypeHint::Pointer) => true,
                (FmtArgType::Pointer, ArgTypeHint::Pointer | ArgTypeHint::Zero) => true,
                (FmtArgType::Char, ArgTypeHint::SmallInt | ArgTypeHint::Int64) => true,
                (FmtArgType::WriteBack, ArgTypeHint::Pointer) => true,
                (_, ArgTypeHint::Unknown) => true, // cannot check
                _ => false,
            };

            if ok {
                results.push(TypeCheckResult::Ok);
            } else {
                results.push(TypeCheckResult::Mismatch {
                    expected: *exp_type,
                    actual: arg.type_hint,
                });
            }
        } else {
            results.push(TypeCheckResult::Missing);
        }
    }

    results
}

/// State of a `va_list` variable as tracked through a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaListState {
    /// `va_start` has been called; the list is active.
    Started,
    /// `va_arg` has been called at least once.
    InUse,
    /// `va_end` has been called; the list has been cleaned up.
    Ended,
    /// State is unknown.
    Unknown,
}

/// A `va_list` usage event within a function.
#[derive(Debug, Clone)]
pub struct VaListEvent {
    /// Address of the instruction that triggers this event.
    pub insn_addr: u64,
    /// New state after this event.
    pub new_state: VaListState,
    /// Argument type extracted (if this is a `va_arg` call).
    pub extracted_type: Option<FmtArgType>,
}

/// Heuristic indicators that a function is a custom variadic function (not in
/// the standard printf family).
#[derive(Debug, Clone)]
pub struct CustomVariadicIndicators {
    /// Whether the function accesses `va_arg` / `va_list` intrinsics.
    pub uses_va_list: bool,
    /// Whether the function calls a known printf-family function internally.
    pub delegates_to_printf: bool,
    /// Whether a parameter register holds an integer count that roughly
    /// matches the number of additional arguments observed at call sites.
    pub has_count_parameter: bool,
    /// Number of observed call sites.
    pub call_site_count: usize,
    /// Average number of arguments across call sites (excluding fixed args).
    pub avg_variadic_args: f64,
}

impl CustomVariadicIndicators {
    /// Heuristic confidence that this function is variadic, in [0.0, 1.0].
    #[must_use]
    pub fn confidence(&self) -> f64 {
        let mut score = 0.0f64;
        if self.uses_va_list {
            score += 0.5;
        }
        if self.delegates_to_printf {
            score += 0.3;
        }
        if self.has_count_parameter {
            score += 0.2;
        }
        if self.avg_variadic_args > 1.0 {
            score += 0.1;
        }
        score.min(1.0)
    }
}

/// Central variadic-function analyser: name-based recognition plus call-site
/// argument type-checking.
pub struct VariadicAnalyzer {
    /// Printf-family table (may include user-defined entries).
    pub printf_family: Vec<PrintfFamily>,
    /// Known variadic functions (name → format-arg index).
    /// Keyed by symbol names from untrusted binary input — use `FxHashMap`
    /// to prevent hash-collision `DoS` via crafted symbol tables.
    pub custom_variadics: FxHashMap<String, usize>,
}

impl VariadicAnalyzer {
    /// Create an analyser with the built-in printf table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            printf_family: printf_family_table(),
            custom_variadics: FxHashMap::default(),
        }
    }

    /// Register a custom variadic function.
    ///
    /// The name is normalised to lowercase on insertion so that lookups via
    /// [`Self::is_variadic`] / [`Self::fmt_arg_index`] — which are
    /// case-insensitive, matching the built-in printf-family lookup — find it
    /// regardless of the case used at a given call site.
    pub fn register_variadic(&mut self, name: impl Into<String>, fmt_arg_index: usize) {
        self.custom_variadics.insert(name.into().to_lowercase(), fmt_arg_index);
    }

    /// Return `true` if `name` is a known variadic function (case-insensitive).
    #[must_use]
    pub fn is_variadic(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.printf_family.iter().any(|f| f.name.to_lowercase() == lower)
            || self.custom_variadics.contains_key(&lower)
    }

    /// Return the format-string argument index for `name`, if known
    /// (case-insensitive).
    #[must_use]
    pub fn fmt_arg_index(&self, name: &str) -> Option<usize> {
        let lower = name.to_lowercase();
        if let Some(f) = self.printf_family.iter().find(|f| f.name.to_lowercase() == lower) {
            return Some(f.fmt_arg_index);
        }
        self.custom_variadics.get(&lower).copied()
    }

    /// Perform a type-check of variadic arguments at a specific call site.
    ///
    /// `func_name` — the name of the callee.
    /// `fmt` — the statically-determined format string (if any).
    /// `varargs` — the variadic arguments at this call site.
    #[must_use]
    pub fn check_call_site(
        &self,
        func_name: &str,
        fmt: Option<&str>,
        varargs: &[VariadicCallArg],
    ) -> Vec<TypeCheckResult> {
        if !self.is_variadic(func_name) {
            return Vec::new();
        }
        match fmt {
            Some(f) => typecheck_varargs(f, varargs),
            None => vec![TypeCheckResult::FormatUnknown],
        }
    }
}

impl Default for VariadicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format specifier parsing ----

    #[test]
    fn test_parse_format_no_specifiers() {
        let specs = parse_format_specifiers("hello world");
        assert!(specs.is_empty());
    }

    #[test]
    fn test_parse_format_basic() {
        let specs = parse_format_specifiers("%d %s %f");
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].conv, 'd');
        assert_eq!(specs[1].conv, 's');
        assert_eq!(specs[2].conv, 'f');
    }

    #[test]
    fn test_parse_format_percent_literal() {
        let specs = parse_format_specifiers("100%%");
        assert_eq!(specs.len(), 1);
        assert!(specs[0].is_literal);
    }

    /// `min_arg_count` must include the extra args consumed by dynamic `*`
    /// width and `.*` precision, not just one arg per specifier.
    #[test]
    fn min_arg_count_includes_star_width_and_precision() {
        // "%d" → 1; "%%" literal → 0.
        assert_eq!(FormatStringArg::from_literal(0, "%d".into(), 0).min_arg_count(), 1);
        assert_eq!(FormatStringArg::from_literal(0, "100%%".into(), 0).min_arg_count(), 0);
        // "%*d" → width arg + value = 2.
        assert_eq!(FormatStringArg::from_literal(0, "%*d".into(), 0).min_arg_count(), 2);
        // "%.*f" → precision arg + value = 2.
        assert_eq!(FormatStringArg::from_literal(0, "%.*f".into(), 0).min_arg_count(), 2);
        // "%*.*f" → width + precision + value = 3.
        assert_eq!(FormatStringArg::from_literal(0, "%*.*f".into(), 0).min_arg_count(), 3);
        // Mixed: "%s %*d %%" → 1 + 2 + 0 = 3.
        assert_eq!(FormatStringArg::from_literal(0, "%s %*d %%".into(), 0).min_arg_count(), 3);
    }

    #[test]
    fn test_parse_format_width_from_arg() {
        let specs = parse_format_specifiers("%*d");
        assert_eq!(specs.len(), 1);
        assert!(specs[0].width_from_arg);
    }

    #[test]
    fn test_parse_format_precision_from_arg() {
        let specs = parse_format_specifiers("%.*f");
        assert_eq!(specs.len(), 1);
        assert!(specs[0].precision_from_arg);
    }

    #[test]
    fn test_parse_format_ll() {
        let specs = parse_format_specifiers("%lld");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].length_mod.as_deref(), Some("ll"));
        assert!(specs[0].is_64bit_arg());
    }

    #[test]
    fn test_format_string_arg_min_count() {
        let arg = FormatStringArg::from_literal(0, "%d %s %%".into(), 0);
        // %d and %s each require 1 arg; %% is literal.
        assert_eq!(arg.min_arg_count(), 2);
    }

    #[test]
    fn test_format_string_arg_has_wildcard() {
        let arg = FormatStringArg::from_literal(0, "%*d".into(), 0);
        assert!(arg.has_wildcard_width());
    }

    // ---- FmtArgType / parse_fmt_arg_types (derived from FormatSpecifier) ----

    #[test]
    fn parse_fmt_arg_types_basic() {
        let types = parse_fmt_arg_types("Hello %s, you have %d messages");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], FmtArgType::StringPtr);
        assert_eq!(types[1], FmtArgType::Integer);
    }

    #[test]
    fn parse_fmt_arg_types_float() {
        let types = parse_fmt_arg_types("value = %f");
        assert_eq!(types, vec![FmtArgType::Float]);
    }

    #[test]
    fn parse_fmt_arg_types_escaped() {
        let types = parse_fmt_arg_types("100%% done, %d items");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], FmtArgType::Integer);
    }

    #[test]
    fn parse_fmt_arg_types_star_width() {
        // `%*d` — width is an argument itself (integer), then `d` is integer
        let types = parse_fmt_arg_types("%*d");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], FmtArgType::Integer); // width arg
        assert_eq!(types[1], FmtArgType::Integer); // `d` arg
    }

    // ---- PrintfFamily / ScanfFamily ----

    #[test]
    fn printf_family_lookup_found() {
        let f = lookup_printf_family("printf").unwrap();
        assert_eq!(f.fmt_arg_index, 0);
    }

    #[test]
    fn printf_family_lookup_snprintf() {
        let f = lookup_printf_family("snprintf").unwrap();
        assert_eq!(f.fmt_arg_index, 2);
    }

    #[test]
    fn printf_family_lookup_unknown() {
        assert!(lookup_printf_family("my_custom_log").is_none());
    }

    #[test]
    fn test_printf_family_printf() {
        assert!(is_printf_family("printf"));
        assert!(is_printf_family("fprintf"));
        assert!(is_printf_family("snprintf"));
    }

    #[test]
    fn test_printf_family_case() {
        assert!(is_printf_family("PRINTF"));
        assert!(is_printf_family("Printf"));
    }

    #[test]
    fn test_printf_family_not_variadic() {
        assert!(!is_printf_family("memcpy"));
        assert!(!is_printf_family("open"));
    }

    #[test]
    fn test_printf_format_arg_index() {
        assert_eq!(lookup_printf_family("printf").unwrap().fmt_arg_index, 0);
        assert_eq!(lookup_printf_family("fprintf").unwrap().fmt_arg_index, 1);
        assert_eq!(lookup_printf_family("snprintf").unwrap().fmt_arg_index, 2);
    }

    #[test]
    fn test_printf_fixed_arg_count() {
        assert_eq!(lookup_printf_family("printf").unwrap().fixed_arg_count(), 1);
        assert_eq!(lookup_printf_family("fprintf").unwrap().fixed_arg_count(), 2);
        assert_eq!(lookup_printf_family("snprintf").unwrap().fixed_arg_count(), 3);
    }

    #[test]
    fn test_printf_family_wprintf() {
        assert!(is_printf_family("wprintf"));
    }

    #[test]
    fn test_scanf_family() {
        assert!(ScanfFamily::is_scanf_family("scanf"));
        assert!(ScanfFamily::is_scanf_family("sscanf"));
        assert!(!ScanfFamily::is_scanf_family("printf"));
    }

    #[test]
    fn test_scanf_format_arg() {
        assert_eq!(ScanfFamily::format_arg_index("scanf"), Some(0));
        assert_eq!(ScanfFamily::format_arg_index("fscanf"), Some(1));
        assert_eq!(ScanfFamily::format_arg_index("sscanf"), Some(1));
    }

    #[test]
    fn test_scanf_case_insensitive() {
        assert!(ScanfFamily::is_scanf_family("SCANF"));
    }

    // ---- VarargDetector (evidence accumulator) ----

    #[test]
    fn test_va_list_makes_variadic() {
        let mut det = VarargDetector::new(8, 6);
        det.observe_va_list_access(VaListAccess {
            instr_offset: 0,
            kind: VaListAccessKind::Start,
            reg: Some("rsi".into()),
            sp_offset: None,
        });
        assert!(det.is_variadic());
    }

    #[test]
    fn test_format_string_increases_score() {
        let mut det = VarargDetector::new(8, 6);
        let arg = FormatStringArg::from_literal(0, "%d %s %f".into(), 0);
        det.observe_format_string(arg);
        assert!(det.total_score() > 0);
    }

    #[test]
    fn test_name_heuristic_printf() {
        let mut det = VarargDetector::new(8, 6);
        det.apply_name_heuristic("my_printf");
        assert!(det.name_heuristic);
        assert!(det.total_score() > 0);
    }

    #[test]
    fn test_name_heuristic_non_variadic() {
        let mut det = VarargDetector::new(8, 6);
        det.apply_name_heuristic("compute_hash");
        assert!(!det.name_heuristic);
    }

    #[test]
    fn test_al_read() {
        let mut det = VarargDetector::new(8, 6);
        det.observe_al_read();
        assert!(det.total_score() > 0);
    }

    #[test]
    fn test_helper_call() {
        let mut det = VarargDetector::new(8, 6);
        det.observe_helper_call("vsnprintf");
        assert!(det.is_variadic());
    }

    #[test]
    fn test_confidence_scale() {
        let mut det = VarargDetector::new(8, 6);
        // No evidence → low confidence.
        assert!(det.confidence() < 0.6);
        det.observe_va_list_access(VaListAccess {
            instr_offset: 0,
            kind: VaListAccessKind::Arg,
            reg: None,
            sp_offset: None,
        });
        assert!(det.confidence() >= 0.6);
    }

    #[test]
    fn test_patterns_deduplicated_by_kind() {
        let mut det = VarargDetector::new(8, 6);
        det.observe_al_read();
        det.observe_al_read();
        let patterns: Vec<_> = det.patterns();
        let al_count = patterns
            .iter()
            .filter(|p| ***p == VarargPattern::AlRegisterRead)
            .count();
        assert_eq!(al_count, 1);
    }

    #[test]
    fn test_batch_analyser() {
        let b = BatchVarargAnalyzer::new(8, 6);
        let r = b.analyse("my_sprintf", |det| {
            let arg = FormatStringArg::from_literal(0, "%d %s".into(), 0);
            det.observe_format_string(arg);
        });
        assert!(r.is_variadic);
    }

    #[test]
    fn test_vararg_stats() {
        let b = BatchVarargAnalyzer::new(8, 6);
        let results: Vec<VarargResult> = vec![
            b.analyse("printf_wrapper", |d| {
                d.observe_helper_call("vprintf");
            }),
            b.analyse("fixed_arity_fn", |_| {}),
        ];
        let stats = BatchVarargAnalyzer::stats(&results);
        assert_eq!(stats.total, 2);
        assert!(stats.variadic >= 1);
    }

    #[test]
    fn test_result_summary_not_empty() {
        let det = VarargDetector::new(8, 6);
        let r = det.result();
        assert!(!r.summary().is_empty());
    }

    #[test]
    fn test_strongest_pattern_none_when_empty() {
        let det = VarargDetector::new(8, 6);
        let r = det.result();
        assert!(r.strongest_pattern().is_none());
    }

    #[test]
    fn test_excessive_arg_regs() {
        let mut det = VarargDetector::new(8, 6);
        // SysV has 6 integer arg regs; 7+ implies variadic.
        det.observe_arg_reg_count(7);
        assert!(det.patterns().iter().any(|p| **p == VarargPattern::ExcessiveArgRegs));
    }

    // ---- VariadicDetection (batch byte-pattern / name driver) ----

    #[test]
    fn test_detect_by_name_printf() {
        let det = VariadicDetection::new();
        let r = det.detect_by_name(0x1000, "printf");
        assert!(r.is_variadic);
        assert_eq!(r.kind, Some(VariadicKind::PrintfFamily));
        assert_eq!(r.fixed_arg_count, 1);
        assert_eq!(r.format_arg_index, Some(0));
        assert!(r.confidence > 90);
    }

    #[test]
    fn test_detect_by_name_scanf() {
        let det = VariadicDetection::new();
        let r = det.detect_by_name(0x2000, "scanf");
        assert!(r.is_variadic);
        assert_eq!(r.kind, Some(VariadicKind::ScanfFamily));
    }

    #[test]
    fn test_detect_by_name_unknown() {
        let det = VariadicDetection::new();
        let r = det.detect_by_name(0x3000, "foo_bar");
        assert!(!r.is_variadic);
    }

    #[test]
    fn test_va_list_pattern_match() {
        let pat = VaListPattern::new("test", vec![Some(0x48), Some(0x8D), None]);
        let data = vec![0x00, 0x48, 0x8D, 0xFF, 0x00];
        assert_eq!(pat.matches_in(&data), Some(1));
    }

    #[test]
    fn test_va_list_pattern_no_match() {
        let pat = VaListPattern::new("test", vec![Some(0x48), Some(0x8D)]);
        let data = vec![0x55, 0x89, 0xE5];
        assert_eq!(pat.matches_in(&data), None);
    }

    #[test]
    fn test_va_list_pattern_empty() {
        let pat = VaListPattern::new("empty", vec![]);
        let data = vec![0x00];
        assert!(pat.matches_in(&data).is_none());
        assert!(pat.is_empty());
    }

    #[test]
    fn test_va_list_pattern_len() {
        let pat = VaListPattern::new("t", vec![Some(1), None, Some(3)]);
        assert_eq!(pat.len(), 3);
    }

    #[test]
    fn test_va_arg_pattern_match() {
        let pat = VaArgPattern::x86_64_fp_check();
        let data = vec![0x84, 0xC0, 0x74, 0x10]; // test al,al; jz rel8
        assert!(pat.matches_at(&data, 0));
    }

    #[test]
    fn test_va_arg_pattern_find_all() {
        let pat = VaArgPattern::x86_64_fp_check();
        let data = vec![0x84, 0xC0, 0x74, 0x10, 0x00, 0x84, 0xC0, 0x74, 0x20];
        let hits = pat.find_all(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_va_arg_pattern_no_match() {
        let pat = VaArgPattern::x86_64_fp_check();
        let data = vec![0x90, 0x90, 0x90]; // NOP
        assert!(pat.find_all(&data).is_empty());
    }

    #[test]
    fn test_va_arg_pattern_mismatched_mask_len_no_panic() {
        // `pattern_bytes`/`mask_bytes` are public fields; a struct literal
        // can desynchronize their lengths (unlike the `x86_64_fp_check`
        // constructor). This must not index out of bounds — it should just
        // fail to match.
        let pat = VaArgPattern {
            pattern_bytes: vec![0x84, 0xC0, 0x74],
            mask_bytes: vec![0xFF, 0xFF], // shorter than pattern_bytes
        };
        let data = vec![0x84, 0xC0, 0x74, 0x10];
        assert!(!pat.matches_at(&data, 0));
        assert!(pat.find_all(&data).is_empty());

        let pat_long_mask = VaArgPattern {
            pattern_bytes: vec![0x84, 0xC0],
            mask_bytes: vec![0xFF, 0xFF, 0xFF], // longer than pattern_bytes
        };
        assert!(!pat_long_mask.matches_at(&data, 0));
    }

    #[test]
    fn test_detect_by_body_va_arg() {
        let det = VariadicDetection::new();
        let mut body = vec![0x55u8; 20];
        body[5] = 0x84;
        body[6] = 0xC0;
        body[7] = 0x74;
        let r = det.detect_by_body(0x4000, &body);
        assert!(r.is_variadic);
        assert!(r.confidence > 0);
    }

    #[test]
    fn test_detect_by_body_too_short() {
        let det = VariadicDetection::new();
        let r = det.detect_by_body(0x5000, &[0x55, 0x89]);
        assert!(!r.is_variadic);
    }

    #[test]
    fn test_detect_by_body_no_match() {
        let det = VariadicDetection::new();
        let body = vec![0x90u8; 32]; // all NOPs
        let r = det.detect_by_body(0x6000, &body);
        assert!(!r.is_variadic);
    }

    #[test]
    fn test_variadic_kind_display() {
        assert_eq!(VariadicKind::PrintfFamily.to_string(), "printf_family");
        assert_eq!(VariadicKind::ScanfFamily.to_string(), "scanf_family");
        assert_eq!(VariadicKind::VaList.to_string(), "va_list");
        assert_eq!(VariadicKind::CustomVariadic.to_string(), "custom_variadic");
    }

    #[test]
    fn test_variadic_report_not_variadic() {
        let r = VariadicReport::not_variadic(0x1000);
        assert!(!r.is_variadic);
        assert!(r.kind.is_none());
    }

    #[test]
    fn test_variadic_report_with_evidence() {
        let r = VariadicReport::variadic(0, VariadicKind::VaList, 80, 0).with_evidence("pattern at 0x10");
        assert_eq!(r.evidence.len(), 1);
    }

    #[test]
    fn test_custom_variadic_detect() {
        let mut cv = CustomVariadic::new("custom", 1);
        cv.add_pattern(VaListPattern::new("magic", vec![Some(0xAA), Some(0xBB)]));
        let data = vec![0x00, 0xAA, 0xBB, 0x00];
        let ev = cv.detect(&data).expect("detected");
        assert!(!ev.is_empty());
    }

    #[test]
    fn test_custom_variadic_no_match() {
        let mut cv = CustomVariadic::new("custom", 1);
        cv.add_pattern(VaListPattern::new("magic", vec![Some(0xDE), Some(0xAD)]));
        let data = vec![0x00, 0xAA, 0xBB, 0x00];
        assert!(cv.detect(&data).is_none());
    }

    #[test]
    fn test_add_custom_detect() {
        let mut det = VariadicDetection::new();
        let mut cv = CustomVariadic::new("my_logger", 2);
        cv.add_pattern(VaListPattern::new("logger_marker", vec![Some(0xCC), Some(0xDD)]));
        det.add_custom(cv);
        let mut body = vec![0x90u8; 20];
        body[10] = 0xCC;
        body[11] = 0xDD;
        let r = det.detect_by_body(0x7000, &body);
        assert!(r.is_variadic);
    }

    #[test]
    fn test_analyse_batch_with_name() {
        let det = VariadicDetection::new();
        let fns = vec![(0x1000, Some("printf".to_string()), None)];
        let results = det.analyse_batch(&fns);
        assert!(results[&0x1000].is_variadic);
    }

    #[test]
    fn test_variadic_functions_filter() {
        let det = VariadicDetection::new();
        let fns = vec![
            (0x1000, Some("printf".to_string()), None),
            (0x2000, Some("memcpy".to_string()), None),
        ];
        let results = det.analyse_batch(&fns);
        let variadic = VariadicDetection::variadic_functions(&results);
        assert_eq!(variadic, vec![0x1000]);
    }

    #[test]
    fn test_analyse_batch_body_fallback() {
        let det = VariadicDetection::new();
        let mut body = vec![0x90u8; 20];
        body[5] = 0x84;
        body[6] = 0xC0;
        body[7] = 0x74;
        let fns = vec![(0x3000, None, Some(body))];
        let results = det.analyse_batch(&fns);
        assert!(results[&0x3000].is_variadic);
    }

    #[test]
    fn test_with_format_arg() {
        let r = VariadicReport::variadic(0, VariadicKind::PrintfFamily, 90, 1).with_format_arg(0);
        assert_eq!(r.format_arg_index, Some(0));
    }

    #[test]
    fn test_va_list_wildcard() {
        let pat = VaListPattern::new("wildcard", vec![None, None]);
        let data = vec![0xFF, 0x00, 0xAB];
        assert!(pat.matches_in(&data).is_some());
    }

    #[test]
    fn test_detection_config_default() {
        let cfg = VariadicDetectionConfig::new();
        assert!(cfg.use_name_matching);
        assert!(cfg.use_pattern_matching);
    }

    #[test]
    fn test_detect_vprintf() {
        // `vprintf(const char *fmt, va_list ap)` takes a va_list: it has a
        // FIXED arity and is not variadic. This used to assert the opposite,
        // which is the defect `PrintfFamily::is_variadic` now encodes.
        let det = VariadicDetection::new();
        let r = det.detect_by_name(0, "vprintf");
        assert!(!r.is_variadic);
        // It is still a printf-family name, so its format string is locatable.
        assert!(is_printf_family("vprintf"));
    }

    #[test]
    fn test_detect_vsscanf() {
        // Same as `vprintf`: `vsscanf` takes a va_list, so it is not variadic.
        let det = VariadicDetection::new();
        let r = det.detect_by_name(0, "vsscanf");
        assert!(!r.is_variadic);
        assert!(ScanfFamily::is_scanf_family("vsscanf"));
    }

    #[test]
    fn test_va_list_confidence() {
        let det = VariadicDetection::new();
        let mut body = vec![0x90u8; 20];
        body[5] = 0x84;
        body[6] = 0xC0;
        body[7] = 0x74;
        let r = det.detect_by_body(0, &body);
        assert!(r.confidence >= 50);
    }

    #[test]
    fn test_empty_batch() {
        let det = VariadicDetection::new();
        let results = det.analyse_batch(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_va_arg_out_of_bounds() {
        let pat = VaArgPattern::x86_64_fp_check();
        let data = vec![0x84, 0xC0]; // too short
        assert!(!pat.matches_at(&data, 0));
    }

    #[test]
    fn test_va_list_match_at_start() {
        let pat = VaListPattern::new("t", vec![Some(0xAA)]);
        let data = vec![0xAA, 0xBB];
        assert_eq!(pat.matches_in(&data), Some(0));
    }

    #[test]
    fn test_custom_fixed_args() {
        let cv = CustomVariadic::new("cv", 3);
        assert_eq!(cv.fixed_args, 3);
    }

    #[test]
    fn test_analyse_batch_no_info() {
        let det = VariadicDetection::new();
        let fns = vec![(0x9000, None, None)];
        let results = det.analyse_batch(&fns);
        assert!(!results[&0x9000].is_variadic);
    }

    // ---- VariadicAnalyzer (type-checking) ----

    #[test]
    fn typecheck_varargs_ok() {
        let args = vec![
            VariadicCallArg {
                variadic_index: 0,
                location: "rsi".into(),
                type_hint: ArgTypeHint::Pointer,
                immediate: None,
            },
            VariadicCallArg {
                variadic_index: 1,
                location: "rdx".into(),
                type_hint: ArgTypeHint::SmallInt,
                immediate: Some(42),
            },
        ];
        let results = typecheck_varargs("%s = %d", &args);
        assert_eq!(results, vec![TypeCheckResult::Ok, TypeCheckResult::Ok]);
    }

    #[test]
    fn typecheck_varargs_mismatch() {
        let args = vec![VariadicCallArg {
            variadic_index: 0,
            location: "xmm0".into(),
            type_hint: ArgTypeHint::Float,
            immediate: None,
        }];
        let results = typecheck_varargs("%s", &args);
        assert!(matches!(results[0], TypeCheckResult::Mismatch { .. }));
    }

    #[test]
    fn typecheck_varargs_missing_arg() {
        let results = typecheck_varargs("%d %d %d", &[]);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| *r == TypeCheckResult::Missing));
    }

    #[test]
    fn variadic_analyzer_is_variadic() {
        let a = VariadicAnalyzer::new();
        assert!(a.is_variadic("printf"));
        assert!(a.is_variadic("fprintf"));
        assert!(!a.is_variadic("memcpy"));
    }

    #[test]
    fn variadic_analyzer_custom_registration() {
        let mut a = VariadicAnalyzer::new();
        a.register_variadic("my_log", 1);
        assert!(a.is_variadic("my_log"));
        assert_eq!(a.fmt_arg_index("my_log"), Some(1));
    }

    #[test]
    fn variadic_analyzer_check_call_site_ok() {
        let a = VariadicAnalyzer::new();
        let args = vec![VariadicCallArg {
            variadic_index: 0,
            location: "rsi".into(),
            type_hint: ArgTypeHint::SmallInt,
            immediate: Some(1),
        }];
        let results = a.check_call_site("printf", Some("%d"), &args);
        assert_eq!(results, vec![TypeCheckResult::Ok]);
    }

    // Regression: registration and lookup must agree on case-sensitivity.
    // The built-in printf-family table is matched case-insensitively, so a
    // custom registration must be discoverable the same way regardless of
    // the case used at the call site.
    #[test]
    fn variadic_analyzer_custom_registration_case_insensitive() {
        let mut a = VariadicAnalyzer::new();
        a.register_variadic("My_Log", 1);
        assert!(a.is_variadic("my_log"));
        assert!(a.is_variadic("MY_LOG"));
        assert!(a.is_variadic("My_Log"));
        assert_eq!(a.fmt_arg_index("my_log"), Some(1));
        assert_eq!(a.fmt_arg_index("MY_LOG"), Some(1));
    }

    #[test]
    fn custom_variadic_confidence() {
        let ind = CustomVariadicIndicators {
            uses_va_list: true,
            delegates_to_printf: false,
            has_count_parameter: false,
            call_site_count: 3,
            avg_variadic_args: 2.0,
        };
        assert!(ind.confidence() >= 0.5);
    }
}
