//! Pretty-print Lua function prototypes: format the prototype tree, disassemble
//! with source line mapping, and produce annotated listings.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

use crate::LuaVersion;

// ─── SourceMap ────────────────────────────────────────────────────────────────

/// Maps instruction offsets (word indices) to source line numbers.
#[derive(Debug, Clone, Default)]
pub struct SourceMap {
    /// Sparse map: `word_offset` -> `source_line`.
    entries: HashMap<usize, u32>,
    /// Source file name, if available.
    pub source_name: Option<String>,
}

impl SourceMap {
    /// Create an empty source map.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a source map with a known source name.
    pub fn with_source(source_name: impl Into<String>) -> Self {
        Self {
            entries: HashMap::new(),
            source_name: Some(source_name.into()),
        }
    }

    /// Insert a mapping from `offset` to `line`.
    pub fn insert(&mut self, offset: usize, line: u32) {
        self.entries.insert(offset, line);
    }

    /// Build from a flat slice where `lines[i]` is the source line for word `i`.
    #[must_use] 
    pub fn from_line_info(lines: &[u32]) -> Self {
        let mut map = Self::new();
        for (i, &line) in lines.iter().enumerate() {
            if line != 0 {
                map.insert(i, line);
            }
        }
        map
    }

    /// Return the line for `offset`, or `None` if unmapped.
    #[must_use] 
    pub fn line_at(&self, offset: usize) -> Option<u32> {
        self.entries.get(&offset).copied()
    }

    /// Return `true` if no source mappings are present.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the minimum and maximum line numbers present, or `None`.
    #[must_use] 
    pub fn line_range(&self) -> Option<(u32, u32)> {
        let mut min = u32::MAX;
        let mut max = 0u32;
        for &line in self.entries.values() {
            if line < min { min = line; }
            if line > max { max = line; }
        }
        if min <= max { Some((min, max)) } else { None }
    }
}

// ─── PrintConfig ─────────────────────────────────────────────────────────────

/// Base used when numbering instructions in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetBase {
    /// The first instruction is numbered 0.
    Zero,
    /// The first instruction is numbered 1.
    One,
}

impl OffsetBase {
    /// Offset to display for the instruction at index `i`.
    #[must_use]
    pub const fn display_index(self, i: usize) -> usize {
        match self {
            Self::Zero => i,
            Self::One => i + 1,
        }
    }
}

/// Which optional sections the printer emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintSections {
    /// Print the constant pool inline after the disassembly.
    pub constants: bool,
    /// Annotate each instruction with its source line.
    pub lines: bool,
    /// Show upvalue names next to GETUPVAL/SETUPVAL references.
    pub upvalue_names: bool,
}

impl Default for PrintSections {
    fn default() -> Self {
        Self { constants: true, lines: true, upvalue_names: true }
    }
}

/// Configuration for `LuaProtoPrinter`.
#[derive(Debug, Clone)]
pub struct PrintConfig {
    /// Prefix used to indent each nesting level of sub-prototypes.
    pub indent: String,
    /// Which optional sections to emit.
    pub sections: PrintSections,
    /// Instruction numbering base.
    pub offset_base: OffsetBase,
    /// Width of the mnemonic column.
    pub mnemonic_width: usize,
    /// Whether to recurse into sub-prototypes.
    pub recurse: bool,
    /// Maximum depth for recursive printing (0 = unlimited).
    pub max_depth: usize,
    /// Hex address column width (bytes).
    pub addr_width: usize,
}

impl Default for PrintConfig {
    fn default() -> Self {
        Self {
            indent: "  ".to_owned(),
            sections: PrintSections::default(),
            offset_base: OffsetBase::Zero,
            mnemonic_width: 14,
            recurse: true,
            max_depth: 0,
            addr_width: 4,
        }
    }
}

// ─── ConstantValue ────────────────────────────────────────────────────────────

/// A Lua constant pool value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConstantValue {
    /// Null constant.
    Nil,
    /// Boolean constant.
    Bool(bool),
    /// Integer constant (Lua 5.3+).
    Integer(i64),
    /// Floating-point constant.
    Float(f64),
    /// String constant.
    Str(String),
}

impl fmt::Display for ConstantValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Float(x) => write!(f, "{x}"),
            Self::Str(s) => write!(f, "{s:?}"),
        }
    }
}

// ─── UpvalueDesc ─────────────────────────────────────────────────────────────

/// Descriptor for a single upvalue in a prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpvalueDesc {
    /// Upvalue name from debug info (may be empty).
    pub name: String,
    /// `true` if the upvalue is from the immediately enclosing function's stack.
    pub in_stack: bool,
    /// Index: register if `in_stack`, upvalue index otherwise.
    pub idx: u8,
}

// ─── LuaProto ─────────────────────────────────────────────────────────────────

/// A Lua function prototype ready to be pretty-printed.
#[derive(Debug, Clone, Default)]
pub struct LuaProto {
    /// Human-readable name (e.g. `"@myscript.lua"` or `"function foo"`).
    pub name: String,
    /// Source file.
    pub source: String,
    /// Line where this function is defined.
    pub defined_at_line: u32,
    /// Last line of the function body.
    pub last_line: u32,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// `true` if the function accepts `...` (vararg).
    pub is_vararg: bool,
    /// Maximum stack slots used.
    pub max_stack: u8,
    /// Raw instruction words.
    pub code: Vec<u32>,
    /// Constant pool.
    pub constants: Vec<ConstantValue>,
    /// Upvalue descriptors.
    pub upvalues: Vec<UpvalueDesc>,
    /// Source map for this function.
    pub source_map: SourceMap,
    /// Nested function prototypes.
    pub protos: Vec<Self>,
    /// Lua version.
    pub version: LuaVersion,
}

impl LuaProto {
    /// Create an empty prototype for the given Lua version.
    #[must_use] 
    pub fn new(version: LuaVersion) -> Self {
        Self {
            version,
            ..Default::default()
        }
    }

    /// Serialize this prototype (and its nested sub-prototypes) to a JSON string.
    ///
    /// Useful for exporting structured bytecode data to external RE tools.
    #[must_use] 
    pub fn to_json(&self) -> String {
        let value = self.to_json_value();
        serde_json::to_string_pretty(&value).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Convert this prototype to a [`serde_json::Value`] for programmatic use.
    #[must_use] 
    pub fn to_json_value(&self) -> serde_json::Value {
        let constants: Vec<serde_json::Value> = self.constants.iter().map(|c| {
            match c {
                ConstantValue::Nil => serde_json::Value::Null,
                ConstantValue::Bool(b) => serde_json::Value::Bool(*b),
                ConstantValue::Integer(n) => serde_json::json!(n),
                ConstantValue::Float(x) => serde_json::json!(x),
                ConstantValue::Str(s) => serde_json::Value::String(s.clone()),
            }
        }).collect();

        let upvalues: Vec<serde_json::Value> = self.upvalues.iter().map(|u| {
            serde_json::json!({
                "name": u.name,
                "in_stack": u.in_stack,
                "idx": u.idx,
            })
        }).collect();

        let protos: Vec<serde_json::Value> = self.protos.iter().map(Self::to_json_value).collect();

        serde_json::json!({
            "name": self.name,
            "source": self.source,
            "defined_at_line": self.defined_at_line,
            "last_line": self.last_line,
            "num_params": self.num_params,
            "is_vararg": self.is_vararg,
            "max_stack": self.max_stack,
            "code_len": self.code.len(),
            "constants": constants,
            "upvalues": upvalues,
            "protos": protos,
        })
    }
}

// ─── LuaProtoPrinter ─────────────────────────────────────────────────────────

/// Formats a [`LuaProto`] tree as an annotated text listing.
///
/// The output closely resembles `luac -l -l` output but is extended with
/// source line annotations, upvalue names, and configurable column widths.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct LuaProtoPrinter {
    /// Print configuration.
    pub config: PrintConfig,
}


impl LuaProtoPrinter {
    /// Create a printer with default configuration.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a printer with a specific configuration.
    #[must_use] 
    pub const fn with_config(config: PrintConfig) -> Self {
        Self { config }
    }

    /// Render `proto` (and, if configured, all sub-prototypes) to a `String`.
    #[must_use] 
    pub fn print_proto(&self, proto: &LuaProto) -> String {
        let mut out = String::new();
        self.print_proto_internal(proto, 0, &mut out);
        out
    }

    /// Render `proto` to the provided `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error when the input bytes are malformed, truncated, or
    /// otherwise cannot be decoded.
    pub fn print_proto_to<W: FmtWrite>(&self, proto: &LuaProto, writer: &mut W) -> fmt::Result {
        self.print_proto_internal_to(proto, 0, writer)
    }

    // ── internal ──────────────────────────────────────────────────────────────

    fn print_proto_internal(&self, proto: &LuaProto, depth: usize, out: &mut String) {
        self.print_proto_internal_to(proto, depth, out).ok();
    }

    fn print_proto_internal_to<W: FmtWrite>(
        &self,
        proto: &LuaProto,
        depth: usize,
        w: &mut W,
    ) -> fmt::Result {
        let indent = self.config.indent.repeat(depth);

        // ── Header ────────────────────────────────────────────────────────────
        writeln!(w, "{indent}; ── Function: {} ──────────────────────", proto.name)?;
        writeln!(w, "{indent}; source    : {}", proto.source)?;
        writeln!(
            w,
            "{indent}; lines     : {}..{}",
            proto.defined_at_line, proto.last_line
        )?;
        writeln!(
            w,
            "{indent}; params    : {} fixed, vararg={}",
            proto.num_params, proto.is_vararg
        )?;
        writeln!(
            w,
            "{indent}; stack     : {} slots",
            proto.max_stack
        )?;
        writeln!(
            w,
            "{indent}; constants : {} entries",
            proto.constants.len()
        )?;
        writeln!(
            w,
            "{indent}; upvalues  : {} entries",
            proto.upvalues.len()
        )?;
        writeln!(
            w,
            "{indent}; protos    : {} sub-functions",
            proto.protos.len()
        )?;
        writeln!(w, "{indent}; instructions : {}:", proto.code.len())?;

        // ── Disassembly ───────────────────────────────────────────────────────
        for (i, &word) in proto.code.iter().enumerate() {
            let offset = self.config.offset_base.display_index(i);
            let addr_str = format!("{:0width$x}", offset, width = self.config.addr_width);

            let (mnemonic, operands) = decode_word(proto.version, word);

            // Annotate operands with upvalue names.
            let operands = if self.config.sections.upvalue_names {
                annotate_upvalue_operands(&mnemonic, &operands, &proto.upvalues, proto.version)
            } else {
                operands
            };

            // Annotate operands with constant values.
            let operands =
                annotate_constant_operands(&mnemonic, &operands, &proto.constants, proto.version);

            let line_str = if self.config.sections.lines {
                proto
                    .source_map
                    .line_at(i).map_or_else(|| "     ".to_owned(), |l| format!("{l:5}"))
            } else {
                String::new()
            };

            write!(
                w,
                "{indent}  {addr_str}  {line_str}  {mnemonic:<width$}  {operands}",
                width = self.config.mnemonic_width
            )?;
            writeln!(w)?;
        }

        // ── Constant pool ─────────────────────────────────────────────────────
        if self.config.sections.constants && !proto.constants.is_empty() {
            writeln!(w, "{indent}; constants:")?;
            for (i, c) in proto.constants.iter().enumerate() {
                writeln!(w, "{indent}  [{i:4}] {c}")?;
            }
        }

        // ── Upvalue table ─────────────────────────────────────────────────────
        if self.config.sections.upvalue_names && !proto.upvalues.is_empty() {
            writeln!(w, "{indent}; upvalues:")?;
            for (i, uv) in proto.upvalues.iter().enumerate() {
                let in_stack = if uv.in_stack { "instack" } else { "       " };
                writeln!(
                    w,
                    "{indent}  [{i:4}] {in_stack}  idx={:3}  {}",
                    uv.idx, uv.name
                )?;
            }
        }

        // ── Sub-prototypes ────────────────────────────────────────────────────
        if self.config.recurse
            && !proto.protos.is_empty()
            && (self.config.max_depth == 0 || depth < self.config.max_depth)
        {
            writeln!(w, "{indent}; sub-functions:")?;
            for sub in &proto.protos {
                self.print_proto_internal_to(sub, depth + 1, w)?;
            }
        }

        Ok(())
    }
}

// ─── Decoding helpers ─────────────────────────────────────────────────────────

/// Decode a single instruction word into `(mnemonic, operands)` strings.
fn decode_word(version: LuaVersion, word: u32) -> (String, String) {
    if version.is_legacy() {
        decode_legacy(version, word)
    } else {
        decode_54(word)
    }
}

fn decode_legacy(version: LuaVersion, word: u32) -> (String, String) {
    let op = (word & 0x3f) as u8;
    let a = (word >> 6) & 0xff;
    let b = (word >> 23) & 0x1ff;
    let c = (word >> 14) & 0x1ff;
    let bx = word >> 14;

    let table: &[&str] = match version {
        LuaVersion::Lua51 => &[
            "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE",
            "SETGLOBAL","SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL",
            "DIV","MOD","POW","UNM","NOT","LEN","CONCAT","JMP","EQ","LT","LE",
            "TEST","TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP",
            "TFORLOOP","SETLIST","CLOSE","CLOSURE","VARARG",
        ],
        LuaVersion::Lua52 => &[
            "MOVE","LOADK","LOADKX","LOADBOOL","LOADNIL","GETUPVAL","GETTABUP","GETTABLE",
            "SETTABUP","SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","DIV",
            "MOD","POW","UNM","NOT","LEN","CONCAT","JMP","EQ","LT","LE","TEST",
            "TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP","TFORCALL",
            "TFORLOOP","SETLIST","CLOSURE","VARARG","EXTRAARG",
        ],
        _ => &[
            "MOVE","LOADK","LOADKX","LOADBOOL","LOADNIL","GETUPVAL","GETTABUP","GETTABLE",
            "SETTABUP","SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","MOD",
            "POW","DIV","IDIV","BAND","BOR","BXOR","SHL","SHR","UNM","BNOT","NOT",
            "LEN","CONCAT","JMP","EQ","LT","LE","TEST","TESTSET","CALL","TAILCALL",
            "RETURN","FORLOOP","FORPREP","TFORCALL","TFORLOOP","SETLIST","CLOSURE",
            "VARARG","EXTRAARG",
        ],
    };

    let mnemonic = table
        .get(op as usize)
        .copied()
        .unwrap_or("???")
        .to_lowercase();

    // Use sBx for JMP and FORLOOP/FORPREP.
    let uses_sbx = match version {
        LuaVersion::Lua51 => matches!(op, 22 | 31 | 32),
        LuaVersion::Lua52 => matches!(op, 23 | 32 | 33 | 35),
        _ => matches!(op, 30 | 39 | 40 | 42),
    };
    let takes_bx_operand = match version {
        LuaVersion::Lua51 => matches!(op, 1 | 5 | 7 | 36),
        LuaVersion::Lua52 => matches!(op, 1 | 2 | 37),
        _ => matches!(op, 1 | 2 | 44),
    };

    let operands = if uses_sbx {
        const MAXARG_SBX: i64 = ((1i64 << 18) - 1) >> 1;
        let sbx = i64::from(bx) - MAXARG_SBX;
        format!("{a}, {sbx:+}")
    } else if takes_bx_operand {
        format!("{a}, {bx}")
    } else {
        format!("{a}, {b}, {c}")
    };

    (mnemonic, operands)
}

fn decode_54(word: u32) -> (String, String) {
    static OPCODES: &[&str] = &[
        "MOVE","LOADI","LOADF","LOADK","LOADKX","LOADFALSE","LOADNIL","GETUPVAL","SETUPVAL",
        "GETTABUP","GETTABLE","GETI","GETFIELD","SETTABUP","SETTABLE","SETI","SETFIELD",
        "NEWTABLE","SELF","ADDI","ADDK","SUBK","MULK","MODK","POWK","DIVK","IDIVK","BANDK",
        "BORK","BXORK","SHRI","SHLI","ADD","SUB","MUL","MOD","POW","DIV","IDIV","BAND","BOR",
        "BXOR","SHL","SHR","MMBIN","MMBINI","MMBINK","UNM","BNOT","NOT","LEN","CONCAT",
        "CLOSE","TBC","JMP","EQ","LT","LE","EQK","EQI","LTI","GTI","LEI","GEI","TEST",
        "TESTSET","CALL","TAILCALL","RETURN","RETURN0","RETURN1","FORLOOP","FORPREP",
        "TFORPREP","TFORCALL","TFORLOOP","SETLIST","CLOSURE","VARARG","VARARGPREP","EXTRAARG",
    ];
    let op = (word & 0x7f) as u8;
    let a = (word >> 7) & 0xff;
    let b = (word >> 16) & 0xff;
    let c = (word >> 24) & 0xff;
    let bx = (word >> 15) & 0x1_ffff;
    let k = (word >> 15) & 1;

    let mnemonic = OPCODES
        .get(op as usize)
        .copied()
        .unwrap_or("???")
        .to_lowercase();

    let operands = match op {
        54 => {
            let sj = i64::from((word >> 7) & 0x01ff_ffff) - 16_777_215;
            format!("{sj:+}")
        }
        3 | 77 => format!("{a}, {bx}"),          // LOADK
        // CLOSURE
        1 | 2 | 71 | 72 | 73 | 75 => {     // LOADI/LOADF/FORLOOP/...
            let sbx = i64::from(bx) - 65535;
            format!("{a}, {sbx:+}")
        }
        80 => format!("{}", word >> 7),     // EXTRAARG
        66..=68 => format!("{a}, {b}, {c}"),
        69 => String::new(),
        70 => format!("{a}"),
        _ => {
            if k == 1 {
                format!("{a}, {b}, {c} k")
            } else {
                format!("{a}, {b}, {c}")
            }
        }
    };

    (mnemonic, operands)
}

/// Replace upvalue index tokens in operands with the upvalue name when known.
fn annotate_upvalue_operands(
    mnemonic: &str,
    operands: &str,
    upvalues: &[UpvalueDesc],
    version: LuaVersion,
) -> String {
    // For GETUPVAL/SETUPVAL the B field is the upvalue index.
    let is_upval_op = matches!(
        mnemonic,
        "getupval" | "setupval" | "gettabup" | "settabup"
    );
    if !is_upval_op || upvalues.is_empty() {
        return operands.to_owned();
    }
    // Extract the second comma-separated token (field B or the upvalue index).
    let parts: Vec<&str> = operands.splitn(3, ',').collect();
    if parts.len() < 2 {
        return operands.to_owned();
    }
    let idx_str = parts[1].trim();
    let idx: usize = idx_str.parse().unwrap_or(usize::MAX);
    if let Some(uv) = upvalues.get(idx)
        && !uv.name.is_empty() {
            let _ = version;
            let tail = if parts.len() > 2 { parts[2] } else { "" };
            let sep = if parts.len() > 2 { ", " } else { "" };
            return format!("{}, {idx} ({}){sep}{tail}", parts[0], uv.name);
        }
    operands.to_owned()
}

/// Append the constant value to operands when the last token looks like a
/// constant-pool index (LOADK, GETTABUP with k flag, etc.).
fn annotate_constant_operands(
    mnemonic: &str,
    operands: &str,
    constants: &[ConstantValue],
    _version: LuaVersion,
) -> String {
    let shows_const = matches!(mnemonic, "loadk" | "loadkx");
    if !shows_const || constants.is_empty() {
        return operands.to_owned();
    }
    // Last token is the Bx (constant index).
    let last = operands.split(',').next_back().map_or("", str::trim);
    if let Ok(idx) = last.parse::<usize>()
        && let Some(c) = constants.get(idx) {
            return format!("{operands}   ; {c}");
        }
    operands.to_owned()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_proto() -> LuaProto {
        let mut p = LuaProto::new(LuaVersion::Lua54);
        p.name = "test_fn".to_owned();
        p.source = "@test.lua".to_owned();
        p.defined_at_line = 1;
        p.last_line = 5;
        p.num_params = 1;
        p.max_stack = 4;
        // LOADK R0, 0  (op=3, a=0, bx=0)
        p.code.push(3u32);
        // RETURN0 (op=69)
        p.code.push(69u32);
        p.constants.push(ConstantValue::Str("hello".to_owned()));
        let mut sm = SourceMap::new();
        sm.insert(0, 2);
        sm.insert(1, 5);
        p.source_map = sm;
        p
    }

    #[test]
    fn test_print_proto_not_empty() {
        let proto = make_simple_proto();
        let printer = LuaProtoPrinter::new();
        let output = printer.print_proto(&proto);
        assert!(!output.is_empty());
        assert!(output.contains("test_fn"));
    }

    #[test]
    fn test_constants_in_output() {
        let proto = make_simple_proto();
        let config = PrintConfig {
            sections: PrintSections { constants: true, ..PrintSections::default() },
            ..Default::default()
        };
        let output = LuaProtoPrinter::with_config(config).print_proto(&proto);
        assert!(output.contains("hello"));
    }

    #[test]
    fn test_line_annotation_present() {
        let proto = make_simple_proto();
        let config = PrintConfig {
            sections: PrintSections { lines: true, ..PrintSections::default() },
            ..Default::default()
        };
        let output = LuaProtoPrinter::with_config(config).print_proto(&proto);
        // Line 2 should appear somewhere.
        assert!(output.contains('2'));
    }

    #[test]
    fn test_source_map_line_range() {
        let mut sm = SourceMap::new();
        sm.insert(0, 10);
        sm.insert(5, 20);
        sm.insert(3, 15);
        assert_eq!(sm.line_range(), Some((10, 20)));
    }

    #[test]
    fn test_recurse_false_omits_sub_protos() {
        let mut proto = make_simple_proto();
        let mut sub = LuaProto::new(LuaVersion::Lua54);
        sub.name = "inner_fn".to_owned();
        proto.protos.push(sub);

        let config = PrintConfig { recurse: false, ..Default::default() };
        let output = LuaProtoPrinter::with_config(config).print_proto(&proto);
        assert!(!output.contains("inner_fn"));
    }

    #[test]
    fn test_recurse_true_includes_sub_protos() {
        let mut proto = make_simple_proto();
        let mut sub = LuaProto::new(LuaVersion::Lua54);
        sub.name = "inner_fn".to_owned();
        proto.protos.push(sub);

        let output = LuaProtoPrinter::new().print_proto(&proto);
        assert!(output.contains("inner_fn"));
    }

    #[test]
    fn test_decode_54_return0() {
        let (mn, ops) = decode_54(69u32);
        assert_eq!(mn, "return0");
        assert!(ops.is_empty());
    }

    #[test]
    fn test_decode_legacy_jmp() {
        // Lua 5.1 JMP (op=22), sBx=0 (no-op jump).
        // bx = MAXARG_SBX_OLD = 131071; encoded as (bx << 14) | 22.
        let bx: u32 = 131_071;
        let word = 0x16u32 | (bx << 14);
        let (mn, ops) = decode_legacy(LuaVersion::Lua51, word);
        assert_eq!(mn, "jmp");
        assert!(ops.contains("+0") || ops.contains("0, +0"));
    }
}
