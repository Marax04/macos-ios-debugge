//! Lua bytecode debug information: locals, upvalues, line numbers, and
//! source-to-address mapping across all supported Lua versions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// LuaVersion
// ─────────────────────────────────────────────────────────────────────────────

/// Supported Lua bytecode versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LuaVersion {
    Lua50,
    Lua51,
    Lua52,
    Lua53,
    Lua54,
}

impl LuaVersion {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x50 => Some(Self::Lua50),
            0x51 => Some(Self::Lua51),
            0x52 => Some(Self::Lua52),
            0x53 => Some(Self::Lua53),
            0x54 => Some(Self::Lua54),
            _ => None,
        }
    }

    #[must_use]
    pub const fn version_byte(self) -> u8 {
        match self {
            Self::Lua50 => 0x50,
            Self::Lua51 => 0x51,
            Self::Lua52 => 0x52,
            Self::Lua53 => 0x53,
            Self::Lua54 => 0x54,
        }
    }

    #[must_use]
    pub const fn display_str(self) -> &'static str {
        match self {
            Self::Lua50 => "5.0",
            Self::Lua51 => "5.1",
            Self::Lua52 => "5.2",
            Self::Lua53 => "5.3",
            Self::Lua54 => "5.4",
        }
    }

    #[must_use]
    pub const fn has_integer_type(self) -> bool {
        matches!(self, Self::Lua53 | Self::Lua54)
    }
    #[must_use]
    pub const fn has_loadkx(self) -> bool {
        matches!(self, Self::Lua52 | Self::Lua53 | Self::Lua54)
    }
    #[must_use]
    pub const fn has_bitwise_ops(self) -> bool {
        matches!(self, Self::Lua53 | Self::Lua54)
    }
    #[must_use]
    pub const fn has_tforcall(self) -> bool {
        matches!(self, Self::Lua52 | Self::Lua53 | Self::Lua54)
    }
}

impl fmt::Display for LuaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaLocalVar
// ─────────────────────────────────────────────────────────────────────────────

/// A local variable debug record (name + PC range it is live).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaLocalVar {
    pub name: String,
    /// First PC where this variable is live (inclusive).
    pub start_pc: u32,
    /// First PC where this variable is dead.
    pub end_pc: u32,
    /// Register slot.
    pub slot: u8,
}

impl LuaLocalVar {
    #[must_use]
    pub const fn is_live_at(&self, pc: u32) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }

    #[must_use]
    pub const fn live_range(&self) -> u32 {
        self.end_pc.saturating_sub(self.start_pc)
    }

    /// Returns true if this is a compiler-internal variable (prefixed with `(`).
    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.name.starts_with('(')
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaUpvalue
// ─────────────────────────────────────────────────────────────────────────────

/// An upvalue descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaUpvalue {
    pub name: Option<String>,
    /// True if the upvalue is in the immediately enclosing function's register file.
    pub in_stack: bool,
    /// Index: register (if `in_stack`) or upvalue index in enclosing proto.
    pub idx: u8,
}

impl LuaUpvalue {
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("(anonymous)")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaSourceMap
// ─────────────────────────────────────────────────────────────────────────────

/// Maps instruction PCs to source line numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaSourceMap {
    /// Per-instruction source lines (index = PC, value = 1-based line).
    pub lines: Vec<i32>,
    /// Source file name.
    pub source: Option<String>,
    /// First defined line.
    pub line_defined: i32,
    /// Last defined line.
    pub last_line_defined: i32,
}

impl LuaSourceMap {
    #[must_use]
    pub const fn new(source: Option<String>, lines: Vec<i32>, defined: i32, last: i32) -> Self {
        Self {
            lines,
            source,
            line_defined: defined,
            last_line_defined: last,
        }
    }

    /// Get the source line for the given PC, or None if out of range.
    #[must_use]
    pub fn line_at(&self, pc: usize) -> Option<i32> {
        self.lines.get(pc).copied().filter(|&l| l > 0)
    }

    /// All unique line numbers in this source map.
    #[must_use]
    pub fn unique_lines(&self) -> Vec<i32> {
        let mut lines: Vec<i32> = self.lines.iter().copied().filter(|&l| l > 0).collect();
        lines.sort_unstable();
        lines.dedup();
        lines
    }

    /// PCs that correspond to the given source line.
    #[must_use]
    pub fn pcs_for_line(&self, line: i32) -> Vec<usize> {
        self.lines
            .iter()
            .enumerate()
            .filter(|&(_, &l)| l == line)
            .map(|(pc, _)| pc)
            .collect()
    }

    /// Number of source lines covered.
    #[must_use]
    pub fn covered_line_count(&self) -> usize {
        self.unique_lines().len()
    }

    /// Source name without `@` or `=` prefix (Lua naming convention).
    #[must_use]
    pub fn clean_source(&self) -> &str {
        match self.source.as_deref() {
            None => "(unknown)",
            Some(s) if s.starts_with('@') => &s[1..],
            Some(s) if s.starts_with('=') => &s[1..],
            Some(s) => s,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaProtoDebugInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Complete debug information for one Lua prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaProtoDebugInfo {
    pub version: LuaVersion,
    pub source_map: LuaSourceMap,
    pub locals: Vec<LuaLocalVar>,
    pub upvalues: Vec<LuaUpvalue>,
    pub instr_count: u32,
    pub num_params: u8,
    pub is_vararg: bool,
    pub max_stack: u8,
    pub children: Vec<Self>,
}

impl LuaProtoDebugInfo {
    #[must_use]
    pub const fn new(version: LuaVersion, source: Option<String>) -> Self {
        Self {
            version,
            source_map: LuaSourceMap::new(source, Vec::new(), 0, 0),
            locals: Vec::new(),
            upvalues: Vec::new(),
            instr_count: 0,
            num_params: 0,
            is_vararg: false,
            max_stack: 0,
            children: Vec::new(),
        }
    }

    /// Locals live at the given PC.
    #[must_use]
    pub fn locals_at_pc(&self, pc: u32) -> Vec<&LuaLocalVar> {
        self.locals.iter().filter(|l| l.is_live_at(pc)).collect()
    }

    /// Total number of local variables (including children).
    #[must_use]
    pub fn total_locals(&self) -> usize {
        self.locals.len()
            + self
                .children
                .iter()
                .map(Self::total_locals)
                .sum::<usize>()
    }

    /// Total instruction count including nested protos.
    #[must_use]
    pub fn total_instrs(&self) -> u32 {
        self.instr_count + self.children.iter().map(Self::total_instrs).sum::<u32>()
    }

    /// Flatten the proto tree into a depth-first list.
    #[must_use]
    pub fn flatten(&self) -> Vec<&Self> {
        let mut v = vec![self];
        for c in &self.children {
            v.extend(c.flatten());
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaDebugDb
// ─────────────────────────────────────────────────────────────────────────────

/// A database of debug information for a Lua bytecode file.
#[derive(Debug, Default)]
pub struct LuaDebugDb {
    pub version: Option<LuaVersion>,
    pub root: Option<LuaProtoDebugInfo>,
    /// Cache of source file → proto index list.
    source_cache: HashMap<String, Vec<usize>>,
}

impl LuaDebugDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_root(&mut self, info: LuaProtoDebugInfo) {
        self.version = Some(info.version);
        self.root = Some(info);
        self.rebuild_source_cache();
    }

    fn rebuild_source_cache(&mut self) {
        self.source_cache.clear();
        if let Some(ref root) = self.root {
            for (i, proto) in root.flatten().iter().enumerate() {
                let src = proto.source_map.clean_source().to_string();
                self.source_cache.entry(src).or_default().push(i);
            }
        }
    }

    #[must_use]
    pub fn source_files(&self) -> Vec<&str> {
        self.source_cache.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn total_protos(&self) -> usize {
        self.root.as_ref().map_or(0, |r| r.flatten().len())
    }

    #[must_use]
    pub fn total_locals(&self) -> usize {
        self.root.as_ref().map_or(0, LuaProtoDebugInfo::total_locals)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaDisasmLine
// ─────────────────────────────────────────────────────────────────────────────

/// A single line of disassembly output with optional debug decoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaDisasmLine {
    pub pc: u32,
    pub raw: u32,
    pub mnemonic: String,
    pub operands: String,
    pub source_line: Option<i32>,
    pub comment: Option<String>,
}

impl fmt::Display for LuaDisasmLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line_s = self
            .source_line
            .map_or_else(|| "      ".to_string(), |l| format!("[{l:4}]"));
        write!(
            f,
            "{:4}: {} {:<12} {}",
            self.pc, line_s, self.mnemonic, self.operands
        )?;
        if let Some(ref c) = self.comment {
            write!(f, "  ; {c}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- LuaVersion ---

    #[test]
    fn version_from_byte_51() {
        assert_eq!(LuaVersion::from_byte(0x51), Some(LuaVersion::Lua51));
    }

    #[test]
    fn version_from_byte_unknown() {
        assert_eq!(LuaVersion::from_byte(0x60), None);
    }

    #[test]
    fn version_has_integer_type() {
        assert!(LuaVersion::Lua53.has_integer_type());
        assert!(!LuaVersion::Lua52.has_integer_type());
    }

    #[test]
    fn version_has_bitwise_ops() {
        assert!(LuaVersion::Lua53.has_bitwise_ops());
        assert!(!LuaVersion::Lua51.has_bitwise_ops());
    }

    #[test]
    fn version_has_loadkx() {
        assert!(LuaVersion::Lua52.has_loadkx());
        assert!(!LuaVersion::Lua51.has_loadkx());
    }

    #[test]
    fn version_display() {
        assert_eq!(format!("{}", LuaVersion::Lua51), "5.1");
    }

    #[test]
    fn version_byte_roundtrip() {
        for v in [
            LuaVersion::Lua51,
            LuaVersion::Lua52,
            LuaVersion::Lua53,
            LuaVersion::Lua54,
        ] {
            assert_eq!(LuaVersion::from_byte(v.version_byte()), Some(v));
        }
    }

    // --- LuaLocalVar ---

    #[test]
    fn local_var_is_live() {
        let lv = LuaLocalVar {
            name: "x".into(),
            start_pc: 5,
            end_pc: 15,
            slot: 0,
        };
        assert!(lv.is_live_at(10));
        assert!(!lv.is_live_at(4));
        assert!(!lv.is_live_at(15));
    }

    #[test]
    fn local_var_live_range() {
        let lv = LuaLocalVar {
            name: "x".into(),
            start_pc: 5,
            end_pc: 15,
            slot: 0,
        };
        assert_eq!(lv.live_range(), 10);
    }

    #[test]
    fn local_var_is_internal() {
        let iv = LuaLocalVar {
            name: "(for index)".into(),
            start_pc: 0,
            end_pc: 10,
            slot: 0,
        };
        assert!(iv.is_internal());
        let uv = LuaLocalVar {
            name: "x".into(),
            start_pc: 0,
            end_pc: 10,
            slot: 0,
        };
        assert!(!uv.is_internal());
    }

    // --- LuaUpvalue ---

    #[test]
    fn upvalue_display_name_known() {
        let uv = LuaUpvalue {
            name: Some("_ENV".into()),
            in_stack: false,
            idx: 0,
        };
        assert_eq!(uv.display_name(), "_ENV");
    }

    #[test]
    fn upvalue_display_name_anon() {
        let uv = LuaUpvalue {
            name: None,
            in_stack: true,
            idx: 0,
        };
        assert_eq!(uv.display_name(), "(anonymous)");
    }

    // --- LuaSourceMap ---

    #[test]
    fn source_map_line_at() {
        let sm = LuaSourceMap::new(None, vec![0, 5, 5, 6, 7], 1, 10);
        assert_eq!(sm.line_at(2), Some(5));
        assert_eq!(sm.line_at(0), None); // 0 is sentinel
    }

    #[test]
    fn source_map_unique_lines() {
        let sm = LuaSourceMap::new(None, vec![1, 1, 2, 2, 3], 1, 5);
        assert_eq!(sm.unique_lines(), vec![1, 2, 3]);
    }

    #[test]
    fn source_map_pcs_for_line() {
        let sm = LuaSourceMap::new(None, vec![1, 2, 2, 3], 1, 5);
        let pcs = sm.pcs_for_line(2);
        assert_eq!(pcs, vec![1, 2]);
    }

    #[test]
    fn source_map_clean_source_at() {
        let sm = LuaSourceMap::new(Some("@main.lua".into()), vec![], 0, 0);
        assert_eq!(sm.clean_source(), "main.lua");
    }

    #[test]
    fn source_map_clean_source_eq() {
        let sm = LuaSourceMap::new(Some("=(stdin)".into()), vec![], 0, 0);
        assert_eq!(sm.clean_source(), "(stdin)");
    }

    #[test]
    fn source_map_no_source() {
        let sm = LuaSourceMap::new(None, vec![], 0, 0);
        assert_eq!(sm.clean_source(), "(unknown)");
    }

    // --- LuaProtoDebugInfo ---

    #[test]
    fn proto_debug_locals_at_pc() {
        let mut p = LuaProtoDebugInfo::new(LuaVersion::Lua51, None);
        p.locals.push(LuaLocalVar {
            name: "x".into(),
            start_pc: 0,
            end_pc: 10,
            slot: 0,
        });
        p.locals.push(LuaLocalVar {
            name: "y".into(),
            start_pc: 5,
            end_pc: 20,
            slot: 1,
        });
        let live = p.locals_at_pc(7);
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn proto_debug_total_instrs() {
        let mut p = LuaProtoDebugInfo::new(LuaVersion::Lua51, None);
        p.instr_count = 10;
        let mut child = LuaProtoDebugInfo::new(LuaVersion::Lua51, None);
        child.instr_count = 5;
        p.children.push(child);
        assert_eq!(p.total_instrs(), 15);
    }

    #[test]
    fn proto_debug_flatten() {
        let mut p = LuaProtoDebugInfo::new(LuaVersion::Lua51, None);
        p.children
            .push(LuaProtoDebugInfo::new(LuaVersion::Lua51, None));
        let flat = p.flatten();
        assert_eq!(flat.len(), 2);
    }

    // --- LuaDebugDb ---

    #[test]
    fn debug_db_total_protos() {
        let mut db = LuaDebugDb::new();
        let mut root = LuaProtoDebugInfo::new(LuaVersion::Lua51, Some("@main.lua".into()));
        root.children.push(LuaProtoDebugInfo::new(
            LuaVersion::Lua51,
            Some("@main.lua".into()),
        ));
        db.set_root(root);
        assert_eq!(db.total_protos(), 2);
    }

    #[test]
    fn debug_db_version() {
        let mut db = LuaDebugDb::new();
        db.set_root(LuaProtoDebugInfo::new(LuaVersion::Lua53, None));
        assert_eq!(db.version, Some(LuaVersion::Lua53));
    }

    // --- LuaDisasmLine ---

    #[test]
    fn disasm_line_display() {
        let line = LuaDisasmLine {
            pc: 5,
            raw: 0,
            mnemonic: "MOVE".into(),
            operands: "1 2 0".into(),
            source_line: Some(10),
            comment: Some("x = y".into()),
        };
        let s = format!("{line}");
        assert!(s.contains("MOVE"));
        assert!(s.contains("x = y"));
    }

    #[test]
    fn disasm_line_no_comment() {
        let line = LuaDisasmLine {
            pc: 0,
            raw: 0,
            mnemonic: "RETURN".into(),
            operands: "0 1".into(),
            source_line: None,
            comment: None,
        };
        let s = format!("{line}");
        assert!(!s.contains(';'));
    }
}
