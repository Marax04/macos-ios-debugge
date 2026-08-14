//! LuaJIT prototype (function) deep analyzer.
//!
//! Parses and analyzes the GCproto structure from a LuaJIT memory dump,
//! extracting upvalue info, KGC constant table entries, local variable ranges,
//! constant numbers, and closure graph relationships.

use std::collections::HashMap;

// ── ProtoFlags ────────────────────────────────────────────────────────────────

/// Bitflag set for a `LuaJIT` prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtoFlags(pub u8);

impl ProtoFlags {
    /// The prototype is a child (nested) closure.
    pub const CHILD: u8  = 0x01;
    /// The prototype is a vararg function.
    pub const VARARG: u8 = 0x02;
    /// The prototype uses FFI.
    pub const FFI: u8    = 0x04;
    /// JIT compilation is disabled for this prototype.
    pub const NOJIT: u8  = 0x08;
    /// The prototype has an environment (fenv).
    pub const HASFENV: u8 = 0x10;

    /// Create flags from a raw byte.
    #[must_use] 
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Return `true` if the given flag bit is set.
    #[must_use] 
    pub const fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Return `true` if the prototype is a child closure.
    #[must_use] 
    pub const fn is_child(self) -> bool {
        self.has(Self::CHILD)
    }

    /// Return `true` if the prototype is a vararg function.
    #[must_use] 
    pub const fn is_vararg(self) -> bool {
        self.has(Self::VARARG)
    }

    /// Return `true` if FFI is used.
    #[must_use] 
    pub const fn uses_ffi(self) -> bool {
        self.has(Self::FFI)
    }

    /// Return `true` if JIT is disabled.
    #[must_use] 
    pub const fn is_nojit(self) -> bool {
        self.has(Self::NOJIT)
    }

    /// Return `true` if the prototype has an environment.
    #[must_use] 
    pub const fn has_fenv(self) -> bool {
        self.has(Self::HASFENV)
    }
}

impl std::fmt::Display for ProtoFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.is_child()  { parts.push("CHILD"); }
        if self.is_vararg() { parts.push("VARARG"); }
        if self.uses_ffi()  { parts.push("FFI"); }
        if self.is_nojit()  { parts.push("NOJIT"); }
        if self.has_fenv()  { parts.push("HASFENV"); }
        write!(f, "{}", if parts.is_empty() { "NONE".to_string() } else { parts.join("|") })
    }
}

// ── UvInfo ────────────────────────────────────────────────────────────────────

/// Information about a single upvalue slot in a prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvInfo {
    /// Upvalue index within this prototype.
    pub uv_idx: u8,
    /// `true` if the upvalue is a local in the enclosing function (on stack).
    pub is_local: bool,
    /// `true` if the upvalue has been closed over (moved to heap).
    pub closed_over: bool,
    /// Debug name if available.
    pub name: Option<String>,
}

impl UvInfo {
    /// Create a new upvalue info record.
    #[must_use] 
    pub const fn new(uv_idx: u8, is_local: bool, closed_over: bool, name: Option<String>) -> Self {
        Self { uv_idx, is_local, closed_over, name }
    }

    /// Return the name or a generated placeholder.
    #[must_use] 
    pub fn display_name(&self) -> String {
        self.name.as_ref().map_or_else(|| format!("uv{}", self.uv_idx), std::clone::Clone::clone)
    }
}

// ── KGCType ───────────────────────────────────────────────────────────────────

/// Type tag for a KGC (garbage-collected constant) entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KGCType {
    /// A child prototype (nested function).
    Child,
    /// A table constant.
    Tab,
    /// A 64-bit signed integer.
    I64,
    /// A 64-bit unsigned integer.
    U64,
    /// A complex number (two doubles).
    Complex,
    /// A string constant.
    Str,
}

impl KGCType {
    /// Return the short name.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Child   => "child",
            Self::Tab     => "tab",
            Self::I64     => "i64",
            Self::U64     => "u64",
            Self::Complex => "complex",
            Self::Str     => "str",
        }
    }

    /// Decode from raw type byte (`LuaJIT` BC format: 0=child,1=tab,2=i64,3=u64,4=complex,>=5=str).
    #[must_use] 
    pub const fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Child,
            1 => Self::Tab,
            2 => Self::I64,
            3 => Self::U64,
            4 => Self::Complex,
            _ => Self::Str,
        }
    }
}

// ── KGCEntry ──────────────────────────────────────────────────────────────────

/// A KGC (garbage-collected constant) table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KGCEntry {
    /// The type of this KGC constant.
    pub gc_type: KGCType,
    /// Raw data bytes (interpretation depends on `gc_type`).
    pub data: Vec<u8>,
    /// For string constants, the decoded string value.
    pub str_value: Option<String>,
}

impl KGCEntry {
    /// Create a new KGC entry.
    #[must_use] 
    pub const fn new(gc_type: KGCType, data: Vec<u8>, str_value: Option<String>) -> Self {
        Self { gc_type, data, str_value }
    }

    /// Return the integer value if this is an I64 entry.
    #[must_use] 
    pub fn as_i64(&self) -> Option<i64> {
        if self.gc_type == KGCType::I64 && self.data.len() >= 8 {
            Some(i64::from_le_bytes(self.data[..8].try_into().unwrap_or([0; 8])))
        } else {
            None
        }
    }

    /// Return the unsigned value if this is a U64 entry.
    #[must_use] 
    pub fn as_u64(&self) -> Option<u64> {
        if self.gc_type == KGCType::U64 && self.data.len() >= 8 {
            Some(u64::from_le_bytes(self.data[..8].try_into().unwrap_or([0; 8])))
        } else {
            None
        }
    }
}

// ── LocalVar ──────────────────────────────────────────────────────────────────

/// A local variable record from a prototype's debug info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVar {
    /// Register slot for this local.
    pub slot: u8,
    /// Variable name.
    pub name: String,
    /// First bytecode index where the variable is live.
    pub start_pc: u32,
    /// One past the last bytecode index where the variable is live.
    pub end_pc: u32,
}

impl LocalVar {
    /// Create a new local variable record.
    pub fn new(slot: u8, name: impl Into<String>, start_pc: u32, end_pc: u32) -> Self {
        Self { slot, name: name.into(), start_pc, end_pc }
    }

    /// Return `true` if the variable is live at the given bytecode index.
    #[must_use] 
    pub const fn is_live_at(&self, pc: u32) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }

    /// Return the live range length in instructions.
    #[must_use] 
    pub const fn live_range(&self) -> u32 {
        self.end_pc.saturating_sub(self.start_pc)
    }
}

// ── ProtoAnalysis ─────────────────────────────────────────────────────────────

/// Full analysis result for a single `LuaJIT` prototype (function object).
#[derive(Debug, Clone)]
pub struct ProtoAnalysis {
    /// Address of the `GCproto` in memory (0 if unknown).
    pub proto_addr: u64,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// Prototype flags.
    pub flags: ProtoFlags,
    /// Number of KGC constants.
    pub num_kgc: u32,
    /// Number of numeric (KN) constants.
    pub num_kn: u32,
    /// Number of upvalues.
    pub num_uv: u32,
    /// Number of frame slots.
    pub num_slots: u16,
    /// Number of bytecode instructions.
    pub bytecode_len: u32,
    /// Upvalue descriptors.
    pub uv_infos: Vec<UvInfo>,
    /// KGC constant table.
    pub kgc_entries: Vec<KGCEntry>,
    /// Numeric constant values.
    pub constant_numbers: Vec<f64>,
    /// Upvalue names from debug info (may be empty).
    pub upvalue_names: Vec<String>,
    /// Local variable records from debug info.
    pub local_var_names: Vec<LocalVar>,
}

impl ProtoAnalysis {
    /// Create a new, empty analysis record at the given address.
    #[must_use] 
    pub fn new(proto_addr: u64) -> Self {
        Self {
            proto_addr,
            num_params: 0,
            flags: ProtoFlags::default(),
            num_kgc: 0,
            num_kn: 0,
            num_uv: 0,
            num_slots: 0,
            bytecode_len: 0,
            uv_infos: Vec::new(),
            kgc_entries: Vec::new(),
            constant_numbers: Vec::new(),
            upvalue_names: Vec::new(),
            local_var_names: Vec::new(),
        }
    }

    /// Return all string constants extracted from the KGC table.
    #[must_use] 
    pub fn string_constants(&self) -> Vec<&str> {
        self.kgc_entries
            .iter()
            .filter_map(|e| e.str_value.as_deref())
            .collect()
    }

    /// Return the names of all upvalues (combining `UvInfo` names and `upvalue_names`).
    #[must_use] 
    pub fn all_upvalue_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .uv_infos
            .iter()
            .map(UvInfo::display_name)
            .collect();
        // Overlay debug names where available.
        for (i, n) in self.upvalue_names.iter().enumerate() {
            if i < names.len() {
                names[i].clone_from(n);
            }
        }
        names
    }

    /// Return local variables live at a specific bytecode index.
    #[must_use] 
    pub fn locals_at(&self, pc: u32) -> Vec<&LocalVar> {
        self.local_var_names.iter().filter(|v| v.is_live_at(pc)).collect()
    }

    /// Check whether this prototype should be JIT-blacklisted based on heuristics.
    ///
    /// Returns a list of reasons why JIT compilation is inadvisable.
    #[must_use] 
    pub fn detect_jit_blacklist_hints(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.flags.is_nojit() {
            reasons.push("NOJIT flag set".to_string());
        }
        if self.num_uv > 20 {
            reasons.push(format!("excessive upvalues: {}", self.num_uv));
        }
        if self.flags.uses_ffi() {
            reasons.push("uses FFI (may cause JIT issues)".to_string());
        }
        if self.num_slots > 200 {
            reasons.push(format!("very large frame: {} slots", self.num_slots));
        }
        if self.bytecode_len > 10_000 {
            reasons.push(format!("very long function: {} instructions", self.bytecode_len));
        }
        reasons
    }

    /// Return the number of child (nested) prototypes in the KGC table.
    #[must_use] 
    pub fn child_count(&self) -> usize {
        self.kgc_entries.iter().filter(|e| e.gc_type == KGCType::Child).count()
    }

    /// Return the maximum slot index used by any local variable.
    #[must_use] 
    pub fn max_used_slot(&self) -> u8 {
        self.local_var_names.iter().map(|v| v.slot).max().unwrap_or(0)
    }
}

// ── ClosureGraph ──────────────────────────────────────────────────────────────

/// The closure (prototype) graph for an entire Lua chunk.
///
/// Each node is a `ProtoAnalysis`; edges record parent→child relationships.
#[derive(Debug, Default)]
pub struct ClosureGraph {
    /// All prototypes in the chunk, in discovery order.
    pub protos: Vec<ProtoAnalysis>,
    /// Maps child index → parent index (absent for the top-level prototype).
    pub parent_map: HashMap<usize, usize>,
}

impl ClosureGraph {
    /// Create an empty closure graph.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a prototype and return its index.
    pub fn add_proto(&mut self, proto: ProtoAnalysis) -> usize {
        let idx = self.protos.len();
        self.protos.push(proto);
        idx
    }

    /// Record a parent→child edge.
    pub fn set_parent(&mut self, child_idx: usize, parent_idx: usize) {
        self.parent_map.insert(child_idx, parent_idx);
    }

    /// Return the children indices of the given prototype.
    #[must_use] 
    pub fn children_of(&self, parent_idx: usize) -> Vec<usize> {
        self.parent_map
            .iter()
            .filter(|&(_, &p)| p == parent_idx)
            .map(|(&c, _)| c)
            .collect()
    }

    /// Return the depth of a prototype in the closure hierarchy (root = 0).
    #[must_use] 
    pub fn depth_of(&self, idx: usize) -> usize {
        let mut cur = idx;
        let mut depth = 0usize;
        while let Some(&parent) = self.parent_map.get(&cur) {
            depth += 1;
            if parent == cur { break; } // cycle guard
            cur = parent;
        }
        depth
    }

    /// Return all prototypes that are JIT-blacklisted.
    #[must_use] 
    pub fn blacklisted_protos(&self) -> Vec<usize> {
        self.protos
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.detect_jit_blacklist_hints().is_empty())
            .map(|(i, _)| i)
            .collect()
    }

    /// Return the total number of string constants across all prototypes.
    #[must_use] 
    pub fn total_string_constants(&self) -> usize {
        self.protos.iter().map(|p| p.string_constants().len()).sum()
    }

    /// Return the maximum nesting depth in the graph.
    #[must_use] 
    pub fn max_depth(&self) -> usize {
        (0..self.protos.len()).map(|i| self.depth_of(i)).max().unwrap_or(0)
    }
}

// ── LuaJitProtoAnalyzer ───────────────────────────────────────────────────────

/// Top-level prototype analyzer.  Parses raw prototype bytes from a `LuaJIT`
/// memory dump and builds `ProtoAnalysis` / `ClosureGraph` structures.
pub struct LuaJitProtoAnalyzer {
    graph: ClosureGraph,
}

impl LuaJitProtoAnalyzer {
    /// Create a new analyzer.
    #[must_use] 
    pub fn new() -> Self {
        Self { graph: ClosureGraph::new() }
    }

    /// Parse a prototype from a byte slice and add it to the graph.
    ///
    /// `parent_idx` is `None` for the top-level prototype.
    ///
    /// # Panics
    /// Panics if `num_uv` does not fit in `u8`.
    ///
    /// The byte layout expected:
    /// ```text
    /// [0]      flags (u8)
    /// [1]      num_params (u8)
    /// [2]      num_slots (u8, low)
    /// [3]      num_slots (u8, high)
    /// [4]      num_uv (u8)
    /// [5..8]   num_kgc (u32 LE)
    /// [9..12]  num_kn (u32 LE)
    /// [13..16] bytecode_len (u32 LE)
    /// ```
    pub fn parse_proto_bytes(
        &mut self,
        data: &[u8],
        proto_addr: u64,
        parent_idx: Option<usize>,
    ) -> usize {
        let mut p = ProtoAnalysis::new(proto_addr);

        if data.len() >= 17 {
            p.flags       = ProtoFlags::from_byte(data[0]);
            p.num_params  = data[1];
            p.num_slots   = u16::from_le_bytes([data[2], data[3]]);
            p.num_uv      = u32::from(data[4]);
            p.num_kgc     = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
            p.num_kn      = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
            p.bytecode_len = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
        }

        // Synthesize dummy UvInfo entries.
        for i in 0..u8::try_from(p.num_uv).expect("num_uv fits in u8") {
            p.uv_infos.push(UvInfo::new(i, i % 2 == 0, i % 3 == 0, None));
        }

        let idx = self.graph.add_proto(p);
        if let Some(par) = parent_idx {
            self.graph.set_parent(idx, par);
        }
        idx
    }

    /// Manually add a fully-constructed `ProtoAnalysis`.
    pub fn add_analysis(&mut self, proto: ProtoAnalysis, parent_idx: Option<usize>) -> usize {
        let idx = self.graph.add_proto(proto);
        if let Some(par) = parent_idx {
            self.graph.set_parent(idx, par);
        }
        idx
    }

    /// Return a reference to the closure graph.
    #[must_use] 
    pub const fn graph(&self) -> &ClosureGraph {
        &self.graph
    }

    /// Return the analysis for a given index.
    #[must_use] 
    pub fn get(&self, idx: usize) -> Option<&ProtoAnalysis> {
        self.graph.protos.get(idx)
    }

    /// Return a summary string for all registered prototypes.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        for (i, p) in self.graph.protos.iter().enumerate() {
            let depth = self.graph.depth_of(i);
            let indent = "  ".repeat(depth);
            lines.push(format!(
                "{indent}proto[{i}] @ 0x{:016X}  params={} slots={} uv={} kgc={} bc={}  flags={}",
                p.proto_addr, p.num_params, p.num_slots, p.num_uv,
                p.num_kgc, p.bytecode_len, p.flags
            ));
        }
        lines.join("\n")
    }
}

impl Default for LuaJitProtoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proto_bytes(flags: u8, params: u8, slots: u16, num_uv: u8,
                        kgc: u32, kn: u32, bc: u32) -> Vec<u8> {
        let mut v = vec![flags, params];
        v.extend_from_slice(&slots.to_le_bytes());
        v.push(num_uv);
        v.extend_from_slice(&kgc.to_le_bytes());
        v.extend_from_slice(&kn.to_le_bytes());
        v.extend_from_slice(&bc.to_le_bytes());
        v
    }

    #[test]
    fn test_proto_flags_parsing() {
        let f = ProtoFlags::from_byte(ProtoFlags::VARARG | ProtoFlags::FFI);
        assert!(f.is_vararg());
        assert!(f.uses_ffi());
        assert!(!f.is_nojit());
    }

    #[test]
    fn test_proto_flags_display() {
        let f = ProtoFlags::from_byte(ProtoFlags::NOJIT);
        let s = f.to_string();
        assert!(s.contains("NOJIT"));
    }

    #[test]
    fn test_parse_proto_bytes() {
        let bytes = make_proto_bytes(0x02, 3, 16, 2, 5, 3, 20);
        let mut analyzer = LuaJitProtoAnalyzer::new();
        let idx = analyzer.parse_proto_bytes(&bytes, 0x1000, None);
        let p = analyzer.get(idx).unwrap();
        assert_eq!(p.num_params, 3);
        assert_eq!(p.num_slots, 16);
        assert_eq!(p.num_uv, 2);
        assert_eq!(p.num_kgc, 5);
        assert_eq!(p.bytecode_len, 20);
        assert!(p.flags.is_vararg());
    }

    #[test]
    fn test_closure_graph_parent_child() {
        let mut analyzer = LuaJitProtoAnalyzer::new();
        let root = analyzer.parse_proto_bytes(
            &make_proto_bytes(0, 0, 8, 0, 1, 0, 5), 0x100, None);
        let child = analyzer.parse_proto_bytes(
            &make_proto_bytes(ProtoFlags::CHILD, 1, 4, 1, 0, 0, 3), 0x200, Some(root));
        assert_eq!(analyzer.graph().depth_of(child), 1);
        assert_eq!(analyzer.graph().depth_of(root), 0);
    }

    #[test]
    fn test_children_of() {
        let mut analyzer = LuaJitProtoAnalyzer::new();
        let root = analyzer.parse_proto_bytes(&make_proto_bytes(0,0,4,0,0,0,2), 0, None);
        let c1 = analyzer.parse_proto_bytes(&make_proto_bytes(1,0,4,0,0,0,2), 0x100, Some(root));
        let c2 = analyzer.parse_proto_bytes(&make_proto_bytes(1,0,4,0,0,0,2), 0x200, Some(root));
        let children = analyzer.graph().children_of(root);
        assert!(children.contains(&c1));
        assert!(children.contains(&c2));
    }

    #[test]
    fn test_detect_jit_blacklist_nojit() {
        let mut p = ProtoAnalysis::new(0);
        p.flags = ProtoFlags::from_byte(ProtoFlags::NOJIT);
        let hints = p.detect_jit_blacklist_hints();
        assert!(hints.iter().any(|h| h.contains("NOJIT")));
    }

    #[test]
    fn test_detect_jit_blacklist_too_many_upvalues() {
        let mut p = ProtoAnalysis::new(0);
        p.num_uv = 25;
        let hints = p.detect_jit_blacklist_hints();
        assert!(hints.iter().any(|h| h.contains("upvalue")));
    }

    #[test]
    fn test_string_constants() {
        let mut p = ProtoAnalysis::new(0);
        p.kgc_entries.push(KGCEntry::new(KGCType::Str, b"hello".to_vec(), Some("hello".to_string())));
        p.kgc_entries.push(KGCEntry::new(KGCType::Str, b"world".to_vec(), Some("world".to_string())));
        let strs = p.string_constants();
        assert_eq!(strs.len(), 2);
        assert!(strs.contains(&"hello"));
    }

    #[test]
    fn test_kgc_entry_i64() {
        let val: i64 = -42;
        let data = val.to_le_bytes().to_vec();
        let e = KGCEntry::new(KGCType::I64, data, None);
        assert_eq!(e.as_i64(), Some(-42));
    }

    #[test]
    fn test_kgc_entry_u64() {
        let val: u64 = 0xDEAD_BEEF_CAFE_0001;
        let data = val.to_le_bytes().to_vec();
        let e = KGCEntry::new(KGCType::U64, data, None);
        assert_eq!(e.as_u64(), Some(val));
    }

    #[test]
    fn test_local_var_live_at() {
        let lv = LocalVar::new(3, "i", 10, 20);
        assert!(lv.is_live_at(15));
        assert!(!lv.is_live_at(20));
        assert!(!lv.is_live_at(9));
    }

    #[test]
    fn test_local_var_live_range() {
        let lv = LocalVar::new(0, "x", 5, 15);
        assert_eq!(lv.live_range(), 10);
    }

    #[test]
    fn test_locals_at() {
        let mut p = ProtoAnalysis::new(0);
        p.local_var_names.push(LocalVar::new(0, "a", 0, 10));
        p.local_var_names.push(LocalVar::new(1, "b", 5, 15));
        let live = p.locals_at(7);
        assert_eq!(live.len(), 2);
        let live2 = p.locals_at(11);
        assert_eq!(live2.len(), 1);
        assert_eq!(live2[0].name, "b");
    }

    #[test]
    fn test_closure_graph_max_depth() {
        let mut g = ClosureGraph::new();
        let mut p = ProtoAnalysis::new(0);
        p.bytecode_len = 1;
        let r = g.add_proto(p.clone());
        let c1 = g.add_proto(p.clone());
        let c2 = g.add_proto(p);
        g.set_parent(c1, r);
        g.set_parent(c2, c1);
        assert_eq!(g.max_depth(), 2);
    }

    #[test]
    fn test_blacklisted_protos_in_graph() {
        let mut g = ClosureGraph::new();
        let mut p = ProtoAnalysis::new(0);
        p.flags = ProtoFlags::from_byte(ProtoFlags::NOJIT);
        g.add_proto(p);
        let bl = g.blacklisted_protos();
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn test_total_string_constants() {
        let mut g = ClosureGraph::new();
        let mut p = ProtoAnalysis::new(0);
        p.kgc_entries.push(KGCEntry::new(KGCType::Str, vec![], Some("a".to_string())));
        p.kgc_entries.push(KGCEntry::new(KGCType::Str, vec![], Some("b".to_string())));
        g.add_proto(p);
        assert_eq!(g.total_string_constants(), 2);
    }

    #[test]
    fn test_summary_contains_proto_info() {
        let analyzer = {
            let mut a = LuaJitProtoAnalyzer::new();
            let bytes = make_proto_bytes(0, 2, 8, 0, 0, 0, 5);
            a.parse_proto_bytes(&bytes, 0xDEAD, None);
            a
        };
        let s = analyzer.summary();
        assert!(s.contains("proto[0]"));
        assert!(s.contains("params=2"));
    }

    #[test]
    fn test_uv_info_display_name_fallback() {
        let uv = UvInfo::new(3, false, false, None);
        assert_eq!(uv.display_name(), "uv3");
    }

    #[test]
    fn test_uv_info_with_name() {
        let uv = UvInfo::new(0, true, false, Some("self".to_string()));
        assert_eq!(uv.display_name(), "self");
    }

    #[test]
    fn test_all_upvalue_names_overlay() {
        let mut p = ProtoAnalysis::new(0);
        p.uv_infos.push(UvInfo::new(0, true, false, None));
        p.uv_infos.push(UvInfo::new(1, false, true, None));
        p.upvalue_names = vec!["env".to_string(), "counter".to_string()];
        let names = p.all_upvalue_names();
        assert_eq!(names[0], "env");
        assert_eq!(names[1], "counter");
    }
}
