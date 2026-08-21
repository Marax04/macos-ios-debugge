//! `lua_closure_analyzer` — Upvalue capture and closure analysis for Lua.
//!
//! Provides [`LuaClosureAnalyzer`], [`ClosureInfo`], and [`UpvalueCapture`]
//! for reasoning about how Lua closures capture upvalues from enclosing scopes.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueCaptureKind
// ─────────────────────────────────────────────────────────────────────────────

/// How an upvalue was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpvalueCaptureKind {
    /// The upvalue is a direct register in the enclosing function's frame.
    Local { register: u8 },
    /// The upvalue is itself an upvalue of the parent (upvalue chaining).
    Upvalue { parent_index: u8 },
    /// The upvalue is the enclosing function's environment table (`_ENV`).
    Environment,
}

impl fmt::Display for UpvalueCaptureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local { register } => write!(f, "local(R[{register}])"),
            Self::Upvalue { parent_index } => write!(f, "upvalue[{parent_index}]"),
            Self::Environment => write!(f, "_ENV"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueCapture
// ─────────────────────────────────────────────────────────────────────────────

/// An upvalue captured by a closure.
#[derive(Debug, Clone)]
pub struct UpvalueCapture {
    /// Index of this upvalue within the closure.
    pub index: u8,
    /// Optional name from debug info.
    pub name: Option<String>,
    /// How it was captured.
    pub kind: UpvalueCaptureKind,
    /// Whether the upvalue has been marked as "closed" (on the heap).
    pub is_closed: bool,
    /// Whether this upvalue is shared with other closures.
    pub is_shared: bool,
}

impl UpvalueCapture {
    /// Create a new upvalue capture from a local register.
    #[must_use]
    pub const fn from_local(index: u8, register: u8) -> Self {
        Self {
            index,
            name: None,
            kind: UpvalueCaptureKind::Local { register },
            is_closed: false,
            is_shared: false,
        }
    }

    /// Create a new upvalue capture from a parent upvalue.
    #[must_use]
    pub const fn from_parent_upvalue(index: u8, parent_index: u8) -> Self {
        Self {
            index,
            name: None,
            kind: UpvalueCaptureKind::Upvalue { parent_index },
            is_closed: false,
            is_shared: false,
        }
    }

    /// Create the environment upvalue.
    #[must_use]
    pub fn environment(index: u8) -> Self {
        Self {
            index,
            name: Some("_ENV".into()),
            kind: UpvalueCaptureKind::Environment,
            is_closed: false,
            is_shared: false,
        }
    }

    /// Set the debug name (builder style).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Return the display name for this upvalue.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("upv_{}", self.index))
    }
}

impl fmt::Display for UpvalueCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} = {} (closed={}, shared={})",
            self.index,
            self.display_name(),
            self.kind,
            self.is_closed,
            self.is_shared,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClosureRef
// ─────────────────────────────────────────────────────────────────────────────

/// A reference to a nested closure created inside a proto.
#[derive(Debug, Clone)]
pub struct ClosureRef {
    /// Index in the parent proto's instruction stream where `CLOSURE` appears.
    pub creation_pc: usize,
    /// Proto index of the nested function.
    pub proto_index: u32,
    /// The upvalues captured by this nested closure.
    pub captures: Vec<UpvalueCapture>,
}

impl ClosureRef {
    #[must_use]
    pub const fn new(creation_pc: usize, proto_index: u32) -> Self {
        Self {
            creation_pc,
            proto_index,
            captures: Vec::new(),
        }
    }

    /// Return the number of upvalues.
    #[must_use]
    pub const fn upvalue_count(&self) -> usize {
        self.captures.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClosureInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Closure analysis result for a single Lua proto (function).
#[derive(Debug, Clone)]
pub struct ClosureInfo {
    /// Proto index.
    pub proto_index: u32,
    /// Optional function name (from debug info or heuristic).
    pub name: Option<String>,
    /// Number of fixed parameters.
    pub n_params: u8,
    /// Whether this is a vararg function.
    pub is_vararg: bool,
    /// Maximum stack size used.
    pub max_stack: u8,
    /// Upvalues captured by *this* function.
    pub upvalues: Vec<UpvalueCapture>,
    /// Nested closures created within this function.
    pub nested_closures: Vec<ClosureRef>,
    /// Set of register indices that are closed over by nested closures
    /// (potential "open upvalue" sources).
    pub closed_registers: Vec<u8>,
    /// Whether this function references `_ENV`.
    pub uses_env: bool,
}

impl ClosureInfo {
    /// Create a new empty `ClosureInfo`.
    #[must_use]
    pub const fn new(proto_index: u32) -> Self {
        Self {
            proto_index,
            name: None,
            n_params: 0,
            is_vararg: false,
            max_stack: 0,
            upvalues: Vec::new(),
            nested_closures: Vec::new(),
            closed_registers: Vec::new(),
            uses_env: false,
        }
    }

    /// Return the number of upvalues.
    #[must_use]
    pub const fn upvalue_count(&self) -> usize {
        self.upvalues.len()
    }

    /// Return `true` if this function has any nested closures.
    #[must_use]
    pub const fn has_nested_closures(&self) -> bool {
        !self.nested_closures.is_empty()
    }

    /// Return the display name.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("proto_{}", self.proto_index))
    }

    /// Return upvalues captured from locals (open captures).
    #[must_use]
    pub fn open_captures(&self) -> Vec<&UpvalueCapture> {
        self.upvalues
            .iter()
            .filter(|u| matches!(u.kind, UpvalueCaptureKind::Local { .. }))
            .collect()
    }

    /// Return upvalues that chain from the parent.
    #[must_use]
    pub fn chained_captures(&self) -> Vec<&UpvalueCapture> {
        self.upvalues
            .iter()
            .filter(|u| matches!(u.kind, UpvalueCaptureKind::Upvalue { .. }))
            .collect()
    }

    /// Return `true` if register `r` is captured as an upvalue by any nested closure.
    #[must_use]
    pub fn register_is_captured(&self, r: u8) -> bool {
        self.closed_registers.contains(&r)
    }
}

impl fmt::Display for ClosureInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClosureInfo({}, upv={}, nested={})",
            self.display_name(),
            self.upvalues.len(),
            self.nested_closures.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueDesc — raw bytecode descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Raw descriptor as found in the bytecode header (`UpvalueDesc` in lobject.h).
#[derive(Debug, Clone, Copy)]
pub struct UpvalueDesc {
    /// `instack`: 1 = capture local from parent stack, 0 = capture parent upvalue.
    pub in_stack: u8,
    /// Index: if `in_stack=1`, register index; if `in_stack=0`, parent upvalue index.
    pub idx: u8,
    /// Lua 5.4 kind field (0 = normal, 1 = close).
    pub kind: u8,
}

impl UpvalueDesc {
    /// Build an [`UpvalueCapture`] from this descriptor.
    #[must_use]
    pub const fn to_capture(self, upv_index: u8) -> UpvalueCapture {
        if self.in_stack == 1 {
            UpvalueCapture::from_local(upv_index, self.idx)
        } else {
            UpvalueCapture::from_parent_upvalue(upv_index, self.idx)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaClosureAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzes closure structures across all protos in a Lua chunk.
pub struct LuaClosureAnalyzer {
    /// One `ClosureInfo` per proto.
    pub infos: Vec<ClosureInfo>,
    /// Proto index of the top-level function.
    pub top_level: u32,
    /// Map from `proto_index` → list of (`parent_proto`, `creation_pc`).
    pub parent_map: HashMap<u32, (u32, usize)>,
}

impl LuaClosureAnalyzer {
    /// Create a new analyzer for a chunk with `n_protos` protos.
    #[must_use]
    pub fn new(n_protos: u32) -> Self {
        let infos = (0..n_protos).map(ClosureInfo::new).collect();
        Self {
            infos,
            top_level: 0,
            parent_map: HashMap::new(),
        }
    }

    /// Register that `child_proto` is created inside `parent_proto` at `pc`.
    pub fn register_nesting(&mut self, parent_proto: u32, child_proto: u32, pc: usize) {
        self.parent_map.insert(child_proto, (parent_proto, pc));
        // Extract child captures first to avoid simultaneous mut+immut borrows.
        let child_captures = self.infos
            .get(child_proto as usize)
            .map(|c| c.upvalues.clone())
            .unwrap_or_default();
        if let Some(parent) = self.infos.get_mut(parent_proto as usize) {
            let mut cr = ClosureRef::new(pc, child_proto);
            cr.captures = child_captures;
            parent.nested_closures.push(cr);
        }
    }

    /// Populate upvalue captures for proto `idx` from raw descriptors.
    pub fn populate_upvalues(&mut self, idx: u32, descs: &[UpvalueDesc], names: &[Option<String>]) {
        if let Some(info) = self.infos.get_mut(idx as usize) {
            info.upvalues.clear();
            for (i, desc) in descs.iter().enumerate() {
                let mut cap = desc.to_capture(u8::try_from(i).unwrap_or(u8::MAX));
                if let Some(name) = names.get(i).and_then(|n| n.as_ref()) {
                    cap = cap.with_name(name.clone());
                    if name == "_ENV" {
                        info.uses_env = true;
                    }
                }
                if matches!(cap.kind, UpvalueCaptureKind::Environment) {
                    info.uses_env = true;
                }
                info.upvalues.push(cap);
            }
        }
    }

    /// Mark which registers in `proto_idx` are captured by any of its nested closures.
    pub fn compute_closed_registers(&mut self, proto_idx: u32) {
        // Collect child capture info without borrowing self.
        let nested: Vec<u32> = self
            .infos
            .get(proto_idx as usize)
            .map(|info| info.nested_closures.iter().map(|c| c.proto_index).collect())
            .unwrap_or_default();

        let mut closed: Vec<u8> = Vec::new();
        for child_idx in nested {
            if let Some(child) = self.infos.get(child_idx as usize) {
                for cap in &child.upvalues {
                    if let UpvalueCaptureKind::Local { register } = cap.kind
                        && !closed.contains(&register) {
                            closed.push(register);
                        }
                }
            }
        }
        if let Some(info) = self.infos.get_mut(proto_idx as usize) {
            info.closed_registers = closed;
        }
    }

    /// Mark upvalues as shared if the same register is captured by multiple children.
    pub fn mark_shared_upvalues(&mut self, proto_idx: u32) {
        let nested: Vec<u32> = self
            .infos
            .get(proto_idx as usize)
            .map(|info| info.nested_closures.iter().map(|c| c.proto_index).collect())
            .unwrap_or_default();

        let mut reg_count: HashMap<u8, u32> = HashMap::new();
        for child_idx in &nested {
            if let Some(child) = self.infos.get(*child_idx as usize) {
                for cap in &child.upvalues {
                    if let UpvalueCaptureKind::Local { register } = cap.kind {
                        *reg_count.entry(register).or_insert(0) += 1;
                    }
                }
            }
        }

        for child_idx in nested {
            if let Some(child) = self.infos.get_mut(child_idx as usize) {
                for cap in &mut child.upvalues {
                    if let UpvalueCaptureKind::Local { register } = cap.kind
                        && reg_count.get(&register).copied().unwrap_or(0) > 1 {
                            cap.is_shared = true;
                        }
                }
            }
        }
    }

    /// Return the parent proto of `proto_idx`, if known.
    #[must_use]
    pub fn parent_of(&self, proto_idx: u32) -> Option<u32> {
        self.parent_map.get(&proto_idx).map(|(p, _)| *p)
    }

    /// Return the `ClosureInfo` for proto `idx`.
    #[must_use]
    pub fn info(&self, idx: u32) -> Option<&ClosureInfo> {
        self.infos.get(idx as usize)
    }

    /// Return a mutable reference to the `ClosureInfo` for proto `idx`.
    #[must_use]
    pub fn info_mut(&mut self, idx: u32) -> Option<&mut ClosureInfo> {
        self.infos.get_mut(idx as usize)
    }

    /// Return all protos that capture at least one upvalue.
    #[must_use]
    pub fn closures_with_upvalues(&self) -> Vec<&ClosureInfo> {
        self.infos.iter().filter(|i| !i.upvalues.is_empty()).collect()
    }

    /// Return all protos that reference `_ENV`.
    #[must_use]
    pub fn protos_using_env(&self) -> Vec<&ClosureInfo> {
        self.infos.iter().filter(|i| i.uses_env).collect()
    }

    /// Total number of upvalue captures across all protos.
    #[must_use]
    pub fn total_upvalue_count(&self) -> usize {
        self.infos.iter().map(|i| i.upvalues.len()).sum()
    }
}

impl fmt::Debug for LuaClosureAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaClosureAnalyzer")
            .field("n_protos", &self.infos.len())
            .field("total_upvalues", &self.total_upvalue_count())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upvalue_capture_from_local() {
        let cap = UpvalueCapture::from_local(0, 3).with_name("x");
        assert_eq!(cap.index, 0);
        assert_eq!(cap.name, Some("x".into()));
        assert!(matches!(cap.kind, UpvalueCaptureKind::Local { register: 3 }));
    }

    #[test]
    fn upvalue_capture_environment() {
        let cap = UpvalueCapture::environment(0);
        assert_eq!(cap.name, Some("_ENV".into()));
        assert!(matches!(cap.kind, UpvalueCaptureKind::Environment));
    }

    #[test]
    fn upvalue_capture_display() {
        let cap = UpvalueCapture::from_local(0, 5).with_name("y");
        let s = cap.to_string();
        assert!(s.contains("local(R[5])"));
        assert!(s.contains('y'));
    }

    #[test]
    fn upvalue_desc_to_capture_local() {
        let desc = UpvalueDesc { in_stack: 1, idx: 2, kind: 0 };
        let cap = desc.to_capture(0);
        assert!(matches!(cap.kind, UpvalueCaptureKind::Local { register: 2 }));
    }

    #[test]
    fn upvalue_desc_to_capture_parent() {
        let desc = UpvalueDesc { in_stack: 0, idx: 1, kind: 0 };
        let cap = desc.to_capture(1);
        assert!(matches!(cap.kind, UpvalueCaptureKind::Upvalue { parent_index: 1 }));
    }

    #[test]
    fn closure_info_new() {
        let info = ClosureInfo::new(0);
        assert_eq!(info.proto_index, 0);
        assert!(info.upvalues.is_empty());
        assert!(!info.has_nested_closures());
    }

    #[test]
    fn closure_info_display_name() {
        let mut info = ClosureInfo::new(3);
        assert_eq!(info.display_name(), "proto_3");
        info.name = Some("my_func".into());
        assert_eq!(info.display_name(), "my_func");
    }

    #[test]
    fn closure_info_open_vs_chained() {
        let mut info = ClosureInfo::new(0);
        info.upvalues.push(UpvalueCapture::from_local(0, 1));
        info.upvalues.push(UpvalueCapture::from_parent_upvalue(1, 0));
        assert_eq!(info.open_captures().len(), 1);
        assert_eq!(info.chained_captures().len(), 1);
    }

    #[test]
    fn closure_info_register_captured() {
        let mut info = ClosureInfo::new(0);
        info.closed_registers = vec![2, 5];
        assert!(info.register_is_captured(2));
        assert!(!info.register_is_captured(3));
    }

    #[test]
    fn analyzer_nesting() {
        let mut a = LuaClosureAnalyzer::new(3);
        a.register_nesting(0, 1, 10);
        a.register_nesting(0, 2, 20);
        assert_eq!(a.infos[0].nested_closures.len(), 2);
        assert_eq!(a.parent_of(1), Some(0));
        assert_eq!(a.parent_of(0), None);
    }

    #[test]
    fn analyzer_populate_upvalues() {
        let mut a = LuaClosureAnalyzer::new(2);
        let descs = vec![
            UpvalueDesc { in_stack: 1, idx: 0, kind: 0 },
            UpvalueDesc { in_stack: 0, idx: 0, kind: 0 },
        ];
        let names = vec![Some("x".into()), None];
        a.populate_upvalues(1, &descs, &names);
        let info = a.info(1).unwrap();
        assert_eq!(info.upvalue_count(), 2);
        assert_eq!(info.upvalues[0].name, Some("x".into()));
    }

    #[test]
    fn analyzer_uses_env() {
        let mut a = LuaClosureAnalyzer::new(2);
        let descs = vec![UpvalueDesc { in_stack: 1, idx: 0, kind: 0 }];
        let names = vec![Some("_ENV".into())];
        a.populate_upvalues(1, &descs, &names);
        assert!(a.info(1).unwrap().uses_env);
    }

    #[test]
    fn analyzer_compute_closed_registers() {
        let mut a = LuaClosureAnalyzer::new(2);
        a.register_nesting(0, 1, 5);
        let descs = vec![UpvalueDesc { in_stack: 1, idx: 3, kind: 0 }];
        a.populate_upvalues(1, &descs, &[]);
        a.register_nesting(0, 1, 5); // re-register so parent has child
        a.compute_closed_registers(0);
        assert!(a.info(0).unwrap().register_is_captured(3));
    }

    #[test]
    fn analyzer_closures_with_upvalues() {
        let mut a = LuaClosureAnalyzer::new(3);
        let descs = vec![UpvalueDesc { in_stack: 1, idx: 0, kind: 0 }];
        a.populate_upvalues(2, &descs, &[]);
        let list = a.closures_with_upvalues();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].proto_index, 2);
    }

    #[test]
    fn analyzer_total_upvalue_count() {
        let mut a = LuaClosureAnalyzer::new(3);
        let d1 = vec![UpvalueDesc { in_stack: 1, idx: 0, kind: 0 }];
        let d2 = vec![
            UpvalueDesc { in_stack: 1, idx: 1, kind: 0 },
            UpvalueDesc { in_stack: 0, idx: 0, kind: 0 },
        ];
        a.populate_upvalues(0, &d1, &[]);
        a.populate_upvalues(1, &d2, &[]);
        assert_eq!(a.total_upvalue_count(), 3);
    }

    #[test]
    fn closure_ref_upvalue_count() {
        let mut cr = ClosureRef::new(0, 1);
        cr.captures.push(UpvalueCapture::from_local(0, 0));
        assert_eq!(cr.upvalue_count(), 1);
    }

    #[test]
    fn upvalue_capture_kind_display() {
        assert_eq!(UpvalueCaptureKind::Local { register: 0 }.to_string(), "local(R[0])");
        assert_eq!(UpvalueCaptureKind::Upvalue { parent_index: 2 }.to_string(), "upvalue[2]");
        assert_eq!(UpvalueCaptureKind::Environment.to_string(), "_ENV");
    }

    #[test]
    fn analyzer_protos_using_env() {
        let mut a = LuaClosureAnalyzer::new(3);
        let descs = vec![UpvalueDesc { in_stack: 1, idx: 0, kind: 0 }];
        a.populate_upvalues(1, &descs, &[Some("_ENV".into())]);
        let envs = a.protos_using_env();
        assert_eq!(envs.len(), 1);
    }

    #[test]
    fn analyzer_debug() {
        let a = LuaClosureAnalyzer::new(4);
        let s = format!("{a:?}");
        assert!(s.contains("n_protos"));
    }
}
