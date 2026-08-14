//! `xref_heuristics` — Heuristic cross-reference analysis.
//!
//! Resolves indirect calls, detects tail calls, analyses jump tables,
//! identifies thunks, and resolves virtual calls via vtable analysis.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeuristicError {
    InsufficientData(String),
    InvalidAddress(u64),
    Ambiguous(String),
}

impl fmt::Display for HeuristicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientData(msg) => write!(f, "insufficient data: {msg}"),
            Self::InvalidAddress(a) => write!(f, "invalid address: {a:#x}"),
            Self::Ambiguous(msg) => write!(f, "ambiguous: {msg}"),
        }
    }
}

impl std::error::Error for HeuristicError {}

// ─── IndirectCallTarget ──────────────────────────────────────────────────────

/// Confidence level for a resolved indirect call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CallTargetConfidence {
    Low,
    Medium,
    High,
    Definitive,
}

/// A resolved target for an indirect call instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallTarget {
    pub call_site: u64,
    pub target: u64,
    pub confidence: CallTargetConfidence,
    pub resolution_method: String,
}

/// Resolves indirect calls via value-set / pointer analysis.
pub struct IndirectCallResolver {
    /// Known pointer → targets mappings (from VSA results).
    pointer_targets: HashMap<u64, Vec<u64>>,
    /// Known function pointers observed at call sites.
    call_site_ptrs: HashMap<u64, HashSet<u64>>,
}

impl IndirectCallResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            pointer_targets: HashMap::new(),
            call_site_ptrs: HashMap::new(),
        }
    }

    /// Register that a pointer variable at `ptr_addr` may point to `target`.
    pub fn register_pointer_target(&mut self, ptr_addr: u64, target: u64) {
        self.pointer_targets
            .entry(ptr_addr)
            .or_default()
            .push(target);
    }

    /// Register an observed function pointer at a call site.
    pub fn register_call_site_ptr(&mut self, call_site: u64, fn_ptr: u64) {
        self.call_site_ptrs
            .entry(call_site)
            .or_default()
            .insert(fn_ptr);
    }

    /// Resolve targets for an indirect call at `call_site` using pointer `ptr_addr`.
    #[must_use] 
    pub fn resolve(&self, call_site: u64, ptr_addr: u64) -> Vec<IndirectCallTarget> {
        let mut targets = Vec::new();

        // Direct pointer targets.
        if let Some(ptrs) = self.pointer_targets.get(&ptr_addr) {
            for &t in ptrs {
                targets.push(IndirectCallTarget {
                    call_site,
                    target: t,
                    confidence: if ptrs.len() == 1 {
                        CallTargetConfidence::High
                    } else {
                        CallTargetConfidence::Medium
                    },
                    resolution_method: "value_set_analysis".into(),
                });
            }
        }

        // Observed function pointers. `call_site_ptrs` is a `HashSet`, whose
        // iteration order is randomized per-process; sort before consuming so
        // the returned `targets` order (and therefore any downstream ids /
        // reports derived from it) is deterministic across runs.
        if let Some(ptrs) = self.call_site_ptrs.get(&call_site) {
            let mut sorted_ptrs: Vec<u64> = ptrs.iter().copied().collect();
            sorted_ptrs.sort_unstable();
            for t in sorted_ptrs {
                if !targets.iter().any(|x| x.target == t) {
                    targets.push(IndirectCallTarget {
                        call_site,
                        target: t,
                        confidence: CallTargetConfidence::Definitive,
                        resolution_method: "observed_pointer".into(),
                    });
                }
            }
        }
        targets
    }

    /// Count registered pointer targets.
    #[must_use] 
    pub fn pointer_count(&self) -> usize {
        self.pointer_targets.len()
    }
}

impl Default for IndirectCallResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TailCallDetector ────────────────────────────────────────────────────────

/// Evidence for a tail call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailCallEvidence {
    pub site: u64,
    pub target: u64,
    pub confidence: f64,
    pub reasons: Vec<String>,
}

/// Detects tail calls from JMP instructions and stack state.
pub struct TailCallDetector;

impl TailCallDetector {
    /// Analyze an unconditional jump to determine if it is a tail call.
    ///
    /// Heuristics:
    /// 1. The jump targets a known function entry point.
    /// 2. The stack pointer matches the function entry SP.
    /// 3. The jump is at the end of a function.
    /// 4. No callee-saved registers have been modified without restore.
    #[must_use] 
    pub fn analyze(
        site: u64,
        target: u64,
        is_known_function_entry: bool,
        sp_matches_entry: bool,
        is_function_tail: bool,
        unsaved_registers: usize,
    ) -> Option<TailCallEvidence> {
        let mut score = 0.0f64;
        let mut reasons = Vec::new();

        if is_known_function_entry {
            score += 0.4;
            reasons.push("target is known function entry".into());
        }
        if sp_matches_entry {
            score += 0.3;
            reasons.push("stack pointer matches function entry".into());
        }
        if is_function_tail {
            score += 0.2;
            reasons.push("jump is at function tail position".into());
        }
        if unsaved_registers == 0 {
            score += 0.1;
            reasons.push("no unsaved callee-saved registers".into());
        } else {
            score -= 0.2 * f64::from(u32::try_from(unsaved_registers).unwrap_or(u32::MAX));
        }

        if score >= 0.4 {
            Some(TailCallEvidence {
                site,
                target,
                confidence: score.clamp(0.0, 1.0),
                reasons,
            })
        } else {
            None
        }
    }

    /// Quick check: is a JMP at `site` likely a tail call based on function context?
    #[must_use] 
    pub fn is_likely_tail_call(
        site: u64,
        target: u64,
        function_start: u64,
        function_end: u64,
        known_functions: &HashSet<u64>,
    ) -> bool {
        site >= function_start
            && site <= function_end
            && known_functions.contains(&target)
    }
}

// ─── JumpTableEntry ──────────────────────────────────────────────────────────

/// A single jump table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpTableEntry {
    pub index: usize,
    pub target: u64,
    /// Confidence this entry is valid.
    pub confidence: f64,
}

/// Detected jump table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpTable {
    pub site: u64,
    pub base_addr: u64,
    pub entries: Vec<JumpTableEntry>,
    pub element_size: usize,
    pub kind: JumpTableKind,
    pub index_var: Option<String>,
    pub bounds_checked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JumpTableKind {
    /// Absolute address table.
    Absolute,
    /// Table of relative offsets added to a base.
    RelativeOffset,
    /// Table of 8-bit relative offsets.
    ByteOffset,
    /// Table of 16-bit relative offsets.
    ShortOffset,
}

impl JumpTable {
    #[must_use] 
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn targets(&self) -> Vec<u64> {
        self.entries.iter().map(|e| e.target).collect()
    }
}

/// Analyses jump tables from binary data.
pub struct JumpTableAnalyzer;

impl JumpTableAnalyzer {
    /// Attempt to decode an absolute pointer table.
    #[must_use] 
    pub fn decode_absolute(
        site: u64,
        base_addr: u64,
        data: &[u8],
        pointer_size: usize,
        code_range: std::ops::Range<u64>,
    ) -> Option<JumpTable> {
        // Validate pointer_size first: this is a pub API, and e.g.
        // pointer_size == 3 with data.len() == 3 passes the length guard but
        // the read below always takes 4 or 8 bytes, panicking on the slice.
        if pointer_size != 4 && pointer_size != 8 {
            return None;
        }
        if data.len() < pointer_size {
            return None;
        }
        let mut entries = Vec::new();
        let mut idx = 0;
        let mut offset = 0;
        while offset + pointer_size <= data.len() {
            let target = if pointer_size == 8 {
                u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?)
            } else {
                u64::from(u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?))
            };
            if !code_range.contains(&target) {
                break;
            }
            entries.push(JumpTableEntry {
                index: idx,
                target,
                confidence: 0.9,
            });
            idx += 1;
            offset += pointer_size;
        }
        if entries.is_empty() {
            return None;
        }
        Some(JumpTable {
            site,
            base_addr,
            entries,
            element_size: pointer_size,
            kind: JumpTableKind::Absolute,
            index_var: None,
            bounds_checked: false,
        })
    }

    /// Attempt to decode a relative offset table (entries are i32 offsets from base).
    #[must_use] 
    pub fn decode_relative(
        site: u64,
        base_addr: u64,
        data: &[u8],
        code_range: std::ops::Range<u64>,
    ) -> Option<JumpTable> {
        if data.len() < 4 {
            return None;
        }
        let mut entries = Vec::new();
        let mut idx = 0;
        let mut offset = 0;
        while offset + 4 <= data.len() {
            let rel = i32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            let target = base_addr.wrapping_add(i64::from(rel).cast_unsigned());
            if !code_range.contains(&target) {
                break;
            }
            entries.push(JumpTableEntry {
                index: idx,
                target,
                confidence: 0.85,
            });
            idx += 1;
            offset += 4;
        }
        if entries.is_empty() {
            return None;
        }
        Some(JumpTable {
            site,
            base_addr,
            entries,
            element_size: 4,
            kind: JumpTableKind::RelativeOffset,
            index_var: None,
            bounds_checked: false,
        })
    }
}

// ─── ThunkDetector ───────────────────────────────────────────────────────────

/// Classification of a thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThunkKind {
    /// Simple JMP target — import thunk or PLT stub.
    Import,
    /// Adjustor thunk — adjusts `this` pointer for multiple inheritance.
    ThisAdjustor { adjustment: i32 },
    /// Virtual base adjustor thunk.
    VirtualBaseAdjustor,
    /// Covariant return thunk.
    CovariantReturn,
}

/// A detected thunk function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thunk {
    pub address: u64,
    pub target: u64,
    pub kind: ThunkKind,
    pub name: Option<String>,
}

/// Identifies thunk functions from their byte patterns.
pub struct ThunkDetector;

impl ThunkDetector {
    /// Check if a function that immediately JMPs to `target` is a thunk.
    #[must_use] 
    pub fn classify(
        function_addr: u64,
        first_instr_bytes: &[u8],
        target_addr: u64,
        is_import: bool,
    ) -> Option<Thunk> {
        if first_instr_bytes.is_empty() {
            return None;
        }
        // Simple JMP thunk: first byte is 0xE9 (near JMP) or 0xFF 0x25 (indirect JMP).
        let kind = if first_instr_bytes[0] == 0xE9
            || (first_instr_bytes.len() >= 2
                && first_instr_bytes[0] == 0xFF
                && first_instr_bytes[1] == 0x25)
        {
            if is_import {
                ThunkKind::Import
            } else {
                // Check for this-pointer adjustment before JMP.
                ThunkKind::ThisAdjustor { adjustment: 0 }
            }
        } else {
            return None;
        };

        Some(Thunk {
            address: function_addr,
            target: target_addr,
            kind,
            name: None,
        })
    }

    /// Detect import thunks from a list of (`fn_addr`, `first_bytes`, `target_addr`).
    #[must_use] 
    pub fn detect_all(
        functions: &[(u64, Vec<u8>, u64)],
        import_addresses: &HashSet<u64>,
    ) -> Vec<Thunk> {
        functions
            .iter()
            .filter_map(|(addr, bytes, target)| {
                Self::classify(*addr, bytes, *target, import_addresses.contains(target))
            })
            .collect()
    }
}

// ─── VirtualCallResolver ──────────────────────────────────────────────────────

/// Resolved virtual call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualCallResolution {
    pub call_site: u64,
    pub vtable_slot: usize,
    pub possible_targets: Vec<VirtualTarget>,
}

/// A possible target for a virtual call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualTarget {
    pub class_name: String,
    pub function_addr: u64,
    pub is_abstract: bool,
}

/// Resolves virtual calls using vtable analysis.
pub struct VirtualCallResolver {
    /// `vtable_addr` → list of function addresses.
    vtables: HashMap<u64, Vec<u64>>,
    /// `class_name` → `vtable_addr`.
    class_vtables: HashMap<String, u64>,
    /// Addresses of pure-virtual stubs (e.g. MSVC `_purecall`,
    /// Itanium `__cxa_pure_virtual`); slots pointing here are abstract.
    pure_virtual_stubs: std::collections::HashSet<u64>,
}

impl VirtualCallResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            vtables: HashMap::new(),
            class_vtables: HashMap::new(),
            pure_virtual_stubs: std::collections::HashSet::new(),
        }
    }

    /// Register the address of a pure-virtual stub function.
    pub fn register_pure_virtual_stub(&mut self, addr: u64) {
        self.pure_virtual_stubs.insert(addr);
    }

    /// Register a vtable.
    pub fn register_vtable(&mut self, vtable_addr: u64, entries: Vec<u64>) {
        self.vtables.insert(vtable_addr, entries);
    }

    /// Associate a class with its vtable.
    pub fn associate_class(&mut self, class_name: impl Into<String>, vtable_addr: u64) {
        self.class_vtables.insert(class_name.into(), vtable_addr);
    }

    /// Resolve a virtual call at `call_site` with vtable slot `slot`.
    #[must_use] 
    pub fn resolve(&self, call_site: u64, slot: usize) -> VirtualCallResolution {
        let mut possible_targets = Vec::new();
        // `class_vtables` is a HashMap, so its iteration order is
        // nondeterministic (varies run-to-run, even for the same input).
        // Collect first, then sort by class name so the result — and any
        // code indexing into `possible_targets` (e.g. `[0]`) or hashing/
        // diffing it — is stable and reproducible.
        for (class_name, &vtable_addr) in &self.class_vtables {
            if let Some(entries) = self.vtables.get(&vtable_addr)
                && let Some(&fn_addr) = entries.get(slot) {
                    possible_targets.push(VirtualTarget {
                        class_name: class_name.clone(),
                        function_addr: fn_addr,
                        is_abstract: fn_addr == 0 || self.pure_virtual_stubs.contains(&fn_addr),
                    });
                }
        }
        possible_targets.sort_by(|a, b| {
            a.class_name.cmp(&b.class_name).then(a.function_addr.cmp(&b.function_addr))
        });
        VirtualCallResolution {
            call_site,
            vtable_slot: slot,
            possible_targets,
        }
    }

    /// Return every target function address reachable via vtable slot `slot`
    /// across all registered vtables.  This is a best-effort stub used when a
    /// full binary-wide call-site scan isn't available — it surfaces the
    /// candidate callees that any indirect call through this slot could resolve to.
    #[must_use] 
    pub fn calls_to_slot(&self, slot: usize) -> Vec<u64> {
        let mut targets = Vec::new();
        for entries in self.vtables.values() {
            if let Some(&fn_addr) = entries.get(slot)
                && fn_addr != 0 {
                    targets.push(fn_addr);
                }
        }
        targets.sort_unstable();
        targets.dedup();
        targets
    }

    /// Number of registered vtables.
    #[must_use] 
    pub fn vtable_count(&self) -> usize {
        self.vtables.len()
    }
}

impl Default for VirtualCallResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── XrefHeuristics ──────────────────────────────────────────────────────────

/// Aggregated heuristic xref analysis.
pub struct XrefHeuristics {
    pub indirect_resolver: IndirectCallResolver,
    pub virtual_resolver: VirtualCallResolver,
    pub jump_tables: Vec<JumpTable>,
    pub thunks: Vec<Thunk>,
    pub tail_calls: Vec<TailCallEvidence>,
}

impl XrefHeuristics {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            indirect_resolver: IndirectCallResolver::new(),
            virtual_resolver: VirtualCallResolver::new(),
            jump_tables: Vec::new(),
            thunks: Vec::new(),
            tail_calls: Vec::new(),
        }
    }

    pub fn add_jump_table(&mut self, jt: JumpTable) {
        self.jump_tables.push(jt);
    }

    pub fn add_thunk(&mut self, thunk: Thunk) {
        self.thunks.push(thunk);
    }

    pub fn add_tail_call(&mut self, tc: TailCallEvidence) {
        self.tail_calls.push(tc);
    }

    /// Summary statistics.
    #[must_use] 
    pub fn stats(&self) -> XrefStats {
        XrefStats {
            jump_table_count: self.jump_tables.len(),
            jump_table_entries: self.jump_tables.iter().map(JumpTable::entry_count).sum(),
            thunk_count: self.thunks.len(),
            tail_call_count: self.tail_calls.len(),
            virtual_classes: self.virtual_resolver.vtable_count(),
        }
    }
}

impl Default for XrefHeuristics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefStats {
    pub jump_table_count: usize,
    pub jump_table_entries: usize,
    pub thunk_count: usize,
    pub tail_call_count: usize,
    pub virtual_classes: usize,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_absolute_rejects_bogus_pointer_size_instead_of_panicking() {
        // Regression: pointer_size == 3 with 3-byte data passed the length
        // guard, but the body always slices 4 (or 8) bytes → panic. Any size
        // other than 4/8 was also silently misread as 4.
        let r = JumpTableAnalyzer::decode_absolute(0, 0x1000, &[0u8; 3], 3, 0..0x1_0000);
        assert!(r.is_none());
        let r = JumpTableAnalyzer::decode_absolute(0, 0x1000, &[0u8; 64], usize::MAX, 0..0x1_0000);
        assert!(r.is_none());
    }

    #[test]
    fn indirect_call_resolver_register_and_resolve() {
        let mut resolver = IndirectCallResolver::new();
        resolver.register_pointer_target(0x1000, 0xABCD);
        let targets = resolver.resolve(0x2000, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target, 0xABCD);
    }

    #[test]
    fn indirect_call_resolver_multiple_targets() {
        let mut resolver = IndirectCallResolver::new();
        resolver.register_pointer_target(0x1000, 0xA000);
        resolver.register_pointer_target(0x1000, 0xB000);
        let targets = resolver.resolve(0x2000, 0x1000);
        assert_eq!(targets.len(), 2);
        // Multiple targets → medium confidence.
        assert!(
            targets
                .iter()
                .all(|t| t.confidence == CallTargetConfidence::Medium)
        );
    }

    #[test]
    fn indirect_call_resolver_observed_pointer() {
        let mut resolver = IndirectCallResolver::new();
        resolver.register_call_site_ptr(0x5000, 0xC000);
        let targets = resolver.resolve(0x5000, 0x9999);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].confidence, CallTargetConfidence::Definitive);
    }

    #[test]
    fn indirect_call_resolver_observed_pointers_deterministic_order() {
        // `call_site_ptrs` is backed by a `HashSet`; the resolver must sort
        // before returning so `targets` order is stable across runs
        // regardless of hash iteration order.
        let mut resolver = IndirectCallResolver::new();
        let ptrs: [u64; 6] = [0xF000, 0x1000, 0xA000, 0x2000, 0xC000, 0x5000];
        for &p in &ptrs {
            resolver.register_call_site_ptr(0x5000, p);
        }
        let targets = resolver.resolve(0x5000, 0x9999);
        let got: Vec<u64> = targets.iter().map(|t| t.target).collect();
        let mut expected = ptrs.to_vec();
        expected.sort_unstable();
        assert_eq!(got, expected);
    }

    #[test]
    fn indirect_call_pointer_count() {
        let mut resolver = IndirectCallResolver::new();
        resolver.register_pointer_target(0x1, 0x10);
        resolver.register_pointer_target(0x2, 0x20);
        assert_eq!(resolver.pointer_count(), 2);
    }

    #[test]
    fn tail_call_detector_positive() {
        let result = TailCallDetector::analyze(0x1000, 0x2000, true, true, true, 0);
        assert!(result.is_some());
        let tc = result.unwrap();
        assert!(tc.confidence >= 0.4);
    }

    #[test]
    fn tail_call_detector_negative() {
        let result = TailCallDetector::analyze(0x1000, 0x2000, false, false, false, 5);
        assert!(result.is_none());
    }

    #[test]
    fn tail_call_is_likely() {
        let mut known = HashSet::new();
        known.insert(0x2000u64);
        assert!(TailCallDetector::is_likely_tail_call(
            0x1FF8, 0x2000, 0x1000, 0x2000, &known
        ));
    }

    #[test]
    fn jump_table_decode_absolute() {
        let mut data = Vec::new();
        // Four 64-bit pointers all within code range 0x1000..0x9000.
        for addr in &[0x1000u64, 0x2000, 0x3000, 0x4000] {
            data.extend_from_slice(&addr.to_le_bytes());
        }
        let jt = JumpTableAnalyzer::decode_absolute(0x500, 0x500, &data, 8, 0x1000..0x9000);
        assert!(jt.is_some());
        let jt = jt.unwrap();
        assert_eq!(jt.entry_count(), 4);
        assert_eq!(jt.kind, JumpTableKind::Absolute);
    }

    #[test]
    fn jump_table_decode_relative() {
        let base = 0x5000u64;
        let mut data = Vec::new();
        // Four relative offsets pointing to base + offset within range.
        for offset in &[0x100i32, 0x200, 0x300, 0x400] {
            data.extend_from_slice(&offset.to_le_bytes());
        }
        let jt = JumpTableAnalyzer::decode_relative(0x500, base, &data, 0x5000..0x6000);
        assert!(jt.is_some());
        assert_eq!(jt.unwrap().kind, JumpTableKind::RelativeOffset);
    }

    #[test]
    fn jump_table_out_of_range() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEAD_BEEF_0000_0000u64.to_le_bytes());
        let jt = JumpTableAnalyzer::decode_absolute(0x500, 0x500, &data, 8, 0x1000..0x9000);
        assert!(jt.is_none());
    }

    #[test]
    fn thunk_detector_import_jmp() {
        let bytes = vec![0xE9u8, 0x00, 0x00, 0x00, 0x00]; // JMP rel
        let mut _imports = HashSet::new();
        _imports.insert(0x2000u64);
        let thunk = ThunkDetector::classify(0x1000, &bytes, 0x2000, true);
        assert!(thunk.is_some());
        assert_eq!(thunk.unwrap().kind, ThunkKind::Import);
    }

    #[test]
    fn thunk_detector_not_a_thunk() {
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5]; // PUSH RBP; MOV RBP, RSP
        let thunk = ThunkDetector::classify(0x1000, &bytes, 0x2000, false);
        assert!(thunk.is_none());
    }

    #[test]
    fn thunk_detector_detect_all() {
        let mut imports = HashSet::new();
        imports.insert(0x2000u64);
        let functions = vec![(0x1000u64, vec![0xE9u8, 0, 0, 0, 0], 0x2000u64)];
        let thunks = ThunkDetector::detect_all(&functions, &imports);
        assert_eq!(thunks.len(), 1);
    }

    #[test]
    fn virtual_call_resolver_register_and_resolve() {
        let mut resolver = VirtualCallResolver::new();
        // Placeholder hex addresses for test setup (originally written as
        // mnemonic literals like 0xVT1 / 0xCALL that were not valid hex).
        let vt1_addr: u64 = 0x0000_A001;
        let call_addr: u64 = 0x0000_CA11;
        resolver.register_vtable(vt1_addr, vec![0xF001, 0xF002, 0xF003]);
        resolver.associate_class("MyClass", vt1_addr);
        let result = resolver.resolve(call_addr, 1);
        assert_eq!(result.vtable_slot, 1);
        assert!(!result.possible_targets.is_empty());
        assert_eq!(result.possible_targets[0].function_addr, 0xF002);
    }

    #[test]
    fn virtual_call_resolver_no_vtable() {
        let resolver = VirtualCallResolver::new();
        let result = resolver.resolve(0xCA11, 0);
        assert!(result.possible_targets.is_empty());
    }

    #[test]
    fn virtual_call_resolver_vtable_count() {
        let mut resolver = VirtualCallResolver::new();
        resolver.register_vtable(0x1, vec![]);
        resolver.register_vtable(0x2, vec![]);
        assert_eq!(resolver.vtable_count(), 2);
    }

    #[test]
    fn xref_heuristics_stats() {
        let mut xh = XrefHeuristics::new();
        xh.add_jump_table(JumpTable {
            site: 0x1000,
            base_addr: 0x2000,
            entries: vec![JumpTableEntry {
                index: 0,
                target: 0x3000,
                confidence: 0.9,
            }],
            element_size: 8,
            kind: JumpTableKind::Absolute,
            index_var: None,
            bounds_checked: false,
        });
        let stats = xh.stats();
        assert_eq!(stats.jump_table_count, 1);
        assert_eq!(stats.jump_table_entries, 1);
    }

    #[test]
    fn heuristic_error_display() {
        let e = HeuristicError::InvalidAddress(0x1234);
        assert!(e.to_string().contains("0x1234"));
    }

    #[test]
    fn call_target_confidence_ordering() {
        assert!(CallTargetConfidence::Definitive > CallTargetConfidence::High);
        assert!(CallTargetConfidence::High > CallTargetConfidence::Low);
    }

    #[test]
    fn jump_table_targets() {
        let jt = JumpTable {
            site: 0,
            base_addr: 0,
            entries: vec![
                JumpTableEntry {
                    index: 0,
                    target: 0x1000,
                    confidence: 1.0,
                },
                JumpTableEntry {
                    index: 1,
                    target: 0x2000,
                    confidence: 1.0,
                },
            ],
            element_size: 8,
            kind: JumpTableKind::Absolute,
            index_var: None,
            bounds_checked: true,
        };
        let targets = jt.targets();
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x2000));
    }

    #[test]
    fn virtual_call_resolver_calls_to_slot() {
        let mut resolver = VirtualCallResolver::new();
        resolver.register_vtable(0x1, vec![0xF001, 0xF002]);
        resolver.register_vtable(0x2, vec![0xF001, 0xF003]);
        resolver.register_vtable(0x3, vec![0x0, 0xF004]); // slot 0 is null, skipped
        let targets = resolver.calls_to_slot(0);
        // 0xF001 appears in two vtables and must be de-duplicated; the null
        // entry from vtable 0x3 must be excluded.
        assert_eq!(targets, vec![0xF001]);
    }

    #[test]
    fn virtual_call_resolver_calls_to_slot_out_of_range() {
        let resolver = VirtualCallResolver::new();
        assert!(resolver.calls_to_slot(5).is_empty());
    }

    #[test]
    fn virtual_call_resolver_pure_virtual_stub_marks_abstract() {
        let mut resolver = VirtualCallResolver::new();
        let stub_addr = 0xDEAD_0000u64;
        resolver.register_pure_virtual_stub(stub_addr);
        resolver.register_vtable(0x1, vec![stub_addr, 0xF002]);
        resolver.associate_class("Abstract", 0x1);
        let result = resolver.resolve(0xCA11, 0);
        assert_eq!(result.possible_targets.len(), 1);
        assert!(result.possible_targets[0].is_abstract);
        assert_eq!(result.possible_targets[0].function_addr, stub_addr);
    }

    #[test]
    fn virtual_call_resolver_null_slot_is_abstract() {
        let mut resolver = VirtualCallResolver::new();
        resolver.register_vtable(0x1, vec![0x0]);
        resolver.associate_class("Abstract", 0x1);
        let result = resolver.resolve(0xCA11, 0);
        assert!(result.possible_targets[0].is_abstract);
    }

    #[test]
    fn default_impls_are_empty() {
        let resolver = IndirectCallResolver::default();
        assert_eq!(resolver.pointer_count(), 0);
        let vresolver = VirtualCallResolver::default();
        assert_eq!(vresolver.vtable_count(), 0);
        let xh = XrefHeuristics::default();
        let stats = xh.stats();
        assert_eq!(stats.jump_table_count, 0);
        assert_eq!(stats.thunk_count, 0);
        assert_eq!(stats.tail_call_count, 0);
        assert_eq!(stats.virtual_classes, 0);
    }

    #[test]
    fn xref_heuristics_full_stats() {
        let mut xh = XrefHeuristics::new();
        xh.add_thunk(Thunk {
            address: 0x1000,
            target: 0x2000,
            kind: ThunkKind::Import,
            name: None,
        });
        xh.add_tail_call(TailCallEvidence {
            site: 0x1000,
            target: 0x2000,
            confidence: 0.9,
            reasons: vec![],
        });
        xh.virtual_resolver.register_vtable(0x1, vec![0xF00]);
        let stats = xh.stats();
        assert_eq!(stats.thunk_count, 1);
        assert_eq!(stats.tail_call_count, 1);
        assert_eq!(stats.virtual_classes, 1);
    }

    #[test]
    fn heuristic_error_variants_display() {
        let e1 = HeuristicError::InsufficientData("no bytes".into());
        assert!(e1.to_string().contains("insufficient data"));
        assert!(e1.to_string().contains("no bytes"));
        let e2 = HeuristicError::Ambiguous("two candidates".into());
        assert!(e2.to_string().contains("ambiguous"));
        assert!(e2.to_string().contains("two candidates"));
        assert_eq!(
            HeuristicError::InvalidAddress(0x10),
            HeuristicError::InvalidAddress(0x10)
        );
    }
}
