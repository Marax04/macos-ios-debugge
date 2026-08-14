//! Symbolic state: `SymbolicState`, `RegisterFile`, `MemoryModel`,
//! `clone_state()`.
//!
//! This module provides a rich, self-contained symbolic execution state that
//! tracks:
//! - A register file that maps register names to symbolic values.
//! - A layered memory model supporting both concrete-addressed and
//!   symbolic-addressed cells.
//! - A path condition accumulating branch constraints.
//! - A depth counter for loop-bound enforcement.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::symbolic_value::{SymbolicValue, ValueWidth, symbolic_add};

// ── RegisterFile ──────────────────────────────────────────────────────────────

/// Register file: maps register names to symbolic values.
///
/// Implements copy-on-write semantics: cloning the register file is cheap
/// because `SymbolicValue` is a value type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterFile {
    /// Register name → symbolic value.
    regs: HashMap<String, SymbolicValue>,
    /// Number of registers defined.
    size: usize,
}

impl RegisterFile {
    /// Create an empty register file.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialise a register file for a 64-bit architecture where all
    /// registers start as fresh symbolic variables.
    #[must_use]
    pub fn symbolic_x86_64() -> Self {
        let names = [
            "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rip", "rflags",
        ];
        let mut rf = Self::new();
        for name in &names {
            rf.write_sym(name, SymbolicValue::fresh_var(*name, ValueWidth::W64));
        }
        rf
    }

    /// Initialise a register file for MSP430 (16 registers × 16-bit).
    #[must_use]
    pub fn symbolic_msp430() -> Self {
        let names = [
            "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        ];
        let mut rf = Self::new();
        for name in &names {
            rf.write_sym(name, SymbolicValue::fresh_var(*name, ValueWidth::W16));
        }
        rf
    }

    /// Write a symbolic value to a register.
    pub fn write_sym(&mut self, reg: &str, val: SymbolicValue) {
        let existed = self.regs.contains_key(reg);
        self.regs.insert(reg.to_string(), val);
        if !existed {
            self.size += 1;
        }
    }

    /// Write a concrete 64-bit constant to a register.
    pub fn write_concrete(&mut self, reg: &str, val: u64, width: ValueWidth) {
        self.write_sym(reg, SymbolicValue::constant(val, width));
    }

    /// Read a register.  Returns a fresh symbolic variable named after the
    /// register if it has never been written.
    #[must_use]
    pub fn read(&self, reg: &str) -> SymbolicValue {
        self.regs
            .get(reg)
            .cloned()
            .unwrap_or_else(|| SymbolicValue::fresh_var(reg, ValueWidth::W64))
    }

    /// Read a register only if it has been explicitly defined.
    #[must_use]
    pub fn try_read(&self, reg: &str) -> Option<&SymbolicValue> {
        self.regs.get(reg)
    }

    /// Return the number of defined registers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.size
    }

    /// Return `true` if no registers have been defined.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Iterate over all (name, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SymbolicValue)> {
        self.regs.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Merge two register files after a branch reconvergence.
    ///
    /// Registers present in only one branch are left as-is (the value from
    /// the branch that defined them is used).  Registers present in both
    /// branches are wrapped in an ITE guarded by `cond`.
    #[must_use]
    pub fn merge_branches(true_rf: Self, false_rf: Self, cond: &SymbolicValue) -> Self {
        let all_keys: std::collections::HashSet<String> = true_rf
            .regs
            .keys()
            .chain(false_rf.regs.keys())
            .cloned()
            .collect();
        let mut merged = Self {
            regs: HashMap::with_capacity(all_keys.len()),
            size: 0,
        };

        for key in all_keys {
            let tv = true_rf.read(&key);
            let fv = false_rf.read(&key);
            let merged_val = if tv == fv {
                tv
            } else {
                SymbolicValue::ite(cond.clone(), tv, fv)
            };
            merged.write_sym(&key, merged_val);
        }
        merged
    }

    /// Concretise all registers that can be evaluated with the given
    /// variable binding environment.
    pub fn concretise(&mut self, env: &HashMap<u64, u64>) {
        for val in self.regs.values_mut() {
            if let Some(concrete) = val.evaluate(env) {
                *val = SymbolicValue::constant(concrete, val.width);
            }
        }
    }
}

impl fmt::Display for RegisterFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pairs: Vec<(&String, &SymbolicValue)> = self.regs.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in pairs {
            writeln!(f, "  {k} = {v}")?;
        }
        Ok(())
    }
}

// ── MemoryModel ───────────────────────────────────────────────────────────────

/// Entry in the symbolic memory model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCell {
    /// Address of this cell.
    pub addr: u64,
    /// Symbolic value stored at the address.
    pub value: SymbolicValue,
    /// Byte-width of the access that last wrote this cell.
    pub width_bytes: u8,
}

impl MemoryCell {
    #[must_use]
    pub const fn new(addr: u64, value: SymbolicValue, width_bytes: u8) -> Self {
        Self { addr, value, width_bytes }
    }
}

/// Symbolic memory model with two layers:
///
/// 1. **Concrete layer**: `BTreeMap` from concrete u64 address to value.
/// 2. **Symbolic layer**: vector of (symbolic-address, value) pairs, kept
///    small for tractability.
///
/// Reads check the symbolic layer first, then the concrete layer, and finally
/// return a fresh unconstrained symbolic variable if the address has never
/// been written.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryModel {
    /// Concrete address → value.
    pub concrete: BTreeMap<u64, MemoryCell>,
    /// (symbolic-address, value) pairs.
    pub symbolic: Vec<(SymbolicValue, MemoryCell)>,
    /// Total number of write operations recorded.
    pub write_count: u64,
    /// Total number of read operations recorded.
    pub read_count: u64,
}

impl MemoryModel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Concrete operations ──────────────────────────────────────────────────

    /// Write a symbolic value to a concrete address.
    pub fn write_concrete(&mut self, addr: u64, val: SymbolicValue, width_bytes: u8) {
        self.concrete.insert(addr, MemoryCell::new(addr, val, width_bytes));
        self.write_count += 1;
    }

    /// Write a concrete byte value at a concrete address.
    pub fn write_byte(&mut self, addr: u64, val: u8) {
        self.write_concrete(addr, SymbolicValue::constant(u64::from(val), ValueWidth::W8), 1);
    }

    /// Write a concrete 16-bit word (little-endian) at a concrete address.
    pub fn write_u16_le(&mut self, addr: u64, val: u16) {
        self.write_byte(addr, (val & 0xFF) as u8);
        self.write_byte(addr + 1, (val >> 8) as u8);
    }

    /// Write a concrete 32-bit word (little-endian) at a concrete address.
    pub fn write_u32_le(&mut self, addr: u64, val: u32) {
        for i in 0..4u64 {
            self.write_byte(addr + i, ((val >> (i * 8)) & 0xFF) as u8);
        }
    }

    /// Write a concrete 64-bit word (little-endian) at a concrete address.
    pub fn write_u64_le(&mut self, addr: u64, val: u64) {
        for i in 0..8u64 {
            self.write_byte(addr + i, ((val >> (i * 8)) & 0xFF) as u8);
        }
    }

    /// Load a symbolic value from a concrete address.
    ///
    /// Returns the stored value or a fresh symbolic variable named
    /// `"mem_0x<addr>"`.
    #[must_use]
    pub fn read_concrete(&mut self, addr: u64) -> SymbolicValue {
        self.read_count += 1;
        self.concrete
            .get(&addr).map_or_else(|| {
                SymbolicValue::fresh_var(format!("mem_{addr:#x}"), ValueWidth::W8)
            }, |c| c.value.clone())
    }

    /// Read a little-endian 16-bit value from a concrete address (bytes
    /// assembled from individual symbolic bytes via shift-and-or).
    #[must_use]
    pub fn read_u16_le(&mut self, addr: u64) -> SymbolicValue {
        let lo = self.read_concrete(addr).zero_extend(ValueWidth::W16);
        let hi = self.read_concrete(addr + 1).zero_extend(ValueWidth::W16);
        symbolic_add(
            lo,
            hi.shl(SymbolicValue::constant(8, ValueWidth::W16)),
        )
    }

    // ── Symbolic operations ──────────────────────────────────────────────────

    /// Write a value at a symbolic address.
    pub fn write_symbolic(&mut self, addr: SymbolicValue, val: SymbolicValue, width_bytes: u8) {
        // Use a concrete placeholder address (0) — only the symbolic addr expr matters.
        let cell = MemoryCell::new(0, val, width_bytes);
        self.symbolic.push((addr, cell));
        self.write_count += 1;
    }

    /// Read a value from a symbolic address.
    ///
    /// Returns a fresh symbolic variable — full symbolic reasoning would
    /// require SMT array select.
    #[must_use]
    pub fn read_symbolic(&mut self, addr: &SymbolicValue) -> SymbolicValue {
        self.read_count += 1;
        // Search the symbolic layer most-recent-first.
        for (written_addr, cell) in self.symbolic.iter().rev() {
            if written_addr == addr {
                return cell.value.clone();
            }
        }
        SymbolicValue::fresh_var("mem_sym", ValueWidth::W8)
    }

    // ── Bulk operations ──────────────────────────────────────────────────────

    /// Load a slice of concrete bytes into the model.
    pub fn load_bytes(&mut self, base: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.write_byte(base + i as u64, b);
        }
    }

    /// Return all concrete addresses that have been written, sorted.
    #[must_use]
    pub fn written_addresses(&self) -> Vec<u64> {
        self.concrete.keys().copied().collect()
    }

    /// Return the number of concrete cells defined.
    #[must_use]
    pub fn concrete_cell_count(&self) -> usize {
        self.concrete.len()
    }

    /// Merge two memory models after branch reconvergence.
    ///
    /// For addresses present in both branches the values are wrapped in an
    /// ITE.  Addresses only in one branch retain that branch's value.
    #[must_use]
    pub fn merge_branches(true_mem: Self, false_mem: Self, cond: &SymbolicValue) -> Self {
        let mut merged = Self::new();
        let all_addrs: std::collections::BTreeSet<u64> = true_mem
            .concrete
            .keys()
            .chain(false_mem.concrete.keys())
            .copied()
            .collect();

        for addr in all_addrs {
            match (true_mem.concrete.get(&addr), false_mem.concrete.get(&addr)) {
                (Some(tc), Some(fc)) => {
                    let merged_val = if tc.value == fc.value {
                        tc.value.clone()
                    } else {
                        SymbolicValue::ite(cond.clone(), tc.value.clone(), fc.value.clone())
                    };
                    merged.write_concrete(addr, merged_val, tc.width_bytes);
                }
                (Some(tc), None) => {
                    merged.write_concrete(addr, tc.value.clone(), tc.width_bytes);
                }
                (None, Some(fc)) => {
                    merged.write_concrete(addr, fc.value.clone(), fc.width_bytes);
                }
                (None, None) => {}
            }
        }

        // Symbolic cells from both sides are appended.
        merged.symbolic.extend(true_mem.symbolic);
        merged.symbolic.extend(false_mem.symbolic);
        merged
    }
}

impl fmt::Display for MemoryModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryModel {{ cells: {}, sym_cells: {}, reads: {}, writes: {} }}",
            self.concrete.len(),
            self.symbolic.len(),
            self.read_count,
            self.write_count
        )
    }
}

// ── PathCondition ─────────────────────────────────────────────────────────────

/// Accumulated path condition: a conjunction of symbolic boolean terms that
/// must all hold for the current execution path to be reachable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathCondition {
    pub terms: Vec<SymbolicValue>,
}

impl PathCondition {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new constraint.
    pub fn push(&mut self, term: SymbolicValue) {
        self.terms.push(term);
    }

    /// Return `true` if any term is a concrete `0` (trivially false).
    #[must_use]
    pub fn is_trivially_false(&self) -> bool {
        self.terms.iter().any(|t| matches!(t.as_concrete(), Some(0)))
    }

    /// Assume a condition: push it and return `true` if the resulting
    /// condition is not trivially false.
    pub fn assume(&mut self, cond: SymbolicValue) -> bool {
        let trivially_false = matches!(cond.as_concrete(), Some(0));
        self.terms.push(cond);
        !trivially_false
    }

    /// Combine into a single conjunction expression.
    #[must_use]
    pub fn as_conjunction(&self) -> SymbolicValue {
        self.terms
            .iter()
            .cloned()
            .reduce(|acc, t| SymbolicValue::ite(
                acc,
                t,
                SymbolicValue::constant(0, ValueWidth::W1),
            ))
            .unwrap_or_else(|| SymbolicValue::constant(1, ValueWidth::W1))
    }

    /// Number of constraints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.terms.len()
    }

    /// Return `true` if there are no constraints.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}

// ── StateId ───────────────────────────────────────────────────────────────────

static NEXT_STATE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn alloc_state_id() -> u64 {
    NEXT_STATE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── SymbolicState ─────────────────────────────────────────────────────────────

/// Full symbolic execution state.
///
/// Captures all mutable components at a single program point:
/// registers, memory, path condition, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicState {
    /// Unique ID for this state (auto-assigned on creation).
    pub id: u64,
    /// Current program counter (concrete).
    pub pc: u64,
    /// Symbolic register file.
    pub registers: RegisterFile,
    /// Symbolic memory model.
    pub memory: MemoryModel,
    /// Accumulated path condition.
    pub path_condition: PathCondition,
    /// Exploration depth (incremented on each fork).
    pub depth: u32,
    /// User-defined tags for debugging / filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether this state has been marked as an error state.
    pub is_error: bool,
    /// Whether execution terminated normally at this state.
    pub is_terminal: bool,
}

impl SymbolicState {
    /// Create a new blank state with PC = 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: alloc_state_id(),
            pc: 0,
            registers: RegisterFile::new(),
            memory: MemoryModel::new(),
            path_condition: PathCondition::new(),
            depth: 0,
            tags: Vec::new(),
            is_error: false,
            is_terminal: false,
        }
    }

    /// Create a state with symbolic x86-64 registers.
    #[must_use]
    pub fn symbolic_x86_64(entry_pc: u64) -> Self {
        let mut s = Self::new();
        s.pc = entry_pc;
        s.registers = RegisterFile::symbolic_x86_64();
        s.registers.write_concrete("rip", entry_pc, ValueWidth::W64);
        s
    }

    /// Create a state with symbolic MSP430 registers.
    #[must_use]
    pub fn symbolic_msp430(entry_pc: u64) -> Self {
        let mut s = Self::new();
        s.pc = entry_pc;
        s.registers = RegisterFile::symbolic_msp430();
        s.registers.write_concrete("R0", entry_pc, ValueWidth::W16);
        s
    }

    // ── Register helpers ─────────────────────────────────────────────────────

    pub fn write_register(&mut self, name: &str, val: SymbolicValue) {
        self.registers.write_sym(name, val);
    }

    #[must_use]
    pub fn read_register(&self, name: &str) -> SymbolicValue {
        self.registers.read(name)
    }

    // ── Path condition ───────────────────────────────────────────────────────

    /// Push a constraint to the path condition.
    pub fn add_constraint(&mut self, cond: SymbolicValue) {
        self.path_condition.push(cond);
    }

    /// Return `true` if the path condition is trivially unsatisfiable.
    #[must_use]
    pub fn is_infeasible(&self) -> bool {
        self.path_condition.is_trivially_false()
    }

    // ── Forking ──────────────────────────────────────────────────────────────

    /// Fork this state into a true-branch / false-branch pair.
    ///
    /// The true branch inherits `cond`; the false branch inherits `!cond`.
    #[must_use]
    pub fn fork(&self, cond: SymbolicValue) -> (Self, Self) {
        let mut true_state = self.clone();
        true_state.id = alloc_state_id();
        true_state.path_condition.push(cond.clone());
        true_state.depth += 1;

        let mut false_state = self.clone();
        false_state.id = alloc_state_id();
        false_state.path_condition.push(cond.bitwise_not());
        false_state.depth += 1;

        (true_state, false_state)
    }

    /// Fork with only the true branch (used for assertions / assumptions).
    #[must_use]
    pub fn assume_branch(&self, cond: SymbolicValue) -> Self {
        let mut s = self.clone();
        s.id = alloc_state_id();
        s.path_condition.push(cond);
        s.depth += 1;
        s
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    pub fn tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    // ── Summary ─────────────────────────────────────────────────────────────

    pub const fn mark_error(&mut self) {
        self.is_error = true;
    }

    pub const fn mark_terminal(&mut self) {
        self.is_terminal = true;
    }
}

impl Default for SymbolicState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SymbolicState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "State #{} pc={:#x} depth={} conds={} error={} terminal={}",
            self.id,
            self.pc,
            self.depth,
            self.path_condition.len(),
            self.is_error,
            self.is_terminal,
        )
    }
}

// ── clone_state ───────────────────────────────────────────────────────────────

/// Deep-clone a symbolic state, assigning a fresh ID to the result.
///
/// This is the canonical way to duplicate a state for fork points, since
/// a plain `.clone()` would reuse the same `id`.
#[must_use]
pub fn clone_state(state: &SymbolicState) -> SymbolicState {
    let mut s = state.clone();
    s.id = alloc_state_id();
    s
}

// ── StatePool ─────────────────────────────────────────────────────────────────

/// A simple LIFO work-list of symbolic states (depth-first exploration).
#[derive(Debug, Default)]
pub struct StatePool {
    states: Vec<SymbolicState>,
    max_depth: u32,
    total_forked: u64,
}

impl StatePool {
    #[must_use]
    pub const fn new(max_depth: u32) -> Self {
        Self { states: Vec::new(), max_depth, total_forked: 0 }
    }

    pub fn push(&mut self, state: SymbolicState) {
        if state.depth <= self.max_depth {
            self.states.push(state);
        }
    }

    pub fn pop(&mut self) -> Option<SymbolicState> {
        self.states.pop()
    }

    pub fn push_fork(&mut self, cond: SymbolicValue, state: &SymbolicState) {
        let (t, f) = state.fork(cond);
        self.total_forked += 2;
        self.push(t);
        self.push(f);
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub const fn total_forked(&self) -> u64 {
        self.total_forked
    }

    /// Drop all states that are trivially infeasible.
    pub fn prune_infeasible(&mut self) {
        self.states.retain(|s| !s.is_infeasible());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic_value::{SymbolicValue, ValueWidth};

    #[test]
    fn test_register_read_write() {
        let mut rf = RegisterFile::new();
        rf.write_concrete("rax", 42, ValueWidth::W64);
        let v = rf.read("rax");
        assert_eq!(v.as_concrete(), Some(42));
    }

    #[test]
    fn test_register_undefined_returns_fresh_sym() {
        let rf = RegisterFile::new();
        let v = rf.read("rbx");
        assert!(!v.is_concrete());
    }

    #[test]
    fn test_memory_write_read_byte() {
        let mut mem = MemoryModel::new();
        mem.write_byte(0x1000, 0xAB);
        let v = mem.read_concrete(0x1000);
        assert_eq!(v.as_concrete(), Some(0xAB));
    }

    #[test]
    fn test_memory_undefined_addr() {
        let mut mem = MemoryModel::new();
        let v = mem.read_concrete(0xDEAD);
        assert!(!v.is_concrete());
    }

    #[test]
    fn test_memory_load_bytes() {
        let mut mem = MemoryModel::new();
        mem.load_bytes(0x100, &[1, 2, 3, 4]);
        assert_eq!(mem.read_concrete(0x100).as_concrete(), Some(1));
        assert_eq!(mem.read_concrete(0x103).as_concrete(), Some(4));
    }

    #[test]
    fn test_state_fork() {
        let s = SymbolicState::new();
        let cond = SymbolicValue::fresh_var("c", ValueWidth::W1);
        let (t, f) = s.fork(cond);
        assert_ne!(t.id, f.id);
        assert_eq!(t.depth, 1);
        assert_eq!(f.depth, 1);
    }

    #[test]
    fn test_clone_state_new_id() {
        let s = SymbolicState::new();
        let id0 = s.id;
        let s2 = clone_state(&s);
        assert_ne!(s2.id, id0);
    }

    #[test]
    fn test_path_condition_trivially_false() {
        let mut pc = PathCondition::new();
        pc.push(SymbolicValue::constant(0, ValueWidth::W1));
        assert!(pc.is_trivially_false());
    }

    #[test]
    fn test_path_condition_not_trivially_false() {
        let mut pc = PathCondition::new();
        pc.push(SymbolicValue::constant(1, ValueWidth::W1));
        assert!(!pc.is_trivially_false());
    }

    #[test]
    fn test_state_pool_depth_limit() {
        let mut pool = StatePool::new(2);
        let mut s = SymbolicState::new();
        s.depth = 3;
        pool.push(s);
        // Exceeds max_depth — should not be added.
        assert!(pool.is_empty());
    }

    #[test]
    fn test_state_pool_push_fork() {
        let mut pool = StatePool::new(10);
        let s = SymbolicState::new();
        let cond = SymbolicValue::fresh_var("x", ValueWidth::W1);
        pool.push_fork(cond, &s);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_register_file_symbolic_x86_64() {
        let rf = RegisterFile::symbolic_x86_64();
        let rax = rf.read("rax");
        assert!(!rax.is_concrete());
    }

    #[test]
    fn test_memory_merge() {
        let mut tm = MemoryModel::new();
        tm.write_byte(0x100, 0xAA);
        let mut fm = MemoryModel::new();
        fm.write_byte(0x100, 0xBB);
        let cond = SymbolicValue::fresh_var("c", ValueWidth::W1);
        let merged = MemoryModel::merge_branches(tm, fm, &cond);
        let cell = merged.concrete.get(&0x100).unwrap();
        // Value should be an ITE — not a concrete constant.
        assert!(!cell.value.is_concrete());
    }

    #[test]
    fn test_state_tagging() {
        let mut s = SymbolicState::new();
        s.tag("interesting");
        assert!(s.has_tag("interesting"));
        assert!(!s.has_tag("boring"));
    }

    #[test]
    fn test_symbolic_msp430() {
        let s = SymbolicState::symbolic_msp430(0x4400);
        assert_eq!(s.pc, 0x4400);
        assert_eq!(s.read_register("R0").as_concrete(), Some(0x4400));
    }
}
