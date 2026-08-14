//! `symbolic_memory_model` — **Byte-level** symbolic memory with segments and logging.
//!
//! Provides a flat symbolic address space with overlapping-write tracking,
//! alias analysis, concrete/symbolic byte reads, and a complete log of
//! all memory operations.
//!
//! # Relationship to [`memory_model`](crate::memory_model)
//!
//! These two modules are **not duplicates** — they operate at different levels
//! of abstraction:
//!
//! | Module | Abstraction level | Value type | Use case |
//! |--------|-------------------|------------|----------|
//! | [`memory_model`](crate::memory_model) | [`SymExpr`](crate::SymExpr) trees | `MemoryCell(SymExpr)` | SMT constraint generation; ITE-chain reads for symbolic addresses |
//! | **`symbolic_memory_model`** (this file) | Byte-level with string names | `SymValue` (named symbolic bytes) | Segment tracking, alias analysis cache, write/read logs, `fork`/`merge` |

use std::collections::{BTreeMap, HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("uninitialised read at address {0:#x} (size {1})")]
    UninitialisedRead(u64, usize),
    #[error("out-of-bounds access at {addr:#x} (size {size}, segment [{seg_start:#x}, {seg_end:#x}))")]
    OutOfBounds { addr: u64, size: usize, seg_start: u64, seg_end: u64 },
    #[error("misaligned access: address {0:#x} is not {1}-byte aligned")]
    Misaligned(u64, usize),
    #[error("aliased write detected: symbolic address {0} may alias concrete address {1:#x}")]
    AliasedWrite(String, u64),
    #[error("symbolic memory model error: {0}")]
    Other(String),
}

// ── SymAddr ───────────────────────────────────────────────────────────────────

/// A symbolic memory address — either a concrete u64 or a named symbolic value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymAddr {
    /// A concrete, fully-resolved address.
    Concrete(u64),
    /// A purely symbolic address (e.g., a function argument).
    Symbolic { name: String, base: u64, offset: i64 },
    /// Concrete base plus a symbolic offset.
    Based { base: u64, offset: Box<Self> },
}

impl SymAddr {
    /// Create a concrete address.
    #[must_use] 
    pub const fn concrete(addr: u64) -> Self { Self::Concrete(addr) }

    /// Create a named symbolic address.
    pub fn symbolic(name: impl Into<String>) -> Self {
        Self::Symbolic { name: name.into(), base: 0, offset: 0 }
    }

    /// Create a symbolic address with a numeric base.
    pub fn symbolic_with_base(name: impl Into<String>, base: u64) -> Self {
        Self::Symbolic { name: name.into(), base, offset: 0 }
    }

    /// Return the concrete value if known.
    ///
    /// Only `Concrete` addresses return `Some`; `Symbolic` addresses are never
    /// concrete even when `base == 0` and `offset == 0`.  Use
    /// [`SymAddr::try_resolve_concrete`] when you explicitly want the numeric
    /// value of a `Symbolic` address with known base/offset.
    #[must_use] 
    pub const fn as_concrete(&self) -> Option<u64> {
        match self {
            Self::Concrete(v) => Some(*v),
            // Symbolic addresses are never concrete, even when base/offset are
            // fully known. Callers that explicitly want the numeric value of a
            // resolvable symbolic address should use `try_resolve_concrete`.
            Self::Symbolic { .. } => None,
            Self::Based { .. } => None,
        }
    }

    /// Attempt to collapse a `Symbolic` or `Based` address to its concrete
    /// numeric value when the base and offset are known.  Unlike
    /// [`SymAddr::as_concrete`] this also handles `Symbolic` addresses.
    #[must_use] 
    pub const fn try_resolve_concrete(&self) -> Option<u64> {
        match self {
            Self::Concrete(v) => Some(*v),
            Self::Symbolic { base, offset, .. } => {
                Some(base.wrapping_add_signed(*offset))
            }
            Self::Based { .. } => None,
        }
    }

    /// True if this address is purely concrete.
    #[must_use] 
    pub const fn is_concrete(&self) -> bool { matches!(self, Self::Concrete(_)) }

    /// True if this address has any symbolic component.
    #[must_use] 
    pub const fn is_symbolic(&self) -> bool { !self.is_concrete() }

    /// Add a concrete offset.
    #[must_use] 
    pub fn add_offset(&self, off: i64) -> Self {
        match self {
            Self::Concrete(v) => Self::Concrete(v.wrapping_add_signed(off)),
            Self::Symbolic { name, base, offset } => Self::Symbolic {
                name: name.clone(),
                base: *base,
                offset: offset + off,
            },
            Self::Based { base, offset } => Self::Based {
                base: *base,
                offset: Box::new(offset.add_offset(off)),
            },
        }
    }
}

impl std::fmt::Display for SymAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#x}"),
            Self::Symbolic { name, base, offset } => {
                if *base == 0 && *offset == 0 {
                    write!(f, "sym({name})")
                } else {
                    write!(f, "sym({name})+{base:#x}+{offset}")
                }
            }
            Self::Based { base, offset } => write!(f, "{base:#x}+{offset}"),
        }
    }
}

// ── SymValue ──────────────────────────────────────────────────────────────────

/// A byte-level value stored in symbolic memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymValue {
    /// A concrete byte value.
    Concrete(u8),
    /// A symbolic byte with a name and constraint label.
    Symbolic { name: String, width_bits: u32 },
    /// A byte derived from an expression involving other symbolic values.
    Derived { expr: String },
    /// Memory that has not been initialised.
    Uninit,
}

impl SymValue {
    #[must_use] 
    pub const fn concrete(v: u8) -> Self { Self::Concrete(v) }
    pub fn symbolic(name: impl Into<String>) -> Self {
        Self::Symbolic { name: name.into(), width_bits: 8 }
    }
    pub fn derived(expr: impl Into<String>) -> Self { Self::Derived { expr: expr.into() } }
    #[must_use] 
    pub const fn is_concrete(&self) -> bool { matches!(self, Self::Concrete(_)) }
    #[must_use] 
    pub const fn is_uninit(&self) -> bool { matches!(self, Self::Uninit) }
    #[must_use] 
    pub const fn as_concrete(&self) -> Option<u8> {
        match self { Self::Concrete(v) => Some(*v), _ => None }
    }
}

impl std::fmt::Display for SymValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#04x}"),
            Self::Symbolic { name, .. } => write!(f, "sym({name})"),
            Self::Derived { expr } => write!(f, "derived({expr})"),
            Self::Uninit => write!(f, "uninit"),
        }
    }
}

// ── SymMemoryWrite ────────────────────────────────────────────────────────────

/// A single write operation logged in symbolic memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymMemoryWrite {
    /// Destination address.
    pub addr: SymAddr,
    /// The value written at each byte offset.
    pub bytes: Vec<SymValue>,
    /// Write sequence number (monotonically increasing).
    pub sequence: u64,
    /// Optional tag or annotation.
    pub tag: Option<String>,
}

// ── SymMemoryRead ─────────────────────────────────────────────────────────────

/// A single read operation result from symbolic memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymMemoryRead {
    /// Source address.
    pub addr: SymAddr,
    /// The values read.
    pub bytes: Vec<SymValue>,
    /// Whether any bytes were uninitialised.
    pub had_uninit: bool,
    /// Whether any bytes were symbolic.
    pub had_symbolic: bool,
    /// Read sequence number.
    pub sequence: u64,
}

impl SymMemoryRead {
    /// True if all bytes are concrete.
    #[must_use] 
    pub fn is_fully_concrete(&self) -> bool {
        self.bytes.iter().all(SymValue::is_concrete)
    }

    /// Attempt to reconstruct a concrete u64 value (up to 8 bytes, little-endian).
    #[must_use] 
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.bytes.len() > 8 || !self.is_fully_concrete() { return None; }
        let mut val = 0u64;
        for (i, b) in self.bytes.iter().enumerate() {
            val |= u64::from(b.as_concrete()?) << (i * 8);
        }
        Some(val)
    }

    /// Attempt to reconstruct a concrete u32 value (4 bytes, little-endian).
    #[must_use] 
    pub fn as_u32_le(&self) -> Option<u32> {
        if self.bytes.len() != 4 { return None; }
        let v = self.as_u64_le()?;
        Some(v as u32)
    }
}

// ── AliasRelation ─────────────────────────────────────────────────────────────

/// Describes the aliasing relationship between two memory addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AliasRelation {
    /// The two addresses definitely refer to the same location.
    MustAlias,
    /// The two addresses definitely do not refer to the same location.
    NoAlias,
    /// The addresses may or may not alias (conservative over-approximation).
    MayAlias,
    /// Aliasing could not be determined (symbolic addresses with unknown constraints).
    Unknown,
}

impl std::fmt::Display for AliasRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MustAlias => write!(f, "MustAlias"),
            Self::NoAlias   => write!(f, "NoAlias"),
            Self::MayAlias  => write!(f, "MayAlias"),
            Self::Unknown   => write!(f, "Unknown"),
        }
    }
}

// ── SymMemory ─────────────────────────────────────────────────────────────────

/// A byte-addressed symbolic memory store.
///
/// Stores concrete regions in a `BTreeMap<u64, SymValue>` and symbolic regions
/// separately. Tracks all writes and reads for replay and alias analysis.
pub struct SymMemory {
    /// Concrete address → symbolic byte value.
    cells: BTreeMap<u64, SymValue>,
    /// Symbolic regions: name → (`base_addr`, `size_bytes`, `initial_value`)
    symbolic_regions: HashMap<String, (u64, usize)>,
    /// Write log.
    write_log: Vec<SymMemoryWrite>,
    /// Read log.
    read_log: Vec<SymMemoryRead>,
    /// Monotonic operation counter.
    sequence: u64,
    /// Configuration: allow uninitialised reads.
    pub allow_uninit: bool,
}

impl Default for SymMemory {
    fn default() -> Self { Self::new() }
}

impl SymMemory {
    /// Create an empty symbolic memory.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            symbolic_regions: HashMap::new(),
            write_log: Vec::new(),
            read_log: Vec::new(),
            sequence: 0,
            allow_uninit: false,
        }
    }

    /// Load a concrete byte region into memory.
    pub fn load_bytes(&mut self, base: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.cells.insert(base.wrapping_add(i as u64), SymValue::Concrete(b));
        }
    }

    /// Register a symbolic region.
    pub fn register_symbolic_region(&mut self, name: impl Into<String>, base: u64, size: usize) {
        let n = name.into();
        self.symbolic_regions.insert(n.clone(), (base, size));
        for i in 0..size {
            let byte_name = format!("{n}[{i}]");
            self.cells.insert(base.wrapping_add(i as u64), SymValue::Symbolic { name: byte_name, width_bits: 8 });
        }
    }

    /// Write `bytes` to the concrete address `addr`.
    pub fn write(&mut self, addr: u64, bytes: Vec<SymValue>, tag: Option<String>) -> SymMemoryWrite {
        let seq = self.next_seq();
        for (i, b) in bytes.iter().enumerate() {
            self.cells.insert(addr.wrapping_add(i as u64), b.clone());
        }
        let w = SymMemoryWrite {
            addr: SymAddr::Concrete(addr),
            bytes,
            sequence: seq,
            tag,
        };
        self.write_log.push(w.clone());
        w
    }

    /// Write concrete bytes to address `addr`.
    pub fn write_concrete(&mut self, addr: u64, bytes: &[u8]) -> SymMemoryWrite {
        let values: Vec<SymValue> = bytes.iter().map(|&b| SymValue::Concrete(b)).collect();
        self.write(addr, values, None)
    }

    /// Write a single concrete u8.
    pub fn write_u8(&mut self, addr: u64, value: u8) {
        self.write(addr, vec![SymValue::Concrete(value)], None);
    }

    /// Write a concrete u32 in little-endian order.
    pub fn write_u32_le(&mut self, addr: u64, value: u32) {
        let bytes = value.to_le_bytes();
        let values: Vec<SymValue> = bytes.iter().map(|&b| SymValue::Concrete(b)).collect();
        self.write(addr, values, None);
    }

    /// Write a concrete u64 in little-endian order.
    pub fn write_u64_le(&mut self, addr: u64, value: u64) {
        let bytes = value.to_le_bytes();
        let values: Vec<SymValue> = bytes.iter().map(|&b| SymValue::Concrete(b)).collect();
        self.write(addr, values, None);
    }

    /// Read `size` bytes starting at concrete address `addr`.
    pub fn read(&mut self, addr: u64, size: usize) -> Result<SymMemoryRead, MemoryError> {
        let seq = self.next_seq();
        let mut bytes = Vec::with_capacity(size);
        let mut had_uninit = false;
        let mut had_symbolic = false;

        for i in 0..size {
            let cell_addr = addr.wrapping_add(i as u64);
            if let Some(v) = self.cells.get(&cell_addr) {
                if v.is_uninit() { had_uninit = true; }
                if matches!(v, SymValue::Symbolic { .. } | SymValue::Derived { .. }) { had_symbolic = true; }
                bytes.push(v.clone());
            } else {
                if !self.allow_uninit {
                    return Err(MemoryError::UninitialisedRead(cell_addr, size));
                }
                had_uninit = true;
                bytes.push(SymValue::Uninit);
            }
        }

        let r = SymMemoryRead { addr: SymAddr::Concrete(addr), bytes, had_uninit, had_symbolic, sequence: seq };
        self.read_log.push(r.clone());
        Ok(r)
    }

    /// Read a u8 from a concrete address.
    pub fn read_u8(&mut self, addr: u64) -> Result<Option<u8>, MemoryError> {
        let r = self.read(addr, 1)?;
        Ok(r.bytes[0].as_concrete())
    }

    /// Read a u32 (little-endian) from a concrete address.
    pub fn read_u32_le(&mut self, addr: u64) -> Result<Option<u32>, MemoryError> {
        let r = self.read(addr, 4)?;
        Ok(r.as_u32_le())
    }

    /// Read a u64 (little-endian) from a concrete address.
    pub fn read_u64_le(&mut self, addr: u64) -> Result<Option<u64>, MemoryError> {
        let r = self.read(addr, 8)?;
        Ok(r.as_u64_le())
    }

    /// Check the alias relationship between two address ranges.
    #[must_use] 
    pub fn alias_check(&self, addr_a: &SymAddr, size_a: usize, addr_b: &SymAddr, size_b: usize) -> AliasRelation {
        // Use is_concrete() rather than as_concrete() so that a symbolic
        // address with a known numeric base/offset is still treated as
        // symbolic for aliasing purposes.
        let conc_a = if addr_a.is_concrete() { addr_a.as_concrete() } else { None };
        let conc_b = if addr_b.is_concrete() { addr_b.as_concrete() } else { None };
        match (conc_a, conc_b) {
            (Some(a), Some(b)) => {
                let a_end = a.saturating_add(size_a as u64);
                let b_end = b.saturating_add(size_b as u64);
                if a == b && size_a == size_b { AliasRelation::MustAlias }
                else if a_end <= b || b_end <= a { AliasRelation::NoAlias }
                else { AliasRelation::MayAlias }
            }
            (None, None) => {
                // Both symbolic — conservative
                if addr_a == addr_b { AliasRelation::MustAlias } else { AliasRelation::MayAlias }
            }
            _ => AliasRelation::MayAlias,
        }
    }

    /// Return the number of cells currently allocated.
    #[must_use] 
    pub fn cell_count(&self) -> usize { self.cells.len() }

    /// Return a snapshot of the write log.
    #[must_use] 
    pub fn write_log(&self) -> &[SymMemoryWrite] { &self.write_log }

    /// Return a snapshot of the read log.
    #[must_use] 
    pub fn read_log(&self) -> &[SymMemoryRead] { &self.read_log }

    /// True if address `addr` is initialised (has a non-Uninit value).
    #[must_use] 
    pub fn is_initialised(&self, addr: u64) -> bool {
        self.cells.get(&addr).is_some_and(|v| !v.is_uninit())
    }

    /// True if address `addr` holds a symbolic value.
    #[must_use] 
    pub fn is_symbolic_addr(&self, addr: u64) -> bool {
        matches!(self.cells.get(&addr), Some(SymValue::Symbolic { .. } | SymValue::Derived { .. }))
    }

    /// Find all symbolic cells (addresses that contain a symbolic value).
    #[must_use] 
    pub fn symbolic_cells(&self) -> Vec<u64> {
        self.cells.iter()
            .filter(|(_, v)| matches!(v, SymValue::Symbolic { .. } | SymValue::Derived { .. }))
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Clear all cells and logs (reset to empty state).
    pub fn reset(&mut self) {
        self.cells.clear();
        self.write_log.clear();
        self.read_log.clear();
        self.sequence = 0;
        self.symbolic_regions.clear();
    }

    const fn next_seq(&mut self) -> u64 {
        let s = self.sequence;
        self.sequence += 1;
        s
    }

    /// Return the value at `addr` without recording a read.
    #[must_use] 
    pub fn peek(&self, addr: u64) -> Option<&SymValue> {
        self.cells.get(&addr)
    }

    /// Copy a range of memory to another address.
    pub fn memmove(&mut self, dst: u64, src: u64, size: usize) -> Result<(), MemoryError> {
        let values: Vec<SymValue> = (0..size).map(|i| {
            self.cells.get(&(src + i as u64)).cloned().unwrap_or(SymValue::Uninit)
        }).collect();
        for (i, v) in values.into_iter().enumerate() {
            self.cells.insert(dst + i as u64, v);
        }
        Ok(())
    }

    /// Fill a range with a concrete byte value (like memset).
    pub fn memset(&mut self, addr: u64, value: u8, size: usize) {
        for i in 0..size {
            self.cells.insert(addr + i as u64, SymValue::Concrete(value));
        }
    }
}

// ── SymbolicMemoryModel ───────────────────────────────────────────────────────

/// High-level symbolic memory model combining multiple segments, an alias
/// analysis cache, and constraint tracking.
pub struct SymbolicMemoryModel {
    /// The underlying symbolic memory store.
    pub memory: SymMemory,
    /// Named segments: name → (base, size).
    segments: HashMap<String, (u64, usize)>,
    /// Alias analysis cache.
    alias_cache: HashMap<(SymAddr, SymAddr), AliasRelation>,
    /// Track all addresses that have been symbolically written.
    symbolic_write_addrs: HashSet<u64>,
    /// Path-condition string constraints (simplified).
    constraints: Vec<String>,
}

impl Default for SymbolicMemoryModel {
    fn default() -> Self { Self::new() }
}

impl SymbolicMemoryModel {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            memory: SymMemory::new(),
            segments: HashMap::new(),
            alias_cache: HashMap::new(),
            symbolic_write_addrs: HashSet::new(),
            constraints: Vec::new(),
        }
    }

    /// Register a named memory segment.
    pub fn add_segment(&mut self, name: impl Into<String>, base: u64, size: usize) {
        let n = name.into();
        self.segments.insert(n, (base, size));
    }

    /// Write a symbolic input to a named segment.
    pub fn symbolise_segment(&mut self, name: &str) -> bool {
        if let Some(&(base, size)) = self.segments.get(name) {
            self.memory.register_symbolic_region(name, base, size);
            for i in 0..size {
                self.symbolic_write_addrs.insert(base + i as u64);
            }
            return true;
        }
        false
    }

    /// Add a constraint string (e.g., from a branch condition).
    pub fn add_constraint(&mut self, constraint: impl Into<String>) {
        self.constraints.push(constraint.into());
    }

    /// Return all current constraints.
    #[must_use] 
    pub fn constraints(&self) -> &[String] { &self.constraints }

    /// Perform an alias query and cache the result.
    pub fn query_alias(
        &mut self,
        a: SymAddr, size_a: usize,
        b: SymAddr, size_b: usize,
    ) -> AliasRelation {
        let key = (a.clone(), b.clone());
        if let Some(&cached) = self.alias_cache.get(&key) {
            return cached;
        }
        let result = self.memory.alias_check(&a, size_a, &b, size_b);
        self.alias_cache.insert(key, result);
        result
    }

    /// Return all symbolic cell addresses.
    #[must_use] 
    pub fn symbolic_addresses(&self) -> Vec<u64> {
        self.memory.symbolic_cells()
    }

    /// Return statistics about the memory state.
    #[must_use] 
    pub fn stats(&self) -> MemoryStats {
        let total = self.memory.cell_count();
        let symbolic = self.memory.symbolic_cells().len();
        let concrete = total - symbolic;
        MemoryStats {
            total_cells: total,
            concrete_cells: concrete,
            symbolic_cells: symbolic,
            write_count: self.memory.write_log().len(),
            read_count: self.memory.read_log().len(),
            constraint_count: self.constraints.len(),
            segment_count: self.segments.len(),
        }
    }

    /// Clone the underlying memory into a new model (for branching).
    #[must_use] 
    pub fn fork(&self) -> Self {
        let mut forked = Self::new();
        forked.memory.cells = self.memory.cells.clone();
        forked.memory.symbolic_regions = self.memory.symbolic_regions.clone();
        forked.memory.sequence = self.memory.sequence;
        forked.memory.allow_uninit = self.memory.allow_uninit;
        forked.segments = self.segments.clone();
        forked.symbolic_write_addrs = self.symbolic_write_addrs.clone();
        forked.constraints = self.constraints.clone();
        forked
    }

    /// Merge two models by taking the union of writes (newer wins).
    pub fn merge_with(&mut self, other: &Self) {
        for (&addr, val) in &other.memory.cells {
            self.memory.cells.insert(addr, val.clone());
        }
        for c in &other.constraints {
            if !self.constraints.contains(c) {
                self.constraints.push(c.clone());
            }
        }
        self.symbolic_write_addrs.extend(&other.symbolic_write_addrs);
    }
}

/// Statistics snapshot of a `SymbolicMemoryModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_cells: usize,
    pub concrete_cells: usize,
    pub symbolic_cells: usize,
    pub write_count: usize,
    pub read_count: usize,
    pub constraint_count: usize,
    pub segment_count: usize,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> SymMemory {
        let mut m = SymMemory::new();
        m.allow_uninit = true;
        m
    }

    #[test]
    fn test_sym_addr_concrete() {
        let a = SymAddr::concrete(0x1000);
        assert!(a.is_concrete());
        assert_eq!(a.as_concrete(), Some(0x1000));
    }

    /// A symbolic address is not concrete, however fully known its base and
    /// offset happen to be.
    ///
    /// This test used to assert `as_concrete() == Some(0)` and had been failing
    /// ever since the two notions were separated: it was reasoning about the
    /// *representation* (`base=0, offset=0`) rather than the meaning. Both
    /// halves are asserted here so the distinction cannot quietly collapse
    /// again — `as_concrete` answers "is this a resolved address?", while
    /// `try_resolve_concrete` answers "what number does this evaluate to?".
    #[test]
    fn test_sym_addr_symbolic_no_base() {
        let a = SymAddr::symbolic("x");
        assert!(a.is_symbolic());
        assert_eq!(a.as_concrete(), None, "a symbolic address is never concrete");
        assert_eq!(
            a.try_resolve_concrete(),
            Some(0),
            "base=0 and offset=0 still resolve to 0 when asked explicitly"
        );
    }

    #[test]
    fn test_sym_addr_add_offset() {
        let a = SymAddr::concrete(0x1000);
        let b = a.add_offset(16);
        assert_eq!(b.as_concrete(), Some(0x1010));
    }

    #[test]
    fn test_sym_addr_display() {
        let a = SymAddr::concrete(0x400);
        assert_eq!(a.to_string(), "0x400");
        let b = SymAddr::symbolic("buf");
        assert!(b.to_string().contains("sym"));
    }

    #[test]
    fn test_sym_value_concrete() {
        let v = SymValue::concrete(0xAB);
        assert!(v.is_concrete());
        assert_eq!(v.as_concrete(), Some(0xAB));
    }

    #[test]
    fn test_sym_value_symbolic() {
        let v = SymValue::symbolic("arg0");
        assert!(!v.is_concrete());
        assert_eq!(v.as_concrete(), None);
    }

    #[test]
    fn test_sym_value_uninit() {
        let v = SymValue::Uninit;
        assert!(v.is_uninit());
        assert_eq!(v.as_concrete(), None);
    }

    #[test]
    fn test_write_and_read_concrete() {
        let mut m = fresh();
        m.write_concrete(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let r = m.read(0x1000, 4).unwrap();
        assert!(r.is_fully_concrete());
        assert_eq!(r.as_u32_le(), Some(0xEFBEADDE));
    }

    #[test]
    fn test_write_u8_and_read() {
        let mut m = fresh();
        m.write_u8(0x2000, 0x42);
        let v = m.read_u8(0x2000).unwrap();
        assert_eq!(v, Some(0x42));
    }

    #[test]
    fn test_write_u32_le() {
        let mut m = fresh();
        m.write_u32_le(0x3000, 0xCAFEBABE);
        let r = m.read_u32_le(0x3000).unwrap();
        assert_eq!(r, Some(0xCAFEBABE));
    }

    #[test]
    fn test_write_u64_le() {
        let mut m = fresh();
        m.write_u64_le(0x4000, 0x0102030405060708);
        let r = m.read_u64_le(0x4000).unwrap();
        assert_eq!(r, Some(0x0102030405060708));
    }

    #[test]
    fn test_read_uninit_with_allow() {
        let mut m = fresh(); // allow_uninit = true
        let r = m.read(0x9999, 2).unwrap();
        assert!(r.had_uninit);
    }

    #[test]
    fn test_read_uninit_without_allow() {
        let mut m = SymMemory::new(); // allow_uninit = false
        let result = m.read(0x9999, 1);
        assert!(matches!(result, Err(MemoryError::UninitialisedRead(0x9999, 1))));
    }

    #[test]
    fn test_symbolic_region() {
        let mut m = fresh();
        m.register_symbolic_region("input", 0x5000, 8);
        assert!(m.is_initialised(0x5000));
        assert!(m.is_symbolic_addr(0x5000));
        let r = m.read(0x5000, 4).unwrap();
        assert!(r.had_symbolic);
    }

    #[test]
    fn test_symbolic_cells_count() {
        let mut m = fresh();
        m.register_symbolic_region("buf", 0x6000, 16);
        assert_eq!(m.symbolic_cells().len(), 16);
    }

    #[test]
    fn test_alias_must_alias() {
        let m = fresh();
        let a = SymAddr::Concrete(0x1000);
        let b = SymAddr::Concrete(0x1000);
        assert_eq!(m.alias_check(&a, 4, &b, 4), AliasRelation::MustAlias);
    }

    #[test]
    fn test_alias_no_alias() {
        let m = fresh();
        let a = SymAddr::Concrete(0x1000);
        let b = SymAddr::Concrete(0x2000);
        assert_eq!(m.alias_check(&a, 4, &b, 4), AliasRelation::NoAlias);
    }

    #[test]
    fn test_alias_may_alias_overlap() {
        let m = fresh();
        let a = SymAddr::Concrete(0x1000);
        let b = SymAddr::Concrete(0x1002);
        // [1000, 1004) overlaps [1002, 1006)
        assert_eq!(m.alias_check(&a, 4, &b, 4), AliasRelation::MayAlias);
    }

    #[test]
    fn test_alias_symbolic_same() {
        let m = fresh();
        let a = SymAddr::symbolic("p");
        let b = SymAddr::symbolic("p");
        assert_eq!(m.alias_check(&a, 4, &b, 4), AliasRelation::MustAlias);
    }

    #[test]
    fn test_alias_symbolic_different() {
        let m = fresh();
        let a = SymAddr::symbolic("p");
        let b = SymAddr::symbolic("q");
        // Different names → MayAlias (conservative)
        assert_eq!(m.alias_check(&a, 4, &b, 4), AliasRelation::MayAlias);
    }

    #[test]
    fn test_write_log_tracking() {
        let mut m = fresh();
        m.write_concrete(0x1000, &[1, 2, 3]);
        m.write_concrete(0x2000, &[4, 5]);
        assert_eq!(m.write_log().len(), 2);
    }

    #[test]
    fn test_read_log_tracking() {
        let mut m = fresh();
        m.write_concrete(0x1000, &[1, 2, 3, 4]);
        m.read(0x1000, 4).unwrap();
        m.read(0x1000, 2).unwrap();
        assert_eq!(m.read_log().len(), 2);
    }

    #[test]
    fn test_memset() {
        let mut m = fresh();
        m.memset(0x7000, 0xFF, 8);
        let r = m.read(0x7000, 8).unwrap();
        assert!(r.bytes.iter().all(|b| b.as_concrete() == Some(0xFF)));
    }

    #[test]
    fn test_memmove() {
        let mut m = fresh();
        m.write_concrete(0x1000, &[0xAA, 0xBB, 0xCC]);
        m.memmove(0x2000, 0x1000, 3).unwrap();
        let r = m.read(0x2000, 3).unwrap();
        assert_eq!(r.bytes[0].as_concrete(), Some(0xAA));
        assert_eq!(r.bytes[2].as_concrete(), Some(0xCC));
    }

    #[test]
    fn test_peek_returns_value() {
        let mut m = fresh();
        m.write_u8(0x800, 0x11);
        assert_eq!(m.peek(0x800).and_then(|v| v.as_concrete()), Some(0x11));
    }

    #[test]
    fn test_peek_missing_returns_none() {
        let m = fresh();
        assert!(m.peek(0xDEAD).is_none());
    }

    #[test]
    fn test_reset_clears() {
        let mut m = fresh();
        m.write_u8(0x100, 42);
        m.reset();
        assert_eq!(m.cell_count(), 0);
        assert!(m.write_log().is_empty());
    }

    #[test]
    fn test_symbolic_memory_model_fork() {
        let mut model = SymbolicMemoryModel::new();
        model.memory.write_concrete(0x1000, &[1, 2, 3]);
        model.add_constraint("x > 0");
        let fork = model.fork();
        assert_eq!(fork.memory.peek(0x1000).and_then(|v| v.as_concrete()), Some(1));
        assert_eq!(fork.constraints().len(), 1);
    }

    #[test]
    fn test_symbolic_memory_model_merge() {
        let mut a = SymbolicMemoryModel::new();
        let mut b = SymbolicMemoryModel::new();
        a.memory.write_u8(0x1000, 0xAA);
        b.memory.write_u8(0x2000, 0xBB);
        a.merge_with(&b);
        assert_eq!(a.memory.peek(0x2000).and_then(|v| v.as_concrete()), Some(0xBB));
    }

    #[test]
    fn test_symbolic_memory_model_stats() {
        let mut model = SymbolicMemoryModel::new();
        model.memory.write_concrete(0x1000, &[1, 2, 3]);
        model.add_segment("stack", 0x8000, 128);
        model.add_constraint("sp > 0");
        let stats = model.stats();
        assert_eq!(stats.total_cells, 3);
        assert_eq!(stats.constraint_count, 1);
        assert_eq!(stats.segment_count, 1);
    }

    #[test]
    fn test_query_alias_caching() {
        let mut model = SymbolicMemoryModel::new();
        let a = SymAddr::Concrete(0x1000);
        let b = SymAddr::Concrete(0x2000);
        let r1 = model.query_alias(a.clone(), 4, b.clone(), 4);
        let r2 = model.query_alias(a, 4, b, 4);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_symbolise_segment() {
        let mut model = SymbolicMemoryModel::new();
        model.add_segment("heap", 0x10000, 64);
        let success = model.symbolise_segment("heap");
        assert!(success);
        assert_eq!(model.symbolic_addresses().len(), 64);
    }

    #[test]
    fn test_symbolise_missing_segment() {
        let mut model = SymbolicMemoryModel::new();
        let success = model.symbolise_segment("nonexistent");
        assert!(!success);
    }

    #[test]
    fn test_sym_memory_read_as_u64() {
        let mut m = fresh();
        m.write_u64_le(0x100, 0xDEADBEEFCAFEBABE);
        let r = m.read(0x100, 8).unwrap();
        assert_eq!(r.as_u64_le(), Some(0xDEADBEEFCAFEBABE));
    }

    #[test]
    fn test_sym_memory_read_symbolic_no_u64() {
        let mut m = fresh();
        m.register_symbolic_region("arg", 0x200, 8);
        let r = m.read(0x200, 8).unwrap();
        assert_eq!(r.as_u64_le(), None);
    }

    #[test]
    fn test_write_with_tag() {
        let mut m = fresh();
        let w = m.write(0x300, vec![SymValue::concrete(0xAB)], Some("test_tag".into()));
        assert_eq!(w.tag.as_deref(), Some("test_tag"));
    }

    #[test]
    fn test_sym_value_display() {
        assert_eq!(SymValue::concrete(0xFF).to_string(), "0xff");
        assert!(SymValue::symbolic("x").to_string().contains("sym"));
        assert_eq!(SymValue::Uninit.to_string(), "uninit");
    }

    #[test]
    fn test_alias_relation_display() {
        assert_eq!(AliasRelation::MustAlias.to_string(), "MustAlias");
        assert_eq!(AliasRelation::NoAlias.to_string(), "NoAlias");
    }
}
