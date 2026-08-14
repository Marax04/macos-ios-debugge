//! `symbolic_memory` — Symbolic memory model for the `RustRE` symbolic execution engine.
//!
//! Provides [`SymbolicMemory`], [`MemoryCell`], and [`MemoryRegion`],
//! plus [`read_symbolic`] and [`write_symbolic`] free functions.

use rustre_symb::{SymExpr, SymbolicError};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ── MemoryCell ─────────────────────────────────────────────────────────────────

/// The contents of a single addressable memory cell (one byte).
#[derive(Debug, Clone)]
pub enum MemoryCell {
    /// A known concrete byte value.
    Concrete(u8),
    /// A symbolic expression representing this byte.
    Symbolic(SymExpr),
    /// Memory that has not been initialised (any read is an error or returns unconstrained symbol).
    Uninit,
}

impl MemoryCell {
    /// Return the concrete value if this cell is concrete.
    #[must_use]
    pub const fn as_concrete(&self) -> Option<u8> {
        if let Self::Concrete(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Return the symbolic expression if this cell is symbolic.
    #[must_use]
    pub const fn as_symbolic(&self) -> Option<&SymExpr> {
        if let Self::Symbolic(e) = self {
            Some(e)
        } else {
            None
        }
    }

    /// Whether this cell has a definite value (concrete or symbolic).
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Uninit)
    }

    /// Promote a concrete cell to a symbolic expression.
    #[must_use]
    pub fn to_sym_expr(&self) -> SymExpr {
        match self {
            Self::Concrete(v) => SymExpr::ConstBv { val: u64::from(*v), width: 8 },
            Self::Symbolic(e) => e.clone(),
            Self::Uninit => SymExpr::ConstBv { val: 0, width: 8 },
        }
    }
}

impl fmt::Display for MemoryCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#04x}"),
            Self::Symbolic(e) => write!(f, "sym({e:?})"),
            Self::Uninit => write!(f, "uninit"),
        }
    }
}

// ── MemoryRegion ───────────────────────────────────────────────────────────────

/// Access permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl RegionPerms {
    #[must_use]
    pub const fn rwx() -> Self {
        Self { read: true, write: true, execute: true }
    }
    #[must_use]
    pub const fn rw() -> Self {
        Self { read: true, write: true, execute: false }
    }
    #[must_use]
    pub const fn rx() -> Self {
        Self { read: true, write: false, execute: true }
    }
    #[must_use]
    pub const fn r() -> Self {
        Self { read: true, write: false, execute: false }
    }
}

/// A contiguous named region of symbolic memory.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Human-readable name (e.g. `"stack"`, `".text"`, `"heap_0"`).
    pub name: String,
    /// Start address (inclusive).
    pub base: u64,
    /// Length in bytes.
    pub size: u64,
    /// Access permissions.
    pub perms: RegionPerms,
    /// Cell storage (sparse; unmapped cells are `Uninit`).
    cells: BTreeMap<u64, MemoryCell>,
}

impl MemoryRegion {
    /// Create a new empty region.
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, size: u64, perms: RegionPerms) -> Self {
        Self {
            name: name.into(),
            base,
            size,
            perms,
            cells: BTreeMap::new(),
        }
    }

    /// Whether `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }

    /// Read one cell at `addr`, returning `Uninit` if not written.
    #[must_use]
    pub fn read_cell(&self, addr: u64) -> &MemoryCell {
        static UNINIT: MemoryCell = MemoryCell::Uninit;
        if !self.contains(addr) {
            return &UNINIT;
        }
        self.cells.get(&addr).unwrap_or(&UNINIT)
    }

    /// Write one cell at `addr`.
    pub fn write_cell(&mut self, addr: u64, cell: MemoryCell) {
        if self.contains(addr) {
            self.cells.insert(addr, cell);
        }
    }

    /// Write concrete bytes starting at `addr`.
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let a = addr + i as u64;
            if self.contains(a) {
                self.cells.insert(a, MemoryCell::Concrete(b));
            }
        }
    }

    /// Number of cells with a defined value.
    #[must_use]
    pub fn defined_cell_count(&self) -> usize {
        self.cells.values().filter(|c| c.is_defined()).count()
    }

    /// Clear all cells (reset to Uninit).
    pub fn clear(&mut self) {
        self.cells.clear();
    }

    /// Iterate over all (addr, cell) pairs stored.
    pub fn iter_cells(&self) -> impl Iterator<Item = (u64, &MemoryCell)> {
        self.cells.iter().map(|(&a, c)| (a, c))
    }
}

// ── SymbolicMemory ─────────────────────────────────────────────────────────────

/// A flat, multi-region symbolic memory model.
///
/// Regions are looked up by address.  Reads and writes outside mapped regions
/// return / raise a [`SymbolicError`].
#[derive(Debug, Clone)]
pub struct SymbolicMemory {
    regions: Vec<MemoryRegion>,
    /// Symbolic base: expressions that represent symbolic pointer offsets.
    symbolic_bases: HashMap<u64, SymExpr>,
    read_count: u64,
    write_count: u64,
    uninit_reads: u64,
}

impl SymbolicMemory {
    /// Create an empty memory model.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            symbolic_bases: HashMap::new(),
            read_count: 0,
            write_count: 0,
            uninit_reads: 0,
        }
    }

    /// Map a new region into the address space.
    pub fn map_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Add a convenience stack region from `base` to `base + size`.
    pub fn map_stack(&mut self, base: u64, size: u64) {
        self.map_region(MemoryRegion::new("stack", base, size, RegionPerms::rw()));
    }

    /// Add a convenience heap region.
    pub fn map_heap(&mut self, base: u64, size: u64) {
        self.map_region(MemoryRegion::new("heap", base, size, RegionPerms::rw()));
    }

    /// Add a read-execute code region pre-filled with `bytes`.
    pub fn map_code(&mut self, base: u64, bytes: &[u8]) {
        // Cap at u64::MAX to avoid truncation; on 32-bit usize this is lossless,
        // on 64-bit usize slices cannot exceed u64::MAX bytes in practice.
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut region = MemoryRegion::new("code", base, size, RegionPerms::rx());
        region.write_bytes(base, bytes);
        self.map_region(region);
    }

    /// Find the region that contains `addr`, if any.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    fn region_at_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    /// Read a single byte cell at `addr`.
    ///
    /// Returns a `SymExpr` representing the value.
    /// Concrete cells produce `SymExpr::Concrete`; symbolic cells return their expression;
    /// uninitialised cells return a fresh unconstrained symbol and increment the uninit counter.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if `addr` is not in any mapped region.
    pub fn read_byte(&mut self, addr: u64) -> Result<SymExpr, SymbolicError> {
        self.read_count += 1;
        if let Some(region) = self.region_at(addr) {
            let cell = region.read_cell(addr).clone();
            Ok(match cell {
                MemoryCell::Concrete(v) => SymExpr::ConstBv { val: u64::from(v), width: 8 },
                MemoryCell::Symbolic(e) => e,
                MemoryCell::Uninit => {
                    self.uninit_reads += 1;
                    SymExpr::Symbol(addr, 8, format!("mem_{addr:#x}"))
                }
            })
        } else {
            Err(SymbolicError::MemoryOutOfBounds(addr))
        }
    }

    /// Write a concrete byte at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if `addr` is not writable.
    pub fn write_byte_concrete(&mut self, addr: u64, val: u8) -> Result<(), SymbolicError> {
        self.write_count += 1;
        if let Some(region) = self.region_at_mut(addr) {
            if !region.perms.write {
                return Err(SymbolicError::MemoryOutOfBounds(addr));
            }
            region.write_cell(addr, MemoryCell::Concrete(val));
            Ok(())
        } else {
            Err(SymbolicError::MemoryOutOfBounds(addr))
        }
    }

    /// Write a symbolic expression at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if `addr` is not writable.
    pub fn write_byte_symbolic(&mut self, addr: u64, expr: SymExpr) -> Result<(), SymbolicError> {
        self.write_count += 1;
        if let Some(region) = self.region_at_mut(addr) {
            if !region.perms.write {
                return Err(SymbolicError::MemoryOutOfBounds(addr));
            }
            region.write_cell(addr, MemoryCell::Symbolic(expr));
            Ok(())
        } else {
            Err(SymbolicError::MemoryOutOfBounds(addr))
        }
    }

    /// Read `width` bytes starting at `addr` (little-endian), returning a combined expression.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if any byte in the range is unmapped.
    pub fn read_le(&mut self, addr: u64, width: u8) -> Result<SymExpr, SymbolicError> {
        let width = width.clamp(1, 8);
        if width == 1 {
            return self.read_byte(addr);
        }
        // Read all bytes
        let mut all_concrete = true;
        let mut bytes = [0u8; 8];
        let mut exprs: Vec<SymExpr> = Vec::with_capacity(usize::from(width));
        for i in 0..u64::from(width) {
            let e = self.read_byte(addr + i)?;
            if let SymExpr::ConstBv { val: v, .. } = &e {
                bytes[usize::try_from(i).unwrap_or(0)] = u8::try_from(*v).unwrap_or(u8::MAX);
            } else {
                all_concrete = false;
            }
            exprs.push(e);
        }
        if all_concrete {
            let mut val = 0u64;
            for (i, b) in bytes[..width as usize].iter().enumerate() {
                val |= u64::from(*b) << (i * 8);
            }
            Ok(SymExpr::ConstBv { val, width: u32::from(width) * 8 })
        } else {
            // Return first symbolic byte for simplicity; a real engine would concat
            Ok(exprs.remove(0))
        }
    }

    /// Write `width` bytes of a concrete value at `addr` (little-endian).
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if any byte in the range is not writable.
    pub fn write_le_concrete(&mut self, addr: u64, val: u64, width: u8) -> Result<(), SymbolicError> {
        // `val` is a u64, so only 8 bytes exist to write: past that the shift
        // below reaches 64+ bits (panic in debug, silently masked back into
        // range in release, writing recycled bytes). Mirrors the upper bound of
        // `read_le`. Unlike `read_le` a width of 0 is left as a no-op rather
        // than promoted to 1, so callers that write nothing keep writing nothing.
        let width = width.min(8);
        for i in 0..u64::from(width) {
            let byte = u8::try_from((val >> (i * 8)) & 0xFF).unwrap_or(u8::MAX);
            self.write_byte_concrete(addr + i, byte)?;
        }
        Ok(())
    }

    /// Write `width` bytes of a symbolic value at `addr` (uses same expression for all bytes).
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::MemoryOutOfBounds`] if any byte in the range is not writable.
    pub fn write_le_symbolic(&mut self, addr: u64, expr: &SymExpr, width: u8) -> Result<(), SymbolicError> {
        for i in 0..u64::from(width) {
            self.write_byte_symbolic(addr + i, expr.clone())?;
        }
        Ok(())
    }

    /// Store a symbolic expression at a named base address.
    pub fn store_symbolic_base(&mut self, id: u64, expr: SymExpr) {
        self.symbolic_bases.insert(id, expr);
    }

    /// Load a previously stored symbolic base expression.
    #[must_use]
    pub fn load_symbolic_base(&self, id: u64) -> Option<&SymExpr> {
        self.symbolic_bases.get(&id)
    }

    /// Statistics: (reads, writes, `uninit_reads`).
    #[must_use]
    pub const fn stats(&self) -> (u64, u64, u64) {
        (self.read_count, self.write_count, self.uninit_reads)
    }

    /// Number of mapped regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Take a snapshot of the memory (clone for fork).
    #[must_use]
    pub fn snapshot(&self) -> Self {
        self.clone()
    }
}

impl Default for SymbolicMemory {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Read `width` bytes from `mem` at `addr` as a symbolic expression.
///
/// Convenience wrapper around [`SymbolicMemory::read_le`].
///
/// # Errors
///
/// Returns [`SymbolicError::MemoryOutOfBounds`] if any byte is not mapped.
pub fn read_symbolic(
    mem: &mut SymbolicMemory,
    addr: u64,
    width: u8,
) -> Result<SymExpr, SymbolicError> {
    mem.read_le(addr, width)
}

/// Write a symbolic expression to `mem` at `addr`.
///
/// Convenience wrapper around [`SymbolicMemory::write_le_symbolic`].
///
/// # Errors
///
/// Returns [`SymbolicError::MemoryOutOfBounds`] if any byte is not writable.
pub fn write_symbolic(
    mem: &mut SymbolicMemory,
    addr: u64,
    expr: &SymExpr,
    width: u8,
) -> Result<(), SymbolicError> {
    mem.write_le_symbolic(addr, expr, width)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mem() -> SymbolicMemory {
        let mut m = SymbolicMemory::new();
        m.map_stack(0x7fff_0000, 0x1000);
        m.map_code(0x1000, &[0x90, 0x90, 0xC3]); // nop nop ret
        m
    }

    #[test]
    fn test_memory_cell_concrete() {
        let c = MemoryCell::Concrete(0xAB);
        assert_eq!(c.as_concrete(), Some(0xAB));
        assert!(c.is_defined());
    }

    #[test]
    fn test_memory_cell_uninit() {
        let c = MemoryCell::Uninit;
        assert!(!c.is_defined());
        assert_eq!(c.as_concrete(), None);
    }

    #[test]
    fn test_memory_cell_symbolic() {
        let e = SymExpr::ConstBv { val: 42, width: 8 };
        let c = MemoryCell::Symbolic(e);
        assert!(c.as_symbolic().is_some());
        assert!(c.is_defined());
    }

    #[test]
    fn test_memory_cell_to_sym_expr_concrete() {
        let c = MemoryCell::Concrete(5);
        let e = c.to_sym_expr();
        assert!(matches!(e, SymExpr::ConstBv { val: 5, width: 8 }));
    }

    #[test]
    fn test_region_contains() {
        let r = MemoryRegion::new("test", 0x1000, 0x100, RegionPerms::rw());
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_region_write_read() {
        let mut r = MemoryRegion::new("test", 0x1000, 0x100, RegionPerms::rw());
        r.write_cell(0x1000, MemoryCell::Concrete(0xFF));
        assert_eq!(r.read_cell(0x1000).as_concrete(), Some(0xFF));
    }

    #[test]
    fn test_region_write_bytes() {
        let mut r = MemoryRegion::new("test", 0x0, 0x10, RegionPerms::rw());
        r.write_bytes(0x0, &[1, 2, 3]);
        assert_eq!(r.read_cell(0x0).as_concrete(), Some(1));
        assert_eq!(r.read_cell(0x2).as_concrete(), Some(3));
    }

    #[test]
    fn test_region_uninit_read() {
        let r = MemoryRegion::new("test", 0x1000, 0x100, RegionPerms::rw());
        let cell = r.read_cell(0x1050);
        assert!(!cell.is_defined());
    }

    #[test]
    fn test_symbolic_memory_map_and_read() {
        let mut m = make_mem();
        let e = m.read_byte(0x1000);
        assert!(e.is_ok());
        if let Ok(SymExpr::ConstBv { val: v, .. }) = e {
            assert_eq!(v, 0x90);
        }
    }

    #[test]
    fn test_symbolic_memory_out_of_range() {
        let mut m = make_mem();
        let e = m.read_byte(0xDEAD_BEEF);
        assert!(e.is_err());
    }

    #[test]
    fn test_symbolic_memory_write_concrete() {
        let mut m = make_mem();
        assert!(m.write_byte_concrete(0x7fff_0000, 0x42).is_ok());
        let e = m.read_byte(0x7fff_0000).unwrap();
        assert!(matches!(e, SymExpr::ConstBv { val: 0x42, .. }));
    }

    #[test]
    fn test_symbolic_memory_write_symbolic() {
        let mut m = make_mem();
        let sym = SymExpr::Symbol(1, 8, "x".to_string());
        assert!(m.write_byte_symbolic(0x7fff_0000, sym).is_ok());
        let e = m.read_byte(0x7fff_0000).unwrap();
        assert!(matches!(e, SymExpr::Var { .. }));
    }

    #[test]
    fn test_symbolic_memory_read_le_concrete() {
        let mut m = SymbolicMemory::new();
        m.map_stack(0x0, 0x10);
        m.write_le_concrete(0x0, 0x0102_0304, 4).unwrap();
        let e = m.read_le(0x0, 4).unwrap();
        assert!(matches!(e, SymExpr::ConstBv { val: 0x0102_0304, .. }));
    }

    #[test]
    fn test_symbolic_memory_uninit_read_counter() {
        let mut m = make_mem();
        let _ = m.read_byte(0x7fff_0500); // uninit
        let (_, _, uninit) = m.stats();
        assert_eq!(uninit, 1);
    }

    #[test]
    fn test_symbolic_memory_stats() {
        let mut m = make_mem();
        m.read_byte(0x1000).unwrap();
        m.write_byte_concrete(0x7fff_0000, 1).unwrap();
        let (reads, writes, _) = m.stats();
        assert_eq!(reads, 1);
        assert_eq!(writes, 1);
    }

    #[test]
    fn test_symbolic_memory_symbolic_base() {
        let mut m = SymbolicMemory::new();
        let e = SymExpr::Symbol(99, 64, "base".to_string());
        m.store_symbolic_base(99, e);
        assert!(m.load_symbolic_base(99).is_some());
        assert!(m.load_symbolic_base(0).is_none());
    }

    #[test]
    fn test_symbolic_memory_snapshot() {
        let mut m = make_mem();
        m.write_byte_concrete(0x7fff_0000, 0xAA).unwrap();
        let snap = m.snapshot();
        assert_eq!(snap.region_count(), m.region_count());
    }

    #[test]
    fn test_read_symbolic_free_fn() {
        let mut m = make_mem();
        let e = read_symbolic(&mut m, 0x1000, 1);
        assert!(e.is_ok());
    }

    #[test]
    fn test_write_symbolic_free_fn() {
        let mut m = make_mem();
        let sym = SymExpr::Symbol(5, 8, "y".to_string());
        let r = write_symbolic(&mut m, 0x7fff_0000, &sym, 1);
        assert!(r.is_ok());
    }
}
