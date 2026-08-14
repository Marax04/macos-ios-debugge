//! Symbolic memory store: map addresses to symbolic expressions, support havoc
//! regions, and symbolic reads with optional concretisation.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SymExpr ──────────────────────────────────────────────────────────────────

/// A symbolic expression representing a value that may not be concretely known.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SymExpr {
    /// A concrete (fully-known) 64-bit value.
    Concrete(u64),
    /// A named symbolic variable.
    Sym(String),
    /// Bitwise NOT of an inner expression.
    Not(Box<Self>),
    /// Addition of two expressions.
    Add(Box<Self>, Box<Self>),
    /// Subtraction: `left - right`.
    Sub(Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Left-shift.
    Shl(Box<Self>, u8),
    /// Logical right-shift.
    Shr(Box<Self>, u8),
    /// Zero-extension of an `n`-bit value to 64 bits.
    ZExt(Box<Self>, u8),
    /// Sign-extension of an `n`-bit value to 64 bits.
    SExt(Box<Self>, u8),
    /// Extract bits `[hi..lo]` (inclusive, 0-based).
    Extract(Box<Self>, u8, u8),
    /// Concatenation of two expressions (upper, lower).
    Concat(Box<Self>, Box<Self>),
    /// A completely unknown (havoc'd) value.
    Havoc,
}

impl SymExpr {
    /// Return `true` if this expression is a concrete value.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete(_))
    }

    /// Return the concrete value if fully known.
    #[must_use]
    pub const fn concrete_value(&self) -> Option<u64> {
        if let Self::Concrete(v) = self { Some(*v) } else { None }
    }

    /// Return `true` if this expression is `Havoc` or contains `Havoc`.
    #[must_use]
    pub const fn is_symbolic(&self) -> bool {
        !self.is_concrete()
    }

    /// Attempt constant folding: evaluate fully-concrete sub-expressions.
    #[must_use]
    pub fn fold(self) -> Self {
        match self {
            Self::Not(inner) => {
                let i = inner.fold();
                if let Self::Concrete(v) = i { Self::Concrete(!v) } else { Self::Not(Box::new(i)) }
            }
            Self::Add(l, r) => {
                let (lf, rf) = (l.fold(), r.fold());
                match (&lf, &rf) {
                    (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(a.wrapping_add(*b)),
                    _ => Self::Add(Box::new(lf), Box::new(rf)),
                }
            }
            Self::Sub(l, r) => {
                let (lf, rf) = (l.fold(), r.fold());
                match (&lf, &rf) {
                    (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(a.wrapping_sub(*b)),
                    _ => Self::Sub(Box::new(lf), Box::new(rf)),
                }
            }
            Self::And(l, r) => {
                let (lf, rf) = (l.fold(), r.fold());
                match (&lf, &rf) {
                    (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(a & b),
                    _ => Self::And(Box::new(lf), Box::new(rf)),
                }
            }
            Self::Or(l, r) => {
                let (lf, rf) = (l.fold(), r.fold());
                match (&lf, &rf) {
                    (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(a | b),
                    _ => Self::Or(Box::new(lf), Box::new(rf)),
                }
            }
            Self::Xor(l, r) => {
                let (lf, rf) = (l.fold(), r.fold());
                match (&lf, &rf) {
                    (Self::Concrete(a), Self::Concrete(b)) => Self::Concrete(a ^ b),
                    _ => Self::Xor(Box::new(lf), Box::new(rf)),
                }
            }
            Self::Shl(e, n) => {
                let ef = e.fold();
                if let Self::Concrete(v) = ef {
                    // Shift amount >= 64 is defined as 0 for left-shift (all bits shifted out).
                    Self::Concrete(if n >= 64 { 0 } else { v << n })
                } else {
                    Self::Shl(Box::new(ef), n)
                }
            }
            Self::Shr(e, n) => {
                let ef = e.fold();
                if let Self::Concrete(v) = ef {
                    // Shift amount >= 64 is defined as 0 for logical right-shift.
                    Self::Concrete(if n >= 64 { 0 } else { v >> n })
                } else {
                    Self::Shr(Box::new(ef), n)
                }
            }
            other => other,
        }
    }

    /// Helper: create a symbolic variable named `s`.
    pub fn sym(s: impl Into<String>) -> Self {
        Self::Sym(s.into())
    }
}

impl fmt::Display for SymExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#x}"),
            Self::Sym(name) => write!(f, "{name}"),
            Self::Not(e) => write!(f, "~({e})"),
            Self::Add(l, r) => write!(f, "({l} + {r})"),
            Self::Sub(l, r) => write!(f, "({l} - {r})"),
            Self::And(l, r) => write!(f, "({l} & {r})"),
            Self::Or(l, r) => write!(f, "({l} | {r})"),
            Self::Xor(l, r) => write!(f, "({l} ^ {r})"),
            Self::Shl(e, n) => write!(f, "({e} << {n})"),
            Self::Shr(e, n) => write!(f, "({e} >> {n})"),
            Self::ZExt(e, n) => write!(f, "zext{n}({e})"),
            Self::SExt(e, n) => write!(f, "sext{n}({e})"),
            Self::Extract(e, hi, lo) => write!(f, "{e}[{hi}:{lo}]"),
            Self::Concat(hi, lo) => write!(f, "concat({hi}, {lo})"),
            Self::Havoc => write!(f, "HAVOC"),
        }
    }
}

// ─── StoreEntry ───────────────────────────────────────────────────────────────

/// One entry in the symbolic memory store, representing the value written to
/// a specific byte address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreEntry {
    /// The address this entry covers (byte granularity).
    pub address: u64,
    /// Number of bytes this entry represents (1, 2, 4, or 8).
    pub width_bytes: u8,
    /// The symbolic or concrete value.
    pub value: SymExpr,
    /// Generation counter: incremented each time this address is written.
    pub version: u32,
}

impl StoreEntry {
    /// Create a concrete store entry.
    #[must_use]
    pub const fn concrete(address: u64, width_bytes: u8, value: u64) -> Self {
        Self {
            address,
            width_bytes,
            value: SymExpr::Concrete(value),
            version: 0,
        }
    }

    /// Create a symbolic store entry.
    #[must_use]
    pub const fn symbolic(address: u64, width_bytes: u8, expr: SymExpr) -> Self {
        Self {
            address,
            width_bytes,
            value: expr,
            version: 0,
        }
    }
}

impl fmt::Display for StoreEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#x}:{}] v{} = {}",
            self.address, self.width_bytes, self.version, self.value
        )
    }
}

// ─── ReadResult ───────────────────────────────────────────────────────────────

/// The result of a symbolic read.
#[derive(Debug, Clone)]
pub enum ReadResult {
    /// A concrete value was found.
    Concrete(u64),
    /// A symbolic expression was found.
    Symbolic(SymExpr),
    /// No entry exists for this address (uninitialized read).
    Uninit,
    /// Multiple overlapping entries exist, producing a merged result.
    Merged(SymExpr),
}

impl fmt::Display for ReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "Concrete({v:#x})"),
            Self::Symbolic(e) => write!(f, "Symbolic({e})"),
            Self::Uninit => write!(f, "Uninit"),
            Self::Merged(e) => write!(f, "Merged({e})"),
        }
    }
}

// ─── SymbolicStore ────────────────────────────────────────────────────────────

/// A symbolic memory store that maps byte-level addresses to symbolic
/// expressions.
///
/// Writes are stored at the byte level; reads assemble the requested number
/// of bytes from overlapping entries.
#[derive(Debug, Clone, Default)]
pub struct SymbolicStore {
    /// The underlying map: address → entry.
    ///
    /// Entries may overlap.  When a wider write is performed (e.g. 8 bytes),
    /// the store records one entry at the base address with `width_bytes=8`.
    entries: BTreeMap<u64, StoreEntry>,
    /// Number of writes performed.
    write_count: u64,
    /// Number of reads performed.
    read_count: u64,
}

impl SymbolicStore {
    /// Create an empty `SymbolicStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Writes ────────────────────────────────────────────────────────────────

    /// Write a concrete value at `address` with `width_bytes` bytes.
    pub fn write_concrete(&mut self, address: u64, width_bytes: u8, value: u64) {
        self.write_expr(address, width_bytes, SymExpr::Concrete(value));
    }

    /// Write a symbolic expression at `address` with `width_bytes` bytes.
    pub fn write_expr(&mut self, address: u64, width_bytes: u8, expr: SymExpr) {
        let version = self
            .entries
            .get(&address)
            .map_or(0, |e| e.version + 1);
        self.entries.insert(
            address,
            StoreEntry {
                address,
                width_bytes,
                value: expr,
                version,
            },
        );
        self.write_count += 1;
    }

    // ── Reads ─────────────────────────────────────────────────────────────────

    /// Symbolically read `width_bytes` bytes starting at `address`.
    ///
    /// * If a single entry with `address == addr` and matching width exists,
    ///   it is returned directly.
    /// * If the address falls inside a wider entry, an `Extract` sub-expression
    ///   is returned.
    /// * If multiple entries partially cover the range, they are merged with
    ///   `Concat` nodes.
    /// * If no entry covers the address, `ReadResult::Uninit` is returned.
    pub fn symbolic_read(&mut self, address: u64, width_bytes: u8) -> ReadResult {
        self.read_count += 1;

        // Fast path: exact match.
        if let Some(entry) = self.entries.get(&address) && entry.width_bytes == width_bytes {
            return match &entry.value {
                SymExpr::Concrete(v) => ReadResult::Concrete(*v),
                other => ReadResult::Symbolic(other.clone()),
            };
        }

        // Slower path: find any entry that contains `address`.
        if let Some(entry) = self.find_containing_entry(address) {
            // Use u32 arithmetic to avoid u8 overflow: byte_offset can be up to
            // (entry.width_bytes - 1) bytes and width_bytes can be up to 8, so
            // hi can be as large as (7 + 8 - 1) * 8 + 7 = 119, which fits in u8,
            // but the intermediate sum may wrap if computed in u8.
            let byte_offset = u32::try_from(address - entry.address).unwrap_or(u32::MAX);
            let width = u32::from(width_bytes);
            let hi_u32 = (byte_offset + width - 1) * 8 + 7;
            let lo_u32 = byte_offset * 8;
            // Clamp to u8::MAX to avoid truncation silently producing wrong
            // bit indices; if either saturates, the entry is too wide for
            // 8-bit index fields and we fall through to the merge path.
            let (Ok(hi), Ok(lo)) = (u8::try_from(hi_u32), u8::try_from(lo_u32)) else {
                // Entry wider than 32 bytes — fall through to merge.
                return self.merge_bytes(address, width_bytes)
                    .map_or(ReadResult::Uninit, ReadResult::Merged);
            };
            let extracted = SymExpr::Extract(Box::new(entry.value), hi, lo).fold();
            return match extracted {
                SymExpr::Concrete(v) => ReadResult::Concrete(v),
                other => ReadResult::Symbolic(other),
            };
        }

        // Merge path: look for partial overlaps.
        self.merge_bytes(address, width_bytes)
            .map_or(ReadResult::Uninit, ReadResult::Merged)
    }

    // ── Havoc ─────────────────────────────────────────────────────────────────

    /// Havoc (mark as completely unknown) all entries whose addresses fall in
    /// `[start, start + len)`.
    pub fn havoc_region(&mut self, start: u64, len: u64) {
        let end = start.saturating_add(len);
        let keys: Vec<u64> = self
            .entries
            .range(start..end)
            .map(|(k, _)| *k)
            .collect();
        for key in keys {
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.value = SymExpr::Havoc;
                entry.version += 1;
            }
        }
    }

    /// Havoc a single address (mark as completely unknown).
    pub fn havoc_address(&mut self, address: u64) {
        self.write_expr(address, 8, SymExpr::Havoc);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return all entries in address order.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&StoreEntry> {
        self.entries.values().collect()
    }

    /// Return all entries whose address falls in `[start, end)`.
    #[must_use]
    pub fn entries_in_range(&self, start: u64, end: u64) -> Vec<&StoreEntry> {
        self.entries.range(start..end).map(|(_, v)| v).collect()
    }

    /// Return the number of tracked entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of writes performed.
    #[must_use]
    pub const fn write_count(&self) -> u64 {
        self.write_count
    }

    /// Return the number of reads performed.
    #[must_use]
    pub const fn read_count(&self) -> u64 {
        self.read_count
    }

    /// Remove all entries in `[start, start+len)`.
    pub fn remove_region(&mut self, start: u64, len: u64) {
        let end = start.saturating_add(len);
        let keys: Vec<u64> = self
            .entries
            .range(start..end)
            .map(|(k, _)| *k)
            .collect();
        for key in keys {
            self.entries.remove(&key);
        }
    }

    /// Merge another store into `self`.  Entries from `other` overwrite
    /// conflicting entries in `self`.
    pub fn merge_from(&mut self, other: &Self) {
        for (addr, entry) in &other.entries {
            self.entries.insert(*addr, entry.clone());
        }
    }

    /// Return `true` if all entries in `[start, start+len)` are concrete.
    #[must_use]
    pub fn region_is_concrete(&self, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        self.entries
            .range(start..end)
            .all(|(_, e)| e.value.is_concrete())
    }

    /// Clone only the entries in `[start, start+len)`.
    #[must_use]
    pub fn clone_region(&self, start: u64, len: u64) -> Self {
        let end = start.saturating_add(len);
        let mut out = Self::new();
        for (addr, entry) in self.entries.range(start..end) {
            out.entries.insert(*addr, entry.clone());
        }
        out
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Find an entry that fully contains `address` (i.e. `entry.address <=
    /// address < entry.address + entry.width_bytes`).
    fn find_containing_entry(&self, address: u64) -> Option<StoreEntry> {
        // Search backwards from address.
        let lo = address.saturating_sub(8); // max width = 8 bytes
        for (_, entry) in self.entries.range(lo..=address).rev() {
            let end = entry.address + u64::from(entry.width_bytes);
            if entry.address <= address && address < end {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Attempt to merge partial byte entries covering `[address, address+len)`.
    fn merge_bytes(&self, address: u64, width: u8) -> Option<SymExpr> {
        // Collect all bytes we can find.
        let end = address + u64::from(width);
        let mut parts: Vec<SymExpr> = Vec::with_capacity(usize::from(width));

        for byte_off in 0..width {
            let byte_addr = address + u64::from(byte_off);
            let expr = if let Some(entry) = self
                .entries
                .range(byte_addr.saturating_sub(8)..=byte_addr)
                .rev()
                .find(|(_, e)| {
                    e.address <= byte_addr && byte_addr < e.address + u64::from(e.width_bytes)
                })
                .map(|(_, e)| e)
            {
                let off = u8::try_from(byte_addr - entry.address).unwrap_or(u8::MAX);
                let hi = off * 8 + 7;
                let lo = off * 8;
                SymExpr::Extract(Box::new(entry.value.clone()), hi, lo).fold()
            } else {
                return None; // gap → give up
            };
            parts.push(expr);
        }
        let _ = end;

        // Build a Concat chain (big-endian: highest byte first).
        let mut acc = parts.pop()?;
        while let Some(next) = parts.pop() {
            acc = SymExpr::Concat(Box::new(next), Box::new(acc)).fold();
        }
        Some(acc)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_concrete() {
        let mut store = SymbolicStore::new();
        store.write_concrete(0x1000, 8, 0xdead_beef);
        let r = store.symbolic_read(0x1000, 8);
        assert!(matches!(r, ReadResult::Concrete(0xdead_beef)));
    }

    #[test]
    fn test_write_and_read_symbolic() {
        let mut store = SymbolicStore::new();
        store.write_expr(0x2000, 8, SymExpr::sym("x"));
        let r = store.symbolic_read(0x2000, 8);
        assert!(matches!(r, ReadResult::Symbolic(_)));
    }

    #[test]
    fn test_uninit_read() {
        let mut store = SymbolicStore::new();
        let r = store.symbolic_read(0xffff, 4);
        assert!(matches!(r, ReadResult::Uninit));
    }

    #[test]
    fn test_havoc_region_marks_unknown() {
        let mut store = SymbolicStore::new();
        store.write_concrete(0x100, 8, 42);
        store.write_concrete(0x108, 8, 99);
        store.havoc_region(0x100, 16);
        let e1 = store.entries.get(&0x100).unwrap();
        let e2 = store.entries.get(&0x108).unwrap();
        assert!(matches!(e1.value, SymExpr::Havoc));
        assert!(matches!(e2.value, SymExpr::Havoc));
    }

    #[test]
    fn test_fold_add_concrete() {
        let e = SymExpr::Add(
            Box::new(SymExpr::Concrete(10)),
            Box::new(SymExpr::Concrete(20)),
        )
        .fold();
        assert_eq!(e, SymExpr::Concrete(30));
    }

    #[test]
    fn test_fold_and_concrete() {
        let e = SymExpr::And(
            Box::new(SymExpr::Concrete(0xff)),
            Box::new(SymExpr::Concrete(0x0f)),
        )
        .fold();
        assert_eq!(e, SymExpr::Concrete(0x0f));
    }

    #[test]
    fn test_fold_not_concrete() {
        let e = SymExpr::Not(Box::new(SymExpr::Concrete(0))).fold();
        assert_eq!(e, SymExpr::Concrete(!0));
    }

    #[test]
    fn test_region_is_concrete() {
        let mut store = SymbolicStore::new();
        store.write_concrete(0x300, 8, 1);
        assert!(store.region_is_concrete(0x300, 8));
        store.write_expr(0x300, 8, SymExpr::Havoc);
        assert!(!store.region_is_concrete(0x300, 8));
    }

    #[test]
    fn test_entry_count_after_writes() {
        let mut store = SymbolicStore::new();
        store.write_concrete(0x10, 8, 1);
        store.write_concrete(0x20, 8, 2);
        assert_eq!(store.entry_count(), 2);
    }

    #[test]
    fn test_remove_region() {
        let mut store = SymbolicStore::new();
        store.write_concrete(0x500, 8, 0);
        store.write_concrete(0x508, 8, 0);
        store.remove_region(0x500, 16);
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_merge_from_overwrites() {
        let mut a = SymbolicStore::new();
        a.write_concrete(0x0, 8, 100);
        let mut b = SymbolicStore::new();
        b.write_concrete(0x0, 8, 999);
        a.merge_from(&b);
        let r = a.symbolic_read(0x0, 8);
        assert!(matches!(r, ReadResult::Concrete(999)));
    }

    #[test]
    fn test_display_sym_expr() {
        let e = SymExpr::Add(
            Box::new(SymExpr::sym("a")),
            Box::new(SymExpr::Concrete(5)),
        );
        assert_eq!(e.to_string(), "(a + 0x5)");
    }
}
