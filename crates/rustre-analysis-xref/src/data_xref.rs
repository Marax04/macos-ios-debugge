//! Data cross-reference analysis for `rustre-analysis-xref`.
//!
//! For every data item (global variable, constant, string, struct field) in a
//! binary this module builds a comprehensive reference database:
//!
//! * **Reference type** — read, write, or address-of (LEA / MOV-imm).
//! * **Reference chains** — transitive chains A → B → C where A references a
//!   pointer that in turn points to B, which contains a pointer to C.
//! * **Orphaned data** — data items that have no incoming references at all.
//! * **Hot data** — data items referenced by many distinct functions.

use std::collections::{HashMap, HashSet, VecDeque};

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Reference type
// ─────────────────────────────────────────────────────────────────────────────

/// The nature of a reference from an instruction to a data address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DataRefKind {
    /// The instruction reads from the data address.
    Read,
    /// The instruction writes to the data address.
    Write,
    /// The instruction loads the *address* of the data (LEA, MOV imm64, etc.).
    AddressOf,
    /// The data section itself contains a pointer to this address.
    DataPointer,
}

impl DataRefKind {
    /// Return a short display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "R",
            Self::Write => "W",
            Self::AddressOf => "&",
            Self::DataPointer => "PTR",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataRef
// ─────────────────────────────────────────────────────────────────────────────

/// One reference from a function to a data address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataRef {
    /// Address of the referencing instruction.
    pub insn_addr: Address,
    /// Address of the function that contains the instruction.
    pub function_addr: Address,
    /// Address of the data item being referenced.
    pub data_addr: Address,
    /// How the data is referenced.
    pub kind: DataRefKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// DataItem
// ─────────────────────────────────────────────────────────────────────────────

/// A single data item in the binary.
#[derive(Debug, Clone)]
pub struct DataItem {
    /// Virtual start address of this item.
    pub addr: Address,
    /// Byte size, if known.
    pub size: Option<usize>,
    /// Optional human-readable name (from symbols or heuristics).
    pub name: Option<String>,
    /// Optional type hint (e.g., "pointer", "string", "int32").
    pub type_hint: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DataXrefDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// The central data-xref database.
///
/// Stores all references to data items, keyed by data address.  Provides
/// efficient queries for incoming references, outgoing references, orphaned
/// items, and hot items.
#[derive(Debug, Default)]
pub struct DataXrefDatabase {
    /// All data items registered in the binary.
    pub items: HashMap<u64, DataItem>,
    /// Incoming references: data address → list of references that point to it.
    pub incoming: HashMap<u64, Vec<DataRef>>,
    /// Outgoing references: function address → list of data refs made by that
    /// function.
    pub outgoing: HashMap<u64, Vec<DataRef>>,
}

impl DataXrefDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a known data item.
    pub fn register_item(&mut self, item: DataItem) {
        self.items.insert(item.addr.as_u64(), item);
    }

    /// Record a reference.
    pub fn add_ref(&mut self, r: DataRef) {
        self.incoming
            .entry(r.data_addr.as_u64())
            .or_default()
            .push(r.clone());
        self.outgoing
            .entry(r.function_addr.as_u64())
            .or_default()
            .push(r);
    }

    /// Return all references that point to `data_addr`.
    #[must_use]
    pub fn refs_to(&self, data_addr: Address) -> &[DataRef] {
        self.incoming
            .get(&data_addr.as_u64())
            .map_or(&[], Vec::as_slice)
    }

    /// Return all data references made by `function_addr`.
    #[must_use]
    pub fn refs_from_function(&self, function_addr: Address) -> &[DataRef] {
        self.outgoing
            .get(&function_addr.as_u64())
            .map_or(&[], Vec::as_slice)
    }

    /// Return all data items that have zero incoming references (orphaned),
    /// sorted by address for deterministic output (`self.items` is a
    /// `HashMap`; its iteration order is not stable across runs).
    #[must_use]
    pub fn orphaned_items(&self) -> Vec<&DataItem> {
        let mut v: Vec<&DataItem> = self
            .items
            .values()
            .filter(|item| !self.incoming.contains_key(&item.addr.as_u64()))
            .collect();
        v.sort_by_key(|item| item.addr.as_u64());
        v
    }

    /// Return data items ordered by the number of distinct functions that
    /// reference them, descending (hottest first).
    #[must_use]
    pub fn hot_items(&self, top_n: usize) -> Vec<HotDataItem> {
        let mut hotness: Vec<HotDataItem> = self
            .items
            .keys()
            .map(|&addr| {
                let refs = self.incoming.get(&addr).map_or(&[] as &[DataRef], Vec::as_slice);
                let distinct_fns: HashSet<u64> =
                    refs.iter().map(|r| r.function_addr.as_u64()).collect();
                HotDataItem {
                    addr: Address::new(addr),
                    name: self.items[&addr].name.clone(),
                    ref_count: refs.len(),
                    distinct_function_count: distinct_fns.len(),
                }
            })
            .collect();

        // Tie-break on address: `self.items.keys()` above is a `HashMap`
        // iteration, so without a secondary key, items with equal
        // `distinct_function_count` would sort in nondeterministic order
        // across runs/processes.
        hotness.sort_by(|a, b| {
            b.distinct_function_count
                .cmp(&a.distinct_function_count)
                .then_with(|| a.addr.as_u64().cmp(&b.addr.as_u64()))
        });
        hotness.truncate(top_n);
        hotness
    }

    /// Return the total number of registered data items.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Return the total number of recorded references.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        self.incoming.values().map(Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HotDataItem
// ─────────────────────────────────────────────────────────────────────────────

/// A data item ranked by hotness.
#[derive(Debug, Clone)]
pub struct HotDataItem {
    /// Address of the data item.
    pub addr: Address,
    /// Optional name.
    pub name: Option<String>,
    /// Total number of references (across all functions).
    pub ref_count: usize,
    /// Number of distinct functions that reference this item.
    pub distinct_function_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Reference chain analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved reference chain: a sequence of data addresses A₀ → A₁ → … → Aₙ
/// where each Aᵢ contains a pointer to A_{i+1}.
#[derive(Debug, Clone)]
pub struct RefChain {
    /// Addresses in the chain, from root to leaf.
    pub chain: Vec<Address>,
}

impl RefChain {
    /// Length of the chain (number of nodes, not edges).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.chain.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}

/// Build all pointer-chains reachable from `root` using the data pointer
/// references in `db`.
///
/// Only `DataRefKind::DataPointer` edges are followed.  Cycles are detected
/// and do not cause infinite loops.
///
/// # Panics
/// Panics if an internal work-queue entry has an empty path (should never happen).
#[must_use]
pub fn build_ref_chains(db: &DataXrefDatabase, root: Address, max_depth: usize) -> Vec<RefChain> {
    let mut results = Vec::new();
    let mut work: VecDeque<(Vec<Address>, HashSet<u64>)> = VecDeque::new();
    let initial_visited: HashSet<u64> = std::iter::once(root.as_u64()).collect();
    work.push_back((vec![root], initial_visited));

    while let Some((path, visited)) = work.pop_front() {
        let current = *path.last().unwrap();
        let outgoing: Vec<Address> = db
            .incoming
            .get(&current.as_u64())
            .into_iter()
            .flatten()
            .filter(|r| r.kind == DataRefKind::DataPointer)
            .map(|r| r.insn_addr) // reuse insn_addr as the pointer target in chains
            .collect();

        if outgoing.is_empty() || path.len() >= max_depth {
            results.push(RefChain { chain: path });
            continue;
        }

        for next in outgoing {
            if visited.contains(&next.as_u64()) {
                // Cycle — terminate this path.
                results.push(RefChain { chain: path.clone() });
                continue;
            }
            let mut new_path = path.clone();
            new_path.push(next);
            let mut new_visited = visited.clone();
            new_visited.insert(next.as_u64());
            work.push_back((new_path, new_visited));
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// x86-64 data-reference scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a code memory slice for x86-64 instructions that reference data.
///
/// Recognised patterns:
/// * `MOV reg, [RIP+rel32]` (`48 8B xx xx xx xx xx`) — read
/// * `MOV [RIP+rel32], reg` (`48 89 xx xx xx xx xx`) — write
/// * `LEA reg, [RIP+rel32]` (`48 8D xx xx xx xx`) — address-of
///
/// The data address is computed as `RIP + rel32` (RIP = next instruction addr).
#[must_use]
pub fn scan_data_refs_x86_64(
    code: &[u8],
    code_base: u64,
    function_addr: Address,
    data_range_start: u64,
    data_range_end: u64,
) -> Vec<DataRef> {
    let mut results = Vec::new();
    let len = code.len();
    let mut i = 0usize;

    while i + 7 <= len {
        // REX.W prefix (48)
        if code[i] != 0x48 {
            i += 1;
            continue;
        }

        let opcode = code[i + 1];
        let modrm = code[i + 2];
        let mode = (modrm >> 6) & 0x3;
        let rm = modrm & 0x7;

        // RIP-relative mode: ModRM.mod=00, ModRM.rm=101
        if mode != 0 || rm != 5 {
            i += 1;
            continue;
        }

        let (kind, insn_len) = match opcode {
            0x8B => (DataRefKind::Read, 7usize),   // MOV reg, [RIP+disp32]
            0x89 => (DataRefKind::Write, 7usize),  // MOV [RIP+disp32], reg
            0x8D => (DataRefKind::AddressOf, 7usize), // LEA reg, [RIP+disp32]
            _ => {
                i += 1;
                continue;
            }
        };

        if i + insn_len > len {
            i += 1;
            continue;
        }

        let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
        let next_pc = code_base.wrapping_add(i as u64).wrapping_add(insn_len as u64);
        let data_addr = u64::from_ne_bytes(
            (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                .to_ne_bytes(),
        );

        if data_addr >= data_range_start && data_addr < data_range_end {
            results.push(DataRef {
                insn_addr: Address::new(code_base.wrapping_add(i as u64)),
                function_addr,
                data_addr: Address::new(data_addr),
                kind,
            });
        }

        i += insn_len;
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Reference-kind summary
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated access-pattern summary for one data item.
#[derive(Debug, Clone, Default)]
pub struct DataAccessSummary {
    /// Number of read references.
    pub reads: usize,
    /// Number of write references.
    pub writes: usize,
    /// Number of address-of references.
    pub address_of: usize,
    /// Number of data-pointer references.
    pub data_pointers: usize,
    /// Distinct functions that access this item.
    pub accessor_functions: HashSet<u64>,
}

impl DataAccessSummary {
    /// Whether the item is write-only (no reads or address-of references).
    #[must_use]
    pub const fn is_write_only(&self) -> bool {
        self.reads == 0 && self.address_of == 0
    }

    /// Whether the item is read-only (no write references).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.writes == 0
    }

    /// Total number of references.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.reads + self.writes + self.address_of + self.data_pointers
    }
}

/// Compute an access summary for a data item given its incoming references.
#[must_use]
pub fn summarize_access(refs: &[DataRef]) -> DataAccessSummary {
    let mut summary = DataAccessSummary::default();
    for r in refs {
        match r.kind {
            DataRefKind::Read => summary.reads += 1,
            DataRefKind::Write => summary.writes += 1,
            DataRefKind::AddressOf => summary.address_of += 1,
            DataRefKind::DataPointer => summary.data_pointers += 1,
        }
        summary.accessor_functions.insert(r.function_addr.as_u64());
    }
    summary
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn database_add_and_query_refs() {
        let mut db = DataXrefDatabase::new();
        db.register_item(DataItem {
            addr: addr(0xD000),
            size: Some(4),
            name: Some("g_count".into()),
            type_hint: Some("int32".into()),
        });
        db.add_ref(DataRef {
            insn_addr: addr(0x1005),
            function_addr: addr(0x1000),
            data_addr: addr(0xD000),
            kind: DataRefKind::Read,
        });
        db.add_ref(DataRef {
            insn_addr: addr(0x1020),
            function_addr: addr(0x1000),
            data_addr: addr(0xD000),
            kind: DataRefKind::Write,
        });

        let refs = db.refs_to(addr(0xD000));
        assert_eq!(refs.len(), 2);
        let from_fn = db.refs_from_function(addr(0x1000));
        assert_eq!(from_fn.len(), 2);
    }

    // Regression: orphaned_items/hot_items must be deterministic across
    // repeated calls, including when several items tie on hotness
    // (previously depended on HashMap iteration order).
    #[test]
    fn orphaned_and_hot_items_are_deterministic() {
        let mut db = DataXrefDatabase::new();
        let addrs = [0xE000u64, 0xD000, 0xF000, 0xC000, 0xB000];
        for &a in &addrs {
            db.register_item(DataItem {
                addr: addr(a),
                size: None,
                name: None,
                type_hint: None,
            });
        }
        // 0xD000 and 0xC000 tie at 1 distinct referencing function each;
        // 0xE000, 0xF000, 0xB000 stay orphaned.
        db.add_ref(DataRef {
            insn_addr: addr(0x100),
            function_addr: addr(0x100),
            data_addr: addr(0xD000),
            kind: DataRefKind::Read,
        });
        db.add_ref(DataRef {
            insn_addr: addr(0x200),
            function_addr: addr(0x200),
            data_addr: addr(0xC000),
            kind: DataRefKind::Read,
        });

        let orphaned1: Vec<u64> = db.orphaned_items().iter().map(|i| i.addr.as_u64()).collect();
        let hot1: Vec<u64> = db.hot_items(10).iter().map(|h| h.addr.as_u64()).collect();
        for _ in 0..5 {
            let o: Vec<u64> = db.orphaned_items().iter().map(|i| i.addr.as_u64()).collect();
            let h: Vec<u64> = db.hot_items(10).iter().map(|h| h.addr.as_u64()).collect();
            assert_eq!(o, orphaned1);
            assert_eq!(h, hot1);
        }
        let mut sorted_orphaned = orphaned1.clone();
        sorted_orphaned.sort_unstable();
        assert_eq!(orphaned1, sorted_orphaned);
    }

    #[test]
    fn orphaned_items_detection() {
        let mut db = DataXrefDatabase::new();
        db.register_item(DataItem {
            addr: addr(0xE000),
            size: None,
            name: None,
            type_hint: None,
        });
        db.register_item(DataItem {
            addr: addr(0xF000),
            size: None,
            name: None,
            type_hint: None,
        });
        db.add_ref(DataRef {
            insn_addr: addr(0x100),
            function_addr: addr(0x100),
            data_addr: addr(0xE000),
            kind: DataRefKind::Read,
        });
        let orphaned = db.orphaned_items();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].addr, addr(0xF000));
    }

    #[test]
    fn hot_items_sorted_by_distinct_fns() {
        let mut db = DataXrefDatabase::new();
        db.register_item(DataItem { addr: addr(0x1), size: None, name: None, type_hint: None });
        db.register_item(DataItem { addr: addr(0x2), size: None, name: None, type_hint: None });

        // addr(0x1) referenced by 3 functions
        for fn_addr in [0x100, 0x200, 0x300] {
            db.add_ref(DataRef {
                insn_addr: addr(fn_addr),
                function_addr: addr(fn_addr),
                data_addr: addr(0x1),
                kind: DataRefKind::Read,
            });
        }
        // addr(0x2) referenced by 1 function
        db.add_ref(DataRef {
            insn_addr: addr(0x400),
            function_addr: addr(0x400),
            data_addr: addr(0x2),
            kind: DataRefKind::Read,
        });

        let hot = db.hot_items(2);
        assert_eq!(hot[0].addr, addr(0x1));
        assert_eq!(hot[0].distinct_function_count, 3);
    }

    #[test]
    fn scan_data_refs_finds_mov_rip_rel() {
        // 48 8B 05 01 00 00 00 — MOV rax, [RIP+1]
        // next_pc = base + 7, data_addr = base + 7 + 1 = base + 8
        let code: &[u8] = &[0x48, 0x8B, 0x05, 0x01, 0x00, 0x00, 0x00];
        let base = 0x1000u64;
        let data_addr_expected = base + 7 + 1;
        let refs = scan_data_refs_x86_64(code, base, addr(0x500), 0, u64::MAX);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, DataRefKind::Read);
        assert_eq!(refs[0].data_addr, addr(data_addr_expected));
    }

    #[test]
    fn scan_data_refs_finds_lea_rip_rel() {
        // 48 8D 05 05 00 00 00 — LEA rax, [RIP+5]
        let code: &[u8] = &[0x48, 0x8D, 0x05, 0x05, 0x00, 0x00, 0x00];
        let base = 0x2000u64;
        let expected = base + 7 + 5;
        let refs = scan_data_refs_x86_64(code, base, addr(0x600), 0, u64::MAX);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, DataRefKind::AddressOf);
        assert_eq!(refs[0].data_addr, addr(expected));
    }

    #[test]
    fn access_summary_correctness() {
        let refs = vec![
            DataRef { insn_addr: addr(1), function_addr: addr(0xA), data_addr: addr(0xD), kind: DataRefKind::Read },
            DataRef { insn_addr: addr(2), function_addr: addr(0xA), data_addr: addr(0xD), kind: DataRefKind::Write },
            DataRef { insn_addr: addr(3), function_addr: addr(0xB), data_addr: addr(0xD), kind: DataRefKind::AddressOf },
        ];
        let summary = summarize_access(&refs);
        assert_eq!(summary.reads, 1);
        assert_eq!(summary.writes, 1);
        assert_eq!(summary.address_of, 1);
        assert_eq!(summary.accessor_functions.len(), 2);
        assert_eq!(summary.total(), 3);
        assert!(!summary.is_read_only());
        assert!(!summary.is_write_only());
    }
}
