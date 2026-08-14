//! WebAssembly table model.
//!
//! Implements the Wasm table semantics: typed element storage, grow, fill,
//! copy, element-segment application, and call_indirect type checking.

use std::collections::HashMap;

/// Maximum number of table elements that will be eagerly allocated.
///
/// A malicious module could set `limits.min` to `u32::MAX` and cause a
/// multi-gigabyte `Vec` allocation in `WasmTable::new`. This cap keeps
/// initial allocation within reason for a static-analysis tool.
const MAX_TABLE_ALLOC: usize = 1_048_576; // 1 M elements

// ---------------------------------------------------------------------------
// WasmRefType
// ---------------------------------------------------------------------------

/// The reference type stored by a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WasmRefType {
    FuncRef,
    ExternRef,
}

impl std::fmt::Display for WasmRefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FuncRef => write!(f, "funcref"),
            Self::ExternRef => write!(f, "externref"),
        }
    }
}

// ---------------------------------------------------------------------------
// TableElement
// ---------------------------------------------------------------------------

/// A single element in a Wasm table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TableElement {
    /// Null reference (typed null).
    Null,
    /// A reference to a function by its module-local function index.
    FuncRef(u32),
    /// An opaque host reference (64-bit handle).
    ExternRef(u64),
}

impl TableElement {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn ref_type(&self) -> Option<WasmRefType> {
        match self {
            Self::Null => None,
            Self::FuncRef(_) => Some(WasmRefType::FuncRef),
            Self::ExternRef(_) => Some(WasmRefType::ExternRef),
        }
    }
}

// ---------------------------------------------------------------------------
// TableLimits
// ---------------------------------------------------------------------------

/// Minimum / maximum element counts for a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TableLimits {
    pub min: u32,
    pub max: Option<u32>,
}

impl TableLimits {
    pub fn new(min: u32, max: Option<u32>) -> Self {
        Self { min, max }
    }

    pub fn effective_max(self) -> u32 {
        self.max.unwrap_or(u32::MAX)
    }
}

// ---------------------------------------------------------------------------
// TableInit — element segment descriptor
// ---------------------------------------------------------------------------

/// Describes an element segment that can be applied to a table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TableInit {
    pub table_idx: u32,
    pub element_idx: u32,
    pub data: Vec<TableElement>,
}

// ---------------------------------------------------------------------------
// TypedTable — tracks function-type associations for call_indirect checking
// ---------------------------------------------------------------------------

/// Maps function index → expected type index for `call_indirect` type checking.
#[derive(Debug, Clone, Default)]
pub struct TypedTable {
    /// `func_idx` → `type_idx`
    pub types: HashMap<u32, u32>,
}

impl TypedTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, func_idx: u32, type_idx: u32) {
        self.types.insert(func_idx, type_idx);
    }

    /// Return `true` if the function at `func_idx` was declared with `type_idx`.
    pub fn matches_type(&self, func_idx: u32, type_idx: u32) -> bool {
        self.types.get(&func_idx).copied() == Some(type_idx)
    }
}

// ---------------------------------------------------------------------------
// WasmTable
// ---------------------------------------------------------------------------

/// A WebAssembly table: a resizable, typed array of references.
#[derive(Debug, Clone)]
pub struct WasmTable {
    elements: Vec<TableElement>,
    limits: TableLimits,
    pub ref_type: WasmRefType,
    typed: TypedTable,
}

impl WasmTable {
    /// Create a new table with `limits.min` null elements.
    ///
    /// Initial allocation is capped at [`MAX_TABLE_ALLOC`] to prevent
    /// memory exhaustion from attacker-controlled `limits.min` values
    /// (dos-memory-exhaustion).
    pub fn new(limits: TableLimits, ref_type: WasmRefType) -> Self {
        let alloc = (limits.min as usize).min(MAX_TABLE_ALLOC);
        WasmTable {
            elements: vec![TableElement::Null; alloc],
            limits,
            ref_type,
            typed: TypedTable::new(),
        }
    }

    /// Create with a pre-populated `TypedTable`.
    ///
    /// Initial allocation is capped at [`MAX_TABLE_ALLOC`] (dos-memory-exhaustion).
    pub fn with_typed(limits: TableLimits, ref_type: WasmRefType, typed: TypedTable) -> Self {
        let alloc = (limits.min as usize).min(MAX_TABLE_ALLOC);
        WasmTable {
            elements: vec![TableElement::Null; alloc],
            limits,
            ref_type,
            typed,
        }
    }

    /// Current number of elements.
    pub fn size(&self) -> u32 {
        self.elements.len() as u32
    }

    /// Get a reference to the element at `idx`, or `None` if out-of-bounds.
    pub fn get(&self, idx: u32) -> Option<&TableElement> {
        self.elements.get(idx as usize)
    }

    /// Set the element at `idx`. Returns `false` if out-of-bounds.
    pub fn set(&mut self, idx: u32, elem: TableElement) -> bool {
        if idx as usize >= self.elements.len() {
            return false;
        }
        self.elements[idx as usize] = elem;
        true
    }

    // -----------------------------------------------------------------------
    // grow
    // -----------------------------------------------------------------------

    /// Grow the table by `delta` elements, initialising them to `init`.
    ///
    /// Returns the old size on success, or `-1` if the grow would violate
    /// limits or overflow.
    pub fn grow(&mut self, delta: u32, init: TableElement) -> i32 {
        let old = self.size();
        let new_size = match old.checked_add(delta) {
            Some(n) => n,
            None => return -1,
        };
        if new_size > self.limits.effective_max() {
            return -1;
        }
        self.elements.resize(new_size as usize, init);
        old as i32
    }

    // -----------------------------------------------------------------------
    // fill
    // -----------------------------------------------------------------------

    /// Fill `len` elements starting at `dst` with `val`.
    ///
    /// Returns `false` if the range is out-of-bounds.
    pub fn fill(&mut self, dst: u32, val: TableElement, len: u32) -> bool {
        let end = match dst.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        if end as usize > self.elements.len() {
            return false;
        }
        for i in dst..end {
            self.elements[i as usize] = val.clone();
        }
        true
    }

    // -----------------------------------------------------------------------
    // copy
    // -----------------------------------------------------------------------

    /// Copy `len` elements from `src_table[src..]` into `dst_table[dst..]`.
    ///
    /// This is an associated function so that the borrow checker can handle
    /// the case where `dst_table` and `src_table` are the same table — callers
    /// must check that case separately.
    pub fn copy(
        dst_table: &mut WasmTable,
        dst: u32,
        src_table: &WasmTable,
        src: u32,
        len: u32,
    ) -> bool {
        let src_end = match src.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let dst_end = match dst.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        if src_end as usize > src_table.elements.len() {
            return false;
        }
        if dst_end as usize > dst_table.elements.len() {
            return false;
        }
        let items: Vec<TableElement> =
            src_table.elements[src as usize..src_end as usize].to_vec();
        dst_table.elements[dst as usize..dst_end as usize].clone_from_slice(&items);
        true
    }

    /// Copy within the same table, handling overlaps correctly.
    pub fn copy_within(&mut self, dst: u32, src: u32, len: u32) -> bool {
        let src_end = match src.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let dst_end = match dst.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        if src_end as usize > self.elements.len() || dst_end as usize > self.elements.len() {
            return false;
        }
        let items: Vec<TableElement> =
            self.elements[src as usize..src_end as usize].to_vec();
        self.elements[dst as usize..dst_end as usize].clone_from_slice(&items);
        true
    }

    // -----------------------------------------------------------------------
    // Element segment application
    // -----------------------------------------------------------------------

    /// Apply an element segment at runtime offset `offset`.
    ///
    /// Returns `false` if the segment would overflow the table.
    pub fn apply_element_segment(&mut self, segment: &TableInit, offset: u32) -> bool {
        let len = segment.data.len() as u32;
        let end = match offset.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        if end as usize > self.elements.len() {
            return false;
        }
        for (i, elem) in segment.data.iter().enumerate() {
            self.elements[offset as usize + i] = elem.clone();
        }
        true
    }

    // -----------------------------------------------------------------------
    // call_indirect
    // -----------------------------------------------------------------------

    /// Validate and return the function index for a `call_indirect` instruction.
    ///
    /// * `idx`      — table index of the target.
    /// * `type_idx` — type index from the instruction's immediate.
    ///
    /// Returns `Some(func_idx)` if:
    ///   - `idx` is in bounds.
    ///   - The element is `FuncRef(func_idx)` (not null or externref).
    ///   - The type matches according to the `TypedTable`.
    ///
    /// Returns `None` (trap) otherwise.
    pub fn call_indirect(&self, idx: u32, type_idx: u32) -> Option<u32> {
        let elem = self.elements.get(idx as usize)?;
        match elem {
            TableElement::FuncRef(func_idx) => {
                if self.typed.matches_type(*func_idx, type_idx) {
                    Some(*func_idx)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Accessor helpers
    // -----------------------------------------------------------------------

    /// Register a function's type for call_indirect checking.
    pub fn register_func_type(&mut self, func_idx: u32, type_idx: u32) {
        self.typed.register(func_idx, type_idx);
    }

    /// Iterate over all non-null elements.
    pub fn non_null_elements(&self) -> impl Iterator<Item = (u32, &TableElement)> {
        self.elements
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_null())
            .map(|(i, e)| (i as u32, e))
    }

    /// Count of non-null elements.
    pub fn non_null_count(&self) -> usize {
        self.elements.iter().filter(|e| !e.is_null()).count()
    }

    /// Returns whether `idx` is in-bounds.
    pub fn is_in_bounds(&self, idx: u32) -> bool {
        (idx as usize) < self.elements.len()
    }

    pub fn limits(&self) -> TableLimits {
        self.limits
    }
}

// ---------------------------------------------------------------------------
// MultiTable — manage multiple indexed tables
// ---------------------------------------------------------------------------

/// Collection of tables keyed by table index (multi-table support).
#[derive(Debug, Default)]
pub struct MultiTable {
    tables: HashMap<u32, WasmTable>,
    next_id: u32,
}

impl MultiTable {
    pub fn add(&mut self, limits: TableLimits, ref_type: WasmRefType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.tables.insert(id, WasmTable::new(limits, ref_type));
        id
    }

    pub fn get(&self, idx: u32) -> Option<&WasmTable> {
        self.tables.get(&idx)
    }

    pub fn get_mut(&mut self, idx: u32) -> Option<&mut WasmTable> {
        self.tables.get_mut(&idx)
    }

    pub fn count(&self) -> usize {
        self.tables.len()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn func_table(min: u32, max: u32) -> WasmTable {
        WasmTable::new(TableLimits::new(min, Some(max)), WasmRefType::FuncRef)
    }

    #[test]
    fn initial_size_is_min() {
        let t = func_table(4, 8);
        assert_eq!(t.size(), 4);
    }

    #[test]
    fn all_elements_null_initially() {
        let t = func_table(4, 8);
        for i in 0..4 {
            assert_eq!(t.get(i), Some(&TableElement::Null));
        }
    }

    #[test]
    fn set_and_get() {
        let mut t = func_table(4, 8);
        assert!(t.set(2, TableElement::FuncRef(99)));
        assert_eq!(t.get(2), Some(&TableElement::FuncRef(99)));
    }

    #[test]
    fn set_out_of_bounds() {
        let mut t = func_table(2, 4);
        assert!(!t.set(5, TableElement::FuncRef(0)));
    }

    #[test]
    fn grow_success() {
        let mut t = func_table(2, 8);
        let old = t.grow(3, TableElement::Null);
        assert_eq!(old, 2);
        assert_eq!(t.size(), 5);
    }

    #[test]
    fn grow_exceeds_max() {
        let mut t = func_table(2, 4);
        let res = t.grow(10, TableElement::Null);
        assert_eq!(res, -1);
        assert_eq!(t.size(), 2);
    }

    #[test]
    fn fill_range() {
        let mut t = func_table(8, 16);
        assert!(t.fill(2, TableElement::FuncRef(7), 3));
        for i in 2..5 {
            assert_eq!(t.get(i), Some(&TableElement::FuncRef(7)));
        }
        assert_eq!(t.get(1), Some(&TableElement::Null));
        assert_eq!(t.get(5), Some(&TableElement::Null));
    }

    #[test]
    fn fill_out_of_bounds() {
        let mut t = func_table(4, 8);
        assert!(!t.fill(3, TableElement::FuncRef(0), 5));
    }

    #[test]
    fn copy_between_tables() {
        let mut src = func_table(4, 8);
        src.set(0, TableElement::FuncRef(10));
        src.set(1, TableElement::FuncRef(20));
        let mut dst = func_table(4, 8);
        assert!(WasmTable::copy(&mut dst, 2, &src, 0, 2));
        assert_eq!(dst.get(2), Some(&TableElement::FuncRef(10)));
        assert_eq!(dst.get(3), Some(&TableElement::FuncRef(20)));
    }

    #[test]
    fn copy_within_table() {
        let mut t = func_table(8, 16);
        t.set(0, TableElement::FuncRef(1));
        t.set(1, TableElement::FuncRef(2));
        assert!(t.copy_within(4, 0, 2));
        assert_eq!(t.get(4), Some(&TableElement::FuncRef(1)));
        assert_eq!(t.get(5), Some(&TableElement::FuncRef(2)));
    }

    #[test]
    fn apply_element_segment() {
        let mut t = func_table(8, 16);
        let seg = TableInit {
            table_idx: 0,
            element_idx: 0,
            data: vec![TableElement::FuncRef(5), TableElement::FuncRef(6)],
        };
        assert!(t.apply_element_segment(&seg, 3));
        assert_eq!(t.get(3), Some(&TableElement::FuncRef(5)));
        assert_eq!(t.get(4), Some(&TableElement::FuncRef(6)));
    }

    #[test]
    fn apply_element_segment_overflow() {
        let mut t = func_table(4, 8);
        let seg = TableInit {
            table_idx: 0,
            element_idx: 0,
            data: vec![TableElement::FuncRef(1); 5],
        };
        assert!(!t.apply_element_segment(&seg, 2));
    }

    #[test]
    fn call_indirect_success() {
        let mut t = func_table(4, 8);
        t.set(1, TableElement::FuncRef(42));
        t.register_func_type(42, 3);
        let result = t.call_indirect(1, 3);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn call_indirect_type_mismatch() {
        let mut t = func_table(4, 8);
        t.set(0, TableElement::FuncRef(10));
        t.register_func_type(10, 1);
        assert_eq!(t.call_indirect(0, 2), None);
    }

    #[test]
    fn call_indirect_null_traps() {
        let t = func_table(4, 8);
        assert_eq!(t.call_indirect(0, 0), None);
    }

    #[test]
    fn non_null_elements_iter() {
        let mut t = func_table(4, 8);
        t.set(1, TableElement::FuncRef(7));
        t.set(3, TableElement::ExternRef(999));
        let nn: Vec<_> = t.non_null_elements().collect();
        assert_eq!(nn.len(), 2);
    }

    #[test]
    fn multi_table_basic() {
        let mut mt = MultiTable::default();
        let id0 = mt.add(TableLimits::new(2, Some(4)), WasmRefType::FuncRef);
        let id1 = mt.add(TableLimits::new(3, Some(6)), WasmRefType::ExternRef);
        assert_ne!(id0, id1);
        assert_eq!(mt.count(), 2);
        mt.get_mut(id0).unwrap().set(0, TableElement::FuncRef(5));
        assert_eq!(mt.get(id0).unwrap().get(0), Some(&TableElement::FuncRef(5)));
    }
}
