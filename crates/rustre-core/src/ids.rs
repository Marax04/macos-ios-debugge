//! Typed ID newtypes for every major RE entity, plus generic ID infrastructure.
//!
//! Every entity in the RustRE platform — views, functions, basic blocks,
//! instructions, types, symbols, segments, sections, data variables, and tags —
//! is identified by a distinct typed ID.  Using separate types prevents
//! accidentally mixing up, for example, a `FunctionId` and a `BasicBlockId`.
//!
//! # Design
//! - Each ID is a thin `u64` newtype with `#[repr(transparent)]`.
//! - The sentinel value `0` is *invalid*; valid IDs start at `1`.
//! - [`IdAllocator<T>`] hands out monotonically increasing IDs using an
//!   atomic counter so it is safe to share across threads.
//! - [`IdPool<T>`] wraps an allocator and maintains a free-list for reclaim.
//! - [`IdMap<K, V>`] is a typed `HashMap` wrapper that only accepts the
//!   matching key type.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Macro to generate boilerplate ID types
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! define_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[repr(transparent)]
        pub struct $name(u64);

        impl $name {
            /// The invalid / null sentinel.
            pub const INVALID: Self = Self(0);

            /// Wrap a raw `u64`.  Prefer [`new`](Self::new) for allocator-generated IDs.
            #[must_use]
            pub const fn from_raw(raw: u64) -> Self {
                Self(raw)
            }

            /// Create an ID from a raw value.  Returns `None` for zero.
            #[must_use]
            pub const fn new(raw: u64) -> Option<Self> {
                if raw == 0 {
                    None
                } else {
                    Some(Self(raw))
                }
            }

            /// Return the underlying `u64`.
            #[must_use]
            pub const fn into_raw(self) -> u64 {
                self.0
            }

            /// Alias for `into_raw`.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Return `true` if this ID is not the zero sentinel.
            #[must_use]
            pub const fn is_valid(self) -> bool {
                self.0 != 0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl From<u64> for $name {
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl From<$name> for u64 {
            fn from(id: $name) -> u64 {
                id.0
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete ID types
// ─────────────────────────────────────────────────────────────────────────────

define_id!(
    /// Uniquely identifies an open binary view.
    ViewId
);

define_id!(
    /// Uniquely identifies a function within a view.
    FunctionId
);

define_id!(
    /// Uniquely identifies a basic block within a function.
    BasicBlockId
);

define_id!(
    /// Uniquely identifies a decoded instruction.
    InstructionId
);

define_id!(
    /// Uniquely identifies a type definition.
    TypeId
);

define_id!(
    /// Uniquely identifies a symbol.
    SymbolId
);

define_id!(
    /// Uniquely identifies a memory segment.
    SegmentId
);

define_id!(
    /// Uniquely identifies a section (e.g. ELF `.text`, PE `.rdata`).
    SectionId
);

define_id!(
    /// Uniquely identifies a data variable (typed data at a known address).
    DataVarId
);

define_id!(
    /// Uniquely identifies an analyst-applied tag.
    TagId
);

// ─────────────────────────────────────────────────────────────────────────────
// IdAllocator<T>
// ─────────────────────────────────────────────────────────────────────────────

/// Marker trait for types that can be used as ID keys.
///
/// Implemented automatically for all types that satisfy the bounds.
pub trait IdType:
    Copy + Eq + Hash + fmt::Debug + From<u64> + Into<u64> + Send + Sync + 'static
{
}

impl<T> IdType for T where
    T: Copy + Eq + Hash + fmt::Debug + From<u64> + Into<u64> + Send + Sync + 'static
{
}

/// A thread-safe monotonic ID allocator.
///
/// Hands out IDs starting from `1`.  The counter is backed by an [`AtomicU64`]
/// so multiple threads may call [`next`](IdAllocator::next) concurrently without
/// any synchronisation overhead beyond a single atomic fetch-add.
///
/// # Panics
/// Panics if the internal counter wraps around to `0` (requires allocating
/// `u64::MAX` IDs, which is not reachable in practice).
#[derive(Debug)]
pub struct IdAllocator<T: IdType> {
    counter: Arc<AtomicU64>,
    _marker: PhantomData<fn() -> T>,
}

impl<T: IdType> Default for IdAllocator<T> {
    fn default() -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(1)),
            _marker: PhantomData,
        }
    }
}

impl<T: IdType> IdAllocator<T> {
    /// Create a new allocator starting at `1`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an allocator whose first ID will be `start`.
    ///
    /// # Panics
    /// Panics if `start` is `0`.
    #[must_use]
    pub fn with_start(start: u64) -> Self {
        assert!(start != 0, "IdAllocator start must be non-zero");
        Self {
            counter: Arc::new(AtomicU64::new(start)),
            _marker: PhantomData,
        }
    }

    /// Allocate the next ID.
    ///
    /// # Panics
    /// Panics on u64 overflow (counter reaches `0` after wrapping).
    #[must_use]
    pub fn next(&self) -> T {
        let raw = self.counter.fetch_add(1, Ordering::Relaxed);
        assert!(raw != u64::MAX, "IdAllocator would overflow: u64::MAX ID was just handed out");
        T::from(raw)
    }

    /// Peek at the next value that *would* be returned without advancing.
    #[must_use]
    pub fn peek(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Number of IDs that have been handed out so far.
    #[must_use]
    pub fn allocated_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// Create a *sibling* allocator that shares the same counter.
    ///
    /// Useful when the same logical ID space is managed from multiple
    /// subsystems (e.g. an analysis pass and the loader both adding functions).
    #[must_use]
    pub fn clone_shared(&self) -> Self {
        Self {
            counter: Arc::clone(&self.counter),
            _marker: PhantomData,
        }
    }
}

impl<T: IdType> Clone for IdAllocator<T> {
    fn clone(&self) -> Self {
        self.clone_shared()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IdPool<T>
// ─────────────────────────────────────────────────────────────────────────────

/// An allocator with a reclaim free-list.
///
/// When an entity is deleted its ID can be returned with
/// [`reclaim`](IdPool::reclaim); the next call to [`alloc`](IdPool::alloc)
/// will reuse a reclaimed ID before minting a new one.
#[derive(Debug)]
pub struct IdPool<T: IdType> {
    allocator: IdAllocator<T>,
    free: Vec<T>,
}

impl<T: IdType> Default for IdPool<T> {
    fn default() -> Self {
        Self {
            allocator: IdAllocator::new(),
            free: Vec::new(),
        }
    }
}

impl<T: IdType> IdPool<T> {
    /// Create a new pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next available ID, preferring reclaimed IDs.
    #[must_use]
    pub fn alloc(&mut self) -> T {
        if let Some(id) = self.free.pop() {
            id
        } else {
            self.allocator.next()
        }
    }

    /// Return an ID to the free list so it can be reused.
    pub fn reclaim(&mut self, id: T) {
        self.free.push(id);
    }

    /// Number of IDs currently in the free list.
    #[must_use]
    pub const fn free_count(&self) -> usize {
        self.free.len()
    }

    /// Total number of IDs ever allocated (including reclaimed ones).
    #[must_use]
    pub fn allocated_count(&self) -> u64 {
        self.allocator.allocated_count()
    }

    /// `true` if the free list is empty.
    #[must_use]
    pub const fn is_free_list_empty(&self) -> bool {
        self.free.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IdMap<K, V>
// ─────────────────────────────────────────────────────────────────────────────

/// A `HashMap<K, V>` wrapper that only accepts typed ID keys.
///
/// This prevents accidentally using an `i64` index where a [`FunctionId`] is
/// expected, and surfaces the `u64` representation only inside the map.
#[derive(Debug, Clone)]
pub struct IdMap<K: IdType, V> {
    inner: HashMap<u64, V>,
    _marker: PhantomData<fn(K) -> V>,
}

impl<K: IdType, V> Default for IdMap<K, V> {
    fn default() -> Self {
        Self {
            inner: HashMap::new(),
            _marker: PhantomData,
        }
    }
}

impl<K: IdType, V> IdMap<K, V> {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `value` under `key`, returning the previous value if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key.into(), value)
    }

    /// Return a reference to the value stored under `key`.
    #[must_use]
    pub fn get(&self, key: K) -> Option<&V> {
        self.inner.get(&key.into())
    }

    /// Return a mutable reference to the value stored under `key`.
    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.inner.get_mut(&key.into())
    }

    /// Remove the entry for `key`, returning the value if it existed.
    pub fn remove(&mut self, key: K) -> Option<V> {
        self.inner.remove(&key.into())
    }

    /// Return `true` if `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: K) -> bool {
        self.inner.contains_key(&key.into())
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over `(key, value)` pairs, reconstructing typed keys.
    pub fn iter(&self) -> impl Iterator<Item = (K, &V)> {
        self.inner.iter().map(|(k, v)| (K::from(*k), v))
    }

    /// Iterate over values.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.inner.values()
    }

    /// Iterate over values mutably.
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.inner.values_mut()
    }

    /// Iterate over keys (typed).
    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        self.inner.keys().map(|k| K::from(*k))
    }

    /// Return an entry for in-place mutation.
    pub fn entry(&mut self, key: K) -> std::collections::hash_map::Entry<'_, u64, V> {
        self.inner.entry(key.into())
    }

    /// Retain only the entries for which `f` returns `true`.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(K, &mut V) -> bool,
    {
        self.inner.retain(|k, v| f(K::from(*k), v));
    }

    /// Drain all entries from the map.
    pub fn drain(&mut self) -> impl Iterator<Item = (K, V)> + '_ {
        self.inner.drain().map(|(k, v)| (K::from(k), v))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Merge all entries from `other` into `self`.
    /// Entries in `other` overwrite existing entries in `self`.
    pub fn merge_from(&mut self, other: &Self)
    where
        V: Clone,
    {
        for (k, v) in &other.inner {
            self.inner.insert(*k, v.clone());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ViewId ─────────────────────────────────────────────────────────────────

    #[test]
    fn view_id_valid_invalid() {
        assert!(!ViewId::INVALID.is_valid());
        assert!(ViewId::from_raw(1).is_valid());
        assert!(ViewId::new(0).is_none());
        assert!(ViewId::new(1).is_some());
    }

    #[test]
    fn view_id_round_trip() {
        let id = ViewId::from_raw(42);
        assert_eq!(id.into_raw(), 42);
        assert_eq!(id.get(), 42);
    }

    #[test]
    fn view_id_ord() {
        let a = ViewId::from_raw(1);
        let b = ViewId::from_raw(2);
        assert!(a < b);
    }

    #[test]
    fn view_id_display() {
        let id = ViewId::from_raw(7);
        assert_eq!(id.to_string(), "ViewId(7)");
    }

    #[test]
    fn view_id_from_into_u64() {
        let id = ViewId::from(99u64);
        let raw: u64 = id.into();
        assert_eq!(raw, 99);
    }

    // ── FunctionId ─────────────────────────────────────────────────────────────

    #[test]
    fn function_id_distinct_from_view_id() {
        // Type-level distinction: the compiler would reject mixing them.
        let fid = FunctionId::from_raw(1);
        let vid = ViewId::from_raw(1);
        assert_eq!(fid.get(), vid.get()); // same raw value
        // But they are different types and cannot be compared to each other.
        let _ = (fid, vid);
    }

    // ── All ID types: basic smoke ──────────────────────────────────────────────

    macro_rules! id_smoke {
        ($test:ident, $T:ty) => {
            #[test]
            fn $test() {
                let id = <$T>::from_raw(100);
                assert!(id.is_valid());
                assert_eq!(id.get(), 100);
                assert!(!<$T>::INVALID.is_valid());
                // Display does not panic.
                let _ = id.to_string();
            }
        };
    }

    id_smoke!(basic_block_id_smoke, BasicBlockId);
    id_smoke!(instruction_id_smoke, InstructionId);
    id_smoke!(type_id_smoke, TypeId);
    id_smoke!(symbol_id_smoke, SymbolId);
    id_smoke!(segment_id_smoke, SegmentId);
    id_smoke!(section_id_smoke, SectionId);
    id_smoke!(data_var_id_smoke, DataVarId);
    id_smoke!(tag_id_smoke, TagId);

    // ── IdAllocator ────────────────────────────────────────────────────────────

    #[test]
    fn allocator_starts_at_one() {
        let alloc = IdAllocator::<ViewId>::new();
        let id = alloc.next();
        assert_eq!(id.get(), 1);
    }

    #[test]
    fn allocator_monotonic() {
        let alloc = IdAllocator::<FunctionId>::new();
        let ids: Vec<_> = (0..10).map(|_| alloc.next()).collect();
        for w in ids.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn allocator_with_start() {
        let alloc = IdAllocator::<SegmentId>::with_start(100);
        assert_eq!(alloc.next().get(), 100);
        assert_eq!(alloc.next().get(), 101);
    }

    #[test]
    fn allocator_allocated_count() {
        let alloc = IdAllocator::<TypeId>::new();
        assert_eq!(alloc.allocated_count(), 0);
        let _ = alloc.next();
        let _ = alloc.next();
        assert_eq!(alloc.allocated_count(), 2);
    }

    #[test]
    fn allocator_peek() {
        let alloc = IdAllocator::<TagId>::new();
        let peeked = alloc.peek();
        let next = alloc.next().get();
        assert_eq!(peeked, next);
    }

    #[test]
    fn allocator_shared_clone() {
        let a = IdAllocator::<SymbolId>::new();
        let b = a.clone_shared();
        let id_a = a.next().get();
        let id_b = b.next().get();
        assert_eq!(id_a, 1);
        assert_eq!(id_b, 2);
    }

    #[test]
    fn allocator_clone_is_shared() {
        let a = IdAllocator::<DataVarId>::new();
        let b = a.clone();
        let _ = a.next();
        // b shares the counter, so its next should be 2.
        assert_eq!(b.next().get(), 2);
    }

    // ── IdPool ─────────────────────────────────────────────────────────────────

    #[test]
    fn pool_alloc_sequential() {
        let mut pool = IdPool::<FunctionId>::new();
        assert_eq!(pool.alloc().get(), 1);
        assert_eq!(pool.alloc().get(), 2);
        assert_eq!(pool.alloc().get(), 3);
    }

    #[test]
    fn pool_reclaim_reuse() {
        let mut pool = IdPool::<SectionId>::new();
        let id1 = pool.alloc();
        let id2 = pool.alloc();
        pool.reclaim(id1);
        // Next alloc must reuse id1 (last pushed to free list).
        let reused = pool.alloc();
        assert_eq!(reused, id1);
        // After reuse, free list is empty again.
        assert!(pool.is_free_list_empty());
        let _ = id2;
    }

    #[test]
    fn pool_free_count() {
        let mut pool = IdPool::<BasicBlockId>::new();
        let a = pool.alloc();
        let b = pool.alloc();
        assert_eq!(pool.free_count(), 0);
        pool.reclaim(a);
        pool.reclaim(b);
        assert_eq!(pool.free_count(), 2);
    }

    // ── IdMap ──────────────────────────────────────────────────────────────────

    #[test]
    fn idmap_insert_get_remove() {
        let mut map: IdMap<FunctionId, String> = IdMap::new();
        assert!(map.is_empty());

        let id = FunctionId::from_raw(1);
        map.insert(id, "main".into());
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(id));
        assert_eq!(map.get(id).unwrap(), "main");

        let prev = map.insert(id, "renamed".into());
        assert_eq!(prev.unwrap(), "main");

        let removed = map.remove(id);
        assert_eq!(removed.unwrap(), "renamed");
        assert!(map.is_empty());
    }

    #[test]
    fn idmap_iter_keys_values() {
        let mut map: IdMap<SymbolId, u32> = IdMap::new();
        for i in 1u64..=5 {
            map.insert(
                SymbolId::from_raw(i),
                u32::try_from(i).unwrap_or(u32::MAX) * 10,
            );
        }
        assert_eq!(map.len(), 5);
        assert_eq!(map.values().copied().sum::<u32>(), 150);
        assert_eq!(map.keys().count(), 5);
    }

    #[test]
    fn idmap_retain() {
        let mut map: IdMap<TypeId, i32> = IdMap::new();
        for i in 1u64..=10 {
            map.insert(TypeId::from_raw(i), i32::try_from(i).unwrap_or(i32::MAX));
        }
        // Keep only even raw values.
        map.retain(|k, _v| k.get() % 2 == 0);
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn idmap_merge_from() {
        let mut a: IdMap<ViewId, String> = IdMap::new();
        let mut b: IdMap<ViewId, String> = IdMap::new();

        a.insert(ViewId::from_raw(1), "view_1_from_a".into());
        b.insert(ViewId::from_raw(1), "view_1_from_b".into());
        b.insert(ViewId::from_raw(2), "view_2".into());

        a.merge_from(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.get(ViewId::from_raw(1)).unwrap(), "view_1_from_b");
    }

    #[test]
    fn idmap_get_mut() {
        let mut map: IdMap<TagId, Vec<u8>> = IdMap::new();
        let id = TagId::from_raw(1);
        map.insert(id, vec![1, 2, 3]);
        map.get_mut(id).unwrap().push(4);
        assert_eq!(map.get(id).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn idmap_clear() {
        let mut map: IdMap<InstructionId, bool> = IdMap::new();
        map.insert(InstructionId::from_raw(1), true);
        map.insert(InstructionId::from_raw(2), false);
        map.clear();
        assert!(map.is_empty());
    }
}
