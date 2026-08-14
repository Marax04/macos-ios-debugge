//! `lua_constant_pool` — Lua constant pool management and analysis.
//!
//! Provides [`LuaConstantPool`] for indexing and querying the constants that
//! appear in a parsed Lua prototype tree, along with [`LuaConst`] re-exports,
//! a [`ConstKind`] classification enum, and the [`resolve_const`] helper.

use std::collections::HashMap;
use std::fmt;

// ── ConstKind ────────────────────────────────────────────────────────────────

/// High-level classification of a Lua constant's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstKind {
    /// The `nil` literal.
    Nil,
    /// A boolean (`true` or `false`).
    Boolean,
    /// A floating-point number.
    Float,
    /// An integer (Lua 5.3+).
    Integer,
    /// A short string.
    ShortString,
    /// A long string (multi-line, no escape processing).
    LongString,
}

impl ConstKind {
    /// Returns `true` if this constant kind is a string variant.
    #[must_use]
    pub const fn is_string(self) -> bool {
        matches!(self, Self::ShortString | Self::LongString)
    }

    /// Returns `true` if this constant kind is numeric.
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        matches!(self, Self::Float | Self::Integer)
    }
}

impl fmt::Display for ConstKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Boolean => write!(f, "boolean"),
            Self::Float => write!(f, "float"),
            Self::Integer => write!(f, "integer"),
            Self::ShortString => write!(f, "string"),
            Self::LongString => write!(f, "longstring"),
        }
    }
}

// ── PooledConst ──────────────────────────────────────────────────────────────

/// A constant entry stored in the pool, carrying its pool index and prototype
/// origin path for cross-reference.
#[derive(Debug, Clone, PartialEq)]
pub struct PooledConst {
    /// Position within its prototype's constant array.
    pub index: usize,
    /// Proto identifier (depth-first walk index).
    pub proto_id: usize,
    /// Kind classification.
    pub kind: ConstKind,
    /// String value, if any.
    pub string_value: Option<String>,
    /// Numeric value (integer representation), if any.
    pub int_value: Option<i64>,
    /// Floating-point value, if any.
    pub float_value: Option<f64>,
    /// Boolean value, if any.
    pub bool_value: Option<bool>,
}

impl PooledConst {
    /// Build from a string constant.
    const fn string(index: usize, proto_id: usize, value: String, long: bool) -> Self {
        let kind = if long {
            ConstKind::LongString
        } else {
            ConstKind::ShortString
        };
        Self {
            index,
            proto_id,
            kind,
            string_value: Some(value),
            int_value: None,
            float_value: None,
            bool_value: None,
        }
    }

    /// Build from an integer constant.
    const fn integer(index: usize, proto_id: usize, value: i64) -> Self {
        Self {
            index,
            proto_id,
            kind: ConstKind::Integer,
            string_value: None,
            int_value: Some(value),
            float_value: None,
            bool_value: None,
        }
    }

    /// Build from a floating-point constant.
    const fn float(index: usize, proto_id: usize, value: f64) -> Self {
        Self {
            index,
            proto_id,
            kind: ConstKind::Float,
            string_value: None,
            int_value: None,
            float_value: Some(value),
            bool_value: None,
        }
    }

    /// Build from a boolean constant.
    const fn boolean(index: usize, proto_id: usize, value: bool) -> Self {
        Self {
            index,
            proto_id,
            kind: ConstKind::Boolean,
            string_value: None,
            int_value: None,
            float_value: None,
            bool_value: Some(value),
        }
    }

    /// Build the nil constant.
    const fn nil(index: usize, proto_id: usize) -> Self {
        Self {
            index,
            proto_id,
            kind: ConstKind::Nil,
            string_value: None,
            int_value: None,
            float_value: None,
            bool_value: None,
        }
    }

    /// Return a short display label for this constant.
    #[must_use]
    pub fn label(&self) -> String {
        match self.kind {
            ConstKind::Nil => "nil".to_string(),
            ConstKind::Boolean => self
                .bool_value
                .map_or_else(|| "?".to_string(), |b| b.to_string()),
            ConstKind::Integer => self
                .int_value
                .map_or_else(|| "?".to_string(), |i| i.to_string()),
            ConstKind::Float => self
                .float_value
                .map_or_else(|| "?".to_string(), |f| format!("{f:.6}")),
            ConstKind::ShortString | ConstKind::LongString => self
                .string_value
                .as_deref()
                .map_or_else(|| "?".to_string(), |s| {
                    if s.len() > 40 {
                        format!("\"{}...\"", &s[..40])
                    } else {
                        format!("\"{s}\"")
                    }
                }),
        }
    }
}

impl fmt::Display for PooledConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[proto={} idx={}] {} {}",
            self.proto_id,
            self.index,
            self.kind,
            self.label()
        )
    }
}

// ── ConstRef ─────────────────────────────────────────────────────────────────

/// A lightweight reference (`proto_id`, `index`) into the constant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstRef {
    /// Depth-first proto index.
    pub proto_id: usize,
    /// Index within that proto's constant array.
    pub const_index: usize,
}

impl ConstRef {
    /// Construct a new reference.
    #[must_use]
    pub const fn new(proto_id: usize, const_index: usize) -> Self {
        Self {
            proto_id,
            const_index,
        }
    }
}

impl fmt::Display for ConstRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConstRef(proto={}, idx={})", self.proto_id, self.const_index)
    }
}

// ── LuaConstantPool ──────────────────────────────────────────────────────────

/// Aggregated, cross-prototype constant pool for an entire Lua module.
///
/// Built from a depth-first traversal of a [`crate::LuaProto`] tree.  Provides
/// efficient lookup by string value, by kind, and by numeric value, as well as
/// deduplication statistics.
#[derive(Debug, Default)]
pub struct LuaConstantPool {
    /// All constants in depth-first prototype order.
    entries: Vec<PooledConst>,
    /// Reverse index: string value → list of `ConstRef`s that have that value.
    string_index: HashMap<String, Vec<ConstRef>>,
    /// Reverse index: integer value → list of `ConstRef`s.
    int_index: HashMap<i64, Vec<ConstRef>>,
    /// Count of each kind.
    kind_counts: HashMap<ConstKind, usize>,
    /// Total number of unique string values.
    unique_strings: usize,
    /// Total number of prototypes visited during construction.
    proto_count: usize,
}

impl LuaConstantPool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a pool from the `constants` slice of a single prototype,
    /// assigning it `proto_id`.
    pub fn ingest_proto_constants(
        &mut self,
        proto_id: usize,
        constants: &[crate::LuaConst],
    ) {
        self.proto_count = self.proto_count.max(proto_id + 1);
        for (index, kst) in constants.iter().enumerate() {
            let pooled = Self::make_pooled(index, proto_id, kst);
            let cref = ConstRef::new(proto_id, index);
            // Update kind count.
            *self.kind_counts.entry(pooled.kind).or_insert(0) += 1;
            // Update string index.
            if let Some(sv) = &pooled.string_value {
                let refs = self.string_index.entry(sv.clone()).or_default();
                let is_new = refs.is_empty();
                refs.push(cref);
                if is_new {
                    self.unique_strings += 1;
                }
            }
            // Update integer index.
            if let Some(iv) = pooled.int_value {
                self.int_index.entry(iv).or_default().push(cref);
            }
            self.entries.push(pooled);
        }
    }

    fn make_pooled(
        index: usize,
        proto_id: usize,
        kst: &crate::LuaConst,
    ) -> PooledConst {
        use crate::LuaConst;
        match kst {
            LuaConst::Nil => PooledConst::nil(index, proto_id),
            LuaConst::Bool(b) => PooledConst::boolean(index, proto_id, *b),
            LuaConst::Number(f) => PooledConst::float(index, proto_id, *f),
            LuaConst::Integer(i) => PooledConst::integer(index, proto_id, *i),
            LuaConst::Str(s) => PooledConst::string(index, proto_id, s.clone(), false),
            LuaConst::LongStr(s) => PooledConst::string(index, proto_id, s.clone(), true),
        }
    }

    /// Resolve a [`ConstRef`] to the underlying [`PooledConst`], if it exists.
    #[must_use]
    pub fn resolve(&self, cref: ConstRef) -> Option<&PooledConst> {
        self.entries.iter().find(|e| {
            let proto_ok = e.proto_id == cref.proto_id;
            let idx_ok = e.index == cref.const_index;
            proto_ok && idx_ok
        })
    }

    /// Return all constants for a given `proto_id`, in index order.
    #[must_use]
    pub fn constants_for_proto(&self, proto_id: usize) -> Vec<&PooledConst> {
        let mut v: Vec<&PooledConst> = self
            .entries
            .iter()
            .filter(|e| e.proto_id == proto_id)
            .collect();
        v.sort_by_key(|e| e.index);
        v
    }

    /// Look up all constants by exact string value.
    #[must_use]
    pub fn find_by_string(&self, value: &str) -> Vec<ConstRef> {
        self.string_index
            .get(value)
            .cloned()
            .unwrap_or_default()
    }

    /// Return all string constants that contain the given substring.
    #[must_use]
    pub fn find_strings_containing(&self, substr: &str) -> Vec<&PooledConst> {
        self.entries
            .iter()
            .filter(|e| {
                e.string_value
                    .as_deref()
                    .is_some_and(|s| s.contains(substr))
            })
            .collect()
    }

    /// Look up all constants by integer value.
    #[must_use]
    pub fn find_by_integer(&self, value: i64) -> Vec<ConstRef> {
        self.int_index
            .get(&value)
            .cloned()
            .unwrap_or_default()
    }

    /// Return all constants of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: ConstKind) -> Vec<&PooledConst> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Return all string constants (short and long) as `&str` slices.
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|e| e.string_value.as_deref())
            .collect()
    }

    /// Return all unique string values.
    #[must_use]
    pub fn unique_string_values(&self) -> Vec<&str> {
        self.string_index.keys().map(String::as_str).collect()
    }

    /// Total number of constant entries across all ingested prototypes.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.entries.len()
    }

    /// Count of entries of a given kind.
    #[must_use]
    pub fn count_by_kind(&self, kind: ConstKind) -> usize {
        self.kind_counts.get(&kind).copied().unwrap_or(0)
    }

    /// Number of unique string values observed across all prototypes.
    #[must_use]
    pub const fn unique_string_count(&self) -> usize {
        self.unique_strings
    }

    /// Number of prototypes ingested.
    #[must_use]
    pub const fn proto_count(&self) -> usize {
        self.proto_count
    }

    /// Strings that appear more than once (across all prototypes).
    #[must_use]
    pub fn duplicate_strings(&self) -> Vec<(&str, usize)> {
        self.string_index
            .iter()
            .filter(|(_, refs)| refs.len() > 1)
            .map(|(s, refs)| (s.as_str(), refs.len()))
            .collect()
    }

    /// Compute a rough entropy measure of string constants.
    ///
    /// High entropy strings (> 4.5 bits/byte on average) may be base64 or
    /// encrypted data rather than human-readable identifiers.
    #[must_use]
    pub fn high_entropy_strings(&self, threshold: f64) -> Vec<&PooledConst> {
        self.entries
            .iter()
            .filter(|e| {
                e.string_value
                    .as_deref()
                    .is_some_and(|s| byte_entropy(s.as_bytes()) >= threshold)
            })
            .collect()
    }

    /// Return all numeric constants sorted ascending by their value.
    #[must_use]
    pub fn sorted_integers(&self) -> Vec<i64> {
        let mut vals: Vec<i64> = self
            .entries
            .iter()
            .filter_map(|e| e.int_value)
            .collect();
        vals.sort_unstable();
        vals.dedup();
        vals
    }

    /// Return a summary map: kind name → count.
    #[must_use]
    pub fn kind_summary(&self) -> HashMap<String, usize> {
        self.kind_counts
            .iter()
            .map(|(k, &v)| (k.to_string(), v))
            .collect()
    }

    /// Pretty-print pool statistics.
    #[must_use]
    pub fn stats_report(&self) -> String {
        let mut lines = vec![format!(
            "LuaConstantPool: {} entries across {} protos",
            self.total_count(),
            self.proto_count()
        )];
        for (kind, count) in &self.kind_counts {
            lines.push(format!("  {kind}: {count}"));
        }
        lines.push(format!("  unique strings: {}", self.unique_strings));
        lines.join("\n")
    }
}

// ── resolve_const ─────────────────────────────────────────────────────────────

/// Resolve a constant from a raw prototype constant array by index.
///
/// Returns `None` if `index` is out of bounds.
///
/// # Examples
/// ```rust
/// use rustre_loader_lua::{LuaConst, LuaVersion};
/// use rustre_loader_lua::lua_constant_pool::resolve_const;
///
/// let consts = vec![LuaConst::Str("hello".into()), LuaConst::Integer(42)];
/// let c = resolve_const(&consts, 1);
/// assert!(c.is_some());
/// ```
#[must_use]
pub fn resolve_const(constants: &[crate::LuaConst], index: usize) -> Option<&crate::LuaConst> {
    constants.get(index)
}

/// Resolve a constant by index and return a [`ConstKind`] classification.
#[must_use]
pub fn resolve_const_kind(constants: &[crate::LuaConst], index: usize) -> Option<ConstKind> {
    use crate::LuaConst;
    constants.get(index).map(|kst| match kst {
        LuaConst::Nil => ConstKind::Nil,
        LuaConst::Bool(_) => ConstKind::Boolean,
        LuaConst::Number(_) => ConstKind::Float,
        LuaConst::Integer(_) => ConstKind::Integer,
        LuaConst::Str(_) => ConstKind::ShortString,
        LuaConst::LongStr(_) => ConstKind::LongString,
    })
}

// ── ConstantPoolBuilder ───────────────────────────────────────────────────────

/// Convenience builder that walks an entire [`crate::LuaProto`] tree depth-first
/// and produces a filled [`LuaConstantPool`].
pub struct ConstantPoolBuilder;

impl ConstantPoolBuilder {
    /// Build a pool from a top-level proto and all its nested protos.
    #[must_use]
    pub fn build(root: &crate::LuaProto) -> LuaConstantPool {
        let mut pool = LuaConstantPool::new();
        let mut counter = 0usize;
        Self::walk(root, &mut pool, &mut counter);
        pool
    }

    fn walk(proto: &crate::LuaProto, pool: &mut LuaConstantPool, counter: &mut usize) {
        let id = *counter;
        *counter += 1;
        pool.ingest_proto_constants(id, &proto.constants);
        for child in &proto.protos {
            Self::walk(child, pool, counter);
        }
    }
}

// ── ConstantUsageTracker ──────────────────────────────────────────────────────

/// Tracks which constants are referenced by instructions in a proto.
///
/// In Lua 5.1-5.4 the B or Bx field of `LOADK` directly indexes the constant
/// table. This tracker records those references so dead constants can be
/// identified.
#[derive(Debug, Default)]
pub struct ConstantUsageTracker {
    /// (`proto_id`, `const_index`) → use count from instruction stream.
    use_counts: HashMap<(usize, usize), usize>,
}

impl ConstantUsageTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a reference to constant `const_index` in proto `proto_id`.
    pub fn record_use(&mut self, proto_id: usize, const_index: usize) {
        *self
            .use_counts
            .entry((proto_id, const_index))
            .or_insert(0) += 1;
    }

    /// Return the number of instruction references to a constant.
    #[must_use]
    pub fn use_count(&self, proto_id: usize, const_index: usize) -> usize {
        self.use_counts
            .get(&(proto_id, const_index))
            .copied()
            .unwrap_or(0)
    }

    /// Identify constants in the pool that have zero recorded uses.
    #[must_use]
    pub fn dead_constants(&self, pool: &LuaConstantPool) -> Vec<ConstRef> {
        pool.entries
            .iter()
            .filter(|e| self.use_count(e.proto_id, e.index) == 0)
            .map(|e| ConstRef::new(e.proto_id, e.index))
            .collect()
    }

    /// Return constants sorted by use count descending (hottest first).
    #[must_use]
    pub fn hottest_constants(&self, pool: &LuaConstantPool) -> Vec<(ConstRef, usize)> {
        let mut v: Vec<(ConstRef, usize)> = pool
            .entries
            .iter()
            .map(|e| {
                let r = ConstRef::new(e.proto_id, e.index);
                let count = self.use_count(e.proto_id, e.index);
                (r, count)
            })
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Shannon entropy of a byte slice, in bits per byte.
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LuaConst, LuaVersion};

    fn sample_consts() -> Vec<LuaConst> {
        vec![
            LuaConst::Str("hello".into()),
            LuaConst::Integer(42),
            LuaConst::Number(std::f64::consts::PI),
            LuaConst::Bool(true),
            LuaConst::Nil,
            LuaConst::Str("world".into()),
            LuaConst::LongStr("long string value".into()),
        ]
    }

    #[test]
    fn test_pool_ingest() {
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &sample_consts());
        assert_eq!(pool.total_count(), 7);
        assert_eq!(pool.count_by_kind(ConstKind::ShortString), 2);
        assert_eq!(pool.count_by_kind(ConstKind::Integer), 1);
        assert_eq!(pool.count_by_kind(ConstKind::Nil), 1);
        assert_eq!(pool.unique_string_count(), 3); // hello, world, long string value
    }

    #[test]
    fn test_find_by_string() {
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &sample_consts());
        let refs = pool.find_by_string("hello");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].const_index, 0);
    }

    #[test]
    fn test_find_by_integer() {
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &sample_consts());
        let refs = pool.find_by_integer(42);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_resolve_const() {
        let consts = sample_consts();
        assert!(resolve_const(&consts, 0).is_some());
        assert!(resolve_const(&consts, 99).is_none());
    }

    #[test]
    fn test_resolve_const_kind() {
        let consts = sample_consts();
        assert_eq!(resolve_const_kind(&consts, 0), Some(ConstKind::ShortString));
        assert_eq!(resolve_const_kind(&consts, 1), Some(ConstKind::Integer));
        assert_eq!(resolve_const_kind(&consts, 4), Some(ConstKind::Nil));
    }

    #[test]
    fn test_builder_from_proto() {
        let proto = crate::LuaProto::mock(LuaVersion::Lua54);
        let pool = ConstantPoolBuilder::build(&proto);
        assert!(pool.total_count() > 0);
    }

    #[test]
    fn test_usage_tracker() {
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &sample_consts());
        let mut tracker = ConstantUsageTracker::new();
        tracker.record_use(0, 0); // hello
        tracker.record_use(0, 0); // hello again
        tracker.record_use(0, 1); // 42
        assert_eq!(tracker.use_count(0, 0), 2);
        assert_eq!(tracker.use_count(0, 1), 1);
        // Constants at indices 2..6 are dead.
        let dead = tracker.dead_constants(&pool);
        assert!(dead.len() >= 4);
    }

    #[test]
    fn test_high_entropy_strings() {
        let consts = vec![
            LuaConst::Str("aGVsbG8gd29ybGQ=".into()), // base64-ish
            LuaConst::Str("hello".into()),
        ];
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &consts);
        let hi = pool.high_entropy_strings(3.0);
        assert!(!hi.is_empty());
    }

    #[test]
    fn test_kind_summary() {
        let mut pool = LuaConstantPool::new();
        pool.ingest_proto_constants(0, &sample_consts());
        let summary = pool.kind_summary();
        assert!(summary.contains_key("string"));
        assert!(summary.contains_key("nil"));
    }
}
