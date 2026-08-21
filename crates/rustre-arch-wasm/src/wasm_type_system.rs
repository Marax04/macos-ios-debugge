//! WebAssembly type system.
//!
//! `ValType`, `FuncType`, `ResultType`, `RefType`, `TableType`, `MemType` and
//! `GlobalType`, plus type compatibility checking, LEB128 encoding, type
//! canonicalization and function type deduplication.

use std::collections::HashMap;
use std::fmt;

// ── WasmValType ───────────────────────────────────────────────────────────────

/// The set of value types in the WebAssembly type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WasmValType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit IEEE 754 floating-point.
    F32,
    /// 64-bit IEEE 754 floating-point.
    F64,
    /// 128-bit SIMD vector.
    V128,
    /// Function reference (funcref).
    FuncRef,
    /// External reference (externref).
    ExternRef,
}

impl WasmValType {
    /// Decode a valtype from its binary encoding byte.
    ///
    /// Returns `None` for unknown bytes.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x7F => Self::I32,
            0x7E => Self::I64,
            0x7D => Self::F32,
            0x7C => Self::F64,
            0x7B => Self::V128,
            0x70 => Self::FuncRef,
            0x6F => Self::ExternRef,
            _ => return None,
        })
    }

    /// Return the binary encoding byte for this valtype.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::I32 => 0x7F,
            Self::I64 => 0x7E,
            Self::F32 => 0x7D,
            Self::F64 => 0x7C,
            Self::V128 => 0x7B,
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }

    /// Return the canonical text name for this valtype.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::V128 => "v128",
            Self::FuncRef => "funcref",
            Self::ExternRef => "externref",
        }
    }

    /// Returns `true` if the type is a numeric type (i32/i64/f32/f64/v128).
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::I32 | Self::I64 | Self::F32 | Self::F64 | Self::V128
        )
    }

    /// Returns `true` if the type is a reference type (funcref/externref).
    #[must_use]
    pub const fn is_reference(self) -> bool {
        matches!(self, Self::FuncRef | Self::ExternRef)
    }

    /// Returns `true` if the type is a floating-point type (f32/f64).
    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    /// Returns `true` if the type is an integer type (i32/i64).
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::I32 | Self::I64)
    }

    /// Return the bit-width of this type (128 for v128, 64 for i64/f64, 32 otherwise).
    #[must_use]
    pub const fn bit_width(self) -> u32 {
        match self {
            Self::V128 => 128,
            Self::I64 | Self::F64 => 64,
            Self::I32 | Self::F32 | Self::FuncRef | Self::ExternRef => 32,
        }
    }

    /// Write the LEB128 encoding of this valtype byte to `out`.
    pub fn encode_leb128(&self, out: &mut Vec<u8>) {
        out.push(self.to_byte());
    }
}

impl fmt::Display for WasmValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── WasmRefType ───────────────────────────────────────────────────────────────

/// Reference types usable in table element types and ref instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmRefType {
    /// `funcref` — a function reference.
    FuncRef,
    /// `externref` — an external/host reference.
    ExternRef,
}

impl WasmRefType {
    /// Decode from a byte (0x70 = funcref, 0x6F = externref).
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x70 => Some(Self::FuncRef),
            0x6F => Some(Self::ExternRef),
            _ => None,
        }
    }

    /// Binary encoding byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }

    /// Text name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FuncRef => "funcref",
            Self::ExternRef => "externref",
        }
    }

    /// Convert to a `WasmValType`.
    #[must_use]
    pub const fn as_val_type(self) -> WasmValType {
        match self {
            Self::FuncRef => WasmValType::FuncRef,
            Self::ExternRef => WasmValType::ExternRef,
        }
    }
}

impl fmt::Display for WasmRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── ResultType ────────────────────────────────────────────────────────────────

/// A sequence of value types (used as parameter or result list).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ResultType {
    /// The ordered list of value types.
    pub types: Vec<WasmValType>,
}

impl ResultType {
    /// Create an empty result type.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a result type from a vector of value types.
    #[must_use]
    pub const fn from_vec(types: Vec<WasmValType>) -> Self {
        Self { types }
    }

    /// Return the number of types.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.types.len()
    }

    /// Return `true` when the result type is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Encode this result type to binary: uleb128(count) then each type byte.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_uleb128(self.types.len() as u64, out);
        for t in &self.types {
            out.push(t.to_byte());
        }
    }

    /// Decode a result type from `bytes` at `pos`.
    ///
    /// Returns `(result_type, bytes_consumed)` on success.
    #[must_use]
    pub fn decode(bytes: &[u8], pos: usize) -> Option<(Self, usize)> {
        let (count, n) = decode_uleb128(bytes, pos)?;
        let count = usize::try_from(count).ok()?;
        let mut p = pos + n;
        // `count` is an attacker-controlled ULEB128 (the br_table paths in
        // `lib.rs`/`wasm_lifter.rs` already bound theirs). Each value type is a
        // single byte, so the bytes left after the count bound the real total.
        let mut types = Vec::with_capacity(count.min(bytes.len().saturating_sub(p)));
        for _ in 0..count {
            if p >= bytes.len() {
                return None;
            }
            let vt = WasmValType::from_byte(bytes[p])?;
            types.push(vt);
            p += 1;
        }
        Some((Self { types }, p - pos))
    }
}

impl fmt::Display for ResultType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, t) in self.types.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{t}")?;
        }
        write!(f, "]")
    }
}

// ── WasmFuncType ──────────────────────────────────────────────────────────────

/// A WebAssembly function type: a pair of parameter and result type lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WasmFuncType {
    /// Parameter types.
    pub params: ResultType,
    /// Result types.
    pub results: ResultType,
}

impl WasmFuncType {
    /// Create a new function type.
    #[must_use]
    pub const fn new(params: Vec<WasmValType>, results: Vec<WasmValType>) -> Self {
        Self {
            params: ResultType::from_vec(params),
            results: ResultType::from_vec(results),
        }
    }

    /// Decode a functype from its binary encoding (starting with 0x60).
    ///
    /// Returns `(func_type, bytes_consumed)` or `None` on failure.
    #[must_use]
    pub fn decode(bytes: &[u8], pos: usize) -> Option<(Self, usize)> {
        if pos >= bytes.len() || bytes[pos] != 0x60 {
            return None;
        }
        let mut p = pos + 1;
        let (params, n1) = ResultType::decode(bytes, p)?;
        p += n1;
        let (results, n2) = ResultType::decode(bytes, p)?;
        p += n2;
        Some((Self { params, results }, p - pos))
    }

    /// Encode this function type to binary.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(0x60); // functype marker
        self.params.encode(out);
        self.results.encode(out);
    }

    /// Number of parameters.
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Number of results.
    #[must_use]
    pub const fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Return the arity as (params, results).
    #[must_use]
    pub const fn arity(&self) -> (usize, usize) {
        (self.params.len(), self.results.len())
    }

    /// Returns `true` when this function type has no parameters and no results.
    #[must_use]
    pub const fn is_void_void(&self) -> bool {
        self.params.is_empty() && self.results.is_empty()
    }
}

impl fmt::Display for WasmFuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.params, self.results)
    }
}

// ── WasmTableType ─────────────────────────────────────────────────────────────

/// A WebAssembly table type: element reftype + limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmTableType {
    /// Element type of the table.
    pub element_type: WasmRefType,
    /// Minimum number of entries.
    pub min: u32,
    /// Optional maximum number of entries.
    pub max: Option<u32>,
}

impl WasmTableType {
    /// Create a new table type with no maximum.
    #[must_use]
    pub const fn new(element_type: WasmRefType, min: u32) -> Self {
        Self {
            element_type,
            min,
            max: None,
        }
    }

    /// Create a new table type with both min and max.
    #[must_use]
    pub const fn bounded(element_type: WasmRefType, min: u32, max: u32) -> Self {
        Self {
            element_type,
            min,
            max: Some(max),
        }
    }

    /// Decode from binary.
    #[must_use]
    pub fn decode(bytes: &[u8], pos: usize) -> Option<(Self, usize)> {
        if pos >= bytes.len() {
            return None;
        }
        let element_type = WasmRefType::from_byte(bytes[pos])?;
        let mut p = pos + 1;
        if p >= bytes.len() {
            return None;
        }
        let kind = bytes[p];
        p += 1;
        let (min, n1) = decode_uleb128(bytes, p)?;
        p += n1;
        let max = if kind == 1 {
            let (max_val, n2) = decode_uleb128(bytes, p)?;
            p += n2;
            Some(u32::try_from(max_val).ok()?)
        } else {
            None
        };
        Some((
            Self {
                element_type,
                min: u32::try_from(min).ok()?,
                max,
            },
            p - pos,
        ))
    }

    /// Encode to binary.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.element_type.to_byte());
        if let Some(max) = self.max {
            out.push(1);
            encode_uleb128(u64::from(self.min), out);
            encode_uleb128(u64::from(max), out);
        } else {
            out.push(0);
            encode_uleb128(u64::from(self.min), out);
        }
    }
}

impl fmt::Display for WasmTableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.max {
            Some(max) => write!(f, "table {} {}..{}", self.element_type, self.min, max),
            None => write!(f, "table {} {}+", self.element_type, self.min),
        }
    }
}

// ── WasmMemType ───────────────────────────────────────────────────────────────

/// A WebAssembly memory type: limits in units of 64 KiB pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmMemType {
    /// Minimum size in pages.
    pub min: u32,
    /// Optional maximum size in pages.
    pub max: Option<u32>,
}

impl WasmMemType {
    /// Create a new memory type with no maximum.
    #[must_use]
    pub const fn new(min: u32) -> Self {
        Self { min, max: None }
    }

    /// Create a new memory type with both min and max.
    #[must_use]
    pub const fn bounded(min: u32, max: u32) -> Self {
        Self {
            min,
            max: Some(max),
        }
    }

    /// Minimum size in bytes.
    #[must_use]
    pub const fn min_bytes(&self) -> u64 {
        self.min as u64 * 65536
    }

    /// Maximum size in bytes, if bounded.
    #[must_use]
    pub fn max_bytes(&self) -> Option<u64> {
        self.max.map(|m| u64::from(m) * 65536)
    }

    /// Decode from binary.
    #[must_use]
    pub fn decode(bytes: &[u8], pos: usize) -> Option<(Self, usize)> {
        if pos >= bytes.len() {
            return None;
        }
        let kind = bytes[pos];
        let mut p = pos + 1;
        let (min, n1) = decode_uleb128(bytes, p)?;
        p += n1;
        let max = if kind == 1 {
            let (max_val, n2) = decode_uleb128(bytes, p)?;
            p += n2;
            Some(u32::try_from(max_val).ok()?)
        } else {
            None
        };
        Some((
            Self {
                min: u32::try_from(min).ok()?,
                max,
            },
            p - pos,
        ))
    }

    /// Encode to binary.
    pub fn encode(&self, out: &mut Vec<u8>) {
        if let Some(max) = self.max {
            out.push(1);
            encode_uleb128(u64::from(self.min), out);
            encode_uleb128(u64::from(max), out);
        } else {
            out.push(0);
            encode_uleb128(u64::from(self.min), out);
        }
    }
}

impl fmt::Display for WasmMemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.max {
            Some(max) => write!(f, "memory {}..{}", self.min, max),
            None => write!(f, "memory {}+", self.min),
        }
    }
}

// ── WasmMutability ────────────────────────────────────────────────────────────

/// Mutability for a global type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmMutability {
    /// Immutable global (0x00).
    Const,
    /// Mutable global (0x01).
    Var,
}

impl WasmMutability {
    /// Decode from byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Const),
            1 => Some(Self::Var),
            _ => None,
        }
    }

    /// Binary encoding byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Const => 0,
            Self::Var => 1,
        }
    }

    /// Return `true` when mutable.
    #[must_use]
    pub const fn is_mutable(self) -> bool {
        matches!(self, Self::Var)
    }
}

impl fmt::Display for WasmMutability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const => write!(f, "const"),
            Self::Var => write!(f, "var"),
        }
    }
}

// ── WasmGlobalType ────────────────────────────────────────────────────────────

/// A WebAssembly global type: value type + mutability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WasmGlobalType {
    /// Value type of the global.
    pub val_type: WasmValType,
    /// Mutability.
    pub mutability: WasmMutability,
}

impl WasmGlobalType {
    /// Create a new global type.
    #[must_use]
    pub const fn new(val_type: WasmValType, mutability: WasmMutability) -> Self {
        Self { val_type, mutability }
    }

    /// Decode from binary.
    #[must_use]
    pub fn decode(bytes: &[u8], pos: usize) -> Option<(Self, usize)> {
        if pos + 1 >= bytes.len() {
            return None;
        }
        let vt = WasmValType::from_byte(bytes[pos])?;
        let mut_ = WasmMutability::from_byte(bytes[pos + 1])?;
        Some((Self { val_type: vt, mutability: mut_ }, 2))
    }

    /// Encode to binary.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.val_type.to_byte());
        out.push(self.mutability.to_byte());
    }
}

impl fmt::Display for WasmGlobalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "global {} {}", self.mutability, self.val_type)
    }
}

// ── TypeRegistry ──────────────────────────────────────────────────────────────

/// Registry for WebAssembly function types that deduplicates equivalent types.
///
/// Stores canonical `WasmFuncType` objects indexed by their type index and
/// provides fast lookup of the canonical index for any given function type.
#[derive(Debug, Clone, Default)]
pub struct TypeRegistry {
    /// Ordered list of unique function types (index = position).
    types: Vec<WasmFuncType>,
    /// Map from canonical key to index for O(1) deduplication.
    index: HashMap<TypeKey, u32>,
}

/// A hashable key derived from a `WasmFuncType` for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypeKey {
    params: Vec<u8>,
    results: Vec<u8>,
}

impl TypeKey {
    fn from_func_type(ft: &WasmFuncType) -> Self {
        Self {
            params: ft.params.types.iter().map(|v| v.to_byte()).collect(),
            results: ft.results.types.iter().map(|v| v.to_byte()).collect(),
        }
    }
}

impl TypeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `ft` into the registry, returning its canonical index.
    ///
    /// If an equivalent type already exists, the existing index is returned.
    ///
    /// # Panics
    ///
    /// Panics if the registry already holds `u32::MAX` types, which exhausts the
    /// 32-bit Wasm type index space.
    pub fn intern(&mut self, ft: WasmFuncType) -> u32 {
        let key = TypeKey::from_func_type(&ft);
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        // A registry cannot address more than `u32::MAX` types: the Wasm index
        // space is 32-bit, so overflowing it is a caller bug, not input data.
        let idx = u32::try_from(self.types.len()).expect("type index space exhausted");
        self.types.push(ft);
        self.index.insert(key, idx);
        idx
    }

    /// Look up a function type by index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&WasmFuncType> {
        self.types.get(index as usize)
    }

    /// Return the canonical index for `ft` without inserting it.
    #[must_use]
    pub fn find(&self, ft: &WasmFuncType) -> Option<u32> {
        let key = TypeKey::from_func_type(ft);
        self.index.get(&key).copied()
    }

    /// Number of unique types in the registry.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns `true` when the registry is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Encode the entire type section (without section header) to binary.
    ///
    /// Format: `uleb128(count)` then each functype encoded as `0x60 params results`.
    #[must_use]
    pub fn encode_type_section(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_uleb128(self.types.len() as u64, &mut out);
        for ft in &self.types {
            ft.encode(&mut out);
        }
        out
    }

    /// Decode a type section (without section header) from `bytes`.
    #[must_use]
    pub fn decode_type_section(bytes: &[u8]) -> Option<Self> {
        let (count, n) = decode_uleb128(bytes, 0)?;
        let count = usize::try_from(count).ok()?;
        let mut reg = Self::new();
        let mut pos = n;
        for _ in 0..count {
            let (ft, consumed) = WasmFuncType::decode(bytes, pos)?;
            pos += consumed;
            reg.intern(ft);
        }
        Some(reg)
    }

    /// Canonicalize: remove duplicate types, returning a mapping from old
    /// indices to new canonical indices.
    pub fn canonicalize(&mut self) -> Vec<u32> {
        let old_types: Vec<WasmFuncType> = std::mem::take(&mut self.types);
        self.index.clear();
        let mut mapping = Vec::with_capacity(old_types.len());
        for ft in old_types {
            let new_idx = self.intern(ft);
            mapping.push(new_idx);
        }
        mapping
    }

    /// Iterate over all types in index order.
    ///
    /// # Panics
    ///
    /// Panics if the registry holds more than `u32::MAX` types, which exhausts
    /// the 32-bit Wasm type index space.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &WasmFuncType)> {
        self.types
            .iter()
            .enumerate()
            .map(|(i, ft)| (u32::try_from(i).expect("type index space exhausted"), ft))
    }
}

// ── Type compatibility ─────────────────────────────────────────────────────────

/// Checks whether `actual` is compatible with `expected` value type.
///
/// In the MVP type system, compatibility means equality.  With reference types,
/// `funcref` and `externref` are not mutually compatible.
#[must_use]
pub fn types_compatible(actual: WasmValType, expected: WasmValType) -> bool {
    actual == expected
}

/// Checks whether two result types are mutually compatible (element-wise).
#[must_use]
pub fn result_types_compatible(a: &ResultType, b: &ResultType) -> bool {
    if a.types.len() != b.types.len() {
        return false;
    }
    a.types
        .iter()
        .zip(b.types.iter())
        .all(|(&ta, &tb)| types_compatible(ta, tb))
}

/// Checks whether function type `a` can be called where `b` is expected.
///
/// In Wasm MVP this is strict equality of both param and result lists.
#[must_use]
pub fn func_types_compatible(a: &WasmFuncType, b: &WasmFuncType) -> bool {
    result_types_compatible(&a.params, &b.params)
        && result_types_compatible(&a.results, &b.results)
}

// ── LEB128 helpers ────────────────────────────────────────────────────────────

/// Encode an unsigned 64-bit value as LEB128 and push bytes to `out`.
pub fn encode_uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        // Masked to 7 bits, so the value is always in `0..=127`.
        let mut byte = u8::try_from(value & 0x7F).unwrap_or(0);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Encode a signed 64-bit value as LEB128 and push bytes to `out`.
pub fn encode_sleb128(mut value: i64, out: &mut Vec<u8>) {
    let mut more = true;
    while more {
        // Masked to 7 bits, so the value is always in `0..=127`.
        let mut byte = u8::try_from(value & 0x7F).unwrap_or(0);
        value >>= 7;
        if (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

/// Decode an unsigned LEB128 value from `bytes` at `pos`.
///
/// Returns `(value, bytes_consumed)` or `None` on truncation/overflow.
#[must_use]
pub fn decode_uleb128(bytes: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut p = pos;
    loop {
        if p >= bytes.len() {
            return None;
        }
        let b = bytes[p];
        p += 1;
        result |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    Some((result, p - pos))
}

/// Decode a signed LEB128 value from `bytes` at `pos`.
///
/// Returns `(value, bytes_consumed)` or `None` on truncation/overflow.
#[must_use]
pub fn decode_sleb128(bytes: &[u8], pos: usize) -> Option<(i64, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut p = pos;
    loop {
        if p >= bytes.len() {
            return None;
        }
        let b = bytes[p];
        p += 1;
        result |= i64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    Some((result, p - pos))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valtype_roundtrip() {
        let types = [
            WasmValType::I32,
            WasmValType::I64,
            WasmValType::F32,
            WasmValType::F64,
            WasmValType::V128,
            WasmValType::FuncRef,
            WasmValType::ExternRef,
        ];
        for t in types {
            let b = t.to_byte();
            assert_eq!(WasmValType::from_byte(b), Some(t));
        }
    }

    #[test]
    fn test_valtype_names() {
        assert_eq!(WasmValType::I32.name(), "i32");
        assert_eq!(WasmValType::ExternRef.name(), "externref");
    }

    #[test]
    fn test_result_type_encode_decode() {
        let rt = ResultType::from_vec(vec![WasmValType::I32, WasmValType::F64]);
        let mut out = Vec::new();
        rt.encode(&mut out);
        let (decoded, n) = ResultType::decode(&out, 0).unwrap();
        assert_eq!(n, out.len());
        assert_eq!(decoded, rt);
    }

    #[test]
    fn test_func_type_encode_decode() {
        let ft = WasmFuncType::new(
            vec![WasmValType::I32, WasmValType::I64],
            vec![WasmValType::F32],
        );
        let mut out = Vec::new();
        ft.encode(&mut out);
        let (decoded, n) = WasmFuncType::decode(&out, 0).unwrap();
        assert_eq!(n, out.len());
        assert_eq!(decoded, ft);
    }

    #[test]
    fn test_type_registry_dedup() {
        let mut reg = TypeRegistry::new();
        let ft1 = WasmFuncType::new(vec![WasmValType::I32], vec![WasmValType::I64]);
        let ft2 = WasmFuncType::new(vec![WasmValType::I32], vec![WasmValType::I64]);
        let ft3 = WasmFuncType::new(vec![], vec![]);
        let i1 = reg.intern(ft1);
        let i2 = reg.intern(ft2);
        let i3 = reg.intern(ft3);
        assert_eq!(i1, i2);
        assert_ne!(i1, i3);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn test_type_registry_encode_decode() {
        let mut reg = TypeRegistry::new();
        reg.intern(WasmFuncType::new(vec![WasmValType::I32], vec![]));
        reg.intern(WasmFuncType::new(vec![], vec![WasmValType::I64]));
        let encoded = reg.encode_type_section();
        let decoded = TypeRegistry::decode_type_section(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn test_global_type_encode_decode() {
        let gt = WasmGlobalType::new(WasmValType::I32, WasmMutability::Var);
        let mut out = Vec::new();
        gt.encode(&mut out);
        let (decoded, n) = WasmGlobalType::decode(&out, 0).unwrap();
        assert_eq!(n, 2);
        assert_eq!(decoded.val_type, WasmValType::I32);
        assert_eq!(decoded.mutability, WasmMutability::Var);
    }

    #[test]
    fn test_mem_type_encode_decode() {
        let mt = WasmMemType::bounded(1, 4);
        let mut out = Vec::new();
        mt.encode(&mut out);
        let (decoded, _) = WasmMemType::decode(&out, 0).unwrap();
        assert_eq!(decoded.min, 1);
        assert_eq!(decoded.max, Some(4));
    }

    #[test]
    fn test_table_type_encode_decode() {
        let tt = WasmTableType::new(WasmRefType::FuncRef, 0);
        let mut out = Vec::new();
        tt.encode(&mut out);
        let (decoded, _) = WasmTableType::decode(&out, 0).unwrap();
        assert_eq!(decoded.element_type, WasmRefType::FuncRef);
        assert_eq!(decoded.min, 0);
        assert!(decoded.max.is_none());
    }

    #[test]
    fn test_uleb128_roundtrip() {
        let values = [0u64, 1, 127, 128, 300, 0x4000, u64::from(u32::MAX)];
        for v in values {
            let mut out = Vec::new();
            encode_uleb128(v, &mut out);
            let (decoded, n) = decode_uleb128(&out, 0).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn test_sleb128_roundtrip() {
        let values = [0i64, -1, 1, -128, 127, -300, i64::from(i32::MIN)];
        for v in values {
            let mut out = Vec::new();
            encode_sleb128(v, &mut out);
            let (decoded, n) = decode_sleb128(&out, 0).unwrap();
            assert_eq!(decoded, v, "failed for {v}");
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn test_func_type_compatibility() {
        let ft1 = WasmFuncType::new(vec![WasmValType::I32], vec![]);
        let ft2 = WasmFuncType::new(vec![WasmValType::I32], vec![]);
        let ft3 = WasmFuncType::new(vec![WasmValType::I64], vec![]);
        assert!(func_types_compatible(&ft1, &ft2));
        assert!(!func_types_compatible(&ft1, &ft3));
    }

    #[test]
    fn test_canonicalize() {
        let mut reg = TypeRegistry::new();
        let a = reg.intern(WasmFuncType::new(vec![WasmValType::I32], vec![]));
        let b = reg.intern(WasmFuncType::new(vec![WasmValType::I32], vec![]));
        let c = reg.intern(WasmFuncType::new(vec![WasmValType::F32], vec![]));
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mapping = reg.canonicalize();
        assert_eq!(mapping.len(), 2); // only 2 unique types
    }

    #[test]
    fn test_ref_type_as_val_type() {
        assert_eq!(WasmRefType::FuncRef.as_val_type(), WasmValType::FuncRef);
        assert_eq!(WasmRefType::ExternRef.as_val_type(), WasmValType::ExternRef);
    }

    #[test]
    fn test_void_void() {
        let ft = WasmFuncType::new(vec![], vec![]);
        assert!(ft.is_void_void());
        let ft2 = WasmFuncType::new(vec![WasmValType::I32], vec![]);
        assert!(!ft2.is_void_void());
    }
}
