//! Array access detection for decompiled code.
//!
//! Recognizes `[base + index*scale + offset]` address patterns, infers element
//! size from scale factors, detects bounds checks, distinguishes array from
//! struct field accesses, and handles multi-dimensional arrays.

use std::collections::HashMap;

// ── ElementSize ───────────────────────────────────────────────────────────────

/// Known element sizes in bytes corresponding to C types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementSize {
    /// 1-byte element (char, `uint8_t`).
    Byte,
    /// 2-byte element (short, `uint16_t`).
    Short,
    /// 4-byte element (int, float, `uint32_t`).
    Int,
    /// 8-byte element (long long, double, pointer on 64-bit).
    Long,
    /// 16-byte element (SSE vector, __int128).
    Vector16,
    /// 32-byte element (AVX vector).
    Vector32,
    /// Unknown / non-power-of-two element size.
    Custom(u64),
}

impl ElementSize {
    /// Return the element size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Byte => 1,
            Self::Short => 2,
            Self::Int => 4,
            Self::Long => 8,
            Self::Vector16 => 16,
            Self::Vector32 => 32,
            Self::Custom(n) => n,
        }
    }

    /// Infer from a scale factor (e.g. from `index * N`).
    #[must_use]
    pub const fn from_scale(scale: u64) -> Self {
        match scale {
            1 => Self::Byte,
            2 => Self::Short,
            4 => Self::Int,
            8 => Self::Long,
            16 => Self::Vector16,
            32 => Self::Vector32,
            other => Self::Custom(other),
        }
    }

    /// Return a C-like type name for the element.
    #[must_use]
    pub const fn c_type_name(self) -> &'static str {
        match self {
            Self::Byte => "uint8_t",
            Self::Short => "uint16_t",
            Self::Int => "uint32_t",
            Self::Long => "uint64_t",
            Self::Vector16 => "__m128i",
            Self::Vector32 => "__m256i",
            Self::Custom(_) => "void",
        }
    }
}

// ── ScaledIndex ───────────────────────────────────────────────────────────────

/// A scaled index expression: `index * scale + constant_offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaledIndex {
    /// The index variable name.
    pub index_var: String,
    /// Scale factor (element size in bytes).
    pub scale: u64,
    /// Constant offset added after scaling.
    pub offset: i64,
}

impl ScaledIndex {
    /// Create a new scaled index without constant offset.
    #[must_use]
    pub fn new(index_var: impl Into<String>, scale: u64) -> Self {
        Self {
            index_var: index_var.into(),
            scale,
            offset: 0,
        }
    }

    /// Create with an additional constant offset.
    #[must_use]
    pub fn with_offset(index_var: impl Into<String>, scale: u64, offset: i64) -> Self {
        Self {
            index_var: index_var.into(),
            scale,
            offset,
        }
    }
}

// ── ArrayAccess ───────────────────────────────────────────────────────────────

/// A recognized array access operation.
#[derive(Debug, Clone)]
pub struct ArrayAccess {
    /// The base pointer variable name.
    pub base: String,
    /// The scaled index.
    pub index: ScaledIndex,
    /// Inferred element size.
    pub element_size: ElementSize,
    /// Whether this is a read or write.
    pub is_write: bool,
    /// Source expression string (for display).
    pub expr_str: String,
}

impl ArrayAccess {
    /// Return the C-style access expression: `base[index]` or `base[index+k]`.
    #[must_use]
    pub fn c_expr(&self) -> String {
        let idx = &self.index.index_var;
        match self.index.offset.cmp(&0) {
            std::cmp::Ordering::Equal => format!("{}[{}]", self.base, idx),
            std::cmp::Ordering::Greater => format!("{}[{}+{}]", self.base, idx, self.index.offset),
            std::cmp::Ordering::Less => format!("{}[{}{}]", self.base, idx, self.index.offset),
        }
    }

    /// Return the underlying pointer arithmetic as `*(base + index*scale + offset)`.
    #[must_use]
    pub fn ptr_arith(&self) -> String {
        let scale = self.index.scale;
        let idx = &self.index.index_var;
        if self.index.offset == 0 {
            format!("*({} + {}*{})", self.base, idx, scale)
        } else {
            format!(
                "*({} + {}*{} + {})",
                self.base, idx, scale, self.index.offset
            )
        }
    }
}

// ── ArrayPattern ─────────────────────────────────────────────────────────────

/// A pattern matching rule for detecting array accesses.
#[derive(Debug, Clone)]
pub struct ArrayPattern {
    /// Human-readable name for this pattern.
    pub name: &'static str,
    /// The minimum scale factor this pattern matches.
    pub min_scale: u64,
    /// The maximum scale factor this pattern matches.
    pub max_scale: u64,
    /// Whether this pattern requires a known base pointer type.
    pub requires_typed_base: bool,
}

impl ArrayPattern {
    /// Create a new pattern.
    #[must_use]
    pub const fn new(
        name: &'static str,
        min_scale: u64,
        max_scale: u64,
        requires_typed_base: bool,
    ) -> Self {
        Self {
            name,
            min_scale,
            max_scale,
            requires_typed_base,
        }
    }

    /// Check if a given scale matches this pattern.
    #[must_use]
    pub const fn matches_scale(&self, scale: u64) -> bool {
        scale >= self.min_scale && scale <= self.max_scale
    }
}

/// Built-in patterns for common array element sizes.
pub static COMMON_ARRAY_PATTERNS: &[ArrayPattern] = &[
    ArrayPattern::new("byte_array", 1, 1, false),
    ArrayPattern::new("short_array", 2, 2, false),
    ArrayPattern::new("int_array", 4, 4, false),
    ArrayPattern::new("long_array", 8, 8, false),
    ArrayPattern::new("vector_array", 16, 32, false),
    ArrayPattern::new("struct_array", 9, 4096, true),
];

// ── BoundsCheck ───────────────────────────────────────────────────────────────

/// A detected bounds check guarding an array access.
#[derive(Debug, Clone)]
pub struct BoundsCheck {
    /// The index variable being checked.
    pub index_var: String,
    /// Comparison operator as string (e.g. `"<"`, `"<="`, `">="`, `"!="`).
    pub operator: String,
    /// The bound value (the array length or last valid index).
    pub bound: i64,
    /// Whether the bound is the array length (exclusive) or last index (inclusive).
    pub is_exclusive: bool,
}

impl BoundsCheck {
    /// Create a standard less-than bounds check: `index < length`.
    #[must_use]
    pub fn lt(index_var: impl Into<String>, length: i64) -> Self {
        Self {
            index_var: index_var.into(),
            operator: "<".to_string(),
            bound: length,
            is_exclusive: true,
        }
    }

    /// Create a less-than-or-equal bounds check: `index <= last_idx`.
    #[must_use]
    pub fn le(index_var: impl Into<String>, last_idx: i64) -> Self {
        Self {
            index_var: index_var.into(),
            operator: "<=".to_string(),
            bound: last_idx,
            is_exclusive: false,
        }
    }

    /// Return the inferred array length.
    #[must_use]
    pub const fn inferred_length(&self) -> i64 {
        if self.is_exclusive {
            self.bound
        } else {
            self.bound + 1
        }
    }
}

// ── MultiDimArrayInfo ─────────────────────────────────────────────────────────

/// Information about a multi-dimensional array.
#[derive(Debug, Clone)]
pub struct MultiDimArrayInfo {
    /// Base variable name.
    pub base: String,
    /// List of (`dimension_size`, `stride_bytes`) pairs, outermost first.
    pub dimensions: Vec<(u64, u64)>,
    /// Innermost element size.
    pub element_size: ElementSize,
}

impl MultiDimArrayInfo {
    /// Create a 2D array descriptor.
    #[must_use]
    pub fn new_2d(
        base: impl Into<String>,
        rows: u64,
        cols: u64,
        element_size: ElementSize,
    ) -> Self {
        let inner_stride = element_size.bytes();
        let outer_stride = cols * inner_stride;
        Self {
            base: base.into(),
            dimensions: vec![(rows, outer_stride), (cols, inner_stride)],
            element_size,
        }
    }

    /// Compute the flat offset for indices [i][j].
    #[must_use]
    pub fn flat_offset(&self, indices: &[u64]) -> u64 {
        let mut offset = 0u64;
        for (dim_idx, &idx) in indices.iter().enumerate() {
            if let Some((_, stride)) = self.dimensions.get(dim_idx) {
                offset += idx * stride;
            }
        }
        offset
    }

    /// Return the total array size in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        if self.dimensions.is_empty() {
            return 0;
        }
        let (outermost_dim, outermost_stride) = self.dimensions[0];
        outermost_dim * outermost_stride
    }
}

// ── ArrayType ─────────────────────────────────────────────────────────────────

/// A fully characterized array type.
#[derive(Debug, Clone)]
pub struct ArrayType {
    /// Inferred element type name.
    pub element_type: String,
    /// Inferred element size.
    pub element_size: ElementSize,
    /// Inferred length (0 = unknown).
    pub length: u64,
    /// Whether the length was inferred from a bounds check.
    pub length_from_bounds_check: bool,
    /// Whether this is multi-dimensional.
    pub is_multidim: bool,
    /// Multi-dimensional info, if detected.
    pub multidim: Option<MultiDimArrayInfo>,
}

impl ArrayType {
    /// Create a simple array type with known element size and unknown length.
    #[must_use]
    pub fn simple(element_size: ElementSize) -> Self {
        Self {
            element_type: element_size.c_type_name().to_string(),
            element_size,
            length: 0,
            length_from_bounds_check: false,
            is_multidim: false,
            multidim: None,
        }
    }

    /// Create an array type with a known length (from bounds check).
    #[must_use]
    pub fn with_length(element_size: ElementSize, length: u64) -> Self {
        Self {
            element_type: element_size.c_type_name().to_string(),
            element_size,
            length,
            length_from_bounds_check: true,
            is_multidim: false,
            multidim: None,
        }
    }

    /// Return a C-style type declaration.
    #[must_use]
    pub fn c_decl(&self, name: &str) -> String {
        if self.length > 0 {
            format!("{} {}[{}]", self.element_type, name, self.length)
        } else {
            format!("{} {}[]", self.element_type, name)
        }
    }
}

// ── ArrayDetector ─────────────────────────────────────────────────────────────

/// Detects array access patterns in a stream of address expressions.
///
/// An "address expression" is represented as the triple:
/// `(base_var, index_var, scale, const_offset)`.
#[derive(Debug)]
pub struct ArrayDetector {
    /// Accumulated array accesses per base variable.
    accesses: HashMap<String, Vec<ArrayAccess>>,
    /// Detected bounds checks per index variable.
    bounds_checks: HashMap<String, BoundsCheck>,
    /// Inferred array types per base variable.
    inferred_types: HashMap<String, ArrayType>,
    /// Whether to distinguish struct vs array accesses.
    distinguish_struct: bool,
    /// Struct field offset table: `base_var` → known offsets.
    struct_offsets: HashMap<String, Vec<u64>>,
}

impl ArrayDetector {
    /// Create a new array detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accesses: HashMap::new(),
            bounds_checks: HashMap::new(),
            inferred_types: HashMap::new(),
            distinguish_struct: true,
            struct_offsets: HashMap::new(),
        }
    }

    /// Register a struct's known field offsets for a base variable.
    pub fn register_struct_offsets(&mut self, base: &str, offsets: Vec<u64>) {
        self.struct_offsets.insert(base.to_string(), offsets);
    }

    /// Record an array access: `*(base + index*scale + offset)`.
    ///
    /// Returns `Some(ArrayAccess)` if the pattern looks like array access,
    /// or `None` if it looks like a struct field access.
    pub fn record_access(
        &mut self,
        base: &str,
        index_var: &str,
        scale: u64,
        const_offset: i64,
        is_write: bool,
    ) -> Option<ArrayAccess> {
        // Distinguish struct access: if scale==1 and const_offset is a known struct field.
        if self.distinguish_struct && scale == 1 && const_offset >= 0
            && let Some(fields) = self.struct_offsets.get(base) {
                let offset_u64 = u64::try_from(const_offset).unwrap_or(0);
                if fields.contains(&offset_u64) {
                    return None; // This is a struct field access
                }
            }

        // For scale > 0, this is likely an array access
        if scale == 0 {
            return None;
        }

        let elem_size = ElementSize::from_scale(scale);
        let expr_str = if const_offset == 0 {
            format!("*({base}+{index_var}*{scale})")
        } else {
            format!("*({base}+{index_var}*{scale}+{const_offset})")
        };

        let access = ArrayAccess {
            base: base.to_string(),
            index: ScaledIndex::with_offset(index_var, scale, const_offset),
            element_size: elem_size,
            is_write,
            expr_str,
        };

        self.accesses
            .entry(base.to_string())
            .or_default()
            .push(access.clone());

        // Update inferred type
        let current_ty = self.inferred_types.get(base).cloned();
        match current_ty {
            None => {
                self.inferred_types
                    .insert(base.to_string(), ArrayType::simple(elem_size));
            }
            Some(ty) if ty.element_size != elem_size
                // Conflicting sizes — keep the wider one
                && elem_size.bytes() > ty.element_size.bytes() => {
                    self.inferred_types
                        .insert(base.to_string(), ArrayType::simple(elem_size));
                }
            _ => {}
        }

        Some(access)
    }

    /// Record a bounds check: `index < bound` (`is_exclusive=true`) or `index <= bound`.
    pub fn record_bounds_check(&mut self, check: BoundsCheck) {
        let index = check.index_var.clone();
        self.bounds_checks.insert(index, check);
    }

    /// Finalize inference: apply bounds checks to refine array lengths.
    pub fn finalize(&mut self) {
        // For each base's accesses, find the associated index variable.
        let bases: Vec<String> = self.inferred_types.keys().cloned().collect();
        for base in bases {
            if let Some(accesses) = self.accesses.get(&base) {
                // Collect all index variables used for this base
                for acc in accesses {
                    let idx_var = &acc.index.index_var;
                    if let Some(check) = self.bounds_checks.get(idx_var) {
                        let raw_len = check.inferred_length();
                        let Ok(length) = u64::try_from(raw_len) else {
                            continue; // negative bound — skip
                        };
                        if let Some(ty) = self.inferred_types.get_mut(&base)
                            && (ty.length == 0 || length < ty.length) {
                                ty.length = length;
                                ty.length_from_bounds_check = true;
                            }
                    }
                }
            }
        }
    }

    /// Get all accesses for a given base variable.
    #[must_use]
    pub fn get_accesses(&self, base: &str) -> &[ArrayAccess] {
        self.accesses.get(base).map_or(&[], Vec::as_slice)
    }

    /// Get the inferred array type for a base variable.
    #[must_use]
    pub fn get_type(&self, base: &str) -> Option<&ArrayType> {
        self.inferred_types.get(base)
    }

    /// Get all inferred array types.
    #[must_use]
    pub fn all_types(&self) -> Vec<(&String, &ArrayType)> {
        self.inferred_types.iter().collect()
    }

    /// Detect if two consecutive accesses look like a 2D array.
    ///
    /// Heuristic: if we see `arr + i*N + j` and `arr + i*N + j + k` with k == `elem_size`,
    /// and N = dim * `elem_size`, infer a 2D array.
    #[must_use]
    pub fn detect_multidim(&self, base: &str) -> Option<MultiDimArrayInfo> {
        let accesses = self.accesses.get(base)?;
        if accesses.len() < 2 {
            return None;
        }

        // Find the most common scale and check for a larger stride multiple.
        let elem_scale = accesses[0].index.scale;
        let outer_scales: Vec<u64> = accesses
            .iter()
            .filter(|a| a.index.scale != elem_scale && a.index.scale > elem_scale)
            .map(|a| a.index.scale)
            .collect();

        if outer_scales.is_empty() {
            return None;
        }

        let outer_scale = outer_scales[0];
        if !outer_scale.is_multiple_of(elem_scale) {
            return None;
        }

        let cols = outer_scale / elem_scale;
        let elem_size = ElementSize::from_scale(elem_scale);
        Some(MultiDimArrayInfo::new_2d(base, 0, cols, elem_size))
    }

    /// Return a summary of all detected arrays as C declarations.
    #[must_use]
    pub fn generate_declarations(&self) -> Vec<String> {
        let mut decls = Vec::new();
        let mut entries: Vec<(&String, &ArrayType)> = self.inferred_types.iter().collect();
        entries.sort_by_key(|(k, _)| k.as_str());
        for (base, ty) in entries {
            decls.push(ty.c_decl(base));
        }
        decls
    }

    /// Count total array accesses across all detected arrays.
    #[must_use]
    pub fn total_access_count(&self) -> usize {
        self.accesses.values().map(Vec::len).sum()
    }

    /// Count distinct base variables with array accesses.
    #[must_use]
    pub fn distinct_array_count(&self) -> usize {
        self.inferred_types.len()
    }
}

impl Default for ArrayDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── PatternMatcher ────────────────────────────────────────────────────────────

/// Matches common array-access textual patterns in disassembly strings.
///
/// Recognizes patterns like:
/// - `[rax + rcx*4]`           → base=rax, index=rcx, scale=4
/// - `[rbx + rdi*8 + 0x10]`   → base=rbx, index=rdi, scale=8, offset=0x10
/// - `[rsp + rax]`             → base=rsp, index=rax, scale=1
#[derive(Debug, Default)]
pub struct PatternMatcher;

impl PatternMatcher {
    /// Create a new pattern matcher.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Try to parse an address expression string into its components.
    ///
    /// Returns `Some((base, index, scale, offset))` on success.
    #[must_use]
    pub fn parse_address_expr(expr: &str) -> Option<(String, String, u64, i64)> {
        // Strip brackets if present.
        let inner = expr.trim();
        let inner = if inner.starts_with('[') && inner.ends_with(']') {
            &inner[1..inner.len() - 1]
        } else {
            inner
        };

        let parts: Vec<&str> = inner.split('+').map(str::trim).collect();
        if parts.len() < 2 {
            return None;
        }

        let base = parts[0].to_string();

        // Look for `reg*scale` in subsequent parts.
        let mut index = String::new();
        let mut scale = 1u64;
        let mut offset = 0i64;

        for part in &parts[1..] {
            if part.contains('*') {
                let sub: Vec<&str> = part.split('*').collect();
                if sub.len() == 2 {
                    let reg = sub[0].trim();
                    let sc_str = sub[1].trim();
                    if let Ok(sc) = sc_str.parse::<u64>() {
                        index = reg.to_string();
                        scale = sc;
                        continue;
                    }
                    if let Some(hex) = sc_str.strip_prefix("0x")
                        && let Ok(sc) = u64::from_str_radix(hex, 16) {
                            index = reg.to_string();
                            scale = sc;
                            continue;
                        }
                }
            }
            // Numeric constant or hex offset
            let trimmed = part.trim();
            if let Ok(n) = trimmed.parse::<i64>() {
                offset += n;
            } else if let Some(hex) = trimmed.strip_prefix("0x") {
                if let Ok(n) = i64::from_str_radix(hex, 16) {
                    offset += n;
                }
            } else if index.is_empty() {
                // Register with no scale = scale of 1
                index = trimmed.to_string();
                scale = 1;
            }
        }

        if index.is_empty() {
            return None;
        }

        Some((base, index, scale, offset))
    }

    /// Batch-parse a list of address expressions.
    #[must_use]
    pub fn parse_batch(exprs: &[&str]) -> Vec<(String, String, u64, i64)> {
        exprs
            .iter()
            .filter_map(|e| Self::parse_address_expr(e))
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_element_size_from_scale() {
        assert_eq!(ElementSize::from_scale(4), ElementSize::Int);
        assert_eq!(ElementSize::from_scale(8), ElementSize::Long);
        assert_eq!(ElementSize::from_scale(3).bytes(), 3);
    }

    #[test]
    fn test_element_size_bytes() {
        assert_eq!(ElementSize::Byte.bytes(), 1);
        assert_eq!(ElementSize::Short.bytes(), 2);
        assert_eq!(ElementSize::Int.bytes(), 4);
        assert_eq!(ElementSize::Long.bytes(), 8);
    }

    #[test]
    fn test_array_access_c_expr() {
        let acc = ArrayAccess {
            base: "arr".to_string(),
            index: ScaledIndex::new("i", 4),
            element_size: ElementSize::Int,
            is_write: false,
            expr_str: "*(arr+i*4)".to_string(),
        };
        assert_eq!(acc.c_expr(), "arr[i]");
    }

    #[test]
    fn test_array_access_c_expr_with_offset() {
        let acc = ArrayAccess {
            base: "arr".to_string(),
            index: ScaledIndex::with_offset("i", 4, 2),
            element_size: ElementSize::Int,
            is_write: false,
            expr_str: String::new(),
        };
        assert_eq!(acc.c_expr(), "arr[i+2]");
    }

    #[test]
    fn test_bounds_check_inferred_length() {
        let c = BoundsCheck::lt("i", 10);
        assert_eq!(c.inferred_length(), 10);
        let c2 = BoundsCheck::le("j", 9);
        assert_eq!(c2.inferred_length(), 10);
    }

    #[test]
    fn test_multidim_flat_offset() {
        let arr = MultiDimArrayInfo::new_2d("matrix", 3, 4, ElementSize::Int);
        // row 1, col 2: offset = 1*4*4 + 2*4 = 16+8 = 24
        let off = arr.flat_offset(&[1, 2]);
        assert_eq!(off, 24);
    }

    #[test]
    fn test_multidim_total_size() {
        let arr = MultiDimArrayInfo::new_2d("mat", 3, 4, ElementSize::Int);
        // 3 rows * 4 cols * 4 bytes = 48
        assert_eq!(arr.total_size(), 48);
    }

    #[test]
    fn test_array_detector_record_access() {
        let mut det = ArrayDetector::new();
        let acc = det.record_access("arr", "i", 4, 0, false);
        assert!(acc.is_some());
        assert_eq!(det.total_access_count(), 1);
    }

    #[test]
    fn test_array_detector_infers_type() {
        let mut det = ArrayDetector::new();
        det.record_access("buf", "i", 1, 0, false);
        let ty = det.get_type("buf").unwrap();
        assert_eq!(ty.element_size, ElementSize::Byte);
    }

    #[test]
    fn test_array_detector_finalize_with_bounds() {
        let mut det = ArrayDetector::new();
        det.record_access("arr", "i", 4, 0, false);
        det.record_bounds_check(BoundsCheck::lt("i", 16));
        det.finalize();
        let ty = det.get_type("arr").unwrap();
        assert_eq!(ty.length, 16);
        assert!(ty.length_from_bounds_check);
    }

    #[test]
    fn test_array_detector_struct_offset_exclusion() {
        let mut det = ArrayDetector::new();
        det.register_struct_offsets("s", vec![0, 4, 8, 12]);
        // scale=1, offset=4 → known struct field → None
        let acc = det.record_access("s", "i", 1, 4, false);
        assert!(acc.is_none());
    }

    #[test]
    fn test_array_detector_struct_unknown_offset() {
        let mut det = ArrayDetector::new();
        det.register_struct_offsets("s", vec![0, 4]);
        // scale=1, offset=7 → not a known field → array access
        let acc = det.record_access("s", "i", 1, 7, false);
        assert!(acc.is_some());
    }

    #[test]
    fn test_pattern_matcher_simple() {
        let result = PatternMatcher::parse_address_expr("[rax + rcx*4]");
        assert!(result.is_some());
        let (base, index, scale, offset) = result.unwrap();
        assert_eq!(base, "rax");
        assert_eq!(index, "rcx");
        assert_eq!(scale, 4);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_pattern_matcher_with_offset() {
        let result = PatternMatcher::parse_address_expr("[rbx + rdi*8 + 0x10]");
        assert!(result.is_some());
        let (base, index, scale, offset) = result.unwrap();
        assert_eq!(base, "rbx");
        assert_eq!(index, "rdi");
        assert_eq!(scale, 8);
        assert_eq!(offset, 16);
    }

    #[test]
    fn test_pattern_matcher_no_scale() {
        let result = PatternMatcher::parse_address_expr("[rsp + rax]");
        assert!(result.is_some());
        let (base, index, scale, _offset) = result.unwrap();
        assert_eq!(base, "rsp");
        assert_eq!(index, "rax");
        assert_eq!(scale, 1);
    }

    #[test]
    fn test_array_type_c_decl() {
        let ty = ArrayType::with_length(ElementSize::Int, 32);
        let decl = ty.c_decl("nums");
        assert!(decl.contains("nums"));
        assert!(decl.contains("32"));
        assert!(decl.contains("uint32_t"));
    }

    #[test]
    fn test_array_type_c_decl_unknown_length() {
        let ty = ArrayType::simple(ElementSize::Long);
        let decl = ty.c_decl("ptrs");
        assert!(decl.contains("ptrs"));
        assert!(decl.contains("[]"));
    }

    #[test]
    fn test_detect_multidim() {
        let mut det = ArrayDetector::new();
        // Inner stride 4, outer stride 16 (4 cols)
        det.record_access("mat", "j", 4, 0, false);
        det.record_access("mat", "i", 16, 0, false);
        let multi = det.detect_multidim("mat");
        assert!(multi.is_some());
        let info = multi.unwrap();
        assert_eq!(info.dimensions[1].1, 4); // inner stride
    }

    #[test]
    fn test_generate_declarations() {
        let mut det = ArrayDetector::new();
        det.record_access("arr", "i", 4, 0, false);
        det.record_bounds_check(BoundsCheck::lt("i", 8));
        det.finalize();
        let decls = det.generate_declarations();
        assert!(!decls.is_empty());
        assert!(decls[0].contains("arr"));
    }

    #[test]
    fn test_pattern_matcher_batch() {
        let exprs = vec!["[rax + rcx*4]", "[rbx + rdx*8 + 0x20]", "invalid"];
        let results = PatternMatcher::parse_batch(&exprs);
        assert_eq!(results.len(), 2); // "invalid" should not parse
    }

    #[test]
    fn test_distinct_array_count() {
        let mut det = ArrayDetector::new();
        det.record_access("arr1", "i", 4, 0, false);
        det.record_access("arr2", "j", 8, 0, false);
        assert_eq!(det.distinct_array_count(), 2);
    }
}
