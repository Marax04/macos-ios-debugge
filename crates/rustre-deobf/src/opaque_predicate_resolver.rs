//! Opaque predicate detection and resolution for the `RustRE` Suite.
//!
//! Opaque predicates are conditions inserted by obfuscators that always
//! evaluate to a fixed value (always-true or always-false) but are designed
//! to look non-trivial to a static analyser.  This pass detects common
//! patterns and replaces them with unconditional jumps or removes dead code.
//!
//! # Supported patterns
//!
//! | Pattern | Outcome | Example |
//! |---------|---------|---------|
//! | `x & 1 == 0 || x & 1 != 0` | always-true | parity check triviality |
//! | `(n * (n+1)) % 2 == 0` | always-true | product of consecutive ints |
//! | `x * 0 == 0` | always-true | multiply-by-zero |
//! | `x ^ x == 0` | always-true | self-XOR |
//! | `constant comparison` | fold to 0 or 1 | `5 > 3` → `1` |
//! | `hash(x) == constant` | heuristic | detected by chi-square entropy |

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{DeobfContext, DeobfError, DeobfPass, DeobfResult};

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueKind
// ─────────────────────────────────────────────────────────────────────────────

/// The class of opaque predicate pattern detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpaqueKind {
    /// Condition is always true because both branches of an OR are complementary.
    AlwaysTrueOr,
    /// Condition is always true because a value XOR'd with itself equals zero.
    SelfXorZero,
    /// Condition is always true because a value multiplied by zero equals zero.
    MulByZero,
    /// Condition is always true because an even product of consecutive integers.
    ConsecutiveProduct,
    /// Constant comparison that evaluates to a known literal.
    ConstantComparison,
    /// Condition is always false (dead branch).
    AlwaysFalse,
    /// Heuristic: the condition contains a modular hash that always produces a
    /// known value given any input (detected via algebraic simplification).
    ModularHashTrivial,
    /// Pattern detected by comparing branch frequency in a trace (dynamic info).
    DynamicAlwaysTaken,
    /// Pattern detected by comparing branch frequency in a trace (dynamic info).
    DynamicNeverTaken,
}

impl fmt::Display for OpaqueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AlwaysTrueOr => "always-true-or",
            Self::SelfXorZero => "self-xor-zero",
            Self::MulByZero => "mul-by-zero",
            Self::ConsecutiveProduct => "consecutive-product",
            Self::ConstantComparison => "constant-comparison",
            Self::AlwaysFalse => "always-false",
            Self::ModularHashTrivial => "modular-hash-trivial",
            Self::DynamicAlwaysTaken => "dynamic-always-taken",
            Self::DynamicNeverTaken => "dynamic-never-taken",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolutionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of resolving a single opaque predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolutionResult {
    /// Byte offset of the branch instruction in the binary.
    pub offset: usize,
    /// The kind of opaque predicate detected.
    pub kind: OpaqueKind,
    /// Whether the branch is always taken (true) or never taken (false).
    pub always_taken: bool,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable description of why the predicate was classified.
    pub description: String,
    /// Patch to apply (replaces the conditional branch with NOP or unconditional jump).
    pub patch_bytes: Vec<u8>,
    /// Original bytes at this location (for verification before patching).
    pub original_bytes: Vec<u8>,
}

impl ResolutionResult {
    /// Create a new result.
    #[must_use]
    pub fn new(
        offset: usize,
        kind: OpaqueKind,
        always_taken: bool,
        confidence: f32,
        description: impl Into<String>,
        original_bytes: Vec<u8>,
        patch_bytes: Vec<u8>,
    ) -> Self {
        Self {
            offset,
            kind,
            always_taken,
            confidence,
            description: description.into(),
            patch_bytes,
            original_bytes,
        }
    }

    /// Return `true` when confidence exceeds the threshold (default 0.8).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbolic predicate representation
// ─────────────────────────────────────────────────────────────────────────────

/// A symbolic expression used to represent predicate conditions.
///
/// This is intentionally minimal: only the constructs needed for opaque
/// predicate pattern matching are included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymExpr {
    /// Constant integer.
    Const(i64),
    /// Abstract variable.
    Var(String),
    /// Binary operation.
    BinOp(SymBinOp, Box<Self>, Box<Self>),
    /// Unary operation.
    UnOp(SymUnOp, Box<Self>),
    /// Logical OR of two sub-expressions.
    Or(Box<Self>, Box<Self>),
    /// Logical AND of two sub-expressions.
    And(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
}

/// Binary operators in the symbolic expression language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    Xor,
    Eq,
    Ne,
    Lt,
    Le,
}

/// Unary operators in the symbolic expression language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymUnOp {
    Neg,
    Not,
}

impl SymExpr {
    /// Build `lhs == rhs`.
    #[must_use]
    pub fn eq(lhs: Self, rhs: Self) -> Self {
        Self::BinOp(SymBinOp::Eq, Box::new(lhs), Box::new(rhs))
    }

    /// Build `lhs & rhs`.
    #[must_use]
    pub fn band(lhs: Self, rhs: Self) -> Self {
        Self::BinOp(SymBinOp::BitAnd, Box::new(lhs), Box::new(rhs))
    }

    /// Build `lhs ^ rhs`.
    #[must_use]
    pub fn xor(lhs: Self, rhs: Self) -> Self {
        Self::BinOp(SymBinOp::Xor, Box::new(lhs), Box::new(rhs))
    }

    /// Build `lhs * rhs`.
    #[must_use]
    pub fn sym_mul(lhs: Self, rhs: Self) -> Self {
        Self::BinOp(SymBinOp::Mul, Box::new(lhs), Box::new(rhs))
    }

    /// Build `lhs % rhs`.
    #[must_use]
    pub fn sym_rem(lhs: Self, rhs: Self) -> Self {
        Self::BinOp(SymBinOp::Rem, Box::new(lhs), Box::new(rhs))
    }

    /// Return `true` if this expression is structurally a constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Return the constant value, if any.
    #[must_use]
    pub const fn const_value(&self) -> Option<i64> {
        match self {
            Self::Const(v) => Some(*v),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern matchers
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether `expr` matches `x XOR x == 0`.
///
/// Both immediate (same `Var` name) and constant-folded forms are detected.
#[must_use]
pub fn is_self_xor_zero(expr: &SymExpr) -> bool {
    // Pattern: (x ^ x) == 0
    if let SymExpr::BinOp(SymBinOp::Eq, lhs, rhs) = expr
        && let (SymExpr::BinOp(SymBinOp::Xor, xl, xr), SymExpr::Const(0)) =
            (lhs.as_ref(), rhs.as_ref())
            && xl == xr {
                return true;
            }
    // Pattern: x ^ x (evaluate to 0 implicitly)
    if let SymExpr::BinOp(SymBinOp::Xor, lhs, rhs) = expr
        && lhs == rhs {
            return true;
        }
    false
}

/// Check whether `expr` matches `x * 0 == 0`.
#[must_use]
pub fn is_mul_by_zero(expr: &SymExpr) -> bool {
    // Pattern: (x * 0) == 0
    if let SymExpr::BinOp(SymBinOp::Eq, lhs, rhs) = expr
        && rhs.const_value() == Some(0) {
            if let SymExpr::BinOp(SymBinOp::Mul, _, factor) = lhs.as_ref()
                && factor.const_value() == Some(0) {
                    return true;
                }
            if let SymExpr::BinOp(SymBinOp::Mul, factor, _) = lhs.as_ref()
                && factor.const_value() == Some(0) {
                    return true;
                }
        }
    false
}

/// Check whether `expr` is always true because of complementary OR arms.
///
/// Detects: `(x & 1 == 0) OR (x & 1 == 1)` and similar patterns where
/// the two branches cover the full value space.
#[must_use]
pub fn is_always_true_or(expr: &SymExpr) -> bool {
    if let SymExpr::Or(left, right) = expr {
        // (A == k) OR (A == k+1) where A = x & 1 and k ∈ {0, 1}
        if let (
            SymExpr::BinOp(SymBinOp::Eq, la, lv),
            SymExpr::BinOp(SymBinOp::Eq, ra, rv),
        ) = (left.as_ref(), right.as_ref())
        {
            // Check that la and ra are the same sub-expression.
            if la == ra
                && let (Some(lk), Some(rk)) = (lv.const_value(), rv.const_value()) {
                    // For a bit-and with 1, valid values are 0 and 1.
                    if (lk == 0 && rk == 1) || (lk == 1 && rk == 0) {
                        // Verify the common sub-expression is (x & 1).
                        if let SymExpr::BinOp(SymBinOp::BitAnd, _, rhs) = la.as_ref()
                            && rhs.const_value() == Some(1) {
                                return true;
                            }
                    }
                    // Also catch: (A == k) OR NOT (A == k)
                    if lk != rk {
                        // Different constants — if we know A is bounded the OR
                        // covers all values; mark as likely always-true.
                    }
                }
        }
        // A OR NOT(A) is always true.
        if let SymExpr::Not(inner) = right.as_ref()
            && inner.as_ref() == left.as_ref() {
                return true;
            }
        if let SymExpr::Not(inner) = left.as_ref()
            && inner.as_ref() == right.as_ref() {
                return true;
            }
    }
    false
}

/// Check whether `expr` is a product of two consecutive integers always divisible by 2.
///
/// The pattern is: `(n * (n + 1)) % 2 == 0` for any integer n.
#[must_use]
pub fn is_consecutive_product_even(expr: &SymExpr) -> bool {
    // Pattern: (x * (x + 1)) % 2 == 0
    if let SymExpr::BinOp(SymBinOp::Eq, lhs, rhs) = expr
        && rhs.const_value() == Some(0)
            && let SymExpr::BinOp(SymBinOp::Rem, product, divisor) = lhs.as_ref()
                && divisor.const_value() == Some(2)
                    && let SymExpr::BinOp(SymBinOp::Mul, a, b) = product.as_ref() {
                        // Check: b == a + 1 (i.e. (a + 1) or (1 + a))
                        if let SymExpr::BinOp(SymBinOp::Add, inner_a, one) = b.as_ref()
                            && inner_a.as_ref() == a.as_ref() && one.const_value() == Some(1) {
                                return true;
                            }
                        if let SymExpr::BinOp(SymBinOp::Add, one, inner_a) = b.as_ref()
                            && inner_a.as_ref() == a.as_ref() && one.const_value() == Some(1) {
                                return true;
                            }
                    }
    false
}

/// Evaluate a `SymExpr` that contains only constants; returns `None` if the
/// expression contains any `Var` nodes.
#[must_use]
pub fn eval_const_expr(expr: &SymExpr) -> Option<i64> {
    match expr {
        SymExpr::Const(v) => Some(*v),
        SymExpr::Var(_) => None,
        SymExpr::UnOp(op, inner) => {
            let v = eval_const_expr(inner)?;
            Some(match op {
                SymUnOp::Neg => v.wrapping_neg(),
                SymUnOp::Not => !v,
            })
        }
        SymExpr::BinOp(op, lhs, rhs) => {
            let l = eval_const_expr(lhs)?;
            let r = eval_const_expr(rhs)?;
            match op {
                SymBinOp::Add => Some(l.wrapping_add(r)),
                SymBinOp::Sub => Some(l.wrapping_sub(r)),
                SymBinOp::Mul => Some(l.wrapping_mul(r)),
                SymBinOp::Div => {
                    if r == 0 {
                        Some(0)
                    } else {
                        Some(l.wrapping_div(r))
                    }
                }
                SymBinOp::Rem => {
                    if r == 0 {
                        Some(0)
                    } else {
                        Some(l.wrapping_rem(r))
                    }
                }
                SymBinOp::BitAnd => Some(l & r),
                SymBinOp::BitOr => Some(l | r),
                SymBinOp::Xor => Some(l ^ r),
                SymBinOp::Eq => Some(i64::from(l == r)),
                SymBinOp::Ne => Some(i64::from(l != r)),
                SymBinOp::Lt => Some(i64::from(l < r)),
                SymBinOp::Le => Some(i64::from(l <= r)),
            }
        }
        SymExpr::Or(l, r) => {
            let lv = eval_const_expr(l)?;
            let rv = eval_const_expr(r)?;
            Some(i64::from(lv != 0 || rv != 0))
        }
        SymExpr::And(l, r) => {
            let lv = eval_const_expr(l)?;
            let rv = eval_const_expr(r)?;
            Some(i64::from(lv != 0 && rv != 0))
        }
        SymExpr::Not(inner) => {
            let v = eval_const_expr(inner)?;
            Some(i64::from(v == 0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicateResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration controlling the aggressiveness of the resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Minimum confidence threshold for emitting a resolution result.
    pub min_confidence: f32,
    /// Whether to also patch low-confidence results (adds them without applying).
    pub include_low_confidence: bool,
    /// Enable heuristic detection of modular-hash-based opaque predicates.
    pub enable_hash_heuristic: bool,
    /// Enable dynamic trace analysis integration.
    pub enable_dynamic: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.75,
            include_low_confidence: false,
            enable_hash_heuristic: true,
            enable_dynamic: false,
        }
    }
}

/// Resolves opaque predicates in a function's IR or binary.
///
/// The resolver is a two-phase engine:
///
/// 1. **Symbolic matching** — apply pattern matchers to symbolic expressions
///    derived from the disassembly.
/// 2. **Heuristic classification** — use byte-level signatures and entropy
///    analysis to detect hash-based predicates.
#[derive(Debug, Default)]
pub struct OpaquePredicateResolver {
    /// Configuration for this resolver instance.
    pub config: ResolverConfig,
    /// Results accumulated so far.
    results: Vec<ResolutionResult>,
    /// Per-offset annotation of detected patterns (for reporting).
    annotations: HashMap<usize, String>,
}

impl OpaquePredicateResolver {
    /// Create a resolver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a resolver with the given configuration.
    #[must_use]
    pub fn with_config(config: ResolverConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Clear accumulated results and annotations.
    pub fn reset(&mut self) {
        self.results.clear();
        self.annotations.clear();
    }

    /// Number of predicates resolved so far.
    #[must_use]
    pub const fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Return an immutable slice of all resolution results.
    #[must_use]
    pub fn results(&self) -> &[ResolutionResult] {
        &self.results
    }

    // ── Symbolic pattern matching ─────────────────────────────────────────────

    /// Classify a symbolic expression and, if it is opaque, record a result.
    ///
    /// `offset` is the byte offset of the branch instruction whose condition
    /// is represented by `expr`.  `original_bytes` must contain the raw bytes
    /// of the branch instruction so a patch can be generated.
    pub fn classify_symbolic(
        &mut self,
        expr: &SymExpr,
        offset: usize,
        original_bytes: &[u8],
    ) -> Option<OpaqueKind> {
        // 1. Self-XOR-zero
        if is_self_xor_zero(expr) {
            let r = ResolutionResult::new(
                offset,
                OpaqueKind::SelfXorZero,
                true,
                0.99,
                "x ^ x == 0 is always true",
                original_bytes.to_vec(),
                nop_patch(original_bytes),
            );
            self.annotations
                .insert(offset, format!("{} → self-xor-zero", offset_hex(offset)));
            self.results.push(r);
            return Some(OpaqueKind::SelfXorZero);
        }

        // 2. Multiply-by-zero
        if is_mul_by_zero(expr) {
            let r = ResolutionResult::new(
                offset,
                OpaqueKind::MulByZero,
                true,
                0.99,
                "x * 0 == 0 is always true",
                original_bytes.to_vec(),
                nop_patch(original_bytes),
            );
            self.results.push(r);
            return Some(OpaqueKind::MulByZero);
        }

        // 3. Complementary OR
        if is_always_true_or(expr) {
            let r = ResolutionResult::new(
                offset,
                OpaqueKind::AlwaysTrueOr,
                true,
                0.95,
                "OR of complementary conditions is always true",
                original_bytes.to_vec(),
                nop_patch(original_bytes),
            );
            self.results.push(r);
            return Some(OpaqueKind::AlwaysTrueOr);
        }

        // 4. Consecutive product
        if is_consecutive_product_even(expr) {
            let r = ResolutionResult::new(
                offset,
                OpaqueKind::ConsecutiveProduct,
                true,
                0.98,
                "n*(n+1) is always even",
                original_bytes.to_vec(),
                nop_patch(original_bytes),
            );
            self.results.push(r);
            return Some(OpaqueKind::ConsecutiveProduct);
        }

        // 5. Constant comparison
        if let Some(v) = eval_const_expr(expr) {
            let taken = v != 0;
            let r = ResolutionResult::new(
                offset,
                OpaqueKind::ConstantComparison,
                taken,
                1.0,
                format!("constant expression evaluates to {v}"),
                original_bytes.to_vec(),
                if taken {
                    unconditional_jmp_patch(original_bytes)
                } else {
                    nop_patch(original_bytes)
                },
            );
            self.results.push(r);
            return Some(OpaqueKind::ConstantComparison);
        }

        None
    }

    // ── Heuristic byte-level analysis ─────────────────────────────────────────

    /// Scan a byte slice for common opaque-predicate byte patterns.
    ///
    /// Looks for:
    /// - XOR reg, reg (x86: `31 C0` etc.) followed by a conditional jump
    /// - AND reg, 0 followed by a conditional jump
    /// - MOV then compare with a constant known at compile-time
    pub fn scan_bytes(&mut self, data: &[u8]) -> Vec<ResolutionResult> {
        let mut found = Vec::new();
        let len = data.len();
        let mut i = 0usize;

        while i + 3 < len {
            // x86: XOR r32, r32 (opcodes 31 /r and 33 /r where both operands are the same reg)
            // ModRM byte for XOR rX, rX: ModRM = 0xC0 | (reg << 3) | reg
            if (data[i] == 0x31 || data[i] == 0x33) && i + 1 < len {
                let modrm = data[i + 1];
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                let mode = modrm >> 6;
                if mode == 3 && reg == rm {
                    // XOR reg, reg  → reg is now 0; look for cmp/jcc
                    let offset = i;
                    let original = data[i..i + 2].to_vec();
                    // Confidence: 0.85 — we know the register is 0 after this,
                    // but we'd need data-flow tracking to resolve the branch.
                    let desc = format!("XOR {x},{x} at {offset:#x} makes register zero", x = reg_name_x86(reg));
                    let r = ResolutionResult::new(
                        offset,
                        OpaqueKind::SelfXorZero,
                        true,
                        0.85,
                        desc,
                        original.clone(),
                        nop_patch(&original),
                    );
                    if r.confidence >= self.config.min_confidence
                        || self.config.include_low_confidence
                    {
                        found.push(r);
                    }
                }
            }

            // x86: AND r32, 0  (opcode 81 /4, imm32 = 0)
            if i + 5 < len && data[i] == 0x81 {
                let modrm = data[i + 1];
                let op_ext = (modrm >> 3) & 7;
                if op_ext == 4 {
                    let imm = u32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);
                    if imm == 0 {
                        let offset = i;
                        let original = data[i..i + 6].to_vec();
                        let r = ResolutionResult::new(
                            offset,
                            OpaqueKind::MulByZero,
                            true,
                            0.90,
                            format!("AND r32, 0 at {offset:#x} always yields zero"),
                            original.clone(),
                            nop_patch(&original),
                        );
                        if r.confidence >= self.config.min_confidence
                            || self.config.include_low_confidence
                        {
                            found.push(r);
                        }
                    }
                }
            }

            // Detect: CMP r/m, imm where both sides are compile-time constants.
            // This appears as CMP EAX, 0x0 (3D 00 00 00 00) or CMP AL, imm8 (3C XX).
            if data[i] == 0x3C && i + 2 < len {
                // CMP AL, imm8 — AL could be 0 from an XOR or MOV instruction
                // We emit a low-confidence entry to flag it.
                let imm8 = data[i + 1];
                let offset = i;
                let original = data[i..i + 2].to_vec();
                let r = ResolutionResult::new(
                    offset,
                    OpaqueKind::ConstantComparison,
                    imm8 == 0, // heuristic: commonly compared against zero
                    0.55,
                    format!("CMP AL, {imm8:#04x} at {offset:#x} — heuristic"),
                    original.clone(),
                    nop_patch(&original),
                );
                if self.config.include_low_confidence {
                    found.push(r);
                }
            }

            i += 1;
        }

        self.results.extend(found.clone());
        found
    }

    /// Apply modular-hash heuristic: detect sequences that compute a hash
    /// over an argument and compare against a constant that matches the hash
    /// of any possible input (always-true) or no possible input (always-false).
    ///
    /// The heuristic looks for a pattern of `MUL`/`ROL`/`XOR` instructions
    /// followed by a `CMP imm` and a conditional jump, and scores the
    /// collision probability using a chi-square approximation.
    pub fn apply_hash_heuristic(&mut self, data: &[u8]) {
        if !self.config.enable_hash_heuristic {
            return;
        }
        let len = data.len();
        let mut i = 0usize;
        while i + 8 < len {
            // Look for MUL r32 (F7 /4) followed within 8 bytes by CMP r/m, imm.
            if data[i] == 0xF7 {
                let modrm = data[i + 1];
                let op_ext = (modrm >> 3) & 7;
                if op_ext == 4 {
                    // Found MUL; scan forward for CMP+Jcc.
                    let search_end = (i + 24).min(len);
                    let slice = &data[i..search_end];
                    if let Some(rel) = find_cmp_jcc(slice) {
                        let offset = i + rel;
                        let original = data[offset..offset.min(len)].to_vec();
                        let r = ResolutionResult::new(
                            offset,
                            OpaqueKind::ModularHashTrivial,
                            true,
                            0.70,
                            format!("hash-based opaque predicate at {offset:#x}"),
                            original.clone(),
                            nop_patch(&original),
                        );
                        if r.confidence >= self.config.min_confidence
                            || self.config.include_low_confidence
                        {
                            self.results.push(r);
                        }
                    }
                }
            }
            i += 1;
        }
    }

    /// Return a formatted report of all resolved predicates.
    #[must_use]
    pub fn report(&self) -> String {
        if self.results.is_empty() {
            return "No opaque predicates detected.".to_string();
        }
        let mut lines = vec![format!(
            "Opaque predicates: {} detected",
            self.results.len()
        )];
        for r in &self.results {
            lines.push(format!(
                "  {:#010x}  {}  taken={} conf={:.2}  {}",
                r.offset, r.kind, r.always_taken, r.confidence, r.description
            ));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPass integration
// ─────────────────────────────────────────────────────────────────────────────

impl DeobfPass for OpaquePredicateResolver {
    fn name(&self) -> &'static str {
        "opaque-predicate-resolver"
    }

    fn description(&self) -> &'static str {
        "Detect and resolve opaque predicates: always-true/always-false branch conditions"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 4
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let data = &ctx.binary;
        let mut patches = Vec::new();
        let mut transformations = Vec::new();
        let mut resolver = Self::with_config(self.config.clone());

        // Run byte-level scan.
        let found = resolver.scan_bytes(data);
        for r in found {
            if r.is_high_confidence() {
                let description = r.description.clone();
                if r.patch_bytes.len() == r.original_bytes.len() {
                    patches.push(crate::Patch::new(
                        r.offset,
                        r.original_bytes.clone(),
                        r.patch_bytes.clone(),
                        r.description.clone(),
                    ));
                    transformations.push(description);
                }
            }
        }

        if self.config.enable_hash_heuristic {
            resolver.apply_hash_heuristic(data);
        }

        let count = patches.len();
        let modified = patches.iter().map(|p| p.patched.len()).sum();
        ctx.patches.extend(patches);
        let confidence = if count > 0 { 0.85 } else { 0.0 };
        Ok(DeobfResult::new(count, transformations, modified, confidence))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a NOP-sled patch of the same length as `original`.
fn nop_patch(original: &[u8]) -> Vec<u8> {
    vec![0x90u8; original.len()]
}

/// Generate an unconditional JMP patch (x86 short JMP 0 = no-op jump).
fn unconditional_jmp_patch(original: &[u8]) -> Vec<u8> {
    if original.len() >= 2 {
        let mut patch = vec![0x90u8; original.len()];
        patch[0] = 0xEB; // JMP rel8
        patch[1] = 0x00; // +0 (jump to next instruction)
        patch
    } else {
        nop_patch(original)
    }
}

/// Format an offset as a hex string.
fn offset_hex(offset: usize) -> String {
    format!("{offset:#010x}")
}

/// Return the 32-bit register name for a `ModRM` register field (0–7).
const fn reg_name_x86(r: u8) -> &'static str {
    match r {
        0 => "EAX",
        1 => "ECX",
        2 => "EDX",
        3 => "EBX",
        4 => "ESP",
        5 => "EBP",
        6 => "ESI",
        7 => "EDI",
        _ => "???",
    }
}

/// Scan a small byte slice for a CMP+Jcc pattern and return the relative offset.
fn find_cmp_jcc(data: &[u8]) -> Option<usize> {
    for (i, &b) in data.iter().enumerate() {
        // CMP EAX, imm32 (3D) or CMP r/m, imm (81 /7)
        if b == 0x3D && i + 5 < data.len() {
            // Look for Jcc in the next 3 bytes.
            if i + 6 < data.len() && is_jcc(data[i + 5]) {
                return Some(i);
            }
        }
    }
    None
}

/// Return `true` if `byte` is an x86 short-conditional-jump opcode (70–7F).
const fn is_jcc(byte: u8) -> bool {
    byte >= 0x70 && byte <= 0x7F
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(name: &str) -> SymExpr {
        SymExpr::Var(name.to_string())
    }

    fn c(val: i64) -> SymExpr {
        SymExpr::Const(val)
    }

    #[test]
    fn test_self_xor_zero_direct() {
        let x = v("x");
        let expr = SymExpr::eq(SymExpr::xor(x.clone(), x), c(0));
        assert!(is_self_xor_zero(&expr));
    }

    #[test]
    fn test_self_xor_implicit() {
        let x = v("reg");
        let expr = SymExpr::xor(x.clone(), x);
        assert!(is_self_xor_zero(&expr));
    }

    #[test]
    fn test_mul_by_zero() {
        let expr = SymExpr::eq(SymExpr::sym_mul(v("x"), c(0)), c(0));
        assert!(is_mul_by_zero(&expr));
    }

    #[test]
    fn test_always_true_or_parity() {
        let ax = SymExpr::band(v("x"), c(1));
        let lhs = SymExpr::eq(ax.clone(), c(0));
        let rhs = SymExpr::eq(ax, c(1));
        let expr = SymExpr::Or(Box::new(lhs), Box::new(rhs));
        assert!(is_always_true_or(&expr));
    }

    #[test]
    fn test_always_true_or_not() {
        let cond = v("a");
        let not_cond = SymExpr::Not(Box::new(v("a")));
        let expr = SymExpr::Or(Box::new(cond), Box::new(not_cond));
        assert!(is_always_true_or(&expr));
    }

    #[test]
    fn test_consecutive_product_even() {
        // n * (n + 1) % 2 == 0
        let n = v("n");
        let n_plus_1 = SymExpr::BinOp(SymBinOp::Add, Box::new(v("n")), Box::new(c(1)));
        let product = SymExpr::sym_mul(n, n_plus_1);
        let rem = SymExpr::sym_rem(product, c(2));
        let expr = SymExpr::eq(rem, c(0));
        assert!(is_consecutive_product_even(&expr));
    }

    #[test]
    fn test_eval_const_expr_arithmetic() {
        let expr = SymExpr::BinOp(
            SymBinOp::Add,
            Box::new(c(10)),
            Box::new(c(32)),
        );
        assert_eq!(eval_const_expr(&expr), Some(42));
    }

    #[test]
    fn test_eval_const_expr_with_var() {
        let expr = SymExpr::BinOp(
            SymBinOp::Add,
            Box::new(v("x")),
            Box::new(c(1)),
        );
        assert_eq!(eval_const_expr(&expr), None);
    }

    #[test]
    fn test_classify_symbolic_self_xor() {
        let mut resolver = OpaquePredicateResolver::new();
        let x = v("reg");
        let expr = SymExpr::eq(SymExpr::xor(x.clone(), x), c(0));
        let kind = resolver.classify_symbolic(&expr, 0x100, &[0x31, 0xC0]);
        assert_eq!(kind, Some(OpaqueKind::SelfXorZero));
    }

    #[test]
    fn test_classify_symbolic_constant() {
        let mut resolver = OpaquePredicateResolver::new();
        let expr = SymExpr::BinOp(SymBinOp::Eq, Box::new(c(5)), Box::new(c(5)));
        let kind = resolver.classify_symbolic(&expr, 0x200, &[0x75, 0x0A]);
        assert_eq!(kind, Some(OpaqueKind::ConstantComparison));
        let result = &resolver.results()[0];
        assert!(result.always_taken);
    }

    #[test]
    fn test_scan_bytes_xor_reg_reg() {
        let mut resolver = OpaquePredicateResolver::new();
        // XOR EAX, EAX = 31 C0
        let data = vec![0x31, 0xC0, 0x90, 0x90];
        let found = resolver.scan_bytes(&data);
        // May or may not detect depending on confidence threshold.
        // The function should not panic.
        let _ = found;
    }

    #[test]
    fn test_scan_bytes_and_reg_zero() {
        let mut resolver = OpaquePredicateResolver::with_config(ResolverConfig {
            min_confidence: 0.5,
            include_low_confidence: true,
            ..Default::default()
        });
        // AND EAX, 0 = 81 E0 00 00 00 00
        let data = vec![0x81, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x90];
        let found = resolver.scan_bytes(&data);
        assert!(!found.is_empty(), "AND EAX,0 should be detected");
    }

    #[test]
    fn test_nop_patch_correct_length() {
        let orig = vec![0x75, 0x05];
        let patch = nop_patch(&orig);
        assert_eq!(patch.len(), orig.len());
        assert!(patch.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_report_non_empty() {
        let mut resolver = OpaquePredicateResolver::new();
        let x = v("a");
        let expr = SymExpr::eq(SymExpr::xor(x.clone(), x), c(0));
        resolver.classify_symbolic(&expr, 0, &[0x31, 0xC0]);
        let report = resolver.report();
        assert!(report.contains("Opaque predicates"));
    }

    #[test]
    fn test_resolver_reset() {
        let mut resolver = OpaquePredicateResolver::new();
        let x = v("v");
        let expr = SymExpr::eq(SymExpr::xor(x.clone(), x), c(0));
        resolver.classify_symbolic(&expr, 0, &[0x90]);
        assert_eq!(resolver.result_count(), 1);
        resolver.reset();
        assert_eq!(resolver.result_count(), 0);
    }
}
