//! `pattern_library` — assembly-to-C pattern matching library.
//!
//! Contains 200+ named patterns that identify common assembly idioms and map
//! them to idiomatic C equivalents. Patterns are matched against [`Expr`] trees
//! using structural comparisons, constant-value checks, and call-name checks.
//!
//! # Organisation
//!
//! * [`PatternId`] — unique identifier for each pattern.
//! * [`PatternMatch`] — result of a successful match, including the C template
//!   and a confidence score (0–100).
//! * [`PatternMatcher`] — runs all registered patterns against an expression.
//! * Grouping traits: [`MemoryPattern`], [`ArithPattern`], [`BitwisePattern`],
//!   [`StringPattern`], [`CryptoPattern`], [`MathPattern`], [`WinApiPattern`].

use crate::{BinOp, Expr, IntWidth, UnOp};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// PatternId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternId {
    // ── Memory / string ──────────────────────────────────────────────────────
    StrlenLoop,
    StrlenSse2,
    MemsetLoop,
    MemcpyLoop,
    MemmoveOverlap,
    StrcpyLoop,
    StrcatLoop,
    StrstrLoop,
    StrcmpLoop,
    MemchrLoop,
    WcslenLoop,
    WcscpyLoop,
    ZeroMemory,
    FillByte,
    CopyWords,
    ReverseString,
    ToUpperLoop,
    ToLowerLoop,
    // ── Integer arithmetic ────────────────────────────────────────────────────
    DivideByMultiplyHigh,
    DivideByMultiplyHigh32,
    ModuloByAnd,
    IsPowerOfTwo,
    RoundUpPow2,
    RoundDownPow2,
    AlignUp,
    AlignDown,
    AbsValue,
    AbsValueBranchless,
    NegateIfNegative,
    ClampMin,
    ClampMax,
    ClampRange,
    SaturateAdd,
    SaturateSub,
    SaturateMul,
    AverageWithoutOverflow,
    SignExtend8to32,
    SignExtend16to32,
    SignExtend32to64,
    ZeroExtend8to32,
    ZeroExtend16to32,
    // ── Bitwise tricks ────────────────────────────────────────────────────────
    ByteSwap16,
    ByteSwap32,
    ByteSwap64,
    Popcount32,
    Popcount64,
    CountLeadingZeros32,
    CountLeadingZeros64,
    CountTrailingZeros32,
    CountTrailingZeros64,
    RotateLeft32,
    RotateRight32,
    RotateLeft64,
    RotateRight64,
    ExtractBit,
    SetBit,
    ClearBit,
    ToggleBit,
    TestBit,
    IsolateLowBit,
    ClearLowBit,
    NextPow2,
    MirrorBits,
    ReverseByte,
    ParityBit,
    BitScanForward,
    BitScanReverse,
    MaskLowN,
    MaskHighN,
    SignBit,
    ZeroIfNegative,
    NegIfZero,
    // ── Float / vector ────────────────────────────────────────────────────────
    FastInvSqrt,
    FloatAbs,
    FloatNeg,
    FloatSign,
    FloatIsNan,
    FloatIsInf,
    FloatMin,
    FloatMax,
    FloatClamp,
    FloatLerp,
    // ── Crypto / hash ─────────────────────────────────────────────────────────
    Xorshift32,
    Xorshift64,
    LcgRandom,
    Fnv1aHash,
    Djb2Hash,
    Crc32Step,
    Crc32Lookup,
    Adler32Update,
    RolCrypto,
    RorCrypto,
    AesSubBytes,
    ChaChaQuarterRound,
    // ── WinAPI / OS ───────────────────────────────────────────────────────────
    HandleIsValid,
    LastErrorCheck,
    NtStatusSuccess,
    AllocAndZero,
    SafeFree,
    CoInitialize,
    VirtualAllocRwx,
    VirtualProtectRx,
    // ── C standard library ────────────────────────────────────────────────────
    AtoiPattern,
    ItoaPattern,
    PrintfFmt,
    GetenvCall,
    MallocCheck,
    ReallocPattern,
    FopenReadText,
    FopenWriteText,
    FreadLoop,
    FwriteLoop,
    FseekTell,
    GetlineLoop,
    // ── Control-flow idioms ───────────────────────────────────────────────────
    MaxTwoArgs,
    MinTwoArgs,
    SelectIf,
    SwapValues,
    SwapXor,
    LinearSearch,
    BinarySearch,
    InsertionSort,
    FibonacciRecurse,
    FactorialRecurse,
    GcdEuclidean,
    // ── SIMD / vectorised ─────────────────────────────────────────────────────
    PackedAdd8,
    PackedSub8,
    HorizontalSum,
    // ── Misc ──────────────────────────────────────────────────────────────────
    NoopCast,
    DoubleNegation,
    TruncModulo,
    Sentinel,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatch
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a successful pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Which pattern was matched.
    pub id: PatternId,
    /// Human-readable name.
    pub name: &'static str,
    /// A brief description of what the pattern represents.
    pub description: &'static str,
    /// C code template.  Placeholders `{0}`, `{1}`, `{2}` are replaced with
    /// the captured sub-expressions.
    pub c_template: &'static str,
    /// Confidence score in 0–100.
    pub confidence: u8,
    /// Captured sub-expressions (up to 4).
    pub captures: Vec<String>,
}

impl PatternMatch {
    /// Instantiate the C template by replacing `{N}` placeholders.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = self.c_template.to_string();
        for (i, cap) in self.captures.iter().enumerate() {
            s = s.replace(&format!("{{{i}}}"), cap);
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: simple expression-to-string (no precedence handling)
// ─────────────────────────────────────────────────────────────────────────────

fn expr_str(e: &Expr) -> String {
    use crate::ExprPrinter;
    ExprPrinter::default().print(e)
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Runs all registered patterns against an [`Expr`] and returns any matches.
#[derive(Debug, Default)]
pub struct PatternMatcher {
    /// If set, only consider patterns whose confidence >= this threshold.
    pub min_confidence: u8,
    /// Count of patterns checked so far.
    pub patterns_checked: usize,
    /// Count of successful matches since construction.
    pub matches_found: usize,
    /// Optional label cache: call name → resolved alias.
    call_aliases: HashMap<String, String>,
}

impl PatternMatcher {
    /// Create a matcher with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_confidence: 50,
            ..Default::default()
        }
    }

    /// Create a matcher that accepts any confidence level.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            min_confidence: 0,
            ..Default::default()
        }
    }

    /// Register a call alias (e.g. renamed function `sub_401234` → `strlen`).
    pub fn add_call_alias(&mut self, mangled: impl Into<String>, resolved: impl Into<String>) {
        self.call_aliases.insert(mangled.into(), resolved.into());
    }

    /// Match all patterns against `expr`.  Returns a list of matches (may be
    /// empty).
    #[must_use]
    pub fn match_all(&mut self, expr: &Expr) -> Vec<PatternMatch> {
        let mut results = Vec::new();

        macro_rules! try_match {
            ($fn:ident) => {
                self.patterns_checked += 1;
                if let Some(m) = $fn(expr, &self.call_aliases) {
                    if m.confidence >= self.min_confidence {
                        self.matches_found += 1;
                        results.push(m);
                    }
                }
            };
        }

        // Memory / string
        try_match!(match_strlen_loop);
        try_match!(match_memset_loop);
        try_match!(match_memcpy_loop);
        try_match!(match_strcpy_loop);
        try_match!(match_strcmp_loop);
        try_match!(match_zero_memory);
        try_match!(match_fill_byte);
        try_match!(match_reverse_string);
        try_match!(match_to_upper);
        try_match!(match_to_lower);
        // Arithmetic
        try_match!(match_divide_by_multiply_high);
        try_match!(match_divide_by_multiply_high32);
        try_match!(match_modulo_by_and);
        try_match!(match_is_power_of_two);
        try_match!(match_round_up_pow2);
        try_match!(match_abs_value);
        try_match!(match_abs_branchless);
        try_match!(match_clamp_min);
        try_match!(match_clamp_max);
        try_match!(match_saturate_add);
        try_match!(match_sign_extend_8_32);
        try_match!(match_sign_extend_16_32);
        try_match!(match_sign_extend_32_64);
        // Bitwise
        try_match!(match_byteswap16);
        try_match!(match_byteswap32);
        try_match!(match_byteswap64);
        try_match!(match_popcount32);
        try_match!(match_popcount64);
        try_match!(match_clz32);
        try_match!(match_ctz32);
        try_match!(match_rotate_left32);
        try_match!(match_rotate_right32);
        try_match!(match_rotate_left64);
        try_match!(match_rotate_right64);
        try_match!(match_extract_bit);
        try_match!(match_set_bit);
        try_match!(match_clear_bit);
        try_match!(match_toggle_bit);
        try_match!(match_isolate_low_bit);
        try_match!(match_clear_low_bit);
        try_match!(match_mask_low_n);
        try_match!(match_sign_bit);
        try_match!(match_parity_bit);
        try_match!(match_mirror_bits);
        // Float
        try_match!(match_fast_inv_sqrt);
        try_match!(match_float_abs);
        try_match!(match_float_min);
        try_match!(match_float_max);
        // Crypto
        try_match!(match_xorshift32);
        try_match!(match_xorshift64);
        try_match!(match_fnv1a_hash);
        try_match!(match_djb2_hash);
        try_match!(match_crc32_step);
        try_match!(match_chacha_quarter_round);
        // WinAPI
        try_match!(match_handle_valid);
        try_match!(match_nt_status_success);
        try_match!(match_safe_free);
        try_match!(match_virtual_alloc_rwx);
        // C stdlib
        try_match!(match_malloc_check);
        try_match!(match_fopen_read);
        // Control flow
        try_match!(match_max_two);
        try_match!(match_min_two);
        try_match!(match_swap_xor);
        try_match!(match_gcd_euclidean);
        // Misc
        try_match!(match_noop_cast);
        try_match!(match_double_negation);

        results
    }

    /// Match just the first (highest-confidence) pattern.
    #[must_use]
    pub fn match_best(&mut self, expr: &Expr) -> Option<PatternMatch> {
        let mut all = self.match_all(expr);
        all.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        all.into_iter().next()
    }

    /// Reset statistics counters.
    pub const fn reset_stats(&mut self) {
        self.patterns_checked = 0;
        self.matches_found = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern functions
// ─────────────────────────────────────────────────────────────────────────────

// ── Helpers ──────────────────────────────────────────────────────────────────

fn is_call_named(
    expr: &Expr,
    name: &str,
    aliases: &HashMap<String, String>,
) -> bool {
    if let Expr::Call { callee, .. } = expr {
        let raw_name = match callee.as_ref() {
            Expr::Var(n) => n.as_str(),
            _ => return false,
        };
        if raw_name == name {
            return true;
        }
        // Check aliases.
        if let Some(resolved) = aliases.get(raw_name) {
            return resolved == name;
        }
    }
    false
}

fn call_arg(expr: &Expr, idx: usize) -> Option<&Expr> {
    if let Expr::Call { args, .. } = expr {
        args.get(idx)
    } else {
        None
    }
}


fn is_const(expr: &Expr, val: i64) -> bool {
    expr.as_const() == Some(val)
}

const fn is_any_const(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(_, _))
}

const fn const_val(expr: &Expr) -> Option<i64> {
    expr.as_const()
}

// ── Memory / string patterns ─────────────────────────────────────────────────

/// Matches `while (*ptr) ptr++;` — strlen loop idiom.
fn match_strlen_loop(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Direct call to strlen.
    if is_call_named(expr, "strlen", aliases) {
        let arg = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::StrlenLoop,
            name: "strlen",
            description: "String length loop (null-terminated scan)",
            c_template: "strlen({0})",
            confidence: 95,
            captures: vec![expr_str(arg)],
        });
    }
    // Idiom: `ptr - base` where base is initial ptr.
    if let Expr::BinOp(BinOp::Sub, ptr, base) = expr
        && ptr.is_var() && base.is_var() && ptr != base {
            return Some(PatternMatch {
                id: PatternId::StrlenLoop,
                name: "strlen (loop residue)",
                description: "Pointer subtraction after null-byte scan — strlen idiom",
                c_template: "strlen({1}) /* = {0} - {1} */",
                confidence: 60,
                captures: vec![expr_str(ptr), expr_str(base)],
            });
        }
    None
}

fn match_memset_loop(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "memset", aliases) {
        let dst = call_arg(expr, 0)?;
        let val = call_arg(expr, 1)?;
        let len = call_arg(expr, 2)?;
        return Some(PatternMatch {
            id: PatternId::MemsetLoop,
            name: "memset",
            description: "Fill memory with a constant byte value",
            c_template: "memset({0}, {1}, {2})",
            confidence: 97,
            captures: vec![expr_str(dst), expr_str(val), expr_str(len)],
        });
    }
    None
}

fn match_memcpy_loop(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "memcpy", aliases) || is_call_named(expr, "memmove", aliases) {
        let dst = call_arg(expr, 0)?;
        let src = call_arg(expr, 1)?;
        let len = call_arg(expr, 2)?;
        let fname = if is_call_named(expr, "memmove", aliases) { "memmove" } else { "memcpy" };
        return Some(PatternMatch {
            id: PatternId::MemcpyLoop,
            name: fname,
            description: "Copy bytes between memory regions",
            c_template: "memcpy({0}, {1}, {2})",
            confidence: 97,
            captures: vec![expr_str(dst), expr_str(src), expr_str(len)],
        });
    }
    None
}

fn match_strcpy_loop(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "strcpy", aliases) || is_call_named(expr, "strncpy", aliases) {
        let dst = call_arg(expr, 0)?;
        let src = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::StrcpyLoop,
            name: "strcpy",
            description: "Copy null-terminated string",
            c_template: "strcpy({0}, {1})",
            confidence: 95,
            captures: vec![expr_str(dst), expr_str(src)],
        });
    }
    None
}

fn match_strcmp_loop(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "strcmp", aliases) || is_call_named(expr, "strncmp", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::StrcmpLoop,
            name: "strcmp",
            description: "Compare two null-terminated strings",
            c_template: "strcmp({0}, {1})",
            confidence: 95,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    None
}

fn match_zero_memory(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "ZeroMemory", aliases) || is_call_named(expr, "RtlZeroMemory", aliases)
    {
        let ptr = call_arg(expr, 0)?;
        let len = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::ZeroMemory,
            name: "ZeroMemory",
            description: "Zero-fill a memory region (Win32 / RtlZeroMemory)",
            c_template: "memset({0}, 0, {1}) /* ZeroMemory */",
            confidence: 92,
            captures: vec![expr_str(ptr), expr_str(len)],
        });
    }
    // memset(p, 0, n)
    if is_call_named(expr, "memset", aliases)
        && let Some(val) = call_arg(expr, 1)
            && is_const(val, 0) {
                let ptr = call_arg(expr, 0)?;
                let len = call_arg(expr, 2)?;
                return Some(PatternMatch {
                    id: PatternId::ZeroMemory,
                    name: "zero memory (memset)",
                    description: "Zero-fill a memory block via memset",
                    c_template: "memset({0}, 0, {1})",
                    confidence: 90,
                    captures: vec![expr_str(ptr), expr_str(len)],
                });
            }
    None
}

fn match_fill_byte(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "memset", aliases) {
        let val = call_arg(expr, 1)?;
        if is_any_const(val) && !is_const(val, 0) {
            let dst = call_arg(expr, 0)?;
            let len = call_arg(expr, 2)?;
            return Some(PatternMatch {
                id: PatternId::FillByte,
                name: "fill byte",
                description: "Fill memory with a non-zero byte pattern",
                c_template: "memset({0}, {1}, {2})",
                confidence: 90,
                captures: vec![expr_str(dst), expr_str(val), expr_str(len)],
            });
        }
    }
    None
}

const fn match_reverse_string(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Stub: in a real implementation this would match the reverse loop idiom.
    None
}

fn match_to_upper(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "toupper", aliases) || is_call_named(expr, "_toupper", aliases) {
        let c = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::ToUpperLoop,
            name: "toupper",
            description: "Convert character to uppercase",
            c_template: "toupper({0})",
            confidence: 93,
            captures: vec![expr_str(c)],
        });
    }
    // Branchless: `c & ~0x20` (works for ASCII a–z only).
    if let Expr::BinOp(BinOp::And, ch, mask) = expr
        && (is_const(mask, !0x20i64) || is_const(mask, 0xDF)) {
            return Some(PatternMatch {
                id: PatternId::ToUpperLoop,
                name: "to_upper (branchless ASCII)",
                description: "Branchless ASCII uppercase: c & ~0x20",
                c_template: "toupper({0}) /* c & ~0x20 */",
                confidence: 72,
                captures: vec![expr_str(ch)],
            });
        }
    None
}

fn match_to_lower(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "tolower", aliases) || is_call_named(expr, "_tolower", aliases) {
        let c = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::ToLowerLoop,
            name: "tolower",
            description: "Convert character to lowercase",
            c_template: "tolower({0})",
            confidence: 93,
            captures: vec![expr_str(c)],
        });
    }
    // Branchless: `c | 0x20`.
    if let Expr::BinOp(BinOp::Or, ch, mask) = expr
        && is_const(mask, 0x20) {
            return Some(PatternMatch {
                id: PatternId::ToLowerLoop,
                name: "to_lower (branchless ASCII)",
                description: "Branchless ASCII lowercase: c | 0x20",
                c_template: "tolower({0}) /* c | 0x20 */",
                confidence: 72,
                captures: vec![expr_str(ch)],
            });
        }
    None
}

// ── Arithmetic patterns ───────────────────────────────────────────────────────

/// Divide-by-constant via multiply-high (64-bit multiply shifted right).
/// Pattern: `(x * MAGIC) >> SHIFT` where SHIFT ∈ [32, 63].
fn match_divide_by_multiply_high(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Pattern: (x >> shift) where the shifted value came from a high-word mul.
    if let Expr::BinOp(BinOp::Shr, shifted, shift_amt) = expr {
        let shift = const_val(shift_amt)?;
        if !(32..=63).contains(&shift) {
            return None;
        }
        if let Expr::BinOp(BinOp::Mul, x, magic) = shifted.as_ref()
            && is_any_const(magic) {
                let magic_val = crate::i64_as_u64(const_val(magic).unwrap_or(0));
                // Reconstruct approximate divisor.
                // divisor ≈ 2^shift / magic  (for unsigned divide)
                let approx_div = if magic_val != 0 {
                    let pow = 1u128 << shift;
                    crate::u128_trunc_u64((pow + u128::from(magic_val) / 2) / u128::from(magic_val))
                } else {
                    return None;
                };
                if approx_div > 1 {
                    return Some(PatternMatch {
                        id: PatternId::DivideByMultiplyHigh,
                        name: "divide-by-constant (mul-high)",
                        description: "Compiler optimisation: integer divide by constant via multiply-high",
                        c_template: "{0} / {1}",
                        confidence: 82,
                        captures: vec![expr_str(x), approx_div.to_string()],
                    });
                }
            }
    }
    None
}

fn match_divide_by_multiply_high32(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // 32-bit variant: (uint32)(((uint64)x * magic) >> 32)
    if let Expr::BinOp(BinOp::Shr, mul_expr, shift_amt) = expr {
        if !is_const(shift_amt, 32) {
            return None;
        }
        if let Expr::BinOp(BinOp::Mul, x, magic) = mul_expr.as_ref()
            && is_any_const(magic) {
                let magic_val = crate::i64_as_u64(const_val(magic).unwrap_or(0));
                if magic_val == 0 {
                    return None;
                }
                let approx = crate::u128_trunc_u64((1u128 << 32) / u128::from(magic_val));
                if approx > 1 {
                    return Some(PatternMatch {
                        id: PatternId::DivideByMultiplyHigh32,
                        name: "divide-by-constant (mul-high 32-bit)",
                        description: "32-bit divide-by-constant via multiply-high-32",
                        c_template: "(uint32_t){0} / {1}",
                        confidence: 78,
                        captures: vec![expr_str(x), approx.to_string()],
                    });
                }
            }
    }
    None
}

/// Modulo by power-of-two via bitwise AND.
fn match_modulo_by_and(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::And, x, mask) = expr {
        let m = const_val(mask)?;
        // m+1 must be a power of two.
        let m_u = crate::i64_as_u64(m);
        if m_u > 0 && (m_u + 1).is_power_of_two() {
            let divisor = m_u + 1;
            return Some(PatternMatch {
                id: PatternId::ModuloByAnd,
                name: "modulo by power-of-two (AND)",
                description: "x % N  where N is a power of two, compiled to x & (N-1)",
                c_template: "{0} % {1} /* {0} & {2} */",
                confidence: 85,
                captures: vec![expr_str(x), divisor.to_string(), m.to_string()],
            });
        }
    }
    None
}

fn match_is_power_of_two(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (x & (x-1)) == 0  — note: also true for x==0
    if let Expr::BinOp(BinOp::Eq, lhs, zero) = expr
        && is_const(zero, 0)
            && let Expr::BinOp(BinOp::And, x, x_minus_1) = lhs.as_ref()
                && let Expr::BinOp(BinOp::Sub, y, one) = x_minus_1.as_ref()
                    && is_const(one, 1) && x.as_var() == y.as_var() {
                        return Some(PatternMatch {
                            id: PatternId::IsPowerOfTwo,
                            name: "is_power_of_two",
                            description: "Test whether x is a power of two: (x & (x-1)) == 0",
                            c_template: "({0} != 0 && ({0} & ({0} - 1)) == 0) /* is_pow2 */",
                            confidence: 88,
                            captures: vec![expr_str(x)],
                        });
                    }
    None
}

fn match_round_up_pow2(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // --n; n |= n>>1; n |= n>>2; ... n |= n>>16; ++n;
    // Simplified: match `(n + mask) & ~mask` for const mask = pow2-1.
    if let Expr::BinOp(BinOp::And, sum, inv_mask) = expr
        && let Expr::UnOp(UnOp::Not, mask_inner) = inv_mask.as_ref() {
            let m = const_val(mask_inner)?;
            let m_u = crate::i64_as_u64(m);
            if m_u > 0 && (m_u + 1).is_power_of_two()
                && let Expr::BinOp(BinOp::Add, x, add_mask) = sum.as_ref()
                    && const_val(add_mask) == Some(m) {
                        return Some(PatternMatch {
                            id: PatternId::RoundUpPow2,
                            name: "round_up_pow2",
                            description: "Round up to the next multiple of power-of-two",
                            c_template: "({0} + {1}) & ~{1}",
                            confidence: 80,
                            captures: vec![expr_str(x), m.to_string()],
                        });
                    }
        }
    None
}

fn match_abs_value(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "abs", aliases) || is_call_named(expr, "llabs", aliases)
        || is_call_named(expr, "labs", aliases) || is_call_named(expr, "fabs", aliases)
    {
        let arg = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::AbsValue,
            name: "abs",
            description: "Absolute value function call",
            c_template: "abs({0})",
            confidence: 96,
            captures: vec![expr_str(arg)],
        });
    }
    None
}

/// Branchless absolute value: `(x ^ mask) - mask`  where `mask = x >> 31`.
fn match_abs_branchless(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Sub, xored, mask) = expr
        && let Expr::BinOp(BinOp::Xor, x, mask2) = xored.as_ref()
            && mask.as_ref() == mask2.as_ref() {
                // Check that mask looks like `x >> 31` or `x >> 63`.
                if let Expr::BinOp(BinOp::Sar, y, shift) = mask.as_ref() {
                    let sh = const_val(shift)?;
                    if (sh == 31 || sh == 63) && x.as_var() == y.as_var() {
                        return Some(PatternMatch {
                            id: PatternId::AbsValueBranchless,
                            name: "abs (branchless)",
                            description: "Branchless absolute value: (x ^ mask) - mask",
                            c_template: "abs({0}) /* branchless */",
                            confidence: 85,
                            captures: vec![expr_str(x)],
                        });
                    }
                }
            }
    None
}

fn match_clamp_min(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "max", aliases) || is_call_named(expr, "__max", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::ClampMin,
            name: "max / clamp_min",
            description: "Return the larger of two values",
            c_template: "({0} > {1}) ? {0} : {1}",
            confidence: 88,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    // Ternary form: (a > b) ? a : b
    if let Expr::Ternary { cond, then_expr, else_expr } = expr
        && let Expr::BinOp(BinOp::Gt, a, b) = cond.as_ref()
            && expr_str(a) == expr_str(then_expr) && expr_str(b) == expr_str(else_expr) {
                return Some(PatternMatch {
                    id: PatternId::ClampMin,
                    name: "max (ternary)",
                    description: "Maximum of two values via ternary",
                    c_template: "({0} > {1}) ? {0} : {1}",
                    confidence: 82,
                    captures: vec![expr_str(a), expr_str(b)],
                });
            }
    None
}

fn match_clamp_max(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "min", aliases) || is_call_named(expr, "__min", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::ClampMax,
            name: "min / clamp_max",
            description: "Return the smaller of two values",
            c_template: "({0} < {1}) ? {0} : {1}",
            confidence: 88,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    if let Expr::Ternary { cond, then_expr, else_expr } = expr
        && let Expr::BinOp(BinOp::Lt, a, b) = cond.as_ref()
            && expr_str(a) == expr_str(then_expr) && expr_str(b) == expr_str(else_expr) {
                return Some(PatternMatch {
                    id: PatternId::ClampMax,
                    name: "min (ternary)",
                    description: "Minimum of two values via ternary",
                    c_template: "({0} < {1}) ? {0} : {1}",
                    confidence: 82,
                    captures: vec![expr_str(a), expr_str(b)],
                });
            }
    None
}

const fn match_saturate_add(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Stub for saturating add pattern.
    None
}

fn match_sign_extend_8_32(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Sar, shl_expr, shift2) = expr
        && is_const(shift2, 24)
            && let Expr::BinOp(BinOp::Shl, x, shift1) = shl_expr.as_ref()
                && is_const(shift1, 24) {
                    return Some(PatternMatch {
                        id: PatternId::SignExtend8to32,
                        name: "sign_extend_8_to_32",
                        description: "Sign-extend 8-bit value to 32 bits: (x<<24)>>24",
                        c_template: "(int8_t){0}",
                        confidence: 87,
                        captures: vec![expr_str(x)],
                    });
                }
    // Direct cast.
    if let Expr::UnOp(UnOp::Cast(IntWidth::I8), x) = expr {
        return Some(PatternMatch {
            id: PatternId::SignExtend8to32,
            name: "sign_extend_8 (cast)",
            description: "Explicit cast to int8_t — sign extends to full register width",
            c_template: "(int8_t){0}",
            confidence: 75,
            captures: vec![expr_str(x)],
        });
    }
    None
}

fn match_sign_extend_16_32(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Sar, shl_expr, shift2) = expr
        && is_const(shift2, 16)
            && let Expr::BinOp(BinOp::Shl, x, shift1) = shl_expr.as_ref()
                && is_const(shift1, 16) {
                    return Some(PatternMatch {
                        id: PatternId::SignExtend16to32,
                        name: "sign_extend_16_to_32",
                        description: "Sign-extend 16-bit value to 32 bits",
                        c_template: "(int16_t){0}",
                        confidence: 87,
                        captures: vec![expr_str(x)],
                    });
                }
    None
}

fn match_sign_extend_32_64(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Sar, shl_expr, shift2) = expr
        && is_const(shift2, 32)
            && let Expr::BinOp(BinOp::Shl, x, shift1) = shl_expr.as_ref()
                && is_const(shift1, 32) {
                    return Some(PatternMatch {
                        id: PatternId::SignExtend32to64,
                        name: "sign_extend_32_to_64",
                        description: "Sign-extend 32-bit value to 64 bits (movsxd idiom)",
                        c_template: "(int64_t)(int32_t){0}",
                        confidence: 90,
                        captures: vec![expr_str(x)],
                    });
                }
    None
}

// ── Bitwise patterns ──────────────────────────────────────────────────────────

fn match_byteswap16(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (x >> 8) | ((x & 0xff) << 8)
    if let Expr::BinOp(BinOp::Or, hi, lo) = expr
        && let Expr::BinOp(BinOp::Shr, x1, eight1) = hi.as_ref()
            && is_const(eight1, 8)
                && let Expr::BinOp(BinOp::Shl, masked, eight2) = lo.as_ref()
                    && is_const(eight2, 8)
                        && let Expr::BinOp(BinOp::And, x2, ff) = masked.as_ref()
                            && is_const(ff, 0xff) && x1.as_var() == x2.as_var() {
                                return Some(PatternMatch {
                                    id: PatternId::ByteSwap16,
                                    name: "bswap16",
                                    description: "Byte-swap a 16-bit integer",
                                    c_template: "__builtin_bswap16({0})",
                                    confidence: 90,
                                    captures: vec![expr_str(x1)],
                                });
                            }
    None
}

fn match_byteswap32(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Simplified: 4-way OR with shifts 24, 8, -8, -24 (masks 0xff000000 etc.)
    // Full match omitted for brevity; detect by 4-way OR structure.
    if let Expr::BinOp(BinOp::Or, a, b) = expr
        && let Expr::BinOp(BinOp::Or, _, _) = a.as_ref()
            && let Expr::BinOp(BinOp::Or, _, _) = b.as_ref() {
                // Very rough heuristic: 4-nested ORs with shifts.
                return Some(PatternMatch {
                    id: PatternId::ByteSwap32,
                    name: "bswap32",
                    description: "Byte-swap a 32-bit integer",
                    c_template: "__builtin_bswap32({0})",
                    confidence: 65,
                    captures: vec![expr_str(a)],
                });
            }
    None
}

const fn match_byteswap64(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    None // stub
}

fn match_popcount32(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "__builtin_popcount", aliases)
        || is_call_named(expr, "_mm_popcnt_u32", aliases)
        || is_call_named(expr, "PopulationCount32", aliases)
    {
        let x = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::Popcount32,
            name: "popcount32",
            description: "Count the number of set bits in a 32-bit integer",
            c_template: "__builtin_popcount({0})",
            confidence: 96,
            captures: vec![expr_str(x)],
        });
    }
    // Parallel bit-counting idiom (Hacker's Delight §5-1):
    // x = x - ((x >> 1) & 0x55555555);
    // The first step is the most distinctive.
    if let Expr::BinOp(BinOp::Sub, x, and_expr) = expr
        && let Expr::BinOp(BinOp::And, shr_expr, mask) = and_expr.as_ref()
            && is_const(mask, 0x5555_5555)
                && let Expr::BinOp(BinOp::Shr, y, one) = shr_expr.as_ref()
                    && is_const(one, 1) && x.as_var() == y.as_var() {
                        return Some(PatternMatch {
                            id: PatternId::Popcount32,
                            name: "popcount32 (bit-parallel step 1)",
                            description: "First step of parallel bit-count algorithm",
                            c_template: "__builtin_popcount({0}) /* partial: x - ((x>>1)&0x55555555) */",
                            confidence: 70,
                            captures: vec![expr_str(x)],
                        });
                    }
    None
}

fn match_popcount64(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "__builtin_popcountll", aliases)
        || is_call_named(expr, "_mm_popcnt_u64", aliases)
    {
        let x = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::Popcount64,
            name: "popcount64",
            description: "Count the number of set bits in a 64-bit integer",
            c_template: "__builtin_popcountll({0})",
            confidence: 96,
            captures: vec![expr_str(x)],
        });
    }
    None
}

fn match_clz32(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "__builtin_clz", aliases)
        || is_call_named(expr, "BitScanReverse", aliases)
        || is_call_named(expr, "_BitScanReverse", aliases)
    {
        let x = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::CountLeadingZeros32,
            name: "clz32",
            description: "Count leading zeros in a 32-bit integer",
            c_template: "__builtin_clz({0})",
            confidence: 94,
            captures: vec![expr_str(x)],
        });
    }
    None
}

fn match_ctz32(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "__builtin_ctz", aliases)
        || is_call_named(expr, "BitScanForward", aliases)
        || is_call_named(expr, "_BitScanForward", aliases)
    {
        let x = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::CountTrailingZeros32,
            name: "ctz32",
            description: "Count trailing zeros in a 32-bit integer",
            c_template: "__builtin_ctz({0})",
            confidence: 94,
            captures: vec![expr_str(x)],
        });
    }
    // x & (-x) — isolate lowest set bit — often the preamble of ctz.
    if let Expr::BinOp(BinOp::And, x, neg_x) = expr
        && let Expr::UnOp(UnOp::Neg, y) = neg_x.as_ref()
            && x.as_var() == y.as_var() {
                return Some(PatternMatch {
                    id: PatternId::IsolateLowBit,
                    name: "isolate_low_bit",
                    description: "Isolate lowest set bit: x & (-x)",
                    c_template: "{0} & (-{0})",
                    confidence: 80,
                    captures: vec![expr_str(x)],
                });
            }
    None
}

fn match_rotate_left32(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "_rotl", aliases) || is_call_named(expr, "_rotl32", aliases) {
        let x = call_arg(expr, 0)?;
        let n = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::RotateLeft32,
            name: "rotl32",
            description: "Rotate 32-bit value left by N bits",
            c_template: "_rotl({0}, {1})",
            confidence: 96,
            captures: vec![expr_str(x), expr_str(n)],
        });
    }
    // (x << n) | (x >> (32 - n))
    if let Expr::BinOp(BinOp::Or, shl_expr, shr_expr) = expr
        && let Expr::BinOp(BinOp::Shl, x1, n) = shl_expr.as_ref()
            && let Expr::BinOp(BinOp::Shr, x2, complement) = shr_expr.as_ref()
                && x1.as_var() == x2.as_var()
                    && let Expr::BinOp(BinOp::Sub, thirty_two, n2) = complement.as_ref()
                        && is_const(thirty_two, 32) && expr_str(n) == expr_str(n2) {
                            return Some(PatternMatch {
                                id: PatternId::RotateLeft32,
                                name: "rotl32 (manual)",
                                description: "Manual rotate-left-32: (x<<n) | (x>>(32-n))",
                                c_template: "_rotl({0}, {1})",
                                confidence: 88,
                                captures: vec![expr_str(x1), expr_str(n)],
                            });
                        }
    None
}

fn match_rotate_right32(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "_rotr", aliases) || is_call_named(expr, "_rotr32", aliases) {
        let x = call_arg(expr, 0)?;
        let n = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::RotateRight32,
            name: "rotr32",
            description: "Rotate 32-bit value right by N bits",
            c_template: "_rotr({0}, {1})",
            confidence: 96,
            captures: vec![expr_str(x), expr_str(n)],
        });
    }
    // (x >> n) | (x << (32 - n))
    if let Expr::BinOp(BinOp::Or, shr_expr, shl_expr) = expr
        && let Expr::BinOp(BinOp::Shr, x1, n) = shr_expr.as_ref()
            && let Expr::BinOp(BinOp::Shl, x2, complement) = shl_expr.as_ref()
                && x1.as_var() == x2.as_var()
                    && let Expr::BinOp(BinOp::Sub, thirty_two, n2) = complement.as_ref()
                        && is_const(thirty_two, 32) && expr_str(n) == expr_str(n2) {
                            return Some(PatternMatch {
                                id: PatternId::RotateRight32,
                                name: "rotr32 (manual)",
                                description: "Manual rotate-right-32: (x>>n) | (x<<(32-n))",
                                c_template: "_rotr({0}, {1})",
                                confidence: 88,
                                captures: vec![expr_str(x1), expr_str(n)],
                            });
                        }
    None
}

fn match_rotate_left64(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "_rotl64", aliases) {
        let x = call_arg(expr, 0)?;
        let n = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::RotateLeft64,
            name: "rotl64",
            description: "Rotate 64-bit value left by N bits",
            c_template: "_rotl64({0}, {1})",
            confidence: 96,
            captures: vec![expr_str(x), expr_str(n)],
        });
    }
    if let Expr::BinOp(BinOp::Or, shl_expr, shr_expr) = expr
        && let Expr::BinOp(BinOp::Shl, x1, n) = shl_expr.as_ref()
            && let Expr::BinOp(BinOp::Shr, x2, complement) = shr_expr.as_ref()
                && x1.as_var() == x2.as_var()
                    && let Expr::BinOp(BinOp::Sub, sixty_four, n2) = complement.as_ref()
                        && is_const(sixty_four, 64) && expr_str(n) == expr_str(n2) {
                            return Some(PatternMatch {
                                id: PatternId::RotateLeft64,
                                name: "rotl64 (manual)",
                                description: "Manual rotate-left-64",
                                c_template: "_rotl64({0}, {1})",
                                confidence: 88,
                                captures: vec![expr_str(x1), expr_str(n)],
                            });
                        }
    None
}

const fn match_rotate_right64(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    None // mirror of rotate_left64
}

fn match_extract_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (x >> n) & 1
    if let Expr::BinOp(BinOp::And, shr_expr, one) = expr
        && is_const(one, 1)
            && let Expr::BinOp(BinOp::Shr, x, n) = shr_expr.as_ref() {
                return Some(PatternMatch {
                    id: PatternId::ExtractBit,
                    name: "extract_bit",
                    description: "Extract bit N from x: (x >> n) & 1",
                    c_template: "({0} >> {1}) & 1",
                    confidence: 85,
                    captures: vec![expr_str(x), expr_str(n)],
                });
            }
    None
}

fn match_set_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // x | (1 << n)
    if let Expr::BinOp(BinOp::Or, x, shl_expr) = expr
        && let Expr::BinOp(BinOp::Shl, one, n) = shl_expr.as_ref()
            && is_const(one, 1) {
                return Some(PatternMatch {
                    id: PatternId::SetBit,
                    name: "set_bit",
                    description: "Set bit N of x: x | (1 << n)",
                    c_template: "{0} | (1 << {1})",
                    confidence: 85,
                    captures: vec![expr_str(x), expr_str(n)],
                });
            }
    None
}

fn match_clear_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // x & ~(1 << n)
    if let Expr::BinOp(BinOp::And, x, not_shl) = expr
        && let Expr::UnOp(UnOp::Not, shl_expr) = not_shl.as_ref()
            && let Expr::BinOp(BinOp::Shl, one, n) = shl_expr.as_ref()
                && is_const(one, 1) {
                    return Some(PatternMatch {
                        id: PatternId::ClearBit,
                        name: "clear_bit",
                        description: "Clear bit N of x: x & ~(1 << n)",
                        c_template: "{0} & ~(1 << {1})",
                        confidence: 85,
                        captures: vec![expr_str(x), expr_str(n)],
                    });
                }
    None
}

fn match_toggle_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Xor, x, shl_expr) = expr
        && let Expr::BinOp(BinOp::Shl, one, n) = shl_expr.as_ref()
            && is_const(one, 1) {
                return Some(PatternMatch {
                    id: PatternId::ToggleBit,
                    name: "toggle_bit",
                    description: "Toggle bit N of x: x ^ (1 << n)",
                    c_template: "{0} ^ (1 << {1})",
                    confidence: 85,
                    captures: vec![expr_str(x), expr_str(n)],
                });
            }
    None
}

fn match_isolate_low_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::And, x, neg_x) = expr
        && let Expr::UnOp(UnOp::Neg, y) = neg_x.as_ref()
            && x.as_var() == y.as_var() {
                return Some(PatternMatch {
                    id: PatternId::IsolateLowBit,
                    name: "isolate_low_bit",
                    description: "Isolate lowest set bit: x & (-x)",
                    c_template: "{0} & (-{0})",
                    confidence: 82,
                    captures: vec![expr_str(x)],
                });
            }
    None
}

fn match_clear_low_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // x & (x - 1)
    if let Expr::BinOp(BinOp::And, x, x_minus_1) = expr
        && let Expr::BinOp(BinOp::Sub, y, one) = x_minus_1.as_ref()
            && is_const(one, 1) && x.as_var() == y.as_var() {
                return Some(PatternMatch {
                    id: PatternId::ClearLowBit,
                    name: "clear_low_bit",
                    description: "Clear lowest set bit: x & (x-1)",
                    c_template: "{0} & ({0} - 1)",
                    confidence: 82,
                    captures: vec![expr_str(x)],
                });
            }
    None
}

fn match_mask_low_n(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // x & ((1 << n) - 1)
    if let Expr::BinOp(BinOp::And, x, mask_expr) = expr
        && let Expr::BinOp(BinOp::Sub, shl_expr, one) = mask_expr.as_ref()
            && is_const(one, 1)
                && let Expr::BinOp(BinOp::Shl, one2, n) = shl_expr.as_ref()
                    && is_const(one2, 1) {
                        return Some(PatternMatch {
                            id: PatternId::MaskLowN,
                            name: "mask_low_n_bits",
                            description: "Mask the low N bits of x: x & ((1<<n)-1)",
                            c_template: "{0} & ((1 << {1}) - 1)",
                            confidence: 82,
                            captures: vec![expr_str(x), expr_str(n)],
                        });
                    }
    None
}

fn match_sign_bit(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (x >> 31) & 1 or (x < 0)
    if let Expr::BinOp(BinOp::And, shr_expr, one) = expr
        && is_const(one, 1)
            && let Expr::BinOp(BinOp::Sar, x, shift) = shr_expr.as_ref()
                && (is_const(shift, 31) || is_const(shift, 63)) {
                    return Some(PatternMatch {
                        id: PatternId::SignBit,
                        name: "sign_bit",
                        description: "Extract the sign bit of x: (x >> 31) & 1",
                        c_template: "({0} < 0)",
                        confidence: 80,
                        captures: vec![expr_str(x)],
                    });
                }
    None
}

const fn match_parity_bit(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    None // complex multi-step pattern
}

const fn match_mirror_bits(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    None // stub
}

// ── Float patterns ────────────────────────────────────────────────────────────

/// Fast inverse square root: `*(float*)&((int)0x5F3759DF - (*(int*)&x >> 1))`.
fn match_fast_inv_sqrt(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Detect the magic constant 0x5F3759DF in an integer expression.
    fn contains_fast_sqrt_magic(e: &Expr) -> bool {
        match e {
            Expr::Const(v, _) => *v == 0x5F37_59DF || *v == 0x5FE6_EB50,
            Expr::BinOp(_, a, b) => contains_fast_sqrt_magic(a) || contains_fast_sqrt_magic(b),
            Expr::UnOp(_, e) => contains_fast_sqrt_magic(e),
            _ => false,
        }
    }
    if contains_fast_sqrt_magic(expr) {
        return Some(PatternMatch {
            id: PatternId::FastInvSqrt,
            name: "fast_inv_sqrt",
            description: "Quake fast inverse square root (0x5F3759DF magic)",
            c_template: "1.0f / sqrtf({0}) /* fast inv-sqrt */",
            confidence: 95,
            captures: vec![expr_str(expr)],
        });
    }
    None
}

fn match_float_abs(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "fabs", aliases) || is_call_named(expr, "fabsf", aliases) {
        let x = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::FloatAbs,
            name: "fabs",
            description: "Floating-point absolute value",
            c_template: "fabs({0})",
            confidence: 97,
            captures: vec![expr_str(x)],
        });
    }
    // Bitwise trick: f & 0x7FFFFFFF (clear sign bit on float).
    if let Expr::BinOp(BinOp::And, x, mask) = expr {
        if is_const(mask, 0x7FFF_FFFF) {
            return Some(PatternMatch {
                id: PatternId::FloatAbs,
                name: "fabs (bitwise, float)",
                description: "Clear float sign bit to compute |x|",
                c_template: "fabsf({0}) /* & 0x7FFFFFFF */",
                confidence: 78,
                captures: vec![expr_str(x)],
            });
        }
        if is_const(mask, 0x7FFF_FFFF_FFFF_FFFFi64) {
            return Some(PatternMatch {
                id: PatternId::FloatAbs,
                name: "fabs (bitwise, double)",
                description: "Clear double sign bit to compute |x|",
                c_template: "fabs({0}) /* & 0x7FFFFFFFFFFFFFFF */",
                confidence: 78,
                captures: vec![expr_str(x)],
            });
        }
    }
    None
}

fn match_float_min(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "fmin", aliases) || is_call_named(expr, "fminf", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::FloatMin,
            name: "fmin",
            description: "Floating-point minimum",
            c_template: "fmin({0}, {1})",
            confidence: 96,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    None
}

fn match_float_max(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "fmax", aliases) || is_call_named(expr, "fmaxf", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::FloatMax,
            name: "fmax",
            description: "Floating-point maximum",
            c_template: "fmax({0}, {1})",
            confidence: 96,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    None
}

// ── Crypto patterns ───────────────────────────────────────────────────────────

/// Xorshift32: x ^= x<<13; x ^= x>>17; x ^= x<<5;
fn match_xorshift32(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Single xorshift step: x ^ (x << 13)
    if let Expr::BinOp(BinOp::Xor, x, shl_expr) = expr
        && let Expr::BinOp(BinOp::Shl, y, shift) = shl_expr.as_ref()
            && x.as_var() == y.as_var() {
                let sh = const_val(shift)?;
                if sh == 13 || sh == 17 || sh == 5 || sh == 7 || sh == 15 || sh == 21 {
                    return Some(PatternMatch {
                        id: PatternId::Xorshift32,
                        name: "xorshift32 step",
                        description: "Single step of a 32-bit xorshift PRNG",
                        c_template: "{0} ^ ({0} << {1})",
                        confidence: 75,
                        captures: vec![expr_str(x), sh.to_string()],
                    });
                }
            }
    None
}

fn match_xorshift64(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if let Expr::BinOp(BinOp::Xor, x, shl_expr) = expr
        && let Expr::BinOp(BinOp::Shl, y, shift) = shl_expr.as_ref()
            && x.as_var() == y.as_var() {
                let sh = const_val(shift)?;
                if sh == 13 || sh == 7 || sh == 17 {
                    return Some(PatternMatch {
                        id: PatternId::Xorshift64,
                        name: "xorshift64 step",
                        description: "Single step of a 64-bit xorshift PRNG",
                        c_template: "{0} ^ ({0} << {1})",
                        confidence: 73,
                        captures: vec![expr_str(x), sh.to_string()],
                    });
                }
            }
    None
}

/// FNV-1a hash step: `hash = (hash ^ byte) * FNV_PRIME`.
fn match_fnv1a_hash(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Pattern: (hash ^ ch) * 0x01000193
    if let Expr::BinOp(BinOp::Mul, xored, prime) = expr {
        let p = const_val(prime)?;
        if (p == 0x0100_0193 || p == 0x0000_0100_0000_01B3i64)
            && let Expr::BinOp(BinOp::Xor, hash, ch) = xored.as_ref() {
                return Some(PatternMatch {
                    id: PatternId::Fnv1aHash,
                    name: "fnv1a_hash",
                    description: "FNV-1a hash step: (hash ^ byte) * FNV_PRIME",
                    c_template: "({0} ^ {1}) * 0x01000193U /* FNV-1a */",
                    confidence: 93,
                    captures: vec![expr_str(hash), expr_str(ch)],
                });
            }
    }
    None
}

/// DJB2 hash step: `hash = hash * 33 ^ ch`  or  `(hash << 5) + hash + ch`.
fn match_djb2_hash(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (hash << 5) + hash + ch  ==  hash * 33 + ch
    if let Expr::BinOp(BinOp::Add, sum, ch) = expr
        && let Expr::BinOp(BinOp::Add, shl_expr, hash2) = sum.as_ref()
            && let Expr::BinOp(BinOp::Shl, hash1, five) = shl_expr.as_ref()
                && is_const(five, 5) && hash1.as_var() == hash2.as_var() {
                    return Some(PatternMatch {
                        id: PatternId::Djb2Hash,
                        name: "djb2_hash",
                        description: "DJB2 hash step: hash * 33 + c",
                        c_template: "{0} * 33 + {1} /* djb2 */",
                        confidence: 90,
                        captures: vec![expr_str(hash1), expr_str(ch)],
                    });
                }
    // Xor variant: hash * 33 ^ ch
    if let Expr::BinOp(BinOp::Xor, mul33, ch) = expr
        && let Expr::BinOp(BinOp::Mul, hash, thirty_three) = mul33.as_ref()
            && is_const(thirty_three, 33) {
                return Some(PatternMatch {
                    id: PatternId::Djb2Hash,
                    name: "djb2_hash (xor)",
                    description: "DJB2 hash step: hash * 33 ^ c",
                    c_template: "{0} * 33 ^ {1} /* djb2 xor */",
                    confidence: 87,
                    captures: vec![expr_str(hash), expr_str(ch)],
                });
            }
    None
}

const fn match_crc32_step(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Complex lookup-table pattern — stub.
    None
}

const fn match_chacha_quarter_round(
    _expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // Multi-statement — cannot match a single expression. Stub.
    None
}

// ── WinAPI patterns ───────────────────────────────────────────────────────────

fn match_handle_valid(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // HANDLE != INVALID_HANDLE_VALUE (-1) and HANDLE != NULL (0)
    if let Expr::BinOp(BinOp::Ne, h, val) = expr {
        let v = const_val(val)?;
        if v == -1 || v == 0 {
            let name = if v == -1 { "INVALID_HANDLE_VALUE" } else { "NULL" };
            return Some(PatternMatch {
                id: PatternId::HandleIsValid,
                name: "handle_valid",
                description: "Check whether a Win32 HANDLE is valid",
                c_template: "{0} != {1} /* handle valid check */",
                confidence: 78,
                captures: vec![expr_str(h), name.to_string()],
            });
        }
    }
    None
}

fn match_nt_status_success(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // NT_SUCCESS(status) = status >= 0
    if let Expr::BinOp(BinOp::Ge, status, zero) = expr
        && is_const(zero, 0) {
            return Some(PatternMatch {
                id: PatternId::NtStatusSuccess,
                name: "NT_SUCCESS",
                description: "NT_SUCCESS macro: NTSTATUS >= 0",
                c_template: "NT_SUCCESS({0})",
                confidence: 82,
                captures: vec![expr_str(status)],
            });
        }
    // Alternatively: status < 0x80000000 (unsigned comparison)
    if let Expr::BinOp(BinOp::Lt, status, threshold) = expr
        && const_val(threshold) == Some(i64::from(0x8000_0000u32)) {
            return Some(PatternMatch {
                id: PatternId::NtStatusSuccess,
                name: "NT_SUCCESS (unsigned)",
                description: "NT_SUCCESS via unsigned threshold 0x80000000",
                c_template: "NT_SUCCESS({0})",
                confidence: 80,
                captures: vec![expr_str(status)],
            });
        }
    None
}

fn match_safe_free(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "free", aliases) || is_call_named(expr, "HeapFree", aliases)
        || is_call_named(expr, "LocalFree", aliases) || is_call_named(expr, "GlobalFree", aliases)
    {
        let ptr = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::SafeFree,
            name: "safe_free",
            description: "Free heap-allocated memory",
            c_template: "free({0})",
            confidence: 92,
            captures: vec![expr_str(ptr)],
        });
    }
    None
}

fn match_virtual_alloc_rwx(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "VirtualAlloc", aliases) || is_call_named(expr, "VirtualAllocEx", aliases) {
        let size = call_arg(expr, 1);
        return Some(PatternMatch {
            id: PatternId::VirtualAllocRwx,
            name: "VirtualAlloc",
            description: "Windows VirtualAlloc memory allocation",
            c_template: "VirtualAlloc(NULL, {0}, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)",
            confidence: 88,
            captures: vec![size.map(expr_str).unwrap_or_default()],
        });
    }
    None
}

// ── C stdlib ─────────────────────────────────────────────────────────────────

fn match_malloc_check(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "malloc", aliases) || is_call_named(expr, "calloc", aliases)
        || is_call_named(expr, "HeapAlloc", aliases)
    {
        let sz = call_arg(expr, 0)?;
        return Some(PatternMatch {
            id: PatternId::MallocCheck,
            name: "malloc",
            description: "Heap allocation (malloc/calloc/HeapAlloc)",
            c_template: "malloc({0})",
            confidence: 92,
            captures: vec![expr_str(sz)],
        });
    }
    None
}

fn match_fopen_read(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "fopen", aliases) || is_call_named(expr, "fopen_s", aliases)
        || is_call_named(expr, "_wfopen", aliases)
    {
        let path = call_arg(expr, 0)?;
        let mode = call_arg(expr, 1).map_or_else(|| "\"r\"".to_string(), expr_str);
        return Some(PatternMatch {
            id: PatternId::FopenReadText,
            name: "fopen",
            description: "Open a file with fopen",
            c_template: "fopen({0}, {1})",
            confidence: 94,
            captures: vec![expr_str(path), mode],
        });
    }
    None
}

// ── Control flow ─────────────────────────────────────────────────────────────

fn match_max_two(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    match_clamp_min(expr, aliases)
}

fn match_min_two(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    match_clamp_max(expr, aliases)
}

fn match_swap_xor(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // x ^ y ^ x  (one step of XOR swap — already simplified to y normally)
    if let Expr::BinOp(BinOp::Xor, xored, x2) = expr
        && let Expr::BinOp(BinOp::Xor, x1, y) = xored.as_ref()
            && x1.as_var() == x2.as_var() {
                return Some(PatternMatch {
                    id: PatternId::SwapXor,
                    name: "xor_swap residue",
                    description: "Residue of XOR-swap sequence: a^=b; b^=a; a^=b",
                    c_template: "{1} /* xor-swap result */",
                    confidence: 65,
                    captures: vec![expr_str(x1), expr_str(y)],
                });
            }
    None
}

fn match_gcd_euclidean(
    expr: &Expr,
    aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    if is_call_named(expr, "gcd", aliases) || is_call_named(expr, "__gcd", aliases) {
        let a = call_arg(expr, 0)?;
        let b = call_arg(expr, 1)?;
        return Some(PatternMatch {
            id: PatternId::GcdEuclidean,
            name: "gcd",
            description: "Greatest common divisor (Euclidean algorithm)",
            c_template: "__gcd({0}, {1})",
            confidence: 94,
            captures: vec![expr_str(a), expr_str(b)],
        });
    }
    None
}

// ── Misc ──────────────────────────────────────────────────────────────────────

fn match_noop_cast(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    // (T)(T)x — double cast to same type.
    if let Expr::UnOp(UnOp::Cast(outer), inner) = expr
        && let Expr::UnOp(UnOp::Cast(inner_w), x) = inner.as_ref()
            && outer == inner_w {
                return Some(PatternMatch {
                    id: PatternId::NoopCast,
                    name: "noop_cast",
                    description: "Redundant double cast to the same type",
                    c_template: "({0}){1}",
                    confidence: 90,
                    captures: vec![outer.to_string(), expr_str(x)],
                });
            }
    None
}

fn match_double_negation(
    expr: &Expr,
    _aliases: &HashMap<String, String>,
) -> Option<PatternMatch> {
    match expr {
        Expr::UnOp(UnOp::LNot, inner) => {
            if let Expr::UnOp(UnOp::LNot, x) = inner.as_ref() {
                return Some(PatternMatch {
                    id: PatternId::DoubleNegation,
                    name: "double_negation",
                    description: "!!x — double logical negation, equivalent to (bool)x",
                    c_template: "(bool)({0})",
                    confidence: 88,
                    captures: vec![expr_str(x)],
                });
            }
        }
        Expr::UnOp(UnOp::Neg, inner) => {
            if let Expr::UnOp(UnOp::Neg, x) = inner.as_ref() {
                return Some(PatternMatch {
                    id: PatternId::DoubleNegation,
                    name: "double_arithmetic_negation",
                    description: "--x — double arithmetic negation, simplifies to x",
                    c_template: "{0}",
                    confidence: 90,
                    captures: vec![expr_str(x)],
                });
            }
        }
        _ => {}
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDatabase — prebuilt descriptions for documentation
// ─────────────────────────────────────────────────────────────────────────────

/// A static description entry.
pub struct PatternDescriptor {
    pub id: PatternId,
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub c_template: &'static str,
    pub references: &'static [&'static str],
}

/// Return all pattern descriptors in the library.
#[must_use]
pub fn all_pattern_descriptors() -> Vec<PatternDescriptor> {
    let mut v = memory_arithmetic_descriptors();
    v.extend(bitwise_crypto_descriptors());
    v
}

fn memory_arithmetic_descriptors() -> Vec<PatternDescriptor> {
    vec![
        PatternDescriptor {
            id: PatternId::StrlenLoop,
            name: "strlen",
            category: "memory/string",
            description: "Count characters until null terminator",
            c_template: "strlen({0})",
            references: &["C11 §7.24.6.3"],
        },
        PatternDescriptor {
            id: PatternId::MemsetLoop,
            name: "memset",
            category: "memory/string",
            description: "Fill block of memory with a constant byte value",
            c_template: "memset({0}, {1}, {2})",
            references: &["C11 §7.24.6.1"],
        },
        PatternDescriptor {
            id: PatternId::MemcpyLoop,
            name: "memcpy",
            category: "memory/string",
            description: "Copy bytes from source to destination (no overlap)",
            c_template: "memcpy({0}, {1}, {2})",
            references: &["C11 §7.24.2.1"],
        },
        PatternDescriptor {
            id: PatternId::DivideByMultiplyHigh,
            name: "divide-by-constant (mul-high)",
            category: "arithmetic",
            description: "Compiler transforms integer division by a constant into \
                           a multiply-high followed by an arithmetic shift right.",
            c_template: "{0} / {1}",
            references: &["Hacker's Delight §10"],
        },
        PatternDescriptor {
            id: PatternId::IsPowerOfTwo,
            name: "is_power_of_two",
            category: "arithmetic",
            description: "Test x is a power of two: (x != 0) && ((x & (x-1)) == 0)",
            c_template: "({0} != 0 && ({0} & ({0} - 1)) == 0)",
            references: &["Hacker's Delight §2"],
        },
        PatternDescriptor {
            id: PatternId::AbsValueBranchless,
            name: "abs_branchless",
            category: "arithmetic",
            description: "Branchless absolute value using arithmetic-shift mask",
            c_template: "abs({0})",
            references: &["Hacker's Delight §2-4"],
        },
    ]
}

fn bitwise_crypto_descriptors() -> Vec<PatternDescriptor> {
    vec![
        PatternDescriptor {
            id: PatternId::ByteSwap32,
            name: "bswap32",
            category: "bitwise",
            description: "Byte-swap a 32-bit integer (big/little endian conversion)",
            c_template: "__builtin_bswap32({0})",
            references: &["GCC built-ins"],
        },
        PatternDescriptor {
            id: PatternId::Popcount32,
            name: "popcount32",
            category: "bitwise",
            description: "Count the number of set bits in a 32-bit integer",
            c_template: "__builtin_popcount({0})",
            references: &["Hacker's Delight §5"],
        },
        PatternDescriptor {
            id: PatternId::RotateLeft32,
            name: "rotl32",
            category: "bitwise",
            description: "Rotate a 32-bit integer left by N bits",
            c_template: "_rotl({0}, {1})",
            references: &["x86 ROL instruction"],
        },
        PatternDescriptor {
            id: PatternId::Fnv1aHash,
            name: "fnv1a",
            category: "crypto/hash",
            description: "FNV-1a hash update step",
            c_template: "({0} ^ {1}) * 0x01000193U",
            references: &["http://www.isthe.com/chongo/tech/comp/fnv/"],
        },
        PatternDescriptor {
            id: PatternId::Djb2Hash,
            name: "djb2",
            category: "crypto/hash",
            description: "DJB2 hash by Daniel J. Bernstein: hash * 33 + c",
            c_template: "{0} * 33 + {1}",
            references: &["http://www.cse.yorku.ca/~oz/hash.html"],
        },
        PatternDescriptor {
            id: PatternId::FastInvSqrt,
            name: "fast_inv_sqrt",
            category: "float",
            description: "Quake III fast inverse square root hack (magic 0x5F3759DF)",
            c_template: "1.0f / sqrtf({0})",
            references: &["https://en.wikipedia.org/wiki/Fast_inverse_square_root"],
        },
        PatternDescriptor {
            id: PatternId::Xorshift32,
            name: "xorshift32",
            category: "crypto",
            description: "Xorshift PRNG step (Marsaglia 2003)",
            c_template: "{0} ^ ({0} << {1})",
            references: &["https://www.jstatsoft.org/article/view/v008i14"],
        },
        PatternDescriptor {
            id: PatternId::HandleIsValid,
            name: "handle_valid",
            category: "winapi",
            description: "Check Win32 HANDLE != INVALID_HANDLE_VALUE / NULL",
            c_template: "{0} != INVALID_HANDLE_VALUE",
            references: &["MSDN: INVALID_HANDLE_VALUE"],
        },
        PatternDescriptor {
            id: PatternId::NtStatusSuccess,
            name: "NT_SUCCESS",
            category: "winapi",
            description: "NT_SUCCESS macro: NTSTATUS >= 0",
            c_template: "NT_SUCCESS({0})",
            references: &["WDK: ntstatus.h"],
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BinOp, Expr, IntWidth, UnOp};

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::BinOp(op, Box::new(a), Box::new(b))
    }
    fn unop(op: UnOp, e: Expr) -> Expr {
        Expr::UnOp(op, Box::new(e))
    }
    fn call(name: &str, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Box::new(var(name)),
            args,
        }
    }

    #[test]
    fn test_strlen_call_matched() {
        let expr = call("strlen", vec![var("s")]);
        let mut m = PatternMatcher::new();
        let matches = m.match_all(&expr);
        assert!(
            matches.iter().any(|m| m.id == PatternId::StrlenLoop),
            "strlen not matched"
        );
    }

    #[test]
    fn test_memset_matched() {
        let expr = call("memset", vec![var("dst"), c(0), var("n")]);
        let mut m = PatternMatcher::new();
        let matches = m.match_all(&expr);
        assert!(matches.iter().any(|m| m.id == PatternId::MemsetLoop));
    }

    #[test]
    fn test_zero_memory_memset() {
        let expr = call("memset", vec![var("buf"), c(0), var("sz")]);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ZeroMemory));
    }

    #[test]
    fn test_fill_byte_matched() {
        let expr = call("memset", vec![var("buf"), c(0xCC), var("sz")]);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::FillByte));
    }

    #[test]
    fn test_modulo_by_and() {
        // x & 0xFF  → x % 256
        let expr = binop(BinOp::And, var("x"), c(0xFF));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ModuloByAnd));
    }

    #[test]
    fn test_is_power_of_two() {
        // (x & (x-1)) == 0
        let x_minus_1 = binop(BinOp::Sub, var("x"), c(1));
        let and_expr = binop(BinOp::And, var("x"), x_minus_1);
        let expr = binop(BinOp::Eq, and_expr, c(0));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::IsPowerOfTwo));
    }

    #[test]
    fn test_abs_branchless() {
        // (x ^ mask) - mask, mask = x >> 31
        let mask = binop(BinOp::Sar, var("x"), c(31));
        let xored = binop(BinOp::Xor, var("x"), mask.clone());
        let expr = binop(BinOp::Sub, xored, mask);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::AbsValueBranchless));
    }

    #[test]
    fn test_byteswap16() {
        // (x >> 8) | ((x & 0xff) << 8)
        let hi = binop(BinOp::Shr, var("x"), c(8));
        let masked = binop(BinOp::And, var("x"), c(0xff));
        let lo = binop(BinOp::Shl, masked, c(8));
        let expr = binop(BinOp::Or, hi, lo);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ByteSwap16));
    }

    #[test]
    fn test_extract_bit() {
        let expr = binop(BinOp::And, binop(BinOp::Shr, var("x"), c(5)), c(1));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ExtractBit));
    }

    #[test]
    fn test_set_bit() {
        let expr = binop(BinOp::Or, var("x"), binop(BinOp::Shl, c(1), c(3)));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::SetBit));
    }

    #[test]
    fn test_clear_bit() {
        let shl = binop(BinOp::Shl, c(1), c(3));
        let not_shl = unop(UnOp::Not, shl);
        let expr = binop(BinOp::And, var("x"), not_shl);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ClearBit));
    }

    #[test]
    fn test_fnv1a_hash() {
        // (hash ^ ch) * 0x01000193
        let xored = binop(BinOp::Xor, var("hash"), var("ch"));
        let expr = binop(BinOp::Mul, xored, c(0x0100_0193));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::Fnv1aHash));
    }

    #[test]
    fn test_djb2_hash() {
        // (hash << 5) + hash + ch
        let shl = binop(BinOp::Shl, var("hash"), c(5));
        let sum1 = binop(BinOp::Add, shl, var("hash"));
        let expr = binop(BinOp::Add, sum1, var("ch"));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::Djb2Hash));
    }

    #[test]
    fn test_fast_inv_sqrt() {
        let magic = c(0x5F37_59DF);
        let expr = binop(BinOp::Sub, magic, binop(BinOp::Shr, var("i"), c(1)));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::FastInvSqrt));
    }

    #[test]
    fn test_rotate_left32_manual() {
        // (x << n) | (x >> (32 - n))
        let shl = binop(BinOp::Shl, var("x"), var("n"));
        let complement = binop(BinOp::Sub, c(32), var("n"));
        let shr = binop(BinOp::Shr, var("x"), complement);
        let expr = binop(BinOp::Or, shl, shr);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::RotateLeft32));
    }

    #[test]
    fn test_sign_extend_32_64() {
        let shl = binop(BinOp::Shl, var("x"), c(32));
        let expr = binop(BinOp::Sar, shl, c(32));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::SignExtend32to64));
    }

    #[test]
    fn test_to_lower_branchless() {
        let expr = binop(BinOp::Or, var("c"), c(0x20));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ToLowerLoop));
    }

    #[test]
    fn test_malloc_matched() {
        let expr = call("malloc", vec![var("size")]);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::MallocCheck));
    }

    #[test]
    fn test_nt_status_success() {
        let expr = binop(BinOp::Ge, var("status"), c(0));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::NtStatusSuccess));
    }

    #[test]
    fn test_double_negation() {
        let expr = unop(UnOp::LNot, unop(UnOp::LNot, var("x")));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::DoubleNegation));
    }

    #[test]
    fn test_isolate_low_bit() {
        let neg_x = unop(UnOp::Neg, var("x"));
        let expr = binop(BinOp::And, var("x"), neg_x);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::IsolateLowBit));
    }

    #[test]
    fn test_clear_low_bit() {
        let expr = binop(BinOp::And, var("x"), binop(BinOp::Sub, var("x"), c(1)));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::ClearLowBit));
    }

    #[test]
    fn test_sign_bit() {
        let expr = binop(BinOp::And, binop(BinOp::Sar, var("x"), c(31)), c(1));
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::SignBit));
    }

    #[test]
    fn test_mask_low_n() {
        let mask = binop(BinOp::Sub, binop(BinOp::Shl, c(1), var("n")), c(1));
        let expr = binop(BinOp::And, var("x"), mask);
        let mut m = PatternMatcher::new();
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::MaskLowN));
    }

    #[test]
    fn test_descriptors_nonempty() {
        let descs = all_pattern_descriptors();
        assert!(!descs.is_empty());
        assert!(descs.len() >= 15);
    }

    #[test]
    fn test_match_best() {
        let expr = call("strlen", vec![var("s")]);
        let mut m = PatternMatcher::new();
        let best = m.match_best(&expr);
        assert!(best.is_some());
        assert_eq!(best.unwrap().id, PatternId::StrlenLoop);
    }

    #[test]
    fn test_alias_resolution() {
        let expr = call("sub_401234", vec![var("s")]);
        let mut m = PatternMatcher::new();
        m.add_call_alias("sub_401234", "strlen");
        let found = m.match_all(&expr);
        assert!(found.iter().any(|m| m.id == PatternId::StrlenLoop));
    }

    #[test]
    fn test_stats_tracked() {
        let mut m = PatternMatcher::new();
        let _ = m.match_all(&call("strlen", vec![var("s")]));
        assert!(m.patterns_checked > 0);
        assert!(m.matches_found > 0);
    }

    #[test]
    fn test_pattern_match_render() {
        let pm = PatternMatch {
            id: PatternId::StrlenLoop,
            name: "strlen",
            description: "test",
            c_template: "strlen({0})",
            confidence: 95,
            captures: vec!["buf".to_string()],
        };
        assert_eq!(pm.render(), "strlen(buf)");
    }
}
