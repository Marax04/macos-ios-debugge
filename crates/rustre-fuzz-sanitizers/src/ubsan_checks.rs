//! `UBSan` checks: full suite of undefined-behaviour sanitizer violations with
//! source-location info (<file:line:col>) and configurable recovery mode.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── source location ─────────────────────────────────────────────────────────

/// Source location attached to every `UBSan` report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl SourceLocation {
    #[must_use]
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self { file: file.into(), line, column }
    }

    #[must_use]
    pub fn unknown() -> Self {
        Self { file: "<unknown>".into(), line: 0, column: 0 }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

// ─── UBSan violation kinds ───────────────────────────────────────────────────

/// Every possible `UBSan` violation kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbsanViolation {
    /// Signed integer overflow (add/sub/mul/negate).
    SignedIntegerOverflow {
        loc: SourceLocation,
        lhs: i128,
        rhs: i128,
        op: ArithOp,
        bit_width: u8,
    },
    /// Unsigned integer overflow.
    UnsignedIntegerOverflow {
        loc: SourceLocation,
        lhs: u128,
        rhs: u128,
        op: ArithOp,
        bit_width: u8,
    },
    /// Shift exponent too large or negative.
    ShiftExponent {
        loc: SourceLocation,
        lhs: u64,
        rhs: i64,
        bit_width: u8,
        exponent_negative: bool,
        exponent_too_large: bool,
    },
    /// Null pointer dereference.
    NullPointerDereference { loc: SourceLocation, ptr: u64, access_size: usize },
    /// Misaligned memory access.
    MisalignedAccess {
        loc: SourceLocation,
        ptr: u64,
        alignment: usize,
        access_size: usize,
    },
    /// Invalid enum value.
    InvalidEnumValue { loc: SourceLocation, value: u64, enum_name: String },
    /// Array index out of bounds.
    ArrayIndexOutOfBounds {
        loc: SourceLocation,
        index: i64,
        bound: u64,
    },
    /// Invalid bool value (not 0 or 1).
    InvalidBoolValue { loc: SourceLocation, value: u8 },
    /// Function called through wrong pointer type.
    FunctionTypeMismatch {
        loc: SourceLocation,
        callee_addr: u64,
        expected_type: String,
        actual_type: String,
    },
    /// Virtual function called on wrong dynamic type.
    VptrTypeMismatch {
        loc: SourceLocation,
        ptr: u64,
        expected_type: String,
        actual_type: String,
    },
    /// Integer division by zero.
    DivisionByZero { loc: SourceLocation, lhs: i64, bit_width: u8 },
    /// Pointer overflow (arithmetic wraps on pointer).
    PointerOverflow { loc: SourceLocation, base: u64, result: u64 },
    /// Return value from non-void function missing.
    MissingReturn { loc: SourceLocation },
    /// Unreachable code was reached.
    Unreachable { loc: SourceLocation },
    /// Load of value with insufficient alignment for its type.
    UnalignedLoad { loc: SourceLocation, ptr: u64, type_name: String, required_align: usize },
}

impl fmt::Display for UbsanViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedIntegerOverflow { loc, lhs, rhs, op, bit_width } => write!(
                f,
                "{loc}: signed integer overflow: {lhs} {op} {rhs} cannot be represented in i{bit_width}"
            ),
            Self::UnsignedIntegerOverflow { loc, lhs, rhs, op, bit_width } => write!(
                f,
                "{loc}: unsigned integer overflow: {lhs} {op} {rhs} cannot be represented in u{bit_width}"
            ),
            Self::ShiftExponent { loc, lhs, rhs, bit_width, exponent_negative, exponent_too_large } => {
                if *exponent_negative {
                    write!(f, "{loc}: shift exponent {rhs} is negative")
                } else if *exponent_too_large {
                    write!(
                        f,
                        "{loc}: shift exponent {rhs} is too large for {bit_width}-bit type"
                    )
                } else {
                    write!(f, "{loc}: shift of {lhs} by {rhs} is UB")
                }
            }
            Self::NullPointerDereference { loc, ptr, access_size } => write!(
                f,
                "{loc}: null pointer dereference: ptr={ptr:#x} size={access_size}"
            ),
            Self::MisalignedAccess { loc, ptr, alignment, access_size } => write!(
                f,
                "{loc}: misaligned address {ptr:#x} for {access_size}-byte access (alignment {alignment})"
            ),
            Self::InvalidEnumValue { loc, value, enum_name } => write!(
                f,
                "{loc}: load of value {value} which is not a valid value for type '{enum_name}'"
            ),
            Self::ArrayIndexOutOfBounds { loc, index, bound } => write!(
                f,
                "{loc}: index {index} out of bounds for array of size {bound}"
            ),
            Self::InvalidBoolValue { loc, value } => {
                write!(f, "{loc}: load of value {value} which is not a valid bool")
            }
            Self::FunctionTypeMismatch { loc, callee_addr, expected_type, actual_type } => write!(
                f,
                "{loc}: call to function {callee_addr:#x} through pointer to {expected_type}, but it has type {actual_type}"
            ),
            Self::VptrTypeMismatch { loc, ptr, expected_type, actual_type } => write!(
                f,
                "{loc}: virtual call on {ptr:#x}: expected {expected_type}, got {actual_type}"
            ),
            Self::DivisionByZero { loc, lhs, bit_width } => {
                write!(f, "{loc}: division of {lhs} by zero (i{bit_width})")
            }
            Self::PointerOverflow { loc, base, result } => write!(
                f,
                "{loc}: pointer arithmetic overflow: {base:#x} + offset wraps to {result:#x}"
            ),
            Self::MissingReturn { loc } => {
                write!(f, "{loc}: execution reached end of value-returning function")
            }
            Self::Unreachable { loc } => {
                write!(f, "{loc}: execution reached an unreachable program point")
            }
            Self::UnalignedLoad { loc, ptr, type_name, required_align } => write!(
                f,
                "{loc}: load of type {type_name} from unaligned address {ptr:#x} (required {required_align})"
            ),
        }
    }
}

/// Arithmetic operation tag used in overflow reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Neg,
    Div,
    Rem,
}

impl fmt::Display for ArithOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "+"),
            Self::Sub | Self::Neg => write!(f, "-"),
            Self::Mul => write!(f, "*"),
            Self::Div => write!(f, "/"),
            Self::Rem => write!(f, "%"),
        }
    }
}

// ─── recovery mode ───────────────────────────────────────────────────────────

/// How the `UBSan` runtime should respond when a violation is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// Log the violation and continue execution.
    Continue,
    /// Abort the process immediately.
    Abort,
    /// Panic (Rust `panic!`).
    Panic,
}

// ─── UBSan runtime ───────────────────────────────────────────────────────────

/// In-process `UBSan` violation collector.
#[derive(Debug)]
pub struct UbsanRuntime {
    pub mode: RecoveryMode,
    violations: std::sync::Mutex<Vec<UbsanViolation>>,
}

impl UbsanRuntime {
    #[must_use]
    pub const fn new(mode: RecoveryMode) -> Self {
        Self { mode, violations: std::sync::Mutex::new(Vec::new()) }
    }

    fn report(&self, v: UbsanViolation) {
        match self.mode {
            RecoveryMode::Continue => {
                self.violations.lock().unwrap().push(v);
            }
            RecoveryMode::Abort => {
                eprintln!("UBSan: {v}");
                std::process::abort();
            }
            RecoveryMode::Panic => {
                panic!("UBSan: {v}");
            }
        }
    }

    /// # Panics
    /// Documented for clippy.
    pub fn violations(&self) -> Vec<UbsanViolation> {
        self.violations.lock().unwrap().clone()
    }

    /// # Panics
    /// Documented for clippy.
    pub fn violation_count(&self) -> usize {
        self.violations.lock().unwrap().len()
    }

    /// # Panics
    /// Documented for clippy.
    pub fn reset(&self) {
        self.violations.lock().unwrap().clear();
    }

    // ── signed integer overflow ─────────────────────────────────────────────

    pub fn check_signed_add_overflow(&self, loc: SourceLocation, lhs: i64, rhs: i64, bit_width: u8) {
        if overflows_signed(i128::from(lhs), i128::from(rhs), ArithOp::Add, bit_width) {
            self.report(UbsanViolation::SignedIntegerOverflow {
                loc, lhs: i128::from(lhs), rhs: i128::from(rhs), op: ArithOp::Add, bit_width,
            });
        }
    }

    pub fn check_signed_sub_overflow(&self, loc: SourceLocation, lhs: i64, rhs: i64, bit_width: u8) {
        if overflows_signed(i128::from(lhs), i128::from(rhs), ArithOp::Sub, bit_width) {
            self.report(UbsanViolation::SignedIntegerOverflow {
                loc, lhs: i128::from(lhs), rhs: i128::from(rhs), op: ArithOp::Sub, bit_width,
            });
        }
    }

    pub fn check_signed_mul_overflow(&self, loc: SourceLocation, lhs: i64, rhs: i64, bit_width: u8) {
        if overflows_signed(i128::from(lhs), i128::from(rhs), ArithOp::Mul, bit_width) {
            self.report(UbsanViolation::SignedIntegerOverflow {
                loc, lhs: i128::from(lhs), rhs: i128::from(rhs), op: ArithOp::Mul, bit_width,
            });
        }
    }

    pub fn check_signed_negate_overflow(&self, loc: SourceLocation, val: i64, bit_width: u8) {
        let (min, _) = signed_bounds(bit_width);
        if i128::from(val) == min {
            self.report(UbsanViolation::SignedIntegerOverflow {
                loc, lhs: i128::from(val), rhs: 0, op: ArithOp::Neg, bit_width,
            });
        }
    }

    // ── unsigned integer overflow ───────────────────────────────────────────

    pub fn check_unsigned_add_overflow(&self, loc: SourceLocation, lhs: u64, rhs: u64, bit_width: u8) {
        if overflows_unsigned(u128::from(lhs), u128::from(rhs), ArithOp::Add, bit_width) {
            self.report(UbsanViolation::UnsignedIntegerOverflow {
                loc, lhs: u128::from(lhs), rhs: u128::from(rhs), op: ArithOp::Add, bit_width,
            });
        }
    }

    pub fn check_unsigned_mul_overflow(&self, loc: SourceLocation, lhs: u64, rhs: u64, bit_width: u8) {
        if overflows_unsigned(u128::from(lhs), u128::from(rhs), ArithOp::Mul, bit_width) {
            self.report(UbsanViolation::UnsignedIntegerOverflow {
                loc, lhs: u128::from(lhs), rhs: u128::from(rhs), op: ArithOp::Mul, bit_width,
            });
        }
    }

    // ── shift exponent ──────────────────────────────────────────────────────

    pub fn check_shift_exponent(&self, loc: SourceLocation, lhs: u64, rhs: i64, bit_width: u8) {
        let neg = rhs < 0;
        let too_large = rhs >= i64::from(bit_width);
        if neg || too_large {
            self.report(UbsanViolation::ShiftExponent {
                loc, lhs, rhs, bit_width,
                exponent_negative: neg,
                exponent_too_large: too_large,
            });
        }
    }

    // ── null pointer ────────────────────────────────────────────────────────

    pub fn check_null_ptr(&self, loc: SourceLocation, ptr: u64, access_size: usize) {
        if ptr == 0 {
            self.report(UbsanViolation::NullPointerDereference { loc, ptr, access_size });
        }
    }

    // ── alignment ───────────────────────────────────────────────────────────

    pub fn check_alignment(&self, loc: SourceLocation, ptr: u64, alignment: usize, access_size: usize) {
        if alignment > 1 && !ptr.is_multiple_of(alignment as u64) {
            self.report(UbsanViolation::MisalignedAccess { loc, ptr, alignment, access_size });
        }
    }

    // ── enum value ──────────────────────────────────────────────────────────

    pub fn check_enum_value(&self, loc: SourceLocation, value: u64, valid_max: u64, enum_name: impl Into<String>) {
        if value > valid_max {
            self.report(UbsanViolation::InvalidEnumValue {
                loc, value, enum_name: enum_name.into(),
            });
        }
    }

    // ── array bounds ────────────────────────────────────────────────────────

    pub fn check_array_bounds(&self, loc: SourceLocation, index: i64, bound: u64) {
        if index < 0 || index.cast_unsigned() >= bound {
            self.report(UbsanViolation::ArrayIndexOutOfBounds { loc, index, bound });
        }
    }

    // ── bool value ──────────────────────────────────────────────────────────

    pub fn check_bool_value(&self, loc: SourceLocation, value: u8) {
        if value > 1 {
            self.report(UbsanViolation::InvalidBoolValue { loc, value });
        }
    }

    // ── function type mismatch ──────────────────────────────────────────────

    pub fn check_function_type_mismatch(
        &self,
        loc: SourceLocation,
        callee_addr: u64,
        expected_type: impl Into<String>,
        actual_type: impl Into<String>,
        types_match: bool,
    ) {
        if !types_match {
            self.report(UbsanViolation::FunctionTypeMismatch {
                loc,
                callee_addr,
                expected_type: expected_type.into(),
                actual_type: actual_type.into(),
            });
        }
    }

    // ── vptr type mismatch ──────────────────────────────────────────────────

    pub fn check_vptr_type_mismatch(
        &self,
        loc: SourceLocation,
        ptr: u64,
        expected_type: impl Into<String>,
        actual_type: impl Into<String>,
        types_match: bool,
    ) {
        if !types_match {
            self.report(UbsanViolation::VptrTypeMismatch {
                loc,
                ptr,
                expected_type: expected_type.into(),
                actual_type: actual_type.into(),
            });
        }
    }

    // ── division by zero ────────────────────────────────────────────────────

    pub fn check_division_by_zero(&self, loc: SourceLocation, lhs: i64, divisor: i64, bit_width: u8) {
        if divisor == 0 {
            self.report(UbsanViolation::DivisionByZero { loc, lhs, bit_width });
        }
    }

    // ── pointer overflow ─────────────────────────────────────────────────────

    pub fn check_pointer_overflow(&self, loc: SourceLocation, base: u64, offset: i64) {
        let result = base.wrapping_add(offset.cast_unsigned());
        let overflowed = if offset < 0 { result > base } else { result < base };
        if overflowed {
            self.report(UbsanViolation::PointerOverflow { loc, base, result });
        }
    }

    // ── unreachable ──────────────────────────────────────────────────────────

    pub fn handle_unreachable(&self, loc: SourceLocation) {
        self.report(UbsanViolation::Unreachable { loc });
    }

    pub fn handle_missing_return(&self, loc: SourceLocation) {
        self.report(UbsanViolation::MissingReturn { loc });
    }

    // ── unaligned load ───────────────────────────────────────────────────────

    pub fn check_unaligned_load(
        &self,
        loc: SourceLocation,
        ptr: u64,
        type_name: impl Into<String>,
        required_align: usize,
    ) {
        if !ptr.is_multiple_of(required_align as u64) {
            self.report(UbsanViolation::UnalignedLoad {
                loc,
                ptr,
                type_name: type_name.into(),
                required_align,
            });
        }
    }

    // ── summary ──────────────────────────────────────────────────────────────

    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn summary(&self) -> UbsanSummary {
        let violations = self.violations.lock().unwrap();
        let mut s = UbsanSummary {
            total: violations.len(),
            signed_overflows: 0,
            unsigned_overflows: 0,
            shift_errors: 0,
            null_derefs: 0,
            misaligned: 0,
            array_oob: 0,
            invalid_enum: 0,
            invalid_bool: 0,
            type_mismatches: 0,
            div_by_zero: 0,
            other: 0,
        };
        for v in violations.iter() {
            match v {
                UbsanViolation::SignedIntegerOverflow { .. } => s.signed_overflows += 1,
                UbsanViolation::UnsignedIntegerOverflow { .. } => s.unsigned_overflows += 1,
                UbsanViolation::ShiftExponent { .. } => s.shift_errors += 1,
                UbsanViolation::NullPointerDereference { .. } => s.null_derefs += 1,
                UbsanViolation::MisalignedAccess { .. } | UbsanViolation::UnalignedLoad { .. } => {
                    s.misaligned += 1;
                }
                UbsanViolation::ArrayIndexOutOfBounds { .. } => s.array_oob += 1,
                UbsanViolation::InvalidEnumValue { .. } => s.invalid_enum += 1,
                UbsanViolation::InvalidBoolValue { .. } => s.invalid_bool += 1,
                UbsanViolation::FunctionTypeMismatch { .. }
                | UbsanViolation::VptrTypeMismatch { .. } => s.type_mismatches += 1,
                UbsanViolation::DivisionByZero { .. } => s.div_by_zero += 1,
                _ => s.other += 1,
            }
        }
        drop(violations);
        s
    }
}

// ─── arithmetic helpers ───────────────────────────────────────────────────────

/// Clamp a caller-supplied bit width to a width this model can represent.
///
/// `bit_width` arrives straight from the public `check_*_overflow` parameters
/// and is validated nowhere, so it can be `0` or wider than 128. Both are
/// degenerate for the `i128`/`u128` arithmetic below: `128 - bit_width`
/// underflows for widths above 128, which panics in a build with overflow
/// checks enabled and wraps silently otherwise — so the very same call would
/// behave differently depending on the build profile. Clamping removes that
/// divergence and keeps the shift amount in range.
fn clamp_bit_width(bit_width: u8) -> u32 {
    u32::from(bit_width).clamp(1, 128)
}

/// Inclusive `[min, max]` range of a signed integer of `bit_width` bits.
fn signed_bounds(bit_width: u8) -> (i128, i128) {
    let bits = clamp_bit_width(bit_width);
    (i128::MIN >> (128 - bits), i128::MAX >> (128 - bits))
}

/// Largest value representable by an unsigned integer of `bit_width` bits.
fn unsigned_max(bit_width: u8) -> u128 {
    u128::MAX >> (128 - clamp_bit_width(bit_width))
}

fn overflows_signed(lhs: i128, rhs: i128, op: ArithOp, bit_width: u8) -> bool {
    let result = match op {
        ArithOp::Add => lhs.checked_add(rhs),
        ArithOp::Sub => lhs.checked_sub(rhs),
        ArithOp::Mul => lhs.checked_mul(rhs),
        ArithOp::Neg => lhs.checked_neg(),
        _ => return false,
    };
    result.is_none_or(|v| {
            let (min, max) = signed_bounds(bit_width);
            v < min || v > max
        })
}

fn overflows_unsigned(lhs: u128, rhs: u128, op: ArithOp, bit_width: u8) -> bool {
    let result = match op {
        ArithOp::Add => lhs.checked_add(rhs),
        ArithOp::Mul => lhs.checked_mul(rhs),
        _ => return false,
    };
    result.is_none_or(|v| v > unsigned_max(bit_width))
}

// ─── UBSan report summary ─────────────────────────────────────────────────────

/// Summary suitable for fuzzer output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbsanSummary {
    pub total: usize,
    pub signed_overflows: usize,
    pub unsigned_overflows: usize,
    pub shift_errors: usize,
    pub null_derefs: usize,
    pub misaligned: usize,
    pub array_oob: usize,
    pub invalid_enum: usize,
    pub invalid_bool: usize,
    pub type_mismatches: usize,
    pub div_by_zero: usize,
    pub other: usize,
}

// ─── UbsanCheck trait (backwards compat) ─────────────────────────────────────

/// Trait for individual check implementations (kept for API compatibility).
pub trait UbsanCheck: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, rt: &UbsanRuntime, loc: SourceLocation, args: &[u64]);
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> SourceLocation {
        SourceLocation::new("test.c", 10, 5)
    }

    fn rt() -> UbsanRuntime {
        UbsanRuntime::new(RecoveryMode::Continue)
    }

    #[test]
    fn signed_add_overflow_detected() {
        let r = rt();
        r.check_signed_add_overflow(loc(), i64::MAX, 1, 64);
        assert_eq!(r.violation_count(), 1);
    }

    #[test]
    fn signed_add_no_overflow() {
        let r = rt();
        r.check_signed_add_overflow(loc(), 1, 2, 64);
        assert_eq!(r.violation_count(), 0);
    }

    #[test]
    fn shift_exponent_negative() {
        let r = rt();
        r.check_shift_exponent(loc(), 5, -1, 32);
        assert_eq!(r.violation_count(), 1);
        let v = &r.violations()[0];
        assert!(matches!(v, UbsanViolation::ShiftExponent { exponent_negative: true, .. }));
    }

    #[test]
    fn null_ptr_deref() {
        let r = rt();
        r.check_null_ptr(loc(), 0, 4);
        assert!(matches!(r.violations()[0], UbsanViolation::NullPointerDereference { .. }));
    }

    #[test]
    fn misaligned_access() {
        let r = rt();
        r.check_alignment(loc(), 0x1003, 4, 4);
        assert!(matches!(r.violations()[0], UbsanViolation::MisalignedAccess { .. }));
    }

    #[test]
    fn array_oob() {
        let r = rt();
        r.check_array_bounds(loc(), 10, 10);
        assert!(matches!(r.violations()[0], UbsanViolation::ArrayIndexOutOfBounds { .. }));
    }

    #[test]
    fn invalid_bool() {
        let r = rt();
        r.check_bool_value(loc(), 2);
        assert!(matches!(r.violations()[0], UbsanViolation::InvalidBoolValue { .. }));
    }

    #[test]
    fn div_by_zero() {
        let r = rt();
        r.check_division_by_zero(loc(), 42, 0, 32);
        assert!(matches!(r.violations()[0], UbsanViolation::DivisionByZero { .. }));
    }

    #[test]
    fn summary_counts() {
        let r = rt();
        r.check_signed_add_overflow(loc(), i64::MAX, 1, 64);
        r.check_null_ptr(loc(), 0, 4);
        let s = r.summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.signed_overflows, 1);
        assert_eq!(s.null_derefs, 1);
    }

    #[test]
    fn source_location_display() {
        let loc = SourceLocation::new("foo.rs", 42, 7);
        assert_eq!(format!("{loc}"), "foo.rs:42:7");
    }
}
