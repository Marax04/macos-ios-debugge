//! Return type analyzer: track return register (eax/rax/xmm0),
//! multi-value returns (edx:eax), pointer vs scalar discrimination.

use serde::{Deserialize, Serialize};

// ─── Return type ─────────────────────────────────────────────────────────────

/// Inferred return type of a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReturnType {
    /// 8-bit integer.
    Int8,
    /// 16-bit integer.
    Int16,
    /// 32-bit integer.
    Int32,
    /// 64-bit integer.
    Int64,
    /// 128-bit integer (e.g., __int128 or pair of 64-bit regs).
    Int128,
    /// Pointer (64-bit on `x86_64`, 32-bit on x86).
    Pointer,
    /// Single-precision float.
    Float32,
    /// Double-precision float.
    Float64,
    /// Extended-precision float (x87 FPU).
    FloatX87,
    /// 128-bit SIMD vector.
    Vector128,
    /// 256-bit SIMD vector.
    Vector256,
    /// Boolean (typically returned in AL/EAX with value 0 or 1).
    Bool,
    /// Void (no return value).
    Void,
    /// Struct returned via hidden pointer (first argument).
    StructByPointer,
    /// Struct returned directly in two registers (e.g., rdx:rax).
    StructInRegs { reg0: String, reg1: String },
    /// Unknown return type.
    Unknown,
}

impl std::fmt::Display for ReturnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int8 => write!(f, "i8"),
            Self::Int16 => write!(f, "i16"),
            Self::Int32 => write!(f, "i32"),
            Self::Int64 => write!(f, "i64"),
            Self::Int128 => write!(f, "i128"),
            Self::Pointer => write!(f, "ptr"),
            Self::Float32 => write!(f, "f32"),
            Self::Float64 => write!(f, "f64"),
            Self::FloatX87 => write!(f, "f80"),
            Self::Vector128 => write!(f, "v128"),
            Self::Vector256 => write!(f, "v256"),
            Self::Bool => write!(f, "bool"),
            Self::Void => write!(f, "void"),
            Self::StructByPointer => write!(f, "struct*"),
            Self::StructInRegs { reg0, reg1 } => write!(f, "struct({reg0}:{reg1})"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl ReturnType {
    /// Size in bytes (0 for void/unknown).
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        match self {
            Self::Int8 | Self::Bool => 1,
            Self::Int16 => 2,
            Self::Int32 | Self::Float32 => 4,
            Self::Int64 | Self::Float64 | Self::Pointer => 8,
            Self::FloatX87 => 10,
            Self::Int128 | Self::Vector128 => 16,
            Self::StructInRegs { .. } => 16,
            Self::Vector256 => 32,
            Self::Void | Self::Unknown | Self::StructByPointer => 0,
        }
    }

    /// Whether this is a floating-point return.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float32 | Self::Float64 | Self::FloatX87 | Self::Vector128 | Self::Vector256)
    }

    /// Whether this type is returned in an integer register.
    #[must_use]
    pub const fn uses_int_reg(&self) -> bool {
        matches!(self, Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64 | Self::Int128 | Self::Pointer | Self::Bool)
    }
}

// ─── Return evidence ─────────────────────────────────────────────────────────

/// Evidence for return type gathered from instruction analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReturnEvidence {
    /// Registers written just before return.
    pub written_before_ret: Vec<String>,
    /// Whether EAX/RAX was written before return.
    pub rax_written: bool,
    /// Whether EDX/RDX was written before return (multi-value).
    pub rdx_written: bool,
    /// Whether XMM0 was written before return.
    pub xmm0_written: bool,
    /// Whether ST0 (x87 FPU) was written.
    pub st0_written: bool,
    /// Whether only AL/BL/CL (byte sub-registers) were written.
    pub only_byte_reg: bool,
    /// Whether RAX was zeroed (xor rax, rax or xor eax, eax).
    pub rax_zeroed: bool,
    /// Whether the function appears to call another function after last write.
    pub tail_call: bool,
    /// Whether a hidden pointer was observed in RCX/RDI (return struct).
    pub hidden_ptr_in_rcx: bool,
    pub hidden_ptr_in_rdi: bool,
    /// The widest write to EAX/RAX family seen.
    pub rax_width_bits: u32,
    /// Observed constant return value (if deterministic).
    pub constant_return: Option<i64>,
}

// ─── Return instruction model ─────────────────────────────────────────────────

/// Simplified instruction for return-type analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnInstr {
    pub address: u64,
    pub kind: ReturnInstrKind,
}

/// Instruction kind for return analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReturnInstrKind {
    /// Write to register.
    RegWrite { reg: String, width_bits: u32 },
    /// Read from a register.
    ///
    /// A read that happens BEFORE any write to the same register makes it a
    /// live-in — an incoming argument. That is the real signal for a hidden
    /// struct-return pointer, and it could not be expressed before this
    /// variant existed (see [`ReturnEvidence::hidden_ptr_in_rdi`]).
    RegRead { reg: String },
    /// XOR reg, reg (zeroing).
    XorSelf { reg: String },
    /// Move immediate to register.
    MovImm { reg: String, imm: i64 },
    /// A RET / RETN instruction.
    Ret { imm: u32 },
    /// A CALL (may be tail call).
    Call { target: Option<u64> },
    /// ST0 written (x87 return).
    Fpu,
    /// Other instruction.
    Other,
}

// ─── ReturnTypeAnalyzer ───────────────────────────────────────────────────────

/// Analyzes a function's instruction stream to infer the return type.
pub struct ReturnTypeAnalyzer {
    pub arch_bits: u32,
    pub analysis_window: usize,
}

impl Default for ReturnTypeAnalyzer {
    fn default() -> Self {
        Self {
            arch_bits: 64,
            analysis_window: 50,
        }
    }
}

impl ReturnTypeAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new(arch_bits: u32) -> Self {
        Self { arch_bits, analysis_window: 50 }
    }

    /// Collect return evidence from a function's instruction stream.
    #[must_use]
    pub fn collect_evidence(&self, instrs: &[ReturnInstr]) -> ReturnEvidence {
        let mut ev = ReturnEvidence::default();
        let window = if instrs.len() > self.analysis_window {
            &instrs[instrs.len() - self.analysis_window..]
        } else {
            instrs
        };

        let mut recent_writes: Vec<(String, u32)> = Vec::new();
        // Every register name written so far, for live-in detection: a read
        // that is NOT preceded by a write to the same register is an incoming
        // argument.
        let mut written_regs: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for instr in window {
            match &instr.kind {
                ReturnInstrKind::RegWrite { reg, width_bits } => {
                    let canonical = canonicalize_reg(reg, self.arch_bits);
                    if !recent_writes.iter().any(|(r, _)| r == &canonical) {
                        recent_writes.push((canonical.clone(), *width_bits));
                        if recent_writes.len() > 16 { recent_writes.remove(0); }
                    }
                    written_regs.insert(reg.to_lowercase());
                    written_regs.insert(canonical.to_lowercase());
                    update_evidence_from_write(&mut ev, reg, *width_bits, self.arch_bits);
                }
                ReturnInstrKind::RegRead { reg } => {
                    update_evidence_from_read(&mut ev, reg, &written_regs);
                }
                ReturnInstrKind::XorSelf { reg } => {
                    let canonical = canonicalize_reg(reg, self.arch_bits);
                    if canonical == "rax" || canonical == "eax" {
                        ev.rax_zeroed = true;
                        ev.rax_written = true;
                        ev.rax_width_bits = ev.rax_width_bits.max(32);
                        ev.constant_return = Some(0);
                    }
                    if !recent_writes.iter().any(|(r, _)| r == &canonical) {
                        recent_writes.push((canonical, 32));
                    }
                }
                ReturnInstrKind::MovImm { reg, imm } => {
                    let canonical = canonicalize_reg(reg, self.arch_bits);
                    // Bug fix (2026-07-12): previously this always used the
                    // architecture's native width (64 on x86-64) regardless of
                    // which sub-register was actually written, so `mov eax,
                    // 42` (a 32-bit write that zero-extends and clears the
                    // upper 32 bits of RAX) was misreported as a full 64-bit
                    // write. That pushed `infer_from_evidence` into the
                    // `_ => Pointer/Int64` branch instead of `Int32` for
                    // ordinary 32-bit immediate loads. Derive the width from
                    // the register name itself, falling back to the
                    // architecture width only for unrecognized names.
                    let width = reg_native_width_bits(reg).unwrap_or(if self.arch_bits == 64 { 64 } else { 32 });
                    if canonical == "rax" || canonical == "eax" {
                        ev.rax_written = true;
                        ev.rax_width_bits = ev.rax_width_bits.max(width);
                        ev.constant_return = Some(*imm);
                    }
                    if !recent_writes.iter().any(|(r, _)| r == &canonical) {
                        recent_writes.push((canonical, width));
                    }
                }
                ReturnInstrKind::Fpu => {
                    ev.st0_written = true;
                }
                ReturnInstrKind::Call { .. } => {
                    ev.tail_call = true;
                }
                ReturnInstrKind::Ret { .. } => {
                    ev.written_before_ret = recent_writes.iter().map(|(r, _)| r.clone()).collect();
                    break;
                }
                ReturnInstrKind::Other => {}
            }
        }
        ev
    }

    /// Infer the return type from evidence.
    #[must_use]
    pub fn infer_from_evidence(&self, ev: &ReturnEvidence) -> ReturnTypeResult {
        // x87 FPU return
        if ev.st0_written {
            return ReturnTypeResult::new(ReturnType::FloatX87, 0.95);
        }

        // XMM0 float return
        if ev.xmm0_written {
            return ReturnTypeResult::new(ReturnType::Float64, 0.85);
        }

        // Struct by pointer (RDI/RCX is the hidden pointer)
        if ev.hidden_ptr_in_rdi || ev.hidden_ptr_in_rcx {
            return ReturnTypeResult::new(ReturnType::StructByPointer, 0.80);
        }

        // Multi-value: both RAX and RDX written (rdx:rax pair)
        if ev.rax_written && ev.rdx_written {
            if self.arch_bits == 64 {
                return ReturnTypeResult::new(
                    ReturnType::StructInRegs { reg0: "rax".into(), reg1: "rdx".into() },
                    0.85,
                );
            }
            return ReturnTypeResult::new(
                ReturnType::Int128,
                0.75,
            );
        }

        // Void: no relevant register written
        if !ev.rax_written && !ev.xmm0_written && !ev.rdx_written && !ev.st0_written {
            return ReturnTypeResult::new(ReturnType::Void, 0.75);
        }

        if !ev.rax_written {
            return ReturnTypeResult::new(ReturnType::Void, 0.6);
        }

        // RAX written: determine sub-type from width
        match ev.rax_width_bits {
            0 => ReturnTypeResult::new(ReturnType::Void, 0.5),
            1..=8 => ReturnTypeResult::new(ReturnType::Int8, 0.7),
            9..=16 => ReturnTypeResult::new(ReturnType::Int16, 0.7),
            17..=32 => {
                // Disambiguate bool vs int32 vs pointer
                if let Some(c) = ev.constant_return
                    && (c == 0 || c == 1) {
                        return ReturnTypeResult::new(ReturnType::Bool, 0.8);
                    }
                if ev.rax_zeroed {
                    ReturnTypeResult::new(ReturnType::Bool, 0.65)
                } else {
                    ReturnTypeResult::new(ReturnType::Int32, 0.75)
                }
            }
            _ => {
                // 64-bit: could be int64 or pointer
                ReturnTypeResult::new(ReturnType::Pointer, 0.6)
                    .with_alternative(ReturnType::Int64, 0.55)
            }
        }
    }

    /// Full analysis: collect evidence then infer type.
    #[must_use]
    pub fn analyze(&self, instrs: &[ReturnInstr]) -> ReturnTypeResult {
        let ev = self.collect_evidence(instrs);
        let mut result = self.infer_from_evidence(&ev);
        result.evidence = Some(ev);
        result
    }
}

/// Native width in bits implied by a register's own name (independent of
/// architecture), e.g. `"eax"` is always 32 bits and `"al"` is always 8 bits
/// even on a 64-bit target. Returns `None` for unrecognized names so callers
/// can fall back to an architecture-wide default.
fn reg_native_width_bits(reg: &str) -> Option<u32> {
    let r = reg.to_lowercase();
    match r.as_str() {
        "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "bpl" | "spl" => Some(8),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" => Some(16),
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" => Some(32),
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" => Some(64),
        _ => {
            // r8-r15 family: r8b/r9w.../r10d/r11 (bare = 64-bit).
            if let Some(rest) = r.strip_prefix('r') {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if !digits.is_empty() && digits.parse::<u32>().is_ok_and(|n| (8..=15).contains(&n)) {
                    let suffix = &rest[digits.len()..];
                    return Some(match suffix {
                        "b" => 8,
                        "w" => 16,
                        "d" => 32,
                        "" => 64,
                        _ => return None,
                    });
                }
            }
            None
        }
    }
}

fn canonicalize_reg(reg: &str, arch_bits: u32) -> String {
    let r = reg.to_lowercase();
    if arch_bits == 64 {
        match r.as_str() {
            "eax" | "ax" | "al" | "ah" => "rax".into(),
            "ebx" | "bx" | "bl" | "bh" => "rbx".into(),
            "ecx" | "cx" | "cl" | "ch" => "rcx".into(),
            "edx" | "dx" | "dl" | "dh" => "rdx".into(),
            _ => r,
        }
    } else {
        match r.as_str() {
            "rax" | "ax" | "al" | "ah" => "eax".into(),
            "rbx" | "bx" | "bl" | "bh" => "ebx".into(),
            "rcx" | "cx" | "cl" | "ch" => "ecx".into(),
            "rdx" | "dx" | "dl" | "dh" => "edx".into(),
            _ => r,
        }
    }
}

fn update_evidence_from_write(ev: &mut ReturnEvidence, reg: &str, width_bits: u32, arch_bits: u32) {
    let r = reg.to_lowercase();
    let is_rax = r == "rax" || r == "eax" || r == "ax" || r == "al";
    let is_rdx = r == "rdx" || r == "edx" || r == "dx" || r == "dl";
    let is_xmm0 = r == "xmm0" || r == "ymm0";
    let is_al = r == "al" || r == "bl";

    if is_rax {
        ev.rax_written = true;
        ev.rax_width_bits = ev.rax_width_bits.max(width_bits);
        if arch_bits == 32 && ev.hidden_ptr_in_rcx {
            ev.rax_written = true;
        }
    }
    if is_rdx { ev.rdx_written = true; }
    if is_xmm0 { ev.xmm0_written = true; }
    if is_al && width_bits <= 8 { ev.only_byte_reg = true; }
    // A WRITE to rdi/rcx says nothing about the return type — it is ordinary
    // argument setup before a call. The hidden struct-return pointer is a
    // register the function READS on entry, which is handled by
    // `update_evidence_from_read`. Setting the flag here short-circuited
    // `infer_from_evidence` to `StructByPointer` ahead of every RAX signal, so
    // `mov edi, …; mov eax, 42; ret` was reported as returning a struct.
    // `heuristics.rs::profile_arg_registers` already does read-before-write.
}

/// Record a register READ. A read that precedes any write to the same register
/// makes it a live-in, i.e. an incoming argument.
fn update_evidence_from_read(
    ev: &mut ReturnEvidence,
    reg: &str,
    written: &std::collections::HashSet<String>,
) {
    let r = reg.to_lowercase();
    if written.contains(&r) {
        return;
    }
    if r == "rdi" || r == "edi" {
        ev.hidden_ptr_in_rdi = true;
    }
    if r == "rcx" || r == "ecx" {
        ev.hidden_ptr_in_rcx = true;
    }
}

// ─── Result type ─────────────────────────────────────────────────────────────

/// Return type inference result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnTypeResult {
    /// Primary inferred return type.
    pub primary: ReturnType,
    /// Confidence in the primary type (0..1).
    pub confidence: f32,
    /// Alternative type candidates with their confidences.
    pub alternatives: Vec<(ReturnType, f32)>,
    /// Evidence used (optional, expensive to clone).
    pub evidence: Option<ReturnEvidence>,
}

impl ReturnTypeResult {
    const fn new(primary: ReturnType, confidence: f32) -> Self {
        Self {
            primary,
            confidence,
            alternatives: vec![],
            evidence: None,
        }
    }

    fn with_alternative(mut self, ty: ReturnType, conf: f32) -> Self {
        self.alternatives.push((ty, conf));
        self
    }

    /// Returns `true` if this is a high-confidence result.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Return the best type (highest confidence).
    #[must_use]
    pub fn best(&self) -> &ReturnType {
        // `partial_cmp` returns `None` for NaN confidences; treat those as
        // equal rather than panicking (confidences are computed values, not
        // trusted invariants, so a NaN must not crash the analyzer).
        let best_alt = self
            .alternatives
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        if let Some((alt, conf)) = best_alt
            && *conf > self.confidence { return alt; }
        &self.primary
    }
}

// ─── Batch analysis ───────────────────────────────────────────────────────────

/// Analyze return types for multiple functions.
#[must_use]
pub fn analyze_return_types(
    functions: &[(u64, Vec<ReturnInstr>)],
    arch_bits: u32,
) -> Vec<(u64, ReturnTypeResult)> {
    let analyzer = ReturnTypeAnalyzer::new(arch_bits);
    functions
        .iter()
        .map(|(addr, instrs)| (*addr, analyzer.analyze(instrs)))
        .collect()
}

/// Statistics over return type analysis.
#[derive(Debug, Clone, Default)]
pub struct ReturnTypeStats {
    pub total: usize,
    pub void_count: usize,
    pub int_count: usize,
    pub ptr_count: usize,
    pub float_count: usize,
    pub bool_count: usize,
    pub multi_value_count: usize,
    pub struct_by_ptr: usize,
    pub unknown_count: usize,
}

impl ReturnTypeStats {
    /// Compute stats over results.
    #[must_use]
    pub fn compute(results: &[(u64, ReturnTypeResult)]) -> Self {
        let mut stats = Self::default();
        stats.total = results.len();
        for (_, r) in results {
            match r.best() {
                ReturnType::Void => stats.void_count += 1,
                ReturnType::Int8 | ReturnType::Int16 | ReturnType::Int32
                | ReturnType::Int64 | ReturnType::Int128 => stats.int_count += 1,
                ReturnType::Pointer => stats.ptr_count += 1,
                ReturnType::Float32 | ReturnType::Float64 | ReturnType::FloatX87
                | ReturnType::Vector128 | ReturnType::Vector256 => stats.float_count += 1,
                ReturnType::Bool => stats.bool_count += 1,
                ReturnType::StructInRegs { .. } => stats.multi_value_count += 1,
                ReturnType::StructByPointer => stats.struct_by_ptr += 1,
                ReturnType::Unknown => stats.unknown_count += 1,
            }
        }
        stats
    }
}

// ─── Register pattern library ─────────────────────────────────────────────────

/// Known return register patterns for standard calling conventions.
pub struct ReturnRegisterPatterns;

impl ReturnRegisterPatterns {
    /// Return value registers for x86 cdecl/stdcall/fastcall.
    pub const X86_INT_RETURN: &'static [&'static str] = &["eax", "edx"];
    /// Return value registers for `x86_64` `SysV`.
    pub const X64_SYSV_RETURN: &'static [&'static str] = &["rax", "rdx"];
    /// Return value registers for `x86_64` MS-x64.
    pub const X64_MS_RETURN: &'static [&'static str] = &["rax"];
    /// Float return for `SysV`.
    pub const X64_SYSV_FP_RETURN: &'static [&'static str] = &["xmm0", "xmm1"];
    /// Float return for x87.
    pub const X86_FP_RETURN: &'static [&'static str] = &["st0"];
    /// ARM32 return.
    pub const ARM32_RETURN: &'static [&'static str] = &["r0", "r1"];
    /// ARM64 return.
    pub const ARM64_RETURN: &'static [&'static str] = &["x0", "x1"];
    /// MIPS return.
    pub const MIPS_RETURN: &'static [&'static str] = &["v0", "v1"];
    /// RISC-V return.
    pub const RISCV_RETURN: &'static [&'static str] = &["a0", "a1"];

    /// Whether `reg` is a known return register for `arch_bits`-bit code.
    #[must_use]
    pub fn is_return_register(reg: &str, arch_bits: u32) -> bool {
        let r = reg.to_lowercase();
        if arch_bits == 64 {
            Self::X64_SYSV_RETURN.contains(&r.as_str())
                || Self::X64_MS_RETURN.contains(&r.as_str())
                || Self::X64_SYSV_FP_RETURN.contains(&r.as_str())
        } else {
            Self::X86_INT_RETURN.contains(&r.as_str())
                || Self::X86_FP_RETURN.contains(&r.as_str())
        }
    }
}

// ─── Heuristic classifier ─────────────────────────────────────────────────────

/// Classify return type from a raw observed pattern.
#[must_use]
pub fn classify_return_from_observed(
    observed: &crate::ObservedPattern,
    arch_bits: u32,
) -> ReturnTypeResult {
    let ret_regs = &observed.written_before_return;

    let has_rax = ret_regs.iter().any(|r| {
        let r = r.to_lowercase();
        r == "rax" || r == "eax" || r == "ax" || r == "al"
    });
    let has_rdx = ret_regs.iter().any(|r| {
        let r = r.to_lowercase();
        r == "rdx" || r == "edx"
    });
    let has_xmm0 = ret_regs.iter().any(|r| r.to_lowercase().starts_with("xmm0"));
    let has_st0 = ret_regs.iter().any(|r| r == "st0");

    if has_st0 {
        return ReturnTypeResult::new(ReturnType::FloatX87, 0.90);
    }
    if has_xmm0 {
        return ReturnTypeResult::new(ReturnType::Float64, 0.80);
    }
    if has_rax && has_rdx {
        return ReturnTypeResult::new(
            ReturnType::StructInRegs { reg0: if arch_bits == 64 { "rax".into() } else { "eax".into() },
                                       reg1: if arch_bits == 64 { "rdx".into() } else { "edx".into() } },
            0.80,
        );
    }
    if has_rax {
        return ReturnTypeResult::new(
            if arch_bits == 64 { ReturnType::Int64 } else { ReturnType::Int32 },
            0.65,
        );
    }
    if ret_regs.is_empty() {
        return ReturnTypeResult::new(ReturnType::Void, 0.70);
    }
    ReturnTypeResult::new(ReturnType::Unknown, 0.4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_void_fn() -> Vec<ReturnInstr> {
        vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::Ret { imm: 0 } },
        ]
    }

    fn make_int_fn() -> Vec<ReturnInstr> {
        vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::MovImm { reg: "eax".into(), imm: 42 } },
            ReturnInstr { address: 5, kind: ReturnInstrKind::Ret { imm: 0 } },
        ]
    }

    fn make_bool_fn() -> Vec<ReturnInstr> {
        vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::XorSelf { reg: "eax".into() } },
            ReturnInstr { address: 2, kind: ReturnInstrKind::Ret { imm: 0 } },
        ]
    }

    fn make_float_fn() -> Vec<ReturnInstr> {
        vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::RegWrite { reg: "xmm0".into(), width_bits: 64 } },
            ReturnInstr { address: 8, kind: ReturnInstrKind::Ret { imm: 0 } },
        ]
    }

    fn make_multi_fn() -> Vec<ReturnInstr> {
        vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::RegWrite { reg: "rax".into(), width_bits: 64 } },
            ReturnInstr { address: 4, kind: ReturnInstrKind::RegWrite { reg: "rdx".into(), width_bits: 64 } },
            ReturnInstr { address: 8, kind: ReturnInstrKind::Ret { imm: 0 } },
        ]
    }

    #[test]
    fn test_void_return() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let result = analyzer.analyze(&make_void_fn());
        assert_eq!(*result.best(), ReturnType::Void);
    }

    #[test]
    fn test_int_return() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let result = analyzer.analyze(&make_int_fn());
        // `mov eax, 42` is a 32-bit write with a non-0/1 constant: must be
        // classified precisely as Int32, not loosely as any int-ish type.
        assert_eq!(*result.best(), ReturnType::Int32);
    }

    #[test]
    fn test_bool_return() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let result = analyzer.analyze(&make_bool_fn());
        // `xor eax, eax` zeroing with nothing else written → Bool precisely.
        assert_eq!(*result.best(), ReturnType::Bool);
    }

    /// Regression test for the register-width bug: on x86-64, `mov eax, imm`
    /// (32-bit sub-register) must NOT be treated as a 64-bit write just
    /// because the architecture is 64-bit. Before the fix this collapsed
    /// into the `_ => Pointer` branch instead of `Int32`.
    #[test]
    fn test_movimm_eax_is_32_bit_not_64_bit() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let instrs = vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::MovImm { reg: "eax".into(), imm: 7 } },
            ReturnInstr { address: 5, kind: ReturnInstrKind::Ret { imm: 0 } },
        ];
        let ev = analyzer.collect_evidence(&instrs);
        assert_eq!(ev.rax_width_bits, 32);
        assert_eq!(*analyzer.infer_from_evidence(&ev).best(), ReturnType::Int32);
    }

    /// A genuine 64-bit immediate load (`mov rax, imm`) should still be
    /// reported with the full 64-bit width.
    #[test]
    fn test_movimm_rax_is_64_bit() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let instrs = vec![
            ReturnInstr { address: 0, kind: ReturnInstrKind::MovImm { reg: "rax".into(), imm: 0x1_0000_0000 } },
            ReturnInstr { address: 5, kind: ReturnInstrKind::Ret { imm: 0 } },
        ];
        let ev = analyzer.collect_evidence(&instrs);
        assert_eq!(ev.rax_width_bits, 64);
    }

    #[test]
    fn test_float_return() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let result = analyzer.analyze(&make_float_fn());
        assert_eq!(*result.best(), ReturnType::Float64);
    }

    #[test]
    fn test_multi_return() {
        let analyzer = ReturnTypeAnalyzer::new(64);
        let result = analyzer.analyze(&make_multi_fn());
        assert!(matches!(*result.best(), ReturnType::StructInRegs { .. }));
    }

    #[test]
    fn test_best_does_not_panic_on_nan_alternative_confidence() {
        // `best()` must not panic even if an alternative's confidence is NaN
        // (e.g. from a corrupted/adversarial confidence computation); it
        // should fall back to treating NaN as "not better" rather than
        // unwrapping a `None` from `partial_cmp`.
        let result = ReturnTypeResult::new(ReturnType::Int32, 0.5)
            .with_alternative(ReturnType::Float64, f32::NAN);
        // Should not panic; NaN comparisons are treated as Equal, so the
        // primary type is kept unless something already beat it.
        let _ = result.best();
    }

    #[test]
    fn test_return_type_display() {
        assert_eq!(ReturnType::Void.to_string(), "void");
        assert_eq!(ReturnType::Pointer.to_string(), "ptr");
        assert_eq!(ReturnType::Float64.to_string(), "f64");
    }

    #[test]
    fn test_batch_analysis() {
        let functions = vec![
            (0x1000u64, make_void_fn()),
            (0x2000u64, make_float_fn()),
        ];
        let results = analyze_return_types(&functions, 64);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_return_stats() {
        let functions = vec![
            (0x1000u64, make_void_fn()),
            (0x2000u64, make_int_fn()),
            (0x3000u64, make_float_fn()),
        ];
        let results = analyze_return_types(&functions, 64);
        let stats = ReturnTypeStats::compute(&results);
        assert_eq!(stats.total, 3);
    }
}
