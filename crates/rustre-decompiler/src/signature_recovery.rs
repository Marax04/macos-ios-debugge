//! Phase D — Function signature recovery.
//!
//! Detects calling convention from prologue/epilogue and argument-register
//! read/write patterns, then assembles a [`RecoveredSignature`] that can be
//! rendered as a C function header.
//!
//! This module is intentionally self-contained: it only depends on a small
//! [`InstructionView`] trait so callers can plug in any disassembler output
//! (raw [`rustre_core::arch::Instruction`], lifted IL, IDA/Ghidra strings, …).

use rustre_core::arch::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// CallingConv
// ─────────────────────────────────────────────────────────────────────────────

/// Calling convention ABIs Zyphora can detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallingConv {
    /// Could not determine a calling convention from the available evidence.
    #[default]
    Unknown,
    /// Microsoft x64 — RCX, RDX, R8, R9 + stack; callee saves RBX RBP RSI RDI R12-R15.
    MsX64,
    /// System V AMD64 — RDI, RSI, RDX, RCX, R8, R9 + XMM0-7; callee saves RBX RBP R12-R15.
    SysVAmd64,
    /// cdecl 32-bit — all on stack; caller cleans.
    Cdecl32,
    /// stdcall 32-bit — all on stack; callee cleans (RET imm16).
    Stdcall32,
    /// fastcall 32-bit — ECX, EDX, rest on stack.
    Fastcall32,
    /// thiscall — ECX = this, rest on stack.
    Thiscall,
    /// Rust ABI — unspecified; falls back to MsX64/SysV based on OS.
    RustAbi,
}

impl CallingConv {
    /// Render this convention as the canonical compiler keyword (e.g. `__fastcall`).
    #[must_use]
    pub const fn as_keyword(self) -> &'static str {
        match self {
            Self::MsX64 | Self::SysVAmd64 | Self::RustAbi | Self::Unknown => "",
            Self::Cdecl32 => "__cdecl",
            Self::Stdcall32 => "__stdcall",
            Self::Fastcall32 => "__fastcall",
            Self::Thiscall => "__thiscall",
        }
    }

    /// Return the ordered list of integer parameter registers for this CC.
    #[must_use]
    pub const fn param_regs(self) -> &'static [&'static str] {
        match self {
            Self::MsX64 => &["rcx", "rdx", "r8", "r9"],
            Self::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Self::Fastcall32 => &["ecx", "edx"],
            Self::Thiscall => &["ecx"],
            Self::RustAbi | Self::Unknown | Self::Cdecl32 | Self::Stdcall32 => &[],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstructionView
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal abstraction over a disassembled instruction so this module can be
/// driven by raw [`rustre_core::arch::Instruction`], IL nodes, or test stubs.
pub trait InstructionView {
    /// Mnemonic (`"mov"`, `"push"`, `"ret"`, …) — lowercase preferred.
    fn mnemonic(&self) -> &str;
    /// Operand string (`"rcx, qword ptr [rbp-0x10]"`).
    fn operands(&self) -> &str;
    /// Whether the instruction *reads* the named register (case-insensitive).
    fn reads_register(&self, reg: &str) -> bool;
    /// Whether the instruction *writes* the named register (case-insensitive).
    fn writes_register(&self, reg: &str) -> bool;
}

impl InstructionView for Instruction {
    fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
    fn operands(&self) -> &str {
        &self.operands
    }
    fn reads_register(&self, reg: &str) -> bool {
        // Use string fallback — Instruction does not directly expose r/w sets here.
        let ops = self.operands.to_ascii_lowercase();
        let r = reg.to_ascii_lowercase();
        // Read = appears on the RHS of the first comma, or anywhere if no comma
        // (since e.g. `push rcx` reads rcx; `ret` reads nothing).
        match self.mnemonic.to_ascii_lowercase().as_str() {
            "mov" | "movq" | "movl" | "movw" | "movb" | "movzx" | "movsx" | "lea"
            // AT&T sign/zero-extend forms — pure dst writes, read only the src.
            | "movslq" | "movsxd" | "movsbl" | "movsbw" | "movsbq" | "movswl" | "movswq"
            | "movzbl" | "movzbw" | "movzbq" | "movzwl" | "movzwq" => {
                // Use the AT&T-aware split: these mnemonics (`movslq`,
                // `movzbl`, …) are AT&T spellings, and AT&T order is
                // `src, dst` — the reverse of Intel. `crate::split_two`
                // normalises both to `(dst, src)`; `lib.rs` has always gone
                // through it. Currently inert here (see `writes_register`).
                if let Some((_dst, src)) = crate::split_two(&ops) {
                    contains_register_token(src, &r)
                } else {
                    false
                }
            }
            _ => contains_register_token(&ops, &r),
        }
    }
    fn writes_register(&self, reg: &str) -> bool {
        let ops = self.operands.to_ascii_lowercase();
        let r = reg.to_ascii_lowercase();
        match self.mnemonic.to_ascii_lowercase().as_str() {
            "mov" | "movq" | "movl" | "movw" | "movb" | "movzx" | "movsx" | "lea" | "add"
            | "sub" | "and" | "or" | "xor" | "shl" | "shr" | "imul" | "pop" | "inc" | "dec"
            // AT&T sign/zero-extend forms write their register dest. Missing them
            // made `movslq …, %rcx` read as live-in → phantom param (_GetPEImageBase).
            | "movslq" | "movsxd" | "movsbl" | "movsbw" | "movsbq" | "movswl" | "movswq"
            | "movzbl" | "movzbw" | "movzbq" | "movzwl" | "movzwq" => {
                // Same AT&T hazard as `reads_register` above: in AT&T the
                // destination of `movslq %eax, %rcx` is the SECOND operand.
                //
                // MEASURED: this is currently INERT — `split_two` only swaps
                // when an operand carries a `%`/`$` sigil, and the operand text
                // reaching THIS path is not sigil-prefixed, so behaviour is
                // byte-identical (corpus 11144/0, fidelity.sh unchanged at
                // 15/16). It is kept as a correct-by-construction guard, not
                // as a fix: the previous raw `split_once(',')` silently assumed
                // Intel order while listing AT&T mnemonics.
                //
                // ⚠ Do NOT credit this with fixing `_GetPEImageBase`. Its
                // phantom `a1` does NOT come from operand order here — that
                // hypothesis was tested and disproved.
                if let Some((dst, _)) = crate::split_two(&ops) {
                    contains_register_token(dst, &r)
                } else {
                    contains_register_token(&ops, &r)
                }
            }
            "call" => matches!(r.as_str(), "rax" | "eax"),
            _ => false,
        }
    }
}

/// Word-boundary register token search.
fn contains_register_token(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return false;
    }
    let mut i = 0usize;
    while i + needle_bytes.len() <= bytes.len() {
        if bytes[i..].starts_with(needle_bytes) {
            let before_ok = i == 0 || {
                let b = bytes[i - 1];
                !b.is_ascii_alphanumeric() && b != b'_'
            };
            let after = i + needle_bytes.len();
            let after_ok = after >= bytes.len() || {
                let b = bytes[after];
                !b.is_ascii_alphanumeric() && b != b'_'
            };
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredSignature
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered function signature ready for C emission.
#[derive(Clone, Debug)]
pub struct RecoveredSignature {
    /// Detected calling convention.
    pub conv: CallingConv,
    /// `"void"`, `"int"`, `"void *"`, …
    pub return_type: String,
    /// Parameter list in source order.
    pub params: Vec<RecoveredParam>,
    /// Whether the function is variadic.
    pub varargs: bool,
    /// Whether the function never returns (gap H — Rust panic, abort, throw,
    /// `ExitProcess`, or a tail-call into any of those).
    pub is_noreturn: bool,
}

/// A single recovered parameter.
#[derive(Clone, Debug)]
pub struct RecoveredParam {
    /// `"arg_0"`, `"arg_1"`, …
    pub name: String,
    /// `"int"`, `"char *"`, `"void *"`.
    pub ty: String,
    /// Source register if passed in a register; `None` for stack params.
    pub register: Option<String>,
    /// Stack offset from rbp/rsp for stack-passed parameters.
    pub stack_offset: Option<i32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// StackFrame
// ─────────────────────────────────────────────────────────────────────────────

/// Layout of the function's stack frame as inferred from its prologue.
#[derive(Clone, Debug, Default)]
pub struct StackFrame {
    /// Bytes from `rbp` down to `rsp` after the prologue.
    pub frame_size: u32,
    /// Callee-saved registers pushed by the prologue (in push order).
    pub saved_regs: Vec<String>,
    /// True if the prologue established a frame pointer (`push rbp; mov rbp, rsp`).
    pub has_frame_pointer: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_calling_convention
// ─────────────────────────────────────────────────────────────────────────────

/// Detect a calling convention by inspecting the function's prologue.
///
/// Heuristics:
/// 1. **32-bit hint:** if `arch_bits == 32`, only the 32-bit families are
///    considered. `ECX` read before written → fastcall/thiscall; otherwise
///    cdecl (default) or stdcall (if a `RET imm16` epilogue is seen).
/// 2. **64-bit OS hint:** PE → MS x64; ELF → System V.
/// 3. **Register-read evidence:** if both RDI/RSI are read before write,
///    System V wins regardless of OS hint; if both RCX/RDX are read before
///    write *and* RDI is never read, MS x64 wins.
pub fn detect_calling_convention(
    instructions: &[impl InstructionView],
    arch_bits: u32,
    is_pe: bool,
) -> CallingConv {
    if arch_bits == 32 {
        return detect_32bit(instructions);
    }

    // 64-bit: look at register-read evidence first.
    let sysv_regs_read = reads_before_write(instructions, "rdi")
        || reads_before_write(instructions, "rsi");
    let ms_regs_read = reads_before_write(instructions, "rcx")
        || reads_before_write(instructions, "rdx");

    if sysv_regs_read {
        return CallingConv::SysVAmd64;
    }
    if ms_regs_read {
        return CallingConv::MsX64;
    }

    // No incoming register read — fall back to OS hint.
    if is_pe {
        CallingConv::MsX64
    } else {
        CallingConv::SysVAmd64
    }
}

fn detect_32bit(instructions: &[impl InstructionView]) -> CallingConv {
    let thiscall_reg_used = reads_before_write(instructions, "ecx");
    let fastcall_reg2_used = reads_before_write(instructions, "edx");
    let stdcall_epilogue = instructions.iter().any(|i| {
        let m = i.mnemonic().to_ascii_lowercase();
        m == "ret" && {
            let ops = i.operands().trim();
            !ops.is_empty() && ops != "0"
        }
    });

    if thiscall_reg_used && fastcall_reg2_used {
        CallingConv::Fastcall32
    } else if thiscall_reg_used {
        CallingConv::Thiscall
    } else if stdcall_epilogue {
        CallingConv::Stdcall32
    } else {
        CallingConv::Cdecl32
    }
}

/// True if `reg` is read in some instruction strictly before being written.
fn reads_before_write(instructions: &[impl InstructionView], reg: &str) -> bool {
    for ins in instructions {
        if ins.writes_register(reg) && !ins.reads_register(reg) {
            return false;
        }
        if ins.reads_register(reg) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_stack_frame
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the prologue (`push rbp; mov rbp, rsp; sub rsp, N`) to compute the
/// frame size, list of callee-saved registers, and frame-pointer status.
pub fn analyze_stack_frame(instructions: &[impl InstructionView]) -> StackFrame {
    let mut frame = StackFrame::default();
    let mut saw_push_rbp = false;
    let mut saw_mov_rbp_rsp = false;

    for ins in instructions.iter().take(32) {
        let m = ins.mnemonic().to_ascii_lowercase();
        let ops = ins.operands().to_ascii_lowercase();
        let ops = ops.trim();

        match m.as_str() {
            "push" => {
                let reg = ops.trim();
                if reg == "rbp" || reg == "ebp" {
                    saw_push_rbp = true;
                    frame.saved_regs.push(reg.to_string());
                } else if is_callee_saved(reg) {
                    frame.saved_regs.push(reg.to_string());
                }
            }
            "mov" => {
                // mov rbp, rsp
                if let Some((dst, src)) = ops.split_once(',') {
                    let dst = dst.trim();
                    let src = src.trim();
                    if (dst == "rbp" && src == "rsp") || (dst == "ebp" && src == "esp") {
                        saw_mov_rbp_rsp = true;
                    }
                }
            }
            "sub" => {
                // sub rsp, 0x20
                if let Some((dst, src)) = ops.split_once(',') {
                    let dst = dst.trim();
                    let src = src.trim();
                    if (dst == "rsp" || dst == "esp")
                        && let Some(n) = parse_int_literal(src) {
                            frame.frame_size = frame.frame_size.saturating_add(n);
                        }
                }
            }
            "ret" | "retn" | "leave" => break,
            _ => {}
        }
    }

    frame.has_frame_pointer = saw_push_rbp && saw_mov_rbp_rsp;
    frame
}

fn is_callee_saved(reg: &str) -> bool {
    matches!(
        reg,
        "rbx" | "rbp"
            | "rsi"
            | "rdi"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "ebx"
            | "ebp"
            | "esi"
            | "edi"
    )
}

pub(crate) fn parse_int_literal(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    // MASM-style hex: `20h`, `0A0h`.
    if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse::<u32>().ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// recover_signature
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`RecoveredSignature`] from prologue/epilogue evidence.
///
/// * Parameter count = count of consecutive arg-registers read before any
///   write, plus stack params at `[rbp+16]`, `[rbp+24]`, … .
/// * Parameter types default to `"int"` (size-based heuristic could refine).
/// * Return type = `"void"` if `rax`/`eax` is never written before `RET`,
///   else `"int"`.
pub fn recover_signature(
    instructions: &[impl InstructionView],
    _func_name: &str,
    arch_bits: u32,
    is_pe: bool,
) -> RecoveredSignature {
    let conv = detect_calling_convention(instructions, arch_bits, is_pe);

    let mut params: Vec<RecoveredParam> = Vec::new();
    let regs = conv.param_regs();

    for (idx, reg) in regs.iter().enumerate() {
        if reads_before_write(instructions, reg) {
            params.push(RecoveredParam {
                name: format!("arg_{idx}"),
                ty: default_param_type(arch_bits),
                register: Some((*reg).to_string()),
                stack_offset: None,
            });
        } else {
            break;
        }
    }

    // Stack-passed parameters: scan for [rbp+16], [rbp+24], … or [esp+4], [esp+8] …
    let mut seen_offsets: Vec<i32> = Vec::new();
    for ins in instructions {
        for off in extract_positive_stack_offsets(ins.operands(), arch_bits) {
            if !seen_offsets.contains(&off) {
                seen_offsets.push(off);
            }
        }
    }
    seen_offsets.sort_unstable();
    for off in seen_offsets {
        let idx = params.len();
        params.push(RecoveredParam {
            name: format!("arg_{idx}"),
            ty: default_param_type(arch_bits),
            register: None,
            stack_offset: Some(off),
        });
    }

    // Return type — rax/eax written before ret?
    let ret_reg = if arch_bits == 32 { "eax" } else { "rax" };
    let mut return_type = "void".to_string();
    let mut rax_written = false;
    for ins in instructions {
        let m = ins.mnemonic().to_ascii_lowercase();
        if m == "ret" || m == "retn" {
            if rax_written {
                return_type = "int".to_string();
            }
            break;
        }
        if ins.writes_register(ret_reg) {
            rax_written = true;
        }
    }
    // If we never saw a ret, fall back to the last-seen state.
    if return_type == "void" && rax_written {
        return_type = "int".to_string();
    }

    RecoveredSignature {
        conv,
        return_type,
        params,
        varargs: false,
        is_noreturn: false,
    }
}

/// Auto-driven variant of [`recover_signature`].
///
/// Runs the `rustre_analysis_callconv` detector first and only falls back to
/// the simple register-grep heuristic when the detector cannot reach a verdict.
///
/// The detector populates the parameter list from observed register reads and
/// any stack-arg offsets seen in operands; the calling convention is taken
/// straight from the detector verdict. When the detector returns
/// [`rustre_analysis_callconv::CallConvError::NoMatch`] or
/// [`rustre_analysis_callconv::CallConvError::Ambiguous`], the legacy heuristic
/// in [`recover_signature`] is used so call sites without strong evidence still
/// produce a sane signature.
#[must_use]
pub fn recover_signature_auto(
    instructions: &[Instruction],
    func_name: &str,
    arch_bits: u32,
    is_pe: bool,
) -> RecoveredSignature {
    let lifted = crate::callconv_bridge::lift_instructions(instructions);
    let arch = if arch_bits == 32 {
        rustre_analysis_callconv::Arch::X86
    } else {
        rustre_analysis_callconv::Arch::X86_64
    };
    let os = crate::callconv_bridge::os_from_pe_flag(is_pe);

    match crate::callconv_bridge::detect(&lifted, &arch, &os) {
        Ok(inf) => {
            let conv = match inf.pattern.name.to_ascii_lowercase().as_str() {
                n if n.contains("microsoft x64") || n.contains("vectorcall") => CallingConv::MsX64,
                n if n.contains("system v") => CallingConv::SysVAmd64,
                n if n.contains("fastcall") => CallingConv::Fastcall32,
                n if n.contains("thiscall") => CallingConv::Thiscall,
                n if n.contains("stdcall") => CallingConv::Stdcall32,
                n if n.contains("cdecl") => CallingConv::Cdecl32,
                _ => CallingConv::Unknown,
            };
            let mut params = inf.params;
            // If the detector found nothing register-shaped, also pull stack
            // overflow parameters via the legacy scan so signatures match the
            // ABI's calling-convention spill area.
            if params.iter().all(|p| p.register.is_none() && p.stack_offset.is_none()) {
                let fallback = recover_signature(instructions, func_name, arch_bits, is_pe);
                params = fallback.params;
            }
            // Return type — rax/eax written before ret?
            let ret_reg = if arch_bits == 32 { "eax" } else { "rax" };
            let mut return_type = "void".to_string();
            let mut rax_written = false;
            for ins in instructions {
                let m = ins.mnemonic.to_ascii_lowercase();
                if m == "ret" || m == "retn" {
                    if rax_written {
                        return_type = "int".to_string();
                    }
                    break;
                }
                if ins.writes_register(ret_reg) {
                    rax_written = true;
                }
            }
            if return_type == "void" && rax_written {
                return_type = "int".to_string();
            }
            RecoveredSignature {
                conv,
                return_type,
                params,
                varargs: false,
                is_noreturn: false,
            }
        }
        Err(_) => recover_signature(instructions, func_name, arch_bits, is_pe),
    }
}

/// Build a [`RecoveredSignature`] like [`recover_signature`] but also consult
/// a [`NoreturnDetector`] to flag the function as noreturn when its address is
/// in the detector's report.
///
/// This is the entry point used by the orchestrator after running the
/// gap-H pass over the whole binary view.
#[must_use]
pub fn recover_signature_with_noreturn(
    instructions: &[impl InstructionView],
    func_name: &str,
    arch_bits: u32,
    is_pe: bool,
    func_addr: u64,
    det: &rustre_analysis_fn::noreturn_detector::NoreturnDetector,
) -> RecoveredSignature {
    let mut sig = recover_signature(instructions, func_name, arch_bits, is_pe);
    let addr = rustre_core::address::Address::new(func_addr);
    if det.is_noreturn(addr) {
        sig.is_noreturn = true;
        sig.return_type = "void".to_string();
    }
    sig
}

fn default_param_type(_arch_bits: u32) -> String {
    "int".to_string()
}

/// Extract positive `[rbp+N]`/`[esp+N]` offsets from an operand string.
fn extract_positive_stack_offsets(operands: &str, arch_bits: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let ops = operands.to_ascii_lowercase();
    let bases: &[&str] = if arch_bits == 32 {
        &["ebp", "esp"]
    } else {
        &["rbp", "rsp"]
    };
    for base in bases {
        let mut rest = ops.as_str();
        while let Some(pos) = rest.find(base) {
            let after = &rest[pos + base.len()..];
            let after = after.trim_start();
            if let Some(num_part) = after.strip_prefix('+') {
                let num_part = num_part.trim_start();
                let end = num_part
                    .find(|c: char| {
                        !c.is_ascii_hexdigit() && c != 'x' && c != 'X' && c != 'h' && c != 'H'
                    })
                    .unwrap_or(num_part.len());
                let tok = &num_part[..end];
                if let Some(n) = parse_int_literal(tok)
                    && let Ok(signed) = i32::try_from(n)
                    // Reject implausibly large stack-arg offsets.
                    && signed <= 0x10000
                {
                    // Only count offsets above the saved-RBP slot (8/16+ on x64, 4/8+ on x86).
                    let min_param = if arch_bits == 32 { 8 } else { 16 };
                    if signed >= min_param {
                        out.push(signed);
                    }
                }
            }
            rest = &rest[pos + base.len()..];
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// render_c_signature
// ─────────────────────────────────────────────────────────────────────────────

/// Render a [`RecoveredSignature`] as a C function header, e.g.
/// `int __fastcall foo(int arg_0, int arg_1)`.
#[must_use]
pub fn render_c_signature(sig: &RecoveredSignature, name: &str) -> String {
    let kw = sig.conv.as_keyword();
    let mut header = String::new();
    if sig.is_noreturn {
        header.push_str("__attribute__((noreturn)) ");
    }
    header.push_str(&sig.return_type);
    header.push(' ');
    if !kw.is_empty() {
        header.push_str(kw);
        header.push(' ');
    }
    header.push_str(name);
    header.push('(');
    if sig.params.is_empty() {
        header.push_str("void");
    } else {
        for (i, p) in sig.params.iter().enumerate() {
            if i > 0 {
                header.push_str(", ");
            }
            header.push_str(&p.ty);
            header.push(' ');
            header.push_str(&p.name);
        }
        if sig.varargs {
            header.push_str(", ...");
        }
    }
    header.push(')');
    header
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test stub for [`InstructionView`].
    struct Ins {
        m: &'static str,
        ops: &'static str,
        reads: &'static [&'static str],
        writes: &'static [&'static str],
    }

    impl InstructionView for Ins {
        fn mnemonic(&self) -> &str {
            self.m
        }
        fn operands(&self) -> &str {
            self.ops
        }
        fn reads_register(&self, reg: &str) -> bool {
            self.reads.iter().any(|r| r.eq_ignore_ascii_case(reg))
        }
        fn writes_register(&self, reg: &str) -> bool {
            self.writes.iter().any(|r| r.eq_ignore_ascii_case(reg))
        }
    }

    fn ins(
        m: &'static str,
        ops: &'static str,
        reads: &'static [&'static str],
        writes: &'static [&'static str],
    ) -> Ins {
        Ins { m, ops, reads, writes }
    }

    #[test]
    fn void_no_args() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("pop", "rbp", &[], &["rbp"]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 64, true);
        assert_eq!(sig.return_type, "void");
        assert!(sig.params.is_empty());
        assert_eq!(sig.conv, CallingConv::MsX64);
        let rendered = render_c_signature(&sig, "f");
        assert_eq!(rendered, "void f(void)");
    }

    #[test]
    fn ms_x64_one_int_arg() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("mov", "eax, ecx", &["rcx"], &["rax"]),
            ins("pop", "rbp", &[], &["rbp"]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 64, true);
        assert_eq!(sig.conv, CallingConv::MsX64);
        assert_eq!(sig.return_type, "int");
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].register.as_deref(), Some("rcx"));
        let rendered = render_c_signature(&sig, "id");
        assert!(rendered.starts_with("int id(int arg_0)"), "got: {rendered}");
    }

    #[test]
    fn ms_x64_two_args_void() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("mov", "[rbp-8], rcx", &["rcx"], &[]),
            ins("mov", "[rbp-16], rdx", &["rdx"], &[]),
            ins("pop", "rbp", &[], &["rbp"]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 64, true);
        assert_eq!(sig.conv, CallingConv::MsX64);
        assert_eq!(sig.return_type, "void");
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].register.as_deref(), Some("rcx"));
        assert_eq!(sig.params[1].register.as_deref(), Some("rdx"));
    }

    #[test]
    fn sysv_two_args() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("mov", "[rbp-8], rdi", &["rdi"], &[]),
            ins("mov", "[rbp-16], rsi", &["rsi"], &[]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 64, false);
        assert_eq!(sig.conv, CallingConv::SysVAmd64);
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].register.as_deref(), Some("rdi"));
        assert_eq!(sig.params[1].register.as_deref(), Some("rsi"));
    }

    #[test]
    fn stack_args_only() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("mov", "eax, [rbp+16]", &[], &["rax"]),
            ins("add", "eax, [rbp+24]", &[], &["rax"]),
            ins("pop", "rbp", &[], &["rbp"]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 64, true);
        assert_eq!(sig.return_type, "int");
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].stack_offset, Some(16));
        assert_eq!(sig.params[1].stack_offset, Some(24));
        assert!(sig.params.iter().all(|p| p.register.is_none()));
    }

    #[test]
    fn stack_frame_prologue() {
        let prog = [
            ins("push", "rbp", &["rbp"], &[]),
            ins("mov", "rbp, rsp", &["rsp"], &["rbp"]),
            ins("push", "rbx", &["rbx"], &[]),
            ins("sub", "rsp, 0x20", &["rsp"], &["rsp"]),
            ins("ret", "", &[], &[]),
        ];
        let frame = analyze_stack_frame(&prog);
        assert!(frame.has_frame_pointer);
        assert_eq!(frame.frame_size, 0x20);
        assert!(frame.saved_regs.iter().any(|r| r == "rbp"));
        assert!(frame.saved_regs.iter().any(|r| r == "rbx"));
    }

    #[test]
    fn auto_path_recovers_ms_x64_params_from_real_instructions() {
        // Build a `rustre_core::arch::Instruction` stream so the auto path can
        // also be exercised end-to-end (not just the InstructionView stub).
        use rustre_core::address::Address;
        let mk = |addr, m: &str, ops: &str| {
            let mut ins = Instruction::new(Address::new(addr), 1, m, vec![]);
            ins.operands = ops.to_string();
            ins
        };
        let prog = vec![
            mk(0x1000, "push", "rbp"),
            mk(0x1001, "mov", "rbp, rsp"),
            mk(0x1004, "mov", "[rbp-8], rcx"),
            mk(0x1008, "mov", "[rbp-16], rdx"),
            mk(0x100c, "pop", "rbp"),
            mk(0x100d, "ret", ""),
        ];
        let sig = recover_signature_auto(&prog, "f", 64, true);
        assert_eq!(sig.conv, CallingConv::MsX64);
        assert!(!sig.params.is_empty());
        assert!(sig.params.iter().any(|p| p.register.as_deref() == Some("rcx")));
        assert!(sig.params.iter().any(|p| p.register.as_deref() == Some("rdx")));
    }

    #[test]
    fn fastcall32_detected() {
        let prog = [
            ins("push", "ebp", &["ebp"], &[]),
            ins("mov", "ebp, esp", &["esp"], &["ebp"]),
            ins("mov", "eax, ecx", &["ecx"], &["eax"]),
            ins("add", "eax, edx", &["edx", "eax"], &["eax"]),
            ins("ret", "", &[], &[]),
        ];
        let sig = recover_signature(&prog, "f", 32, true);
        assert_eq!(sig.conv, CallingConv::Fastcall32);
        assert_eq!(sig.return_type, "int");
        let rendered = render_c_signature(&sig, "addi");
        assert!(rendered.contains("__fastcall"), "got: {rendered}");
    }
}
