// rustre-analysis-fn/src/stack_frame_analyzer.rs
//
// Analyze stack frames: local variables, saved registers, stack cookies,
// frame size, and calling convention inference from prologue/epilogue.

use std::collections::{BTreeMap, HashMap, HashSet};

use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Register names
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known x86-64 / x86-32 register names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Register {
    // 64-bit GPRs
    Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp,
    R8, R9, R10, R11, R12, R13, R14, R15,
    // 32-bit GPRs
    Eax, Ebx, Ecx, Edx, Esi, Edi, Ebp, Esp,
    // XMM
    Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7,
    // Unknown
    Unknown(String),
}

impl Register {
    /// Parse a register name string.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "rax" => Self::Rax, "rbx" => Self::Rbx, "rcx" => Self::Rcx, "rdx" => Self::Rdx,
            "rsi" => Self::Rsi, "rdi" => Self::Rdi, "rbp" => Self::Rbp, "rsp" => Self::Rsp,
            "r8"  => Self::R8,  "r9"  => Self::R9,  "r10" => Self::R10, "r11" => Self::R11,
            "r12" => Self::R12, "r13" => Self::R13, "r14" => Self::R14, "r15" => Self::R15,
            "eax" => Self::Eax, "ebx" => Self::Ebx, "ecx" => Self::Ecx, "edx" => Self::Edx,
            "esi" => Self::Esi, "edi" => Self::Edi, "ebp" => Self::Ebp, "esp" => Self::Esp,
            "xmm0" => Self::Xmm0, "xmm1" => Self::Xmm1, "xmm2" => Self::Xmm2, "xmm3" => Self::Xmm3,
            "xmm4" => Self::Xmm4, "xmm5" => Self::Xmm5, "xmm6" => Self::Xmm6, "xmm7" => Self::Xmm7,
            other  => Self::Unknown(other.to_owned()),
        }
    }

    /// Whether this register is callee-saved in x86-64 System V ABI.
    #[must_use]
    pub const fn is_callee_saved_sysv(&self) -> bool {
        matches!(self, Self::Rbx | Self::Rbp | Self::R12 | Self::R13 | Self::R14 | Self::R15
                     | Self::Ebx | Self::Ebp)
    }

    /// Whether this register is callee-saved in Windows x64 ABI.
    #[must_use]
    pub const fn is_callee_saved_win64(&self) -> bool {
        matches!(self, Self::Rbx | Self::Rbp | Self::Rdi | Self::Rsi
                     | Self::R12 | Self::R13 | Self::R14 | Self::R15
                     | Self::Xmm6 | Self::Xmm7)
    }

    /// Register size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        match self {
            Self::Rax | Self::Rbx | Self::Rcx | Self::Rdx | Self::Rsi | Self::Rdi
            | Self::Rbp | Self::Rsp | Self::R8  | Self::R9  | Self::R10 | Self::R11
            | Self::R12 | Self::R13 | Self::R14 | Self::R15
            | Self::Unknown(_) => 8,
            Self::Eax | Self::Ebx | Self::Ecx | Self::Edx | Self::Esi | Self::Edi
            | Self::Ebp | Self::Esp => 4,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 | Self::Xmm3 | Self::Xmm4
            | Self::Xmm5 | Self::Xmm6 | Self::Xmm7 => 16,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LocalVar — a local variable on the stack
// ─────────────────────────────────────────────────────────────────────────────

/// Type of a local variable slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalVarKind {
    /// Primitive integer/pointer.
    Scalar,
    /// Part of a local array (detected by adjacent allocations).
    Array { element_size: usize, count: usize },
    /// Spill slot for a floating-point value.
    Float,
    /// Spilled vector register.
    Vector,
    /// Unknown / unclassified.
    Unknown,
}

/// A single local variable inferred from stack accesses.
#[derive(Debug, Clone)]
pub struct LocalVar {
    /// Byte offset from the frame base (negative = below saved rbp).
    pub offset: i64,
    /// Size in bytes inferred from the access width.
    pub size: usize,
    /// Inferred variable kind.
    pub kind: LocalVarKind,
    /// Number of times this slot was read.
    pub read_count: usize,
    /// Number of times this slot was written.
    pub write_count: usize,
    /// Optional user-assigned name.
    pub name: Option<String>,
}

impl LocalVar {
    /// Create a new unnamed local variable at `offset` with `size` bytes.
    #[must_use]
    pub const fn new(offset: i64, size: usize) -> Self {
        Self {
            offset,
            size,
            kind: LocalVarKind::Unknown,
            read_count: 0,
            write_count: 0,
            name: None,
        }
    }

    /// Human-readable default name: `var_N` where N is the (positive) offset.
    #[must_use]
    pub fn auto_name(&self) -> String {
        if self.offset < 0 {
            format!("var_{:x}", self.offset.unsigned_abs())
        } else {
            format!("arg_{:x}", u64::try_from(self.offset).unwrap_or(0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SavedReg — a callee-saved register pushed in the prologue
// ─────────────────────────────────────────────────────────────────────────────

/// A callee-saved register that the function saves on entry and restores on exit.
#[derive(Debug, Clone)]
pub struct SavedReg {
    /// The register.
    pub reg: Register,
    /// Stack offset where it is saved (negative = below frame base).
    pub stack_offset: i64,
    /// Whether a corresponding restore was found in the epilogue.
    pub restored: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// StackCookie — stack canary / security cookie
// ─────────────────────────────────────────────────────────────────────────────

/// Evidence of a stack security cookie in the prologue.
#[derive(Debug, Clone)]
pub struct StackCookie {
    /// Stack offset where the cookie is stored.
    pub stack_offset: i64,
    /// Address of the instruction that loads the cookie from the security cookie global.
    pub load_addr: u64,
    /// Address of the instruction that validates the cookie before return.
    pub check_addr: Option<u64>,
    /// Symbol name of the cookie global, if known.
    pub cookie_symbol: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Calling convention inferred from prologue / epilogue patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// x86-64 System V (Linux/macOS).
    SysV64,
    /// Windows x64 (Microsoft ABI).
    MsX64,
    /// 32-bit cdecl (caller cleans stack).
    Cdecl,
    /// 32-bit stdcall (callee cleans stack).
    Stdcall,
    /// 32-bit fastcall (first two args in ECX/EDX).
    Fastcall,
    /// 32-bit thiscall (this in ECX).
    Thiscall,
    /// Could not be determined.
    Unknown,
}

impl CallingConvention {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SysV64   => "sysv64",
            Self::MsX64    => "msvc_x64",
            Self::Cdecl    => "cdecl",
            Self::Stdcall  => "stdcall",
            Self::Fastcall => "fastcall",
            Self::Thiscall => "thiscall",
            Self::Unknown  => "unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameAnalysis — full result
// ─────────────────────────────────────────────────────────────────────────────

/// Complete stack-frame analysis for a function.
#[derive(Debug, Clone)]
pub struct FrameAnalysis {
    /// Function entry-point address.
    pub func_addr: u64,
    /// Computed frame size in bytes.
    pub frame_size: usize,
    /// Whether the function uses a frame pointer (RBP / EBP).
    pub has_frame_pointer: bool,
    /// All detected local variables.
    pub locals: Vec<LocalVar>,
    /// Callee-saved registers pushed in the prologue.
    pub saved_regs: Vec<SavedReg>,
    /// Stack cookie information, if detected.
    pub cookie: Option<StackCookie>,
    /// Inferred calling convention.
    pub calling_convention: CallingConvention,
    /// Total number of instructions analysed.
    pub insn_count: usize,
}

impl FrameAnalysis {
    /// Number of local array slots detected.
    #[must_use]
    pub fn array_count(&self) -> usize {
        self.locals.iter().filter(|v| matches!(v.kind, LocalVarKind::Array { .. })).count()
    }

    /// Whether a stack security cookie was found.
    #[must_use]
    pub const fn has_cookie(&self) -> bool {
        self.cookie.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackFrame — a lightweight representation used during analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable working state for an ongoing frame analysis.
#[derive(Debug, Default)]
pub struct StackFrame {
    pub func_addr: u64,
    /// Allocation amount (positive) deduced from `sub rsp, N` or `sub esp, N`.
    pub alloc_size: usize,
    /// Whether `push rbp` / `mov rbp, rsp` was seen.
    pub has_frame_pointer: bool,
    /// Stack accesses: offset → (size, reads, writes).
    accesses: HashMap<i64, (usize, usize, usize)>,
    /// Saved registers seen in prologue.
    saved_regs: Vec<SavedReg>,
    /// Stack-cookie load address.
    cookie_load: Option<(u64, i64)>,
    /// Stack-cookie check address.
    cookie_check: Option<u64>,
}

impl StackFrame {
    /// Create a frame with the given function address.
    #[must_use]
    pub fn new(func_addr: u64) -> Self {
        Self { func_addr, ..Default::default() }
    }

    /// Record a stack access at `offset` bytes from the frame base.
    pub fn record_access(&mut self, offset: i64, size: usize, is_write: bool) {
        let entry = self.accesses.entry(offset).or_insert((size, 0, 0));
        if size > entry.0 { entry.0 = size; }
        if is_write { entry.2 += 1; } else { entry.1 += 1; }
    }

    /// Record a saved register push.
    pub fn record_saved_reg(&mut self, reg: Register, stack_offset: i64) {
        self.saved_regs.push(SavedReg { reg, stack_offset, restored: false });
    }

    /// Record a cookie load.
    pub const fn record_cookie_load(&mut self, addr: u64, offset: i64) {
        self.cookie_load = Some((addr, offset));
    }

    /// Record a cookie check in the epilogue.
    pub const fn record_cookie_check(&mut self, addr: u64) {
        self.cookie_check = Some(addr);
    }

    /// Mark a saved register as restored.
    pub fn mark_restored(&mut self, reg: &Register) {
        if let Some(sr) = self.saved_regs.iter_mut().find(|sr| &sr.reg == reg) {
            sr.restored = true;
        }
    }

    /// Convert to a [`FrameAnalysis`].
    #[must_use]
    pub fn into_analysis(self, insn_count: usize, calling_convention: CallingConvention) -> FrameAnalysis {
        // Build local var list
        let mut locals: Vec<LocalVar> = self.accesses
            .iter()
            .map(|(&offset, &(size, reads, writes))| {
                let mut v = LocalVar::new(offset, size);
                v.read_count = reads;
                v.write_count = writes;
                v.kind = LocalVarKind::Scalar;
                v
            })
            .collect();
        locals.sort_by_key(|v| v.offset);

        // Detect adjacent arrays
        detect_arrays(&mut locals);

        let cookie = self.cookie_load.map(|(load_addr, stack_offset)| StackCookie {
            stack_offset,
            load_addr,
            check_addr: self.cookie_check,
            cookie_symbol: Some("__security_cookie".into()),
        });

        let frame_size = if self.alloc_size > 0 {
            self.alloc_size
        } else {
            // Estimate from deepest negative offset
            locals.iter()
                .filter(|v| v.offset < 0)
                .map(|v| {
                    // i64::MIN.checked_neg() is None; treat as 0 to avoid overflow.
                    let abs = usize::try_from(v.offset.checked_neg().unwrap_or(0)).unwrap_or(0);
                    abs.saturating_add(v.size)
                })
                .max()
                .unwrap_or(0)
        };

        FrameAnalysis {
            func_addr: self.func_addr,
            frame_size,
            has_frame_pointer: self.has_frame_pointer,
            locals,
            saved_regs: self.saved_regs,
            cookie,
            calling_convention,
            insn_count,
        }
    }
}

/// Scan `locals` (sorted by offset, in EITHER direction) and promote adjacent
/// same-size slots to arrays.
///
/// The run used to be followed with a hardcoded `base_offset - count*size`,
/// i.e. assuming DESCENDING offsets — but the only production caller,
/// [`StackFrame::into_analysis`], sorts ASCENDING. The two never agreed, so no
/// stack array was ever promoted: `array_count()` was structurally always 0 and
/// every slot stayed `Scalar`. Taking the direction from the data keeps the
/// existing descending callers working while fixing the ascending one, instead
/// of flipping the sort and risking whatever else reads `FrameAnalysis::locals`.
fn detect_arrays(locals: &mut [LocalVar]) {
    let n = locals.len();
    if n < 2 {
        return;
    }
    let mut i = 0;
    while i < n {
        let elem_size = locals[i].size;
        let base_offset = locals[i].offset;
        // Direction of this run, read off the neighbour.
        let dir: i64 = if i + 1 < n && locals[i + 1].offset < base_offset {
            -1
        } else {
            1
        };
        let mut count = 1usize;
        let mut j = i + 1;
        while j < n {
            let stride = i64::try_from(count)
                .ok()
                .and_then(|c| c.checked_mul(i64::try_from(elem_size).unwrap_or(i64::MAX)))
                .and_then(|s| s.checked_mul(dir));
            let Some(expected) = stride.and_then(|s| base_offset.checked_add(s)) else {
                break;
            };
            if locals[j].offset == expected && locals[j].size == elem_size {
                count += 1;
                j += 1;
            } else {
                break;
            }
        }
        if count >= 2 {
            for local in &mut locals[i..j] {
                local.kind = LocalVarKind::Array { element_size: elem_size, count };
            }
        }
        i = j;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrologueParser — extract frame info from raw bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Parses x86-64 function prologues to build a [`StackFrame`].
pub struct PrologueParser {
    pub is_64bit: bool,
    /// Maximum bytes to scan for prologue.
    pub max_prologue_bytes: usize,
}

impl Default for PrologueParser {
    fn default() -> Self {
        Self { is_64bit: true, max_prologue_bytes: 64 }
    }
}

impl PrologueParser {
    #[must_use]
    pub const fn new(is_64bit: bool) -> Self {
        Self { is_64bit, max_prologue_bytes: 64 }
    }

    /// Parse up to `max_prologue_bytes` from `code` to populate a [`StackFrame`].
    #[must_use]
    pub fn parse(&self, func_addr: u64, code: &[u8]) -> StackFrame {
        let mut frame = StackFrame::new(func_addr);
        let limit = self.max_prologue_bytes.min(code.len());
        let mut i = 0usize;

        while i < limit {
            let b = code[i];

            // push rbp (55)
            if b == 0x55 && self.is_64bit {
                frame.record_saved_reg(Register::Rbp, -(8i64));
                i += 1;
                continue;
            }
            // push ebp (55) in 32-bit mode
            if b == 0x55 && !self.is_64bit {
                frame.record_saved_reg(Register::Ebp, -(4i64));
                i += 1;
                continue;
            }
            // mov rbp, rsp  (48 89 E5)
            if self.is_64bit && i + 2 < limit && code[i] == 0x48 && code[i+1] == 0x89 && code[i+2] == 0xE5 {
                frame.has_frame_pointer = true;
                i += 3;
                continue;
            }
            // mov ebp, esp  (89 E5)
            if !self.is_64bit && i + 1 < limit && code[i] == 0x89 && code[i+1] == 0xE5 {
                frame.has_frame_pointer = true;
                i += 2;
                continue;
            }
            // sub rsp, imm8  (48 83 EC xx)
            if self.is_64bit && i + 3 < limit && code[i] == 0x48 && code[i+1] == 0x83 && code[i+2] == 0xEC {
                frame.alloc_size = code[i+3] as usize;
                i += 4;
                continue;
            }
            // sub rsp, imm32  (48 81 EC xx xx xx xx)
            if self.is_64bit && i + 6 < limit && code[i] == 0x48 && code[i+1] == 0x81 && code[i+2] == 0xEC {
                let imm = u32::from_le_bytes([code[i+3], code[i+4], code[i+5], code[i+6]]);
                frame.alloc_size = imm as usize;
                i += 7;
                continue;
            }
            // sub esp, imm8  (83 EC xx)
            if !self.is_64bit && i + 2 < limit && code[i] == 0x83 && code[i+1] == 0xEC {
                frame.alloc_size = code[i+2] as usize;
                i += 3;
                continue;
            }
            // push r12-r15  (41 54..57)
            if self.is_64bit && i + 1 < limit && code[i] == 0x41 && (0x54..=0x57).contains(&code[i+1]) {
                let reg_idx = (code[i+1] - 0x54) as usize;
                let reg = [Register::R12, Register::R13, Register::R14, Register::R15][reg_idx].clone();
                let slot = i64::try_from(1 + frame.saved_regs.len()).unwrap_or(i64::MAX);
                let offset = -(8i64.saturating_mul(slot));
                frame.record_saved_reg(reg, offset);
                i += 2;
                continue;
            }
            // push rbx (53) / push rsi (56) / push rdi (57)
            if self.is_64bit && matches!(b, 0x53 | 0x56 | 0x57) {
                let reg = match b { 0x53 => Register::Rbx, 0x56 => Register::Rsi, _ => Register::Rdi };
                let slot = i64::try_from(1 + frame.saved_regs.len()).unwrap_or(i64::MAX);
                let offset = -(8i64.saturating_mul(slot));
                frame.record_saved_reg(reg, offset);
                i += 1;
                continue;
            }
            // stack cookie load pattern: mov rax, [__security_cookie] (48 8B 05 ...)
            // followed by xor rax, rsp, then store at [rbp-8]
            if self.is_64bit && i + 6 < limit && code[i] == 0x48 && code[i+1] == 0x8B && code[i+2] == 0x05 {
                frame.record_cookie_load(func_addr.saturating_add(i as u64), -8);
                i += 7;
                continue;
            }
            // End of prologue on RET
            if b == 0xC3 || b == 0xC2 {
                break;
            }
            i += 1;
        }

        frame
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EpilogueParser — detect cookie check and register restores
// ─────────────────────────────────────────────────────────────────────────────

/// Parses function epilogues to detect cookie checks and register restores.
pub struct EpilogueParser {
    pub is_64bit: bool,
    pub max_epilogue_bytes: usize,
}

impl Default for EpilogueParser {
    fn default() -> Self {
        Self { is_64bit: true, max_epilogue_bytes: 48 }
    }
}

impl EpilogueParser {
    #[must_use]
    pub const fn new(is_64bit: bool) -> Self {
        Self { is_64bit, max_epilogue_bytes: 48 }
    }

    /// Scan backward from a RET instruction to detect epilogue patterns.
    pub fn parse(&self, func_end: u64, code: &[u8], frame: &mut StackFrame) {
        let limit = self.max_epilogue_bytes.min(code.len());
        let slice = if code.len() > limit { &code[code.len() - limit..] } else { code };
        let base_addr = func_end.saturating_sub(limit as u64);

        let mut i = 0usize;
        while i < slice.len() {
            let b = slice[i];

            // __security_check_cookie call pattern (E8 xx xx xx xx)
            if b == 0xE8 && i + 4 < slice.len() {
                frame.record_cookie_check(base_addr.saturating_add(i as u64));
                i += 5;
                continue;
            }
            // add rsp, imm8 (48 83 C4 xx) — epilogue frame pop
            if self.is_64bit && i + 3 < slice.len() && slice[i] == 0x48 && slice[i+1] == 0x83 && slice[i+2] == 0xC4 {
                i += 4;
                continue;
            }
            // pop rbp (5D)
            if b == 0x5D {
                frame.mark_restored(&Register::Rbp);
                i += 1;
                continue;
            }
            // pop rbx (5B)
            if b == 0x5B { frame.mark_restored(&Register::Rbx); i += 1; continue; }
            // pop rsi (5E)
            if b == 0x5E { frame.mark_restored(&Register::Rsi); i += 1; continue; }
            // pop rdi (5F)
            if b == 0x5F { frame.mark_restored(&Register::Rdi); i += 1; continue; }
            // pop r12-r15 (41 5C..5F)
            if self.is_64bit && i + 1 < slice.len() && b == 0x41 && (0x5C..=0x5F).contains(&slice[i+1]) {
                let reg = match slice[i+1] {
                    0x5C => Register::R12, 0x5D => Register::R13, 0x5E => Register::R14, _ => Register::R15,
                };
                frame.mark_restored(&reg);
                i += 2;
                continue;
            }
            i += 1;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionInferrer
// ─────────────────────────────────────────────────────────────────────────────

/// Infers calling convention from prologue saved-register patterns.
pub struct CallingConventionInferrer;

impl CallingConventionInferrer {
    /// Infer calling convention from a populated [`StackFrame`].
    #[must_use]
    pub fn infer(frame: &StackFrame, is_64bit: bool) -> CallingConvention {
        if is_64bit {
            // Windows x64: saves RDI and RSI
            if frame.saved_regs.iter().any(|s| matches!(s.reg, Register::Rdi | Register::Rsi)) {
                return CallingConvention::MsX64;
            }
            CallingConvention::SysV64
        } else {
            // 32-bit heuristics
            let saves_ecx = frame.saved_regs.iter().any(|s| s.reg == Register::Ecx);
            if saves_ecx {
                return CallingConvention::Thiscall;
            }
            if frame.has_frame_pointer {
                CallingConvention::Cdecl
            } else {
                CallingConvention::Unknown
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level analyse function
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse the stack frame of a function from its raw code bytes.
///
/// `func_addr` — virtual address of the first byte.
/// `code`      — raw bytes of the function body.
/// `is_64bit`  — set to `true` for x86-64, `false` for x86-32.
#[must_use]
pub fn analyse_stack_frame(func_addr: u64, code: &[u8], is_64bit: bool) -> FrameAnalysis {
    let prologue_parser = PrologueParser::new(is_64bit);
    let mut frame = prologue_parser.parse(func_addr, code);

    let epilogue_parser = EpilogueParser::new(is_64bit);
    epilogue_parser.parse(func_addr.saturating_add(code.len() as u64), code, &mut frame);

    // Heuristic: scan for stack accesses in the body
    let body_limit = code.len().min(512);
    let mut i = 0usize;
    while i < body_limit.saturating_sub(3) {
        // MOV [rbp - N], reg  or  MOV reg, [rbp - N]
        // Pattern: 48 89 45 xx  or  48 8B 45 xx  (simplified)
        if is_64bit && code[i] == 0x48 {
            if i + 3 < body_limit && (code[i+1] == 0x89 || code[i+1] == 0x8B) && code[i+2] == 0x45 {
                let offset = i64::from(i8::from_ne_bytes([code[i+3]]));
                let is_write = code[i+1] == 0x89;
                frame.record_access(offset, 8, is_write);
                i += 4;
                continue;
            }
            // 48 89 4D xx  MOV [rbp-N], rcx
            if i + 3 < body_limit && code[i+1] == 0x89 && code[i+2] == 0x4D {
                let offset = i64::from(i8::from_ne_bytes([code[i+3]]));
                frame.record_access(offset, 8, true);
                i += 4;
                continue;
            }
        }
        // 32-bit: MOV [ebp-N], reg
        if !is_64bit && i + 2 < body_limit && code[i] == 0x89 && code[i+1] == 0x45 {
            let offset = i64::from(i8::from_ne_bytes([code[i+2]]));
            frame.record_access(offset, 4, true);
            i += 3;
            continue;
        }
        i += 1;
    }

    let cc = CallingConventionInferrer::infer(&frame, is_64bit);
    frame.into_analysis(body_limit, cc)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public stack-frame record API (LLIL-driven)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StackVarRec {
    pub offset: i64,
    pub size: u64,
    pub name: String,
    pub access_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct StackFrameRec {
    pub total_size: u64,
    pub saved_regs: Vec<String>,
    pub vars: Vec<StackVarRec>,
    pub has_alloca: bool,
}

fn is_callee_saved_name(n: &str) -> bool {
    matches!(
        n.to_ascii_lowercase().as_str(),
        "rbp" | "rbx" | "rsi" | "rdi" | "r12" | "r13" | "r14" | "r15"
    )
}

const fn is_rsp(n: &str) -> bool {
    n.eq_ignore_ascii_case("rsp") || n.eq_ignore_ascii_case("esp")
}

const fn is_rbp(n: &str) -> bool {
    n.eq_ignore_ascii_case("rbp") || n.eq_ignore_ascii_case("ebp")
}

fn reg_name(reg: &LlilRegister) -> String {
    reg.name()
}

fn expr_reg_name(expr: &LlilExpr) -> Option<String> {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => Some(reg.name()),
        LlilExpr::StackPointer(_) => Some("rsp".to_string()),
        _ => None,
    }
}

const fn expr_const(expr: &LlilExpr) -> Option<u64> {
    if let LlilExpr::Const { value, .. } = expr {
        Some(*value)
    } else {
        None
    }
}

fn classify_stack_addr(expr: &LlilExpr) -> Option<(bool, i64)> {
    let (left, right, is_sub) = match expr {
        LlilExpr::SubT(l, r, _) | LlilExpr::Sub { left: l, right: r, .. } => {
            (l.as_ref(), r.as_ref(), true)
        }
        LlilExpr::AddT(l, r, _) | LlilExpr::Add { left: l, right: r, .. } => {
            (l.as_ref(), r.as_ref(), false)
        }
        _ => return None,
    };
    let base = expr_reg_name(left)?;
    let imm = i64::from_ne_bytes(expr_const(right)?.to_ne_bytes());
    let frame_ptr_based = is_rbp(&base);
    if !frame_ptr_based && !is_rsp(&base) {
        return None;
    }
    let signed = if is_sub { -imm } else { imm };
    Some((frame_ptr_based, signed))
}

fn collect_stack_accesses(expr: &LlilExpr, out: &mut Vec<(i64, u64, bool)>) {
    if let LlilExpr::Load { addr, size } = expr {
        if let Some((_, off)) = classify_stack_addr(addr) {
            out.push((off, size.bytes() as u64, false));
        }
        collect_stack_accesses(addr, out);
        return;
    }
    match expr {
        LlilExpr::AddT(a, b, _)
        | LlilExpr::SubT(a, b, _)
        | LlilExpr::MulT(a, b, _)
        | LlilExpr::And(a, b, _)
        | LlilExpr::Or(a, b, _)
        | LlilExpr::Xor(a, b, _)
        | LlilExpr::Shr(a, b, _)
        | LlilExpr::Sar(a, b, _)
        | LlilExpr::Add { left: a, right: b, .. }
        | LlilExpr::Sub { left: a, right: b, .. }
        | LlilExpr::Mul { left: a, right: b, .. } => {
            collect_stack_accesses(a, out);
            collect_stack_accesses(b, out);
        }
        _ => {}
    }
}

struct PrologueInfo {
    total_alloc: i64,
    has_alloca: bool,
    pushed: Vec<String>,
}

fn scan_prologue(instrs: &[(Address, LlilInstruction)]) -> PrologueInfo {
    let n = instrs.len();
    let mut total_alloc: i64 = 0;
    let mut has_alloca = false;
    let mut pushed: Vec<String> = Vec::new();
    let mut prologue_done = false;
    let mut epilogue_start = n;
    let mut popped: HashSet<String> = HashSet::new();

    for (i, (_, ins)) in instrs.iter().enumerate() {
        match ins {
            LlilInstruction::Push { src, .. } => {
                if !prologue_done
                    && let Some(name) = expr_reg_name(src)
                    && is_callee_saved_name(&name)
                {
                    pushed.push(name);
                    continue;
                }
                prologue_done = true;
            }
            LlilInstruction::Pop { dest, .. } => {
                let name = reg_name(dest);
                if is_callee_saved_name(&name) {
                    popped.insert(name);
                    if epilogue_start == n {
                        epilogue_start = i;
                    }
                }
            }
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(s), value, .. }
                if is_rsp(s) =>
            {
                if let LlilExpr::SubT(lhs, rhs, _)
                | LlilExpr::Sub { left: lhs, right: rhs, .. } = value
                {
                    if expr_reg_name(lhs).as_deref().is_some_and(is_rsp) {
                        if let Some(c) = expr_const(rhs) {
                            total_alloc = total_alloc.saturating_add(
                                i64::from_ne_bytes(c.to_ne_bytes()));
                            prologue_done = true;
                        } else if matches!(rhs.as_ref(), LlilExpr::RegisterRef { .. }) {
                            has_alloca = true;
                        }
                    }
                } else if let LlilExpr::AddT(lhs, rhs, _)
                | LlilExpr::Add { left: lhs, right: rhs, .. } = value
                    && expr_reg_name(lhs).as_deref().is_some_and(is_rsp)
                    && let Some(c) = expr_const(rhs)
                {
                    total_alloc = total_alloc.saturating_sub(
                        i64::from_ne_bytes(c.to_ne_bytes()));
                }
            }
            _ => {}
        }
    }
    let _ = (epilogue_start, popped);
    PrologueInfo { total_alloc, has_alloca, pushed }
}

fn build_access_map(instrs: &[(Address, LlilInstruction)]) -> BTreeMap<i64, (u64, HashSet<usize>)> {
    let mut access_map: BTreeMap<i64, (u64, HashSet<usize>)> = BTreeMap::new();
    let record = |off: i64, sz: u64, idx: usize, m: &mut BTreeMap<i64, (u64, HashSet<usize>)>| {
        let e = m.entry(off).or_insert_with(|| (sz, HashSet::new()));
        if sz > e.0 {
            e.0 = sz;
        }
        e.1.insert(idx);
    };
    for (i, (_, ins)) in instrs.iter().enumerate() {
        match ins {
            LlilInstruction::Store { addr, size, value } => {
                if let Some((_, off)) = classify_stack_addr(addr) {
                    record(off, size.bytes() as u64, i, &mut access_map);
                }
                let mut accs = Vec::new();
                collect_stack_accesses(value, &mut accs);
                for (o, s, _) in accs {
                    record(o, s, i, &mut access_map);
                }
            }
            LlilInstruction::Load { addr, size, .. } => {
                if let Some((_, off)) = classify_stack_addr(addr) {
                    record(off, size.bytes() as u64, i, &mut access_map);
                }
            }
            LlilInstruction::SetReg { value, .. }
            | LlilInstruction::SetRegister { value, .. }
            | LlilInstruction::Push { src: value, .. } => {
                let mut accs = Vec::new();
                collect_stack_accesses(value, &mut accs);
                for (o, s, _) in accs {
                    record(o, s, i, &mut access_map);
                }
            }
            _ => {}
        }
    }
    access_map
}

fn coalesce_access_entries(
    mut entries: Vec<(i64, u64, u32)>,
) -> Vec<(i64, u64, u32)> {
    entries.sort_by_key(|(o, _, _)| *o);
    let mut coalesced: Vec<(i64, u64, u32)> = Vec::new();
    for (off, sz, cnt) in entries {
        if let Some(last) = coalesced.last_mut() {
            let last_end = last.0.saturating_add(i64::try_from(last.1).unwrap_or(i64::MAX));
            if off < last_end {
                let end = last_end.max(off.saturating_add(i64::try_from(sz).unwrap_or(i64::MAX)));
                last.1 = u64::try_from(end - last.0).unwrap_or(0);
                last.2 = last.2.saturating_add(cnt);
                continue;
            }
        }
        coalesced.push((off, sz, cnt));
    }
    coalesced
}

#[must_use]
pub fn analyze_stack_frame(addr: u64, instrs: &[(Address, LlilInstruction)]) -> StackFrameRec {
    let _ = addr;
    let PrologueInfo { total_alloc, has_alloca, pushed } = scan_prologue(instrs);
    let total_size = u64::try_from(total_alloc.max(0)).unwrap_or(0);

    let raw_entries: Vec<(i64, u64, u32)> = build_access_map(instrs)
        .into_iter()
        .map(|(o, (s, set))| (o, s, u32::try_from(set.len()).unwrap_or(u32::MAX)))
        .collect();
    let coalesced = coalesce_access_entries(raw_entries);

    let vars = coalesced
        .into_iter()
        .map(|(offset, size, access_count)| {
            let name = if offset < 0 {
                format!("var_{:x}", offset.unsigned_abs())
            } else {
                format!("arg_{:x}", u64::try_from(offset).unwrap_or(0))
            };
            StackVarRec { offset, size, name, access_count }
        })
        .collect();

    StackFrameRec { total_size, saved_regs: pushed, vars, has_alloca }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prologue_push_rbp_mov_rbp_rsp_sub_rsp() {
        // push rbp; mov rbp, rsp; sub rsp, 0x28; ret
        let code = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0xC3];
        let frame = analyse_stack_frame(0x1000, &code, true);
        assert!(frame.has_frame_pointer);
        assert_eq!(frame.frame_size, 0x28);
    }

    #[test]
    fn callee_saved_reg_detection() {
        // push rbp; push rbx; mov rbp, rsp; sub rsp, 0x10; ret
        let code = [0x55u8, 0x53, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0xC3];
        let frame = analyse_stack_frame(0x1000, &code, true);
        let regs: Vec<_> = frame.saved_regs.iter().map(|r| &r.reg).collect();
        assert!(regs.contains(&&Register::Rbp) || regs.contains(&&Register::Rbx));
    }

    #[test]
    fn stack_cookie_detection() {
        // sub rsp, 0x28; mov rax, [__security_cookie] (48 8B 05 xx xx xx xx); sub rsp ...
        let mut code = vec![0x48u8, 0x83, 0xEC, 0x28]; // sub rsp, 0x28
        code.extend_from_slice(&[0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]); // mov rax, [rip+0]
        code.push(0xC3); // ret
        let frame = analyse_stack_frame(0x1000, &code, true);
        assert!(frame.has_cookie());
    }

    #[test]
    fn local_var_recorded_from_access() {
        // sub rsp, 0x20; mov [rbp-8], rax; ret
        let code = [0x48u8, 0x83, 0xEC, 0x20, 0x48, 0x89, 0x45, 0xF8, 0xC3];
        let frame = analyse_stack_frame(0x1000, &code, true);
        assert!(!frame.locals.is_empty());
    }

    #[test]
    fn register_callee_saved_sysv() {
        assert!(Register::Rbx.is_callee_saved_sysv());
        assert!(Register::R12.is_callee_saved_sysv());
        assert!(!Register::Rax.is_callee_saved_sysv());
    }

    #[test]
    fn calling_convention_sysv() {
        let code = [0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let frame = analyse_stack_frame(0x1000, &code, true);
        assert_eq!(frame.calling_convention, CallingConvention::SysV64);
    }

    #[test]
    fn detect_arrays_marks_adjacent_slots() {
        let mut locals = vec![
            LocalVar::new(-8,  8),
            LocalVar::new(-16, 8),
            LocalVar::new(-24, 8),
            LocalVar::new(-40, 4),
        ];
        detect_arrays(&mut locals);
        let arrays: Vec<_> = locals.iter().filter(|v| matches!(v.kind, LocalVarKind::Array { .. })).collect();
        assert!(!arrays.is_empty());
    }

    #[test]
    fn auto_name_format() {
        let v = LocalVar::new(-0x10, 8);
        assert_eq!(v.auto_name(), "var_10");
        let v2 = LocalVar::new(0x10, 8);
        assert_eq!(v2.auto_name(), "arg_10");
    }

    #[test]
    fn register_from_str() {
        assert_eq!(Register::parse("rbp"), Register::Rbp);
        assert_eq!(Register::parse("XMM7"), Register::Xmm7);
    }

    #[test]
    fn epilogue_marks_restored() {
        let mut frame = StackFrame::new(0x1000);
        frame.record_saved_reg(Register::Rbp, -8);
        let ep = EpilogueParser::new(true);
        // epilogue: pop rbp (5D); ret (C3)
        let code = [0x5Du8, 0xC3];
        ep.parse(0x1002, &code, &mut frame);
        assert!(frame.saved_regs[0].restored);
    }

    use rustre_il_llil::Size;

    fn rsp_ref() -> LlilExpr {
        LlilExpr::RegisterRef { reg: LlilRegister::Concrete("rsp".into()), size: Size::QWord }
    }
    fn konst(v: u64) -> LlilExpr {
        LlilExpr::Const { value: v, size: Size::QWord }
    }
    fn rbp_minus(n: u64) -> LlilExpr {
        LlilExpr::SubT(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbp".into()),
                size: Size::QWord,
            }),
            Box::new(konst(n)),
            Size::QWord,
        )
    }
    fn at(a: u64) -> Address {
        Address::new(a)
    }

    #[test]
    fn analyze_stack_frame_basic_prologue_alloc_and_saved() {
        let prog = vec![
            (
                at(0x1000),
                LlilInstruction::Push {
                    size: Size::QWord,
                    src: LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rbp".into()),
                        size: Size::QWord,
                    },
                },
            ),
            (
                at(0x1001),
                LlilInstruction::Push {
                    size: Size::QWord,
                    src: LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rbx".into()),
                        size: Size::QWord,
                    },
                },
            ),
            (
                at(0x1003),
                LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rsp".into()),
                    size: Size::QWord,
                    value: LlilExpr::SubT(Box::new(rsp_ref()), Box::new(konst(0x20)), Size::QWord),
                },
            ),
            (at(0x100A), LlilInstruction::Ret),
        ];
        let rec = analyze_stack_frame(0x1000, &prog);
        assert_eq!(rec.total_size, 0x20);
        assert_eq!(rec.saved_regs, vec!["rbp".to_string(), "rbx".to_string()]);
        assert!(!rec.has_alloca);
    }

    #[test]
    fn analyze_stack_frame_records_vars_and_access_count() {
        let prog = vec![
            (
                at(0x2000),
                LlilInstruction::Store {
                    addr: rbp_minus(0x8),
                    size: Size::QWord,
                    value: konst(1),
                },
            ),
            (
                at(0x2008),
                LlilInstruction::Store {
                    addr: rbp_minus(0x8),
                    size: Size::QWord,
                    value: konst(2),
                },
            ),
            (
                at(0x2010),
                LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: LlilExpr::Load {
                        addr: Box::new(rbp_minus(0x10)),
                        size: Size::QWord,
                    },
                },
            ),
        ];
        let rec = analyze_stack_frame(0x2000, &prog);
        let names: Vec<&str> = rec.vars.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"var_8"));
        assert!(names.contains(&"var_10"));
        let v8 = rec.vars.iter().find(|v| v.name == "var_8").unwrap();
        assert_eq!(v8.access_count, 2);
    }

    #[test]
    fn analyze_stack_frame_detects_alloca() {
        let prog = vec![(
            at(0x3000),
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rsp".into()),
                size: Size::QWord,
                value: LlilExpr::SubT(
                    Box::new(rsp_ref()),
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
            },
        )];
        let rec = analyze_stack_frame(0x3000, &prog);
        assert!(rec.has_alloca);
    }
}
