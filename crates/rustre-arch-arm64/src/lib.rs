//! `rustre-arch-arm64`
//!
//! Production-grade ARM64/AArch64 architecture support for the `RustRE` Suite.
//!
//! Provides instruction decoding via [`yaxpeax_arm`] (pure-Rust, fixed 32-bit
//! instruction words), flag classification, branch-target extraction, a full
//! register table (250+ entries), and both the AAPCS64 and Apple ARM64 calling
//! conventions.
//!
//! # Main entry points
//! - [`Arm64Arch`] — implements [`Architecture`]
//! - [`Arm64LinearDisassembler`] — streaming iterator over a byte slice
//! - [`Arm64InstrCategory`] — classify an instruction by mnemonic

/// ARM64 NEON/Advanced SIMD extension: NeonDecoder, NeonRegister,
/// NeonInstruction, ArrangementSpec, and NeonLifter.
pub mod aarch64_neon;

/// ARM64 Pointer Authentication Code (PAC) analysis: PacAnalyzer, PacInstruction,
/// PacKey, PacSignature, and security findings.
pub mod aarch64_pac;

/// AArch64 SVE/SVE2 vector extension decoder and lifter: AArch64Sve, SvePredicate,
/// SveVector, SveInstruction, SveLifter, and all SVE/SVE2 opcodes.
///
pub mod aarch64_sve;

pub mod arm64_system_registers;
pub mod arm64_pac_analyzer;
pub mod arm64_sve_decoder;
pub mod arm64_feature_detector;
pub mod arm64_calling_conventions;
pub mod arm64_exception_levels;
pub mod arm64_jump_table;

pub use arm64_jump_table::{detect_jump_tables, JumpTableInfo, JumpTableKind};

use rustre_core::address::Address;
use rustre_core::arch::{
    Architecture, BranchCondition, BranchInfo, BranchKind, CallingConvention, InstrFlags,
    Instruction, RegisterInfo, RegisterKind,
};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode four little-endian bytes into a yaxpeax `Instruction`.
/// Returns an error when fewer than four bytes are provided or when the
/// instruction word is not valid A64.
fn yaxpeax_decode(bytes: &[u8]) -> Result<yaxpeax_arm::armv8::a64::Instruction, CoreError> {
    if bytes.len() < 4 {
        return Err(CoreError::PluginError {
            plugin: "arm64".into(),
            message: format!(
                "ARM64 requires 4 bytes; only {} byte(s) supplied",
                bytes.len()
            ),
        });
    }
    let decoder = InstDecoder::default();
    let mut reader = U8Reader::new(&bytes[..4]);
    decoder
        .decode(&mut reader)
        .map_err(|e| CoreError::PluginError {
            plugin: "arm64".into(),
            message: format!("ARM64 decode error: {e:?}"),
        })
}

/// Format the mnemonic of a decoded A64 instruction.
///
/// yaxpeax formats the full instruction via `Display`; we split on the first
/// ASCII space to separate mnemonic from operands.
fn mnemonic_of(instr: &yaxpeax_arm::armv8::a64::Instruction) -> String {
    let full = instr.to_string();
    let trimmed = full.trim();
    trimmed.find(|c: char| c.is_ascii_whitespace()).map_or_else(|| trimmed.to_string(), |pos| trimmed[..pos].to_string())
}

/// Format the operand string of a decoded A64 instruction (everything after
/// the first whitespace run in the full formatted output).
fn operands_of(instr: &yaxpeax_arm::armv8::a64::Instruction) -> String {
    let full = instr.to_string();
    let trimmed = full.trim();
    trimmed.find(|c: char| c.is_ascii_whitespace())
        .map_or_else(String::new, |pos| trimmed[pos..].trim().to_string())
}

/// Compute [`InstrFlags`] for a decoded A64 instruction.
fn flags_for(instr: &yaxpeax_arm::armv8::a64::Instruction) -> InstrFlags {
    match instr.opcode {
        // ── Unconditional direct branch ─────────────────────────────────────
        Opcode::B => InstrFlags::BRANCH,

        // ── Direct call ─────────────────────────────────────────────────────
        Opcode::BL => InstrFlags::BRANCH | InstrFlags::CALL,

        // ── Returns ─────────────────────────────────────────────────────────
        Opcode::RET | Opcode::ERET => InstrFlags::RET,

        // ── Conditional branches (B.cond) ────────────────────────────────────
        Opcode::Bcc(_) | Opcode::BCcc(_) => InstrFlags::BRANCH | InstrFlags::CONDITIONAL,

        // ── Compare/test and branch ──────────────────────────────────────────
        Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            InstrFlags::BRANCH | InstrFlags::CONDITIONAL
        }

        // ── Indirect branch ──────────────────────────────────────────────────
        Opcode::BR => InstrFlags::BRANCH | InstrFlags::INDIRECT,

        // ── Indirect call ────────────────────────────────────────────────────
        Opcode::BLR => InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::INDIRECT,

        // ── Loads ────────────────────────────────────────────────────────────
        Opcode::LDR
        | Opcode::LDRB
        | Opcode::LDRH
        | Opcode::LDRSB
        | Opcode::LDRSH
        | Opcode::LDRSW
        | Opcode::LDP
        | Opcode::LDXR
        | Opcode::LDAXR
        | Opcode::LDNP
        | Opcode::PRFM
        | Opcode::LDAR
        | Opcode::LDAPR
        | Opcode::LDXRB
        | Opcode::LDXRH
        | Opcode::LDAXRB
        | Opcode::LDAXRH
        | Opcode::LDPSW
        | Opcode::LDXP
        | Opcode::LDAXP => InstrFlags::READ_MEM,

        // ── Stores ───────────────────────────────────────────────────────────
        Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STP
        | Opcode::STXR
        | Opcode::STLXR
        | Opcode::STNP
        | Opcode::STLR
        | Opcode::STXRB
        | Opcode::STXRH
        | Opcode::STLXRB
        | Opcode::STLXRH
        | Opcode::STXP
        | Opcode::STLXP => InstrFlags::WRITE_MEM,

        // ── Memory barriers ───────────────────────────────────────────────────
        Opcode::DMB(_) | Opcode::DSB(_) | Opcode::ISB | Opcode::SB => InstrFlags::BARRIER,

        // ── Everything else ───────────────────────────────────────────────────
        _ => InstrFlags::NONE,
    }
}

/// Extract a static branch target from an A64 instruction operand list.
///
/// A64 encodes branch targets as `Operand::PCOffset(i64)`.  We compute the
/// absolute address by adding the (signed) offset to the instruction address.
///
/// # Operand ordering assumption
///
/// For compare-and-branch instructions (CBZ/CBNZ/TBZ/TBNZ), yaxpeax places
/// the register-to-test operand(s) **before** the `PCOffset` operand.  This
/// function iterates all operands and returns the **first** `PCOffset` found,
/// which is correct as long as yaxpeax maintains that ordering.  If yaxpeax
/// were to change its operand order, this function would return the wrong
/// address silently.  Should that happen, the fix is to match only on the
/// *last* operand (the branch offset is always the final operand in A64
/// encoding).
fn branch_target(instr: &yaxpeax_arm::armv8::a64::Instruction, instr_addr: u64) -> Option<Address> {
    for op in &instr.operands {
        if let Operand::PCOffset(offset) = op {
            let target = instr_addr.wrapping_add((*offset).cast_unsigned());
            return Some(Address::new(target));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Arm64Arch
// ---------------------------------------------------------------------------

/// ARM64/AArch64 architecture descriptor.
///
/// Fixed 32-bit instruction words, little-endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Arch;

impl Arm64Arch {
    /// Create a new `Arm64Arch` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Arm64Arch {
    fn default() -> Self {
        Self::new()
    }
}

impl Architecture for Arm64Arch {
    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let decoded = yaxpeax_decode(bytes)?;
        let mnemonic = mnemonic_of(&decoded);
        let operands = operands_of(&decoded);
        let flags = flags_for(&decoded);

        {
            let mut instr = Instruction::new(address, 4, mnemonic, bytes[..4].to_vec());
            instr.operands = operands;
            instr.flags = flags;
            Ok(instr)
        }
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if instr.bytes.len() < 4 {
            return vec![];
        }

        let Ok(decoded) = yaxpeax_decode(&instr.bytes) else { return vec![] };

        let addr = instr.address.as_u64();

        match decoded.opcode {
            // ── Direct unconditional branch ──────────────────────────────────
            Opcode::B => {
                branch_target(&decoded, addr)
                    .map_or_else(Vec::new, |target| vec![BranchInfo::unconditional_jump(target.as_u64())])
            }

            // ── Direct call ──────────────────────────────────────────────────
            Opcode::BL => {
                branch_target(&decoded, addr)
                    .map_or_else(Vec::new, |target| vec![BranchInfo::call(target.as_u64())])
            }

            // ── Conditional branches ─────────────────────────────────────────
            Opcode::Bcc(_)
            | Opcode::BCcc(_)
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ => {
                branch_target(&decoded, addr)
                    .map_or_else(Vec::new, |target| vec![BranchInfo::conditional_jump(
                        target.as_u64(),
                        BranchCondition::Custom(0),
                    )])
            }

            // ── Return instructions ──────────────────────────────────────────
            // RET has no static target, but "no target" is not "no branch":
            // `BranchInfo::ret()` exists in rustre-core precisely to model a
            // targetless function return (`target: None, kind: Return`), and it
            // is what the other architectures emit (rustre-arch-6502 lib.rs:952,
            // rustre-arch-luajit lib.rs:564). Returning an empty vec here made
            // AArch64 the sole outlier and contradicted this very function's
            // ERET arm below, which already emits a targetless BranchInfo.
            //
            // The practical cost of the old behaviour: a CFG builder driven by
            // `get_branches` saw no terminator at a RET, so basic blocks ran
            // past function returns.
            Opcode::RET => vec![BranchInfo::ret()],

            // ERET returns from an exception-level context.  We model it as
            // an exception-return branch with no statically-known target.
            Opcode::ERET => vec![BranchInfo {
                target: None,
                kind: BranchKind::ExceptionReturn,
                condition: BranchCondition::Always,
            }],

            // ── Non-branch instructions (incl. indirect branches — no static target) ──
            _ => vec![],
        }
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        build_registers()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            // AAPCS64 — the standard AArch64 ABI used on Linux, BSD, etc.
            CallingConvention::new("aapcs64")
                .with_int_args(vec![
                    "x0".to_string(),
                    "x1".to_string(),
                    "x2".to_string(),
                    "x3".to_string(),
                    "x4".to_string(),
                    "x5".to_string(),
                    "x6".to_string(),
                    "x7".to_string(),
                ])
                .with_return_regs(vec!["x0".to_string(), "x1".to_string()]),
            // Apple ARM64 ABI — same integer register usage; x18 is reserved
            // by the platform.
            CallingConvention::new("apple_arm64")
                .with_int_args(vec![
                    "x0".to_string(),
                    "x1".to_string(),
                    "x2".to_string(),
                    "x3".to_string(),
                    "x4".to_string(),
                    "x5".to_string(),
                    "x6".to_string(),
                    "x7".to_string(),
                ])
                .with_return_regs(vec!["x0".to_string(), "x1".to_string()]),
        ]
    }
}

// ---------------------------------------------------------------------------
// Register table
// ---------------------------------------------------------------------------

fn reg(name: &str, size: usize, id: u32) -> RegisterInfo {
    RegisterInfo::new(name, id, size, RegisterKind::General)
}

/// Build the complete ARM64 register list (250+ entries).
///
/// ID values are dense and unique across the full table.
fn build_registers() -> Vec<RegisterInfo> {
    let mut regs: Vec<RegisterInfo> = Vec::with_capacity(270);
    let mut id: u32 = 0;

    // ── 64-bit general-purpose (X0–X30, XZR, SP, PC) ───────────────────────
    for i in 0u32..31 {
        regs.push(reg(&format!("x{i}"), 8, id));
        id += 1;
    }
    regs.push(reg("xzr", 8, id));
    id += 1;
    regs.push(reg("sp", 8, id));
    id += 1;
    regs.push(reg("pc", 8, id));
    id += 1;

    // ── 32-bit aliases (W0–W30, WZR, WSP) ──────────────────────────────────
    for i in 0u32..31 {
        regs.push(reg(&format!("w{i}"), 4, id));
        id += 1;
    }
    regs.push(reg("wzr", 4, id));
    id += 1;
    regs.push(reg("wsp", 4, id));
    id += 1;

    // ── FP/SIMD 128-bit vector (V0–V31) ─────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("v{i}"), 16, id));
        id += 1;
    }

    // ── FP/SIMD 128-bit quad (Q0–Q31) ───────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("q{i}"), 16, id));
        id += 1;
    }

    // ── FP/SIMD 64-bit double (D0–D31) ──────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("d{i}"), 8, id));
        id += 1;
    }

    // ── FP/SIMD 32-bit single (S0–S31) ──────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("s{i}"), 4, id));
        id += 1;
    }

    // ── FP/SIMD 16-bit half (H0–H31) ────────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("h{i}"), 2, id));
        id += 1;
    }

    // ── FP/SIMD 8-bit byte (B0–B31) ─────────────────────────────────────────
    for i in 0u32..32 {
        regs.push(reg(&format!("b{i}"), 1, id));
        id += 1;
    }

    // ── System / status registers ────────────────────────────────────────────
    for (name, size) in &[
        ("nzcv", 4u32),
        ("fpcr", 4),
        ("fpsr", 4),
        ("daif", 4),
        ("currentel", 4),
        ("spsel", 4),
        ("tpidr_el0", 8),
        ("tpidrro_el0", 8),
        ("elr_el1", 8),
        ("spsr_el1", 4),
        ("esr_el1", 4),
        ("far_el1", 8),
        ("vbar_el1", 8),
        ("sctlr_el1", 8),
        ("ttbr0_el1", 8),
        ("ttbr1_el1", 8),
    ] {
        regs.push(reg(name, *size as usize, id));
        id += 1;
    }

    // Suppress unused-variable warning for the last increment.
    let _ = id;

    regs
}

// ---------------------------------------------------------------------------
// Arm64LinearDisassembler
// ---------------------------------------------------------------------------

/// Streaming, iterator-based linear disassembler for ARM64.
///
/// Each call to [`Iterator::next`] decodes the next 4-byte instruction word
/// and advances the internal offset by 4.  Yields `None` once the byte slice
/// is fully consumed.  On a decode failure the iterator yields
/// `Some(Err(...))` and **halts** (does not skip the bad word).
///
/// # Example
/// ```no_run
/// use rustre_arch_arm64::Arm64LinearDisassembler;
/// use rustre_core::address::Address;
///
/// let code: &[u8] = &[0x1f, 0x20, 0x03, 0xd5]; // NOP
/// let base = Address::new(0x1000);
/// for result in Arm64LinearDisassembler::new(code, base) {
///     let instr = result.unwrap();
///     println!("{} {}", instr.mnemonic, instr.operands);
/// }
/// ```
pub struct Arm64LinearDisassembler<'a> {
    bytes: &'a [u8],
    base: Address,
    offset: usize,
    arch: Arm64Arch,
}

impl<'a> Arm64LinearDisassembler<'a> {
    /// Create a new linear disassembler starting at `base` address.
    #[must_use]
    pub const fn new(bytes: &'a [u8], base: Address) -> Self {
        Self {
            bytes,
            base,
            offset: 0,
            arch: Arm64Arch,
        }
    }

    /// Byte offset of the *next* instruction within `bytes`.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Virtual address of the *next* instruction to be decoded.
    #[must_use]
    pub const fn current_address(&self) -> Address {
        Address::new(self.base.as_u64().wrapping_add(self.offset as u64))
    }

    /// `true` when the byte slice has been fully consumed.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

impl Iterator for Arm64LinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let remaining = &self.bytes[self.offset..];
        let cur_addr = Address::new(self.base.as_u64().wrapping_add(self.offset as u64));

        match self.arch.disassemble(cur_addr, remaining) {
            Ok(instr) => {
                self.offset += 4;
                Some(Ok(instr))
            }
            Err(e) => {
                self.offset += 4;
                Some(Err(e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Arm64InstrCategory
// ---------------------------------------------------------------------------

/// Broad functional category of an ARM64 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arm64InstrCategory {
    /// Arithmetic, logical, shift, move, comparison.
    DataProcessing,
    /// All memory-access instructions (loads and stores).
    LoadStore,
    /// Branches: conditional, unconditional, indirect, calls, returns.
    Branch,
    /// Floating-point and SIMD/NEON instructions.
    FloatSimd,
    /// System instructions: MSR, MRS, SVC, HVC, SMC, etc.
    System,
    /// Memory barriers: DMB, DSB, ISB, SB.
    Barrier,
    /// Atomic memory operations: LDXR, STXR, CAS, SWP, etc.
    AtomicMemory,
    /// Everything else.
    Miscellaneous,
}

impl Arm64InstrCategory {
    fn is_branch_mnemonic(m: &str) -> bool {
        m == "b" || m == "bl" || m == "br" || m == "blr"
            || m == "ret" || m == "eret"
            || m == "cbz" || m == "cbnz"
            || m == "tbz" || m == "tbnz"
            || m.starts_with("b.")
    }

    fn is_atomic_mnemonic(m: &str) -> bool {
        m.starts_with("ldx") || m.starts_with("ldax")
            || m.starts_with("stx") || m.starts_with("stlx")
            || m.starts_with("cas") || m.starts_with("swp")
            || m.starts_with("ldadd") || m.starts_with("ldclr")
            || m.starts_with("ldeor") || m.starts_with("ldset")
            || m.starts_with("ldsmax") || m.starts_with("ldsmin")
            || m.starts_with("ldumax") || m.starts_with("ldumin")
            || m.starts_with("stadd") || m.starts_with("stclr")
            || m.starts_with("steor") || m.starts_with("stset")
            || m.starts_with("stsmax") || m.starts_with("stsmin")
            || m.starts_with("stumax") || m.starts_with("stumin")
    }

    fn is_load_store_mnemonic(m: &str) -> bool {
        m.starts_with("ldr") || m.starts_with("ldp")
            || m.starts_with("lda") || m.starts_with("ld")
            || m.starts_with("str") || m.starts_with("stp")
            || m.starts_with("stl") || m.starts_with("st")
            || m == "prfm" || m == "prfum"
    }

    fn is_fp_simd_mnemonic(m: &str) -> bool {
        m.starts_with('f') || m.starts_with("scvtf") || m.starts_with("ucvtf")
            || m.starts_with("dup") || m.starts_with("ins")
            || m.starts_with("umov") || m.starts_with("smov")
            || m.starts_with("ext") || m.starts_with("tbl") || m.starts_with("tbx")
            || m.starts_with("zip") || m.starts_with("uzp") || m.starts_with("trn")
            || m.starts_with("mla") || m.starts_with("mls") || m.starts_with("pmul")
            || m.starts_with("saddl") || m.starts_with("uaddl")
            || m.starts_with("ssubl") || m.starts_with("usubl")
            || m.starts_with("sabd") || m.starts_with("uabd")
            || m.starts_with("saba") || m.starts_with("uaba")
            || m.starts_with("sqadd") || m.starts_with("uqadd")
            || m.starts_with("sqsub") || m.starts_with("uqsub")
            || m.starts_with("cnt")
            || m.starts_with("rev64") || m.starts_with("rev32") || m.starts_with("rev16")
            || m.starts_with("addp") || m.starts_with("addv")
    }

    fn is_system_mnemonic(m: &str) -> bool {
        matches!(
            m,
            "msr" | "mrs" | "svc" | "hvc" | "smc"
                | "dc" | "ic" | "at" | "tlbi" | "sys" | "sysl"
                | "hint" | "nop" | "yield" | "wfe" | "wfi"
                | "sev" | "sevl"
                | "xpaclri" | "autiasp" | "autibsp" | "paciasp" | "pacibsp"
                | "brk" | "hlt" | "dcps1" | "dcps2" | "dcps3" | "drps"
        )
    }

    fn is_data_proc_mnemonic(m: &str) -> bool {
        m.starts_with("add") || m.starts_with("sub")
            || m.starts_with("mul") || m.starts_with("div")
            || m.starts_with("and") || m.starts_with("orr")
            || m.starts_with("eor") || m.starts_with("bic")
            || m.starts_with("orn") || m.starts_with("eon")
            || m.starts_with("adr") || m.starts_with("mov") || m.starts_with("mvn")
            || m.starts_with("lsl") || m.starts_with("lsr")
            || m.starts_with("asr") || m.starts_with("ror")
            || m.starts_with("cmp") || m.starts_with("cmn") || m.starts_with("tst")
            || m.starts_with("neg") || m.starts_with("ngc")
            || m.starts_with("csel") || m.starts_with("csinc")
            || m.starts_with("csinv") || m.starts_with("csneg")
            || m.starts_with("cset") || m.starts_with("csetm")
            || m.starts_with("cinc") || m.starts_with("cinv") || m.starts_with("cneg")
            || m.starts_with("extr")
            || m.starts_with("sbfm") || m.starts_with("ubfm") || m.starts_with("bfm")
            || m.starts_with("sbfx") || m.starts_with("ubfx")
            || m.starts_with("sbfiz") || m.starts_with("ubfiz")
            || m.starts_with("bfi") || m.starts_with("bfxil")
            || m.starts_with("sxt") || m.starts_with("uxt")
            || m.starts_with("cls") || m.starts_with("clz")
            || m.starts_with("rbit") || m.starts_with("rev")
            || m.starts_with("madd") || m.starts_with("msub")
            || m.starts_with("smaddl") || m.starts_with("smsubl") || m.starts_with("smulh")
            || m.starts_with("umaddl") || m.starts_with("umsubl") || m.starts_with("umulh")
            || m.starts_with("sdiv") || m.starts_with("udiv")
            || m.starts_with("pac") || m.starts_with("aut") || m.starts_with("xpac")
    }

    /// Classify an ARM64 instruction by its mnemonic string (case-insensitive).
    #[must_use]
    pub fn classify(mnemonic: &str) -> Self {
        let m = mnemonic.to_ascii_lowercase();
        let m = m.as_str();
        if matches!(m, "dmb" | "dsb" | "isb" | "sb") { return Self::Barrier; }
        if Self::is_branch_mnemonic(m)    { return Self::Branch; }
        if Self::is_atomic_mnemonic(m)    { return Self::AtomicMemory; }
        if Self::is_load_store_mnemonic(m){ return Self::LoadStore; }
        if Self::is_fp_simd_mnemonic(m)   { return Self::FloatSimd; }
        if Self::is_system_mnemonic(m)    { return Self::System; }
        if Self::is_data_proc_mnemonic(m) { return Self::DataProcessing; }
        Self::Miscellaneous
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::arch::Architecture;

    fn arch() -> Arm64Arch {
        Arm64Arch::new()
    }

    // ── 1. Architecture meta-properties ─────────────────────────────────────

    #[test]
    fn test_name() {
        assert_eq!(arch().name(), "aarch64");
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(arch().pointer_size(), 8);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    // ── 2. NOP (0xD503_201F little-endian: 1F 20 03 D5) ──────────────────────

    #[test]
    fn test_disassemble_nop() {
        let bytes: &[u8] = &[0x1f, 0x20, 0x03, 0xd5];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        // yaxpeax emits "nop" for HINT #0
        assert!(
            instr.mnemonic == "nop" || instr.mnemonic == "hint",
            "expected nop or hint, got '{}'",
            instr.mnemonic
        );
        assert_eq!(instr.size, 4);
        assert_eq!(instr.address.as_u64(), 0x1000);
        assert_eq!(instr.bytes, bytes);
        assert_eq!(instr.flags, InstrFlags::NONE);
    }

    // ── 3. RET (0xD65F_03C0 little-endian: C0 03 5F D6) ──────────────────────

    #[test]
    fn test_disassemble_ret() {
        let bytes: &[u8] = &[0xc0, 0x03, 0x5f, 0xd6];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "ret");
        assert!(
            instr.flags.contains(InstrFlags::RET),
            "RET must have RETURN flag; got {:?}",
            instr.flags
        );
        assert!(!instr.flags.contains(InstrFlags::BRANCH));
    }

    // ── 4. BL +4 (0x9400_0001 LE: 01 00 00 94) ── flags BRANCH | CALL ────────

    #[test]
    fn test_disassemble_bl() {
        let bytes: &[u8] = &[0x01, 0x00, 0x00, 0x94];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "bl");
        assert!(instr.flags.contains(InstrFlags::BRANCH | InstrFlags::CALL));
        assert!(!instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── 5. B +4 (0x1400_0001 LE: 01 00 00 14) ── flags BRANCH ────────────────

    #[test]
    fn test_disassemble_b() {
        let bytes: &[u8] = &[0x01, 0x00, 0x00, 0x14];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "b");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
        assert!(!instr.flags.contains(InstrFlags::CALL));
        assert!(!instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── 6. B.EQ +8 (0x5400_0040 LE: 40 00 00 54) ── flags BRANCH|CONDITIONAL ─

    #[test]
    fn test_disassemble_b_eq() {
        let bytes: &[u8] = &[0x40, 0x00, 0x00, 0x54];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "b.eq");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CONDITIONAL)
        );
        assert!(!instr.flags.contains(InstrFlags::CALL));
    }

    // ── 7. CBZ X0,+8 (0xB400_0040 LE: 40 00 00 B4) ── flags BRANCH|CONDITIONAL

    #[test]
    fn test_disassemble_cbz() {
        let bytes: &[u8] = &[0x40, 0x00, 0x00, 0xb4];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "cbz");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CONDITIONAL)
        );
    }

    // ── 8. LDR X0,[X1] (0xF940_0020 LE: 20 00 40 F9) ── flags READ_MEM ───────

    #[test]
    fn test_disassemble_ldr() {
        let bytes: &[u8] = &[0x20, 0x00, 0x40, 0xf9];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "ldr");
        assert!(
            instr.flags.contains(InstrFlags::READ_MEM),
            "LDR must have READ_MEM; got {:?}",
            instr.flags
        );
        assert!(!instr.flags.contains(InstrFlags::BRANCH));
    }

    // ── 9. STR X0,[X1] (0xF900_0020 LE: 20 00 00 F9) ── flags WRITE_MEM ──────

    #[test]
    fn test_disassemble_str() {
        let bytes: &[u8] = &[0x20, 0x00, 0x00, 0xf9];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "str");
        assert!(
            instr.flags.contains(InstrFlags::WRITE_MEM),
            "STR must have WRITE_MEM; got {:?}",
            instr.flags
        );
        assert!(!instr.flags.contains(InstrFlags::BRANCH));
    }

    // ── 10. BLR X0 (0xD63F_0000 LE: 00 00 3F D6) ── flags BRANCH|CALL|INDIRECT

    #[test]
    fn test_disassemble_blr() {
        let bytes: &[u8] = &[0x00, 0x00, 0x3f, 0xd6];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "blr");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::INDIRECT),
            "BLR must have BRANCH|CALL|INDIRECT; got {:?}",
            instr.flags
        );
    }

    // ── 11. BR X0 (0xD61F_0000 LE: 00 00 1F D6) ── flags BRANCH|INDIRECT ─────

    #[test]
    fn test_disassemble_br() {
        let bytes: &[u8] = &[0x00, 0x00, 0x1f, 0xd6];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "br");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::INDIRECT),
            "BR must have BRANCH|INDIRECT; got {:?}",
            instr.flags
        );
        assert!(!instr.flags.contains(InstrFlags::CALL));
    }

    // ── 12. get_branches on BL: correct target ────────────────────────────────

    #[test]
    fn test_get_branches_bl_target() {
        // BL +4 at 0x1000 → target 0x1004
        let bytes: &[u8] = &[0x01, 0x00, 0x00, 0x94];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target.unwrap(), 0x1004);
        assert!(branches[0].kind.is_call());
        assert!(branches[0].is_unconditional());
    }

    // ── 13. get_branches on B: correct target ────────────────────────────────

    #[test]
    fn test_get_branches_b_target() {
        // B +4 at 0x1000 → target 0x1004
        let bytes: &[u8] = &[0x01, 0x00, 0x00, 0x14];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].target.unwrap(), 0x1004);
        assert!(!branches[0].kind.is_call());
        assert!(branches[0].is_unconditional());
    }

    // ── 14. get_branches on B.EQ: conditional=true ───────────────────────────

    #[test]
    fn test_get_branches_b_eq_conditional() {
        // B.EQ +8 at 0x1000 → target 0x1008
        let bytes: &[u8] = &[0x40, 0x00, 0x00, 0x54];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert!(!branches[0].is_unconditional());
        assert!(!branches[0].kind.is_call());
        assert_eq!(branches[0].target.unwrap(), 0x1008);
    }

    // ── 15. get_branches on RET: empty ────────────────────────────────────────

    #[test]
    /// RET emits a TARGETLESS `BranchInfo::ret()`, not an empty vec.
    ///
    /// This test previously asserted `branches.is_empty()` and directly
    /// CONTRADICTED `tests/blitz.rs::branches_ret_emits_ret_branch`, which
    /// asserts exactly one BranchInfo. Both could not hold; the crate had two
    /// tests pinning opposite semantics, so `RET` was never actually decided.
    ///
    /// Resolved in favour of emitting, on evidence:
    ///  * `BranchInfo::ret()` exists in rustre-core specifically to model a
    ///    targetless function return (`target: None, kind: Return`);
    ///  * rustre-arch-6502 (lib.rs:952) and rustre-arch-luajit (lib.rs:564)
    ///    already emit it, so empty made AArch64 the outlier;
    ///  * `get_branches`' own ERET arm already emits a targetless BranchInfo;
    ///  * it is ADDITIVE: `InstrFlags::RET` is untouched, so a flags-driven CFG
    ///    builder behaves identically, while a `get_branches`-driven one stops
    ///    running basic blocks past function returns. The empty form strictly
    ///    loses information; this direction cannot break either consumer.
    ///
    /// "No static target" is still true and is expressed by `target == None` —
    /// that was the real content of the old assertion, so it is kept below.
    #[test]
    fn test_get_branches_ret_is_targetless_return() {
        let bytes: &[u8] = &[0xc0, 0x03, 0x5f, 0xd6];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert_eq!(branches.len(), 1, "RET must emit one BranchInfo");
        assert_eq!(branches[0].kind, BranchKind::Return);
        assert!(
            branches[0].target.is_none(),
            "RET has no static branch target"
        );
    }

    // ── 16. get_branches on BLR: empty (indirect) ────────────────────────────

    #[test]
    fn test_get_branches_blr_empty() {
        let bytes: &[u8] = &[0x00, 0x00, 0x3f, 0xd6];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert!(branches.is_empty(), "BLR has no static target");
    }

    // ── 17. registers(): count > 100, and contains key names ─────────────────

    #[test]
    fn test_registers_count_and_key_names() {
        let regs = arch().registers();
        assert!(
            regs.len() > 100,
            "expected >100 registers; got {}",
            regs.len()
        );
        assert!(regs.iter().any(|r| r.name == "x0"), "missing x0");
        assert!(regs.iter().any(|r| r.name == "sp"), "missing sp");
        assert!(regs.iter().any(|r| r.name == "pc"), "missing pc");
        assert!(regs.iter().any(|r| r.name == "v0"), "missing v0");
    }

    // ── 18. calling_conventions: aapcs64 with x0-x7 ──────────────────────────

    #[test]
    fn test_calling_conventions_aapcs64() {
        let ccs = arch().calling_conventions();
        let aapcs = ccs
            .iter()
            .find(|c| c.name == "aapcs64")
            .expect("aapcs64 missing");
        assert_eq!(aapcs.int_args.len(), 8);
        assert_eq!(aapcs.int_args[0], "x0");
        assert_eq!(aapcs.int_args[7], "x7");
        assert_eq!(aapcs.return_regs, vec!["x0", "x1"]);
        assert!(aapcs.caller_cleans_stack);
    }

    // ── 19. Arm64LinearDisassembler iterates 4 instructions ──────────────────

    #[test]
    fn test_linear_disassembler_four_nops() {
        let nop: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];
        let code: Vec<u8> = nop.iter().cycle().take(16).copied().collect();
        let base = Address::new(0x4000);
        let results: Vec<_> = Arm64LinearDisassembler::new(&code, base)
            .collect::<Result<Vec<_>, _>>()
            .expect("all NOPs must decode cleanly");
        assert_eq!(results.len(), 4);
        for (i, instr) in results.iter().enumerate() {
            assert_eq!(instr.address.as_u64(), 0x4000 + (i as u64) * 4);
            assert_eq!(instr.size, 4);
        }
    }

    // ── 20. Arm64InstrCategory::classify ─────────────────────────────────────

    #[test]
    fn test_instr_category_classify() {
        assert_eq!(
            Arm64InstrCategory::classify("add"),
            Arm64InstrCategory::DataProcessing
        );
        assert_eq!(
            Arm64InstrCategory::classify("ldr"),
            Arm64InstrCategory::LoadStore
        );
        assert_eq!(
            Arm64InstrCategory::classify("str"),
            Arm64InstrCategory::LoadStore
        );
        assert_eq!(
            Arm64InstrCategory::classify("b"),
            Arm64InstrCategory::Branch
        );
        assert_eq!(
            Arm64InstrCategory::classify("bl"),
            Arm64InstrCategory::Branch
        );
        assert_eq!(
            Arm64InstrCategory::classify("ret"),
            Arm64InstrCategory::Branch
        );
        assert_eq!(
            Arm64InstrCategory::classify("cbz"),
            Arm64InstrCategory::Branch
        );
        assert_eq!(
            Arm64InstrCategory::classify("b.eq"),
            Arm64InstrCategory::Branch
        );
        assert_eq!(
            Arm64InstrCategory::classify("fadd"),
            Arm64InstrCategory::FloatSimd
        );
        assert_eq!(
            Arm64InstrCategory::classify("svc"),
            Arm64InstrCategory::System
        );
        assert_eq!(
            Arm64InstrCategory::classify("msr"),
            Arm64InstrCategory::System
        );
        assert_eq!(
            Arm64InstrCategory::classify("dmb"),
            Arm64InstrCategory::Barrier
        );
        assert_eq!(
            Arm64InstrCategory::classify("dsb"),
            Arm64InstrCategory::Barrier
        );
        assert_eq!(
            Arm64InstrCategory::classify("isb"),
            Arm64InstrCategory::Barrier
        );
        assert_eq!(
            Arm64InstrCategory::classify("ldxr"),
            Arm64InstrCategory::AtomicMemory
        );
        assert_eq!(
            Arm64InstrCategory::classify("stxr"),
            Arm64InstrCategory::AtomicMemory
        );
        assert_eq!(
            Arm64InstrCategory::classify("nop"),
            Arm64InstrCategory::System
        );
    }

    // ── 21. disassemble with < 4 bytes returns error ──────────────────────────

    #[test]
    fn test_disassemble_too_few_bytes() {
        let result = arch().disassemble(Address::new(0x1000), &[0x1f, 0x20]);
        assert!(result.is_err(), "< 4 bytes must produce an error");
    }

    // ── 22. Empty byte slice returns error ────────────────────────────────────

    #[test]
    fn test_disassemble_empty_bytes() {
        let result = arch().disassemble(Address::new(0x1000), &[]);
        assert!(result.is_err());
    }

    // ── 23. Arm64Arch usable as a trait object ────────────────────────────────

    #[test]
    fn test_trait_object() {
        let boxed: Box<dyn Architecture> = Box::new(Arm64Arch::new());
        assert_eq!(boxed.name(), "aarch64");
        assert_eq!(boxed.pointer_size(), 8);
    }

    // ── 24. DMB ISH (0xD503_3BBF LE: BF 3B 03 D5) ── flags BARRIER ────────────

    #[test]
    fn test_disassemble_dmb() {
        let bytes: &[u8] = &[0xbf, 0x3b, 0x03, 0xd5];
        let instr = arch().disassemble(Address::new(0x1000), bytes).unwrap();
        assert_eq!(instr.mnemonic, "dmb");
        assert!(
            instr.flags.contains(InstrFlags::BARRIER),
            "DMB must have BARRIER; got {:?}",
            instr.flags
        );
    }

    // ── 25. Linear disassembler: offset tracking and is_done ─────────────────

    #[test]
    fn test_linear_disassembler_offset_tracking() {
        let nop: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];
        let code: Vec<u8> = nop.iter().cycle().take(8).copied().collect();
        let base = Address::new(0x2000);
        let mut ld = Arm64LinearDisassembler::new(&code, base);

        assert_eq!(ld.offset(), 0);
        assert!(!ld.is_done());

        let _ = ld.next().unwrap().unwrap();
        assert_eq!(ld.offset(), 4);
        assert_eq!(ld.current_address().as_u64(), 0x2004);

        let _ = ld.next().unwrap().unwrap();
        assert_eq!(ld.offset(), 8);
        assert!(ld.is_done());

        assert!(ld.next().is_none());
    }

    // ── 26. Apple ABI present ─────────────────────────────────────────────────

    #[test]
    fn test_calling_conventions_apple_arm64() {
        let ccs = arch().calling_conventions();
        let apple = ccs
            .iter()
            .find(|c| c.name == "apple_arm64")
            .expect("apple_arm64 missing");
        assert_eq!(apple.int_args[0], "x0");
        assert_eq!(apple.return_regs[0], "x0");
    }

    // ── 27. Register IDs are unique ───────────────────────────────────────────

    #[test]
    fn test_register_ids_unique() {
        let regs = arch().registers();
        let mut ids: Vec<u32> = regs.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), regs.len(), "register IDs must be unique");
    }

    // ── 28. Linear disassembler: mixed instructions ───────────────────────────

    #[test]
    fn test_linear_disassembler_mixed() {
        // NOP, BL +4, RET, STR X0 [X1]
        let code: &[u8] = &[
            0x1f, 0x20, 0x03, 0xd5, // NOP
            0x01, 0x00, 0x00, 0x94, // BL +4
            0xc0, 0x03, 0x5f, 0xd6, // RET
            0x20, 0x00, 0x00, 0xf9, // STR X0, [X1]
        ];
        let base = Address::new(0x3000);
        let instrs: Vec<_> = Arm64LinearDisassembler::new(code, base)
            .collect::<Result<Vec<_>, _>>()
            .expect("all instructions must decode");

        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].address.as_u64(), 0x3000);

        assert_eq!(instrs[1].mnemonic, "bl");
        assert!(
            instrs[1]
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CALL)
        );
        assert_eq!(instrs[1].address.as_u64(), 0x3004);

        assert_eq!(instrs[2].mnemonic, "ret");
        assert!(instrs[2].flags.contains(InstrFlags::RET));
        assert_eq!(instrs[2].address.as_u64(), 0x3008);

        assert_eq!(instrs[3].mnemonic, "str");
        assert!(instrs[3].flags.contains(InstrFlags::WRITE_MEM));
        assert_eq!(instrs[3].address.as_u64(), 0x300c);
    }

    // ── 29. Arm64Arch::default() ─────────────────────────────────────────────

    #[test]
    fn test_default() {
        let a = Arm64Arch;
        assert_eq!(a.name(), "aarch64");
    }

    // ── 30. CBZ get_branches target ──────────────────────────────────────────

    #[test]
    fn test_get_branches_cbz_target() {
        // CBZ X0, +8 at 0x2000 → target 0x2008
        let bytes: &[u8] = &[0x40, 0x00, 0x00, 0xb4];
        let instr = arch().disassemble(Address::new(0x2000), bytes).unwrap();
        let branches = arch().get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert!(!branches[0].is_unconditional());
        assert!(!branches[0].kind.is_call());
        assert_eq!(branches[0].target.unwrap(), 0x2008);
    }

    // ── Spec-required instruction tests ─────────────────────────────────────

    #[test]
    fn test_ret_d65f03c0() {
        // 0xD65F_03C0 LE = C0 03 5F D6 → RET (already tested above as test_disassemble_ret)
        let bytes: &[u8] = &[0xc0, 0x03, 0x5f, 0xd6];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "ret");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_bl_94000000() {
        // 0x9400_0000 LE = 00 00 00 94 → BL #0
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x94];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "bl");
        assert!(instr.flags.contains(InstrFlags::CALL | InstrFlags::BRANCH));
    }

    #[test]
    fn test_br_x0_d61f0000() {
        // 0xD61F_0000 LE = 00 00 1F D6 → BR X0
        let bytes: &[u8] = &[0x00, 0x00, 0x1f, 0xd6];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "br");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::INDIRECT)
        );
    }

    #[test]
    fn test_b_14000000() {
        // 0x1400_0000 LE = 00 00 00 14 → B #0
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x14];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "b");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
        assert!(!instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_mov_x0_x0_aa0003e0() {
        // 0xAA00_03E0 LE = E0 03 00 AA → ORR X0,XZR,X0 (MOV X0,X0)
        let bytes: &[u8] = &[0xe0, 0x03, 0x00, 0xaa];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        // yaxpeax may emit "mov" or "orr"
        assert!(
            instr.mnemonic == "mov" || instr.mnemonic == "orr",
            "expected mov or orr; got '{}'",
            instr.mnemonic
        );
    }

    #[test]
    fn test_stp_x29_x30_sp_minus32() {
        // 0xA9BE_7BFD LE = FD 7B BE A9 → STP X29,X30,[SP,#-32]!
        let bytes: &[u8] = &[0xfd, 0x7b, 0xbe, 0xa9];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "stp");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_ldp_x29_x30_sp_post32() {
        // 0xA8C2_7BFD LE = FD 7B C2 A8 → LDP X29,X30,[SP],#32
        let bytes: &[u8] = &[0xfd, 0x7b, 0xc2, 0xa8];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "ldp");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_add_x0_x0_0_91000000() {
        // 0x9100_0000 LE = 00 00 00 91 → ADD X0,X0,#0
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x91];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "add");
    }

    #[test]
    fn test_ldr_x0_x0_f9400000() {
        // 0xF940_0000 LE = 00 00 40 F9 → LDR X0,[X0]
        let bytes: &[u8] = &[0x00, 0x00, 0x40, 0xf9];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "ldr");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_svc_d4000001() {
        // 0xD400_0001 LE = 01 00 00 D4 → SVC #0
        let bytes: &[u8] = &[0x01, 0x00, 0x00, 0xd4];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "svc");
    }

    #[test]
    fn test_cbnz_w0_35000000() {
        // 0x3500_0000 LE = 00 00 00 35 → CBNZ W0,#0
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x35];
        let instr = arch().disassemble(Address::new(0x0), bytes).unwrap();
        assert_eq!(instr.mnemonic, "cbnz");
        assert!(
            instr
                .flags
                .contains(InstrFlags::BRANCH | InstrFlags::CONDITIONAL)
        );
    }

    #[test]
    fn test_calling_conventions_count_at_least_2() {
        let ccs = arch().calling_conventions();
        assert!(
            ccs.len() >= 2,
            "expected >= 2 calling conventions; got {}",
            ccs.len()
        );
    }
}

// ---------------------------------------------------------------------------
// AArch64 system register table
// ---------------------------------------------------------------------------

/// An `AArch64` system register descriptor (MRS/MSR operand).
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Arm64SysReg {
    /// Register name as used in assembly.
    pub name: &'static str,
    /// op0 field (2 bits).
    pub op0: u8,
    /// op1 field (3 bits).
    pub op1: u8,
    /// `CRn` field (4 bits).
    pub crn: u8,
    /// `CRm` field (4 bits).
    pub crm: u8,
    /// op2 field (3 bits).
    pub op2: u8,
    /// Brief description.
    pub desc: &'static str,
}

impl Arm64SysReg {
    const fn new(
        name: &'static str,
        op0: u8,
        op1: u8,
        crn: u8,
        crm: u8,
        op2: u8,
        desc: &'static str,
    ) -> Self {
        Self {
            name,
            op0,
            op1,
            crn,
            crm,
            op2,
            desc,
        }
    }

    /// Compute the 16-bit encoded register field (op0:op1:CRn:CRm:op2).
    #[must_use]
    pub fn encoded(self) -> u16 {
        (u16::from(self.op0) << 14)
            | (u16::from(self.op1) << 11)
            | (u16::from(self.crn) << 7)
            | (u16::from(self.crm) << 3)
            | u16::from(self.op2)
    }
}

/// Key `AArch64` system registers.
pub static ARM64_SYS_REGS: &[Arm64SysReg] = &[
    // EL1 control / exception registers
    Arm64SysReg::new("SCTLR_EL1", 3, 0, 1, 0, 0, "System Control Register EL1"),
    Arm64SysReg::new("ACTLR_EL1", 3, 0, 1, 0, 1, "Auxiliary Control Register EL1"),
    Arm64SysReg::new(
        "CPACR_EL1",
        3,
        0,
        1,
        0,
        2,
        "Architectural Feature Access Control EL1",
    ),
    Arm64SysReg::new(
        "TTBR0_EL1",
        3,
        0,
        2,
        0,
        0,
        "Translation Table Base Register 0 EL1",
    ),
    Arm64SysReg::new(
        "TTBR1_EL1",
        3,
        0,
        2,
        0,
        1,
        "Translation Table Base Register 1 EL1",
    ),
    Arm64SysReg::new("TCR_EL1", 3, 0, 2, 0, 2, "Translation Control Register EL1"),
    Arm64SysReg::new(
        "SPSR_EL1",
        3,
        0,
        4,
        0,
        0,
        "Saved Program Status Register EL1",
    ),
    Arm64SysReg::new("ELR_EL1", 3, 0, 4, 0, 1, "Exception Link Register EL1"),
    Arm64SysReg::new("SP_EL0", 3, 0, 4, 1, 0, "Stack Pointer EL0"),
    Arm64SysReg::new("ESR_EL1", 3, 0, 5, 2, 0, "Exception Syndrome Register EL1"),
    Arm64SysReg::new(
        "AFSR0_EL1",
        3,
        0,
        5,
        1,
        0,
        "Auxiliary Fault Status Register 0 EL1",
    ),
    Arm64SysReg::new(
        "AFSR1_EL1",
        3,
        0,
        5,
        1,
        1,
        "Auxiliary Fault Status Register 1 EL1",
    ),
    Arm64SysReg::new("FAR_EL1", 3, 0, 6, 0, 0, "Fault Address Register EL1"),
    Arm64SysReg::new("PAR_EL1", 3, 0, 7, 4, 0, "Physical Address Register EL1"),
    Arm64SysReg::new(
        "VBAR_EL1",
        3,
        0,
        12,
        0,
        0,
        "Vector Base Address Register EL1",
    ),
    Arm64SysReg::new("ISR_EL1", 3, 0, 12, 1, 0, "Interrupt Status Register EL1"),
    Arm64SysReg::new("CONTEXTIDR_EL1", 3, 0, 13, 0, 1, "Context ID Register EL1"),
    Arm64SysReg::new(
        "TPIDR_EL1",
        3,
        0,
        13,
        0,
        4,
        "EL1 Software Thread ID Register",
    ),
    Arm64SysReg::new(
        "CNTKCTL_EL1",
        3,
        0,
        14,
        1,
        0,
        "Counter-timer Kernel Control EL1",
    ),
    // EL0-accessible
    Arm64SysReg::new("NZCV", 3, 3, 4, 2, 0, "Condition Flags"),
    Arm64SysReg::new("DAIF", 3, 3, 4, 2, 1, "Interrupt Mask Bits"),
    Arm64SysReg::new("FPCR", 3, 3, 4, 4, 0, "Floating-point Control Register"),
    Arm64SysReg::new("FPSR", 3, 3, 4, 4, 1, "Floating-point Status Register"),
    Arm64SysReg::new(
        "TPIDR_EL0",
        3,
        3,
        13,
        0,
        2,
        "EL0 Read/Write Software Thread ID Register",
    ),
    Arm64SysReg::new(
        "TPIDRRO_EL0",
        3,
        3,
        13,
        0,
        3,
        "EL0 Read-only Software Thread ID Register",
    ),
    // EL2 hypervisor
    Arm64SysReg::new(
        "HCR_EL2",
        3,
        4,
        1,
        1,
        0,
        "Hypervisor Configuration Register EL2",
    ),
    Arm64SysReg::new(
        "VTCR_EL2",
        3,
        4,
        2,
        1,
        2,
        "Virtualization Translation Control EL2",
    ),
    Arm64SysReg::new(
        "VTTBR_EL2",
        3,
        4,
        2,
        1,
        0,
        "Virtualization Translation Table Base EL2",
    ),
    Arm64SysReg::new("ELR_EL2", 3, 4, 4, 0, 1, "Exception Link Register EL2"),
    Arm64SysReg::new("ESR_EL2", 3, 4, 5, 2, 0, "Exception Syndrome Register EL2"),
    Arm64SysReg::new(
        "VBAR_EL2",
        3,
        4,
        12,
        0,
        0,
        "Vector Base Address Register EL2",
    ),
    // EL3 secure monitor
    Arm64SysReg::new(
        "SCR_EL3",
        3,
        6,
        1,
        1,
        0,
        "Secure Configuration Register EL3",
    ),
    Arm64SysReg::new("ELR_EL3", 3, 6, 4, 0, 1, "Exception Link Register EL3"),
    Arm64SysReg::new(
        "VBAR_EL3",
        3,
        6,
        12,
        0,
        0,
        "Vector Base Address Register EL3",
    ),
    // Performance / PMU
    Arm64SysReg::new(
        "PMCR_EL0",
        3,
        3,
        9,
        12,
        0,
        "Performance Monitor Control Register",
    ),
    Arm64SysReg::new(
        "PMCCNTR_EL0",
        3,
        3,
        9,
        13,
        0,
        "Performance Monitor Cycle Count Register",
    ),
    Arm64SysReg::new(
        "PMEVCNTR0_EL0",
        3,
        3,
        14,
        8,
        0,
        "Performance Monitor Event Count 0",
    ),
    // ID registers
    Arm64SysReg::new("MIDR_EL1", 3, 0, 0, 0, 0, "Main ID Register EL1"),
    Arm64SysReg::new(
        "MPIDR_EL1",
        3,
        0,
        0,
        0,
        5,
        "Multiprocessor Affinity Register EL1",
    ),
    Arm64SysReg::new("REVIDR_EL1", 3, 0, 0, 0, 6, "Revision ID Register EL1"),
    Arm64SysReg::new(
        "ID_AA64PFR0_EL1",
        3,
        0,
        0,
        4,
        0,
        "AArch64 Processor Feature Register 0",
    ),
    Arm64SysReg::new(
        "ID_AA64PFR1_EL1",
        3,
        0,
        0,
        4,
        1,
        "AArch64 Processor Feature Register 1",
    ),
    Arm64SysReg::new(
        "ID_AA64ISAR0_EL1",
        3,
        0,
        0,
        6,
        0,
        "AArch64 ISA Feature Register 0",
    ),
    Arm64SysReg::new(
        "ID_AA64MMFR0_EL1",
        3,
        0,
        0,
        7,
        0,
        "AArch64 Memory Model Feature Register 0",
    ),
    // Debug
    Arm64SysReg::new(
        "MDSCR_EL1",
        2,
        0,
        0,
        2,
        2,
        "Monitor Debug System Control Register",
    ),
    Arm64SysReg::new("OSLAR_EL1", 2, 0, 1, 0, 4, "OS Lock Access Register"),
    Arm64SysReg::new(
        "DBGBVR0_EL1",
        2,
        0,
        0,
        0,
        4,
        "Debug Breakpoint Value Register 0",
    ),
    Arm64SysReg::new(
        "DBGBCR0_EL1",
        2,
        0,
        0,
        0,
        5,
        "Debug Breakpoint Control Register 0",
    ),
];

/// Look up an `AArch64` system register by name.
#[must_use]
pub fn arm64_sysreg_lookup(name: &str) -> Option<&'static Arm64SysReg> {
    ARM64_SYS_REGS
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// AArch64 NZCV / PSTATE helpers
// ---------------------------------------------------------------------------

/// `AArch64` NZCV condition flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Nzcv(pub u8);

impl Nzcv {
    /// Create from the upper 4 bits of a PSTATE/NZCV value.
    pub const fn from_u32(v: u32) -> Self {
        Self(((v >> 28) & 0xf) as u8)
    }

    /// Negative flag.
    #[must_use]
    pub const fn n(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }
    /// Zero flag.
    #[must_use]
    pub const fn z(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }
    /// Carry flag.
    #[must_use]
    pub const fn c(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }
    /// Overflow flag.
    #[must_use]
    pub const fn v(self) -> bool {
        self.0 & 1 != 0
    }

    /// Encode back to NZCV bits[31:28].
    #[must_use]
    pub fn to_u32(self) -> u32 {
        u32::from(self.0) << 28
    }
}

/// `AArch64` condition code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum A64Cond {
    Eq = 0,
    Ne = 1,
    Cs = 2,
    Cc = 3,
    Mi = 4,
    Pl = 5,
    Vs = 6,
    Vc = 7,
    Hi = 8,
    Ls = 9,
    Ge = 10,
    Lt = 11,
    Gt = 12,
    Le = 13,
    Al = 14,
    Nv = 15,
}

impl A64Cond {
    /// Decode from 4-bit condition field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0xf {
            0 => Self::Eq,
            1 => Self::Ne,
            2 => Self::Cs,
            3 => Self::Cc,
            4 => Self::Mi,
            5 => Self::Pl,
            6 => Self::Vs,
            7 => Self::Vc,
            8 => Self::Hi,
            9 => Self::Ls,
            10 => Self::Ge,
            11 => Self::Lt,
            12 => Self::Gt,
            13 => Self::Le,
            14 => Self::Al,
            _ => Self::Nv,
        }
    }

    /// Mnemonic suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Cs => "cs",
            Self::Cc => "cc",
            Self::Mi => "mi",
            Self::Pl => "pl",
            Self::Vs => "vs",
            Self::Vc => "vc",
            Self::Hi => "hi",
            Self::Ls => "ls",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Gt => "gt",
            Self::Le => "le",
            Self::Al => "al",
            Self::Nv => "nv",
        }
    }

    /// Evaluate this condition against NZCV flags.
    #[must_use]
    pub const fn evaluate(self, nzcv: Nzcv) -> bool {
        match self {
            Self::Eq => nzcv.z(),
            Self::Ne => !nzcv.z(),
            Self::Cs => nzcv.c(),
            Self::Cc => !nzcv.c(),
            Self::Mi => nzcv.n(),
            Self::Pl => !nzcv.n(),
            Self::Vs => nzcv.v(),
            Self::Vc => !nzcv.v(),
            Self::Hi => nzcv.c() && !nzcv.z(),
            Self::Ls => !nzcv.c() || nzcv.z(),
            Self::Ge => nzcv.n() == nzcv.v(),
            Self::Lt => nzcv.n() != nzcv.v(),
            Self::Gt => !nzcv.z() && (nzcv.n() == nzcv.v()),
            Self::Le => nzcv.z() || (nzcv.n() != nzcv.v()),
            Self::Al | Self::Nv => true,
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 AAPCS64 calling convention full description
// ---------------------------------------------------------------------------

/// Role of an `AArch64` general-purpose register in the AAPCS64 ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Aapcs64Role {
    /// x0–x7: parameter / result registers (caller-saved).
    Parameter,
    /// x8: indirect result location register (caller-saved).
    IndirectResult,
    /// x9–x15: temporary / corruptible registers (caller-saved).
    Temporary,
    /// x16–x17: intra-procedure-call scratch registers (IP0/IP1).
    IntraProcedureCall,
    /// x18: platform register (reserved on some OSes).
    Platform,
    /// x19–x28: callee-saved registers.
    CalleeSaved,
    /// x29: frame pointer.
    FramePointer,
    /// x30: link register (return address).
    LinkRegister,
    /// SP / XZR (index 31 depending on context).
    StackPointerOrZero,
}

/// Return the AAPCS64 role for GPR `n` (0–31).
pub const fn aapcs64_role(n: u8) -> Aapcs64Role {
    match n {
        0..=7 => Aapcs64Role::Parameter,
        8 => Aapcs64Role::IndirectResult,
        9..=15 => Aapcs64Role::Temporary,
        16..=17 => Aapcs64Role::IntraProcedureCall,
        18 => Aapcs64Role::Platform,
        19..=28 => Aapcs64Role::CalleeSaved,
        29 => Aapcs64Role::FramePointer,
        30 => Aapcs64Role::LinkRegister,
        _ => Aapcs64Role::StackPointerOrZero,
    }
}

/// AAPCS64 FP/SIMD register role (v0–v31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Aapcs64FpRole {
    /// v0–v7: argument / result FP registers.
    Argument,
    /// v8–v15: callee-saved (low 64-bits only).
    CalleeSaved,
    /// v16–v31: temporary (caller-saved).
    Temporary,
}

/// Return the AAPCS64 FP role for SIMD register `n` (0–31).
pub const fn aapcs64_fp_role(n: u8) -> Aapcs64FpRole {
    match n {
        0..=7 => Aapcs64FpRole::Argument,
        8..=15 => Aapcs64FpRole::CalleeSaved,
        _ => Aapcs64FpRole::Temporary,
    }
}

// ---------------------------------------------------------------------------
// AArch64 instruction encoding groups
// ---------------------------------------------------------------------------

/// Top-level `AArch64` instruction encoding group (bits[28:25] of the word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum A64Group {
    /// Unallocated.
    Unallocated,
    /// Data processing — immediate.
    DpImm,
    /// Branches, exception generation, and system instructions.
    BranchExcSys,
    /// Loads and stores.
    LoadsStores,
    /// Data processing — register.
    DpReg,
    /// Data processing — scalar FP and SIMD.
    DpFpSimd,
}

/// Classify an `AArch64` instruction word into its top-level group.
pub const fn a64_group(word: u32) -> A64Group {
    match (word >> 25) & 0xf {
        0b1000 | 0b1001 => A64Group::DpImm,
        0b1010 | 0b1011 => A64Group::BranchExcSys,
        0b0100 | 0b0110 | 0b1100 | 0b1110 => A64Group::LoadsStores,
        0b0101 | 0b1101 => A64Group::DpReg,
        0b0111 | 0b1111 => A64Group::DpFpSimd,
        _ => A64Group::Unallocated,
    }
}

// ---------------------------------------------------------------------------
// AArch64 LSE atomic operations table
// ---------------------------------------------------------------------------

/// An LSE atomic operation descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct LseAtomicOp {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Operation description.
    pub desc: &'static str,
    /// Whether the operation is load-acquire (ordering).
    pub acquire: bool,
    /// Whether the operation has store-release (ordering).
    pub release: bool,
}

impl LseAtomicOp {
    const fn new(mnemonic: &'static str, desc: &'static str, acquire: bool, release: bool) -> Self {
        Self {
            mnemonic,
            desc,
            acquire,
            release,
        }
    }
}

/// LSE (ARMv8.1 Large System Extensions) atomic operations.
pub static LSE_ATOMIC_OPS: &[LseAtomicOp] = &[
    LseAtomicOp::new("cas", "Compare and Swap", false, false),
    LseAtomicOp::new("casa", "Compare and Swap, acquire", true, false),
    LseAtomicOp::new("casl", "Compare and Swap, release", false, true),
    LseAtomicOp::new("casal", "Compare and Swap, acquire+release", true, true),
    LseAtomicOp::new("casb", "Compare and Swap Byte", false, false),
    LseAtomicOp::new("casab", "Compare and Swap Byte, acquire", true, false),
    LseAtomicOp::new("caslb", "Compare and Swap Byte, release", false, true),
    LseAtomicOp::new(
        "casalb",
        "Compare and Swap Byte, acquire+release",
        true,
        true,
    ),
    LseAtomicOp::new("cash", "Compare and Swap Halfword", false, false),
    LseAtomicOp::new("casah", "Compare and Swap Halfword, acquire", true, false),
    LseAtomicOp::new("caslh", "Compare and Swap Halfword, release", false, true),
    LseAtomicOp::new(
        "casalh",
        "Compare and Swap Halfword, acquire+release",
        true,
        true,
    ),
    LseAtomicOp::new("swp", "Swap", false, false),
    LseAtomicOp::new("swpa", "Swap, acquire", true, false),
    LseAtomicOp::new("swpl", "Swap, release", false, true),
    LseAtomicOp::new("swpal", "Swap, acquire+release", true, true),
    LseAtomicOp::new("ldadd", "Atomic Add", false, false),
    LseAtomicOp::new("ldadda", "Atomic Add, acquire", true, false),
    LseAtomicOp::new("ldaddl", "Atomic Add, release", false, true),
    LseAtomicOp::new("ldaddal", "Atomic Add, acquire+release", true, true),
    LseAtomicOp::new("ldclr", "Atomic Bit Clear", false, false),
    LseAtomicOp::new("ldclra", "Atomic Bit Clear, acquire", true, false),
    LseAtomicOp::new("ldclrl", "Atomic Bit Clear, release", false, true),
    LseAtomicOp::new("ldclral", "Atomic Bit Clear, acquire+release", true, true),
    LseAtomicOp::new("ldeor", "Atomic EOR", false, false),
    LseAtomicOp::new("ldeora", "Atomic EOR, acquire", true, false),
    LseAtomicOp::new("ldeorl", "Atomic EOR, release", false, true),
    LseAtomicOp::new("ldeoral", "Atomic EOR, acquire+release", true, true),
    LseAtomicOp::new("ldset", "Atomic Bit Set", false, false),
    LseAtomicOp::new("ldseta", "Atomic Bit Set, acquire", true, false),
    LseAtomicOp::new("ldsetl", "Atomic Bit Set, release", false, true),
    LseAtomicOp::new("ldsetal", "Atomic Bit Set, acquire+release", true, true),
    LseAtomicOp::new("stadd", "Atomic Add (no return)", false, false),
    LseAtomicOp::new("stclr", "Atomic Bit Clear (no return)", false, false),
    LseAtomicOp::new("steor", "Atomic EOR (no return)", false, false),
    LseAtomicOp::new("stset", "Atomic Bit Set (no return)", false, false),
];

/// Look up an LSE atomic operation by mnemonic.
#[must_use]
pub fn lse_lookup(mnemonic: &str) -> Option<&'static LseAtomicOp> {
    LSE_ATOMIC_OPS
        .iter()
        .find(|op| op.mnemonic.eq_ignore_ascii_case(mnemonic))
}

// ---------------------------------------------------------------------------
// AArch64 PAC (Pointer Authentication) helpers
// ---------------------------------------------------------------------------

/// `AArch64` PAC instruction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PacKind {
    /// Add PAC to instruction address (key A).
    PacIA,
    /// Add PAC to instruction address (key B).
    PacIB,
    /// Add PAC to data address (key A).
    PacDA,
    /// Add PAC to data address (key B).
    PacDB,
    /// Authenticate instruction address (key A).
    AutIA,
    /// Authenticate instruction address (key B).
    AutIB,
    /// Authenticate data address (key A).
    AutDA,
    /// Authenticate data address (key B).
    AutDB,
    /// Strip PAC from instruction address.
    XPacI,
    /// Strip PAC from data address.
    XPacD,
}

impl PacKind {
    /// Classify from a mnemonic string.
    #[must_use]
    pub fn from_mnemonic(m: &str) -> Option<Self> {
        match m.to_ascii_lowercase().as_str() {
            "pacia" | "paciasp" | "pacia1716" => Some(Self::PacIA),
            "pacib" | "pacibsp" | "pacib1716" => Some(Self::PacIB),
            "pacda" => Some(Self::PacDA),
            "pacdb" => Some(Self::PacDB),
            "autia" | "autiasp" | "autia1716" => Some(Self::AutIA),
            "autib" | "autibsp" | "autib1716" => Some(Self::AutIB),
            "autda" => Some(Self::AutDA),
            "autdb" => Some(Self::AutDB),
            "xpaci" | "xpaclri" => Some(Self::XPacI),
            "xpacd" => Some(Self::XPacD),
            _ => None,
        }
    }

    /// Returns `true` if this is an authentication (AUT) operation.
    #[must_use]
    pub const fn is_authenticate(self) -> bool {
        matches!(self, Self::AutIA | Self::AutIB | Self::AutDA | Self::AutDB)
    }

    /// Returns `true` if this is a signing (PAC) operation.
    #[must_use]
    pub const fn is_sign(self) -> bool {
        matches!(self, Self::PacIA | Self::PacIB | Self::PacDA | Self::PacDB)
    }

    /// Returns `true` if this operates on instruction addresses (A/B suffix).
    #[must_use]
    pub const fn is_instruction_addr(self) -> bool {
        matches!(
            self,
            Self::PacIA | Self::PacIB | Self::AutIA | Self::AutIB | Self::XPacI
        )
    }
}

// ---------------------------------------------------------------------------
// AArch64 SIMD arrangement specifiers
// ---------------------------------------------------------------------------

/// `AArch64` SIMD vector arrangement (e.g., 8B, 16B, 4H, 8H, 2S, 4S, 1D, 2D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum SimdArrangement {
    /// 8 x 8-bit lanes (64-bit vector).
    V8B,
    /// 16 x 8-bit lanes (128-bit vector).
    V16B,
    /// 4 x 16-bit lanes (64-bit vector).
    V4H,
    /// 8 x 16-bit lanes (128-bit vector).
    V8H,
    /// 2 x 32-bit lanes (64-bit vector).
    V2S,
    /// 4 x 32-bit lanes (128-bit vector).
    V4S,
    /// 1 x 64-bit lane (64-bit vector).
    V1D,
    /// 2 x 64-bit lanes (128-bit vector).
    V2D,
    /// 1 x 128-bit lane (polynomial).
    V1Q,
}

impl SimdArrangement {
    /// Width in bits of each element lane.
    #[must_use]
    pub const fn lane_bits(self) -> u8 {
        match self {
            Self::V8B | Self::V16B => 8,
            Self::V4H | Self::V8H => 16,
            Self::V2S | Self::V4S => 32,
            Self::V1D | Self::V2D => 64,
            Self::V1Q => 128,
        }
    }

    /// Number of lanes.
    #[must_use]
    pub const fn lane_count(self) -> u8 {
        match self {
            Self::V8B | Self::V8H => 8,
            Self::V16B => 16,
            Self::V4H | Self::V4S => 4,
            Self::V2S | Self::V2D => 2,
            Self::V1D | Self::V1Q => 1,
        }
    }

    /// Total register width in bits.
    #[must_use]
    pub const fn register_bits(self) -> u16 {
        (self.lane_bits() as u16) * (self.lane_count() as u16)
    }

    /// Assembly suffix string.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::V8B => "8b",
            Self::V16B => "16b",
            Self::V4H => "4h",
            Self::V8H => "8h",
            Self::V2S => "2s",
            Self::V4S => "4s",
            Self::V1D => "1d",
            Self::V2D => "2d",
            Self::V1Q => "1q",
        }
    }

    /// Decode from the `Q` bit and `size` field (Q:size encoding).
    #[must_use]
    pub const fn from_q_size(q: bool, size: u8) -> Option<Self> {
        match (q, size & 0x3) {
            (false, 0) => Some(Self::V8B),
            (true, 0) => Some(Self::V16B),
            (false, 1) => Some(Self::V4H),
            (true, 1) => Some(Self::V8H),
            (false, 2) => Some(Self::V2S),
            (true, 2) => Some(Self::V4S),
            (false, 3) => Some(Self::V1D),
            (true, 3) => Some(Self::V2D),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 FPCR bit fields
// ---------------------------------------------------------------------------

/// An `AArch64` FPCR bit-field descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct FpcrField {
    /// Field name.
    pub name: &'static str,
    /// MSB bit position.
    pub msb: u8,
    /// LSB bit position.
    pub lsb: u8,
    /// Description.
    pub desc: &'static str,
}

impl FpcrField {
    const fn new(name: &'static str, msb: u8, lsb: u8, desc: &'static str) -> Self {
        Self {
            name,
            msb,
            lsb,
            desc,
        }
    }

    /// Extract the field from an FPCR value.
    #[must_use]
    pub const fn extract(self, fpcr: u64) -> u64 {
        let width = self.msb - self.lsb + 1;
        let mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        (fpcr >> self.lsb) & mask
    }
}

/// `AArch64` FPCR field table.
pub static FPCR_FIELDS: &[FpcrField] = &[
    FpcrField::new("AHP", 26, 26, "Alternative Half-Precision"),
    FpcrField::new("DN", 25, 25, "Default NaN mode"),
    FpcrField::new("FZ", 24, 24, "Flush-to-zero mode"),
    FpcrField::new("RMode", 23, 22, "Rounding mode: 00=RN,01=RP,10=RM,11=RZ"),
    FpcrField::new("FZ16", 19, 19, "Flush-to-zero mode for half-precision"),
    FpcrField::new("IDE", 15, 15, "Input denormal exception trap enable"),
    FpcrField::new("IXE", 12, 12, "Inexact exception trap enable"),
    FpcrField::new("UFE", 11, 11, "Underflow exception trap enable"),
    FpcrField::new("OFE", 10, 10, "Overflow exception trap enable"),
    FpcrField::new("DZE", 9, 9, "Division-by-zero exception trap enable"),
    FpcrField::new("IOE", 8, 8, "Invalid operation exception trap enable"),
    FpcrField::new(
        "AHPE",
        1,
        1,
        "Alternative Half-Precision exception trap enable (deprecated)",
    ),
    FpcrField::new("NEP", 2, 2, "Non-EL0 access trap enable (FEAT_AFP)"),
];

// ---------------------------------------------------------------------------
// AArch64 MTE (Memory Tagging Extension) helpers
// ---------------------------------------------------------------------------

/// An MTE instruction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum MteInstr {
    /// IRG: Insert Random Tag.
    Irg,
    /// GMI: Exclude Tag.
    Gmi,
    /// SUBP: Subtract Pointer with Tag.
    Subp,
    /// ADDG: Add with Tag.
    Addg,
    /// SUBG: Subtract with Tag.
    Subg,
    /// LDG: Load Tag.
    Ldg,
    /// STG: Store Tag.
    Stg,
    /// ST2G: Store Two Tags.
    St2g,
    /// STZG: Store Zero with Tag.
    Stzg,
    /// STZ2G: Store Zero Two Tags.
    Stz2g,
    /// LDGM: Load Multiple Tags.
    Ldgm,
    /// STGM: Store Multiple Tags.
    Stgm,
    /// STZGM: Store Zero Multiple Tags.
    Stzgm,
}

impl MteInstr {
    /// Classify from a mnemonic.
    #[must_use]
    pub fn from_mnemonic(m: &str) -> Option<Self> {
        match m.to_ascii_lowercase().as_str() {
            "irg" => Some(Self::Irg),
            "gmi" => Some(Self::Gmi),
            "subp" => Some(Self::Subp),
            "addg" => Some(Self::Addg),
            "subg" => Some(Self::Subg),
            "ldg" => Some(Self::Ldg),
            "stg" => Some(Self::Stg),
            "st2g" => Some(Self::St2g),
            "stzg" => Some(Self::Stzg),
            "stz2g" => Some(Self::Stz2g),
            "ldgm" => Some(Self::Ldgm),
            "stgm" => Some(Self::Stgm),
            "stzgm" => Some(Self::Stzgm),
            _ => None,
        }
    }

    /// Returns `true` if this is a load operation.
    #[must_use]
    pub const fn is_load(self) -> bool {
        matches!(self, Self::Ldg | Self::Ldgm)
    }

    /// Returns `true` if this is a store operation.
    #[must_use]
    pub const fn is_store(self) -> bool {
        !self.is_load()
            && !matches!(
                self,
                Self::Irg | Self::Gmi | Self::Subp | Self::Addg | Self::Subg
            )
    }
}

// ---------------------------------------------------------------------------
// AArch64 SVE register helpers
// ---------------------------------------------------------------------------

/// Format an SVE Z register name.
#[must_use]
pub fn z_reg(n: u8) -> String {
    format!("z{}", n & 0x1f)
}

/// Format an SVE P (predicate) register name.
#[must_use]
pub fn p_reg(n: u8) -> String {
    format!("p{}", n & 0xf)
}

/// Format an SVE FFR (first-faulting register) name.
#[must_use]
pub const fn ffr_reg() -> &'static str {
    "ffr"
}

/// SVE predication qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum SvePredQual {
    /// Merging predication (/m).
    Merging,
    /// Zeroing predication (/z).
    Zeroing,
}

impl SvePredQual {
    /// Assembly suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Merging => "/m",
            Self::Zeroing => "/z",
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 exception level helpers
// ---------------------------------------------------------------------------

/// `AArch64` Exception Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
pub enum ExceptionLevel {
    /// EL0: Unprivileged (application).
    El0 = 0,
    /// EL1: Privileged (OS kernel).
    El1 = 1,
    /// EL2: Hypervisor.
    El2 = 2,
    /// EL3: Secure Monitor.
    El3 = 3,
}

impl ExceptionLevel {
    /// Decode from a 2-bit field.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x3 {
            0 => Self::El0,
            1 => Self::El1,
            2 => Self::El2,
            _ => Self::El3,
        }
    }

    /// String representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::El0 => "EL0",
            Self::El1 => "EL1",
            Self::El2 => "EL2",
            Self::El3 => "EL3",
        }
    }

    /// Returns `true` if this EL is considered privileged.
    #[must_use]
    pub fn is_privileged(self) -> bool {
        self != Self::El0
    }
}

// ---------------------------------------------------------------------------
// AArch64 B-immediate decode helper
// ---------------------------------------------------------------------------

/// Decode the signed 26-bit offset from a B / BL instruction.
/// The offset is shifted left 2 to give the byte offset from the instruction.
#[must_use]
pub fn a64_b_offset(word: u32) -> i64 {
    let imm26 = word & 0x03ff_ffff;
    let signed = if imm26 & 0x0200_0000 != 0 {
        i64::from((imm26 | 0xfc00_0000).cast_signed())
    } else {
        i64::from(imm26)
    };
    signed << 2
}

/// Compute the target address of a B/BL instruction.
#[must_use]
pub fn a64_b_target(pc: u64, word: u32) -> u64 {
    let offset = a64_b_offset(word);
    pc.wrapping_add(offset.cast_unsigned())
}

/// Decode the signed 19-bit offset from a CBZ/CBNZ or B.cond instruction.
#[must_use]
pub fn a64_b19_offset(word: u32) -> i64 {
    let imm19 = (word >> 5) & 0x0007_ffff;
    let signed = if imm19 & 0x0004_0000 != 0 {
        i64::from((imm19 | 0xfff8_0000).cast_signed())
    } else {
        i64::from(imm19)
    };
    signed << 2
}

/// Decode the signed 14-bit offset from a TBZ/TBNZ instruction.
#[must_use]
pub fn a64_b14_offset(word: u32) -> i64 {
    let imm14 = (word >> 5) & 0x0000_3fff;
    let signed = if imm14 & 0x0000_2000 != 0 {
        i64::from((imm14 | 0xffff_c000).cast_signed())
    } else {
        i64::from(imm14)
    };
    signed << 2
}

// ---------------------------------------------------------------------------
// AArch64 ADD/SUB immediate decode
// ---------------------------------------------------------------------------

/// Decode an ADD/SUB immediate (bits[21:10] = imm12, bit22 = shift).
/// Returns `(imm, shift)` where shift is 0 or 12.
#[must_use]
pub const fn a64_add_imm(word: u32) -> (u32, u8) {
    let imm12 = (word >> 10) & 0xfff;
    let shift = if (word >> 22) & 1 != 0 { 12u8 } else { 0u8 };
    (imm12, shift)
}

/// Apply a 12-bit ADD/SUB immediate with optional 12-bit LSL shift.
#[must_use]
pub fn a64_add_imm_value(word: u32) -> u64 {
    let (imm, shift) = a64_add_imm(word);
    (u64::from(imm)) << shift
}

// ---------------------------------------------------------------------------
// AArch64 load/store unsigned offset decode
// ---------------------------------------------------------------------------

/// Decode the scaled unsigned offset of a load/store (unsigned offset variant).
/// `size` is the register size in bytes (1/2/4/8/16).
#[must_use]
pub fn a64_ls_uoff(word: u32, size: u8) -> u32 {
    let imm12 = (word >> 10) & 0xfff;
    imm12 * (u32::from(size))
}

// ---------------------------------------------------------------------------
// AArch64 MOV immediate decode helpers
// ---------------------------------------------------------------------------

/// Decode a MOVZ/MOVN/MOVK 16-bit immediate with shift.
/// Returns `(imm16, shift_amount)`.
#[must_use]
pub const fn a64_mov_imm(word: u32) -> (u16, u8) {
    let imm16 = ((word >> 5) & 0xffff) as u16;
    let hw = ((word >> 21) & 0x3) as u8;
    (imm16, hw * 16)
}

/// Reconstruct the 64-bit constant produced by `MOVZ Xn, #imm16, LSL #shift`.
#[must_use]
pub fn a64_movz_value(word: u32) -> u64 {
    let (imm16, shift) = a64_mov_imm(word);
    (u64::from(imm16)) << shift
}

// ---------------------------------------------------------------------------
// Comprehensive ARM64 tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_extended_tests {
    use super::*;

    // ── System register lookup ────────────────────────────────────────────

    #[test]
    fn test_sysreg_sctlr_el1() {
        let r = arm64_sysreg_lookup("SCTLR_EL1");
        assert!(r.is_some());
        assert_eq!(r.unwrap().op0, 3);
    }

    #[test]
    fn test_sysreg_nzcv() {
        let r = arm64_sysreg_lookup("NZCV");
        assert!(r.is_some());
        assert_eq!(r.unwrap().name, "NZCV");
    }

    #[test]
    fn test_sysreg_case_insensitive() {
        assert!(arm64_sysreg_lookup("sctlr_el1").is_some());
    }

    #[test]
    fn test_sysreg_missing() {
        assert!(arm64_sysreg_lookup("BOGUS_REG").is_none());
    }

    #[test]
    fn test_sysreg_table_count() {
        assert!(ARM64_SYS_REGS.len() >= 20);
    }

    // ── NZCV flags ────────────────────────────────────────────────────────

    #[test]
    fn test_nzcv_n_set() {
        let nzcv = Nzcv::from_u32(0x8000_0000);
        assert!(nzcv.n());
        assert!(!nzcv.z());
        assert!(!nzcv.c());
        assert!(!nzcv.v());
    }

    #[test]
    fn test_nzcv_z_set() {
        let nzcv = Nzcv::from_u32(0x4000_0000);
        assert!(nzcv.z());
        assert!(!nzcv.n());
    }

    #[test]
    fn test_nzcv_roundtrip() {
        let original: u32 = 0xb000_0000; // N=1, Z=0, C=1, V=1 → 0b1011 << 28
        let nzcv = Nzcv::from_u32(original);
        assert_eq!(nzcv.to_u32(), original);
    }

    // ── A64Cond evaluation ────────────────────────────────────────────────

    #[test]
    fn test_cond_eq_evaluates_true_when_z() {
        let nzcv = Nzcv::from_u32(0x4000_0000); // Z=1
        assert!(A64Cond::Eq.evaluate(nzcv));
    }

    #[test]
    fn test_cond_ne_evaluates_false_when_z() {
        let nzcv = Nzcv::from_u32(0x4000_0000); // Z=1
        assert!(!A64Cond::Ne.evaluate(nzcv));
    }

    #[test]
    fn test_cond_al_always_true() {
        assert!(A64Cond::Al.evaluate(Nzcv(0)));
    }

    #[test]
    fn test_cond_ge_n_equals_v() {
        // N=1, V=1 → N==V → GE
        let nzcv = Nzcv::from_u32(0x9000_0000); // N=1, V=1
        assert!(A64Cond::Ge.evaluate(nzcv));
    }

    #[test]
    fn test_cond_from_bits_all() {
        for i in 0u8..16 {
            let cond = A64Cond::from_bits(i);
            let suffix = cond.suffix();
            assert!(!suffix.is_empty());
        }
    }

    // ── AAPCS64 roles ─────────────────────────────────────────────────────

    #[test]
    fn test_aapcs64_role_x0_parameter() {
        assert_eq!(aapcs64_role(0), Aapcs64Role::Parameter);
        assert_eq!(aapcs64_role(7), Aapcs64Role::Parameter);
    }

    #[test]
    fn test_aapcs64_role_x8_indirect() {
        assert_eq!(aapcs64_role(8), Aapcs64Role::IndirectResult);
    }

    #[test]
    fn test_aapcs64_role_x29_fp() {
        assert_eq!(aapcs64_role(29), Aapcs64Role::FramePointer);
    }

    #[test]
    fn test_aapcs64_role_x30_lr() {
        assert_eq!(aapcs64_role(30), Aapcs64Role::LinkRegister);
    }

    #[test]
    fn test_aapcs64_fp_role_argument() {
        assert_eq!(aapcs64_fp_role(0), Aapcs64FpRole::Argument);
        assert_eq!(aapcs64_fp_role(7), Aapcs64FpRole::Argument);
    }

    #[test]
    fn test_aapcs64_fp_role_callee_saved() {
        assert_eq!(aapcs64_fp_role(8), Aapcs64FpRole::CalleeSaved);
        assert_eq!(aapcs64_fp_role(15), Aapcs64FpRole::CalleeSaved);
    }

    // ── A64 encoding group ────────────────────────────────────────────────

    #[test]
    fn test_a64_group_branch_0x14000001() {
        // B #4 — bits[28:25]=0b1010
        let word: u32 = 0x1400_0001;
        assert_eq!(a64_group(word), A64Group::BranchExcSys);
    }

    #[test]
    fn test_a64_group_ldr_f9400000() {
        // LDR X0, [X0] — bits[28:25]=0b1100
        let word: u32 = 0xf940_0000;
        assert_eq!(a64_group(word), A64Group::LoadsStores);
    }

    #[test]
    fn test_a64_group_dp_imm_91000000() {
        // ADD X0,X0,#0 — bits[28:25]=0b1000 or 0b1001
        let word: u32 = 0x9100_0000;
        assert_eq!(a64_group(word), A64Group::DpImm);
    }

    // ── LSE atomic ops ────────────────────────────────────────────────────

    #[test]
    fn test_lse_cas_no_ordering() {
        let op = lse_lookup("cas").unwrap();
        assert!(!op.acquire);
        assert!(!op.release);
    }

    #[test]
    fn test_lse_casal_both() {
        let op = lse_lookup("casal").unwrap();
        assert!(op.acquire);
        assert!(op.release);
    }

    #[test]
    fn test_lse_missing() {
        assert!(lse_lookup("nop").is_none());
    }

    #[test]
    fn test_lse_table_count() {
        assert!(LSE_ATOMIC_OPS.len() >= 20);
    }

    // ── PAC helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_pac_paciasp_classify() {
        let k = PacKind::from_mnemonic("paciasp").unwrap();
        assert_eq!(k, PacKind::PacIA);
        assert!(k.is_sign());
        assert!(k.is_instruction_addr());
    }

    #[test]
    fn test_pac_autia_classify() {
        let k = PacKind::from_mnemonic("autia").unwrap();
        assert!(k.is_authenticate());
        assert!(k.is_instruction_addr());
    }

    #[test]
    fn test_pac_xpacd() {
        let k = PacKind::from_mnemonic("xpacd").unwrap();
        assert_eq!(k, PacKind::XPacD);
        assert!(!k.is_sign());
        assert!(!k.is_authenticate());
    }

    #[test]
    fn test_pac_unknown() {
        assert!(PacKind::from_mnemonic("add").is_none());
    }

    // ── SIMD arrangement ──────────────────────────────────────────────────

    #[test]
    fn test_simd_8b_lanes() {
        let arr = SimdArrangement::V8B;
        assert_eq!(arr.lane_bits(), 8);
        assert_eq!(arr.lane_count(), 8);
        assert_eq!(arr.register_bits(), 64);
        assert_eq!(arr.suffix(), "8b");
    }

    #[test]
    fn test_simd_4s_lanes() {
        let arr = SimdArrangement::V4S;
        assert_eq!(arr.lane_bits(), 32);
        assert_eq!(arr.lane_count(), 4);
        assert_eq!(arr.register_bits(), 128);
    }

    #[test]
    fn test_simd_from_q_size_16b() {
        let arr = SimdArrangement::from_q_size(true, 0).unwrap();
        assert_eq!(arr, SimdArrangement::V16B);
    }

    #[test]
    fn test_simd_from_q_size_2d() {
        let arr = SimdArrangement::from_q_size(true, 3).unwrap();
        assert_eq!(arr, SimdArrangement::V2D);
    }

    // ── Exception level ───────────────────────────────────────────────────

    #[test]
    fn test_el_ordering() {
        assert!(ExceptionLevel::El3 > ExceptionLevel::El0);
    }

    #[test]
    fn test_el_privileged() {
        assert!(!ExceptionLevel::El0.is_privileged());
        assert!(ExceptionLevel::El1.is_privileged());
    }

    #[test]
    fn test_el_from_bits() {
        assert_eq!(ExceptionLevel::from_bits(2), ExceptionLevel::El2);
    }

    // ── Branch offset helpers ─────────────────────────────────────────────

    #[test]
    fn test_a64_b_offset_zero() {
        // B #0 — imm26=0 → offset=0
        assert_eq!(a64_b_offset(0x1400_0000), 0);
    }

    #[test]
    fn test_a64_b_offset_positive() {
        // imm26=1 → offset=4
        assert_eq!(a64_b_offset(0x1400_0001), 4);
    }

    #[test]
    fn test_a64_b_target_basic() {
        // pc=0x1000, B +4 → 0x1004
        assert_eq!(a64_b_target(0x1000, 0x1400_0001), 0x1004);
    }

    #[test]
    fn test_a64_b19_offset_zero() {
        // CBZ X0, #0 — imm19=0 at bits[23:5], so 0 → offset=0
        assert_eq!(a64_b19_offset(0xb400_0000), 0);
    }

    // ── ADD imm helpers ───────────────────────────────────────────────────

    #[test]
    fn test_a64_add_imm_no_shift() {
        // ADD X0,X0,#4 — imm12=4, shift=0
        let word: u32 = 0x9100_1000; // imm12 in bits[21:10], shift bit22=0
        let (imm, shift) = a64_add_imm(word);
        assert_eq!(imm, 4);
        assert_eq!(shift, 0);
    }

    #[test]
    fn test_a64_add_imm_with_shift() {
        // bit22=1 → shift=12
        let word: u32 = 0x9140_1000; // bit22 set
        let (_, shift) = a64_add_imm(word);
        assert_eq!(shift, 12);
    }

    // ── LS unsigned offset ────────────────────────────────────────────────

    #[test]
    fn test_a64_ls_uoff_8byte() {
        // imm12=1, size=8 → offset=8
        let word: u32 = 0xf940_0400; // bits[21:10]=1
        let off = a64_ls_uoff(word, 8);
        assert_eq!(off, 8);
    }

    // ── MOV immediate ─────────────────────────────────────────────────────

    #[test]
    fn test_a64_movz_value_hw0() {
        // MOVZ X0, #5 (hw=0) — imm16=5, shift=0
        let word: u32 = 0xd280_00a0; // imm16=5, hw=0
        let val = a64_movz_value(word);
        assert_eq!(val, 5);
    }

    // ── FPCR fields ───────────────────────────────────────────────────────

    #[test]
    fn test_fpcr_rmode_extract() {
        let f = FPCR_FIELDS.iter().find(|f| f.name == "RMode").unwrap();
        // bits[23:22] = 0b10 = RM
        assert_eq!(f.extract(0x00c0_0000), 0b11); // bits 23:22 both set
    }

    #[test]
    fn test_fpcr_fz_extract() {
        let f = FPCR_FIELDS.iter().find(|f| f.name == "FZ").unwrap();
        assert_eq!(f.extract(0x0100_0000), 1);
    }

    // ── MTE helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_mte_ldg_is_load() {
        let k = MteInstr::from_mnemonic("ldg").unwrap();
        assert!(k.is_load());
        assert!(!k.is_store());
    }

    #[test]
    fn test_mte_stg_is_store() {
        let k = MteInstr::from_mnemonic("stg").unwrap();
        assert!(k.is_store());
        assert!(!k.is_load());
    }

    #[test]
    fn test_mte_unknown() {
        assert!(MteInstr::from_mnemonic("nop").is_none());
    }

    // ── SVE helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_z_reg_formatting() {
        assert_eq!(z_reg(0), "z0");
        assert_eq!(z_reg(31), "z31");
    }

    #[test]
    fn test_p_reg_formatting() {
        assert_eq!(p_reg(0), "p0");
        assert_eq!(p_reg(15), "p15");
    }

    #[test]
    fn test_sve_pred_qual_suffix() {
        assert_eq!(SvePredQual::Merging.suffix(), "/m");
        assert_eq!(SvePredQual::Zeroing.suffix(), "/z");
    }

    // ── Arm64InstrCategory additional tests ──────────────────────────────

    #[test]
    fn test_category_ldxr_atomic() {
        assert_eq!(
            Arm64InstrCategory::classify("ldxr"),
            Arm64InstrCategory::AtomicMemory
        );
    }

    #[test]
    fn test_category_fmul_fp() {
        assert_eq!(
            Arm64InstrCategory::classify("fmul"),
            Arm64InstrCategory::FloatSimd
        );
    }

    #[test]
    fn test_category_csel_dp() {
        assert_eq!(
            Arm64InstrCategory::classify("csel"),
            Arm64InstrCategory::DataProcessing
        );
    }

    #[test]
    fn test_category_hvc_sys() {
        assert_eq!(
            Arm64InstrCategory::classify("hvc"),
            Arm64InstrCategory::System
        );
    }
}

// ---------------------------------------------------------------------------
// AArch64 data-processing opcode table
// ---------------------------------------------------------------------------

/// `AArch64` DP operation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum A64DpClass {
    /// Arithmetic (ADD, SUB, ADC, SBC, etc.).
    Arithmetic,
    /// Logical (AND, ORR, EOR, BIC, etc.).
    Logical,
    /// Move (MOV, MOVZ, MOVN, MOVK).
    Move,
    /// Comparison (CMP, CMN, TST).
    Compare,
    /// Bit field (UBFM, SBFM, BFM, UBFX, etc.).
    BitField,
    /// Shift (LSL, LSR, ASR, ROR).
    Shift,
    /// Conditional (CSEL, CSINC, CSET, etc.).
    Conditional,
    /// Multiply (MUL, MADD, MSUB, UMULH, etc.).
    Multiply,
    /// Divide (SDIV, UDIV).
    Divide,
    /// Count/reverse (CLZ, CLS, RBIT, REV).
    CountReverse,
    /// Sign/zero extend (SXTB, UXTB, etc.).
    Extend,
}

/// A DP instruction descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct DpInstr {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Class.
    pub class: A64DpClass,
    /// Description.
    pub desc: &'static str,
}

impl DpInstr {
    const fn new(mnemonic: &'static str, class: A64DpClass, desc: &'static str) -> Self {
        Self {
            mnemonic,
            class,
            desc,
        }
    }
}

/// `AArch64` data-processing instruction reference table.
pub static DP_INSTRS: &[DpInstr] = &[
    // Arithmetic
    DpInstr::new("add", A64DpClass::Arithmetic, "Add"),
    DpInstr::new("adds", A64DpClass::Arithmetic, "Add, set flags"),
    DpInstr::new("sub", A64DpClass::Arithmetic, "Subtract"),
    DpInstr::new("subs", A64DpClass::Arithmetic, "Subtract, set flags"),
    DpInstr::new("adc", A64DpClass::Arithmetic, "Add with carry"),
    DpInstr::new("adcs", A64DpClass::Arithmetic, "Add with carry, set flags"),
    DpInstr::new("sbc", A64DpClass::Arithmetic, "Subtract with carry"),
    DpInstr::new(
        "sbcs",
        A64DpClass::Arithmetic,
        "Subtract with carry, set flags",
    ),
    DpInstr::new("neg", A64DpClass::Arithmetic, "Negate (SUB Xd,XZR,Xm)"),
    DpInstr::new("negs", A64DpClass::Arithmetic, "Negate, set flags"),
    DpInstr::new("ngc", A64DpClass::Arithmetic, "Negate with carry"),
    DpInstr::new(
        "ngcs",
        A64DpClass::Arithmetic,
        "Negate with carry, set flags",
    ),
    // Logical
    DpInstr::new("and", A64DpClass::Logical, "Bitwise AND"),
    DpInstr::new("ands", A64DpClass::Logical, "Bitwise AND, set flags"),
    DpInstr::new("orr", A64DpClass::Logical, "Bitwise OR"),
    DpInstr::new("orn", A64DpClass::Logical, "Bitwise OR NOT"),
    DpInstr::new("eor", A64DpClass::Logical, "Bitwise XOR"),
    DpInstr::new("eon", A64DpClass::Logical, "Bitwise XOR NOT"),
    DpInstr::new("bic", A64DpClass::Logical, "Bit clear"),
    DpInstr::new("bics", A64DpClass::Logical, "Bit clear, set flags"),
    // Move
    DpInstr::new("mov", A64DpClass::Move, "Move register"),
    DpInstr::new("movz", A64DpClass::Move, "Move wide with zero"),
    DpInstr::new("movn", A64DpClass::Move, "Move wide with NOT"),
    DpInstr::new("movk", A64DpClass::Move, "Move wide with keep"),
    DpInstr::new("mvn", A64DpClass::Move, "Bitwise NOT (ORN Xd,XZR,Xm)"),
    // Compare
    DpInstr::new("cmp", A64DpClass::Compare, "Compare (SUBS XZR,Xn,Xm)"),
    DpInstr::new(
        "cmn",
        A64DpClass::Compare,
        "Compare negative (ADDS XZR,Xn,Xm)",
    ),
    DpInstr::new("tst", A64DpClass::Compare, "Test bits (ANDS XZR,Xn,Xm)"),
    DpInstr::new("ccmp", A64DpClass::Compare, "Conditional compare"),
    DpInstr::new("ccmn", A64DpClass::Compare, "Conditional compare negative"),
    // Bit field
    DpInstr::new("ubfm", A64DpClass::BitField, "Unsigned bit field move"),
    DpInstr::new("sbfm", A64DpClass::BitField, "Signed bit field move"),
    DpInstr::new("bfm", A64DpClass::BitField, "Bit field move"),
    DpInstr::new("ubfx", A64DpClass::BitField, "Unsigned bit field extract"),
    DpInstr::new("sbfx", A64DpClass::BitField, "Signed bit field extract"),
    DpInstr::new(
        "ubfiz",
        A64DpClass::BitField,
        "Unsigned bit field insert in zero",
    ),
    DpInstr::new(
        "sbfiz",
        A64DpClass::BitField,
        "Signed bit field insert in zero",
    ),
    DpInstr::new("bfi", A64DpClass::BitField, "Bit field insert"),
    DpInstr::new(
        "bfxil",
        A64DpClass::BitField,
        "Bit field extract and insert low",
    ),
    DpInstr::new("extr", A64DpClass::BitField, "Extract register"),
    // Shift
    DpInstr::new("lsl", A64DpClass::Shift, "Logical shift left"),
    DpInstr::new("lsr", A64DpClass::Shift, "Logical shift right"),
    DpInstr::new("asr", A64DpClass::Shift, "Arithmetic shift right"),
    DpInstr::new("ror", A64DpClass::Shift, "Rotate right"),
    // Conditional
    DpInstr::new("csel", A64DpClass::Conditional, "Conditional select"),
    DpInstr::new(
        "csinc",
        A64DpClass::Conditional,
        "Conditional select increment",
    ),
    DpInstr::new(
        "csinv",
        A64DpClass::Conditional,
        "Conditional select invert",
    ),
    DpInstr::new(
        "csneg",
        A64DpClass::Conditional,
        "Conditional select negate",
    ),
    DpInstr::new("cset", A64DpClass::Conditional, "Conditional set"),
    DpInstr::new("csetm", A64DpClass::Conditional, "Conditional set mask"),
    DpInstr::new("cinc", A64DpClass::Conditional, "Conditional increment"),
    DpInstr::new("cinv", A64DpClass::Conditional, "Conditional invert"),
    DpInstr::new("cneg", A64DpClass::Conditional, "Conditional negate"),
    // Multiply
    DpInstr::new("mul", A64DpClass::Multiply, "Multiply (MADD Xd,Xn,Xm,XZR)"),
    DpInstr::new("madd", A64DpClass::Multiply, "Multiply-add"),
    DpInstr::new("msub", A64DpClass::Multiply, "Multiply-subtract"),
    DpInstr::new(
        "mneg",
        A64DpClass::Multiply,
        "Multiply negate (MSUB Xd,Xn,Xm,XZR)",
    ),
    DpInstr::new("smulh", A64DpClass::Multiply, "Signed multiply high"),
    DpInstr::new("umulh", A64DpClass::Multiply, "Unsigned multiply high"),
    DpInstr::new("smaddl", A64DpClass::Multiply, "Signed multiply-add long"),
    DpInstr::new(
        "smsubl",
        A64DpClass::Multiply,
        "Signed multiply-subtract long",
    ),
    DpInstr::new("umaddl", A64DpClass::Multiply, "Unsigned multiply-add long"),
    DpInstr::new(
        "umsubl",
        A64DpClass::Multiply,
        "Unsigned multiply-subtract long",
    ),
    DpInstr::new(
        "smull",
        A64DpClass::Multiply,
        "Signed multiply long (SMADDL Xd,Wn,Wm,XZR)",
    ),
    DpInstr::new("umull", A64DpClass::Multiply, "Unsigned multiply long"),
    DpInstr::new(
        "smnegl",
        A64DpClass::Multiply,
        "Signed multiply negate long",
    ),
    DpInstr::new(
        "umnegl",
        A64DpClass::Multiply,
        "Unsigned multiply negate long",
    ),
    // Divide
    DpInstr::new("sdiv", A64DpClass::Divide, "Signed divide"),
    DpInstr::new("udiv", A64DpClass::Divide, "Unsigned divide"),
    // Count/reverse
    DpInstr::new("clz", A64DpClass::CountReverse, "Count leading zeros"),
    DpInstr::new("cls", A64DpClass::CountReverse, "Count leading sign bits"),
    DpInstr::new("rbit", A64DpClass::CountReverse, "Reverse bits"),
    DpInstr::new("rev", A64DpClass::CountReverse, "Reverse bytes"),
    DpInstr::new(
        "rev16",
        A64DpClass::CountReverse,
        "Reverse bytes in 16-bit halfwords",
    ),
    DpInstr::new(
        "rev32",
        A64DpClass::CountReverse,
        "Reverse bytes in 32-bit words",
    ),
    // Extend
    DpInstr::new("sxtb", A64DpClass::Extend, "Sign extend byte"),
    DpInstr::new("sxth", A64DpClass::Extend, "Sign extend halfword"),
    DpInstr::new("sxtw", A64DpClass::Extend, "Sign extend word"),
    DpInstr::new("uxtb", A64DpClass::Extend, "Zero extend byte"),
    DpInstr::new("uxth", A64DpClass::Extend, "Zero extend halfword"),
    DpInstr::new(
        "uxtw",
        A64DpClass::Extend,
        "Zero extend word (alias for AND Xd,Xn,#0xffff_ffff)",
    ),
];

/// Look up a DP instruction by mnemonic.
#[must_use]
pub fn dp_lookup(mnemonic: &str) -> Option<&'static DpInstr> {
    DP_INSTRS.iter().find(|i| i.mnemonic == mnemonic)
}

// ---------------------------------------------------------------------------
// AArch64 load/store instruction table
// ---------------------------------------------------------------------------

/// An `AArch64` load/store instruction descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct LsInstr {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Data size in bytes (0 = variable).
    pub data_size: u8,
    /// Packed boolean flags: bit 0 = `is_load`, bit 1 = `sign_extend`,
    /// bit 2 = `is_pair`, bit 3 = `is_exclusive`.
    flags: u8,
    /// Brief description.
    pub desc: &'static str,
}

impl LsInstr {
    const FLAG_LOAD: u8      = 1 << 0;
    const FLAG_SIGN_EXT: u8  = 1 << 1;
    const FLAG_PAIR: u8      = 1 << 2;
    const FLAG_EXCLUSIVE: u8 = 1 << 3;

    const fn new(mnemonic: &'static str, data_size: u8, flags: u8, desc: &'static str) -> Self {
        Self { mnemonic, data_size, flags, desc }
    }

    /// Load (`true`) or store (`false`).
    #[must_use]
    pub const fn is_load(self) -> bool { self.flags & Self::FLAG_LOAD != 0 }
    /// Sign-extends on load.
    #[must_use]
    pub const fn sign_extend(self) -> bool { self.flags & Self::FLAG_SIGN_EXT != 0 }
    /// Pair instruction.
    #[must_use]
    pub const fn is_pair(self) -> bool { self.flags & Self::FLAG_PAIR != 0 }
    /// Exclusive / atomic.
    #[must_use]
    pub const fn is_exclusive(self) -> bool { self.flags & Self::FLAG_EXCLUSIVE != 0 }
}

/// `AArch64` load/store instruction reference table.
pub static LS_INSTRS: &[LsInstr] = &[
    LsInstr::new(
        "ldr",
        8,
        0x01,
        "Load register (64-bit)",
    ),
    LsInstr::new("ldrb", 1, 0x01, "Load register byte"),
    LsInstr::new(
        "ldrh",
        2,
        0x01,
        "Load register halfword",
    ),
    LsInstr::new(
        "ldrsb",
        1,
        0x03,
        "Load register signed byte",
    ),
    LsInstr::new(
        "ldrsh",
        2,
        0x03,
        "Load register signed halfword",
    ),
    LsInstr::new(
        "ldrsw",
        4,
        0x03,
        "Load register signed word",
    ),
    LsInstr::new("ldp", 8, 0x05, "Load pair of registers"),
    LsInstr::new(
        "ldpsw",
        4,
        0x07,
        "Load pair of signed words",
    ),
    LsInstr::new(
        "ldnp",
        8,
        0x05,
        "Load pair (non-temporal hint)",
    ),
    LsInstr::new(
        "ldar",
        8,
        0x01,
        "Load-acquire register",
    ),
    LsInstr::new(
        "ldarb",
        1,
        0x01,
        "Load-acquire register byte",
    ),
    LsInstr::new(
        "ldarh",
        2,
        0x01,
        "Load-acquire register halfword",
    ),
    LsInstr::new(
        "ldapr",
        8,
        0x01,
        "Load-acquire RCpc register",
    ),
    LsInstr::new(
        "ldxr",
        8,
        0x09,
        "Load exclusive register",
    ),
    LsInstr::new(
        "ldxrb",
        1,
        0x09,
        "Load exclusive register byte",
    ),
    LsInstr::new(
        "ldxrh",
        2,
        0x09,
        "Load exclusive register halfword",
    ),
    LsInstr::new("ldxp", 8, 0x0D, "Load exclusive pair"),
    LsInstr::new(
        "ldaxr",
        8,
        0x09,
        "Load-acquire exclusive register",
    ),
    LsInstr::new(
        "ldaxrb",
        1,
        0x09,
        "Load-acquire exclusive register byte",
    ),
    LsInstr::new(
        "ldaxrh",
        2,
        0x09,
        "Load-acquire exclusive register halfword",
    ),
    LsInstr::new(
        "ldaxp",
        8,
        0x0D,
        "Load-acquire exclusive pair",
    ),
    LsInstr::new(
        "str",
        8,
        0x00,
        "Store register (64-bit)",
    ),
    LsInstr::new("strb", 1, 0x00, "Store register byte"),
    LsInstr::new(
        "strh",
        2,
        0x00,
        "Store register halfword",
    ),
    LsInstr::new(
        "stp",
        8,
        0x04,
        "Store pair of registers",
    ),
    LsInstr::new(
        "stnp",
        8,
        0x04,
        "Store pair (non-temporal hint)",
    ),
    LsInstr::new(
        "stlr",
        8,
        0x00,
        "Store-release register",
    ),
    LsInstr::new(
        "stlrb",
        1,
        0x00,
        "Store-release register byte",
    ),
    LsInstr::new(
        "stlrh",
        2,
        0x00,
        "Store-release register halfword",
    ),
    LsInstr::new(
        "stxr",
        8,
        0x08,
        "Store exclusive register",
    ),
    LsInstr::new(
        "stxrb",
        1,
        0x08,
        "Store exclusive register byte",
    ),
    LsInstr::new(
        "stxrh",
        2,
        0x08,
        "Store exclusive register halfword",
    ),
    LsInstr::new("stxp", 8, 0x0C, "Store exclusive pair"),
    LsInstr::new(
        "stlxr",
        8,
        0x08,
        "Store-release exclusive register",
    ),
    LsInstr::new(
        "stlxrb",
        1,
        0x08,
        "Store-release exclusive register byte",
    ),
    LsInstr::new(
        "stlxrh",
        2,
        0x08,
        "Store-release exclusive register halfword",
    ),
    LsInstr::new(
        "stlxp",
        8,
        0x0C,
        "Store-release exclusive pair",
    ),
    LsInstr::new("prfm", 0, 0x00, "Prefetch memory"),
    LsInstr::new(
        "prfum",
        0,
        0x00,
        "Prefetch memory (unscaled offset)",
    ),
];

/// Look up a load/store instruction by mnemonic.
#[must_use]
pub fn ls_lookup(mnemonic: &str) -> Option<&'static LsInstr> {
    LS_INSTRS.iter().find(|i| i.mnemonic == mnemonic)
}

// ---------------------------------------------------------------------------
// AArch64 SIMD/FP instruction table
// ---------------------------------------------------------------------------

/// `AArch64` SIMD/FP instruction class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum SimdFpClass {
    /// Floating-point arithmetic (FADD, FSUB, etc.).
    FpArithmetic,
    /// Floating-point compare (FCMP, FCCMP).
    FpCompare,
    /// Floating-point convert (FCVT, SCVTF, UCVTF).
    FpConvert,
    /// Floating-point move (FMOV, FMOV immediate).
    FpMove,
    /// Integer SIMD arithmetic.
    SimdInteger,
    /// SIMD compare.
    SimdCompare,
    /// SIMD load/store.
    SimdLoadStore,
    /// SIMD permute (ZIP, UZP, TRN, EXT, REV).
    SimdPermute,
    /// SIMD shift.
    SimdShift,
    /// SIMD table lookup (TBL, TBX).
    SimdTable,
    /// SIMD crypto (AES, SHA).
    SimdCrypto,
    /// SIMD reduce across lanes (ADDV, etc.).
    SimdReduce,
}

/// A SIMD/FP instruction descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct SimdFpInstr {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Class.
    pub class: SimdFpClass,
    /// Description.
    pub desc: &'static str,
}

impl SimdFpInstr {
    const fn new(mnemonic: &'static str, class: SimdFpClass, desc: &'static str) -> Self {
        Self {
            mnemonic,
            class,
            desc,
        }
    }
}

/// `AArch64` SIMD/FP instruction reference table.
pub static SIMD_FP_INSTRS: &[SimdFpInstr] = &[
    // FP arithmetic
    SimdFpInstr::new("fadd", SimdFpClass::FpArithmetic, "Floating-point add"),
    SimdFpInstr::new("fsub", SimdFpClass::FpArithmetic, "Floating-point subtract"),
    SimdFpInstr::new("fmul", SimdFpClass::FpArithmetic, "Floating-point multiply"),
    SimdFpInstr::new("fdiv", SimdFpClass::FpArithmetic, "Floating-point divide"),
    SimdFpInstr::new(
        "fabs",
        SimdFpClass::FpArithmetic,
        "Floating-point absolute value",
    ),
    SimdFpInstr::new("fneg", SimdFpClass::FpArithmetic, "Floating-point negate"),
    SimdFpInstr::new(
        "fsqrt",
        SimdFpClass::FpArithmetic,
        "Floating-point square root",
    ),
    SimdFpInstr::new("fmax", SimdFpClass::FpArithmetic, "Floating-point maximum"),
    SimdFpInstr::new("fmin", SimdFpClass::FpArithmetic, "Floating-point minimum"),
    SimdFpInstr::new(
        "fmaxnm",
        SimdFpClass::FpArithmetic,
        "Floating-point maximum number",
    ),
    SimdFpInstr::new(
        "fminnm",
        SimdFpClass::FpArithmetic,
        "Floating-point minimum number",
    ),
    SimdFpInstr::new(
        "fmadd",
        SimdFpClass::FpArithmetic,
        "Floating-point fused multiply-add",
    ),
    SimdFpInstr::new(
        "fmsub",
        SimdFpClass::FpArithmetic,
        "Floating-point fused multiply-subtract",
    ),
    SimdFpInstr::new(
        "fnmadd",
        SimdFpClass::FpArithmetic,
        "Floating-point fused negate multiply-add",
    ),
    SimdFpInstr::new(
        "fnmsub",
        SimdFpClass::FpArithmetic,
        "Floating-point fused negate multiply-subtract",
    ),
    SimdFpInstr::new(
        "fnmul",
        SimdFpClass::FpArithmetic,
        "Floating-point negate multiply",
    ),
    SimdFpInstr::new(
        "frintn",
        SimdFpClass::FpArithmetic,
        "FP round to integer, nearest",
    ),
    SimdFpInstr::new(
        "frintp",
        SimdFpClass::FpArithmetic,
        "FP round to integer, towards +infinity",
    ),
    SimdFpInstr::new(
        "frintm",
        SimdFpClass::FpArithmetic,
        "FP round to integer, towards -infinity",
    ),
    SimdFpInstr::new(
        "frintz",
        SimdFpClass::FpArithmetic,
        "FP round to integer, towards zero",
    ),
    SimdFpInstr::new(
        "frinta",
        SimdFpClass::FpArithmetic,
        "FP round to integer, away from zero",
    ),
    SimdFpInstr::new(
        "frintx",
        SimdFpClass::FpArithmetic,
        "FP round to integer (exact)",
    ),
    SimdFpInstr::new(
        "frinti",
        SimdFpClass::FpArithmetic,
        "FP round to integer (current rounding mode)",
    ),
    // FP compare
    SimdFpInstr::new("fcmp", SimdFpClass::FpCompare, "Floating-point compare"),
    SimdFpInstr::new(
        "fcmpe",
        SimdFpClass::FpCompare,
        "Floating-point compare with exception",
    ),
    SimdFpInstr::new(
        "fccmp",
        SimdFpClass::FpCompare,
        "Floating-point conditional compare",
    ),
    SimdFpInstr::new(
        "fccmpe",
        SimdFpClass::FpCompare,
        "Floating-point conditional compare (exc.)",
    ),
    SimdFpInstr::new(
        "facge",
        SimdFpClass::FpCompare,
        "FP absolute compare greater-equal",
    ),
    SimdFpInstr::new(
        "facgt",
        SimdFpClass::FpCompare,
        "FP absolute compare greater-than",
    ),
    // FP convert
    SimdFpInstr::new(
        "fcvt",
        SimdFpClass::FpConvert,
        "Floating-point convert precision",
    ),
    SimdFpInstr::new(
        "fcvtas",
        SimdFpClass::FpConvert,
        "FP convert to integer, round to nearest (ties to away), signed",
    ),
    SimdFpInstr::new(
        "fcvtau",
        SimdFpClass::FpConvert,
        "FP convert to integer, round to nearest (ties to away), unsigned",
    ),
    SimdFpInstr::new(
        "fcvtms",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards -inf, signed",
    ),
    SimdFpInstr::new(
        "fcvtmu",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards -inf, unsigned",
    ),
    SimdFpInstr::new(
        "fcvtns",
        SimdFpClass::FpConvert,
        "FP convert to integer, round to nearest, signed",
    ),
    SimdFpInstr::new(
        "fcvtnu",
        SimdFpClass::FpConvert,
        "FP convert to integer, round to nearest, unsigned",
    ),
    SimdFpInstr::new(
        "fcvtps",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards +inf, signed",
    ),
    SimdFpInstr::new(
        "fcvtpu",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards +inf, unsigned",
    ),
    SimdFpInstr::new(
        "fcvtzs",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards zero, signed",
    ),
    SimdFpInstr::new(
        "fcvtzu",
        SimdFpClass::FpConvert,
        "FP convert to integer, round towards zero, unsigned",
    ),
    SimdFpInstr::new(
        "scvtf",
        SimdFpClass::FpConvert,
        "Convert signed integer to FP",
    ),
    SimdFpInstr::new(
        "ucvtf",
        SimdFpClass::FpConvert,
        "Convert unsigned integer to FP",
    ),
    // FP move
    SimdFpInstr::new("fmov", SimdFpClass::FpMove, "Floating-point move"),
    // SIMD integer
    SimdFpInstr::new("add", SimdFpClass::SimdInteger, "SIMD Add"),
    SimdFpInstr::new("sub", SimdFpClass::SimdInteger, "SIMD Subtract"),
    SimdFpInstr::new("mul", SimdFpClass::SimdInteger, "SIMD Multiply"),
    SimdFpInstr::new("mla", SimdFpClass::SimdInteger, "SIMD Multiply-accumulate"),
    SimdFpInstr::new("mls", SimdFpClass::SimdInteger, "SIMD Multiply-subtract"),
    SimdFpInstr::new("sqadd", SimdFpClass::SimdInteger, "SIMD Saturating add"),
    SimdFpInstr::new(
        "uqadd",
        SimdFpClass::SimdInteger,
        "SIMD Unsigned saturating add",
    ),
    SimdFpInstr::new(
        "sqsub",
        SimdFpClass::SimdInteger,
        "SIMD Saturating subtract",
    ),
    SimdFpInstr::new(
        "uqsub",
        SimdFpClass::SimdInteger,
        "SIMD Unsigned saturating subtract",
    ),
    SimdFpInstr::new("abs", SimdFpClass::SimdInteger, "SIMD Absolute value"),
    SimdFpInstr::new("neg", SimdFpClass::SimdInteger, "SIMD Negate"),
    SimdFpInstr::new("smax", SimdFpClass::SimdInteger, "SIMD Signed maximum"),
    SimdFpInstr::new("smin", SimdFpClass::SimdInteger, "SIMD Signed minimum"),
    SimdFpInstr::new("umax", SimdFpClass::SimdInteger, "SIMD Unsigned maximum"),
    SimdFpInstr::new("umin", SimdFpClass::SimdInteger, "SIMD Unsigned minimum"),
    SimdFpInstr::new("addp", SimdFpClass::SimdInteger, "SIMD Add pairwise"),
    SimdFpInstr::new(
        "smaxp",
        SimdFpClass::SimdInteger,
        "SIMD Signed maximum pairwise",
    ),
    SimdFpInstr::new(
        "sminp",
        SimdFpClass::SimdInteger,
        "SIMD Signed minimum pairwise",
    ),
    SimdFpInstr::new(
        "umaxp",
        SimdFpClass::SimdInteger,
        "SIMD Unsigned maximum pairwise",
    ),
    SimdFpInstr::new(
        "uminp",
        SimdFpClass::SimdInteger,
        "SIMD Unsigned minimum pairwise",
    ),
    // SIMD compare
    SimdFpInstr::new("cmeq", SimdFpClass::SimdCompare, "SIMD Compare equal"),
    SimdFpInstr::new(
        "cmgt",
        SimdFpClass::SimdCompare,
        "SIMD Compare greater-than (signed)",
    ),
    SimdFpInstr::new(
        "cmge",
        SimdFpClass::SimdCompare,
        "SIMD Compare greater-equal (signed)",
    ),
    SimdFpInstr::new(
        "cmlt",
        SimdFpClass::SimdCompare,
        "SIMD Compare less-than (signed, zero)",
    ),
    SimdFpInstr::new(
        "cmle",
        SimdFpClass::SimdCompare,
        "SIMD Compare less-equal (signed, zero)",
    ),
    SimdFpInstr::new(
        "cmhi",
        SimdFpClass::SimdCompare,
        "SIMD Compare higher (unsigned)",
    ),
    SimdFpInstr::new(
        "cmhs",
        SimdFpClass::SimdCompare,
        "SIMD Compare higher-same (unsigned)",
    ),
    SimdFpInstr::new("cmtst", SimdFpClass::SimdCompare, "SIMD Compare test bits"),
    // SIMD permute
    SimdFpInstr::new(
        "zip1",
        SimdFpClass::SimdPermute,
        "SIMD Zip interleave part 1",
    ),
    SimdFpInstr::new(
        "zip2",
        SimdFpClass::SimdPermute,
        "SIMD Zip interleave part 2",
    ),
    SimdFpInstr::new("uzp1", SimdFpClass::SimdPermute, "SIMD Unzip part 1"),
    SimdFpInstr::new("uzp2", SimdFpClass::SimdPermute, "SIMD Unzip part 2"),
    SimdFpInstr::new("trn1", SimdFpClass::SimdPermute, "SIMD Transpose part 1"),
    SimdFpInstr::new("trn2", SimdFpClass::SimdPermute, "SIMD Transpose part 2"),
    SimdFpInstr::new("ext", SimdFpClass::SimdPermute, "SIMD Extract vector"),
    SimdFpInstr::new(
        "rev16",
        SimdFpClass::SimdPermute,
        "SIMD Reverse 16-bit halfwords",
    ),
    SimdFpInstr::new(
        "rev32",
        SimdFpClass::SimdPermute,
        "SIMD Reverse 32-bit words",
    ),
    SimdFpInstr::new(
        "rev64",
        SimdFpClass::SimdPermute,
        "SIMD Reverse 64-bit doublewords",
    ),
    SimdFpInstr::new("dup", SimdFpClass::SimdPermute, "SIMD Duplicate element"),
    SimdFpInstr::new("ins", SimdFpClass::SimdPermute, "SIMD Insert element"),
    SimdFpInstr::new(
        "umov",
        SimdFpClass::SimdPermute,
        "SIMD Unsigned move element to GPR",
    ),
    SimdFpInstr::new(
        "smov",
        SimdFpClass::SimdPermute,
        "SIMD Signed move element to GPR",
    ),
    // SIMD shift
    SimdFpInstr::new("sshr", SimdFpClass::SimdShift, "SIMD Signed shift right"),
    SimdFpInstr::new("ushr", SimdFpClass::SimdShift, "SIMD Unsigned shift right"),
    SimdFpInstr::new(
        "ssra",
        SimdFpClass::SimdShift,
        "SIMD Signed shift right and accumulate",
    ),
    SimdFpInstr::new(
        "usra",
        SimdFpClass::SimdShift,
        "SIMD Unsigned shift right and accumulate",
    ),
    SimdFpInstr::new(
        "srshr",
        SimdFpClass::SimdShift,
        "SIMD Signed rounding shift right",
    ),
    SimdFpInstr::new(
        "urshr",
        SimdFpClass::SimdShift,
        "SIMD Unsigned rounding shift right",
    ),
    SimdFpInstr::new("shl", SimdFpClass::SimdShift, "SIMD Shift left"),
    SimdFpInstr::new(
        "sqshl",
        SimdFpClass::SimdShift,
        "SIMD Signed saturating shift left",
    ),
    SimdFpInstr::new(
        "uqshl",
        SimdFpClass::SimdShift,
        "SIMD Unsigned saturating shift left",
    ),
    SimdFpInstr::new("shrn", SimdFpClass::SimdShift, "SIMD Shift right narrow"),
    SimdFpInstr::new(
        "rshrn",
        SimdFpClass::SimdShift,
        "SIMD Rounding shift right narrow",
    ),
    SimdFpInstr::new(
        "sshll",
        SimdFpClass::SimdShift,
        "SIMD Signed shift left long",
    ),
    SimdFpInstr::new(
        "ushll",
        SimdFpClass::SimdShift,
        "SIMD Unsigned shift left long",
    ),
    SimdFpInstr::new("sri", SimdFpClass::SimdShift, "SIMD Shift right and insert"),
    SimdFpInstr::new("sli", SimdFpClass::SimdShift, "SIMD Shift left and insert"),
    // SIMD table
    SimdFpInstr::new("tbl", SimdFpClass::SimdTable, "SIMD Table vector lookup"),
    SimdFpInstr::new(
        "tbx",
        SimdFpClass::SimdTable,
        "SIMD Table vector lookup extension",
    ),
    // SIMD crypto
    SimdFpInstr::new(
        "aese",
        SimdFpClass::SimdCrypto,
        "AES single round encryption",
    ),
    SimdFpInstr::new(
        "aesd",
        SimdFpClass::SimdCrypto,
        "AES single round decryption",
    ),
    SimdFpInstr::new("aesmc", SimdFpClass::SimdCrypto, "AES mix columns"),
    SimdFpInstr::new("aesimc", SimdFpClass::SimdCrypto, "AES inverse mix columns"),
    SimdFpInstr::new(
        "sha1c",
        SimdFpClass::SimdCrypto,
        "SHA-1 hash update (choose)",
    ),
    SimdFpInstr::new(
        "sha1p",
        SimdFpClass::SimdCrypto,
        "SHA-1 hash update (parity)",
    ),
    SimdFpInstr::new(
        "sha1m",
        SimdFpClass::SimdCrypto,
        "SHA-1 hash update (majority)",
    ),
    SimdFpInstr::new("sha1h", SimdFpClass::SimdCrypto, "SHA-1 fixed rotate"),
    SimdFpInstr::new(
        "sha1su0",
        SimdFpClass::SimdCrypto,
        "SHA-1 schedule update 0",
    ),
    SimdFpInstr::new(
        "sha1su1",
        SimdFpClass::SimdCrypto,
        "SHA-1 schedule update 1",
    ),
    SimdFpInstr::new(
        "sha256h",
        SimdFpClass::SimdCrypto,
        "SHA-256 hash update part 1",
    ),
    SimdFpInstr::new(
        "sha256h2",
        SimdFpClass::SimdCrypto,
        "SHA-256 hash update part 2",
    ),
    SimdFpInstr::new(
        "sha256su0",
        SimdFpClass::SimdCrypto,
        "SHA-256 schedule update 0",
    ),
    SimdFpInstr::new(
        "sha256su1",
        SimdFpClass::SimdCrypto,
        "SHA-256 schedule update 1",
    ),
    // SIMD reduce
    SimdFpInstr::new("addv", SimdFpClass::SimdReduce, "SIMD Add across vector"),
    SimdFpInstr::new(
        "smaxv",
        SimdFpClass::SimdReduce,
        "SIMD Signed maximum across vector",
    ),
    SimdFpInstr::new(
        "sminv",
        SimdFpClass::SimdReduce,
        "SIMD Signed minimum across vector",
    ),
    SimdFpInstr::new(
        "umaxv",
        SimdFpClass::SimdReduce,
        "SIMD Unsigned maximum across vector",
    ),
    SimdFpInstr::new(
        "uminv",
        SimdFpClass::SimdReduce,
        "SIMD Unsigned minimum across vector",
    ),
    SimdFpInstr::new(
        "addlv",
        SimdFpClass::SimdReduce,
        "SIMD Unsigned add long across vector",
    ),
];

/// Look up a SIMD/FP instruction by mnemonic.
#[must_use]
pub fn simd_fp_lookup(mnemonic: &str) -> Option<&'static SimdFpInstr> {
    SIMD_FP_INSTRS.iter().find(|i| i.mnemonic == mnemonic)
}

// ---------------------------------------------------------------------------
// AArch64 exception vector table
// ---------------------------------------------------------------------------

/// An `AArch64` exception vector descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct A64ExcVector {
    /// Offset from VBAR.
    pub offset: u32,
    /// Vector name.
    pub name: &'static str,
    /// Exception type.
    pub exc_type: &'static str,
    /// Source state.
    pub source: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl A64ExcVector {
    const fn new(
        offset: u32,
        name: &'static str,
        exc_type: &'static str,
        source: &'static str,
        desc: &'static str,
    ) -> Self {
        Self {
            offset,
            name,
            exc_type,
            source,
            desc,
        }
    }
}

/// `AArch64` exception vectors.
pub static A64_EXC_VECTORS: &[A64ExcVector] = &[
    // Current EL with SP0
    A64ExcVector::new(
        0x000,
        "Sync/SP0",
        "Synchronous",
        "current EL, SP0",
        "Synchronous exception, using SP_EL0",
    ),
    A64ExcVector::new(
        0x080,
        "IRQ/SP0",
        "IRQ",
        "current EL, SP0",
        "IRQ, using SP_EL0",
    ),
    A64ExcVector::new(
        0x100,
        "FIQ/SP0",
        "FIQ",
        "current EL, SP0",
        "FIQ, using SP_EL0",
    ),
    A64ExcVector::new(
        0x180,
        "SError/SP0",
        "SError",
        "current EL, SP0",
        "System error, using SP_EL0",
    ),
    // Current EL with SPx
    A64ExcVector::new(
        0x200,
        "Sync/SPx",
        "Synchronous",
        "current EL, SPx",
        "Synchronous exception, using SP_ELx",
    ),
    A64ExcVector::new(
        0x280,
        "IRQ/SPx",
        "IRQ",
        "current EL, SPx",
        "IRQ, using SP_ELx",
    ),
    A64ExcVector::new(
        0x300,
        "FIQ/SPx",
        "FIQ",
        "current EL, SPx",
        "FIQ, using SP_ELx",
    ),
    A64ExcVector::new(
        0x380,
        "SError/SPx",
        "SError",
        "current EL, SPx",
        "System error, using SP_ELx",
    ),
    // Lower EL using AArch64
    A64ExcVector::new(
        0x400,
        "Sync/A64",
        "Synchronous",
        "lower EL, AArch64",
        "Synchronous from lower EL, AArch64",
    ),
    A64ExcVector::new(
        0x480,
        "IRQ/A64",
        "IRQ",
        "lower EL, AArch64",
        "IRQ from lower EL, AArch64",
    ),
    A64ExcVector::new(
        0x500,
        "FIQ/A64",
        "FIQ",
        "lower EL, AArch64",
        "FIQ from lower EL, AArch64",
    ),
    A64ExcVector::new(
        0x580,
        "SError/A64",
        "SError",
        "lower EL, AArch64",
        "System error from lower EL, AArch64",
    ),
    // Lower EL using AArch32
    A64ExcVector::new(
        0x600,
        "Sync/A32",
        "Synchronous",
        "lower EL, AArch32",
        "Synchronous from lower EL, AArch32",
    ),
    A64ExcVector::new(
        0x680,
        "IRQ/A32",
        "IRQ",
        "lower EL, AArch32",
        "IRQ from lower EL, AArch32",
    ),
    A64ExcVector::new(
        0x700,
        "FIQ/A32",
        "FIQ",
        "lower EL, AArch32",
        "FIQ from lower EL, AArch32",
    ),
    A64ExcVector::new(
        0x780,
        "SError/A32",
        "SError",
        "lower EL, AArch32",
        "System error from lower EL, AArch32",
    ),
];

/// Look up an exception vector by offset.
#[must_use]
pub fn a64_exc_vector_at(offset: u32) -> Option<&'static A64ExcVector> {
    A64_EXC_VECTORS.iter().find(|v| v.offset == offset)
}

// ---------------------------------------------------------------------------
// AArch64 ESR_EL1 exception class table
// ---------------------------------------------------------------------------

/// An `AArch64` ESR exception class.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct EsrClass {
    /// 6-bit exception class value.
    pub ec: u8,
    /// Name.
    pub name: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl EsrClass {
    const fn new(ec: u8, name: &'static str, desc: &'static str) -> Self {
        Self { ec, name, desc }
    }
}

/// `AArch64` ESR exception class table.
pub static ESR_CLASSES: &[EsrClass] = &[
    EsrClass::new(0x00, "Unknown", "Unknown reason"),
    EsrClass::new(0x01, "WFx", "Trapped WFI or WFE"),
    EsrClass::new(
        0x03,
        "MCR/MRC_CP15",
        "Trapped MCR/MRC access to CP15 (not all)",
    ),
    EsrClass::new(0x04, "MCRR/MRRC", "Trapped MCRR/MRRC access to CP15"),
    EsrClass::new(0x05, "MCR/MRC_CP14", "Trapped MCR/MRC access to CP14"),
    EsrClass::new(0x06, "LDC/STC", "Trapped LDC/STC access"),
    EsrClass::new(0x07, "SVE/SIMD/FP", "Trapped SVE/SIMD/FP access or SME"),
    EsrClass::new(0x0c, "FP16", "Trapped FP16 access"),
    EsrClass::new(0x0e, "PSTATE_IL", "Illegal execution state"),
    EsrClass::new(0x11, "SVC_A32", "SVC instruction (AArch32)"),
    EsrClass::new(0x12, "HVC_A32", "HVC instruction (AArch32)"),
    EsrClass::new(0x13, "SMC_A32", "SMC instruction (AArch32)"),
    EsrClass::new(0x15, "SVC_A64", "SVC instruction (AArch64)"),
    EsrClass::new(0x16, "HVC_A64", "HVC instruction (AArch64)"),
    EsrClass::new(0x17, "SMC_A64", "SMC instruction (AArch64)"),
    EsrClass::new(0x18, "MSR/MRS_SYS", "Trapped MSR/MRS or System instruction"),
    EsrClass::new(0x19, "SVE", "Trapped SVE access"),
    EsrClass::new(0x1d, "TSTART", "Trapped TSTART (TME)"),
    EsrClass::new(0x1e, "GPC", "Granule protection check"),
    EsrClass::new(0x1f, "ERET", "Exception from ERET/ERETAA/ERETAB"),
    EsrClass::new(0x20, "IABT_EL0", "Instruction Abort (EL0)"),
    EsrClass::new(0x21, "IABT_EL1", "Instruction Abort (EL1)"),
    EsrClass::new(0x22, "PC_ALIGN", "PC alignment fault"),
    EsrClass::new(0x24, "DABT_EL0", "Data Abort (EL0)"),
    EsrClass::new(0x25, "DABT_EL1", "Data Abort (EL1)"),
    EsrClass::new(0x26, "SP_ALIGN", "SP alignment fault"),
    EsrClass::new(0x28, "FP_EXC_A32", "Trapped FP exception (AArch32)"),
    EsrClass::new(0x2c, "FP_EXC_A64", "Trapped FP exception (AArch64)"),
    EsrClass::new(0x2f, "SError", "SError interrupt"),
    EsrClass::new(0x30, "BP_EL0", "Breakpoint (EL0)"),
    EsrClass::new(0x31, "BP_EL1", "Breakpoint (EL1)"),
    EsrClass::new(0x32, "SW_STEP_EL0", "Software step (EL0)"),
    EsrClass::new(0x33, "SW_STEP_EL1", "Software step (EL1)"),
    EsrClass::new(0x34, "WP_EL0", "Watchpoint (EL0)"),
    EsrClass::new(0x35, "WP_EL1", "Watchpoint (EL1)"),
    EsrClass::new(0x38, "BKPT_A32", "BKPT instruction (AArch32)"),
    EsrClass::new(0x3a, "VECTOR_CATCH", "Vector catch (AArch32)"),
    EsrClass::new(0x3c, "BRK_A64", "BRK instruction (AArch64)"),
];

/// Look up an ESR class by 6-bit EC value.
#[must_use]
pub fn esr_class_lookup(ec: u8) -> Option<&'static EsrClass> {
    ESR_CLASSES.iter().find(|c| c.ec == ec & 0x3f)
}

// ---------------------------------------------------------------------------
// Final extended tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_final_tests {
    use super::*;

    // ── DP instruction table ──────────────────────────────────────────────

    #[test]
    fn test_dp_table_has_add() {
        assert!(dp_lookup("add").is_some());
        assert_eq!(dp_lookup("add").unwrap().class, A64DpClass::Arithmetic);
    }

    #[test]
    fn test_dp_table_has_csel() {
        assert_eq!(dp_lookup("csel").unwrap().class, A64DpClass::Conditional);
    }

    #[test]
    fn test_dp_table_has_sdiv() {
        assert_eq!(dp_lookup("sdiv").unwrap().class, A64DpClass::Divide);
    }

    #[test]
    fn test_dp_table_count() {
        assert!(DP_INSTRS.len() >= 50);
    }

    #[test]
    fn test_dp_missing() {
        assert!(dp_lookup("nop").is_none());
    }

    // ── LS instruction table ──────────────────────────────────────────────

    #[test]
    fn test_ls_ldr_is_load() {
        let i = ls_lookup("ldr").unwrap();
        assert!(i.is_load());
        assert!(!i.is_exclusive());
    }

    #[test]
    fn test_ls_stxr_is_exclusive() {
        let i = ls_lookup("stxr").unwrap();
        assert!(!i.is_load());
        assert!(i.is_exclusive());
    }

    #[test]
    fn test_ls_ldp_is_pair() {
        let i = ls_lookup("ldp").unwrap();
        assert!(i.is_pair());
        assert!(i.is_load());
    }

    #[test]
    fn test_ls_ldrsb_sign_extend() {
        let i = ls_lookup("ldrsb").unwrap();
        assert!(i.sign_extend());
        assert_eq!(i.data_size, 1);
    }

    #[test]
    fn test_ls_table_count() {
        assert!(LS_INSTRS.len() >= 30);
    }

    // ── SIMD/FP instruction table ─────────────────────────────────────────

    #[test]
    fn test_simd_fadd_fp_arith() {
        let i = simd_fp_lookup("fadd").unwrap();
        assert_eq!(i.class, SimdFpClass::FpArithmetic);
    }

    #[test]
    fn test_simd_fcmp_fp_compare() {
        let i = simd_fp_lookup("fcmp").unwrap();
        assert_eq!(i.class, SimdFpClass::FpCompare);
    }

    #[test]
    fn test_simd_scvtf_convert() {
        let i = simd_fp_lookup("scvtf").unwrap();
        assert_eq!(i.class, SimdFpClass::FpConvert);
    }

    #[test]
    fn test_simd_aese_crypto() {
        let i = simd_fp_lookup("aese").unwrap();
        assert_eq!(i.class, SimdFpClass::SimdCrypto);
    }

    #[test]
    fn test_simd_zip1_permute() {
        let i = simd_fp_lookup("zip1").unwrap();
        assert_eq!(i.class, SimdFpClass::SimdPermute);
    }

    #[test]
    fn test_simd_table_count() {
        assert!(SIMD_FP_INSTRS.len() >= 50);
    }

    // ── Exception vectors ─────────────────────────────────────────────────

    #[test]
    fn test_exc_vector_0x000_sync_sp0() {
        let v = a64_exc_vector_at(0x000).unwrap();
        assert_eq!(v.exc_type, "Synchronous");
    }

    #[test]
    fn test_exc_vector_0x200_sync_spx() {
        let v = a64_exc_vector_at(0x200).unwrap();
        assert!(v.name.contains("SPx"));
    }

    #[test]
    fn test_exc_vector_0x780_serror_a32() {
        let v = a64_exc_vector_at(0x780).unwrap();
        assert_eq!(v.exc_type, "SError");
    }

    #[test]
    fn test_exc_vector_count() {
        assert_eq!(A64_EXC_VECTORS.len(), 16);
    }

    #[test]
    fn test_exc_vector_missing() {
        assert!(a64_exc_vector_at(0x999).is_none());
    }

    // ── ESR class table ───────────────────────────────────────────────────

    #[test]
    fn test_esr_svc_a64() {
        let c = esr_class_lookup(0x15).unwrap();
        assert_eq!(c.name, "SVC_A64");
    }

    #[test]
    fn test_esr_dabt_el0() {
        let c = esr_class_lookup(0x24).unwrap();
        assert_eq!(c.name, "DABT_EL0");
    }

    #[test]
    fn test_esr_brk_a64() {
        let c = esr_class_lookup(0x3c).unwrap();
        assert_eq!(c.name, "BRK_A64");
    }

    #[test]
    fn test_esr_missing() {
        assert!(esr_class_lookup(0x02).is_none());
    }

    #[test]
    fn test_esr_table_count() {
        assert!(ESR_CLASSES.len() >= 20);
    }
}

// ---------------------------------------------------------------------------
// AArch64 address translation helpers
// ---------------------------------------------------------------------------

/// `AArch64` translation regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum TranslationRegime {
    /// EL1&0: stage 1 using `TTBR0_EL1` (user space).
    El1Ttbr0,
    /// EL1&0: stage 1 using `TTBR1_EL1` (kernel space).
    El1Ttbr1,
    /// EL1&0: stage 2 (guest-to-intermediate physical).
    El1Stage2,
    /// EL2: hypervisor stage 1.
    El2,
    /// EL3: secure monitor stage 1.
    El3,
}

impl TranslationRegime {
    /// Returns `true` if a stage 2 translation is applied.
    #[must_use]
    pub fn has_stage2(self) -> bool {
        self == Self::El1Stage2
    }

    /// Select regime from virtual address top bits and current EL.
    pub const fn from_va_el(va: u64, el: ExceptionLevel) -> Self {
        match el {
            ExceptionLevel::El2 => Self::El2,
            ExceptionLevel::El3 => Self::El3,
            _ => {
                // Bit 63 selects TTBR0 (0) or TTBR1 (1)
                if (va >> 63) & 1 != 0 {
                    Self::El1Ttbr1
                } else {
                    Self::El1Ttbr0
                }
            }
        }
    }
}

/// Compute the page-aligned base of a virtual address (4 KB page).
#[must_use]
pub const fn page_base_4k(va: u64) -> u64 {
    va & !0xfff
}

/// Compute the 4 KB page offset of a virtual address.
#[must_use]
pub const fn page_offset_4k(va: u64) -> u64 {
    va & 0xfff
}

/// Compute the page-aligned base of a virtual address (64 KB page).
#[must_use]
pub const fn page_base_64k(va: u64) -> u64 {
    va & !0xffff
}

/// Compute the 64 KB page offset of a virtual address.
#[must_use]
pub const fn page_offset_64k(va: u64) -> u64 {
    va & 0xffff
}

// ---------------------------------------------------------------------------
// AArch64 immediate logical decode (DecodeBitMasks)
// ---------------------------------------------------------------------------

/// Decode an `AArch64` logical immediate into its 64-bit immediate value.
///
/// Returns `None` if the encoding is reserved.
/// `n`, `rot` (immr), `size_field` (imms) are the raw bit fields from the instruction.
/// `reg_size` must be 32 or 64.
#[must_use]
pub fn decode_logical_imm(n: u8, rot: u8, size_field: u8, reg_size: u8) -> Option<u64> {
    // Determine the element size
    let len: u8 = if n == 1 {
        6
    } else {
        // Find the highest set bit of NOT(size_field):6..0 where size_field high bits are ~N
        let tmp = (!size_field) & 0x3f;
        if tmp == 0 {
            return None;
        }
        let mut l = 0u8;
        for i in (0u8..6).rev() {
            if tmp & (1 << i) != 0 {
                l = i;
                break;
            }
        }
        l
    };
    let levels = (1u8 << len) - 1;
    let s = size_field & levels;
    let r = rot & levels;
    let esize = 1u32 << len;

    // Build the base bit pattern: s+1 ones
    let welem: u64 = if s + 1 >= 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    // Rotate right by r
    let ror = if r == 0 {
        welem
    } else {
        (welem >> u32::from(r)) | (welem << (esize - u32::from(r)))
    };
    let ror = if esize < 64 {
        ror & ((1u64 << esize) - 1)
    } else {
        ror
    };

    // Replicate esize-bit pattern to reg_size
    let mut result: u64 = 0;
    let mut remaining = u32::from(reg_size);
    let mut shift = 0u32;
    while remaining > 0 {
        let chunk = remaining.min(esize);
        let mask = if chunk >= 64 {
            u64::MAX
        } else {
            (1u64 << chunk) - 1
        };
        result |= (ror & mask) << shift;
        shift += chunk;
        remaining = remaining.saturating_sub(esize);
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// AArch64 condition flag arithmetic
// ---------------------------------------------------------------------------

/// Compute NZCV flags for a 64-bit ADD operation.
pub const fn add64_nzcv(lhs: u64, rhs: u64) -> Nzcv {
    let (result, carry) = lhs.overflowing_add(rhs);
    let neg = (result >> 63) & 1 != 0;
    let zero = result == 0;
    let carry_flag = carry;
    // Overflow: same signs of lhs,rhs but different sign of result
    let overflow = ((!(lhs ^ rhs) & (lhs ^ result)) >> 63) & 1 != 0;
    let bits = ((neg as u8) << 3) | ((zero as u8) << 2) | ((carry_flag as u8) << 1) | (overflow as u8);
    Nzcv(bits)
}

/// Compute NZCV flags for a 64-bit SUB operation.
pub const fn sub64_nzcv(lhs: u64, rhs: u64) -> Nzcv {
    // SUB is implemented as ADD with NOT(rhs)+1 = ~rhs+carry_in
    let (result, borrow) = lhs.overflowing_sub(rhs);
    let neg = (result >> 63) & 1 != 0;
    let zero = result == 0;
    // C flag in AArch64 SUB: set if no borrow (i.e., lhs >= rhs unsigned)
    let carry_flag = !borrow;
    let overflow = (((lhs ^ rhs) & (lhs ^ result)) >> 63) & 1 != 0;
    let bits = ((neg as u8) << 3) | ((zero as u8) << 2) | ((carry_flag as u8) << 1) | (overflow as u8);
    Nzcv(bits)
}

// ---------------------------------------------------------------------------
// AArch64 FP special values
// ---------------------------------------------------------------------------

/// `AArch64` floating-point special value class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum FpClass {
    /// Positive zero.
    PosZero,
    /// Negative zero.
    NegZero,
    /// Positive infinity.
    PosInfinity,
    /// Negative infinity.
    NegInfinity,
    /// Positive NaN (quiet or signaling).
    Nan,
    /// Positive denormal (subnormal).
    PosDenormal,
    /// Negative denormal (subnormal).
    NegDenormal,
    /// Normal positive.
    PosNormal,
    /// Normal negative.
    NegNormal,
}

impl FpClass {
    /// Classify a 64-bit IEEE 754 double.
    pub const fn classify_f64(bits: u64) -> Self {
        let sign = (bits >> 63) & 1 != 0;
        let exp = (bits >> 52) & 0x7ff;
        let frac = bits & 0x000f_ffff_ffff_ffff;
        match (sign, exp, frac) {
            (false, 0, 0) => Self::PosZero,
            (true, 0, 0) => Self::NegZero,
            (false, 0x7ff, 0) => Self::PosInfinity,
            (true, 0x7ff, 0) => Self::NegInfinity,
            (_, 0x7ff, _) => Self::Nan,
            (false, 0, _) => Self::PosDenormal,
            (true, 0, _) => Self::NegDenormal,
            (false, _, _) => Self::PosNormal,
            (true, _, _) => Self::NegNormal,
        }
    }

    /// Returns `true` for any zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        matches!(self, Self::PosZero | Self::NegZero)
    }

    /// Returns `true` for any infinity.
    #[must_use]
    pub const fn is_infinite(self) -> bool {
        matches!(self, Self::PosInfinity | Self::NegInfinity)
    }

    /// Returns `true` for NaN.
    #[must_use]
    pub const fn is_nan(self) -> bool {
        matches!(self, Self::Nan)
    }
}

// ---------------------------------------------------------------------------
// AArch64 system instruction table
// ---------------------------------------------------------------------------

/// An `AArch64` system instruction descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct SysInstr {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Required privilege level.
    pub min_el: u8,
    /// Description.
    pub desc: &'static str,
}

impl SysInstr {
    const fn new(mnemonic: &'static str, min_el: u8, desc: &'static str) -> Self {
        Self {
            mnemonic,
            min_el,
            desc,
        }
    }
}

/// `AArch64` system instruction reference.
pub static SYS_INSTRS: &[SysInstr] = &[
    SysInstr::new("svc", 0, "Supervisor call (EL0→EL1)"),
    SysInstr::new("hvc", 1, "Hypervisor call (EL1→EL2)"),
    SysInstr::new("smc", 1, "Secure Monitor call (EL1→EL3)"),
    SysInstr::new("eret", 1, "Exception return"),
    SysInstr::new("nop", 0, "No operation"),
    SysInstr::new("yield", 0, "Yield hint"),
    SysInstr::new("wfe", 0, "Wait for event"),
    SysInstr::new("wfi", 0, "Wait for interrupt"),
    SysInstr::new("sev", 0, "Send event"),
    SysInstr::new("sevl", 0, "Send event local"),
    SysInstr::new("hint", 0, "Hint instruction"),
    SysInstr::new("brk", 0, "Breakpoint"),
    SysInstr::new("hlt", 0, "Halt instruction"),
    SysInstr::new("dcps1", 1, "Debug change PC to EL1"),
    SysInstr::new("dcps2", 1, "Debug change PC to EL2"),
    SysInstr::new("dcps3", 1, "Debug change PC to EL3"),
    SysInstr::new("drps", 1, "Debug restore PE state"),
    SysInstr::new("msr", 0, "Move to system register"),
    SysInstr::new("mrs", 0, "Move from system register"),
    SysInstr::new("sys", 0, "System instruction"),
    SysInstr::new("sysl", 0, "System instruction, returning result"),
    SysInstr::new("at", 1, "Address translate"),
    SysInstr::new("dc", 0, "Data cache operation"),
    SysInstr::new("ic", 0, "Instruction cache operation"),
    SysInstr::new("tlbi", 1, "TLB invalidate operation"),
    SysInstr::new("tlbip", 1, "TLB invalidate pair (FEAT_TLBIOS)"),
    SysInstr::new("cfp", 0, "Control flow prediction restriction"),
    SysInstr::new("cpp", 0, "Cache prefetch prediction restriction"),
    SysInstr::new("dvp", 0, "Data value prediction restriction"),
    SysInstr::new("cosp", 0, "Clear other speculative predictions"),
    SysInstr::new(
        "xaflag",
        0,
        "Convert floating-point condition flags (FEAT_FlagM2)",
    ),
    SysInstr::new(
        "axflag",
        0,
        "Convert floating-point condition flags (FEAT_FlagM2)",
    ),
    SysInstr::new("tcancel", 0, "Cancel transactional execution (FEAT_TME)"),
    SysInstr::new("tcommit", 0, "Commit transactional execution (FEAT_TME)"),
    SysInstr::new("tstart", 0, "Start transactional execution (FEAT_TME)"),
    SysInstr::new("ttest", 0, "Test transactional depth (FEAT_TME)"),
];

/// Look up a system instruction by mnemonic.
#[must_use]
pub fn sys_instr_lookup(mnemonic: &str) -> Option<&'static SysInstr> {
    SYS_INSTRS
        .iter()
        .find(|i| i.mnemonic.eq_ignore_ascii_case(mnemonic))
}

// ---------------------------------------------------------------------------
// AArch64 GCR_EL1 / RGSR_EL1 tag generation helpers (MTE)
// ---------------------------------------------------------------------------

/// Extract the tag from a tagged pointer (bits[59:56]).
#[must_use]
pub const fn get_ptr_tag(ptr: u64) -> u8 {
    ((ptr >> 56) & 0xf) as u8
}

/// Insert a 4-bit tag into a pointer (bits[59:56]).
#[must_use]
pub fn set_ptr_tag(ptr: u64, tag: u8) -> u64 {
    (ptr & !(0xfu64 << 56)) | ((u64::from(tag) & 0xf) << 56)
}

/// Strip the tag from a pointer (zeroes bits[59:56]).
#[must_use]
pub const fn strip_ptr_tag(ptr: u64) -> u64 {
    ptr & !(0xfu64 << 56)
}

// ---------------------------------------------------------------------------
// AArch64 address generation helpers
// ---------------------------------------------------------------------------

/// Compute the canonical address by sign-extending bit[55] downwards.
/// Addresses with bits[63:56] != bits[55] repeated are non-canonical.
#[must_use]
pub const fn canonical_address(va: u64) -> u64 {
    if (va >> 55) & 1 != 0 {
        // Top byte should be all 1s
        va | (0xffu64 << 56)
    } else {
        // Top byte should be all 0s
        va & !(0xffu64 << 56)
    }
}

/// Align a value to the next multiple of `align` (must be a power of two).
#[must_use]
pub fn align_up(val: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (val + align - 1) & !(align - 1)
}

/// Align a value down to a multiple of `align` (must be a power of two).
#[must_use]
pub fn align_down(val: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    val & !(align - 1)
}

// ---------------------------------------------------------------------------
// AArch64 barrier option table
// ---------------------------------------------------------------------------

/// An `AArch64` memory barrier option.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct BarrierOption {
    /// 4-bit option value.
    pub option: u8,
    /// Name.
    pub name: &'static str,
    /// Shareability domain.
    pub domain: &'static str,
    /// Types of access.
    pub access: &'static str,
}

impl BarrierOption {
    const fn new(
        option: u8,
        name: &'static str,
        domain: &'static str,
        access: &'static str,
    ) -> Self {
        Self {
            option,
            name,
            domain,
            access,
        }
    }
}

/// `AArch64` DMB/DSB option table.
pub static BARRIER_OPTIONS: &[BarrierOption] = &[
    BarrierOption::new(0xf, "SY", "Full system", "Reads and writes"),
    BarrierOption::new(0xe, "ST", "Full system", "Writes only"),
    BarrierOption::new(0xd, "LD", "Full system", "Reads only"),
    BarrierOption::new(0xb, "ISH", "Inner shareable", "Reads and writes"),
    BarrierOption::new(0xa, "ISHST", "Inner shareable", "Writes only"),
    BarrierOption::new(0x9, "ISHLD", "Inner shareable", "Reads only"),
    BarrierOption::new(0x7, "NSH", "Non-shareable", "Reads and writes"),
    BarrierOption::new(0x6, "NSHST", "Non-shareable", "Writes only"),
    BarrierOption::new(0x5, "NSHLD", "Non-shareable", "Reads only"),
    BarrierOption::new(0x3, "OSH", "Outer shareable", "Reads and writes"),
    BarrierOption::new(0x2, "OSHST", "Outer shareable", "Writes only"),
    BarrierOption::new(0x1, "OSHLD", "Outer shareable", "Reads only"),
];

/// Look up a barrier option by its 4-bit value.
#[must_use]
pub fn barrier_option_lookup(option: u8) -> Option<&'static BarrierOption> {
    BARRIER_OPTIONS.iter().find(|o| o.option == option & 0xf)
}

// ---------------------------------------------------------------------------
// AArch64 instruction printer
// ---------------------------------------------------------------------------

/// Format a compact disassembly line given mnemonic and operands.
#[must_use]
pub fn format_instr(mnemonic: &str, operands: &str) -> String {
    if operands.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operands}")
    }
}

/// Format a register name with optional width qualifier.
#[must_use]
pub fn format_reg(n: u8, is_64bit: bool) -> String {
    let n = n & 0x1f;
    if n == 31 {
        if is_64bit {
            "xzr".to_string()
        } else {
            "wzr".to_string()
        }
    } else if is_64bit {
        format!("x{n}")
    } else {
        format!("w{n}")
    }
}

/// Format an SP reference.
#[must_use]
pub const fn format_sp(is_64bit: bool) -> &'static str {
    if is_64bit { "sp" } else { "wsp" }
}

// ---------------------------------------------------------------------------
// AArch64 feature flags
// ---------------------------------------------------------------------------

/// `AArch64` optional feature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct A64Features(u64);

impl A64Features {
    /// `FEAT_LSE` — Large System Extensions (atomics).
    pub const LSE: Self = Self(1 << 0);
    /// `FEAT_PAC` — Pointer Authentication.
    pub const PAC: Self = Self(1 << 1);
    /// `FEAT_BTI` — Branch Target Identification.
    pub const BTI: Self = Self(1 << 2);
    /// `FEAT_SVE` — Scalable Vector Extension.
    pub const SVE: Self = Self(1 << 3);
    /// `FEAT_SVE2` — SVE2.
    pub const SVE2: Self = Self(1 << 4);
    /// `FEAT_MTE` — Memory Tagging Extension.
    pub const MTE: Self = Self(1 << 5);
    /// `FEAT_FP16` — Full half-precision FP support.
    pub const FP16: Self = Self(1 << 6);
    /// `FEAT_SHA3` — SHA-3 crypto.
    pub const SHA3: Self = Self(1 << 7);
    /// `FEAT_SM4` — SM3/SM4 crypto.
    pub const SM4: Self = Self(1 << 8);
    /// `FEAT_DOTPROD` — Dot product.
    pub const DOTPROD: Self = Self(1 << 9);
    /// `FEAT_RNG` — Random number generation.
    pub const RNG: Self = Self(1 << 10);
    /// `FEAT_TME` — Transactional Memory Extension.
    pub const TME: Self = Self(1 << 11);
    /// `FEAT_AMU` — Activity Monitor Extension.
    pub const AMU: Self = Self(1 << 12);
    /// `FEAT_BRBE` — Branch Record Buffer Extension.
    pub const BRBE: Self = Self(1 << 13);
    /// `FEAT_SME` — Scalable Matrix Extension.
    pub const SME: Self = Self(1 << 14);
    /// `FEAT_WFxT` — WFE/WFI with timeout.
    pub const WFXT: Self = Self(1 << 15);

    /// Create an empty feature set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Test if a feature is present.
    #[must_use]
    pub const fn has(self, f: Self) -> bool {
        (self.0 & f.0) != 0
    }

    /// Combine two feature sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Feature set for a Cortex-A72 (ARMv8.0-A baseline).
    pub const fn cortex_a72() -> Self {
        Self::empty()
    }

    /// Feature set for a Cortex-A78 (ARMv8.2-A with LSE, PAC, BTI).
    pub const fn cortex_a78() -> Self {
        Self::LSE
            .union(Self::PAC)
            .union(Self::BTI)
            .union(Self::FP16)
            .union(Self::DOTPROD)
    }

    /// Feature set for a Cortex-X1 (ARMv8.2-A).
    pub const fn cortex_x1() -> Self {
        Self::cortex_a78().union(Self::SVE)
    }

    /// Feature set for Apple M1 (ARMv8.5-A).
    pub const fn apple_m1() -> Self {
        Self::LSE
            .union(Self::PAC)
            .union(Self::BTI)
            .union(Self::FP16)
            .union(Self::SHA3)
            .union(Self::DOTPROD)
            .union(Self::RNG)
    }
}

// ---------------------------------------------------------------------------
// More comprehensive tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_more_tests {
    use super::*;

    // ── Translation regime ────────────────────────────────────────────────

    #[test]
    fn test_translation_regime_el1_ttbr0() {
        // VA bit 63 = 0 → TTBR0
        let r = TranslationRegime::from_va_el(0x0000_0000_0000_1000, ExceptionLevel::El1);
        assert_eq!(r, TranslationRegime::El1Ttbr0);
    }

    #[test]
    fn test_translation_regime_el1_ttbr1() {
        // VA bit 63 = 1 → TTBR1 (kernel space)
        let r = TranslationRegime::from_va_el(0xffff_0000_0000_1000, ExceptionLevel::El1);
        assert_eq!(r, TranslationRegime::El1Ttbr1);
    }

    #[test]
    fn test_translation_regime_el2() {
        let r = TranslationRegime::from_va_el(0, ExceptionLevel::El2);
        assert_eq!(r, TranslationRegime::El2);
    }

    #[test]
    fn test_page_base_4k() {
        assert_eq!(page_base_4k(0x1fff), 0x1000);
        assert_eq!(page_base_4k(0x1000), 0x1000);
    }

    #[test]
    fn test_page_offset_4k() {
        assert_eq!(page_offset_4k(0x1abc), 0xabc);
    }

    // ── Add/sub NZCV ──────────────────────────────────────────────────────

    #[test]
    fn test_add64_nzcv_zero() {
        let nzcv = add64_nzcv(0, 0);
        assert!(nzcv.z());
        assert!(!nzcv.n());
        assert!(!nzcv.c());
        assert!(!nzcv.v());
    }

    #[test]
    fn test_add64_nzcv_carry() {
        let nzcv = add64_nzcv(u64::MAX, 1);
        assert!(nzcv.z());
        assert!(nzcv.c());
    }

    #[test]
    fn test_sub64_nzcv_equal() {
        let nzcv = sub64_nzcv(5, 5);
        assert!(nzcv.z());
        assert!(nzcv.c()); // no borrow
    }

    #[test]
    fn test_sub64_nzcv_negative() {
        let nzcv = sub64_nzcv(0, 1);
        assert!(nzcv.n()); // result = 0xffff... which has bit 63 set
        assert!(!nzcv.c()); // borrow occurred
    }

    // ── FP class ──────────────────────────────────────────────────────────

    #[test]
    fn test_fp_pos_zero() {
        assert_eq!(
            FpClass::classify_f64(0x0000_0000_0000_0000),
            FpClass::PosZero
        );
        assert!(FpClass::PosZero.is_zero());
    }

    #[test]
    fn test_fp_neg_infinity() {
        assert_eq!(
            FpClass::classify_f64(0xfff0_0000_0000_0000),
            FpClass::NegInfinity
        );
        assert!(FpClass::NegInfinity.is_infinite());
    }

    #[test]
    fn test_fp_nan() {
        assert_eq!(FpClass::classify_f64(0x7ff8_0000_0000_0000), FpClass::Nan);
        assert!(FpClass::Nan.is_nan());
    }

    #[test]
    fn test_fp_pos_normal() {
        // 1.0 = 0x3ff0000000000000
        assert_eq!(
            FpClass::classify_f64(0x3ff0_0000_0000_0000),
            FpClass::PosNormal
        );
    }

    // ── Logical immediate ─────────────────────────────────────────────────

    #[test]
    fn test_decode_logical_imm_simple() {
        // N=1, immr=0, imms=0 → 1 one, no rotation → 0x0000...0001
        let v = decode_logical_imm(1, 0, 0, 64);
        assert_eq!(v, Some(1));
    }

    #[test]
    fn test_decode_logical_imm_all_ones_32() {
        // N=0, immr=0, imms=0b01_1111 → 32 ones in 32-bit → 0xffff_ffff
        let v = decode_logical_imm(0, 0, 0b01_1111, 32);
        assert!(v.is_some());
    }

    // ── System instruction lookup ─────────────────────────────────────────

    #[test]
    fn test_sys_lookup_svc() {
        let i = sys_instr_lookup("svc").unwrap();
        assert_eq!(i.min_el, 0);
    }

    #[test]
    fn test_sys_lookup_hvc() {
        let i = sys_instr_lookup("hvc").unwrap();
        assert_eq!(i.min_el, 1);
    }

    #[test]
    fn test_sys_table_count() {
        assert!(SYS_INSTRS.len() >= 20);
    }

    // ── Barrier option lookup ─────────────────────────────────────────────

    #[test]
    fn test_barrier_sy() {
        let b = barrier_option_lookup(0xf).unwrap();
        assert_eq!(b.name, "SY");
    }

    #[test]
    fn test_barrier_ish() {
        let b = barrier_option_lookup(0xb).unwrap();
        assert_eq!(b.name, "ISH");
    }

    #[test]
    fn test_barrier_missing() {
        assert!(barrier_option_lookup(0x0).is_none());
    }

    // ── MTE pointer helpers ───────────────────────────────────────────────

    #[test]
    fn test_get_ptr_tag_zero() {
        assert_eq!(get_ptr_tag(0x0000_0000_0000_1234), 0);
    }

    #[test]
    fn test_set_ptr_tag_and_get() {
        let ptr = set_ptr_tag(0x0000_0000_0000_1234, 0xa);
        assert_eq!(get_ptr_tag(ptr), 0xa);
        assert_eq!(strip_ptr_tag(ptr), 0x0000_0000_0000_1234);
    }

    // ── Address helpers ───────────────────────────────────────────────────

    #[test]
    fn test_align_up_4k() {
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn test_align_down_4k() {
        assert_eq!(align_down(0x1fff, 0x1000), 0x1000);
    }

    // ── Feature flags ─────────────────────────────────────────────────────

    #[test]
    fn test_a64_features_apple_m1_has_pac() {
        assert!(A64Features::apple_m1().has(A64Features::PAC));
    }

    #[test]
    fn test_a64_features_a72_has_nothing() {
        let f = A64Features::cortex_a72();
        assert!(!f.has(A64Features::LSE));
    }

    #[test]
    fn test_a64_features_union() {
        let a = A64Features::LSE;
        let b = A64Features::SVE;
        let c = a.union(b);
        assert!(c.has(A64Features::LSE));
        assert!(c.has(A64Features::SVE));
    }

    // ── format_reg / format_instr helpers ────────────────────────────────

    #[test]
    fn test_format_reg_64_bit() {
        assert_eq!(format_reg(0, true), "x0");
        assert_eq!(format_reg(30, true), "x30");
        assert_eq!(format_reg(31, true), "xzr");
    }

    #[test]
    fn test_format_reg_32_bit() {
        assert_eq!(format_reg(0, false), "w0");
        assert_eq!(format_reg(31, false), "wzr");
    }

    #[test]
    fn test_format_instr_with_operands() {
        assert_eq!(format_instr("add", "x0, x1, #1"), "add x0, x1, #1");
    }

    #[test]
    fn test_format_instr_no_operands() {
        assert_eq!(format_instr("nop", ""), "nop");
    }

    #[test]
    fn test_canonical_address_kernel() {
        // bit55=1 → top byte = 0xff
        let va: u64 = 0x0080_0000_0000_0000;
        let ca = canonical_address(va);
        assert_eq!(ca >> 56, 0xff);
    }

    #[test]
    fn test_canonical_address_user() {
        // bit55=0 → top byte = 0x00
        let va: u64 = 0x0000_1234_5678_0000;
        let ca = canonical_address(va);
        assert_eq!(ca >> 56, 0x00);
    }
}

// ---------------------------------------------------------------------------
// AArch64 TCR_EL1 bit-field table
// ---------------------------------------------------------------------------

/// A `TCR_EL1` (Translation Control Register) bit-field descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct TcrField {
    /// Field name.
    pub name: &'static str,
    /// MSB bit position.
    pub msb: u8,
    /// LSB bit position.
    pub lsb: u8,
    /// Description.
    pub desc: &'static str,
}

impl TcrField {
    const fn new(name: &'static str, msb: u8, lsb: u8, desc: &'static str) -> Self {
        Self {
            name,
            msb,
            lsb,
            desc,
        }
    }

    /// Extract field from a `TCR_EL1` value.
    #[must_use]
    pub const fn extract(self, tcr: u64) -> u64 {
        let width = self.msb - self.lsb + 1;
        let mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        (tcr >> self.lsb) & mask
    }
}

/// `TCR_EL1` field table.
pub static TCR_EL1_FIELDS: &[TcrField] = &[
    TcrField::new(
        "T0SZ",
        5,
        0,
        "Size offset for TTBR0 region (2^(64-T0SZ) bytes)",
    ),
    TcrField::new("EPD0", 7, 7, "Translation table walk disable for TTBR0"),
    TcrField::new("IRGN0", 9, 8, "Inner cacheability attr for TTBR0 walks"),
    TcrField::new("ORGN0", 11, 10, "Outer cacheability attr for TTBR0 walks"),
    TcrField::new("SH0", 13, 12, "Shareability for TTBR0 walks"),
    TcrField::new(
        "TG0",
        15,
        14,
        "Granule size for TTBR0 (00=4KB,01=64KB,10=16KB)",
    ),
    TcrField::new("T1SZ", 21, 16, "Size offset for TTBR1 region"),
    TcrField::new("A1", 22, 22, "ASID select: 0=TTBR0.ASID, 1=TTBR1.ASID"),
    TcrField::new("EPD1", 23, 23, "Translation table walk disable for TTBR1"),
    TcrField::new("IRGN1", 25, 24, "Inner cacheability attr for TTBR1 walks"),
    TcrField::new("ORGN1", 27, 26, "Outer cacheability attr for TTBR1 walks"),
    TcrField::new("SH1", 29, 28, "Shareability for TTBR1 walks"),
    TcrField::new(
        "TG1",
        31,
        30,
        "Granule size for TTBR1 (01=16KB,10=4KB,11=64KB)",
    ),
    TcrField::new("IPS", 34, 32, "Intermediate physical address size"),
    TcrField::new("AS", 36, 36, "ASID size: 0=8-bit, 1=16-bit"),
    TcrField::new("TBI0", 37, 37, "Top Byte Ignore for TTBR0 addresses"),
    TcrField::new("TBI1", 38, 38, "Top Byte Ignore for TTBR1 addresses"),
    TcrField::new("HA", 39, 39, "Hardware Access Flag update"),
    TcrField::new("HD", 40, 40, "Hardware Dirty state update"),
    TcrField::new("HPD0", 41, 41, "Hierarchical Permission Disable for TTBR0"),
    TcrField::new("HPD1", 42, 42, "Hierarchical Permission Disable for TTBR1"),
    TcrField::new("HWU059", 43, 43, "Hardware-managed dirty/access bit update"),
    TcrField::new("TBID0", 51, 51, "Top byte ignored for data access, TTBR0"),
    TcrField::new("TBID1", 52, 52, "Top byte ignored for data access, TTBR1"),
    TcrField::new("NFD0", 53, 53, "No fault for TTBR0 translations (FEAT_SVE)"),
    TcrField::new("NFD1", 54, 54, "No fault for TTBR1 translations (FEAT_SVE)"),
    TcrField::new("E0PD0", 55, 55, "Fault on EL0 access to TTBR0 (FEAT_E0PD)"),
    TcrField::new("E0PD1", 56, 56, "Fault on EL0 access to TTBR1 (FEAT_E0PD)"),
    TcrField::new("TCMA0", 57, 57, "Tag Checking Memory Attribute (FEAT_MTE2)"),
    TcrField::new("TCMA1", 58, 58, "Tag Checking Memory Attribute (FEAT_MTE2)"),
    TcrField::new("DS", 59, 59, "Descriptor size (FEAT_LPA2)"),
];

// ---------------------------------------------------------------------------
// AArch64 MAIR_EL1 attribute encoding helpers
// ---------------------------------------------------------------------------

/// `AArch64` memory attribute encoding (one byte of `MAIR_EL1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct MemAttr(pub u8);

impl MemAttr {
    /// Device memory — nGnRnE (non-gathering, non-reordering, non-early-write-ack).
    pub const DEVICE_NGNRNE: Self = Self(0b0000_0000);
    /// Device memory — nGnRE.
    pub const DEVICE_NGNRE: Self = Self(0b0000_0100);
    /// Device memory — nGRE.
    pub const DEVICE_NGRE: Self = Self(0b0000_1000);
    /// Device memory — GRE.
    pub const DEVICE_GRE: Self = Self(0b0000_1100);
    /// Normal memory, non-cacheable.
    pub const NORMAL_NC: Self = Self(0b0100_0100);
    /// Normal memory, write-through, non-transient.
    pub const NORMAL_WT: Self = Self(0b1010_1010);
    /// Normal memory, write-back, non-transient, read/write allocate.
    pub const NORMAL_WB: Self = Self(0b1111_1111);

    /// Returns `true` if this is a device memory attribute.
    #[must_use]
    pub const fn is_device(self) -> bool {
        (self.0 & 0xf0) == 0
    }

    /// Returns `true` if this is a normal memory attribute.
    #[must_use]
    pub const fn is_normal(self) -> bool {
        !self.is_device()
    }

    /// Description string.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self.0 {
            0b0000_0000 => "Device-nGnRnE",
            0b0000_0100 => "Device-nGnRE",
            0b0000_1000 => "Device-nGRE",
            0b0000_1100 => "Device-GRE",
            0b0100_0100 => "Normal NC",
            0b1010_1010 => "Normal WT non-transient",
            0b1111_1111 => "Normal WB read/write-alloc non-transient",
            _ => "Custom/reserved",
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 register file helper
// ---------------------------------------------------------------------------

/// Format an `AArch64` GPR name, preferring alias for sp/lr/fp/xzr.
#[must_use]
pub fn gpr_alias(n: u8, is_64bit: bool, use_sp: bool) -> String {
    let n = n & 0x1f;
    if n == 31 {
        if use_sp {
            return if is_64bit {
                "sp".to_string()
            } else {
                "wsp".to_string()
            };
        }
        return if is_64bit {
            "xzr".to_string()
        } else {
            "wzr".to_string()
        };
    }
    if is_64bit {
        match n {
            29 => "fp".to_string(),
            30 => "lr".to_string(),
            _ => format!("x{n}"),
        }
    } else {
        format!("w{n}")
    }
}

// ---------------------------------------------------------------------------
// AArch64 calling convention stack frame layout
// ---------------------------------------------------------------------------

/// Describes one slot in an `AArch64` AAPCS64 stack frame.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct FrameSlot {
    /// Offset from FP (frame pointer).
    pub fp_offset: i16,
    /// What is stored in this slot.
    pub contents: &'static str,
}

/// Typical AAPCS64 frame layout (function prologue pattern).
pub static AAPCS64_FRAME_LAYOUT: &[FrameSlot] = &[
    FrameSlot {
        fp_offset: -0,
        contents: "previous FP (x29)",
    },
    FrameSlot {
        fp_offset: -8,
        contents: "return address (x30 / LR)",
    },
    FrameSlot {
        fp_offset: -16,
        contents: "callee-saved x19 (if used)",
    },
    FrameSlot {
        fp_offset: -24,
        contents: "callee-saved x20 (if used)",
    },
    FrameSlot {
        fp_offset: -32,
        contents: "callee-saved x21 (if used)",
    },
    FrameSlot {
        fp_offset: -40,
        contents: "callee-saved x22 (if used)",
    },
    FrameSlot {
        fp_offset: -48,
        contents: "callee-saved x23 (if used)",
    },
    FrameSlot {
        fp_offset: -56,
        contents: "callee-saved x24 (if used)",
    },
    FrameSlot {
        fp_offset: -64,
        contents: "callee-saved x25 (if used)",
    },
    FrameSlot {
        fp_offset: -72,
        contents: "callee-saved x26 (if used)",
    },
    FrameSlot {
        fp_offset: -80,
        contents: "callee-saved x27 (if used)",
    },
    FrameSlot {
        fp_offset: -88,
        contents: "callee-saved x28 (if used)",
    },
    FrameSlot {
        fp_offset: -96,
        contents: "local variable area",
    },
];

// ---------------------------------------------------------------------------
// AArch64 instruction length constant
// ---------------------------------------------------------------------------

/// `AArch64` instruction size in bytes (always 4 for A64).
pub const A64_INSTR_SIZE: usize = 4;

/// `AArch64` minimum stack alignment (16 bytes per AAPCS64).
pub const A64_STACK_ALIGN: usize = 16;

/// `AArch64` pointer size in bytes.
pub const A64_POINTER_SIZE: usize = 8;

/// `AArch64` maximum number of GPRs (including XZR/SP at index 31).
pub const A64_GPR_COUNT: usize = 32;

/// `AArch64` maximum number of SIMD/FP registers.
pub const A64_FP_REG_COUNT: usize = 32;

// ---------------------------------------------------------------------------
// AArch64 SCTLR_EL1 bit-field table
// ---------------------------------------------------------------------------

/// A `SCTLR_EL1` (System Control Register) bit-field descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct SctlrField {
    /// Field name.
    pub name: &'static str,
    /// Bit position.
    pub bit: u8,
    /// Description.
    pub desc: &'static str,
    /// Reset value (1 = enabled, 0 = disabled).
    pub reset: u8,
}

impl SctlrField {
    const fn new(name: &'static str, bit: u8, desc: &'static str, reset: u8) -> Self {
        Self {
            name,
            bit,
            desc,
            reset,
        }
    }

    /// Extract bit from SCTLR value.
    #[must_use]
    pub const fn get(self, sctlr: u64) -> u8 {
        ((sctlr >> self.bit) & 1) as u8
    }
}

/// `SCTLR_EL1` important bit fields.
pub static SCTLR_EL1_FIELDS: &[SctlrField] = &[
    SctlrField::new("M", 0, "MMU enable", 0),
    SctlrField::new("A", 1, "Alignment check enable", 0),
    SctlrField::new("C", 2, "Data cache enable", 0),
    SctlrField::new("SA", 3, "Stack alignment check enable (EL1)", 1),
    SctlrField::new("SA0", 4, "Stack alignment check enable (EL0)", 1),
    SctlrField::new("CP15BEN", 5, "CP15 barrier enable (AArch32)", 0),
    SctlrField::new("nAA", 6, "Non-aligned access trap disable", 0),
    SctlrField::new("ITD", 7, "IT disable", 0),
    SctlrField::new("SED", 8, "SETEND instruction disable", 0),
    SctlrField::new("UMA", 9, "User mask access", 0),
    SctlrField::new(
        "EnRCTX",
        10,
        "Enable EL0 access to FEAT_SPECRES instructions",
        0,
    ),
    SctlrField::new("EOS", 11, "Exception exit is context synchronizing", 1),
    SctlrField::new("I", 12, "Instruction cache enable", 0),
    SctlrField::new("EnDB", 13, "PAC using key DB enable", 0),
    SctlrField::new("DZE", 14, "Trap EL0 DC ZVA instructions", 0),
    SctlrField::new("UCT", 15, "Trap EL0 access to CTR_EL0", 0),
    SctlrField::new("nTWI", 16, "Don't trap WFI to EL1", 0),
    SctlrField::new("nTWE", 18, "Don't trap WFE to EL1", 0),
    SctlrField::new("WXN", 19, "Write permission implies execute-never", 0),
    SctlrField::new("TSCXT", 20, "Trap EL0 reads of SCXTNUM_EL0", 1),
    SctlrField::new("IESB", 21, "Implicit error synchronization barrier", 0),
    SctlrField::new("EIS", 22, "Exception entry is context synchronizing", 1),
    SctlrField::new("SPAN", 23, "Set Privileged Access Never (on exception)", 1),
    SctlrField::new("E0E", 24, "Endianness at EL0 (0=LE, 1=BE)", 0),
    SctlrField::new("EE", 25, "Endianness at EL1 (0=LE, 1=BE)", 0),
    SctlrField::new("UCI", 26, "Trap EL0 cache instructions", 0),
    SctlrField::new("EnDA", 27, "PAC using key DA enable", 0),
    SctlrField::new("nTLSMD", 28, "No trap to EL1 for TLSMD instructions", 1),
    SctlrField::new(
        "LSMAOE",
        29,
        "Load/store multiple atomicity and ordering",
        1,
    ),
    SctlrField::new("EnIB", 30, "PAC using key IB enable", 0),
    SctlrField::new("EnIA", 31, "PAC using key IA enable", 0),
];

// ---------------------------------------------------------------------------
// Final large tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_large_tests {
    use super::*;

    // ── TCR_EL1 fields ────────────────────────────────────────────────────

    #[test]
    fn test_tcr_t0sz_extract() {
        let f = TCR_EL1_FIELDS.iter().find(|f| f.name == "T0SZ").unwrap();
        // T0SZ = 39 (common for 48-bit VA with 4KB pages)
        assert_eq!(f.extract(39), 39);
    }

    #[test]
    fn test_tcr_tg0_extract_4kb() {
        let f = TCR_EL1_FIELDS.iter().find(|f| f.name == "TG0").unwrap();
        // bits[15:14] = 0b00 → 4KB granule
        assert_eq!(f.extract(0), 0);
    }

    #[test]
    fn test_tcr_table_count() {
        assert!(TCR_EL1_FIELDS.len() >= 15);
    }

    // ── MemAttr ───────────────────────────────────────────────────────────

    #[test]
    fn test_mem_attr_device_ngnrne() {
        assert!(MemAttr::DEVICE_NGNRNE.is_device());
        assert!(!MemAttr::DEVICE_NGNRNE.is_normal());
        assert_eq!(MemAttr::DEVICE_NGNRNE.description(), "Device-nGnRnE");
    }

    #[test]
    fn test_mem_attr_normal_wb() {
        assert!(MemAttr::NORMAL_WB.is_normal());
        assert!(!MemAttr::NORMAL_WB.is_device());
    }

    #[test]
    fn test_mem_attr_normal_nc() {
        assert!(MemAttr::NORMAL_NC.is_normal());
    }

    // ── gpr_alias ─────────────────────────────────────────────────────────

    #[test]
    fn test_gpr_alias_x29_fp() {
        assert_eq!(gpr_alias(29, true, false), "fp");
    }

    #[test]
    fn test_gpr_alias_x30_lr() {
        assert_eq!(gpr_alias(30, true, false), "lr");
    }

    #[test]
    fn test_gpr_alias_x31_sp() {
        assert_eq!(gpr_alias(31, true, true), "sp");
    }

    #[test]
    fn test_gpr_alias_x31_xzr() {
        assert_eq!(gpr_alias(31, true, false), "xzr");
    }

    #[test]
    fn test_gpr_alias_w5() {
        assert_eq!(gpr_alias(5, false, false), "w5");
    }

    // ── AAPCS64 frame layout ──────────────────────────────────────────────

    #[test]
    fn test_frame_layout_nonempty() {
        assert!(!AAPCS64_FRAME_LAYOUT.is_empty());
    }

    #[test]
    fn test_frame_layout_first_is_fp() {
        assert!(AAPCS64_FRAME_LAYOUT[0].contents.contains("FP"));
    }

    // ── Constants ─────────────────────────────────────────────────────────

    #[test]
    fn test_a64_constants() {
        assert_eq!(A64_INSTR_SIZE, 4);
        assert_eq!(A64_STACK_ALIGN, 16);
        assert_eq!(A64_POINTER_SIZE, 8);
        assert_eq!(A64_GPR_COUNT, 32);
        assert_eq!(A64_FP_REG_COUNT, 32);
    }

    // ── SCTLR_EL1 fields ─────────────────────────────────────────────────

    #[test]
    fn test_sctlr_m_bit() {
        let f = SCTLR_EL1_FIELDS.iter().find(|f| f.name == "M").unwrap();
        assert_eq!(f.bit, 0);
        // MMU enabled: bit 0 = 1
        assert_eq!(f.get(1), 1);
        assert_eq!(f.get(0), 0);
    }

    #[test]
    fn test_sctlr_i_bit_at_12() {
        let f = SCTLR_EL1_FIELDS.iter().find(|f| f.name == "I").unwrap();
        assert_eq!(f.bit, 12);
    }

    #[test]
    fn test_sctlr_table_count() {
        assert!(SCTLR_EL1_FIELDS.len() >= 20);
    }

    // ── More instruction category tests ───────────────────────────────────

    #[test]
    fn test_arm64_sysreg_encoded_nzcv() {
        let r = arm64_sysreg_lookup("NZCV").unwrap();
        let enc = r.encoded();
        // Just verify encoding is non-zero
        assert!(enc > 0);
    }

    #[test]
    fn test_barrier_options_all_sy() {
        let b = barrier_option_lookup(0xf).unwrap();
        assert_eq!(b.access, "Reads and writes");
    }

    #[test]
    fn test_fp16_normal_val() {
        // 1.0f64 = 0x3FF0000000000000
        assert_eq!(
            FpClass::classify_f64(0x3ff0_0000_0000_0000),
            FpClass::PosNormal
        );
    }

    #[test]
    fn test_add64_nzcv_overflow() {
        // i64::MAX + 1 overflows signed
        let max: u64 = i64::MAX as u64;
        let nzcv = add64_nzcv(max, 1);
        assert!(nzcv.v()); // overflow
        assert!(nzcv.n()); // result is negative in signed interpretation
    }

    #[test]
    fn test_a64_b_offset_negative() {
        // imm26 = 0x3fffffe → -4 (all ones except bit0=0)
        let word: u32 = 0x17ff_ffff; // B #-4
        assert_eq!(a64_b_offset(word), -4);
    }

    #[test]
    fn test_a64_movz_value_hw1() {
        // MOVZ X0, #1, LSL #16 → hw=1 → shift=16 → value=0x10000
        // bits[22:21]=01 (hw=1), bits[20:5]=1 → word: 0b1101_0010_101_00001_00000000000_00000
        // opcode = 0xD2A0_0020
        let word: u32 = 0xd2a0_0020; // hw=1, imm16=1
        let val = a64_movz_value(word);
        assert_eq!(val, 1u64 << 16);
    }

    #[test]
    fn test_ls_prfm_is_not_load() {
        let i = ls_lookup("prfm").unwrap();
        assert!(!i.is_load()); // prefetch is technically a hint
    }

    #[test]
    fn test_simd_addv_reduce() {
        let i = simd_fp_lookup("addv").unwrap();
        assert_eq!(i.class, SimdFpClass::SimdReduce);
    }

    #[test]
    fn test_dp_rbit_count_reverse() {
        let i = dp_lookup("rbit").unwrap();
        assert_eq!(i.class, A64DpClass::CountReverse);
    }

    #[test]
    fn test_a64_ls_uoff_1_byte() {
        // imm12=1 is bit10 set, so word with only bit10 set = 0x400
        // a64_ls_uoff: (word >> 10) & 0xfff = 1; 1 * 1 (size) = 1
        let word: u32 = 0x0000_0400; // bit10=1 → imm12=1
        let off = a64_ls_uoff(word, 1);
        assert_eq!(off, 1);
    }
}

// ---------------------------------------------------------------------------
// AArch64 HW breakpoint / watchpoint descriptor
// ---------------------------------------------------------------------------

/// `AArch64` debug breakpoint / watchpoint descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DebugPointKind {
    /// Instruction address breakpoint.
    Breakpoint,
    /// Data address watchpoint.
    Watchpoint,
    /// Vector-catch (`AArch32` compatible).
    VectorCatch,
}

/// An `AArch64` hardware debug point.
#[derive(Debug, Clone)]
#[must_use]
pub struct DebugPoint {
    /// Index (0–15).
    pub index: u8,
    /// Kind.
    pub kind: DebugPointKind,
    /// Address match value.
    pub address: u64,
    /// Enabled.
    pub enabled: bool,
}

impl DebugPoint {
    /// Create a new disabled debug point.
    pub const fn new(index: u8, kind: DebugPointKind, address: u64) -> Self {
        Self {
            index,
            kind,
            address,
            enabled: false,
        }
    }

    /// Enable this debug point.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this debug point.
    pub const fn disable(&mut self) {
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// AArch64 PMU (Performance Monitor Unit) event table
// ---------------------------------------------------------------------------

/// A Performance Monitor Unit event descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct PmuEvent {
    /// Event number.
    pub number: u16,
    /// Mnemonic.
    pub name: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl PmuEvent {
    const fn new(number: u16, name: &'static str, desc: &'static str) -> Self {
        Self { number, name, desc }
    }
}

/// `AArch64` common PMU events (Arm Cortex-class).
pub static PMU_EVENTS: &[PmuEvent] = &[
    PmuEvent::new(0x0000, "SW_INCR", "Software increment"),
    PmuEvent::new(0x0001, "L1I_CACHE_REFILL", "L1 instruction cache refill"),
    PmuEvent::new(0x0002, "L1I_TLB_REFILL", "L1 instruction TLB refill"),
    PmuEvent::new(0x0003, "L1D_CACHE_REFILL", "L1 data cache refill"),
    PmuEvent::new(0x0004, "L1D_CACHE", "L1 data cache access"),
    PmuEvent::new(0x0005, "L1D_TLB_REFILL", "L1 data TLB refill"),
    PmuEvent::new(
        0x0006,
        "LD_RETIRED",
        "Load instruction architecturally executed",
    ),
    PmuEvent::new(
        0x0007,
        "ST_RETIRED",
        "Store instruction architecturally executed",
    ),
    PmuEvent::new(
        0x0008,
        "INST_RETIRED",
        "Instruction architecturally executed",
    ),
    PmuEvent::new(0x0009, "EXC_TAKEN", "Exception taken"),
    PmuEvent::new(0x000a, "EXC_RETURN", "Exception return"),
    PmuEvent::new(0x000b, "CID_WRITE_RETIRED", "Context ID register write"),
    PmuEvent::new(0x000c, "PC_WRITE_RETIRED", "Software PC change"),
    PmuEvent::new(0x000d, "BR_IMMED_RETIRED", "Immediate branch taken"),
    PmuEvent::new(0x000e, "BR_RETURN_RETIRED", "Function return"),
    PmuEvent::new(0x000f, "UNALIGNED_LDST_RETIRED", "Unaligned memory access"),
    PmuEvent::new(
        0x0010,
        "BR_MIS_PRED",
        "Mispredicted or not-predicted branch",
    ),
    PmuEvent::new(0x0011, "CPU_CYCLES", "CPU cycle"),
    PmuEvent::new(0x0012, "BR_PRED", "Predictable branch"),
    PmuEvent::new(0x0013, "MEM_ACCESS", "Data memory access"),
    PmuEvent::new(0x0014, "L1I_CACHE", "L1 instruction cache access"),
    PmuEvent::new(0x0015, "L1D_CACHE_WB", "L1 data cache write-back"),
    PmuEvent::new(0x0016, "L2D_CACHE", "L2 data cache access"),
    PmuEvent::new(0x0017, "L2D_CACHE_REFILL", "L2 data cache refill"),
    PmuEvent::new(0x0018, "L2D_CACHE_WB", "L2 data cache write-back"),
    PmuEvent::new(0x0019, "BUS_ACCESS", "Bus access"),
    PmuEvent::new(0x001a, "MEMORY_ERROR", "Local memory error"),
    PmuEvent::new(0x001b, "INST_SPEC", "Instruction speculatively executed"),
    PmuEvent::new(0x001c, "TTBR_WRITE_RETIRED", "TTB write"),
    PmuEvent::new(0x001d, "BUS_CYCLES", "Bus cycle"),
    PmuEvent::new(0x001e, "CHAIN", "Odd/even chain"),
    PmuEvent::new(0x001f, "L1D_CACHE_ALLOCATE", "L1 data cache allocation"),
    PmuEvent::new(0x0020, "L2D_CACHE_ALLOCATE", "L2 data cache allocation"),
    PmuEvent::new(0x0021, "BR_RETIRED", "Branch architecturally executed"),
    PmuEvent::new(
        0x0022,
        "BR_MIS_PRED_RETIRED",
        "Mispredicted branch (retired)",
    ),
    PmuEvent::new(0x0023, "STALL_FRONTEND", "Frontend stall cycles"),
    PmuEvent::new(0x0024, "STALL_BACKEND", "Backend stall cycles"),
    PmuEvent::new(0x0025, "L1D_TLB", "L1 data TLB access"),
    PmuEvent::new(0x0026, "L1I_TLB", "L1 instruction TLB access"),
    PmuEvent::new(0x0027, "L2I_CACHE", "L2 instruction cache access"),
    PmuEvent::new(0x0028, "L2I_CACHE_REFILL", "L2 instruction cache refill"),
    PmuEvent::new(0x0029, "L3D_CACHE_ALLOCATE", "L3 data cache allocation"),
    PmuEvent::new(0x002a, "L3D_CACHE_REFILL", "L3 data cache refill"),
    PmuEvent::new(0x002b, "L3D_CACHE", "L3 data cache access"),
    PmuEvent::new(0x002c, "L3D_CACHE_WB", "L3 data cache write-back"),
    PmuEvent::new(0x002d, "L2D_TLB_REFILL", "L2 data TLB refill"),
    PmuEvent::new(0x002e, "L2I_TLB_REFILL", "L2 instruction TLB refill"),
    PmuEvent::new(0x002f, "L2D_TLB", "L2 data TLB access"),
    PmuEvent::new(0x0030, "L2I_TLB", "L2 instruction TLB access"),
    PmuEvent::new(0x0031, "REMOTE_ACCESS", "Access to remote memory"),
    PmuEvent::new(0x0032, "LL_CACHE", "Last-level data cache access"),
    PmuEvent::new(0x0033, "LL_CACHE_MISS", "Last-level data cache miss"),
    PmuEvent::new(0x0034, "DTLB_WALK", "Data TLB walk"),
    PmuEvent::new(0x0035, "ITLB_WALK", "Instruction TLB walk"),
    PmuEvent::new(0x0036, "LL_CACHE_RD", "Last-level cache access, read"),
    PmuEvent::new(0x0037, "LL_CACHE_MISS_RD", "Last-level cache miss, read"),
    PmuEvent::new(0x0038, "REMOTE_ACCESS_RD", "Remote memory access, read"),
    PmuEvent::new(0x003c, "SAMPLE_POP", "Sample population"),
    PmuEvent::new(0x003d, "SAMPLE_FEED", "Sample consumed"),
    PmuEvent::new(0x003e, "SAMPLE_FILTRATE", "Sample post-filtering"),
    PmuEvent::new(0x003f, "SAMPLE_COLLISION", "Sample collided"),
    // Cycle count (fixed)
    PmuEvent::new(0xffff, "FIXED_CYCLE", "Fixed cycle counter"),
];

/// Look up a PMU event by number.
#[must_use]
pub fn pmu_event_lookup(number: u16) -> Option<&'static PmuEvent> {
    PMU_EVENTS.iter().find(|e| e.number == number)
}

// ---------------------------------------------------------------------------
// AArch64 Cortex-A series CPU table
// ---------------------------------------------------------------------------

/// `AArch64` CPU descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Arm64Cpu {
    /// CPU name.
    pub name: &'static str,
    /// Architectural version (e.g. "ARMv8.0-A").
    pub arch_version: &'static str,
    /// MIDR implementer code.
    pub implementer: u8,
    /// MIDR part number.
    pub part_number: u16,
    /// Maximum pipeline width.
    pub pipeline_width: u8,
    /// Brief description.
    pub desc: &'static str,
}

impl Arm64Cpu {
    const fn new(
        name: &'static str,
        arch_version: &'static str,
        implementer: u8,
        part_number: u16,
        pipeline_width: u8,
        desc: &'static str,
    ) -> Self {
        Self {
            name,
            arch_version,
            implementer,
            part_number,
            pipeline_width,
            desc,
        }
    }
}

/// Known `AArch64` CPUs.
pub static ARM64_CPUS: &[Arm64Cpu] = &[
    Arm64Cpu::new(
        "Cortex-A53",
        "ARMv8.0-A",
        0x41,
        0xd03,
        2,
        "In-order, 8-stage pipeline",
    ),
    Arm64Cpu::new(
        "Cortex-A55",
        "ARMv8.2-A",
        0x41,
        0xd05,
        2,
        "In-order with enhanced uarch",
    ),
    Arm64Cpu::new(
        "Cortex-A57",
        "ARMv8.0-A",
        0x41,
        0xd07,
        3,
        "Out-of-order, enterprise class",
    ),
    Arm64Cpu::new(
        "Cortex-A72",
        "ARMv8.0-A",
        0x41,
        0xd08,
        3,
        "Out-of-order, flagship performance",
    ),
    Arm64Cpu::new(
        "Cortex-A73",
        "ARMv8.0-A",
        0x41,
        0xd09,
        2,
        "Efficiency optimized",
    ),
    Arm64Cpu::new(
        "Cortex-A75",
        "ARMv8.2-A",
        0x41,
        0xd0a,
        3,
        "High-performance mobile",
    ),
    Arm64Cpu::new(
        "Cortex-A76",
        "ARMv8.2-A",
        0x41,
        0xd0b,
        4,
        "Desktop-class performance in mobile",
    ),
    Arm64Cpu::new(
        "Cortex-A77",
        "ARMv8.2-A",
        0x41,
        0xd0d,
        4,
        "Enhanced IPC over A76",
    ),
    Arm64Cpu::new(
        "Cortex-A78",
        "ARMv8.2-A",
        0x41,
        0xd41,
        4,
        "Power-efficiency improvements",
    ),
    Arm64Cpu::new(
        "Cortex-A78C",
        "ARMv8.2-A",
        0x41,
        0xd4b,
        4,
        "Client/compute variant",
    ),
    Arm64Cpu::new(
        "Cortex-A710",
        "ARMv9.0-A",
        0x41,
        0xd47,
        5,
        "ARMv9 mainstream core",
    ),
    Arm64Cpu::new(
        "Cortex-A715",
        "ARMv9.0-A",
        0x41,
        0xd4d,
        5,
        "Efficiency-focused ARMv9",
    ),
    Arm64Cpu::new(
        "Cortex-A720",
        "ARMv9.2-A",
        0x41,
        0xd81,
        5,
        "Latest efficiency core",
    ),
    Arm64Cpu::new(
        "Cortex-X1",
        "ARMv8.2-A",
        0x41,
        0xd44,
        5,
        "High-performance prime core",
    ),
    Arm64Cpu::new("Cortex-X2", "ARMv9.0-A", 0x41, 0xd48, 5, "ARMv9 prime core"),
    Arm64Cpu::new(
        "Cortex-X3",
        "ARMv9.0-A",
        0x41,
        0xd4e,
        5,
        "Enhanced ARMv9 prime",
    ),
    Arm64Cpu::new(
        "Neoverse-N1",
        "ARMv8.2-A",
        0x41,
        0xd0c,
        4,
        "Cloud/server optimized",
    ),
    Arm64Cpu::new("Neoverse-N2", "ARMv9.0-A", 0x41, 0xd49, 5, "ARMv9 server"),
    Arm64Cpu::new(
        "Neoverse-V1",
        "ARMv8.4-A",
        0x41,
        0xd40,
        6,
        "HPC-focused server core",
    ),
    Arm64Cpu::new("Neoverse-V2", "ARMv9.0-A", 0x41, 0xd4f, 6, "ARMv9 HPC"),
    Arm64Cpu::new(
        "Apple A14",
        "ARMv8.5-A",
        0x61,
        0x022,
        6,
        "Apple Firestorm/Icestorm",
    ),
    Arm64Cpu::new(
        "Apple M1",
        "ARMv8.5-A",
        0x61,
        0x023,
        8,
        "Apple high-performance desktop",
    ),
    Arm64Cpu::new(
        "Apple M2",
        "ARMv8.6-A",
        0x61,
        0x025,
        8,
        "Apple enhanced M-series",
    ),
    Arm64Cpu::new(
        "Ampere Altra",
        "ARMv8.2-A",
        0xc0,
        0xac3,
        4,
        "Cloud server optimized",
    ),
    Arm64Cpu::new(
        "AWS Graviton3",
        "ARMv9.0-A",
        0xc0,
        0xd40,
        4,
        "AWS custom server",
    ),
];

/// Look up an `AArch64` CPU by its MIDR part number.
#[must_use]
pub fn arm64_cpu_lookup(implementer: u8, part_number: u16) -> Option<&'static Arm64Cpu> {
    ARM64_CPUS
        .iter()
        .find(|c| c.implementer == implementer && c.part_number == part_number)
}

// ---------------------------------------------------------------------------
// AArch64 instruction set extensions lookup
// ---------------------------------------------------------------------------

/// An `AArch64` ISA extension.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct IsaExtension {
    /// Extension name.
    pub name: &'static str,
    /// First architecture that includes it as mandatory.
    pub mandatory_from: &'static str,
    /// Brief description.
    pub desc: &'static str,
}

impl IsaExtension {
    const fn new(name: &'static str, mandatory_from: &'static str, desc: &'static str) -> Self {
        Self {
            name,
            mandatory_from,
            desc,
        }
    }
}

/// `AArch64` ISA extension table.
pub static ISA_EXTENSIONS: &[IsaExtension] = &[
    IsaExtension::new("FEAT_FP", "ARMv8.0", "Floating-point (mandatory)"),
    IsaExtension::new("FEAT_AdvSIMD", "ARMv8.0", "Advanced SIMD (mandatory)"),
    IsaExtension::new("FEAT_CRC32", "ARMv8.0", "CRC32 instructions"),
    IsaExtension::new("FEAT_LSE", "ARMv8.1", "Large System Extensions atomics"),
    IsaExtension::new("FEAT_RDM", "ARMv8.1", "Rounding Double Multiply"),
    IsaExtension::new("FEAT_LOR", "ARMv8.1", "Limited Ordering Regions"),
    IsaExtension::new("FEAT_PAN", "ARMv8.1", "Privileged Access Never"),
    IsaExtension::new("FEAT_VHE", "ARMv8.1", "Virtualization Host Extensions"),
    IsaExtension::new("FEAT_VMID16", "ARMv8.1", "16-bit VMID"),
    IsaExtension::new("FEAT_DotProd", "ARMv8.2", "Dot product instructions"),
    IsaExtension::new("FEAT_FP16", "ARMv8.2", "Half-precision FP"),
    IsaExtension::new("FEAT_SVE", "ARMv8.2", "Scalable Vector Extension"),
    IsaExtension::new("FEAT_IESB", "ARMv8.2", "Implicit Error Sync Barrier"),
    IsaExtension::new("FEAT_LPA", "ARMv8.2", "Larger Physical Address"),
    IsaExtension::new(
        "FEAT_FHM",
        "ARMv8.2",
        "Half-precision FP multiply-accumulate",
    ),
    IsaExtension::new("FEAT_DPB", "ARMv8.2", "DC CVAP instruction"),
    IsaExtension::new("FEAT_JSCVT", "ARMv8.3", "JavaScript conversion"),
    IsaExtension::new("FEAT_PAUTH", "ARMv8.3", "Pointer Authentication"),
    IsaExtension::new("FEAT_LRCPC", "ARMv8.3", "Load-acquire RCpc instructions"),
    IsaExtension::new("FEAT_FCMA", "ARMv8.3", "Complex number multiply"),
    IsaExtension::new("FEAT_SHA3", "ARMv8.4", "SHA-3 cryptography"),
    IsaExtension::new("FEAT_SM3", "ARMv8.4", "SM3 cryptography"),
    IsaExtension::new("FEAT_SM4", "ARMv8.4", "SM4 cryptography"),
    IsaExtension::new("FEAT_DotProd2", "ARMv8.4", "SDOT/UDOT with BFloat16"),
    IsaExtension::new("FEAT_DIT", "ARMv8.4", "Data Independent Timing"),
    IsaExtension::new("FEAT_MPAM", "ARMv8.4", "Memory Partitioning and Monitoring"),
    IsaExtension::new("FEAT_MTE", "ARMv8.5", "Memory Tagging Extension"),
    IsaExtension::new("FEAT_RNG", "ARMv8.5", "Random Number Generation"),
    IsaExtension::new("FEAT_BTI", "ARMv8.5", "Branch Target Identification"),
    IsaExtension::new("FEAT_SB", "ARMv8.5", "Speculation Barrier"),
    IsaExtension::new("FEAT_SSBS", "ARMv8.5", "Speculative Store Bypass Safe"),
    IsaExtension::new("FEAT_BF16", "ARMv8.6", "BFloat16 instructions"),
    IsaExtension::new("FEAT_I8MM", "ARMv8.6", "Int8 matrix multiply"),
    IsaExtension::new("FEAT_ECV", "ARMv8.6", "Enhanced Counter Virtualization"),
    IsaExtension::new("FEAT_MPAM2", "ARMv8.6", "MPAM extensions"),
    IsaExtension::new("FEAT_AFP", "ARMv8.7", "Alternate Float PNaN/infinite"),
    IsaExtension::new("FEAT_RPRES", "ARMv8.7", "Reciprocal/sqrt precision"),
    IsaExtension::new("FEAT_WFxT", "ARMv8.7", "WFE/WFI with timeout"),
    IsaExtension::new("FEAT_HCX", "ARMv8.7", "Extended Hypervisor Config"),
    IsaExtension::new("FEAT_SVE2", "ARMv9.0", "SVE2 instructions"),
    IsaExtension::new("FEAT_SVE_AES", "ARMv9.0", "SVE AES extensions"),
    IsaExtension::new("FEAT_SVE_BitPerm", "ARMv9.0", "SVE Bit Permute"),
    IsaExtension::new("FEAT_SME", "ARMv9.2", "Scalable Matrix Extension"),
    IsaExtension::new("FEAT_SME2", "ARMv9.2", "SME2 extensions"),
    IsaExtension::new("FEAT_MOPS", "ARMv8.8", "Memory operations (CPYFP etc.)"),
    IsaExtension::new("FEAT_GCS", "ARMv9.4", "Guarded Control Stack"),
    IsaExtension::new("FEAT_THE", "ARMv9.4", "Translation Hardening Extension"),
];

/// Look up an ISA extension by name.
#[must_use]
pub fn isa_ext_lookup(name: &str) -> Option<&'static IsaExtension> {
    ISA_EXTENSIONS
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Final comprehensive tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_final2_tests {
    use super::*;

    // ── Debug points ──────────────────────────────────────────────────────

    #[test]
    fn test_debug_point_enable() {
        let mut dp = DebugPoint::new(0, DebugPointKind::Breakpoint, 0x1000);
        assert!(!dp.enabled);
        dp.enable();
        assert!(dp.enabled);
        dp.disable();
        assert!(!dp.enabled);
    }

    // ── PMU events ────────────────────────────────────────────────────────

    #[test]
    fn test_pmu_cpu_cycles() {
        let e = pmu_event_lookup(0x0011).unwrap();
        assert_eq!(e.name, "CPU_CYCLES");
    }

    #[test]
    fn test_pmu_inst_retired() {
        let e = pmu_event_lookup(0x0008).unwrap();
        assert_eq!(e.name, "INST_RETIRED");
    }

    #[test]
    fn test_pmu_missing() {
        assert!(pmu_event_lookup(0x1234).is_none());
    }

    #[test]
    fn test_pmu_table_count() {
        assert!(PMU_EVENTS.len() >= 30);
    }

    // ── CPU table ─────────────────────────────────────────────────────────

    #[test]
    fn test_cpu_cortex_a72() {
        let cpu = arm64_cpu_lookup(0x41, 0xd08).unwrap();
        assert_eq!(cpu.name, "Cortex-A72");
        assert_eq!(cpu.arch_version, "ARMv8.0-A");
    }

    #[test]
    fn test_cpu_apple_m1() {
        let cpu = arm64_cpu_lookup(0x61, 0x023).unwrap();
        assert!(cpu.name.contains("M1"));
    }

    #[test]
    fn test_cpu_missing() {
        assert!(arm64_cpu_lookup(0xff, 0xffff).is_none());
    }

    #[test]
    fn test_cpu_table_count() {
        assert!(ARM64_CPUS.len() >= 10);
    }

    // ── ISA extensions ────────────────────────────────────────────────────

    #[test]
    fn test_isa_ext_lse() {
        let e = isa_ext_lookup("FEAT_LSE").unwrap();
        assert_eq!(e.mandatory_from, "ARMv8.1");
    }

    #[test]
    fn test_isa_ext_pauth() {
        let e = isa_ext_lookup("FEAT_PAUTH").unwrap();
        assert_eq!(e.mandatory_from, "ARMv8.3");
    }

    #[test]
    fn test_isa_ext_sve2() {
        let e = isa_ext_lookup("FEAT_SVE2").unwrap();
        assert_eq!(e.mandatory_from, "ARMv9.0");
    }

    #[test]
    fn test_isa_ext_case_insensitive() {
        assert!(isa_ext_lookup("feat_lse").is_some());
    }

    #[test]
    fn test_isa_ext_missing() {
        assert!(isa_ext_lookup("FEAT_BOGUS").is_none());
    }

    #[test]
    fn test_isa_ext_table_count() {
        assert!(ISA_EXTENSIONS.len() >= 30);
    }

    // ── Additional instruction decode tests ───────────────────────────────

    #[test]
    fn test_a64_b19_offset_cbnz() {
        // CBZ X0, #4 — imm19 at bits[23:5] = 1 → offset = 4
        // word: 0xB400_0020 → bits[23:5] = 1
        let word: u32 = 0xb400_0020; // imm19=1 at bits[23:5]
        assert_eq!(a64_b19_offset(word), 4);
    }

    #[test]
    fn test_a64_add_imm_value_with_shift() {
        // ADD X0,X0,#1,LSL#12 → imm=1, shift=12 → value=4096
        let (_, shift) = a64_add_imm(0x9140_1000); // bit22=1
        assert_eq!(shift, 12);
    }

    #[test]
    fn test_lse_table_has_swp() {
        assert!(lse_lookup("swp").is_some());
    }

    #[test]
    fn test_lse_table_has_ldadd() {
        assert!(lse_lookup("ldadd").is_some());
    }

    #[test]
    fn test_a64_group_dp_reg_2a000000() {
        // OR X0,X0,X0 — bits[28:25]=0b0101
        let word: u32 = 0xaa00_0000;
        assert_eq!(a64_group(word), A64Group::DpReg);
    }

    #[test]
    fn test_a64_group_fp_simd_1f000000() {
        // bits[28:25]=0b0111 → DpFpSimd
        let word: u32 = 0x1f00_0000;
        assert_eq!(a64_group(word), A64Group::DpFpSimd);
    }

    #[test]
    fn test_a64_cond_hi_evaluates() {
        // HI = C && !Z
        // Nzcv bits: bit3=N, bit2=Z, bit1=C, bit0=V
        // 0b0010 → C=1, Z=0, N=0, V=0
        let nzcv = Nzcv(0b0010); // C=1, Z=0
        assert!(A64Cond::Hi.evaluate(nzcv));
    }

    #[test]
    fn test_nzcv_all_set() {
        let nzcv = Nzcv::from_u32(0xf000_0000);
        assert!(nzcv.n() && nzcv.z() && nzcv.c() && nzcv.v());
    }

    #[test]
    fn test_page_base_64k() {
        assert_eq!(page_base_64k(0x1_2345), 0x1_0000);
    }

    #[test]
    fn test_page_offset_64k() {
        assert_eq!(page_offset_64k(0x1_2345), 0x2345);
    }

    #[test]
    fn test_format_sp_64() {
        assert_eq!(format_sp(true), "sp");
    }

    #[test]
    fn test_format_sp_32() {
        assert_eq!(format_sp(false), "wsp");
    }

    #[test]
    fn test_aapcs64_callee_saved_x19() {
        assert_eq!(aapcs64_role(19), Aapcs64Role::CalleeSaved);
        assert_eq!(aapcs64_role(28), Aapcs64Role::CalleeSaved);
    }

    #[test]
    fn test_aapcs64_ip0_ip1() {
        assert_eq!(aapcs64_role(16), Aapcs64Role::IntraProcedureCall);
        assert_eq!(aapcs64_role(17), Aapcs64Role::IntraProcedureCall);
    }

    #[test]
    fn test_aapcs64_platform_x18() {
        assert_eq!(aapcs64_role(18), Aapcs64Role::Platform);
    }

    #[test]
    fn test_a64_features_x1_has_sve() {
        assert!(A64Features::cortex_x1().has(A64Features::SVE));
    }

    #[test]
    fn test_strip_tag_roundtrip() {
        let ptr: u64 = 0x0000_cafe_dead_beef;
        let tagged = set_ptr_tag(ptr, 0xb);
        assert_eq!(get_ptr_tag(tagged), 0xb);
        assert_eq!(strip_ptr_tag(tagged), ptr);
    }
}

// ---------------------------------------------------------------------------
// AArch64 TLB invalidate operation table
// ---------------------------------------------------------------------------

/// An `AArch64` TLBI (TLB Invalidate) operation descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct TlbiOp {
    /// Assembly operand name.
    pub name: &'static str,
    /// Required exception level.
    pub min_el: u8,
    /// Scope description.
    pub scope: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl TlbiOp {
    const fn new(name: &'static str, min_el: u8, scope: &'static str, desc: &'static str) -> Self {
        Self {
            name,
            min_el,
            scope,
            desc,
        }
    }
}

/// `AArch64` TLBI operation table.
pub static TLBI_OPS: &[TlbiOp] = &[
    TlbiOp::new(
        "VMALLE1IS",
        1,
        "inner-shareable",
        "Invalidate all EL1 entries, IS",
    ),
    TlbiOp::new("VMALLE1", 1, "local", "Invalidate all EL1 entries, local"),
    TlbiOp::new(
        "ALLE2IS",
        2,
        "inner-shareable",
        "Invalidate all EL2 entries, IS",
    ),
    TlbiOp::new("ALLE2", 2, "local", "Invalidate all EL2 entries, local"),
    TlbiOp::new(
        "ALLE3IS",
        3,
        "inner-shareable",
        "Invalidate all EL3 entries, IS",
    ),
    TlbiOp::new("ALLE3", 3, "local", "Invalidate all EL3 entries, local"),
    TlbiOp::new("VAE1IS", 1, "inner-shareable", "Invalidate by VA, EL1, IS"),
    TlbiOp::new("VAE1", 1, "local", "Invalidate by VA, EL1, local"),
    TlbiOp::new(
        "ASIDE1IS",
        1,
        "inner-shareable",
        "Invalidate by ASID, EL1, IS",
    ),
    TlbiOp::new("ASIDE1", 1, "local", "Invalidate by ASID, EL1, local"),
    TlbiOp::new(
        "VAAE1IS",
        1,
        "inner-shareable",
        "Invalidate by VA, all ASID, EL1, IS",
    ),
    TlbiOp::new(
        "VAALE1IS",
        1,
        "inner-shareable",
        "Invalidate by VA+level, all ASID, EL1, IS",
    ),
    TlbiOp::new(
        "IPAS2E1IS",
        1,
        "inner-shareable",
        "Invalidate IPA, EL1 stage 2, IS",
    ),
    TlbiOp::new(
        "IPAS2LE1IS",
        1,
        "inner-shareable",
        "Invalidate IPA+level, EL1 stage 2, IS",
    ),
    TlbiOp::new(
        "VMALLS12E1IS",
        1,
        "inner-shareable",
        "Invalidate all EL1/2 stage 1+2, IS",
    ),
    TlbiOp::new(
        "VMALLS12E1",
        1,
        "local",
        "Invalidate all EL1/2 stage 1+2, local",
    ),
    TlbiOp::new("VAE2IS", 2, "inner-shareable", "Invalidate by VA, EL2, IS"),
    TlbiOp::new("VAE2", 2, "local", "Invalidate by VA, EL2, local"),
    TlbiOp::new("VAE3IS", 3, "inner-shareable", "Invalidate by VA, EL3, IS"),
    TlbiOp::new("VAE3", 3, "local", "Invalidate by VA, EL3, local"),
];

/// Look up a TLBI operation by name.
#[must_use]
pub fn tlbi_op_lookup(name: &str) -> Option<&'static TlbiOp> {
    TLBI_OPS
        .iter()
        .find(|op| op.name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// AArch64 data cache operation table
// ---------------------------------------------------------------------------

/// An `AArch64` data cache (DC) operation descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct DcOp {
    /// Operation name.
    pub name: &'static str,
    /// Required EL.
    pub min_el: u8,
    /// Description.
    pub desc: &'static str,
}

impl DcOp {
    const fn new(name: &'static str, min_el: u8, desc: &'static str) -> Self {
        Self { name, min_el, desc }
    }
}

/// `AArch64` DC operation table.
pub static DC_OPS: &[DcOp] = &[
    DcOp::new(
        "IVAC",
        1,
        "Invalidate by VA to PoC (EL1 write permission required)",
    ),
    DcOp::new("ISW", 1, "Invalidate by set/way"),
    DcOp::new("CSW", 1, "Clean by set/way"),
    DcOp::new("CISW", 1, "Clean and Invalidate by set/way"),
    DcOp::new("ZVA", 0, "Zero to PoU"),
    DcOp::new("CVAC", 0, "Clean by VA to PoC"),
    DcOp::new("CVAP", 0, "Clean by VA to PoP (FEAT_DPB)"),
    DcOp::new("CVAU", 0, "Clean by VA to PoU"),
    DcOp::new("CIVAC", 0, "Clean and Invalidate by VA to PoC"),
    DcOp::new("GVA", 0, "Zero GVA to PoU (FEAT_MTE)"),
    DcOp::new("GZVA", 0, "Zero and tag GVA to PoU (FEAT_MTE)"),
    DcOp::new("CGVAC", 0, "Clean+tag by VA to PoC (FEAT_MTE)"),
    DcOp::new("CGVAP", 0, "Clean+tag by VA to PoP (FEAT_MTE, FEAT_DPB)"),
    DcOp::new("CIGVAC", 0, "Clean+Invalidate+tag by VA to PoC (FEAT_MTE)"),
];

/// Look up a DC operation by name.
#[must_use]
pub fn dc_op_lookup(name: &str) -> Option<&'static DcOp> {
    DC_OPS.iter().find(|op| op.name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// AArch64 IC (instruction cache) operation table
// ---------------------------------------------------------------------------

/// An `AArch64` IC operation descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct IcOp {
    /// Operation name.
    pub name: &'static str,
    /// Minimum EL.
    pub min_el: u8,
    /// Description.
    pub desc: &'static str,
}

/// `AArch64` IC operations.
pub static IC_OPS: &[IcOp] = &[
    IcOp {
        name: "IALLUIS",
        min_el: 1,
        desc: "Invalidate all to PoU, inner-shareable",
    },
    IcOp {
        name: "IALLU",
        min_el: 1,
        desc: "Invalidate all to PoU, local",
    },
    IcOp {
        name: "IVAU",
        min_el: 0,
        desc: "Invalidate by VA to PoU",
    },
];

// ---------------------------------------------------------------------------
// Tests for cache/TLB ops
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_cache_tests {
    use super::*;

    #[test]
    fn test_tlbi_vmalle1() {
        let op = tlbi_op_lookup("VMALLE1").unwrap();
        assert_eq!(op.min_el, 1);
    }

    #[test]
    fn test_tlbi_case_insensitive() {
        assert!(tlbi_op_lookup("vmalle1").is_some());
    }

    #[test]
    fn test_tlbi_missing() {
        assert!(tlbi_op_lookup("BOGUS").is_none());
    }

    #[test]
    fn test_tlbi_table_count() {
        assert!(TLBI_OPS.len() >= 10);
    }

    #[test]
    fn test_dc_zva_el0() {
        let op = dc_op_lookup("ZVA").unwrap();
        assert_eq!(op.min_el, 0);
    }

    #[test]
    fn test_dc_isw_el1() {
        let op = dc_op_lookup("ISW").unwrap();
        assert_eq!(op.min_el, 1);
    }

    #[test]
    fn test_dc_missing() {
        assert!(dc_op_lookup("BOGUS").is_none());
    }

    #[test]
    fn test_ic_ops_count() {
        assert_eq!(IC_OPS.len(), 3);
    }

    #[test]
    fn test_ic_ivau_el0() {
        let op = IC_OPS.iter().find(|o| o.name == "IVAU").unwrap();
        assert_eq!(op.min_el, 0);
    }

    // More ISA/CPU tests for coverage
    #[test]
    fn test_isa_ext_fp_mandatory() {
        let e = isa_ext_lookup("FEAT_FP").unwrap();
        assert_eq!(e.mandatory_from, "ARMv8.0");
    }

    #[test]
    fn test_isa_ext_sve_v8_2() {
        let e = isa_ext_lookup("FEAT_SVE").unwrap();
        assert_eq!(e.mandatory_from, "ARMv8.2");
    }

    #[test]
    fn test_cpu_neoverse_n1() {
        let cpu = arm64_cpu_lookup(0x41, 0xd0c).unwrap();
        assert_eq!(cpu.name, "Neoverse-N1");
    }

    #[test]
    fn test_simd_sha1c_crypto() {
        let i = simd_fp_lookup("sha1c").unwrap();
        assert_eq!(i.class, SimdFpClass::SimdCrypto);
    }

    #[test]
    fn test_dp_ubfx_bitfield() {
        let i = dp_lookup("ubfx").unwrap();
        assert_eq!(i.class, A64DpClass::BitField);
    }

    #[test]
    fn test_ls_ldar_load_acquire() {
        let i = ls_lookup("ldar").unwrap();
        assert!(i.is_load());
        assert!(!i.is_exclusive());
    }

    #[test]
    fn test_sctlr_mmu_bit() {
        let f = SCTLR_EL1_FIELDS.iter().find(|f| f.name == "M").unwrap();
        assert_eq!(f.reset, 0); // MMU disabled at reset
    }

    #[test]
    fn test_tcr_as_bit_extract() {
        let f = TCR_EL1_FIELDS.iter().find(|f| f.name == "AS").unwrap();
        // 16-bit ASID: bit 36 set in TCR
        assert_eq!(f.extract(1u64 << 36), 1);
    }

    #[test]
    fn test_mem_attr_normal_wt() {
        assert!(MemAttr::NORMAL_WT.is_normal());
        assert_eq!(MemAttr::NORMAL_WT.description(), "Normal WT non-transient");
    }

    #[test]
    fn test_fpscr_fz16_exists() {
        let f = FPCR_FIELDS.iter().find(|f| f.name == "FZ16");
        assert!(f.is_some());
    }

    #[test]
    fn test_a64_b14_offset_tbz() {
        // TBZ with imm14=1 → offset=4
        // imm14 is bits[18:5], so bit5=1 means imm14=1 (shifted right 5)
        // word with only bit5 set = 0x20
        let word: u32 = 0x0000_0020; // bit5=1 → imm14=1 → offset=4
        assert_eq!(a64_b14_offset(word), 4);
    }
}

// ---------------------------------------------------------------------------
// AArch64 AT (Address Translate) operation table
// ---------------------------------------------------------------------------

/// An `AArch64` AT (address translate) operation.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct AtOp {
    /// Operation name.
    pub name: &'static str,
    /// Required EL.
    pub min_el: u8,
    /// Translation regime.
    pub regime: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl AtOp {
    const fn new(name: &'static str, min_el: u8, regime: &'static str, desc: &'static str) -> Self {
        Self {
            name,
            min_el,
            regime,
            desc,
        }
    }
}

/// `AArch64` AT operations.
pub static AT_OPS: &[AtOp] = &[
    AtOp::new("S1E1R", 1, "EL1 read", "Stage 1 EL1 translation, read"),
    AtOp::new("S1E1W", 1, "EL1 write", "Stage 1 EL1 translation, write"),
    AtOp::new("S1E0R", 1, "EL0 read", "Stage 1 EL0 translation, read"),
    AtOp::new("S1E0W", 1, "EL0 write", "Stage 1 EL0 translation, write"),
    AtOp::new(
        "S12E1R",
        2,
        "EL1 read, stages",
        "Stage 1&2 EL1 translation, read",
    ),
    AtOp::new(
        "S12E1W",
        2,
        "EL1 write, stages",
        "Stage 1&2 EL1 translation, write",
    ),
    AtOp::new(
        "S12E0R",
        2,
        "EL0 read, stages",
        "Stage 1&2 EL0 translation, read",
    ),
    AtOp::new(
        "S12E0W",
        2,
        "EL0 write, stages",
        "Stage 1&2 EL0 translation, write",
    ),
    AtOp::new("S1E2R", 2, "EL2 read", "Stage 1 EL2 translation, read"),
    AtOp::new("S1E2W", 2, "EL2 write", "Stage 1 EL2 translation, write"),
    AtOp::new("S1E3R", 3, "EL3 read", "Stage 1 EL3 translation, read"),
    AtOp::new("S1E3W", 3, "EL3 write", "Stage 1 EL3 translation, write"),
    AtOp::new(
        "S1E1RP",
        1,
        "EL1 read+PAN",
        "Stage 1 EL1 translation, read (FEAT_PAN)",
    ),
    AtOp::new(
        "S1E1WP",
        1,
        "EL1 write+PAN",
        "Stage 1 EL1 translation, write (FEAT_PAN)",
    ),
];

/// Look up an AT operation by name.
#[must_use]
pub fn at_op_lookup(name: &str) -> Option<&'static AtOp> {
    AT_OPS.iter().find(|op| op.name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// AArch64 HINT instruction encodings
// ---------------------------------------------------------------------------

/// `AArch64` HINT instruction.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct HintInstr {
    /// CRm:op2 field value.
    pub encoding: u8,
    /// Mnemonic (or "hint #N").
    pub mnemonic: &'static str,
    /// Description.
    pub desc: &'static str,
}

impl HintInstr {
    const fn new(encoding: u8, mnemonic: &'static str, desc: &'static str) -> Self {
        Self {
            encoding,
            mnemonic,
            desc,
        }
    }
}

/// `AArch64` hint instruction encodings.
pub static HINT_INSTRS: &[HintInstr] = &[
    HintInstr::new(0, "nop", "No operation"),
    HintInstr::new(1, "yield", "Yield"),
    HintInstr::new(2, "wfe", "Wait for event"),
    HintInstr::new(3, "wfi", "Wait for interrupt"),
    HintInstr::new(4, "sev", "Send event"),
    HintInstr::new(5, "sevl", "Send event, local"),
    HintInstr::new(6, "dgh", "Hint for data gathering (FEAT_DGH)"),
    HintInstr::new(7, "xpaclri", "Strip PAC from LR (FEAT_PAuth)"),
    HintInstr::new(8, "pacia1716", "PAC IA using key A, X17, X16"),
    HintInstr::new(10, "pacib1716", "PAC IB using key B, X17, X16"),
    HintInstr::new(12, "autia1716", "Auth IA using key A, X17, X16"),
    HintInstr::new(14, "autib1716", "Auth IB using key B, X17, X16"),
    HintInstr::new(24, "paciasp", "PAC IA using key A, SP"),
    HintInstr::new(25, "autiasp", "Auth IA using key A, SP"),
    HintInstr::new(26, "pacibsp", "PAC IB using key B, SP"),
    HintInstr::new(27, "autibsp", "Auth IB using key B, SP"),
    HintInstr::new(28, "bti", "Branch target identification (FEAT_BTI)"),
    HintInstr::new(32, "esb", "Error synchronization barrier (FEAT_RAS)"),
    HintInstr::new(33, "psb csync", "Profiling sync barrier (FEAT_SPE)"),
    HintInstr::new(34, "tsb csync", "Trace sync barrier (FEAT_TRF)"),
    HintInstr::new(36, "csdb", "Consumption of speculative data barrier"),
];

/// Look up a HINT instruction by encoding.
#[must_use]
pub fn hint_lookup(encoding: u8) -> Option<&'static HintInstr> {
    HINT_INSTRS.iter().find(|h| h.encoding == encoding)
}

// ---------------------------------------------------------------------------
// AArch64 additional branch classification helpers
// ---------------------------------------------------------------------------

/// Returns `true` if an A64 instruction word is a BL (direct call).
#[must_use]
pub const fn is_bl(word: u32) -> bool {
    // BL: bits[31:26] = 100101
    (word >> 26) & 0x3f == 0b10_0101
}

/// Returns `true` if an A64 instruction word is a B (direct branch).
#[must_use]
pub const fn is_b(word: u32) -> bool {
    // B: bits[31:26] = 000101
    (word >> 26) & 0x3f == 0b00_0101
}

/// Returns `true` if an A64 instruction word is a CBZ (compare and branch zero).
#[must_use]
pub const fn is_cbz(word: u32) -> bool {
    // CBZ: bits[31:24] = 0B4 or 34 (32 vs 64 bit Rt)
    let op = (word >> 24) & 0xff;
    op == 0xb4 || op == 0x34
}

/// Returns `true` if an A64 instruction word is a CBNZ.
#[must_use]
pub const fn is_cbnz(word: u32) -> bool {
    let op = (word >> 24) & 0xff;
    op == 0xb5 || op == 0x35
}

/// Returns `true` if an A64 instruction word is a RET.
#[must_use]
pub const fn is_ret(word: u32) -> bool {
    // RET: 0xD65F_0000 | (Rn << 5) where Rn defaults to x30
    (word & 0xffff_fc1f) == 0xd65f_0000
}

/// Returns `true` if an A64 instruction word is a BLR (indirect call).
#[must_use]
pub const fn is_blr(word: u32) -> bool {
    (word & 0xffff_fc1f) == 0xd63f_0000
}

/// Returns `true` if an A64 instruction word is a BR (indirect branch).
#[must_use]
pub const fn is_br(word: u32) -> bool {
    (word & 0xffff_fc1f) == 0xd61f_0000
}

// ---------------------------------------------------------------------------
// AArch64 PRFM (Prefetch) option helpers
// ---------------------------------------------------------------------------

/// `AArch64` prefetch type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PrfType {
    /// Prefetch for load.
    Pldl1Keep,
    Pldl1Strm,
    Pldl2Keep,
    Pldl2Strm,
    Pldl3Keep,
    Pldl3Strm,
    /// Prefetch for instruction.
    Plil1Keep,
    Plil1Strm,
    Plil2Keep,
    Plil2Strm,
    Plil3Keep,
    Plil3Strm,
    /// Prefetch for store.
    Pstl1Keep,
    Pstl1Strm,
    Pstl2Keep,
    Pstl2Strm,
    Pstl3Keep,
    Pstl3Strm,
}

impl PrfType {
    /// Encode to 5-bit immediate.
    #[must_use]
    pub const fn encode(self) -> u8 {
        match self {
            Self::Pldl1Keep => 0x00,
            Self::Pldl1Strm => 0x01,
            Self::Pldl2Keep => 0x02,
            Self::Pldl2Strm => 0x03,
            Self::Pldl3Keep => 0x04,
            Self::Pldl3Strm => 0x05,
            Self::Plil1Keep => 0x08,
            Self::Plil1Strm => 0x09,
            Self::Plil2Keep => 0x0a,
            Self::Plil2Strm => 0x0b,
            Self::Plil3Keep => 0x0c,
            Self::Plil3Strm => 0x0d,
            Self::Pstl1Keep => 0x10,
            Self::Pstl1Strm => 0x11,
            Self::Pstl2Keep => 0x12,
            Self::Pstl2Strm => 0x13,
            Self::Pstl3Keep => 0x14,
            Self::Pstl3Strm => 0x15,
        }
    }
}

// ---------------------------------------------------------------------------
// Final cache/misc tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_misc_tests {
    use super::*;

    // ── AT operations ─────────────────────────────────────────────────────

    #[test]
    fn test_at_s1e1r() {
        let op = at_op_lookup("S1E1R").unwrap();
        assert_eq!(op.min_el, 1);
    }

    #[test]
    fn test_at_s1e3w_el3() {
        let op = at_op_lookup("S1E3W").unwrap();
        assert_eq!(op.min_el, 3);
    }

    #[test]
    fn test_at_case_insensitive() {
        assert!(at_op_lookup("s1e1r").is_some());
    }

    #[test]
    fn test_at_table_count() {
        assert!(AT_OPS.len() >= 10);
    }

    // ── HINT instructions ─────────────────────────────────────────────────

    #[test]
    fn test_hint_nop() {
        let h = hint_lookup(0).unwrap();
        assert_eq!(h.mnemonic, "nop");
    }

    #[test]
    fn test_hint_wfi() {
        let h = hint_lookup(3).unwrap();
        assert_eq!(h.mnemonic, "wfi");
    }

    #[test]
    fn test_hint_paciasp() {
        let h = hint_lookup(24).unwrap();
        assert_eq!(h.mnemonic, "paciasp");
    }

    #[test]
    fn test_hint_bti() {
        let h = hint_lookup(28).unwrap();
        assert_eq!(h.mnemonic, "bti");
    }

    #[test]
    fn test_hint_table_count() {
        assert!(HINT_INSTRS.len() >= 10);
    }

    // ── Branch detection helpers ──────────────────────────────────────────

    #[test]
    fn test_is_bl_true() {
        assert!(is_bl(0x9400_0001));
    }

    #[test]
    fn test_is_bl_false_b() {
        assert!(!is_bl(0x1400_0001));
    }

    #[test]
    fn test_is_b_true() {
        assert!(is_b(0x1400_0001));
    }

    #[test]
    fn test_is_cbz_64bit() {
        // CBZ X0, #8: 0xB400_0040
        assert!(is_cbz(0xb400_0040));
    }

    #[test]
    fn test_is_cbz_32bit() {
        // CBZ W0: 0x3400_0040
        assert!(is_cbz(0x3400_0040));
    }

    #[test]
    fn test_is_cbnz() {
        assert!(is_cbnz(0xb500_0001));
    }

    #[test]
    fn test_is_ret_x30() {
        // RET = 0xD65F_03C0
        assert!(is_ret(0xd65f_03c0));
    }

    #[test]
    fn test_is_blr_x0() {
        // BLR X0 = 0xD63F_0000
        assert!(is_blr(0xd63f_0000));
    }

    #[test]
    fn test_is_br_x0() {
        // BR X0 = 0xD61F_0000
        assert!(is_br(0xd61f_0000));
    }

    #[test]
    fn test_is_br_false_blr() {
        assert!(!is_br(0xd63f_0000));
    }

    // ── PRFM types ────────────────────────────────────────────────────────

    #[test]
    fn test_prfm_pldl1keep_encode() {
        assert_eq!(PrfType::Pldl1Keep.encode(), 0x00);
    }

    #[test]
    fn test_prfm_pstl1keep_encode() {
        assert_eq!(PrfType::Pstl1Keep.encode(), 0x10);
    }
}

// ---------------------------------------------------------------------------
// AArch64 instruction size helpers
// ---------------------------------------------------------------------------

/// Returns the size in bytes of the data accessed by a load/store instruction.
/// Based on the opcode/opc field (bits[31:30] in most LS variants).
#[must_use]
pub const fn ls_data_size_bits(size_field: u8) -> u8 {
    match size_field & 0x3 {
        0 => 8,
        1 => 16,
        2 => 32,
        _ => 64,
    }
}

/// Returns the number of bytes corresponding to a size-field value.
#[must_use]
pub const fn ls_data_size_bytes(size_field: u8) -> u8 {
    ls_data_size_bits(size_field) / 8
}

// ---------------------------------------------------------------------------
// AArch64 shift extend type encode/decode
// ---------------------------------------------------------------------------

/// `AArch64` shift type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum A64Shift {
    /// Logical shift left.
    Lsl,
    /// Logical shift right.
    Lsr,
    /// Arithmetic shift right.
    Asr,
    /// Rotate right.
    Ror,
}

impl A64Shift {
    /// Decode from 2-bit field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x3 {
            0 => Some(Self::Lsl),
            1 => Some(Self::Lsr),
            2 => Some(Self::Asr),
            3 => Some(Self::Ror),
            _ => None,
        }
    }

    /// Assembly mnemonic.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Lsl => "lsl",
            Self::Lsr => "lsr",
            Self::Asr => "asr",
            Self::Ror => "ror",
        }
    }
}

/// `AArch64` extend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum A64Extend {
    /// Unsigned extend byte.
    Uxtb,
    /// Unsigned extend halfword.
    Uxth,
    /// Unsigned extend word (LSL for 64-bit registers).
    Uxtw,
    /// Unsigned extend doubleword.
    Uxtx,
    /// Signed extend byte.
    Sxtb,
    /// Signed extend halfword.
    Sxth,
    /// Signed extend word.
    Sxtw,
    /// Signed extend doubleword.
    Sxtx,
}

impl A64Extend {
    /// Decode from 3-bit field.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x7 {
            0 => Self::Uxtb,
            1 => Self::Uxth,
            2 => Self::Uxtw,
            3 => Self::Uxtx,
            4 => Self::Sxtb,
            5 => Self::Sxth,
            6 => Self::Sxtw,
            _ => Self::Sxtx,
        }
    }

    /// Assembly mnemonic.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Uxtb => "uxtb",
            Self::Uxth => "uxth",
            Self::Uxtw => "uxtw",
            Self::Uxtx => "uxtx",
            Self::Sxtb => "sxtb",
            Self::Sxth => "sxth",
            Self::Sxtw => "sxtw",
            Self::Sxtx => "sxtx",
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64 FPSR bit fields
// ---------------------------------------------------------------------------

/// `AArch64` FPSR field descriptor.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct FpsrField {
    /// Field name.
    pub name: &'static str,
    /// Bit position.
    pub bit: u8,
    /// Description.
    pub desc: &'static str,
}

impl FpsrField {
    const fn new(name: &'static str, bit: u8, desc: &'static str) -> Self {
        Self { name, bit, desc }
    }

    /// Extract bit from FPSR.
    #[must_use]
    pub const fn get(self, fpsr: u64) -> u8 {
        ((fpsr >> self.bit) & 1) as u8
    }
}

/// `AArch64` FPSR fields.
pub static FPSR_FIELDS: &[FpsrField] = &[
    FpsrField::new("IOC", 0, "Invalid operation cumulative flag"),
    FpsrField::new("DZC", 1, "Division-by-zero cumulative flag"),
    FpsrField::new("OFC", 2, "Overflow cumulative flag"),
    FpsrField::new("UFC", 3, "Underflow cumulative flag"),
    FpsrField::new("IXC", 4, "Inexact cumulative flag"),
    FpsrField::new("IDC", 7, "Input denormal cumulative flag"),
    FpsrField::new("QC", 27, "Cumulative saturation flag"),
    FpsrField::new("V", 28, "Overflow condition flag (copy of NZCV.V)"),
    FpsrField::new("C", 29, "Carry condition flag (copy of NZCV.C)"),
    FpsrField::new("Z", 30, "Zero condition flag (copy of NZCV.Z)"),
    FpsrField::new("N", 31, "Negative condition flag (copy of NZCV.N)"),
];

// ---------------------------------------------------------------------------
// Shift/extend + FPSR tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_shift_tests {
    use super::*;

    #[test]
    fn test_ls_data_size_bits() {
        assert_eq!(ls_data_size_bits(0), 8);
        assert_eq!(ls_data_size_bits(1), 16);
        assert_eq!(ls_data_size_bits(2), 32);
        assert_eq!(ls_data_size_bits(3), 64);
    }

    #[test]
    fn test_ls_data_size_bytes() {
        assert_eq!(ls_data_size_bytes(3), 8);
    }

    #[test]
    fn test_a64_shift_from_bits() {
        assert_eq!(A64Shift::from_bits(0), Some(A64Shift::Lsl));
        assert_eq!(A64Shift::from_bits(2), Some(A64Shift::Asr));
        assert_eq!(A64Shift::from_bits(3), Some(A64Shift::Ror));
    }

    #[test]
    fn test_a64_shift_mnemonic() {
        assert_eq!(A64Shift::Lsl.mnemonic(), "lsl");
        assert_eq!(A64Shift::Ror.mnemonic(), "ror");
    }

    #[test]
    fn test_a64_extend_from_bits() {
        assert_eq!(A64Extend::from_bits(0), A64Extend::Uxtb);
        assert_eq!(A64Extend::from_bits(6), A64Extend::Sxtw);
    }

    #[test]
    fn test_a64_extend_mnemonic() {
        assert_eq!(A64Extend::Sxtw.mnemonic(), "sxtw");
        assert_eq!(A64Extend::Uxtb.mnemonic(), "uxtb");
    }

    #[test]
    fn test_fpsr_qc_bit() {
        let f = FPSR_FIELDS.iter().find(|f| f.name == "QC").unwrap();
        assert_eq!(f.get(1u64 << 27), 1);
    }

    #[test]
    fn test_fpsr_ioc_bit() {
        let f = FPSR_FIELDS.iter().find(|f| f.name == "IOC").unwrap();
        assert_eq!(f.get(1), 1);
        assert_eq!(f.get(0), 0);
    }

    #[test]
    fn test_fpsr_table_count() {
        assert!(FPSR_FIELDS.len() >= 5);
    }
}

// ---------------------------------------------------------------------------
// AArch64 reserved registers and special names
// ---------------------------------------------------------------------------

/// The 16 special-purpose register names for `AArch64`.
pub static ARM64_SPECIAL_REGS: &[(&str, &str)] = &[
    ("sp", "Stack Pointer"),
    ("pc", "Program Counter"),
    ("xzr", "64-bit zero register"),
    ("wzr", "32-bit zero register"),
    ("fp", "Frame Pointer (alias x29)"),
    ("lr", "Link Register (alias x30)"),
    ("nzcv", "Condition Flags"),
    ("fpcr", "Floating-point Control Register"),
    ("fpsr", "Floating-point Status Register"),
    ("daif", "Debug/SError/IRQ/FIQ mask"),
    ("spsel", "Stack Pointer Select"),
    ("currentel", "Current Exception Level"),
    ("wsp", "32-bit stack pointer alias"),
    ("ip0", "Intra-Procedure-Call scratch 0 (alias x16)"),
    ("ip1", "Intra-Procedure-Call scratch 1 (alias x17)"),
    ("x18", "Platform register (reserved on some OSes)"),
];

// ---------------------------------------------------------------------------
// AArch64 VHE (Virtualization Host Extensions) helpers
// ---------------------------------------------------------------------------

/// Returns `true` if VHE is enabled based on `HCR_EL2.E2H` bit.
#[must_use]
pub const fn vhe_enabled(hcr_el2: u64) -> bool {
    (hcr_el2 >> 34) & 1 != 0
}

/// Returns the effective SCTLR register name for the current VHE mode.
#[must_use]
pub const fn effective_sctlr(vhe: bool) -> &'static str {
    if vhe { "SCTLR_EL12" } else { "SCTLR_EL1" }
}

// ---------------------------------------------------------------------------
// AArch64 DAIF mask helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the D (debug) exception mask is set in DAIF.
#[must_use]
pub const fn daif_d(daif: u64) -> bool {
    (daif >> 9) & 1 != 0
}

/// Returns `true` if the A (`SError`) exception mask is set in DAIF.
#[must_use]
pub const fn daif_a(daif: u64) -> bool {
    (daif >> 8) & 1 != 0
}

/// Returns `true` if the I (IRQ) exception mask is set in DAIF.
#[must_use]
pub const fn daif_i(daif: u64) -> bool {
    (daif >> 7) & 1 != 0
}

/// Returns `true` if the F (FIQ) exception mask is set in DAIF.
#[must_use]
pub const fn daif_f(daif: u64) -> bool {
    (daif >> 6) & 1 != 0
}

// ---------------------------------------------------------------------------
// Tests for final helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arm64_final3_tests {
    use super::*;

    #[test]
    fn test_special_regs_table() {
        assert!(ARM64_SPECIAL_REGS.iter().any(|(n, _)| *n == "sp"));
        assert!(ARM64_SPECIAL_REGS.iter().any(|(n, _)| *n == "xzr"));
    }

    #[test]
    fn test_vhe_enabled_true() {
        let hcr: u64 = 1u64 << 34;
        assert!(vhe_enabled(hcr));
    }

    #[test]
    fn test_vhe_enabled_false() {
        assert!(!vhe_enabled(0));
    }

    #[test]
    fn test_effective_sctlr_vhe() {
        assert_eq!(effective_sctlr(true), "SCTLR_EL12");
        assert_eq!(effective_sctlr(false), "SCTLR_EL1");
    }

    #[test]
    fn test_daif_all_masked() {
        // DAIF: bits [9:6] = D=1, A=1, I=1, F=1 → 0b1111 << 6 = 0x3C0
        let daif: u64 = 0x3C0;
        assert!(daif_d(daif));
        assert!(daif_a(daif));
        assert!(daif_i(daif));
        assert!(daif_f(daif));
    }

    #[test]
    fn test_daif_none_masked() {
        assert!(!daif_d(0));
        assert!(!daif_i(0));
    }

    #[test]
    fn test_a64_instr_decode_add() {
        let arch = Arm64Arch::new();
        // ADD X0, X0, #0 = 0x9100_0000
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x91];
        let i = arch
            .disassemble(rustre_core::address::Address::new(0), bytes)
            .unwrap();
        assert_eq!(i.mnemonic, "add");
        assert_eq!(i.flags, InstrFlags::NONE);
    }

    #[test]
    fn test_a64_instr_decode_sub() {
        let arch = Arm64Arch::new();
        // SUB X0, X0, #0 = 0xD100_0000
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0xd1];
        let i = arch
            .disassemble(rustre_core::address::Address::new(0), bytes)
            .unwrap();
        assert_eq!(i.mnemonic, "sub");
    }

    #[test]
    fn test_extend_sxtb_index0() {
        assert_eq!(A64Extend::from_bits(4), A64Extend::Sxtb);
    }

    #[test]
    fn test_shift_lsr_index1() {
        assert_eq!(A64Shift::from_bits(1), Some(A64Shift::Lsr));
        assert_eq!(A64Shift::Lsr.mnemonic(), "lsr");
    }
}

// ---------------------------------------------------------------------------
// AArch64 architecture version string
// ---------------------------------------------------------------------------

/// Return the architecture version string for a given feature set.
#[must_use]
pub const fn arch_version_str(features: A64Features) -> &'static str {
    if features.has(A64Features::SME) {
        return "ARMv9.2-A";
    }
    if features.has(A64Features::SVE2) {
        return "ARMv9.0-A";
    }
    if features.has(A64Features::MTE) {
        return "ARMv8.5-A";
    }
    if features.has(A64Features::BTI) {
        return "ARMv8.5-A";
    }
    if features.has(A64Features::SVE) {
        return "ARMv8.2-A";
    }
    if features.has(A64Features::LSE) {
        return "ARMv8.1-A";
    }
    "ARMv8.0-A"
}

// ---------------------------------------------------------------------------
// AArch64 arithmetic helpers
// ---------------------------------------------------------------------------

/// Sign-extend a value from `bits` wide to 64 bits.
#[must_use]
pub fn sign_extend(val: u64, bits: u8) -> i64 {
    debug_assert!(bits > 0 && bits <= 64);
    if bits == 64 {
        return val.cast_signed();
    }
    let sign_bit = 1u64 << (bits - 1);
    if val & sign_bit != 0 {
        (val | (u64::MAX << bits)).cast_signed()
    } else {
        val.cast_signed()
    }
}

/// Zero-extend a value from `bits` wide to 64 bits.
#[must_use]
pub const fn zero_extend(val: u64, bits: u8) -> u64 {
    if bits >= 64 {
        return val;
    }
    val & ((1u64 << bits) - 1)
}

#[cfg(test)]
mod arm64_arithmetic_tests {
    use super::*;

    #[test]
    fn test_sign_extend_positive() {
        // 8-bit 0x7f = 127 positive
        assert_eq!(sign_extend(0x7f, 8), 127);
    }

    #[test]
    fn test_sign_extend_negative() {
        // 8-bit 0x80 = -128 in signed
        assert_eq!(sign_extend(0x80, 8), -128);
    }

    #[test]
    fn test_zero_extend() {
        assert_eq!(zero_extend(0xff, 8), 0xff);
        assert_eq!(zero_extend(0x1ff, 8), 0xff);
    }

    #[test]
    fn test_arch_version_lse() {
        let f = A64Features::LSE;
        assert_eq!(arch_version_str(f), "ARMv8.1-A");
    }

    #[test]
    fn test_arch_version_sve2() {
        let f = A64Features::SVE2;
        assert_eq!(arch_version_str(f), "ARMv9.0-A");
    }

    #[test]
    fn test_arch_version_baseline() {
        assert_eq!(arch_version_str(A64Features::empty()), "ARMv8.0-A");
    }

    #[test]
    fn test_hint_csdb() {
        let h = hint_lookup(36).unwrap();
        assert_eq!(h.mnemonic, "csdb");
    }

    #[test]
    fn test_at_ops_table_count() {
        assert!(AT_OPS.len() >= 12);
    }

    #[test]
    fn test_arm64_special_regs_count() {
        assert!(ARM64_SPECIAL_REGS.len() >= 10);
    }
}

// ── AArch64 data-processing instruction encodings ──────────────────────────

/// Describes the shift amount for a shifted-register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegShiftKind {
    /// Logical shift left.
    Lsl,
    /// Logical shift right.
    Lsr,
    /// Arithmetic shift right.
    Asr,
    /// Rotate right (only valid in some contexts).
    Ror,
}

impl RegShiftKind {
    /// Return the two-bit encoding for use in `AArch64` shifted-register fields.
    #[must_use]
    pub const fn encode(self) -> u8 {
        match self {
            Self::Lsl => 0,
            Self::Lsr => 1,
            Self::Asr => 2,
            Self::Ror => 3,
        }
    }

    /// Decode from two-bit field.
    #[must_use]
    pub const fn decode(bits: u8) -> Self {
        match bits & 0x3 {
            0 => Self::Lsl,
            1 => Self::Lsr,
            2 => Self::Asr,
            _ => Self::Ror,
        }
    }

    /// Return the assembler mnemonic string.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Lsl => "lsl",
            Self::Lsr => "lsr",
            Self::Asr => "asr",
            Self::Ror => "ror",
        }
    }
}

/// Describes an extend kind for extended-register addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegExtendKind {
    /// Unsigned extend byte.
    Uxtb,
    /// Unsigned extend halfword.
    Uxth,
    /// Unsigned extend word.
    Uxtw,
    /// Unsigned extend doubleword (identity).
    Uxtx,
    /// Signed extend byte.
    Sxtb,
    /// Signed extend halfword.
    Sxth,
    /// Signed extend word.
    Sxtw,
    /// Signed extend doubleword.
    Sxtx,
}

impl RegExtendKind {
    /// Decode from three-bit option field.
    #[must_use]
    pub const fn decode(option: u8) -> Self {
        match option & 0x7 {
            0 => Self::Uxtb,
            1 => Self::Uxth,
            2 => Self::Uxtw,
            3 => Self::Uxtx,
            4 => Self::Sxtb,
            5 => Self::Sxth,
            6 => Self::Sxtw,
            _ => Self::Sxtx,
        }
    }

    /// Return the assembler mnemonic string.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Uxtb => "uxtb",
            Self::Uxth => "uxth",
            Self::Uxtw => "uxtw",
            Self::Uxtx => "uxtx",
            Self::Sxtb => "sxtb",
            Self::Sxth => "sxth",
            Self::Sxtw => "sxtw",
            Self::Sxtx => "sxtx",
        }
    }

    /// Returns `true` if this is a signed extension.
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(self, Self::Sxtb | Self::Sxth | Self::Sxtw | Self::Sxtx)
    }

    /// Width in bits of the source before extension.
    #[must_use]
    pub const fn source_bits(self) -> u8 {
        match self {
            Self::Uxtb | Self::Sxtb => 8,
            Self::Uxth | Self::Sxth => 16,
            Self::Uxtw | Self::Sxtw => 32,
            Self::Uxtx | Self::Sxtx => 64,
        }
    }
}

// ── AArch64 condition code tables ──────────────────────────────────────────

/// Maps each of the 16 `AArch64` condition codes to its inverse.
pub static COND_INVERSE: [(u8, u8); 8] = [
    (0, 1),   // EQ / NE
    (2, 3),   // CS / CC
    (4, 5),   // MI / PL
    (6, 7),   // VS / VC
    (8, 9),   // HI / LS
    (10, 11), // GE / LT
    (12, 13), // GT / LE
    (14, 15), // AL / NV
];

/// Return the inverse (logical NOT) of an `AArch64` condition-code value.
///
/// The inverse is obtained by flipping bit 0, except `AL` (14) stays `AL`.
#[must_use]
pub const fn cond_inverse(cond: u8) -> u8 {
    if cond == 14 { 14 } else { cond ^ 1 }
}

// ── AArch64 immediate helper functions ─────────────────────────────────────

/// Decode a `bitmask immediate` value for logical instructions.
///
/// Returns the 64-bit pattern or `None` if the encoding is reserved.
///
/// # Errors
///
/// Returns `None` when the combination of `n`, `rot`, and `size_field` is a
/// reserved encoding for the given `reg_size`.
#[must_use]
pub fn decode_bitmask(n: u8, rot: u8, size_field: u8, reg_size: u8) -> Option<u64> {
    decode_logical_imm(n, rot, size_field, reg_size)
}

/// Decode an unsigned 12-bit immediate shifted left by `shift` bits.
///
/// `shift` must be 0 or 12. Returns `None` for other shift values.
#[must_use]
pub fn decode_add_sub_imm12(imm12: u16, shift: u8) -> Option<u64> {
    if imm12 > 0xfff {
        return None;
    }
    match shift {
        0 => Some(u64::from(imm12)),
        12 => Some(u64::from(imm12) << 12),
        _ => None,
    }
}

/// Decode a PC-relative ADR immediate (21-bit signed).
#[must_use]
pub const fn adr_offset(word: u32) -> i32 {
    let immlo = (word >> 29) & 0x3;
    let immhi = (word >> 5) & 0x7ffff;
    let raw = ((immhi << 2) | immlo).cast_signed();
    // sign-extend from bit 20
    (raw << 11) >> 11
}

/// Decode a PC-relative ADRP immediate (33-bit page offset, shifted by 12).
#[must_use]
pub const fn adrp_offset(word: u32) -> i64 {
    let immlo = ((word >> 29) & 0x3) as i64;
    let immhi = ((word >> 5) & 0x7ffff) as i64;
    let raw = (immhi << 2) | immlo;
    // sign-extend from bit 20 then shift left 12
    let signed = (raw << 43) >> 43;
    signed << 12
}

// ── AArch64 memory model helpers ───────────────────────────────────────────

/// Describes an `AArch64` load/store ordering annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdStOrder {
    /// No ordering — plain load/store.
    None,
    /// Load-acquire / store-release (one-way barrier).
    Acquire,
    /// Load-acquire / store-release with `RCpc` semantics.
    AcquireRcpc,
    /// Sequential consistency (LDAR/STLR).
    Sequential,
}

impl LdStOrder {
    /// Returns the assembler suffix for this ordering.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Acquire => "a",
            Self::AcquireRcpc => "ap",
            Self::Sequential => "al",
        }
    }

    /// Returns `true` if any ordering constraint is present.
    #[must_use]
    pub const fn is_ordered(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Returns the natural alignment requirement in bytes for a data size.
#[must_use]
pub const fn natural_align(size_bytes: u32) -> u32 {
    size_bytes
}

// ── AArch64 calling-convention frame helpers ────────────────────────────────

/// Compute the frame pointer (x29) value given a stack-pointer base and the
/// frame size allocated by the function prologue.
///
/// In AAPCS64 the saved `{x29, x30}` pair is stored at the top of the local
/// frame, so `fp = sp + frame_size - 16`.
#[must_use]
pub const fn compute_fp(sp: u64, frame_size: u64) -> u64 {
    sp.wrapping_add(frame_size).wrapping_sub(16)
}

/// Recover the caller's SP from a saved frame pointer.
///
/// Inverse of `compute_fp`: `sp = fp - frame_size + 16`.
#[must_use]
pub const fn recover_sp(fp: u64, frame_size: u64) -> u64 {
    fp.wrapping_sub(frame_size).wrapping_add(16)
}

// ── AArch64 vector lane addressing ─────────────────────────────────────────

/// Compute the byte offset within a 128-bit SIMD register for a given
/// element index and element size (in bytes).
///
/// # Panics
///
/// Panics (in debug builds) if `elem_size` is zero or if the computed offset
/// exceeds 15 bytes.
#[must_use]
pub fn lane_byte_offset(lane: u8, elem_size: u8) -> u8 {
    assert!(elem_size > 0, "elem_size must be non-zero");
    let off = lane * elem_size;
    assert!(off < 16, "lane byte offset out of range");
    off
}

/// Number of elements that fit in a 128-bit (Q) register for a given element
/// size in bytes.
#[must_use]
pub const fn q_lane_count(elem_size: u8) -> u8 {
    match 16u8.checked_div(elem_size) {
        Some(n) => n,
        None => 0,
    }
}

/// Number of elements that fit in a 64-bit (D) register for a given element
/// size in bytes.
#[must_use]
pub const fn d_lane_count(elem_size: u8) -> u8 {
    match 8u8.checked_div(elem_size) {
        Some(n) => n,
        None => 0,
    }
}

// ── AArch64 instruction-set state ──────────────────────────────────────────

/// The current `AArch64` instruction-set state (`AArch64` always runs in A64,
/// but interworking stubs can transition to `AArch32` T32 or A32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaState {
    /// `AArch64` A64 instructions.
    A64,
    /// `AArch32` A32 instructions (ARM state).
    A32,
    /// `AArch32` T32 instructions (Thumb state).
    T32,
}

impl IsaState {
    /// Returns `true` if this state uses 32-bit fixed-width instructions.
    #[must_use]
    pub const fn is_fixed_width(self) -> bool {
        matches!(self, Self::A64 | Self::A32)
    }

    /// Minimum instruction size in bytes.
    #[must_use]
    pub const fn min_instr_bytes(self) -> u8 {
        match self {
            Self::A64 | Self::A32 => 4,
            Self::T32 => 2,
        }
    }

    /// Name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A64 => "A64",
            Self::A32 => "A32",
            Self::T32 => "T32",
        }
    }
}

// ── Miscellaneous AArch64 helpers ───────────────────────────────────────────

/// Return `true` if `addr` is naturally aligned to `align` bytes.
///
/// `align` must be a power of two.
#[must_use]
pub const fn is_aligned(addr: u64, align: u64) -> bool {
    addr & (align - 1) == 0
}

/// Round `addr` up to the next multiple of `align` (must be power of two).
#[must_use]
pub const fn round_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

/// Round `addr` down to the previous multiple of `align` (must be power of two).
#[must_use]
pub const fn round_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// Rotate a 32-bit value right by `shift` bits.
#[must_use]
pub const fn ror32(val: u32, shift: u8) -> u32 {
    val.rotate_right(shift as u32)
}

/// Rotate a 64-bit value right by `shift` bits.
#[must_use]
pub const fn ror64(val: u64, shift: u8) -> u64 {
    val.rotate_right(shift as u32)
}

/// Count the number of set bits (population count) in a 64-bit value.
#[must_use]
pub const fn popcount64(val: u64) -> u32 {
    val.count_ones()
}

/// Return the index of the highest set bit, or `None` if `val` is zero.
#[must_use]
pub fn highest_set_bit(val: u64) -> Option<u8> {
    if val == 0 {
        None
    } else {
        Some(63 - val.leading_zeros().try_into().unwrap_or(64u8))
    }
}

/// Return `true` if `val` is a power of two (and non-zero).
#[must_use]
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && (val & val.wrapping_sub(1)) == 0
}

/// Extract a bit-field from `val`: bits `[hi:lo]` (both inclusive).
#[must_use]
pub const fn bit_field(val: u64, hi: u8, lo: u8) -> u64 {
    let width = hi - lo + 1;
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (val >> lo) & mask
}

// ── AArch64 test module ─────────────────────────────────────────────────────

#[cfg(test)]
mod arm64_helpers_tests {
    use super::*;

    #[test]
    fn test_reg_shift_kind_encode_decode() {
        for bits in 0u8..4 {
            assert_eq!(RegShiftKind::decode(bits).encode(), bits);
        }
    }

    #[test]
    fn test_reg_shift_mnemonic() {
        assert_eq!(RegShiftKind::Lsl.mnemonic(), "lsl");
        assert_eq!(RegShiftKind::Ror.mnemonic(), "ror");
    }

    #[test]
    fn test_reg_extend_decode() {
        assert_eq!(RegExtendKind::decode(6).mnemonic(), "sxtw");
        assert_eq!(RegExtendKind::decode(2).mnemonic(), "uxtw");
    }

    #[test]
    fn test_reg_extend_signed() {
        assert!(RegExtendKind::Sxtb.is_signed());
        assert!(!RegExtendKind::Uxtw.is_signed());
    }

    #[test]
    fn test_reg_extend_source_bits() {
        assert_eq!(RegExtendKind::Uxtb.source_bits(), 8);
        assert_eq!(RegExtendKind::Sxtx.source_bits(), 64);
    }

    #[test]
    fn test_cond_inverse_eq_ne() {
        assert_eq!(cond_inverse(0), 1); // EQ -> NE
        assert_eq!(cond_inverse(1), 0); // NE -> EQ
    }

    #[test]
    fn test_cond_inverse_al() {
        assert_eq!(cond_inverse(14), 14);
    }

    #[test]
    fn test_decode_add_sub_imm12_zero_shift() {
        assert_eq!(decode_add_sub_imm12(42, 0), Some(42));
    }

    #[test]
    fn test_decode_add_sub_imm12_shift12() {
        assert_eq!(decode_add_sub_imm12(1, 12), Some(4096));
    }

    #[test]
    fn test_decode_add_sub_imm12_invalid_shift() {
        assert_eq!(decode_add_sub_imm12(1, 1), None);
    }

    #[test]
    fn test_adr_offset_zero() {
        // All immediate bits zero in an ADR -> offset = 0
        // ADR encoding: bits[29:29]=immlo[1:0], bits[23:5]=immhi
        // Use 0x1000_0000 (ADR x0, . i.e. offset 0)
        let word: u32 = 0x1000_0000;
        assert_eq!(adr_offset(word), 0);
    }

    #[test]
    fn test_adrp_offset_zero() {
        let word: u32 = 0x9000_0000; // ADRP x0, . (offset 0)
        assert_eq!(adrp_offset(word), 0);
    }

    #[test]
    fn test_ldst_order_suffix() {
        assert_eq!(LdStOrder::None.suffix(), "");
        assert_eq!(LdStOrder::Acquire.suffix(), "a");
        assert_eq!(LdStOrder::Sequential.suffix(), "al");
    }

    #[test]
    fn test_ldst_order_is_ordered() {
        assert!(!LdStOrder::None.is_ordered());
        assert!(LdStOrder::Acquire.is_ordered());
    }

    #[test]
    fn test_q_lane_count() {
        assert_eq!(q_lane_count(1), 16);
        assert_eq!(q_lane_count(4), 4);
        assert_eq!(q_lane_count(8), 2);
    }

    #[test]
    fn test_d_lane_count() {
        assert_eq!(d_lane_count(2), 4);
        assert_eq!(d_lane_count(8), 1);
    }

    #[test]
    fn test_isa_state_fixed_width() {
        assert!(IsaState::A64.is_fixed_width());
        assert!(!IsaState::T32.is_fixed_width());
    }

    #[test]
    fn test_isa_state_min_instr() {
        assert_eq!(IsaState::A64.min_instr_bytes(), 4);
        assert_eq!(IsaState::T32.min_instr_bytes(), 2);
    }

    #[test]
    fn test_is_aligned() {
        assert!(is_aligned(0x1000, 0x1000));
        assert!(!is_aligned(0x1001, 0x1000));
    }

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(1, 16), 16);
        assert_eq!(round_up(16, 16), 16);
        assert_eq!(round_up(17, 16), 32);
    }

    #[test]
    fn test_round_down() {
        assert_eq!(round_down(17, 16), 16);
        assert_eq!(round_down(16, 16), 16);
    }

    #[test]
    fn test_ror32() {
        assert_eq!(ror32(0x8000_0000, 1), 0x4000_0000);
        assert_eq!(ror32(1, 1), 0x8000_0000);
    }

    #[test]
    fn test_ror64() {
        assert_eq!(ror64(1, 1), 0x8000_0000_0000_0000);
    }

    #[test]
    fn test_popcount64() {
        assert_eq!(popcount64(0xff), 8);
        assert_eq!(popcount64(0), 0);
    }

    #[test]
    fn test_highest_set_bit() {
        assert_eq!(highest_set_bit(0), None);
        assert_eq!(highest_set_bit(1), Some(0));
        assert_eq!(highest_set_bit(0x8000_0000_0000_0000), Some(63));
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(1024));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
    }

    #[test]
    fn test_bit_field() {
        assert_eq!(bit_field(0b1101, 3, 2), 0b11);
        assert_eq!(bit_field(0xff, 7, 4), 0xf);
    }

    #[test]
    fn test_compute_fp_recover_sp() {
        let sp: u64 = 0x1000;
        let frame: u64 = 64;
        let fp = compute_fp(sp, frame);
        assert_eq!(recover_sp(fp, frame), sp);
    }

    #[test]
    fn test_decode_bitmask_all_ones() {
        // N=1, immr=0, imms=63 -> 64-bit all-ones
        let v = decode_bitmask(1, 0, 63, 64);
        assert_eq!(v, Some(u64::MAX));
    }

    #[test]
    fn test_lane_byte_offset() {
        assert_eq!(lane_byte_offset(3, 4), 12);
    }

    #[test]
    fn test_natural_align() {
        assert_eq!(natural_align(8), 8);
    }
}
