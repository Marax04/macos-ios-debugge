//! `cv_symbol_records` — `CodeView` symbol record decoder.
//!
//! Decodes `S_PUB32`, `S_LDATA32`, `S_GDATA32`, `S_LPROC32`, `S_GPROC32`, `S_THUNK32`,
//! `S_BLOCK32`, `S_LABEL32`, `S_CONSTANT`, `S_UDT`, `S_COMPILE3`, `S_REGREL32`,
//! `S_LOCAL`, `S_DEFRANGE_REGISTER`, `S_DEFRANGE_FRAMEPOINTER_REL`,
//! `S_FRAMEPROC`, `S_CALLSITEINFO`, `S_INLINESITE`, `S_INLINESITE_END`,
//! `S_END`, and more.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::CodeViewError;

// ---------------------------------------------------------------------------
// Symbol kind constants (S_*)
// ---------------------------------------------------------------------------

/// `CodeView` symbol record kind constants (`S_*` values from `cvinfo.h`).
pub mod sk {
    /// `S_COMPILE` — obsolete compile-flags record (CV4 era).
    pub const COMPILE: u16 = 0x0001;
    /// `S_REGISTER_16t` — register variable (16-bit type index format).
    pub const REGISTER_16T: u16 = 0x0002;
    /// `S_CONSTANT_16t` — constant symbol (16-bit type index format).
    pub const CONSTANT_16T: u16 = 0x0003;
    /// `S_UDT_16t` — user-defined type name (16-bit type index format).
    pub const UDT_16T: u16 = 0x0004;
    /// `S_SSEARCH` — start-search record for a segment.
    pub const SSEARCH: u16 = 0x000A;
    /// `S_END` — closes the scope opened by a proc/block/thunk/with record.
    pub const END: u16 = 0x0006;
    /// `S_SKIP` — reserved space to be skipped by the reader.
    pub const SKIP: u16 = 0x0007;
    /// `S_OBJNAME` — name of the originating object file.
    pub const OBJNAME: u16 = 0x1101;
    /// `S_THUNK32` — thunk (stub) start record.
    pub const THUNK32: u16 = 0x1102;
    /// `S_BLOCK32` — lexical block start record.
    pub const BLOCK32: u16 = 0x1103;
    /// `S_WITH32` — Pascal `with` block start record.
    pub const WITH32: u16 = 0x1104;
    /// `S_LABEL32` — code label.
    pub const LABEL32: u16 = 0x1105;
    /// `S_REGISTER` — variable held in a register.
    pub const REGISTER: u16 = 0x1106;
    /// `S_CONSTANT` — named constant with a numeric-leaf value.
    pub const CONSTANT: u16 = 0x1107;
    /// `S_UDT` — user-defined type name → type index mapping.
    pub const UDT: u16 = 0x1108;
    /// `S_COBOLUDT` — COBOL user-defined type.
    pub const COBOLUDT: u16 = 0x1109;
    /// `S_MANYREG` — variable split across multiple registers.
    pub const MANYREG: u16 = 0x110A;
    /// `S_BPREL32` — BP-relative stack variable.
    pub const BPREL32: u16 = 0x110B;
    /// `S_LDATA32` — module-local (static) data symbol.
    pub const LDATA32: u16 = 0x110C;
    /// `S_GDATA32` — global data symbol.
    pub const GDATA32: u16 = 0x110D;
    /// `S_PUB32` — public (linker-visible) symbol in the publics stream.
    pub const PUB32: u16 = 0x110E;
    /// `S_LPROC32` — local (static) procedure start.
    pub const LPROC32: u16 = 0x110F;
    /// `S_GPROC32` — global procedure start.
    pub const GPROC32: u16 = 0x1110;
    /// `S_REGREL32` — register-relative variable (e.g. `[rsp+N]` locals).
    pub const REGREL32: u16 = 0x1111;
    /// `S_LTHREAD32` — module-local thread-local storage data.
    pub const LTHREAD32: u16 = 0x1112;
    /// `S_GTHREAD32` — global thread-local storage data.
    pub const GTHREAD32: u16 = 0x1113;
    /// `S_LPROCMIPS` — local MIPS procedure start.
    pub const LPROCMIPS: u16 = 0x1114;
    /// `S_GPROCMIPS` — global MIPS procedure start.
    pub const GPROCMIPS: u16 = 0x1115;
    /// `S_COMPILE2` — compiler information (superseded by `S_COMPILE3`).
    pub const COMPILE2: u16 = 0x1116;
    /// `S_MANYREG2` — multi-register variable (16-bit register count form).
    pub const MANYREG2: u16 = 0x1117;
    /// `S_LPROCIA64` — local IA64 procedure start.
    pub const LPROCIA64: u16 = 0x1118;
    /// `S_GPROCIA64` — global IA64 procedure start.
    pub const GPROCIA64: u16 = 0x1119;
    /// `S_LOCALSLOT` — local variable in a managed slot.
    pub const LOCALSLOT: u16 = 0x111A;
    /// `S_PARAMSLOT` — parameter in a managed slot.
    pub const PARAMSLOT: u16 = 0x111B;
    /// `S_LMANDATA` — module-local managed data.
    pub const LMANDATA: u16 = 0x111C;
    /// `S_GMANDATA` — global managed data.
    pub const GMANDATA: u16 = 0x111D;
    /// `S_MANFRAMEREL` — managed frame-relative variable.
    pub const MANFRAMEREL: u16 = 0x111E;
    /// `S_MANREGISTER` — managed register variable.
    pub const MANREGISTER: u16 = 0x111F;
    /// `S_MANSLOT` — managed slot variable.
    pub const MANSLOT: u16 = 0x1120;
    /// `S_MANMANYREG` — managed multi-register variable.
    pub const MANMANYREG: u16 = 0x1121;
    /// `S_MANREGREL` — managed register-relative variable.
    pub const MANREGREL: u16 = 0x1122;
    /// `S_MANMANYREG2` — managed multi-register variable (16-bit count form).
    pub const MANMANYREG2: u16 = 0x1123;
    /// `S_UNAMESPACE` — `using namespace` directive.
    pub const UNAMESPACE: u16 = 0x1124;
    /// `S_PROCREF` — reference to a global procedure in another module.
    pub const PROCREF: u16 = 0x1125;
    /// `S_DATAREF` — reference to data in another module.
    pub const DATAREF: u16 = 0x1126;
    /// `S_LPROCREF` — reference to a local (static) procedure.
    pub const LPROCREF: u16 = 0x1127;
    /// `S_ANNOTATIONREF` — reference to an annotation record.
    pub const ANNOTATIONREF: u16 = 0x1128;
    /// `S_TOKENREF` — reference to a managed metadata token.
    pub const TOKENREF: u16 = 0x1129;
    /// `S_GMANPROC` — global managed procedure start.
    pub const GMANPROC: u16 = 0x112A;
    /// `S_LMANPROC` — local managed procedure start.
    pub const LMANPROC: u16 = 0x112B;
    /// `S_TRAMPOLINE` — trampoline (incremental-link or import thunk).
    pub const TRAMPOLINE: u16 = 0x112C;
    /// `S_MANCONSTANT` — managed constant symbol.
    pub const MANCONSTANT: u16 = 0x112D;
    /// `S_ATTR_FRAMEREL` — frame-relative variable with attributes.
    pub const ATTR_FRAMEREL: u16 = 0x112E;
    /// `S_ATTR_REGISTER` — register variable with attributes.
    pub const ATTR_REGISTER: u16 = 0x112F;
    /// `S_ATTR_REGREL` — register-relative variable with attributes.
    pub const ATTR_REGREL: u16 = 0x1130;
    /// `S_ATTR_MANYREG` — multi-register variable with attributes.
    pub const ATTR_MANYREG: u16 = 0x1131;
    /// `S_SEPCODE` — separated code region (e.g. hot/cold splitting).
    pub const SEPCODE: u16 = 0x1132;
    /// `S_LOCAL` — local variable (new format; location given by defrange records).
    pub const LOCAL: u16 = 0x113E;
    /// `S_DEFRANGE` — live range of a `S_LOCAL` given by a program.
    pub const DEFRANGE: u16 = 0x113F;
    /// `S_DEFRANGE_SUBFIELD` — live range of a subfield of a local.
    pub const DEFRANGE_SUBFIELD: u16 = 0x1140;
    /// `S_DEFRANGE_REGISTER` — live range where the local is in a register.
    pub const DEFRANGE_REGISTER: u16 = 0x1141;
    /// `S_DEFRANGE_FRAMEPOINTER_REL` — live range at a frame-pointer offset.
    pub const DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
    /// `S_DEFRANGE_SUBFIELD_REGISTER` — live range of a subfield in a register.
    pub const DEFRANGE_SUBFIELD_REGISTER: u16 = 0x1143;
    /// `S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE` — frame-relative for the whole function.
    pub const DEFRANGE_FRAMEPOINTER_REL_FULL: u16 = 0x1144;
    /// `S_DEFRANGE_REGISTER_REL` — live range at a register-relative address.
    pub const DEFRANGE_REGISTER_REL: u16 = 0x1145;
    /// `S_LPROC32_ID` — local procedure start using an ID-stream type index.
    pub const LPROC32_ID: u16 = 0x1146;
    /// `S_GPROC32_ID` — global procedure start using an ID-stream type index.
    pub const GPROC32_ID: u16 = 0x1147;
    /// `S_LPROCMIPS_ID` — local MIPS procedure (ID-stream form).
    pub const LPROCMIPS_ID: u16 = 0x1148;
    /// `S_GPROCMIPS_ID` — global MIPS procedure (ID-stream form).
    pub const GPROCMIPS_ID: u16 = 0x1149;
    /// `S_LPROCIA64_ID` — local IA64 procedure (ID-stream form).
    pub const LPROCIA64_ID: u16 = 0x114A;
    /// `S_GPROCIA64_ID` — global IA64 procedure (ID-stream form).
    pub const GPROCIA64_ID: u16 = 0x114B;
    /// `S_BUILDINFO` — build info: references an `LF_BUILDINFO` item id.
    pub const BUILDINFO: u16 = 0x114C;
    /// `S_INLINESITE` — start of an inlined call site.
    pub const INLINESITE: u16 = 0x114D;
    /// `S_INLINESITE_END` — end of an inlined call site scope.
    pub const INLINESITE_END: u16 = 0x114E;
    /// `S_PROC_ID_END` — end of a `*_ID` procedure scope.
    pub const PROC_ID_END: u16 = 0x114F;
    /// `S_DEFRANGE_HLSL` — live range of an HLSL variable.
    pub const DEFRANGE_HLSL: u16 = 0x1150;
    /// `S_GDATA_HLSL` — global HLSL data symbol.
    pub const GDATA_HLSL: u16 = 0x1151;
    /// `S_LDATA_HLSL` — local HLSL data symbol.
    pub const LDATA_HLSL: u16 = 0x1152;
    /// `S_FILESTATIC` — file-scoped static variable.
    pub const FILESTATIC: u16 = 0x1153;
    /// `S_LOCAL_DPC_GROUPSHARED` — DPC group-shared local variable.
    pub const LOCAL_DPC_GROUPSHARED: u16 = 0x1154;
    /// `S_LPROC32_DPC` — local DPC procedure start.
    pub const LPROC32_DPC: u16 = 0x1155;
    /// `S_LPROC32_DPC_ID` — local DPC procedure (ID-stream form).
    pub const LPROC32_DPC_ID: u16 = 0x1156;
    /// `S_DEFRANGE_DPC_PTR_TAG` — DPC pointer-tag live range.
    pub const DEFRANGE_DPC_PTR_TAG: u16 = 0x1157;
    /// `S_COMPILE3` — compiler information (language, machine, versions).
    pub const COMPILE3: u16 = 0x113C;
    /// `S_ENVBLOCK` — environment block (key/value build environment strings).
    pub const ENVBLOCK: u16 = 0x113D;
    /// `S_FRAMEPROC` — extra frame/stack layout info for a procedure.
    pub const FRAMEPROC: u16 = 0x1012;
    /// `S_CALLSITEINFO` — type signature of an indirect call site.
    pub const CALLSITEINFO: u16 = 0x1139;
    /// `S_HEAPALLOCSITE` — call site of a heap allocation, with allocated type.
    pub const HEAPALLOCSITE: u16 = 0x115E;
}

// ---------------------------------------------------------------------------
// Register encoding
// ---------------------------------------------------------------------------

/// `CodeView` register number (`CV_HREG_e`) as used by `S_REGREL32` and
/// register-based defranges. Only the common x86/x64 subset is enumerated.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CvReg {
    /// `al` — low byte of `ax`.
    Al = 1,
    /// `cl` — low byte of `cx`.
    Cl = 2,
    /// `dl` — low byte of `dx`.
    Dl = 3,
    /// `bl` — low byte of `bx`.
    Bl = 4,
    /// `ax` — 16-bit accumulator.
    Ax = 9,
    /// `cx` — 16-bit count register.
    Cx = 10,
    /// `dx` — 16-bit data register.
    Dx = 11,
    /// `bx` — 16-bit base register.
    Bx = 12,
    /// `sp` — 16-bit stack pointer.
    Sp = 13,
    /// `bp` — 16-bit base pointer.
    Bp = 14,
    /// `si` — 16-bit source index.
    Si = 15,
    /// `di` — 16-bit destination index.
    Di = 16,
    /// `eax` — 32-bit accumulator.
    Eax = 17,
    /// `ecx` — 32-bit count register.
    Ecx = 18,
    /// `edx` — 32-bit data register.
    Edx = 19,
    /// `ebx` — 32-bit base register.
    Ebx = 20,
    /// `esp` — 32-bit stack pointer.
    Esp = 21,
    /// `ebp` — 32-bit base pointer.
    Ebp = 22,
    /// `esi` — 32-bit source index.
    Esi = 23,
    /// `edi` — 32-bit destination index.
    Edi = 24,
    // NOTE: the AMD64 block is NOT in the classic x86 order (AX, CX, DX, BX,
    // SP, BP, SI, DI). CodeView numbers these registers RAX, RBX, RCX, RDX,
    // RSI, RDI, RBP, RSP — which is why four other places in this crate treat
    // 335 as RSP and 334 as RBP.
    /// `rax` — 64-bit accumulator.
    Rax = 328,
    /// `rbx` — 64-bit base register.
    Rbx = 329,
    /// `rcx` — 64-bit count register.
    Rcx = 330,
    /// `rdx` — 64-bit data register.
    Rdx = 331,
    /// `rsi` — 64-bit source index.
    Rsi = 332,
    /// `rdi` — 64-bit destination index.
    Rdi = 333,
    /// `rbp` — 64-bit base pointer.
    Rbp = 334,
    /// `rsp` — 64-bit stack pointer.
    Rsp = 335,
    /// `r8` — x64 general-purpose register.
    R8 = 336,
    /// `r9` — x64 general-purpose register.
    R9 = 337,
    /// `r10` — x64 general-purpose register.
    R10 = 338,
    /// `r11` — x64 general-purpose register.
    R11 = 339,
    /// `r12` — x64 general-purpose register.
    R12 = 340,
    /// `r13` — x64 general-purpose register.
    R13 = 341,
    /// `r14` — x64 general-purpose register.
    R14 = 342,
    /// `r15` — x64 general-purpose register.
    R15 = 343,
    /// `xmm0` — SSE register 0.
    Xmm0 = 154,
    /// `xmm1` — SSE register 1.
    Xmm1 = 155,
    /// `xmm2` — SSE register 2.
    Xmm2 = 156,
    /// `xmm3` — SSE register 3.
    Xmm3 = 157,
    /// Any register number not modeled by this enum.
    Unknown = 0xFFFF,
}

impl CvReg {
    /// Map a raw `CV_HREG_e` value to a known register, or [`CvReg::Unknown`].
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Al, 2 => Self::Cl, 3 => Self::Dl, 4 => Self::Bl,
            9 => Self::Ax, 10 => Self::Cx, 11 => Self::Dx, 12 => Self::Bx,
            13 => Self::Sp, 14 => Self::Bp, 15 => Self::Si, 16 => Self::Di,
            17 => Self::Eax, 18 => Self::Ecx, 19 => Self::Edx, 20 => Self::Ebx,
            21 => Self::Esp, 22 => Self::Ebp, 23 => Self::Esi, 24 => Self::Edi,
            328 => Self::Rax, 329 => Self::Rbx, 330 => Self::Rcx, 331 => Self::Rdx,
            332 => Self::Rsi, 333 => Self::Rdi, 334 => Self::Rbp, 335 => Self::Rsp,
            336 => Self::R8, 337 => Self::R9, 338 => Self::R10, 339 => Self::R11,
            340 => Self::R12, 341 => Self::R13, 342 => Self::R14, 343 => Self::R15,
            154 => Self::Xmm0, 155 => Self::Xmm1, 156 => Self::Xmm2, 157 => Self::Xmm3,
            _ => Self::Unknown,
        }
    }
}

/// Target architecture of the image a `CodeView` record belongs to.
///
/// Needed because several `CodeView` fields (register numbers above all) are
/// per-architecture and the records themselves do not say which one applies.
///
/// **Two different numeric spaces name architectures in this format and they
/// must not be mixed**: `IMAGE_FILE_MACHINE_*` from the PE COFF header
/// (`0x8664` = x64) and `CV_CPU_TYPE_e` from `S_COMPILE3` (`0xD0` = x64). The
/// repo already confused them once (a test builds `SCompile3 { machine: 0x8664 }`
/// in a field documented as `CV_CPU_TYPE_e`), which is why there are two
/// constructors and no single `from_u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CvArch {
    /// 32-bit x86.
    X86,
    /// 64-bit x86 (AMD64).
    X64,
    /// 64-bit ARM.
    Arm64,
    /// 32-bit ARM.
    Arm32,
    /// A value this decoder does not recognise; never guessed at.
    Unknown(u16),
}

impl CvArch {
    /// Decode an `IMAGE_FILE_MACHINE_*` value from a PE COFF header.
    #[must_use]
    pub const fn from_image_file_machine(v: u16) -> Self {
        match v {
            0x014C => Self::X86,
            0x8664 => Self::X64,
            0xAA64 => Self::Arm64,
            0x01C4 => Self::Arm32,
            other => Self::Unknown(other),
        }
    }

    /// Decode a `CV_CPU_TYPE_e` value as found in `S_COMPILE3::machine`.
    ///
    /// Deliberately near-empty: only `0xD0` (x64) is encoded, because it is the
    /// single value this crate can cross-check against its own documentation
    /// (`SCompile3::machine`, "`0xD0` = x64"). Everything else maps to
    /// [`CvArch::Unknown`] rather than to a constant written from memory — a
    /// previous iteration shipped a register table where seven of eight entries
    /// were wrong for exactly that reason.
    // TODO: verify 0xF6 (ARM64) against LLVM `CodeView.h` `CPUType` before
    // adding it; an unverified constant is worse than `Unknown`.
    #[must_use]
    pub const fn from_cv_cpu_type(v: u16) -> Self {
        match v {
            0xD0 => Self::X64,
            other => Self::Unknown(other),
        }
    }
}

/// Is `reg` the frame or stack pointer under `arch`?
///
/// One table, shared by every `S_REGREL32`-shaped type in this crate, so the
/// per-architecture knowledge cannot drift between them.
///
/// - x64: `334` = RBP, `335` = RSP (see the `CvReg` AMD64 block).
/// - x86: `21` = `esp`, `22` = `ebp`, cross-checked against `CvReg::Esp`/`Ebp`.
/// - arm64: `79` = FP, `81` = SP (`CvArm64Reg`).
/// - unknown architecture: `false` — never guess.
#[must_use]
pub const fn reg_is_frame_or_stack(reg: u16, arch: CvArch) -> bool {
    match arch {
        CvArch::X64 => matches!(reg, 334 | 335),
        CvArch::X86 => matches!(reg, 21 | 22),
        CvArch::Arm64 => matches!(reg, 79 | 81),
        CvArch::Arm32 | CvArch::Unknown(_) => false,
    }
}

/// `CodeView` register number for an **arm64** image (`CV_ARM64_*`).
///
/// A separate type on purpose: the arm64 numbers are a different space from the
/// x86/x64 ones and they overlap. `10..=40` are the 32-bit `w` registers, which
/// in the x86 space are `cx`/`dx`/`eax`/… — so feeding an arm64 record to
/// [`CvReg::from_u16`] yields a confident, wrong x86 name rather than nothing.
///
/// Numbering per LLVM's `CodeViewRegisters.def`: `w0` = 10, `x0` = 50,
/// `fp` = 79, `lr` = 80, `sp` = 81, `pc` = 83.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CvArm64Reg {
    /// 32-bit view `w0`-`w30`.
    W(u8),
    /// 64-bit general purpose `x0`-`x28`.
    X(u8),
    /// Frame pointer (`x29`).
    Fp,
    /// Link register (`x30`).
    Lr,
    /// Stack pointer.
    Sp,
    /// Zero register.
    Zr,
    /// Program counter.
    Pc,
    /// Not one of the numbers this decoder knows.
    Unknown(u16),
}

impl CvArm64Reg {
    /// Decode a raw `CV_HREG_e` number as an arm64 register.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            10..=40 => Self::W((v - 10) as u8),
            50..=78 => Self::X((v - 50) as u8),
            79 => Self::Fp,
            80 => Self::Lr,
            81 => Self::Sp,
            82 => Self::Zr,
            83 => Self::Pc,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for CvArm64Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::W(n) => write!(f, "w{n}"),
            Self::X(n) => write!(f, "x{n}"),
            Self::Fp => write!(f, "fp"),
            Self::Lr => write!(f, "lr"),
            Self::Sp => write!(f, "sp"),
            Self::Zr => write!(f, "xzr"),
            Self::Pc => write!(f, "pc"),
            Self::Unknown(v) => write!(f, "reg{v}"),
        }
    }
}

impl fmt::Display for CvReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Rax => "rax", Self::Rcx => "rcx", Self::Rdx => "rdx", Self::Rbx => "rbx",
            Self::Rsp => "rsp", Self::Rbp => "rbp", Self::Rsi => "rsi", Self::Rdi => "rdi",
            Self::R8 => "r8", Self::R9 => "r9", Self::R10 => "r10", Self::R11 => "r11",
            Self::R12 => "r12", Self::R13 => "r13", Self::R14 => "r14", Self::R15 => "r15",
            Self::Eax => "eax", Self::Ecx => "ecx", Self::Edx => "edx", Self::Ebx => "ebx",
            Self::Esp => "esp", Self::Ebp => "ebp", Self::Esi => "esi", Self::Edi => "edi",
            Self::Xmm0 => "xmm0", Self::Xmm1 => "xmm1", Self::Xmm2 => "xmm2", Self::Xmm3 => "xmm3",
            _ => "?reg",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Symbol record structures
// ---------------------------------------------------------------------------

/// CV public symbol (`S_PUB32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymPub32 {
    /// `CV_PUBSYMFLAGS`: bit 1 = code, bit 2 = function, bit 3 = managed, bit 4 = MSIL.
    pub flags: u32,
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Decorated (mangled) public symbol name.
    pub name: String,
}

impl SymPub32 {
    /// True if the public symbol refers to a function.
    #[must_use]
    pub const fn is_function(&self) -> bool { (self.flags & 2) != 0 }
    /// True if the symbol is managed code.
    #[must_use]
    pub const fn is_managed(&self) -> bool { (self.flags & 4) != 0 }
    /// True if the symbol is MSIL code.
    #[must_use]
    pub const fn is_msil(&self) -> bool { (self.flags & 8) != 0 }
}

/// CV data symbol (`S_LDATA32` / `S_GDATA32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymData32 {
    /// TPI type index of the data.
    pub type_index: u32,
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Symbol name.
    pub name: String,
    /// True for `S_GDATA32`/`S_GTHREAD32` (global), false for the local forms.
    pub is_global: bool,
}

/// CV procedure symbol (`S_LPROC32` / `S_GPROC32` / `LPROC32_ID` / `GPROC32_ID`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymProc32 {
    /// Parent scope offset in the symbol stream (0 if none).
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Stream offset of the next procedure (linked list; often 0).
    pub next: u32,
    /// Length of the procedure in bytes.
    pub proc_len: u32,
    /// Offset from procedure start where the prologue ends (debuggable start).
    pub debug_start: u32,
    /// Offset from procedure start where the epilogue begins (debuggable end).
    pub debug_end: u32,
    /// TPI (or IPI for `*_ID` forms) type index of the function signature.
    pub type_index: u32,
    /// Offset within `segment` of the entry point.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// `CV_PROCFLAGS` bit set (see the `is_*` accessors).
    pub flags: u8,
    /// Procedure name.
    pub name: String,
    /// True for the global forms (`S_GPROC32`/`S_GPROC32_ID`).
    pub is_global: bool,
}

impl SymProc32 {
    /// True if frame-pointer omission is in effect (`CV_PFLAG_NOFPO`).
    #[must_use]
    pub const fn is_no_fpo(&self) -> bool { (self.flags & 1) != 0 }
    /// True if this is an interrupt routine (`CV_PFLAG_INT`).
    #[must_use]
    pub const fn is_interrupt(&self) -> bool { (self.flags & 2) != 0 }
    /// True if the procedure performs a far return (`CV_PFLAG_FAR`).
    #[must_use]
    pub const fn is_far_return(&self) -> bool { (self.flags & 4) != 0 }
    /// True if the procedure never returns (`CV_PFLAG_NEVER`).
    #[must_use]
    pub const fn is_never_return(&self) -> bool { (self.flags & 8) != 0 }
    /// True if the procedure is never reached (`CV_PFLAG_NOTREACHED`).
    #[must_use]
    pub const fn is_not_reached(&self) -> bool { (self.flags & 0x10) != 0 }
    /// True if a custom calling convention is used (`CV_PFLAG_CUST_CALL`).
    #[must_use]
    pub const fn is_custom_calling_conv(&self) -> bool { (self.flags & 0x20) != 0 }
    /// True if the function was compiled with optimized debug info (`CV_PFLAG_NOINLINE`/opt-debug bit).
    #[must_use]
    pub const fn is_optimized_debug(&self) -> bool { (self.flags & 0x40) != 0 }
    /// True if the function contains a Control Flow Guard check (`CV_PFLAG_OPTDBGINFO`/CFG bit).
    #[must_use]
    pub const fn is_guard_cf(&self) -> bool { (self.flags & 0x80) != 0 }
}

/// CV thunk symbol (`S_THUNK32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymThunk32 {
    /// Parent scope offset in the symbol stream.
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Stream offset of the next thunk (linked list; often 0).
    pub next: u32,
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Length of the thunk in bytes.
    pub thunk_len: u16,
    /// Thunk ordinal (`THUNK_ORDINAL`: 0 = no type, 1 = adjustor, 2 = vcall, ...).
    pub kind: u8,
    /// Thunk name.
    pub name: String,
}

/// CV block symbol (`S_BLOCK32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymBlock32 {
    /// Parent scope offset in the symbol stream.
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Length of the block in bytes.
    pub block_len: u32,
    /// Offset within `segment` of the block start.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Optional block name (usually empty).
    pub name: String,
}

/// CV label symbol (`S_LABEL32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymLabel32 {
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// `CV_PROCFLAGS`-style flags for the label.
    pub flags: u8,
    /// Label name.
    pub name: String,
}

/// CV constant symbol (`S_CONSTANT`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymConstant {
    /// TPI type index of the constant (often an enum type).
    pub type_index: u32,
    /// Constant value, decoded from the numeric leaf.
    pub value: i64,
    /// Constant name.
    pub name: String,
}

/// CV UDT symbol (`S_UDT`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymUdt {
    /// TPI type index the name refers to.
    pub type_index: u32,
    /// User-defined type name (e.g. a typedef or struct name).
    pub name: String,
}

/// CV register-relative symbol (`S_REGREL32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymRegRel32 {
    /// Signed offset from `register` (e.g. `-8` for `[rbp-8]`).
    pub offset: i32,
    /// TPI type index of the variable.
    pub type_index: u32,
    /// Base register the offset is relative to, decoded with the **x86/x64**
    /// register numbering.
    ///
    /// Only meaningful when the PDB describes an x86 or x64 image. The record
    /// itself carries no architecture, so this field cannot know: check
    /// `register_number` against the DBI machine for anything else.
    pub register: CvReg,
    /// The raw `CV_HREG_e` number exactly as stored in the record.
    ///
    /// Kept because register numbering is per-architecture and this parser has
    /// no way to know which one applies: decoding to `CvReg` alone would turn
    /// an arm64 number into a wrong x86 name and DESTROY the only piece of
    /// information a caller that does know the architecture could act on.
    pub register_number: u16,
    /// Variable name.
    pub name: String,
}

impl SymRegRel32 {
    /// Is this local addressed off the frame or stack pointer of `arch`?
    ///
    /// Takes the architecture explicitly because the record does not carry it
    /// and the register numbering differs per architecture: answering without
    /// it means answering for x64 and being silently wrong everywhere else.
    #[must_use]
    pub const fn is_stack_relative(&self, arch: CvArch) -> bool {
        // Uses the RAW number, never the `CvReg` interpretation: that field is
        // only meaningful for an x86/x64 image.
        reg_is_frame_or_stack(self.register_number, arch)
    }
}

/// CV local variable symbol (`S_LOCAL`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymLocal {
    /// TPI type index of the variable.
    pub type_index: u32,
    /// `CV_LVARFLAGS` bit set (see the `is_*` accessors).
    pub flags: u16,
    /// Variable name.
    pub name: String,
}

impl SymLocal {
    /// True if the local is a formal parameter.
    #[must_use]
    pub const fn is_param(&self) -> bool { (self.flags & 1) != 0 }
    /// True if the variable's address is taken.
    #[must_use]
    pub const fn is_addr_taken(&self) -> bool { (self.flags & 2) != 0 }
    /// True if the variable is compiler-generated.
    #[must_use]
    pub const fn is_compgen(&self) -> bool { (self.flags & 4) != 0 }
    /// True if the symbol is part of an aggregate split across symbols.
    #[must_use]
    pub const fn is_agg(&self) -> bool { (self.flags & 8) != 0 }
    /// True if this is the function's return value slot.
    #[must_use]
    pub const fn is_return(&self) -> bool { (self.flags & 0x80) != 0 }
}

/// `S_COMPILE3` — compiler info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymCompile3 {
    /// Flags: low byte = source language, plus EC/hot-patch/LTCG etc. bits.
    pub flags: u32,
    /// Target machine (`CV_CPU_TYPE_e`, e.g. `0xD0` = x64).
    pub machine: u16,
    /// Front-end compiler major version.
    pub ver_fe_major: u16,
    /// Front-end compiler minor version.
    pub ver_fe_minor: u16,
    /// Front-end compiler build number.
    pub ver_fe_build: u16,
    /// Front-end compiler QFE (hotfix) number.
    pub ver_fe_qfe: u16,
    /// Back-end compiler major version.
    pub ver_major: u16,
    /// Back-end compiler minor version.
    pub ver_minor: u16,
    /// Back-end compiler build number.
    pub ver_build: u16,
    /// Back-end compiler QFE (hotfix) number.
    pub ver_qfe: u16,
    /// Compiler version string (e.g. "Microsoft (R) Optimizing Compiler").
    pub compiler_version: String,
}

/// `S_FRAMEPROC` — frame procedure info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymFrameProc {
    /// Total frame size in bytes.
    pub frame_size: u32,
    /// Size of frame padding in bytes.
    pub pad_size: u32,
    /// Offset of the padding within the frame.
    pub pad_offset: u32,
    /// Bytes used to save callee-saved registers.
    pub save_reg_size: u32,
    /// Offset of the exception handler, if any.
    pub except_handler_offset: u32,
    /// Section of the exception handler.
    pub except_handler_section: u16,
    /// Frame flags (alloca, setjmp, SEH, /GS security checks, ...).
    pub flags: u32,
}

/// `S_CALLSITEINFO` — indirect call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymCallSiteInfo {
    /// Offset of the call instruction within `section`.
    pub offset: u32,
    /// Section index of the call instruction.
    pub section: u16,
    /// TPI type index of the callee function signature.
    pub type_index: u32,
}

/// `S_HEAPALLOCSITE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymHeapAllocSite {
    /// Offset of the allocation call within `section`.
    pub offset: u32,
    /// Section index of the allocation call.
    pub section: u16,
    /// Length of the call instruction in bytes.
    pub inst_len: u16,
    /// TPI type index of the allocated type.
    pub type_index: u32,
}

/// `S_OBJNAME` — object file name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymObjName {
    /// Object file signature (usually 0).
    pub signature: u32,
    /// Path of the originating object file.
    pub name: String,
}

/// `S_UNAMESPACE` — using namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymUsingNamespace {
    /// Namespace name brought into scope.
    pub name: String,
}

/// `S_BUILDINFO` — build info key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymBuildInfo {
    /// IPI item id of the `LF_BUILDINFO` record (cwd, compiler, source, pdb, args).
    pub item_id: u32,
}

/// Top-level decoded symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymRecord {
    /// `S_PUB32` public symbol.
    Pub32(SymPub32),
    /// `S_LDATA32` module-local data.
    LData32(SymData32),
    /// `S_GDATA32` global data.
    GData32(SymData32),
    /// `S_LPROC32` local (static) procedure.
    LProc32(SymProc32),
    /// `S_GPROC32` global procedure.
    GProc32(SymProc32),
    /// `S_THUNK32` thunk.
    Thunk32(SymThunk32),
    /// `S_BLOCK32` lexical block.
    Block32(SymBlock32),
    /// `S_LABEL32` code label.
    Label32(SymLabel32),
    /// `S_CONSTANT` named constant.
    Constant(SymConstant),
    /// `S_UDT` user-defined type name.
    Udt(SymUdt),
    /// `S_REGREL32` register-relative variable.
    RegRel32(SymRegRel32),
    /// `S_LOCAL` local variable.
    Local(SymLocal),
    /// `S_COMPILE3` compiler info.
    Compile3(SymCompile3),
    /// `S_FRAMEPROC` frame layout info.
    FrameProc(SymFrameProc),
    /// `S_CALLSITEINFO` indirect call site.
    CallSiteInfo(SymCallSiteInfo),
    /// `S_HEAPALLOCSITE` heap allocation site.
    HeapAllocSite(SymHeapAllocSite),
    /// `S_OBJNAME` object file name.
    ObjName(SymObjName),
    /// `S_UNAMESPACE` using-namespace directive.
    UsingNamespace(SymUsingNamespace),
    /// `S_BUILDINFO` build info reference.
    BuildInfo(SymBuildInfo),
    /// `S_END` / `S_PROC_ID_END` scope terminator.
    End,
    /// `S_INLINESITE_END` inline-site scope terminator.
    InlineSiteEnd,
    /// Any record kind this decoder does not model.
    Unknown {
        /// The raw `S_*` kind value.
        kind: u16,
    },
}

impl SymRecord {
    /// Symbol name, for record kinds that carry one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Pub32(s) => Some(&s.name),
            Self::LData32(s) | Self::GData32(s) => Some(&s.name),
            Self::LProc32(s) | Self::GProc32(s) => Some(&s.name),
            Self::Thunk32(s) => Some(&s.name),
            Self::Block32(s) => Some(&s.name),
            Self::Label32(s) => Some(&s.name),
            Self::Constant(s) => Some(&s.name),
            Self::Udt(s) => Some(&s.name),
            Self::RegRel32(s) => Some(&s.name),
            Self::Local(s) => Some(&s.name),
            Self::ObjName(s) => Some(&s.name),
            Self::UsingNamespace(s) => Some(&s.name),
            _ => None,
        }
    }

    /// `(segment, offset)` address, for addressable record kinds.
    #[must_use]
    pub const fn segment_offset(&self) -> Option<(u16, u32)> {
        match self {
            Self::Pub32(s) => Some((s.segment, s.offset)),
            Self::LData32(s) | Self::GData32(s) => Some((s.segment, s.offset)),
            Self::LProc32(s) | Self::GProc32(s) => Some((s.segment, s.offset)),
            Self::Label32(s) => Some((s.segment, s.offset)),
            Self::Thunk32(s) => Some((s.segment, s.offset)),
            Self::Block32(s) => Some((s.segment, s.offset)),
            _ => None,
        }
    }

    /// True for procedure records (`S_LPROC32` / `S_GPROC32`).
    #[must_use]
    pub const fn is_proc(&self) -> bool {
        matches!(self, Self::LProc32(_) | Self::GProc32(_))
    }

    /// True for globally visible records (`S_GDATA32`, `S_GPROC32`, `S_PUB32`).
    #[must_use]
    pub const fn is_global(&self) -> bool {
        matches!(self, Self::GData32(_) | Self::GProc32(_) | Self::Pub32(_))
    }
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_i32(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4).map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_nul_str(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off + end]).into_owned()
}

fn read_numeric_leaf_local(data: &[u8]) -> (i64, usize) {
    super::cv_type_records::read_numeric_leaf(data).unwrap_or((0, 2))
}

// ---------------------------------------------------------------------------
// Symbol record decoder
// ---------------------------------------------------------------------------

fn decode_pub32(data: &[u8]) -> Result<SymRecord, CodeViewError> {
    if data.len() < 10 { return Err(CodeViewError::TruncatedStream); }
    let flags = read_u32(data, 0).unwrap();
    let offset = read_u32(data, 4).unwrap();
    let segment = read_u16(data, 8).unwrap();
    let name = read_nul_str(data, 10);
    Ok(SymRecord::Pub32(SymPub32 { flags, offset, segment, name }))
}

fn decode_data32(kind: u16, data: &[u8]) -> Result<SymRecord, CodeViewError> {
    if data.len() < 10 { return Err(CodeViewError::TruncatedStream); }
    let type_index = read_u32(data, 0).unwrap();
    let offset = read_u32(data, 4).unwrap();
    let segment = read_u16(data, 8).unwrap();
    let name = read_nul_str(data, 10);
    let is_global = kind == sk::GDATA32 || kind == sk::GTHREAD32;
    let rec = SymData32 { type_index, offset, segment, name, is_global };
    if is_global { Ok(SymRecord::GData32(rec)) } else { Ok(SymRecord::LData32(rec)) }
}

fn decode_proc32(kind: u16, data: &[u8]) -> Result<SymRecord, CodeViewError> {
    if data.len() < 36 { return Err(CodeViewError::TruncatedStream); }
    let parent = read_u32(data, 0).unwrap();
    let end = read_u32(data, 4).unwrap();
    let next = read_u32(data, 8).unwrap();
    let proc_len = read_u32(data, 12).unwrap();
    let debug_start = read_u32(data, 16).unwrap();
    let debug_end = read_u32(data, 20).unwrap();
    let type_index = read_u32(data, 24).unwrap();
    let offset = read_u32(data, 28).unwrap();
    let segment = read_u16(data, 32).unwrap();
    let flags = data.get(34).copied().unwrap_or(0);
    let name = read_nul_str(data, 35);
    let is_global = kind == sk::GPROC32 || kind == sk::GPROC32_ID;
    let rec = SymProc32 { parent, end, next, proc_len, debug_start, debug_end, type_index, offset, segment, flags, name, is_global };
    if is_global { Ok(SymRecord::GProc32(rec)) } else { Ok(SymRecord::LProc32(rec)) }
}

fn decode_compile3(data: &[u8]) -> Result<SymRecord, CodeViewError> {
    if data.len() < 22 { return Err(CodeViewError::TruncatedStream); }
    let flags = read_u32(data, 0).unwrap();
    let machine = read_u16(data, 4).unwrap();
    let ver_fe_major = read_u16(data, 6).unwrap();
    let ver_fe_minor = read_u16(data, 8).unwrap();
    let ver_fe_build = read_u16(data, 10).unwrap();
    let ver_fe_qfe = read_u16(data, 12).unwrap();
    let ver_major = read_u16(data, 14).unwrap();
    let ver_minor = read_u16(data, 16).unwrap();
    let ver_build = read_u16(data, 18).unwrap();
    let ver_qfe = read_u16(data, 20).unwrap();
    let compiler_version = read_nul_str(data, 22);
    Ok(SymRecord::Compile3(SymCompile3 {
        flags, machine, ver_fe_major, ver_fe_minor, ver_fe_build, ver_fe_qfe,
        ver_major, ver_minor, ver_build, ver_qfe, compiler_version,
    }))
}

fn decode_frameproc(data: &[u8]) -> Result<SymRecord, CodeViewError> {
    if data.len() < 24 { return Err(CodeViewError::TruncatedStream); }
    Ok(SymRecord::FrameProc(SymFrameProc {
        frame_size: read_u32(data, 0).unwrap(),
        pad_size: read_u32(data, 4).unwrap(),
        pad_offset: read_u32(data, 8).unwrap(),
        save_reg_size: read_u32(data, 12).unwrap(),
        except_handler_offset: read_u32(data, 16).unwrap(),
        except_handler_section: read_u16(data, 20).unwrap(),
        flags: read_u32(data, 22).unwrap_or(0),
    }))
}

/// Decode a single `CodeView` symbol record body given its `kind` and raw `data`.
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when `data` is shorter than the
/// kind-specific minimum header.
///
/// # Panics
/// Does not panic — `read_*` unwraps are guarded by explicit `data.len()`
/// checks at the start of each match arm.
pub fn decode_symbol_record(kind: u16, data: &[u8]) -> Result<SymRecord, CodeViewError> {
    match kind {
        sk::PUB32 => decode_pub32(data),
        sk::LDATA32 | sk::GDATA32 | sk::LTHREAD32 | sk::GTHREAD32 => decode_data32(kind, data),
        sk::LPROC32 | sk::GPROC32 | sk::LPROC32_ID | sk::GPROC32_ID => decode_proc32(kind, data),
        sk::THUNK32 => {
            if data.len() < 17 { return Err(CodeViewError::TruncatedStream); }
            let parent = read_u32(data, 0).unwrap();
            let end = read_u32(data, 4).unwrap();
            let next = read_u32(data, 8).unwrap();
            let offset = read_u32(data, 12).unwrap();
            let segment = read_u16(data, 16).unwrap();
            let thunk_len = read_u16(data, 18).unwrap_or(0);
            let kind = data.get(20).copied().unwrap_or(0);
            let name = read_nul_str(data, 21);
            Ok(SymRecord::Thunk32(SymThunk32 { parent, end, next, offset, segment, thunk_len, kind, name }))
        }
        sk::BLOCK32 => {
            if data.len() < 18 { return Err(CodeViewError::TruncatedStream); }
            let parent = read_u32(data, 0).unwrap();
            let end = read_u32(data, 4).unwrap();
            let block_len = read_u32(data, 8).unwrap();
            let offset = read_u32(data, 12).unwrap();
            let segment = read_u16(data, 16).unwrap();
            let name = read_nul_str(data, 18);
            Ok(SymRecord::Block32(SymBlock32 { parent, end, block_len, offset, segment, name }))
        }
        sk::LABEL32 => {
            if data.len() < 7 { return Err(CodeViewError::TruncatedStream); }
            let offset = read_u32(data, 0).unwrap();
            let segment = read_u16(data, 4).unwrap();
            let flags = data.get(6).copied().unwrap_or(0);
            let name = read_nul_str(data, 7);
            Ok(SymRecord::Label32(SymLabel32 { offset, segment, flags, name }))
        }
        sk::CONSTANT | sk::MANCONSTANT => {
            if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
            let type_index = read_u32(data, 0).unwrap();
            let (value, consumed) = read_numeric_leaf_local(&data[4..]);
            let name = read_nul_str(data, 4 + consumed);
            Ok(SymRecord::Constant(SymConstant { type_index, value, name }))
        }
        sk::UDT | sk::COBOLUDT => {
            if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
            let type_index = read_u32(data, 0).unwrap();
            let name = read_nul_str(data, 4);
            Ok(SymRecord::Udt(SymUdt { type_index, name }))
        }
        sk::REGREL32 => {
            if data.len() < 10 { return Err(CodeViewError::TruncatedStream); }
            let offset = read_i32(data, 0).unwrap();
            let type_index = read_u32(data, 4).unwrap();
            let reg_val = read_u16(data, 8).unwrap();
            let register = CvReg::from_u16(reg_val);
            let name = read_nul_str(data, 10);
            Ok(SymRecord::RegRel32(SymRegRel32 {
                offset,
                type_index,
                register,
                register_number: reg_val,
                name,
            }))
        }
        sk::LOCAL | sk::LOCAL_DPC_GROUPSHARED => {
            if data.len() < 6 { return Err(CodeViewError::TruncatedStream); }
            let type_index = read_u32(data, 0).unwrap();
            let flags = read_u16(data, 4).unwrap();
            let name = read_nul_str(data, 6);
            Ok(SymRecord::Local(SymLocal { type_index, flags, name }))
        }
        sk::COMPILE3 => decode_compile3(data),
        sk::FRAMEPROC => decode_frameproc(data),
        sk::CALLSITEINFO => {
            // CALLSITEINFO: off:u32@0, sect:u16@4, __reserved:u16@6, typind:u32@8
            if data.len() < 10 { return Err(CodeViewError::TruncatedStream); }
            let offset = read_u32(data, 0).unwrap();
            let section = read_u16(data, 4).unwrap();
            let type_index = read_u32(data, 8).unwrap_or(0);
            Ok(SymRecord::CallSiteInfo(SymCallSiteInfo { offset, section, type_index }))
        }
        sk::HEAPALLOCSITE => {
            if data.len() < 10 { return Err(CodeViewError::TruncatedStream); }
            let offset = read_u32(data, 0).unwrap();
            let section = read_u16(data, 4).unwrap();
            let inst_len = read_u16(data, 6).unwrap();
            let type_index = read_u32(data, 8).unwrap();
            Ok(SymRecord::HeapAllocSite(SymHeapAllocSite { offset, section, inst_len, type_index }))
        }
        sk::OBJNAME => {
            if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
            let signature = read_u32(data, 0).unwrap();
            let name = read_nul_str(data, 4);
            Ok(SymRecord::ObjName(SymObjName { signature, name }))
        }
        sk::UNAMESPACE => {
            let name = read_nul_str(data, 0);
            Ok(SymRecord::UsingNamespace(SymUsingNamespace { name }))
        }
        sk::BUILDINFO => {
            if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
            let item_id = read_u32(data, 0).unwrap();
            Ok(SymRecord::BuildInfo(SymBuildInfo { item_id }))
        }
        sk::END | sk::PROC_ID_END => Ok(SymRecord::End),
        sk::INLINESITE_END => Ok(SymRecord::InlineSiteEnd),
        _ => Ok(SymRecord::Unknown { kind }),
    }
}

// ---------------------------------------------------------------------------
// Symbol stream decoder — decodes all records
// ---------------------------------------------------------------------------

/// Decode every record in a raw `CodeView` symbol stream, one `Result` per record.
///
/// # Status: unused (as of 2026-07-21)
/// No caller anywhere in the crate or `rustre-mcp-tools` — only this file's
/// own `#[cfg(test)]` module exercises it. The live symbol path is
/// `mod.rs::parse_cv_symbols` (via `CodeViewProvider`). See
/// `ENHANCEMENT_LOG.md` iters 230/232/233. Note: `read_numeric_leaf` is
/// re-exported from `cv_type_records.rs`, not defined here.
#[must_use]
pub fn decode_symbol_stream(data: &[u8]) -> Vec<Result<SymRecord, CodeViewError>> {
    use super::codeview_parser::RawSymIter;
    RawSymIter::new(data)
        .map(|r| r.and_then(|raw| decode_symbol_record(raw.kind, raw.data)))
        .collect()
}

// ---------------------------------------------------------------------------
// Address map builder from symbol stream
// ---------------------------------------------------------------------------

/// Sorted `(segment, offset)` → `(name, type_index)` index over the addressable
/// symbols of a symbol stream, supporting exact and nearest-preceding lookup.
#[derive(Debug, Default, Clone)]
pub struct SymbolAddressIndex {
    /// (segment, offset) → (name, `type_index`)
    entries: Vec<(u16, u32, String, u32)>,
    sorted: bool,
}

impl SymbolAddressIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Build a sorted index from a raw symbol stream via [`decode_symbol_stream`].
    #[must_use]
    pub fn build_from_stream(data: &[u8]) -> Self {
        let mut idx = Self::new();
        for result in decode_symbol_stream(data) {
            if let Ok(rec) = result
                && let Some((seg, off)) = rec.segment_offset() {
                    let name = rec.name().unwrap_or("").to_owned();
                    let ti = match &rec {
                        SymRecord::LData32(s) | SymRecord::GData32(s) => s.type_index,
                        SymRecord::LProc32(s) | SymRecord::GProc32(s) => s.type_index,
                        _ => 0,
                    };
                    idx.insert(seg, off, name, ti);
                }
        }
        idx.sort();
        idx
    }

    /// Add an entry; the index must be re-[`sort`](Self::sort)ed before lookup.
    pub fn insert(&mut self, seg: u16, off: u32, name: String, ti: u32) {
        self.entries.push((seg, off, name, ti));
        self.sorted = false;
    }

    /// Sort entries by `(segment, offset)`, enabling the `find_*` lookups.
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|&(s, o, _, _)| (s, o));
        self.sorted = true;
    }

    /// Exact-address lookup; returns `(name, type_index)`. `None` if unsorted or absent.
    #[must_use]
    pub fn find_exact(&self, seg: u16, off: u32) -> Option<(&str, u32)> {
        if !self.sorted { return None; }
        let idx = self.entries.partition_point(|&(s, o, _, _)| (s, o) < (seg, off));
        let e = self.entries.get(idx)?;
        if e.0 == seg && e.1 == off { Some((&e.2, e.3)) } else { None }
    }

    /// Nearest symbol at or before the address in the same segment; returns
    /// `(name, displacement, type_index)`. `None` if unsorted or none precedes.
    #[must_use]
    pub fn find_nearest(&self, seg: u16, off: u32) -> Option<(&str, u32, u32)> {
        if !self.sorted { return None; }
        let idx = self.entries.partition_point(|&(s, o, _, _)| (s, o) <= (seg, off));
        if idx == 0 { return None; }
        let e = &self.entries[idx - 1];
        if e.0 != seg { return None; }
        let disp = off.saturating_sub(e.1);
        Some((&e.2, disp, e.3))
    }

    /// Iterate `(name, offset)` over all entries in the given segment.
    pub fn all_names_in_segment(&self, seg: u16) -> impl Iterator<Item = (&str, u32)> {
        self.entries.iter()
            .filter(move |e| e.0 == seg)
            .map(|e| (e.2.as_str(), e.1))
    }

    /// Number of entries in the index.
    #[must_use]
    pub const fn len(&self) -> usize { self.entries.len() }
    /// True if the index has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ---------------------------------------------------------------------------
// Annotation helper (inline site binary annotations)
// ---------------------------------------------------------------------------

/// Decode a compressed unsigned integer from binary annotation stream.
fn decode_unsigned_int(data: &[u8]) -> Option<(u32, usize)> {
    let b0 = u32::from(*data.first()?);
    if (b0 & 0x80) == 0 { return Some((b0, 1)); }
    if data.len() < 2 { return None; }
    let b1 = u32::from(data[1]);
    if (b0 & 0xC0) == 0x80 { return Some(((b0 & 0x3F) << 8 | b1, 2)); }
    if data.len() < 4 { return None; }
    let b2 = u32::from(data[2]);
    let b3 = u32::from(data[3]);
    Some(((b0 & 0x1F) << 24 | b1 << 16 | b2 << 8 | b3, 4))
}

/// A decoded binary annotation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryAnnotation {
    /// Set the absolute code offset (`BA_OP_CodeOffset`).
    CodeOffset(u32),
    /// Change the code-offset base segment (`BA_OP_ChangeCodeOffsetBase`).
    ChangeCodeOffsetBase(u32),
    /// Advance the code offset by a delta (`BA_OP_ChangeCodeOffset`).
    ChangeCodeOffset(u32),
    /// Set the length of the current code range (`BA_OP_ChangeCodeLength`).
    ChangeCodeLength(u32),
    /// Switch to a different source file id (`BA_OP_ChangeFile`).
    ChangeFile(u32),
    /// Advance the source line by a signed delta (`BA_OP_ChangeLineOffset`).
    ChangeLineOffset(i32),
    /// Change the line-end delta (`BA_OP_ChangeLineEndDelta`).
    ChangeLineEndDelta(u32),
    /// Change the range kind, statement vs expression (`BA_OP_ChangeRangeKind`).
    ChangeRangeKind(u32),
    /// Set the starting column (`BA_OP_ChangeColumnStart`).
    ChangeColumnStart(u32),
    /// Set the ending column (`BA_OP_ChangeColumnEnd`).
    ChangeColumnEnd(u32),
    /// Combined code-offset and line-offset advance (`BA_OP_ChangeCodeOffsetAndLineOffset`).
    ChangeCodeOffsetAndLineOffset {
        /// Code offset delta (high bits of the packed operand).
        code_delta: u32,
        /// Signed line delta (zigzag-decoded low nibble).
        line_delta: i32,
    },
    /// Combined code-length and code-offset update (`BA_OP_ChangeCodeLengthAndCodeOffset`).
    ChangeCodeLengthAndCodeOffset {
        /// New code range length.
        code_length: u32,
        /// New code offset.
        code_offset: u32,
    },
    /// Signed change to the ending column (`BA_OP_ChangeColumnEndDelta`).
    ChangeColumnEndDelta(i32),
}

/// Decode a `CodeView` zigzag-encoded signed operand.
const fn zigzag(v: u32) -> i32 {
    let s = super::casts::u32_as_i32(v >> 1);
    if v & 1 != 0 { -s } else { s }
}

/// Decode the binary annotation stream of an `S_INLINESITE` record into a list
/// of [`BinaryAnnotation`] ops. Decoding stops at the 0 terminator or on any
/// unrecognized opcode.
#[must_use]
pub fn decode_binary_annotations(data: &[u8]) -> Vec<BinaryAnnotation> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < data.len() {
        let Some((op, n)) = decode_unsigned_int(&data[pos..]) else { break };
        pos += n;
        match op {
            1 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::CodeOffset(v)); } }
            2 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeCodeOffsetBase(v)); } }
            3 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeCodeOffset(v)); } }
            4 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeCodeLength(v)); } }
            5 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeFile(v)); } }
            6 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; let s = zigzag(v); out.push(BinaryAnnotation::ChangeLineOffset(s)); } }
            7 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeLineEndDelta(v)); } }
            8 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeRangeKind(v)); } }
            9 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeColumnStart(v)); } }
            10 => { if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) { pos += n2; out.push(BinaryAnnotation::ChangeColumnEnd(v)); } }
            11 => {
                if let Some((v, n2)) = decode_unsigned_int(&data[pos..]) {
                    pos += n2;
                    out.push(BinaryAnnotation::ChangeColumnEndDelta(zigzag(v)));
                }
            }
            12 => {
                // ChangeCodeOffsetAndLineOffset: code delta in the high bits,
                // zigzag-encoded line delta in the low nibble.
                if let Some((packed, n2)) = decode_unsigned_int(&data[pos..]) {
                    pos += n2;
                    let code_delta = packed >> 4;
                    let line_delta = zigzag(packed & 0xF);
                    out.push(BinaryAnnotation::ChangeCodeOffsetAndLineOffset { code_delta, line_delta });
                }
            }
            13 => {
                if let Some((code_length, n2)) = decode_unsigned_int(&data[pos..]) {
                    pos += n2;
                    if let Some((code_offset, n3)) = decode_unsigned_int(&data[pos..]) {
                        pos += n3;
                        out.push(BinaryAnnotation::ChangeCodeLengthAndCodeOffset { code_length, code_offset });
                    }
                }
            }
            // op == 0 is the explicit terminator; any other unrecognized op also stops decoding.
            _ => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pub32(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes()); // flags: function
        v.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        v.extend_from_slice(&1u16.to_le_bytes()); // segment
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        v
    }

    /// An arm64 PDB must remain decodable: keep the raw number, decode it right.
    ///
    /// Register numbering is per-architecture and an `S_REGREL32` record does
    /// not say which one it uses (the machine lives in the DBI header). The
    /// parser decoded straight to `CvReg`, the x86/x64 table, and threw the raw
    /// number away — so an arm64 local at `[sp+N]` came back as some x86
    /// register and the evidence needed to fix it was gone.
    ///
    /// The overlap is real, not theoretical: arm64 numbers 10..=40 are the `w`
    /// registers, and those same numbers in the x86 space are `cx`, `dx`,
    /// `eax`, … — a confident wrong answer rather than an obvious blank.
    #[test]
    fn an_arm64_regrel_record_keeps_the_number_needed_to_decode_it() {
        // 81 = CV_ARM64_SP: a local relative to the stack pointer.
        let mut data = Vec::new();
        data.extend_from_slice(&(-16i32).to_le_bytes());
        data.extend_from_slice(&0x1074u32.to_le_bytes());
        data.extend_from_slice(&81u16.to_le_bytes());
        data.extend_from_slice(b"arm_local ");
        let SymRecord::RegRel32(r) = decode_symbol_record(sk::REGREL32, &data).unwrap() else {
            panic!("expected an S_REGREL32 record");
        };

        assert_eq!(
            r.register_number, 81,
            "the raw number must survive: it is the only architecture-independent fact"
        );
        assert_eq!(
            CvArm64Reg::from_u16(r.register_number),
            CvArm64Reg::Sp,
            "a caller that knows the image is arm64 must be able to decode it correctly"
        );
        assert_eq!(CvArm64Reg::from_u16(r.register_number).to_string(), "sp");

        // The overlapping range: 17 is `eax` on x86 and `w7` on arm64. Both
        // decoders must be available and must disagree — that disagreement is
        // exactly why the raw number has to be kept.
        assert_eq!(CvReg::from_u16(17), CvReg::Eax);
        assert_eq!(CvArm64Reg::from_u16(17), CvArm64Reg::W(7));

        // Spot-check the rest of the arm64 space.
        assert_eq!(CvArm64Reg::from_u16(50), CvArm64Reg::X(0));
        assert_eq!(CvArm64Reg::from_u16(78), CvArm64Reg::X(28));
        assert_eq!(CvArm64Reg::from_u16(79), CvArm64Reg::Fp);
        assert_eq!(CvArm64Reg::from_u16(80), CvArm64Reg::Lr);
        assert_eq!(CvArm64Reg::from_u16(83), CvArm64Reg::Pc);
        assert_eq!(CvArm64Reg::from_u16(9999), CvArm64Reg::Unknown(9999));
    }

    /// `IMAGE_FILE_MACHINE_*` and `CV_CPU_TYPE_e` are different number spaces.
    ///
    /// This crate already mixed them once: a test builds
    /// `SCompile3 { machine: 0x8664, .. }` while that field is documented as
    /// `CV_CPU_TYPE_e` (where x64 is `0xD0`). Two constructors, and this test,
    /// exist so the confusion cannot be re-introduced silently.
    #[test]
    fn image_file_machine_and_cv_cpu_type_are_different_spaces() {
        assert_eq!(CvArch::from_image_file_machine(0x8664), CvArch::X64);
        assert!(
            matches!(CvArch::from_cv_cpu_type(0x8664), CvArch::Unknown(0x8664)),
            "0x8664 is a COFF machine value, not a CV_CPU_TYPE_e: it must not decode"
        );
        assert_eq!(CvArch::from_cv_cpu_type(0xD0), CvArch::X64);
        assert!(matches!(
            CvArch::from_image_file_machine(0xD0),
            CvArch::Unknown(0xD0)
        ));
    }

    /// `0xAA64` is arm64 and must not be mistaken for anything else.
    #[test]
    fn arm64_image_file_machine_is_aa64() {
        assert_eq!(CvArch::from_image_file_machine(0xAA64), CvArch::Arm64);
        assert_ne!(CvArch::from_image_file_machine(0xAA64), CvArch::X64);
        assert_eq!(CvArch::from_image_file_machine(0x014C), CvArch::X86);
        assert_eq!(CvArch::from_image_file_machine(0x01C4), CvArch::Arm32);
        assert!(matches!(
            CvArch::from_image_file_machine(0x01F0),
            CvArch::Unknown(0x01F0)
        ));
    }

    /// Stack-relativeness is an architecture-dependent question.
    ///
    /// Built from a real decoded record rather than a hand-made struct, so the
    /// parser is in the loop. The second assertion is the one that carries the
    /// weight: it proves the fix is "81 means SP **on arm64**", not "81 is
    /// always accepted".
    #[test]
    fn an_arm64_regrel_is_stack_relative_only_when_the_arch_says_arm64() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-16i32).to_le_bytes());
        data.extend_from_slice(&0x1074u32.to_le_bytes());
        data.extend_from_slice(&81u16.to_le_bytes()); // CV_ARM64_SP
        data.extend_from_slice(b"arm_local ");
        let SymRecord::RegRel32(r) = decode_symbol_record(sk::REGREL32, &data).unwrap() else {
            panic!("expected an S_REGREL32 record");
        };

        assert!(
            r.is_stack_relative(CvArch::Arm64),
            "81 is SP on arm64: a local at [sp-16] is stack-relative"
        );
        assert!(
            !r.is_stack_relative(CvArch::X64),
            "81 is not a stack/frame register in the x86/x64 space; accepting it \
             everywhere would just be a different wrong answer"
        );
        assert!(!r.is_stack_relative(CvArch::Unknown(0)));
    }

    /// The x64 answer must not regress while making the check arch-aware.
    #[test]
    fn an_x64_regrel_is_stack_relative_under_x64_only() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-8i32).to_le_bytes());
        data.extend_from_slice(&0x74u32.to_le_bytes());
        data.extend_from_slice(&335u16.to_le_bytes()); // RSP
        data.extend_from_slice(b"x64_local ");
        let SymRecord::RegRel32(r) = decode_symbol_record(sk::REGREL32, &data).unwrap() else {
            panic!("expected an S_REGREL32 record");
        };
        assert!(r.is_stack_relative(CvArch::X64));
        assert!(!r.is_stack_relative(CvArch::Arm64));
        assert!(!r.is_stack_relative(CvArch::X86));
    }

    /// The shared table is the only place the numbers live.
    #[test]
    fn reg_is_frame_or_stack_knows_each_architecture_separately() {
        assert!(reg_is_frame_or_stack(334, CvArch::X64));
        assert!(reg_is_frame_or_stack(335, CvArch::X64));
        assert!(!reg_is_frame_or_stack(79, CvArch::X64));

        assert!(reg_is_frame_or_stack(79, CvArch::Arm64));
        assert!(reg_is_frame_or_stack(81, CvArch::Arm64));
        assert!(!reg_is_frame_or_stack(335, CvArch::Arm64));
        // 80 is LR, not a frame pointer.
        assert!(!reg_is_frame_or_stack(80, CvArch::Arm64));

        // Cross-checked against the enum in this file, not written from memory.
        assert_eq!(CvReg::Esp as u16, 21);
        assert_eq!(CvReg::Ebp as u16, 22);
        assert!(reg_is_frame_or_stack(21, CvArch::X86));
        assert!(reg_is_frame_or_stack(22, CvArch::X86));

        assert!(!reg_is_frame_or_stack(335, CvArch::Unknown(0xAAAA)));
    }

    /// The AMD64 `CV_HREG_e` numbers must agree with the rest of the crate.
    ///
    /// Four other places treat **335 as RSP** and 334 as RBP
    /// (`is_stack_relative`, and the synthetic records in
    /// `codeview_symbol_parser` and `cv_function_info`), which matches the real
    /// CodeView order: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP for 328..=335.
    /// `CvReg` instead used the classic x86 order (AX, CX, DX, BX, SP, BP, SI,
    /// DI) on those numbers, so seven of the eight were wrong — only RAX lined
    /// up.
    ///
    /// `S_REGREL32` is how a PDB expresses ordinary local variables, nearly all
    /// of them `[rsp+N]` or `[rbp+N]`. Decoding 335 as `rdi` means the debugger
    /// reports a local as living at an offset from the WRONG register, and
    /// reads its value from there.
    ///
    /// Checked as internal consistency, not against an external table: whatever
    /// number the crate elsewhere calls RSP must decode to `Rsp` here.
    #[test]
    fn amd64_register_numbers_agree_across_the_crate() {
        // The numbers the rest of the crate uses for the stack registers.
        assert_eq!(CvReg::from_u16(335), CvReg::Rsp, "335 is RSP everywhere else in this crate");
        assert_eq!(CvReg::from_u16(334), CvReg::Rbp, "334 is RBP everywhere else in this crate");

        // The full 328..=335 block, in CodeView order.
        for (num, reg, name) in [
            (328u16, CvReg::Rax, "rax"),
            (329, CvReg::Rbx, "rbx"),
            (330, CvReg::Rcx, "rcx"),
            (331, CvReg::Rdx, "rdx"),
            (332, CvReg::Rsi, "rsi"),
            (333, CvReg::Rdi, "rdi"),
            (334, CvReg::Rbp, "rbp"),
            (335, CvReg::Rsp, "rsp"),
        ] {
            assert_eq!(CvReg::from_u16(num), reg, "{num} should decode to {name}");
            assert_eq!(reg as u16, num, "{name}'s discriminant must be its CV number");
            assert_eq!(reg.to_string(), name);
        }

        // The 32-bit block was already right and must stay so.
        assert_eq!(CvReg::from_u16(21), CvReg::Esp);
        assert_eq!(CvReg::from_u16(22), CvReg::Ebp);
    }

    #[test]
    fn test_decode_pub32() {
        let data = build_pub32("_MyFunction");
        let rec = decode_symbol_record(sk::PUB32, &data).unwrap();
        if let SymRecord::Pub32(p) = rec {
            assert_eq!(p.name, "_MyFunction");
            assert!(p.is_function());
            assert_eq!(p.offset, 0x1000);
            assert_eq!(p.segment, 1);
        } else { panic!(); }
    }

    #[test]
    fn test_decode_data32() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1074u32.to_le_bytes()); // type_index
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // offset
        data.extend_from_slice(&2u16.to_le_bytes()); // segment
        data.extend_from_slice(b"g_count\0");
        let rec = decode_symbol_record(sk::GDATA32, &data).unwrap();
        if let SymRecord::GData32(d) = rec {
            assert_eq!(d.name, "g_count");
            assert!(d.is_global);
        } else { panic!(); }
    }

    #[test]
    fn test_decode_proc32() {
        let mut data = vec![0u8; 35];
        data[12..16].copy_from_slice(&100u32.to_le_bytes()); // proc_len
        data[24..28].copy_from_slice(&0x1068u32.to_le_bytes()); // type_index
        data[28..32].copy_from_slice(&0x1000u32.to_le_bytes()); // offset
        data[32..34].copy_from_slice(&1u16.to_le_bytes()); // segment
        data[34] = 0; // flags
        data.extend_from_slice(b"main\0");
        let rec = decode_symbol_record(sk::GPROC32, &data).unwrap();
        if let SymRecord::GProc32(p) = rec {
            assert_eq!(p.name, "main");
            assert_eq!(p.proc_len, 100);
            assert!(p.is_global);
        } else { panic!(); }
    }

    #[test]
    fn test_decode_constant() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1007u32.to_le_bytes()); // enum type
        data.extend_from_slice(&7u16.to_le_bytes()); // numeric leaf = 7
        data.extend_from_slice(b"MAX_VALUE\0");
        let rec = decode_symbol_record(sk::CONSTANT, &data).unwrap();
        if let SymRecord::Constant(c) = rec {
            assert_eq!(c.value, 7);
            assert_eq!(c.name, "MAX_VALUE");
        } else { panic!(); }
    }

    #[test]
    fn test_symbol_address_index() {
        let mut idx = SymbolAddressIndex::new();
        idx.insert(1, 0x1000, "func_a".into(), 0x1100);
        idx.insert(1, 0x2000, "func_b".into(), 0x1101);
        idx.insert(1, 0x1800, "func_c".into(), 0x1102);
        idx.sort();
        let (name, disp, _ti) = idx.find_nearest(1, 0x1900).unwrap();
        assert_eq!(name, "func_c");
        assert_eq!(disp, 0x100);
        let exact = idx.find_exact(1, 0x1000);
        assert!(exact.is_some());
        assert_eq!(exact.unwrap().0, "func_a");
    }

    /// Regression: `typind` lives at offset 8 of `CALLSITEINFO`, after the
    /// 2-byte `__reserved` field; it was read at offset 6.
    #[test]
    fn test_decode_callsiteinfo_type_index_at_offset_8() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u32.to_le_bytes()); // off
        data.extend_from_slice(&2u16.to_le_bytes()); // sect
        data.extend_from_slice(&0u16.to_le_bytes()); // __reserved
        data.extend_from_slice(&0x1080u32.to_le_bytes()); // typind
        let rec = decode_symbol_record(sk::CALLSITEINFO, &data).unwrap();
        match rec {
            SymRecord::CallSiteInfo(cs) => {
                assert_eq!(cs.offset, 0x1234);
                assert_eq!(cs.section, 2);
                assert_eq!(cs.type_index, 0x1080);
            }
            other => panic!("expected CallSiteInfo, got {other:?}"),
        }
    }

    /// Regression: `ChangeCodeOffsetAndLineOffset` is opcode 12 and
    /// `ChangeCodeLengthAndCodeOffset` is 13 — they were decoded as 13 and 14,
    /// and opcode 11 (`ChangeColumnEndDelta`) terminated the stream.
    #[test]
    fn test_binary_annotation_opcodes_are_shifted_correctly() {
        // op 12, packed = (code_delta << 4) | zigzag(line_delta = -1) = 3
        let packed: u32 = (5u32 << 4) | 3;
        let ann = decode_binary_annotations(&[12, u8::try_from(packed).unwrap()]);
        assert_eq!(ann.len(), 1);
        match ann[0] {
            BinaryAnnotation::ChangeCodeOffsetAndLineOffset { code_delta, line_delta } => {
                assert_eq!(code_delta, 5);
                assert_eq!(line_delta, -1);
            }
            ref other => panic!("expected ChangeCodeOffsetAndLineOffset, got {other:?}"),
        }

        let ann = decode_binary_annotations(&[13, 0x10, 0x20]);
        assert!(matches!(
            ann.as_slice(),
            [BinaryAnnotation::ChangeCodeLengthAndCodeOffset { code_length: 0x10, code_offset: 0x20 }]
        ));

        // op 11 = ChangeColumnEndDelta, zigzag(4) = 2
        let ann = decode_binary_annotations(&[11, 4]);
        assert!(matches!(
            ann.as_slice(),
            [BinaryAnnotation::ChangeColumnEndDelta(2)]
        ));
    }

    #[test]
    fn test_decode_end() {
        let rec = decode_symbol_record(sk::END, &[]).unwrap();
        assert!(matches!(rec, SymRecord::End));
    }

    #[test]
    fn test_cv_reg_display() {
        assert_eq!(CvReg::Rax.to_string(), "rax");
        assert_eq!(CvReg::R15.to_string(), "r15");
    }

    #[test]
    fn test_decode_regrel32() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-8i32).to_le_bytes()); // offset
        data.extend_from_slice(&0x1074u32.to_le_bytes()); // type_index
        // 334, not 333: CodeView numbers the AMD64 block RAX, RBX, RCX, RDX,
        // RSI, RDI, RBP, RSP over 328..=335. This test previously said 333 was
        // `rbp` because it was written against the crate's own (wrong) table —
        // it pinned the defect rather than the format. 334 is what the rest of
        // the crate, and the format, call RBP.
        data.extend_from_slice(&334u16.to_le_bytes()); // rbp
        data.extend_from_slice(b"local_var\0");
        let rec = decode_symbol_record(sk::REGREL32, &data).unwrap();
        if let SymRecord::RegRel32(r) = rec {
            assert_eq!(r.offset, -8);
            assert_eq!(r.register, CvReg::Rbp);
            assert_eq!(r.name, "local_var");
        } else { panic!(); }
    }
}
