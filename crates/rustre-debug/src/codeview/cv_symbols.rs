//! `CodeView` symbol records.
//!
//! Full decoding of `S_PUB32`, `S_GPROC32`, `S_LPROC32`, `S_GDATA32`, `S_LDATA32`,
//! `S_LABEL32`, `S_THUNK32`, `S_BLOCK32`, `S_WITH32`, `S_COMPILE3`, `S_FRAMEPROC`,
//! `S_REGREL32`, `S_LOCAL`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::cv_types::TypeIndex;

// ─────────────────────────────────────────────────────────────────────────────
// Symbol kind codes (S_*)
// ─────────────────────────────────────────────────────────────────────────────

/// `CodeView` symbol record kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum SymKind {
    /// `S_PUB32` — public (linker-visible) symbol.
    Pub32 = 0x110E,
    /// `S_GPROC32` — global procedure start.
    Gproc32 = 0x1110,
    /// `S_LPROC32` — local (static) procedure start.
    Lproc32 = 0x110F,
    /// `S_GDATA32` — global data symbol.
    Gdata32 = 0x110D,
    /// `S_LDATA32` — module-local (static) data symbol.
    Ldata32 = 0x110C,
    /// `S_LABEL32` — code label.
    Label32 = 0x1105,
    /// `S_THUNK32` — thunk (stub) procedure.
    Thunk32 = 0x1102,
    /// `S_BLOCK32` — lexical block start.
    Block32 = 0x1103,
    /// `S_WITH32` — Pascal `with` block start.
    With32 = 0x1104,
    /// `S_COMPILE3` — compilation unit / compiler info.
    Compile3 = 0x113C,
    /// `S_FRAMEPROC` — frame/stack layout info for a procedure.
    FrameProc = 0x1012,
    /// `S_REGREL32` — register-relative variable.
    Regrel32 = 0x1111,
    /// `S_LOCAL` — local variable (new format).
    Local = 0x113E,
    // Additional common ones
    /// `S_OBJNAME` — originating object file name.
    ObjName = 0x1101,
    /// `S_END` — scope terminator for proc/block/thunk/with records.
    End = 0x0006,
    /// `S_LPROCREF` — reference to a local procedure in another module.
    Proc32Id = 0x1127,
    /// Annotated label record.
    LabelAnnot = 0x1019,
}

impl SymKind {
    /// Map a raw `S_*` kind value to a known [`SymKind`], or `None` if unmodeled.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x110E => Self::Pub32,
            0x1110 => Self::Gproc32,
            0x110F => Self::Lproc32,
            0x1111 => Self::Regrel32,
            0x110D => Self::Gdata32,
            0x110C => Self::Ldata32,
            0x1105 => Self::Label32,
            0x1102 => Self::Thunk32,
            0x1103 => Self::Block32,
            0x1104 => Self::With32,
            0x113C => Self::Compile3,
            0x1012 => Self::FrameProc,
            0x113E => Self::Local,
            0x1101 => Self::ObjName,
            0x0006 => Self::End,
            _ => return None,
        })
    }

    /// Canonical `S_*` name of this kind (e.g. `"S_GPROC32"`).
    #[must_use]
    pub const fn name_str(self) -> &'static str {
        match self {
            Self::Pub32 => "S_PUB32",
            Self::Gproc32 => "S_GPROC32",
            Self::Lproc32 => "S_LPROC32",
            Self::Gdata32 => "S_GDATA32",
            Self::Ldata32 => "S_LDATA32",
            Self::Label32 => "S_LABEL32",
            Self::Thunk32 => "S_THUNK32",
            Self::Block32 => "S_BLOCK32",
            Self::With32 => "S_WITH32",
            Self::Compile3 => "S_COMPILE3",
            Self::FrameProc => "S_FRAMEPROC",
            Self::Regrel32 => "S_REGREL32",
            Self::Local => "S_LOCAL",
            Self::ObjName => "S_OBJNAME",
            Self::End => "S_END",
            Self::Proc32Id => "S_PROC32ID",
            Self::LabelAnnot => "S_LABEL_ANNOT",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol record structs
// ─────────────────────────────────────────────────────────────────────────────

/// `S_PUB32` — public symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPub32 {
    /// `CV_PUBSYMFLAGS`: bit 1 = code, bit 2 = function, bit 3 = managed, bit 4 = MSIL.
    pub flags: u32,
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Decorated (mangled) public symbol name.
    pub name: String,
}

impl SPub32 {
    /// True if the public symbol refers to a function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.flags & 0x02 != 0
    }
    /// True if the symbol is managed code.
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        self.flags & 0x04 != 0
    }
    /// True if the symbol is MSIL code.
    #[must_use]
    pub const fn is_msil(&self) -> bool {
        self.flags & 0x08 != 0
    }
}

/// `S_GPROC32` / `S_LPROC32` — global/local procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SProc32 {
    /// Parent scope offset in the symbol stream (0 if none).
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Stream offset of the next procedure (linked list; often 0).
    pub next: u32,
    /// Length of the procedure in bytes.
    pub len: u32,
    /// Offset from procedure start where the prologue ends.
    pub debug_start: u32,
    /// Offset from procedure start where the epilogue begins.
    pub debug_end: u32,
    /// TPI type index of the function signature.
    pub type_index: TypeIndex,
    /// Offset within `segment` of the entry point.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// `CV_PROCFLAGS` bit set.
    pub flags: u8,
    /// Procedure name.
    pub name: String,
    /// True for `S_GPROC32`, false for `S_LPROC32`.
    pub is_global: bool,
}

/// `CV_PROCFLAGS`, from Microsoft's `cvinfo.h`.
///
/// The bit that means "this function never returns" is **`CV_PFLAG_NEVER`,
/// bit 3**. Three places in this crate decoded it, and all three were wrong in
/// two different ways: `SProc32`/`SLabel32` read bit 0 (`CV_PFLAG_NOFPO`, which
/// is about frame-pointer omission) and `cv_function_info` read bit 1
/// (`CV_PFLAG_INT`, an interrupt return). Neither answer has anything to do
/// with returning, and both are booleans a caller acts on — a `noreturn`
/// function is one a debugger will not plant a return breakpoint in.
///
/// This file already carries the scar of the same class: iteration 342 found
/// seven of eight `CodeView` AMD64 registers wrong, unnoticed because nothing
/// read them.
pub mod cv_procflags {
    /// Frame pointer present (NOT "inlined", NOT "noreturn").
    pub const NOFPO: u8 = 0x01;
    /// Interrupt return.
    pub const INT: u8 = 0x02;
    /// Far return.
    pub const FAR: u8 = 0x04;
    /// The function never returns.
    pub const NEVER: u8 = 0x08;
    /// The label is not fallen into.
    pub const NOTREACHED: u8 = 0x10;
    /// Custom calling convention.
    pub const CUST_CALL: u8 = 0x20;
    /// Marked `noinline`.
    pub const NOINLINE: u8 = 0x40;
    /// Has debug information for optimized code.
    pub const OPTDBGINFO: u8 = 0x80;
}

/// Whether a `CV_PROCFLAGS` byte says the function never returns.
///
/// One definition, so the three decoders cannot disagree again.
#[must_use]
pub const fn procflags_never_returns(flags: u8) -> bool {
    flags & cv_procflags::NEVER != 0
}

impl SProc32 {
    /// Segment-relative start address of the procedure.
    #[must_use]
    pub const fn start_addr(&self) -> u64 {
        self.offset as u64
    }
    /// Segment-relative end address (`offset + len`).
    ///
    /// Saturating: both fields come from the file, and `offset + len` used to
    /// be an unchecked `u32` addition — a panic in a debug build and a wrapped,
    /// far too small end in release.
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        self.offset as u64 + self.len as u64
    }
    /// True if the procedure never returns (`CV_PFLAG_NEVER`).
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        procflags_never_returns(self.flags)
    }
}

/// `S_GDATA32` / `S_LDATA32` — global/local data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SData32 {
    /// TPI type index of the data.
    pub type_index: TypeIndex,
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Symbol name.
    pub name: String,
    /// True for `S_GDATA32` (global), false for `S_LDATA32` (module-local).
    pub is_global: bool,
}

/// `S_LABEL32` — code label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLabel32 {
    /// Offset within `segment`.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// `CV_PROCFLAGS`-style flags for the label.
    pub flags: u8,
    /// Label name.
    pub name: String,
}

impl SLabel32 {
    /// True if code at the label never returns (`CV_PFLAG_NEVER`).
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        procflags_never_returns(self.flags)
    }
}

/// `S_THUNK32` — thunk (stub) procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SThunk32 {
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
    pub len: u16,
    /// `THUNK_ORDINAL` (0 = no type, 1 = adjustor, 2 = vcall, ...).
    pub ordinal: u8,
    /// Thunk name.
    pub name: String,
    /// Ordinal-specific trailing variant data (e.g. adjustor delta).
    pub variant: Vec<u8>,
}

/// `S_BLOCK32` — lexical block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SBlock32 {
    /// Parent scope offset in the symbol stream.
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Length of the block in bytes.
    pub len: u32,
    /// Offset within `segment` of the block start.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Optional block name (usually empty).
    pub name: String,
}

impl SBlock32 {
    /// Segment-relative start address of the block.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.offset as u64
    }
    /// Segment-relative end address (`offset + len`).
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        (self.offset + self.len) as u64
    }
}

/// `S_WITH32` — with block (Pascal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SWith32 {
    /// Parent scope offset in the symbol stream.
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Length of the block in bytes.
    pub len: u32,
    /// Offset within `segment` of the block start.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// The `with` expression text.
    pub expression: String,
}

/// `S_COMPILE3` — compilation unit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SCompile3 {
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
    /// Compiler version string.
    pub ver_str: String,
}

impl SCompile3 {
    /// Architecture declared by this record, decoded as a `CV_CPU_TYPE_e`.
    ///
    /// A second, independent source of the architecture beside the PE COFF
    /// machine ([`pe_arch`](crate::codeview::pe_arch)) — useful when only a PDB
    /// is at hand.
    ///
    /// Unrecognised values give [`CvArch::Unknown`] rather than a guess. Note
    /// that `machine` is a `CV_CPU_TYPE_e`, **not** an `IMAGE_FILE_MACHINE_*`:
    /// a record carrying `0x8664` (as one test in this file does) is malformed
    /// with respect to the format and correctly decodes to `Unknown`.
    #[must_use]
    pub const fn arch(&self) -> crate::codeview::cv_symbol_records::CvArch {
        crate::codeview::cv_symbol_records::CvArch::from_cv_cpu_type(self.machine)
    }

    /// Source language of the compilation unit (low byte of `flags`).
    #[must_use]
    pub const fn language(&self) -> CompileLanguage {
        match self.flags & 0xFF {
            0 => CompileLanguage::C,
            1 => CompileLanguage::Cpp,
            2 => CompileLanguage::Fortran,
            3 => CompileLanguage::Masm,
            4 => CompileLanguage::Pascal,
            5 => CompileLanguage::Basic,
            6 => CompileLanguage::Cobol,
            7 => CompileLanguage::Link,
            8 => CompileLanguage::Cvtres,
            9 => CompileLanguage::Cvtpgd,
            10 => CompileLanguage::CSharp,
            11 => CompileLanguage::VisualBasic,
            12 => CompileLanguage::ILAsm,
            13 => CompileLanguage::Java,
            14 => CompileLanguage::JScript,
            15 => CompileLanguage::Msil,
            16 => CompileLanguage::HLSl,
            _ => CompileLanguage::Unknown,
        }
    }
}

/// Source language code carried in `S_COMPILE3` (`CV_CFL_LANG`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompileLanguage {
    /// C.
    C,
    /// C++.
    Cpp,
    /// Fortran.
    Fortran,
    /// Microsoft Macro Assembler.
    Masm,
    /// Pascal.
    Pascal,
    /// BASIC.
    Basic,
    /// COBOL.
    Cobol,
    /// Linker-generated module.
    Link,
    /// CVTRES resource conversion tool.
    Cvtres,
    /// CVTPGD profile-guided-data tool.
    Cvtpgd,
    /// C#.
    CSharp,
    /// Visual Basic.
    VisualBasic,
    /// IL assembler.
    ILAsm,
    /// Java.
    Java,
    /// `JScript`.
    JScript,
    /// MSIL netmodule.
    Msil,
    /// High Level Shader Language.
    HLSl,
    /// Any language code not listed above.
    Unknown,
}

impl fmt::Display for CompileLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Fortran => "Fortran",
            Self::Masm => "MASM",
            Self::Pascal => "Pascal",
            Self::Basic => "BASIC",
            Self::Cobol => "COBOL",
            Self::Link => "Linker",
            Self::Cvtres => "CVTRES",
            Self::Cvtpgd => "CVTPGD",
            Self::CSharp => "C#",
            Self::VisualBasic => "VB",
            Self::ILAsm => "ILAsm",
            Self::Java => "Java",
            Self::JScript => "JScript",
            Self::Msil => "MSIL",
            Self::HLSl => "HLSL",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// `S_FRAMEPROC` — frame/stack layout of a procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SFrameProc {
    /// Total frame size in bytes.
    pub frame_size: u32,
    /// Size of frame padding in bytes.
    pub pad_size: u32,
    /// Offset of the padding within the frame.
    pub pad_offset: u32,
    /// Bytes used to save callee-saved registers.
    pub save_regs_size: u32,
    /// Offset of the exception handler, if any.
    pub exception_handler_offset: u32,
    /// Section of the exception handler.
    pub exception_handler_section: u16,
    /// Frame flags (see the `has_*`/`is_*` accessors).
    pub flags: u32,
}

impl SFrameProc {
    /// True if the function uses `alloca`.
    #[must_use]
    pub const fn has_alloca(&self) -> bool {
        self.flags & 0x0001 != 0
    }
    /// True if the function calls `setjmp`.
    #[must_use]
    pub const fn has_setjmp(&self) -> bool {
        self.flags & 0x0002 != 0
    }
    /// True if the function calls `longjmp`.
    #[must_use]
    pub const fn has_longjmp(&self) -> bool {
        self.flags & 0x0004 != 0
    }
    /// True if the function contains inline assembly.
    #[must_use]
    pub const fn has_inlasm(&self) -> bool {
        self.flags & 0x0008 != 0
    }
    /// True if the function has C++ exception handling (EH states).
    #[must_use]
    pub const fn has_eh(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    /// True if the function was declared `inline`.
    #[must_use]
    pub const fn is_inlined(&self) -> bool {
        self.flags & 0x0020 != 0
    }
    /// True if the function has structured exception handling (SEH).
    #[must_use]
    pub const fn has_seh(&self) -> bool {
        self.flags & 0x0040 != 0
    }
    /// True if the function is `__declspec(naked)`.
    #[must_use]
    pub const fn naked(&self) -> bool {
        self.flags & 0x0080 != 0
    }
    /// True if the function has /GS buffer security checks.
    #[must_use]
    pub const fn security_checks(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    /// True if the function was compiled with /`EHa` asynchronous exception handling.
    #[must_use]
    pub const fn async_eh(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// `S_REGREL32` — register-relative address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRegrel32 {
    /// Signed offset from `register` (e.g. `-8` for `[rbp-8]`).
    pub offset: i32,
    /// TPI type index of the variable.
    pub type_index: TypeIndex,
    /// Raw `CV_HREG_e` register number the offset is relative to.
    pub register: u16,
    /// Variable name.
    pub name: String,
}

impl SRegrel32 {
    /// Returns true if this is a stack-relative variable (`RSP` or `RBP`).
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "x64-only: blind to arm64 (sp = 81, fp = 79). Use is_stack_relative_for(arch)."
    )]
    pub const fn is_stack_relative(&self) -> bool {
        crate::codeview::cv_symbol_records::reg_is_frame_or_stack(
            self.register,
            crate::codeview::cv_symbol_records::CvArch::X64,
        )
    }

    /// Is this local addressed off the frame or stack pointer of `arch`?
    ///
    /// Shares [`reg_is_frame_or_stack`](crate::codeview::cv_symbol_records::reg_is_frame_or_stack)
    /// with `SymRegRel32` so the two `S_REGREL32` representations in this crate
    /// cannot drift apart — the previous iteration could only fix one of them
    /// precisely because each carried its own copy of the numbers.
    #[must_use]
    pub const fn is_stack_relative_for(
        &self,
        arch: crate::codeview::cv_symbol_records::CvArch,
    ) -> bool {
        crate::codeview::cv_symbol_records::reg_is_frame_or_stack(self.register, arch)
    }
}

/// `S_LOCAL` — local variable (new format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLocal {
    /// TPI type index of the variable.
    pub type_index: TypeIndex,
    /// `CV_LVARFLAGS` bit set (see the `is_*` accessors).
    pub flags: u16,
    /// Variable name.
    pub name: String,
}

impl SLocal {
    /// True if the local is a formal parameter.
    #[must_use]
    pub const fn is_param(&self) -> bool {
        self.flags & 0x0001 != 0
    }
    /// True if the variable's address is taken.
    #[must_use]
    pub const fn is_addr_taken(&self) -> bool {
        self.flags & 0x0002 != 0
    }
    /// True if the variable is compiler-generated.
    #[must_use]
    pub const fn is_compiler_gen(&self) -> bool {
        self.flags & 0x0004 != 0
    }
    /// True if the symbol is part of an aggregate split across symbols.
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        self.flags & 0x0008 != 0
    }
    /// True if the symbol was aggregated into another symbol.
    #[must_use]
    pub const fn is_aggregated(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    /// True if the variable has aliases.
    #[must_use]
    pub const fn is_aliased(&self) -> bool {
        self.flags & 0x0020 != 0
    }
    /// True if the symbol is an alias of another variable.
    #[must_use]
    pub const fn is_alias(&self) -> bool {
        self.flags & 0x0040 != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvSymRecord — unified enum
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded `CodeView` symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvSymRecord {
    /// `S_PUB32` public symbol.
    Pub32(SPub32),
    /// `S_GPROC32` global procedure.
    Gproc32(SProc32),
    /// `S_LPROC32` local (static) procedure.
    Lproc32(SProc32),
    /// `S_GDATA32` global data.
    Gdata32(SData32),
    /// `S_LDATA32` module-local data.
    Ldata32(SData32),
    /// `S_LABEL32` code label.
    Label32(SLabel32),
    /// `S_THUNK32` thunk.
    Thunk32(SThunk32),
    /// `S_BLOCK32` lexical block.
    Block32(SBlock32),
    /// `S_WITH32` Pascal `with` block.
    With32(SWith32),
    /// `S_COMPILE3` compiler info.
    Compile3(SCompile3),
    /// `S_FRAMEPROC` frame layout info.
    FrameProc(SFrameProc),
    /// `S_REGREL32` register-relative variable.
    Regrel32(SRegrel32),
    /// `S_LOCAL` local variable.
    Local(SLocal),
    /// Any record kind this decoder does not model.
    Unknown {
        /// The raw `S_*` kind value.
        kind: u16,
        /// The undecoded record payload.
        data: Vec<u8>,
    },
}

impl CvSymRecord {
    /// Canonical `S_*` name of this record's kind.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Pub32(_) => "S_PUB32",
            Self::Gproc32(_) => "S_GPROC32",
            Self::Lproc32(_) => "S_LPROC32",
            Self::Gdata32(_) => "S_GDATA32",
            Self::Ldata32(_) => "S_LDATA32",
            Self::Label32(_) => "S_LABEL32",
            Self::Thunk32(_) => "S_THUNK32",
            Self::Block32(_) => "S_BLOCK32",
            Self::With32(_) => "S_WITH32",
            Self::Compile3(_) => "S_COMPILE3",
            Self::FrameProc(_) => "S_FRAMEPROC",
            Self::Regrel32(_) => "S_REGREL32",
            Self::Local(_) => "S_LOCAL",
            Self::Unknown { .. } => "S_UNKNOWN",
        }
    }

    /// Symbol name, if applicable.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Pub32(s) => Some(&s.name),
            Self::Gproc32(s) | Self::Lproc32(s) => Some(&s.name),
            Self::Gdata32(s) | Self::Ldata32(s) => Some(&s.name),
            Self::Label32(s) => Some(&s.name),
            Self::Thunk32(s) => Some(&s.name),
            Self::Block32(s) => Some(&s.name),
            Self::Regrel32(s) => Some(&s.name),
            Self::Local(s) => Some(&s.name),
            _ => None,
        }
    }

    /// Segment-relative offset (for addressable symbols).
    #[must_use]
    pub const fn offset(&self) -> Option<u32> {
        match self {
            Self::Pub32(s) => Some(s.offset),
            Self::Gproc32(s) | Self::Lproc32(s) => Some(s.offset),
            Self::Gdata32(s) | Self::Ldata32(s) => Some(s.offset),
            Self::Label32(s) => Some(s.offset),
            Self::Thunk32(s) => Some(s.offset),
            Self::Block32(s) => Some(s.offset),
            _ => None,
        }
    }

    /// Whether this is a function (procedure) symbol.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Gproc32(_) | Self::Lproc32(_) | Self::Thunk32(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvSymDb
// ─────────────────────────────────────────────────────────────────────────────

/// Database of `CodeView` symbol records.
#[derive(Debug, Default)]
pub struct CvSymDb {
    records: Vec<CvSymRecord>,
    /// Map from symbol name → record index.
    by_name: HashMap<String, Vec<usize>>,
    /// Map from offset → record index (for addressable symbols).
    by_offset: HashMap<u32, Vec<usize>>,
}

impl CvSymDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol record.
    pub fn insert(&mut self, rec: CvSymRecord) {
        let idx = self.records.len();
        if let Some(name) = rec.name() {
            self.by_name.entry(name.to_string()).or_default().push(idx);
        }
        if let Some(off) = rec.offset() {
            self.by_offset.entry(off).or_default().push(idx);
        }
        self.records.push(rec);
    }

    /// Record at insertion index `idx`, if it exists.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&CvSymRecord> {
        self.records.get(idx)
    }

    /// Number of records in the database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }
    /// True if the database has no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Find all records with the given name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&CvSymRecord> {
        self.by_name
            .get(name)
            .map(|idxs| idxs.iter().filter_map(|&i| self.records.get(i)).collect())
            .unwrap_or_default()
    }

    /// Find all records at the given segment-relative offset.
    #[must_use]
    pub fn find_by_offset(&self, offset: u32) -> Vec<&CvSymRecord> {
        self.by_offset
            .get(&offset)
            .map(|idxs| idxs.iter().filter_map(|&i| self.records.get(i)).collect())
            .unwrap_or_default()
    }

    /// All function symbols.
    #[must_use]
    pub fn functions(&self) -> Vec<&CvSymRecord> {
        self.records.iter().filter(|r| r.is_function()).collect()
    }

    /// All global data symbols.
    #[must_use]
    pub fn globals(&self) -> Vec<&CvSymRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r, CvSymRecord::Gdata32(_)))
            .collect()
    }

    /// All public symbols.
    #[must_use]
    pub fn publics(&self) -> Vec<&CvSymRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r, CvSymRecord::Pub32(_)))
            .collect()
    }

    /// Iterate over all records.
    pub fn iter(&self) -> impl Iterator<Item = &CvSymRecord> {
        self.records.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codeview::cv_symbol_records::{
        decode_symbol_record, sk as sym_kind, CvArch, SymRecord,
    };

    fn make_pub32(name: &str, off: u32, flags: u32) -> CvSymRecord {
        CvSymRecord::Pub32(SPub32 {
            flags,
            offset: off,
            segment: 1,
            name: name.to_string(),
        })
    }

    fn make_gproc(name: &str, off: u32) -> CvSymRecord {
        CvSymRecord::Gproc32(SProc32 {
            parent: 0,
            end: 0,
            next: 0,
            len: 0x40,
            debug_start: 0,
            debug_end: 0x3c,
            type_index: TypeIndex(0),
            offset: off,
            segment: 1,
            flags: 0,
            name: name.to_string(),
            is_global: true,
        })
    }

    fn make_gdata(name: &str, off: u32) -> CvSymRecord {
        CvSymRecord::Gdata32(SData32 {
            type_index: TypeIndex(0),
            offset: off,
            segment: 1,
            name: name.to_string(),
            is_global: true,
        })
    }

    // --- SymKind ---

    #[test]
    fn sym_kind_from_u16_pub32() {
        assert_eq!(SymKind::from_u16(0x110E), Some(SymKind::Pub32));
    }

    /// Regression: `S_LPROC32` is 0x110F and `S_REGREL32` is 0x1111 per the
    /// `CodeView` symbol table (LLVM `CVSymbolTypes.def`). The crate previously
    /// mapped 0x1111 to `Lproc32` and gave `Regrel32` a synthetic 0xF111
    /// discriminant, dropping static functions and decoding register-relative
    /// locals as procedures.
    #[test]
    fn sym_kind_lproc32_and_regrel32_match_the_spec() {
        assert_eq!(SymKind::Lproc32 as u16, 0x110F);
        assert_eq!(SymKind::Gproc32 as u16, 0x1110);
        assert_eq!(SymKind::Regrel32 as u16, 0x1111);
        assert_eq!(SymKind::from_u16(0x110F), Some(SymKind::Lproc32));
        assert_eq!(SymKind::from_u16(0x1110), Some(SymKind::Gproc32));
        assert_eq!(SymKind::from_u16(0x1111), Some(SymKind::Regrel32));
        assert_eq!(SymKind::from_u16(0x110E), Some(SymKind::Pub32));
    }

    #[test]
    fn sym_kind_from_u16_unknown() {
        assert!(SymKind::from_u16(0xFFFF).is_none());
    }

    #[test]
    fn sym_kind_name_str() {
        assert_eq!(SymKind::Gproc32.name_str(), "S_GPROC32");
    }

    // --- SPub32 ---

    #[test]
    fn pub32_is_function() {
        let p = SPub32 {
            flags: 0x02,
            offset: 0,
            segment: 1,
            name: "foo".into(),
        };
        assert!(p.is_function());
    }

    #[test]
    fn pub32_not_function() {
        let p = SPub32 {
            flags: 0x01,
            offset: 0,
            segment: 1,
            name: "bar".into(),
        };
        assert!(!p.is_function());
    }

    // --- SProc32 ---

    #[test]
    fn proc32_end_addr() {
        if let CvSymRecord::Gproc32(p) = make_gproc("foo", 0x1000) {
            assert_eq!(p.end_addr(), 0x1040);
        }
    }

    #[test]
    fn proc32_is_noreturn_false() {
        if let CvSymRecord::Gproc32(p) = make_gproc("foo", 0) {
            assert!(!p.is_noreturn());
        }
    }

    // --- SLabel32 ---

    /// A label that never returns carries `CV_PFLAG_NEVER` (bit 3).
    ///
    /// This test used to build the label with flags `0x01` and assert
    /// `is_noreturn()` — bit 0 is `CV_PFLAG_NOFPO`, a statement about the frame
    /// pointer. The test passed because the decoder had the same bug.
    #[test]
    fn label32_noreturn() {
        let l = SLabel32 {
            offset: 0x1000,
            segment: 1,
            flags: 0x08,
            name: "lbl".into(),
        };
        assert!(l.is_noreturn());

        let nofpo = SLabel32 { flags: 0x01, ..l };
        assert!(!nofpo.is_noreturn(), "NOFPO says nothing about returning");
    }

    /// The three `CV_PROCFLAGS` decoders in this crate must answer the same
    /// question the same way. They did not: two read bit 0 and one read bit 1.
    #[test]
    fn the_three_procflags_decoders_agree() {
        for flags in 0u8..=0xFF {
            let expected = flags & 0x08 != 0;
            assert_eq!(procflags_never_returns(flags), expected);
            let l = SLabel32 { offset: 0, segment: 1, flags, name: "l".into() };
            assert_eq!(l.is_noreturn(), expected, "SLabel32 disagrees at {flags:#04x}");
            let p = SProc32 {
                parent: 0, end: 0, next: 0, len: 4, debug_start: 0, debug_end: 0,
                type_index: crate::codeview::cv_types::TypeIndex(0), offset: 0, segment: 1, flags, is_global: true, name: "p".into(),
            };
            assert_eq!(p.is_noreturn(), expected, "SProc32 disagrees at {flags:#04x}");
        }
    }

    /// `offset + len` used to be an unchecked u32 addition.
    #[test]
    fn proc32_end_addr_does_not_wrap() {
        let p = SProc32 {
            parent: 0, end: 0, next: 0, len: u32::MAX, debug_start: 0, debug_end: 0,
            type_index: crate::codeview::cv_types::TypeIndex(0), offset: u32::MAX, segment: 1, flags: 0, is_global: true, name: "p".into(),
        };
        assert_eq!(p.end_addr(), u64::from(u32::MAX) * 2);
    }

    // --- SLocal ---

    #[test]
    fn local_is_param() {
        let l = SLocal {
            type_index: TypeIndex(0),
            flags: 0x01,
            name: "arg".into(),
        };
        assert!(l.is_param());
    }

    #[test]
    fn local_addr_taken() {
        let l = SLocal {
            type_index: TypeIndex(0),
            flags: 0x02,
            name: "x".into(),
        };
        assert!(l.is_addr_taken());
    }

    // --- SCompile3 ---

    #[test]
    fn compile3_language_cpp() {
        let c = SCompile3 {
            flags: 1,
            machine: 0x8664,
            ver_fe_major: 19,
            ver_fe_minor: 0,
            ver_fe_build: 0,
            ver_fe_qfe: 0,
            ver_major: 14,
            ver_minor: 0,
            ver_build: 0,
            ver_qfe: 0,
            ver_str: "MSVC".into(),
        };
        assert_eq!(c.language(), CompileLanguage::Cpp);
    }

    #[test]
    fn compile_language_display() {
        assert_eq!(format!("{}", CompileLanguage::Cpp), "C++");
        assert_eq!(format!("{}", CompileLanguage::C), "C");
    }

    /// `S_COMPILE3::machine` is a `CV_CPU_TYPE_e`, not a COFF machine value.
    ///
    /// The `compile3_language_cpp` test above builds the record with `0x8664`,
    /// which is `IMAGE_FILE_MACHINE_AMD64` — the wrong number space for this
    /// field. Rather than quietly accept it (which would bake the confusion
    /// into the decoder), that record decodes to `Unknown`, and this test says
    /// so out loud so the discrepancy stays documented instead of propagating.
    #[test]
    fn compile3_arch_uses_the_cv_cpu_type_space() {
        let mk = |machine| SCompile3 {
            flags: 1,
            machine,
            ver_fe_major: 19,
            ver_fe_minor: 0,
            ver_fe_build: 0,
            ver_fe_qfe: 0,
            ver_major: 14,
            ver_minor: 0,
            ver_build: 0,
            ver_qfe: 0,
            ver_str: "test".into(),
        };
        assert_eq!(mk(0xD0).arch(), CvArch::X64);
        assert!(
            matches!(mk(0x8664).arch(), CvArch::Unknown(0x8664)),
            "the record used by compile3_language_cpp carries a COFF machine value \
             in a CV_CPU_TYPE_e field; it must not decode as x64 by accident"
        );
        // Not encoded on purpose: no source was available in-session to confirm
        // the arm64 CV_CPU_TYPE_e value, and an invented constant is worse than
        // Unknown.
        assert!(matches!(mk(0xF6).arch(), CvArch::Unknown(0xF6)));
    }

    // --- SFrameProc ---

    #[test]
    fn frameproc_has_alloca() {
        let fp = SFrameProc {
            frame_size: 0x40,
            pad_size: 0,
            pad_offset: 0,
            save_regs_size: 0x10,
            exception_handler_offset: 0,
            exception_handler_section: 0,
            flags: 0x0001,
        };
        assert!(fp.has_alloca());
    }

    #[test]
    fn frameproc_security_checks() {
        let fp = SFrameProc {
            flags: 0x0100,
            frame_size: 0,
            pad_size: 0,
            pad_offset: 0,
            save_regs_size: 0,
            exception_handler_offset: 0,
            exception_handler_section: 0,
        };
        assert!(fp.security_checks());
    }

    // --- SRegrel32 ---

    #[test]
    fn regrel32_stack_relative() {
        let r = SRegrel32 {
            offset: -8,
            type_index: TypeIndex(0),
            register: 335,
            name: "i".into(),
        };
        #[allow(deprecated)]
        {
            assert!(r.is_stack_relative());
        }
        // Same answer through the arch-aware entry point.
        assert!(r.is_stack_relative_for(CvArch::X64));
    }

    /// The two `S_REGREL32` representations must answer identically.
    ///
    /// `SRegrel32` (this file) and `SymRegRel32` (`cv_symbol_records`) both
    /// model the same record; only the latter is ever built by a parser. They
    /// used to carry independent copies of the register numbers, which is why
    /// the previous iteration could fix arm64 in one and leave the other blind.
    /// Now both call `reg_is_frame_or_stack`, and this test pins that.
    #[test]
    fn the_two_regrel_types_agree_on_stack_relativeness() {
        for (reg, arch, expected) in [
            (335u16, CvArch::X64, true),
            (81u16, CvArch::Arm64, true),
            (81u16, CvArch::X64, false),
            (335u16, CvArch::Arm64, false),
            (79u16, CvArch::Arm64, true),
        ] {
            let legacy = SRegrel32 {
                offset: -16,
                type_index: TypeIndex(0),
                register: reg,
                name: "v".into(),
            };

            // The live type, built the only way it is ever built: by decoding.
            let mut data = Vec::new();
            data.extend_from_slice(&(-16i32).to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&reg.to_le_bytes());
            data.extend_from_slice(b"v ");
            let SymRecord::RegRel32(live) =
                decode_symbol_record(sym_kind::REGREL32, &data).unwrap()
            else {
                panic!("expected an S_REGREL32 record");
            };

            assert_eq!(
                legacy.is_stack_relative_for(arch),
                expected,
                "SRegrel32 reg={reg} arch={arch:?}"
            );
            assert_eq!(
                live.is_stack_relative(arch),
                expected,
                "SymRegRel32 reg={reg} arch={arch:?}"
            );
        }
    }

    // --- CvSymRecord ---

    #[test]
    fn sym_record_kind_str_pub32() {
        assert_eq!(make_pub32("main", 0, 0x02).kind_str(), "S_PUB32");
    }

    #[test]
    fn sym_record_name_pub32() {
        assert_eq!(make_pub32("init", 0, 0).name(), Some("init"));
    }

    #[test]
    fn sym_record_offset_gproc() {
        assert_eq!(make_gproc("foo", 0x1000).offset(), Some(0x1000));
    }

    #[test]
    fn sym_record_is_function_proc() {
        assert!(make_gproc("f", 0).is_function());
    }

    #[test]
    fn sym_record_is_not_function_data() {
        assert!(!make_gdata("g", 0).is_function());
    }

    // --- CvSymDb ---

    #[test]
    fn db_insert_len() {
        let mut db = CvSymDb::new();
        db.insert(make_pub32("main", 0x1000, 0x02));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn db_is_empty() {
        let db = CvSymDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn db_find_by_name() {
        let mut db = CvSymDb::new();
        db.insert(make_gproc("foo", 0x1000));
        let found = db.find_by_name("foo");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn db_find_by_name_missing() {
        let db = CvSymDb::new();
        assert!(db.find_by_name("no_such").is_empty());
    }

    #[test]
    fn db_find_by_offset() {
        let mut db = CvSymDb::new();
        db.insert(make_pub32("a", 0x2000, 0));
        let found = db.find_by_offset(0x2000);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn db_functions() {
        let mut db = CvSymDb::new();
        db.insert(make_gproc("f1", 0x1000));
        db.insert(make_gdata("g1", 0x2000));
        assert_eq!(db.functions().len(), 1);
    }

    #[test]
    fn db_globals() {
        let mut db = CvSymDb::new();
        db.insert(make_gdata("gvar", 0x3000));
        assert_eq!(db.globals().len(), 1);
    }

    #[test]
    fn db_publics() {
        let mut db = CvSymDb::new();
        db.insert(make_pub32("pub", 0, 0));
        db.insert(make_gproc("fn", 0));
        assert_eq!(db.publics().len(), 1);
    }

    #[test]
    fn db_get_by_index() {
        let mut db = CvSymDb::new();
        db.insert(make_pub32("x", 0, 0));
        assert!(db.get(0).is_some());
        assert!(db.get(99).is_none());
    }
}
