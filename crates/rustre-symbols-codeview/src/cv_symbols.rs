//! `CodeView` symbol records.
//!
//! Data model for `S_PUB32`, `S_GPROC32`, `S_LPROC32`, `S_GDATA32`, `S_LDATA32`,
//! `S_LABEL32`, `S_THUNK32`, `S_BLOCK32`, `S_WITH32`, `S_COMPILE3`, `S_FRAMEPROC`,
//! `S_REGREL32` and `S_LOCAL`.
//!
//! This module defines the record structs and predicates only; it contains no
//! byte-level parser. To decode records from bytes, use
//! [`crate::cv_symbol_records::decode_symbol_record`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cv_types::TypeIndex;

// ─────────────────────────────────────────────────────────────────────────────
// Symbol kind codes (S_*)
// ─────────────────────────────────────────────────────────────────────────────

/// `CodeView` symbol record kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum SymKind {
    Pub32 = 0x110E,
    Gproc32 = 0x1110,
    Lproc32 = 0x110F,
    Gdata32 = 0x110D,
    Ldata32 = 0x110C,
    Label32 = 0x1105,
    Thunk32 = 0x1102,
    Block32 = 0x1103,
    With32 = 0x1104,
    Compile3 = 0x113C,
    FrameProc = 0x1012,
    Regrel32 = 0x1111,
    Local = 0x113E,
    // Additional common ones
    ObjName = 0x1101,
    End = 0x0006,
    Proc32Id = 0x1127,
    LabelAnnot = 0x1019,
}

impl SymKind {
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
    pub flags: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
}

impl SPub32 {
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.flags & 0x02 != 0
    }
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        self.flags & 0x04 != 0
    }
    #[must_use]
    pub const fn is_msil(&self) -> bool {
        self.flags & 0x08 != 0
    }
}

/// `S_GPROC32` / `S_LPROC32` — global/local procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SProc32 {
    pub parent: u32,
    pub end: u32,
    pub next: u32,
    pub len: u32,
    pub debug_start: u32,
    pub debug_end: u32,
    pub type_index: TypeIndex,
    pub offset: u32,
    pub segment: u16,
    pub flags: u8,
    pub name: String,
    pub is_global: bool,
}

impl SProc32 {
    #[must_use]
    pub const fn start_addr(&self) -> u64 {
        self.offset as u64
    }
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        // Widen before adding: both fields come straight from parsed bytes and
        // a u32 addition would overflow (panic in debug, wrap in release).
        self.offset as u64 + self.len as u64
    }
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

/// `S_GDATA32` / `S_LDATA32` — global/local data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SData32 {
    pub type_index: TypeIndex,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
    pub is_global: bool,
}

/// `S_LABEL32` — code label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLabel32 {
    pub offset: u32,
    pub segment: u16,
    pub flags: u8,
    pub name: String,
}

impl SLabel32 {
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

/// `S_THUNK32` — thunk (stub) procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SThunk32 {
    pub parent: u32,
    pub end: u32,
    pub next: u32,
    pub offset: u32,
    pub segment: u16,
    pub len: u16,
    pub ordinal: u8,
    pub name: String,
    pub variant: Vec<u8>,
}

/// `S_BLOCK32` — lexical block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SBlock32 {
    pub parent: u32,
    pub end: u32,
    pub len: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
}

impl SBlock32 {
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.offset as u64
    }
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        // Widen before adding: both fields come straight from parsed bytes and
        // a u32 addition would overflow (panic in debug, wrap in release).
        self.offset as u64 + self.len as u64
    }
}

/// `S_WITH32` — with block (Pascal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SWith32 {
    pub parent: u32,
    pub end: u32,
    pub len: u32,
    pub offset: u32,
    pub segment: u16,
    pub expression: String,
}

/// `S_COMPILE3` — compilation unit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SCompile3 {
    pub flags: u32,
    pub machine: u16,
    pub ver_fe_major: u16,
    pub ver_fe_minor: u16,
    pub ver_fe_build: u16,
    pub ver_fe_qfe: u16,
    pub ver_major: u16,
    pub ver_minor: u16,
    pub ver_build: u16,
    pub ver_qfe: u16,
    pub ver_str: String,
}

impl SCompile3 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompileLanguage {
    C,
    Cpp,
    Fortran,
    Masm,
    Pascal,
    Basic,
    Cobol,
    Link,
    Cvtres,
    Cvtpgd,
    CSharp,
    VisualBasic,
    ILAsm,
    Java,
    JScript,
    Msil,
    HLSl,
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
    pub frame_size: u32,
    pub pad_size: u32,
    pub pad_offset: u32,
    pub save_regs_size: u32,
    pub exception_handler_offset: u32,
    pub exception_handler_section: u16,
    pub flags: u32,
}

impl SFrameProc {
    #[must_use]
    pub const fn has_alloca(&self) -> bool {
        self.flags & 0x0001 != 0
    }
    #[must_use]
    pub const fn has_setjmp(&self) -> bool {
        self.flags & 0x0002 != 0
    }
    #[must_use]
    pub const fn has_longjmp(&self) -> bool {
        self.flags & 0x0004 != 0
    }
    #[must_use]
    pub const fn has_inlasm(&self) -> bool {
        self.flags & 0x0008 != 0
    }
    #[must_use]
    pub const fn has_eh(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    #[must_use]
    pub const fn is_inlined(&self) -> bool {
        self.flags & 0x0020 != 0
    }
    #[must_use]
    pub const fn has_seh(&self) -> bool {
        self.flags & 0x0040 != 0
    }
    #[must_use]
    pub const fn naked(&self) -> bool {
        self.flags & 0x0080 != 0
    }
    #[must_use]
    pub const fn security_checks(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    #[must_use]
    pub const fn async_eh(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// `S_REGREL32` — register-relative address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRegrel32 {
    pub offset: i32,
    pub type_index: TypeIndex,
    pub register: u16,
    pub name: String,
}

impl SRegrel32 {
    /// Returns true if this is an x64 stack-relative variable (`RSP` or `RBP`).
    ///
    /// In `CV_AMD64` register encoding `RBP` = 334 and `RSP` = 335
    /// (see [`crate::cv_symbol_records::CvReg`]); 332/333 are `RSI`/`RDI`.
    /// The block runs RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP over 328..=335 —
    /// NOT the classic x86 order, which is what this used to assume.
    #[must_use]
    pub const fn is_stack_relative(&self) -> bool {
        const RSP: u16 = crate::cv_symbol_records::CvReg::Rsp as u16;
        const RBP: u16 = crate::cv_symbol_records::CvReg::Rbp as u16;
        matches!(self.register, RSP | RBP)
    }

    /// Machine-type-aware variant of [`Self::is_stack_relative`].
    ///
    /// `machine` is the `CV_CPU_TYPE_e` value recorded by `S_COMPILE3`.
    /// The same `u16` register number means different registers per CPU, so a
    /// caller that knows the module machine type should prefer this.
    ///
    /// Recognised: x86 (`ESP` = 21, `EBP` = 22) and x64 (`RBP` = 334,
    /// `RSP` = 335). For any other machine the x64 encoding is assumed.
    #[must_use]
    pub const fn is_stack_relative_for(&self, machine: u16) -> bool {
        match machine {
            // CV_CFL_8080..=CV_CFL_PENTIUMIII and CV_CFL_80386-family: 32-bit x86
            0x00..=0x06 | 0x10..=0x14 => matches!(self.register, 21 | 22),
            _ => self.is_stack_relative(),
        }
    }
}

/// `S_LOCAL` — local variable (new format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLocal {
    pub type_index: TypeIndex,
    pub flags: u16,
    pub name: String,
}

impl SLocal {
    #[must_use]
    pub const fn is_param(&self) -> bool {
        self.flags & 0x0001 != 0
    }
    #[must_use]
    pub const fn is_addr_taken(&self) -> bool {
        self.flags & 0x0002 != 0
    }
    #[must_use]
    pub const fn is_compiler_gen(&self) -> bool {
        self.flags & 0x0004 != 0
    }
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        self.flags & 0x0008 != 0
    }
    #[must_use]
    pub const fn is_aggregated(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    #[must_use]
    pub const fn is_aliased(&self) -> bool {
        self.flags & 0x0020 != 0
    }
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
    Pub32(SPub32),
    Gproc32(SProc32),
    Lproc32(SProc32),
    Gdata32(SData32),
    Ldata32(SData32),
    Label32(SLabel32),
    Thunk32(SThunk32),
    Block32(SBlock32),
    With32(SWith32),
    Compile3(SCompile3),
    FrameProc(SFrameProc),
    Regrel32(SRegrel32),
    Local(SLocal),
    Unknown { kind: u16, data: Vec<u8> },
}

impl CvSymRecord {
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

    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&CvSymRecord> {
        self.records.get(idx)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }
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

    #[test]
    fn label32_noreturn() {
        let l = SLabel32 {
            offset: 0x1000,
            segment: 1,
            flags: 0x01,
            name: "lbl".into(),
        };
        assert!(l.is_noreturn());
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
        let mk = |reg: u16| SRegrel32 {
            offset: -8,
            type_index: TypeIndex(0),
            register: reg,
            name: "i".into(),
        };
        // CV_AMD64 numbers the block RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP
        // over 328..=335, so RBP = 334 and RSP = 335. This test used to assert
        // the opposite — it pinned the crate's own wrong table rather than the
        // format, and so defended the defect instead of catching it.
        assert!(mk(334).is_stack_relative(), "334 is RBP");
        assert!(mk(335).is_stack_relative(), "335 is RSP");
        // 332/333 are RSI/RDI: not stack pointers.
        assert!(!mk(332).is_stack_relative());
        assert!(!mk(333).is_stack_relative());
    }

    #[test]
    fn regrel32_stack_relative_for_machine() {
        let mk = |reg: u16| SRegrel32 {
            offset: -8,
            type_index: TypeIndex(0),
            register: reg,
            name: "i".into(),
        };
        // x86 (CV_CFL_80386 = 0x03): EBP = 22, ESP = 21.
        assert!(mk(22).is_stack_relative_for(0x03));
        assert!(mk(21).is_stack_relative_for(0x03));
        assert!(!mk(334).is_stack_relative_for(0x03));
        // x64 (CV_CFL_X64 = 0xD0).
        assert!(mk(334).is_stack_relative_for(0xD0), "334 is RBP on x64");
        assert!(!mk(22).is_stack_relative_for(0xD0));
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
