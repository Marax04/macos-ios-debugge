//! `cv_symbol_records` — `CodeView` symbol record decoder.
//!
//! Decodes `S_PUB32`, `S_LDATA32`, `S_GDATA32`, `S_LPROC32`, `S_GPROC32`, `S_THUNK32`,
//! `S_BLOCK32`, `S_LABEL32`, `S_CONSTANT`, `S_UDT`, `S_COMPILE3`, `S_REGREL32`,
//! `S_LOCAL`, `S_FRAMEPROC`, `S_CALLSITEINFO`, `S_HEAPALLOCSITE`, `S_OBJNAME`,
//! `S_END`, and more.
//!
//! Note: the `S_DEFRANGE_*` and `S_INLINESITE` kinds have constants in [`sk`]
//! but are **not** decoded — [`decode_symbol_record`] returns
//! [`SymRecord::Unknown`] for them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CodeViewError;

// ---------------------------------------------------------------------------
// Symbol kind constants (S_*)
// ---------------------------------------------------------------------------

pub mod sk {
    pub const COMPILE: u16 = 0x0001;
    pub const REGISTER_16T: u16 = 0x0002;
    pub const CONSTANT_16T: u16 = 0x0003;
    pub const UDT_16T: u16 = 0x0004;
    pub const SSEARCH: u16 = 0x000A;
    pub const END: u16 = 0x0006;
    pub const SKIP: u16 = 0x0007;
    pub const OBJNAME: u16 = 0x1101;
    pub const THUNK32: u16 = 0x1102;
    pub const BLOCK32: u16 = 0x1103;
    pub const WITH32: u16 = 0x1104;
    pub const LABEL32: u16 = 0x1105;
    pub const REGISTER: u16 = 0x1106;
    pub const CONSTANT: u16 = 0x1107;
    pub const UDT: u16 = 0x1108;
    pub const COBOLUDT: u16 = 0x1109;
    pub const MANYREG: u16 = 0x110A;
    pub const BPREL32: u16 = 0x110B;
    pub const LDATA32: u16 = 0x110C;
    pub const GDATA32: u16 = 0x110D;
    pub const PUB32: u16 = 0x110E;
    pub const LPROC32: u16 = 0x110F;
    pub const GPROC32: u16 = 0x1110;
    pub const REGREL32: u16 = 0x1111;
    pub const LTHREAD32: u16 = 0x1112;
    pub const GTHREAD32: u16 = 0x1113;
    pub const LPROCMIPS: u16 = 0x1114;
    pub const GPROCMIPS: u16 = 0x1115;
    pub const COMPILE2: u16 = 0x1116;
    pub const MANYREG2: u16 = 0x1117;
    pub const LPROCIA64: u16 = 0x1118;
    pub const GPROCIA64: u16 = 0x1119;
    pub const LOCALSLOT: u16 = 0x111A;
    pub const PARAMSLOT: u16 = 0x111B;
    pub const LMANDATA: u16 = 0x111C;
    pub const GMANDATA: u16 = 0x111D;
    pub const MANFRAMEREL: u16 = 0x111E;
    pub const MANREGISTER: u16 = 0x111F;
    pub const MANSLOT: u16 = 0x1120;
    pub const MANMANYREG: u16 = 0x1121;
    pub const MANREGREL: u16 = 0x1122;
    pub const MANMANYREG2: u16 = 0x1123;
    pub const UNAMESPACE: u16 = 0x1124;
    pub const PROCREF: u16 = 0x1125;
    pub const DATAREF: u16 = 0x1126;
    pub const LPROCREF: u16 = 0x1127;
    pub const ANNOTATIONREF: u16 = 0x1128;
    pub const TOKENREF: u16 = 0x1129;
    pub const GMANPROC: u16 = 0x112A;
    pub const LMANPROC: u16 = 0x112B;
    pub const TRAMPOLINE: u16 = 0x112C;
    pub const MANCONSTANT: u16 = 0x112D;
    pub const ATTR_FRAMEREL: u16 = 0x112E;
    pub const ATTR_REGISTER: u16 = 0x112F;
    pub const ATTR_REGREL: u16 = 0x1130;
    pub const ATTR_MANYREG: u16 = 0x1131;
    pub const SEPCODE: u16 = 0x1132;
    pub const LOCAL: u16 = 0x113E;
    pub const DEFRANGE: u16 = 0x113F;
    pub const DEFRANGE_SUBFIELD: u16 = 0x1140;
    pub const DEFRANGE_REGISTER: u16 = 0x1141;
    pub const DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
    pub const DEFRANGE_SUBFIELD_REGISTER: u16 = 0x1143;
    pub const DEFRANGE_FRAMEPOINTER_REL_FULL: u16 = 0x1144;
    pub const DEFRANGE_REGISTER_REL: u16 = 0x1145;
    pub const LPROC32_ID: u16 = 0x1146;
    pub const GPROC32_ID: u16 = 0x1147;
    pub const LPROCMIPS_ID: u16 = 0x1148;
    pub const GPROCMIPS_ID: u16 = 0x1149;
    pub const LPROCIA64_ID: u16 = 0x114A;
    pub const GPROCIA64_ID: u16 = 0x114B;
    pub const BUILDINFO: u16 = 0x114C;
    pub const INLINESITE: u16 = 0x114D;
    pub const INLINESITE_END: u16 = 0x114E;
    pub const PROC_ID_END: u16 = 0x114F;
    pub const DEFRANGE_HLSL: u16 = 0x1150;
    pub const GDATA_HLSL: u16 = 0x1151;
    pub const LDATA_HLSL: u16 = 0x1152;
    pub const FILESTATIC: u16 = 0x1153;
    pub const LOCAL_DPC_GROUPSHARED: u16 = 0x1154;
    pub const LPROC32_DPC: u16 = 0x1155;
    pub const LPROC32_DPC_ID: u16 = 0x1156;
    pub const DEFRANGE_DPC_PTR_TAG: u16 = 0x1157;
    pub const COMPILE3: u16 = 0x113C;
    pub const ENVBLOCK: u16 = 0x113D;
    pub const FRAMEPROC: u16 = 0x1012;
    pub const CALLSITEINFO: u16 = 0x1139;
    pub const HEAPALLOCSITE: u16 = 0x115E;
}

// ---------------------------------------------------------------------------
// Register encoding
// ---------------------------------------------------------------------------

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CvReg {
    Al = 1, Cl = 2, Dl = 3, Bl = 4,
    Ax = 9, Cx = 10, Dx = 11, Bx = 12, Sp = 13, Bp = 14, Si = 15, Di = 16,
    Eax = 17, Ecx = 18, Edx = 19, Ebx = 20, Esp = 21, Ebp = 22, Esi = 23, Edi = 24,
    // CodeView does NOT number the AMD64 block in the classic x86 order
    // (AX, CX, DX, BX, SP, BP, SI, DI). The real order for 328..=335 is
    // RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP — see LLVM's
    // CodeViewRegisters.def. Using the x86 order here put SEVEN of the
    // eight registers on the wrong number; only RAX lined up.
    Rax = 328, Rbx = 329, Rcx = 330, Rdx = 331, Rsi = 332, Rdi = 333, Rbp = 334, Rsp = 335,
    R8 = 336, R9 = 337, R10 = 338, R11 = 339, R12 = 340, R13 = 341, R14 = 342, R15 = 343,
    Xmm0 = 154, Xmm1 = 155, Xmm2 = 156, Xmm3 = 157,
    Unknown = 0xFFFF,
}

impl CvReg {
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
    pub flags: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
}

impl SymPub32 {
    #[must_use] 
    pub const fn is_function(&self) -> bool { (self.flags & 2) != 0 }
    #[must_use] 
    pub const fn is_managed(&self) -> bool { (self.flags & 4) != 0 }
    #[must_use] 
    pub const fn is_msil(&self) -> bool { (self.flags & 8) != 0 }
}

/// CV data symbol (`S_LDATA32` / `S_GDATA32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymData32 {
    pub type_index: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
    pub is_global: bool,
}

/// CV procedure symbol (`S_LPROC32` / `S_GPROC32` / `LPROC32_ID` / `GPROC32_ID`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymProc32 {
    pub parent: u32,
    pub end: u32,
    pub next: u32,
    pub proc_len: u32,
    pub debug_start: u32,
    pub debug_end: u32,
    pub type_index: u32,
    pub offset: u32,
    pub segment: u16,
    pub flags: u8,
    pub name: String,
    pub is_global: bool,
}

impl SymProc32 {
    #[must_use] 
    pub const fn is_no_fpo(&self) -> bool { (self.flags & 1) != 0 }
    #[must_use] 
    pub const fn is_interrupt(&self) -> bool { (self.flags & 2) != 0 }
    #[must_use] 
    pub const fn is_far_return(&self) -> bool { (self.flags & 4) != 0 }
    #[must_use] 
    pub const fn is_never_return(&self) -> bool { (self.flags & 8) != 0 }
    #[must_use] 
    pub const fn is_not_reached(&self) -> bool { (self.flags & 0x10) != 0 }
    #[must_use] 
    pub const fn is_custom_calling_conv(&self) -> bool { (self.flags & 0x20) != 0 }
    #[must_use] 
    pub const fn is_optimized_debug(&self) -> bool { (self.flags & 0x40) != 0 }
    #[must_use] 
    pub const fn is_guard_cf(&self) -> bool { (self.flags & 0x80) != 0 }
}

/// CV thunk symbol (`S_THUNK32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymThunk32 {
    pub parent: u32,
    pub end: u32,
    pub next: u32,
    pub offset: u32,
    pub segment: u16,
    pub thunk_len: u16,
    pub kind: u8,
    pub name: String,
}

/// CV block symbol (`S_BLOCK32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymBlock32 {
    pub parent: u32,
    pub end: u32,
    pub block_len: u32,
    pub offset: u32,
    pub segment: u16,
    pub name: String,
}

/// CV label symbol (`S_LABEL32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymLabel32 {
    pub offset: u32,
    pub segment: u16,
    pub flags: u8,
    pub name: String,
}

/// CV constant symbol (`S_CONSTANT`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymConstant {
    pub type_index: u32,
    pub value: i64,
    pub name: String,
}

/// CV UDT symbol (`S_UDT`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymUdt {
    pub type_index: u32,
    pub name: String,
}

/// CV register-relative symbol (`S_REGREL32`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymRegRel32 {
    pub offset: i32,
    pub type_index: u32,
    pub register: CvReg,
    pub name: String,
}

/// CV local variable symbol (`S_LOCAL`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymLocal {
    pub type_index: u32,
    pub flags: u16,
    pub name: String,
}

impl SymLocal {
    #[must_use] 
    pub const fn is_param(&self) -> bool { (self.flags & 1) != 0 }
    #[must_use] 
    pub const fn is_addr_taken(&self) -> bool { (self.flags & 2) != 0 }
    #[must_use] 
    pub const fn is_compgen(&self) -> bool { (self.flags & 4) != 0 }
    #[must_use] 
    pub const fn is_agg(&self) -> bool { (self.flags & 8) != 0 }
    #[must_use] 
    pub const fn is_return(&self) -> bool { (self.flags & 0x80) != 0 }
}

/// `S_COMPILE3` — compiler info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymCompile3 {
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
    pub compiler_version: String,
}

/// `S_FRAMEPROC` — frame procedure info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymFrameProc {
    pub frame_size: u32,
    pub pad_size: u32,
    pub pad_offset: u32,
    pub save_reg_size: u32,
    pub except_handler_offset: u32,
    pub except_handler_section: u16,
    pub flags: u32,
}

/// `S_CALLSITEINFO` — indirect call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymCallSiteInfo {
    pub offset: u32,
    pub section: u16,
    pub type_index: u32,
}

/// `S_HEAPALLOCSITE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymHeapAllocSite {
    pub offset: u32,
    pub section: u16,
    pub inst_len: u16,
    pub type_index: u32,
}

/// `S_OBJNAME` — object file name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymObjName {
    pub signature: u32,
    pub name: String,
}

/// `S_UNAMESPACE` — using namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymUsingNamespace {
    pub name: String,
}

/// `S_BUILDINFO` — build info key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymBuildInfo {
    pub item_id: u32,
}

/// Top-level decoded symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymRecord {
    Pub32(SymPub32),
    LData32(SymData32),
    GData32(SymData32),
    LProc32(SymProc32),
    GProc32(SymProc32),
    Thunk32(SymThunk32),
    Block32(SymBlock32),
    Label32(SymLabel32),
    Constant(SymConstant),
    Udt(SymUdt),
    RegRel32(SymRegRel32),
    Local(SymLocal),
    Compile3(SymCompile3),
    FrameProc(SymFrameProc),
    CallSiteInfo(SymCallSiteInfo),
    HeapAllocSite(SymHeapAllocSite),
    ObjName(SymObjName),
    UsingNamespace(SymUsingNamespace),
    BuildInfo(SymBuildInfo),
    End,
    InlineSiteEnd,
    Unknown { kind: u16 },
}

impl SymRecord {
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

    #[must_use] 
    pub const fn is_proc(&self) -> bool {
        matches!(self, Self::LProc32(_) | Self::GProc32(_))
    }

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
    crate::cv_type_records::read_numeric_leaf(data).unwrap_or((0, 2))
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
            Ok(SymRecord::RegRel32(SymRegRel32 { offset, type_index, register, name }))
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

#[must_use] 
pub fn decode_symbol_stream(data: &[u8]) -> Vec<Result<SymRecord, CodeViewError>> {
    use crate::codeview_parser::RawSymIter;
    RawSymIter::new(data)
        .map(|r| r.and_then(|raw| decode_symbol_record(raw.kind, raw.data)))
        .collect()
}

// ---------------------------------------------------------------------------
// Address map builder from symbol stream
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct SymbolAddressIndex {
    /// (segment, offset) → (name, `type_index`)
    entries: Vec<(u16, u32, String, u32)>,
    sorted: bool,
}

impl SymbolAddressIndex {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

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

    pub fn insert(&mut self, seg: u16, off: u32, name: String, ti: u32) {
        self.entries.push((seg, off, name, ti));
        self.sorted = false;
    }

    pub fn sort(&mut self) {
        self.entries.sort_by_key(|&(s, o, _, _)| (s, o));
        self.sorted = true;
    }

    #[must_use] 
    pub fn find_exact(&self, seg: u16, off: u32) -> Option<(&str, u32)> {
        if !self.sorted { return None; }
        let idx = self.entries.partition_point(|&(s, o, _, _)| (s, o) < (seg, off));
        let e = self.entries.get(idx)?;
        if e.0 == seg && e.1 == off { Some((&e.2, e.3)) } else { None }
    }

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

    pub fn all_names_in_segment(&self, seg: u16) -> impl Iterator<Item = (&str, u32)> {
        self.entries.iter()
            .filter(move |e| e.0 == seg)
            .map(|e| (e.2.as_str(), e.1))
    }

    #[must_use] 
    pub const fn len(&self) -> usize { self.entries.len() }
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
    CodeOffset(u32),
    ChangeCodeOffsetBase(u32),
    ChangeCodeOffset(u32),
    ChangeCodeLength(u32),
    ChangeFile(u32),
    ChangeLineOffset(i32),
    ChangeLineEndDelta(u32),
    ChangeRangeKind(u32),
    ChangeColumnStart(u32),
    ChangeColumnEnd(u32),
    ChangeCodeOffsetAndLineOffset { code_delta: u32, line_delta: i32 },
    ChangeCodeLengthAndCodeOffset { code_length: u32, code_offset: u32 },
    ChangeColumnEndDelta(i32),
}

/// Decode a `CodeView` zigzag-encoded signed operand.
const fn zigzag(v: u32) -> i32 {
    let s = crate::casts::u32_as_i32(v >> 1);
    if v & 1 != 0 { -s } else { s }
}

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
        // 334, not 333: CV_AMD64 runs RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP
        // over 328..=335. Written against this crate's own wrong table, this
        // line pinned the defect instead of the format.
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
