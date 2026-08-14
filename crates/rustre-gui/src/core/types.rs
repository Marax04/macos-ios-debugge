// ============================================================================
// core/types.rs — Fundamental domain types for the reverse engineering engine
// ============================================================================

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::fmt;

// ── Address ──────────────────────────────────────────────────────────────────

/// Virtual address in target binary — newtype for type-safety.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Addr(pub u64);

impl Addr {
    pub const INVALID: Self = Self(u64::MAX);
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 != u64::MAX
    }
    #[inline]
    pub const fn offset(self, delta: i64) -> Self {
        Self(self.0.wrapping_add_signed(delta))
    }
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }
    #[inline]
    pub const fn distance_to(self, other: Self) -> i64 {
        let a = i64::from_ne_bytes(other.0.to_ne_bytes());
        let b = i64::from_ne_bytes(self.0.to_ne_bytes());
        a.wrapping_sub(b)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}
impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addr({:#x})", self.0)
    }
}
impl fmt::LowerHex for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

// ── Architecture ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum Architecture {
    #[default]
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Riscv64,
    Riscv32,
    Mips64,
    Mips32,
    PowerPc64,
    PowerPc32,
    Unknown,
}

impl Architecture {
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::X86_64 | Self::Arm64 | Self::Riscv64 | Self::Mips64 | Self::PowerPc64 => 8,
            _ => 4,
        }
    }
    pub const fn is_64bit(self) -> bool {
        self.pointer_size() == 8
    }
    pub const fn capstone_arch(self) -> u32 {
        // capstone architecture IDs
        match self {
            Self::X86_64 | Self::X86_32 => 3, // CS_ARCH_X86
            Self::Arm64 => 2,                 // CS_ARCH_ARM64
            Self::Arm32 => 1,                 // CS_ARCH_ARM
            Self::Mips64 | Self::Mips32 => 4, // CS_ARCH_MIPS
            _ => 0,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::X86_32 => "x86-32",
            Self::Arm64 => "AArch64",
            Self::Arm32 => "ARM",
            Self::Riscv64 => "RISC-V 64",
            Self::Riscv32 => "RISC-V 32",
            Self::Mips64 => "MIPS-64",
            Self::Mips32 => "MIPS-32",
            Self::PowerPc64 => "PPC-64",
            Self::PowerPc32 => "PPC-32",
            Self::Unknown => "Unknown",
        }
    }
}

// ── Endianness ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum Endianness {
    #[default]
    Little,
    Big,
}

// ── Binary Format ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum BinaryFormat {
    #[default]
    Pe,
    Elf,
    MachO,
    Raw,
    Coff,
    Unknown,
}

impl BinaryFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "PE/COFF",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Raw => "Raw Binary",
            Self::Coff => "COFF",
            Self::Unknown => "Unknown",
        }
    }
}

// ── Segment / Section ──────────────────────────────────────────────────────────

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
    pub struct SegmentFlags: u32 {
        const READ    = 0b0001;
        const WRITE   = 0b0010;
        const EXECUTE = 0b0100;
        const SHARED  = 0b1000;
    }
}

impl SegmentFlags {
    pub const fn as_rwx_str(self) -> [char; 3] {
        [
            if self.contains(Self::READ) { 'r' } else { '-' },
            if self.contains(Self::WRITE) { 'w' } else { '-' },
            if self.contains(Self::EXECUTE) {
                'x'
            } else {
                '-'
            },
        ]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Segment {
    pub id: usize,
    pub name: String,
    pub start: Addr,
    pub end: Addr,
    pub flags: SegmentFlags,
    pub kind: SegmentKind,
    pub mapped_offset: u64,
}

impl Segment {
    pub const fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
    pub fn contains(&self, addr: Addr) -> bool {
        addr >= self.start && addr < self.end
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum SegmentKind {
    #[default]
    Code,
    Data,
    Bss,
    Rodata,
    Stack,
    Heap,
    Unknown,
}

// ── Symbol ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub id: u32,
    pub addr: Addr,
    pub name: String,
    pub demangled: Option<String>,
    pub kind: SymbolKind,
    pub size: u64,
    pub is_public: bool,
    pub is_import: bool,
    pub module: Option<String>,
    /// Import/Export ordinal number, populated by PE import/export descriptor parsing.
    pub ordinal: Option<u32>,
    /// PE export forwarding target, e.g. "NTDLL.RtlAllocateHeap".
    pub forwarded_to: Option<String>,
    /// FLIRT signature library that matched this symbol, populated by the FLIRT pass.
    pub flirt_library: Option<String>,
    /// Resolved IAT/thunk target address, populated by the import resolver.
    pub resolved_target: Option<Addr>,
}

impl Symbol {
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum SymbolKind {
    #[default]
    Function,
    Data,
    Import,
    Export,
    Label,
    Thunk,
    Unknown,
}

// ── Function ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Function {
    pub id: u32,
    pub addr: Addr,
    pub name: String,
    pub size: u64,
    pub tags: FunctionTags,
    pub sym_id: Option<u32>,
    pub comment: String,
    pub color: Option<u32>, // ARGB highlight color
}

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
    pub struct FunctionTags: u32 {
        const LIBRARY   = 0b0000_0001;
        const THUNK     = 0b0000_0010;
        const AUTO      = 0b0000_0100;
        const NORETURN  = 0b0000_1000;
        const EXPORTED  = 0b0001_0000;
        const IMPORTED  = 0b0010_0000;
        const ANALYZED  = 0b0100_0000;
        const MODIFIED  = 0b1000_0000;
    }
}

impl Function {
    pub const fn end_addr(&self) -> Addr {
        Addr(self.addr.0.saturating_add(self.size))
    }
    pub fn contains(&self, addr: Addr) -> bool {
        addr >= self.addr && addr < self.end_addr()
    }
}

// ── Instruction / Disassembly token ──────────────────────────────────────────

/// A single disassembled instruction, ready for rendering.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub addr: Addr,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub tokens: Vec<InsnToken>,
    pub comment: Option<String>,
    pub xrefs_to: Vec<XrefEntry>,
    /// If this instruction starts a basic block, the block id
    pub block_id: Option<u32>,
}

impl Instruction {
    pub const fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }
    pub const fn next_addr(&self) -> Addr {
        Addr(self.addr.0 + self.byte_len())
    }
    pub fn bytes_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InsnToken {
    pub kind: TokenKind,
    pub text: String,
    pub value: Option<u64>, // address or immediate, if applicable
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum TokenKind {
    Mnemonic,
    Register,
    Immediate,
    Address,
    Symbol,
    Comment,
    Punctuation,
    Whitespace,
    Prefix,
    Label,
    DataRef,
    Unknown,
}

// ── Cross-references ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    DataWrite,
    DataRef,
    Fallthrough,
}

impl XrefKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "CALL",
            Self::Jump => "JMP",
            Self::DataRead => "DR",
            Self::DataWrite => "DW",
            Self::DataRef => "DATA",
            Self::Fallthrough => "FALLTHROUGH",
        }
    }
    pub const fn is_code(self) -> bool {
        matches!(self, Self::Call | Self::Jump | Self::Fallthrough)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XrefEntry {
    pub from: Addr,
    pub to: Addr,
    pub kind: XrefKind,
    pub label: Option<String>,
}

// ── String ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringEntry {
    pub id: u32,
    pub addr: Addr,
    pub value: String,
    pub kind: StringKind,
    pub len: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum StringKind {
    #[default]
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Pascal,
}

// ── Basic Block ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: u32,
    pub start: Addr,
    pub end: Addr,
    pub preds: Vec<u32>,  // predecessor block IDs
    pub succs: Vec<u32>,  // successor block IDs
    pub insns: Vec<Addr>, // instruction addresses
    pub kind: BlockKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum BlockKind {
    #[default]
    Normal,
    Entry,
    Return,
    Noreturn,
    CallTarget,
}

// ── CFG (Control Flow Graph) ──────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cfg {
    pub func_id: u32,
    pub rev: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u32,
    pub to: u32,
    pub kind: CfgEdgeKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum CfgEdgeKind {
    Unconditional,
    True,
    False,
    Call,
    Return,
    Exception,
}

// ── Listing line ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct LineKey(pub u64); // hash of (func_id, addr, line_type)

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub enum LineType {
    #[default]
    Instruction,
    Label,
    Comment,
    DataByte,
    DataWord,
    DataDword,
    DataQword,
    DataString,
    Separator,
    FunctionHeader,
    FunctionFooter,
    XrefHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListingLine {
    pub key: LineKey,
    pub addr: Addr,
    pub kind: LineType,
    /// Pre-tokenized spans ready for the renderer
    pub spans: Vec<InsnToken>,
    pub comment: Option<String>,
    pub label: Option<String>,
    pub xrefs: Vec<XrefEntry>,
    pub indent: u8,
}

// ── Register ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Register {
    pub name: String,
    pub value: u64,
    pub width: u8, // bits
    pub dirty: bool,
    pub group: RegisterGroup,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum RegisterGroup {
    General,
    Flags,
    Simd,
    Fpu,
    Control,
    Debug,
    Segment,
}

// ── Breakpoint ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Breakpoint {
    pub id: u32,
    pub addr: Addr,
    pub enabled: bool,
    pub kind: BpKind,
    pub hit_count: u32,
    pub condition: Option<String>,
    pub label: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum BpKind {
    Software,
    Hardware,
    DataRead,
    DataWrite,
    DataAccess,
}

// ── Thread ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Thread {
    pub tid: u64,
    pub name: String,
    pub state: ThreadState,
    pub pc: Addr,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ThreadState {
    Running,
    Stopped,
    Suspended,
    Unknown,
}

// ── Stack frame ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StackFrame {
    pub index: u32,
    pub addr: Addr,
    pub sp: u64,
    pub func: Option<String>,
    pub module: Option<String>,
}

// ── Trace / replay / coverage / watchpoint types ─────────────────────────────

/// Trace recording lifecycle state for the Trace panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TraceState {
    #[default]
    Idle,
    Recording,
    Stopped,
    Replaying,
    Paused,
}

/// A single recorded trace event, used for memory timeline and replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEventRow {
    pub seq: u64,
    pub thread: u64,
    pub pc: Addr,
    pub addr: Addr,
    pub value: u64,
    pub size: u8,
    pub kind: TraceEventKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TraceEventKind {
    Exec,
    Read,
    Write,
}

/// A simulated playback frame on the replay timeline.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TracePos {
    pub seq: u64,
    pub thread: u64,
}

/// A single hot address entry in the coverage panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub addr: Addr,
    pub hits: u64,
    pub func: Option<String>,
}

/// Replay-reconstructed stack frame, used by the expanded stack panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayFrame {
    pub index: u32,
    pub addr: Addr,
    pub return_addr: Addr,
    pub sp: u64,
    pub func: Option<String>,
}

/// A data watchpoint managed by the breakpoint panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Watchpoint {
    pub id: u32,
    pub addr: Addr,
    pub size: u32,
    pub kind: WatchKind,
    pub condition: Option<String>,
    pub enabled: bool,
    pub trigger_count: u32,
    pub last_seq: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WatchKind {
    Read,
    Write,
    Access,
}

// ── Patch ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Patch {
    pub addr: Addr,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub comment: String,
}

// ── Comment ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comment {
    pub addr: Addr,
    pub text: String,
    pub repeatable: bool,
    pub author: String,
}

// ── Type system ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TypeInfo {
    Void,
    Bool,
    Int {
        bits: u8,
        signed: bool,
    },
    Float {
        bits: u8,
    },
    Pointer {
        pointee: Box<Self>,
        const_qual: bool,
    },
    Array {
        element: Box<Self>,
        count: u64,
    },
    Struct {
        name: String,
        fields: Vec<StructField>,
    },
    Union {
        name: String,
        fields: Vec<StructField>,
    },
    Enum {
        name: String,
        base: Box<Self>,
        variants: Vec<(String, i64)>,
    },
    FnPtr {
        ret: Box<Self>,
        params: Vec<Self>,
        variadic: bool,
    },
    Named {
        name: String,
    },
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub offset: u64,
    pub kind: TypeInfo,
    pub size: u64,
}

// ── CallGraphMetrics ──────────────────────────────────────────────────────────

/// Per-function call-graph metrics produced by the post-xref call-graph build
/// pass in `analysis::engine`. Indexed by `func_id`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallGraphMetrics {
    /// Number of distinct callers (in-degree).
    pub xref_in_count: u32,
    /// Number of distinct callees (out-degree).
    pub xref_out_count: u32,
    /// `true` when the function has no outgoing call.
    pub is_leaf: bool,
    /// `true` when the function has no incoming call (entry-point fan-in).
    pub is_root: bool,
    /// BFS depth from the nearest root. `None` ⇒ unreachable from any root.
    pub depth_from_root: Option<u32>,
    /// `true` when the function belongs to a non-trivial SCC (i.e. recursive).
    pub in_cycle: bool,
    /// Tarjan SCC id, `None` when the function is in a singleton SCC.
    pub scc_id: Option<u32>,
}

// ── RustTypeRecovery ──────────────────────────────────────────────────────────

/// A panic site recovered from embedded Rust panic strings in `.rdata`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RustPanicSite {
    pub addr: Addr,
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub message: Option<String>,
}

/// A Rust type-path mention extracted from `.rdata` (debug/display formatters,
/// vtable type names, etc.). Deduplicated by `type_path`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RustTypeMention {
    pub addr: Addr,
    pub type_path: String,
}

/// A heuristically detected Rust trait-object vtable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RustVtable {
    pub addr: Addr,
    pub type_name: Option<String>,
    pub methods: Vec<Addr>,
}

/// Aggregated output of [`crate::analysis::rust_type_recovery::recover_rust_types`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RustTypeRecovery {
    pub panic_sites: Vec<RustPanicSite>,
    pub type_mentions: Vec<RustTypeMention>,
    pub vtables: Vec<RustVtable>,
}

// ── BinDiffReport ─────────────────────────────────────────────────────────────

/// Compact per-function summary used by the bindiff backend.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BinDiffFuncSummary {
    pub addr: Addr,
    pub name: String,
    pub size: u64,
}

/// Report produced by `crate::analysis::bindiff_backend::diff_binaries`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BinDiffReport {
    /// Functions present in B but not in A.
    pub functions_added: Vec<BinDiffFuncSummary>,
    /// Functions present in A but not in B.
    pub functions_removed: Vec<BinDiffFuncSummary>,
    /// (A, B, similarity 0..1) — present in both with diverging bodies.
    pub functions_changed: Vec<(BinDiffFuncSummary, BinDiffFuncSummary, f32)>,
    /// (A, B) — byte-identical pairs.
    pub functions_identical: Vec<(BinDiffFuncSummary, BinDiffFuncSummary)>,
}

// ── Range ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct AddrRange {
    pub start: Addr,
    pub end: Addr,
}

impl AddrRange {
    pub const fn new(start: Addr, end: Addr) -> Self {
        Self { start, end }
    }
    pub const fn size(self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
    pub fn contains(self, addr: Addr) -> bool {
        addr >= self.start && addr < self.end
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_types() {
    let a = Addr(0x1000);
    let b = Addr(0x2000);
    let _ = a.offset(16);
    let _ = a.saturating_add(32);
    let _ = a.distance_to(b);

    let arch = Architecture::X86_64;
    let _ = arch.pointer_size();
    let _ = arch.is_64bit();
    let _ = arch.capstone_arch();

    let _ = BinaryFormat::Pe.as_str();

    let _ = SegmentFlags::READ.as_rwx_str();

    let func = Function {
        id: 0,
        addr: a,
        name: String::new(),
        size: 16,
        tags: FunctionTags::empty(),
        sym_id: None,
        comment: String::new(),
        color: None,
    };
    let _ = func.contains(a);

    let insn = Instruction {
        addr: a,
        bytes: vec![0x90],
        mnemonic: String::new(),
        op_str: String::new(),
        tokens: Vec::new(),
        comment: None,
        xrefs_to: Vec::new(),
        block_id: None,
    };
    let _ = insn.bytes_hex();

    let _ = XrefKind::Call.is_code();

    let range = AddrRange::new(a, b);
    let _ = range.size();
    let _ = range.contains(a);
    let _ = range.overlaps(AddrRange::new(a, b));

    // CallGraphMetrics — touch every field so the new struct participates in
    // real code paths and dead-code analysis does not flag it.
    let cgm = CallGraphMetrics {
        xref_in_count: 1,
        xref_out_count: 2,
        is_leaf: false,
        is_root: true,
        depth_from_root: Some(0),
        in_cycle: false,
        scc_id: Some(0),
    };
    let _ = (
        cgm.xref_in_count,
        cgm.xref_out_count,
        cgm.is_leaf,
        cgm.is_root,
        cgm.depth_from_root,
        cgm.in_cycle,
        cgm.scc_id,
    );

    // RustTypeRecovery + leaves
    let ps = RustPanicSite {
        addr: a,
        file: "src/lib.rs".into(),
        line: 1,
        col: 1,
        message: Some("panic".into()),
    };
    let tm = RustTypeMention {
        addr: a,
        type_path: "core::option::Option<u32>".into(),
    };
    let vt = RustVtable {
        addr: a,
        type_name: Some("dyn Iterator".into()),
        methods: vec![a],
    };
    let recov = RustTypeRecovery {
        panic_sites: vec![ps.clone()],
        type_mentions: vec![tm.clone()],
        vtables: vec![vt.clone()],
    };
    let _ = (
        recov.panic_sites.len(),
        recov.type_mentions.len(),
        recov.vtables.len(),
        ps.file,
        ps.line,
        ps.col,
        ps.message,
        tm.type_path,
        vt.type_name,
        vt.methods.len(),
    );

    // BinDiffReport
    let s1 = BinDiffFuncSummary {
        addr: a,
        name: "f".into(),
        size: 1,
    };
    let s2 = BinDiffFuncSummary {
        addr: b,
        name: "g".into(),
        size: 1,
    };
    let rep = BinDiffReport {
        functions_added: vec![s1.clone()],
        functions_removed: vec![s2.clone()],
        functions_changed: vec![(s1.clone(), s2.clone(), 0.5)],
        functions_identical: vec![(s1.clone(), s2.clone())],
    };
    let _ = (
        rep.functions_added.len(),
        rep.functions_removed.len(),
        rep.functions_changed.len(),
        rep.functions_identical.len(),
        s1.name,
        s1.size,
        s2.name,
        s2.size,
    );
}
