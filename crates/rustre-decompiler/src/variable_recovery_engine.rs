//! Variable recovery engine —  instruction-level variable identification.
//!
//! This module operates at the **instruction / MLIL layer**: it processes
//! [`InsnSummary`] records to track def/use sites, cross-block liveness, and
//! dead-variable detection.
//!
//! For the higher-level SSA naming layer —" alias analysis, heuristic naming,
//! and type-based renaming —" see [`super::variable_recovery`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VarKind
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Classification of a recovered variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarKind {
    /// Function parameter passed in a register.
    RegisterParam,
    /// Function parameter passed on the stack (positive frame offset).
    StackParam,
    /// Local variable on the stack (negative frame offset or rbp-relative).
    StackLocal,
    /// Global / static variable at a fixed virtual address.
    Global,
    /// Temporary register value not promoted to a named variable.
    Temp,
    /// Return value register.
    ReturnValue,
    /// Callee-saved register that is saved and restored by the function.
    CalleeSaved,
    /// Phi-node variable (SSA join point).
    Phi,
}

impl fmt::Display for VarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterParam => write!(f, "reg_param"),
            Self::StackParam => write!(f, "stack_param"),
            Self::StackLocal => write!(f, "local"),
            Self::Global => write!(f, "global"),
            Self::Temp => write!(f, "temp"),
            Self::ReturnValue => write!(f, "retval"),
            Self::CalleeSaved => write!(f, "callee_saved"),
            Self::Phi => write!(f, "phi"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VarStorage —" where a variable lives
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Describes where a recovered variable is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarStorage {
    Register(String),
    StackOffset(i64),
    GlobalAddr(u64),
    SsaVersion { base: String, version: u32 },
}

impl fmt::Display for VarStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::StackOffset(o) => write!(f, "stack[{o:+}]"),
            Self::GlobalAddr(a) => write!(f, "global:{a:#x}"),
            Self::SsaVersion { base, version } => write!(f, "{base}#{version}"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RecoveredVar
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single recovered variable.
#[derive(Debug, Clone)]
pub struct RecoveredVar {
    /// Unique variable ID within the function.
    pub id: u32,
    /// Human-readable name (may be auto-generated or recovered from debug info).
    pub name: String,
    /// Classification.
    pub kind: VarKind,
    /// Storage location.
    pub storage: VarStorage,
    /// Inferred type string (e.g. `"uint64_t"`, `"int *"`).
    pub type_hint: String,
    /// Byte size of the variable (0 = unknown).
    pub size: u32,
    /// Confidence score 0—"100 for the name assignment.
    pub name_confidence: u8,
    /// Set of instruction addresses that define this variable.
    pub def_sites: Vec<u64>,
    /// Set of instruction addresses that use this variable.
    pub use_sites: Vec<u64>,
    /// Whether the variable is referenced across basic block boundaries.
    pub cross_block: bool,
    /// Distinct access widths observed at this variable's storage location
    /// (in bytes). Used to detect struct-on-stack candidates.
    pub access_widths: BTreeSet<u32>,
}

impl RecoveredVar {
    /// Return `true` if this variable is a function parameter.
    #[must_use]
    pub const fn is_parameter(&self) -> bool {
        matches!(self.kind, VarKind::RegisterParam | VarKind::StackParam)
    }

    /// Return `true` if this is a local (non-parameter, non-global) variable.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self.kind, VarKind::StackLocal | VarKind::Temp | VarKind::Phi)
    }

    /// Return `true` if the variable has at least one definition site.
    #[must_use]
    pub const fn has_definition(&self) -> bool {
        !self.def_sites.is_empty()
    }

    /// Return `true` if this is a dead variable (defined but never used).
    #[must_use]
    pub const fn is_dead(&self) -> bool {
        self.has_definition() && self.use_sites.is_empty()
    }
}

impl fmt::Display for RecoveredVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({}) @ {} size={}B conf={}",
            self.type_hint, self.name, self.kind, self.storage, self.size, self.name_confidence
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CallingConvention
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Calling convention for parameter recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallingConvention {
    SysVAmd64,
    WindowsX64,
    Arm64,
    Arm32,
    /// x86 cdecl (32-bit): all arguments on the stack, caller cleans up.
    Cdecl,
    /// x86 stdcall (32-bit Windows API): all arguments on the stack, callee cleans up.
    Stdcall,
    /// x86 `__fastcall` (32-bit): first two integers in ecx, edx.
    Fastcall,
    /// x86 `__thiscall` (32-bit MSVC member fns): `this` in ecx.
    Thiscall,
    Generic,
}

impl CallingConvention {
    /// Integer parameter registers in argument order.
    #[must_use]
    pub const fn int_param_regs(self) -> &'static [&'static str] {
        match self {
            Self::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Self::WindowsX64 => &["rcx", "rdx", "r8", "r9"],
            Self::Arm64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            Self::Arm32 => &["r0", "r1", "r2", "r3"],
            Self::Fastcall => &["ecx", "edx"],
            Self::Thiscall => &["ecx"],
            Self::Cdecl | Self::Stdcall => &[],
            Self::Generic => &["arg0", "arg1", "arg2", "arg3"],
        }
    }

    /// Return value register.
    #[must_use]
    pub const fn return_reg(self) -> &'static str {
        match self {
            Self::SysVAmd64 | Self::WindowsX64 => "rax",
            Self::Arm64 => "x0",
            Self::Arm32 => "r0",
            // x86 32-bit conventions all return integers in eax.
            Self::Cdecl | Self::Stdcall | Self::Fastcall | Self::Thiscall => "eax",
            Self::Generic => "ret",
        }
    }

    /// Callee-saved registers.
    #[must_use]
    pub const fn callee_saved(self) -> &'static [&'static str] {
        match self {
            Self::SysVAmd64 => &["rbx", "rbp", "r12", "r13", "r14", "r15"],
            Self::WindowsX64 => &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            Self::Arm64 => &["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"],
            Self::Arm32 => &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
            // System V/MSVC x86-32 both preserve ebx, esi, edi, ebp.
            Self::Cdecl | Self::Stdcall | Self::Fastcall | Self::Thiscall => &["ebx", "esi", "edi", "ebp"],
            Self::Generic => &[],
        }
    }

    /// Infer from an architecture string.
    #[must_use]
    pub fn from_arch(arch: &str) -> Self {
        let a = arch.to_lowercase();
        if a.contains("aarch64") || a.contains("arm64") {
            Self::Arm64
        } else if a.contains("arm") {
            Self::Arm32
        } else if a.contains("x86_64") || a.contains("amd64") {
            // 64-bit takes priority over a bare "win" hint.
            if a.contains("win") || a.contains("msvc") {
                Self::WindowsX64
            } else {
                Self::SysVAmd64
            }
        } else if a.contains("win") || a.contains("msvc") {
            Self::WindowsX64
        } else if a.contains("x86") || a.contains("i386") || a.contains("i686") {
            Self::Cdecl
        } else {
            Self::Generic
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StackFrame
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Per-slot record tracking the widest access size, every distinct access
/// width observed, and an optional debug name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackSlot {
    /// Widest access size observed at this offset, in bytes.
    pub max_width: u32,
    /// Distinct access widths observed at this offset, in bytes (sorted).
    pub observed_widths: Vec<u32>,
    /// Optional debug name (e.g. from DWARF / PDB).
    pub debug_name: Option<String>,
}

impl StackSlot {
    fn record(&mut self, size: u32, name: Option<String>) {
        if size > self.max_width {
            self.max_width = size;
        }
        if !self.observed_widths.contains(&size) {
            self.observed_widths.push(size);
            self.observed_widths.sort_unstable();
        }
        if self.debug_name.is_none() {
            self.debug_name = name;
        }
    }
}

/// A struct-on-stack candidate detected from heterogeneous accesses near a
/// common base offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructOnStackCandidate {
    /// Suggested name (mirrors the underlying stack var name, e.g. `var_3`).
    pub name: String,
    /// Base offset (lowest absolute offset in the candidate).
    pub base_offset: i64,
    /// Total candidate span in bytes.
    pub span: u32,
    /// Sub-fields as `(sub_offset_from_base, width)`.
    pub fields: Vec<(u32, u32)>,
}

/// Describes the stack frame layout of a function.
#[derive(Debug, Clone, Default)]
pub struct StackFrame {
    /// Total frame size in bytes (0 = unknown).
    pub size: u64,
    /// Stack slots: `frame_offset` to per-slot record.
    pub slots: BTreeMap<i64, StackSlot>,
    /// Whether the frame pointer (rbp/r29) is used.
    pub frame_pointer_used: bool,
    /// The register used as frame pointer (if any).
    pub frame_pointer_reg: Option<String>,
}

impl StackFrame {
    /// Create a new empty stack frame.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a stack slot access.
    pub fn record_access(&mut self, offset: i64, size: u32, name: Option<String>) {
        let entry = self.slots.entry(offset).or_default();
        entry.record(size, name);
    }

    /// Return the number of stack slots.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Return parameter slots (positive offsets on typical ABIs).
    #[must_use]
    pub fn param_slots(&self) -> Vec<(i64, u32)> {
        self.slots
            .iter()
            .filter(|(o, _)| **o > 0)
            .map(|(o, s)| (*o, s.max_width))
            .collect()
    }

    /// Return local slots (negative offsets).
    #[must_use]
    pub fn local_slots(&self) -> Vec<(i64, u32)> {
        self.slots
            .iter()
            .filter(|(o, _)| **o < 0)
            .map(|(o, s)| (*o, s.max_width))
            .collect()
    }

    /// Detect struct-on-stack candidates.
    ///
    /// A slot is a candidate when **either** (a) it was accessed with two or
    /// more distinct widths, **or** (b) one or more adjacent slots fall inside
    /// the `[offset, offset + max_width)` window of a prior slot.
    #[must_use]
    pub fn struct_candidates(&self) -> Vec<StructOnStackCandidate> {
        let mut out = Vec::new();
        let entries: Vec<(i64, &StackSlot)> = self.slots.iter().map(|(o, s)| (*o, s)).collect();

        let mut consumed: HashSet<i64> = HashSet::new();
        for (i, (base_off, base_slot)) in entries.iter().enumerate() {
            if consumed.contains(base_off) {
                continue;
            }
            let mut fields: Vec<(u32, u32)> = Vec::new();
            for w in &base_slot.observed_widths {
                fields.push((0, *w));
            }
            let mut span = base_slot.max_width;
            for (off2, slot2) in entries.iter().skip(i + 1) {
                if *off2 <= *base_off {
                    continue;
                }
                let delta = (*off2 - *base_off).cast_unsigned();
                if delta < u64::from(base_slot.max_width) {
                    let sub = u32::try_from(delta).unwrap_or(u32::MAX);
                    for w in &slot2.observed_widths {
                        fields.push((sub, *w));
                    }
                    let end = sub + slot2.max_width;
                    if end > span {
                        span = end;
                    }
                    consumed.insert(*off2);
                } else {
                    break;
                }
            }
            let multi_width = base_slot.observed_widths.len() >= 2;
            let multi_field = fields.iter().map(|(s, _)| *s).collect::<HashSet<_>>().len() >= 2;
            if multi_width || multi_field {
                let name = if *base_off < 0 {
                    format!("local_{}", base_off.unsigned_abs())
                } else {
                    format!("arg_{base_off}")
                };
                out.push(StructOnStackCandidate {
                    name,
                    base_offset: *base_off,
                    span,
                    fields,
                });
            }
        }
        out
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VariableRecoveryEngine
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Engine that recovers variables from instruction-level information.
#[derive(Debug)]
pub struct VariableRecoveryEngine {
    calling_convention: CallingConvention,
    stack_frame: StackFrame,
    vars: Vec<RecoveredVar>,
    next_id: u32,
    next_temp: u32,
    /// Register â†' variable ID mapping for current allocation.
    reg_map: HashMap<String, u32>,
    /// Global address â†' variable ID.
    global_map: HashMap<u64, u32>,
    /// Stack offset â†' variable ID (avoids a linear scan over `vars` on every
    /// stack access, which is the hottest path in variable recovery).
    stack_map: HashMap<i64, u32>,
    /// Known debug names: storage â†' name.
    debug_names: HashMap<String, String>,
    /// Whether to emit callee-saved registers as variables.
    track_callee_saved: bool,
}

impl VariableRecoveryEngine {
    /// Create a new engine for a function with the given calling convention.
    #[must_use]
    pub fn new(cc: CallingConvention) -> Self {
        Self {
            calling_convention: cc,
            stack_frame: StackFrame::new(),
            vars: Vec::new(),
            next_id: 0,
            next_temp: 0,
            reg_map: HashMap::new(),
            global_map: HashMap::new(),
            stack_map: HashMap::new(),
            debug_names: HashMap::new(),
            track_callee_saved: false,
        }
    }

    /// Enable tracking of callee-saved registers.
    #[must_use] 
    pub const fn with_callee_saved(mut self) -> Self {
        self.track_callee_saved = true;
        self
    }

    /// Register a debug name for a storage location string.
    pub fn set_debug_name(&mut self, storage: impl Into<String>, name: impl Into<String>) {
        self.debug_names.insert(storage.into(), name.into());
    }

    const fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Seed parameter variables from the calling convention.
    pub fn seed_parameters(&mut self) {
        let cc = self.calling_convention;
        for (i, &reg) in cc.int_param_regs().iter().enumerate() {
            let storage = VarStorage::Register(reg.to_string());
            let name = self
                .debug_names
                .get(&format!("reg:{reg}"))
                .cloned()
                .unwrap_or_else(|| format!("param{i}"));
            let id = self.alloc_id();
            let var = RecoveredVar {
                id,
                name,
                kind: VarKind::RegisterParam,
                storage,
                type_hint: "uint64_t".into(),
                size: 8,
                name_confidence: 80,
                def_sites: Vec::new(),
                use_sites: Vec::new(),
                cross_block: false,
                access_widths: BTreeSet::new(),
            };
            self.vars.push(var);
            self.reg_map.insert(reg.to_string(), id);
        }

        // Return value register.
        let ret_reg = cc.return_reg();
        let id = self.alloc_id();
        let var = RecoveredVar {
            id,
            name: "retval".into(),
            kind: VarKind::ReturnValue,
            storage: VarStorage::Register(ret_reg.to_string()),
            type_hint: "uint64_t".into(),
            size: 8,
            name_confidence: 90,
            def_sites: Vec::new(),
            use_sites: Vec::new(),
            cross_block: false,
                access_widths: BTreeSet::new(),
        };
        self.vars.push(var);
        self.reg_map.insert(ret_reg.to_string(), id);

        // Callee-saved registers.
        if self.track_callee_saved {
            for &reg in cc.callee_saved() {
                let id = self.alloc_id();
                let var = RecoveredVar {
                    id,
                    name: format!("saved_{reg}"),
                    kind: VarKind::CalleeSaved,
                    storage: VarStorage::Register(reg.to_string()),
                    type_hint: "uint64_t".into(),
                    size: 8,
                    name_confidence: 95,
                    def_sites: Vec::new(),
                    use_sites: Vec::new(),
                    cross_block: false,
                access_widths: BTreeSet::new(),
                };
                self.vars.push(var);
            }
        }
    }

    /// Record a stack access and return the associated variable ID.
    pub fn record_stack_access(&mut self, offset: i64, size: u32, addr: u64, is_def: bool) -> u32 {
        // Check if we already have a variable at this offset.
        if let Some(&id) = self.stack_map.get(&offset) {
            let var = &mut self.vars[id as usize];
            if is_def {
                if !var.def_sites.contains(&addr) { var.def_sites.push(addr); }
            } else if !var.use_sites.contains(&addr) {
                var.use_sites.push(addr);
            }
            var.access_widths.insert(size);
            // Widen the variable size and the underlying stack-frame slot if
            // this access is wider than what we have recorded so far.
            if size > var.size {
                var.size = size;
                let type_hint = if size == 1 { "uint8_t" } else if size == 2 { "uint16_t" }
                                else if size == 4 { "uint32_t" } else { "uint64_t" };
                var.type_hint = type_hint.into();
            }
            let id = var.id;
            self.stack_frame.record_access(offset, size, None);
            return id;
        }

        // Allocate new variable.
        let kind = if offset > 0 { VarKind::StackParam } else { VarKind::StackLocal };
        let storage = VarStorage::StackOffset(offset);
        let name = self
            .debug_names
            .get(&format!("stack[{offset:+}]"))
            .cloned()
            .unwrap_or_else(|| {
                if offset < 0 {
                    format!("local_{}", offset.unsigned_abs())
                } else {
                    format!("arg_{offset}")
                }
            });
        let type_hint = if size == 1 { "uint8_t" } else if size == 2 { "uint16_t" }
                        else if size == 4 { "uint32_t" } else { "uint64_t" };
        let id = self.alloc_id();
        let mut var = RecoveredVar {
            id,
            name,
            kind,
            storage,
            type_hint: type_hint.into(),
            size,
            name_confidence: 60,
            def_sites: Vec::new(),
            use_sites: Vec::new(),
            cross_block: false,
            access_widths: BTreeSet::new(),
        };
        var.access_widths.insert(size);
        if is_def { var.def_sites.push(addr); } else { var.use_sites.push(addr); }
        self.stack_frame.record_access(offset, size, None);
        self.vars.push(var);
        self.stack_map.insert(offset, id);
        id
    }

    /// Record a global variable access.
    pub fn record_global_access(&mut self, addr: u64, size: u32, insn_addr: u64, is_def: bool) -> u32 {
        if let Some(&id) = self.global_map.get(&addr) {
            if let Some(var) = self.vars.get_mut(id as usize) {
                if is_def { var.def_sites.push(insn_addr); } else { var.use_sites.push(insn_addr); }
            }
            return id;
        }
        let name = self
            .debug_names
            .get(&format!("global:{addr:#x}"))
            .cloned()
            .unwrap_or_else(|| format!("g_{addr:#x}"));
        let type_hint = if size == 1 { "uint8_t" } else if size == 2 { "uint16_t" }
                        else if size == 4 { "uint32_t" } else { "uint64_t" };
        let id = self.alloc_id();
        let mut var = RecoveredVar {
            id,
            name,
            kind: VarKind::Global,
            storage: VarStorage::GlobalAddr(addr),
            type_hint: type_hint.into(),
            size,
            name_confidence: 50,
            def_sites: Vec::new(),
            use_sites: Vec::new(),
            cross_block: false,
                access_widths: BTreeSet::new(),
        };
        if is_def { var.def_sites.push(insn_addr); } else { var.use_sites.push(insn_addr); }
        self.vars.push(var);
        self.global_map.insert(addr, id);
        id
    }

    /// Allocate a temporary variable for a register not yet named.
    pub fn alloc_temp(&mut self, reg: impl Into<String>) -> u32 {
        let reg = reg.into();
        if let Some(&id) = self.reg_map.get(&reg) {
            return id;
        }
        let name = format!("t{}", self.next_temp);
        self.next_temp += 1;
        let id = self.alloc_id();
        let var = RecoveredVar {
            id,
            name,
            kind: VarKind::Temp,
            storage: VarStorage::Register(reg.clone()),
            type_hint: "uint64_t".into(),
            size: 8,
            name_confidence: 30,
            def_sites: Vec::new(),
            use_sites: Vec::new(),
            cross_block: false,
                access_widths: BTreeSet::new(),
        };
        self.vars.push(var);
        self.reg_map.insert(reg, id);
        id
    }

    /// Mark a variable as crossing basic block boundaries.
    pub fn mark_cross_block(&mut self, id: u32) {
        if let Some(var) = self.vars.get_mut(id as usize) {
            var.cross_block = true;
        }
    }

    /// Return all recovered variables.
    #[must_use]
    pub fn vars(&self) -> &[RecoveredVar] {
        &self.vars
    }

    /// Return only parameter variables.
    #[must_use]
    pub fn parameters(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| v.is_parameter()).collect()
    }

    /// Return only local variables.
    #[must_use]
    pub fn locals(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| v.is_local()).collect()
    }

    /// Return dead variables (defined but never used).
    #[must_use]
    pub fn dead_vars(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| v.is_dead()).collect()
    }

    /// Return the stack frame analysis.
    #[must_use]
    pub const fn stack_frame(&self) -> &StackFrame {
        &self.stack_frame
    }

    /// Record a sub-field access against an existing struct-on-stack base
    /// offset.  The `sub` byte offset is relative to `base`, and `width` is
    /// the access width in bytes.  Returns `true` if the access was applied
    /// (i.e. a base variable existed at `base`).
    pub fn record_struct_field_access(&mut self, base: i64, sub: u32, width: u32) -> bool {
        // Record the field in the underlying stack frame so struct candidate
        // detection sees the heterogeneous layout.
        self.stack_frame
            .record_access(base + i64::from(sub), width, None);
        if let Some(var) = self
            .stack_map
            .get(&base)
            .and_then(|&id| self.vars.get_mut(id as usize))
        {
            var.access_widths.insert(width);
            let needed = sub + width;
            if needed > var.size {
                var.size = needed;
            }
            true
        } else {
            false
        }
    }

    /// Return all stack locals re-named monotonically as `var_0`, `var_1`,
    /// ... in offset order (most-negative offset first).  The original
    /// stack offset is returned alongside each rename so callers can build a
    /// rewrite map.
    #[must_use]
    pub fn stack_locals_named(&self) -> Vec<(i64, String, u32)> {
        let mut locals: Vec<(i64, u32)> = self
            .vars
            .iter()
            .filter_map(|v| match v.storage {
                VarStorage::StackOffset(o) if v.kind == VarKind::StackLocal => Some((o, v.size)),
                _ => None,
            })
            .collect();
        locals.sort_by_key(|(o, _)| *o);
        locals
            .into_iter()
            .enumerate()
            .map(|(i, (o, w))| (o, format!("var_{i}"), w))
            .collect()
    }

    /// Return struct-on-stack candidates from the underlying stack frame.
    #[must_use]
    pub fn struct_candidates(&self) -> Vec<StructOnStackCandidate> {
        self.stack_frame.struct_candidates()
    }

    /// Total number of recovered variables.
    #[must_use]
    pub const fn var_count(&self) -> usize {
        self.vars.len()
    }

    /// Return the set of distinct register names occupied by any recovered
    /// variable.
    ///
    /// Useful for callers that want to detect register pressure or build a
    /// liveness summary across the recovered set.
    #[must_use]
    pub fn distinct_register_storage(&self) -> HashSet<String> {
        let mut out: HashSet<String> = HashSet::new();
        for v in &self.vars {
            if let VarStorage::Register(r) = &v.storage {
                out.insert(r.clone());
            }
        }
        out
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// recover_vars —" high-level convenience function
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A minimal description of a single instruction for variable recovery.
#[derive(Debug, Clone)]
pub struct InsnSummary {
    /// Address of the instruction.
    pub addr: u64,
    /// Mnemonic.
    pub mnemonic: String,
    /// Destination register (if any).
    pub dst_reg: Option<String>,
    /// Source register(s).
    pub src_regs: Vec<String>,
    /// Stack offset accessed (if any).
    pub stack_offset: Option<i64>,
    /// Access size in bytes.
    pub access_size: u32,
    /// Whether this instruction writes to the destination.
    pub is_def: bool,
    /// Global address accessed (if any).
    pub global_addr: Option<u64>,
}

/// Recover variables from a list of instruction summaries.
///
/// Returns all recovered variables in the order they were discovered.
#[must_use]
pub fn recover_vars(
    instructions: &[InsnSummary],
    cc: CallingConvention,
) -> Vec<RecoveredVar> {
    let mut engine = VariableRecoveryEngine::new(cc);
    engine.seed_parameters();

    for insn in instructions {
        if let Some(offset) = insn.stack_offset {
            engine.record_stack_access(offset, insn.access_size.max(1), insn.addr, insn.is_def);
        }
        if let Some(addr) = insn.global_addr {
            engine.record_global_access(addr, insn.access_size.max(1), insn.addr, insn.is_def);
        }
        if let Some(reg) = &insn.dst_reg {
            // Only allocate temp for unknown registers.
            if !cc.int_param_regs().contains(&reg.as_str()) && reg != cc.return_reg() {
                engine.alloc_temp(reg.clone());
            }
        }
    }

    engine.vars().to_vec()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_parameters_sysv() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.seed_parameters();
        let params: Vec<_> = eng.parameters();
        assert_eq!(params.len(), 6); // rdi..r9
        assert_eq!(params[0].name, "param0");
        assert_eq!(params[0].storage, VarStorage::Register("rdi".into()));
    }

    #[test]
    fn stack_local_allocation() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.record_stack_access(-8, 8, 0x1000, true);
        eng.record_stack_access(-8, 8, 0x1004, false);
        let locals: Vec<_> = eng.vars().iter().filter(|v| v.kind == VarKind::StackLocal).collect();
        assert_eq!(locals.len(), 1);
        assert!(!locals[0].is_dead());
    }

    #[test]
    fn dead_variable_detection() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.record_stack_access(-16, 4, 0x2000, true); // define only
        let dead: Vec<_> = eng.dead_vars();
        assert_eq!(dead.len(), 1);
    }

    #[test]
    fn recover_vars_convenience() {
        let insns = vec![
            InsnSummary {
                addr: 0x100,
                mnemonic: "mov".into(),
                dst_reg: Some("rbx".into()),
                src_regs: vec!["rdi".into()],
                stack_offset: None,
                access_size: 8,
                is_def: true,
                global_addr: None,
            },
        ];
        let vars = recover_vars(&insns, CallingConvention::SysVAmd64);
        assert!(!vars.is_empty());
    }

    #[test]
    fn cc_from_arch() {
        assert_eq!(CallingConvention::from_arch("x86_64-linux"), CallingConvention::SysVAmd64);
        assert_eq!(CallingConvention::from_arch("aarch64-apple"), CallingConvention::Arm64);
        assert_eq!(CallingConvention::from_arch("x86_64-win32-msvc"), CallingConvention::WindowsX64);
    }

    // â"€â"€ Added comprehensive tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn empty_engine_has_no_vars() {
        let eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        assert_eq!(eng.var_count(), 0);
        assert!(eng.vars().is_empty());
        assert!(eng.parameters().is_empty());
        assert!(eng.locals().is_empty());
        assert!(eng.dead_vars().is_empty());
        assert_eq!(eng.stack_frame().slot_count(), 0);
    }

    #[test]
    fn seed_parameters_windows_x64_has_four() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::WindowsX64);
        eng.seed_parameters();
        let params = eng.parameters();
        assert_eq!(params.len(), 4); // rcx, rdx, r8, r9
        assert_eq!(params[0].storage, VarStorage::Register("rcx".into()));
        // Retval reg should also be present.
        assert!(eng.vars().iter().any(|v| v.kind == VarKind::ReturnValue));
    }

    #[test]
    fn callee_saved_only_emitted_when_enabled() {
        let mut eng_off = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng_off.seed_parameters();
        assert!(eng_off.vars().iter().all(|v| v.kind != VarKind::CalleeSaved));

        let mut eng_on = VariableRecoveryEngine::new(CallingConvention::SysVAmd64).with_callee_saved();
        eng_on.seed_parameters();
        let cs: Vec<_> = eng_on.vars().iter().filter(|v| v.kind == VarKind::CalleeSaved).collect();
        assert_eq!(cs.len(), CallingConvention::SysVAmd64.callee_saved().len());
    }

    #[test]
    fn stack_access_widens_slot_size() {
        // First access is 1 byte; later 8 bytes should widen the recorded slot.
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-4, 1, 0x10, true);
        eng.record_stack_access(-4, 8, 0x14, false);
        // Slot widens.
        let slot = &eng.stack_frame().slots[&-4];
        assert_eq!(slot.max_width, 8);
        assert!(slot.observed_widths.contains(&1));
        assert!(slot.observed_widths.contains(&8));
        // Still one variable, with both a def and a use site.
        let v = eng.vars().iter().find(|v| v.storage == VarStorage::StackOffset(-4)).unwrap();
        assert_eq!(v.def_sites, vec![0x10]);
        assert_eq!(v.use_sites, vec![0x14]);
        assert!(!v.is_dead());
    }

    #[test]
    fn stack_access_dedupes_repeated_sites() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-8, 8, 0x100, true);
        eng.record_stack_access(-8, 8, 0x100, true); // duplicate def at same addr
        eng.record_stack_access(-8, 8, 0x104, false);
        eng.record_stack_access(-8, 8, 0x104, false); // duplicate use
        let v = &eng.vars()[0];
        assert_eq!(v.def_sites.len(), 1);
        assert_eq!(v.use_sites.len(), 1);
    }

    #[test]
    fn positive_offset_classified_as_stack_param() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(16, 8, 0x200, false);
        let v = &eng.vars()[0];
        assert_eq!(v.kind, VarKind::StackParam);
        assert!(v.is_parameter());
        assert!(v.name.starts_with("arg_"));
    }

    #[test]
    fn negative_offset_classified_as_local() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-32, 4, 0x200, true);
        let v = &eng.vars()[0];
        assert_eq!(v.kind, VarKind::StackLocal);
        assert!(v.is_local());
        assert!(v.name.starts_with("local_"));
        assert_eq!(v.type_hint, "uint32_t");
    }

    #[test]
    fn type_hint_chosen_from_size() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-1, 1, 0x300, true);
        eng.record_stack_access(-2, 2, 0x304, true);
        eng.record_stack_access(-3, 4, 0x308, true);
        eng.record_stack_access(-4, 8, 0x30c, true);
        let types: Vec<&str> = eng.vars().iter().map(|v| v.type_hint.as_str()).collect();
        assert!(types.contains(&"uint8_t"));
        assert!(types.contains(&"uint16_t"));
        assert!(types.contains(&"uint32_t"));
        assert!(types.contains(&"uint64_t"));
    }

    #[test]
    fn global_access_dedup_and_lookup() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        let id1 = eng.record_global_access(0xdead_beef, 4, 0x500, true);
        let id2 = eng.record_global_access(0xdead_beef, 4, 0x504, false);
        assert_eq!(id1, id2, "same global address should yield same id");
        let v = eng.vars().iter().find(|v| v.id == id1).unwrap();
        assert_eq!(v.kind, VarKind::Global);
        assert_eq!(v.storage, VarStorage::GlobalAddr(0xdead_beef));
        assert_eq!(v.def_sites.len(), 1);
        assert_eq!(v.use_sites.len(), 1);
    }

    #[test]
    fn debug_names_override_default() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.set_debug_name("reg:rdi", "argc");
        eng.set_debug_name("stack[-16]", "counter");
        eng.set_debug_name("global:0x1000", "g_flag");
        eng.seed_parameters();
        eng.record_stack_access(-16, 4, 0x10, true);
        eng.record_global_access(0x1000, 4, 0x20, false);

        let names: Vec<&str> = eng.vars().iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"argc"));
        assert!(names.contains(&"counter"));
        assert!(names.contains(&"g_flag"));
    }

    #[test]
    fn alloc_temp_is_idempotent_per_register() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        let a = eng.alloc_temp("r10");
        let b = eng.alloc_temp("r10");
        let c = eng.alloc_temp("r11");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(eng.vars().iter().filter(|v| v.kind == VarKind::Temp).count(), 2);
    }

    #[test]
    fn mark_cross_block_only_affects_target() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        let id1 = eng.alloc_temp("r10");
        let id2 = eng.alloc_temp("r11");
        eng.mark_cross_block(id1);
        assert!(eng.vars().iter().find(|v| v.id == id1).unwrap().cross_block);
        assert!(!eng.vars().iter().find(|v| v.id == id2).unwrap().cross_block);
        // Marking an unknown id is a silent no-op.
        eng.mark_cross_block(9999);
    }

    #[test]
    fn stack_frame_param_and_local_partition() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-8, 8, 0x1, true);
        eng.record_stack_access(-16, 4, 0x2, true);
        eng.record_stack_access(16, 8, 0x3, false);
        eng.record_stack_access(24, 8, 0x4, false);
        let frame = eng.stack_frame();
        assert_eq!(frame.local_slots().len(), 2);
        assert_eq!(frame.param_slots().len(), 2);
        // Offset 0 is excluded from both (strict positive/negative).
        eng.record_stack_access(0, 4, 0x5, true);
        let frame = eng.stack_frame();
        assert_eq!(frame.local_slots().len(), 2);
        assert_eq!(frame.param_slots().len(), 2);
    }

    #[test]
    fn extreme_stack_offsets_handled() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        // i64::MIN would overflow the unsigned_abs format inside, but let's
        // stay near boundary values that the i64 arithmetic supports cleanly.
        eng.record_stack_access(i64::MIN + 1, 8, 0x1, true);
        eng.record_stack_access(i64::MAX, 8, 0x2, false);
        assert_eq!(eng.var_count(), 2);
        let kinds: Vec<_> = eng.vars().iter().map(|v| v.kind).collect();
        assert!(kinds.contains(&VarKind::StackLocal));
        assert!(kinds.contains(&VarKind::StackParam));
    }

    #[test]
    fn distinct_register_storage_collects_unique_regs() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.seed_parameters();
        eng.alloc_temp("rbx");
        let regs = eng.distinct_register_storage();
        // 6 param regs + rax retval + rbx temp = 8 distinct registers.
        assert_eq!(regs.len(), 8);
        assert!(regs.contains("rdi"));
        assert!(regs.contains("rax"));
        assert!(regs.contains("rbx"));
    }

    #[test]
    fn recover_vars_empty_input_still_seeds_params() {
        let vars = recover_vars(&[], CallingConvention::SysVAmd64);
        // Only the seeded params + retval should appear.
        assert!(vars.iter().any(|v| v.kind == VarKind::ReturnValue));
        assert_eq!(vars.iter().filter(|v| v.is_parameter()).count(), 6);
    }

    #[test]
    fn recover_vars_does_not_alloc_temp_for_param_regs() {
        // A def into rdi (a sysv param reg) should not create a *new* temp var.
        let insn = InsnSummary {
            addr: 0x100,
            mnemonic: "mov".into(),
            dst_reg: Some("rdi".into()),
            src_regs: vec![],
            stack_offset: None,
            access_size: 8,
            is_def: true,
            global_addr: None,
        };
        let vars = recover_vars(&[insn], CallingConvention::SysVAmd64);
        // Should still be exactly 7 vars (6 params + retval).
        assert_eq!(vars.len(), 7);
        assert_eq!(vars.iter().filter(|v| v.kind == VarKind::Temp).count(), 0);
    }

    #[test]
    fn recover_vars_zero_access_size_clamped_to_one() {
        // access_size=0 must not produce a zero-size variable.
        let insn = InsnSummary {
            addr: 0x100,
            mnemonic: "ld".into(),
            dst_reg: None,
            src_regs: vec![],
            stack_offset: Some(-4),
            access_size: 0,
            is_def: true,
            global_addr: None,
        };
        let vars = recover_vars(&[insn], CallingConvention::Generic);
        let local = vars.iter().find(|v| v.kind == VarKind::StackLocal).unwrap();
        assert_eq!(local.size, 1, "zero size should be clamped to 1");
    }

    #[test]
    fn varkind_display_matches_expected_tokens() {
        assert_eq!(VarKind::RegisterParam.to_string(), "reg_param");
        assert_eq!(VarKind::StackLocal.to_string(), "local");
        assert_eq!(VarKind::ReturnValue.to_string(), "retval");
        assert_eq!(VarKind::Phi.to_string(), "phi");
    }

    #[test]
    fn varstorage_display_uses_signed_offset() {
        assert_eq!(VarStorage::StackOffset(-8).to_string(), "stack[-8]");
        assert_eq!(VarStorage::StackOffset(16).to_string(), "stack[+16]");
        assert_eq!(VarStorage::GlobalAddr(0x1234).to_string(), "global:0x1234");
        assert_eq!(VarStorage::Register("rax".into()).to_string(), "reg:rax");
    }

    #[test]
    fn cc_from_arch_unknown_falls_back_generic() {
        assert_eq!(CallingConvention::from_arch(""), CallingConvention::Generic);
        assert_eq!(CallingConvention::from_arch("riscv64"), CallingConvention::Generic);
    }

    #[test]
    fn cc_from_arch_is_case_insensitive() {
        assert_eq!(CallingConvention::from_arch("X86_64"), CallingConvention::SysVAmd64);
        assert_eq!(CallingConvention::from_arch("ARM64"), CallingConvention::Arm64);
    }

    #[test]
    fn access_widths_tracked_per_var() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-8, 4, 0x10, true);
        eng.record_stack_access(-8, 8, 0x14, false);
        eng.record_stack_access(-8, 4, 0x18, false);
        let v = eng.vars().iter().find(|v| v.storage == VarStorage::StackOffset(-8)).unwrap();
        assert_eq!(v.access_widths.len(), 2);
        assert!(v.access_widths.contains(&4));
        assert!(v.access_widths.contains(&8));
    }

    #[test]
    fn struct_candidate_from_multi_width_slot() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        // Same offset accessed with two distinct widths -> struct candidate.
        eng.record_stack_access(-16, 4, 0x10, true);
        eng.record_stack_access(-16, 8, 0x14, false);
        let cands = eng.struct_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].base_offset, -16);
        assert!(cands[0].fields.iter().any(|(_, w)| *w == 4));
        assert!(cands[0].fields.iter().any(|(_, w)| *w == 8));
    }

    #[test]
    fn struct_candidate_from_adjacent_slots() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        // base at -32 (8 bytes), then adjacent fields at -32+4 (4 bytes).
        eng.record_stack_access(-32, 8, 0x10, true);
        eng.record_stack_access(-28, 4, 0x14, true);
        let cands = eng.struct_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].base_offset, -32);
        assert_eq!(cands[0].name, "local_32");
        // fields should include (0,8) and (4,4)
        assert!(cands[0].fields.contains(&(0, 8)));
        assert!(cands[0].fields.contains(&(4, 4)));
    }

    #[test]
    fn stack_locals_named_uses_monotonic_var_n() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-8, 8, 0x10, true);
        eng.record_stack_access(-16, 8, 0x14, true);
        eng.record_stack_access(-24, 4, 0x18, true);
        let renames = eng.stack_locals_named();
        assert_eq!(renames.len(), 3);
        // Sorted by offset ascending (most-negative first).
        assert_eq!(renames[0].0, -24);
        assert_eq!(renames[0].1, "var_0");
        assert_eq!(renames[1].0, -16);
        assert_eq!(renames[1].1, "var_1");
        assert_eq!(renames[2].0, -8);
        assert_eq!(renames[2].1, "var_2");
    }

    #[test]
    fn record_struct_field_access_widens_base_var() {
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-32, 4, 0x10, true);
        let ok = eng.record_struct_field_access(-32, 8, 4);
        assert!(ok);
        let v = eng.vars().iter().find(|v| v.storage == VarStorage::StackOffset(-32)).unwrap();
        assert!(v.size >= 12);
        // The frame now has a slot for the sub-field as well.
        assert!(eng.stack_frame().slots.contains_key(&-24));
    }

    #[test]
    fn x86_abis_have_correct_registers() {
        assert_eq!(CallingConvention::Cdecl.int_param_regs(), &[] as &[&str]);
        assert_eq!(CallingConvention::Stdcall.int_param_regs(), &[] as &[&str]);
        assert_eq!(CallingConvention::Fastcall.int_param_regs(), &["ecx", "edx"]);
        assert_eq!(CallingConvention::Thiscall.int_param_regs(), &["ecx"]);
        // 32-bit conventions return integers in eax.
        for cc in [
            CallingConvention::Cdecl,
            CallingConvention::Stdcall,
            CallingConvention::Fastcall,
            CallingConvention::Thiscall,
        ] {
            assert_eq!(cc.return_reg(), "eax");
            assert!(cc.callee_saved().contains(&"ebx"));
        }
    }

    #[test]
    fn from_arch_maps_32bit_x86_to_cdecl() {
        assert_eq!(CallingConvention::from_arch("i386"), CallingConvention::Cdecl);
        assert_eq!(CallingConvention::from_arch("x86"), CallingConvention::Cdecl);
        // 64-bit must still win over a bare width-agnostic match.
        assert_eq!(CallingConvention::from_arch("x86_64"), CallingConvention::SysVAmd64);
    }
}
