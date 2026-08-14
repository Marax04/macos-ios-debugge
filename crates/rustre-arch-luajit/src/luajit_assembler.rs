//! LuaJIT bytecode assembler.
//!
//! Provides:
//! - [`AssemblerInstruction`] — a symbolic assembler instruction
//! - [`LabelResolver`] — forward/backward label resolution
//! - [`RegisterAllocator`] — simple linear-scan register allocator
//! - [`ConstantTable`] — constant pool management
//! - [`AssemblerOutput`] — the final assembled bytecode
//! - [`LuaJitAssembler`] — the main assembler facade

// ---------------------------------------------------------------------------
// LuaJIT opcode table
// ---------------------------------------------------------------------------

/// `LuaJIT` 2 opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LjOp {
    // Comparison
    ISLT = 0,
    ISGE = 1,
    ISLE = 2,
    ISGT = 3,
    ISEQV = 4,
    ISNEV = 5,
    ISEQS = 6,
    ISNES = 7,
    ISEQN = 8,
    ISNEN = 9,
    ISEQP = 10,
    ISNEP = 11,
    // Unary tests
    ISTC = 12,
    ISFC = 13,
    IST = 14,
    ISF = 15,
    ISTYPE = 16,
    ISNUM = 17,
    // Copies
    MOV = 18,
    NOT = 19,
    UNM = 20,
    LEN = 21,
    // Binary ops
    ADDVN = 22,
    SUBVN = 23,
    MULVN = 24,
    DIVVN = 25,
    MODVN = 26,
    ADDNV = 27,
    SUBNV = 28,
    MULNV = 29,
    DIVNV = 30,
    MODNV = 31,
    ADDVV = 32,
    SUBVV = 33,
    MULVV = 34,
    DIVVV = 35,
    MODVV = 36,
    POW = 37,
    CAT = 38,
    // Constant loads
    KSTR = 39,
    KCDATA = 40,
    KSHORT = 41,
    KNUM = 42,
    KPRI = 43,
    KNIL = 44,
    // Upvalue / function env
    UGET = 45,
    USETV = 46,
    USETS = 47,
    USETN = 48,
    USETP = 49,
    UCLO = 50,
    FNEW = 51,
    // Table ops
    TNEW = 52,
    TDUP = 53,
    GGET = 54,
    GSET = 55,
    TGETV = 56,
    TGETS = 57,
    TGETB = 58,
    TGETR = 59,
    TSETV = 60,
    TSETS = 61,
    TSETB = 62,
    TSETM = 63,
    TSETR = 64,
    // Calls / vararg
    CALLM = 65,
    CALL = 66,
    CALLMT = 67,
    CALLT = 68,
    ITERC = 69,
    ITERN = 70,
    VARG = 71,
    ISNEXT = 72,
    // Returns
    RETM = 73,
    RET = 74,
    RET0 = 75,
    RET1 = 76,
    // Jumps
    FORI = 77,
    JFORI = 78,
    FORL = 79,
    IFORL = 80,
    JFORL = 81,
    ITERL = 82,
    IITERL = 83,
    JITERL = 84,
    LOOP = 85,
    ILOOP = 86,
    JLOOP = 87,
    JMP = 88,
    // Function headers
    FUNCF = 89,
    IFUNCF = 90,
    JFUNCF = 91,
    FUNCV = 92,
    IFUNCV = 93,
    JFUNCV = 94,
    FUNCC = 95,
    FUNCCW = 96,
}

impl LjOp {
    /// Opcode number as u8.
    #[must_use] 
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// `true` if this opcode is a comparison.
    #[must_use] 
    pub const fn is_comparison(self) -> bool {
        (self as u8) <= 11
    }

    /// `true` if this opcode causes a jump.
    #[must_use] 
    pub const fn is_jump(self) -> bool {
        matches!(
            self,
            Self::JMP
                | Self::FORI
                | Self::JFORI
                | Self::FORL
                | Self::IFORL
                | Self::JFORL
                | Self::ITERL
                | Self::IITERL
                | Self::JITERL
                | Self::LOOP
                | Self::ILOOP
                | Self::JLOOP
                | Self::ISLT
                | Self::ISGE
                | Self::ISLE
                | Self::ISGT
                | Self::ISEQV
                | Self::ISNEV
        )
    }

    /// `true` if this is a return opcode.
    #[must_use] 
    pub const fn is_return(self) -> bool {
        matches!(self, Self::RET | Self::RET0 | Self::RET1 | Self::RETM)
    }

    /// Mnemonic string.
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::ISLT => "ISLT",
            Self::ISGE => "ISGE",
            Self::ISLE => "ISLE",
            Self::ISGT => "ISGT",
            Self::ISEQV => "ISEQV",
            Self::ISNEV => "ISNEV",
            Self::ISEQS => "ISEQS",
            Self::ISNES => "ISNES",
            Self::ISEQN => "ISEQN",
            Self::ISNEN => "ISNEN",
            Self::ISEQP => "ISEQP",
            Self::ISNEP => "ISNEP",
            Self::ISTC => "ISTC",
            Self::ISFC => "ISFC",
            Self::IST => "IST",
            Self::ISF => "ISF",
            Self::ISTYPE => "ISTYPE",
            Self::ISNUM => "ISNUM",
            Self::MOV => "MOV",
            Self::NOT => "NOT",
            Self::UNM => "UNM",
            Self::LEN => "LEN",
            Self::ADDVN => "ADDVN",
            Self::SUBVN => "SUBVN",
            Self::MULVN => "MULVN",
            Self::DIVVN => "DIVVN",
            Self::MODVN => "MODVN",
            Self::ADDNV => "ADDNV",
            Self::SUBNV => "SUBNV",
            Self::MULNV => "MULNV",
            Self::DIVNV => "DIVNV",
            Self::MODNV => "MODNV",
            Self::ADDVV => "ADDVV",
            Self::SUBVV => "SUBVV",
            Self::MULVV => "MULVV",
            Self::DIVVV => "DIVVV",
            Self::MODVV => "MODVV",
            Self::POW => "POW",
            Self::CAT => "CAT",
            Self::KSTR => "KSTR",
            Self::KCDATA => "KCDATA",
            Self::KSHORT => "KSHORT",
            Self::KNUM => "KNUM",
            Self::KPRI => "KPRI",
            Self::KNIL => "KNIL",
            Self::UGET => "UGET",
            Self::USETV => "USETV",
            Self::USETS => "USETS",
            Self::USETN => "USETN",
            Self::USETP => "USETP",
            Self::UCLO => "UCLO",
            Self::FNEW => "FNEW",
            Self::TNEW => "TNEW",
            Self::TDUP => "TDUP",
            Self::GGET => "GGET",
            Self::GSET => "GSET",
            Self::TGETV => "TGETV",
            Self::TGETS => "TGETS",
            Self::TGETB => "TGETB",
            Self::TGETR => "TGETR",
            Self::TSETV => "TSETV",
            Self::TSETS => "TSETS",
            Self::TSETB => "TSETB",
            Self::TSETM => "TSETM",
            Self::TSETR => "TSETR",
            Self::CALLM => "CALLM",
            Self::CALL => "CALL",
            Self::CALLMT => "CALLMT",
            Self::CALLT => "CALLT",
            Self::ITERC => "ITERC",
            Self::ITERN => "ITERN",
            Self::VARG => "VARG",
            Self::ISNEXT => "ISNEXT",
            Self::RETM => "RETM",
            Self::RET => "RET",
            Self::RET0 => "RET0",
            Self::RET1 => "RET1",
            Self::FORI => "FORI",
            Self::JFORI => "JFORI",
            Self::FORL => "FORL",
            Self::IFORL => "IFORL",
            Self::JFORL => "JFORL",
            Self::ITERL => "ITERL",
            Self::IITERL => "IITERL",
            Self::JITERL => "JITERL",
            Self::LOOP => "LOOP",
            Self::ILOOP => "ILOOP",
            Self::JLOOP => "JLOOP",
            Self::JMP => "JMP",
            Self::FUNCF => "FUNCF",
            Self::IFUNCF => "IFUNCF",
            Self::JFUNCF => "JFUNCF",
            Self::FUNCV => "FUNCV",
            Self::IFUNCV => "IFUNCV",
            Self::JFUNCV => "JFUNCV",
            Self::FUNCC => "FUNCC",
            Self::FUNCCW => "FUNCCW",
        }
    }
}

impl std::fmt::Display for LjOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

// ---------------------------------------------------------------------------
// AssemblerInstruction
// ---------------------------------------------------------------------------

/// A symbolic assembler instruction (before encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblerInstruction {
    /// Opcode.
    pub op: LjOp,
    /// A field (destination register, 8-bit).
    pub a: u8,
    /// C field or low byte of D.
    pub c: u8,
    /// B field or high byte of D.
    pub b: u8,
    /// Optional label reference for jump instructions.
    pub label: Option<String>,
}

impl AssemblerInstruction {
    /// Create a standard ABC instruction.
    #[must_use] 
    pub const fn abc(op: LjOp, a: u8, b: u8, c: u8) -> Self {
        Self {
            op,
            a,
            b,
            c,
            label: None,
        }
    }

    /// Create an AD instruction (D = (b << 8) | c).
    #[must_use] 
    pub const fn ad(op: LjOp, a: u8, d: u16) -> Self {
        Self {
            op,
            a,
            b: d.to_be_bytes()[0],
            c: d.to_le_bytes()[0],
            label: None,
        }
    }

    /// Create a jump instruction with a label reference.
    #[must_use] 
    pub fn jump(op: LjOp, a: u8, label: &str) -> Self {
        Self {
            op,
            a,
            b: 0,
            c: 0,
            label: Some(label.to_string()),
        }
    }

    /// Get the D field (16-bit unsigned).
    #[must_use] 
    pub fn d(&self) -> u16 {
        (u16::from(self.b) << 8) | u16::from(self.c)
    }

    /// Get the signed D field.
    ///
    /// # Panics
    /// Panics if `D - 0x8000` is out of `i16` range (should never occur for valid bytecode).
    #[must_use]
    pub fn sd(&self) -> i16 {
        i16::try_from(i32::from(self.d()) - 0x8000i32).expect("BIAS-subtracted D fits in i16")
    }

    /// Encode to a 32-bit `LuaJIT` instruction word.
    #[must_use] 
    pub fn encode(&self) -> u32 {
        u32::from(self.op.byte())
            | (u32::from(self.a) << 8)
            | (u32::from(self.c) << 16)
            | (u32::from(self.b) << 24)
    }
}

// ---------------------------------------------------------------------------
// LabelResolver
// ---------------------------------------------------------------------------

/// Forward and backward label resolver.
#[derive(Debug, Default)]
pub struct LabelResolver {
    /// Map from label name to instruction index.
    labels: std::collections::HashMap<String, usize>,
    /// Pending forward references: (`instruction_index`, `label_name`).
    pending: Vec<(usize, String)>,
}

impl LabelResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a label at the current instruction position.
    pub fn define(&mut self, name: &str, pos: usize) {
        self.labels.insert(name.to_string(), pos);
    }

    /// Add a forward reference to be resolved later.
    pub fn add_forward_ref(&mut self, insn_idx: usize, label: &str) {
        self.pending.push((insn_idx, label.to_string()));
    }

    /// Look up a label by name.
    #[must_use] 
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.labels.get(name).copied()
    }

    /// `true` if the label is defined.
    #[must_use] 
    pub fn is_defined(&self, name: &str) -> bool {
        self.labels.contains_key(name)
    }

    /// Number of defined labels.
    #[must_use] 
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Number of unresolved forward references.
    #[must_use] 
    pub const fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Resolve all pending forward references into `insns`.
    ///
    /// Returns the number of references that could not be resolved.
    ///
    /// # Panics
    /// Panics if a label index or target index does not fit in `i32` or if a biased offset does not fit in `u16`.
    pub fn patch(&mut self, insns: &mut [AssemblerInstruction]) -> usize {
        let mut unresolved = 0;
        let pending = std::mem::take(&mut self.pending);
        for (idx, label) in pending {
            if let Some(&target) = self.labels.get(&label) {
                if idx < insns.len() {
                    // Encode jump offset as signed D (target - (idx+1))
                    let offset = i32::try_from(target).expect("target fits in i32") - (i32::try_from(idx).expect("idx fits in i32") + 1);
                    let d = u16::try_from(offset + 0x8000).expect("jump offset + BIAS fits in u16");
                    insns[idx].b = u8::try_from(d >> 8).expect("high byte fits in u8");
                    insns[idx].c = u8::try_from(d & 0xff).expect("low byte fits in u8");
                }
            } else {
                unresolved += 1;
            }
        }
        unresolved
    }
}

// ---------------------------------------------------------------------------
// RegisterAllocator
// ---------------------------------------------------------------------------

/// Liveness interval for one virtual register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveInterval {
    pub vreg: u32,
    pub start: usize,
    pub end: usize,
    /// Assigned physical slot.
    pub slot: Option<u8>,
}

impl LiveInterval {
    #[must_use] 
    pub const fn new(vreg: u32, start: usize, end: usize) -> Self {
        Self {
            vreg,
            start,
            end,
            slot: None,
        }
    }

    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Simple linear-scan register allocator.
#[derive(Debug, Default)]
pub struct RegisterAllocator {
    intervals: Vec<LiveInterval>,
    /// Number of available physical slots.
    pub slot_count: u8,
    /// Next unallocated virtual register ID.
    next_vreg: u32,
}

impl RegisterAllocator {
    /// Create an allocator with `slot_count` physical slots.
    #[must_use] 
    pub const fn new(slot_count: u8) -> Self {
        Self {
            intervals: Vec::new(),
            slot_count,
            next_vreg: 0,
        }
    }

    /// Allocate a new virtual register.
    pub const fn new_vreg(&mut self) -> u32 {
        let v = self.next_vreg;
        self.next_vreg += 1;
        v
    }

    /// Set the liveness interval for a virtual register.
    pub fn set_interval(&mut self, vreg: u32, start: usize, end: usize) {
        if let Some(iv) = self.intervals.iter_mut().find(|iv| iv.vreg == vreg) {
            iv.start = iv.start.min(start);
            iv.end = iv.end.max(end);
        } else {
            self.intervals.push(LiveInterval::new(vreg, start, end));
        }
    }

    /// Run linear scan allocation.  Assigns slots to all intervals.
    pub fn allocate(&mut self) {
        // Sort by start point
        self.intervals.sort_by_key(|iv| iv.start);
        let mut active: Vec<(usize, u8)> = Vec::new(); // (end_point, slot) for live intervals
        let mut free: Vec<u8> = (0..self.slot_count).collect();

        for iv in &mut self.intervals {
            // Expire intervals that ended before this one starts
            let mut still_active = Vec::new();
            for (end, slot) in active {
                if end <= iv.start {
                    free.push(slot);
                } else {
                    still_active.push((end, slot));
                }
            }
            active = still_active;

            if let Some(slot) = free.pop() {
                iv.slot = Some(slot);
                active.push((iv.end, slot));
            }
        }
    }

    /// Return the physical slot for a virtual register.
    #[must_use] 
    pub fn slot_for(&self, vreg: u32) -> Option<u8> {
        self.intervals
            .iter()
            .find(|iv| iv.vreg == vreg)
            .and_then(|iv| iv.slot)
    }

    /// Number of virtual registers allocated.
    #[must_use] 
    pub const fn vreg_count(&self) -> u32 {
        self.next_vreg
    }

    /// Number of intervals.
    #[must_use] 
    pub const fn interval_count(&self) -> usize {
        self.intervals.len()
    }
}

// ---------------------------------------------------------------------------
// ConstantTable
// ---------------------------------------------------------------------------

/// Kind of a constant pool entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstEntry {
    Nil,
    True,
    False,
    Integer(i32),
    Number(f64),
    String(String),
    Table,
}

/// `LuaJIT` constant pool.
#[derive(Debug, Default)]
pub struct ConstantTable {
    entries: Vec<ConstEntry>,
}

impl ConstantTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constant, returning its index.  Deduplicates strings and numbers.
    ///
    /// # Panics
    /// Panics if the constant table grows beyond `u16::MAX` entries.
    pub fn add(&mut self, entry: ConstEntry) -> u16 {
        // Deduplicate
        if let Some(pos) = self.entries.iter().position(|e| *e == entry) {
            return u16::try_from(pos).expect("constant index fits in u16");
        }
        let idx = u16::try_from(self.entries.len()).expect("constant table fits in u16");
        self.entries.push(entry);
        idx
    }

    /// Add a string constant.
    pub fn add_string(&mut self, s: &str) -> u16 {
        self.add(ConstEntry::String(s.to_string()))
    }

    /// Add a number constant.
    ///
    /// # Panics
    /// Panics if the constant table grows beyond `u16::MAX` entries.
    pub fn add_number(&mut self, n: f64) -> u16 {
        // Use bit-equality for dedup (NaN not handled)
        let bits = n.to_bits();
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| matches!(e, ConstEntry::Number(v) if v.to_bits() == bits))
        {
            return u16::try_from(pos).expect("constant index fits in u16");
        }
        self.add(ConstEntry::Number(n))
    }

    /// Add an integer constant.
    pub fn add_integer(&mut self, n: i32) -> u16 {
        self.add(ConstEntry::Integer(n))
    }

    /// Get a constant by index.
    #[must_use] 
    pub fn get(&self, idx: u16) -> Option<&ConstEntry> {
        self.entries.get(idx as usize)
    }

    /// Total number of constants.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    /// `true` if empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AssemblerOutput
// ---------------------------------------------------------------------------

/// The final assembled output: encoded instruction words + metadata.
#[derive(Debug, Default)]
pub struct AssemblerOutput {
    /// Encoded 32-bit instruction words.
    pub instructions: Vec<u32>,
    /// The constant table.
    pub constants: ConstantTable,
    /// Maximum register slot used.
    pub max_slot: u8,
    /// Number of upvalues.
    pub num_upvalues: u8,
    /// Number of parameters.
    pub num_params: u8,
}

impl AssemblerOutput {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of instructions.
    #[must_use] 
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Decode instruction `i` back to fields (op, a, c, b).
    #[must_use] 
    pub fn decode_at(&self, i: usize) -> Option<(u8, u8, u8, u8)> {
        self.instructions.get(i).map(|&w| {
            let op = (w & 0xff) as u8;
            let a = ((w >> 8) & 0xff) as u8;
            let c = ((w >> 16) & 0xff) as u8;
            let b = ((w >> 24) & 0xff) as u8;
            (op, a, c, b)
        })
    }
}

// ---------------------------------------------------------------------------
// LuaJitAssembler
// ---------------------------------------------------------------------------

/// `LuaJIT` bytecode assembler.
#[derive(Debug, Default)]
pub struct LuaJitAssembler {
    instructions: Vec<AssemblerInstruction>,
    pub labels: LabelResolver,
    pub constants: ConstantTable,
    pub registers: RegisterAllocator,
}

impl LuaJitAssembler {
    /// Create a new assembler with `slot_count` physical register slots.
    #[must_use] 
    pub fn new(slot_count: u8) -> Self {
        Self {
            instructions: Vec::new(),
            labels: LabelResolver::new(),
            constants: ConstantTable::new(),
            registers: RegisterAllocator::new(slot_count),
        }
    }

    /// Emit an instruction.
    pub fn emit(&mut self, insn: AssemblerInstruction) -> usize {
        let idx = self.instructions.len();
        if let Some(ref lbl) = insn.label.clone() {
            self.labels.add_forward_ref(idx, lbl);
        }
        self.instructions.push(insn);
        idx
    }

    /// Emit an ABC instruction.
    pub fn emit_abc(&mut self, op: LjOp, a: u8, b: u8, c: u8) -> usize {
        self.emit(AssemblerInstruction::abc(op, a, b, c))
    }

    /// Emit an AD instruction.
    pub fn emit_ad(&mut self, op: LjOp, a: u8, d: u16) -> usize {
        self.emit(AssemblerInstruction::ad(op, a, d))
    }

    /// Emit a jump to a label.
    pub fn emit_jump(&mut self, op: LjOp, a: u8, label: &str) -> usize {
        self.emit(AssemblerInstruction::jump(op, a, label))
    }

    /// Define a label at the current position.
    pub fn define_label(&mut self, name: &str) {
        let pos = self.instructions.len();
        self.labels.define(name, pos);
    }

    /// Finalize: patch all labels and encode instructions.
    #[must_use] 
    pub fn finalize(mut self) -> AssemblerOutput {
        let unresolved = self.labels.patch(&mut self.instructions);
        let _ = unresolved; // in production, this would be an error

        let mut out = AssemblerOutput::new();
        out.constants = self.constants;
        out.instructions = self.instructions.iter().map(AssemblerInstruction::encode).collect();
        out.max_slot = self.registers.slot_count;
        out
    }

    /// Number of instructions emitted so far.
    #[must_use] 
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// The current instruction index (= emit position).
    #[must_use] 
    pub const fn current_pos(&self) -> usize {
        self.instructions.len()
    }
}

// ---------------------------------------------------------------------------
// Helper for tests: a NOP-like instruction
// ---------------------------------------------------------------------------
impl LjOp {
    #[cfg(test)]
    const fn nop_like() -> Self {
        Self::KNIL
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn asm() -> LuaJitAssembler {
        LuaJitAssembler::new(16)
    }

    // ── 1. LjOp basics ──────────────────────────────────────────────────────
    #[test]
    fn test_ljop_byte() {
        assert_eq!(LjOp::ISLT.byte(), 0);
        assert_eq!(LjOp::JMP.byte(), 88);
    }

    #[test]
    fn test_ljop_is_comparison() {
        assert!(LjOp::ISLT.is_comparison());
        assert!(LjOp::ISNEP.is_comparison());
        assert!(!LjOp::MOV.is_comparison());
    }

    #[test]
    fn test_ljop_is_return() {
        assert!(LjOp::RET.is_return());
        assert!(LjOp::RET0.is_return());
        assert!(!LjOp::JMP.is_return());
    }

    #[test]
    fn test_ljop_is_jump() {
        assert!(LjOp::JMP.is_jump());
        assert!(LjOp::ISLT.is_jump());
        assert!(!LjOp::MOV.is_jump());
    }

    #[test]
    fn test_ljop_mnemonic() {
        assert_eq!(LjOp::MOV.mnemonic(), "MOV");
        assert_eq!(LjOp::CALL.mnemonic(), "CALL");
        assert_eq!(LjOp::RET0.mnemonic(), "RET0");
    }

    #[test]
    fn test_ljop_display() {
        assert_eq!(format!("{}", LjOp::KNUM), "KNUM");
    }

    // ── 2. AssemblerInstruction ──────────────────────────────────────────────
    #[test]
    fn test_asm_insn_abc() {
        let insn = AssemblerInstruction::abc(LjOp::MOV, 1, 2, 3);
        assert_eq!(insn.op, LjOp::MOV);
        assert_eq!(insn.a, 1);
        assert_eq!(insn.b, 2);
        assert_eq!(insn.c, 3);
    }

    #[test]
    fn test_asm_insn_ad() {
        let insn = AssemblerInstruction::ad(LjOp::KSHORT, 0, 1000);
        assert_eq!(insn.d(), 1000);
    }

    #[test]
    fn test_asm_insn_sd() {
        let insn = AssemblerInstruction::ad(LjOp::JMP, 0, 0x8010);
        assert_eq!(insn.sd(), 0x0010_u16.cast_signed()); // 16 as i16
    }

    #[test]
    fn test_asm_insn_encode_decode() {
        let insn = AssemblerInstruction::abc(LjOp::ADDVV, 3, 4, 5);
        let enc = insn.encode();
        // op=byte(), a=3, c=5, b=4
        assert_eq!(u8::try_from(enc & 0xff).expect("low byte fits in u8"), LjOp::ADDVV.byte());
        assert_eq!(u8::try_from((enc >> 8) & 0xff).expect("a field fits in u8"), 3); // a
        assert_eq!(u8::try_from((enc >> 16) & 0xff).expect("c field fits in u8"), 5); // c
        assert_eq!(u8::try_from((enc >> 24) & 0xff).expect("b field fits in u8"), 4); // b
    }

    #[test]
    fn test_asm_insn_jump_label() {
        let insn = AssemblerInstruction::jump(LjOp::JMP, 0, "loop");
        assert_eq!(insn.label, Some("loop".to_string()));
    }

    // ── 3. LabelResolver ────────────────────────────────────────────────────
    #[test]
    fn test_label_define_resolve() {
        let mut lr = LabelResolver::new();
        lr.define("start", 0);
        lr.define("end", 10);
        assert_eq!(lr.resolve("start"), Some(0));
        assert_eq!(lr.resolve("end"), Some(10));
        assert!(lr.resolve("missing").is_none());
    }

    #[test]
    fn test_label_is_defined() {
        let mut lr = LabelResolver::new();
        lr.define("x", 5);
        assert!(lr.is_defined("x"));
        assert!(!lr.is_defined("y"));
    }

    #[test]
    fn test_label_count() {
        let mut lr = LabelResolver::new();
        lr.define("a", 0);
        lr.define("b", 1);
        assert_eq!(lr.label_count(), 2);
    }

    #[test]
    fn test_label_pending_count() {
        let mut lr = LabelResolver::new();
        lr.add_forward_ref(0, "x");
        lr.add_forward_ref(1, "x");
        assert_eq!(lr.pending_count(), 2);
    }

    #[test]
    fn test_label_patch_resolves() {
        let mut lr = LabelResolver::new();
        lr.add_forward_ref(0, "target");
        lr.define("target", 5);
        let mut insns = vec![AssemblerInstruction::jump(LjOp::JMP, 0, "target")];
        let unresolved = lr.patch(&mut insns);
        assert_eq!(unresolved, 0);
    }

    #[test]
    fn test_label_patch_unresolved() {
        let mut lr = LabelResolver::new();
        lr.add_forward_ref(0, "missing");
        let mut insns = vec![AssemblerInstruction::jump(LjOp::JMP, 0, "missing")];
        let unresolved = lr.patch(&mut insns);
        assert_eq!(unresolved, 1);
    }

    // ── 4. RegisterAllocator ─────────────────────────────────────────────────
    #[test]
    fn test_reg_alloc_new_vreg() {
        let mut ra = RegisterAllocator::new(8);
        let v0 = ra.new_vreg();
        let v1 = ra.new_vreg();
        assert_ne!(v0, v1);
        assert_eq!(ra.vreg_count(), 2);
    }

    #[test]
    fn test_reg_alloc_set_interval() {
        let mut ra = RegisterAllocator::new(4);
        let v = ra.new_vreg();
        ra.set_interval(v, 0, 10);
        assert_eq!(ra.interval_count(), 1);
    }

    #[test]
    fn test_reg_alloc_allocate() {
        let mut ra = RegisterAllocator::new(4);
        let v = ra.new_vreg();
        ra.set_interval(v, 0, 5);
        ra.allocate();
        assert!(ra.slot_for(v).is_some());
    }

    #[test]
    fn test_live_interval_overlaps() {
        let a = LiveInterval::new(0, 0, 5);
        let b = LiveInterval::new(1, 3, 8);
        let c = LiveInterval::new(2, 5, 10);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    // ── 5. ConstantTable ─────────────────────────────────────────────────────
    #[test]
    fn test_const_table_add_string() {
        let mut ct = ConstantTable::new();
        let idx = ct.add_string("hello");
        assert_eq!(ct.count(), 1);
        assert_eq!(ct.get(idx), Some(&ConstEntry::String("hello".into())));
    }

    #[test]
    fn test_const_table_dedup_string() {
        let mut ct = ConstantTable::new();
        let i1 = ct.add_string("x");
        let i2 = ct.add_string("x");
        assert_eq!(i1, i2);
        assert_eq!(ct.count(), 1);
    }

    #[test]
    fn test_const_table_add_number() {
        let mut ct = ConstantTable::new();
        let idx = ct.add_number(std::f64::consts::PI);
        assert!(matches!(ct.get(idx), Some(ConstEntry::Number(v)) if (*v - std::f64::consts::PI).abs() < 1e-9));
    }

    #[test]
    fn test_const_table_add_integer() {
        let mut ct = ConstantTable::new();
        let idx = ct.add_integer(42);
        assert_eq!(ct.get(idx), Some(&ConstEntry::Integer(42)));
    }

    #[test]
    fn test_const_table_is_empty() {
        let ct = ConstantTable::new();
        assert!(ct.is_empty());
    }

    #[test]
    fn test_const_table_nil_true_false() {
        let mut ct = ConstantTable::new();
        ct.add(ConstEntry::Nil);
        ct.add(ConstEntry::True);
        ct.add(ConstEntry::False);
        assert_eq!(ct.count(), 3);
    }

    // ── 6. LuaJitAssembler ───────────────────────────────────────────────────
    #[test]
    fn test_assembler_emit() {
        let mut a = asm();
        let idx = a.emit_abc(LjOp::MOV, 0, 1, 0);
        assert_eq!(idx, 0);
        assert_eq!(a.instruction_count(), 1);
    }

    #[test]
    fn test_assembler_emit_ad() {
        let mut a = asm();
        a.emit_ad(LjOp::KSHORT, 0, 42);
        assert_eq!(a.instruction_count(), 1);
    }

    #[test]
    fn test_assembler_define_label() {
        let mut a = asm();
        a.emit_abc(LjOp::MOV, 0, 1, 0);
        a.define_label("start");
        assert!(a.labels.is_defined("start"));
        assert_eq!(a.labels.resolve("start"), Some(1));
    }

    #[test]
    fn test_assembler_finalize() {
        let mut a = asm();
        a.emit_abc(LjOp::MOV, 0, 1, 0);
        a.emit_ad(LjOp::RET0, 0, 1);
        let out = a.finalize();
        assert_eq!(out.instruction_count(), 2);
    }

    #[test]
    fn test_assembler_finalize_with_constant() {
        let mut a = asm();
        let ci = a.constants.add_string("hello");
        a.emit_ad(LjOp::KSTR, 0, ci);
        a.emit_ad(LjOp::RET1, 0, 2);
        let out = a.finalize();
        assert_eq!(out.constants.count(), 1);
        assert_eq!(out.instruction_count(), 2);
    }

    #[test]
    fn test_assembler_decode_at() {
        let mut a = asm();
        a.emit_abc(LjOp::ADDVV, 3, 4, 5);
        let out = a.finalize();
        let (op, av, cv, bv) = out.decode_at(0).unwrap();
        assert_eq!(op, LjOp::ADDVV.byte());
        assert_eq!(av, 3);
        assert_eq!(cv, 5);
        assert_eq!(bv, 4);
    }

    #[test]
    fn test_assembler_current_pos() {
        let mut a = asm();
        assert_eq!(a.current_pos(), 0);
        a.emit_abc(LjOp::nop_like(), 0, 0, 0);
        assert_eq!(a.current_pos(), 1);
    }

    #[test]
    fn test_assembler_jump_to_label() {
        let mut a = asm();
        a.define_label("loop");
        a.emit_abc(LjOp::MOV, 0, 1, 0);
        a.emit_jump(LjOp::JMP, 0, "loop");
        let out = a.finalize();
        assert_eq!(out.instruction_count(), 2);
    }

    // ── 7. All LjOp mnemonics non-empty ─────────────────────────────────────
    #[test]
    fn test_all_ljop_mnemonics() {
        let ops = [
            LjOp::ISLT,
            LjOp::ISGE,
            LjOp::ISLE,
            LjOp::ISGT,
            LjOp::ISEQV,
            LjOp::ISNEV,
            LjOp::MOV,
            LjOp::KSTR,
            LjOp::KNUM,
            LjOp::JMP,
            LjOp::CALL,
            LjOp::RET,
            LjOp::RET0,
            LjOp::RET1,
            LjOp::FNEW,
            LjOp::TNEW,
            LjOp::TGETS,
            LjOp::GGET,
        ];
        for op in ops {
            assert!(!op.mnemonic().is_empty(), "{op:?}");
        }
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_const_table_get_out_of_bounds() {
        let ct = ConstantTable::new();
        assert!(ct.get(0).is_none());
    }

    #[test]
    fn test_assembler_constants_shared() {
        let mut a = asm();
        let idx = a.constants.add_string("x");
        a.emit_ad(LjOp::KSTR, 0, idx);
        let out = a.finalize();
        assert_eq!(out.constants.count(), 1);
    }

    #[test]
    fn test_label_resolver_define_overwrite() {
        let mut lr = LabelResolver::new();
        lr.define("x", 0);
        lr.define("x", 5); // overwrite
        assert_eq!(lr.resolve("x"), Some(5));
        assert_eq!(lr.label_count(), 1);
    }

    #[test]
    fn test_reg_alloc_slot_for_unknown() {
        let ra = RegisterAllocator::new(4);
        assert!(ra.slot_for(9999).is_none());
    }

    #[test]
    fn test_ljop_funcc() {
        assert_eq!(LjOp::FUNCC.mnemonic(), "FUNCC");
        assert!(!LjOp::FUNCC.is_return());
        assert!(!LjOp::FUNCC.is_comparison());
    }

    #[test]
    fn test_asm_insn_jump_no_label_none() {
        let insn = AssemblerInstruction::abc(LjOp::JMP, 0, 0, 10);
        assert!(insn.label.is_none());
    }

    #[test]
    fn test_assembler_output_decode_out_of_bounds() {
        let out = AssemblerOutput::new();
        assert!(out.decode_at(0).is_none());
    }

    #[test]
    fn test_const_table_table_entry() {
        let mut ct = ConstantTable::new();
        ct.add(ConstEntry::Table);
        assert_eq!(ct.count(), 1);
    }

    #[test]
    fn test_live_interval_no_overlap_adjacent() {
        let a = LiveInterval::new(0, 0, 3);
        let b = LiveInterval::new(1, 3, 6); // adjacent but not overlapping
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn test_assembler_new_slot_count() {
        let a = LuaJitAssembler::new(32);
        assert_eq!(a.registers.slot_count, 32);
    }

    #[test]
    fn test_ljop_varg() {
        assert_eq!(LjOp::VARG.mnemonic(), "VARG");
        assert!(!LjOp::VARG.is_jump());
        assert!(!LjOp::VARG.is_return());
    }

    #[test]
    fn test_assembler_labels_pending_after_emit_jump() {
        let mut a = asm();
        a.emit_jump(LjOp::JMP, 0, "nowhere");
        assert_eq!(a.labels.pending_count(), 1);
    }
}
