//! `instruction_semantics` — Instruction semantic modeling.
//!
//! Models the side-effects of instructions: flags set, memory accesses,
//! registers defined and used.  Defines instruction categories (arithmetic,
//! logical, branch, call, ret, load, store, system) and predicate conditions
//! for ARM/x86 conditional moves and branches.
//!
//! All types are architecture-neutral; they are populated by arch backends.

use std::collections::HashSet;
use std::fmt;

// ─── FlagEffect ───────────────────────────────────────────────────────────────

/// Which flags register bits are affected by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagEffect {
    /// The flag is written (defined) by this instruction.
    Written,
    /// The flag is read (used) by this instruction.
    Read,
    /// The flag is preserved (not touched).
    Preserved,
    /// The flag is left in an undefined state.
    Undefined,
}

impl fmt::Display for FlagEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Written => write!(f, "W"),
            Self::Read => write!(f, "R"),
            Self::Preserved => write!(f, "P"),
            Self::Undefined => write!(f, "U"),
        }
    }
}

/// Effect on a single named flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagEntry {
    /// Flag name (e.g. `"CF"`, `"ZF"`, `"N"`, `"C"`).
    pub name: String,
    /// The effect.
    pub effect: FlagEffect,
}

impl FlagEntry {
    /// Create a new flag entry.
    #[must_use]
    pub fn new(name: impl Into<String>, effect: FlagEffect) -> Self {
        Self {
            name: name.into(),
            effect,
        }
    }

    /// Return `true` if this flag is written by the instruction.
    #[must_use]
    pub fn is_written(&self) -> bool {
        self.effect == FlagEffect::Written
    }

    /// Return `true` if this flag is read by the instruction.
    #[must_use]
    pub fn is_read(&self) -> bool {
        self.effect == FlagEffect::Read
    }
}

// ─── MemEffect ────────────────────────────────────────────────────────────────

/// Kind of memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemAccessKind {
    /// Read from memory.
    Read,
    /// Write to memory.
    Write,
    /// Atomic read-modify-write.
    ReadWrite,
}

impl fmt::Display for MemAccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "LD"),
            Self::Write => write!(f, "ST"),
            Self::ReadWrite => write!(f, "RMW"),
        }
    }
}

/// Description of a memory access performed by an instruction.
#[derive(Debug, Clone)]
pub struct MemEffect {
    /// Kind of access (read / write / atomic).
    pub kind: MemAccessKind,
    /// Width of the access in bytes (0 = unknown).
    pub bytes: u8,
    /// Base register (if address is register-based).
    pub base_reg: Option<String>,
    /// Index register (if present).
    pub index_reg: Option<String>,
    /// Scale factor for index (1, 2, 4, 8, …).
    pub scale: u8,
    /// Constant displacement.
    pub disp: i64,
    /// Segment prefix (x86 only; empty = default DS).
    pub segment: String,
    /// Whether the access is volatile / device I/O.
    pub volatile: bool,
}

impl MemEffect {
    /// Create a simple register-indirect access.
    #[must_use]
    pub fn register_indirect(
        kind: MemAccessKind,
        base: impl Into<String>,
        disp: i64,
        bytes: u8,
    ) -> Self {
        Self {
            kind,
            bytes,
            base_reg: Some(base.into()),
            index_reg: None,
            scale: 1,
            disp,
            segment: String::new(),
            volatile: false,
        }
    }

    /// Create an absolute memory access.
    #[must_use]
    pub const fn absolute(kind: MemAccessKind, addr: i64, bytes: u8) -> Self {
        Self {
            kind,
            bytes,
            base_reg: None,
            index_reg: None,
            scale: 1,
            disp: addr,
            segment: String::new(),
            volatile: false,
        }
    }

    /// Return `true` if this is a read.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self.kind, MemAccessKind::Read | MemAccessKind::ReadWrite)
    }

    /// Return `true` if this is a write.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(self.kind, MemAccessKind::Write | MemAccessKind::ReadWrite)
    }
}

impl fmt::Display for MemEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self.base_reg.as_deref().unwrap_or("?");
        write!(f, "{}:[{base}+{}]({} bytes)", self.kind, self.disp, self.bytes)
    }
}

// ─── InstrCategory ────────────────────────────────────────────────────────────

/// High-level instruction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstrCategory {
    /// Integer addition, subtraction, multiplication, division.
    Arithmetic,
    /// AND, OR, XOR, NOT, shifts, rotates.
    Logical,
    /// Unconditional direct branch / jump.
    Branch,
    /// Conditional branch / jump.
    ConditionalBranch,
    /// Direct or indirect call.
    Call,
    /// Return from function.
    Ret,
    /// Load from memory to register.
    Load,
    /// Store from register to memory.
    Store,
    /// Load + store (e.g., `xchg`, `cmpxchg`).
    LoadStore,
    /// Move / copy between registers or immediate to register.
    Move,
    /// Conditional move (`cmovcc`, ARM conditional instructions).
    ConditionalMove,
    /// Push to stack.
    Push,
    /// Pop from stack.
    Pop,
    /// No operation.
    Nop,
    /// Floating-point operation.
    FloatOp,
    /// SIMD/vector operation.
    SimdOp,
    /// System / privileged instruction (syscall, sysenter, HLT, etc.).
    System,
    /// Comparison (sets flags only, no output register).
    Compare,
    /// String operation (MOVS, STOS, etc.).
    StringOp,
    /// Bit manipulation (BSF, BSR, POPCNT, etc.).
    BitManip,
    /// Cryptographic (AES-NI, SHA, etc.).
    Crypto,
    /// Unknown / uncategorized.
    Unknown,
}

impl fmt::Display for InstrCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Arithmetic => "arith",
            Self::Logical => "logic",
            Self::Branch => "branch",
            Self::ConditionalBranch => "cbranch",
            Self::Call => "call",
            Self::Ret => "ret",
            Self::Load => "load",
            Self::Store => "store",
            Self::LoadStore => "load_store",
            Self::Move => "move",
            Self::ConditionalMove => "cmove",
            Self::Push => "push",
            Self::Pop => "pop",
            Self::Nop => "nop",
            Self::FloatOp => "float",
            Self::SimdOp => "simd",
            Self::System => "system",
            Self::Compare => "compare",
            Self::StringOp => "string",
            Self::BitManip => "bitmanip",
            Self::Crypto => "crypto",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ─── Predicate ────────────────────────────────────────────────────────────────

/// A predicate condition for conditional instructions (ARM / x86).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// Always execute (ARM AL condition / unconditional).
    Always,
    /// Never execute (ARM NV condition).
    Never,
    /// Equal / zero (ZF=1).
    Equal,
    /// Not equal / not zero (ZF=0).
    NotEqual,
    /// Carry set (CF=1).
    CarrySet,
    /// Carry clear (CF=0).
    CarryClear,
    /// Negative (SF=1 / N=1).
    Negative,
    /// Positive or zero (SF=0 / N=0).
    NonNegative,
    /// Overflow (OF=1 / V=1).
    Overflow,
    /// No overflow (OF=0 / V=0).
    NoOverflow,
    /// Unsigned higher (CF=0 ∧ ZF=0).
    UnsignedHigher,
    /// Unsigned lower or same (CF=1 ∨ ZF=1).
    UnsignedLowerSame,
    /// Signed greater than (ZF=0 ∧ SF=OF).
    SignedGreater,
    /// Signed less than or equal (ZF=1 ∨ SF≠OF).
    SignedLessEqual,
    /// Signed greater than or equal (SF=OF).
    SignedGreaterEqual,
    /// Signed less than (SF≠OF).
    SignedLess,
    /// Unsigned higher or same (CF=0).
    UnsignedHigherSame,
    /// Unsigned lower (CF=1).
    UnsignedLower,
    /// Parity even (PF=1).
    ParityEven,
    /// Parity odd (PF=0).
    ParityOdd,
}

impl Predicate {
    /// Return the inverse of this predicate.
    #[must_use]
    pub const fn inverse(self) -> Self {
        match self {
            Self::Always => Self::Never,
            Self::Never => Self::Always,
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::CarrySet => Self::CarryClear,
            Self::CarryClear => Self::CarrySet,
            Self::Negative => Self::NonNegative,
            Self::NonNegative => Self::Negative,
            Self::Overflow => Self::NoOverflow,
            Self::NoOverflow => Self::Overflow,
            Self::UnsignedHigher => Self::UnsignedLowerSame,
            Self::UnsignedLowerSame => Self::UnsignedHigher,
            Self::SignedGreater => Self::SignedLessEqual,
            Self::SignedLessEqual => Self::SignedGreater,
            Self::SignedGreaterEqual => Self::SignedLess,
            Self::SignedLess => Self::SignedGreaterEqual,
            Self::UnsignedHigherSame => Self::UnsignedLower,
            Self::UnsignedLower => Self::UnsignedHigherSame,
            Self::ParityEven => Self::ParityOdd,
            Self::ParityOdd => Self::ParityEven,
        }
    }

    /// Return `true` if this predicate is Always.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::Always)
    }

    /// Map from an x86 condition code suffix to a predicate.
    #[must_use]
    pub fn from_x86_suffix(suffix: &str) -> Option<Self> {
        Some(match suffix.to_lowercase().as_str() {
            "e" | "z" => Self::Equal,
            "ne" | "nz" => Self::NotEqual,
            "b" | "c" | "nae" => Self::UnsignedLower,
            "nb" | "nc" | "ae" => Self::UnsignedHigherSame,
            "be" | "na" => Self::UnsignedLowerSame,
            "nbe" | "a" => Self::UnsignedHigher,
            "s" => Self::Negative,
            "ns" => Self::NonNegative,
            "o" => Self::Overflow,
            "no" => Self::NoOverflow,
            "l" | "nge" => Self::SignedLess,
            "nl" | "ge" => Self::SignedGreaterEqual,
            "le" | "ng" => Self::SignedLessEqual,
            "nle" | "g" => Self::SignedGreater,
            "p" | "pe" => Self::ParityEven,
            "np" | "po" => Self::ParityOdd,
            _ => return None,
        })
    }

    /// Map from an ARM condition code to a predicate.
    #[must_use]
    pub fn from_arm_condition(cond: &str) -> Option<Self> {
        Some(match cond.to_uppercase().as_str() {
            "EQ" => Self::Equal,
            "NE" => Self::NotEqual,
            "CS" | "HS" => Self::CarrySet,
            "CC" | "LO" => Self::CarryClear,
            "MI" => Self::Negative,
            "PL" => Self::NonNegative,
            "VS" => Self::Overflow,
            "VC" => Self::NoOverflow,
            "HI" => Self::UnsignedHigher,
            "LS" => Self::UnsignedLowerSame,
            "GE" => Self::SignedGreaterEqual,
            "LT" => Self::SignedLess,
            "GT" => Self::SignedGreater,
            "LE" => Self::SignedLessEqual,
            "AL" => Self::Always,
            "NV" => Self::Never,
            _ => return None,
        })
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!("{self:?}").to_lowercase();
        write!(f, "{s}")
    }
}

// ─── SideEffect ───────────────────────────────────────────────────────────────

/// A single side effect of an instruction.
#[derive(Debug, Clone)]
pub enum SideEffect {
    /// The instruction defines (writes) a register.
    DefinesRegister(String),
    /// The instruction uses (reads) a register.
    UsesRegister(String),
    /// The instruction performs a memory access.
    Memory(MemEffect),
    /// The instruction sets / reads / clears flags.
    Flags(Vec<FlagEntry>),
    /// The instruction may raise an exception / fault.
    MayFault,
    /// The instruction has an implicit dependency on the program counter.
    ImplicitPc,
    /// The instruction serializes the instruction stream (fence, mfence, etc.).
    Serializing,
    /// The instruction may modify control flow (branch / call / ret).
    ControlFlow { predicate: Predicate },
}

impl fmt::Display for SideEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinesRegister(r) => write!(f, "def:{r}"),
            Self::UsesRegister(r) => write!(f, "use:{r}"),
            Self::Memory(m) => write!(f, "mem:{m}"),
            Self::Flags(flags) => {
                write!(f, "flags:[")?;
                for (i, fl) in flags.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{}={}", fl.name, fl.effect)?;
                }
                write!(f, "]")
            }
            Self::MayFault => write!(f, "may_fault"),
            Self::ImplicitPc => write!(f, "implicit_pc"),
            Self::Serializing => write!(f, "serializing"),
            Self::ControlFlow { predicate } => write!(f, "ctrl_flow({predicate})"),
        }
    }
}

// ─── InstrSemantics ───────────────────────────────────────────────────────────

/// Full semantic description of a single instruction.
#[derive(Debug, Clone)]
pub struct InstrSemantics {
    /// The canonical mnemonic (lowercase).
    pub mnemonic: String,
    /// High-level category.
    pub category: InstrCategory,
    /// All side effects.
    pub effects: Vec<SideEffect>,
    /// Execution predicate (for conditional instructions).
    pub predicate: Predicate,
    /// Number of micro-ops (approximate, for performance modeling).
    pub uop_count: u8,
    /// Latency in clock cycles (approximate).
    pub latency_cycles: u8,
    /// Whether this instruction can be speculatively executed.
    pub can_speculate: bool,
    /// Whether this is a NOP variant.
    pub is_nop: bool,
}

impl InstrSemantics {
    /// Create a new semantics descriptor.
    #[must_use]
    pub fn new(mnemonic: impl Into<String>, category: InstrCategory) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            category,
            effects: Vec::new(),
            predicate: Predicate::Always,
            uop_count: 1,
            latency_cycles: 1,
            can_speculate: true,
            is_nop: false,
        }
    }

    /// Add a side effect.
    pub fn add_effect(&mut self, effect: SideEffect) {
        self.effects.push(effect);
    }

    /// Return all registers defined (written) by this instruction.
    #[must_use]
    pub fn defined_regs(&self) -> Vec<&str> {
        self.effects
            .iter()
            .filter_map(|e| {
                if let SideEffect::DefinesRegister(r) = e {
                    Some(r.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all registers used (read) by this instruction.
    #[must_use]
    pub fn used_regs(&self) -> Vec<&str> {
        self.effects
            .iter()
            .filter_map(|e| {
                if let SideEffect::UsesRegister(r) = e {
                    Some(r.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all memory effects.
    #[must_use]
    pub fn mem_effects(&self) -> Vec<&MemEffect> {
        self.effects
            .iter()
            .filter_map(|e| {
                if let SideEffect::Memory(m) = e {
                    Some(m)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all flag effects.
    #[must_use]
    pub fn flag_effects(&self) -> Vec<&FlagEntry> {
        self.effects
            .iter()
            .flat_map(|e| {
                if let SideEffect::Flags(flags) = e {
                    flags.iter().collect::<Vec<_>>()
                } else {
                    vec![]
                }
            })
            .collect()
    }

    /// Return `true` if this instruction reads from memory.
    #[must_use]
    pub fn reads_memory(&self) -> bool {
        self.mem_effects().iter().any(|m| m.is_read())
    }

    /// Return `true` if this instruction writes to memory.
    #[must_use]
    pub fn writes_memory(&self) -> bool {
        self.mem_effects().iter().any(|m| m.is_write())
    }

    /// Return `true` if this instruction has a control-flow effect.
    #[must_use]
    pub fn has_control_flow(&self) -> bool {
        self.effects
            .iter()
            .any(|e| matches!(e, SideEffect::ControlFlow { .. }))
    }

    /// Return `true` if this instruction is conditional.
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        !self.predicate.is_unconditional()
    }

    /// Return the set of flags written by this instruction.
    #[must_use]
    pub fn written_flags(&self) -> HashSet<String> {
        self.flag_effects()
            .into_iter()
            .filter(|f| f.is_written())
            .map(|f| f.name.clone())
            .collect()
    }

    /// Return the set of flags read by this instruction.
    #[must_use]
    pub fn read_flags(&self) -> HashSet<String> {
        self.flag_effects()
            .into_iter()
            .filter(|f| f.is_read())
            .map(|f| f.name.clone())
            .collect()
    }
}

impl fmt::Display for InstrSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InstrSemantics {{ mnem={}, cat={}, predicate={}, effects={} }}",
            self.mnemonic,
            self.category,
            self.predicate,
            self.effects.len()
        )
    }
}

// ─── SemanticDatabase ─────────────────────────────────────────────────────────

/// A database of instruction semantics indexed by mnemonic.
#[derive(Debug, Default)]
pub struct SemanticDatabase {
    by_mnemonic: std::collections::HashMap<String, InstrSemantics>,
}

impl SemanticDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the database with common x86-64 instruction semantics.
    #[must_use]
    pub fn x86_64_builtins() -> Self {
        let mut db = Self::new();
        Self::x86_64_arithmetic(&mut db);
        Self::x86_64_control_flow(&mut db);
        Self::x86_64_stack_and_logic(&mut db);
        db
    }

    fn x86_64_arithmetic(db: &mut Self) {
        // ADD
        let mut add = InstrSemantics::new("add", InstrCategory::Arithmetic);
        add.add_effect(SideEffect::Flags(vec![
            FlagEntry::new("CF", FlagEffect::Written),
            FlagEntry::new("ZF", FlagEffect::Written),
            FlagEntry::new("SF", FlagEffect::Written),
            FlagEntry::new("OF", FlagEffect::Written),
            FlagEntry::new("PF", FlagEffect::Written),
            FlagEntry::new("AF", FlagEffect::Written),
        ]));
        db.insert(add);

        // SUB
        let mut sub = InstrSemantics::new("sub", InstrCategory::Arithmetic);
        sub.add_effect(SideEffect::Flags(vec![
            FlagEntry::new("CF", FlagEffect::Written),
            FlagEntry::new("ZF", FlagEffect::Written),
            FlagEntry::new("SF", FlagEffect::Written),
            FlagEntry::new("OF", FlagEffect::Written),
        ]));
        db.insert(sub);

        // MOV
        let mov = InstrSemantics::new("mov", InstrCategory::Move);
        db.insert(mov);

        // CMP
        let mut cmp = InstrSemantics::new("cmp", InstrCategory::Compare);
        cmp.add_effect(SideEffect::Flags(vec![
            FlagEntry::new("CF", FlagEffect::Written),
            FlagEntry::new("ZF", FlagEffect::Written),
            FlagEntry::new("SF", FlagEffect::Written),
            FlagEntry::new("OF", FlagEffect::Written),
        ]));
        db.insert(cmp);

        // LEA
        let lea = InstrSemantics::new("lea", InstrCategory::Arithmetic);
        db.insert(lea);

        // CMOVE / CMOVNE
        for (mnem, pred) in &[
            ("cmove", Predicate::Equal),
            ("cmovne", Predicate::NotEqual),
            ("cmovl", Predicate::SignedLess),
            ("cmovge", Predicate::SignedGreaterEqual),
        ] {
            let mut cmov = InstrSemantics::new(*mnem, InstrCategory::ConditionalMove);
            cmov.predicate = *pred;
            db.insert(cmov);
        }
    }

    fn x86_64_control_flow(db: &mut Self) {
        // JMP
        let mut jmp = InstrSemantics::new("jmp", InstrCategory::Branch);
        jmp.add_effect(SideEffect::ControlFlow {
            predicate: Predicate::Always,
        });
        jmp.can_speculate = false;
        db.insert(jmp);

        // JE / JZ
        for mnem in &["je", "jz"] {
            let mut je = InstrSemantics::new(*mnem, InstrCategory::ConditionalBranch);
            je.predicate = Predicate::Equal;
            je.add_effect(SideEffect::Flags(vec![FlagEntry::new(
                "ZF",
                FlagEffect::Read,
            )]));
            je.add_effect(SideEffect::ControlFlow {
                predicate: Predicate::Equal,
            });
            db.insert(je);
        }

        // JNE / JNZ
        for mnem in &["jne", "jnz"] {
            let mut jne = InstrSemantics::new(*mnem, InstrCategory::ConditionalBranch);
            jne.predicate = Predicate::NotEqual;
            jne.add_effect(SideEffect::Flags(vec![FlagEntry::new(
                "ZF",
                FlagEffect::Read,
            )]));
            jne.add_effect(SideEffect::ControlFlow {
                predicate: Predicate::NotEqual,
            });
            db.insert(jne);
        }

        // CALL
        let mut call = InstrSemantics::new("call", InstrCategory::Call);
        call.add_effect(SideEffect::ControlFlow {
            predicate: Predicate::Always,
        });
        call.add_effect(SideEffect::Memory(MemEffect::register_indirect(
            MemAccessKind::Write,
            "rsp",
            -8,
            8,
        )));
        call.add_effect(SideEffect::DefinesRegister("rsp".into()));
        call.can_speculate = false;
        db.insert(call);

        // RET
        let mut ret = InstrSemantics::new("ret", InstrCategory::Ret);
        ret.add_effect(SideEffect::ControlFlow {
            predicate: Predicate::Always,
        });
        ret.add_effect(SideEffect::Memory(MemEffect::register_indirect(
            MemAccessKind::Read,
            "rsp",
            0,
            8,
        )));
        ret.add_effect(SideEffect::DefinesRegister("rsp".into()));
        ret.can_speculate = false;
        db.insert(ret);

        // SYSCALL
        let mut syscall = InstrSemantics::new("syscall", InstrCategory::System);
        syscall.can_speculate = false;
        syscall.add_effect(SideEffect::Serializing);
        db.insert(syscall);
    }

    fn x86_64_stack_and_logic(db: &mut Self) {
        // PUSH
        let mut push = InstrSemantics::new("push", InstrCategory::Push);
        push.add_effect(SideEffect::Memory(MemEffect::register_indirect(
            MemAccessKind::Write,
            "rsp",
            -8,
            8,
        )));
        push.add_effect(SideEffect::DefinesRegister("rsp".into()));
        db.insert(push);

        // POP
        let mut pop = InstrSemantics::new("pop", InstrCategory::Pop);
        pop.add_effect(SideEffect::Memory(MemEffect::register_indirect(
            MemAccessKind::Read,
            "rsp",
            0,
            8,
        )));
        pop.add_effect(SideEffect::DefinesRegister("rsp".into()));
        db.insert(pop);

        // NOP
        let mut nop = InstrSemantics::new("nop", InstrCategory::Nop);
        nop.is_nop = true;
        db.insert(nop);

        // XOR (special case for zeroing: xor rax,rax)
        let mut xor = InstrSemantics::new("xor", InstrCategory::Logical);
        xor.add_effect(SideEffect::Flags(vec![
            FlagEntry::new("CF", FlagEffect::Written),
            FlagEntry::new("OF", FlagEffect::Written),
            FlagEntry::new("ZF", FlagEffect::Written),
            FlagEntry::new("SF", FlagEffect::Written),
        ]));
        db.insert(xor);

        // AND, OR
        for mnem in &["and", "or"] {
            let mut ins = InstrSemantics::new(*mnem, InstrCategory::Logical);
            ins.add_effect(SideEffect::Flags(vec![
                FlagEntry::new("CF", FlagEffect::Written),
                FlagEntry::new("OF", FlagEffect::Written),
                FlagEntry::new("ZF", FlagEffect::Written),
                FlagEntry::new("SF", FlagEffect::Written),
            ]));
            db.insert(ins);
        }
    }

    /// Insert or replace an entry.
    pub fn insert(&mut self, sem: InstrSemantics) {
        self.by_mnemonic.insert(sem.mnemonic.clone(), sem);
    }

    /// Look up semantics by mnemonic (case-insensitive).
    #[must_use]
    pub fn get(&self, mnemonic: &str) -> Option<&InstrSemantics> {
        self.by_mnemonic.get(&mnemonic.to_lowercase())
    }

    /// Return all known mnemonics.
    #[must_use]
    pub fn all_mnemonics(&self) -> Vec<&str> {
        self.by_mnemonic.keys().map(String::as_str).collect()
    }

    /// Return all instructions in a given category.
    #[must_use]
    pub fn by_category(&self, cat: InstrCategory) -> Vec<&InstrSemantics> {
        self.by_mnemonic
            .values()
            .filter(|s| s.category == cat)
            .collect()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_mnemonic.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_mnemonic.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> SemanticDatabase {
        SemanticDatabase::x86_64_builtins()
    }

    #[test]
    fn test_db_has_add() {
        let db = db();
        let sem = db.get("add").unwrap();
        assert_eq!(sem.category, InstrCategory::Arithmetic);
        let written = sem.written_flags();
        assert!(written.contains("CF"));
        assert!(written.contains("ZF"));
    }

    #[test]
    fn test_db_has_mov() {
        let db = db();
        let sem = db.get("mov").unwrap();
        assert_eq!(sem.category, InstrCategory::Move);
        assert!(!sem.is_nop);
    }

    #[test]
    fn test_db_nop() {
        let db = db();
        let sem = db.get("nop").unwrap();
        assert!(sem.is_nop);
    }

    #[test]
    fn test_db_call_writes_stack() {
        let db = db();
        let sem = db.get("call").unwrap();
        assert!(sem.writes_memory());
        assert!(!sem.can_speculate);
    }

    #[test]
    fn test_db_ret_reads_stack() {
        let db = db();
        let sem = db.get("ret").unwrap();
        assert!(sem.reads_memory());
        assert!(sem.has_control_flow());
    }

    #[test]
    fn test_predicate_inverse() {
        assert_eq!(Predicate::Equal.inverse(), Predicate::NotEqual);
        assert_eq!(Predicate::Always.inverse(), Predicate::Never);
        assert_eq!(Predicate::SignedLess.inverse(), Predicate::SignedGreaterEqual);
    }

    #[test]
    fn test_predicate_from_x86_suffix() {
        assert_eq!(Predicate::from_x86_suffix("e"), Some(Predicate::Equal));
        assert_eq!(Predicate::from_x86_suffix("ne"), Some(Predicate::NotEqual));
        assert_eq!(Predicate::from_x86_suffix("l"), Some(Predicate::SignedLess));
        assert_eq!(Predicate::from_x86_suffix("xyz"), None);
    }

    #[test]
    fn test_predicate_from_arm() {
        assert_eq!(
            Predicate::from_arm_condition("EQ"),
            Some(Predicate::Equal)
        );
        assert_eq!(
            Predicate::from_arm_condition("AL"),
            Some(Predicate::Always)
        );
        assert_eq!(Predicate::from_arm_condition("??"), None);
    }

    #[test]
    fn test_je_conditional() {
        let db = db();
        let sem = db.get("je").unwrap();
        assert!(sem.is_conditional());
        let read = sem.read_flags();
        assert!(read.contains("ZF"));
    }

    #[test]
    fn test_cmove_category() {
        let db = db();
        let sem = db.get("cmove").unwrap();
        assert_eq!(sem.category, InstrCategory::ConditionalMove);
    }

    #[test]
    fn test_by_category_branches() {
        let db = db();
        let branches = db.by_category(InstrCategory::ConditionalBranch);
        assert!(!branches.is_empty());
    }

    #[test]
    fn test_mem_effect_is_read_write() {
        let ld = MemEffect::register_indirect(MemAccessKind::Read, "rsp", 0, 8);
        assert!(ld.is_read());
        assert!(!ld.is_write());
        let st = MemEffect::absolute(MemAccessKind::Write, 0x1000, 4);
        assert!(st.is_write());
        assert!(!st.is_read());
    }

    #[test]
    fn test_instr_category_display() {
        assert_eq!(InstrCategory::Arithmetic.to_string(), "arith");
        assert_eq!(InstrCategory::System.to_string(), "system");
    }

    #[test]
    fn test_flag_entry_is_written() {
        let f = FlagEntry::new("CF", FlagEffect::Written);
        assert!(f.is_written());
        assert!(!f.is_read());
    }
}
