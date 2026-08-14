//! x86/x64 instruction metadata database.
//!
//! Provides a structured, queryable database of instruction properties used
//! throughout the lifter and analysis passes. For each mnemonic the database
//! records:
//!
//!   * **semantic category** (arithmetic, logical, control-flow, SIMD, …)
//!   * **flag semantics** — which EFLAGS are written (defined) and read
//!   * **implicit operands** — registers implicitly read or written that do
//!     not appear in the explicit operand list (e.g. `MUL` writes `RDX:RAX`)
//!   * **approximate latency tier** — rough latency bucket used by
//!     scheduling passes: Fast (1 cycle), Medium (2-5), Slow (>5), Variable
//!   * **SIMD width** — None for scalar, or the XMM/YMM/ZMM lane width
//!
//! The database is intentionally conservative: a mnemonic appears here only
//! if its entry is believed correct. Unknown/exotic mnemonics fall through to
//! `InsnInfo::unknown()`.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Semantic category
// ─────────────────────────────────────────────────────────────────────────────

/// Broad semantic category of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InsnCategory {
    DataMove,
    Arithmetic,
    Logical,
    Shift,
    ControlFlow,
    Stack,
    StringOp,
    FlagOp,
    SetCC,
    System,
    FpuX87,
    Simd,
    Bit,
    Crypto,
    Prefetch,
    Nop,
    Unknown,
}

impl fmt::Display for InsnCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag access pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Which flags an instruction touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagAccess {
    /// Flags that the instruction writes (defines a new value).
    pub written: &'static [&'static str],
    /// Flags that the instruction reads (uses the existing value).
    pub read: &'static [&'static str],
    /// Flags that become architecturally undefined after the instruction.
    pub undefined: &'static [&'static str],
}

impl FlagAccess {
    const NONE: &'static Self = &Self {
        written: &[],
        read: &[],
        undefined: &[],
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Latency tier
// ─────────────────────────────────────────────────────────────────────────────

/// Rough execution latency bucket for scheduling hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LatencyTier {
    /// Single cycle (e.g. NOP, MOV between registers).
    Fast,
    /// 2–5 cycles (e.g. ADD, logical ops, shifts).
    Medium,
    /// 6–20 cycles (e.g. IMUL 64-bit, DIV, FPU ops).
    Slow,
    /// > 20 cycles (e.g. IDIV, RDTSC, CPUID).
    VerySlow,
    /// Latency depends on operands / cache state (e.g. memory ops).
    Variable,
}

// ─────────────────────────────────────────────────────────────────────────────
// InsnInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a single mnemonic.
#[derive(Debug, Clone)]
pub struct InsnInfo {
    /// Short mnemonic string (lower-case, without operand-size suffix).
    pub mnemonic: &'static str,
    /// Semantic category.
    pub category: InsnCategory,
    /// Flag read/write semantics.
    pub flags: &'static FlagAccess,
    /// Implicit registers written (not appearing in the operand list).
    pub implicit_writes: &'static [&'static str],
    /// Implicit registers read.
    pub implicit_reads: &'static [&'static str],
    /// Execution latency tier (rough approximation; microarchitecture-neutral).
    pub latency: LatencyTier,
    /// If this instruction is a SIMD operation, the lane width in bits.
    pub simd_lane_bits: Option<u32>,
    /// `true` if the instruction has a memory operand by definition.
    pub may_access_memory: bool,
    /// `true` if the instruction is always a CFG terminator.
    pub is_terminator: bool,
}

impl InsnInfo {
    /// Placeholder for unknown mnemonics.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            mnemonic: "?",
            category: InsnCategory::Unknown,
            flags: FlagAccess::NONE,
            implicit_writes: &[],
            implicit_reads: &[],
            latency: LatencyTier::Variable,
            simd_lane_bits: None,
            may_access_memory: false,
            is_terminator: false,
        }
    }

    /// `true` if this instruction modifies any arithmetic flag.
    #[must_use]
    pub const fn modifies_flags(&self) -> bool {
        !self.flags.written.is_empty() || !self.flags.undefined.is_empty()
    }

    /// `true` if this instruction reads any flag.
    #[must_use]
    pub const fn reads_flags(&self) -> bool {
        !self.flags.read.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static flag access records
// ─────────────────────────────────────────────────────────────────────────────

static FLAGS_ARITH: FlagAccess = FlagAccess {
    written: &["cf", "pf", "af", "zf", "sf", "of"],
    read: &[],
    undefined: &[],
};

static FLAGS_LOGIC: FlagAccess = FlagAccess {
    written: &["cf", "pf", "zf", "sf", "of"],
    read: &[],
    undefined: &["af"],
};

static FLAGS_INC_DEC: FlagAccess = FlagAccess {
    written: &["pf", "af", "zf", "sf", "of"],
    read: &[],
    undefined: &[],
};

static FLAGS_SHIFT: FlagAccess = FlagAccess {
    written: &["cf", "pf", "zf", "sf", "of"],
    read: &[],
    undefined: &["af"],
};

static FLAGS_ROTATE: FlagAccess = FlagAccess {
    written: &["cf", "of"],
    read: &["cf"],
    undefined: &[],
};

static FLAGS_MUL: FlagAccess = FlagAccess {
    written: &["cf", "of"],
    read: &[],
    undefined: &["pf", "af", "zf", "sf"],
};

static FLAGS_DIV: FlagAccess = FlagAccess {
    written: &[],
    read: &[],
    undefined: &["cf", "pf", "af", "zf", "sf", "of"],
};

static FLAGS_ADC_SBB: FlagAccess = FlagAccess {
    written: &["cf", "pf", "af", "zf", "sf", "of"],
    read: &["cf"],
    undefined: &[],
};

static FLAGS_BT: FlagAccess = FlagAccess {
    written: &["cf"],
    read: &[],
    undefined: &["of", "sf", "af", "pf"],
};

static FLAGS_JCC: FlagAccess = FlagAccess {
    written: &[],
    read: &["cf", "pf", "af", "zf", "sf", "of"],
    undefined: &[],
};

static FLAGS_SETCC: FlagAccess = FlagAccess {
    written: &[],
    read: &["cf", "pf", "af", "zf", "sf", "of"],
    undefined: &[],
};

static FLAGS_NONE: FlagAccess = FlagAccess {
    written: &[],
    read: &[],
    undefined: &[],
};

static FLAGS_BSF_BSR: FlagAccess = FlagAccess {
    written: &["zf"],
    read: &[],
    undefined: &["cf", "of", "sf", "af", "pf"],
};

static FLAGS_LZCNT_TZCNT: FlagAccess = FlagAccess {
    written: &["cf", "zf"],
    read: &[],
    undefined: &["of", "sf", "af", "pf"],
};

static FLAGS_POPCNT: FlagAccess = FlagAccess {
    written: &["zf", "cf", "of", "sf", "af", "pf"],
    read: &[],
    undefined: &[],
};

// ─────────────────────────────────────────────────────────────────────────────
// The database
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! db_insn {
    ($db:expr, $mnemonic:expr, $cat:expr, $flags:expr, $impl_w:expr, $impl_r:expr, $lat:expr, $simd:expr, $mem:expr, $term:expr) => {
        $db.insert(
            $mnemonic,
            InsnInfo {
                mnemonic: $mnemonic,
                category: $cat,
                flags: $flags,
                implicit_writes: $impl_w,
                implicit_reads: $impl_r,
                latency: $lat,
                simd_lane_bits: $simd,
                may_access_memory: $mem,
                is_terminator: $term,
            },
        );
    };
}

fn populate_data_arith_logic_shift(db: &mut HashMap<&'static str, InsnInfo>) {
    use InsnCategory as C;
    use LatencyTier as L;
    // ── Data movement ────────────────────────────────────────────────────────
    db_insn!(db, "mov", C::DataMove, &FLAGS_NONE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "movzx", C::DataMove, &FLAGS_NONE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "movsx", C::DataMove, &FLAGS_NONE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "movsxd", C::DataMove, &FLAGS_NONE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "lea", C::DataMove, &FLAGS_NONE, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "xchg", C::DataMove, &FLAGS_NONE, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "cmpxchg", C::DataMove, &FLAGS_ARITH, &["rax"], &["rax"], L::Slow, None, true, false);
    db_insn!(db, "movnti", C::DataMove, &FLAGS_NONE, &[], &[], L::Medium, None, true, false);
    // ── Arithmetic ──────────────────────────────────────────────────────────
    db_insn!(db, "add", C::Arithmetic, &FLAGS_ARITH, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "adc", C::Arithmetic, &FLAGS_ADC_SBB, &[], &["cf"], L::Fast, None, true, false);
    db_insn!(db, "sub", C::Arithmetic, &FLAGS_ARITH, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "sbb", C::Arithmetic, &FLAGS_ADC_SBB, &[], &["cf"], L::Fast, None, true, false);
    db_insn!(db, "cmp", C::Arithmetic, &FLAGS_ARITH, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "inc", C::Arithmetic, &FLAGS_INC_DEC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "dec", C::Arithmetic, &FLAGS_INC_DEC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "neg", C::Arithmetic, &FLAGS_ARITH, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "mul", C::Arithmetic, &FLAGS_MUL, &["rdx", "rax"], &["rax"], L::Slow, None, true, false);
    db_insn!(db, "imul", C::Arithmetic, &FLAGS_MUL, &["rdx", "rax"], &["rax"], L::Slow, None, true, false);
    db_insn!(db, "div", C::Arithmetic, &FLAGS_DIV, &["rdx", "rax"], &["rdx", "rax"], L::VerySlow, None, true, false);
    db_insn!(db, "idiv", C::Arithmetic, &FLAGS_DIV, &["rdx", "rax"], &["rdx", "rax"], L::VerySlow, None, true, false);
    db_insn!(db, "aaa", C::Arithmetic, &FLAGS_ARITH, &["al", "ah"], &["al", "ah", "cf", "af"], L::Slow, None, false, false);
    db_insn!(db, "aas", C::Arithmetic, &FLAGS_ARITH, &["al", "ah"], &["al", "ah", "cf", "af"], L::Slow, None, false, false);
    db_insn!(db, "daa", C::Arithmetic, &FLAGS_ARITH, &["al"], &["al", "cf", "af"], L::Slow, None, false, false);
    db_insn!(db, "das", C::Arithmetic, &FLAGS_ARITH, &["al"], &["al", "cf", "af"], L::Slow, None, false, false);
    // ── Logical ─────────────────────────────────────────────────────────────
    db_insn!(db, "and", C::Logical, &FLAGS_LOGIC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "or", C::Logical, &FLAGS_LOGIC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "xor", C::Logical, &FLAGS_LOGIC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "not", C::Logical, &FLAGS_NONE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "test", C::Logical, &FLAGS_LOGIC, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "bt", C::Bit, &FLAGS_BT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "bts", C::Bit, &FLAGS_BT, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "btr", C::Bit, &FLAGS_BT, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "btc", C::Bit, &FLAGS_BT, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "andn", C::Logical, &FLAGS_LOGIC, &[], &[], L::Fast, None, true, false);
    // ── Shifts ──────────────────────────────────────────────────────────────
    db_insn!(db, "shl", C::Shift, &FLAGS_SHIFT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "sal", C::Shift, &FLAGS_SHIFT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "shr", C::Shift, &FLAGS_SHIFT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "sar", C::Shift, &FLAGS_SHIFT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "rol", C::Shift, &FLAGS_ROTATE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "ror", C::Shift, &FLAGS_ROTATE, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "rcl", C::Shift, &FLAGS_ROTATE, &[], &["cf"], L::Medium, None, true, false);
    db_insn!(db, "rcr", C::Shift, &FLAGS_ROTATE, &[], &["cf"], L::Medium, None, true, false);
    db_insn!(db, "shld", C::Shift, &FLAGS_SHIFT, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "shrd", C::Shift, &FLAGS_SHIFT, &[], &[], L::Medium, None, true, false);
}

fn populate_control_stack_strings(db: &mut HashMap<&'static str, InsnInfo>) {
    use InsnCategory as C;
    use LatencyTier as L;
    // ── Control flow ─────────────────────────────────────────────────────────
    db_insn!(db, "jmp", C::ControlFlow, &FLAGS_NONE, &[], &[], L::Fast, None, false, true);
    db_insn!(db, "je", C::ControlFlow, &FLAGS_JCC, &[], &["zf"], L::Fast, None, false, true);
    db_insn!(db, "jne", C::ControlFlow, &FLAGS_JCC, &[], &["zf"], L::Fast, None, false, true);
    db_insn!(db, "jb", C::ControlFlow, &FLAGS_JCC, &[], &["cf"], L::Fast, None, false, true);
    db_insn!(db, "jae", C::ControlFlow, &FLAGS_JCC, &[], &["cf"], L::Fast, None, false, true);
    db_insn!(db, "jbe", C::ControlFlow, &FLAGS_JCC, &[], &["cf", "zf"], L::Fast, None, false, true);
    db_insn!(db, "ja", C::ControlFlow, &FLAGS_JCC, &[], &["cf", "zf"], L::Fast, None, false, true);
    db_insn!(db, "jl", C::ControlFlow, &FLAGS_JCC, &[], &["sf", "of"], L::Fast, None, false, true);
    db_insn!(db, "jge", C::ControlFlow, &FLAGS_JCC, &[], &["sf", "of"], L::Fast, None, false, true);
    db_insn!(db, "jle", C::ControlFlow, &FLAGS_JCC, &[], &["zf", "sf", "of"], L::Fast, None, false, true);
    db_insn!(db, "jg", C::ControlFlow, &FLAGS_JCC, &[], &["zf", "sf", "of"], L::Fast, None, false, true);
    db_insn!(db, "js", C::ControlFlow, &FLAGS_JCC, &[], &["sf"], L::Fast, None, false, true);
    db_insn!(db, "jns", C::ControlFlow, &FLAGS_JCC, &[], &["sf"], L::Fast, None, false, true);
    db_insn!(db, "jo", C::ControlFlow, &FLAGS_JCC, &[], &["of"], L::Fast, None, false, true);
    db_insn!(db, "jno", C::ControlFlow, &FLAGS_JCC, &[], &["of"], L::Fast, None, false, true);
    db_insn!(db, "jp", C::ControlFlow, &FLAGS_JCC, &[], &["pf"], L::Fast, None, false, true);
    db_insn!(db, "jnp", C::ControlFlow, &FLAGS_JCC, &[], &["pf"], L::Fast, None, false, true);
    db_insn!(db, "jcxz", C::ControlFlow, &FLAGS_NONE, &[], &["rcx"], L::Fast, None, false, true);
    db_insn!(db, "jecxz", C::ControlFlow, &FLAGS_NONE, &[], &["ecx"], L::Fast, None, false, true);
    db_insn!(db, "jrcxz", C::ControlFlow, &FLAGS_NONE, &[], &["rcx"], L::Fast, None, false, true);
    db_insn!(db, "call", C::ControlFlow, &FLAGS_NONE, &["rsp"], &["rsp"], L::Medium, None, true, true);
    db_insn!(db, "ret", C::ControlFlow, &FLAGS_NONE, &["rsp"], &["rsp"], L::Medium, None, true, true);
    db_insn!(db, "iret", C::ControlFlow, &FLAGS_ARITH, &["rsp"], &["rsp"], L::Slow, None, true, true);
    db_insn!(db, "loop", C::ControlFlow, &FLAGS_NONE, &["rcx"], &["rcx"], L::Fast, None, false, true);
    db_insn!(db, "loope", C::ControlFlow, &FLAGS_JCC, &["rcx"], &["rcx", "zf"], L::Fast, None, false, true);
    db_insn!(db, "loopne", C::ControlFlow, &FLAGS_JCC, &["rcx"], &["rcx", "zf"], L::Fast, None, false, true);
    // ── Stack ────────────────────────────────────────────────────────────────
    db_insn!(db, "push", C::Stack, &FLAGS_NONE, &["rsp"], &["rsp"], L::Fast, None, true, false);
    db_insn!(db, "pop", C::Stack, &FLAGS_NONE, &["rsp"], &["rsp"], L::Fast, None, true, false);
    db_insn!(db, "pusha", C::Stack, &FLAGS_NONE, &["esp"], &["esp"], L::Slow, None, true, false);
    db_insn!(db, "popa", C::Stack, &FLAGS_NONE, &["esp"], &["esp"], L::Slow, None, true, false);
    db_insn!(db, "pushf", C::Stack, &FLAGS_NONE, &["rsp"], &["rsp"], L::Medium, None, true, false);
    db_insn!(db, "popf", C::Stack, &FLAGS_ARITH, &["rsp"], &["rsp"], L::Medium, None, true, false);
    db_insn!(db, "enter", C::Stack, &FLAGS_NONE, &["rsp", "rbp"], &["rsp", "rbp"], L::Slow, None, true, false);
    db_insn!(db, "leave", C::Stack, &FLAGS_NONE, &["rsp", "rbp"], &["rsp", "rbp"], L::Fast, None, true, false);
    // ── String ops ───────────────────────────────────────────────────────────
    db_insn!(db, "movsb", C::StringOp, &FLAGS_NONE, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "movsw", C::StringOp, &FLAGS_NONE, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "movsd", C::StringOp, &FLAGS_NONE, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "movsq", C::StringOp, &FLAGS_NONE, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "stosb", C::StringOp, &FLAGS_NONE, &["rdi"], &["rdi", "rax", "df"], L::Medium, None, true, false);
    db_insn!(db, "stosw", C::StringOp, &FLAGS_NONE, &["rdi"], &["rdi", "rax", "df"], L::Medium, None, true, false);
    db_insn!(db, "stosd", C::StringOp, &FLAGS_NONE, &["rdi"], &["rdi", "rax", "df"], L::Medium, None, true, false);
    db_insn!(db, "stosq", C::StringOp, &FLAGS_NONE, &["rdi"], &["rdi", "rax", "df"], L::Medium, None, true, false);
    db_insn!(db, "lodsb", C::StringOp, &FLAGS_NONE, &["rsi", "al"], &["rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "lodsw", C::StringOp, &FLAGS_NONE, &["rsi", "ax"], &["rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "lodsd", C::StringOp, &FLAGS_NONE, &["rsi", "eax"], &["rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "lodsq", C::StringOp, &FLAGS_NONE, &["rsi", "rax"], &["rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "cmpsb", C::StringOp, &FLAGS_ARITH, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "cmpsw", C::StringOp, &FLAGS_ARITH, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "cmpsd", C::StringOp, &FLAGS_ARITH, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "cmpsq", C::StringOp, &FLAGS_ARITH, &["rdi", "rsi"], &["rdi", "rsi", "df"], L::Medium, None, true, false);
    db_insn!(db, "scasb", C::StringOp, &FLAGS_ARITH, &["rdi"], &["rdi", "al", "df"], L::Medium, None, true, false);
    db_insn!(db, "scasw", C::StringOp, &FLAGS_ARITH, &["rdi"], &["rdi", "ax", "df"], L::Medium, None, true, false);
    db_insn!(db, "scasd", C::StringOp, &FLAGS_ARITH, &["rdi"], &["rdi", "eax", "df"], L::Medium, None, true, false);
    db_insn!(db, "scasq", C::StringOp, &FLAGS_ARITH, &["rdi"], &["rdi", "rax", "df"], L::Medium, None, true, false);
}

fn populate_flags_system_simd(db: &mut HashMap<&'static str, InsnInfo>) {
    use InsnCategory as C;
    use LatencyTier as L;
    // ── Flag operations ──────────────────────────────────────────────────────
    db_insn!(db, "clc", C::FlagOp, &FlagAccess { written: &["cf"], read: &[], undefined: &[] }, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "stc", C::FlagOp, &FlagAccess { written: &["cf"], read: &[], undefined: &[] }, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "cmc", C::FlagOp, &FlagAccess { written: &["cf"], read: &["cf"], undefined: &[] }, &[], &["cf"], L::Fast, None, false, false);
    db_insn!(db, "cld", C::FlagOp, &FlagAccess { written: &["df"], read: &[], undefined: &[] }, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "std", C::FlagOp, &FlagAccess { written: &["df"], read: &[], undefined: &[] }, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "lahf", C::FlagOp, &FlagAccess { written: &[], read: &["sf", "zf", "af", "pf", "cf"], undefined: &[] }, &["ah"], &[], L::Fast, None, false, false);
    db_insn!(db, "sahf", C::FlagOp, &FlagAccess { written: &["sf", "zf", "af", "pf", "cf"], read: &[], undefined: &[] }, &[], &["ah"], L::Fast, None, false, false);
    // ── SETcc ───────────────────────────────────────────────────────────────
    db_insn!(db, "sete", C::SetCC, &FLAGS_SETCC, &[], &["zf"], L::Fast, None, true, false);
    db_insn!(db, "setne", C::SetCC, &FLAGS_SETCC, &[], &["zf"], L::Fast, None, true, false);
    db_insn!(db, "setb", C::SetCC, &FLAGS_SETCC, &[], &["cf"], L::Fast, None, true, false);
    db_insn!(db, "setae", C::SetCC, &FLAGS_SETCC, &[], &["cf"], L::Fast, None, true, false);
    db_insn!(db, "setbe", C::SetCC, &FLAGS_SETCC, &[], &["cf", "zf"], L::Fast, None, true, false);
    db_insn!(db, "seta", C::SetCC, &FLAGS_SETCC, &[], &["cf", "zf"], L::Fast, None, true, false);
    db_insn!(db, "setl", C::SetCC, &FLAGS_SETCC, &[], &["sf", "of"], L::Fast, None, true, false);
    db_insn!(db, "setge", C::SetCC, &FLAGS_SETCC, &[], &["sf", "of"], L::Fast, None, true, false);
    db_insn!(db, "setle", C::SetCC, &FLAGS_SETCC, &[], &["zf", "sf", "of"], L::Fast, None, true, false);
    db_insn!(db, "setg", C::SetCC, &FLAGS_SETCC, &[], &["zf", "sf", "of"], L::Fast, None, true, false);
    db_insn!(db, "sets", C::SetCC, &FLAGS_SETCC, &[], &["sf"], L::Fast, None, true, false);
    db_insn!(db, "setns", C::SetCC, &FLAGS_SETCC, &[], &["sf"], L::Fast, None, true, false);
    db_insn!(db, "seto", C::SetCC, &FLAGS_SETCC, &[], &["of"], L::Fast, None, true, false);
    db_insn!(db, "setno", C::SetCC, &FLAGS_SETCC, &[], &["of"], L::Fast, None, true, false);
    db_insn!(db, "setp", C::SetCC, &FLAGS_SETCC, &[], &["pf"], L::Fast, None, true, false);
    db_insn!(db, "setnp", C::SetCC, &FLAGS_SETCC, &[], &["pf"], L::Fast, None, true, false);
    // ── System ──────────────────────────────────────────────────────────────
    db_insn!(db, "syscall", C::System, &FlagAccess { written: &["rcx", "r11"], read: &[], undefined: &[] }, &["rcx", "r11"], &["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"], L::VerySlow, None, false, false);
    db_insn!(db, "sysenter", C::System, &FLAGS_NONE, &[], &["rax", "rbx", "rcx", "rdx"], L::VerySlow, None, false, false);
    db_insn!(db, "cpuid", C::System, &FLAGS_NONE, &["eax", "ebx", "ecx", "edx"], &["eax", "ecx"], L::VerySlow, None, false, false);
    db_insn!(db, "rdtsc", C::System, &FLAGS_NONE, &["edx", "eax"], &[], L::VerySlow, None, false, false);
    db_insn!(db, "rdmsr", C::System, &FLAGS_NONE, &["edx", "eax"], &["ecx"], L::VerySlow, None, false, false);
    db_insn!(db, "wrmsr", C::System, &FLAGS_NONE, &[], &["edx", "eax", "ecx"], L::VerySlow, None, false, false);
    db_insn!(db, "hlt", C::System, &FLAGS_NONE, &[], &[], L::VerySlow, None, false, false);
    db_insn!(db, "ud2", C::System, &FLAGS_NONE, &[], &[], L::VerySlow, None, false, true);
    db_insn!(db, "nop", C::Nop, &FLAGS_NONE, &[], &[], L::Fast, None, false, false);
    // ── Bit operations ───────────────────────────────────────────────────────
    db_insn!(db, "bsf", C::Bit, &FLAGS_BSF_BSR, &[], &[], L::Slow, None, true, false);
    db_insn!(db, "bsr", C::Bit, &FLAGS_BSF_BSR, &[], &[], L::Slow, None, true, false);
    db_insn!(db, "lzcnt", C::Bit, &FLAGS_LZCNT_TZCNT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "tzcnt", C::Bit, &FLAGS_LZCNT_TZCNT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "popcnt", C::Bit, &FLAGS_POPCNT, &[], &[], L::Fast, None, true, false);
    db_insn!(db, "bswap", C::Bit, &FLAGS_NONE, &[], &[], L::Fast, None, false, false);
    db_insn!(db, "movbe", C::DataMove, &FLAGS_NONE, &[], &[], L::Medium, None, true, false);
    db_insn!(db, "crc32", C::Crypto, &FLAGS_NONE, &[], &[], L::Slow, None, true, false);
    db_insn!(db, "rdrand", C::System, &FlagAccess { written: &["cf"], read: &[], undefined: &["of", "sf", "zf", "af", "pf"] }, &[], &[], L::Slow, None, false, false);
    db_insn!(db, "rdseed", C::System, &FlagAccess { written: &["cf"], read: &[], undefined: &["of", "sf", "zf", "af", "pf"] }, &[], &[], L::Slow, None, false, false);
    // ── SIMD (representative subset) ─────────────────────────────────────────
    db_insn!(db, "movaps", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(32), true, false);
    db_insn!(db, "movapd", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(64), true, false);
    db_insn!(db, "movups", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(32), true, false);
    db_insn!(db, "movupd", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(64), true, false);
    db_insn!(db, "addps", C::Simd, &FLAGS_NONE, &[], &[], L::Medium, Some(32), true, false);
    db_insn!(db, "addpd", C::Simd, &FLAGS_NONE, &[], &[], L::Medium, Some(64), true, false);
    db_insn!(db, "subps", C::Simd, &FLAGS_NONE, &[], &[], L::Medium, Some(32), true, false);
    db_insn!(db, "subpd", C::Simd, &FLAGS_NONE, &[], &[], L::Medium, Some(64), true, false);
    db_insn!(db, "mulps", C::Simd, &FLAGS_NONE, &[], &[], L::Slow, Some(32), true, false);
    db_insn!(db, "mulpd", C::Simd, &FLAGS_NONE, &[], &[], L::Slow, Some(64), true, false);
    db_insn!(db, "andps", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(32), true, false);
    db_insn!(db, "xorps", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(32), true, false);
    db_insn!(db, "xorpd", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(64), true, false);
    db_insn!(db, "ucomiss", C::Simd, &FlagAccess { written: &["zf", "pf", "cf"], read: &[], undefined: &["of", "sf", "af"] }, &[], &[], L::Medium, Some(32), true, false);
    db_insn!(db, "ucomisd", C::Simd, &FlagAccess { written: &["zf", "pf", "cf"], read: &[], undefined: &["of", "sf", "af"] }, &[], &[], L::Medium, Some(64), true, false);
    db_insn!(db, "vzeroupper", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(256), false, false);
    db_insn!(db, "vzeroall", C::Simd, &FLAGS_NONE, &[], &[], L::Fast, Some(512), false, false);
    // ── Prefetch ─────────────────────────────────────────────────────────────
    db_insn!(db, "prefetcht0", C::Prefetch, &FLAGS_NONE, &[], &[], L::Variable, None, true, false);
    db_insn!(db, "prefetcht1", C::Prefetch, &FLAGS_NONE, &[], &[], L::Variable, None, true, false);
    db_insn!(db, "prefetcht2", C::Prefetch, &FLAGS_NONE, &[], &[], L::Variable, None, true, false);
    db_insn!(db, "prefetchnta", C::Prefetch, &FLAGS_NONE, &[], &[], L::Variable, None, true, false);
}

fn build_database() -> HashMap<&'static str, InsnInfo> {
    let mut db: HashMap<&'static str, InsnInfo> = HashMap::with_capacity(256);
    populate_data_arith_logic_shift(&mut db);
    populate_control_stack_strings(&mut db);
    populate_flags_system_simd(&mut db);
    db
}

// ─────────────────────────────────────────────────────────────────────────────
// InsnDb
// ─────────────────────────────────────────────────────────────────────────────

/// The instruction metadata database.
pub struct InsnDb {
    db: HashMap<&'static str, InsnInfo>,
}

impl InsnDb {
    /// Build and return the singleton-style database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: build_database(),
        }
    }

    /// Look up an instruction by mnemonic (lower-case).
    /// Returns `InsnInfo::unknown()` for unrecognised mnemonics.
    #[must_use]
    pub fn get(&self, mnemonic: &str) -> &InsnInfo {
        self.db.get(mnemonic).unwrap_or_else(|| {
            // SAFETY: This is intentionally returning a reference to a
            // stack-local InsnInfo. To avoid lifetime issues we return a
            // reference to a static sentinel instead.
            static UNKNOWN: std::sync::OnceLock<InsnInfo> = std::sync::OnceLock::new();
            UNKNOWN.get_or_init(InsnInfo::unknown)
        })
    }

    /// All mnemonic strings in the database, sorted.
    #[must_use]
    pub fn all_mnemonics(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.db.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// All instructions in a given category.
    #[must_use]
    pub fn by_category(&self, cat: InsnCategory) -> Vec<&InsnInfo> {
        self.db.values().filter(|i| i.category == cat).collect()
    }

    /// All instructions that write the given flag.
    #[must_use]
    pub fn writers_of_flag(&self, flag: &str) -> Vec<&InsnInfo> {
        self.db
            .values()
            .filter(|i| i.flags.written.contains(&flag))
            .collect()
    }

    /// All instructions that read the given flag.
    #[must_use]
    pub fn readers_of_flag(&self, flag: &str) -> Vec<&InsnInfo> {
        self.db
            .values()
            .filter(|i| i.flags.read.contains(&flag))
            .collect()
    }

    /// Number of entries in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.db.len()
    }

    /// `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }
}

impl Default for InsnDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> &'static InsnDb {
        use std::sync::OnceLock;
        static DB: OnceLock<InsnDb> = OnceLock::new();
        DB.get_or_init(InsnDb::new)
    }

    #[test]
    fn db_not_empty() {
        assert!(!db().is_empty());
    }

    #[test]
    fn db_known_mnemonic_mov() {
        let i = db().get("mov");
        assert_eq!(i.category, InsnCategory::DataMove);
        assert_eq!(i.latency, LatencyTier::Fast);
    }

    #[test]
    fn db_unknown_mnemonic_returns_unknown() {
        let i = db().get("nonexistent_insn");
        assert_eq!(i.category, InsnCategory::Unknown);
    }

    #[test]
    fn db_add_writes_all_flags() {
        let i = db().get("add");
        for f in ["cf", "pf", "af", "zf", "sf", "of"] {
            assert!(i.flags.written.contains(&f), "add should write {f}");
        }
    }

    #[test]
    fn db_add_is_arithmetic() {
        assert_eq!(db().get("add").category, InsnCategory::Arithmetic);
    }

    #[test]
    fn db_jmp_is_terminator() {
        assert!(db().get("jmp").is_terminator);
    }

    #[test]
    fn db_nop_not_terminator() {
        assert!(!db().get("nop").is_terminator);
    }

    #[test]
    fn db_mul_has_implicit_writes() {
        let i = db().get("mul");
        assert!(i.implicit_writes.contains(&"rdx") || i.implicit_writes.contains(&"rax"));
    }

    #[test]
    fn db_adc_reads_cf() {
        let i = db().get("adc");
        assert!(i.flags.read.contains(&"cf"));
    }

    #[test]
    fn db_inc_preserves_cf() {
        let i = db().get("inc");
        // CF not in written (INC does not change CF).
        assert!(!i.flags.written.contains(&"cf"), "inc must not write cf");
    }

    #[test]
    fn db_writers_of_zf_includes_add() {
        
        assert!(db()
            .writers_of_flag("zf")
            .iter()
            .map(|i| i.mnemonic).any(|x| x == "add"), "add should write zf");
    }

    #[test]
    fn db_readers_of_cf_includes_adc() {
        
        assert!(db()
            .readers_of_flag("cf")
            .iter()
            .map(|i| i.mnemonic).any(|x| x == "adc"), "adc should read cf");
    }

    #[test]
    fn db_by_category_simd_not_empty() {
        assert!(!db().by_category(InsnCategory::Simd).is_empty());
    }

    #[test]
    fn db_by_category_nop() {
        let nops = db().by_category(InsnCategory::Nop);
        assert!(!nops.is_empty());
        assert_eq!(nops[0].mnemonic, "nop");
    }

    #[test]
    fn db_all_mnemonics_sorted() {
        let mnems = db().all_mnemonics();
        let mut sorted = mnems.clone();
        sorted.sort_unstable();
        assert_eq!(mnems, sorted);
    }

    #[test]
    fn db_syscall_is_very_slow() {
        assert_eq!(db().get("syscall").latency, LatencyTier::VerySlow);
    }

    #[test]
    fn db_movaps_is_simd() {
        let i = db().get("movaps");
        assert_eq!(i.category, InsnCategory::Simd);
        assert_eq!(i.simd_lane_bits, Some(32));
    }

    #[test]
    fn db_not_modifies_no_flags_nop() {
        assert!(!db().get("nop").modifies_flags());
    }

    #[test]
    fn db_not_reads_flags_nop() {
        assert!(!db().get("nop").reads_flags());
    }

    #[test]
    fn db_je_reads_flags() {
        assert!(db().get("je").reads_flags());
    }

    #[test]
    fn db_call_accesses_memory() {
        assert!(db().get("call").may_access_memory);
    }

    #[test]
    fn db_lea_no_memory() {
        assert!(!db().get("lea").may_access_memory);
    }

    #[test]
    fn db_bsf_zf_undefined_side_effects() {
        let i = db().get("bsf");
        assert!(i.flags.undefined.contains(&"cf"));
    }

    #[test]
    fn db_cpuid_implicit_writes() {
        let i = db().get("cpuid");
        assert!(i.implicit_writes.contains(&"eax"));
        assert!(i.implicit_writes.contains(&"ebx"));
    }
}
