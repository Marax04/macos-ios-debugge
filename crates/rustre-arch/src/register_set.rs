//! Register-set abstractions for all supported architectures.
//!
//! This module defines the [`RegisterSet`] trait and provides concrete
//! implementations for x86-64, `AArch64` (Arm64), MIPS-32, and RISC-V 64.
//! A [`RegisterSetRegistry`] allows discovery at runtime by architecture name.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// RegId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque, architecture-specific register identifier.
///
/// Values are architecture-scoped: `RegId(0)` on x86-64 is not the same
/// register as `RegId(0)` on `AArch64`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RegId(pub u32);

/// Interns a string, returning a `&'static str`. Repeated calls with the same
/// content return the same leaked allocation, so memory use is bounded by the
/// set of distinct strings rather than the number of deserializations.
///
/// A hard cap of 65 536 unique interned strings is enforced to prevent
/// unbounded memory growth when deserializing attacker-controlled data that
/// supplies an arbitrary number of distinct register names.
fn intern_str(s: String) -> &'static str {
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Maximum number of distinct strings that may be interned.  Legitimate
    /// use (register names across all supported ISAs) stays well below 1 000.
    const MAX_INTERNED: usize = 65_536;

    static INTERNED: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);

    let mut guard = INTERNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let leaked = {
        let set = guard.get_or_insert_with(HashSet::new);
        if let Some(existing) = set.get(s.as_str()) {
            return existing;
        }
        // Refuse to intern more strings once the cap is reached; callers fall back
        // to returning the non-static string through a different code path, but
        // since this function must return `&'static str` we return an empty string
        // sentinel.  The cap is generous enough that legitimate data never hits it.
        if set.len() >= MAX_INTERNED {
            return "";
        }
        let leaked: &'static str = Box::leak(s.into_boxed_str());
        set.insert(leaked);
        leaked
    };
    drop(guard);
    leaked
}

/// Serde helper for `&'static str` fields: deserializes by interning the string.
pub mod serde_static_str {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize the string.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying serializer.
    pub fn serialize<S: Serializer>(s: &&'static str, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(s)
    }

    /// Deserialize a string and intern it to obtain a `&'static str`.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying deserializer.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<&'static str, D::Error> {
        let s: String = String::deserialize(de)?;
        Ok(super::intern_str(s))
    }
}

/// Serde helper for `&'static [&'static str]` fields: deserializes by leaking boxed slices.
pub mod serde_static_str_slice {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    /// Serialize the slice of strings as a sequence.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying serializer.
    pub fn serialize<S: Serializer>(
        s: &&'static [&'static str],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(s.len()))?;
        for item in *s {
            seq.serialize_element(item)?;
        }
        seq.end()
    }

    /// Deserialize a sequence of strings and intern it to obtain static slices.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying deserializer.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<&'static [&'static str], D::Error> {
        use std::collections::HashSet;
        use std::sync::Mutex;

        /// Hard cap on the total number of distinct leaked slices.
        const MAX_INTERNED_SLICES: usize = 65_536;

        static INTERNED: Mutex<Option<HashSet<&'static [&'static str]>>> = Mutex::new(None);

        let items: Vec<String> = Vec::deserialize(de)?;
        let interned: Vec<&'static str> = items.into_iter().map(super::intern_str).collect();

        let mut guard = INTERNED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let leaked = {
            let set = guard.get_or_insert_with(HashSet::new);
            if let Some(existing) = set.get(interned.as_slice()) {
                return Ok(existing);
            }
            // Enforce the cap to prevent unbounded heap growth from attacker-
            // controlled deserialized data.  When the cap is reached, drop the
            // candidate vec without leaking it, and return a static empty slice
            // as a safe sentinel.  Leaking a new allocation on every call beyond
            // the cap would silently accumulate unbounded memory.
            if set.len() >= MAX_INTERNED_SLICES {
                drop(interned);
                return Ok(&[]);
            }
            let leaked: &'static [&'static str] = Box::leak(interned.into_boxed_slice());
            set.insert(leaked);
            leaked
        };
        drop(guard);
        Ok(leaked)
    }
}

impl fmt::Display for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reg#{}", self.0)
    }
}

impl From<u32> for RegId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterCategory
// ─────────────────────────────────────────────────────────────────────────────

/// High-level classification of a processor register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RegisterCategory {
    /// General-purpose integer registers (RAX, RBX, X0, …).
    General,
    /// Floating-point scalar registers (ST0–ST7, F0–F31, …).
    Float,
    /// SIMD / vector registers (XMM, YMM, ZMM, V0–V31, …).
    Vector,
    /// Control / status registers (RFLAGS, CPSR, MSTATUS, …).
    Control,
    /// Debug registers (DR0–DR7, …).
    Debug,
    /// Segment registers (CS, DS, FS, GS, …).
    Segment,
    /// Special-purpose (SP, PC/RIP, LR, RA, …).
    Special,
}

impl fmt::Display for RegisterCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::General => "general",
            Self::Float => "float",
            Self::Vector => "vector",
            Self::Control => "control",
            Self::Debug => "debug",
            Self::Segment => "segment",
            Self::Special => "special",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Full metadata for a single register.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisterDescriptor {
    /// Canonical name (lower-case, e.g. `"rax"`, `"x0"`, `"v0"`, `"f0"`).
    #[serde(with = "serde_static_str")]
    pub name: &'static str,
    /// Alternative names / aliases (e.g. `["eax", "ax", "al", "ah"]` for RAX).
    #[serde(with = "serde_static_str_slice")]
    pub aliases: &'static [&'static str],
    /// Width in bits.
    pub width: u16,
    /// Architecture-local register identifier.
    pub id: RegId,
    /// Register category.
    pub category: RegisterCategory,
    /// Dwarf register number (if defined for this architecture).
    pub dwarf_num: Option<u16>,
    /// Whether the register is callee-saved in the default calling convention.
    pub callee_saved: bool,
    /// Special role this register plays (stack pointer, program counter, …).
    pub role: RegisterRole,
}

/// Special role a register plays in the architecture, if any.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RegisterRole {
    /// No special role.
    #[default]
    None,
    /// Holds the return address.
    ReturnAddress,
    /// The stack pointer.
    StackPointer,
    /// The frame/base pointer.
    FramePointer,
    /// The program counter.
    ProgramCounter,
}

impl RegisterDescriptor {
    /// Returns `true` if the given string matches the canonical name or any alias.
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        let lo = name.to_lowercase();
        if self.name == lo.as_str() {
            return true;
        }
        self.aliases.contains(&lo.as_str())
    }

    /// Whether this register holds the return address.
    #[must_use]
    pub fn is_return_address(&self) -> bool {
        self.role == RegisterRole::ReturnAddress
    }

    /// Whether this register is the stack pointer.
    #[must_use]
    pub fn is_stack_pointer(&self) -> bool {
        self.role == RegisterRole::StackPointer
    }

    /// Whether this register is the frame/base pointer.
    #[must_use]
    pub fn is_frame_pointer(&self) -> bool {
        self.role == RegisterRole::FramePointer
    }

    /// Whether this is the program counter.
    #[must_use]
    pub fn is_program_counter(&self) -> bool {
        self.role == RegisterRole::ProgramCounter
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterSet trait
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture register-set interface.
pub trait RegisterSet: Send + Sync + fmt::Debug {
    /// Architecture identifier string (e.g. `"x86_64"`).
    fn arch_name(&self) -> &'static str;

    /// All registers in this set.
    fn registers(&self) -> &[RegisterDescriptor];

    /// Look up a register by its [`RegId`].
    fn by_id(&self, id: RegId) -> Option<&RegisterDescriptor> {
        self.registers().iter().find(|r| r.id == id)
    }

    /// Look up a register by canonical name or alias (case-insensitive).
    fn by_name(&self, name: &str) -> Option<&RegisterDescriptor> {
        self.registers().iter().find(|r| r.matches_name(name))
    }

    /// All registers in the given category.
    fn by_category(&self, cat: RegisterCategory) -> Vec<&RegisterDescriptor> {
        self.registers()
            .iter()
            .filter(|r| r.category == cat)
            .collect()
    }

    /// General-purpose registers (convenience).
    fn gpr(&self) -> Vec<&RegisterDescriptor> {
        self.by_category(RegisterCategory::General)
    }

    /// The stack pointer descriptor.
    fn stack_pointer(&self) -> Option<&RegisterDescriptor> {
        self.registers().iter().find(|r| r.is_stack_pointer())
    }

    /// The frame pointer descriptor.
    fn frame_pointer(&self) -> Option<&RegisterDescriptor> {
        self.registers().iter().find(|r| r.is_frame_pointer())
    }

    /// The program counter descriptor.
    fn program_counter(&self) -> Option<&RegisterDescriptor> {
        self.registers().iter().find(|r| r.is_program_counter())
    }

    /// All callee-saved registers.
    fn callee_saved(&self) -> Vec<&RegisterDescriptor> {
        self.registers().iter().filter(|r| r.callee_saved).collect()
    }

    /// Number of bits in a pointer for this architecture.
    fn pointer_width_bits(&self) -> u16;

    /// Returns true if a register overlaps with another (e.g. `rax`/`eax`/`ax`).
    fn overlaps(&self, a: RegId, b: RegId) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// x86-64
// ─────────────────────────────────────────────────────────────────────────────

/// x86-64 register set.
#[derive(Debug, Default)]
pub struct RegisterSetX86_64;

static X86_64_REGS: &[RegisterDescriptor] = &[
    // --- General purpose (64-bit) ---
    RegisterDescriptor {
        name: "rax",
        aliases: &["eax", "ax", "al", "ah"],
        width: 64,
        id: RegId(0),
        category: RegisterCategory::General,
        dwarf_num: Some(0),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rbx",
        aliases: &["ebx", "bx", "bl", "bh"],
        width: 64,
        id: RegId(1),
        category: RegisterCategory::General,
        dwarf_num: Some(3),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rcx",
        aliases: &["ecx", "cx", "cl", "ch"],
        width: 64,
        id: RegId(2),
        category: RegisterCategory::General,
        dwarf_num: Some(2),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rdx",
        aliases: &["edx", "dx", "dl", "dh"],
        width: 64,
        id: RegId(3),
        category: RegisterCategory::General,
        dwarf_num: Some(1),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rsi",
        aliases: &["esi", "si", "sil"],
        width: 64,
        id: RegId(4),
        category: RegisterCategory::General,
        dwarf_num: Some(4),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rdi",
        aliases: &["edi", "di", "dil"],
        width: 64,
        id: RegId(5),
        category: RegisterCategory::General,
        dwarf_num: Some(5),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "rsp",
        aliases: &["esp", "sp", "spl"],
        width: 64,
        id: RegId(6),
        category: RegisterCategory::Special,
        dwarf_num: Some(7),
        callee_saved: true,
        role: RegisterRole::StackPointer,
    },
    RegisterDescriptor {
        name: "rbp",
        aliases: &["ebp", "bp", "bpl"],
        width: 64,
        id: RegId(7),
        category: RegisterCategory::Special,
        dwarf_num: Some(6),
        callee_saved: true,
        role: RegisterRole::FramePointer,
    },
    RegisterDescriptor {
        name: "r8",
        aliases: &["r8d", "r8w", "r8b"],
        width: 64,
        id: RegId(8),
        category: RegisterCategory::General,
        dwarf_num: Some(8),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r9",
        aliases: &["r9d", "r9w", "r9b"],
        width: 64,
        id: RegId(9),
        category: RegisterCategory::General,
        dwarf_num: Some(9),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r10",
        aliases: &["r10d", "r10w", "r10b"],
        width: 64,
        id: RegId(10),
        category: RegisterCategory::General,
        dwarf_num: Some(10),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r11",
        aliases: &["r11d", "r11w", "r11b"],
        width: 64,
        id: RegId(11),
        category: RegisterCategory::General,
        dwarf_num: Some(11),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r12",
        aliases: &["r12d", "r12w", "r12b"],
        width: 64,
        id: RegId(12),
        category: RegisterCategory::General,
        dwarf_num: Some(12),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r13",
        aliases: &["r13d", "r13w", "r13b"],
        width: 64,
        id: RegId(13),
        category: RegisterCategory::General,
        dwarf_num: Some(13),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r14",
        aliases: &["r14d", "r14w", "r14b"],
        width: 64,
        id: RegId(14),
        category: RegisterCategory::General,
        dwarf_num: Some(14),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "r15",
        aliases: &["r15d", "r15w", "r15b"],
        width: 64,
        id: RegId(15),
        category: RegisterCategory::General,
        dwarf_num: Some(15),
        callee_saved: true,
        role: RegisterRole::None,
    },
    // --- Instruction pointer ---
    RegisterDescriptor {
        name: "rip",
        aliases: &["eip", "ip"],
        width: 64,
        id: RegId(16),
        category: RegisterCategory::Special,
        dwarf_num: Some(16),
        callee_saved: false,
        role: RegisterRole::ProgramCounter,
    },
    // --- Flags ---
    RegisterDescriptor {
        name: "rflags",
        aliases: &["eflags", "flags"],
        width: 64,
        id: RegId(17),
        category: RegisterCategory::Control,
        dwarf_num: Some(49),
        callee_saved: false,
        role: RegisterRole::None,
    },
    // --- Segment registers ---
    RegisterDescriptor {
        name: "cs",
        aliases: &[],
        width: 16,
        id: RegId(18),
        category: RegisterCategory::Segment,
        dwarf_num: Some(43),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "ds",
        aliases: &[],
        width: 16,
        id: RegId(19),
        category: RegisterCategory::Segment,
        dwarf_num: Some(46),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "es",
        aliases: &[],
        width: 16,
        id: RegId(20),
        category: RegisterCategory::Segment,
        dwarf_num: Some(40),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "fs",
        aliases: &[],
        width: 16,
        id: RegId(21),
        category: RegisterCategory::Segment,
        dwarf_num: Some(54),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "gs",
        aliases: &[],
        width: 16,
        id: RegId(22),
        category: RegisterCategory::Segment,
        dwarf_num: Some(55),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "ss",
        aliases: &[],
        width: 16,
        id: RegId(23),
        category: RegisterCategory::Segment,
        dwarf_num: Some(52),
        callee_saved: false,
        role: RegisterRole::None,
    },
    // --- Debug registers ---
    RegisterDescriptor {
        name: "dr0",
        aliases: &[],
        width: 64,
        id: RegId(24),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "dr1",
        aliases: &[],
        width: 64,
        id: RegId(25),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "dr2",
        aliases: &[],
        width: 64,
        id: RegId(26),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "dr3",
        aliases: &[],
        width: 64,
        id: RegId(27),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "dr6",
        aliases: &[],
        width: 64,
        id: RegId(28),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "dr7",
        aliases: &[],
        width: 64,
        id: RegId(29),
        category: RegisterCategory::Debug,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::None,
    },
    // --- XMM registers (0-15) ---
    RegisterDescriptor {
        name: "xmm0",
        aliases: &["ymm0", "zmm0"],
        width: 128,
        id: RegId(40),
        category: RegisterCategory::Vector,
        dwarf_num: Some(17),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm1",
        aliases: &["ymm1", "zmm1"],
        width: 128,
        id: RegId(41),
        category: RegisterCategory::Vector,
        dwarf_num: Some(18),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm2",
        aliases: &["ymm2", "zmm2"],
        width: 128,
        id: RegId(42),
        category: RegisterCategory::Vector,
        dwarf_num: Some(19),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm3",
        aliases: &["ymm3", "zmm3"],
        width: 128,
        id: RegId(43),
        category: RegisterCategory::Vector,
        dwarf_num: Some(20),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm4",
        aliases: &["ymm4", "zmm4"],
        width: 128,
        id: RegId(44),
        category: RegisterCategory::Vector,
        dwarf_num: Some(21),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm5",
        aliases: &["ymm5", "zmm5"],
        width: 128,
        id: RegId(45),
        category: RegisterCategory::Vector,
        dwarf_num: Some(22),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm6",
        aliases: &["ymm6", "zmm6"],
        width: 128,
        id: RegId(46),
        category: RegisterCategory::Vector,
        dwarf_num: Some(23),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "xmm7",
        aliases: &["ymm7", "zmm7"],
        width: 128,
        id: RegId(47),
        category: RegisterCategory::Vector,
        dwarf_num: Some(24),
        callee_saved: false,
        role: RegisterRole::None,
    },
];

impl RegisterSet for RegisterSetX86_64 {
    fn arch_name(&self) -> &'static str {
        "x86_64"
    }
    fn registers(&self) -> &[RegisterDescriptor] {
        X86_64_REGS
    }
    fn pointer_width_bits(&self) -> u16 {
        64
    }

    fn overlaps(&self, a: RegId, b: RegId) -> bool {
        // Overlap groups: {rax=0, rbx=1, rcx=2, rdx=3, rsi=4, rdi=5} and their sub-regs
        // For simplicity: a and b overlap if they share the same group (base id).
        // The aliases table handles name-level overlap; here we track structural overlap.
        const GROUPS: &[(u32, &[u32])] = &[
            (0, &[0]), // rax family
            (1, &[1]), // rbx family
            (2, &[2]), // rcx family
            (3, &[3]), // rdx family
            (4, &[4]), // rsi family
            (5, &[5]), // rdi family
            (6, &[6]), // rsp family
            (7, &[7]), // rbp family
        ];
        if a == b {
            return true;
        }
        for (_, group) in GROUPS {
            if group.contains(&a.0) && group.contains(&b.0) {
                return true;
            }
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AArch64
// ─────────────────────────────────────────────────────────────────────────────

/// `AArch64` (Arm64) register set.
#[derive(Debug, Default)]
pub struct RegisterSetArm64;

static ARM64_REGS: &[RegisterDescriptor] = &[
    RegisterDescriptor {
        name: "x0",
        aliases: &["w0"],
        width: 64,
        id: RegId(0),
        category: RegisterCategory::General,
        dwarf_num: Some(0),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x1",
        aliases: &["w1"],
        width: 64,
        id: RegId(1),
        category: RegisterCategory::General,
        dwarf_num: Some(1),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x2",
        aliases: &["w2"],
        width: 64,
        id: RegId(2),
        category: RegisterCategory::General,
        dwarf_num: Some(2),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x3",
        aliases: &["w3"],
        width: 64,
        id: RegId(3),
        category: RegisterCategory::General,
        dwarf_num: Some(3),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x4",
        aliases: &["w4"],
        width: 64,
        id: RegId(4),
        category: RegisterCategory::General,
        dwarf_num: Some(4),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x5",
        aliases: &["w5"],
        width: 64,
        id: RegId(5),
        category: RegisterCategory::General,
        dwarf_num: Some(5),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x6",
        aliases: &["w6"],
        width: 64,
        id: RegId(6),
        category: RegisterCategory::General,
        dwarf_num: Some(6),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x7",
        aliases: &["w7"],
        width: 64,
        id: RegId(7),
        category: RegisterCategory::General,
        dwarf_num: Some(7),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x8",
        aliases: &["w8"],
        width: 64,
        id: RegId(8),
        category: RegisterCategory::General,
        dwarf_num: Some(8),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x9",
        aliases: &["w9"],
        width: 64,
        id: RegId(9),
        category: RegisterCategory::General,
        dwarf_num: Some(9),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x10",
        aliases: &["w10"],
        width: 64,
        id: RegId(10),
        category: RegisterCategory::General,
        dwarf_num: Some(10),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x11",
        aliases: &["w11"],
        width: 64,
        id: RegId(11),
        category: RegisterCategory::General,
        dwarf_num: Some(11),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x12",
        aliases: &["w12"],
        width: 64,
        id: RegId(12),
        category: RegisterCategory::General,
        dwarf_num: Some(12),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x13",
        aliases: &["w13"],
        width: 64,
        id: RegId(13),
        category: RegisterCategory::General,
        dwarf_num: Some(13),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x14",
        aliases: &["w14"],
        width: 64,
        id: RegId(14),
        category: RegisterCategory::General,
        dwarf_num: Some(14),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x15",
        aliases: &["w15"],
        width: 64,
        id: RegId(15),
        category: RegisterCategory::General,
        dwarf_num: Some(15),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x16",
        aliases: &["w16", "ip0"],
        width: 64,
        id: RegId(16),
        category: RegisterCategory::General,
        dwarf_num: Some(16),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x17",
        aliases: &["w17", "ip1"],
        width: 64,
        id: RegId(17),
        category: RegisterCategory::General,
        dwarf_num: Some(17),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x18",
        aliases: &["w18"],
        width: 64,
        id: RegId(18),
        category: RegisterCategory::General,
        dwarf_num: Some(18),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x19",
        aliases: &["w19"],
        width: 64,
        id: RegId(19),
        category: RegisterCategory::General,
        dwarf_num: Some(19),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x20",
        aliases: &["w20"],
        width: 64,
        id: RegId(20),
        category: RegisterCategory::General,
        dwarf_num: Some(20),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x21",
        aliases: &["w21"],
        width: 64,
        id: RegId(21),
        category: RegisterCategory::General,
        dwarf_num: Some(21),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x22",
        aliases: &["w22"],
        width: 64,
        id: RegId(22),
        category: RegisterCategory::General,
        dwarf_num: Some(22),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x23",
        aliases: &["w23"],
        width: 64,
        id: RegId(23),
        category: RegisterCategory::General,
        dwarf_num: Some(23),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x24",
        aliases: &["w24"],
        width: 64,
        id: RegId(24),
        category: RegisterCategory::General,
        dwarf_num: Some(24),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x25",
        aliases: &["w25"],
        width: 64,
        id: RegId(25),
        category: RegisterCategory::General,
        dwarf_num: Some(25),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x26",
        aliases: &["w26"],
        width: 64,
        id: RegId(26),
        category: RegisterCategory::General,
        dwarf_num: Some(26),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x27",
        aliases: &["w27"],
        width: 64,
        id: RegId(27),
        category: RegisterCategory::General,
        dwarf_num: Some(27),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x28",
        aliases: &["w28"],
        width: 64,
        id: RegId(28),
        category: RegisterCategory::General,
        dwarf_num: Some(28),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x29",
        aliases: &["w29", "fp"],
        width: 64,
        id: RegId(29),
        category: RegisterCategory::Special,
        dwarf_num: Some(29),
        callee_saved: true,
        role: RegisterRole::FramePointer,
    },
    RegisterDescriptor {
        name: "x30",
        aliases: &["w30", "lr"],
        width: 64,
        id: RegId(30),
        category: RegisterCategory::Special,
        dwarf_num: Some(30),
        callee_saved: true,
        role: RegisterRole::ReturnAddress,
    },
    RegisterDescriptor {
        name: "sp",
        aliases: &[],
        width: 64,
        id: RegId(31),
        category: RegisterCategory::Special,
        dwarf_num: Some(31),
        callee_saved: true,
        role: RegisterRole::StackPointer,
    },
    RegisterDescriptor {
        name: "pc",
        aliases: &[],
        width: 64,
        id: RegId(32),
        category: RegisterCategory::Special,
        dwarf_num: Some(32),
        callee_saved: false,
        role: RegisterRole::ProgramCounter,
    },
    RegisterDescriptor {
        name: "nzcv",
        aliases: &[],
        width: 64,
        id: RegId(33),
        category: RegisterCategory::Control,
        dwarf_num: Some(66),
        callee_saved: false,
        role: RegisterRole::None,
    },
    // V (SIMD) registers
    RegisterDescriptor {
        name: "v0",
        aliases: &["q0", "d0", "s0", "h0", "b0"],
        width: 128,
        id: RegId(64),
        category: RegisterCategory::Vector,
        dwarf_num: Some(64),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v1",
        aliases: &["q1", "d1", "s1", "h1", "b1"],
        width: 128,
        id: RegId(65),
        category: RegisterCategory::Vector,
        dwarf_num: Some(65),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v2",
        aliases: &["q2", "d2", "s2", "h2", "b2"],
        width: 128,
        id: RegId(66),
        category: RegisterCategory::Vector,
        dwarf_num: Some(66),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v3",
        aliases: &["q3", "d3", "s3", "h3", "b3"],
        width: 128,
        id: RegId(67),
        category: RegisterCategory::Vector,
        dwarf_num: Some(67),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v8",
        aliases: &["q8", "d8", "s8", "h8", "b8"],
        width: 128,
        id: RegId(72),
        category: RegisterCategory::Vector,
        dwarf_num: Some(72),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v9",
        aliases: &["q9", "d9", "s9", "h9", "b9"],
        width: 128,
        id: RegId(73),
        category: RegisterCategory::Vector,
        dwarf_num: Some(73),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v15",
        aliases: &["q15", "d15", "s15", "h15", "b15"],
        width: 128,
        id: RegId(79),
        category: RegisterCategory::Vector,
        dwarf_num: Some(79),
        callee_saved: true,
        role: RegisterRole::None,
    },
];

impl RegisterSet for RegisterSetArm64 {
    fn arch_name(&self) -> &'static str {
        "aarch64"
    }
    fn registers(&self) -> &[RegisterDescriptor] {
        ARM64_REGS
    }
    fn pointer_width_bits(&self) -> u16 {
        64
    }
    fn overlaps(&self, a: RegId, b: RegId) -> bool {
        if a == b {
            return true;
        }
        // x29/fp and x30/lr are special but share the same id
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIPS-32
// ─────────────────────────────────────────────────────────────────────────────

/// MIPS-32 register set.
#[derive(Debug, Default)]
pub struct RegisterSetMips32;

static MIPS32_REGS: &[RegisterDescriptor] = &[
    RegisterDescriptor {
        name: "zero",
        aliases: &["r0"],
        width: 32,
        id: RegId(0),
        category: RegisterCategory::General,
        dwarf_num: Some(0),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "at",
        aliases: &["r1"],
        width: 32,
        id: RegId(1),
        category: RegisterCategory::General,
        dwarf_num: Some(1),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v0",
        aliases: &["r2"],
        width: 32,
        id: RegId(2),
        category: RegisterCategory::General,
        dwarf_num: Some(2),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "v1",
        aliases: &["r3"],
        width: 32,
        id: RegId(3),
        category: RegisterCategory::General,
        dwarf_num: Some(3),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "a0",
        aliases: &["r4"],
        width: 32,
        id: RegId(4),
        category: RegisterCategory::General,
        dwarf_num: Some(4),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "a1",
        aliases: &["r5"],
        width: 32,
        id: RegId(5),
        category: RegisterCategory::General,
        dwarf_num: Some(5),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "a2",
        aliases: &["r6"],
        width: 32,
        id: RegId(6),
        category: RegisterCategory::General,
        dwarf_num: Some(6),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "a3",
        aliases: &["r7"],
        width: 32,
        id: RegId(7),
        category: RegisterCategory::General,
        dwarf_num: Some(7),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t0",
        aliases: &["r8"],
        width: 32,
        id: RegId(8),
        category: RegisterCategory::General,
        dwarf_num: Some(8),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t1",
        aliases: &["r9"],
        width: 32,
        id: RegId(9),
        category: RegisterCategory::General,
        dwarf_num: Some(9),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t2",
        aliases: &["r10"],
        width: 32,
        id: RegId(10),
        category: RegisterCategory::General,
        dwarf_num: Some(10),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t3",
        aliases: &["r11"],
        width: 32,
        id: RegId(11),
        category: RegisterCategory::General,
        dwarf_num: Some(11),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t4",
        aliases: &["r12"],
        width: 32,
        id: RegId(12),
        category: RegisterCategory::General,
        dwarf_num: Some(12),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t5",
        aliases: &["r13"],
        width: 32,
        id: RegId(13),
        category: RegisterCategory::General,
        dwarf_num: Some(13),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t6",
        aliases: &["r14"],
        width: 32,
        id: RegId(14),
        category: RegisterCategory::General,
        dwarf_num: Some(14),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t7",
        aliases: &["r15"],
        width: 32,
        id: RegId(15),
        category: RegisterCategory::General,
        dwarf_num: Some(15),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s0",
        aliases: &["r16"],
        width: 32,
        id: RegId(16),
        category: RegisterCategory::General,
        dwarf_num: Some(16),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s1",
        aliases: &["r17"],
        width: 32,
        id: RegId(17),
        category: RegisterCategory::General,
        dwarf_num: Some(17),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s2",
        aliases: &["r18"],
        width: 32,
        id: RegId(18),
        category: RegisterCategory::General,
        dwarf_num: Some(18),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s3",
        aliases: &["r19"],
        width: 32,
        id: RegId(19),
        category: RegisterCategory::General,
        dwarf_num: Some(19),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s4",
        aliases: &["r20"],
        width: 32,
        id: RegId(20),
        category: RegisterCategory::General,
        dwarf_num: Some(20),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s5",
        aliases: &["r21"],
        width: 32,
        id: RegId(21),
        category: RegisterCategory::General,
        dwarf_num: Some(21),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s6",
        aliases: &["r22"],
        width: 32,
        id: RegId(22),
        category: RegisterCategory::General,
        dwarf_num: Some(22),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "s7",
        aliases: &["r23"],
        width: 32,
        id: RegId(23),
        category: RegisterCategory::General,
        dwarf_num: Some(23),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t8",
        aliases: &["r24"],
        width: 32,
        id: RegId(24),
        category: RegisterCategory::General,
        dwarf_num: Some(24),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "t9",
        aliases: &["r25"],
        width: 32,
        id: RegId(25),
        category: RegisterCategory::General,
        dwarf_num: Some(25),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "k0",
        aliases: &["r26"],
        width: 32,
        id: RegId(26),
        category: RegisterCategory::General,
        dwarf_num: Some(26),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "k1",
        aliases: &["r27"],
        width: 32,
        id: RegId(27),
        category: RegisterCategory::General,
        dwarf_num: Some(27),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "gp",
        aliases: &["r28"],
        width: 32,
        id: RegId(28),
        category: RegisterCategory::General,
        dwarf_num: Some(28),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "sp",
        aliases: &["r29"],
        width: 32,
        id: RegId(29),
        category: RegisterCategory::Special,
        dwarf_num: Some(29),
        callee_saved: true,
        role: RegisterRole::StackPointer,
    },
    RegisterDescriptor {
        name: "s8",
        aliases: &["r30", "fp"],
        width: 32,
        id: RegId(30),
        category: RegisterCategory::Special,
        dwarf_num: Some(30),
        callee_saved: true,
        role: RegisterRole::FramePointer,
    },
    RegisterDescriptor {
        name: "ra",
        aliases: &["r31"],
        width: 32,
        id: RegId(31),
        category: RegisterCategory::Special,
        dwarf_num: Some(31),
        callee_saved: true,
        role: RegisterRole::ReturnAddress,
    },
    RegisterDescriptor {
        name: "pc",
        aliases: &[],
        width: 32,
        id: RegId(32),
        category: RegisterCategory::Special,
        dwarf_num: Some(37),
        callee_saved: false,
        role: RegisterRole::ProgramCounter,
    },
    RegisterDescriptor {
        name: "hi",
        aliases: &[],
        width: 32,
        id: RegId(33),
        category: RegisterCategory::Special,
        dwarf_num: Some(33),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "lo",
        aliases: &[],
        width: 32,
        id: RegId(34),
        category: RegisterCategory::Special,
        dwarf_num: Some(34),
        callee_saved: false,
        role: RegisterRole::None,
    },
];

impl RegisterSet for RegisterSetMips32 {
    fn arch_name(&self) -> &'static str {
        "mips32"
    }
    fn registers(&self) -> &[RegisterDescriptor] {
        MIPS32_REGS
    }
    fn pointer_width_bits(&self) -> u16 {
        32
    }
    fn overlaps(&self, a: RegId, b: RegId) -> bool {
        a == b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RISC-V 64
// ─────────────────────────────────────────────────────────────────────────────

/// RISC-V 64-bit register set.
#[derive(Debug, Default)]
pub struct RegisterSetRiscV64;

static RISCV64_REGS: &[RegisterDescriptor] = &[
    RegisterDescriptor {
        name: "x0",
        aliases: &["zero"],
        width: 64,
        id: RegId(0),
        category: RegisterCategory::General,
        dwarf_num: Some(0),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x1",
        aliases: &["ra"],
        width: 64,
        id: RegId(1),
        category: RegisterCategory::Special,
        dwarf_num: Some(1),
        callee_saved: false,
        role: RegisterRole::ReturnAddress,
    },
    RegisterDescriptor {
        name: "x2",
        aliases: &["sp"],
        width: 64,
        id: RegId(2),
        category: RegisterCategory::Special,
        dwarf_num: Some(2),
        callee_saved: true,
        role: RegisterRole::StackPointer,
    },
    RegisterDescriptor {
        name: "x3",
        aliases: &["gp"],
        width: 64,
        id: RegId(3),
        category: RegisterCategory::General,
        dwarf_num: Some(3),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x4",
        aliases: &["tp"],
        width: 64,
        id: RegId(4),
        category: RegisterCategory::General,
        dwarf_num: Some(4),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x5",
        aliases: &["t0"],
        width: 64,
        id: RegId(5),
        category: RegisterCategory::General,
        dwarf_num: Some(5),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x6",
        aliases: &["t1"],
        width: 64,
        id: RegId(6),
        category: RegisterCategory::General,
        dwarf_num: Some(6),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x7",
        aliases: &["t2"],
        width: 64,
        id: RegId(7),
        category: RegisterCategory::General,
        dwarf_num: Some(7),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x8",
        aliases: &["s0", "fp"],
        width: 64,
        id: RegId(8),
        category: RegisterCategory::Special,
        dwarf_num: Some(8),
        callee_saved: true,
        role: RegisterRole::FramePointer,
    },
    RegisterDescriptor {
        name: "x9",
        aliases: &["s1"],
        width: 64,
        id: RegId(9),
        category: RegisterCategory::General,
        dwarf_num: Some(9),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x10",
        aliases: &["a0"],
        width: 64,
        id: RegId(10),
        category: RegisterCategory::General,
        dwarf_num: Some(10),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x11",
        aliases: &["a1"],
        width: 64,
        id: RegId(11),
        category: RegisterCategory::General,
        dwarf_num: Some(11),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x12",
        aliases: &["a2"],
        width: 64,
        id: RegId(12),
        category: RegisterCategory::General,
        dwarf_num: Some(12),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x13",
        aliases: &["a3"],
        width: 64,
        id: RegId(13),
        category: RegisterCategory::General,
        dwarf_num: Some(13),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x14",
        aliases: &["a4"],
        width: 64,
        id: RegId(14),
        category: RegisterCategory::General,
        dwarf_num: Some(14),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x15",
        aliases: &["a5"],
        width: 64,
        id: RegId(15),
        category: RegisterCategory::General,
        dwarf_num: Some(15),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x16",
        aliases: &["a6"],
        width: 64,
        id: RegId(16),
        category: RegisterCategory::General,
        dwarf_num: Some(16),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x17",
        aliases: &["a7"],
        width: 64,
        id: RegId(17),
        category: RegisterCategory::General,
        dwarf_num: Some(17),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x18",
        aliases: &["s2"],
        width: 64,
        id: RegId(18),
        category: RegisterCategory::General,
        dwarf_num: Some(18),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x19",
        aliases: &["s3"],
        width: 64,
        id: RegId(19),
        category: RegisterCategory::General,
        dwarf_num: Some(19),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x20",
        aliases: &["s4"],
        width: 64,
        id: RegId(20),
        category: RegisterCategory::General,
        dwarf_num: Some(20),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x21",
        aliases: &["s5"],
        width: 64,
        id: RegId(21),
        category: RegisterCategory::General,
        dwarf_num: Some(21),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x22",
        aliases: &["s6"],
        width: 64,
        id: RegId(22),
        category: RegisterCategory::General,
        dwarf_num: Some(22),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x23",
        aliases: &["s7"],
        width: 64,
        id: RegId(23),
        category: RegisterCategory::General,
        dwarf_num: Some(23),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x24",
        aliases: &["s8"],
        width: 64,
        id: RegId(24),
        category: RegisterCategory::General,
        dwarf_num: Some(24),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x25",
        aliases: &["s9"],
        width: 64,
        id: RegId(25),
        category: RegisterCategory::General,
        dwarf_num: Some(25),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x26",
        aliases: &["s10"],
        width: 64,
        id: RegId(26),
        category: RegisterCategory::General,
        dwarf_num: Some(26),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x27",
        aliases: &["s11"],
        width: 64,
        id: RegId(27),
        category: RegisterCategory::General,
        dwarf_num: Some(27),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x28",
        aliases: &["t3"],
        width: 64,
        id: RegId(28),
        category: RegisterCategory::General,
        dwarf_num: Some(28),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x29",
        aliases: &["t4"],
        width: 64,
        id: RegId(29),
        category: RegisterCategory::General,
        dwarf_num: Some(29),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x30",
        aliases: &["t5"],
        width: 64,
        id: RegId(30),
        category: RegisterCategory::General,
        dwarf_num: Some(30),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "x31",
        aliases: &["t6"],
        width: 64,
        id: RegId(31),
        category: RegisterCategory::General,
        dwarf_num: Some(31),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "pc",
        aliases: &[],
        width: 64,
        id: RegId(32),
        category: RegisterCategory::Special,
        dwarf_num: None,
        callee_saved: false,
        role: RegisterRole::ProgramCounter,
    },
    // Floating point (f0-f31)
    RegisterDescriptor {
        name: "f0",
        aliases: &["ft0"],
        width: 64,
        id: RegId(33),
        category: RegisterCategory::Float,
        dwarf_num: Some(33),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "f1",
        aliases: &["ft1"],
        width: 64,
        id: RegId(34),
        category: RegisterCategory::Float,
        dwarf_num: Some(34),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "f8",
        aliases: &["fs0"],
        width: 64,
        id: RegId(41),
        category: RegisterCategory::Float,
        dwarf_num: Some(41),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "f9",
        aliases: &["fs1"],
        width: 64,
        id: RegId(42),
        category: RegisterCategory::Float,
        dwarf_num: Some(42),
        callee_saved: true,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "f10",
        aliases: &["fa0"],
        width: 64,
        id: RegId(43),
        category: RegisterCategory::Float,
        dwarf_num: Some(43),
        callee_saved: false,
        role: RegisterRole::None,
    },
    RegisterDescriptor {
        name: "f11",
        aliases: &["fa1"],
        width: 64,
        id: RegId(44),
        category: RegisterCategory::Float,
        dwarf_num: Some(44),
        callee_saved: false,
        role: RegisterRole::None,
    },
];

impl RegisterSet for RegisterSetRiscV64 {
    fn arch_name(&self) -> &'static str {
        "riscv64"
    }
    fn registers(&self) -> &[RegisterDescriptor] {
        RISCV64_REGS
    }
    fn pointer_width_bits(&self) -> u16 {
        64
    }
    fn overlaps(&self, a: RegId, b: RegId) -> bool {
        a == b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterSetRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe registry mapping architecture names to their [`RegisterSet`] implementations.
pub struct RegisterSetRegistry {
    inner: HashMap<&'static str, Arc<dyn RegisterSet>>,
}

impl RegisterSetRegistry {
    /// Create a new registry populated with all built-in register sets.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut m: HashMap<&'static str, Arc<dyn RegisterSet>> = HashMap::new();
        m.insert("x86_64", Arc::new(RegisterSetX86_64));
        m.insert("aarch64", Arc::new(RegisterSetArm64));
        m.insert("mips32", Arc::new(RegisterSetMips32));
        m.insert("riscv64", Arc::new(RegisterSetRiscV64));
        Self { inner: m }
    }

    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Register a new architecture.
    pub fn register(&mut self, rs: Arc<dyn RegisterSet>) {
        self.inner.insert(rs.arch_name(), rs);
    }

    /// Retrieve a register set by architecture name.
    #[must_use]
    pub fn get(&self, arch: &str) -> Option<Arc<dyn RegisterSet>> {
        self.inner.get(arch).cloned()
    }

    /// All registered architecture names.
    #[must_use]
    pub fn arch_names(&self) -> Vec<&'static str> {
        self.inner.keys().copied().collect()
    }

    /// Number of registered architectures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if no architectures are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for RegisterSetRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl fmt::Debug for RegisterSetRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterSetRegistry")
            .field("archs", &self.arch_names())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- RegId ---

    #[test]
    fn reg_id_from_u32() {
        let id: RegId = 42u32.into();
        assert_eq!(id.0, 42);
    }

    #[test]
    fn reg_id_display() {
        assert_eq!(format!("{}", RegId(7)), "reg#7");
    }

    #[test]
    fn reg_id_ord() {
        assert!(RegId(1) < RegId(2));
    }

    // --- RegisterDescriptor ---

    #[test]
    fn descriptor_matches_name_canonical() {
        let rs = RegisterSetX86_64;
        let rax = rs.by_name("rax").unwrap();
        assert!(rax.matches_name("rax"));
    }

    #[test]
    fn descriptor_matches_name_alias() {
        let rs = RegisterSetX86_64;
        let rax = rs.by_name("rax").unwrap();
        assert!(rax.matches_name("eax"));
        assert!(rax.matches_name("al"));
    }

    #[test]
    fn descriptor_matches_name_case_insensitive() {
        let rs = RegisterSetX86_64;
        let rax = rs.by_name("RAX").unwrap();
        assert!(rax.matches_name("RAX"));
    }

    // --- x86-64 ---

    #[test]
    fn x86_64_arch_name() {
        assert_eq!(RegisterSetX86_64.arch_name(), "x86_64");
    }

    #[test]
    fn x86_64_pointer_width() {
        assert_eq!(RegisterSetX86_64.pointer_width_bits(), 64);
    }

    #[test]
    fn x86_64_has_rax() {
        let rs = RegisterSetX86_64;
        let r = rs.by_name("rax").unwrap();
        assert_eq!(r.width, 64);
        assert_eq!(r.category, RegisterCategory::General);
    }

    #[test]
    fn x86_64_rsp_is_stack_pointer() {
        let rs = RegisterSetX86_64;
        let sp = rs.stack_pointer().unwrap();
        assert_eq!(sp.name, "rsp");
        assert!(sp.is_stack_pointer());
    }

    #[test]
    fn x86_64_rbp_is_frame_pointer() {
        let rs = RegisterSetX86_64;
        let fp = rs.frame_pointer().unwrap();
        assert_eq!(fp.name, "rbp");
    }

    #[test]
    fn x86_64_rip_is_program_counter() {
        let rs = RegisterSetX86_64;
        let pc = rs.program_counter().unwrap();
        assert_eq!(pc.name, "rip");
    }

    #[test]
    fn x86_64_callee_saved_includes_rbx() {
        let rs = RegisterSetX86_64;
        let cs = rs.callee_saved();
        assert!(cs.iter().any(|r| r.name == "rbx"));
    }

    #[test]
    fn x86_64_gpr_count() {
        let rs = RegisterSetX86_64;
        assert!(rs.gpr().len() >= 14);
    }

    #[test]
    fn x86_64_segment_registers() {
        let rs = RegisterSetX86_64;
        let segs = rs.by_category(RegisterCategory::Segment);
        assert_eq!(segs.len(), 6);
    }

    #[test]
    fn x86_64_by_id_roundtrip() {
        let rs = RegisterSetX86_64;
        let rax = rs.by_name("rax").unwrap();
        let again = rs.by_id(rax.id).unwrap();
        assert_eq!(rax.name, again.name);
    }

    // --- AArch64 ---

    #[test]
    fn arm64_arch_name() {
        assert_eq!(RegisterSetArm64.arch_name(), "aarch64");
    }

    #[test]
    fn arm64_sp_is_stack_pointer() {
        let rs = RegisterSetArm64;
        let sp = rs.stack_pointer().unwrap();
        assert_eq!(sp.name, "sp");
    }

    #[test]
    fn arm64_lr_is_return_address() {
        let rs = RegisterSetArm64;
        let lr = rs.by_name("x30").unwrap();
        assert!(lr.is_return_address());
    }

    #[test]
    fn arm64_fp_via_alias() {
        let rs = RegisterSetArm64;
        let fp = rs.by_name("fp").unwrap();
        assert!(fp.is_frame_pointer());
    }

    #[test]
    fn arm64_vector_regs_exist() {
        let rs = RegisterSetArm64;
        let vregs = rs.by_category(RegisterCategory::Vector);
        assert!(!vregs.is_empty());
    }

    // --- MIPS-32 ---

    #[test]
    fn mips32_arch_name() {
        assert_eq!(RegisterSetMips32.arch_name(), "mips32");
    }

    #[test]
    fn mips32_pointer_width() {
        assert_eq!(RegisterSetMips32.pointer_width_bits(), 32);
    }

    #[test]
    fn mips32_ra_is_return_address() {
        let rs = RegisterSetMips32;
        let ra = rs.by_name("ra").unwrap();
        assert!(ra.is_return_address());
    }

    #[test]
    fn mips32_zero_reg() {
        let rs = RegisterSetMips32;
        let zero = rs.by_name("zero").unwrap();
        assert_eq!(zero.id, RegId(0));
    }

    #[test]
    fn mips32_callee_saved_s_regs() {
        let rs = RegisterSetMips32;
        let cs = rs.callee_saved();
        assert!(cs.iter().any(|r| r.name == "s0"));
        assert!(cs.iter().any(|r| r.name == "s7"));
    }

    // --- RISC-V 64 ---

    #[test]
    fn riscv64_arch_name() {
        assert_eq!(RegisterSetRiscV64.arch_name(), "riscv64");
    }

    #[test]
    fn riscv64_ra_is_return_address() {
        let rs = RegisterSetRiscV64;
        let ra = rs.by_name("ra").unwrap();
        assert!(ra.is_return_address());
    }

    #[test]
    fn riscv64_sp_is_stack_pointer() {
        let rs = RegisterSetRiscV64;
        let sp = rs.stack_pointer().unwrap();
        assert_eq!(sp.name, "x2");
    }

    #[test]
    fn riscv64_fp_alias() {
        let rs = RegisterSetRiscV64;
        let fp = rs.by_name("fp").unwrap();
        assert!(fp.is_frame_pointer());
    }

    // --- Registry ---

    #[test]
    fn registry_with_builtins_has_four_archs() {
        let reg = RegisterSetRegistry::with_builtins();
        assert_eq!(reg.len(), 4);
    }

    #[test]
    fn registry_get_x86_64() {
        let reg = RegisterSetRegistry::with_builtins();
        let rs = reg.get("x86_64").unwrap();
        assert_eq!(rs.arch_name(), "x86_64");
    }

    #[test]
    fn registry_get_missing_returns_none() {
        let reg = RegisterSetRegistry::with_builtins();
        assert!(reg.get("pdp11").is_none());
    }

    #[test]
    fn registry_arch_names_contains_all_builtins() {
        let reg = RegisterSetRegistry::with_builtins();
        let names = reg.arch_names();
        assert!(names.contains(&"x86_64"));
        assert!(names.contains(&"aarch64"));
        assert!(names.contains(&"mips32"));
        assert!(names.contains(&"riscv64"));
    }

    #[test]
    fn registry_custom_register() {
        let mut reg = RegisterSetRegistry::new();
        reg.register(Arc::new(RegisterSetX86_64));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_is_empty_on_new() {
        let reg = RegisterSetRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_default_has_builtins() {
        let reg = RegisterSetRegistry::default();
        assert!(!reg.is_empty());
    }

    #[test]
    fn registry_debug_format() {
        let reg = RegisterSetRegistry::with_builtins();
        let s = format!("{reg:?}");
        assert!(s.contains("RegisterSetRegistry"));
    }
}
