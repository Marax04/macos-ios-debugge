//! Architecture-specific prologue pattern database.
//!
//! Each entry stores:
//! - A byte pattern with wildcard positions.
//! - The architecture it applies to.
//! - The minimum confidence when this pattern matches.
//! - Optional minimum alignment for the pattern scan stride.
//!
//! Supported architectures: x86-64, x86-32, ARM (Thumb/ARM state), ARM64
//! (`AArch64`), MIPS32, MIPS64, RISC-V (32 & 64-bit), PowerPC (32 & 64-bit),
//! SPARC (32 & 64-bit).
//!
//! Patterns are sorted from longest/most-specific to shortest/least-specific
//! so that the scanner can stop at the first match per offset (most specific
//! wins).

use crate::Confidence;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Architecture enum
// ─────────────────────────────────────────────────────────────────────────────

/// Target architecture for a prologue pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    X86_32,
    /// `AArch64` / ARM64.
    Arm64,
    /// ARM 32-bit (ARM state).
    Arm32,
    /// ARM Thumb/Thumb-2.
    Thumb,
    Mips32,
    Mips64,
    RiscV32,
    RiscV64,
    Ppc32,
    Ppc64,
    Sparc32,
    Sparc64,
}

impl Arch {
    /// Minimum instruction alignment in bytes for this architecture.
    /// The scanner advances by this stride between candidate addresses.
    #[must_use]
    pub const fn instruction_align(self) -> usize {
        match self {
            Self::X86_64 | Self::X86_32 => 1,
            Self::Arm64
            | Self::Arm32
            | Self::Mips32
            | Self::Mips64
            | Self::Ppc32
            | Self::Ppc64
            | Self::Sparc32
            | Self::Sparc64 => 4,
            Self::Thumb | Self::RiscV32 | Self::RiscV64 => 2, // compressed extensions may use 2
        }
    }

    /// A short tag used in serialization / display.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86_32 => "x86_32",
            Self::Arm64 => "arm64",
            Self::Arm32 => "arm32",
            Self::Thumb => "thumb",
            Self::Mips32 => "mips32",
            Self::Mips64 => "mips64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Ppc32 => "ppc32",
            Self::Ppc64 => "ppc64",
            Self::Sparc32 => "sparc32",
            Self::Sparc64 => "sparc64",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternByte — a single byte in a pattern
// ─────────────────────────────────────────────────────────────────────────────

/// One byte position in a prologue pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    /// An exact byte value that must match.
    Exact(u8),
    /// A wildcard that matches any byte value.
    Any,
}

impl PatternByte {
    /// Return `true` when `byte` satisfies this pattern position.
    #[must_use]
    pub const fn matches(self, byte: u8) -> bool {
        match self {
            Self::Exact(b) => b == byte,
            Self::Any => true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrologueEntry — one entry in the database
// ─────────────────────────────────────────────────────────────────────────────

/// One prologue pattern entry in the database.
#[derive(Debug, Clone)]
pub struct PrologueEntry {
    /// Human-readable name, useful for debugging.
    pub name: &'static str,
    /// Target architecture.
    pub arch: Arch,
    /// Byte-level pattern (with possible wildcards).
    pub pattern: &'static [PatternByte],
    /// Confidence assigned when this pattern matches.
    pub confidence: Confidence,
    /// Optional description of the pattern.
    pub description: &'static str,
}

impl PrologueEntry {
    /// Number of bytes in the pattern.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pattern.len()
    }

    /// Whether the pattern is empty (always false for well-formed entries).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }

    /// Test whether `bytes` (starting at offset 0) matches this pattern.
    /// `bytes` must be at least `self.len()` long.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        if bytes.len() < self.pattern.len() {
            return false;
        }
        self.pattern
            .iter()
            .zip(bytes.iter())
            .all(|(p, &b)| p.matches(b))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience macro for defining patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `&'static [PatternByte]` from a mix of `Some(u8)` and `None` values,
/// mirroring the existing `ProloguePattern` convention.
macro_rules! pat {
    ($($b:expr),* $(,)?) => {
        {
            const PAT: &[PatternByte] = &[ $(match $b {
                Some(v) => PatternByte::Exact(v),
                None    => PatternByte::Any,
            }),* ];
            PAT
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// PrologueDb — the full database
// ─────────────────────────────────────────────────────────────────────────────

/// The prologue-pattern database.
///
/// Use [`PrologueDb::for_arch`] to get all patterns for a specific architecture,
/// or [`PrologueDb::all`] to iterate the entire database.
pub struct PrologueDb;

impl PrologueDb {
    /// Return all patterns for the given architecture, sorted from most specific
    /// (longest / highest confidence) to least specific.
    #[must_use]
    pub fn for_arch(arch: Arch) -> Vec<&'static PrologueEntry> {
        let mut entries: Vec<&'static PrologueEntry> =
            Self::iter_all().filter(|e| e.arch == arch).collect();
        // Sort: longer patterns first; break ties by confidence (higher wins).
        entries.sort_by(|a, b| {
            b.pattern
                .len()
                .cmp(&a.pattern.len())
                .then_with(|| b.confidence.cmp(&a.confidence))
        });
        entries
    }

    /// All x86-64 entries.
    #[must_use]
    pub fn x86_64() -> &'static [PrologueEntry] {
        X86_64_PATTERNS
    }

    /// All x86-32 entries.
    #[must_use]
    pub fn x86_32() -> &'static [PrologueEntry] {
        X86_32_PATTERNS
    }

    /// All ARM64 entries.
    #[must_use]
    pub fn arm64() -> &'static [PrologueEntry] {
        ARM64_PATTERNS
    }

    /// All ARM32 entries.
    #[must_use]
    pub fn arm32() -> &'static [PrologueEntry] {
        ARM32_PATTERNS
    }

    /// All Thumb entries.
    #[must_use]
    pub fn thumb() -> &'static [PrologueEntry] {
        THUMB_PATTERNS
    }

    /// Iterate all patterns for every architecture.
    pub fn iter_all() -> impl Iterator<Item = &'static PrologueEntry> {
        X86_64_PATTERNS
            .iter()
            .chain(X86_32_PATTERNS.iter())
            .chain(ARM64_PATTERNS.iter())
            .chain(ARM32_PATTERNS.iter())
            .chain(THUMB_PATTERNS.iter())
            .chain(MIPS32_PATTERNS.iter())
            .chain(MIPS64_PATTERNS.iter())
            .chain(RISCV_PATTERNS.iter())
            .chain(PPC32_PATTERNS.iter())
            .chain(PPC64_PATTERNS.iter())
            .chain(SPARC_PATTERNS.iter())
    }

    /// Return the total number of patterns in the database.
    #[must_use]
    pub fn count() -> usize {
        X86_64_PATTERNS.len()
            + X86_32_PATTERNS.len()
            + ARM64_PATTERNS.len()
            + ARM32_PATTERNS.len()
            + THUMB_PATTERNS.len()
            + MIPS32_PATTERNS.len()
            + MIPS64_PATTERNS.len()
            + RISCV_PATTERNS.len()
            + PPC32_PATTERNS.len()
            + PPC64_PATTERNS.len()
            + SPARC_PATTERNS.len()
    }

    /// Serialize all patterns for `arch` to a JSON string.
    ///
    /// Each entry is serialized as a JSON object with fields:
    /// `name`, `arch`, `confidence`, `description`, and `pattern`
    /// (an array of byte values or `null` for wildcards).
    ///
    /// Returns an error if serialization fails (should not happen in practice).
    ///
    /// # Errors
    /// Returns `Err` if JSON serialization fails (extremely unlikely in practice).
    pub fn to_json(arch: Arch) -> Result<String, serde_json::Error> {
        let entries: Vec<Value> = Self::for_arch(arch)
            .into_iter()
            .map(|e| {
                let pattern: Vec<Value> = e
                    .pattern
                    .iter()
                    .map(|pb| match pb {
                        PatternByte::Exact(b) => Value::Number((*b).into()),
                        PatternByte::Any => Value::Null,
                    })
                    .collect();
                serde_json::json!({
                    "name": e.name,
                    "arch": e.arch.tag(),
                    "confidence": format!("{:?}", e.confidence),
                    "description": e.description,
                    "pattern": pattern,
                })
            })
            .collect();
        serde_json::to_string_pretty(&Value::Array(entries))
    }

    /// Serialize the entire database (all architectures) to a JSON string.
    ///
    /// # Errors
    /// Returns `Err` if JSON serialization fails (extremely unlikely in practice).
    pub fn all_to_json() -> Result<String, serde_json::Error> {
        let entries: Vec<Value> = Self::iter_all()
            .map(|e| {
                let pattern: Vec<Value> = e
                    .pattern
                    .iter()
                    .map(|pb| match pb {
                        PatternByte::Exact(b) => Value::Number((*b).into()),
                        PatternByte::Any => Value::Null,
                    })
                    .collect();
                serde_json::json!({
                    "name": e.name,
                    "arch": e.arch.tag(),
                    "confidence": format!("{:?}", e.confidence),
                    "description": e.description,
                    "pattern": pattern,
                })
            })
            .collect();
        serde_json::to_string_pretty(&Value::Array(entries))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// x86-64 patterns
// ─────────────────────────────────────────────────────────────────────────────

static X86_64_PATTERNS: &[PrologueEntry] = &[
    PrologueEntry {
        name: "push_rbp_mov_rbp_rsp_sub_rsp_imm32",
        arch: Arch::X86_64,
        pattern: pat![
            Some(0x55),
            Some(0x48),
            Some(0x89),
            Some(0xE5),
            Some(0x48),
            Some(0x81),
            Some(0xEC),
            None,
            None,
            None,
            None
        ],
        confidence: Confidence::High,
        description: "push rbp; mov rbp,rsp; sub rsp,imm32",
    },
    PrologueEntry {
        name: "push_rbp_mov_rbp_rsp_sub_rsp_imm8",
        arch: Arch::X86_64,
        pattern: pat![
            Some(0x55),
            Some(0x48),
            Some(0x89),
            Some(0xE5),
            Some(0x48),
            Some(0x83),
            Some(0xEC),
            None
        ],
        confidence: Confidence::High,
        description: "push rbp; mov rbp,rsp; sub rsp,imm8",
    },
    PrologueEntry {
        name: "push_rbp_mov_rbp_rsp_push_rbx",
        arch: Arch::X86_64,
        pattern: pat![Some(0x55), Some(0x48), Some(0x89), Some(0xE5), Some(0x53)],
        confidence: Confidence::High,
        description: "push rbp; mov rbp,rsp; push rbx (PIC)",
    },
    PrologueEntry {
        name: "push_rbp_mov_rbp_rsp",
        arch: Arch::X86_64,
        pattern: pat![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
        confidence: Confidence::High,
        description: "push rbp; mov rbp,rsp (classical System-V / MSVC)",
    },
    PrologueEntry {
        name: "endbr64_push_rbp_mov_rbp_rsp",
        arch: Arch::X86_64,
        pattern: pat![
            Some(0xF3),
            Some(0x0F),
            Some(0x1E),
            Some(0xFA),
            Some(0x55),
            Some(0x48),
            Some(0x89),
            Some(0xE5)
        ],
        confidence: Confidence::High,
        description: "endbr64; push rbp; mov rbp,rsp",
    },
    PrologueEntry {
        name: "endbr64",
        arch: Arch::X86_64,
        pattern: pat![Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFA)],
        confidence: Confidence::Medium,
        description: "endbr64 (CET indirect branch tracking)",
    },
    PrologueEntry {
        name: "sub_rsp_imm32",
        arch: Arch::X86_64,
        pattern: pat![Some(0x48), Some(0x81), Some(0xEC), None, None, None, None],
        confidence: Confidence::Medium,
        description: "sub rsp,imm32 (large frame, no frame pointer)",
    },
    PrologueEntry {
        name: "sub_rsp_imm8",
        arch: Arch::X86_64,
        pattern: pat![Some(0x48), Some(0x83), Some(0xEC), None],
        confidence: Confidence::Medium,
        description: "sub rsp,imm8 (small frame, no frame pointer)",
    },
    PrologueEntry {
        name: "push_r15_r14_r13",
        arch: Arch::X86_64,
        pattern: pat![
            Some(0x41),
            Some(0x57),
            Some(0x41),
            Some(0x56),
            Some(0x41),
            Some(0x55)
        ],
        confidence: Confidence::Medium,
        description: "push r15; push r14; push r13 (callee-saved regs)",
    },
    PrologueEntry {
        name: "push_rdi_rsi_rbx",
        arch: Arch::X86_64,
        pattern: pat![Some(0x57), Some(0x56), Some(0x53)],
        confidence: Confidence::Low,
        description: "push rdi; push rsi; push rbx",
    },
    // MSVC-specific: mov [rsp+N], rN patterns
    PrologueEntry {
        name: "msvc_mov_rsp_r8",
        arch: Arch::X86_64,
        pattern: pat![Some(0x4C), Some(0x89), Some(0x44), Some(0x24), None],
        confidence: Confidence::Low,
        description: "MSVC: mov [rsp+N],r8",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// x86-32 patterns
// ─────────────────────────────────────────────────────────────────────────────

static X86_32_PATTERNS: &[PrologueEntry] = &[
    PrologueEntry {
        name: "push_ebp_mov_ebp_esp_sub_esp_imm32",
        arch: Arch::X86_32,
        pattern: pat![
            Some(0x55),
            Some(0x89),
            Some(0xE5),
            Some(0x81),
            Some(0xEC),
            None,
            None,
            None,
            None
        ],
        confidence: Confidence::High,
        description: "push ebp; mov ebp,esp; sub esp,imm32",
    },
    PrologueEntry {
        name: "push_ebp_mov_ebp_esp_sub_esp_imm8",
        arch: Arch::X86_32,
        pattern: pat![
            Some(0x55),
            Some(0x89),
            Some(0xE5),
            Some(0x83),
            Some(0xEC),
            None
        ],
        confidence: Confidence::High,
        description: "push ebp; mov ebp,esp; sub esp,imm8",
    },
    PrologueEntry {
        name: "push_ebp_mov_ebp_esp_push_ebx",
        arch: Arch::X86_32,
        pattern: pat![Some(0x55), Some(0x89), Some(0xE5), Some(0x53)],
        confidence: Confidence::High,
        description: "push ebp; mov ebp,esp; push ebx",
    },
    PrologueEntry {
        name: "push_ebp_mov_ebp_esp",
        arch: Arch::X86_32,
        pattern: pat![Some(0x55), Some(0x89), Some(0xE5)],
        confidence: Confidence::High,
        description: "push ebp; mov ebp,esp (cdecl / stdcall)",
    },
    PrologueEntry {
        name: "endbr32",
        arch: Arch::X86_32,
        pattern: pat![Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFB)],
        confidence: Confidence::Medium,
        description: "endbr32 (CET, hardened builds)",
    },
    PrologueEntry {
        name: "sub_esp_imm8_32",
        arch: Arch::X86_32,
        pattern: pat![Some(0x83), Some(0xEC), None],
        confidence: Confidence::Medium,
        description: "sub esp,imm8 (leaf, no frame pointer)",
    },
    PrologueEntry {
        name: "push_esi_edi_ebx",
        arch: Arch::X86_32,
        pattern: pat![Some(0x56), Some(0x57), Some(0x53)],
        confidence: Confidence::Low,
        description: "push esi; push edi; push ebx",
    },
    // MSVC __fastcall thunk stub: mov ecx,ecx / nop / ...
    PrologueEntry {
        name: "msvc_nop_fastcall",
        arch: Arch::X86_32,
        pattern: pat![Some(0x8B), Some(0xFF)],
        confidence: Confidence::Low,
        description: "MSVC mov edi,edi (hot-patch entry point stub)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 / AArch64 patterns (little-endian encoding)
// ─────────────────────────────────────────────────────────────────────────────

static ARM64_PATTERNS: &[PrologueEntry] = &[
    // stp x29,x30,[sp,#-N]! + mov x29,sp
    PrologueEntry {
        name: "stp_x29_x30_pre_mov_fp",
        arch: Arch::Arm64,
        pattern: pat![
            None,
            Some(0x7D),
            Some(0xBF),
            Some(0xA9), // stp x29,x30,[sp,#-N]!
            Some(0xFD),
            Some(0x03),
            Some(0x00),
            Some(0x91)
        ], // mov x29,sp
        confidence: Confidence::High,
        description: "stp x29,x30,[sp,#-N]!; mov x29,sp",
    },
    // pacibsp prologue (pointer authentication, arm64e / iOS)
    PrologueEntry {
        name: "pacibsp_stp_x29_x30",
        arch: Arch::Arm64,
        pattern: pat![
            Some(0x7F),
            Some(0x23),
            Some(0x03),
            Some(0xD5), // pacibsp
            None,
            Some(0x7D),
            Some(0xBF),
            Some(0xA9)
        ], // stp x29,x30,…
        confidence: Confidence::High,
        description: "pacibsp; stp x29,x30,[sp,#-N]!",
    },
    // pacisp variant
    PrologueEntry {
        name: "pacisp",
        arch: Arch::Arm64,
        pattern: pat![Some(0x5F), Some(0x24), Some(0x03), Some(0xD5)],
        confidence: Confidence::High,
        description: "pacisp (pointer-auth variant)",
    },
    PrologueEntry {
        name: "pacibsp",
        arch: Arch::Arm64,
        pattern: pat![Some(0x7F), Some(0x23), Some(0x03), Some(0xD5)],
        confidence: Confidence::High,
        description: "pacibsp (iOS/arm64e entry)",
    },
    PrologueEntry {
        name: "stp_x29_x30_sp_neg",
        arch: Arch::Arm64,
        pattern: pat![None, Some(0x7D), Some(0xBF), Some(0xA9)],
        confidence: Confidence::High,
        description: "stp x29,x30,[sp,#-N]! (frame prologue)",
    },
    PrologueEntry {
        name: "sub_sp_sp_imm",
        arch: Arch::Arm64,
        pattern: pat![None, None, Some(0x00), Some(0xD1)],
        confidence: Confidence::Medium,
        description: "sub sp,sp,#imm (no frame pointer)",
    },
    PrologueEntry {
        name: "stp_x19_x20_sp_neg",
        arch: Arch::Arm64,
        pattern: pat![None, Some(0x53), Some(0xBF), Some(0xA9)],
        confidence: Confidence::Medium,
        description: "stp x19,x20,[sp,#-N]! (callee-saved pair)",
    },
    PrologueEntry {
        name: "mov_x29_sp",
        arch: Arch::Arm64,
        pattern: pat![Some(0xFD), Some(0x03), Some(0x00), Some(0x91)],
        confidence: Confidence::Medium,
        description: "mov x29,sp (set frame pointer without stp)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// ARM 32-bit (ARM state) patterns
// ─────────────────────────────────────────────────────────────────────────────

static ARM32_PATTERNS: &[PrologueEntry] = &[
    // PUSH {r4-r7,lr}  — little-endian encoding
    PrologueEntry {
        name: "push_r4_r7_lr",
        arch: Arch::Arm32,
        pattern: pat![Some(0xF0), Some(0x41), Some(0x2D), Some(0xE9)], // stmdb sp!, {r4-r7,lr}
        confidence: Confidence::High,
        description: "stmdb sp!,{r4-r7,lr}",
    },
    // PUSH {r4-r11,lr}
    PrologueEntry {
        name: "push_r4_r11_lr",
        arch: Arch::Arm32,
        pattern: pat![Some(0xF0), Some(0x4F), Some(0x2D), Some(0xE9)],
        confidence: Confidence::High,
        description: "stmdb sp!,{r4-r11,lr}",
    },
    // SUB sp,sp,#N (no saved regs)
    PrologueEntry {
        name: "sub_sp_imm",
        arch: Arch::Arm32,
        pattern: pat![None, None, Some(0x4D), Some(0xE2)], // sub sp,sp,#imm (ARM encoding partial match)
        confidence: Confidence::Medium,
        description: "sub sp,sp,#imm (ARM state)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// ARM Thumb / Thumb-2 patterns
// ─────────────────────────────────────────────────────────────────────────────

static THUMB_PATTERNS: &[PrologueEntry] = &[
    // PUSH {r4-r7, lr}  Thumb encoding: 0x2D 0xE9 (16-bit) or F0 41 2D E9 (32-bit)
    PrologueEntry {
        name: "thumb_push_r4_r7_lr",
        arch: Arch::Thumb,
        pattern: pat![Some(0xF0), Some(0xB5)], // PUSH {r4-r7,lr} Thumb16
        confidence: Confidence::High,
        description: "PUSH {r4-r7,lr} (Thumb-16)",
    },
    PrologueEntry {
        name: "thumb_push_lr",
        arch: Arch::Thumb,
        pattern: pat![Some(0x10), Some(0xB5)], // PUSH {r4,lr}
        confidence: Confidence::High,
        description: "PUSH {r4,lr} (Thumb-16)",
    },
    PrologueEntry {
        name: "thumb_push_r4",
        arch: Arch::Thumb,
        pattern: pat![Some(0x10), Some(0xB4)], // PUSH {r4}
        confidence: Confidence::Medium,
        description: "PUSH {r4} (Thumb-16 callee-save)",
    },
    // SUB sp, sp, #N  (Thumb-16: 0xNN 0xB0 where byte[0] = offset/4)
    PrologueEntry {
        name: "thumb_sub_sp_imm",
        arch: Arch::Thumb,
        pattern: pat![None, Some(0xB0)],
        confidence: Confidence::Low,
        description: "SUB sp,sp,#N (Thumb-16)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// MIPS32 patterns (big-endian)
// ─────────────────────────────────────────────────────────────────────────────

static MIPS32_PATTERNS: &[PrologueEntry] = &[
    // addiu sp,sp,-N  (big-endian: 27 BD FF xx)
    PrologueEntry {
        name: "mips32_addiu_sp",
        arch: Arch::Mips32,
        pattern: pat![Some(0x27), Some(0xBD), Some(0xFF), None],
        confidence: Confidence::High,
        description: "addiu sp,sp,-N (MIPS32 big-endian)",
    },
    // sw ra, N(sp)  (big-endian: AF BF xx xx)
    PrologueEntry {
        name: "mips32_sw_ra_sp",
        arch: Arch::Mips32,
        pattern: pat![Some(0xAF), Some(0xBF), None, None],
        confidence: Confidence::Medium,
        description: "sw ra,N(sp) — save return address",
    },
    // sw s8, N(sp)  (AKA sw fp,N(sp))
    PrologueEntry {
        name: "mips32_sw_s8_sp",
        arch: Arch::Mips32,
        pattern: pat![Some(0xAF), Some(0xBE), None, None],
        confidence: Confidence::Medium,
        description: "sw s8,N(sp) — save frame pointer",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// MIPS64 patterns (big-endian)
// ─────────────────────────────────────────────────────────────────────────────

static MIPS64_PATTERNS: &[PrologueEntry] = &[
    // daddiu sp,sp,-N  (big-endian: 67 BD FF xx)
    PrologueEntry {
        name: "mips64_daddiu_sp",
        arch: Arch::Mips64,
        pattern: pat![Some(0x67), Some(0xBD), Some(0xFF), None],
        confidence: Confidence::High,
        description: "daddiu sp,sp,-N (MIPS64 big-endian)",
    },
    // sd ra, N(sp)  (big-endian: FF BF xx xx)
    PrologueEntry {
        name: "mips64_sd_ra_sp",
        arch: Arch::Mips64,
        pattern: pat![Some(0xFF), Some(0xBF), None, None],
        confidence: Confidence::Medium,
        description: "sd ra,N(sp)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// RISC-V 32/64 patterns (little-endian)
// ─────────────────────────────────────────────────────────────────────────────

static RISCV_PATTERNS: &[PrologueEntry] = &[
    // addi sp,sp,-N  (little-endian compressed: 01 11 xx xx)
    // addi sp,sp,-N (normal 32-bit):  opcode=0x13, rd=sp(x2), rs1=sp, imm=-N
    // The canonical encoding is: imm[11:0] | rs1 | 000 | rd | 0010011
    // For rd=x2, rs1=x2: bytes = 13 01 01 ?? (ignoring imm bits beyond byte 1)
    PrologueEntry {
        name: "riscv_addi_sp",
        arch: Arch::RiscV64,
        pattern: pat![Some(0x13), Some(0x01), None, None],
        confidence: Confidence::Medium,
        description: "addi sp,sp,-N (RISC-V 32-bit encoding, LE)",
    },
    PrologueEntry {
        name: "riscv32_addi_sp",
        arch: Arch::RiscV32,
        pattern: pat![Some(0x13), Some(0x01), None, None],
        confidence: Confidence::Medium,
        description: "addi sp,sp,-N (RISC-V 32-bit encoding, LE)",
    },
    // sd ra,N(sp) → opcode=0x23, funct3=011, rs1=x2, rs2=x1
    // lower bytes: 23 30 11 xx
    PrologueEntry {
        name: "riscv_sd_ra_sp",
        arch: Arch::RiscV64,
        pattern: pat![Some(0x23), Some(0x30), None, None],
        confidence: Confidence::Medium,
        description: "sd ra,N(sp) (RISC-V 64-bit LE)",
    },
    // C.ADDI16SP (compressed): 01 61 (lower bits vary for imm)
    PrologueEntry {
        name: "riscv_c_addi16sp",
        arch: Arch::RiscV64,
        pattern: pat![Some(0x01), Some(0x61)],
        confidence: Confidence::Low,
        description: "C.ADDI16SP (compressed frame alloc)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// PowerPC 32-bit patterns (big-endian)
// ─────────────────────────────────────────────────────────────────────────────

static PPC32_PATTERNS: &[PrologueEntry] = &[
    // stwu r1,-N(r1)  (big-endian: 94 21 FF xx)
    PrologueEntry {
        name: "ppc32_stwu_r1",
        arch: Arch::Ppc32,
        pattern: pat![Some(0x94), Some(0x21), Some(0xFF), None],
        confidence: Confidence::High,
        description: "stwu r1,-N(r1) (PPC32 frame setup)",
    },
    // mflr r0 → 7C 08 02 A6
    PrologueEntry {
        name: "ppc32_mflr_r0",
        arch: Arch::Ppc32,
        pattern: pat![Some(0x7C), Some(0x08), Some(0x02), Some(0xA6)],
        confidence: Confidence::Medium,
        description: "mflr r0 (save link register)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// PowerPC 64-bit patterns (big-endian)
// ─────────────────────────────────────────────────────────────────────────────

static PPC64_PATTERNS: &[PrologueEntry] = &[
    // stdu r1,-N(r1)  (big-endian: F8 21 FF xx, typically F8 21 80 01 for -128)
    PrologueEntry {
        name: "ppc64_stdu_r1",
        arch: Arch::Ppc64,
        pattern: pat![Some(0xF8), Some(0x21), Some(0xFF), None],
        confidence: Confidence::High,
        description: "stdu r1,-N(r1) (PPC64 frame setup)",
    },
    // mflr r0 → same 4 bytes on 64-bit PPC
    PrologueEntry {
        name: "ppc64_mflr_r0",
        arch: Arch::Ppc64,
        pattern: pat![Some(0x7C), Some(0x08), Some(0x02), Some(0xA6)],
        confidence: Confidence::Medium,
        description: "mflr r0 (save link register, PPC64)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// SPARC 32/64-bit patterns (big-endian)
// ─────────────────────────────────────────────────────────────────────────────

static SPARC_PATTERNS: &[PrologueEntry] = &[
    // save %sp,-N,%sp  (SPARC32/64 big-endian: 9D E3 Bx xx)
    // SAVE encoding: op=10, rd=%sp(14), op3=111100(0x3C), rs1=%sp(14), simm13=-N
    // Bytes: 9D E3 Bx xx (upper byte 0x9D for rd=%sp/op=10, 0xE3 for op3 + rs1 upper bit)
    PrologueEntry {
        name: "sparc_save_sp",
        arch: Arch::Sparc64,
        pattern: pat![Some(0x9D), Some(0xE3), Some(0xBF), None],
        confidence: Confidence::High,
        description: "save %sp,-N,%sp (SPARC64 frame prologue)",
    },
    PrologueEntry {
        name: "sparc32_save_sp",
        arch: Arch::Sparc32,
        pattern: pat![Some(0x9D), Some(0xE3), Some(0xBF), None],
        confidence: Confidence::High,
        description: "save %sp,-N,%sp (SPARC32 frame prologue)",
    },
    // SPARC leaf function: just a retl (may appear as a 2-instruction sequence)
    PrologueEntry {
        name: "sparc_nop",
        arch: Arch::Sparc32,
        pattern: pat![Some(0x01), Some(0x00), Some(0x00), Some(0x00)],
        confidence: Confidence::Low,
        description: "nop (SPARC delay-slot filler / leaf function)",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Matcher — apply patterns from the DB at a given byte offset
// ─────────────────────────────────────────────────────────────────────────────

/// Apply all patterns for `arch` to `bytes` and return the first (most
/// specific) match, or `None` if no pattern matches.
#[must_use]
pub fn match_prologue(arch: Arch, bytes: &[u8]) -> Option<&'static PrologueEntry> {
    PrologueDb::for_arch(arch)
        .into_iter()
        .find(|&entry| entry.matches(bytes))
        .map(|v| v as _)
}

/// Apply all patterns for `arch` to `bytes` and return *all* matching entries.
#[must_use]
pub fn match_all_prologues(arch: Arch, bytes: &[u8]) -> Vec<&'static PrologueEntry> {
    PrologueDb::for_arch(arch)
        .into_iter()
        .filter(|e| e.matches(bytes))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Architecture metadata ─────────────────────────────────────────────

    #[test]
    fn arch_align_x86_is_one() {
        assert_eq!(Arch::X86_64.instruction_align(), 1);
        assert_eq!(Arch::X86_32.instruction_align(), 1);
    }

    #[test]
    fn arch_align_arm64_is_four() {
        assert_eq!(Arch::Arm64.instruction_align(), 4);
    }

    #[test]
    fn arch_align_thumb_is_two() {
        assert_eq!(Arch::Thumb.instruction_align(), 2);
    }

    #[test]
    fn arch_tags_unique() {
        let tags = [
            Arch::X86_64,
            Arch::X86_32,
            Arch::Arm64,
            Arch::Arm32,
            Arch::Thumb,
            Arch::Mips32,
            Arch::Mips64,
            Arch::RiscV32,
            Arch::RiscV64,
            Arch::Ppc32,
            Arch::Ppc64,
            Arch::Sparc32,
            Arch::Sparc64,
        ];
        let tag_strs: std::collections::HashSet<&str> = tags.iter().map(|a| a.tag()).collect();
        assert_eq!(tag_strs.len(), tags.len(), "all arch tags must be unique");
    }

    // ── PatternByte ───────────────────────────────────────────────────────

    #[test]
    fn pattern_byte_exact_matches_correct() {
        assert!(PatternByte::Exact(0x55).matches(0x55));
        assert!(!PatternByte::Exact(0x55).matches(0x56));
    }

    #[test]
    fn pattern_byte_any_matches_all() {
        for b in 0u8..=255 {
            assert!(PatternByte::Any.matches(b));
        }
    }

    // ── PrologueEntry.matches ─────────────────────────────────────────────

    #[test]
    fn entry_matches_exact() {
        let entry = PrologueEntry {
            name: "test",
            arch: Arch::X86_64,
            pattern: pat![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            confidence: Confidence::High,
            description: "test",
        };
        assert!(entry.matches(&[0x55, 0x48, 0x89, 0xE5, 0x90]));
        assert!(!entry.matches(&[0x55, 0x48, 0x89, 0xE6]));
    }

    #[test]
    fn entry_does_not_match_too_short() {
        let entry = PrologueEntry {
            name: "test",
            arch: Arch::X86_64,
            pattern: pat![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            confidence: Confidence::High,
            description: "test",
        };
        assert!(!entry.matches(&[0x55, 0x48]));
    }

    #[test]
    fn entry_wildcard_matches_any_byte() {
        let entry = PrologueEntry {
            name: "test",
            arch: Arch::X86_64,
            pattern: pat![Some(0x48), Some(0x83), Some(0xEC), None],
            confidence: Confidence::Medium,
            description: "test",
        };
        assert!(entry.matches(&[0x48, 0x83, 0xEC, 0x28]));
        assert!(entry.matches(&[0x48, 0x83, 0xEC, 0xFF]));
        assert!(!entry.matches(&[0x48, 0x83, 0xED, 0x28]));
    }

    // ── PrologueDb ────────────────────────────────────────────────────────

    #[test]
    fn db_count_nonzero() {
        assert!(PrologueDb::count() > 0);
    }

    #[test]
    fn db_for_arch_x86_64_nonempty() {
        let entries = PrologueDb::for_arch(Arch::X86_64);
        assert!(!entries.is_empty());
    }

    #[test]
    fn db_for_arch_sorted_longest_first() {
        let entries = PrologueDb::for_arch(Arch::X86_64);
        for w in entries.windows(2) {
            assert!(
                w[0].pattern.len() >= w[1].pattern.len(),
                "patterns should be sorted longest-first"
            );
        }
    }

    #[test]
    fn db_for_arch_arm64_has_stp() {
        let entries = PrologueDb::for_arch(Arch::Arm64);
        assert!(entries.iter().any(|e| e.name.contains("stp")));
    }

    #[test]
    fn db_for_arch_mips32_has_addiu() {
        let entries = PrologueDb::for_arch(Arch::Mips32);
        assert!(entries.iter().any(|e| e.name.contains("addiu")));
    }

    #[test]
    fn db_iter_all_covers_multiple_arches() {
        let arches: std::collections::HashSet<&str> =
            PrologueDb::iter_all().map(|e| e.arch.tag()).collect();
        assert!(arches.len() >= 4, "expected at least 4 architectures in DB");
    }

    // ── match_prologue ────────────────────────────────────────────────────

    #[test]
    fn match_prologue_x86_64_push_rbp() {
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x90];
        let m = match_prologue(Arch::X86_64, &bytes);
        assert!(m.is_some());
        assert!(m.unwrap().name.contains("push_rbp"));
    }

    #[test]
    fn match_prologue_x86_64_prefers_longer() {
        // sub rsp,imm32 match: first 4 bytes are sub rsp imm8 pattern,
        // but with imm32 form the 7-byte pattern should win.
        let bytes = [0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00];
        let m = match_prologue(Arch::X86_64, &bytes);
        assert!(m.is_some());
        // The 7-byte "sub_rsp_imm32" pattern should match.
        assert!(m.unwrap().name.contains("imm32"));
    }

    #[test]
    fn match_prologue_no_match_returns_none() {
        let bytes = [0x00, 0x00, 0x00, 0x00];
        let m = match_prologue(Arch::X86_64, &bytes);
        assert!(m.is_none());
    }

    #[test]
    fn match_prologue_arm64_stp() {
        // stp x29,x30,[sp,#-16]!: bytes = 0xEF 0x7D 0xBF 0xA9 (offset -16 = 0xF0)
        let bytes = [0xF0, 0x7D, 0xBF, 0xA9];
        let m = match_prologue(Arch::Arm64, &bytes);
        assert!(m.is_some());
    }

    #[test]
    fn match_all_prologues_returns_all_matching() {
        // push rbp; mov rbp,rsp — both the 4-byte and longer patterns may match.
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        let all = match_all_prologues(Arch::X86_64, &bytes);
        assert!(
            all.len() >= 2,
            "expected multiple matches for push_rbp + sub_rsp combo"
        );
    }

    // ── Per-arch pattern counts ───────────────────────────────────────────

    #[test]
    fn all_arch_tables_non_empty() {
        for arch in &[
            Arch::X86_64,
            Arch::X86_32,
            Arch::Arm64,
            Arch::Arm32,
            Arch::Thumb,
            Arch::Mips32,
            Arch::Mips64,
            Arch::RiscV64,
            Arch::Ppc32,
            Arch::Ppc64,
            Arch::Sparc64,
        ] {
            assert!(
                !PrologueDb::for_arch(*arch).is_empty(),
                "arch {arch:?} has no patterns"
            );
        }
    }

    #[test]
    fn mips32_addiu_sp_matches() {
        // addiu sp,sp,-16: big-endian = 27 BD FF F0
        let bytes = [0x27, 0xBD, 0xFF, 0xF0];
        let m = match_prologue(Arch::Mips32, &bytes);
        assert!(m.is_some());
        assert!(m.unwrap().name.contains("addiu"));
    }

    #[test]
    fn ppc64_stdu_matches() {
        // stdu r1,-128(r1): F8 21 FF 81
        let bytes = [0xF8, 0x21, 0xFF, 0x81];
        let m = match_prologue(Arch::Ppc64, &bytes);
        assert!(m.is_some());
        assert!(m.unwrap().name.contains("stdu"));
    }

    #[test]
    fn sparc_save_sp_matches() {
        // save %sp,-104,%sp
        let bytes = [0x9D, 0xE3, 0xBF, 0x98];
        let m = match_prologue(Arch::Sparc64, &bytes);
        assert!(m.is_some());
    }

    #[test]
    fn entry_len_is_pattern_len() {
        for entry in PrologueDb::iter_all() {
            assert_eq!(entry.len(), entry.pattern.len());
        }
    }
}
