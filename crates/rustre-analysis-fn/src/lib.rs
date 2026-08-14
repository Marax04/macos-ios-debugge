//! `rustre-analysis-fn`
//!
//! Production-grade function detection for the `RustRE` Suite.
//!
//! This crate locates function boundaries inside raw binary memory by combining
//! three complementary strategies:
//!
//! 1. **Prologue-pattern scanning** — byte-level pattern matching for
//!    architecture-specific function prologues (x86-64, x86-32, ARM64).
//! 2. **CALL-target collection** — linear scan for direct CALL instructions
//!    whose targets are new, previously-unseen addresses.
//! 3. **Gap analysis** — heuristic search for code hidden in alignment padding
//!    between already-known functions.
//!
//! The results are merged, deduplicated, and returned as a [`FunctionBoundarySet`].

pub mod function_classifier;
pub mod function_entropy;
pub mod function_similarity;
pub mod yara_from_function;
pub mod stack_frame_analyzer;
pub mod advanced_function_detection;
pub mod function_clustering;
pub mod function_discovery;
pub mod function_fingerprint;
pub mod function_splitting;
pub mod heuristics;
pub mod prologue_db;
pub mod prologue_scanner;
pub mod recursive_detection;
pub mod strategies;
pub mod function_splitter;
pub mod noreturn_detector;
pub mod function_size_estimator;
pub mod library_propagation;
pub mod callgraph;

/// Shared test-only PRNG step for randomized property tests.
///
/// One definition instead of the nine byte-identical nested `fn xs` copies the
/// crate's test modules used to carry (function_similarity ×4, callgraph,
/// function_fingerprint ×2, recursive_detection ×2). Same algorithm, so no
/// test's random sequence changes.
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xs(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *s = x;
        x
    }
}
pub mod callees;

pub use library_propagation::{LibraryPropagationStats, apply_library_marks};
pub use callgraph::{
    CallGraphSlice, DotOpts, NodeRec, callgraph_from, render_callgraph_dot,
    render_callgraph_dot_styled,
};
pub use callees::{CalleeKind, CalleeRecord, callees};

pub use strategies::{
    CandidateEvidence, ConfidenceLattice, EXTRA_PDATA_MIN_BODY_BYTES, EXTRA_PDATA_MIN_GAP_SIZE,
    ExtraPdataStats, FunctionSymbol, RuntimeFunction, StrategyEngine, StrategyInputs, StrategyKind,
    boundaries_from_pdata, boundaries_from_symbols, find_extra_pdata_funcs, parse_arm_exidx,
    parse_eh_frame_fdes, parse_macho_function_starts, parse_pdata, recursive_descent_x86,
};

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use rustre_core::address::{Address, AddressRange};

// ─────────────────────────────────────────────────────────────────────────────
// Confidence
// ─────────────────────────────────────────────────────────────────────────────

/// How confident the detector is that a given address is a function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Weak heuristic signal; may produce false positives.
    Low = 1,
    /// Moderate evidence (e.g. matched a short prologue pattern).
    Medium = 2,
    /// Strong evidence (e.g. matched a long, distinctive prologue).
    High = 3,
    /// Definitive evidence (e.g. export table or debug symbols).
    Certain = 4,
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionSource
// ─────────────────────────────────────────────────────────────────────────────

/// Records which analysis pass produced a particular [`FunctionBoundary`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectionSource {
    /// Binary entry point reported by the loader.
    EntryPoint,
    /// Address was the target of a CALL instruction.
    CallTarget,
    /// Address matched a known function prologue pattern.
    ProloguePattern,
    /// Address originated from an exception handler / unwind table.
    ExceptionHandler,
    /// Address came from the symbol table, exports, or debug info.
    SymbolTable,
    /// Address matched a FLIRT library signature.
    Flirt,
    /// Address was found via gap analysis between known functions.
    HeuristicGap,
    /// Address was manually added by the user.
    User,
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionBoundary
// ─────────────────────────────────────────────────────────────────────────────

/// A single detected function boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionBoundary {
    /// Inclusive start address of the function.
    pub start: Address,
    /// Exclusive end address of the function body, if known.
    pub end: Option<Address>,
    /// Confidence in this detection.
    pub confidence: Confidence,
    /// Which analysis pass found this boundary.
    pub source: DetectionSource,
    /// Optional name (from symbols / user annotation).
    pub name: Option<String>,
}

impl FunctionBoundary {
    /// Construct a boundary with no end address and no name.
    #[must_use]
    pub const fn new(start: Address, confidence: Confidence, source: DetectionSource) -> Self {
        Self {
            start,
            end: None,
            confidence,
            source,
            name: None,
        }
    }

    /// Attach an end address.
    #[must_use]
    pub const fn with_end(mut self, end: Address) -> Self {
        self.end = Some(end);
        self
    }

    /// Attach a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Estimated byte size of the function body, if both endpoints are known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.end
            .map(|e| e.as_u64().saturating_sub(self.start.as_u64()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySlice
// ─────────────────────────────────────────────────────────────────────────────

/// A thin, address-aware view over a contiguous byte slice.
///
/// All read methods return `None` when the requested address falls outside
/// `[base, base + len)`.
pub struct MemorySlice<'a> {
    /// Virtual address of `bytes[0]`.
    pub base: Address,
    /// Raw bytes of the mapped region.
    pub bytes: &'a [u8],
}

impl<'a> MemorySlice<'a> {
    /// Create a new memory slice with the given base address.
    #[must_use]
    pub const fn new(base: Address, bytes: &'a [u8]) -> Self {
        Self { base, bytes }
    }

    /// Return the byte at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u8(&self, addr: Address) -> Option<u8> {
        let off = self.offset_of(addr)?;
        Some(self.bytes[off])
    }

    /// Return the little-endian `u16` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u16_le(&self, addr: Address) -> Option<u16> {
        let off = self.offset_of(addr)?;
        let s = self.bytes.get(off..off + 2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Return the little-endian `u32` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u32_le(&self, addr: Address) -> Option<u32> {
        let off = self.offset_of(addr)?;
        let s = self.bytes.get(off..off + 4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Return the little-endian `u64` at `addr`, or `None` if out of range.
    ///
    /// # Panics
    ///
    /// This method will never panic in practice: the slice passed to
    /// `from_le_bytes` is always exactly 8 bytes, enforced by the preceding
    /// bounds check.  The `expect` is unreachable.
    #[must_use]
    pub fn read_u64_le(&self, addr: Address) -> Option<u64> {
        let off = self.offset_of(addr)?;
        let s = self.bytes.get(off..off + 8)?;
        Some(u64::from_le_bytes(s.try_into().expect("slice of length 8")))
    }

    /// Return a sub-slice of `len` bytes starting at `addr`, or `None`.
    #[must_use]
    pub fn slice_at(&self, addr: Address, len: usize) -> Option<&[u8]> {
        let off = self.offset_of(addr)?;
        self.bytes.get(off..off + len)
    }

    /// Return `true` if `addr` falls within `[base, base + len)`.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        let base = self.base.as_u64();
        let end = base.saturating_add(self.bytes.len() as u64);
        addr.as_u64() >= base && addr.as_u64() < end
    }

    /// Total number of bytes in the slice.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` when the slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Exclusive end address: `base + len`.
    #[must_use]
    pub const fn end(&self) -> Address {
        Address::new(self.base.as_u64().wrapping_add(self.bytes.len() as u64))
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Convert a virtual address to a byte-slice offset, returning `None` if
    /// the address is outside the slice.
    fn offset_of(&self, addr: Address) -> Option<usize> {
        let base = self.base.as_u64();
        let a = addr.as_u64();
        if a < base {
            return None;
        }
        // Safe: a >= base, so subtraction is exact.
        let off = usize::try_from(a - base).ok()?;
        if off >= self.bytes.len() {
            return None;
        }
        Some(off)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProloguePattern
// ─────────────────────────────────────────────────────────────────────────────

/// A byte-level description of a machine-code function prologue.
///
/// Bytes in the pattern are either concrete (`Some(b)`) or wildcards (`None`).
pub struct ProloguePattern {
    /// Human-readable pattern name.
    pub name: &'static str,
    /// Architecture the pattern applies to.
    pub arch: &'static str,
    /// Pattern bytes; `None` is a wildcard that matches any byte.
    pub bytes: &'static [Option<u8>],
    /// Confidence assigned when this pattern matches.
    pub confidence: Confidence,
}

impl ProloguePattern {
    /// Return `true` if `bytes` (which must be at least `self.min_len()` long)
    /// matches this pattern at offset 0.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        if bytes.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(bytes.iter())
            .all(|(pat, &b)| pat.is_none_or(|p| p == b))
    }

    /// Minimum number of bytes required to attempt a match.
    #[must_use]
    pub const fn min_len(&self) -> usize {
        self.bytes.len()
    }
}

// ── x86-64 patterns ──────────────────────────────────────────────────────────

/// Return all built-in x86-64 prologue patterns, ordered from most specific
/// (highest confidence, longest) to least specific.
#[must_use]
pub fn x86_64_prologue_patterns() -> Vec<ProloguePattern> {
    let mut v = x86_64_frame_patterns();
    v.extend(x86_64_leaf_patterns());
    v
}

fn x86_64_frame_patterns() -> Vec<ProloguePattern> {
    vec![
        // push rbp; mov rbp, rsp  — the classical System-V / MSVC prologue
        ProloguePattern {
            name: "push_rbp_mov_rbp_rsp",
            arch: "x86_64",
            bytes: &[Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            confidence: Confidence::High,
        },
        // push rbp; mov rbp, rsp; push rbx  (common in position-independent code)
        ProloguePattern {
            name: "push_rbp_mov_rbp_rsp_push_rbx",
            arch: "x86_64",
            bytes: &[Some(0x55), Some(0x48), Some(0x89), Some(0xE5), Some(0x53)],
            confidence: Confidence::High,
        },
        // push rbp; mov rbp, rsp; sub rsp, imm8
        ProloguePattern {
            name: "push_rbp_mov_rbp_rsp_sub_rsp_imm8",
            arch: "x86_64",
            bytes: &[
                Some(0x55),
                Some(0x48),
                Some(0x89),
                Some(0xE5),
                Some(0x48),
                Some(0x83),
                Some(0xEC),
                None,
            ],
            confidence: Confidence::High,
        },
        // push rbp; mov rbp, rsp; sub rsp, imm32
        ProloguePattern {
            name: "push_rbp_mov_rbp_rsp_sub_rsp_imm32",
            arch: "x86_64",
            bytes: &[
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
                None,
            ],
            confidence: Confidence::High,
        },
        // endbr64 (CET indirect branch tracking, common in PIE/hardened binaries)
        ProloguePattern {
            name: "endbr64",
            arch: "x86_64",
            bytes: &[Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFA)],
            confidence: Confidence::Medium,
        },
        // endbr64 followed by push rbp
        ProloguePattern {
            name: "endbr64_push_rbp",
            arch: "x86_64",
            bytes: &[Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFA), Some(0x55)],
            confidence: Confidence::High,
        },
    ]
}

fn x86_64_leaf_patterns() -> Vec<ProloguePattern> {
    vec![
        // sub rsp, imm8  (leaf / MSVC fastcall without frame pointer)
        ProloguePattern {
            name: "sub_rsp_imm8",
            arch: "x86_64",
            bytes: &[Some(0x48), Some(0x83), Some(0xEC), None],
            confidence: Confidence::Medium,
        },
        // sub rsp, imm32  (larger stack frame without frame pointer)
        ProloguePattern {
            name: "sub_rsp_imm32",
            arch: "x86_64",
            bytes: &[Some(0x48), Some(0x81), Some(0xEC), None, None, None, None],
            confidence: Confidence::Medium,
        },
        // push r15; push r14; push r13  (callee-saved regs in leaf-ish functions)
        ProloguePattern {
            name: "push_r15_r14_r13",
            arch: "x86_64",
            bytes: &[
                Some(0x41),
                Some(0x57),
                Some(0x41),
                Some(0x56),
                Some(0x41),
                Some(0x55),
            ],
            confidence: Confidence::Medium,
        },
        // push rdi; push rsi; push rbx  (vararg / specialized prologue)
        ProloguePattern {
            name: "push_rdi_rsi_rbx",
            arch: "x86_64",
            bytes: &[Some(0x57), Some(0x56), Some(0x53)],
            confidence: Confidence::Low,
        },
    ]
}

// ── x86-32 patterns ──────────────────────────────────────────────────────────

/// Return all built-in x86-32 prologue patterns.
#[must_use]
pub fn x86_32_prologue_patterns() -> Vec<ProloguePattern> {
    vec![
        // push ebp; mov ebp, esp  — classical cdecl / stdcall prologue
        ProloguePattern {
            name: "push_ebp_mov_ebp_esp",
            arch: "x86_32",
            bytes: &[
                Some(0x55), // push ebp
                Some(0x89),
                Some(0xE5), // mov ebp, esp
            ],
            confidence: Confidence::High,
        },
        // push ebp; mov ebp, esp; push ebx
        ProloguePattern {
            name: "push_ebp_mov_ebp_esp_push_ebx",
            arch: "x86_32",
            bytes: &[
                Some(0x55),
                Some(0x89),
                Some(0xE5),
                Some(0x53), // push ebx
            ],
            confidence: Confidence::High,
        },
        // push ebp; mov ebp, esp; sub esp, imm8
        ProloguePattern {
            name: "push_ebp_mov_ebp_esp_sub_esp_imm8",
            arch: "x86_32",
            bytes: &[
                Some(0x55),
                Some(0x89),
                Some(0xE5),
                Some(0x83),
                Some(0xEC),
                None,
            ],
            confidence: Confidence::High,
        },
        // push ebp; mov ebp, esp; sub esp, imm32
        ProloguePattern {
            name: "push_ebp_mov_ebp_esp_sub_esp_imm32",
            arch: "x86_32",
            bytes: &[
                Some(0x55),
                Some(0x89),
                Some(0xE5),
                Some(0x81),
                Some(0xEC),
                None,
                None,
                None,
                None,
            ],
            confidence: Confidence::High,
        },
        // sub esp, imm8  (small leaf)
        ProloguePattern {
            name: "sub_esp_imm8",
            arch: "x86_32",
            bytes: &[Some(0x83), Some(0xEC), None],
            confidence: Confidence::Medium,
        },
        // push esi; push edi; push ebx
        ProloguePattern {
            name: "push_esi_edi_ebx",
            arch: "x86_32",
            bytes: &[
                Some(0x56), // push esi
                Some(0x57), // push edi
                Some(0x53), // push ebx
            ],
            confidence: Confidence::Low,
        },
        // endbr32 (CET, less common on 32-bit but exists in some hardened builds)
        ProloguePattern {
            name: "endbr32",
            arch: "x86_32",
            bytes: &[Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFB)],
            confidence: Confidence::Medium,
        },
    ]
}

// ── ARM64 patterns ────────────────────────────────────────────────────────────

/// Return all built-in `AArch64` prologue patterns.
///
/// ARM64 instructions are always 4 bytes wide and little-endian encoded on
/// little-endian systems.  Patterns are expressed as little-endian u32 values
/// split into bytes, with wildcards for immediate fields.
#[must_use]
pub fn arm64_prologue_patterns() -> Vec<ProloguePattern> {
    vec![
        // stp x29, x30, [sp, #-N]!  (pre-indexed, common frame prologue)
        // We match the fixed bits with a wildcard for the offset byte.
        ProloguePattern {
            name: "stp_x29_x30_sp_neg",
            arch: "arm64",
            bytes: &[
                None,       // offset byte (varies)
                Some(0x7D), // x29=0b11101, x30=0b11110, partial
                Some(0xBF), // pre-index bit + stack pointer
                Some(0xA9), // major opcode for stp 64-bit
            ],
            confidence: Confidence::High,
        },
        // sub sp, sp, #imm  (frame setup without frame-pointer)
        ProloguePattern {
            name: "sub_sp_sp_imm",
            arch: "arm64",
            bytes: &[
                None,       // imm bits [5:0] + Rd (sp=0x1F)
                None,       // imm bits [11:6]
                Some(0x00), // imm bits upper + shift=0
                Some(0xD1), // SUB 64-bit immediate opcode
            ],
            confidence: Confidence::Medium,
        },
        // pacibsp (pointer authentication, iOS/arm64e)  — encoding: 7F 23 03 D5
        ProloguePattern {
            name: "pacibsp",
            arch: "arm64",
            bytes: &[Some(0x7F), Some(0x23), Some(0x03), Some(0xD5)],
            confidence: Confidence::High,
        },
        // pacisp (alternative pointer auth variant)  — encoding: 5F 24 03 D5
        ProloguePattern {
            name: "pacisp",
            arch: "arm64",
            bytes: &[Some(0x5F), Some(0x24), Some(0x03), Some(0xD5)],
            confidence: Confidence::High,
        },
        // stp x19, x20, [sp, #-N]!  (callee-saved pair, first common variant)
        ProloguePattern {
            name: "stp_x19_x20_sp_neg",
            arch: "arm64",
            bytes: &[
                None,
                Some(0x53), // x19+x20 encoding
                Some(0xBF),
                Some(0xA9),
            ],
            confidence: Confidence::Medium,
        },
        // mov x29, sp  (frame pointer set without stp)  — encoding: FD 03 00 91
        ProloguePattern {
            name: "mov_x29_sp",
            arch: "arm64",
            bytes: &[Some(0xFD), Some(0x03), Some(0x00), Some(0x91)],
            confidence: Confidence::Medium,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectedArch
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture of the binary being analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedArch {
    /// 64-bit x86.
    X86_64,
    /// 32-bit x86.
    X86_32,
    /// `AArch64`.
    Arm64,
    /// Architecture could not be determined.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallTargetCollector
// ─────────────────────────────────────────────────────────────────────────────

/// Scans a memory slice for direct CALL instructions and returns the set of
/// reachable targets, filtered to the configured address range.
pub struct CallTargetCollector {
    /// Architecture being scanned.
    pub arch: DetectedArch,
    /// Minimum valid target address (inclusive).
    pub min_target: Address,
    /// Maximum valid target address (exclusive).
    pub max_target: Address,
}

impl CallTargetCollector {
    /// Create a collector for the given architecture.
    ///
    /// The initial range is `[0, u64::MAX)`, accepting any target address.
    #[must_use]
    pub const fn new(arch: DetectedArch) -> Self {
        Self {
            arch,
            min_target: Address::new(0),
            max_target: Address::new(u64::MAX),
        }
    }

    /// Restrict target addresses to `[min, max)`.
    #[must_use]
    pub const fn with_range(mut self, min: Address, max: Address) -> Self {
        self.min_target = min;
        self.max_target = max;
        self
    }

    /// Scan `mem` and return all discovered CALL target addresses.
    #[must_use]
    pub fn collect(&self, mem: &MemorySlice<'_>) -> Vec<Address> {
        match self.arch {
            DetectedArch::X86_64 | DetectedArch::X86_32 => self.collect_x86_calls(mem),
            DetectedArch::Arm64 => self.collect_arm64_calls(mem),
            DetectedArch::Unknown => {
                // Try x86 heuristics on unknown architecture as a best-effort.
                self.collect_x86_calls(mem)
            }
        }
    }

    /// Scan for x86/x64 `CALL rel32` (`E8 imm32`) instructions.
    ///
    /// Each such instruction is 5 bytes: `E8 lo hi hi hi`.  The 32-bit
    /// signed relative displacement is added to the address of the *next*
    /// instruction (`PC + 5`) to yield the absolute target.
    #[must_use]
    pub fn collect_x86_calls(&self, mem: &MemorySlice<'_>) -> Vec<Address> {
        let mut targets: Vec<Address> = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        // We need at least 5 bytes for a CALL rel32 (opcode + 4-byte disp).
        // The loop body indexes `bytes[i+4]`, which requires `i + 4 < bytes.len()`,
        // i.e. `i < bytes.len() - 4`. Using `saturating_sub(4)` as the strict
        // upper bound (`while i < limit`) yields exactly that condition, and
        // also safely handles `bytes.len() < 4` by producing `limit == 0`.
        let limit = bytes.len().saturating_sub(4);

        let mut i = 0usize;
        while i < limit {
            if bytes[i] == 0xE8 {
                // Read the 32-bit signed displacement (little-endian).
                let disp_i32 =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                // Compute the absolute target via wrapping 64-bit arithmetic so
                // that negative displacements wrap correctly.
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                // Compute target via wrapping signed offset.  We reinterpret
                // next_pc/target as i64/u64 pairs to avoid sign-change lints:
                // i64::from_ne_bytes(next_pc.to_ne_bytes()) + disp == target.
                let next_pc_i64 = i64::from_ne_bytes(next_pc.to_ne_bytes());
                let target_i64 = next_pc_i64.wrapping_add(i64::from(disp_i32));
                let target_raw = u64::from_ne_bytes(target_i64.to_ne_bytes());
                let target = Address::new(target_raw);

                if self.in_range(target) {
                    targets.push(target);
                }
                // Advance past the full instruction.
                i += 5;
            } else {
                i += 1;
            }
        }

        targets.sort_unstable_by_key(|a| a.as_u64());
        targets.dedup();
        targets
    }

    /// Scan for ARM64 BL (branch-and-link) instructions.
    ///
    /// BL encoding (little-endian): bits `[31:26] == 100101`.
    /// The 26-bit signed offset is left-shifted by 2 and added to the PC.
    #[must_use]
    pub fn collect_arm64_calls(&self, mem: &MemorySlice<'_>) -> Vec<Address> {
        let mut targets: Vec<Address> = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        // ARM64 instructions are always 4-byte aligned.
        let limit = bytes.len().saturating_sub(3);
        let mut i = 0usize;

        while i < limit {
            // Only process 4-byte aligned offsets.
            if !i.is_multiple_of(4) {
                i += 1;
                continue;
            }

            let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);

            // BL: opcode = 100101, bits [31:26]
            if (word >> 26) == 0b10_0101 {
                // 26-bit signed offset, sign-extended and left-shifted by 2.
                let imm26 = word & 0x03FF_FFFF;
                // Sign-extend the 26-bit value to i32 via byte reinterpretation
                // to avoid triggering cast_possible_wrap.
                let extended = u32::from_ne_bytes(
                    i32::from_ne_bytes((imm26 << 6).to_ne_bytes())
                        .wrapping_shr(6)
                        .to_ne_bytes(),
                );
                let offset_instr = i32::from_ne_bytes(extended.to_ne_bytes());
                // Byte offset = instruction offset * 4.
                let byte_offset = i64::from(offset_instr) * 4;
                let pc = base.wrapping_add(i as u64);
                // Reinterpret pc as i64 to add a signed byte offset without
                // triggering cast_possible_wrap / cast_sign_loss lints.
                let pc_i64 = i64::from_ne_bytes(pc.to_ne_bytes());
                let target_raw = u64::from_ne_bytes(pc_i64.wrapping_add(byte_offset).to_ne_bytes());
                let target = Address::new(target_raw);

                if self.in_range(target) {
                    targets.push(target);
                }
            }
            i += 4;
        }

        targets.sort_unstable_by_key(|a| a.as_u64());
        targets.dedup();
        targets
    }

    // ── Private ───────────────────────────────────────────────────────────────

    const fn in_range(&self, addr: Address) -> bool {
        addr.as_u64() >= self.min_target.as_u64() && addr.as_u64() < self.max_target.as_u64()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GapAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Finds potential function starts hidden in alignment padding between known
/// functions.
///
/// Alignment padding is typically filled with NOP (`0x90`) or INT3 (`0xCC`)
/// bytes on x86.  A gap that contains something other than these bytes after
/// the padding is a candidate for an additional function entry point.
pub struct GapAnalyzer {
    /// Gaps smaller than this (in bytes) are ignored.
    pub min_gap_size: usize,
    /// The NOP byte for this architecture (0x90 on x86).
    pub nop_byte: u8,
    /// The INT3 / breakpoint padding byte (0xCC on x86).
    pub int3_byte: u8,
}

impl GapAnalyzer {
    /// Create a gap analyser with default x86 settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_gap_size: 8,
            nop_byte: 0x90,
            int3_byte: 0xCC,
        }
    }

    /// Override the NOP byte (useful for non-x86 architectures).
    #[must_use]
    pub const fn with_nop(mut self, nop: u8) -> Self {
        self.nop_byte = nop;
        self
    }

    /// Given a sorted slice of known function start addresses and the overall
    /// code range, return the [`AddressRange`] of every gap that is large enough
    /// to be worth inspecting.
    #[must_use]
    pub fn find_gaps(
        &self,
        known_starts: &[Address],
        code_range: AddressRange,
        _mem: &MemorySlice<'_>,
    ) -> Vec<AddressRange> {
        // We only care about addresses inside code_range.
        let range_start = code_range.start.as_u64();
        let range_end = code_range.end.as_u64();

        // Build a sorted, deduplicated list of boundaries within the code range.
        let mut boundaries: Vec<u64> = known_starts
            .iter()
            .map(|a| a.as_u64())
            .filter(|&a| a >= range_start && a < range_end)
            .collect();
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut gaps = Vec::new();

        // Check the gap between the code range start and the first known function.
        let first = *boundaries.first().unwrap_or(&range_end);
        if first > range_start {
            let gap_len = usize::try_from(first - range_start).unwrap_or(usize::MAX);
            if gap_len >= self.min_gap_size {
                gaps.push(AddressRange::new(
                    Address::new(range_start),
                    Address::new(first),
                ));
            }
        }

        // Check gaps between consecutive known functions.
        for window in boundaries.windows(2) {
            let gap_start = window[0];
            let gap_end = window[1];
            let gap_len = usize::try_from(gap_end.saturating_sub(gap_start)).unwrap_or(usize::MAX);
            if gap_len >= self.min_gap_size {
                gaps.push(AddressRange::new(
                    Address::new(gap_start),
                    Address::new(gap_end),
                ));
            }
        }

        // Check the gap between the last known function and the code range end.
        if let Some(&last) = boundaries.last()
            && last < range_end
        {
            let gap_len = usize::try_from(range_end - last).unwrap_or(usize::MAX);
            if gap_len >= self.min_gap_size {
                gaps.push(AddressRange::new(
                    Address::new(last),
                    Address::new(range_end),
                ));
            }
        }

        // Note: when `boundaries` is empty, the "gap before first known" branch
        // above already emits the entire code range as a single gap (because
        // `first` falls back to `range_end`), so no additional handling is
        // needed here.

        gaps
    }

    /// Within a gap, skip leading NOP/INT3 padding and return the address of
    /// the first byte that could be real code.  Returns `None` if the gap
    /// contains nothing but padding.
    #[must_use]
    pub fn first_code_byte(&self, gap: AddressRange, mem: &MemorySlice<'_>) -> Option<Address> {
        let mut addr = gap.start;
        while gap.contains(addr) {
            let b = mem.read_u8(addr)?;
            if b != self.nop_byte && b != self.int3_byte {
                return Some(addr);
            }
            addr += 1;
        }
        None
    }
}

impl Default for GapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDetector
// ─────────────────────────────────────────────────────────────────────────────

/// The main function-detection engine.
///
/// Combines prologue scanning, CALL-target collection, and gap analysis to
/// produce a comprehensive list of [`FunctionBoundary`] entries.
pub struct FunctionDetector {
    /// Architecture of the binary under analysis.
    pub arch: DetectedArch,
    /// Whether to run the prologue-pattern scan.
    pub enable_prologue_scan: bool,
    /// Whether to run the CALL-target scan.
    pub enable_call_target_scan: bool,
    /// Whether to run the gap analyser.
    pub enable_gap_analysis: bool,
    /// Functions smaller than this many bytes are discarded.
    pub min_function_size: usize,
}

impl FunctionDetector {
    /// Create a detector for the given architecture with all passes enabled.
    #[must_use]
    pub const fn new(arch: DetectedArch) -> Self {
        Self {
            arch,
            enable_prologue_scan: true,
            enable_call_target_scan: true,
            enable_gap_analysis: true,
            min_function_size: 4,
        }
    }

    /// Override the architecture.
    #[must_use]
    pub const fn with_arch(mut self, arch: DetectedArch) -> Self {
        self.arch = arch;
        self
    }

    /// Disable the prologue-pattern scan.
    #[must_use]
    pub const fn disable_prologue_scan(mut self) -> Self {
        self.enable_prologue_scan = false;
        self
    }

    /// Disable the gap analysis pass.
    #[must_use]
    pub const fn disable_gap_analysis(mut self) -> Self {
        self.enable_gap_analysis = false;
        self
    }

    // ── Main entry point ─────────────────────────────────────────────────────

    /// Run all enabled analysis passes over `mem`, merge the results with any
    /// caller-supplied `hints`, and return a deduplicated, sorted list.
    #[must_use]
    pub fn analyze(
        &self,
        mem: &MemorySlice<'_>,
        hints: Vec<FunctionBoundary>,
    ) -> Vec<FunctionBoundary> {
        let mut results = hints;

        if self.enable_prologue_scan {
            results.extend(self.scan_prologues(mem));
        }
        if self.enable_call_target_scan {
            results.extend(self.collect_call_targets(mem));
        }

        // Gap analysis uses the results collected so far.
        if self.enable_gap_analysis {
            let known: Vec<FunctionBoundary> = results.clone();
            results.extend(self.scan_gaps(mem, &known));
        }

        // Estimate end addresses for boundaries that don't have one yet.
        for fb in &mut results {
            if fb.end.is_none() {
                fb.end = self.estimate_end(fb.start, mem);
            }
        }

        let mut merged = self.merge_results(results);

        // Discard suspiciously tiny "functions".
        let min_size = self.min_function_size;
        merged.retain(|fb| {
            fb.end.is_none_or(|e| {
                usize::try_from(e.as_u64().saturating_sub(fb.start.as_u64())).unwrap_or(usize::MAX)
                    >= min_size
            })
        });

        merged
    }

    // ── Per-pass methods ─────────────────────────────────────────────────────

    /// Scan every byte offset of `mem` for known architecture prologues.
    #[must_use]
    pub fn scan_prologues(&self, mem: &MemorySlice<'_>) -> Vec<FunctionBoundary> {
        let patterns = match self.arch {
            DetectedArch::X86_64 => x86_64_prologue_patterns(),
            DetectedArch::X86_32 => x86_32_prologue_patterns(),
            DetectedArch::Arm64 => arm64_prologue_patterns(),
            DetectedArch::Unknown => {
                // Try both x86 variants on unknown architecture.
                let mut p = x86_64_prologue_patterns();
                p.extend(x86_32_prologue_patterns());
                p
            }
        };

        let mut results = Vec::new();

        // For ARM64, instructions are 4-byte aligned; step by 4.
        // For x86, every byte offset is a candidate.
        let step = match self.arch {
            DetectedArch::Arm64 => 4usize,
            _ => 1usize,
        };

        let bytes = mem.bytes;
        let mut offset = 0usize;

        while offset < bytes.len() {
            let candidate = &bytes[offset..];
            for pat in &patterns {
                if candidate.len() >= pat.min_len() && pat.matches(candidate) {
                    let addr = mem.base + offset as u64;
                    results.push(FunctionBoundary::new(
                        addr,
                        pat.confidence,
                        DetectionSource::ProloguePattern,
                    ));
                    // Don't try more patterns for the same offset; take the
                    // first (most specific) match.
                    break;
                }
            }
            offset += step;
        }

        results
    }

    /// Collect all CALL targets visible in `mem`.
    #[must_use]
    pub fn collect_call_targets(&self, mem: &MemorySlice<'_>) -> Vec<FunctionBoundary> {
        let code_range = AddressRange::new(mem.base, mem.end());
        let collector =
            CallTargetCollector::new(self.arch).with_range(code_range.start, code_range.end);

        collector
            .collect(mem)
            .into_iter()
            .map(|addr| {
                FunctionBoundary::new(addr, Confidence::Medium, DetectionSource::CallTarget)
            })
            .collect()
    }

    /// Run gap analysis over `mem` using the already-discovered `known`
    /// boundaries as anchor points.
    #[must_use]
    pub fn scan_gaps(
        &self,
        mem: &MemorySlice<'_>,
        known: &[FunctionBoundary],
    ) -> Vec<FunctionBoundary> {
        let analyzer = GapAnalyzer::new();
        let code_range = AddressRange::new(mem.base, mem.end());

        let known_starts: Vec<Address> = known
            .iter()
            .map(|fb| fb.start)
            .collect();
        let gaps = analyzer.find_gaps(&known_starts, code_range, mem);

        let mut results = Vec::new();
        for gap in gaps {
            if let Some(addr) = analyzer.first_code_byte(gap, mem) {
                results.push(FunctionBoundary::new(
                    addr,
                    Confidence::Low,
                    DetectionSource::HeuristicGap,
                ));
            }
        }
        results
    }

    /// Deduplicate `results` by start address, keeping the entry with the
    /// highest [`Confidence`].  The returned list is sorted by address.
    #[must_use]
    pub fn merge_results(&self, mut results: Vec<FunctionBoundary>) -> Vec<FunctionBoundary> {
        // Sort so that for equal addresses the highest confidence comes first.
        results.sort_by(|a, b| {
            a.start
                .as_u64()
                .cmp(&b.start.as_u64())
                .then_with(|| b.confidence.cmp(&a.confidence))
        });

        // Deduplicate: for each unique start address, keep the first entry
        // (which now has the highest confidence after sorting).
        let mut seen: HashSet<u64> = HashSet::new();
        results.retain(|fb| seen.insert(fb.start.as_u64()));

        results
    }

    /// Estimate the end of a function starting at `start` by scanning forward
    /// for the first `RET` / `RETN` instruction (x86: `C3`, `C2`, `CB`, `CA`)
    /// or an unconditional JMP, then returning the address immediately following
    /// that instruction.
    ///
    /// Returns `None` if no terminator is found within a reasonable distance.
    #[must_use]
    pub fn estimate_end(&self, start: Address, mem: &MemorySlice<'_>) -> Option<Address> {
        const MAX_SCAN: u64 = 4096;

        match self.arch {
            DetectedArch::X86_64 | DetectedArch::X86_32 | DetectedArch::Unknown => {
                Self::estimate_end_x86(start, mem, MAX_SCAN)
            }
            DetectedArch::Arm64 => Self::estimate_end_arm64(start, mem, MAX_SCAN),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn estimate_end_x86(start: Address, mem: &MemorySlice<'_>, max_scan: u64) -> Option<Address> {
        let limit = Address::new(start.as_u64().saturating_add(max_scan));
        let mut addr = start;

        while addr.as_u64() < limit.as_u64() {
            let b = mem.read_u8(addr)?;
            match b {
                // RET near/far (no pop) and HLT — all terminate with 1 byte.
                0xC3 | 0xCB | 0xF4 => return Some(addr + 1),
                // RET near imm16, RET far imm16  (3 bytes total)
                0xC2 | 0xCA => return Some(addr + 3),
                // JMP rel8  (2 bytes)
                0xEB => return Some(addr + 2),
                // JMP rel32  (5 bytes)
                0xE9 => return Some(addr + 5),
                // JMP r/m64 FF /4  (2+ bytes — treat as terminator)
                0xFF => {
                    let modrm = mem.read_u8(addr + 1)?;
                    let reg = (modrm >> 3) & 0x7;
                    if reg == 4 {
                        // JMP r/m — use a conservative 2-byte size
                        return Some(addr + 2);
                    }
                    addr += 1;
                }
                // INT3 padding — treat as implicit end (but not at the very start)
                0xCC if addr.as_u64() > start.as_u64() => return Some(addr),
                _ => {
                    addr += 1;
                }
            }
        }
        None
    }

    fn estimate_end_arm64(start: Address, mem: &MemorySlice<'_>, max_scan: u64) -> Option<Address> {
        let limit = Address::new(start.as_u64().saturating_add(max_scan));
        let mut addr = start;

        while addr.as_u64() + 4 <= limit.as_u64() {
            let word = mem.read_u32_le(addr)?;

            // RET instruction: 0xD65F03C0
            if word == 0xD65F_03C0 {
                return Some(addr + 4);
            }
            // RETAA / RETAB (pointer-auth returns): 0xD65F0BFF / 0xD65F0FFF
            if word == 0xD65F_0BFF || word == 0xD65F_0FFF {
                return Some(addr + 4);
            }
            // B (unconditional branch): bits [31:26] == 000101
            if (word >> 26) == 0b00_0101 {
                return Some(addr + 4);
            }

            addr += 4;
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics about a detection run.
#[derive(Debug, Clone)]
pub struct DetectionStats {
    /// Total number of function boundaries found.
    pub total_found: usize,
    /// Breakdown by detection source.
    pub by_source: HashMap<DetectionSource, usize>,
    /// Breakdown by confidence level.
    pub by_confidence: HashMap<Confidence, usize>,
    /// Number of bytes analysed.
    pub bytes_analyzed: usize,
    /// Wall-clock duration of the analysis in milliseconds.
    pub duration_ms: u64,
}

impl DetectionStats {
    fn compute(functions: &[FunctionBoundary], bytes_analyzed: usize, duration_ms: u64) -> Self {
        let mut by_source: HashMap<DetectionSource, usize> = HashMap::new();
        let mut by_confidence: HashMap<Confidence, usize> = HashMap::new();

        for fb in functions {
            *by_source.entry(fb.source.clone()).or_insert(0) += 1;
            *by_confidence.entry(fb.confidence).or_insert(0) += 1;
        }

        Self {
            total_found: functions.len(),
            by_source,
            by_confidence,
            bytes_analyzed,
            duration_ms,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionBoundarySet
// ─────────────────────────────────────────────────────────────────────────────

/// The result container returned by a complete detection run.
pub struct FunctionBoundarySet {
    /// Detected function boundaries, sorted by address.
    pub functions: Vec<FunctionBoundary>,
    /// Statistics about the run.
    pub stats: DetectionStats,
}

impl FunctionBoundarySet {
    /// Build a set from a pre-sorted list, measuring elapsed time from `start`.
    fn from_timed(functions: Vec<FunctionBoundary>, bytes_analyzed: usize, start: Instant) -> Self {
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let stats = DetectionStats::compute(&functions, bytes_analyzed, duration_ms);
        Self { functions, stats }
    }

    /// Build a set synchronously (used in tests and when timing is irrelevant).
    #[must_use]
    pub fn new(functions: Vec<FunctionBoundary>) -> Self {
        let stats = DetectionStats::compute(&functions, 0, 0);
        Self { functions, stats }
    }

    /// Look up the function boundary that starts at exactly `addr`.
    #[must_use]
    pub fn at(&self, addr: Address) -> Option<&FunctionBoundary> {
        self.functions
            .iter()
            .find(|fb| fb.start.as_u64() == addr.as_u64())
    }

    /// Look up the function boundary that CONTAINS `addr` (start <= addr < end).
    ///
    /// When multiple boundaries overlap, the one with the highest confidence and
    /// nearest start is returned. This enables `decompile.function` and similar
    /// tools to accept any address inside a function, not only the entry.
    #[must_use]
    pub fn containing(&self, addr: Address) -> Option<&FunctionBoundary> {
        let a = addr.as_u64();
        self.functions
            .iter()
            .filter(|fb| {
                let s = fb.start.as_u64();
                let e = fb.end.map_or(u64::MAX, |e| e.as_u64());
                s <= a && a < e
            })
            .max_by(|x, y| {
                // Highest confidence, then closest start (largest start wins for tightest fit).
                x.confidence
                    .cmp(&y.confidence)
                    .then_with(|| x.start.as_u64().cmp(&y.start.as_u64()))
            })
    }

    /// Iterate over all function boundaries.
    pub fn iter(&self) -> impl Iterator<Item = &FunctionBoundary> {
        self.functions.iter()
    }

    /// Iterate over boundaries with [`Confidence::High`] or [`Confidence::Certain`].
    pub fn high_confidence(&self) -> impl Iterator<Item = &FunctionBoundary> {
        self.functions
            .iter()
            .filter(|fb| fb.confidence >= Confidence::High)
    }

    /// Return references to all boundaries, sorted by start address.
    ///
    /// The internal list is already sorted, so this is a zero-copy collect.
    #[must_use]
    pub fn sorted_by_address(&self) -> Vec<&FunctionBoundary> {
        self.functions.iter().collect()
    }

    /// Total number of discovered boundaries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.functions.len()
    }

    /// Number of discovered boundaries that carry a symbolic name.
    #[must_use]
    pub fn named_count(&self) -> usize {
        self.functions.iter().filter(|f| f.name.is_some()).count()
    }

    /// Remove any [`Confidence::Low`] entry whose address range fully contains
    /// at least one [`Confidence::Medium`] (or higher) entry.
    ///
    /// This eliminates the "HeuristicGap over-approximation" pattern where a
    /// large gap candidate at Low confidence subsumes a more precise prologue
    /// match at Medium or above.  The pass is O(n log n) via sorted lookup.
    pub fn remove_low_containing_higher(&mut self) {
        // Collect every Medium+ start address in sorted order for binary search.
        let mut higher_starts: Vec<u64> = self
            .functions
            .iter()
            .filter(|fb| fb.confidence >= Confidence::Medium)
            .map(|fb| fb.start.as_u64())
            .collect();
        higher_starts.sort_unstable();
        higher_starts.dedup();

        self.functions.retain(|fb| {
            // Only filter Low-confidence entries that have a known end.
            if fb.confidence != Confidence::Low {
                return true;
            }
            let end = match fb.end {
                Some(e) => e.as_u64(),
                // No end address known — keep it; cannot determine containment.
                None => return true,
            };
            let start = fb.start.as_u64();
            // Find the first Medium+ address strictly greater than `start`.
            let idx = higher_starts.partition_point(|&h| h <= start);
            // Retain the Low entry only when no such address is below `end`.
            let contained = higher_starts.get(idx).is_some_and(|&h| h < end);
            !contained
        });

        // Recompute stats after the filter.
        self.stats = DetectionStats::compute(
            &self.functions,
            self.stats.bytes_analyzed,
            self.stats.duration_ms,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Detect all function boundaries in `mem` for the given architecture.
///
/// This is the primary public API: it wraps [`FunctionDetector`] and returns a
/// fully-populated [`FunctionBoundarySet`] including timing statistics.
#[must_use]
pub fn detect_functions(arch: DetectedArch, mem: &MemorySlice<'_>) -> FunctionBoundarySet {
    let start = Instant::now();
    let detector = FunctionDetector::new(arch);
    let functions = detector.analyze(mem, Vec::new());
    let mut set = FunctionBoundarySet::from_timed(functions, mem.len(), start);
    set.remove_low_containing_higher();
    set
}

/// Convenience: detect functions over a raw byte slice loaded at `image_base`
/// without forcing callers to construct a [`MemorySlice`] manually.
#[must_use]
pub fn detect_functions_at(
    arch: DetectedArch,
    image_base: u64,
    bytes: &[u8],
) -> FunctionBoundarySet {
    let mem = MemorySlice::new(Address::new(image_base), bytes);
    detect_functions(arch, &mem)
}

/// A single function discovered inside a path-loaded binary.
///
/// Carries a final virtual address (segment.start + intra-segment byte offset)
/// plus the originating [`FunctionBoundary`] so callers can inspect the
/// detection source / confidence.
#[derive(Debug, Clone)]
pub struct DetectedFunction {
    /// Virtual address of the function start.
    pub va: u64,
    /// Optional end address (exclusive).
    pub end_va: Option<u64>,
    /// Detection confidence.
    pub confidence: Confidence,
    /// Which pass discovered the function.
    pub source: DetectionSource,
    /// Optional symbol name.
    pub name: Option<String>,
}

/// Detect functions across every executable segment of a PE binary on disk.
///
/// Reads `path`, parses it as PE, iterates **all** executable segments (sections
/// with `IMAGE_SCN_MEM_EXECUTE`), runs the in-memory detector on each segment's
/// raw bytes using the segment's virtual address as base, and returns a flat
/// vector of [`DetectedFunction`] with properly-rebased VAs.
///
/// `arch` overrides the detected architecture; pass [`DetectedArch::Unknown`]
/// to infer it from the PE machine field.
///
/// # Errors
/// Returns an `io::Error` on file read failure. PE parse failures bubble up as
/// `io::ErrorKind::InvalidData`.
pub fn detect_functions_from_path_segments(
    path: &std::path::Path,
    arch: DetectedArch,
) -> std::io::Result<Vec<DetectedFunction>> {
    let data = std::fs::read(path)?;
    let info = rustre_loader_pe::PeInfo::parse(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let effective_arch = if matches!(arch, DetectedArch::Unknown) {
        match info.machine {
            rustre_loader_pe::Machine::X64 => DetectedArch::X86_64,
            rustre_loader_pe::Machine::X86 => DetectedArch::X86_32,
            rustre_loader_pe::Machine::Arm64 => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        }
    } else {
        arch
    };

    let mut out: Vec<DetectedFunction> = Vec::new();
    for sec in &info.sections {
        if sec.characteristics & 0x2000_0000u32 == 0 {
            continue;
        }
        let raw_start = sec.raw_offset as usize;
        let raw_end = raw_start.saturating_add(sec.raw_size as usize).min(data.len());
        if raw_start >= raw_end {
            continue;
        }
        let bytes = &data[raw_start..raw_end];
        let base = sec.virtual_address;
        let set = detect_functions_at(effective_arch, base, bytes);
        for fb in set.functions {
            out.push(DetectedFunction {
                va: fb.start.as_u64(),
                end_va: fb.end.map(Address::as_u64),
                confidence: fb.confidence,
                source: fb.source,
                name: fb.name,
            });
        }
    }

    // Deduplicate by va, keeping the highest-confidence entry.
    out.sort_by(|a, b| {
        a.va.cmp(&b.va)
            .then_with(|| b.confidence.cmp(&a.confidence))
    });
    out.dedup_by(|a, b| a.va == b.va);
    Ok(out)
}

/// Convenience: load a PE/ELF binary from disk, find the primary code
/// section, infer arch, and run [`detect_functions`] over the section bytes
/// using the section's virtual address as base.
///
/// Returns `(FunctionBoundarySet, DetectedArch, u64 /* image_base */)`.
///
/// # Errors
/// Returns an `io::Error` if the file cannot be read.
pub fn detect_functions_from_path(
    path: &std::path::Path,
) -> std::io::Result<(FunctionBoundarySet, DetectedArch, u64)> {
    let data = std::fs::read(path)?;
    // Try PE first
    if let Ok(info) = rustre_loader_pe::PeInfo::parse(&data) {
        let arch = match info.machine {
            rustre_loader_pe::Machine::X64 => DetectedArch::X86_64,
            rustre_loader_pe::Machine::X86 => DetectedArch::X86_32,
            rustre_loader_pe::Machine::Arm64 => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };
        let image_base = info.image_base;
        // Find the .text / first executable section
        let sec = info.sections.iter().find(|s| {
            s.name.eq_ignore_ascii_case(".text")
                || s.characteristics & 0x2000_0000 != 0 // IMAGE_SCN_MEM_EXECUTE
        });
        if let Some(sec) = sec {
            let start = sec.raw_offset as usize;
            let end = (start + sec.raw_size as usize).min(data.len());
            if start < end {
                let bytes = &data[start..end];
                // SectionInfo.virtual_address already includes image_base
                let base = sec.virtual_address;
                let mut set = detect_functions_at(arch, base, bytes);
                // Authoritative anchors: PE .pdata RUNTIME_FUNCTION entries.
                // These are ground truth for x64/ARM64 PEs and would otherwise
                // be missed for non-prologue / non-call-target leaf functions.
                if !info.exception_functions.is_empty() {
                    let anchors: Vec<RuntimeFunction> = info
                        .exception_functions
                        .iter()
                        .map(|e| RuntimeFunction {
                            begin_rva: e.begin_address,
                            end_rva: e.end_address,
                            unwind_rva: e.unwind_info,
                        })
                        .collect();
                    let pdata_boundaries = boundaries_from_pdata(
                        crate::Address::new(image_base),
                        &anchors,
                    );
                    if !pdata_boundaries.is_empty() {
                        let detector = FunctionDetector::new(arch);
                        let mut merged: Vec<FunctionBoundary> =
                            std::mem::take(&mut set.functions);
                        merged.extend(pdata_boundaries);
                        let merged = detector.merge_results(merged);
                        set = FunctionBoundarySet::new(merged);
                    }
                }
                return Ok((set, arch, image_base));
            }
        }
        // Fall back: scan the whole image with image_base as base
        let set = detect_functions_at(arch, image_base, &data);
        return Ok((set, arch, image_base));
    }
    // Fall back: raw scan as x86_64 starting at 0
    let set = detect_functions_at(DetectedArch::X86_64, 0, &data);
    Ok((set, DetectedArch::X86_64, 0))
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPass implementation
// ─────────────────────────────────────────────────────────────────────────────

/// An [`rustre_analysis::AnalysisPass`] that discovers function boundaries
/// using prologue scanning, call-target analysis, and gap detection.
pub struct FunctionDetectionPass {
    arch: DetectedArch,
}

impl FunctionDetectionPass {
    #[must_use]
    pub const fn new(arch: DetectedArch) -> Self {
        Self { arch }
    }

    #[must_use]
    pub const fn x86_64() -> Self {
        Self::new(DetectedArch::X86_64)
    }
}

impl Default for FunctionDetectionPass {
    fn default() -> Self {
        Self::x86_64()
    }
}

impl std::fmt::Debug for FunctionDetectionPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionDetectionPass")
            .field("arch", &self.arch)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for FunctionDetectionPass {
    fn name(&self) -> &'static str {
        "function_detection"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::LinearSweep
    }

    fn description(&self) -> &'static str {
        "Discovers function boundaries using prologue scanning, call-target analysis, and gap detection"
    }

    fn priority(&self) -> i32 {
        100
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        use std::time::Instant;
        let start = Instant::now();

        let functions_found = {
            let mem_guard = view.mem.read();
            let mut count = 0usize;
            for seg in &mem_guard.segments {
                if !seg
                    .permissions
                    .contains(rustre_core::permissions::Permissions::EXECUTE)
                {
                    continue;
                }
                let slice = MemorySlice::new(seg.range.start, &seg.data);
                let result = detect_functions(self.arch, &slice);
                count += result.functions.len();
            }
            drop(mem_guard);
            count
        };

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(rustre_analysis::AnalysisResult {
            kind: self.kind(),
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms,
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemorySlice ───────────────────────────────────────────────────────────

    #[test]
    fn memory_slice_read_u8_in_bounds() {
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        let mem = MemorySlice::new(Address::new(0x1000), &data);
        assert_eq!(mem.read_u8(Address::new(0x1000)), Some(0xAA));
        assert_eq!(mem.read_u8(Address::new(0x1003)), Some(0xDD));
    }

    #[test]
    fn memory_slice_read_u8_out_of_bounds() {
        let data = [0x01, 0x02];
        let mem = MemorySlice::new(Address::new(0x2000), &data);
        // Address before base
        assert_eq!(mem.read_u8(Address::new(0x1FFF)), None);
        // Address at or past end
        assert_eq!(mem.read_u8(Address::new(0x2002)), None);
    }

    #[test]
    fn memory_slice_read_u16_le() {
        let data = [0x34, 0x12]; // LE 0x1234
        let mem = MemorySlice::new(Address::new(0x0), &data);
        assert_eq!(mem.read_u16_le(Address::new(0x0)), Some(0x1234));
        // Not enough bytes for u16
        assert_eq!(mem.read_u16_le(Address::new(0x1)), None);
    }

    #[test]
    fn memory_slice_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12]; // LE 0x12345678
        let mem = MemorySlice::new(Address::new(0x0), &data);
        assert_eq!(mem.read_u32_le(Address::new(0x0)), Some(0x1234_5678));
    }

    #[test]
    fn memory_slice_read_u64_le() {
        let data: [u8; 8] = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let mem = MemorySlice::new(Address::new(0x0), &data);
        assert_eq!(
            mem.read_u64_le(Address::new(0x0)),
            Some(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn memory_slice_slice_at() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mem = MemorySlice::new(Address::new(0x100), &data);
        assert_eq!(
            mem.slice_at(Address::new(0x101), 2),
            Some([0xAD, 0xBE].as_slice())
        );
        // Out-of-bounds slice
        assert_eq!(mem.slice_at(Address::new(0x103), 2), None);
    }

    #[test]
    fn memory_slice_contains_and_end() {
        let data = [0u8; 16];
        let mem = MemorySlice::new(Address::new(0x4000), &data);
        assert!(mem.contains(Address::new(0x4000)));
        assert!(mem.contains(Address::new(0x400F)));
        assert!(!mem.contains(Address::new(0x4010)));
        assert!(!mem.contains(Address::new(0x3FFF)));
        assert_eq!(mem.end(), Address::new(0x4010));
    }

    // ── ProloguePattern ───────────────────────────────────────────────────────

    #[test]
    fn prologue_pattern_matches_exact() {
        let pat = ProloguePattern {
            name: "test",
            arch: "x86_64",
            bytes: &[Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            confidence: Confidence::High,
        };
        assert!(pat.matches(&[0x55, 0x48, 0x89, 0xE5, 0x90]));
        assert!(!pat.matches(&[0x55, 0x48, 0x89, 0xE6, 0x90]));
    }

    #[test]
    fn prologue_pattern_matches_with_wildcard() {
        let pat = ProloguePattern {
            name: "wildcard_test",
            arch: "x86_64",
            bytes: &[Some(0x48), Some(0x83), Some(0xEC), None],
            confidence: Confidence::Medium,
        };
        // Wildcard allows any value for the last byte.
        assert!(pat.matches(&[0x48, 0x83, 0xEC, 0x28]));
        assert!(pat.matches(&[0x48, 0x83, 0xEC, 0xFF]));
        assert!(!pat.matches(&[0x48, 0x83, 0xED, 0x28]));
    }

    #[test]
    fn prologue_pattern_too_short() {
        let pat = ProloguePattern {
            name: "short_test",
            arch: "x86_64",
            bytes: &[Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            confidence: Confidence::High,
        };
        // Input shorter than the pattern must not match.
        assert!(!pat.matches(&[0x55, 0x48]));
        assert!(!pat.matches(&[]));
    }

    #[test]
    fn x86_64_prologue_patterns_non_empty() {
        let patterns = x86_64_prologue_patterns();
        assert!(!patterns.is_empty(), "expected at least one x86-64 pattern");
        // All patterns must cover at least 3 bytes.
        for p in &patterns {
            assert!(p.min_len() >= 3, "pattern '{}' too short", p.name);
        }
    }

    #[test]
    fn x86_32_prologue_patterns_non_empty() {
        let patterns = x86_32_prologue_patterns();
        assert!(!patterns.is_empty(), "expected at least one x86-32 pattern");
    }

    #[test]
    fn arm64_prologue_patterns_non_empty() {
        let patterns = arm64_prologue_patterns();
        assert!(!patterns.is_empty(), "expected at least one arm64 pattern");
    }

    // ── CallTargetCollector ───────────────────────────────────────────────────

    #[test]
    fn call_target_collector_x86_basic() {
        // Layout (base = 0x1000):
        //   0x1000: E8 05 00 00 00  CALL  → next_pc=0x1005, target=0x100A
        //   0x1005: 90 90 90 90 90  (5 NOPs)
        //   0x100A: E8 00 00 00 00  CALL  → next_pc=0x100F, target=0x100F
        let mut code = vec![0x90u8; 16];
        code[0] = 0xE8;
        code[1] = 0x05;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;
        code[10] = 0xE8;
        code[11] = 0x00;
        code[12] = 0x00;
        code[13] = 0x00;
        code[14] = 0x00;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let collector = CallTargetCollector::new(DetectedArch::X86_64)
            .with_range(Address::new(0x1000), Address::new(0x2000));
        let targets = collector.collect_x86_calls(&mem);

        assert!(
            targets.contains(&Address::new(0x100A)),
            "expected 0x100A in {targets:?}"
        );
        assert!(
            targets.contains(&Address::new(0x100F)),
            "expected 0x100F in {targets:?}"
        );
    }

    #[test]
    fn call_target_collector_respects_range() {
        // A CALL pointing outside the allowed range must be filtered out.
        let disp: i32 = 0x7FFF_0000u32 as i32;
        let disp_bytes = disp.to_le_bytes();
        let mut code = vec![0x90u8; 16];
        code[0] = 0xE8;
        code[1] = disp_bytes[0];
        code[2] = disp_bytes[1];
        code[3] = disp_bytes[2];
        code[4] = disp_bytes[3];

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let collector = CallTargetCollector::new(DetectedArch::X86_64)
            .with_range(Address::new(0x1000), Address::new(0x2000));
        let targets = collector.collect_x86_calls(&mem);
        assert!(targets.is_empty(), "out-of-range target should be filtered");
    }

    // ── GapAnalyzer ───────────────────────────────────────────────────────────

    #[test]
    fn gap_analyzer_find_gaps_basic() {
        // Code range [0x1000, 0x2000), known functions at 0x1000, 0x1500.
        // There should be a gap between 0x1500 and 0x2000.
        let data = vec![0u8; 0x1000];
        let mem = MemorySlice::new(Address::new(0x1000), &data);
        let known = vec![Address::new(0x1000), Address::new(0x1500)];
        let code_range = AddressRange::new(Address::new(0x1000), Address::new(0x2000));

        let analyzer = GapAnalyzer::new();
        let gaps = analyzer.find_gaps(&known, code_range, &mem);

        let trailing = gaps
            .iter()
            .any(|g| g.start.as_u64() == 0x1500 && g.end.as_u64() == 0x2000);
        assert!(trailing, "expected trailing gap [0x1500,0x2000): {gaps:?}");
    }

    #[test]
    fn gap_analyzer_no_gaps_when_tight() {
        let data = vec![0u8; 4];
        let mem = MemorySlice::new(Address::new(0x1000), &data);
        let known = vec![Address::new(0x1000), Address::new(0x1004)];
        let code_range = AddressRange::new(Address::new(0x1000), Address::new(0x1004));

        let analyzer = GapAnalyzer {
            min_gap_size: 8,
            nop_byte: 0x90,
            int3_byte: 0xCC,
        };
        let gaps = analyzer.find_gaps(&known, code_range, &mem);
        // Any returned gap must be >= min_gap_size.
        for g in &gaps {
            assert!(
                g.len() >= 8,
                "gap smaller than min_gap_size returned: {g:?}"
            );
        }
    }

    #[test]
    fn gap_analyzer_first_code_byte_skips_nops() {
        let mut data = vec![0x90u8; 8]; // 8 NOPs
        data.push(0x55); // push rbp
        data.extend_from_slice(&[0x48, 0x89, 0xE5]);

        let mem = MemorySlice::new(Address::new(0x2000), &data);
        let gap = AddressRange::new(Address::new(0x2000), Address::new(0x200B));
        let analyzer = GapAnalyzer::new();

        let first = analyzer.first_code_byte(gap, &mem);
        assert_eq!(
            first,
            Some(Address::new(0x2008)),
            "expected first non-NOP at 0x2008"
        );
    }

    #[test]
    fn gap_analyzer_first_code_byte_all_nops_returns_none() {
        let data = vec![0x90u8; 16];
        let mem = MemorySlice::new(Address::new(0x3000), &data);
        let gap = AddressRange::new(Address::new(0x3000), Address::new(0x3010));
        let analyzer = GapAnalyzer::new();
        assert_eq!(analyzer.first_code_byte(gap, &mem), None);
    }

    // ── FunctionDetector ─────────────────────────────────────────────────────

    #[test]
    fn function_detector_scan_prologues_x64() {
        let mut code = vec![0x90u8; 0x20];
        code[0x10] = 0x55;
        code[0x11] = 0x48;
        code[0x12] = 0x89;
        code[0x13] = 0xE5;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let detector = FunctionDetector::new(DetectedArch::X86_64);
        let hits = detector.scan_prologues(&mem);

        let found = hits.iter().any(|fb| fb.start == Address::new(0x1010));
        assert!(found, "expected prologue hit at 0x1010, got: {hits:?}");
    }

    #[test]
    fn function_detector_collect_call_targets() {
        // CALL rel32 at offset 0: next_pc=0x1005, disp=0x05 → target=0x100A
        let mut code = vec![0x90u8; 32];
        code[0] = 0xE8;
        code[1] = 0x05;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let detector = FunctionDetector::new(DetectedArch::X86_64);
        let results = detector.collect_call_targets(&mem);

        let target = Address::new(0x100A);
        assert!(
            results.iter().any(|fb| fb.start == target),
            "expected call target at 0x100A, got: {results:?}"
        );
    }

    #[test]
    fn function_detector_merge_results_deduplicates() {
        let detector = FunctionDetector::new(DetectedArch::X86_64);

        let addr = Address::new(0x4000);
        let a = FunctionBoundary::new(addr, Confidence::Low, DetectionSource::HeuristicGap);
        let b = FunctionBoundary::new(addr, Confidence::High, DetectionSource::ProloguePattern);
        let c = FunctionBoundary::new(
            Address::new(0x5000),
            Confidence::Medium,
            DetectionSource::CallTarget,
        );

        let merged = detector.merge_results(vec![a, b, c]);
        assert_eq!(merged.len(), 2, "expected 2 unique addresses");

        let at_4000 = merged.iter().find(|fb| fb.start == addr).unwrap();
        assert_eq!(at_4000.confidence, Confidence::High);
    }

    #[test]
    fn function_detector_analyze_integrates_all() {
        let mut code = vec![0x90u8; 0x40];
        // Prologue at 0
        code[0] = 0x55;
        code[1] = 0x48;
        code[2] = 0x89;
        code[3] = 0xE5;
        code[8] = 0xC3; // RET

        // CALL at offset 0x10 → target = 0x1030
        // next_pc = 0x1015, disp = 0x001B → target = 0x1030
        let disp: i32 = 0x001B;
        let db = disp.to_le_bytes();
        code[0x10] = 0xE8;
        code[0x11] = db[0];
        code[0x12] = db[1];
        code[0x13] = db[2];
        code[0x14] = db[3];

        // Prologue at 0x30
        code[0x30] = 0x55;
        code[0x31] = 0x48;
        code[0x32] = 0x89;
        code[0x33] = 0xE5;
        code[0x38] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let detector = FunctionDetector::new(DetectedArch::X86_64).disable_gap_analysis();
        let results = detector.analyze(&mem, Vec::new());

        assert!(
            results.iter().any(|fb| fb.start == Address::new(0x1000)),
            "missing 0x1000"
        );
        assert!(
            results.iter().any(|fb| fb.start == Address::new(0x1030)),
            "missing 0x1030: {results:?}"
        );
    }

    // ── FunctionBoundarySet ───────────────────────────────────────────────────

    #[test]
    fn function_boundary_set_high_confidence_filter() {
        let boundaries = vec![
            FunctionBoundary::new(
                Address::new(0x1000),
                Confidence::Low,
                DetectionSource::HeuristicGap,
            ),
            FunctionBoundary::new(
                Address::new(0x2000),
                Confidence::Medium,
                DetectionSource::CallTarget,
            ),
            FunctionBoundary::new(
                Address::new(0x3000),
                Confidence::High,
                DetectionSource::ProloguePattern,
            ),
            FunctionBoundary::new(
                Address::new(0x4000),
                Confidence::Certain,
                DetectionSource::SymbolTable,
            ),
        ];

        let set = FunctionBoundarySet::new(boundaries);
        let high: Vec<_> = set.high_confidence().collect();

        assert_eq!(high.len(), 2);
        assert!(high.iter().all(|fb| fb.confidence >= Confidence::High));
    }

    #[test]
    fn function_boundary_set_at_lookup() {
        let boundaries = vec![FunctionBoundary::new(
            Address::new(0xDEAD),
            Confidence::Certain,
            DetectionSource::User,
        )];
        let set = FunctionBoundarySet::new(boundaries);
        assert!(set.at(Address::new(0xDEAD)).is_some());
        assert!(set.at(Address::new(0xBEEF)).is_none());
    }

    #[test]
    fn function_boundary_set_stats_computed() {
        let boundaries = vec![
            FunctionBoundary::new(
                Address::new(0x1000),
                Confidence::High,
                DetectionSource::ProloguePattern,
            ),
            FunctionBoundary::new(
                Address::new(0x2000),
                Confidence::Medium,
                DetectionSource::CallTarget,
            ),
            FunctionBoundary::new(
                Address::new(0x3000),
                Confidence::High,
                DetectionSource::ProloguePattern,
            ),
        ];
        let set = FunctionBoundarySet::new(boundaries);
        assert_eq!(set.stats.total_found, 3);
        assert_eq!(set.stats.by_confidence[&Confidence::High], 2);
        assert_eq!(set.stats.by_confidence[&Confidence::Medium], 1);
        assert_eq!(set.stats.by_source[&DetectionSource::ProloguePattern], 2);
        assert_eq!(set.stats.by_source[&DetectionSource::CallTarget], 1);
    }

    // ── Confidence ordering ───────────────────────────────────────────────────

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
        assert!(Confidence::High < Confidence::Certain);
        assert_eq!(Confidence::Certain, Confidence::Certain);
    }

    // ── DetectionSource equality ──────────────────────────────────────────────

    #[test]
    fn detection_source_equality() {
        assert_eq!(DetectionSource::CallTarget, DetectionSource::CallTarget);
        assert_ne!(
            DetectionSource::CallTarget,
            DetectionSource::ProloguePattern
        );
        assert_eq!(DetectionSource::User, DetectionSource::User);
        assert_ne!(DetectionSource::SymbolTable, DetectionSource::Flirt);
    }

    // ── detect_functions convenience ─────────────────────────────────────────

    #[test]
    fn detect_functions_returns_set_with_stats() {
        let mut code = vec![0x90u8; 32];
        code[0] = 0x55;
        code[1] = 0x48;
        code[2] = 0x89;
        code[3] = 0xE5;
        code[16] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x5000), &code);
        let set = detect_functions(DetectedArch::X86_64, &mem);

        assert!(set.count() > 0, "expected at least one function");
        assert_eq!(set.stats.bytes_analyzed, 32);
        let _ = set.stats.duration_ms;
    }

    #[test]
    fn detected_function_struct_basic() {
        let f = DetectedFunction {
            va: 0x1400,
            end_va: Some(0x1410),
            confidence: Confidence::High,
            source: DetectionSource::ProloguePattern,
            name: None,
        };
        assert_eq!(f.va, 0x1400);
        assert_eq!(f.end_va, Some(0x1410));
        assert_eq!(f.confidence, Confidence::High);
    }
}
