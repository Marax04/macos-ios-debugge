//! `register_context` — Register context management for a debugged thread.
//!
//! Stores and formats CPU register state for x86-64, ARM64, x86 (32-bit),
//! and ARM (32-bit) targets.
//!
//! Key types: [`RegisterContext`], [`RegisterSet`], [`RegValue`],
//! [`format_registers`]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;
use zeroize::Zeroize;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by register context operations.
#[derive(Debug, thiserror::Error)]
pub enum RegError {
    #[error("register '{0}' not found in this context")]
    NotFound(String),
    #[error("register '{name}' has wrong width (expected {expected}, got {got})")]
    WidthMismatch { name: String, expected: u8, got: u8 },
    #[error("invalid register value: {0}")]
    InvalidValue(String),
}

// ─── Architecture ─────────────────────────────────────────────────────────────

/// CPU architecture that determines the register set layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86_64,
    X86,
    Arm64,
    Arm32,
    Mips32,
    Mips64,
    Riscv32,
    Riscv64,
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86-64"),
            Self::X86 => write!(f, "x86"),
            Self::Arm64 => write!(f, "AArch64"),
            Self::Arm32 => write!(f, "ARM"),
            Self::Mips32 => write!(f, "MIPS32"),
            Self::Mips64 => write!(f, "MIPS64"),
            Self::Riscv32 => write!(f, "RISC-V 32"),
            Self::Riscv64 => write!(f, "RISC-V 64"),
        }
    }
}

impl Architecture {
    /// Width of general-purpose registers in bits.
    #[must_use]
    pub const fn gpr_bits(self) -> u8 {
        match self {
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::Riscv64 => 64,
            Self::X86 | Self::Arm32 | Self::Mips32 | Self::Riscv32 => 32,
        }
    }
}

// ─── RegValue ─────────────────────────────────────────────────────────────────

/// The value stored in a register.
///
/// Implements [`Zeroize`] so that register snapshots containing potentially
/// sensitive data (passwords, keys found in registers) can be cleared before
/// the memory is freed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

impl Zeroize for RegValue {
    fn zeroize(&mut self) {
        *self = Self::U64(0);
    }
}

impl RegValue {
    /// Extract as a 64-bit value (zero-extending narrower types).
    #[must_use]
    pub fn as_u64(self) -> u64 {
        match self {
            Self::U8(v) => u64::from_le_bytes([v, 0, 0, 0, 0, 0, 0, 0]),
            Self::U16(v) => { let b = v.to_le_bytes(); u64::from_le_bytes([b[0], b[1], 0, 0, 0, 0, 0, 0]) }
            Self::U32(v) => { let b = v.to_le_bytes(); u64::from_le_bytes([b[0], b[1], b[2], b[3], 0, 0, 0, 0]) }
            Self::U64(v) => v,
            Self::U128(v) => u64::try_from(v).unwrap_or(u64::MAX),
        }
    }

    /// Width in bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::U8(_) => 8,
            Self::U16(_) => 16,
            Self::U32(_) => 32,
            Self::U64(_) => 64,
            Self::U128(_) => 128,
        }
    }

    /// Hex string representation, zero-padded to the natural width.
    #[must_use]
    pub fn hex_str(self) -> String {
        match self {
            Self::U8(v) => format!("{v:02X}"),
            Self::U16(v) => format!("{v:04X}"),
            Self::U32(v) => format!("{v:08X}"),
            Self::U64(v) => format!("{v:016X}"),
            Self::U128(v) => format!("{v:032X}"),
        }
    }
}

impl fmt::Display for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex_str())
    }
}

// ─── RegMeta ──────────────────────────────────────────────────────────────────

/// Metadata about a single register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegMeta {
    /// Canonical name (e.g. `"rax"`, `"x0"`, `"eax"`).
    pub name: String,
    /// Aliases (e.g. `"ax"`, `"al"`, `"ah"` for `"rax"`).
    pub aliases: Vec<String>,
    /// Width in bits.
    pub bits: u8,
    /// Human-readable description.
    pub description: String,
}

impl RegMeta {
    fn new(name: &str, bits: u8, description: &str) -> Self {
        Self {
            name: name.to_string(),
            aliases: Vec::new(),
            bits,
            description: description.to_string(),
        }
    }

    fn with_aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(ToString::to_string).collect();
        self
    }
}

// ─── RegisterSet ──────────────────────────────────────────────────────────────

/// A description of all registers for a given architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSet {
    pub arch: Architecture,
    pub registers: Vec<RegMeta>,
}

impl RegisterSet {
    /// Build the register set for the given architecture.
    #[must_use]
    pub fn for_arch(arch: Architecture) -> Self {
        let regs = match arch {
            Architecture::X86_64 => Self::x86_64_regs(),
            Architecture::X86 => Self::x86_regs(),
            Architecture::Arm64 => Self::arm64_regs(),
            Architecture::Arm32 => Self::arm32_regs(),
            Architecture::Mips32 | Architecture::Mips64 => Self::mips_regs(arch),
            Architecture::Riscv32 | Architecture::Riscv64 => Self::riscv_regs(arch),
        };
        Self { arch, registers: regs }
    }

    /// Look up register metadata by name (including aliases).
    ///
    /// The metadata returned for an ALIAS is the parent's, so `bits` is the
    /// parent's width — 64 for `al`. Use [`Self::width_bits`] when the question
    /// is how wide the named register actually is.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&RegMeta> {
        let lc = name.to_lowercase();
        self.registers
            .iter()
            .find(|r| r.name == lc || r.aliases.iter().any(|a| a == &lc))
    }

    /// Width in bits of the register `name` NAMES, not of the register it
    /// lives inside.
    ///
    /// `find("al")` returns `rax`'s metadata, whose `bits` is 64: correct as
    /// "which register is this part of", wrong as "how wide is `al`". A caller
    /// formatting or masking a sub-register by that number reads eight bytes
    /// where one was asked for — the same defect corrected in the condition
    /// evaluator in iteration 450, in a second table that answers the same
    /// question.
    ///
    /// Delegates to [`crate::sub_register_of`] so the two tables cannot drift:
    /// there is one answer to "how wide is `r12b`", not one per module.
    #[must_use]
    pub fn width_bits(&self, name: &str) -> Option<u32> {
        let lc = name.to_lowercase();
        // An exact register of this architecture answers with its own width.
        if let Some(meta) = self.registers.iter().find(|r| r.name == lc) {
            return Some(u32::from(meta.bits));
        }
        // Otherwise it may be a sub-register: the shared table knows its width,
        // and the parent must be a register of THIS architecture.
        if let Some((parent, _shift, mask)) = crate::sub_register_of(&lc)
            && self.registers.iter().any(|r| r.name == parent) {
                return Some(mask.count_ones());
            }
        // Finally, an alias this table lists but the shared one does not model
        // (segment aliases, `flags`) keeps the parent's width.
        self.find(&lc).map(|m| u32::from(m.bits))
    }

    fn x86_64_regs() -> Vec<RegMeta> {
        vec![
            RegMeta::new("rax", 64, "Accumulator").with_aliases(&["eax", "ax", "al", "ah"]),
            RegMeta::new("rbx", 64, "Base").with_aliases(&["ebx", "bx", "bl", "bh"]),
            RegMeta::new("rcx", 64, "Counter").with_aliases(&["ecx", "cx", "cl", "ch"]),
            RegMeta::new("rdx", 64, "Data").with_aliases(&["edx", "dx", "dl", "dh"]),
            RegMeta::new("rsi", 64, "Source Index").with_aliases(&["esi", "si", "sil"]),
            RegMeta::new("rdi", 64, "Destination Index").with_aliases(&["edi", "di", "dil"]),
            RegMeta::new("rbp", 64, "Base Pointer").with_aliases(&["ebp", "bp", "bpl"]),
            RegMeta::new("rsp", 64, "Stack Pointer").with_aliases(&["esp", "sp", "spl"]),
            RegMeta::new("rip", 64, "Instruction Pointer").with_aliases(&["eip", "ip"]),
            RegMeta::new("r8", 64, "General Purpose 8").with_aliases(&["r8d", "r8w", "r8b"]),
            RegMeta::new("r9", 64, "General Purpose 9").with_aliases(&["r9d", "r9w", "r9b"]),
            RegMeta::new("r10", 64, "General Purpose 10").with_aliases(&["r10d", "r10w", "r10b"]),
            RegMeta::new("r11", 64, "General Purpose 11").with_aliases(&["r11d", "r11w", "r11b"]),
            RegMeta::new("r12", 64, "General Purpose 12").with_aliases(&["r12d", "r12w", "r12b"]),
            RegMeta::new("r13", 64, "General Purpose 13").with_aliases(&["r13d", "r13w", "r13b"]),
            RegMeta::new("r14", 64, "General Purpose 14").with_aliases(&["r14d", "r14w", "r14b"]),
            RegMeta::new("r15", 64, "General Purpose 15").with_aliases(&["r15d", "r15w", "r15b"]),
            RegMeta::new("rflags", 64, "Flags register").with_aliases(&["eflags", "flags"]),
            RegMeta::new("cs", 16, "Code Segment"),
            RegMeta::new("ss", 16, "Stack Segment"),
            RegMeta::new("ds", 16, "Data Segment"),
            RegMeta::new("es", 16, "Extra Segment"),
            RegMeta::new("fs", 16, "FS Segment"),
            RegMeta::new("gs", 16, "GS Segment"),
        ]
    }

    fn x86_regs() -> Vec<RegMeta> {
        vec![
            RegMeta::new("eax", 32, "Accumulator").with_aliases(&["ax", "al", "ah"]),
            RegMeta::new("ebx", 32, "Base").with_aliases(&["bx", "bl", "bh"]),
            RegMeta::new("ecx", 32, "Counter").with_aliases(&["cx", "cl", "ch"]),
            RegMeta::new("edx", 32, "Data").with_aliases(&["dx", "dl", "dh"]),
            RegMeta::new("esi", 32, "Source Index").with_aliases(&["si"]),
            RegMeta::new("edi", 32, "Destination Index").with_aliases(&["di"]),
            RegMeta::new("ebp", 32, "Base Pointer").with_aliases(&["bp"]),
            RegMeta::new("esp", 32, "Stack Pointer").with_aliases(&["sp"]),
            RegMeta::new("eip", 32, "Instruction Pointer").with_aliases(&["ip"]),
            RegMeta::new("eflags", 32, "Flags").with_aliases(&["flags"]),
            RegMeta::new("cs", 16, "Code Segment"),
            RegMeta::new("ss", 16, "Stack Segment"),
            RegMeta::new("ds", 16, "Data Segment"),
            RegMeta::new("es", 16, "Extra Segment"),
            RegMeta::new("fs", 16, "FS Segment"),
            RegMeta::new("gs", 16, "GS Segment"),
        ]
    }

    fn arm64_regs() -> Vec<RegMeta> {
        // x0-x28 only: x29 and x30 are not separate registers, they are the
        // frame pointer and the link register. Generating them here as well
        // would give each of those two physical registers a second, independent
        // entry — `find` scans in order, so `x30` and `lr` would resolve to
        // different keys and a context could hold two disagreeing values for
        // one register.
        // `w<n>` is the low 32 bits of `x<n>` — a name a user writes as
        // readily as `eax` on x86, and one the condition evaluator already
        // resolves. It was missing from this table entirely, so the same name
        // existed on one path and not the other.
        let mut regs: Vec<RegMeta> = (0..=28)
            .map(|i| {
                RegMeta::new(&format!("x{i}"), 64, &format!("General Purpose x{i}"))
                    .with_aliases(&[&format!("w{i}")])
            })
            .collect();
        regs.push(RegMeta::new("sp", 64, "Stack Pointer"));
        regs.push(RegMeta::new("pc", 64, "Program Counter"));
        regs.push(RegMeta::new("xzr", 64, "Zero Register"));
        // `w30`/`w29` name the low halves of the link and frame pointers, and
        // belong to the SAME entry as `x30`/`x29` so one physical register
        // cannot end up with two disagreeing keys (see the note above).
        regs.push(RegMeta::new("lr", 64, "Link Register").with_aliases(&["x30", "w30"]));
        regs.push(RegMeta::new("fp", 64, "Frame Pointer").with_aliases(&["x29", "w29"]));
        // `cpsr` is the SAME physical register under its other name — it is
        // what `ARM64_NT_CONTEXT` calls the field, so the minidump parser
        // inserts registers under that key, while this table only knew
        // `pstate`. Asking for `cpsr` here found nothing and asking for
        // `pstate` on a parsed arm64 dump found nothing either: the same
        // register existed on one path and not the other, exactly like `w<n>`
        // above. An alias rather than a second entry, for the reason spelled
        // out in the x29/x30 note — two entries would let one physical
        // register hold two disagreeing values.
        regs.push(RegMeta::new("pstate", 32, "Processor State").with_aliases(&["cpsr"]));
        regs
    }

    fn arm32_regs() -> Vec<RegMeta> {
        let mut regs: Vec<RegMeta> = (0..=12)
            .map(|i| RegMeta::new(&format!("r{i}"), 32, &format!("General Purpose r{i}")))
            .collect();
        regs.push(RegMeta::new("sp", 32, "Stack Pointer").with_aliases(&["r13"]));
        regs.push(RegMeta::new("lr", 32, "Link Register").with_aliases(&["r14"]));
        regs.push(RegMeta::new("pc", 32, "Program Counter").with_aliases(&["r15"]));
        regs.push(RegMeta::new("cpsr", 32, "Current Program Status Register"));
        regs
    }

    fn mips_regs(arch: Architecture) -> Vec<RegMeta> {
        let bits = arch.gpr_bits();
        let names = [
            ("zero", "Zero"), ("at", "Assembler Temp"), ("v0", "Value 0"), ("v1", "Value 1"),
            ("a0", "Arg 0"), ("a1", "Arg 1"), ("a2", "Arg 2"), ("a3", "Arg 3"),
            ("t0", "Temp 0"), ("t1", "Temp 1"), ("t2", "Temp 2"), ("t3", "Temp 3"),
            ("t4", "Temp 4"), ("t5", "Temp 5"), ("t6", "Temp 6"), ("t7", "Temp 7"),
            ("s0", "Saved 0"), ("s1", "Saved 1"), ("s2", "Saved 2"), ("s3", "Saved 3"),
            ("s4", "Saved 4"), ("s5", "Saved 5"), ("s6", "Saved 6"), ("s7", "Saved 7"),
            ("t8", "Temp 8"), ("t9", "Temp 9"), ("k0", "Kernel 0"), ("k1", "Kernel 1"),
            ("gp", "Global Pointer"), ("sp", "Stack Pointer"), ("fp", "Frame Pointer"),
            ("ra", "Return Address"),
        ];
        let mut regs: Vec<RegMeta> = names
            .iter()
            .map(|(n, d)| RegMeta::new(n, bits, d))
            .collect();
        regs.push(RegMeta::new("pc", bits, "Program Counter"));
        regs.push(RegMeta::new("hi", bits, "Multiply High"));
        regs.push(RegMeta::new("lo", bits, "Multiply Low"));
        regs
    }

    fn riscv_regs(arch: Architecture) -> Vec<RegMeta> {
        let bits = arch.gpr_bits();
        let names = [
            ("zero", "Hard-wired zero"), ("ra", "Return Address"), ("sp", "Stack Pointer"),
            ("gp", "Global Pointer"), ("tp", "Thread Pointer"), ("t0", "Temp 0"),
            ("t1", "Temp 1"), ("t2", "Temp 2"), ("s0", "Saved 0 / Frame Pointer"),
            ("s1", "Saved 1"), ("a0", "Arg 0 / Return 0"), ("a1", "Arg 1 / Return 1"),
            ("a2", "Arg 2"), ("a3", "Arg 3"), ("a4", "Arg 4"), ("a5", "Arg 5"),
            ("a6", "Arg 6"), ("a7", "Arg 7"),
        ];
        let mut regs: Vec<RegMeta> = names
            .iter()
            .map(|(n, d)| RegMeta::new(n, bits, d))
            .collect();
        for i in 2..=11 {
            regs.push(RegMeta::new(&format!("s{i}"), bits, &format!("Saved {i}")));
        }
        for i in 3..=6 {
            regs.push(RegMeta::new(&format!("t{i}"), bits, &format!("Temp {i}")));
        }
        regs.push(RegMeta::new("pc", bits, "Program Counter"));
        regs
    }
}

// ─── RegisterContext ──────────────────────────────────────────────────────────

/// Snapshot of all register values for a given thread.
pub struct RegisterContext {
    pub arch: Architecture,
    register_set: RegisterSet,
    values: HashMap<String, RegValue>,
    pub tid: u32,
}

impl RegisterContext {
    /// Create an empty context for `arch` and `tid`.
    #[must_use]
    pub fn new(arch: Architecture, tid: u32) -> Self {
        Self {
            arch,
            register_set: RegisterSet::for_arch(arch),
            values: HashMap::new(),
            tid,
        }
    }

    /// Set a register by name.
    ///
    /// # Errors
    /// Returns `NotFound` if the register name is unrecognised.
    ///
    /// # Panics
    /// Panics if the register lookup succeeds on the first call but fails on the
    /// alias-resolution call (cannot happen in practice).
    pub fn set(&mut self, name: &str, value: RegValue) -> Result<(), RegError> {
        let lc = name.to_lowercase();
        if self.register_set.find(&lc).is_none() {
            return Err(RegError::NotFound(name.to_string()));
        }
        // Resolve alias to canonical name
        let canonical = self
            .register_set
            .find(&lc)
            .map(|m| m.name.clone())
            .unwrap();
        self.values.insert(canonical, value);
        Ok(())
    }

    /// Get a register by name (including aliases).
    ///
    /// # Errors
    /// Returns `NotFound` if the register is unknown or has no value set.
    pub fn get(&self, name: &str) -> Result<RegValue, RegError> {
        let lc = name.to_lowercase();
        let meta = self
            .register_set
            .find(&lc)
            .ok_or_else(|| RegError::NotFound(name.to_string()))?;
        self.values
            .get(&meta.name)
            .copied()
            .ok_or_else(|| RegError::NotFound(name.to_string()))
    }

    /// Get the program counter value.
    #[must_use]
    pub fn pc(&self) -> u64 {
        let pc_name = match self.arch {
            Architecture::X86_64 => "rip",
            Architecture::X86 => "eip",
            Architecture::Arm64
            | Architecture::Arm32
            | Architecture::Mips32
            | Architecture::Mips64
            | Architecture::Riscv32
            | Architecture::Riscv64 => "pc",
        };
        self.get(pc_name).map_or(0, RegValue::as_u64)
    }

    /// Get the stack pointer value.
    #[must_use]
    pub fn sp(&self) -> u64 {
        let sp_name = match self.arch {
            Architecture::X86_64 => "rsp",
            Architecture::X86 => "esp",
            _ => "sp",
        };
        self.get(sp_name).map_or(0, RegValue::as_u64)
    }

    /// Return all set registers as `(name, value)` pairs sorted by name.
    #[must_use]
    pub fn all_values(&self) -> Vec<(String, RegValue)> {
        let mut pairs: Vec<(String, RegValue)> = self
            .values
            .iter()
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    /// Return the number of registers that have values set.
    #[must_use]
    pub fn set_count(&self) -> usize {
        self.values.len()
    }

    /// Return the register set metadata.
    #[must_use]
    pub const fn register_set(&self) -> &RegisterSet {
        &self.register_set
    }

    /// Diff two register contexts, returning `(name, old, new)` for changed regs.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<(String, RegValue, RegValue)> {
        let mut changed = Vec::with_capacity(self.values.len().min(other.values.len()));
        for (name, &old_val) in &self.values {
            if let Some(&new_val) = other.values.get(name) && old_val != new_val {
                changed.push((name.clone(), old_val, new_val));
            }
        }
        changed.sort_by(|a, b| a.0.cmp(&b.0));
        changed
    }
}

impl Drop for RegisterContext {
    /// Zeroize all register values on drop to prevent sensitive data (e.g.
    /// key material or passwords found in registers) from lingering in memory.
    fn drop(&mut self) {
        for v in self.values.values_mut() {
            v.zeroize();
        }
    }
}

// ─── format_registers ─────────────────────────────────────────────────────────

/// Format a register context as a multi-line string.
///
/// Each line has the form `  <NAME>  =  0xVALUE  (<decimal>)`.
#[must_use]
pub fn format_registers(ctx: &RegisterContext) -> String {
    let mut out = format!("Register context [{}] tid={}\n", ctx.arch, ctx.tid);
    let vals = ctx.all_values();
    for (name, val) in vals {
        let meta = ctx.register_set.find(&name);
        let desc = meta.map_or("", |m| m.description.as_str());
        let _ = writeln!(
            out,
            "  {:<8} = 0x{:<16}  ({:>20})  {}",
            name,
            val.hex_str(),
            val.as_u64(),
            desc
        );
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn x86_64_ctx() -> RegisterContext {
        let mut ctx = RegisterContext::new(Architecture::X86_64, 1);
        ctx.set("rax", RegValue::U64(0xDEAD_BEEF_CAFE_BABE)).unwrap();
        ctx.set("rip", RegValue::U64(0x0000_0000_0040_1000)).unwrap();
        ctx.set("rsp", RegValue::U64(0x0000_7FFF_FF00_0000)).unwrap();
        ctx.set("rflags", RegValue::U64(0x0202)).unwrap();
        ctx
    }

    #[test]
    fn get_set_basic() {
        let mut ctx = RegisterContext::new(Architecture::X86_64, 1);
        ctx.set("rax", RegValue::U64(42)).unwrap();
        let v = ctx.get("rax").unwrap();
        assert_eq!(v.as_u64(), 42);
    }

    #[test]
    fn get_unknown_register_errors() {
        let ctx = RegisterContext::new(Architecture::X86_64, 1);
        let err = ctx.get("zzz").unwrap_err();
        assert!(matches!(err, RegError::NotFound(_)));
    }

    #[test]
    fn set_unknown_register_errors() {
        let mut ctx = RegisterContext::new(Architecture::X86_64, 1);
        let err = ctx.set("zzz", RegValue::U64(0)).unwrap_err();
        assert!(matches!(err, RegError::NotFound(_)));
    }

    #[test]
    fn pc_returns_rip_for_x86_64() {
        let ctx = x86_64_ctx();
        assert_eq!(ctx.pc(), 0x0000_0000_0040_1000);
    }

    #[test]
    fn sp_returns_rsp_for_x86_64() {
        let ctx = x86_64_ctx();
        assert_eq!(ctx.sp(), 0x0000_7FFF_FF00_0000);
    }

    #[test]
    fn all_values_sorted() {
        let ctx = x86_64_ctx();
        let vals = ctx.all_values();
        let names: Vec<&str> = vals.iter().map(|(n, _)| n.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn set_count() {
        let ctx = x86_64_ctx();
        assert_eq!(ctx.set_count(), 4);
    }

    #[test]
    fn diff_detects_changed() {
        let ctx1 = x86_64_ctx();
        let mut ctx2 = x86_64_ctx();
        ctx2.set("rax", RegValue::U64(0)).unwrap();
        let diffs = ctx1.diff(&ctx2);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "rax");
    }

    #[test]
    fn diff_no_changes() {
        let ctx1 = x86_64_ctx();
        let ctx2 = x86_64_ctx();
        assert!(ctx1.diff(&ctx2).is_empty());
    }

    #[test]
    fn format_registers_contains_arch() {
        let ctx = x86_64_ctx();
        let s = format_registers(&ctx);
        assert!(s.contains("x86-64"));
    }

    #[test]
    fn format_registers_contains_rax() {
        let ctx = x86_64_ctx();
        let s = format_registers(&ctx);
        assert!(s.contains("rax"));
    }

    #[test]
    fn reg_value_hex_str() {
        assert_eq!(RegValue::U8(0xAB).hex_str(), "AB");
        assert_eq!(RegValue::U16(0xABCD).hex_str(), "ABCD");
        assert_eq!(RegValue::U32(0x1234_5678).hex_str(), "12345678");
        assert_eq!(RegValue::U64(0).hex_str(), "0000000000000000");
    }

    #[test]
    fn reg_value_as_u64() {
        assert_eq!(RegValue::U8(0xFF).as_u64(), 255);
        assert_eq!(RegValue::U32(0xFFFF_FFFF).as_u64(), 0xFFFF_FFFF);
    }

    #[test]
    fn reg_value_bits() {
        assert_eq!(RegValue::U8(0).bits(), 8);
        assert_eq!(RegValue::U64(0).bits(), 64);
        assert_eq!(RegValue::U128(0).bits(), 128);
    }

    #[test]
    fn reg_value_display() {
        let v = RegValue::U32(0xDEAD_BEEF);
        assert_eq!(v.to_string(), "DEADBEEF");
    }

    #[test]
    fn arm64_pc_via_pc_name() {
        let mut ctx = RegisterContext::new(Architecture::Arm64, 2);
        ctx.set("pc", RegValue::U64(0x100_0000)).unwrap();
        assert_eq!(ctx.pc(), 0x100_0000);
    }

    #[test]
    fn arm64_sp_via_sp_name() {
        let mut ctx = RegisterContext::new(Architecture::Arm64, 2);
        ctx.set("sp", RegValue::U64(0xFFFF_F000)).unwrap();
        assert_eq!(ctx.sp(), 0xFFFF_F000);
    }

    /// On `AArch64` `x30` IS the link register and `x29` IS the frame pointer —
    /// one physical register each, two spellings.
    ///
    /// The table generated `x0..=x30` as canonical registers AND declared `x30`
    /// an alias of `lr` (same for `x29`/`fp`). Because `find` scans in order and
    /// the generated range comes first, each spelling resolved to a different
    /// key, so a context could hold two independent values for one register:
    /// writing `x30` and reading `lr` did not see the write. For a debugger,
    /// showing `lr` and `x30` disagreeing is worse than showing neither.
    #[test]
    fn arm64_link_and_frame_registers_have_one_value_per_physical_register() {
        for (gpr, name) in [("x30", "lr"), ("x29", "fp")] {
            let mut ctx = RegisterContext::new(Architecture::Arm64, 2);
            ctx.set(gpr, RegValue::U64(0xAAAA)).unwrap();
            assert_eq!(
                ctx.get(name).map(super::RegValue::as_u64).ok(),
                Some(0xAAAA),
                "{gpr} and {name} are the same physical register: a write to one must be visible through the other"
            );

            // ...and the reverse direction, with the later write winning rather
            // than landing in a second slot.
            ctx.set(name, RegValue::U64(0xBBBB)).unwrap();
            assert_eq!(ctx.get(gpr).map(super::RegValue::as_u64).ok(), Some(0xBBBB));
            assert_eq!(
                ctx.set_count(),
                1,
                "{gpr}/{name} must occupy one slot, not two"
            );
        }
    }

    /// No alias in any architecture may also be another register's canonical
    /// name.
    ///
    /// This is the general form of the `x30`/`lr` defect: `find` returns the
    /// first entry whose name OR alias matches, so such a collision silently
    /// splits one physical register into two independently-writable slots. The
    /// check covers every architecture the crate knows, including ones added
    /// later — the `AArch64` table is simply where the collision happened to
    /// exist.
    #[test]
    fn no_alias_collides_with_another_registers_canonical_name() {
        for arch in [
            Architecture::X86_64,
            Architecture::X86,
            Architecture::Arm64,
            Architecture::Arm32,
            Architecture::Mips32,
            Architecture::Mips64,
            Architecture::Riscv32,
            Architecture::Riscv64,
        ] {
            let rs = RegisterSet::for_arch(arch);
            let canonical: std::collections::HashSet<&str> =
                rs.registers.iter().map(|r| r.name.as_str()).collect();
            for reg in &rs.registers {
                for alias in &reg.aliases {
                    assert!(
                        !canonical.contains(alias.as_str()),
                        "{arch}: `{alias}` is an alias of `{}` and also a register of its own; \
                         one physical register would get two independent slots",
                        reg.name
                    );
                }
            }
        }
    }

    #[test]
    fn register_set_for_x86() {
        let rs = RegisterSet::for_arch(Architecture::X86);
        assert!(rs.find("eax").is_some());
        assert!(rs.find("ebp").is_some());
    }

    #[test]
    fn register_set_find_alias() {
        let rs = RegisterSet::for_arch(Architecture::X86_64);
        // "eax" is an alias of "rax"
        let meta = rs.find("eax").unwrap();
        assert_eq!(meta.name, "rax");
    }

    /// Every register name the minidump parser PRODUCES for arm64 must be a
    /// name this table RESOLVES.
    ///
    /// The two halves are written independently — one from
    /// `ARM64_NT_CONTEXT`, one from the architecture manual — and nothing ties
    /// them together, so a register can end up named `cpsr` on the producing
    /// side and `pstate` on the consuming side and be invisible from both.
    /// That is what had happened: this asks the question across the seam
    /// instead of restating either table.
    #[test]
    fn every_arm64_register_the_minidump_parser_emits_resolves_here() {
        let rs = RegisterSet::for_arch(Architecture::Arm64);
        // The exact keys `minidump_analysis` inserts for an ARM64_NT_CONTEXT.
        let mut produced: Vec<String> = (0..29).map(|i| format!("x{i}")).collect();
        produced.extend(["fp", "lr", "sp", "pc", "cpsr"].iter().map(|s| (*s).to_string()));
        for name in &produced {
            assert!(
                rs.find(name).is_some(),
                "the minidump parser emits `{name}` for arm64 but this table cannot resolve it"
            );
        }
        // `cpsr` and `pstate` are one register, so they must resolve to ONE
        // entry — not to two that could hold disagreeing values.
        assert_eq!(rs.find("cpsr").map(|m| m.name.as_str()), Some("pstate"));
    }

    #[test]
    fn register_set_mips() {
        let rs = RegisterSet::for_arch(Architecture::Mips32);
        assert!(rs.find("zero").is_some());
        assert!(rs.find("ra").is_some());
        assert!(rs.find("sp").is_some());
    }

    #[test]
    fn register_set_riscv() {
        let rs = RegisterSet::for_arch(Architecture::Riscv64);
        assert!(rs.find("a0").is_some());
        assert!(rs.find("pc").is_some());
    }

    #[test]
    fn architecture_display() {
        assert_eq!(Architecture::X86_64.to_string(), "x86-64");
        assert_eq!(Architecture::Arm64.to_string(), "AArch64");
    }

    #[test]
    fn architecture_gpr_bits() {
        assert_eq!(Architecture::X86_64.gpr_bits(), 64);
        assert_eq!(Architecture::X86.gpr_bits(), 32);
        assert_eq!(Architecture::Arm32.gpr_bits(), 32);
    }

    /// The two register tables in this crate must answer the same question
    /// the same way.
    ///
    /// `register_context` keeps its own alias lists; `lib.rs::sub_register_of`
    /// (iteration 450) keeps another, used by the condition evaluator. They
    /// disagreed: `r8`/`r9` listed the `d`/`w`/`b` forms, `r10`-`r15` listed
    /// only `d`. So `r12b` resolved in a breakpoint condition and did not
    /// exist for the schema - one of the two was wrong, and no test looking at
    /// either alone could say which.
    #[test]
    fn every_shared_sub_register_resolves_in_the_schema_too() {
        let x64 = RegisterSet::for_arch(Architecture::X86_64);
        let arm = RegisterSet::for_arch(Architecture::Arm64);
        let mut checked = 0;
        for name in crate::SUB_REGISTER_NAMES {
            let (parent, _shift, _mask) =
                crate::sub_register_of(name).expect("advertised names must resolve");
            // Only check the names whose parent belongs to that architecture.
            let set = if parent.starts_with(char::is_alphabetic) && parent.starts_with('x') {
                &arm
            } else {
                &x64
            };
            if set.registers.iter().all(|r| r.name != parent) {
                continue;
            }
            assert!(
                set.find(name).is_some(),
                "{name} resolves in the condition evaluator but not in the register schema"
            );
            checked += 1;
        }
        assert!(checked > 40, "the check must actually have examined the names, saw {checked}");
    }

    /// A sub-register must report ITS width, not the width of the register it
    /// lives inside.
    ///
    /// `find("al")` returns `rax`s metadata, whose `bits` is 64. Correct as
    /// "which register is this part of", wrong as "how wide is al" - and a
    /// caller formatting or masking by that number reads eight bytes where one
    /// was asked for.
    #[test]
    fn a_sub_register_reports_its_own_width() {
        let s = RegisterSet::for_arch(Architecture::X86_64);
        assert_eq!(s.width_bits("rax"), Some(64));
        assert_eq!(s.width_bits("eax"), Some(32));
        assert_eq!(s.width_bits("ax"), Some(16));
        assert_eq!(s.width_bits("al"), Some(8));
        assert_eq!(s.width_bits("ah"), Some(8));
        assert_eq!(s.width_bits("r12b"), Some(8));
        assert_eq!(s.width_bits("r12w"), Some(16));
        assert_eq!(s.width_bits("r12d"), Some(32));
        // The parent metadata still says 64 - that is a different question.
        assert_eq!(s.find("al").map(|m| m.bits), Some(64));

        let a = RegisterSet::for_arch(Architecture::Arm64);
        assert_eq!(a.width_bits("x0"), Some(64));
        assert_eq!(a.width_bits("w0"), Some(32));

        // An unknown name stays unknown.
        assert_eq!(s.width_bits("not_a_register"), None);
    }

}
