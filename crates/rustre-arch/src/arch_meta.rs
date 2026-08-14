//! Architecture metadata and encoding helpers.
//!
//! [`ArchMetadata`] provides supplementary information about a CPU architecture
//! including ISA extensions, pointer model, memory model, and endianness.
//! [`EncodeContext`] holds state needed for instruction encoding.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// IsaExtension
// ─────────────────────────────────────────────────────────────────────────────

/// A CPU ISA extension flag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsaExtension {
    // x86 / x86-64
    Mmx,
    Sse,
    Sse2,
    Sse3,
    Ssse3,
    Sse4_1,
    Sse4_2,
    Avx,
    Avx2,
    Avx512F,
    Avx512Bw,
    Avx512Cd,
    Avx512Dq,
    Avx512Vl,
    AesNi,
    Sha,
    Pclmul,
    Rdrand,
    Rdseed,
    Popcnt,
    Lzcnt,
    Bmi1,
    Bmi2,
    Fma,
    F16C,
    Adx,
    Clflush,
    Cet,
    // ARM / AArch64
    Neon,
    Sve,
    Sve2,
    Sme,
    Armv8a,
    Armv8_2a,
    Armv8_5a,
    Armv9a,
    CrC32,
    Crypto,
    Fp16,
    DotProd,
    Bf16,
    I8Mm,
    // MIPS
    Mips32r2,
    Mips64r2,
    MipsDsp,
    MipsMsa,
    // RISC-V
    RvI,
    RvM,
    RvA,
    RvF,
    RvD,
    RvC,
    RvB,
    RvV,
    RvZicsr,
    RvZifencei,
    RvK,
    // Custom
    Custom(String),
}

impl fmt::Display for IsaExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mmx => f.write_str("MMX"),
            Self::Sse => f.write_str("SSE"),
            Self::Sse2 => f.write_str("SSE2"),
            Self::Sse3 => f.write_str("SSE3"),
            Self::Ssse3 => f.write_str("SSSE3"),
            Self::Sse4_1 => f.write_str("SSE4.1"),
            Self::Sse4_2 => f.write_str("SSE4.2"),
            Self::Avx => f.write_str("AVX"),
            Self::Avx2 => f.write_str("AVX2"),
            Self::Avx512F => f.write_str("AVX-512F"),
            Self::AesNi => f.write_str("AES-NI"),
            Self::Sha => f.write_str("SHA"),
            Self::Neon => f.write_str("NEON"),
            Self::Sve => f.write_str("SVE"),
            Self::Sve2 => f.write_str("SVE2"),
            Self::RvI => f.write_str("RV-I"),
            Self::RvM => f.write_str("RV-M"),
            Self::RvV => f.write_str("RV-V"),
            Self::Custom(s) => f.write_str(s),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerModel
// ─────────────────────────────────────────────────────────────────────────────

/// Integer + pointer model for an architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerModel {
    Ilp32, // int=32, long=32, pointer=32
    Lp64,  // int=32, long=64, pointer=64  (Linux/macOS x86-64)
    Llp64, // int=32, long=32, pointer=64  (Windows x86-64)
    Ilp64, // int=64, long=64, pointer=64  (rare)
    Ip16,  // 16-bit
    Custom {
        ptr_bits: u8,
        int_bits: u8,
        long_bits: u8,
    },
}

impl PointerModel {
    #[must_use]
    pub const fn pointer_bits(self) -> u8 {
        match self {
            Self::Ilp32 => 32,
            Self::Lp64 | Self::Llp64 | Self::Ilp64 => 64,
            Self::Ip16 => 16,
            Self::Custom { ptr_bits, .. } => ptr_bits,
        }
    }

    #[must_use]
    pub const fn int_bits(self) -> u8 {
        match self {
            Self::Ilp64 => 64,
            Self::Ip16 => 16,
            Self::Custom { int_bits, .. } => int_bits,
            _ => 32,
        }
    }

    #[must_use]
    pub const fn long_bits(self) -> u8 {
        match self {
            Self::Ilp32 | Self::Llp64 => 32,
            Self::Lp64 | Self::Ilp64 => 64,
            Self::Ip16 => 16,
            Self::Custom { long_bits, .. } => long_bits,
        }
    }
}

impl fmt::Display for PointerModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ilp32 => "ILP32",
            Self::Lp64 => "LP64",
            Self::Llp64 => "LLP64",
            Self::Ilp64 => "ILP64",
            Self::Ip16 => "IP16",
            Self::Custom {
                ptr_bits,
                int_bits,
                long_bits,
            } => {
                return write!(f, "Custom(ptr={ptr_bits},int={int_bits},long={long_bits})");
            }
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryModel
// ─────────────────────────────────────────────────────────────────────────────

/// Memory ordering model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryModel {
    /// Strong (Total Store Order) — x86.
    Tso,
    /// Weak (relaxed) — ARM, RISC-V.
    Weak,
    /// Very weak — POWER.
    VeryWeak,
    /// Sequential consistency (rarely hardware).
    SeqCst,
}

impl fmt::Display for MemoryModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tso => "TSO",
            Self::Weak => "Weak",
            Self::VeryWeak => "VeryWeak",
            Self::SeqCst => "SeqCst",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// Rich metadata for a specific architecture variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchMetadata {
    pub name: String,
    pub display_name: String,
    pub triple: String,
    pub pointer_model: PointerModel,
    pub memory_model: MemoryModel,
    pub is_little_endian: bool,
    pub instruction_alignment: u8,
    pub min_instr_size: u8,
    pub max_instr_size: u8,
    pub stack_grows_down: bool,
    pub stack_alignment: u8,
    pub red_zone_bytes: u16,
    pub extensions: HashSet<IsaExtension>,
    pub syscall_numbers: HashMap<String, u32>,
    pub tags: Vec<String>,
}

impl ArchMetadata {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            display_name: name.clone(),
            triple: format!("{name}-unknown-unknown"),
            name,
            pointer_model: PointerModel::Lp64,
            memory_model: MemoryModel::Weak,
            is_little_endian: true,
            instruction_alignment: 1,
            min_instr_size: 1,
            max_instr_size: 15,
            stack_grows_down: true,
            stack_alignment: 16,
            red_zone_bytes: 0,
            extensions: HashSet::new(),
            syscall_numbers: HashMap::new(),
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_pointer_model(mut self, pm: PointerModel) -> Self {
        self.pointer_model = pm;
        self
    }
    #[must_use]
    pub const fn with_memory_model(mut self, mm: MemoryModel) -> Self {
        self.memory_model = mm;
        self
    }
    #[must_use]
    pub const fn big_endian(mut self) -> Self {
        self.is_little_endian = false;
        self
    }
    #[must_use]
    pub fn with_extension(mut self, ext: IsaExtension) -> Self {
        self.extensions.insert(ext);
        self
    }
    #[must_use]
    pub fn with_syscall(mut self, name: impl Into<String>, num: u32) -> Self {
        self.syscall_numbers.insert(name.into(), num);
        self
    }

    #[must_use]
    pub fn has_extension(&self, ext: &IsaExtension) -> bool {
        self.extensions.contains(ext)
    }
    #[must_use]
    pub const fn pointer_bits(&self) -> u8 {
        self.pointer_model.pointer_bits()
    }
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.pointer_bits() == 64
    }
    #[must_use]
    pub const fn is_32bit(&self) -> bool {
        self.pointer_bits() == 32
    }
    #[must_use]
    pub const fn is_variable_length_isa(&self) -> bool {
        self.min_instr_size != self.max_instr_size
    }

    /// Common x86-64 metadata.
    #[must_use]
    pub fn x86_64() -> Self {
        Self::new("x86_64")
            .with_pointer_model(PointerModel::Lp64)
            .with_memory_model(MemoryModel::Tso)
            .with_extension(IsaExtension::Sse2)
            .with_syscall("read", 0)
            .with_syscall("write", 1)
            .with_syscall("open", 2)
            .with_syscall("close", 3)
            .with_syscall("exit", 60)
    }

    /// Common `AArch64` metadata.
    #[must_use]
    pub fn aarch64() -> Self {
        let mut m = Self::new("aarch64");
        m.instruction_alignment = 4;
        m.min_instr_size = 4;
        m.max_instr_size = 4;
        m.memory_model = MemoryModel::Weak;
        m.extensions.insert(IsaExtension::Neon);
        m.with_syscall("read", 63)
            .with_syscall("write", 64)
            .with_syscall("exit", 93)
    }

    /// Common MIPS-32 metadata.
    #[must_use]
    pub fn mips32() -> Self {
        let mut m = Self::new("mips32");
        m.pointer_model = PointerModel::Ilp32;
        m.instruction_alignment = 4;
        m.min_instr_size = 4;
        m.max_instr_size = 4;
        m.memory_model = MemoryModel::Weak;
        m.extensions.insert(IsaExtension::Mips32r2);
        m
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodeContext
// ─────────────────────────────────────────────────────────────────────────────

/// State needed for assembling / encoding instructions.
#[derive(Debug, Clone)]
pub struct EncodeContext {
    pub arch: String,
    pub current_address: u64,
    pub labels: HashMap<String, u64>,
    pub pending_fixups: Vec<Fixup>,
    pub is_little_endian: bool,
    pub pointer_bits: u8,
}

/// A relocation fixup to be applied after encoding.
#[derive(Debug, Clone)]
pub struct Fixup {
    pub offset: u64,
    pub label: String,
    pub kind: FixupKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupKind {
    Rel32, // 32-bit relative offset
    Abs64, // 64-bit absolute address
    Rel16, // 16-bit relative offset (MIPS)
    Rel26, // 26-bit target (MIPS J-type)
}

impl EncodeContext {
    pub fn new(arch: impl Into<String>, start: u64, little_endian: bool, ptr_bits: u8) -> Self {
        Self {
            arch: arch.into(),
            current_address: start,
            labels: HashMap::new(),
            pending_fixups: Vec::new(),
            is_little_endian: little_endian,
            pointer_bits: ptr_bits,
        }
    }

    pub fn define_label(&mut self, name: impl Into<String>) {
        self.labels.insert(name.into(), self.current_address);
    }

    #[must_use]
    pub fn resolve_label(&self, name: &str) -> Option<u64> {
        self.labels.get(name).copied()
    }

    pub fn add_fixup(&mut self, offset: u64, label: impl Into<String>, kind: FixupKind) {
        self.pending_fixups.push(Fixup {
            offset,
            label: label.into(),
            kind,
        });
    }

    pub const fn advance(&mut self, bytes: u64) {
        self.current_address += bytes;
    }

    /// Apply all pending fixups to the given byte buffer.
    pub fn apply_fixups(&self, buf: &mut [u8], base: u64) -> Vec<String> {
        let mut errors = Vec::new();
        for fixup in &self.pending_fixups {
            let Some(&target) = self.labels.get(&fixup.label) else {
                errors.push(format!("unresolved: {}", fixup.label));
                continue;
            };
            let Some(raw_offset) = fixup.offset.checked_sub(base) else {
                errors.push(format!(
                    "fixup offset {} below base {}",
                    fixup.offset, base
                ));
                continue;
            };
            let offset = usize::try_from(raw_offset).unwrap_or(usize::MAX);
            match fixup.kind {
                FixupKind::Rel32 => {
                    let rel = i32::try_from(
                        target.cast_signed().wrapping_sub(fixup.offset.cast_signed()).wrapping_sub(4_i64),
                    )
                    .unwrap_or(0);
                    let bytes = if self.is_little_endian {
                        rel.to_le_bytes()
                    } else {
                        rel.to_be_bytes()
                    };
                    if offset + 4 <= buf.len() {
                        buf[offset..offset + 4].copy_from_slice(&bytes);
                    }
                }
                FixupKind::Abs64 => {
                    let bytes = if self.is_little_endian {
                        target.to_le_bytes()
                    } else {
                        target.to_be_bytes()
                    };
                    if offset + 8 <= buf.len() {
                        buf[offset..offset + 8].copy_from_slice(&bytes);
                    }
                }
                _ => {}
            }
        }
        errors
    }

    #[must_use]
    pub const fn fixup_count(&self) -> usize {
        self.pending_fixups.len()
    }
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- IsaExtension ---

    #[test]
    fn isa_ext_display_sse2() {
        assert_eq!(format!("{}", IsaExtension::Sse2), "SSE2");
    }

    #[test]
    fn isa_ext_display_neon() {
        assert_eq!(format!("{}", IsaExtension::Neon), "NEON");
    }

    #[test]
    fn isa_ext_custom() {
        let e = IsaExtension::Custom("MYEXT".into());
        assert_eq!(format!("{e}"), "MYEXT");
    }

    // --- PointerModel ---

    #[test]
    fn pointer_model_lp64_bits() {
        assert_eq!(PointerModel::Lp64.pointer_bits(), 64);
        assert_eq!(PointerModel::Lp64.int_bits(), 32);
        assert_eq!(PointerModel::Lp64.long_bits(), 64);
    }

    #[test]
    fn pointer_model_ilp32_bits() {
        assert_eq!(PointerModel::Ilp32.pointer_bits(), 32);
    }

    #[test]
    fn pointer_model_llp64_long_is_32() {
        assert_eq!(PointerModel::Llp64.long_bits(), 32);
    }

    #[test]
    fn pointer_model_display() {
        assert_eq!(format!("{}", PointerModel::Lp64), "LP64");
    }

    // --- MemoryModel ---

    #[test]
    fn memory_model_display() {
        assert_eq!(format!("{}", MemoryModel::Tso), "TSO");
    }

    // --- ArchMetadata ---

    #[test]
    fn arch_meta_x86_64() {
        let m = ArchMetadata::x86_64();
        assert_eq!(m.name, "x86_64");
        assert!(m.is_little_endian);
        assert!(m.is_64bit());
        assert!(m.has_extension(&IsaExtension::Sse2));
    }

    #[test]
    fn arch_meta_aarch64() {
        let m = ArchMetadata::aarch64();
        assert_eq!(m.instruction_alignment, 4);
        assert!(m.has_extension(&IsaExtension::Neon));
    }

    #[test]
    fn arch_meta_mips32_is_32bit() {
        let m = ArchMetadata::mips32();
        assert!(m.is_32bit());
    }

    #[test]
    fn arch_meta_big_endian() {
        let m = ArchMetadata::mips32().big_endian();
        assert!(!m.is_little_endian);
    }

    #[test]
    fn arch_meta_variable_length_isa() {
        let m = ArchMetadata::x86_64();
        assert!(m.is_variable_length_isa()); // 1..15
    }

    #[test]
    fn arch_meta_fixed_length_isa() {
        let m = ArchMetadata::aarch64();
        assert!(!m.is_variable_length_isa()); // 4..4
    }

    #[test]
    fn arch_meta_syscall_number() {
        let m = ArchMetadata::x86_64();
        assert_eq!(m.syscall_numbers.get("exit"), Some(&60));
    }

    #[test]
    fn arch_meta_with_extension() {
        let m = ArchMetadata::new("test").with_extension(IsaExtension::Avx2);
        assert!(m.has_extension(&IsaExtension::Avx2));
    }

    // --- EncodeContext ---

    #[test]
    fn encode_ctx_define_resolve_label() {
        let mut ctx = EncodeContext::new("x86_64", 0x1000, true, 64);
        ctx.define_label("loop_top");
        assert_eq!(ctx.resolve_label("loop_top"), Some(0x1000));
    }

    #[test]
    fn encode_ctx_advance() {
        let mut ctx = EncodeContext::new("x86_64", 0x1000, true, 64);
        ctx.advance(5);
        assert_eq!(ctx.current_address, 0x1005);
    }

    #[test]
    fn encode_ctx_add_fixup() {
        let mut ctx = EncodeContext::new("x86_64", 0x1000, true, 64);
        ctx.add_fixup(0x1001, "target", FixupKind::Rel32);
        assert_eq!(ctx.fixup_count(), 1);
    }

    #[test]
    fn encode_ctx_unresolved_fixup_error() {
        let ctx = EncodeContext::new("x86_64", 0x1000, true, 64);
        let mut buf = vec![0u8; 8];
        // No labels defined
        let mut ctx2 = ctx;
        ctx2.add_fixup(0x1000, "missing", FixupKind::Rel32);
        let errs = ctx2.apply_fixups(&mut buf, 0x1000);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("missing"));
    }

    #[test]
    fn encode_ctx_apply_abs64_fixup() {
        let mut ctx = EncodeContext::new("x86_64", 0x1000, true, 64);
        ctx.define_label("func");
        ctx.current_address = 0x2000;
        ctx.add_fixup(0x1000, "func", FixupKind::Abs64);
        let mut buf = vec![0u8; 8];
        ctx.apply_fixups(&mut buf, 0x1000);
        let addr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(addr, 0x1000);
    }

    #[test]
    fn encode_ctx_label_count() {
        let mut ctx = EncodeContext::new("x86_64", 0, true, 64);
        ctx.define_label("a");
        ctx.define_label("b");
        assert_eq!(ctx.label_count(), 2);
    }

    // ───── Edge-case coverage ─────────────────────────────────────────────

    #[test]
    fn pointer_model_bits_all_variants() {
        assert_eq!(PointerModel::Ilp32.pointer_bits(), 32);
        assert_eq!(PointerModel::Lp64.pointer_bits(), 64);
        assert_eq!(PointerModel::Llp64.pointer_bits(), 64);
        assert_eq!(PointerModel::Ilp64.pointer_bits(), 64);
        assert_eq!(PointerModel::Ip16.pointer_bits(), 16);
        assert_eq!(
            PointerModel::Custom { ptr_bits: 24, int_bits: 16, long_bits: 24 }.pointer_bits(),
            24
        );
    }

    #[test]
    fn pointer_model_int_long_bits_consistency() {
        // ILP32: int=32, long=32, ptr=32
        let m = PointerModel::Ilp32;
        assert_eq!(m.int_bits(), 32);
        assert_eq!(m.long_bits(), 32);
        // LLP64: int=32, long=32, ptr=64
        let m = PointerModel::Llp64;
        assert_eq!(m.long_bits(), 32);
        // ILP64: all 64
        let m = PointerModel::Ilp64;
        assert_eq!(m.int_bits(), 64);
        assert_eq!(m.long_bits(), 64);
    }

    #[test]
    fn pointer_model_custom_extremes() {
        let zero = PointerModel::Custom { ptr_bits: 0, int_bits: 0, long_bits: 0 };
        assert_eq!(zero.pointer_bits(), 0);
        let max = PointerModel::Custom { ptr_bits: u8::MAX, int_bits: u8::MAX, long_bits: u8::MAX };
        assert_eq!(max.pointer_bits(), u8::MAX);
        assert_eq!(max.int_bits(), u8::MAX);
        assert_eq!(max.long_bits(), u8::MAX);
    }

    #[test]
    fn arch_metadata_64_32_predicates() {
        let m = ArchMetadata::x86_64();
        assert!(m.is_64bit());
        assert!(!m.is_32bit());
        let m32 = ArchMetadata::mips32();
        assert!(m32.is_32bit());
        assert!(!m32.is_64bit());
    }

    #[test]
    fn arch_metadata_variable_length_isa_flag() {
        let mut m = ArchMetadata::new("test");
        m.min_instr_size = 1;
        m.max_instr_size = 15;
        assert!(m.is_variable_length_isa());
        m.min_instr_size = 4;
        m.max_instr_size = 4;
        assert!(!m.is_variable_length_isa());
    }

    #[test]
    fn arch_metadata_extension_helpers() {
        let m = ArchMetadata::aarch64();
        assert!(m.has_extension(&IsaExtension::Neon));
        assert!(!m.has_extension(&IsaExtension::Avx512F));
    }

    #[test]
    fn arch_metadata_x86_64_has_syscalls() {
        let m = ArchMetadata::x86_64();
        assert_eq!(m.syscall_numbers.get("write").copied(), Some(1));
        assert_eq!(m.syscall_numbers.get("exit").copied(), Some(60));
    }

    #[test]
    fn pointer_model_display_includes_name() {
        assert_eq!(format!("{}", PointerModel::Ilp32), "ILP32");
        assert_eq!(format!("{}", PointerModel::Lp64), "LP64");
        let s = format!("{}", PointerModel::Custom { ptr_bits: 24, int_bits: 16, long_bits: 24 });
        assert!(s.contains("24"));
    }

    #[test]
    fn memory_model_display_all_variants() {
        assert_eq!(format!("{}", MemoryModel::Tso), "TSO");
        assert_eq!(format!("{}", MemoryModel::Weak), "Weak");
        assert_eq!(format!("{}", MemoryModel::VeryWeak), "VeryWeak");
        assert_eq!(format!("{}", MemoryModel::SeqCst), "SeqCst");
    }
}
