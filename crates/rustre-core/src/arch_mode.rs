//! Architecture mode enumeration.
//!
//! This module provides [`Mode`], a comprehensive enumeration of all
//! execution modes supported across every architecture that RustRE targets.
//! Where the `arch` module's [`ArchMode`] is a minimal local enum used by
//! the [`Architecture`] trait, [`Mode`] is the platform-wide canonical form
//! exposed as a first-class value that can be stored, compared, serialised,
//! and queried.
//!
//! [`Architecture`]: crate::arch::Architecture

use serde::{Deserialize, Serialize};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Mode
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical execution-mode enumeration for all supported architectures.
///
/// Modes that differ only in instruction encoding width (e.g. Thumb vs ARM,
/// or x86-16 vs x86-32) are represented as separate variants so that a single
/// `Mode` value fully determines the disassembler configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mode {
    // ── x86 family ────────────────────────────────────────────────────────────
    /// 16-bit real-mode x86.
    X86_16,
    /// 32-bit protected-mode x86 (IA-32).
    X86_32,
    /// 64-bit x86-64 / AMD64.
    X86_64,

    // ── ARM family ────────────────────────────────────────────────────────────
    /// ARM 32-bit (A32 / Cortex-A in ARM state).
    Arm32,
    /// ARM Thumb (16-bit fixed-length Thumb instructions).
    Thumb,
    /// ARM Thumb-2 (mixed 16/32-bit Thumb instructions).
    Thumb2,
    /// `AArch64` / ARM64.
    Aarch64,

    // ── MIPS family ───────────────────────────────────────────────────────────
    /// MIPS32 big-endian.
    Mips32Be,
    /// MIPS32 little-endian.
    Mips32Le,
    /// MIPS64 big-endian.
    Mips64Be,
    /// MIPS64 little-endian.
    Mips64Le,
    /// MIPS16 compressed ISA extension.
    Mips16,
    /// microMIPS compressed ISA extension.
    MicroMips,

    // ── PowerPC family ────────────────────────────────────────────────────────
    /// PowerPC 32-bit big-endian.
    Ppc32Be,
    /// PowerPC 32-bit little-endian.
    Ppc32Le,
    /// PowerPC 64-bit big-endian.
    Ppc64Be,
    /// PowerPC 64-bit little-endian (POWER8+).
    Ppc64Le,

    // ── RISC-V family ─────────────────────────────────────────────────────────
    /// RISC-V 32-bit.
    RiscV32,
    /// RISC-V 64-bit.
    RiscV64,
    /// RISC-V 128-bit (experimental).
    RiscV128,

    // ── SPARC family ──────────────────────────────────────────────────────────
    /// SPARC 32-bit (V8).
    Sparc32,
    /// SPARC 64-bit (V9 / `UltraSPARC`).
    Sparc64,

    // ── AVR ───────────────────────────────────────────────────────────────────
    /// Atmel AVR 8-bit microcontroller.
    Avr,

    // ── Xtensa ────────────────────────────────────────────────────────────────
    /// Tensilica Xtensa (ESP32, etc.).
    Xtensa,

    // ── S390x ─────────────────────────────────────────────────────────────────
    /// IBM System/390 / z/Architecture.
    S390x,

    // ── LoongArch ─────────────────────────────────────────────────────────────
    /// `LoongArch` 32-bit.
    LoongArch32,
    /// `LoongArch` 64-bit.
    LoongArch64,

    // ── m68k ──────────────────────────────────────────────────────────────────
    /// Motorola 68000 family.
    M68k,

    // ── WebAssembly ───────────────────────────────────────────────────────────
    /// WebAssembly bytecode.
    Wasm,

    // ── JVM bytecode ─────────────────────────────────────────────────────────
    /// Java Virtual Machine bytecode.
    Jvm,

    // ── .NET CIL ─────────────────────────────────────────────────────────────
    /// .NET Common Intermediate Language.
    Cil,

    // ── Unknown / custom ─────────────────────────────────────────────────────
    /// Architecture is unknown or not enumerated above.
    Unknown,
    /// A user-defined / custom mode identified by an opaque `u32` tag.
    Custom(u32),
}

impl Mode {
    /// Return `true` if this is a 64-bit mode.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(
            self,
            Self::X86_64
                | Self::Aarch64
                | Self::Mips64Be
                | Self::Mips64Le
                | Self::Ppc64Be
                | Self::Ppc64Le
                | Self::RiscV64
                | Self::RiscV128
                | Self::Sparc64
                | Self::S390x
                | Self::LoongArch64
        )
    }

    /// Return `true` if this is a 32-bit mode.
    #[must_use]
    pub const fn is_32bit(self) -> bool {
        matches!(
            self,
            Self::X86_32
                | Self::Arm32
                | Self::Thumb
                | Self::Thumb2
                | Self::Mips32Be
                | Self::Mips32Le
                | Self::Ppc32Be
                | Self::Ppc32Le
                | Self::RiscV32
                | Self::Sparc32
                | Self::LoongArch32
                | Self::M68k
        )
    }

    /// Return `true` if this is a 16-bit mode.
    #[must_use]
    pub const fn is_16bit(self) -> bool {
        matches!(self, Self::X86_16 | Self::Mips16)
    }

    /// Return `true` if this is an 8-bit mode.
    #[must_use]
    pub const fn is_8bit(self) -> bool {
        matches!(self, Self::Avr)
    }

    /// Pointer size in bytes for this mode.
    ///
    /// Returns `0` for unknown or variable-width modes.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        if self.is_64bit() {
            8
        } else if self.is_32bit() {
            4
        } else if self.is_16bit() {
            2
        } else if self.is_8bit() {
            1
        } else {
            0
        }
    }

    /// Word size in bits.
    #[must_use]
    pub fn word_bits(self) -> u32 {
        u32::try_from(self.pointer_size().saturating_mul(8)).unwrap_or(u32::MAX)
    }

    /// Return `true` if this is a compressed/variable-length instruction ISA.
    #[must_use]
    pub const fn is_variable_length(self) -> bool {
        matches!(
            self,
            Self::X86_16
                | Self::X86_32
                | Self::X86_64
                | Self::Thumb2
                | Self::MicroMips
                | Self::RiscV32
                | Self::RiscV64
                | Self::RiscV128
                | Self::Xtensa
                | Self::Wasm
                | Self::Jvm
                | Self::Cil
        )
    }

    /// Return `true` if this mode uses big-endian byte order by default.
    #[must_use]
    pub const fn is_big_endian_default(self) -> bool {
        matches!(
            self,
            Self::Mips32Be
                | Self::Mips64Be
                | Self::Ppc32Be
                | Self::Ppc64Be
                | Self::Sparc32
                | Self::Sparc64
                | Self::S390x
                | Self::M68k
                | Self::Avr
        )
    }

    /// Return the LLVM triple for this mode, or `None` if not applicable.
    #[must_use]
    pub const fn llvm_triple(self) -> Option<&'static str> {
        Some(match self {
            Self::X86_16 => "i16-unknown-unknown",
            Self::X86_32 => "i386-unknown-unknown",
            Self::X86_64 => "x86_64-unknown-unknown",
            Self::Arm32 => "armv7-unknown-unknown-eabi",
            Self::Thumb => "thumbv7m-unknown-none-eabi",
            Self::Thumb2 => "thumbv7em-unknown-none-eabi",
            Self::Aarch64 => "aarch64-unknown-unknown",
            Self::Mips32Be => "mips-unknown-unknown",
            Self::Mips32Le => "mipsel-unknown-unknown",
            Self::Mips64Be => "mips64-unknown-unknown",
            Self::Mips64Le => "mips64el-unknown-unknown",
            Self::Ppc32Be => "powerpc-unknown-unknown",
            Self::Ppc64Be => "powerpc64-unknown-unknown",
            Self::Ppc64Le => "powerpc64le-unknown-unknown",
            Self::RiscV32 => "riscv32-unknown-unknown",
            Self::RiscV64 => "riscv64-unknown-unknown",
            Self::Sparc32 => "sparc-unknown-unknown",
            Self::Sparc64 => "sparcv9-unknown-unknown",
            Self::Avr => "avr-unknown-unknown",
            Self::S390x => "s390x-unknown-unknown",
            Self::LoongArch64 => "loongarch64-unknown-unknown",
            _ => return None,
        })
    }

    /// Return the canonical short-name as a static string.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::X86_16 => "x86_16",
            Self::X86_32 => "x86_32",
            Self::X86_64 => "x86_64",
            Self::Arm32 => "arm32",
            Self::Thumb => "thumb",
            Self::Thumb2 => "thumb2",
            Self::Aarch64 => "aarch64",
            Self::Mips32Be => "mips32be",
            Self::Mips32Le => "mips32le",
            Self::Mips64Be => "mips64be",
            Self::Mips64Le => "mips64le",
            Self::Mips16 => "mips16",
            Self::MicroMips => "micromips",
            Self::Ppc32Be => "ppc32be",
            Self::Ppc32Le => "ppc32le",
            Self::Ppc64Be => "ppc64be",
            Self::Ppc64Le => "ppc64le",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::RiscV128 => "riscv128",
            Self::Sparc32 => "sparc32",
            Self::Sparc64 => "sparc64",
            Self::Avr => "avr",
            Self::Xtensa => "xtensa",
            Self::S390x => "s390x",
            Self::LoongArch32 => "loongarch32",
            Self::LoongArch64 => "loongarch64",
            Self::M68k => "m68k",
            Self::Wasm => "wasm",
            Self::Jvm => "jvm",
            Self::Cil => "cil",
            Self::Unknown => "unknown",
            Self::Custom(_) => "custom",
        }
    }

    /// Parse a mode from a short-name string (case-insensitive).
    ///
    /// Returns `None` if the name is not recognised.
    #[must_use]
    pub fn from_short_name(s: &str) -> Option<Self> {
        Some(match s.to_lowercase().as_str() {
            "x86_16" | "x86-16" | "8086" => Self::X86_16,
            "x86_32" | "x86-32" | "i386" | "ia32" => Self::X86_32,
            "x86_64" | "x86-64" | "amd64" | "x64" => Self::X86_64,
            "arm32" | "arm" | "arm-32" => Self::Arm32,
            "thumb" => Self::Thumb,
            "thumb2" | "thumb-2" => Self::Thumb2,
            "aarch64" | "arm64" | "arm-64" => Self::Aarch64,
            "mips32be" | "mips-32-be" | "mips" => Self::Mips32Be,
            "mips32le" | "mips-32-le" | "mipsel" => Self::Mips32Le,
            "mips64be" | "mips-64-be" => Self::Mips64Be,
            "mips64le" | "mips-64-le" | "mips64el" => Self::Mips64Le,
            "mips16" => Self::Mips16,
            "micromips" => Self::MicroMips,
            "ppc32be" | "ppc32" | "ppc" => Self::Ppc32Be,
            "ppc32le" => Self::Ppc32Le,
            "ppc64be" | "ppc64" => Self::Ppc64Be,
            "ppc64le" | "power8" => Self::Ppc64Le,
            "riscv32" | "rv32" => Self::RiscV32,
            "riscv64" | "rv64" => Self::RiscV64,
            "riscv128" | "rv128" => Self::RiscV128,
            "sparc32" | "sparc" => Self::Sparc32,
            "sparc64" | "sparcv9" => Self::Sparc64,
            "avr" => Self::Avr,
            "xtensa" => Self::Xtensa,
            "s390x" | "s390" | "z/architecture" => Self::S390x,
            "loongarch32" => Self::LoongArch32,
            "loongarch64" => Self::LoongArch64,
            "m68k" | "68000" | "68k" => Self::M68k,
            "wasm" | "webassembly" => Self::Wasm,
            "jvm" | "java" | "bytecode" => Self::Jvm,
            "cil" | "msil" | ".net" => Self::Cil,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_16 => write!(f, "x86_16"),
            Self::X86_32 => write!(f, "x86_32"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "ARM32"),
            Self::Thumb => write!(f, "Thumb"),
            Self::Thumb2 => write!(f, "Thumb2"),
            Self::Aarch64 => write!(f, "AArch64"),
            Self::Mips32Be => write!(f, "MIPS32-BE"),
            Self::Mips32Le => write!(f, "MIPS32-LE"),
            Self::Mips64Be => write!(f, "MIPS64-BE"),
            Self::Mips64Le => write!(f, "MIPS64-LE"),
            Self::Mips16 => write!(f, "MIPS16"),
            Self::MicroMips => write!(f, "microMIPS"),
            Self::Ppc32Be => write!(f, "PPC32-BE"),
            Self::Ppc32Le => write!(f, "PPC32-LE"),
            Self::Ppc64Be => write!(f, "PPC64-BE"),
            Self::Ppc64Le => write!(f, "PPC64-LE"),
            Self::RiscV32 => write!(f, "RV32"),
            Self::RiscV64 => write!(f, "RV64"),
            Self::RiscV128 => write!(f, "RV128"),
            Self::Sparc32 => write!(f, "SPARC32"),
            Self::Sparc64 => write!(f, "SPARC64"),
            Self::Avr => write!(f, "AVR"),
            Self::Xtensa => write!(f, "Xtensa"),
            Self::S390x => write!(f, "s390x"),
            Self::LoongArch32 => write!(f, "LoongArch32"),
            Self::LoongArch64 => write!(f, "LoongArch64"),
            Self::M68k => write!(f, "m68k"),
            Self::Wasm => write!(f, "WASM"),
            Self::Jvm => write!(f, "JVM"),
            Self::Cil => write!(f, "CIL"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Custom(tag) => write!(f, "Custom({tag})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_x86_64() {
        assert_eq!(Mode::X86_64.to_string(), "x86_64");
    }

    #[test]
    fn display_thumb() {
        assert_eq!(Mode::Thumb.to_string(), "Thumb");
    }

    #[test]
    fn display_mips16() {
        assert_eq!(Mode::Mips16.to_string(), "MIPS16");
    }

    #[test]
    fn pointer_size_x86_64() {
        assert_eq!(Mode::X86_64.pointer_size(), 8);
    }

    #[test]
    fn pointer_size_x86_32() {
        assert_eq!(Mode::X86_32.pointer_size(), 4);
    }

    #[test]
    fn pointer_size_x86_16() {
        assert_eq!(Mode::X86_16.pointer_size(), 2);
    }

    #[test]
    fn pointer_size_avr() {
        assert_eq!(Mode::Avr.pointer_size(), 1);
    }

    #[test]
    fn pointer_size_aarch64() {
        assert_eq!(Mode::Aarch64.pointer_size(), 8);
    }

    #[test]
    fn pointer_size_arm32() {
        assert_eq!(Mode::Arm32.pointer_size(), 4);
    }

    #[test]
    fn is_64bit_true() {
        assert!(Mode::X86_64.is_64bit());
        assert!(Mode::Aarch64.is_64bit());
        assert!(Mode::Ppc64Le.is_64bit());
        assert!(Mode::RiscV64.is_64bit());
    }

    #[test]
    fn is_64bit_false() {
        assert!(!Mode::X86_32.is_64bit());
        assert!(!Mode::Arm32.is_64bit());
        assert!(!Mode::X86_16.is_64bit());
    }

    #[test]
    fn is_32bit_true() {
        assert!(Mode::X86_32.is_32bit());
        assert!(Mode::Arm32.is_32bit());
        assert!(Mode::Mips32Be.is_32bit());
        assert!(Mode::RiscV32.is_32bit());
    }

    #[test]
    fn is_16bit_true() {
        assert!(Mode::X86_16.is_16bit());
        assert!(Mode::Mips16.is_16bit());
    }

    #[test]
    fn is_big_endian_default() {
        assert!(Mode::Mips32Be.is_big_endian_default());
        assert!(Mode::Ppc64Be.is_big_endian_default());
        assert!(Mode::S390x.is_big_endian_default());
        assert!(!Mode::X86_64.is_big_endian_default());
        assert!(!Mode::Aarch64.is_big_endian_default());
    }

    #[test]
    fn is_variable_length_x86() {
        assert!(Mode::X86_64.is_variable_length());
        assert!(Mode::X86_32.is_variable_length());
        assert!(Mode::X86_16.is_variable_length());
    }

    #[test]
    fn is_variable_length_fixed() {
        assert!(!Mode::Arm32.is_variable_length());
        assert!(!Mode::Ppc32Be.is_variable_length());
    }

    #[test]
    fn word_bits() {
        assert_eq!(Mode::X86_64.word_bits(), 64);
        assert_eq!(Mode::X86_32.word_bits(), 32);
        assert_eq!(Mode::X86_16.word_bits(), 16);
    }

    #[test]
    fn llvm_triple_x86_64() {
        assert_eq!(Mode::X86_64.llvm_triple(), Some("x86_64-unknown-unknown"));
    }

    #[test]
    fn llvm_triple_unknown() {
        assert!(Mode::Unknown.llvm_triple().is_none());
    }

    #[test]
    fn from_short_name_round_trip() {
        let modes = [
            Mode::X86_64,
            Mode::X86_32,
            Mode::X86_16,
            Mode::Aarch64,
            Mode::Arm32,
            Mode::Thumb,
            Mode::Thumb2,
            Mode::Mips32Be,
            Mode::Mips32Le,
            Mode::Mips64Be,
            Mode::Mips64Le,
            Mode::RiscV32,
            Mode::RiscV64,
            Mode::Avr,
        ];
        for mode in &modes {
            let name = mode.short_name();
            let parsed = Mode::from_short_name(name).expect(name);
            assert_eq!(*mode, parsed, "round-trip failed for {name}");
        }
    }

    #[test]
    fn from_short_name_aliases() {
        assert_eq!(Mode::from_short_name("amd64"), Some(Mode::X86_64));
        assert_eq!(Mode::from_short_name("arm64"), Some(Mode::Aarch64));
        assert_eq!(Mode::from_short_name("mipsel"), Some(Mode::Mips32Le));
        assert_eq!(Mode::from_short_name("rv64"), Some(Mode::RiscV64));
    }

    #[test]
    fn from_short_name_unknown() {
        assert!(Mode::from_short_name("definitely-not-a-mode").is_none());
    }

    #[test]
    fn serde_roundtrip_all_variants() {
        let modes = vec![
            Mode::X86_16,
            Mode::X86_32,
            Mode::X86_64,
            Mode::Arm32,
            Mode::Thumb,
            Mode::Thumb2,
            Mode::Aarch64,
            Mode::Mips32Be,
            Mode::Mips32Le,
            Mode::Mips64Be,
            Mode::Mips64Le,
            Mode::Mips16,
            Mode::MicroMips,
            Mode::Ppc32Be,
            Mode::Ppc32Le,
            Mode::Ppc64Be,
            Mode::Ppc64Le,
            Mode::RiscV32,
            Mode::RiscV64,
            Mode::RiscV128,
            Mode::Sparc32,
            Mode::Sparc64,
            Mode::Avr,
            Mode::Xtensa,
            Mode::S390x,
            Mode::LoongArch32,
            Mode::LoongArch64,
            Mode::M68k,
            Mode::Wasm,
            Mode::Jvm,
            Mode::Cil,
            Mode::Unknown,
            Mode::Custom(42),
        ];
        let json = serde_json::to_string(&modes).unwrap();
        let back: Vec<Mode> = serde_json::from_str(&json).unwrap();
        assert_eq!(modes, back);
    }

    #[test]
    fn custom_mode_display() {
        assert_eq!(Mode::Custom(99).to_string(), "Custom(99)");
    }

    #[test]
    fn ordering_is_defined() {
        // Modes implement PartialOrd; just confirm comparison does not panic.
        assert!(Mode::X86_16 < Mode::X86_64);
    }

    #[test]
    fn hash_works() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(Mode::X86_64, "x64");
        map.insert(Mode::Aarch64, "arm64");
        assert_eq!(map[&Mode::X86_64], "x64");
        assert_eq!(map[&Mode::Aarch64], "arm64");
    }
}
