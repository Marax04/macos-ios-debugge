//! ELF header (Ehdr) parsing — complete EI_* and EM_* constants.
//!
//! Supports both 32-bit and 64-bit ELF files in little- or big-endian byte order.

// ---------------------------------------------------------------------------
// ELF magic and ident offsets
// ---------------------------------------------------------------------------

pub const ELFMAG: &[u8; 4] = b"\x7FELF";
pub const EI_MAG0: usize = 0;
pub const EI_MAG1: usize = 1;
pub const EI_MAG2: usize = 2;
pub const EI_MAG3: usize = 3;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_ABIVERSION: usize = 8;
pub const EI_PAD: usize = 9;
pub const EI_NIDENT: usize = 16;

// ---------------------------------------------------------------------------
// EI_CLASS values
// ---------------------------------------------------------------------------

pub const ELFCLASSNONE: u8 = 0;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

// ---------------------------------------------------------------------------
// EI_DATA values
// ---------------------------------------------------------------------------

pub const ELFDATANONE: u8 = 0;
pub const ELFDATA2LSB: u8 = 1; // Little-endian
pub const ELFDATA2MSB: u8 = 2; // Big-endian

// ---------------------------------------------------------------------------
// EI_VERSION / e_version
// ---------------------------------------------------------------------------

pub const EV_NONE: u8 = 0;
pub const EV_CURRENT: u8 = 1;

// ---------------------------------------------------------------------------
// EI_OSABI values
// ---------------------------------------------------------------------------

pub const ELFOSABI_NONE: u8 = 0; // System V
pub const ELFOSABI_HPUX: u8 = 1;
pub const ELFOSABI_NETBSD: u8 = 2;
pub const ELFOSABI_LINUX: u8 = 3;
pub const ELFOSABI_SOLARIS: u8 = 6;
pub const ELFOSABI_AIX: u8 = 7;
pub const ELFOSABI_IRIX: u8 = 8;
pub const ELFOSABI_FREEBSD: u8 = 9;
pub const ELFOSABI_TRU64: u8 = 10;
pub const ELFOSABI_MODESTO: u8 = 11;
pub const ELFOSABI_OPENBSD: u8 = 12;
pub const ELFOSABI_OPENVMS: u8 = 13;
pub const ELFOSABI_NSK: u8 = 14;
pub const ELFOSABI_AROS: u8 = 15;
pub const ELFOSABI_FENIXOS: u8 = 16;
pub const ELFOSABI_CLOUDABI: u8 = 17;
pub const ELFOSABI_ARM_AEABI: u8 = 64;
pub const ELFOSABI_ARM: u8 = 97;
pub const ELFOSABI_STANDALONE: u8 = 255;

// ---------------------------------------------------------------------------
// e_type values (ET_*)
// ---------------------------------------------------------------------------

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;
pub const ET_LOOS: u16 = 0xFE00;
pub const ET_HIOS: u16 = 0xFEFF;
pub const ET_LOPROC: u16 = 0xFF00;
pub const ET_HIPROC: u16 = 0xFFFF;

/// Human-readable name for an ELF type.
#[must_use]
pub fn elf_type_name(t: u16) -> &'static str {
    match t {
        ET_NONE => "ET_NONE (None)",
        ET_REL => "ET_REL (Relocatable)",
        ET_EXEC => "ET_EXEC (Executable)",
        ET_DYN => "ET_DYN (Shared object)",
        ET_CORE => "ET_CORE (Core dump)",
        _ if (ET_LOOS..=ET_HIOS).contains(&t) => "OS-specific",
        _ if t >= ET_LOPROC => "Processor-specific",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// e_machine values (EM_*)
// ---------------------------------------------------------------------------

pub const EM_NONE: u16 = 0;
pub const EM_M32: u16 = 1;
pub const EM_SPARC: u16 = 2;
pub const EM_386: u16 = 3;
pub const EM_68K: u16 = 4;
pub const EM_88K: u16 = 5;
pub const EM_IAMCU: u16 = 6;
pub const EM_860: u16 = 7;
pub const EM_MIPS: u16 = 8;
pub const EM_S370: u16 = 9;
pub const EM_MIPS_RS3_LE: u16 = 10;
pub const EM_PARISC: u16 = 15;
pub const EM_VPP500: u16 = 17;
pub const EM_SPARC32PLUS: u16 = 18;
pub const EM_960: u16 = 19;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_SPU: u16 = 23;
pub const EM_V800: u16 = 36;
pub const EM_FR20: u16 = 37;
pub const EM_RH32: u16 = 38;
pub const EM_RCE: u16 = 39;
pub const EM_ARM: u16 = 40;
pub const EM_FAKE_ALPHA: u16 = 41;
pub const EM_SH: u16 = 42;
pub const EM_SPARCV9: u16 = 43;
pub const EM_TRICORE: u16 = 44;
pub const EM_ARC: u16 = 45;
pub const EM_H8_300: u16 = 46;
pub const EM_H8_300H: u16 = 47;
pub const EM_H8S: u16 = 48;
pub const EM_H8_500: u16 = 49;
pub const EM_IA_64: u16 = 50;
pub const EM_MIPS_X: u16 = 51;
pub const EM_COLDFIRE: u16 = 52;
pub const EM_68HC12: u16 = 53;
pub const EM_MMA: u16 = 54;
pub const EM_PCP: u16 = 55;
pub const EM_NCPU: u16 = 56;
pub const EM_NDR1: u16 = 57;
pub const EM_STARCORE: u16 = 58;
pub const EM_ME16: u16 = 59;
pub const EM_ST100: u16 = 60;
pub const EM_TINYJ: u16 = 61;
pub const EM_X86_64: u16 = 62;
pub const EM_PDSP: u16 = 63;
pub const EM_PDP10: u16 = 64;
pub const EM_PDP11: u16 = 65;
pub const EM_FX66: u16 = 66;
pub const EM_ST9PLUS: u16 = 67;
pub const EM_ST7: u16 = 68;
pub const EM_68HC16: u16 = 69;
pub const EM_68HC11: u16 = 70;
pub const EM_68HC08: u16 = 71;
pub const EM_68HC05: u16 = 72;
pub const EM_SVX: u16 = 73;
pub const EM_ST19: u16 = 74;
pub const EM_VAX: u16 = 75;
pub const EM_CRIS: u16 = 76;
pub const EM_JAVELIN: u16 = 77;
pub const EM_FIREPATH: u16 = 78;
pub const EM_ZSP: u16 = 79;
pub const EM_MMIX: u16 = 80;
pub const EM_HUANY: u16 = 81;
pub const EM_PRISM: u16 = 82;
pub const EM_AVR: u16 = 83;
pub const EM_FR30: u16 = 84;
pub const EM_D10V: u16 = 85;
pub const EM_D30V: u16 = 86;
pub const EM_V850: u16 = 87;
pub const EM_M32R: u16 = 88;
pub const EM_MN10300: u16 = 89;
pub const EM_MN10200: u16 = 90;
pub const EM_PJ: u16 = 91;
pub const EM_OPENRISC: u16 = 92;
pub const EM_ARC_COMPACT: u16 = 93;
pub const EM_XTENSA: u16 = 94;
pub const EM_VIDEOCORE: u16 = 95;
pub const EM_TMM_GPP: u16 = 96;
pub const EM_NS32K: u16 = 97;
pub const EM_TPC: u16 = 98;
pub const EM_SNP1K: u16 = 99;
pub const EM_ST200: u16 = 100;
pub const EM_MSP430: u16 = 105;
pub const EM_BLACKFIN: u16 = 106;
pub const EM_ALTERA_NIOS2: u16 = 113;
pub const EM_CRX: u16 = 114;
pub const EM_MICROBLAZE: u16 = 189;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;
pub const EM_BPF: u16 = 247;
pub const EM_CSKY: u16 = 252;
pub const EM_LOONGARCH: u16 = 258;

/// Human-readable name for an ELF machine type.
#[must_use]
pub const fn elf_machine_name(m: u16) -> &'static str {
    match m {
        EM_NONE => "None",
        EM_M32 => "WE32100",
        EM_SPARC => "SPARC",
        EM_386 => "i386",
        EM_68K => "68000",
        EM_88K => "88000",
        EM_IAMCU => "Intel MCU",
        EM_860 => "Intel 80860",
        EM_MIPS => "MIPS",
        EM_S370 => "IBM System/370",
        EM_MIPS_RS3_LE => "MIPS RS3000 LE",
        EM_PARISC => "HP PA-RISC",
        EM_PPC => "PowerPC 32",
        EM_PPC64 => "PowerPC 64",
        EM_S390 => "IBM S390",
        EM_ARM => "ARM",
        EM_SH => "SuperH",
        EM_SPARCV9 => "SPARC V9",
        EM_IA_64 => "IA-64",
        EM_X86_64 => "x86-64",
        EM_AVR => "Atmel AVR",
        EM_OPENRISC => "OpenRISC",
        EM_XTENSA => "Xtensa",
        EM_MSP430 => "MSP430",
        EM_BLACKFIN => "Blackfin",
        EM_ALTERA_NIOS2 => "Altera NIOS II",
        EM_AARCH64 => "AArch64",
        EM_RISCV => "RISC-V",
        EM_BPF => "eBPF",
        EM_CSKY => "C-SKY",
        EM_LOONGARCH => "LoongArch",
        EM_MICROBLAZE => "MicroBlaze",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// ELF class name
// ---------------------------------------------------------------------------

/// Human-readable class name.
#[must_use]
pub const fn elf_class_name(c: u8) -> &'static str {
    match c {
        ELFCLASSNONE => "None",
        ELFCLASS32 => "ELF32",
        ELFCLASS64 => "ELF64",
        _ => "Unknown",
    }
}

/// Human-readable data encoding name.
#[must_use]
pub const fn elf_data_name(d: u8) -> &'static str {
    match d {
        ELFDATANONE => "None",
        ELFDATA2LSB => "Little-endian (2's complement)",
        ELFDATA2MSB => "Big-endian (2's complement)",
        _ => "Unknown",
    }
}

/// Human-readable OS/ABI name.
#[must_use]
pub const fn elf_osabi_name(abi: u8) -> &'static str {
    match abi {
        ELFOSABI_NONE => "System V / None",
        ELFOSABI_HPUX => "HP-UX",
        ELFOSABI_NETBSD => "NetBSD",
        ELFOSABI_LINUX => "Linux",
        ELFOSABI_SOLARIS => "Solaris",
        ELFOSABI_AIX => "AIX",
        ELFOSABI_IRIX => "IRIX",
        ELFOSABI_FREEBSD => "FreeBSD",
        ELFOSABI_TRU64 => "TRU64 UNIX",
        ELFOSABI_OPENBSD => "OpenBSD",
        ELFOSABI_ARM_AEABI => "ARM EABI",
        ELFOSABI_ARM => "ARM",
        ELFOSABI_STANDALONE => "Standalone (embedded)",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Ehdr32 / Ehdr64
// ---------------------------------------------------------------------------

/// Parsed 32-bit ELF header (Ehdr32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ehdr32 {
    /// `e_ident` bytes.
    pub ident: [u8; EI_NIDENT],
    /// Object file type (ET_*).
    pub e_type: u16,
    /// Architecture (EM_*).
    pub e_machine: u16,
    /// Object file version (`EV_CURRENT`).
    pub e_version: u32,
    /// Entry point virtual address.
    pub e_entry: u32,
    /// Program header table file offset.
    pub e_phoff: u32,
    /// Section header table file offset.
    pub e_shoff: u32,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes (52).
    pub e_ehsize: u16,
    /// Program header entry size.
    pub e_phentsize: u16,
    /// Number of program headers.
    pub e_phnum: u16,
    /// Section header entry size.
    pub e_shentsize: u16,
    /// Number of section headers.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

impl Ehdr32 {
    /// Parse a 52-byte ELF32 header.
    ///
    /// # Errors
    /// Returns an error string if the data is too short or malformed.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 52 {
            return Err(format!(
                "ELF32 header truncated: need 52 bytes, have {}",
                data.len()
            ));
        }
        if &data[0..4] != ELFMAG {
            return Err("Not an ELF file (bad magic)".into());
        }
        if data[EI_CLASS] != ELFCLASS32 {
            return Err(format!("Expected ELFCLASS32 (1), got {}", data[EI_CLASS]));
        }

        let le = data[EI_DATA] == ELFDATA2LSB;
        let r16 = |off: usize| -> u16 {
            let b = [data[off], data[off + 1]];
            if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };

        let mut ident = [0u8; EI_NIDENT];
        ident.copy_from_slice(&data[0..EI_NIDENT]);

        Ok(Self {
            ident,
            e_type: r16(16),
            e_machine: r16(18),
            e_version: r32(20),
            e_entry: r32(24),
            e_phoff: r32(28),
            e_shoff: r32(32),
            e_flags: r32(36),
            e_ehsize: r16(40),
            e_phentsize: r16(42),
            e_phnum: r16(44),
            e_shentsize: r16(46),
            e_shnum: r16(48),
            e_shstrndx: r16(50),
        })
    }

    /// Returns `true` for little-endian.
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        self.ident[EI_DATA] == ELFDATA2LSB
    }

    /// Returns the OS/ABI byte.
    #[must_use]
    pub const fn osabi(&self) -> u8 {
        self.ident[EI_OSABI]
    }
}

/// Parsed 64-bit ELF header (Ehdr64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ehdr64 {
    /// `e_ident` bytes.
    pub ident: [u8; EI_NIDENT],
    /// Object file type (ET_*).
    pub e_type: u16,
    /// Architecture (EM_*).
    pub e_machine: u16,
    /// Object file version.
    pub e_version: u32,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size (64).
    pub e_ehsize: u16,
    /// Program header entry size.
    pub e_phentsize: u16,
    /// Number of program headers.
    pub e_phnum: u16,
    /// Section header entry size.
    pub e_shentsize: u16,
    /// Number of section headers.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

impl Ehdr64 {
    /// Parse a 64-byte ELF64 header.
    ///
    /// # Errors
    /// Returns an error string if the data is too short or malformed.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 64 {
            return Err(format!(
                "ELF64 header truncated: need 64 bytes, have {}",
                data.len()
            ));
        }
        if &data[0..4] != ELFMAG {
            return Err("Not an ELF file (bad magic)".into());
        }
        if data[EI_CLASS] != ELFCLASS64 {
            return Err(format!("Expected ELFCLASS64 (2), got {}", data[EI_CLASS]));
        }

        let le = data[EI_DATA] == ELFDATA2LSB;
        let r16 = |off: usize| -> u16 {
            let b = [data[off], data[off + 1]];
            if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let r64 = |off: usize| -> u64 {
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap_or([0; 8]);
            if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };

        let mut ident = [0u8; EI_NIDENT];
        ident.copy_from_slice(&data[0..EI_NIDENT]);

        Ok(Self {
            ident,
            e_type: r16(16),
            e_machine: r16(18),
            e_version: r32(20),
            e_entry: r64(24),
            e_phoff: r64(32),
            e_shoff: r64(40),
            e_flags: r32(48),
            e_ehsize: r16(52),
            e_phentsize: r16(54),
            e_phnum: r16(56),
            e_shentsize: r16(58),
            e_shnum: r16(60),
            e_shstrndx: r16(62),
        })
    }

    /// Returns `true` for little-endian.
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        self.ident[EI_DATA] == ELFDATA2LSB
    }

    /// Returns the OS/ABI byte.
    #[must_use]
    pub const fn osabi(&self) -> u8 {
        self.ident[EI_OSABI]
    }
}

// ---------------------------------------------------------------------------
// Generic ELF header
// ---------------------------------------------------------------------------

/// Unified ELF header (either 32-bit or 64-bit).
#[derive(Debug, Clone)]
pub enum ElfHeader {
    Elf32(Ehdr32),
    Elf64(Ehdr64),
}

impl ElfHeader {
    /// Parse an ELF header from the beginning of `data`, auto-detecting class.
    ///
    /// # Errors
    /// Returns an error string if the data is too short or not a valid ELF header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < EI_NIDENT {
            return Err("File too small for ELF ident".into());
        }
        if &data[0..4] != ELFMAG {
            return Err("Not an ELF file".into());
        }
        match data[EI_CLASS] {
            ELFCLASS32 => Ehdr32::parse(data).map(ElfHeader::Elf32),
            ELFCLASS64 => Ehdr64::parse(data).map(ElfHeader::Elf64),
            c => Err(format!("Unknown ELF class {c}")),
        }
    }

    /// Returns the machine type (EM_*).
    #[must_use]
    pub const fn machine(&self) -> u16 {
        match self {
            Self::Elf32(h) => h.e_machine,
            Self::Elf64(h) => h.e_machine,
        }
    }

    /// Returns the file type (ET_*).
    #[must_use]
    pub const fn elf_type(&self) -> u16 {
        match self {
            Self::Elf32(h) => h.e_type,
            Self::Elf64(h) => h.e_type,
        }
    }

    /// Returns `true` for 64-bit ELF.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        matches!(self, Self::Elf64(_))
    }

    /// Returns `true` for little-endian.
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        match self {
            Self::Elf32(h) => h.is_little_endian(),
            Self::Elf64(h) => h.is_little_endian(),
        }
    }

    /// Returns the entry point as a u64.
    #[must_use]
    pub const fn entry_point(&self) -> u64 {
        match self {
            Self::Elf32(h) => h.e_entry as u64,
            Self::Elf64(h) => h.e_entry,
        }
    }

    /// Returns `e_flags`.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        match self {
            Self::Elf32(h) => h.e_flags,
            Self::Elf64(h) => h.e_flags,
        }
    }
}

// ---------------------------------------------------------------------------
// ARM-specific e_flags
// ---------------------------------------------------------------------------

pub const EF_ARM_EABI_MASK: u32 = 0xFF00_0000;
pub const EF_ARM_EABI_VER1: u32 = 0x0100_0000;
pub const EF_ARM_EABI_VER2: u32 = 0x0200_0000;
pub const EF_ARM_EABI_VER3: u32 = 0x0300_0000;
pub const EF_ARM_EABI_VER4: u32 = 0x0400_0000;
pub const EF_ARM_EABI_VER5: u32 = 0x0500_0000;
pub const EF_ARM_INTERWORK: u32 = 0x0000_0004;
pub const EF_ARM_APCS_26: u32 = 0x0000_0008;
pub const EF_ARM_APCS_FLOAT: u32 = 0x0000_0010;
pub const EF_ARM_PIC: u32 = 0x0000_0020;
pub const EF_ARM_ALIGN8: u32 = 0x0000_0040;
pub const EF_ARM_NEW_ABI: u32 = 0x0000_0080;
pub const EF_ARM_OLD_ABI: u32 = 0x0000_0100;
pub const EF_ARM_SOFT_FLOAT: u32 = 0x0000_0200;
pub const EF_ARM_VFP_FLOAT: u32 = 0x0000_0400;
pub const EF_ARM_MAVERICK_FLOAT: u32 = 0x0000_0800;
pub const EF_ARM_THUMB_EE: u32 = 0x0000_2000;

/// Decode the ARM EABI version from `e_flags`.
#[must_use]
pub const fn arm_eabi_version(flags: u32) -> u32 {
    (flags & EF_ARM_EABI_MASK) >> 24
}

// ---------------------------------------------------------------------------
// RISC-V e_flags
// ---------------------------------------------------------------------------

pub const EF_RISCV_RVC: u32 = 0x0000_0001;
pub const EF_RISCV_FLOAT_ABI_MASK: u32 = 0x0000_0006;
pub const EF_RISCV_FLOAT_ABI_SOFT: u32 = 0x0000_0000;
pub const EF_RISCV_FLOAT_ABI_SINGLE: u32 = 0x0000_0002;
pub const EF_RISCV_FLOAT_ABI_DOUBLE: u32 = 0x0000_0004;
pub const EF_RISCV_FLOAT_ABI_QUAD: u32 = 0x0000_0006;
pub const EF_RISCV_RVE: u32 = 0x0000_0008;
pub const EF_RISCV_TSO: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elf32_header(machine: u16, entry: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 52];
        buf[0..4].copy_from_slice(ELFMAG);
        buf[EI_CLASS] = ELFCLASS32;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version = EV_CURRENT
        buf[24..28].copy_from_slice(&entry.to_le_bytes());
        buf[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        buf
    }

    fn make_elf64_header(machine: u16, entry: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(ELFMAG);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&entry.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf
    }

    #[test]
    fn test_parse_elf32_header() {
        let buf = make_elf32_header(EM_386, 0x0804_8000);
        let hdr = Ehdr32::parse(&buf).unwrap();
        assert_eq!(hdr.e_machine, EM_386);
        assert_eq!(hdr.e_entry, 0x0804_8000);
        assert_eq!(hdr.e_type, ET_EXEC);
        assert!(hdr.is_little_endian());
    }

    #[test]
    fn test_parse_elf64_header() {
        let buf = make_elf64_header(EM_X86_64, 0x0040_1000);
        let hdr = Ehdr64::parse(&buf).unwrap();
        assert_eq!(hdr.e_machine, EM_X86_64);
        assert_eq!(hdr.e_entry, 0x0040_1000);
        assert_eq!(hdr.e_type, ET_EXEC);
        assert!(hdr.is_little_endian());
    }

    #[test]
    fn test_elf_header_auto_detect_32() {
        let buf = make_elf32_header(EM_ARM, 0x10000);
        let hdr = ElfHeader::parse(&buf).unwrap();
        assert!(!hdr.is_64bit());
        assert_eq!(hdr.machine(), EM_ARM);
        assert_eq!(hdr.entry_point(), 0x10000);
    }

    #[test]
    fn test_elf_header_auto_detect_64() {
        let buf = make_elf64_header(EM_AARCH64, 0x0040_0000);
        let hdr = ElfHeader::parse(&buf).unwrap();
        assert!(hdr.is_64bit());
        assert_eq!(hdr.machine(), EM_AARCH64);
    }

    #[test]
    fn test_elf32_bad_magic() {
        let mut buf = make_elf32_header(EM_386, 0);
        buf[0] = 0x00; // break magic
        assert!(Ehdr32::parse(&buf).is_err());
    }

    #[test]
    fn test_elf64_bad_class() {
        let mut buf = make_elf64_header(EM_X86_64, 0);
        buf[EI_CLASS] = ELFCLASS32; // wrong class
        assert!(Ehdr64::parse(&buf).is_err());
    }

    #[test]
    fn test_elf_type_name() {
        assert_eq!(elf_type_name(ET_EXEC), "ET_EXEC (Executable)");
        assert_eq!(elf_type_name(ET_DYN), "ET_DYN (Shared object)");
        assert_eq!(elf_type_name(ET_CORE), "ET_CORE (Core dump)");
        assert_eq!(elf_type_name(0xFFFF), "Processor-specific");
    }

    #[test]
    fn test_elf_machine_name() {
        assert_eq!(elf_machine_name(EM_X86_64), "x86-64");
        assert_eq!(elf_machine_name(EM_ARM), "ARM");
        assert_eq!(elf_machine_name(EM_AARCH64), "AArch64");
        assert_eq!(elf_machine_name(EM_RISCV), "RISC-V");
        assert_eq!(elf_machine_name(9999), "Unknown");
    }

    #[test]
    fn test_elf_class_name() {
        assert_eq!(elf_class_name(ELFCLASS32), "ELF32");
        assert_eq!(elf_class_name(ELFCLASS64), "ELF64");
        assert_eq!(elf_class_name(99), "Unknown");
    }

    #[test]
    fn test_elf_osabi_name() {
        assert_eq!(elf_osabi_name(ELFOSABI_NONE), "System V / None");
        assert_eq!(elf_osabi_name(ELFOSABI_LINUX), "Linux");
        assert_eq!(elf_osabi_name(ELFOSABI_FREEBSD), "FreeBSD");
    }

    #[test]
    fn test_arm_eabi_version() {
        let flags = EF_ARM_EABI_VER5 | EF_ARM_SOFT_FLOAT;
        assert_eq!(arm_eabi_version(flags), 5);
    }

    #[test]
    fn test_elf_header_too_short() {
        assert!(ElfHeader::parse(&[0u8; 4]).is_err());
        assert!(Ehdr32::parse(&[0u8; 10]).is_err());
        assert!(Ehdr64::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_elf_header_unknown_class() {
        let mut buf = make_elf32_header(EM_386, 0);
        buf[EI_CLASS] = 99;
        assert!(ElfHeader::parse(&buf).is_err());
    }
}
