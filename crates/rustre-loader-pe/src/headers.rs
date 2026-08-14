//! Complete PE header structures: DOS, COFF, Optional (PE32/PE32+),
//! data directories, section characteristics, and Rich header decoding.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"

// Optional header magic
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

// Machine types
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01A2;
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01A3;
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01A6;
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01A8;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01C2;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01D3;
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01F1;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0CEF;
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xC0EE;
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
pub const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;

// COFF characteristics
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

// Section characteristics
pub const IMAGE_SCN_TYPE_REG: u32 = 0x0000_0000;
pub const IMAGE_SCN_TYPE_DSECT: u32 = 0x0000_0001;
pub const IMAGE_SCN_TYPE_NOLOAD: u32 = 0x0000_0002;
pub const IMAGE_SCN_TYPE_GROUP: u32 = 0x0000_0004;
pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x0000_0008;
pub const IMAGE_SCN_TYPE_COPY: u32 = 0x0000_0010;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_OTHER: u32 = 0x0000_0100;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_NO_DEFER_SPEC_EXC: u32 = 0x0000_4000;
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
pub const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x0002_0000;
pub const IMAGE_SCN_MEM_16BIT: u32 = 0x0002_0000;
pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x0004_0000;
pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x0008_0000;
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A0_0000;
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B0_0000;
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C0_0000;
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D0_0000;
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E0_0000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// Rich header magic bytes
const RICH_MAGIC: &[u8; 4] = b"Rich";
const DANS_MAGIC: &[u8; 4] = b"DanS";

// ---------------------------------------------------------------------------
// DOS Header
// ---------------------------------------------------------------------------

/// `IMAGE_DOS_HEADER` — the MZ header at the start of every PE file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    /// Magic number: must be 0x5A4D ("MZ").
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File address of new exe header (`e_lfanew`).
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Parse a `DosHeader` from the beginning of `data`.
    ///
    /// # Errors
    /// Returns `Err` if data is too short or the magic is wrong.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 64 {
            return Err(format!("DOS header too short: {} bytes", data.len()));
        }
        let r16 = |off: usize| -> u16 {
            data.get(off..off + 2)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u16::from_le_bytes)
        };
        let r32 = |off: usize| -> u32 {
            data.get(off..off + 4)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };

        let e_magic = r16(0);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!("Invalid DOS magic: 0x{e_magic:04X}"));
        }

        let mut e_res = [0u16; 4];
        for (i, val) in e_res.iter_mut().enumerate() {
            *val = r16(28 + i * 2);
        }
        let mut e_res2 = [0u16; 10];
        for (i, val) in e_res2.iter_mut().enumerate() {
            *val = r16(40 + i * 2);
        }

        Ok(Self {
            e_magic,
            e_cblp: r16(2),
            e_cp: r16(4),
            e_crlc: r16(6),
            e_cparhdr: r16(8),
            e_minalloc: r16(10),
            e_maxalloc: r16(12),
            e_ss: r16(14),
            e_sp: r16(16),
            e_csum: r16(18),
            e_ip: r16(20),
            e_cs: r16(22),
            e_lfarlc: r16(24),
            e_ovno: r16(26),
            e_res,
            e_oemid: r16(36),
            e_oeminfo: r16(38),
            e_res2,
            e_lfanew: r32(60),
        })
    }

    /// Return the file offset of the PE signature.
    #[must_use]
    pub const fn pe_offset(&self) -> usize {
        self.e_lfanew as usize
    }
}

// ---------------------------------------------------------------------------
// COFF File Header
// ---------------------------------------------------------------------------

/// `IMAGE_FILE_HEADER` — the COFF file header immediately after the PE signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffFileHeader {
    /// Target machine type (see `IMAGE_FILE_MACHINE_*` constants).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Unix timestamp of when the file was created.
    pub time_date_stamp: u32,
    /// File offset of the symbol table (usually 0 for PE files).
    pub pointer_to_symbol_table: u32,
    /// Number of symbols.
    pub number_of_symbols: u32,
    /// Size of the optional header.
    pub size_of_optional_header: u16,
    /// File characteristics bitfield.
    pub characteristics: u16,
}

impl CoffFileHeader {
    /// Parse a 20-byte `CoffFileHeader` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 20 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 20 > data.len() {
            return Err(format!("COFF header truncated at offset {offset}"));
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;
        Ok(Self {
            machine: r16(b),
            number_of_sections: r16(b + 2),
            time_date_stamp: r32(b + 4),
            pointer_to_symbol_table: r32(b + 8),
            number_of_symbols: r32(b + 12),
            size_of_optional_header: r16(b + 16),
            characteristics: r16(b + 18),
        })
    }

    /// Return `true` if this file has the DLL flag set.
    #[must_use]
    pub const fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    /// Return `true` if this is an executable image.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0
    }

    /// Return `true` if this has large address awareness.
    #[must_use]
    pub const fn is_large_address_aware(&self) -> bool {
        self.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0
    }

    /// Return a human-readable name for the machine type.
    #[must_use]
    pub const fn machine_name(&self) -> &'static str {
        match self.machine {
            IMAGE_FILE_MACHINE_I386 => "x86",
            IMAGE_FILE_MACHINE_AMD64 => "x86-64",
            IMAGE_FILE_MACHINE_ARM => "ARM",
            IMAGE_FILE_MACHINE_ARMNT => "ARMv7 (ARMNT)",
            IMAGE_FILE_MACHINE_ARM64 => "ARM64",
            IMAGE_FILE_MACHINE_IA64 => "Intel Itanium",
            IMAGE_FILE_MACHINE_POWERPC => "PowerPC",
            IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
            IMAGE_FILE_MACHINE_RISCV32 => "RISC-V 32-bit",
            IMAGE_FILE_MACHINE_RISCV64 => "RISC-V 64-bit",
            IMAGE_FILE_MACHINE_EBC => "EFI Byte Code",
            0 => "Unknown",
            _ => "Other",
        }
    }
}

// ---------------------------------------------------------------------------
// Data Directory
// ---------------------------------------------------------------------------

/// One entry of the data directory array in the optional header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    /// Virtual address of this directory.
    pub virtual_address: u32,
    /// Size in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Return `true` if this directory entry is present (non-zero address and size).
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

// ---------------------------------------------------------------------------
// Optional Header — PE32
// ---------------------------------------------------------------------------

/// `IMAGE_OPTIONAL_HEADER32` — 32-bit PE optional header.
#[derive(Debug, Clone)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader32 {
    /// Parse a PE32 optional header from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the magic number is wrong.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 96 > data.len() {
            return Err("Optional header PE32 truncated".into());
        }
        let r8 = |off: usize| -> u8 { data.get(off).copied().unwrap_or(0) };
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;

        let magic = r16(b);
        if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
            return Err(format!("Expected PE32 magic 0x010B, got 0x{magic:04X}"));
        }

        let number_of_rva_and_sizes = r32(b + 92);
        let dir_count = (number_of_rva_and_sizes as usize).min(16);
        let mut data_directory = Vec::with_capacity(dir_count);
        for i in 0..dir_count {
            let dir_off = b + 96 + i * 8;
            if dir_off + 8 > data.len() {
                break;
            }
            data_directory.push(DataDirectory {
                virtual_address: r32(dir_off),
                size: r32(dir_off + 4),
            });
        }
        // Pad to 16 entries
        while data_directory.len() < 16 {
            data_directory.push(DataDirectory {
                virtual_address: 0,
                size: 0,
            });
        }

        Ok(Self {
            magic,
            major_linker_version: r8(b + 2),
            minor_linker_version: r8(b + 3),
            size_of_code: r32(b + 4),
            size_of_initialized_data: r32(b + 8),
            size_of_uninitialized_data: r32(b + 12),
            address_of_entry_point: r32(b + 16),
            base_of_code: r32(b + 20),
            base_of_data: r32(b + 24),
            image_base: r32(b + 28),
            section_alignment: r32(b + 32),
            file_alignment: r32(b + 36),
            major_os_version: r16(b + 40),
            minor_os_version: r16(b + 42),
            major_image_version: r16(b + 44),
            minor_image_version: r16(b + 46),
            major_subsystem_version: r16(b + 48),
            minor_subsystem_version: r16(b + 50),
            win32_version_value: r32(b + 52),
            size_of_image: r32(b + 56),
            size_of_headers: r32(b + 60),
            checksum: r32(b + 64),
            subsystem: r16(b + 68),
            dll_characteristics: r16(b + 70),
            size_of_stack_reserve: r32(b + 72),
            size_of_stack_commit: r32(b + 76),
            size_of_heap_reserve: r32(b + 80),
            size_of_heap_commit: r32(b + 84),
            loader_flags: r32(b + 88),
            number_of_rva_and_sizes,
            data_directory,
        })
    }
}

// ---------------------------------------------------------------------------
// Optional Header — PE32+ (64-bit)
// ---------------------------------------------------------------------------

/// `IMAGE_OPTIONAL_HEADER64` — 64-bit PE optional header.
#[derive(Debug, Clone)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader64 {
    /// Parse a PE32+ optional header from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the magic number is wrong.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 112 > data.len() {
            return Err("Optional header PE32+ truncated".into());
        }
        let r8 = |off: usize| -> u8 { data.get(off).copied().unwrap_or(0) };
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let r64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        };
        let b = offset;

        let magic = r16(b);
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(format!("Expected PE32+ magic 0x020B, got 0x{magic:04X}"));
        }

        let number_of_rva_and_sizes = r32(b + 108);
        let dir_count = (number_of_rva_and_sizes as usize).min(16);
        let mut data_directory = Vec::with_capacity(dir_count);
        for i in 0..dir_count {
            let dir_off = b + 112 + i * 8;
            if dir_off + 8 > data.len() {
                break;
            }
            data_directory.push(DataDirectory {
                virtual_address: r32(dir_off),
                size: r32(dir_off + 4),
            });
        }
        while data_directory.len() < 16 {
            data_directory.push(DataDirectory {
                virtual_address: 0,
                size: 0,
            });
        }

        Ok(Self {
            magic,
            major_linker_version: r8(b + 2),
            minor_linker_version: r8(b + 3),
            size_of_code: r32(b + 4),
            size_of_initialized_data: r32(b + 8),
            size_of_uninitialized_data: r32(b + 12),
            address_of_entry_point: r32(b + 16),
            base_of_code: r32(b + 20),
            image_base: r64(b + 24),
            section_alignment: r32(b + 32),
            file_alignment: r32(b + 36),
            major_os_version: r16(b + 40),
            minor_os_version: r16(b + 42),
            major_image_version: r16(b + 44),
            minor_image_version: r16(b + 46),
            major_subsystem_version: r16(b + 48),
            minor_subsystem_version: r16(b + 50),
            win32_version_value: r32(b + 52),
            size_of_image: r32(b + 56),
            size_of_headers: r32(b + 60),
            checksum: r32(b + 64),
            subsystem: r16(b + 68),
            dll_characteristics: r16(b + 70),
            size_of_stack_reserve: r64(b + 72),
            size_of_stack_commit: r64(b + 80),
            size_of_heap_reserve: r64(b + 88),
            size_of_heap_commit: r64(b + 96),
            loader_flags: r32(b + 104),
            number_of_rva_and_sizes,
            data_directory,
        })
    }
}

// ---------------------------------------------------------------------------
// Optional Header Variant
// ---------------------------------------------------------------------------

/// Either a PE32 or PE32+ optional header.
#[derive(Debug, Clone)]
pub enum OptionalHeader {
    /// 32-bit PE optional header.
    Pe32(OptionalHeader32),
    /// 64-bit PE+ optional header.
    Pe64(OptionalHeader64),
}

impl OptionalHeader {
    /// Parse by inspecting the magic number at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the magic is not PE32 or PE32+.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 2 > data.len() {
            return Err("Not enough data to read optional header magic".into());
        }
        let magic = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]));
        match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Ok(Self::Pe32(OptionalHeader32::parse(data, offset)?)),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Ok(Self::Pe64(OptionalHeader64::parse(data, offset)?)),
            other => Err(format!("Unknown optional header magic: 0x{other:04X}")),
        }
    }

    /// Return the image base.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        match self {
            Self::Pe32(h) => u64::from(h.image_base),
            Self::Pe64(h) => h.image_base,
        }
    }

    /// Return the address of the entry point (RVA).
    #[must_use]
    pub const fn entry_point_rva(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.address_of_entry_point,
            Self::Pe64(h) => h.address_of_entry_point,
        }
    }

    /// Return the subsystem value.
    #[must_use]
    pub const fn subsystem(&self) -> u16 {
        match self {
            Self::Pe32(h) => h.subsystem,
            Self::Pe64(h) => h.subsystem,
        }
    }

    /// Return a data directory entry by index.
    #[must_use]
    pub fn data_dir(&self, idx: usize) -> Option<&DataDirectory> {
        match self {
            Self::Pe32(h) => h.data_directory.get(idx),
            Self::Pe64(h) => h.data_directory.get(idx),
        }
    }

    /// Return all data directory entries.
    #[must_use]
    pub fn data_directories(&self) -> &[DataDirectory] {
        match self {
            Self::Pe32(h) => &h.data_directory,
            Self::Pe64(h) => &h.data_directory,
        }
    }

    /// Return the section alignment.
    #[must_use]
    pub const fn section_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.section_alignment,
            Self::Pe64(h) => h.section_alignment,
        }
    }

    /// Return the file alignment.
    #[must_use]
    pub const fn file_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.file_alignment,
            Self::Pe64(h) => h.file_alignment,
        }
    }

    /// Return the DLL characteristics bitfield.
    #[must_use]
    pub const fn dll_characteristics(&self) -> u16 {
        match self {
            Self::Pe32(h) => h.dll_characteristics,
            Self::Pe64(h) => h.dll_characteristics,
        }
    }
}

// ---------------------------------------------------------------------------
// Section Header
// ---------------------------------------------------------------------------

/// Parsed PE section header (`IMAGE_SECTION_HEADER`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section name (up to 8 bytes, NUL-trimmed).
    pub name: String,
    /// The virtual size of the section when loaded.
    pub virtual_size: u32,
    /// The RVA of the section when loaded.
    pub virtual_address: u32,
    /// The size of the section data in the file.
    pub size_of_raw_data: u32,
    /// File offset of the section data.
    pub pointer_to_raw_data: u32,
    /// File offset of relocations.
    pub pointer_to_relocations: u32,
    /// File offset of line numbers.
    pub pointer_to_linenumbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_linenumbers: u16,
    /// Section characteristics bitfield.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Parse one 40-byte section header from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 40 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 40 > data.len() {
            return Err(format!("Section header at {offset} truncated"));
        }
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;

        let raw_name = &data[b..b + 8];
        let name_end = raw_name.iter().position(|&x| x == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();

        Ok(Self {
            name,
            virtual_size: r32(b + 8),
            virtual_address: r32(b + 12),
            size_of_raw_data: r32(b + 16),
            pointer_to_raw_data: r32(b + 20),
            pointer_to_relocations: r32(b + 24),
            pointer_to_linenumbers: r32(b + 28),
            number_of_relocations: r16(b + 32),
            number_of_linenumbers: r16(b + 34),
            characteristics: r32(b + 36),
        })
    }

    /// Parse all section headers following the optional header.
    #[must_use]
    pub fn parse_all(
        data: &[u8],
        pe_offset: usize,
        coff_size_of_optional: u16,
        num_sections: u16,
    ) -> Vec<Self> {
        // sections start after PE sig (4) + COFF header (20) + optional header
        let sections_start = pe_offset + 4 + 20 + coff_size_of_optional as usize;
        // `num_sections` is a raw u16 from the COFF header: cap the
        // pre-allocation by the bytes remaining (40 bytes per section header).
        let cap = (num_sections as usize).min(data.len().saturating_sub(sections_start) / 40);
        let mut sections = Vec::with_capacity(cap);
        for i in 0..num_sections as usize {
            let off = sections_start + i * 40;
            if let Ok(sec) = Self::parse(data, off) {
                sections.push(sec);
            }
        }
        sections
    }

    /// Return `true` if this section contains executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
            || self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Return `true` if this section is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Return `true` if this section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Return `true` if this section is discardable.
    #[must_use]
    pub const fn is_discardable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0
    }

    /// Return the decoded alignment in bytes, or 0 if unspecified.
    #[must_use]
    pub const fn alignment(&self) -> u32 {
        let align_field = (self.characteristics >> 20) & 0xF;
        match align_field {
            0 => 0,
            n => 1u32 << (n - 1),
        }
    }

    /// Describe characteristics as a readable string.
    #[must_use]
    pub fn characteristics_str(&self) -> String {
        let mut parts = Vec::new();
        if self.characteristics & IMAGE_SCN_CNT_CODE != 0 {
            parts.push("CODE");
        }
        if self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            parts.push("IDATA");
        }
        if self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            parts.push("UDATA");
        }
        if self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            parts.push("EXEC");
        }
        if self.characteristics & IMAGE_SCN_MEM_READ != 0 {
            parts.push("READ");
        }
        if self.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            parts.push("WRITE");
        }
        if self.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 {
            parts.push("DISC");
        }
        if self.characteristics & IMAGE_SCN_MEM_NOT_PAGED != 0 {
            parts.push("NOTPG");
        }
        if self.characteristics & IMAGE_SCN_MEM_SHARED != 0 {
            parts.push("SHARED");
        }
        parts.join("|")
    }
}

// ---------------------------------------------------------------------------
// Rich Header
// ---------------------------------------------------------------------------

/// Known compiler/linker product IDs extracted from the Rich header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichProductInfo {
    /// Linker/compiler product ID (top 16 bits of `CompID`).
    pub product_id: u16,
    /// Build number (bottom 16 bits of `CompID`).
    pub build_number: u16,
    /// Number of objects compiled with this tool.
    pub count: u32,
    /// Human-readable tool name (best-effort).
    pub tool_name: String,
}

/// Decoded Rich header from the DOS stub.
#[derive(Debug, Clone)]
pub struct RichHeader {
    /// XOR key used to obfuscate the entries.
    pub key: u32,
    /// Decoded product entries.
    pub products: Vec<RichProductInfo>,
}

impl RichHeader {
    /// Parse the Rich header from the DOS stub region `[64..pe_offset)` in `data`.
    ///
    /// Returns `None` if no valid Rich header is present.
    #[must_use]
    pub fn parse(data: &[u8], pe_offset: usize) -> Option<Self> {
        if pe_offset < 64 || pe_offset > data.len() {
            return None;
        }
        let stub = &data[64..pe_offset];

        // Locate "Rich" marker (must be followed by the 4-byte XOR key)
        let rich_pos = stub.windows(4).position(|w| w == RICH_MAGIC)?;
        if rich_pos + 8 > stub.len() {
            return None;
        }
        let key = u32::from_le_bytes(stub[rich_pos + 4..rich_pos + 8].try_into().ok()?);

        // Verify "DanS" at the start of the stub (first DWORD XOR'd with key)
        if stub.len() < 4 {
            return None;
        }
        let first = u32::from_le_bytes(stub[0..4].try_into().ok()?);
        if first ^ key != u32::from_le_bytes(*DANS_MAGIC) {
            return None;
        }

        // Payload: entries start at byte 16 (after "DanS" + 3 padding DWORDs)
        let payload_start = 16usize;
        let payload_end = rich_pos;
        if payload_start >= payload_end {
            return None;
        }

        let payload = &stub[payload_start..payload_end];
        let mut products = Vec::new();
        let mut off = 0;
        while off + 8 <= payload.len() {
            let raw_comp = u32::from_le_bytes(payload[off..off + 4].try_into().ok()?) ^ key;
            let raw_cnt = u32::from_le_bytes(payload[off + 4..off + 8].try_into().ok()?) ^ key;
            let product_id = u16::try_from(raw_comp >> 16).unwrap_or(u16::MAX);
            let build_number = u16::try_from(raw_comp & 0xFFFF).unwrap_or(u16::MAX);
            let tool_name = known_tool_name(product_id, build_number);
            products.push(RichProductInfo {
                product_id,
                build_number,
                count: raw_cnt,
                tool_name: tool_name.to_string(),
            });
            off += 8;
        }

        Some(Self { key, products })
    }

    /// Return the XOR checksum that should equal the key, for integrity verification.
    #[must_use]
    pub fn compute_checksum(data: &[u8], pe_offset: usize) -> u32 {
        if pe_offset < 64 || pe_offset > data.len() {
            return 0;
        }
        let mut sum: u32 = 0;
        // Sum DOS header bytes[0..60], rotating left by position
        for (i, &b) in data[..60].iter().enumerate() {
            sum = sum.wrapping_add(u32::from(b).rotate_left(u32::try_from(i).unwrap_or(u32::MAX)));
        }
        // Sum the stub (after "DanS" checkmark)
        for (i, &b) in data[64..pe_offset].iter().enumerate() {
            sum = sum.wrapping_add(u32::from(b).rotate_left(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(64)));
        }
        sum
    }
}

/// Return a human-readable guess for well-known compiler product IDs.
const fn known_tool_name(product_id: u16, _build: u16) -> &'static str {
    // These are approximate — the authoritative mapping is in Microsoft's Rich
    // header research by Daniel Pistelli, et al.
    match product_id {
        0x0000 => "Unmarked objects",
        0x0001 | 0x0002 => "MASM (Visual Studio 6)",
        0x000A | 0x000B => "Visual C++ 6.0",
        0x00AA | 0x00AB => "Visual C++ 7.0 (.NET 2002)",
        0x00C7 | 0x00C8 => "Visual C++ 7.1 (.NET 2003)",
        0x00DB | 0x00DC => "Visual C++ 8.0 (VS 2005)",
        0x00EC | 0x00ED => "Visual C++ 9.0 (VS 2008)",
        0x00FD | 0x00FE => "Visual C++ 10.0 (VS 2010)",
        0x010B | 0x010C => "Visual C++ 11.0 (VS 2012)",
        0x011B | 0x011C => "Visual C++ 12.0 (VS 2013)",
        0x0190 | 0x0191 => "Visual C++ 14.0 (VS 2015)",
        0x019A => "Visual C++ 14.1 (VS 2017)",
        0x01B4 => "Visual C++ 14.2 (VS 2019)",
        0x01D0 => "Visual C++ 14.3 (VS 2022)",
        _ => "Unknown tool",
    }
}

// ---------------------------------------------------------------------------
// Complete parsed PE headers
// ---------------------------------------------------------------------------

/// All PE headers parsed together from a file.
#[derive(Debug, Clone)]
pub struct PeHeaders {
    /// The DOS header.
    pub dos: DosHeader,
    /// The COFF file header.
    pub coff: CoffFileHeader,
    /// The optional header (PE32 or PE64).
    pub optional: OptionalHeader,
    /// All section headers.
    pub sections: Vec<SectionHeader>,
    /// The Rich header, if present.
    pub rich: Option<RichHeader>,
}

impl PeHeaders {
    /// Parse all PE headers from `data`.
    ///
    /// # Errors
    /// Returns a descriptive error string if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let dos = DosHeader::parse(data)?;
        let pe_off = dos.pe_offset();

        if pe_off + 4 > data.len() {
            return Err("PE signature out of bounds".into());
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err("Invalid PE signature".into());
        }

        let coff = CoffFileHeader::parse(data, pe_off + 4)?;
        let opt_off = pe_off + 4 + 20;
        let optional = OptionalHeader::parse(data, opt_off)?;
        let rich = RichHeader::parse(data, pe_off);
        let sections = SectionHeader::parse_all(
            data,
            pe_off,
            coff.size_of_optional_header,
            coff.number_of_sections,
        );

        Ok(Self {
            dos,
            coff,
            optional,
            sections,
            rich,
        })
    }

    /// Convert an RVA to a file offset using the section table.
    ///
    /// Returns `None` if no section covers the given RVA.
    #[must_use]
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let sec_rva = sec.virtual_address;
            let sec_end = sec_rva.saturating_add(sec.virtual_size);
            if rva >= sec_rva && rva < sec_end {
                let offset_in_sec = rva - sec_rva;
                if offset_in_sec >= sec.size_of_raw_data {
                    return None;
                }
                return (sec.pointer_to_raw_data as usize).checked_add(offset_in_sec as usize);
            }
        }
        None
    }

    /// Read `size` bytes starting at the given RVA from `file_data`.
    #[must_use]
    pub fn read_rva<'a>(&self, file_data: &'a [u8], rva: u32, size: usize) -> Option<&'a [u8]> {
        let off = self.rva_to_file_offset(rva)?;
        let end = off.checked_add(size)?;
        file_data.get(off..end)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pe32() -> Vec<u8> {
        let pe_off: usize = 0x80;
        let opt_sz: u16 = 224;
        let headers = pe_off + 4 + 20 + opt_sz as usize + 40;
        let raw_sec = (headers + 0x1FF) & !0x1FF;
        let total = raw_sec + 0x200;
        let mut buf = vec![0u8; total];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

        let coff = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        buf[coff + 16..coff + 18].copy_from_slice(&opt_sz.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes()); // executable

        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes()); // file align
        buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
        buf[opt + 60..opt + 64].copy_from_slice(&(raw_sec as u32).to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // CUI
        buf[opt + 92..opt + 96].copy_from_slice(&0u32.to_le_bytes()); // no dirs

        let sec = opt + opt_sz as usize;
        buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // vsize
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        buf[sec + 20..sec + 24].copy_from_slice(&(raw_sec as u32).to_le_bytes()); // raw off
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // RX+CODE
        buf
    }

    #[test]
    fn test_dos_header_parse_valid() {
        let buf = make_minimal_pe32();
        let dos = DosHeader::parse(&buf).unwrap();
        assert_eq!(dos.e_magic, IMAGE_DOS_SIGNATURE);
        assert_eq!(dos.e_lfanew, 0x80);
    }

    #[test]
    fn test_dos_header_parse_too_short() {
        assert!(DosHeader::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_dos_header_bad_magic() {
        let mut buf = vec![0u8; 64];
        buf[0] = b'P';
        buf[1] = b'E';
        assert!(DosHeader::parse(&buf).is_err());
    }

    #[test]
    fn test_coff_header_parse() {
        let buf = make_minimal_pe32();
        let coff = CoffFileHeader::parse(&buf, 0x84).unwrap();
        assert_eq!(coff.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(coff.number_of_sections, 1);
        assert!(!coff.is_dll());
        assert!(coff.is_executable());
    }

    #[test]
    fn test_optional_header_pe32_parse() {
        let buf = make_minimal_pe32();
        let opt = OptionalHeader::parse(&buf, 0x84 + 20).unwrap();
        assert_eq!(opt.image_base(), 0x0040_0000);
        assert_eq!(opt.entry_point_rva(), 0x1000);
    }

    #[test]
    fn test_section_header_parse() {
        let buf = make_minimal_pe32();
        let headers = PeHeaders::parse(&buf).unwrap();
        assert_eq!(headers.sections.len(), 1);
        let sec = &headers.sections[0];
        assert_eq!(sec.name, ".text");
        assert!(sec.is_code());
        assert!(sec.is_readable());
        assert!(!sec.is_writable());
    }

    #[test]
    fn test_pe_headers_rva_to_file_offset() {
        let buf = make_minimal_pe32();
        let headers = PeHeaders::parse(&buf).unwrap();
        // RVA 0x1000 should map into the .text section
        let off = headers.rva_to_file_offset(0x1000);
        assert!(off.is_some());
        let raw_sec = (0x80usize + 4 + 20 + 224usize + 40 + 0x1FF) & !0x1FF;
        assert_eq!(off.unwrap(), raw_sec);
    }

    #[test]
    fn test_section_characteristics_str() {
        let sec = SectionHeader {
            name: ".text".into(),
            virtual_size: 0x100,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        };
        let s = sec.characteristics_str();
        assert!(s.contains("CODE"));
        assert!(s.contains("EXEC"));
        assert!(s.contains("READ"));
    }

    #[test]
    fn test_data_directory_is_present() {
        let present = DataDirectory {
            virtual_address: 0x1000,
            size: 0x100,
        };
        let absent = DataDirectory {
            virtual_address: 0,
            size: 0,
        };
        assert!(present.is_present());
        assert!(!absent.is_present());
    }

    #[test]
    fn test_machine_name() {
        let mut h = CoffFileHeader {
            machine: IMAGE_FILE_MACHINE_AMD64,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
        };
        assert_eq!(h.machine_name(), "x86-64");
        h.machine = IMAGE_FILE_MACHINE_ARM64;
        assert_eq!(h.machine_name(), "ARM64");
    }

    #[test]
    fn test_known_tool_name() {
        assert_eq!(known_tool_name(0x0000, 0), "Unmarked objects");
        assert!(!known_tool_name(0x01B4, 0).is_empty());
    }

    #[test]
    fn test_rich_header_no_rich_returns_none() {
        let buf = vec![0u8; 256];
        assert!(RichHeader::parse(&buf, 0x80).is_none());
    }

    #[test]
    fn test_section_alignment() {
        let sec = SectionHeader {
            name: String::new(),
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: IMAGE_SCN_ALIGN_16BYTES,
        };
        // Field 5 at bits [20..24] = 0x5 → 1 << 4 = 16
        assert_eq!(sec.alignment(), 16);
    }
}
