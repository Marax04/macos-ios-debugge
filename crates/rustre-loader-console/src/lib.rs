//! `rustre-loader-console`
//!
//! Console/ROM loader implementing full parsing for NES, SNES, Game Boy,
//! Game Boy Advance, and Sega Genesis ROM images. Each loader performs header
//! validation, memory-map construction, bank-switching detection, and entry
//! point resolution faithful to original hardware specs.

pub mod format_detection;
pub mod nca_format;
pub mod nso_loader;
pub mod nso_nro;
pub mod ps_loader;
pub mod ps2_elf_loader;
pub mod self_format;
pub mod switch_formats;
pub mod switch_nso_loader;
pub mod xex;
pub mod xex_loader;
pub mod xbox_xex_loader;
pub mod gba_rom_loader;
pub mod console_rom_header;
pub mod console_memory_map;
pub mod console_symbol_provider;

pub use switch_formats::{
    NRO_MAGIC, NSO_MAGIC, NroHeader, NsoBss, NsoHeader, NsoModuleInfo, NsoSegmentInfo, RomFsEntry,
    RomFsHeader, SwitchError, SwitchFormats, SwitchRomFs,
};

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::permissions::Permissions;
use rustre_core::loader::{LoadResult, Loader, LoaderInput, NestedBinary};

// ─────────────────────────────────────────────────────────────────────────────
// Shared utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Read a little-endian u16 from `data` at `offset`, returning `None` on OOB.
#[must_use]
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let hi = *data.get(offset + 1)?;
    let lo = *data.get(offset)?;
    Some(u16::from_le_bytes([lo, hi]))
}

/// Read a big-endian u16 from `data` at `offset`, returning `None` on OOB.
#[must_use]
fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    let hi = *data.get(offset)?;
    let lo = *data.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Read a big-endian u32 from `data` at `offset`.
#[must_use]
fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Extract a null-terminated ASCII string from `data` starting at `offset`,
/// capped at `max_len` bytes.
#[must_use]
fn read_cstr(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    if offset >= end {
        return String::new();
    }
    let slice = &data[offset..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).trim().to_string()
}

/// Compute the simple 8-bit checksum (XOR of all bytes except the checksum
/// byte itself) used in several ROM headers.
#[must_use]
pub fn xor_checksum(data: &[u8], skip_offset: Option<usize>) -> u8 {
    data.iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != skip_offset)
        .fold(0u8, |acc, (_, &b)| acc ^ b)
}

/// Detect the most likely format of `data` by checking common magic bytes.
#[must_use]
pub fn detect_format(data: &[u8]) -> Option<String> {
    if data.starts_with(b"MZ") {
        return Some("pe".to_string());
    }
    if data.starts_with(b"\x7fELF") {
        return Some("elf".to_string());
    }
    if data.starts_with(b"\xCA\xFE\xBA\xBE") {
        return Some("java-class".to_string());
    }
    if data.starts_with(b"\x1bLua") {
        return Some("lua-bytecode".to_string());
    }
    if data.starts_with(b"\x1bLJ") {
        return Some("luajit-bytecode".to_string());
    }
    if data.starts_with(b"dex\n") {
        return Some("dex".to_string());
    }
    if data.starts_with(b"PK\x03\x04") {
        return Some("zip".to_string());
    }
    if data.starts_with(b"%PDF-") {
        return Some("pdf".to_string());
    }
    if data.starts_with(b"\xD0\xCF\x11\xE0") {
        return Some("ole2".to_string());
    }
    if data.starts_with(b"\x1f\x8b") {
        return Some("gzip".to_string());
    }
    if is_nes(data) {
        return Some("nes".to_string());
    }
    if is_snes(data) {
        return Some("snes".to_string());
    }
    if is_gb(data) {
        return Some("gameboy".to_string());
    }
    if is_gba(data) {
        return Some("gba".to_string());
    }
    if is_genesis(data) {
        return Some("genesis".to_string());
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared architecture stubs
// ─────────────────────────────────────────────────────────────────────────────

/// Generic minimal Architecture stub used as a placeholder by all console loaders.
#[derive(Debug)]
pub struct ConsoleArch {
    name: &'static str,
    ptr_size: usize,
    endian: Endian,
}

impl ConsoleArch {
    /// Create a new architecture stub.
    #[must_use]
    pub const fn new(name: &'static str, ptr_size: usize, endian: Endian) -> Self {
        Self {
            name,
            ptr_size,
            endian,
        }
    }
}

impl Architecture for ConsoleArch {
    fn name(&self) -> &str {
        self.name
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let size = 1;
        let byte = bytes.first().copied().unwrap_or(0);
        let mut instr = Instruction::new(address, size, "data", vec![byte]);
        instr.operands = format!("{byte:#04x}");
        instr.flags = InstrFlags::NONE;
        Ok(instr)
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Console stream (stdin pass-through) support types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about data received from the console / stdin stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleStream {
    /// Number of bytes received.
    pub byte_count: usize,
    /// Whether any non-printable bytes were detected (suggests binary data).
    pub is_binary: bool,
    /// Whether the stream starts with a known magic pattern.
    pub detected_format: Option<String>,
}

impl ConsoleStream {
    /// Analyse `data` received from stdin.
    #[must_use]
    pub fn analyse(data: &[u8]) -> Self {
        let is_binary = data.iter().any(|&b| b < 0x09 || (b > 0x0D && b < 0x20));
        let detected_format = detect_format(data);
        Self {
            byte_count: data.len(),
            is_binary,
            detected_format,
        }
    }
}

impl fmt::Display for ConsoleStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "console bytes={} binary={} format={}",
            self.byte_count,
            self.is_binary,
            self.detected_format.as_deref().unwrap_or("unknown"),
        )
    }
}

/// Statistics about the bytes in a console stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStats {
    /// Number of zero bytes.
    pub null_bytes: usize,
    /// Number of printable ASCII bytes.
    pub printable_ascii: usize,
    /// Maximum byte value seen.
    pub max_byte: u8,
    /// Minimum byte value seen.
    pub min_byte: u8,
}

impl StreamStats {
    /// Compute statistics over `data`.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self {
                null_bytes: 0,
                printable_ascii: 0,
                max_byte: 0,
                min_byte: 0,
            };
        }
        let null_bytes = bytecount::count(data, 0);
        let printable_ascii = data.iter().filter(|&&b| b.is_ascii_graphic()).count();
        let max_byte = *data.iter().max().unwrap_or(&0);
        let min_byte = *data.iter().min().unwrap_or(&0);
        Self {
            null_bytes,
            printable_ascii,
            max_byte,
            min_byte,
        }
    }
}

impl fmt::Display for StreamStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stats nulls={} printable={} min=0x{:02x} max=0x{:02x}",
            self.null_bytes, self.printable_ascii, self.min_byte, self.max_byte,
        )
    }
}

/// Loader for console / stdin data. Accepts any input unconditionally.
#[derive(Debug)]
pub struct ConsoleLoader;

#[async_trait]
impl Loader for ConsoleLoader {
    fn name(&self) -> &'static str {
        "console"
    }

    fn can_load(&self, _input: &LoaderInput) -> bool {
        true
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, rustre_core::Address::as_u64);
        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(base + size)),
                permissions: Permissions::READ,
                data: input.data.clone(),
            });
        }
        let arch = Arc::new(ConsoleArch::new("unknown", 8, Endian::Little));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NES / iNES loader
// ─────────────────────────────────────────────────────────────────────────────

/// iNES magic constant: ASCII "NES" followed by MS-DOS EOF (0x1A).
pub const NES_MAGIC: &[u8; 4] = b"NES\x1a";

/// Size of one PRG-ROM bank (16 KiB).
pub const NES_PRG_BANK_SIZE: usize = 16 * 1024;
/// Size of one CHR-ROM bank (8 KiB).
pub const NES_CHR_BANK_SIZE: usize = 8 * 1024;

/// Returns `true` if `data` starts with the iNES magic bytes.
#[must_use]
pub fn is_nes(data: &[u8]) -> bool {
    data.len() >= 16 && data.starts_with(NES_MAGIC)
}

/// NES TV system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NesTvSystem {
    /// NTSC (60 Hz).
    Ntsc,
    /// PAL (50 Hz).
    Pal,
    /// Dual-compatible.
    DualCompatible,
}

impl fmt::Display for NesTvSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ntsc => write!(f, "NTSC"),
            Self::Pal => write!(f, "PAL"),
            Self::DualCompatible => write!(f, "Dual"),
        }
    }
}

/// NES mirroring mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NesMirroring {
    /// Horizontal mirroring (vertical arrangement).
    Horizontal,
    /// Vertical mirroring (horizontal arrangement).
    Vertical,
    /// Four-screen VRAM.
    FourScreen,
    /// Mapper-controlled.
    MapperControlled,
}

impl fmt::Display for NesMirroring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Horizontal => write!(f, "horizontal"),
            Self::Vertical => write!(f, "vertical"),
            Self::FourScreen => write!(f, "four-screen"),
            Self::MapperControlled => write!(f, "mapper"),
        }
    }
}

bitflags::bitflags! {
    /// Feature flags parsed from the iNES header flag bytes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NesFlags: u8 {
        /// Battery-backed PRG-RAM present.
        const HAS_BATTERY     = 0x01;
        /// 512-byte trainer present before PRG-ROM.
        const HAS_TRAINER     = 0x02;
        /// Playchoice-10 ROM.
        const IS_PLAYCHOICE   = 0x04;
        /// VS Unisystem ROM.
        const IS_VS_UNISYSTEM = 0x08;
        /// NES 2.0 extended format detected.
        const IS_NES2         = 0x10;
    }
}

/// Parsed iNES 1.0 / NES 2.0 ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NesHeader {
    /// Number of 16 KiB PRG-ROM banks.
    pub prg_rom_banks: u8,
    /// Number of 8 KiB CHR-ROM banks (0 = CHR-RAM).
    pub chr_rom_banks: u8,
    /// iNES mapper number (0–255).
    pub mapper: u16,
    /// Nametable mirroring.
    pub mirroring: NesMirroring,
    /// Feature flags (battery, trainer, Playchoice, VS, NES 2.0).
    pub flags: NesFlags,
    /// TV system.
    pub tv_system: NesTvSystem,
}

impl NesHeader {
    /// Parse a 16-byte iNES header from `data`.
    ///
    /// # Errors
    /// Returns an error string if `data` is too short or magic does not match.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("iNES header too short".to_string());
        }
        if &data[..4] != NES_MAGIC {
            return Err("invalid iNES magic".to_string());
        }
        let prg_rom_banks = data[4];
        let chr_rom_banks = data[5];
        let flags6 = data[6];
        let flags7 = data[7];
        let flags9 = if data.len() > 9 { data[9] } else { 0 };

        let four_screen = (flags6 & 0x08) != 0;
        let mirroring = if four_screen {
            NesMirroring::FourScreen
        } else if (flags6 & 0x01) != 0 {
            NesMirroring::Vertical
        } else {
            NesMirroring::Horizontal
        };

        let mut flags = NesFlags::empty();
        if (flags6 & 0x02) != 0 { flags |= NesFlags::HAS_BATTERY; }
        if (flags6 & 0x04) != 0 { flags |= NesFlags::HAS_TRAINER; }
        if (flags7 & 0x01) != 0 { flags |= NesFlags::IS_VS_UNISYSTEM; }
        if (flags7 & 0x02) != 0 { flags |= NesFlags::IS_PLAYCHOICE; }
        if (flags7 & 0x0C) == 0x08 { flags |= NesFlags::IS_NES2; }

        let mapper = u16::from((flags7 & 0xF0) | (flags6 >> 4));

        let tv_system = match flags9 & 0x01 {
            0 => NesTvSystem::Ntsc,
            _ => NesTvSystem::Pal,
        };

        Ok(Self {
            prg_rom_banks,
            chr_rom_banks,
            mapper,
            mirroring,
            flags,
            tv_system,
        })
    }

    /// Return the total PRG-ROM size in bytes.
    #[must_use]
    pub const fn prg_rom_size(&self) -> usize {
        self.prg_rom_banks as usize * NES_PRG_BANK_SIZE
    }

    /// Return the total CHR-ROM size in bytes.
    #[must_use]
    pub const fn chr_rom_size(&self) -> usize {
        self.chr_rom_banks as usize * NES_CHR_BANK_SIZE
    }

    /// Offset of the PRG-ROM data within the iNES file.
    #[must_use]
    pub const fn prg_rom_offset(&self) -> usize {
        16 + if self.has_trainer() { 512 } else { 0 }
    }

    /// Battery-backed PRG-RAM present.
    #[must_use]
    pub const fn has_battery(&self) -> bool { self.flags.contains(NesFlags::HAS_BATTERY) }
    /// 512-byte trainer present before PRG-ROM.
    #[must_use]
    pub const fn has_trainer(&self) -> bool { self.flags.contains(NesFlags::HAS_TRAINER) }
    /// Playchoice-10 ROM.
    #[must_use]
    pub const fn is_playchoice(&self) -> bool { self.flags.contains(NesFlags::IS_PLAYCHOICE) }
    /// VS Unisystem ROM.
    #[must_use]
    pub const fn is_vs_unisystem(&self) -> bool { self.flags.contains(NesFlags::IS_VS_UNISYSTEM) }
    /// NES 2.0 extended format.
    #[must_use]
    pub const fn is_nes2(&self) -> bool { self.flags.contains(NesFlags::IS_NES2) }

    /// Detect the likely bank-switching scheme by mapper number.
    #[must_use]
    pub const fn bank_switching_scheme(&self) -> &'static str {
        match self.mapper {
            0 => "NROM (no banking)",
            1 => "MMC1 (SxROM)",
            2 => "UxROM",
            3 => "CNROM",
            4 => "MMC3 (TxROM)",
            5 => "MMC5 (ExROM)",
            7 => "AxROM",
            9 => "MMC2 (PxROM)",
            10 => "MMC4 (FxROM)",
            11 => "ColorDreams",
            13 => "CPROM",
            15 => "100-in-1",
            16 => "Bandai EPROM",
            18 => "Jaleco SS8806",
            19 => "Namco 129/163",
            21 | 25 => "Konami VRC4",
            22 => "Konami VRC2a",
            23 => "Konami VRC2b",
            24 => "Konami VRC6a",
            26 => "Konami VRC6b",
            32 => "Irem G-101",
            33 => "Taito TC0190",
            34 => "BxROM / NINA-001",
            64 => "Tengen RAMBO-1",
            65 => "Irem H3001",
            66 => "GxROM",
            67 => "Sunsoft-3",
            68 => "Sunsoft-4",
            69 => "Sunsoft FME-7",
            71 => "Camerica/Codemasters",
            73 => "Konami VRC3",
            75 => "Konami VRC1",
            76 => "Namco 109",
            79 => "NINA-03/06",
            85 => "Konami VRC7",
            86 => "Jaleco JF-13",
            87 => "Jaleco JF-11/14",
            89 => "Sunsoft-2",
            93 => "Sunsoft-2 (93)",
            94 => "HVC-UN1ROM",
            97 => "Irem TAM-S1",
            105 => "NES-EVENT",
            113 => "Multicart",
            118 => "TxSROM",
            119 => "TQROM",
            159 => "Bandai LZ93D50+EEPROM",
            180 => "Crazy Climber",
            184 => "Sunsoft-1",
            185 => "CNROM with protection",
            _ => "unknown",
        }
    }

    /// Return the NES reset vector address from the PRG-ROM data.
    ///
    /// The reset vector is always located at CPU $FFFC–$FFFD regardless of mapper.
    /// For NROM (mapper 0) with 2 banks it maps to file offset `prg_rom_offset + 0x7FFC`.
    #[must_use]
    pub fn reset_vector(&self, file_data: &[u8]) -> Option<u16> {
        let prg_start = self.prg_rom_offset();
        let prg_size = self.prg_rom_size();
        let prg_end = prg_start + prg_size;
        if prg_end > file_data.len() || prg_size < 2 {
            return None;
        }
        // Last bank maps to $C000–$FFFF; reset vector at offset -4 from end
        let vec_off = prg_start + prg_size - 4;
        read_u16_le(file_data, vec_off)
    }

    /// Return the NMI vector.
    #[must_use]
    pub fn nmi_vector(&self, file_data: &[u8]) -> Option<u16> {
        let prg_start = self.prg_rom_offset();
        let prg_size = self.prg_rom_size();
        let prg_end = prg_start + prg_size;
        if prg_end > file_data.len() || prg_size < 6 {
            return None;
        }
        let vec_off = prg_start + prg_size - 6;
        read_u16_le(file_data, vec_off)
    }

    /// Return the IRQ/BRK vector.
    #[must_use]
    pub fn irq_vector(&self, file_data: &[u8]) -> Option<u16> {
        let prg_start = self.prg_rom_offset();
        let prg_size = self.prg_rom_size();
        let prg_end = prg_start + prg_size;
        if prg_end > file_data.len() || prg_size < 2 {
            return None;
        }
        let vec_off = prg_start + prg_size - 2;
        read_u16_le(file_data, vec_off)
    }
}

impl fmt::Display for NesHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NES PRG={}×16K CHR={}×8K mapper={} mirror={} {}{}{}",
            self.prg_rom_banks,
            self.chr_rom_banks,
            self.mapper,
            self.mirroring,
            self.tv_system,
            if self.has_battery() { " battery" } else { "" },
            if self.has_trainer() { " trainer" } else { "" },
        )
    }
}

/// NES ROM loader implementing the `Loader` trait.
#[derive(Debug, Default)]
pub struct NesLoader;

impl NesLoader {
    /// Create a new NES loader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for NesLoader {
    fn name(&self) -> &'static str {
        "nes"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_nes(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::InvalidFormat`] if the iNES header is invalid or the ROM data
    /// is truncated.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let header = NesHeader::parse(&input.data)
            .map_err(|e| CoreError::InvalidFormat { message: e })?;

        let mut mem = Memory::new();

        // Map PRG-ROM
        let prg_off = header.prg_rom_offset();
        let prg_size = header.prg_rom_size();
        let prg_end_file = prg_off + prg_size;
        if prg_end_file <= input.data.len() && prg_size > 0 {
            // NROM-128 (1 bank) mirrors at $C000
            // NROM-256 (2 banks) is at $8000–$FFFF
            let cpu_base: u64 = 0x8000;
            let cpu_len = (prg_size as u64).min(0x8000);
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(cpu_base), Address::new(cpu_base + cpu_len)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data[prg_off..prg_off + prg_size.min(0x8000)].to_vec(),
            });

            // Mirror for 1-bank NROM
            if header.prg_rom_banks == 1 {
                mem.add_segment(Segment {
                    range: AddressRange::new(Address::new(0xC000), Address::new(0x10000)),
                    permissions: Permissions::READ | Permissions::EXECUTE,
                    data: input.data[prg_off..prg_off + prg_size].to_vec(),
                });
            }
        }

        // Map CHR-ROM at PPU $0000
        let chr_off = prg_off + prg_size;
        let chr_size = header.chr_rom_size();
        if chr_size > 0 && chr_off + chr_size <= input.data.len() {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0x0000_0000), Address::new(chr_size as u64)),
                permissions: Permissions::READ,
                data: input.data[chr_off..chr_off + chr_size].to_vec(),
            });
        }

        // RAM region $0000–$07FF (mirrored 4×)
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x2000_0000), Address::new(0x2000_0800)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x800],
        });

        let reset_vec = header
            .reset_vector(&input.data)
            .map_or(0x8000, u64::from);

        let arch = Arc::new(ConsoleArch::new("6502", 2, Endian::Little));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            16,
            vec![Address::new(reset_vec)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SNES / Super NES loader
// ─────────────────────────────────────────────────────────────────────────────

/// Offset of the internal SNES header in `LoROM` images.
pub const SNES_LOROM_HEADER_OFFSET: usize = 0x7FB0;
/// Offset of the internal SNES header in `HiROM` images.
pub const SNES_HIROM_HEADER_OFFSET: usize = 0xFFB0;
/// Offset of the internal SNES header in `ExLoROM` images.
pub const SNES_EXLOROM_HEADER_OFFSET: usize = 0x40_7FB0;
/// Offset of the internal SNES header in `ExHiROM` images.
pub const SNES_EXHIROM_HEADER_OFFSET: usize = 0x40_FFB0;

/// Returns `true` if `data` appears to be a SNES ROM image.
#[must_use]
pub fn is_snes(data: &[u8]) -> bool {
    // Try both common offsets; check validity score
    snes_header_score(data, SNES_LOROM_HEADER_OFFSET) >= 2
        || snes_header_score(data, SNES_HIROM_HEADER_OFFSET) >= 2
}

/// Heuristic score for a SNES header at `offset`.
#[must_use]
fn snes_header_score(data: &[u8], offset: usize) -> u32 {
    if offset + 0x50 > data.len() {
        return 0;
    }
    let mut score = 0u32;
    let h = &data[offset..];
    // Title region (0x10–0x25): printable ASCII
    let title_printable = h[0x10..0x25.min(h.len())]
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count();
    if title_printable >= 10 {
        score += 2;
    }
    // Map mode byte (0x25)
    let map_mode = h.get(0x25).copied().unwrap_or(0);
    if map_mode & 0xEF == 0x20 || map_mode & 0xEF == 0x21 || map_mode & 0xEF == 0x25 {
        score += 2;
    }
    // ROM type (0x26) plausible
    let rom_type = h.get(0x26).copied().unwrap_or(0xFF);
    if rom_type <= 0x14 {
        score += 1;
    }
    // ROM size (0x27) plausible
    let rom_size = h.get(0x27).copied().unwrap_or(0);
    if (5..=14).contains(&rom_size) {
        score += 1;
    }
    // Complement check (0x2C/0x2D ^ 0x2E/0x2F == 0xFFFF)
    if h.len() >= 0x30 {
        let comp = u16::from_le_bytes([h[0x2C], h[0x2D]]);
        let check = u16::from_le_bytes([h[0x2E], h[0x2F]]);
        if comp ^ check == 0xFFFF {
            score += 3;
        }
    }
    score
}

/// SNES memory mapping mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnesMapMode {
    /// `LoROM`: 32 KiB ROM banks mapped into lower half of each bank.
    LoRom,
    /// `HiROM`: 64 KiB ROM banks mapped into upper half of each bank.
    HiRom,
    /// `ExLoROM`: Extended `LoROM`.
    ExLoRom,
    /// `ExHiROM`: Extended `HiROM`.
    ExHiRom,
    /// SA-1 ROM.
    Sa1Rom,
    /// SDD1 ROM.
    Sdd1Rom,
    /// Unknown.
    Unknown(u8),
}

impl SnesMapMode {
    /// Decode from the map-mode byte in the internal header.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b & 0x0F {
            0x00 => Self::LoRom,
            0x01 => Self::HiRom,
            0x02 => Self::Sdd1Rom,
            0x03 => Self::Sa1Rom,
            0x05 => Self::ExHiRom,
            0x0A => Self::ExLoRom,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for SnesMapMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoRom => write!(f, "LoROM"),
            Self::HiRom => write!(f, "HiROM"),
            Self::ExLoRom => write!(f, "ExLoROM"),
            Self::ExHiRom => write!(f, "ExHiROM"),
            Self::Sa1Rom => write!(f, "SA-1 ROM"),
            Self::Sdd1Rom => write!(f, "SDD1 ROM"),
            Self::Unknown(b) => write!(f, "Unknown({b:#04x})"),
        }
    }
}

/// Parsed SNES internal ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnesHeader {
    /// Game title (up to 21 bytes, Shift-JIS or ASCII).
    pub title: String,
    /// Memory map mode.
    pub map_mode: SnesMapMode,
    /// Chipset flags (coprocessor).
    pub chipset: u8,
    /// ROM size as power-of-two kilobytes.
    pub rom_size_kb_pow2: u8,
    /// SRAM size as power-of-two kilobytes.
    pub sram_size_kb_pow2: u8,
    /// Country/region code.
    pub country: u8,
    /// Licensee code.
    pub licensee: u8,
    /// ROM version.
    pub version: u8,
    /// Complement check value.
    pub complement: u16,
    /// Checksum value.
    pub checksum: u16,
    /// Offset used (`LoROM` or `HiROM`).
    pub header_offset: usize,
}

impl SnesHeader {
    /// Parse from `data`, auto-detecting LoROM/HiROM.
    ///
    /// # Errors
    /// Returns an error string if neither offset yields a valid header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let lo_score = snes_header_score(data, SNES_LOROM_HEADER_OFFSET);
        let hi_score = snes_header_score(data, SNES_HIROM_HEADER_OFFSET);
        let (offset, _score) = if hi_score > lo_score {
            (SNES_HIROM_HEADER_OFFSET, hi_score)
        } else {
            (SNES_LOROM_HEADER_OFFSET, lo_score)
        };
        Self::parse_at(data, offset)
    }

    /// Parse at an explicit `offset`.
    ///
    /// # Errors
    /// Returns an error string if `data` is too short at `offset`.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 0x30 > data.len() {
            return Err(format!("SNES header at {offset:#x} out of bounds"));
        }
        let h = &data[offset..];
        let title = String::from_utf8_lossy(&h[0x10..0x25])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        let map_mode = SnesMapMode::from_byte(h[0x25]);
        let chipset = h[0x26];
        let rom_size_kb_pow2 = h[0x27];
        let sram_size_kb_pow2 = h[0x28];
        let country = h[0x29];
        let licensee = h[0x2A];
        let version = h[0x2B];
        let complement = u16::from_le_bytes([h[0x2C], h[0x2D]]);
        let checksum = u16::from_le_bytes([h[0x2E], h[0x2F]]);
        Ok(Self {
            title,
            map_mode,
            chipset,
            rom_size_kb_pow2,
            sram_size_kb_pow2,
            country,
            licensee,
            version,
            complement,
            checksum,
            header_offset: offset,
        })
    }

    /// Verify the complement/checksum relationship (`complement ^ checksum == 0xFFFF`).
    #[must_use]
    pub const fn checksum_valid(&self) -> bool {
        self.complement ^ self.checksum == 0xFFFF
    }

    /// Determine whether the ROM has a 512-byte copier header prepended.
    #[must_use]
    pub const fn has_copier_header(data: &[u8]) -> bool {
        data.len() % 1024 == 512
    }

    /// Reset vector address for a `LoROM` image.
    #[must_use]
    pub fn lorom_reset_vector(&self, data: &[u8]) -> Option<u32> {
        let vec_off = SNES_LOROM_HEADER_OFFSET + 0x3C + 2;
        read_u16_le(data, vec_off).map(|v| 0x8000_u32 | u32::from(v))
    }

    /// Reset vector address for a `HiROM` image.
    #[must_use]
    pub fn hirom_reset_vector(&self, data: &[u8]) -> Option<u32> {
        let vec_off = SNES_HIROM_HEADER_OFFSET + 0x3C + 2;
        read_u16_le(data, vec_off).map(|v| 0xC0_0000_u32 | u32::from(v))
    }

    /// Detect whether a coprocessor is present.
    #[must_use]
    pub const fn coprocessor(&self) -> &'static str {
        match self.chipset & 0xF0 {
            0x00 => "none",
            0x10 => "DSP",
            0x20 => "SuperFX / GSU",
            0x30 => "OBC1",
            0x40 => "SA-1",
            0x50 => "S-DD1",
            0x60 => "S-RTC",
            0xE0 => "Other (SETA)",
            0xF0 => "Custom",
            _ => "unknown",
        }
    }
}

impl fmt::Display for SnesHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SNES \"{}\" {} chipset={:#04x} coproc={} ROM={}KB SRAM={}KB",
            self.title,
            self.map_mode,
            self.chipset,
            self.coprocessor(),
            if self.rom_size_kb_pow2 < 32 { 1u32 << self.rom_size_kb_pow2 } else { u32::MAX },
            if self.sram_size_kb_pow2 > 0 && self.sram_size_kb_pow2 < 32 {
                1u32 << self.sram_size_kb_pow2
            } else {
                0
            },
        )
    }
}

/// SNES ROM loader.
#[derive(Debug, Default)]
pub struct SnesLoader;

impl SnesLoader {
    /// Create a new SNES loader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for SnesLoader {
    fn name(&self) -> &'static str {
        "snes"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_snes(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::InvalidFormat`] if header parsing fails.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let data_ref = &input.data;
        let has_copier = SnesHeader::has_copier_header(data_ref);
        let data_start = if has_copier { 512usize } else { 0usize };
        let trimmed = &data_ref[data_start..];

        let header = SnesHeader::parse(trimmed)
            .map_err(|e| CoreError::InvalidFormat { message: e })?;

        let mut mem = Memory::new();
        let rom_size = trimmed.len() as u64;

        match header.map_mode {
            SnesMapMode::LoRom | SnesMapMode::ExLoRom => {
                // LoROM: banks $00–$7D, ROM in $8000–$FFFF per bank
                let bank_size = 0x8000u64;
                let num_banks = rom_size.div_ceil(bank_size);
                for bank in 0..num_banks {
                    let file_off = bank * bank_size;
                    let end = (file_off + bank_size).min(rom_size);
                    let chunk = &trimmed[usize::try_from(file_off).unwrap_or(usize::MAX)..usize::try_from(end).unwrap_or(usize::MAX)];
                    let cpu_base = (bank << 16) | 0x8000;
                    mem.add_segment(Segment {
                        range: AddressRange::new(
                            Address::new(cpu_base),
                            Address::new(cpu_base + chunk.len() as u64),
                        ),
                        permissions: Permissions::READ | Permissions::EXECUTE,
                        data: chunk.to_vec(),
                    });
                }
            }
            SnesMapMode::HiRom | SnesMapMode::ExHiRom => {
                // HiROM: banks $C0–$FF, full 64 KiB per bank
                let bank_size = 0x1_0000u64;
                let num_banks = rom_size.div_ceil(bank_size);
                for bank in 0..num_banks {
                    let file_off = bank * bank_size;
                    let end = (file_off + bank_size).min(rom_size);
                    let chunk = &trimmed[usize::try_from(file_off).unwrap_or(usize::MAX)..usize::try_from(end).unwrap_or(usize::MAX)];
                    let cpu_base = 0xC0_0000u64 + bank * 0x1_0000;
                    mem.add_segment(Segment {
                        range: AddressRange::new(
                            Address::new(cpu_base),
                            Address::new(cpu_base + chunk.len() as u64),
                        ),
                        permissions: Permissions::READ | Permissions::EXECUTE,
                        data: chunk.to_vec(),
                    });
                }
            }
            _ => {
                // Fallback: flat map
                mem.add_segment(Segment {
                    range: AddressRange::new(Address::new(0), Address::new(rom_size)),
                    permissions: Permissions::READ | Permissions::EXECUTE,
                    data: trimmed.to_vec(),
                });
            }
        }

        // SRAM region
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x70_0000), Address::new(0x70_8000)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x8000],
        });

        let reset_vec = match header.map_mode {
            SnesMapMode::HiRom | SnesMapMode::ExHiRom => {
                u64::from(header.hirom_reset_vector(trimmed).unwrap_or(0xC000))
            }
            _ => {
                u64::from(header.lorom_reset_vector(trimmed).unwrap_or(0x8000))
            }
        };

        let arch = Arc::new(ConsoleArch::new("65816", 3, Endian::Little));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            24,
            vec![Address::new(reset_vec)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Game Boy loader
// ─────────────────────────────────────────────────────────────────────────────

/// Nintendo logo bytes that must appear at $0104–$0133 in every GB ROM.
pub const GB_LOGO: [u8; 48] = [
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
];

/// Returns `true` if `data` looks like a Game Boy ROM.
#[must_use]
pub fn is_gb(data: &[u8]) -> bool {
    if data.len() < 0x150 {
        return false;
    }
    // Check Nintendo logo at 0x104
    data[0x104..0x134] == GB_LOGO
}

/// Game Boy cartridge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbCartType {
    RomOnly,
    Mbc1,
    Mbc1Ram,
    Mbc1RamBattery,
    Mbc2,
    Mbc2Battery,
    RomRam,
    RomRamBattery,
    Mmm01,
    Mbc3TimerBattery,
    Mbc3TimerRamBattery,
    Mbc3,
    Mbc3Ram,
    Mbc3RamBattery,
    Mbc5,
    Mbc5Ram,
    Mbc5RamBattery,
    Mbc5Rumble,
    Mbc5RumbleRam,
    Mbc5RumbleRamBattery,
    Mbc6,
    Mbc7SensorRumbleRamBattery,
    PocketCamera,
    BandaiTama5,
    HuC3,
    HuC1RamBattery,
    Unknown(u8),
}

impl GbCartType {
    /// Decode from the cartridge type byte at $0147.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::RomOnly,
            0x01 => Self::Mbc1,
            0x02 => Self::Mbc1Ram,
            0x03 => Self::Mbc1RamBattery,
            0x05 => Self::Mbc2,
            0x06 => Self::Mbc2Battery,
            0x08 => Self::RomRam,
            0x09 => Self::RomRamBattery,
            0x0B => Self::Mmm01,
            0x0F => Self::Mbc3TimerBattery,
            0x10 => Self::Mbc3TimerRamBattery,
            0x11 => Self::Mbc3,
            0x12 => Self::Mbc3Ram,
            0x13 => Self::Mbc3RamBattery,
            0x19 => Self::Mbc5,
            0x1A => Self::Mbc5Ram,
            0x1B => Self::Mbc5RamBattery,
            0x1C => Self::Mbc5Rumble,
            0x1D => Self::Mbc5RumbleRam,
            0x1E => Self::Mbc5RumbleRamBattery,
            0x20 => Self::Mbc6,
            0x22 => Self::Mbc7SensorRumbleRamBattery,
            0xFC => Self::PocketCamera,
            0xFD => Self::BandaiTama5,
            0xFE => Self::HuC3,
            0xFF => Self::HuC1RamBattery,
            other => Self::Unknown(other),
        }
    }

    /// Return the MBC chip name string.
    #[must_use]
    pub const fn mbc_name(self) -> &'static str {
        match self {
            Self::RomOnly | Self::RomRam | Self::RomRamBattery => "None",
            Self::Mbc1 | Self::Mbc1Ram | Self::Mbc1RamBattery => "MBC1",
            Self::Mbc2 | Self::Mbc2Battery => "MBC2",
            Self::Mmm01 => "MMM01",
            Self::Mbc3
            | Self::Mbc3Ram
            | Self::Mbc3RamBattery
            | Self::Mbc3TimerBattery
            | Self::Mbc3TimerRamBattery => "MBC3",
            Self::Mbc5
            | Self::Mbc5Ram
            | Self::Mbc5RamBattery
            | Self::Mbc5Rumble
            | Self::Mbc5RumbleRam
            | Self::Mbc5RumbleRamBattery => "MBC5",
            Self::Mbc6 => "MBC6",
            Self::Mbc7SensorRumbleRamBattery => "MBC7",
            Self::PocketCamera => "Pocket Camera",
            Self::BandaiTama5 => "TAMA5",
            Self::HuC3 => "HuC3",
            Self::HuC1RamBattery => "HuC1",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for GbCartType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mbc_name())
    }
}

/// Parsed Game Boy cartridge header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbHeader {
    /// Game title (up to 16 bytes).
    pub title: String,
    /// Manufacturer code (4 bytes, GBC only, part of title field).
    pub manufacturer_code: [u8; 4],
    /// CGB flag byte ($0143).
    pub cgb_flag: u8,
    /// Super Game Boy flag byte ($0146).
    pub sgb_flag: u8,
    /// Cartridge type.
    pub cart_type: GbCartType,
    /// ROM size code ($0148).
    pub rom_size_code: u8,
    /// RAM size code ($0149).
    pub ram_size_code: u8,
    /// Destination code ($014A): 0 = Japan, 1 = other.
    pub destination: u8,
    /// Old licensee code ($014B).
    pub old_licensee: u8,
    /// ROM version number ($014C).
    pub version: u8,
    /// Header checksum ($014D).
    pub header_checksum: u8,
    /// Global checksum ($014E–$014F).
    pub global_checksum: u16,
}

impl GbHeader {
    /// Parse the Game Boy header from `data`.
    ///
    /// # Errors
    /// Returns an error string if `data` is too short or logo is invalid.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x150 {
            return Err("GB ROM too short".to_string());
        }
        if data[0x104..0x134] != GB_LOGO {
            return Err("invalid Nintendo logo".to_string());
        }
        let title_raw = &data[0x134..0x144];
        // Trim trailing NUL bytes and non-printable chars
        let nul_pos = title_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(title_raw.len());
        let title = String::from_utf8_lossy(&title_raw[..nul_pos])
            .trim()
            .to_string();
        let mut manufacturer_code = [0u8; 4];
        manufacturer_code.copy_from_slice(&data[0x13F..0x143]);
        let cgb_flag = data[0x143];
        let sgb_flag = data[0x146];
        let cart_type = GbCartType::from_byte(data[0x147]);
        let rom_size_code = data[0x148];
        let sram_code = data[0x149];
        let destination = data[0x14A];
        let old_licensee = data[0x14B];
        let version = data[0x14C];
        let header_checksum = data[0x14D];
        let global_checksum = u16::from_be_bytes([data[0x14E], data[0x14F]]);
        Ok(Self {
            title,
            manufacturer_code,
            cgb_flag,
            sgb_flag,
            cart_type,
            rom_size_code,
            ram_size_code: sram_code,
            destination,
            old_licensee,
            version,
            header_checksum,
            global_checksum,
        })
    }

    /// Verify the header checksum.
    #[must_use]
    pub fn verify_header_checksum(&self, data: &[u8]) -> bool {
        if data.len() < 0x14E {
            return false;
        }
        let mut x = 0u8;
        for &b in &data[0x134..0x14D] {
            x = x.wrapping_sub(b).wrapping_sub(1);
        }
        x == self.header_checksum
    }

    /// Total ROM size in bytes derived from `rom_size_code`.
    #[must_use]
    pub const fn rom_size_bytes(&self) -> usize {
        // rom_size_code comes from untrusted file data; guard against shift and
        // multiplication overflow. Total size is 32 KiB << shift.
        let shift = self.rom_size_code as u32; // infallible u8→u32; `u32::from` not yet stable in const
        // 32 KiB = 1 << 15; total bits = 15 + shift; must fit in usize.
        if shift >= usize::BITS - 15 {
            return 0;
        }
        32usize * 1024 * (1usize << shift)
    }

    /// SRAM size in bytes.
    #[must_use]
    pub const fn sram_size_bytes(&self) -> usize {
        match self.ram_size_code {
            0x01 => 2 * 1024,
            0x02 => 8 * 1024,
            0x03 => 32 * 1024,
            0x04 => 128 * 1024,
            0x05 => 64 * 1024,
            _ => 0,
        }
    }

    /// Whether this is a Color Game Boy ROM.
    #[must_use]
    pub const fn is_cgb(&self) -> bool {
        self.cgb_flag == 0x80 || self.cgb_flag == 0xC0
    }

    /// Whether this supports Super Game Boy enhancements.
    #[must_use]
    pub const fn is_sgb(&self) -> bool {
        self.sgb_flag == 0x03
    }
}

impl fmt::Display for GbHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GB \"{}\" MBC={} ROM={}KB SRAM={}B{}{}",
            self.title,
            self.cart_type,
            self.rom_size_bytes() / 1024,
            self.sram_size_bytes(),
            if self.is_cgb() { " CGB" } else { "" },
            if self.is_sgb() { " SGB" } else { "" },
        )
    }
}

/// Game Boy ROM loader.
#[derive(Debug, Default)]
pub struct GbLoader;

impl GbLoader {
    /// Create a new Game Boy loader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for GbLoader {
    fn name(&self) -> &'static str {
        "gameboy"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_gb(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::InvalidFormat`] if header parsing fails.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let header = GbHeader::parse(&input.data)
            .map_err(|e| CoreError::InvalidFormat { message: e })?;

        let mut mem = Memory::new();

        // Bank 0: $0000–$3FFF (always mapped)
        let bank0_end = 0x4000usize.min(input.data.len());
        if bank0_end > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0x0000), Address::new(bank0_end as u64)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data[..bank0_end].to_vec(),
            });
        }

        // Switchable bank $4000–$7FFF
        if input.data.len() > 0x4000 {
            let bank1_end = 0x8000usize.min(input.data.len());
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0x4000), Address::new(0x8000)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data[0x4000..bank1_end].to_vec(),
            });
        }

        // External RAM $A000–$BFFF
        let sram = header.sram_size_bytes();
        if sram > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(0xA000), Address::new(0xC000)),
                permissions: Permissions::READ | Permissions::WRITE,
                data: vec![0u8; 0x2000],
            });
        }

        // Internal WRAM $C000–$DFFF
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0xC000), Address::new(0xE000)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x2000],
        });

        // HRAM $FF80–$FFFE
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0xFF80), Address::new(0xFFFF)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x7F],
        });

        let arch = Arc::new(ConsoleArch::new("lr35902", 2, Endian::Little));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            16,
            // Entry point after Nintendo logo check at $0100
            vec![Address::new(0x0100)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Game Boy Advance loader
// ─────────────────────────────────────────────────────────────────────────────

/// GBA ROM header entry point instruction is always `EA00002E` (ARM branch).
pub const GBA_ENTRY_INSTR: [u8; 4] = [0x2E, 0x00, 0x00, 0xEA];
/// GBA Nintendo logo begins at offset 4.
pub const GBA_LOGO_OFFSET: usize = 4;
/// Size of the compressed GBA Nintendo logo (156 bytes).
pub const GBA_LOGO_SIZE: usize = 156;
/// GBA header size.
pub const GBA_HEADER_SIZE: usize = 192;

/// Returns `true` if `data` starts with the GBA entry instruction.
#[must_use]
pub fn is_gba(data: &[u8]) -> bool {
    data.len() >= GBA_HEADER_SIZE && data.starts_with(&GBA_ENTRY_INSTR)
}

/// GBA save type detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbaSaveType {
    /// No save.
    None,
    /// EEPROM (4 or 16 KB).
    Eeprom,
    /// SRAM (32 KB).
    Sram,
    /// Flash 64 KB.
    Flash64,
    /// Flash 128 KB.
    Flash128,
}

impl fmt::Display for GbaSaveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Eeprom => write!(f, "EEPROM"),
            Self::Sram => write!(f, "SRAM"),
            Self::Flash64 => write!(f, "Flash64"),
            Self::Flash128 => write!(f, "Flash128"),
        }
    }
}

impl GbaSaveType {
    /// Detect save type by scanning for magic strings in `data`.
    #[must_use]
    pub fn detect(data: &[u8]) -> Self {
        if data.windows(6).any(|w| w == b"EEPROM") {
            return Self::Eeprom;
        }
        if data.windows(4).any(|w| w == b"SRAM") {
            return Self::Sram;
        }
        if data.windows(9).any(|w| w == b"FLASH1M_V") {
            return Self::Flash128;
        }
        if data.windows(5).any(|w| w == b"FLASH") {
            return Self::Flash64;
        }
        Self::None
    }
}

/// Parsed GBA ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbaHeader {
    /// Game title (12 bytes, padded with NUL).
    pub title: String,
    /// Game code (4 bytes).
    pub game_code: String,
    /// Maker code (2 bytes).
    pub maker_code: String,
    /// Fixed value, should be $96.
    pub fixed_value: u8,
    /// Main unit code.
    pub unit_code: u8,
    /// Device type.
    pub device_type: u8,
    /// Software version.
    pub version: u8,
    /// Complement check.
    pub complement: u8,
    /// Save type detected from ROM content.
    pub save_type: GbaSaveType,
}

impl GbaHeader {
    /// Parse the GBA ROM header from `data`.
    ///
    /// # Errors
    /// Returns an error string if `data` is too short or entry instruction invalid.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < GBA_HEADER_SIZE {
            return Err("GBA ROM too short".to_string());
        }
        if data[..4] != GBA_ENTRY_INSTR {
            return Err("invalid GBA entry instruction".to_string());
        }
        let title = read_cstr(data, 0xA0, 12);
        let game_code = String::from_utf8_lossy(&data[0xAC..0xB0]).to_string();
        let maker_code = String::from_utf8_lossy(&data[0xB0..0xB2]).to_string();
        let fixed_value = data[0xB2];
        let unit_code = data[0xB3];
        let device_type = data[0xB4];
        let version = data[0xBC];
        let complement = data[0xBD];
        let save_type = GbaSaveType::detect(data);

        Ok(Self {
            title,
            game_code,
            maker_code,
            fixed_value,
            unit_code,
            device_type,
            version,
            complement,
            save_type,
        })
    }

    /// Verify the complement check over bytes 0xA0–0xBC.
    #[must_use]
    pub fn verify_complement(&self, data: &[u8]) -> bool {
        if data.len() < 0xBE {
            return false;
        }
        let sum: u8 = data[0xA0..0xBD]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        let expected = (0x19u8.wrapping_add(sum)).wrapping_neg();
        expected == self.complement
    }
}

impl fmt::Display for GbaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GBA \"{}\" code={} maker={} ver={} save={}",
            self.title, self.game_code, self.maker_code, self.version, self.save_type,
        )
    }
}

/// Game Boy Advance ROM loader.
#[derive(Debug, Default)]
pub struct GbaLoader;

impl GbaLoader {
    /// Create a new GBA loader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for GbaLoader {
    fn name(&self) -> &'static str {
        "gba"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_gba(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::InvalidFormat`] if header parsing fails.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let header = GbaHeader::parse(&input.data)
            .map_err(|e| CoreError::InvalidFormat { message: e })?;
        let _ = header; // used for validation

        let mut mem = Memory::new();
        let rom_size = input.data.len() as u64;

        // GBA ROM mapped at $08000000 (GAMEPAK ROM bank 0/1)
        mem.add_segment(Segment {
            range: AddressRange::new(
                Address::new(0x0800_0000),
                Address::new(0x0800_0000 + rom_size),
            ),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: input.data.clone(),
        });

        // Also mirror at $0A000000 (wait state 1) and $0C000000 (wait state 2)
        if rom_size <= 0x200_0000 {
            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(0x0A00_0000),
                    Address::new(0x0A00_0000 + rom_size),
                ),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(0x0C00_0000),
                    Address::new(0x0C00_0000 + rom_size),
                ),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }

        // EWRAM $02000000–$02040000 (256 KB)
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x0200_0000), Address::new(0x0204_0000)),
            permissions: Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
            data: vec![0u8; 0x4_0000],
        });

        // IWRAM $03000000–$03008000 (32 KB)
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x0300_0000), Address::new(0x0300_8000)),
            permissions: Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
            data: vec![0u8; 0x8000],
        });

        // BIOS $00000000–$00004000 (16 KB, execute-only stub)
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x0000_0000), Address::new(0x0000_4000)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: vec![0u8; 0x4000],
        });

        let arch = Arc::new(ConsoleArch::new("arm7tdmi", 4, Endian::Little));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(0x0800_0000)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sega Genesis / Mega Drive loader
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `data` looks like a Sega Genesis ROM.
#[must_use]
pub fn is_genesis(data: &[u8]) -> bool {
    if data.len() < 0x200 {
        return false;
    }
    let console_name = &data[0x100..0x110];
    console_name.starts_with(b"SEGA MEGA DRIVE")
        || console_name.starts_with(b"SEGA GENESIS")
        || console_name.starts_with(b"SEGA PICO")
        || console_name.starts_with(b"SEGA 32X")
}

/// Genesis region code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisRegion {
    /// Japan / Asia.
    Japan,
    /// USA / Canada.
    Usa,
    /// Europe / PAL.
    Europe,
    /// Multiple regions.
    Multi(Vec<Self>),
    /// Unknown.
    Unknown,
}

impl fmt::Display for GenesisRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Japan => write!(f, "JP"),
            Self::Usa => write!(f, "US"),
            Self::Europe => write!(f, "EU"),
            Self::Multi(v) => {
                let mut first = true;
                for r in v {
                    if !first {
                        f.write_str("|")?;
                    }
                    write!(f, "{r}")?;
                    first = false;
                }
                Ok(())
            }
            Self::Unknown => write!(f, "??"),
        }
    }
}

impl GenesisRegion {
    /// Decode region from a space-separated region string.
    #[must_use]
    pub fn parse_region(s: &str) -> Self {
        <Self as std::str::FromStr>::from_str(s).unwrap_or(Self::Unknown)
    }
}

impl std::str::FromStr for GenesisRegion {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut regions = Vec::new();
        if s.contains('J') || s.contains("Japan") {
            regions.push(Self::Japan);
        }
        if s.contains('U') || s.contains("USA") {
            regions.push(Self::Usa);
        }
        if s.contains('E') || s.contains("Europe") {
            regions.push(Self::Europe);
        }
        Ok(match regions.len() {
            0 => Self::Unknown,
            1 => regions.remove(0),
            _ => Self::Multi(regions),
        })
    }
}

/// Parsed Sega Genesis ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisHeader {
    /// Console name string (16 bytes).
    pub console_name: String,
    /// Copyright string (16 bytes).
    pub copyright: String,
    /// Domestic (Japanese) title (48 bytes).
    pub domestic_title: String,
    /// Overseas (international) title (48 bytes).
    pub overseas_title: String,
    /// Serial number and revision (14 bytes).
    pub serial_number: String,
    /// ROM checksum.
    pub checksum: u16,
    /// IO device support string.
    pub io_support: String,
    /// ROM start address.
    pub rom_start: u32,
    /// ROM end address.
    pub rom_end: u32,
    /// RAM start address.
    pub ram_start: u32,
    /// RAM end address.
    pub ram_end: u32,
    /// Extra memory type string.
    pub extra_memory: String,
    /// Modem support string.
    pub modem_support: String,
    /// Country/region.
    pub region: GenesisRegion,
}

impl GenesisHeader {
    /// Parse the Genesis ROM header from `data` at offset $100.
    ///
    /// # Errors
    /// Returns an error string if `data` is too short or magic is not found.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x200 {
            return Err("Genesis ROM too short".to_string());
        }
        if !is_genesis(data) {
            return Err("invalid Genesis console name".to_string());
        }
        let h = &data[0x100..];
        let console_name = read_cstr(h, 0x00, 16);
        let copyright = read_cstr(h, 0x10, 16);
        let domestic_title = read_cstr(h, 0x20, 48);
        let overseas_title = read_cstr(h, 0x50, 48);
        let serial_number = read_cstr(h, 0x80, 14);
        let checksum = read_u16_be(h, 0x8E).unwrap_or(0);
        let io_support = read_cstr(h, 0x90, 16);
        let rom_start = read_u32_be(h, 0xA0).unwrap_or(0);
        let rom_end = read_u32_be(h, 0xA4).unwrap_or(0);
        let sram_start = read_u32_be(h, 0xA8).unwrap_or(0);
        let sram_end = read_u32_be(h, 0xAC).unwrap_or(0);
        let extra_memory = read_cstr(h, 0xB0, 12);
        let modem_support = read_cstr(h, 0xBC, 12);
        let region_str = read_cstr(h, 0xF0, 16);
        let region = GenesisRegion::parse_region(&region_str);

        Ok(Self {
            console_name,
            copyright,
            domestic_title,
            overseas_title,
            serial_number,
            checksum,
            io_support,
            rom_start,
            rom_end,
            ram_start: sram_start,
            ram_end: sram_end,
            extra_memory,
            modem_support,
            region,
        })
    }

    /// Compute checksum over words from $200 to `rom_end`.
    #[must_use]
    pub fn compute_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u16;
        let start = 0x200usize;
        let end = data.len() & !1;
        for off in (start..end).step_by(2) {
            let word = u16::from_be_bytes([data[off], data[off + 1]]);
            sum = sum.wrapping_add(word);
        }
        sum
    }

    /// Verify the stored checksum.
    #[must_use]
    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        Self::compute_checksum(data) == self.checksum
    }

    /// Detect whether this is a 32X ROM.
    #[must_use]
    pub fn is_32x(&self) -> bool {
        self.console_name.contains("32X")
    }

    /// Detect whether this is a Sega CD (MCD) ROM.
    #[must_use]
    pub fn is_mega_cd(&self) -> bool {
        self.console_name.contains("MEGA-CD") || self.console_name.contains("SEGACD")
    }
}

impl fmt::Display for GenesisHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Genesis \"{}\" sn={} region={} ROM=${:08X}–${:08X}",
            self.domestic_title, self.serial_number, self.region, self.rom_start, self.rom_end,
        )
    }
}

/// Sega Genesis ROM loader.
#[derive(Debug, Default)]
pub struct GenesisLoader;

impl GenesisLoader {
    /// Create a new Genesis loader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for GenesisLoader {
    fn name(&self) -> &'static str {
        "genesis"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_genesis(&input.data)
    }

    /// # Errors
    /// Returns [`CoreError::InvalidFormat`] if header parsing fails.
    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let header = GenesisHeader::parse(&input.data)
            .map_err(|e| CoreError::InvalidFormat { message: e })?;

        let mut mem = Memory::new();
        let rom_size = input.data.len() as u64;

        // ROM region: $000000–$3FFFFF (4 MB max)
        let map_rom_end = rom_size.min(0x40_0000);
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x00_0000), Address::new(map_rom_end)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: input.data[..map_rom_end as usize].to_vec(),
        });

        // 68K work RAM: $FF0000–$FFFFFF (64 KB)
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0xFF_0000), Address::new(0x100_0000)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x10000],
        });

        // Z80 address space: $A00000–$A0FFFF
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0xA0_0000), Address::new(0xA0_2000)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x2000],
        });

        // VDP registers: $C00000–$C0001F
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0xC0_0000), Address::new(0xC0_0020)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0u8; 0x20],
        });

        // Reset vector at $000000 (initial SSP) and $000004 (initial PC)
        let reset_pc = if input.data.len() >= 8 {
            u64::from(read_u32_be(&input.data, 4).unwrap_or(0x200))
        } else {
            0x200u64
        };

        // Extra memory / SRAM if detected
        if !header.extra_memory.is_empty() && header.extra_memory.contains("RA") {
            let sram_start = u64::from(header.ram_start);
            let sram_end = u64::from(header.ram_end);
            if sram_end > sram_start && sram_end - sram_start <= 0x10000 {
                mem.add_segment(Segment {
                    range: AddressRange::new(Address::new(sram_start), Address::new(sram_end.saturating_add(1))),
                    permissions: Permissions::READ | Permissions::WRITE,
                    data: vec![0u8; usize::try_from(sram_end - sram_start + 1).unwrap_or(usize::MAX)],
                });
            }
        }

        let arch = Arc::new(ConsoleArch::new("m68k", 4, Endian::Big));
        let view = BinaryView::new(
            ViewId::from_raw(1),
            input.uri,
            arch,
            Endian::Big,
            32,
            vec![Address::new(reset_pc)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bank-switching analysis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a detected bank-switching scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankSwitchInfo {
    /// Name of the scheme.
    pub scheme: String,
    /// Number of switchable banks.
    pub bank_count: usize,
    /// Size of each bank in bytes.
    pub bank_size: usize,
    /// Whether SRAM banking is supported.
    pub has_sram_banking: bool,
}

impl BankSwitchInfo {
    /// Construct for NES ROMs using the mapper number from the header.
    #[must_use]
    pub fn from_nes_header(header: &NesHeader) -> Self {
        let scheme = header.bank_switching_scheme().to_string();
        let bank_count = header.prg_rom_banks as usize;
        Self {
            scheme,
            bank_count,
            bank_size: NES_PRG_BANK_SIZE,
            has_sram_banking: header.has_battery(),
        }
    }

    /// Construct for GB ROMs.
    #[must_use]
    pub fn from_gb_header(header: &GbHeader) -> Self {
        let scheme = header.cart_type.mbc_name().to_string();
        let bank_count = if header.rom_size_code > 0 {
            let shift = u32::from(header.rom_size_code);
            // Guard against shift overflow from untrusted file data.
            // 2 << shift = 1 << (shift+1); needs shift+1 < usize::BITS.
            if shift + 1 < usize::BITS { 2usize << shift } else { 2 }
        } else {
            2
        };
        Self {
            scheme,
            bank_count,
            bank_size: 16 * 1024,
            has_sram_banking: header.sram_size_bytes() > 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// String extraction from ROM data
// ─────────────────────────────────────────────────────────────────────────────

/// A printable string found inside ROM data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RomString {
    /// Offset of the string in the ROM file.
    pub offset: usize,
    /// The string content.
    pub text: String,
}

/// Extract all ASCII strings of length >= `min_len` from `data`.
#[must_use]
pub fn extract_rom_strings(data: &[u8], min_len: usize) -> Vec<RomString> {
    let mut result = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len {
                let text = String::from_utf8_lossy(&data[s..i]).to_string();
                result.push(RomString { offset: s, text });
            }
        }
    }
    // Handle tail
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_len {
            let text = String::from_utf8_lossy(&data[s..]).to_string();
            result.push(RomString { offset: s, text });
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::loader::LoaderHint;

    // ── detect_format ──────────────────────────────────────────────────────────

    #[test]
    fn test_detect_pe() {
        assert_eq!(detect_format(b"MZfoo"), Some("pe".to_string()));
    }

    #[test]
    fn test_detect_elf() {
        assert_eq!(detect_format(b"\x7fELFfoo"), Some("elf".to_string()));
    }

    #[test]
    fn test_detect_java() {
        assert_eq!(
            detect_format(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0]),
            Some("java-class".to_string()),
        );
    }

    #[test]
    fn test_detect_lua() {
        let mut data = vec![0x1B, b'L', b'u', b'a', 0x54];
        data.extend_from_slice(&[0u8; 10]);
        assert_eq!(detect_format(&data), Some("lua-bytecode".to_string()));
    }

    #[test]
    fn test_detect_luajit() {
        assert_eq!(
            detect_format(b"\x1bLJfoo"),
            Some("luajit-bytecode".to_string())
        );
    }

    #[test]
    fn test_detect_dex() {
        assert_eq!(detect_format(b"dex\n035\0"), Some("dex".to_string()));
    }

    #[test]
    fn test_detect_zip() {
        assert_eq!(detect_format(b"PK\x03\x04"), Some("zip".to_string()));
    }

    #[test]
    fn test_detect_pdf() {
        assert_eq!(detect_format(b"%PDF-1.7"), Some("pdf".to_string()));
    }

    #[test]
    fn test_detect_ole() {
        let data = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(detect_format(&data), Some("ole2".to_string()));
    }

    #[test]
    fn test_detect_gzip() {
        assert_eq!(detect_format(&[0x1f, 0x8b, 0x08]), Some("gzip".to_string()));
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(detect_format(b"randomdata"), None);
    }

    // ── NesHeader ─────────────────────────────────────────────────────────────

    fn make_nes_rom(prg_banks: u8, chr_banks: u8, mapper: u8) -> Vec<u8> {
        let mut header = vec![0u8; 16];
        header[..4].copy_from_slice(NES_MAGIC);
        header[4] = prg_banks;
        header[5] = chr_banks;
        header[6] = (mapper & 0x0F) << 4;
        header[7] = mapper & 0xF0;
        let prg = vec![0xEAu8; prg_banks as usize * NES_PRG_BANK_SIZE];
        let chr = vec![0u8; chr_banks as usize * NES_CHR_BANK_SIZE];
        let mut rom = header;
        rom.extend_from_slice(&prg);
        rom.extend_from_slice(&chr);
        rom
    }

    #[test]
    fn test_nes_header_parse() {
        let rom = make_nes_rom(2, 1, 0);
        let hdr = NesHeader::parse(&rom).unwrap();
        assert_eq!(hdr.prg_rom_banks, 2);
        assert_eq!(hdr.chr_rom_banks, 1);
        assert_eq!(hdr.mapper, 0);
    }

    #[test]
    fn test_nes_header_short_data() {
        let result = NesHeader::parse(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nes_header_bad_magic() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(b"NES!");
        let result = NesHeader::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_nes_prg_rom_size() {
        let rom = make_nes_rom(4, 0, 1);
        let hdr = NesHeader::parse(&rom).unwrap();
        assert_eq!(hdr.prg_rom_size(), 4 * 16 * 1024);
    }

    #[test]
    fn test_nes_chr_rom_size() {
        let rom = make_nes_rom(2, 2, 0);
        let hdr = NesHeader::parse(&rom).unwrap();
        assert_eq!(hdr.chr_rom_size(), 2 * 8 * 1024);
    }

    #[test]
    fn test_nes_bank_switching_scheme() {
        let rom = make_nes_rom(2, 1, 4);
        let hdr = NesHeader::parse(&rom).unwrap();
        assert!(hdr.bank_switching_scheme().contains("MMC3"));
    }

    #[test]
    fn test_nes_mirroring_vertical() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(NES_MAGIC);
        data[4] = 1;
        data[6] = 0x01; // vertical
        let hdr = NesHeader::parse(&data).unwrap();
        assert_eq!(hdr.mirroring, NesMirroring::Vertical);
    }

    #[test]
    fn test_nes_mirroring_four_screen() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(NES_MAGIC);
        data[4] = 1;
        data[6] = 0x08; // four-screen
        let hdr = NesHeader::parse(&data).unwrap();
        assert_eq!(hdr.mirroring, NesMirroring::FourScreen);
    }

    #[test]
    fn test_nes_trainer_flag() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(NES_MAGIC);
        data[4] = 1;
        data[6] = 0x04; // trainer
        let hdr = NesHeader::parse(&data).unwrap();
        assert!(hdr.has_trainer());
        assert_eq!(hdr.prg_rom_offset(), 16 + 512);
    }

    #[test]
    fn test_is_nes_true() {
        let rom = make_nes_rom(1, 1, 0);
        assert!(is_nes(&rom));
    }

    #[test]
    fn test_is_nes_false() {
        assert!(!is_nes(b"not a nes rom"));
    }

    // ── GbHeader ──────────────────────────────────────────────────────────────

    fn make_gb_rom() -> Vec<u8> {
        let mut rom = vec![0u8; 0x8000];
        rom[0x100] = 0xC3; // JP
        rom[0x101] = 0x50;
        rom[0x102] = 0x01;
        rom[0x103] = 0x00;
        // Nintendo logo
        rom[0x104..0x134].copy_from_slice(&GB_LOGO);
        // Title
        rom[0x134..0x143].copy_from_slice(b"TESTGAME\0\0\0\0\0\0\0");
        rom[0x143] = 0x80; // CGB flag
        rom[0x146] = 0x00; // no SGB
        rom[0x147] = 0x13; // MBC3 + RAM + BATTERY
        rom[0x148] = 0x05; // 1 MB
        rom[0x149] = 0x03; // 32 KB SRAM
        rom[0x14A] = 0x01; // overseas
        rom[0x14B] = 0x33; // new licensee
        rom[0x14C] = 0x00;
        // compute header checksum
        let mut x = 0u8;
        for &b in &rom[0x134..0x14D] {
            x = x.wrapping_sub(b).wrapping_sub(1);
        }
        rom[0x14D] = x;
        rom
    }

    #[test]
    fn test_gb_header_parse() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        assert_eq!(hdr.title, "TESTGAME");
        assert!(hdr.is_cgb());
    }

    #[test]
    fn test_gb_header_cart_type() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        assert_eq!(hdr.cart_type, GbCartType::Mbc3RamBattery);
    }

    #[test]
    fn test_gb_checksum_verify() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        assert!(hdr.verify_header_checksum(&rom));
    }

    #[test]
    fn test_gb_sram_size() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        assert_eq!(hdr.sram_size_bytes(), 32 * 1024);
    }

    #[test]
    fn test_gb_rom_size() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        assert_eq!(hdr.rom_size_bytes(), 32 * 1024 * 32);
    }

    #[test]
    fn test_gb_is_nes_false() {
        let rom = make_gb_rom();
        assert!(!is_nes(&rom));
    }

    // ── GbaHeader ─────────────────────────────────────────────────────────────

    fn make_gba_rom() -> Vec<u8> {
        let mut rom = vec![0u8; 0x200];
        rom[..4].copy_from_slice(&GBA_ENTRY_INSTR);
        rom[0xA0..0xAC].copy_from_slice(b"GBAGAME\0\0\0\0\0");
        rom[0xAC..0xB0].copy_from_slice(b"AABJ");
        rom[0xB0..0xB2].copy_from_slice(b"01");
        rom[0xB2] = 0x96;
        // compute complement
        let sum: u8 = rom[0xA0..0xBD]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        rom[0xBD] = (0x19u8.wrapping_add(sum)).wrapping_neg();
        rom
    }

    #[test]
    fn test_gba_header_parse() {
        let rom = make_gba_rom();
        let hdr = GbaHeader::parse(&rom).unwrap();
        assert_eq!(hdr.game_code, "AABJ");
    }

    #[test]
    fn test_gba_complement_valid() {
        let rom = make_gba_rom();
        let hdr = GbaHeader::parse(&rom).unwrap();
        assert!(hdr.verify_complement(&rom));
    }

    #[test]
    fn test_gba_is_gba_true() {
        let rom = make_gba_rom();
        assert!(is_gba(&rom));
    }

    #[test]
    fn test_gba_is_gba_false_short() {
        let rom = vec![0u8; 10];
        assert!(!is_gba(&rom));
    }

    #[test]
    fn test_gba_save_type_detection() {
        let mut data = vec![0u8; 0x200];
        data[..4].copy_from_slice(&GBA_ENTRY_INSTR);
        data[0x100..0x106].copy_from_slice(b"EEPROM");
        let save = GbaSaveType::detect(&data);
        assert_eq!(save, GbaSaveType::Eeprom);
    }

    // ── GenesisHeader ─────────────────────────────────────────────────────────

    fn make_genesis_rom() -> Vec<u8> {
        let mut rom = vec![0u8; 0x400];
        // Initial SSP and PC vectors
        rom[0..4].copy_from_slice(&u32::to_be_bytes(0x00FF_FFFE));
        rom[4..8].copy_from_slice(&u32::to_be_bytes(0x0000_0200));
        // Console name
        rom[0x100..0x110].copy_from_slice(b"SEGA MEGA DRIVE ");
        rom[0x110..0x120].copy_from_slice(b"(C)SEGA 1993.JAN");
        rom[0x120..0x150].copy_from_slice(b"TEST GAME                                       ");
        rom[0x150..0x180].copy_from_slice(b"TEST GAME INT                                   ");
        rom[0x180..0x18E].copy_from_slice(b"GM T-00001 -00");
        // Checksum placeholder
        rom[0x18E..0x190].copy_from_slice(&u16::to_be_bytes(0x0000));
        // IO
        rom[0x190..0x1A0].copy_from_slice(b"J               ");
        // ROM start/end
        rom[0x1A0..0x1A4].copy_from_slice(&u32::to_be_bytes(0x0000_0000));
        rom[0x1A4..0x1A8].copy_from_slice(&u32::to_be_bytes(0x0003_FFFF));
        // RAM
        rom[0x1A8..0x1AC].copy_from_slice(&u32::to_be_bytes(0xFF00_0000));
        rom[0x1AC..0x1B0].copy_from_slice(&u32::to_be_bytes(0xFF00_FFFF));
        // Region
        rom[0x1F0..0x200].copy_from_slice(b"JUE             ");
        rom
    }

    #[test]
    fn test_genesis_header_parse() {
        let rom = make_genesis_rom();
        let hdr = GenesisHeader::parse(&rom).unwrap();
        assert!(hdr.console_name.contains("SEGA MEGA DRIVE"));
    }

    #[test]
    fn test_genesis_is_genesis_true() {
        let rom = make_genesis_rom();
        assert!(is_genesis(&rom));
    }

    #[test]
    fn test_genesis_is_genesis_false() {
        assert!(!is_genesis(b"not genesis"));
    }

    #[test]
    fn test_genesis_region_multi() {
        let rom = make_genesis_rom();
        let hdr = GenesisHeader::parse(&rom).unwrap();
        // "JUE" → Multi([Japan, Usa, Europe])
        assert!(matches!(hdr.region, GenesisRegion::Multi(_)));
    }

    // ── ConsoleStream ─────────────────────────────────────────────────────────

    #[test]
    fn test_console_stream_text() {
        let stream = ConsoleStream::analyse(b"hello world");
        assert!(!stream.is_binary);
        assert_eq!(stream.byte_count, 11);
        assert!(stream.detected_format.is_none());
    }

    #[test]
    fn test_console_stream_binary() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let stream = ConsoleStream::analyse(&data);
        assert!(stream.is_binary);
    }

    #[test]
    fn test_console_stream_display() {
        let stream = ConsoleStream {
            byte_count: 100,
            is_binary: true,
            detected_format: Some("pe".to_string()),
        };
        let s = stream.to_string();
        assert!(s.contains("console"));
        assert!(s.contains("pe"));
    }

    // ── StreamStats ───────────────────────────────────────────────────────────

    #[test]
    fn test_stream_stats_basic() {
        let data = b"Hello\x00World";
        let stats = StreamStats::compute(data);
        assert_eq!(stats.null_bytes, 1);
        assert!(stats.printable_ascii >= 10);
        assert_eq!(stats.min_byte, 0);
    }

    #[test]
    fn test_stream_stats_empty() {
        let stats = StreamStats::compute(b"");
        assert_eq!(stats.null_bytes, 0);
        assert_eq!(stats.printable_ascii, 0);
    }

    #[test]
    fn test_stream_stats_display() {
        let stats = StreamStats {
            null_bytes: 2,
            printable_ascii: 8,
            max_byte: 0xFF,
            min_byte: 0x00,
        };
        let s = stats.to_string();
        assert!(s.contains("stats"));
    }

    // ── ConsoleLoader ─────────────────────────────────────────────────────────

    #[test]
    fn test_console_loader_name() {
        assert_eq!(ConsoleLoader.name(), "console");
    }

    #[test]
    fn test_can_load_anything() {
        let input = LoaderInput::new("stdin", b"some data".to_vec());
        assert!(ConsoleLoader.can_load(&input));
    }

    #[test]
    fn test_can_load_empty() {
        let input = LoaderInput::new("stdin", vec![]);
        assert!(ConsoleLoader.can_load(&input));
    }

    #[tokio::test]
    async fn test_load_with_data() {
        let input = LoaderInput::new("stdin", b"binary data here".to_vec());
        let result = ConsoleLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "stdin");
        assert_eq!(result.view.entry_points.len(), 1);
        assert_eq!(result.view.entry_points[0].as_u64(), 0);
    }

    #[tokio::test]
    async fn test_load_empty_data() {
        let input = LoaderInput::new("stdin", vec![]);
        let result = ConsoleLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "stdin");
    }

    #[tokio::test]
    async fn test_load_with_hint() {
        let input = LoaderInput::new("stdin", b"hello".to_vec())
            .with_hint(LoaderHint::BaseAddress(Address::new(0x8000)));
        let result = ConsoleLoader.load(input).await.unwrap();
        assert_eq!(result.view.entry_points[0].as_u64(), 0x8000);
    }

    #[tokio::test]
    async fn test_find_nested_empty() {
        let input = LoaderInput::new("stdin", b"data".to_vec());
        let nested = ConsoleLoader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    // ── NesLoader integration ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_nes_loader_load() {
        let rom = make_nes_rom(2, 1, 0);
        let input = LoaderInput::new("test.nes", rom);
        let result = NesLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.nes");
    }

    #[test]
    fn test_nes_loader_can_load() {
        let rom = make_nes_rom(1, 0, 0);
        let input = LoaderInput::new("test.nes", rom);
        assert!(NesLoader::new().can_load(&input));
    }

    #[test]
    fn test_nes_loader_cannot_load_gb() {
        let rom = make_gb_rom();
        let input = LoaderInput::new("test.gb", rom);
        assert!(!NesLoader::new().can_load(&input));
    }

    // ── GbLoader integration ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_gb_loader_load() {
        let rom = make_gb_rom();
        let input = LoaderInput::new("test.gb", rom);
        let result = GbLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.gb");
    }

    #[test]
    fn test_gb_loader_can_load() {
        let rom = make_gb_rom();
        let input = LoaderInput::new("test.gb", rom);
        assert!(GbLoader::new().can_load(&input));
    }

    // ── GbaLoader integration ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_gba_loader_load() {
        let rom = make_gba_rom();
        let input = LoaderInput::new("test.gba", rom);
        let result = GbaLoader::new().load(input).await.unwrap();
        assert!(result.view.entry_points[0].as_u64() == 0x0800_0000);
    }

    #[test]
    fn test_gba_loader_can_load() {
        let rom = make_gba_rom();
        let input = LoaderInput::new("test.gba", rom);
        assert!(GbaLoader::new().can_load(&input));
    }

    // ── GenesisLoader integration ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_genesis_loader_load() {
        let rom = make_genesis_rom();
        let input = LoaderInput::new("test.md", rom);
        let result = GenesisLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.md");
    }

    #[test]
    fn test_genesis_loader_can_load() {
        let rom = make_genesis_rom();
        let input = LoaderInput::new("test.md", rom);
        assert!(GenesisLoader::new().can_load(&input));
    }

    // ── extract_rom_strings ───────────────────────────────────────────────────

    #[test]
    fn test_extract_rom_strings_basic() {
        let data = b"\x00\x00Hello World\x00\x00test\x00";
        let strings = extract_rom_strings(data, 4);
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.text == "Hello World"));
    }

    #[test]
    fn test_extract_rom_strings_min_len() {
        let data = b"ab\x00abcde\x00";
        let strings = extract_rom_strings(data, 4);
        // "ab" (2 chars) should be excluded; "abcde" (5 chars) included
        assert!(strings.iter().all(|s| s.text.len() >= 4));
    }

    // ── BankSwitchInfo ────────────────────────────────────────────────────────

    #[test]
    fn test_bank_switch_info_nes() {
        let rom = make_nes_rom(4, 0, 4);
        let hdr = NesHeader::parse(&rom).unwrap();
        let info = BankSwitchInfo::from_nes_header(&hdr);
        assert_eq!(info.bank_count, 4);
        assert_eq!(info.bank_size, NES_PRG_BANK_SIZE);
    }

    #[test]
    fn test_bank_switch_info_gb() {
        let rom = make_gb_rom();
        let hdr = GbHeader::parse(&rom).unwrap();
        let info = BankSwitchInfo::from_gb_header(&hdr);
        assert!(info.bank_count > 0);
    }

    // ── ConsoleArch ───────────────────────────────────────────────────────────

    #[test]
    fn test_console_arch_name() {
        let arch = ConsoleArch::new("6502", 2, Endian::Little);
        assert_eq!(arch.name(), "6502");
    }

    #[test]
    fn test_console_arch_endian() {
        let arch = ConsoleArch::new("m68k", 4, Endian::Big);
        assert_eq!(arch.endian(), Endian::Big);
    }

    #[test]
    fn test_console_arch_ptr_size() {
        let arch = ConsoleArch::new("arm", 4, Endian::Little);
        assert_eq!(arch.pointer_size(), 4);
    }

    // ── xor_checksum ──────────────────────────────────────────────────────────

    #[test]
    fn test_xor_checksum_basic() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(xor_checksum(&data, None), 0x01 ^ 0x02 ^ 0x03);
    }

    #[test]
    fn test_xor_checksum_skip() {
        let data = [0x01, 0xFF, 0x03];
        // Skip index 1 (0xFF)
        assert_eq!(xor_checksum(&data, Some(1)), 0x01 ^ 0x03);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GameConsoleRomLoader — unified ROM info parser
// ─────────────────────────────────────────────────────────────────────────────

/// The console platform identified from a ROM image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Nintendo Entertainment System (iNES format).
    Nes,
    /// Super Nintendo Entertainment System (`LoROM` or `HiROM`).
    Snes,
    /// Original Game Boy / Game Boy Color.
    GameBoy,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nes => f.write_str("NES"),
            Self::Snes => f.write_str("SNES"),
            Self::GameBoy => f.write_str("Game Boy"),
        }
    }
}

/// Parsed metadata common across all supported console ROM formats.
#[derive(Debug, Clone)]
pub struct ConsoleRomInfo {
    /// Identified console platform.
    pub platform: Platform,
    /// Game title extracted from the ROM header (may be empty).
    pub title: String,
    /// PRG-ROM size in bytes (NES) or total ROM size (SNES/GB).
    pub prg_size: u32,
    /// CHR-ROM size in bytes (NES); 0 for platforms without a CHR-ROM.
    pub chr_size: u32,
    /// Mapper number (NES); 0 for platforms without a mapper byte.
    pub mapper: u8,
}

// ── NES iNES header constants (reuse the public ones defined earlier) ─────────

const NES_HEADER_LEN: usize = 16;
const NES_PRG_UNIT: u32 = 16 * 1024;
const NES_CHR_UNIT: u32 = 8 * 1024;

fn parse_nes(data: &[u8]) -> Option<ConsoleRomInfo> {
    if data.len() < NES_HEADER_LEN {
        return None;
    }
    if &data[0..4] != NES_MAGIC {
        return None;
    }
    let prg_pages = u32::from(data[4]);
    let chr_pages = u32::from(data[5]);
    let flags6 = data[6];
    let flags7 = data[7];
    let mapper = (flags7 & 0xF0) | (flags6 >> 4);

    Some(ConsoleRomInfo {
        platform: Platform::Nes,
        title: String::new(),
        prg_size: prg_pages * NES_PRG_UNIT,
        chr_size: chr_pages * NES_CHR_UNIT,
        mapper,
    })
}

// ── SNES header detection ─────────────────────────────────────────────────────

/// Attempt to read and score a SNES internal header at a given offset.
/// Returns `(title, rom_size_bytes)` if the header looks valid, else `None`.
fn try_snes_header(data: &[u8], base: usize) -> Option<(String, u32)> {
    // Minimum bytes needed: base + 0x30 (header is 48 bytes from base)
    if data.len() < base + 0x30 {
        return None;
    }
    // Title is 21 bytes of ASCII at `base`
    let title_bytes = &data[base..base + 21];
    let all_printable = title_bytes
        .iter()
        .all(|&b| b == 0x20 || (0x20..0x80).contains(&b));
    if !all_printable {
        return None;
    }
    let title = String::from_utf8_lossy(title_bytes).trim_end().to_string();

    // ROM size byte at base + 0x17; value encodes 1<<n KiB
    let rom_size_byte = data[base + 0x17];
    let rom_size = if rom_size_byte <= 13 {
        (1u32 << rom_size_byte) * 1024
    } else {
        0
    };
    Some((title, rom_size))
}

fn parse_snes(data: &[u8]) -> Option<ConsoleRomInfo> {
    // Try LoROM (header at 0x7FC0) then HiROM (header at 0xFFC0)
    let lorom = if data.len() >= 0x8000 {
        try_snes_header(data, 0x7FC0)
    } else {
        None
    };
    let hirom = if data.len() >= 0x10000 {
        try_snes_header(data, 0xFFC0)
    } else {
        None
    };

    let (title, prg_size) = lorom.or(hirom)?;
    Some(ConsoleRomInfo {
        platform: Platform::Snes,
        title,
        prg_size,
        chr_size: 0,
        mapper: 0,
    })
}

// ── Game Boy header ───────────────────────────────────────────────────────────

/// ROM size lookup table indexed by the byte at 0x0148.
const GB_ROM_SIZES: &[u32] = &[
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    8 * 1024 * 1024,
];

fn parse_gb(data: &[u8]) -> Option<ConsoleRomInfo> {
    if data.len() < 0x0150 {
        return None;
    }
    // Verify Nintendo logo
    if &data[0x0104..0x0134] != GB_LOGO.as_ref() {
        return None;
    }
    // Title: 16 bytes at 0x0134 (may overlap CGB flag at 0x013F for newer ROMs)
    let title = read_cstr(data, 0x0134, 16);
    let cartridge_type = data[0x0147];
    let rom_size_idx = data[0x0148] as usize;
    let prg_size = GB_ROM_SIZES.get(rom_size_idx).copied().unwrap_or(0);

    Some(ConsoleRomInfo {
        platform: Platform::GameBoy,
        title,
        prg_size,
        chr_size: 0,
        mapper: cartridge_type,
    })
}

/// High-level ROM parser that tries NES → SNES → Game Boy in order.
pub struct GameConsoleRomLoader;

impl GameConsoleRomLoader {
    /// Attempt to parse `bytes` as a supported console ROM.
    ///
    /// Returns `Some(ConsoleRomInfo)` for NES, SNES, or Game Boy images;
    /// `None` if the format is not recognised.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<ConsoleRomInfo> {
        parse_nes(bytes)
            .or_else(|| parse_gb(bytes))
            .or_else(|| parse_snes(bytes))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConsoleDisassemblyHints
// ─────────────────────────────────────────────────────────────────────────────

/// Provides the canonical disassembler architecture string for each supported
/// console platform.
pub struct ConsoleDisassemblyHints;

impl ConsoleDisassemblyHints {
    /// Architecture string for the NES (MOS 6502).
    #[must_use]
    pub const fn nes_arch() -> &'static str {
        "6502"
    }

    /// Architecture string for the SNES (WDC 65816).
    #[must_use]
    pub const fn snes_arch() -> &'static str {
        "65816"
    }

    /// Architecture string for the original Game Boy (Sharp LR35902 / SM83).
    #[must_use]
    pub const fn gameboy_arch() -> &'static str {
        "lr35902"
    }

    /// Return the architecture string for the given `Platform`.
    #[must_use]
    pub const fn arch_for(platform: Platform) -> &'static str {
        match platform {
            Platform::Nes => Self::nes_arch(),
            Platform::Snes => Self::snes_arch(),
            Platform::GameBoy => Self::gameboy_arch(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests for the new types
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod console_loader_tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn build_nes_rom(prg_pages: u8, chr_pages: u8, mapper: u8) -> Vec<u8> {
        let mut rom = vec![0u8; NES_HEADER_LEN];
        rom[0..4].copy_from_slice(NES_MAGIC);
        rom[4] = prg_pages;
        rom[5] = chr_pages;
        rom[6] = mapper << 4; // lower nibble of mapper
        rom[7] = mapper & 0xF0; // upper nibble of mapper
        rom
    }

    fn build_gb_rom() -> Vec<u8> {
        let mut rom = vec![0u8; 0x0150];
        rom[0x0104..0x0134].copy_from_slice(GB_LOGO.as_ref());
        // Title "TETRIS"
        let title = b"TETRIS";
        rom[0x0134..0x0134 + title.len()].copy_from_slice(title);
        rom[0x0147] = 0x00; // ROM only
        rom[0x0148] = 0x00; // 32 KiB
        rom
    }

    // ── NES ───────────────────────────────────────────────────────────────────

    #[test]
    fn nes_parse_basic() {
        let rom = build_nes_rom(2, 1, 0);
        let info = GameConsoleRomLoader::parse(&rom).unwrap();
        assert_eq!(info.platform, Platform::Nes);
        assert_eq!(info.prg_size, 2 * NES_PRG_UNIT);
        assert_eq!(info.chr_size, NES_CHR_UNIT);
    }

    #[test]
    fn nes_mapper_extracted() {
        // Mapper 4 (MMC3): upper nibble of flags7 = 0x40, lower nibble of flags6 = 0x00
        // Formula: mapper = (flags7 & 0xF0) | (flags6 >> 4)
        // To get mapper == 4: flags7 = 0x40 (upper nibble 4), flags6 = 0x00 (lower nibble 0)
        // Result: (0x40 & 0xF0) | (0x00 >> 4) = 0x40 | 0 = 0x40 = 64, not 4.
        // Correct: to get mapper 4, need (flags7 & 0xF0) = 0x40 and (flags6 >> 4) = 0.
        // 0x40 in decimal is 64. So mapper 4 requires flags7 upper nibble = 0 and
        // flags6 lower nibble (upper nibble of flags6) = 4.
        // flags6 = 0x40 → (0x40 >> 4) = 4, flags7 = 0x00 → (0x00 & 0xF0) = 0 → mapper = 4.
        let mut rom = build_nes_rom(4, 0, 0);
        rom[6] = 0x40; // (flags6 >> 4) = 4 → lower nibble of mapper
        rom[7] = 0x00; // (flags7 & 0xF0) = 0 → upper nibble of mapper
        let info = GameConsoleRomLoader::parse(&rom).unwrap();
        assert_eq!(info.mapper, 4);
    }

    #[test]
    fn nes_bad_magic_returns_none() {
        let rom = b"BAD\x1a\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        assert!(GameConsoleRomLoader::parse(&rom).is_none());
    }

    #[test]
    fn nes_too_short_returns_none() {
        assert!(GameConsoleRomLoader::parse(&[0u8; 4]).is_none());
    }

    // ── Game Boy ─────────────────────────────────────────────────────────────

    #[test]
    fn gb_parse_basic() {
        let rom = build_gb_rom();
        let info = GameConsoleRomLoader::parse(&rom).unwrap();
        assert_eq!(info.platform, Platform::GameBoy);
        assert_eq!(info.prg_size, 32 * 1024);
        assert_eq!(info.chr_size, 0);
    }

    #[test]
    fn gb_title_extracted() {
        let rom = build_gb_rom();
        let info = GameConsoleRomLoader::parse(&rom).unwrap();
        assert_eq!(info.title, "TETRIS");
    }

    #[test]
    fn gb_bad_logo_returns_none() {
        let mut rom = build_gb_rom();
        rom[0x0104] ^= 0xFF; // corrupt logo
        // Should not be detected as GB; might return None overall
        let result = GameConsoleRomLoader::parse(&rom);
        // NES and SNES also won't match, so None is expected
        assert!(result.is_none());
    }

    // ── ConsoleDisassemblyHints ───────────────────────────────────────────────

    #[test]
    fn nes_arch_string() {
        assert_eq!(ConsoleDisassemblyHints::nes_arch(), "6502");
    }

    #[test]
    fn snes_arch_string() {
        assert_eq!(ConsoleDisassemblyHints::snes_arch(), "65816");
    }

    #[test]
    fn gameboy_arch_string() {
        assert_eq!(ConsoleDisassemblyHints::gameboy_arch(), "lr35902");
    }

    #[test]
    fn arch_for_platform() {
        assert_eq!(ConsoleDisassemblyHints::arch_for(Platform::Nes), "6502");
        assert_eq!(ConsoleDisassemblyHints::arch_for(Platform::Snes), "65816");
        assert_eq!(
            ConsoleDisassemblyHints::arch_for(Platform::GameBoy),
            "lr35902"
        );
    }

    #[test]
    fn platform_display() {
        assert_eq!(Platform::Nes.to_string(), "NES");
        assert_eq!(Platform::Snes.to_string(), "SNES");
        assert_eq!(Platform::GameBoy.to_string(), "Game Boy");
    }
}
