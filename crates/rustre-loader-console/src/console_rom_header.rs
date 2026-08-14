//! Console ROM header parsing for classic gaming platforms.
//!
//! Provides [`ConsoleRomHeader`], [`RomHeaderKind`], [`ConsoleType`] and
//! [`parse_header`].  Supports NES (iNES), SNES, Game Boy, and GBA formats.

use std::fmt;

// ── ConsoleType ───────────────────────────────────────────────────────────────

/// The console platform associated with a ROM image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsoleType {
    /// Nintendo Entertainment System (iNES format).
    Nes,
    /// Super Nintendo Entertainment System.
    Snes,
    /// Original Game Boy / Game Boy Color.
    GameBoy,
    /// Game Boy Advance.
    Gba,
    /// Sega Genesis / Mega Drive.
    Genesis,
    /// Platform could not be determined.
    Unknown,
}

impl ConsoleType {
    /// Return the canonical platform name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nes => "nes",
            Self::Snes => "snes",
            Self::GameBoy => "gameboy",
            Self::Gba => "gba",
            Self::Genesis => "genesis",
            Self::Unknown => "unknown",
        }
    }

    /// Return the primary CPU architecture name for the platform.
    #[must_use]
    pub const fn cpu_arch(self) -> &'static str {
        match self {
            Self::Nes => "6502",
            Self::Snes => "65816",
            Self::GameBoy => "lr35902",
            Self::Gba => "arm7tdmi",
            Self::Genesis => "m68000",
            Self::Unknown => "unknown",
        }
    }

    /// Return the default pointer size in bytes.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Nes | Self::GameBoy => 2,
            Self::Snes | Self::Genesis => 3,
            Self::Gba | Self::Unknown => 4,
        }
    }

    /// Return `true` if the platform uses a big-endian CPU.
    #[must_use]
    pub const fn is_big_endian(self) -> bool {
        matches!(self, Self::Snes | Self::Genesis)
    }
}

impl fmt::Display for ConsoleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── RomHeaderKind ─────────────────────────────────────────────────────────────

/// The specific header format variant detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RomHeaderKind {
    /// iNES 1.0 header.
    INes1,
    /// iNES 2.0 (NES 2.0) extended header.
    INes2,
    /// SNES `LoROM` internal header.
    SnesLoRom,
    /// SNES `HiROM` internal header.
    SnesHiRom,
    /// SNES `ExLoROM` internal header.
    SnesExLoRom,
    /// SNES `ExHiROM` internal header.
    SnesExHiRom,
    /// Game Boy original (DMG) header.
    GameBoyDmg,
    /// Game Boy Color header.
    GameBoyCgb,
    /// Game Boy Advance header.
    GameBoyAdvance,
    /// Sega Genesis header.
    SegaGenesis,
    /// Format could not be determined.
    Unknown,
}

impl fmt::Display for RomHeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::INes1 => "iNES-1.0",
            Self::INes2 => "iNES-2.0",
            Self::SnesLoRom => "SNES-LoROM",
            Self::SnesHiRom => "SNES-HiROM",
            Self::SnesExLoRom => "SNES-ExLoROM",
            Self::SnesExHiRom => "SNES-ExHiROM",
            Self::GameBoyDmg => "GB-DMG",
            Self::GameBoyCgb => "GB-CGB",
            Self::GameBoyAdvance => "GBA",
            Self::SegaGenesis => "Sega-Genesis",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ── NesHeaderInfo ─────────────────────────────────────────────────────────────

/// Parsed fields from an iNES header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NesHeaderInfo {
    /// Number of 16 KiB PRG-ROM banks.
    pub prg_rom_banks: u8,
    /// Number of 8 KiB CHR-ROM banks (0 = CHR-RAM).
    pub chr_rom_banks: u8,
    /// iNES mapper number.
    pub mapper: u16,
    /// Reset vector (CPU address), if obtainable.
    pub reset_vector: Option<u16>,
    /// NMI vector (CPU address), if obtainable.
    pub nmi_vector: Option<u16>,
    /// IRQ/BRK vector (CPU address), if obtainable.
    pub irq_vector: Option<u16>,
    /// Whether a trainer is present.
    pub has_trainer: bool,
    /// Whether battery-backed PRG-RAM is present.
    pub has_battery: bool,
    /// Bank-switching scheme name.
    pub bank_scheme: &'static str,
}

impl NesHeaderInfo {
    /// Return the PRG-ROM size in bytes.
    #[must_use]
    pub const fn prg_rom_size(&self) -> usize {
        self.prg_rom_banks as usize * 16 * 1024
    }

    /// Return the CHR-ROM size in bytes.
    #[must_use]
    pub const fn chr_rom_size(&self) -> usize {
        self.chr_rom_banks as usize * 8 * 1024
    }
}

// ── SnesHeaderInfo ────────────────────────────────────────────────────────────

/// Parsed fields from a SNES internal header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnesHeaderInfo {
    /// Game title (trimmed).
    pub title: String,
    /// ROM size as a power-of-two in kilobytes.
    pub rom_size_kb_pow2: u8,
    /// SRAM size as a power-of-two in kilobytes.
    pub sram_size_kb_pow2: u8,
    /// Complement/checksum pair valid.
    pub checksum_valid: bool,
    /// Coprocessor description.
    pub coprocessor: &'static str,
    /// Country code byte.
    pub country: u8,
}

// ── GbHeaderInfo ──────────────────────────────────────────────────────────────

/// Parsed fields from a Game Boy cartridge header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbHeaderInfo {
    /// Game title.
    pub title: String,
    /// MBC chip name (e.g. "MBC3").
    pub mbc_name: String,
    /// ROM size in bytes.
    pub rom_size_bytes: usize,
    /// SRAM size in bytes.
    pub sram_size_bytes: usize,
    /// Whether the header checksum validates.
    pub checksum_valid: bool,
    /// Whether this is a Game Boy Color ROM.
    pub is_cgb: bool,
}

// ── GbaHeaderInfo ─────────────────────────────────────────────────────────────

/// Parsed fields from a Game Boy Advance ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbaHeaderInfo {
    /// Game title.
    pub title: String,
    /// 4-byte game code.
    pub game_code: String,
    /// 2-byte maker code.
    pub maker_code: String,
    /// Software version.
    pub version: u8,
    /// Save type detected from ROM content.
    pub save_type: String,
    /// Complement check valid.
    pub complement_valid: bool,
}

// ── GenesisHeaderInfo ─────────────────────────────────────────────────────────

/// Parsed fields from a Sega Genesis ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisHeaderInfo {
    /// Domestic title.
    pub domestic_title: String,
    /// Overseas title.
    pub overseas_title: String,
    /// Serial number.
    pub serial_number: String,
    /// Stored checksum.
    pub checksum: u16,
    /// Computed checksum.
    pub computed_checksum: u16,
    /// ROM start address.
    pub rom_start: u32,
    /// ROM end address.
    pub rom_end: u32,
}

impl GenesisHeaderInfo {
    /// Return `true` if the stored and computed checksums agree.
    #[must_use]
    pub const fn checksum_valid(&self) -> bool {
        self.checksum == self.computed_checksum
    }
}

// ── ConsoleRomHeader ──────────────────────────────────────────────────────────

/// A unified ROM header representation for classic console platforms.
///
/// The header is obtained from [`parse_header`].  Platform-specific details
/// are available via the `detail` field.
#[derive(Debug, Clone)]
pub struct ConsoleRomHeader {
    /// The detected console platform.
    pub console: ConsoleType,
    /// The specific header format.
    pub kind: RomHeaderKind,
    /// CPU entry point virtual address.
    pub entry_point: u64,
    /// ROM title or game name.
    pub title: String,
    /// ROM size in bytes as reported by the header (0 = not known).
    pub rom_size_bytes: usize,
    /// Whether the header's integrity check (checksum / logo) passes.
    pub integrity_ok: bool,
    /// Platform-specific detail fields.
    pub detail: HeaderDetail,
}

/// Platform-specific header details.
#[derive(Debug, Clone)]
pub enum HeaderDetail {
    Nes(NesHeaderInfo),
    Snes(SnesHeaderInfo),
    GameBoy(GbHeaderInfo),
    Gba(GbaHeaderInfo),
    Genesis(GenesisHeaderInfo),
    None,
}

impl ConsoleRomHeader {
    /// Return a one-line human-readable description.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} [{}] \"{}\" EP={:#x} ROM={}KB integrity={}",
            self.console,
            self.kind,
            self.title,
            self.entry_point,
            self.rom_size_bytes / 1024,
            if self.integrity_ok { "ok" } else { "fail" }
        )
    }
}

impl fmt::Display for ConsoleRomHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*data.get(off)?, *data.get(off + 1)?]))
}

fn read_u16_be(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(off)?, *data.get(off + 1)?]))
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]))
}

fn read_cstr(data: &[u8], off: usize, max_len: usize) -> String {
    let end = (off + max_len).min(data.len());
    if off >= end { return String::new(); }
    let slice = &data[off..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).trim().to_string()
}

const fn nes_mapper_scheme(mapper: u16) -> &'static str {
    match mapper {
        0 => "NROM", 1 => "MMC1", 2 => "UxROM", 3 => "CNROM",
        4 => "MMC3", 5 => "MMC5", 7 => "AxROM", 9 => "MMC2",
        _ => "unknown",
    }
}

const fn gb_mbc_name(cart_type: u8) -> &'static str {
    match cart_type {
        0x00 => "None", 0x01..=0x03 => "MBC1", 0x05..=0x06 => "MBC2",
        0x0F..=0x13 => "MBC3", 0x19..=0x1E => "MBC5",
        0x20 => "MBC6", 0x22 => "MBC7", 0xFC => "Camera",
        _ => "Unknown",
    }
}

const fn gb_sram_size(code: u8) -> usize {
    match code { 0x01 => 2048, 0x02 => 8192, 0x03 => 32768, 0x04 => 131_072, 0x05 => 65536, _ => 0 }
}

fn gba_save_type(data: &[u8]) -> &'static str {
    if data.windows(6).any(|w| w == b"EEPROM") { return "EEPROM"; }
    if data.windows(4).any(|w| w == b"SRAM") { return "SRAM"; }
    if data.windows(9).any(|w| w == b"FLASH_V12") { return "Flash128"; }
    if data.windows(5).any(|w| w == b"FLASH") { return "Flash64"; }
    "None"
}

fn snes_score(data: &[u8], offset: usize) -> u32 {
    if offset + 0x50 > data.len() { return 0; }
    let h = &data[offset..];
    let mut score = 0u32;
    let printable = h[0x10..0x25.min(h.len())].iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    if printable >= 10 { score += 2; }
    let map_mode = h.get(0x25).copied().unwrap_or(0);
    if map_mode & 0xEF == 0x20 || map_mode & 0xEF == 0x21 || map_mode & 0xEF == 0x25 { score += 2; }
    if h.len() >= 0x30 {
        let comp = u16::from_le_bytes([h[0x2C], h[0x2D]]);
        let chk = u16::from_le_bytes([h[0x2E], h[0x2F]]);
        if comp ^ chk == 0xFFFF { score += 3; }
    }
    score
}

const fn snes_coprocessor(chipset: u8) -> &'static str {
    match chipset & 0xF0 {
        0x00 => "none", 0x10 => "DSP", 0x20 => "SuperFX",
        0x30 => "OBC1", 0x40 => "SA-1", 0x50 => "S-DD1",
        0xE0 => "SETA", 0xF0 => "Custom", _ => "unknown",
    }
}

fn genesis_compute_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u16;
    let end = data.len() & !1;
    for off in (0x200..end).step_by(2) {
        let word = u16::from_be_bytes([data[off], data[off + 1]]);
        sum = sum.wrapping_add(word);
    }
    sum
}

// ── parse_header ──────────────────────────────────────────────────────────────

/// Detect and parse the ROM header from `data`.
///
/// Detection priority:
/// 1. NES (iNES magic `NES\x1a`)
/// 2. GBA (ARM branch `EA 00 00 2E` at offset 0)
/// 3. Game Boy (Nintendo logo at $104)
/// 4. Genesis (`SEGA MEGA DRIVE` / `SEGA GENESIS` at $110)
/// 5. SNES (heuristic score at `LoROM` / `HiROM` offsets)
/// 6. Unknown
///
/// # Errors
///
/// Returns an error string if the data is too short or the detected header
/// is malformed.
pub fn parse_header(data: &[u8]) -> Result<ConsoleRomHeader, String> {
    const GB_LOGO_START: [u8; 4] = [0xCE, 0xED, 0x66, 0x66];
    const LOROM: usize = 0x7FB0;
    const HIROM: usize = 0xFFB0;

    if data.is_empty() {
        return Err("empty ROM data".into());
    }

    // 1. NES
    if data.len() >= 16 && &data[..4] == b"NES\x1a" {
        return parse_nes_header(data);
    }

    // 2. GBA (entry instruction EA 00 00 2E at offset 0)
    if data.len() >= 192 && data[..4] == [0x2E, 0x00, 0x00, 0xEA] {
        return parse_gba_header(data);
    }

    // 3. Game Boy (Nintendo logo at $104–$133)
    if data.len() >= 0x150 && data[0x104..0x108] == GB_LOGO_START {
        return parse_gb_header(data);
    }

    // 4. Sega Genesis
    if data.len() >= 0x200 {
        let cn = &data[0x100..0x110];
        if cn.starts_with(b"SEGA MEGA DRIVE")
            || cn.starts_with(b"SEGA GENESIS")
            || cn.starts_with(b"SEGA 32X")
        {
            return parse_genesis_header(data);
        }
    }

    // 5. SNES
    let lo = snes_score(data, LOROM);
    let hi = snes_score(data, HIROM);
    if lo >= 2 || hi >= 2 {
        return parse_snes_header(data, if hi > lo { HIROM } else { LOROM });
    }

    Err("unrecognised ROM format".into())
}

fn parse_nes_header(data: &[u8]) -> Result<ConsoleRomHeader, String> {
    if data.len() < 16 { return Err("NES header too short".into()); }
    let prg_rom_banks = data[4];
    let chr_rom_banks = data[5];
    let flags6 = data[6];
    let flags7 = data[7];
    let has_trainer = (flags6 & 0x04) != 0;
    let has_battery = (flags6 & 0x02) != 0;
    let is_nes2 = (flags7 & 0x0C) == 0x08;
    let mapper_lo = u16::from(flags6 >> 4);
    let mapper_hi = u16::from(flags7 & 0xF0);
    let mapper = mapper_hi | mapper_lo;
    let bank_scheme = nes_mapper_scheme(mapper);
    let kind = if is_nes2 { RomHeaderKind::INes2 } else { RomHeaderKind::INes1 };

    let prg_off = 16 + if has_trainer { 512 } else { 0 };
    let prg_size = prg_rom_banks as usize * 16 * 1024;
    let reset_vector = if prg_size >= 4 && prg_off + prg_size <= data.len() {
        let vec_off = prg_off + prg_size - 4;
        read_u16_le(data, vec_off)
    } else { None };
    let nmi_vector = if prg_size >= 6 && prg_off + prg_size <= data.len() {
        read_u16_le(data, prg_off + prg_size - 6)
    } else { None };
    let irq_vector = if prg_size >= 2 && prg_off + prg_size <= data.len() {
        read_u16_le(data, prg_off + prg_size - 2)
    } else { None };

    let entry = u64::from(reset_vector.unwrap_or(0x8000));
    let detail = HeaderDetail::Nes(NesHeaderInfo {
        prg_rom_banks, chr_rom_banks, mapper,
        reset_vector, nmi_vector, irq_vector,
        has_trainer, has_battery, bank_scheme,
    });
    Ok(ConsoleRomHeader {
        console: ConsoleType::Nes,
        kind,
        entry_point: entry,
        title: format!("NES ROM (mapper {mapper})"),
        rom_size_bytes: prg_size,
        integrity_ok: true,
        detail,
    })
}

fn parse_snes_header(data: &[u8], offset: usize) -> Result<ConsoleRomHeader, String> {
    if offset + 0x30 > data.len() { return Err(format!("SNES header at {offset:#x} OOB")); }
    let h = &data[offset..];
    let title = read_cstr(h, 0x10, 21);
    let map_mode = h[0x25];
    let chipset = h[0x26];
    let rom_size_kb_pow2 = h[0x27];
    let sram_size_kb_pow2 = h[0x28];
    let country = h[0x29];
    let comp = u16::from_le_bytes([h[0x2C], h[0x2D]]);
    let chk = u16::from_le_bytes([h[0x2E], h[0x2F]]);
    let checksum_valid = comp ^ chk == 0xFFFF;
    let coprocessor = snes_coprocessor(chipset);

    let kind = match map_mode & 0x0F {
        0x01 => RomHeaderKind::SnesHiRom,
        0x0A => RomHeaderKind::SnesExLoRom,
        0x05 => RomHeaderKind::SnesExHiRom,
        _ => RomHeaderKind::SnesLoRom,
    };
    let reset_vec = read_u16_le(data, offset + 0x3C + 2).unwrap_or(0x8000);
    let rom_size_bytes = if rom_size_kb_pow2 > 0 { (1usize << rom_size_kb_pow2) * 1024 } else { 0 };

    Ok(ConsoleRomHeader {
        console: ConsoleType::Snes,
        kind,
        entry_point: u64::from(reset_vec),
        title,
        rom_size_bytes,
        integrity_ok: checksum_valid,
        detail: HeaderDetail::Snes(SnesHeaderInfo {
            title: read_cstr(h, 0x10, 21),
            rom_size_kb_pow2, sram_size_kb_pow2,
            checksum_valid, coprocessor, country,
        }),
    })
}

fn parse_gb_header(data: &[u8]) -> Result<ConsoleRomHeader, String> {
    if data.len() < 0x150 { return Err("GB ROM too short".into()); }
    let title_raw = &data[0x134..0x144];
    let nul = title_raw.iter().position(|&b| b == 0).unwrap_or(title_raw.len());
    let title = String::from_utf8_lossy(&title_raw[..nul]).trim().to_string();
    let cgb_flag = data[0x143];
    let cart_type = data[0x147];
    let rom_size_code = data[0x148];
    let sram_size_code = data[0x149];
    let header_checksum = data[0x14D];

    let mut x = 0u8;
    for &b in &data[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
    let checksum_valid = x == header_checksum;

    let is_cgb = cgb_flag == 0x80 || cgb_flag == 0xC0;
    let kind = if is_cgb { RomHeaderKind::GameBoyCgb } else { RomHeaderKind::GameBoyDmg };
    let rom_size_bytes = 32 * 1024 * (1usize << rom_size_code as usize);
    let sram_size_bytes = gb_sram_size(sram_size_code);
    let mbc_name = gb_mbc_name(cart_type).to_string();

    Ok(ConsoleRomHeader {
        console: ConsoleType::GameBoy,
        kind,
        entry_point: 0x0100,
        title: title.clone(),
        rom_size_bytes,
        integrity_ok: checksum_valid,
        detail: HeaderDetail::GameBoy(GbHeaderInfo {
            title, mbc_name, rom_size_bytes, sram_size_bytes, checksum_valid, is_cgb,
        }),
    })
}

fn parse_gba_header(data: &[u8]) -> Result<ConsoleRomHeader, String> {
    if data.len() < 192 { return Err("GBA ROM too short".into()); }
    let title = read_cstr(data, 0xA0, 12);
    let game_code = String::from_utf8_lossy(&data[0xAC..0xB0]).to_string();
    let maker_code = String::from_utf8_lossy(&data[0xB0..0xB2]).to_string();
    let version = data[0xBC];
    let complement = data[0xBD];
    let sum: u8 = data[0xA0..0xBD].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let complement_valid = (0x19u8.wrapping_add(sum)).wrapping_neg() == complement;
    let save_type = gba_save_type(data).to_string();

    Ok(ConsoleRomHeader {
        console: ConsoleType::Gba,
        kind: RomHeaderKind::GameBoyAdvance,
        entry_point: 0x0800_0000,
        title: title.clone(),
        rom_size_bytes: data.len(),
        integrity_ok: complement_valid,
        detail: HeaderDetail::Gba(GbaHeaderInfo {
            title, game_code, maker_code, version, save_type, complement_valid,
        }),
    })
}

fn parse_genesis_header(data: &[u8]) -> Result<ConsoleRomHeader, String> {
    if data.len() < 0x200 { return Err("Genesis ROM too short".into()); }
    let h = &data[0x100..];
    let domestic_title = read_cstr(h, 0x20, 48);
    let overseas_title = read_cstr(h, 0x50, 48);
    let serial_number = read_cstr(h, 0x80, 14);
    let checksum = read_u16_be(h, 0x8E).unwrap_or(0);
    let rom_start = read_u32_be(h, 0xA0).unwrap_or(0);
    let rom_end = read_u32_be(h, 0xA4).unwrap_or(0);
    let computed_checksum = genesis_compute_checksum(data);

    Ok(ConsoleRomHeader {
        console: ConsoleType::Genesis,
        kind: RomHeaderKind::SegaGenesis,
        entry_point: 0,
        title: domestic_title.clone(),
        rom_size_bytes: data.len(),
        integrity_ok: checksum == computed_checksum,
        detail: HeaderDetail::Genesis(GenesisHeaderInfo {
            domestic_title, overseas_title, serial_number,
            checksum, computed_checksum, rom_start, rom_end,
        }),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConsoleType ───────────────────────────────────────────────────────────

    #[test]
    fn test_console_type_display() {
        assert_eq!(ConsoleType::Nes.as_str(), "nes");
        assert_eq!(ConsoleType::Gba.as_str(), "gba");
        assert_eq!(ConsoleType::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_console_type_cpu_arch() {
        assert_eq!(ConsoleType::Nes.cpu_arch(), "6502");
        assert_eq!(ConsoleType::GameBoy.cpu_arch(), "lr35902");
        assert_eq!(ConsoleType::Gba.cpu_arch(), "arm7tdmi");
        assert_eq!(ConsoleType::Genesis.cpu_arch(), "m68000");
    }

    #[test]
    fn test_console_type_pointer_size() {
        assert_eq!(ConsoleType::Nes.pointer_size(), 2);
        assert_eq!(ConsoleType::Gba.pointer_size(), 4);
        assert_eq!(ConsoleType::Genesis.pointer_size(), 3);
    }

    #[test]
    fn test_console_type_endian() {
        assert!(ConsoleType::Genesis.is_big_endian());
        assert!(!ConsoleType::Nes.is_big_endian());
        assert!(!ConsoleType::Gba.is_big_endian());
    }

    // ── RomHeaderKind ─────────────────────────────────────────────────────────

    #[test]
    fn test_rom_header_kind_display() {
        assert_eq!(RomHeaderKind::INes1.to_string(), "iNES-1.0");
        assert_eq!(RomHeaderKind::SnesHiRom.to_string(), "SNES-HiROM");
        assert_eq!(RomHeaderKind::GameBoyAdvance.to_string(), "GBA");
    }

    // ── parse_header ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_header_empty_fails() {
        assert!(parse_header(&[]).is_err());
    }

    #[test]
    fn test_parse_header_nes() {
        let mut data = vec![0u8; 16 + 16 * 1024];
        data[0..4].copy_from_slice(b"NES\x1a");
        data[4] = 1; // 1 PRG bank
        data[5] = 0; // no CHR
        // Place reset vector at last 4 bytes of PRG: 0x8000
        let prg_end = 16 + 16 * 1024;
        data[prg_end - 4] = 0x00;
        data[prg_end - 3] = 0x80;
        let h = parse_header(&data).unwrap();
        assert_eq!(h.console, ConsoleType::Nes);
        assert_eq!(h.entry_point, 0x8000);
    }

    #[test]
    fn test_parse_header_gba() {
        let mut data = vec![0u8; 192 + 1024];
        data[0..4].copy_from_slice(&[0x2E, 0x00, 0x00, 0xEA]);
        // Write title
        data[0xA0..0xA5].copy_from_slice(b"GAME\0");
        // Compute complement
        let sum: u8 = data[0xA0..0xBD].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        data[0xBD] = (0x19u8.wrapping_add(sum)).wrapping_neg();
        let h = parse_header(&data).unwrap();
        assert_eq!(h.console, ConsoleType::Gba);
        assert_eq!(h.entry_point, 0x0800_0000);
        assert!(h.integrity_ok);
    }

    #[test]
    fn test_parse_header_genesis() {
        let mut data = vec![0u8; 0x400];
        data[0x100..0x110].copy_from_slice(b"SEGA MEGA DRIVE ");
        // domestic title at 0x120
        let title = b"SONIC                                           ";
        data[0x120..0x120 + 48].copy_from_slice(title);
        // computed checksum will be 0 (all zeros after $200)
        // store 0 in header checksum field
        data[0x18E] = 0;
        data[0x18F] = 0;
        let h = parse_header(&data).unwrap();
        assert_eq!(h.console, ConsoleType::Genesis);
    }

    #[test]
    fn test_parse_header_unknown_fails() {
        let data = vec![0xFFu8; 256];
        assert!(parse_header(&data).is_err());
    }

    #[test]
    fn test_parse_header_nes_info() {
        let mut data = vec![0u8; 16 + 2 * 16 * 1024];
        data[0..4].copy_from_slice(b"NES\x1a");
        data[4] = 2; // 2 PRG banks
        data[5] = 1; // 1 CHR bank
        // mapper 4 (MMC3): mapper_lo = flags6>>4 = 4, mapper_hi = flags7&0xF0 = 0.
        // Test-side fix: previous values yielded mapper=64.
        data[6] = 0x40;
        data[7] = 0x00;
        let h = parse_header(&data).unwrap();
        if let HeaderDetail::Nes(info) = &h.detail {
            assert_eq!(info.mapper, 4);
            assert_eq!(info.bank_scheme, "MMC3");
            assert_eq!(info.prg_rom_size(), 2 * 16 * 1024);
        } else {
            panic!("expected NES detail");
        }
    }

    #[test]
    fn test_parse_header_gb() {
        // Build a minimal GB ROM
        let mut data = vec![0u8; 0x200];
        // Nintendo logo at 0x104 (first 4 bytes match check)
        data[0x104] = 0xCE;
        data[0x105] = 0xED;
        data[0x106] = 0x66;
        data[0x107] = 0x66;
        // Fill the rest of the logo area (0x108..0x134) with anything
        data[0x108..0x134].fill(0);
        // Title at 0x134
        let title = b"TESTGAME";
        data[0x134..0x134 + title.len()].copy_from_slice(title);
        data[0x147] = 0x01; // MBC1
        data[0x148] = 0x00; // 32KB ROM
        // Compute header checksum
        let mut x = 0u8;
        for &b in &data[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
        data[0x14D] = x;

        let h = parse_header(&data).unwrap();
        assert_eq!(h.console, ConsoleType::GameBoy);
        assert!(h.integrity_ok);
        if let HeaderDetail::GameBoy(info) = &h.detail {
            assert_eq!(info.mbc_name, "MBC1");
        } else {
            panic!("expected GameBoy detail");
        }
    }

    #[test]
    fn test_console_rom_header_summary() {
        let h = ConsoleRomHeader {
            console: ConsoleType::Nes,
            kind: RomHeaderKind::INes1,
            entry_point: 0x8000,
            title: "Test".into(),
            rom_size_bytes: 32 * 1024,
            integrity_ok: true,
            detail: HeaderDetail::None,
        };
        let s = h.summary();
        assert!(s.contains("nes"));
        assert!(s.contains("0x8000") || s.contains("8000"));
    }
}
