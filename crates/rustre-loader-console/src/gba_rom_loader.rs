//! Game Boy Advance ROM Loader.
//!
//! Parses the GBA ROM header (Nintendo logo, game title, game/maker codes,
//! complement check), detects multiboot ROMs, identifies save type from ROM
//! content, and handles ARM/Thumb mixed-code detection.

use std::fmt;

// ─── Constants ────────────────────────────────────────────────────────────────

/// GBA ROM header: ARM branch instruction at offset 0.
/// Value is `EA 00 00 2E` (little-endian B instruction to entry point).
pub const GBA_ENTRY_ARM_BRANCH: [u8; 4] = [0x2E, 0x00, 0x00, 0xEA];

/// Offset of the Nintendo logo in the GBA header.
pub const GBA_LOGO_OFFSET: usize = 4;

/// Length of the Nintendo compressed logo (156 bytes).
pub const GBA_LOGO_LEN: usize = 156;

/// Offset of the game title (12 bytes, ASCII).
pub const GBA_TITLE_OFFSET: usize = 0xA0;

/// Length of the game title field.
pub const GBA_TITLE_LEN: usize = 12;

/// Offset of the game code (4 bytes, ASCII).
pub const GBA_GAME_CODE_OFFSET: usize = 0xAC;

/// Offset of the maker code (2 bytes, ASCII).
pub const GBA_MAKER_CODE_OFFSET: usize = 0xB0;

/// Fixed value byte at 0xB2; must be 0x96.
pub const GBA_FIXED_VALUE: u8 = 0x96;

/// Offset of the fixed value byte.
pub const GBA_FIXED_OFFSET: usize = 0xB2;

/// Offset of the main unit code byte.
pub const GBA_UNIT_CODE_OFFSET: usize = 0xB3;

/// Offset of the device type byte.
pub const GBA_DEVICE_TYPE_OFFSET: usize = 0xB4;

/// Offset of the ROM version byte (0xBC).
pub const GBA_VERSION_OFFSET: usize = 0xBC;

/// Offset of the header complement check byte (0xBD).
pub const GBA_COMPLEMENT_OFFSET: usize = 0xBD;

/// Offset of the global checksum (2 bytes, 0xBE–0xBF).
pub const GBA_CHECKSUM_OFFSET: usize = 0xBE;

/// Minimum GBA ROM size (must contain at least the header).
pub const GBA_MIN_SIZE: usize = 0xC0;

/// GBA ROM is mapped at this base address in the virtual address space.
pub const GBA_ROM_BASE: u32 = 0x0800_0000;

/// EWRAM base address.
pub const GBA_EWRAM_BASE: u32 = 0x0200_0000;

/// EWRAM size (256 KB).
pub const GBA_EWRAM_SIZE: u32 = 256 * 1024;

/// IWRAM base address.
pub const GBA_IWRAM_BASE: u32 = 0x0300_0000;

/// IWRAM size (32 KB).
pub const GBA_IWRAM_SIZE: u32 = 32 * 1024;

/// BIOS base address.
pub const GBA_BIOS_BASE: u32 = 0x0000_0000;

/// BIOS size (16 KB).
pub const GBA_BIOS_SIZE: u32 = 16 * 1024;

/// I/O registers base.
pub const GBA_IO_BASE: u32 = 0x0400_0000;

/// Palette RAM base.
pub const GBA_PALETTE_BASE: u32 = 0x0500_0000;

/// VRAM base.
pub const GBA_VRAM_BASE: u32 = 0x0600_0000;

/// OAM base.
pub const GBA_OAM_BASE: u32 = 0x0700_0000;

/// Multiboot detection: header at 0xA0 begins with "MBT".
pub const MULTIBOOT_SIG: &[u8] = b"MBT";

/// Nintendo logo bytes (compressed bitmap, 156 bytes).
pub const GBA_NINTENDO_LOGO: [u8; GBA_LOGO_LEN] = [
    0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A, 0xA2, 0x21, 0x3D, 0x84, 0x82, 0x0A, 0x84, 0xE4, 0x09, 0xAD,
    0x11, 0x24, 0x8B, 0x98, 0xC0, 0x81, 0x7F, 0x21, 0xA3, 0x52, 0xBE, 0x19, 0x93, 0x09, 0xCE, 0x20,
    0x10, 0x46, 0x4A, 0x4A, 0xF8, 0x27, 0x31, 0xEC, 0x58, 0xC7, 0xE8, 0x33, 0x82, 0xE3, 0xCE, 0xBF,
    0x85, 0xF4, 0xDF, 0x94, 0xCE, 0x4B, 0x09, 0xC1, 0x94, 0x56, 0x8A, 0xC0, 0x13, 0x72, 0xA7, 0xFC,
    0x9F, 0x84, 0x4D, 0x73, 0xA3, 0xCA, 0x9A, 0x61, 0x58, 0x97, 0xA3, 0x27, 0xFC, 0x03, 0x98, 0x76,
    0x23, 0x1D, 0xC7, 0x61, 0x03, 0x04, 0xAE, 0x56, 0xBF, 0x38, 0x84, 0x00, 0x40, 0xA7, 0x0E, 0xFD,
    0xFF, 0x52, 0xFE, 0x03, 0x6F, 0x95, 0x30, 0xF1, 0x97, 0xFB, 0xC0, 0x85, 0x60, 0xD6, 0x80, 0x25,
    0xA9, 0x63, 0xBE, 0x03, 0x01, 0x4E, 0x38, 0xE2, 0xF9, 0xA2, 0x34, 0xFF, 0xBB, 0x3E, 0x03, 0x44,
    0x78, 0x00, 0x90, 0xCB, 0x88, 0x11, 0x3A, 0x94, 0x65, 0xC0, 0x7C, 0x63, 0x87, 0xF0, 0x3C, 0xAF,
    0xD6, 0x25, 0xE4, 0x8B, 0x38, 0x0A, 0xAC, 0x72, 0x21, 0xD4, 0xF8, 0x07,
];

// ─── GbaSaveType ──────────────────────────────────────────────────────────────

/// Detected save type for a GBA game ROM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbaSaveType {
    /// No save storage detected.
    None,
    /// EEPROM (4 Kbit or 64 Kbit).
    Eeprom,
    /// SRAM 256 Kbit (32 KB).
    Sram,
    /// Flash 512 Kbit (64 KB).
    Flash512k,
    /// Flash 1 Mbit (128 KB).
    Flash1m,
}

impl GbaSaveType {
    /// Scan the ROM for save type signature strings.
    ///
    /// Save types are identified by manufacturer-defined ASCII strings embedded
    /// in the ROM code.
    #[must_use]
    pub fn detect(data: &[u8]) -> Self {
        // Scan for known save type signature strings.
        if contains_sig(data, b"EEPROM_V") {
            return Self::Eeprom;
        }
        if contains_sig(data, b"SRAM_V") || contains_sig(data, b"SRAM_F_V") {
            return Self::Sram;
        }
        if contains_sig(data, b"FLASH_V") || contains_sig(data, b"FLASH512_V") {
            return Self::Flash512k;
        }
        if contains_sig(data, b"FLASH1M_V") {
            return Self::Flash1m;
        }
        // Secondary detection: EEPROM/FLASH without version suffix.
        if contains_sig(data, b"EEPROM") {
            return Self::Eeprom;
        }
        if contains_sig(data, b"FLASH") {
            return Self::Flash512k;
        }
        if contains_sig(data, b"SRAM") {
            return Self::Sram;
        }
        Self::None
    }

    /// Human-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Eeprom => "EEPROM",
            Self::Sram => "SRAM",
            Self::Flash512k => "Flash 512Kbit",
            Self::Flash1m => "Flash 1Mbit",
        }
    }

    /// Whether this save type requires battery backup.
    #[must_use]
    pub const fn requires_battery(self) -> bool {
        matches!(self, Self::Sram | Self::Eeprom | Self::Flash512k | Self::Flash1m)
    }
}

impl fmt::Display for GbaSaveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── MultibootHeader ──────────────────────────────────────────────────────────

/// GBA Multiboot ROM header information.
///
/// A multiboot ROM can be downloaded over the link cable. The multiboot
/// header is located at the same position as the normal GBA header but
/// has different semantics for certain fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultibootHeader {
    /// Branch instruction at offset 0.
    pub entry_branch: u32,
    /// Boot mode: 0 = normal, 1 = multiboot (0x96 in header byte).
    pub boot_mode: u8,
    /// Slave ID (assigned during multiboot handshake).
    pub slave_id: u8,
    /// Master ID (set by the host device).
    pub master_id: u8,
    /// Game code from offset 0xAC.
    pub game_code: String,
    /// Version number.
    pub version: u8,
    /// Whether the header checksum is valid.
    pub complement_ok: bool,
}

impl MultibootHeader {
    /// Parse from the ROM data.
    ///
    /// # Errors
    /// Returns an error string if the data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < GBA_MIN_SIZE {
            return Err("ROM too short for multiboot header".to_string());
        }
        let entry_branch = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let boot_mode = data[0xBA];
        let slave_id  = data[0xBB];
        let master_id = if data.len() > 0xBD { data[0xBD] } else { 0 };
        let game_code = String::from_utf8_lossy(&data[GBA_GAME_CODE_OFFSET..GBA_GAME_CODE_OFFSET+4]).to_string();
        let version   = data[GBA_VERSION_OFFSET];
        let complement = data[GBA_COMPLEMENT_OFFSET];
        let complement_ok = check_complement(data) == complement;
        Ok(Self { entry_branch, boot_mode, slave_id, master_id, game_code, version, complement_ok })
    }

    /// Returns `true` if this looks like a valid multiboot ROM.
    #[must_use]
    pub fn is_valid_multiboot(&self) -> bool {
        // Multiboot ROMs typically have 0x96 at 0xBA and a "MBT" signature or
        // game code starting with specific patterns.
        self.boot_mode == 0x96
            || self.game_code.starts_with("MB")
            || self.game_code.starts_with("M8")
    }
}

impl fmt::Display for MultibootHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Multiboot code={} mode={:#04x} slave={:#04x} ok={}",
            self.game_code, self.boot_mode, self.slave_id, self.complement_ok
        )
    }
}

// ─── GbaHeader ────────────────────────────────────────────────────────────────

/// Fully parsed GBA ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbaHeader {
    /// ARM branch instruction at offset 0.
    pub entry_instr: u32,
    /// Game title (up to 12 bytes, ASCII).
    pub title: String,
    /// Game code (4 bytes, ASCII).
    pub game_code: String,
    /// Maker code (2 bytes, ASCII).
    pub maker_code: String,
    /// Fixed value at 0xB2 (should be 0x96).
    pub fixed_value: u8,
    /// Main unit code.
    pub unit_code: u8,
    /// Device type.
    pub device_type: u8,
    /// ROM version.
    pub version: u8,
    /// Header complement check byte.
    pub complement: u8,
    /// Global checksum (not enforced by hardware).
    pub global_checksum: u16,
    /// Whether the Nintendo logo is present and valid.
    pub logo_valid: bool,
    /// Whether the complement check passes.
    pub complement_valid: bool,
    /// Detected save type.
    pub save_type: GbaSaveType,
    /// Whether this might be a multiboot ROM.
    pub is_multiboot: bool,
}

impl GbaHeader {
    /// Parse the GBA ROM header from `data`.
    ///
    /// # Errors
    /// Returns an error string if the data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < GBA_MIN_SIZE {
            return Err(format!(
                "GBA ROM too short: {} < {GBA_MIN_SIZE}",
                data.len()
            ));
        }

        let entry_instr = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        // Validate Nintendo logo.
        let logo_valid = data.len() >= GBA_LOGO_OFFSET + GBA_LOGO_LEN
            && data[GBA_LOGO_OFFSET..GBA_LOGO_OFFSET + GBA_LOGO_LEN] == GBA_NINTENDO_LOGO;

        // Title: 12 bytes at 0xA0, null-padded.
        let title_raw = &data[GBA_TITLE_OFFSET..GBA_TITLE_OFFSET + GBA_TITLE_LEN];
        let nul = title_raw.iter().position(|&b| b == 0).unwrap_or(GBA_TITLE_LEN);
        let title = String::from_utf8_lossy(&title_raw[..nul])
            .trim()
            .to_string();

        // Game code: 4 bytes at 0xAC.
        let game_code = String::from_utf8_lossy(&data[GBA_GAME_CODE_OFFSET..GBA_GAME_CODE_OFFSET + 4])
            .to_string();

        // Maker code: 2 bytes at 0xB0.
        let maker_code = String::from_utf8_lossy(&data[GBA_MAKER_CODE_OFFSET..GBA_MAKER_CODE_OFFSET + 2])
            .to_string();

        let fixed_value = data[GBA_FIXED_OFFSET];
        let unit_code   = data[GBA_UNIT_CODE_OFFSET];
        let device_type = data[GBA_DEVICE_TYPE_OFFSET];
        let version     = data[GBA_VERSION_OFFSET];
        let complement  = data[GBA_COMPLEMENT_OFFSET];

        let global_checksum = u16::from_le_bytes([
            data[GBA_CHECKSUM_OFFSET],
            data[GBA_CHECKSUM_OFFSET + 1],
        ]);

        let complement_valid = check_complement(data) == complement;
        let save_type = GbaSaveType::detect(data);

        // Multiboot detection.
        let is_multiboot = data.len() > 0xBA && (
            data[0xBA] == 0x96
                || (data.len() > 0xAC + 4 && data[0xAC..0xAC + 3] == *b"MBT")
        );

        Ok(Self {
            entry_instr,
            title,
            game_code,
            maker_code,
            fixed_value,
            unit_code,
            device_type,
            version,
            complement,
            global_checksum,
            logo_valid,
            complement_valid,
            save_type,
            is_multiboot,
        })
    }

    /// Returns `true` if the fixed value at 0xB2 is correct.
    #[must_use]
    pub const fn fixed_value_ok(&self) -> bool {
        self.fixed_value == GBA_FIXED_VALUE
    }

    /// Returns `true` if the header appears fully valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.logo_valid && self.complement_valid && self.fixed_value_ok()
    }

    /// Decoded game region from the last byte of the game code.
    #[must_use]
    pub const fn region(&self) -> &'static str {
        let code = self.game_code.as_bytes();
        match code.last() {
            Some(b'J') => "Japan",
            Some(b'E' | b'P') => "USA/Europe",
            Some(b'D') => "Germany",
            Some(b'F') => "France",
            Some(b'I') => "Italy",
            Some(b'S') => "Spain",
            Some(b'X') => "Europe/Australia",
            Some(b'K') => "Korea",
            Some(b'A') => "All regions",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for GbaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GBA \"{}\" code={} maker={} ver={} region={} save={} logo={} ck={}",
            self.title,
            self.game_code,
            self.maker_code,
            self.version,
            self.region(),
            self.save_type,
            if self.logo_valid { "ok" } else { "BAD" },
            if self.complement_valid { "ok" } else { "BAD" },
        )
    }
}

// ─── GbaRomInfo ───────────────────────────────────────────────────────────────

/// Extended information about a GBA ROM derived from scanning its content.
#[derive(Debug, Clone)]
pub struct GbaRomInfo {
    /// The parsed header.
    pub header: GbaHeader,
    /// Detected ARM/Thumb code regions.
    pub code_regions: Vec<CodeRegion>,
    /// ROM size in bytes.
    pub rom_size: usize,
    /// Number of branch-link instructions found (heuristic for function count).
    pub bl_count: usize,
    /// Number of Thumb BL instructions found.
    pub thumb_bl_count: usize,
    /// Whether the ROM appears to use mostly Thumb code.
    pub thumb_dominant: bool,
    /// Detected IRQ handler address (from interrupt vector table if present).
    pub irq_handler: Option<u32>,
}

/// A detected code region with its instruction set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegion {
    /// Start address (ROM-relative).
    pub start: u32,
    /// Length in bytes.
    pub length: u32,
    /// Instruction set used in this region.
    pub isa: GbaIsa,
    /// Confidence score (0–100).
    pub confidence: u8,
}

/// Instruction set architecture for a GBA code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbaIsa {
    /// 32-bit ARM instructions.
    Arm,
    /// 16-bit Thumb instructions.
    Thumb,
}

impl fmt::Display for GbaIsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arm => write!(f, "ARM"),
            Self::Thumb => write!(f, "Thumb"),
        }
    }
}

impl GbaRomInfo {
    /// Analyse a GBA ROM and return extended info.
    ///
    /// # Errors
    /// Returns an error string if header parsing fails.
    pub fn analyse(data: &[u8]) -> Result<Self, String> {
        let header = GbaHeader::parse(data)?;
        let rom_size = data.len();

        // Count ARM BL (0xEB______) and Thumb BL (0xF7/0xF0 patterns).
        let bl_count = count_arm_bl(data);
        let thumb_bl_count = count_thumb_bl(data);

        let thumb_dominant = thumb_bl_count > bl_count;

        // Detect code regions heuristically.
        let code_regions = detect_code_regions(data);

        // Try to find the IRQ handler from the BIOS interrupt vector table at
        // ROM address 0 (if this is a direct-boot ROM rather than multiboot).
        let irq_handler = find_irq_handler(data);

        Ok(Self {
            header,
            code_regions,
            rom_size,
            bl_count,
            thumb_bl_count,
            thumb_dominant,
            irq_handler,
        })
    }

    /// Total number of identified ARM branch-link targets (rough function count).
    #[must_use]
    pub const fn branch_link_count(&self) -> usize {
        self.bl_count + self.thumb_bl_count
    }
}

// ─── GbaLoader ────────────────────────────────────────────────────────────────

/// The top-level GBA ROM loader.
///
/// Validates the header, detects save type, analyses code regions, and
/// provides segment layout information for memory-map construction.
#[derive(Debug)]
pub struct GbaLoader {
    /// Extended ROM information.
    pub info: GbaRomInfo,
    /// Multiboot header if the ROM is a multiboot program.
    pub multiboot: Option<MultibootHeader>,
    /// ROM data.
    data: Vec<u8>,
}

impl GbaLoader {
    /// Load a GBA ROM from `data`.
    ///
    /// # Errors
    /// Returns an error string if the ROM cannot be parsed.
    pub fn load(data: Vec<u8>) -> Result<Self, String> {
        let info = GbaRomInfo::analyse(&data)?;

        let multiboot = if info.header.is_multiboot {
            MultibootHeader::parse(&data).ok()
        } else {
            None
        };

        Ok(Self { info, multiboot, data })
    }

    /// Whether the ROM data is valid according to the header checks.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.info.header.is_valid()
    }

    /// The ROM virtual base address in the GBA address space.
    #[must_use]
    pub const fn rom_base(&self) -> u32 {
        GBA_ROM_BASE
    }

    /// The ROM virtual end address.
    #[must_use]
    pub fn rom_end(&self) -> u32 {
        GBA_ROM_BASE.wrapping_add(u32::try_from(self.data.len()).unwrap_or(u32::MAX))
    }

    /// Entry point virtual address (ARM branch target from offset 0).
    #[must_use]
    pub const fn entry_point(&self) -> u32 {
        // Decode the ARM B instruction: branch offset is bits[23:0] * 4 + 8.
        let instr = self.info.header.entry_instr;
        if (instr >> 24) == 0xEA {
            let offset = instr & 0x00FF_FFFF;
            let sign_extended = if offset & 0x0080_0000 != 0 {
                (offset | 0xFF00_0000).cast_signed()
            } else {
                offset.cast_signed()
            };
            let target = 8i32.wrapping_add(sign_extended * 4).cast_unsigned();
            GBA_ROM_BASE.wrapping_add(target)
        } else {
            GBA_ROM_BASE
        }
    }

    /// Return segment descriptors for memory map construction.
    ///
    /// Returns tuples of (name, vaddr, size, readable, writable, executable).
    #[must_use]
    pub fn segments(&self) -> Vec<(&'static str, u32, u32, bool, bool, bool)> {
        let rom_size = u32::try_from(self.data.len()).unwrap_or(u32::MAX);
        vec![
            // ROM (wait state 0)
            ("ROM_WS0", GBA_ROM_BASE,            rom_size, true, false, true),
            // ROM mirror at wait state 1
            ("ROM_WS1", 0x0A00_0000,             rom_size, true, false, true),
            // ROM mirror at wait state 2
            ("ROM_WS2", 0x0C00_0000,             rom_size, true, false, true),
            // EWRAM
            ("EWRAM",   GBA_EWRAM_BASE,           GBA_EWRAM_SIZE, true, true, true),
            // IWRAM
            ("IWRAM",   GBA_IWRAM_BASE,           GBA_IWRAM_SIZE, true, true, true),
            // BIOS (execute-only stub)
            ("BIOS",    GBA_BIOS_BASE,            GBA_BIOS_SIZE,  true, false, true),
            // I/O
            ("IO",      GBA_IO_BASE,              0x400, true, true, false),
            // Palette RAM
            ("PALETTE", GBA_PALETTE_BASE,         0x400, true, true, false),
            // VRAM
            ("VRAM",    GBA_VRAM_BASE,            0x18000, true, true, false),
            // OAM
            ("OAM",     GBA_OAM_BASE,             0x400, true, true, false),
        ]
    }

    /// Raw ROM data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} entry={:#010x} size={} BL_count={}+{} thumb={}",
            self.info.header,
            self.entry_point(),
            self.info.rom_size,
            self.info.bl_count,
            self.info.thumb_bl_count,
            self.info.thumb_dominant,
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Check whether `data` contains the byte pattern `sig` as a complete word-aligned string.
fn contains_sig(data: &[u8], sig: &[u8]) -> bool {
    data.windows(sig.len()).any(|w| w == sig)
}

/// Compute the GBA header complement check.
///
/// Sum bytes 0xA0..=0xBC, negate, subtract 0x19, mask to u8.
#[must_use]
pub fn check_complement(data: &[u8]) -> u8 {
    if data.len() < GBA_COMPLEMENT_OFFSET {
        return 0;
    }
    let sum: u8 = data[0xA0..=0xBC]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    (0x19u8.wrapping_add(sum)).wrapping_neg()
}

/// Count 32-bit ARM BL instructions (`0xEB??????`).
fn count_arm_bl(data: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 4 <= data.len() {
        // ARM BL: bits[31:24] = 0xEB (condition=1110, BL=1011).
        if data[i + 3] == 0xEB {
            count += 1;
        }
        i += 4;
    }
    count
}

/// Count 16-bit Thumb BL instruction pairs.
///
/// In Thumb, a BL is encoded as two consecutive 16-bit halfwords:
/// - First:  0xF??? (bits 15:11 = 11110)
/// - Second: 0xF??? (bits 15:11 = 11111) or 0xE??? (bits 15:11 = 11101 for BLX)
fn count_thumb_bl(data: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let hw1 = u16::from_le_bytes([data[i], data[i + 1]]);
        let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
        let h1_top5 = hw1 >> 11;
        let h2_top5 = hw2 >> 11;
        if h1_top5 == 0b11110 && (h2_top5 == 0b11111 || h2_top5 == 0b11101) {
            count += 1;
            i += 4;
        } else {
            i += 2;
        }
    }
    count
}

/// Heuristically detect ARM vs Thumb code regions in a GBA ROM.
///
/// Uses BX/BLX instruction patterns and Thumb prologue patterns to classify
/// windows of code.  Returns a list of detected regions.
fn detect_code_regions(data: &[u8]) -> Vec<CodeRegion> {
    const WINDOW: usize = 0x400; // 1 KB windows
    let mut regions = Vec::new();
    let mut offset = 0usize;

    while offset + WINDOW <= data.len() {
        let window = &data[offset..offset + WINDOW];
        let arm_score = score_arm(window);
        let thumb_score = score_thumb(window);

        if arm_score > 0 || thumb_score > 0 {
            let isa = if thumb_score > arm_score { GbaIsa::Thumb } else { GbaIsa::Arm };
            let max_score = u8::try_from(arm_score.max(thumb_score)).unwrap_or(u8::MAX);
            regions.push(CodeRegion {
                start: GBA_ROM_BASE + u32::try_from(offset).unwrap_or(u32::MAX),
                length: u32::try_from(WINDOW).unwrap_or(u32::MAX),
                isa,
                confidence: max_score.min(100),
            });
        }
        offset += WINDOW;
    }

    // Merge adjacent regions of the same ISA.
    merge_code_regions(regions)
}

/// Count ARM code pattern indicators in a window.
fn score_arm(window: &[u8]) -> u32 {
    let mut score = 0u32;
    for i in (0..window.len().saturating_sub(3)).step_by(4) {
        let cond = window[i + 3] >> 4;
        let op   = window[i + 3] & 0x0F;
        if cond <= 0xE {
            // Valid ARM condition code.
            if op == 0xA || op == 0xB || op == 0x8 || op == 0x9 {
                // B / BL / LDM / STM — common ARM instructions.
                score += 2;
            } else if op <= 0x7 {
                score += 1;
            }
        }
    }
    score.min(100)
}

/// Count Thumb code pattern indicators in a window.
fn score_thumb(window: &[u8]) -> u32 {
    let mut score = 0u32;
    for i in (0..window.len().saturating_sub(1)).step_by(2) {
        let hw = u16::from_le_bytes([window[i], window[i + 1]]);
        let top5 = hw >> 11;
        match top5 {
            0b00000..=0b01111 | 0b11000 | 0b11001 => score += 1, // Shift/add/sub/move/compare/branch
            0b11100..=0b11111 => score += 2, // BL/BLX/branches
            _ => {}
        }
    }
    score.min(100)
}

/// Merge adjacent `CodeRegion` entries of the same ISA.
fn merge_code_regions(regions: Vec<CodeRegion>) -> Vec<CodeRegion> {
    if regions.is_empty() {
        return regions;
    }
    let mut out: Vec<CodeRegion> = Vec::with_capacity(regions.len());
    for region in regions {
        if let Some(last) = out.last_mut()
            .filter(|last| last.isa == region.isa && last.start + last.length == region.start)
        {
            last.length += region.length;
            last.confidence = last.confidence.max(region.confidence);
        } else {
            out.push(region);
        }
    }
    out
}

/// Try to find the IRQ handler address from the ROM interrupt vectors.
///
/// In GBA ROMs the interrupt handler vector is stored at offset 0x03 in IWRAM
/// ($03007FFC), but many ROMs store the address in the ROM data header or
/// borrow it from `$0000_0018` (ARM BIOS IRQ vector). We scan the first 0x100
/// bytes for plausible ROM addresses.
fn find_irq_handler(data: &[u8]) -> Option<u32> {
    // Scan for 32-bit LE values that look like valid ROM or IWRAM addresses.
    for i in (0..data.len().min(0x100)).step_by(4) {
        if i + 4 > data.len() {
            break;
        }
        let val = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
        if (GBA_ROM_BASE..GBA_ROM_BASE + 0x200_0000).contains(&val)
            || (GBA_IWRAM_BASE..GBA_IWRAM_BASE + GBA_IWRAM_SIZE).contains(&val)
        {
            return Some(val);
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gba_rom(size: usize) -> Vec<u8> {
        let mut d = vec![0u8; size.max(GBA_MIN_SIZE + 64)];
        // ARM B instruction to offset 0xC0.
        let branch: u32 = 0xEA00_0022; // B #0xC0 from 0 (offset 0x88 → PC+8 = 0xC0)
        d[0..4].copy_from_slice(&branch.to_le_bytes());
        // Nintendo logo
        d[GBA_LOGO_OFFSET..GBA_LOGO_OFFSET + GBA_LOGO_LEN]
            .copy_from_slice(&GBA_NINTENDO_LOGO);
        // Title
        d[GBA_TITLE_OFFSET..GBA_TITLE_OFFSET + 4].copy_from_slice(b"TEST");
        // Game code
        d[GBA_GAME_CODE_OFFSET..GBA_GAME_CODE_OFFSET + 4].copy_from_slice(b"AEJE");
        // Maker code
        d[GBA_MAKER_CODE_OFFSET..GBA_MAKER_CODE_OFFSET + 2].copy_from_slice(b"01");
        // Fixed value
        d[GBA_FIXED_OFFSET] = GBA_FIXED_VALUE;
        // Compute complement
        let ck = check_complement(&d);
        d[GBA_COMPLEMENT_OFFSET] = ck;
        d
    }

    #[test]
    fn test_header_parse_valid() {
        let d = make_gba_rom(0x200);
        let h = GbaHeader::parse(&d).unwrap();
        assert_eq!(h.title.trim(), "TEST");
        assert_eq!(h.game_code, "AEJE");
        assert!(h.logo_valid);
        assert!(h.complement_valid);
        assert!(h.fixed_value_ok());
        assert!(h.is_valid());
    }

    #[test]
    fn test_header_too_short() {
        let d = vec![0u8; 16];
        assert!(GbaHeader::parse(&d).is_err());
    }

    #[test]
    fn test_complement_check() {
        let d = make_gba_rom(0x200);
        assert_eq!(check_complement(&d), d[GBA_COMPLEMENT_OFFSET]);
    }

    #[test]
    fn test_save_type_detection_eeprom() {
        let mut d = make_gba_rom(0x400);
        d[0x300..0x308].copy_from_slice(b"EEPROM_V");
        assert_eq!(GbaSaveType::detect(&d), GbaSaveType::Eeprom);
    }

    #[test]
    fn test_save_type_detection_sram() {
        let mut d = make_gba_rom(0x400);
        d[0x300..0x306].copy_from_slice(b"SRAM_V");
        assert_eq!(GbaSaveType::detect(&d), GbaSaveType::Sram);
    }

    #[test]
    fn test_save_type_detection_flash() {
        let mut d = make_gba_rom(0x400);
        d[0x300..0x307].copy_from_slice(b"FLASH_V");
        assert_eq!(GbaSaveType::detect(&d), GbaSaveType::Flash512k);
    }

    #[test]
    fn test_save_type_none() {
        let d = make_gba_rom(0x200);
        assert_eq!(GbaSaveType::detect(&d), GbaSaveType::None);
    }

    #[test]
    fn test_gba_isa_display() {
        assert_eq!(GbaIsa::Arm.to_string(), "ARM");
        assert_eq!(GbaIsa::Thumb.to_string(), "Thumb");
    }

    #[test]
    fn test_region_decode() {
        let mut d = make_gba_rom(0x200);
        d[GBA_GAME_CODE_OFFSET + 3] = b'J';
        let h = GbaHeader::parse(&d).unwrap();
        assert_eq!(h.region(), "Japan");
    }

    #[test]
    fn test_loader_entry_point() {
        // ARM B #0xC0: offset = (0xC0 - 8) / 4 = 0x2E
        let mut d = make_gba_rom(0x400);
        let branch: u32 = 0xEA00_002E; // B +0xC0+8 = 0xC8? Let's compute:
        // B offset: PC+8 + offset*4 = 8 + 0x2E*4 = 8 + 0xB8 = 0xC0
        d[0..4].copy_from_slice(&branch.to_le_bytes());
        let loader = GbaLoader::load(d).unwrap();
        let ep = loader.entry_point();
        assert_eq!(ep, GBA_ROM_BASE + 0xC0);
    }

    #[test]
    fn test_loader_segments() {
        let d = make_gba_rom(0x400);
        let loader = GbaLoader::load(d).unwrap();
        let segs = loader.segments();
        // Should include ROM_WS0, EWRAM, IWRAM, etc.
        assert!(segs.iter().any(|(name, _, _, _, _, _)| *name == "ROM_WS0"));
        assert!(segs.iter().any(|(name, _, _, _, _, _)| *name == "EWRAM"));
    }

    #[test]
    fn test_arm_bl_count() {
        let mut d = vec![0u8; 32];
        // Two ARM BL instructions.
        d[0x03] = 0xEB;
        d[0x07] = 0xEB;
        assert_eq!(count_arm_bl(&d), 2);
    }

    #[test]
    fn test_thumb_bl_count() {
        let mut d = vec![0u8; 32];
        // One Thumb BL pair: 0xF000, 0xF800
        d[0] = 0x00; d[1] = 0xF0; // hw1 top5 = 0b11110 ✓
        d[2] = 0x00; d[3] = 0xF8; // hw2 top5 = 0b11111 ✓
        assert_eq!(count_thumb_bl(&d), 1);
    }

    #[test]
    fn test_multiboot_detection() {
        let mut d = make_gba_rom(0x200);
        d[0xBA] = 0x96;
        let h = GbaHeader::parse(&d).unwrap();
        assert!(h.is_multiboot);
    }

    #[test]
    fn test_gba_save_requires_battery() {
        assert!(GbaSaveType::Eeprom.requires_battery());
        assert!(GbaSaveType::Sram.requires_battery());
        assert!(!GbaSaveType::None.requires_battery());
    }
}
