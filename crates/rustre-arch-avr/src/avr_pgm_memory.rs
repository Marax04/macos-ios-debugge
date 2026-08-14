//! AVR program memory utilities.
//!
//! Models flash memory layout for common AVR chips:
//! `ATmega328P`, `ATmega2560`, `ATtiny85`.
//! Provides `PgmMemoryMap`, `BootloaderSection` detection, `PgmReader`,
//! `IvectorTable`, `ApplicationSection`, `BootSection`, and `FlashUsageMap`.

use std::collections::HashMap;
use std::fmt;

// ─── Chip Model ───────────────────────────────────────────────────────────────

/// Supported AVR chip models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvrChip {
    /// `ATmega328P` — 32 KiB flash, 2 KiB RAM, 1 KiB EEPROM (Arduino Uno).
    ATmega328P,
    /// `ATmega2560` — 256 KiB flash, 8 KiB RAM (Arduino Mega).
    ATmega2560,
    /// `ATtiny85` — 8 KiB flash, 512 B RAM.
    ATtiny85,
    /// Generic AVR with configurable flash size.
    Generic { flash_bytes: u32 },
}

impl AvrChip {
    /// Flash size in bytes.
    #[must_use]
    pub const fn flash_size(self) -> u32 {
        match self {
            Self::ATmega328P => 32 * 1024,
            Self::ATmega2560 => 256 * 1024,
            Self::ATtiny85 => 8 * 1024,
            Self::Generic { flash_bytes } => flash_bytes,
        }
    }

    /// SRAM size in bytes.
    #[must_use]
    pub const fn sram_size(self) -> u16 {
        match self {
            Self::ATmega328P => 2048,
            Self::ATmega2560 => 8192,
            Self::ATtiny85 => 512,
            Self::Generic { .. } => 0,
        }
    }

    /// Page size in bytes.
    #[must_use]
    pub const fn page_size(self) -> u16 {
        match self {
            Self::ATmega328P => 128,
            Self::ATmega2560 => 256,
            Self::ATtiny85 | Self::Generic { .. } => 64,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ATmega328P => "ATmega328P",
            Self::ATmega2560 => "ATmega2560",
            Self::ATtiny85 => "ATtiny85",
            Self::Generic { .. } => "Generic AVR",
        }
    }

    /// Number of interrupt vectors.
    #[must_use]
    pub const fn ivector_count(self) -> u8 {
        match self {
            Self::ATmega328P => 26,
            Self::ATmega2560 => 57,
            Self::ATtiny85 => 15,
            Self::Generic { .. } => 1,
        }
    }

    /// True if this chip supports a bootloader section (BOOTRST fuse).
    #[must_use]
    pub const fn has_bootloader_section(self) -> bool {
        !matches!(self, Self::ATtiny85)
    }
}

// ─── Flash Region ─────────────────────────────────────────────────────────────

/// A named region in the AVR flash address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashRegion {
    pub name: &'static str,
    /// Start address in bytes (word-addressed × 2).
    pub start_byte: u32,
    /// End address (exclusive) in bytes.
    pub end_byte: u32,
    /// Description.
    pub description: &'static str,
}

impl FlashRegion {
    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u32 {
        self.end_byte.saturating_sub(self.start_byte)
    }

    /// Size in words (16-bit).
    #[must_use]
    pub const fn size_words(&self) -> u32 {
        self.size_bytes() / 2
    }

    /// True if the byte address `addr` falls within this region.
    #[must_use]
    pub const fn contains_byte_addr(&self, addr: u32) -> bool {
        addr >= self.start_byte && addr < self.end_byte
    }

    /// True if the word address (PC value) falls within this region.
    #[must_use]
    pub const fn contains_word_addr(&self, word_addr: u32) -> bool {
        let byte = word_addr.saturating_mul(2);
        self.contains_byte_addr(byte)
    }
}

impl fmt::Display for FlashRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{:#06x}..{:#06x}] ({} bytes)",
            self.name,
            self.start_byte,
            self.end_byte,
            self.size_bytes()
        )
    }
}

// ─── Bootloader Section ───────────────────────────────────────────────────────

/// Bootloader section size options (BOOTSZ fuse bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderSize {
    /// 256 words (512 bytes).
    Words256,
    /// 512 words (1024 bytes).
    Words512,
    /// 1024 words (2048 bytes).
    Words1024,
    /// 2048 words (4096 bytes).
    Words2048,
}

impl BootloaderSize {
    /// Size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::Words256 => 512,
            Self::Words512 => 1024,
            Self::Words1024 => 2048,
            Self::Words2048 => 4096,
        }
    }
}

/// Bootloader section descriptor.
#[derive(Debug, Clone)]
pub struct BootloaderSection {
    pub chip: AvrChip,
    pub size: BootloaderSize,
    /// Start byte address of the bootloader section.
    pub start_byte: u32,
    /// End byte address (exclusive) — always equal to `chip.flash_size()`.
    pub end_byte: u32,
}

impl BootloaderSection {
    /// Compute the bootloader section for a chip and boot size setting.
    #[must_use]
    pub const fn for_chip(chip: AvrChip, size: BootloaderSize) -> Option<Self> {
        if !chip.has_bootloader_section() {
            return None;
        }
        let flash = chip.flash_size();
        let boot_bytes = size.bytes();
        if boot_bytes > flash / 2 {
            return None;
        }
        let start = flash - boot_bytes;
        Some(Self {
            chip,
            size,
            start_byte: start,
            end_byte: flash,
        })
    }

    /// True if the byte address `addr` falls in the bootloader section.
    #[must_use]
    pub const fn contains(&self, addr: u32) -> bool {
        addr >= self.start_byte && addr < self.end_byte
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u32 {
        self.end_byte.saturating_sub(self.start_byte)
    }
}

// ─── Interrupt Vector Table ───────────────────────────────────────────────────

/// A single interrupt vector entry.
#[derive(Debug, Clone)]
pub struct IvectorEntry {
    /// Vector number (0 = RESET).
    pub number: u8,
    /// Byte address of this vector in flash.
    pub byte_addr: u32,
    /// Name of the interrupt (e.g. `RESET`, `INT0`, `TIMER0_OVF`).
    pub name: &'static str,
}

impl IvectorEntry {
    /// Word address (PC value).
    #[must_use]
    pub const fn word_addr(&self) -> u32 {
        self.byte_addr / 2
    }
}

/// Interrupt vector table for a specific AVR chip.
#[derive(Debug, Clone)]
pub struct IvectorTable {
    pub chip: AvrChip,
    pub vectors: Vec<IvectorEntry>,
}

impl IvectorTable {
    /// Build the IVT for `chip`.  Each vector occupies 2 bytes (JMP word or RJMP).
    #[must_use]
    pub fn for_chip(chip: AvrChip) -> Self {
        let names = match chip {
            AvrChip::ATmega328P => ATMEGA328P_VECTORS,
            AvrChip::ATmega2560 => ATMEGA2560_VECTORS,
            AvrChip::ATtiny85 => ATTINY85_VECTORS,
            AvrChip::Generic { .. } => &[("RESET", 0u8)][..],
        };

        let vectors = names
            .iter()
            .map(|&(name, num)| IvectorEntry {
                number: num,
                byte_addr: u32::from(num) * 4, // 4-byte wide for AVRs with JMP
                name,
            })
            .collect();

        Self { chip, vectors }
    }

    /// Look up a vector by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&IvectorEntry> {
        self.vectors.iter().find(|v| v.name == name)
    }

    /// Look up a vector by number.
    #[must_use]
    pub fn find_by_number(&self, num: u8) -> Option<&IvectorEntry> {
        self.vectors.iter().find(|v| v.number == num)
    }

    /// Total number of vectors.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.vectors.len()
    }

    /// Total byte size of the IVT.
    #[must_use]
    pub fn size_bytes(&self) -> u32 {
        u32::try_from(self.vectors.len()).unwrap_or(u32::MAX).saturating_mul(4)
    }
}

static ATMEGA328P_VECTORS: &[(&str, u8)] = &[
    ("RESET", 0),
    ("INT0", 1),
    ("INT1", 2),
    ("PCINT0", 3),
    ("PCINT1", 4),
    ("PCINT2", 5),
    ("WDT", 6),
    ("TIMER2_COMPA", 7),
    ("TIMER2_COMPB", 8),
    ("TIMER2_OVF", 9),
    ("TIMER1_CAPT", 10),
    ("TIMER1_COMPA", 11),
    ("TIMER1_COMPB", 12),
    ("TIMER1_OVF", 13),
    ("TIMER0_COMPA", 14),
    ("TIMER0_COMPB", 15),
    ("TIMER0_OVF", 16),
    ("SPI_STC", 17),
    ("USART_RX", 18),
    ("USART_UDRE", 19),
    ("USART_TX", 20),
    ("ADC", 21),
    ("EE_READY", 22),
    ("ANALOG_COMP", 23),
    ("TWI", 24),
    ("SPM_READY", 25),
];

static ATMEGA2560_VECTORS: &[(&str, u8)] = &[
    ("RESET", 0),
    ("INT0", 1),
    ("INT1", 2),
    ("INT2", 3),
    ("INT3", 4),
    ("INT4", 5),
    ("INT5", 6),
    ("INT6", 7),
    ("INT7", 8),
    ("PCINT0", 9),
    ("PCINT1", 10),
    ("PCINT2", 11),
    ("WDT", 12),
    ("TIMER2_COMPA", 13),
    ("TIMER2_COMPB", 14),
    ("TIMER2_OVF", 15),
    ("TIMER1_CAPT", 16),
    ("TIMER1_COMPA", 17),
    ("TIMER1_COMPB", 18),
    ("TIMER1_COMPC", 19),
    ("TIMER1_OVF", 20),
    ("TIMER0_COMPA", 21),
    ("TIMER0_COMPB", 22),
    ("TIMER0_OVF", 23),
    ("SPI_STC", 24),
    ("USART0_RX", 25),
    ("USART0_UDRE", 26),
    ("USART0_TX", 27),
    ("ANALOG_COMP", 28),
    ("ADC", 29),
    ("EE_READY", 30),
    ("TWI", 31),
    ("SPM_READY", 32),
    ("TIMER3_CAPT", 33),
    ("TIMER3_COMPA", 34),
    ("TIMER3_COMPB", 35),
    ("TIMER3_COMPC", 36),
    ("TIMER3_OVF", 37),
    ("USART1_RX", 38),
    ("USART1_UDRE", 39),
    ("USART1_TX", 40),
    ("USART2_RX", 41),
    ("USART2_UDRE", 42),
    ("USART2_TX", 43),
    ("TIMER4_CAPT", 44),
    ("TIMER4_COMPA", 45),
    ("TIMER4_COMPB", 46),
    ("TIMER4_COMPC", 47),
    ("TIMER4_OVF", 48),
    ("TIMER5_CAPT", 49),
    ("TIMER5_COMPA", 50),
    ("TIMER5_COMPB", 51),
    ("TIMER5_COMPC", 52),
    ("TIMER5_OVF", 53),
    ("USART3_RX", 54),
    ("USART3_UDRE", 55),
    ("USART3_TX", 56),
];

static ATTINY85_VECTORS: &[(&str, u8)] = &[
    ("RESET", 0),
    ("INT0", 1),
    ("PCINT0", 2),
    ("TIMER1_COMPA", 3),
    ("TIMER1_OVF", 4),
    ("TIMER0_OVF", 5),
    ("EE_READY", 6),
    ("ANA_COMP", 7),
    ("ADC", 8),
    ("TIMER1_COMPB", 9),
    ("TIMER0_COMPA", 10),
    ("TIMER0_COMPB", 11),
    ("WDT", 12),
    ("USI_START", 13),
    ("USI_OVF", 14),
];

// ─── Program Memory Map ───────────────────────────────────────────────────────

/// Program memory map for an AVR chip.
#[derive(Debug, Clone)]
pub struct PgmMemoryMap {
    pub chip: AvrChip,
    pub flash_size: u32,
    pub application_section: ApplicationSection,
    pub boot_section: Option<BootSection>,
    pub ivt: IvectorTable,
}

impl PgmMemoryMap {
    /// Create a default memory map (no bootloader) for `chip`.
    #[must_use]
    pub fn new(chip: AvrChip) -> Self {
        let flash_size = chip.flash_size();
        let ivt = IvectorTable::for_chip(chip);
        let ivt_end = ivt.size_bytes();

        let application_section = ApplicationSection {
            chip,
            start_byte: 0,
            end_byte: flash_size,
            app_code_start: ivt_end,
        };

        Self {
            chip,
            flash_size,
            application_section,
            boot_section: None,
            ivt,
        }
    }

    /// Create a map with a bootloader section.
    #[must_use]
    pub fn with_bootloader(chip: AvrChip, boot_size: BootloaderSize) -> Self {
        let mut map = Self::new(chip);
        if let Some(boot) = BootloaderSection::for_chip(chip, boot_size) {
            let app_end = boot.start_byte;
            map.application_section.end_byte = app_end;
            map.boot_section = Some(BootSection {
                chip,
                start_byte: boot.start_byte,
                end_byte: boot.end_byte,
                size: boot.size,
            });
        }
        map
    }

    /// True if `byte_addr` falls in the application section.
    #[must_use]
    pub const fn is_application(&self, byte_addr: u32) -> bool {
        self.application_section.contains(byte_addr)
    }

    /// True if `byte_addr` falls in the bootloader section.
    #[must_use]
    pub fn is_bootloader(&self, byte_addr: u32) -> bool {
        self.boot_section
            .as_ref()
            .is_some_and(|b| b.contains(byte_addr))
    }

    /// True if `byte_addr` is within the IVT.
    #[must_use]
    pub fn is_ivt(&self, byte_addr: u32) -> bool {
        byte_addr < self.ivt.size_bytes()
    }

    /// Region name for a given byte address.
    #[must_use]
    pub fn region_name(&self, byte_addr: u32) -> &'static str {
        if self.is_ivt(byte_addr) {
            "IVT"
        } else if self.is_bootloader(byte_addr) {
            "BOOTLOADER"
        } else if self.is_application(byte_addr) {
            "APPLICATION"
        } else {
            "UNKNOWN"
        }
    }

    /// Total flash size in bytes.
    #[must_use]
    pub const fn total_flash(&self) -> u32 {
        self.flash_size
    }
}

// ─── Application / Boot Sections ─────────────────────────────────────────────

/// The application section of AVR flash.
#[derive(Debug, Clone)]
pub struct ApplicationSection {
    pub chip: AvrChip,
    pub start_byte: u32,
    pub end_byte: u32,
    /// Byte offset where actual application code starts (after IVT).
    pub app_code_start: u32,
}

impl ApplicationSection {
    #[must_use]
    pub const fn contains(&self, addr: u32) -> bool {
        addr >= self.start_byte && addr < self.end_byte
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u32 {
        self.end_byte.saturating_sub(self.start_byte)
    }

    #[must_use]
    pub const fn code_size_bytes(&self) -> u32 {
        self.end_byte.saturating_sub(self.app_code_start)
    }
}

/// The bootloader section of AVR flash.
#[derive(Debug, Clone)]
pub struct BootSection {
    pub chip: AvrChip,
    pub start_byte: u32,
    pub end_byte: u32,
    pub size: BootloaderSize,
}

impl BootSection {
    #[must_use]
    pub const fn contains(&self, addr: u32) -> bool {
        addr >= self.start_byte && addr < self.end_byte
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u32 {
        self.end_byte.saturating_sub(self.start_byte)
    }
}

// ─── PgmReader ────────────────────────────────────────────────────────────────

/// Word-addressed program memory reader.
///
/// AVR program memory is word-addressed: each instruction word is 2 bytes,
/// and the PC increments by 1 for each 2-byte word fetched.
#[derive(Debug, Clone)]
pub struct PgmReader {
    /// Raw flash image bytes (little-endian, as burned to flash).
    data: Vec<u8>,
    /// Base byte address (usually 0 for a full flash image).
    base: u32,
}

impl PgmReader {
    /// Create a new reader from raw flash bytes.
    #[must_use]
    pub const fn new(data: Vec<u8>, base: u32) -> Self {
        Self { data, base }
    }

    /// Read a 16-bit instruction word at *word address* `word_addr`.
    ///
    /// Returns `None` if out of range.
    #[must_use]
    pub fn read_word(&self, word_addr: u32) -> Option<u16> {
        let byte_off = word_addr.checked_mul(2)?.checked_sub(self.base)? as usize;
        let b0 = *self.data.get(byte_off)?;
        let b1 = *self.data.get(byte_off + 1)?;
        Some(u16::from_le_bytes([b0, b1]))
    }

    /// Read a 16-bit value at *byte address* `addr`.
    #[must_use]
    pub fn read_u16_at(&self, byte_addr: u32) -> Option<u16> {
        let off = byte_addr.checked_sub(self.base)? as usize;
        let b0 = *self.data.get(off)?;
        let b1 = *self.data.get(off + 1)?;
        Some(u16::from_le_bytes([b0, b1]))
    }

    /// Read a byte at *byte address* `addr`.
    #[must_use]
    pub fn read_byte_at(&self, byte_addr: u32) -> Option<u8> {
        let off = byte_addr.checked_sub(self.base)? as usize;
        self.data.get(off).copied()
    }

    /// Flash image size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.data.len()
    }

    /// Number of 16-bit words in the image.
    #[must_use]
    pub const fn size_words(&self) -> usize {
        self.data.len() / 2
    }

    /// True if the image appears to be blank (all 0xFF).
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.data.iter().all(|&b| b == 0xFF)
    }

    /// Compute a simple Fletcher-16 checksum of the flash image.
    #[must_use]
    pub fn checksum(&self) -> u16 {
        let mut s1: u16 = 0;
        let mut s2: u16 = 0;
        for &b in &self.data {
            s1 = s1.wrapping_add(u16::from(b));
            s2 = s2.wrapping_add(s1);
        }
        (s2 << 8) | (s1 & 0xFF)
    }

    /// Detect the reset vector target by reading the first instruction.
    ///
    /// For `RJMP`: PC+1 + signed 12-bit offset.
    /// For `JMP`:  32-bit absolute target.
    /// Returns byte address.
    #[must_use]
    pub fn reset_vector_target(&self) -> Option<u32> {
        let word = self.read_word(0)?;
        // RJMP: 1100 kkkk kkkk kkkk
        if (word & 0xF000) == 0xC000 {
            let k = (word & 0x0FFF).cast_signed();
            let k_signed = if k & 0x0800 != 0 { k | -0x1000_i16 } else { k };
            // Target word addr = 1 + k_signed, convert to byte addr
            let target_word = 1i32.wrapping_add(i32::from(k_signed)).cast_unsigned();
            return Some(target_word * 2);
        }
        // JMP: 1001 010k kkkk 110k  + 16-bit word
        if (word & 0xFE0E) == 0x940C && let Some(w2) = self.read_word(1) {
            let k_hi = ((u32::from(word) & 0x01F0) >> 3) | (u32::from(word) & 1);
            let k_lo = u32::from(w2);
            return Some(((k_hi << 16) | k_lo) * 2);
        }
        None
    }
}

// ─── Flash Usage Map ──────────────────────────────────────────────────────────

/// Records which byte ranges of flash are occupied by code, data, or are blank.
#[derive(Debug, Clone)]
pub struct FlashUsageMap {
    pub flash_size: u32,
    entries: Vec<FlashUsageEntry>,
    stats: FlashUsageStats,
}

/// A contiguous range of flash with a usage tag.
#[derive(Debug, Clone)]
pub struct FlashUsageEntry {
    pub start: u32,
    pub end: u32,
    pub kind: FlashUsageKind,
}

/// Flash usage kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlashUsageKind {
    /// Interrupt vector table.
    IVT,
    /// Application code.
    Code,
    /// Constant data (strings, tables).
    Data,
    /// Bootloader code.
    Bootloader,
    /// Blank (0xFF).
    Blank,
    /// Unknown / not analyzed.
    Unknown,
}

/// Aggregate statistics for a flash image.
#[derive(Debug, Clone, Default)]
pub struct FlashUsageStats {
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub blank_bytes: u32,
    pub ivt_bytes: u32,
    pub bootloader_bytes: u32,
}

impl FlashUsageMap {
    /// Create a map from a `PgmReader` and a `PgmMemoryMap`.
    #[must_use]
    pub fn from_image(reader: &PgmReader, map: &PgmMemoryMap) -> Self {
        let flash_size = map.flash_size;
        let mut entries = Vec::new();
        let ivt_bytes = map.ivt.size_bytes();

        // IVT
        entries.push(FlashUsageEntry {
            start: 0,
            end: ivt_bytes,
            kind: FlashUsageKind::IVT,
        });

        // Scan application section for blank vs non-blank words
        let app_start = map.application_section.app_code_start;
        let app_end = map.application_section.end_byte;
        let mut i = app_start;
        while i + 2 <= app_end {
            if let Some(w) = reader.read_u16_at(i) {
                let kind = if w == 0xFFFF {
                    FlashUsageKind::Blank
                } else {
                    FlashUsageKind::Code
                };
                // Coalesce with previous entry if same kind
                if let Some(last) = entries.last_mut() && last.kind == kind && last.end == i {
                    last.end += 2;
                    i += 2;
                    continue;
                }
                entries.push(FlashUsageEntry {
                    start: i,
                    end: i + 2,
                    kind,
                });
            }
            i += 2;
        }

        // Bootloader section
        if let Some(ref bs) = map.boot_section {
            entries.push(FlashUsageEntry {
                start: bs.start_byte,
                end: bs.end_byte,
                kind: FlashUsageKind::Bootloader,
            });
        }

        // Compute stats
        let mut stats = FlashUsageStats::default();
        for e in &entries {
            let sz = e.end.saturating_sub(e.start);
            match e.kind {
                FlashUsageKind::IVT => stats.ivt_bytes += sz,
                FlashUsageKind::Code => stats.code_bytes += sz,
                FlashUsageKind::Data => stats.data_bytes += sz,
                FlashUsageKind::Blank => stats.blank_bytes += sz,
                FlashUsageKind::Bootloader => stats.bootloader_bytes += sz,
                FlashUsageKind::Unknown => {}
            }
        }

        Self {
            flash_size,
            entries,
            stats,
        }
    }

    /// Fraction of flash used (non-blank, non-IVT).
    #[must_use]
    pub fn usage_fraction(&self) -> f64 {
        let used = self.stats.code_bytes
            .saturating_add(self.stats.data_bytes)
            .saturating_add(self.stats.ivt_bytes)
            .saturating_add(self.stats.bootloader_bytes);
        if self.flash_size == 0 {
            return 0.0;
        }
        f64::from(used) / f64::from(self.flash_size)
    }

    /// Number of distinct regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.entries.len()
    }

    /// Stats summary.
    #[must_use]
    pub const fn stats(&self) -> &FlashUsageStats {
        &self.stats
    }

    /// Total byte count per `FlashUsageKind` across all entries.
    #[must_use]
    pub fn kind_histogram(&self) -> HashMap<FlashUsageKind, u32> {
        let mut hist: HashMap<FlashUsageKind, u32> = HashMap::new();
        for e in &self.entries {
            *hist.entry(e.kind).or_insert(0) += e.end.saturating_sub(e.start);
        }
        hist
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chip_flash_sizes() {
        assert_eq!(AvrChip::ATmega328P.flash_size(), 32768);
        assert_eq!(AvrChip::ATmega2560.flash_size(), 262_144);
        assert_eq!(AvrChip::ATtiny85.flash_size(), 8192);
    }

    #[test]
    fn test_chip_sram() {
        assert_eq!(AvrChip::ATmega328P.sram_size(), 2048);
        assert_eq!(AvrChip::ATmega2560.sram_size(), 8192);
    }

    #[test]
    fn test_chip_names() {
        assert_eq!(AvrChip::ATmega328P.name(), "ATmega328P");
        assert_eq!(AvrChip::ATtiny85.name(), "ATtiny85");
    }

    #[test]
    fn test_bootloader_section() {
        let bs =
            BootloaderSection::for_chip(AvrChip::ATmega328P, BootloaderSize::Words512).unwrap();
        assert_eq!(bs.size_bytes(), 1024);
        assert_eq!(bs.end_byte, 32768);
        assert_eq!(bs.start_byte, 31744);
        assert!(bs.contains(31800));
        assert!(!bs.contains(100));
    }

    #[test]
    fn test_attiny85_no_bootloader() {
        assert!(BootloaderSection::for_chip(AvrChip::ATtiny85, BootloaderSize::Words256).is_none());
    }

    #[test]
    fn test_ivt_atmega328p() {
        let ivt = IvectorTable::for_chip(AvrChip::ATmega328P);
        assert_eq!(ivt.count(), 26);
        let reset = ivt.find_by_number(0).unwrap();
        assert_eq!(reset.name, "RESET");
        assert_eq!(reset.byte_addr, 0);
    }

    #[test]
    fn test_ivt_atmega2560() {
        let ivt = IvectorTable::for_chip(AvrChip::ATmega2560);
        assert_eq!(ivt.count(), 57);
        assert!(ivt.find_by_name("TIMER5_OVF").is_some());
    }

    #[test]
    fn test_ivt_attiny85() {
        let ivt = IvectorTable::for_chip(AvrChip::ATtiny85);
        assert_eq!(ivt.count(), 15);
        assert!(ivt.find_by_name("WDT").is_some());
    }

    #[test]
    fn test_memory_map_no_bootloader() {
        let m = PgmMemoryMap::new(AvrChip::ATmega328P);
        assert!(m.boot_section.is_none());
        assert!(m.is_application(0x1000));
        assert!(!m.is_bootloader(0x1000));
        assert!(m.is_ivt(0x10)); // within IVT
    }

    #[test]
    fn test_memory_map_with_bootloader() {
        let m = PgmMemoryMap::with_bootloader(AvrChip::ATmega328P, BootloaderSize::Words512);
        let boot = m.boot_section.as_ref().unwrap();
        assert!(m.is_bootloader(boot.start_byte + 10));
        assert!(!m.is_application(boot.start_byte + 10));
    }

    #[test]
    fn test_region_name() {
        let m = PgmMemoryMap::with_bootloader(AvrChip::ATmega328P, BootloaderSize::Words512);
        assert_eq!(m.region_name(0x0004), "IVT");
        assert_eq!(m.region_name(0x0200), "APPLICATION");
        let boot_start = m.boot_section.as_ref().unwrap().start_byte;
        assert_eq!(m.region_name(boot_start + 8), "BOOTLOADER");
    }

    #[test]
    fn test_pgm_reader_rjmp() {
        // RJMP 0 (self-loop) at address 0: 0xCFFF → k = -1 → target = (1 + (-1)) * 2 = 0
        let data = vec![0xFF, 0xCF, 0x00, 0x00];
        let reader = PgmReader::new(data, 0);
        let target = reader.reset_vector_target().unwrap();
        assert_eq!(target, 0);
    }

    #[test]
    fn test_pgm_reader_rjmp_forward() {
        // RJMP +10 words: k=10 → word 0xC00A → target = (1+10)*2 = 22
        let data = vec![0x0A, 0xC0, 0x00, 0x00];
        let reader = PgmReader::new(data, 0);
        let target = reader.reset_vector_target().unwrap();
        assert_eq!(target, 22);
    }

    #[test]
    fn test_pgm_reader_checksum() {
        let data = vec![1u8, 2, 3, 4];
        let reader = PgmReader::new(data, 0);
        let cs = reader.checksum();
        assert_ne!(cs, 0); // just verify it runs
    }

    #[test]
    fn test_pgm_reader_blank() {
        let data = vec![0xFF; 32];
        let reader = PgmReader::new(data, 0);
        assert!(reader.is_blank());
    }

    #[test]
    fn test_pgm_reader_not_blank() {
        let mut data = vec![0xFF; 32];
        data[16] = 0x00;
        let reader = PgmReader::new(data, 0);
        assert!(!reader.is_blank());
    }

    #[test]
    fn test_flash_region_contains() {
        let r = FlashRegion {
            name: "test",
            start_byte: 0x100,
            end_byte: 0x200,
            description: "",
        };
        assert!(r.contains_byte_addr(0x150));
        assert!(!r.contains_byte_addr(0x50));
        assert!(r.contains_word_addr(0x80)); // byte = 0x100
    }

    #[test]
    fn test_flash_usage_map() {
        // Create a small flash image: IVT (104 bytes = 26 vectors × 4) + code + blank
        let map = PgmMemoryMap::new(AvrChip::ATmega328P);
        let ivt_bytes = map.ivt.size_bytes() as usize;
        let mut data = vec![0xFFu8; 32768];
        // Write some non-blank "code" right after IVT
        for i in 0..128 {
            data[ivt_bytes + i] = 0x00;
        }
        let reader = PgmReader::new(data, 0);
        let usage = FlashUsageMap::from_image(&reader, &map);
        assert!(usage.stats().code_bytes > 0);
        assert!(usage.stats().blank_bytes > 0);
        assert_eq!(usage.stats().ivt_bytes, u32::try_from(ivt_bytes).unwrap_or(u32::MAX));
        assert!(usage.usage_fraction() > 0.0 && usage.usage_fraction() < 1.0);
    }

    #[test]
    fn test_ivector_entry_word_addr() {
        let e = IvectorEntry {
            number: 2,
            byte_addr: 8,
            name: "INT1",
        };
        assert_eq!(e.word_addr(), 4);
    }

    #[test]
    fn test_application_section_code_size() {
        let m = PgmMemoryMap::new(AvrChip::ATmega328P);
        let code_size = m.application_section.code_size_bytes();
        let total = m.application_section.size_bytes();
        assert!(code_size < total); // IVT takes some space
    }
}
