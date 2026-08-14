//! Console memory map modelling for classic gaming platforms.
//!
//! Provides [`ConsoleMemoryMap`], [`MemoryRegion`], [`RegionKind`], and
//! [`map_address`].  Pre-built maps are supplied for NES, SNES, Game Boy,
//! GBA, and Sega Genesis.

use std::collections::BTreeMap;
use std::fmt;

// ── RegionKind ────────────────────────────────────────────────────────────────

/// The purpose / access type of a memory region.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// Program ROM (executable, read-only).
    PrgRom,
    /// Character / graphics ROM.
    ChrRom,
    /// Work RAM.
    WorkRam,
    /// Video RAM.
    VideoRam,
    /// Object Attribute Memory (sprites).
    Oam,
    /// Memory-mapped I/O registers.
    IoRegisters,
    /// Save / battery-backed RAM.
    SaveRam,
    /// Boot ROM overlay.
    BootRom,
    /// DMA channel.
    Dma,
    /// Sound / APU registers.
    Sound,
    /// Cartridge expansion ROM/RAM.
    Expansion,
    /// Region whose function is unknown or unmapped.
    Unmapped,
}

impl RegionKind {
    /// Return `true` if this region is executable (can hold instructions).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::PrgRom | Self::WorkRam | Self::BootRom)
    }

    /// Return `true` if this region is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        !matches!(self, Self::PrgRom | Self::ChrRom | Self::BootRom)
    }

    /// Short human-readable tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::PrgRom => "PRG-ROM",
            Self::ChrRom => "CHR-ROM",
            Self::WorkRam => "WRAM",
            Self::VideoRam => "VRAM",
            Self::Oam => "OAM",
            Self::IoRegisters => "IO",
            Self::SaveRam => "SRAM",
            Self::BootRom => "BOOT",
            Self::Dma => "DMA",
            Self::Sound => "APU",
            Self::Expansion => "EXP",
            Self::Unmapped => "---",
        }
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

// ── MemoryRegion ──────────────────────────────────────────────────────────────

/// A contiguous region within a console's address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Human-readable name.
    pub name: String,
    /// First address in the range (inclusive).
    pub start: u64,
    /// Last address in the range (inclusive).
    pub end: u64,
    /// The purpose of this region.
    pub kind: RegionKind,
    /// Bus alias / mirror stride.  `None` means no mirroring.
    pub mirror_stride: Option<u64>,
    /// Notes for the analyst.
    pub notes: &'static str,
}

impl MemoryRegion {
    /// Create a new region without mirroring.
    #[must_use]
    pub fn new(name: impl Into<String>, start: u64, end: u64, kind: RegionKind) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            kind,
            mirror_stride: None,
            notes: "",
        }
    }

    /// Builder: attach a mirror stride.
    #[must_use]
    pub const fn with_mirror(mut self, stride: u64) -> Self {
        self.mirror_stride = Some(stride);
        self
    }

    /// Builder: attach analyst notes.
    #[must_use]
    pub const fn with_notes(mut self, notes: &'static str) -> Self {
        self.notes = notes;
        self
    }

    /// Size of the region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start) + 1
    }

    /// Return `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr <= self.end
    }

    /// Translate `addr` to an offset within this region (physical address).
    ///
    /// Applies mirror folding when `mirror_stride` is set.
    #[must_use]
    pub fn translate(&self, addr: u64) -> Option<u64> {
        if !self.contains(addr) {
            return None;
        }
        let offset = addr - self.start;
        let phys = self.mirror_stride.map_or(offset, |stride| offset % stride);
        Some(self.start + phys)
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<12} [{:#010x}–{:#010x}] {} ({}B)",
            self.name, self.start, self.end, self.kind, self.size()
        )
    }
}

// ── AddressMappingResult ──────────────────────────────────────────────────────

/// The result of looking up an address in a [`ConsoleMemoryMap`].
#[derive(Debug, Clone)]
pub struct AddressMappingResult<'a> {
    /// The region that owns this address.
    pub region: &'a MemoryRegion,
    /// The physical (de-mirrored) address within the region.
    pub physical_address: u64,
    /// Whether the address was resolved via a mirror fold.
    pub is_mirrored: bool,
}

impl AddressMappingResult<'_> {
    /// Offset from the region start (physical).
    #[must_use]
    pub const fn region_offset(&self) -> u64 {
        self.physical_address - self.region.start
    }
}

impl fmt::Display for AddressMappingResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ phys {:#010x}{}",
            self.region.name,
            self.physical_address,
            if self.is_mirrored { " (mirrored)" } else { "" }
        )
    }
}

// ── ConsoleMemoryMap ──────────────────────────────────────────────────────────

/// A complete address-space map for a console platform.
///
/// Regions are stored sorted by start address; overlapping regions are allowed
/// (e.g. an I/O region that aliases part of a RAM window).
#[derive(Debug, Clone)]
pub struct ConsoleMemoryMap {
    /// Platform name.
    pub platform: String,
    /// Address bus width in bits.
    pub address_bits: u8,
    /// Regions ordered by start address.
    regions: Vec<MemoryRegion>,
    /// Quick index: `start_address` → region index.
    index: BTreeMap<u64, usize>,
}

impl ConsoleMemoryMap {
    /// Create an empty map for the given platform.
    #[must_use]
    pub fn new(platform: impl Into<String>, address_bits: u8) -> Self {
        Self {
            platform: platform.into(),
            address_bits,
            regions: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Add a region.  Regions may overlap.
    pub fn add_region(&mut self, region: MemoryRegion) {
        let start = region.start;
        self.regions.push(region);
        let idx = self.regions.len() - 1;
        self.index.insert(start, idx);
    }

    /// Return all regions that contain `addr`.
    #[must_use]
    pub fn regions_at(&self, addr: u64) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.contains(addr)).collect()
    }

    /// Return all regions.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Maximum addressable value.
    #[must_use]
    pub const fn max_address(&self) -> u64 {
        (1u64 << self.address_bits).saturating_sub(1)
    }

    /// Return all regions of a specific kind.
    #[must_use]
    pub fn regions_by_kind(&self, kind: &RegionKind) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| &r.kind == kind).collect()
    }

    /// Find the first region whose name contains `needle` (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, needle: &str) -> Option<&MemoryRegion> {
        let lo = needle.to_ascii_lowercase();
        self.regions.iter().find(|r| r.name.to_ascii_lowercase().contains(&lo))
    }

    /// Return a coverage report: fraction of address space covered.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        let total = self.max_address() + 1;
        if total == 0 { return 0.0; }
        let covered: u64 = self.regions.iter().map(MemoryRegion::size).sum();
        // Clamp to u32 range to avoid precision-loss cast from u64 to f64;
        // practical console address spaces fit within u32.
        let covered_f = f64::from(u32::try_from(covered).unwrap_or(u32::MAX));
        let total_f = f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        covered_f / total_f
    }

    /// One-line per-region summary.
    #[must_use]
    pub fn display_table(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("Memory map: {} ({}-bit)\n", self.platform, self.address_bits);
        for r in &self.regions {
            let _ = writeln!(out, "  {r}");
        }
        out
    }
}

// ── map_address ───────────────────────────────────────────────────────────────

/// Look up `addr` in `map` and return the mapping result.
///
/// When multiple regions contain the address the first match (by insertion
/// order) is returned.  Returns `None` when no region covers `addr` or when
/// the address exceeds the bus width.
#[must_use]
pub fn map_address(map: &ConsoleMemoryMap, addr: u64) -> Option<AddressMappingResult<'_>> {
    if addr > map.max_address() {
        return None;
    }
    for region in &map.regions {
        if region.contains(addr) {
            let phys = region.translate(addr)?;
            let is_mirrored = region.mirror_stride.is_some() && phys != addr;
            return Some(AddressMappingResult { region, physical_address: phys, is_mirrored });
        }
    }
    None
}

// ── Pre-built platform maps ───────────────────────────────────────────────────

/// Build the standard NES CPU address space map.
///
/// The NES has a 16-bit address bus.  Internal RAM (2 KiB) is mirrored
/// four times across $0000–$1FFF.  PPU registers mirror every 8 bytes
/// across $2000–$3FFF.
#[must_use]
pub fn nes_cpu_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("NES-CPU", 16);
    m.add_region(
        MemoryRegion::new("Internal RAM", 0x0000, 0x1FFF, RegionKind::WorkRam)
            .with_mirror(0x0800)
            .with_notes("2 KiB physical, mirrored 4×"),
    );
    m.add_region(
        MemoryRegion::new("PPU Registers", 0x2000, 0x3FFF, RegionKind::IoRegisters)
            .with_mirror(0x0008)
            .with_notes("8 registers, mirrored across 8 KiB"),
    );
    m.add_region(MemoryRegion::new("APU & I/O", 0x4000, 0x401F, RegionKind::Sound));
    m.add_region(
        MemoryRegion::new("Expansion ROM", 0x4020, 0x5FFF, RegionKind::Expansion)
            .with_notes("cart-specific"),
    );
    m.add_region(
        MemoryRegion::new("Save RAM", 0x6000, 0x7FFF, RegionKind::SaveRam)
            .with_notes("battery-backed on cartridges that support it"),
    );
    m.add_region(
        MemoryRegion::new("PRG-ROM Lower", 0x8000, 0xBFFF, RegionKind::PrgRom)
            .with_notes("bank-switched via mapper"),
    );
    m.add_region(
        MemoryRegion::new("PRG-ROM Upper", 0xC000, 0xFFFF, RegionKind::PrgRom)
            .with_notes("fixed or bank-switched; vectors at $FFFA–$FFFF"),
    );
    m
}

/// Build the standard NES PPU address space map.
#[must_use]
pub fn nes_ppu_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("NES-PPU", 14);
    m.add_region(MemoryRegion::new("Pattern Tables", 0x0000, 0x1FFF, RegionKind::ChrRom)
        .with_notes("8 KiB CHR-ROM/RAM from cartridge"));
    m.add_region(MemoryRegion::new("Nametables", 0x2000, 0x2FFF, RegionKind::VideoRam)
        .with_notes("4 nametables; actual VRAM is 2 KiB"));
    m.add_region(MemoryRegion::new("Nametable Mirror", 0x3000, 0x3EFF, RegionKind::VideoRam)
        .with_mirror(0x1000).with_notes("mirrors $2000–$2EFF"));
    m.add_region(MemoryRegion::new("Palette RAM", 0x3F00, 0x3FFF, RegionKind::VideoRam)
        .with_mirror(0x0020).with_notes("32 bytes, mirrored"));
    m
}

/// Build the SNES (65816) address space map (`LoROM` layout).
#[must_use]
pub fn snes_lorom_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("SNES-LoROM", 24);
    m.add_region(MemoryRegion::new("Work RAM", 0x007E_0000, 0x007F_FFFF, RegionKind::WorkRam)
        .with_notes("128 KiB internal WRAM"));
    m.add_region(MemoryRegion::new("LoROM Banks", 0x0000_8000, 0x007D_7FFF, RegionKind::PrgRom)
        .with_notes("ROM mapped at upper half of each bank"));
    m.add_region(MemoryRegion::new("SRAM", 0x0070_0000, 0x007D_FFFF, RegionKind::SaveRam)
        .with_notes("battery-backed SRAM (optional)"));
    m.add_region(MemoryRegion::new("Hardware Regs", 0x0000_2100, 0x0000_21FF, RegionKind::IoRegisters)
        .with_notes("PPU registers"));
    m.add_region(MemoryRegion::new("DMA Channels", 0x0000_4300, 0x0000_44FF, RegionKind::Dma));
    m.add_region(MemoryRegion::new("APU I/O", 0x0000_2140, 0x0000_217F, RegionKind::Sound));
    m
}

/// Build the Game Boy address space map.
#[must_use]
pub fn gameboy_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("Game Boy", 16);
    m.add_region(MemoryRegion::new("ROM Bank 0", 0x0000, 0x3FFF, RegionKind::PrgRom)
        .with_notes("fixed first ROM bank"));
    m.add_region(MemoryRegion::new("ROM Bank N", 0x4000, 0x7FFF, RegionKind::PrgRom)
        .with_notes("switchable ROM bank via MBC"));
    m.add_region(MemoryRegion::new("Video RAM", 0x8000, 0x9FFF, RegionKind::VideoRam)
        .with_notes("tiles & maps; CGB has 2 banks"));
    m.add_region(MemoryRegion::new("External RAM", 0xA000, 0xBFFF, RegionKind::SaveRam)
        .with_notes("cartridge SRAM if present"));
    m.add_region(MemoryRegion::new("Work RAM", 0xC000, 0xDFFF, RegionKind::WorkRam)
        .with_notes("8 KiB (CGB: 32 KiB banked)"));
    m.add_region(MemoryRegion::new("Echo RAM", 0xE000, 0xFDFF, RegionKind::WorkRam)
        .with_mirror(0x2000).with_notes("mirrors $C000–$DDFF"));
    m.add_region(MemoryRegion::new("OAM", 0xFE00, 0xFE9F, RegionKind::Oam)
        .with_notes("sprite attribute table"));
    m.add_region(MemoryRegion::new("I/O Regs", 0xFF00, 0xFF7F, RegionKind::IoRegisters));
    m.add_region(MemoryRegion::new("HRAM", 0xFF80, 0xFFFE, RegionKind::WorkRam)
        .with_notes("127 bytes high RAM; usable during DMA"));
    m.add_region(MemoryRegion::new("IE Register", 0xFFFF, 0xFFFF, RegionKind::IoRegisters)
        .with_notes("interrupt enable"));
    m
}

/// Build the GBA address space map.
#[must_use]
pub fn gba_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("GBA", 32);
    m.add_region(MemoryRegion::new("BIOS ROM", 0x0000_0000, 0x0000_3FFF, RegionKind::BootRom)
        .with_notes("16 KiB; read-protected when not executing from it"));
    m.add_region(MemoryRegion::new("EWRAM", 0x0200_0000, 0x0203_FFFF, RegionKind::WorkRam)
        .with_notes("256 KiB external work RAM (16-bit bus)"));
    m.add_region(MemoryRegion::new("IWRAM", 0x0300_0000, 0x0300_7FFF, RegionKind::WorkRam)
        .with_notes("32 KiB internal work RAM (32-bit bus)"));
    m.add_region(MemoryRegion::new("I/O Regs", 0x0400_0000, 0x0400_03FF, RegionKind::IoRegisters));
    m.add_region(MemoryRegion::new("Palette RAM", 0x0500_0000, 0x0500_03FF, RegionKind::VideoRam)
        .with_notes("1 KiB; 2 palettes × 256 colours"));
    m.add_region(MemoryRegion::new("VRAM", 0x0600_0000, 0x0601_7FFF, RegionKind::VideoRam)
        .with_notes("96 KiB"));
    m.add_region(MemoryRegion::new("OAM", 0x0700_0000, 0x0700_03FF, RegionKind::Oam)
        .with_notes("128 sprites × 8 bytes"));
    m.add_region(MemoryRegion::new("ROM Wait 0", 0x0800_0000, 0x09FF_FFFF, RegionKind::PrgRom)
        .with_notes("cartridge ROM, wait-state 0"));
    m.add_region(MemoryRegion::new("ROM Wait 1", 0x0A00_0000, 0x0BFF_FFFF, RegionKind::PrgRom)
        .with_notes("cartridge ROM, wait-state 1"));
    m.add_region(MemoryRegion::new("ROM Wait 2", 0x0C00_0000, 0x0DFF_FFFF, RegionKind::PrgRom)
        .with_notes("cartridge ROM, wait-state 2"));
    m.add_region(MemoryRegion::new("SRAM", 0x0E00_0000, 0x0E00_FFFF, RegionKind::SaveRam)
        .with_notes("64 KiB cartridge SRAM / Flash"));
    m
}

/// Build the Sega Genesis / Mega Drive address space map.
#[must_use]
pub fn genesis_map() -> ConsoleMemoryMap {
    let mut m = ConsoleMemoryMap::new("Sega-Genesis", 24);
    m.add_region(MemoryRegion::new("Cartridge ROM", 0x00_0000, 0x3F_FFFF, RegionKind::PrgRom)
        .with_notes("up to 4 MiB; bank-switched with SSF2 mapper"));
    m.add_region(MemoryRegion::new("Z80 RAM", 0xA0_0000, 0xA0_FFFF, RegionKind::WorkRam)
        .with_notes("Z80 address space accessible via M68k bus request"));
    m.add_region(MemoryRegion::new("VDP Regs", 0xC0_0000, 0xC0_001F, RegionKind::IoRegisters)
        .with_notes("Video Display Processor control"));
    m.add_region(MemoryRegion::new("Work RAM", 0xFF_0000, 0xFF_FFFF, RegionKind::WorkRam)
        .with_notes("64 KiB M68k work RAM"));
    m.add_region(MemoryRegion::new("VRAM (via VDP)", 0xC0_0000, 0xC0_FFFF, RegionKind::VideoRam)
        .with_notes("64 KiB VRAM accessed indirectly through VDP ports"));
    m
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_kind_properties() {
        assert!(RegionKind::PrgRom.is_executable());
        assert!(!RegionKind::PrgRom.is_writable());
        assert!(RegionKind::WorkRam.is_writable());
        assert!(RegionKind::WorkRam.is_executable());
        assert!(!RegionKind::IoRegisters.is_executable());
    }

    #[test]
    fn test_region_kind_tag() {
        assert_eq!(RegionKind::WorkRam.tag(), "WRAM");
        assert_eq!(RegionKind::PrgRom.tag(), "PRG-ROM");
        assert_eq!(RegionKind::Unmapped.tag(), "---");
    }

    #[test]
    fn test_memory_region_size() {
        let r = MemoryRegion::new("Test", 0x100, 0x1FF, RegionKind::WorkRam);
        assert_eq!(r.size(), 256);
    }

    #[test]
    fn test_memory_region_contains() {
        let r = MemoryRegion::new("Test", 0x0000, 0x07FF, RegionKind::WorkRam);
        assert!(r.contains(0x0000));
        assert!(r.contains(0x07FF));
        assert!(!r.contains(0x0800));
    }

    #[test]
    fn test_memory_region_mirror_translate() {
        // NES RAM: 2 KiB mirrored 4× across 0x0000–0x1FFF
        let r = MemoryRegion::new("RAM", 0x0000, 0x1FFF, RegionKind::WorkRam).with_mirror(0x0800);
        // Address 0x0900 should translate to 0x0100 (0x0900 % 0x0800 = 0x100)
        assert_eq!(r.translate(0x0900), Some(0x0100));
        // Address 0x0100 should not need folding
        assert_eq!(r.translate(0x0100), Some(0x0100));
    }

    #[test]
    fn test_console_memory_map_add_and_lookup() {
        let mut map = ConsoleMemoryMap::new("Test", 16);
        map.add_region(MemoryRegion::new("ROM", 0x8000, 0xFFFF, RegionKind::PrgRom));
        map.add_region(MemoryRegion::new("RAM", 0x0000, 0x07FF, RegionKind::WorkRam));
        assert_eq!(map.regions().len(), 2);
        let r = map.regions_at(0x0400);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "RAM");
    }

    #[test]
    fn test_map_address_found() {
        let map = nes_cpu_map();
        let result = map_address(&map, 0xC000).unwrap();
        assert_eq!(result.region.name, "PRG-ROM Upper");
        assert!(!result.is_mirrored);
    }

    #[test]
    fn test_map_address_mirrored() {
        let map = nes_cpu_map();
        // 0x0900 is in the mirrored NES RAM range ($0000–$1FFF, stride $0800)
        let result = map_address(&map, 0x0900).unwrap();
        assert_eq!(result.region.name, "Internal RAM");
        assert!(result.is_mirrored);
    }

    #[test]
    fn test_map_address_out_of_range() {
        let map = ConsoleMemoryMap::new("Test", 8);
        assert!(map_address(&map, 0x1000).is_none());
    }

    #[test]
    fn test_nes_cpu_map_coverage() {
        let map = nes_cpu_map();
        assert!(map.coverage_ratio() > 0.8);
    }

    #[test]
    fn test_gba_map_entry_point() {
        let map = gba_map();
        let result = map_address(&map, 0x0800_0000).unwrap();
        assert_eq!(result.region.kind, RegionKind::PrgRom);
    }

    #[test]
    fn test_gameboy_map_oam() {
        let map = gameboy_map();
        let result = map_address(&map, 0xFE00).unwrap();
        assert_eq!(result.region.kind, RegionKind::Oam);
    }

    #[test]
    fn test_genesis_map_wram() {
        let map = genesis_map();
        let result = map_address(&map, 0xFF_8000).unwrap();
        assert_eq!(result.region.kind, RegionKind::WorkRam);
    }

    #[test]
    fn test_regions_by_kind() {
        let map = nes_cpu_map();
        let rom = map.regions_by_kind(&RegionKind::PrgRom);
        assert!(!rom.is_empty());
        for r in rom {
            assert!(r.kind == RegionKind::PrgRom);
        }
    }

    #[test]
    fn test_find_by_name() {
        let map = gba_map();
        let r = map.find_by_name("BIOS");
        assert!(r.is_some());
        assert_eq!(r.unwrap().kind, RegionKind::BootRom);
    }

    #[test]
    fn test_display_table_nonempty() {
        let map = gameboy_map();
        let t = map.display_table();
        assert!(t.contains("Game Boy"));
        assert!(t.contains("WRAM"));
    }
}
