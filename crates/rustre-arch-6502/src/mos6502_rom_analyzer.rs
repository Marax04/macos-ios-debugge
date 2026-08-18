//! MOS 6502 ROM format analyzer.
//!
//! Detects iNES/NES ROMs, C64 PRG binaries, Atari 2600 cartridges, Apple II
//! disk images, and generic blobs.  Parses headers, extracts interrupt vectors,
//! and traces subroutine call-graphs from the reset vector.

use crate::mos6502_disassembler::Mos6502Disassembler;

// ── ROM type detection ────────────────────────────────────────────────────────

/// Detected ROM format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RomType {
    /// iNES / NES cartridge with `NES\x1A` magic.
    Nes,
    /// SNES (Super Famicom) ROM image.
    Snes,
    /// Commodore 64 `.PRG` binary (2-byte load address header).
    C64,
    /// Apple II DOS 3.3 / `ProDOS` binary.
    Apple2,
    /// Atari 2600 cartridge (2 KB or 4 KB with no header).
    Atari2600,
    /// Unrecognized format; treated as a flat 6502 binary.
    Generic,
}

impl std::fmt::Display for RomType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RomType::Nes       => "NES (iNES)",
            RomType::Snes      => "SNES",
            RomType::C64       => "Commodore 64 PRG",
            RomType::Apple2    => "Apple II binary",
            RomType::Atari2600 => "Atari 2600 cartridge",
            RomType::Generic   => "Generic 6502 binary",
        };
        write!(f, "{s}")
    }
}

/// Identify the format of a ROM image.
#[must_use]
pub fn identify_rom_type(data: &[u8]) -> RomType {
    if data.len() >= 4 && &data[0..4] == b"NES\x1A" {
        return RomType::Nes;
    }
    if data.len() >= 4 && &data[0..2] == b"SN" {
        // Very basic SNES detection: LoROM/HiROM header checksum complement
        // at fixed offsets
        if data.len() >= 0x8000 {
            let chk = u16::from_le_bytes([data[0x7FDE], data[0x7FDF]]);
            let cpl = u16::from_le_bytes([data[0x7FDC], data[0x7FDD]]);
            if chk ^ cpl == 0xFFFF {
                return RomType::Snes;
            }
        }
    }
    // Apple II binary: starts with $60 (RTS) at $C000 or has $08 in first two bytes
    if data.len() >= 2 {
        let load = u16::from_le_bytes([data[0], data[1]]);
        // C64 load addresses — 0x2000 must NOT appear here because it is also
        // a valid Apple II ProDOS address (parser-ambiguity: the same input
        // would always be misclassified as C64 when it could be Apple II).
        if load == 0x0801 || load == 0x0400 {
            // Plausible C64 load addresses
            return RomType::C64;
        }
        if load == 0x0803 || load == 0x2000 || load == 0x6000 {
            // Plausible Apple II ProDOS addresses
            return RomType::Apple2;
        }
    }
    // Atari 2600: 2 KB or 4 KB cartridge with vectors near end
    if data.len() == 2048 || data.len() == 4096 {
        return RomType::Atari2600;
    }
    RomType::Generic
}

// ── iNES header ───────────────────────────────────────────────────────────────

/// Parsed iNES 1.0 ROM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NesHeader {
    /// Number of 16 KB PRG-ROM banks.
    pub prg_rom_size: u8,
    /// Number of 8 KB CHR-ROM banks (0 = uses CHR-RAM).
    pub chr_rom_size: u8,
    /// Flags byte 6: mirroring, battery, trainer, four-screen, mapper lo.
    pub flags6: u8,
    /// Flags byte 7: VS/PlayChoice, NES 2.0 flag, mapper hi.
    pub flags7: u8,
    /// Mapper number (flags6 hi nibble | flags7 hi nibble << 4).
    pub mapper: u8,
    /// True if a 512-byte trainer is present.
    pub has_trainer: bool,
    /// True if battery-backed PRG-RAM is present.
    pub has_battery: bool,
    /// Nametable mirroring: false = horizontal, true = vertical.
    pub vertical_mirror: bool,
}

/// Parse an iNES 1.0 header from the first 16 bytes of a ROM image.
#[must_use]
pub fn parse_ines_header(data: &[u8]) -> Option<NesHeader> {
    if data.len() < 16 {
        return None;
    }
    if &data[0..4] != b"NES\x1A" {
        return None;
    }
    let flags6 = data[6];
    let flags7 = data[7];
    Some(NesHeader {
        prg_rom_size: data[4],
        chr_rom_size: data[5],
        flags6,
        flags7,
        mapper: (flags6 >> 4) | (flags7 & 0xF0),
        has_trainer: (flags6 & 0x04) != 0,
        has_battery: (flags6 & 0x02) != 0,
        vertical_mirror: (flags6 & 0x01) != 0,
    })
}

/// Compute byte offset of the PRG-ROM within an iNES image.
#[must_use]
pub const fn nes_prg_offset(header: &NesHeader) -> usize {
    16 + if header.has_trainer { 512 } else { 0 }
}

// ── C64 PRG format ────────────────────────────────────────────────────────────

/// Minimal C64 PRG header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C64BinHeader {
    /// The load address encoded in the first two bytes of the file.
    pub load_addr: u16,
}

/// Parse a C64 `.PRG` file: return `(load_addr, code_bytes)`.
#[must_use]
pub fn parse_c64_prg(data: &[u8]) -> (u16, Vec<u8>) {
    if data.len() < 2 {
        return (0x0801, data.to_vec());
    }
    let load = u16::from_le_bytes([data[0], data[1]]);
    (load, data[2..].to_vec())
}

// ── Interrupt vectors ─────────────────────────────────────────────────────────

/// The three 6502 hardware interrupt vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptVectors {
    /// Non-Maskable Interrupt vector ($FFFA/$FFFB).
    pub nmi: u16,
    /// RESET vector ($FFFC/$FFFD).
    pub reset: u16,
    /// IRQ/BRK vector ($FFFE/$FFFF).
    pub irq: u16,
}

/// Read interrupt vectors from `data`, treating the last 6 bytes as $FFFA–$FFFF.
///
/// `base` is the address of `data[0]`; vectors are read relative to $FFFA.
#[must_use]
pub fn read_vectors(data: &[u8], base: u16) -> InterruptVectors {
    let read16 = |addr: u16| -> u16 {
        let offset = addr.wrapping_sub(base) as usize;
        if offset + 1 < data.len() {
            u16::from_le_bytes([data[offset], data[offset + 1]])
        } else {
            0
        }
    };
    InterruptVectors {
        nmi:   read16(0xFFFA),
        reset: read16(0xFFFC),
        irq:   read16(0xFFFE),
    }
}

// ── Memory bank ───────────────────────────────────────────────────────────────

/// A named, contiguous memory bank within a ROM image.
#[derive(Debug, Clone)]
pub struct MemoryBank {
    /// Human-readable bank name (e.g., `"PRG-ROM 0"`, `"WRAM"`).
    pub name: String,
    /// Address range [start, end] (inclusive) as seen by the CPU.
    pub addr_range: (u16, u16),
    /// Byte offset into the ROM image where this bank begins.
    pub data_offset: usize,
    /// True if the bank is read-only (ROM).
    pub read_only: bool,
}

impl MemoryBank {
    /// Size in bytes of the bank's address range.
    #[must_use]
    pub const fn size(&self) -> usize {
        // Guard against inverted ranges (addr_range.0 > addr_range.1) which
        // would cause u16 underflow and a wildly wrong result.
        if self.addr_range.1 < self.addr_range.0 {
            return 0;
        }
        (self.addr_range.1 - self.addr_range.0) as usize + 1
    }

    /// True if `addr` falls within this bank's address range.
    #[must_use]
    pub const fn contains(&self, addr: u16) -> bool {
        addr >= self.addr_range.0 && addr <= self.addr_range.1
    }
}

// ── ROM analyzer ─────────────────────────────────────────────────────────────

/// High-level ROM analysis result.
pub struct RomAnalyzer {
    /// Detected format.
    pub rom_type: RomType,
    /// NES header (populated only for `RomType::Nes`).
    pub nes_header: Option<NesHeader>,
    /// C64 load address (populated only for `RomType::C64`).
    pub c64_load_addr: Option<u16>,
    /// Memory banks parsed from the image.
    pub banks: Vec<MemoryBank>,
    /// Interrupt vectors (if the ROM maps to $FFFA–$FFFF).
    pub vectors: Option<InterruptVectors>,
    /// Subroutine entry points discovered by tracing from the reset vector.
    pub subroutines: Vec<u16>,
    raw: Vec<u8>,
}

impl RomAnalyzer {
    /// Analyse a ROM image and populate all fields.
    #[must_use]
    pub fn analyze(data: &[u8]) -> Self {
        let rom_type = identify_rom_type(data);
        let mut analyzer = RomAnalyzer {
            rom_type: rom_type.clone(),
            nes_header: None,
            c64_load_addr: None,
            banks: Vec::new(),
            vectors: None,
            subroutines: Vec::new(),
            raw: data.to_vec(),
        };

        match rom_type {
            RomType::Nes => analyzer.analyze_nes(data),
            RomType::C64 => analyzer.analyze_c64(data),
            RomType::Atari2600 => analyzer.analyze_atari2600(data),
            RomType::Apple2 => analyzer.analyze_apple2(data),
            _ => analyzer.analyze_generic(data),
        }
        analyzer
    }

    fn analyze_nes(&mut self, data: &[u8]) {
        if let Some(hdr) = parse_ines_header(data) {
            let prg_off = nes_prg_offset(&hdr);
            // prg_rom_size is u8 (0–255); 255 * 16384 = 4_177_920 which is
            // safely within usize on all 32/64-bit targets. No overflow.
            let prg_size = (hdr.prg_rom_size as usize).saturating_mul(16384);
            // Last PRG bank always maps to $C000.
            let last_bank_off = prg_off + prg_size.saturating_sub(16384);
            self.banks.push(MemoryBank {
                name: "PRG-ROM (last bank)".to_string(),
                addr_range: (0xC000, 0xFFFF),
                data_offset: last_bank_off,
                read_only: true,
            });
            if prg_size >= 32768 {
                self.banks.push(MemoryBank {
                    name: "PRG-ROM (first bank)".to_string(),
                    addr_range: (0x8000, 0xBFFF),
                    data_offset: prg_off,
                    read_only: true,
                });
            }
            // Read vectors from end of last PRG bank.
            if data.len() >= last_bank_off + 6 {
                let vec_slice = &data[last_bank_off..];
                // (last_bank_off - prg_off) is prg_size - 16384; this can exceed
                // u16::MAX for large ROMs (prg_rom_size >= 6), so clamp to u16.
                let bank_rel = (last_bank_off.saturating_sub(prg_off)) as u64;
                let vec_base = (0x8000u64 + bank_rel) as u16;
                self.vectors = Some(read_vectors(vec_slice, vec_base));
                // Simpler: read directly from last 6 bytes of PRG data.
                let prg_end = prg_off + prg_size;
                if prg_end <= data.len() && prg_end >= 6 {
                    let last6 = &data[prg_end - 6..prg_end];
                    self.vectors = Some(InterruptVectors {
                        nmi:   u16::from_le_bytes([last6[0], last6[1]]),
                        reset: u16::from_le_bytes([last6[2], last6[3]]),
                        irq:   u16::from_le_bytes([last6[4], last6[5]]),
                    });
                }
            }
            self.nes_header = Some(hdr);
            self.find_subroutines_nes(data);
        }
    }

    fn analyze_c64(&mut self, data: &[u8]) {
        let (load_addr, code) = parse_c64_prg(data);
        self.c64_load_addr = Some(load_addr);
        self.banks.push(MemoryBank {
            name: format!("C64 PRG at ${load_addr:04X}"),
            addr_range: (load_addr, load_addr.saturating_add(code.len().saturating_sub(1) as u16)),
            data_offset: 2,
            read_only: false,
        });
        let dis = Mos6502Disassembler::new();
        let insns = dis.decode(&code, load_addr);
        self.subroutines.push(load_addr);
        let mut jsrs = dis.find_jsr_targets(&insns);
        jsrs.sort_unstable();
        jsrs.dedup();
        self.subroutines.extend_from_slice(&jsrs);
    }

    fn analyze_atari2600(&mut self, data: &[u8]) {
        let base: u16 = if data.len() == 2048 { 0xF800 } else { 0xF000 };
        self.banks.push(MemoryBank {
            name: format!("Atari 2600 ROM at ${base:04X}"),
            addr_range: (base, 0xFFFF),
            data_offset: 0,
            read_only: true,
        });
        if data.len() >= 6 {
            let last6 = &data[data.len() - 6..];
            self.vectors = Some(InterruptVectors {
                nmi:   u16::from_le_bytes([last6[0], last6[1]]),
                reset: u16::from_le_bytes([last6[2], last6[3]]),
                irq:   u16::from_le_bytes([last6[4], last6[5]]),
            });
        }
        self.find_subroutines_generic(data, base);
    }

    fn analyze_apple2(&mut self, data: &[u8]) {
        let (load_addr, code) = parse_c64_prg(data); // same 2-byte header
        self.banks.push(MemoryBank {
            name: format!("Apple II binary at ${load_addr:04X}"),
            addr_range: (load_addr, load_addr.saturating_add(code.len().saturating_sub(1) as u16)),
            data_offset: 2,
            read_only: false,
        });
        let dis = Mos6502Disassembler::new();
        let insns = dis.decode(&code, load_addr);
        self.subroutines.push(load_addr);
        let mut jsrs = dis.find_jsr_targets(&insns);
        jsrs.sort_unstable();
        jsrs.dedup();
        self.subroutines.extend_from_slice(&jsrs);
    }

    fn analyze_generic(&mut self, data: &[u8]) {
        // Assume flat binary starting at $8000 or $C000.
        let base: u16 = if data.len() <= 0x4000 { 0xC000 } else { 0x8000 };
        self.banks.push(MemoryBank {
            name: "Generic ROM".to_string(),
            addr_range: (base, base.saturating_add(data.len().saturating_sub(1) as u16)),
            data_offset: 0,
            read_only: true,
        });
        if data.len() >= 6 {
            let last6 = &data[data.len() - 6..];
            self.vectors = Some(InterruptVectors {
                nmi:   u16::from_le_bytes([last6[0], last6[1]]),
                reset: u16::from_le_bytes([last6[2], last6[3]]),
                irq:   u16::from_le_bytes([last6[4], last6[5]]),
            });
        }
        self.find_subroutines_generic(data, base);
    }

    fn find_subroutines_nes(&mut self, data: &[u8]) {
        if let Some(hdr) = &self.nes_header {
            let prg_off = nes_prg_offset(hdr);
            let prg_size = hdr.prg_rom_size as usize * 16384;
            if prg_off + prg_size <= data.len() {
                let code = &data[prg_off..prg_off + prg_size];
                let base: u16 = if prg_size >= 32768 { 0x8000 } else { 0xC000 };
                self.find_subroutines_generic(code, base);
            }
        }
    }

    fn find_subroutines_generic(&mut self, code: &[u8], base: u16) {
        let dis = Mos6502Disassembler::new();
        let insns = dis.decode(code, base);
        // Start from reset vector if available.
        if let Some(ref vecs) = self.vectors {
            let reset = vecs.reset;
            if reset >= base {
                let offset = (reset - base) as usize;
                if offset < code.len() {
                    self.subroutines.push(reset);
                }
            }
        } else if !insns.is_empty() {
            self.subroutines.push(insns[0].addr);
        }
        let mut jsrs = dis.find_jsr_targets(&insns);
        jsrs.sort_unstable();
        jsrs.dedup();
        self.subroutines.extend_from_slice(&jsrs);
        self.subroutines.sort_unstable();
        self.subroutines.dedup();
    }

    /// Return the code bytes for a given bank.
    #[must_use]
    pub fn bank_data(&self, bank: &MemoryBank) -> &[u8] {
        let end = (bank.data_offset + bank.size()).min(self.raw.len());
        if bank.data_offset >= self.raw.len() {
            return &[];
        }
        &self.raw[bank.data_offset..end]
    }

    /// Disassemble a named bank using the base address from its `addr_range`.
    #[must_use]
    pub fn disassemble_bank(&self, bank: &MemoryBank)
        -> Vec<crate::mos6502_disassembler::Mos6502Insn>
    {
        let data = self.bank_data(bank);
        let dis = Mos6502Disassembler::new();
        dis.decode(data, bank.addr_range.0)
    }

    /// Compute a simple code/data size estimate for the ROM.
    #[must_use]
    pub fn code_size_estimate(&self) -> usize {
        self.banks.iter().filter(|b| b.read_only).map(MemoryBank::size).sum()
    }

    /// Return a human-readable summary of the analyzed ROM.
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128);
        let _ = writeln!(s, "ROM type: {}", self.rom_type);
        if let Some(ref h) = self.nes_header {
            let _ = writeln!(
                s,
                "  PRG banks: {}  CHR banks: {}  Mapper: {}",
                h.prg_rom_size, h.chr_rom_size, h.mapper
            );
        }
        if let Some(addr) = self.c64_load_addr {
            let _ = writeln!(s, "  C64 load address: ${addr:04X}");
        }
        if let Some(ref v) = self.vectors {
            let _ = writeln!(
                s,
                "  NMI: ${:04X}  RESET: ${:04X}  IRQ: ${:04X}",
                v.nmi, v.reset, v.irq
            );
        }
        let _ = writeln!(s, "  Banks: {}", self.banks.len());
        let _ = writeln!(s, "  Subroutines found: {}", self.subroutines.len());
        s
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ines_rom() -> Vec<u8> {
        let mut rom = vec![0u8; 16 + 16384];
        rom[0..4].copy_from_slice(b"NES\x1A");
        rom[4] = 1;  // 1 PRG-ROM bank (16 KB)
        rom[5] = 0;  // no CHR-ROM
        rom[6] = 0;
        rom[7] = 0;
        // Write vectors at end of PRG data
        let prg_end = 16 + 16384;
        rom[prg_end - 6] = 0x00; rom[prg_end - 5] = 0xC0; // NMI
        rom[prg_end - 4] = 0x00; rom[prg_end - 3] = 0xC0; // RESET
        rom[prg_end - 2] = 0x00; rom[prg_end - 1] = 0xFF; // IRQ
        // Write a JSR at reset vector
        let reset_off = 16; // first byte of PRG
        rom[reset_off] = 0x20; // JSR
        rom[reset_off + 1] = 0x10;
        rom[reset_off + 2] = 0xC0; // target $C010
        rom
    }

    #[test]
    fn parse_ines_header_valid() {
        let rom = minimal_ines_rom();
        let hdr = parse_ines_header(&rom).unwrap();
        assert_eq!(hdr.prg_rom_size, 1);
        assert_eq!(hdr.chr_rom_size, 0);
        assert_eq!(hdr.mapper, 0);
    }

    #[test]
    fn parse_ines_header_invalid_magic() {
        let data = b"NOTNES\x1A";
        assert!(parse_ines_header(data).is_none());
    }

    #[test]
    fn identify_nes_rom() {
        let rom = minimal_ines_rom();
        assert_eq!(identify_rom_type(&rom), RomType::Nes);
    }

    #[test]
    fn identify_atari2600_2k() {
        let data = vec![0u8; 2048];
        assert_eq!(identify_rom_type(&data), RomType::Atari2600);
    }

    #[test]
    fn identify_atari2600_4k() {
        let data = vec![0u8; 4096];
        assert_eq!(identify_rom_type(&data), RomType::Atari2600);
    }

    #[test]
    fn identify_c64() {
        let mut data = vec![0u8; 64];
        data[0] = 0x01;
        data[1] = 0x08; // load_addr = $0801
        assert_eq!(identify_rom_type(&data), RomType::C64);
    }

    #[test]
    fn parse_c64_prg_basic() {
        let data = [0x01u8, 0x08, 0xEA, 0xEA]; // load = $0801, 2x NOP
        let (addr, code) = parse_c64_prg(&data);
        assert_eq!(addr, 0x0801);
        assert_eq!(code, vec![0xEA, 0xEA]);
    }

    #[test]
    fn read_vectors_basic() {
        let mut data = vec![0u8; 6];
        data[0] = 0x00; data[1] = 0x80;
        data[2] = 0x00; data[3] = 0xC0;
        data[4] = 0x00; data[5] = 0xFF;
        let v = read_vectors(&data, 0xFFFA);
        assert_eq!(v.nmi, 0x8000);
        assert_eq!(v.reset, 0xC000);
        assert_eq!(v.irq, 0xFF00);
    }

    #[test]
    fn memory_bank_contains() {
        let bank = MemoryBank {
            name: "test".into(),
            addr_range: (0x8000, 0xBFFF),
            data_offset: 0,
            read_only: true,
        };
        assert!(bank.contains(0x8000));
        assert!(bank.contains(0xBFFF));
        assert!(!bank.contains(0xC000));
    }

    #[test]
    fn memory_bank_size() {
        let bank = MemoryBank {
            name: "test".into(),
            addr_range: (0x8000, 0xBFFF),
            data_offset: 0,
            read_only: true,
        };
        assert_eq!(bank.size(), 0x4000);
    }

    #[test]
    fn nes_prg_offset_no_trainer() {
        let hdr = NesHeader {
            prg_rom_size: 1, chr_rom_size: 0,
            flags6: 0, flags7: 0, mapper: 0,
            has_trainer: false, has_battery: false, vertical_mirror: false,
        };
        assert_eq!(nes_prg_offset(&hdr), 16);
    }

    #[test]
    fn nes_prg_offset_with_trainer() {
        let hdr = NesHeader {
            prg_rom_size: 1, chr_rom_size: 0,
            flags6: 0x04, flags7: 0, mapper: 0,
            has_trainer: true, has_battery: false, vertical_mirror: false,
        };
        assert_eq!(nes_prg_offset(&hdr), 528);
    }

    #[test]
    fn analyze_nes_finds_banks() {
        let rom = minimal_ines_rom();
        let result = RomAnalyzer::analyze(&rom);
        assert_eq!(result.rom_type, RomType::Nes);
        assert!(!result.banks.is_empty());
    }

    #[test]
    fn analyze_nes_finds_vectors() {
        let rom = minimal_ines_rom();
        let result = RomAnalyzer::analyze(&rom);
        assert!(result.vectors.is_some());
    }

    #[test]
    fn analyze_nes_finds_subroutines() {
        let rom = minimal_ines_rom();
        let result = RomAnalyzer::analyze(&rom);
        // We put a JSR $C010 in the ROM; $C010 should be in subroutines.
        assert!(result.subroutines.contains(&0xC010));
    }

    #[test]
    fn analyze_atari2600_2k() {
        let mut data = vec![0u8; 2048];
        data[2042] = 0x00; data[2043] = 0xF8; // NMI = $F800
        data[2044] = 0x00; data[2045] = 0xF8; // RESET = $F800
        data[2046] = 0x00; data[2047] = 0xF8; // IRQ = $F800
        let result = RomAnalyzer::analyze(&data);
        assert_eq!(result.rom_type, RomType::Atari2600);
        assert!(result.vectors.is_some());
    }

    #[test]
    fn summary_contains_rom_type() {
        let rom = minimal_ines_rom();
        let result = RomAnalyzer::analyze(&rom);
        let s = result.summary();
        assert!(s.contains("NES"));
    }

    #[test]
    fn nes_header_battery_flag() {
        let mut rom = minimal_ines_rom();
        rom[6] |= 0x02; // set battery bit
        let hdr = parse_ines_header(&rom).unwrap();
        assert!(hdr.has_battery);
    }

    #[test]
    fn nes_header_vertical_mirror() {
        let mut rom = minimal_ines_rom();
        rom[6] |= 0x01; // set vertical mirror bit
        let hdr = parse_ines_header(&rom).unwrap();
        assert!(hdr.vertical_mirror);
    }
}
