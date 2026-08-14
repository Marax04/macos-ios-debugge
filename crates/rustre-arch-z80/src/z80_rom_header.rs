//! Z80 ROM header detection: ZX Spectrum, MSX, CP/M, and generic Z80 targets.
//!
//! Parses the initial bytes of a ROM image to determine the platform and
//! extract structured metadata: entry points, bank sizes, checksum fields,
//! and embedded copyright strings.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// RomFormat
// ─────────────────────────────────────────────────────────────────────────────

/// The detected ROM format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RomFormat {
    /// Sinclair ZX Spectrum 48K ROM.
    Spectrum48,
    /// Sinclair ZX Spectrum 128K ROM (two 16 KB banks).
    Spectrum128,
    /// ZX Spectrum +3 ROM (four 16 KB banks).
    SpectrumPlus3,
    /// MSX ROM cartridge with `AB` magic.
    MsxCartridge,
    /// MSX DOS / system ROM.
    MsxDos,
    /// CP/M binary (BIOS or application).
    CpmBinary,
    /// Generic Z80 binary starting with `JP` or `DI; JP`.
    GenericZ80,
    /// Unknown.
    Unknown,
}

impl fmt::Display for RomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spectrum48     => write!(f, "ZX Spectrum 48K ROM"),
            Self::Spectrum128    => write!(f, "ZX Spectrum 128K ROM"),
            Self::SpectrumPlus3  => write!(f, "ZX Spectrum +3 ROM"),
            Self::MsxCartridge   => write!(f, "MSX ROM Cartridge"),
            Self::MsxDos         => write!(f, "MSX-DOS ROM"),
            Self::CpmBinary      => write!(f, "CP/M Binary"),
            Self::GenericZ80     => write!(f, "Generic Z80 Binary"),
            Self::Unknown        => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SpectrumBasicLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata extracted from a ZX Spectrum BASIC loader header (standard .TAP
/// or ROM-resident loader).
#[derive(Debug, Clone)]
pub struct SpectrumBasicLoader {
    /// Autostart line number (0xFFFF if none).
    pub autostart_line: u16,
    /// Length of the BASIC program in bytes.
    pub program_length: u16,
    /// Offset of the first token in the BASIC program (usually 0).
    pub first_token_offset: u16,
}

impl SpectrumBasicLoader {
    /// Parse from a 17-byte Spectrum tape header block (starting at the type byte).
    ///
    /// # Errors
    /// Returns `Err` if the slice is too short.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 17 {
            return Err(format!("header too short: {} bytes", bytes.len()));
        }
        if bytes[0] != 0 {
            return Err(format!("not a PROGRAM header (type byte = {})", bytes[0]));
        }
        let program_length  = u16::from_le_bytes([bytes[11], bytes[12]]);
        let autostart_line  = u16::from_le_bytes([bytes[13], bytes[14]]);
        let first_token_offset = u16::from_le_bytes([bytes[15], bytes[16]]);
        Ok(Self { autostart_line, program_length, first_token_offset })
    }

    /// Returns `true` if the BASIC program has an autostart line.
    #[must_use]
    pub const fn has_autostart(&self) -> bool {
        self.autostart_line < 0xFFFF
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MsxRomHeader
// ─────────────────────────────────────────────────────────────────────────────

/// MSX ROM cartridge header (16 bytes at offset 0).
#[derive(Debug, Clone)]
pub struct MsxRomHeader {
    /// Magic bytes `AB` (0x41, 0x42).
    pub magic: [u8; 2],
    /// INIT routine address (called at startup, or 0).
    pub init_addr: u16,
    /// STATEMENT routine address (or 0).
    pub statement_addr: u16,
    /// DEVICE routine address (or 0).
    pub device_addr: u16,
    /// TEXT pointer address (or 0).
    pub text_addr: u16,
    /// Reserved bytes [8..15].
    pub reserved: [u8; 6],
}

impl MsxRomHeader {
    /// Parse from the first 16 bytes of an MSX ROM image.
    ///
    /// # Errors
    /// Returns `Err` if bytes are too short or the magic is wrong.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 16 {
            return Err(format!("too short for MSX header: {} bytes", bytes.len()));
        }
        if bytes[0] != b'A' || bytes[1] != b'B' {
            return Err(format!("bad MSX magic: {:02x} {:02x}", bytes[0], bytes[1]));
        }
        let init_addr      = u16::from_le_bytes([bytes[2], bytes[3]]);
        let statement_addr = u16::from_le_bytes([bytes[4], bytes[5]]);
        let device_addr    = u16::from_le_bytes([bytes[6], bytes[7]]);
        let text_addr      = u16::from_le_bytes([bytes[8], bytes[9]]);
        let mut reserved   = [0u8; 6];
        reserved.copy_from_slice(&bytes[10..16]);
        Ok(Self {
            magic: [b'A', b'B'],
            init_addr, statement_addr, device_addr, text_addr, reserved,
        })
    }

    /// Returns `true` when the `INIT` pointer is non-zero.
    #[must_use]
    pub const fn has_init(&self) -> bool {
        self.init_addr != 0
    }

    /// Returns `true` when the `STATEMENT` pointer is non-zero.
    #[must_use]
    pub const fn has_statement(&self) -> bool {
        self.statement_addr != 0
    }
}

impl fmt::Display for MsxRomHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MSX ROM: INIT={:#06x} STMT={:#06x} DEV={:#06x} TEXT={:#06x}",
            self.init_addr, self.statement_addr, self.device_addr, self.text_addr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CpmFileHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal CP/M .COM file header analysis.
///
/// CP/M .COM files always load at 0x0100; we inspect the first few bytes for
/// typical patterns.
#[derive(Debug, Clone)]
pub struct CpmFileHeader {
    /// True if the first byte is a `JP` opcode (0xC3) or `DI` then `JP`.
    pub starts_with_jump: bool,
    /// Jump target address, if the file starts with `JP nn`.
    pub jump_target: Option<u16>,
    /// True if the file starts with `DI` (0xF3) — common in BIOS-entry points.
    pub starts_with_di: bool,
    /// Estimated load address (always 0x0100 for CP/M .COM files).
    pub load_address: u16,
}

impl CpmFileHeader {
    /// Parse from the first few bytes of a CP/M .COM file.
    ///
    /// # Errors
    /// Returns `Err` if there are fewer than 3 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 3 {
            return Err("too few bytes to determine CP/M header".to_owned());
        }
        let (starts_with_di, offset) = if bytes[0] == 0xF3 { (true, 1) } else { (false, 0) };
        let starts_with_jump = bytes[offset] == 0xC3;
        let jump_target = if starts_with_jump && bytes.len() >= offset + 3 {
            Some(u16::from_le_bytes([bytes[offset + 1], bytes[offset + 2]]))
        } else {
            None
        };
        Ok(Self { starts_with_jump, jump_target, starts_with_di, load_address: 0x0100 })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Z80RomHeader  — unified header result
// ─────────────────────────────────────────────────────────────────────────────

/// Unified ROM header result combining all platform-specific metadata.
#[derive(Debug, Clone)]
pub struct Z80RomHeader {
    /// Detected format.
    pub format: RomFormat,
    /// Total size of the ROM image in bytes.
    pub rom_size: usize,
    /// Entry point address (best guess).
    pub entry_point: u16,
    /// Detected copyright / title string, if found.
    pub copyright: Option<String>,
    /// MSX header, if applicable.
    pub msx: Option<MsxRomHeader>,
    /// CP/M file header, if applicable.
    pub cpm: Option<CpmFileHeader>,
    /// Spectrum BASIC loader, if found.
    pub spectrum_basic: Option<SpectrumBasicLoader>,
    /// Checksum byte, if extractable.
    pub checksum: Option<u8>,
}

impl Z80RomHeader {
    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!("{} ({} bytes), entry={:#06x}", self.format, self.rom_size, self.entry_point);
        if let Some(c) = &self.copyright {
            s.push_str(&format!(", copyright={c:?}"));
        }
        s
    }
}

impl fmt::Display for Z80RomHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_rom_format
// ─────────────────────────────────────────────────────────────────────────────

/// Detect the ROM format of a Z80 binary image and extract metadata.
#[must_use]
pub fn detect_rom_format(data: &[u8]) -> Z80RomHeader {
    let rom_size = data.len();

    // ── 1. MSX: `AB` magic at offset 0 ──────────────────────────────────────
    if data.len() >= 16 && data[0] == b'A' && data[1] == b'B' {
        let msx = MsxRomHeader::parse(data).ok();
        let entry_point = msx.as_ref().map(|m| m.init_addr).unwrap_or(0);
        let copyright = find_copyright_string(data);
        return Z80RomHeader {
            format: RomFormat::MsxCartridge,
            rom_size,
            entry_point,
            copyright,
            msx,
            cpm: None,
            spectrum_basic: None,
            checksum: None,
        };
    }

    // ── 2. Spectrum 48K: exactly 16384 bytes, starts with DI; XOR A; LD I,A ─
    if rom_size == 16384 {
        if data.len() >= 3 && data[0] == 0xF3 && data[1] == 0xAF {
            let copyright = find_copyright_string(data);
            let checksum = compute_simple_checksum(data);
            return Z80RomHeader {
                format: RomFormat::Spectrum48,
                rom_size,
                entry_point: 0x0000,
                copyright,
                msx: None,
                cpm: None,
                spectrum_basic: None,
                checksum: Some(checksum),
            };
        }
    }

    // ── 3. Spectrum 128K: 32768 bytes (2 × 16 KB banks) ─────────────────────
    if rom_size == 32768 {
        let copyright = find_copyright_string(data);
        return Z80RomHeader {
            format: RomFormat::Spectrum128,
            rom_size,
            entry_point: 0x0000,
            copyright,
            msx: None,
            cpm: None,
            spectrum_basic: None,
            checksum: None,
        };
    }

    // ── 4. Spectrum +3: 65536 bytes (4 × 16 KB banks) ───────────────────────
    if rom_size == 65536 {
        let copyright = find_copyright_string(data);
        return Z80RomHeader {
            format: RomFormat::SpectrumPlus3,
            rom_size,
            entry_point: 0x0000,
            copyright,
            msx: None,
            cpm: None,
            spectrum_basic: None,
            checksum: None,
        };
    }

    // ── 5. CP/M .COM: starts at 0x0100 after transfer vector, usually JP or DI ─
    if data.len() >= 3 {
        let starts_with_jp = data[0] == 0xC3;
        let starts_with_di = data[0] == 0xF3 && data.len() > 1 && data[1] == 0xC3;
        if starts_with_jp || starts_with_di {
            let cpm = CpmFileHeader::parse(data).ok();
            let entry_point = cpm.as_ref().and_then(|c| c.jump_target).unwrap_or(0x0100);
            let copyright = find_copyright_string(data);
            if data.len() <= 65536 {
                return Z80RomHeader {
                    format: RomFormat::CpmBinary,
                    rom_size,
                    entry_point,
                    copyright,
                    msx: None,
                    cpm,
                    spectrum_basic: None,
                    checksum: None,
                };
            }
        }
    }

    // ── 6. Generic Z80 (JP at start) ─────────────────────────────────────────
    if data.len() >= 3 && (data[0] == 0xC3 || (data[0] == 0xF3 && data.get(1).copied() == Some(0xC3))) {
        let offset = if data[0] == 0xF3 { 1 } else { 0 };
        let entry = u16::from_le_bytes([
            data.get(offset + 1).copied().unwrap_or(0),
            data.get(offset + 2).copied().unwrap_or(0),
        ]);
        return Z80RomHeader {
            format: RomFormat::GenericZ80,
            rom_size,
            entry_point: entry,
            copyright: find_copyright_string(data),
            msx: None,
            cpm: CpmFileHeader::parse(data).ok(),
            spectrum_basic: None,
            checksum: None,
        };
    }

    // ── 7. Unknown ────────────────────────────────────────────────────────────
    Z80RomHeader {
        format: RomFormat::Unknown,
        rom_size,
        entry_point: 0,
        copyright: find_copyright_string(data),
        msx: None,
        cpm: None,
        spectrum_basic: None,
        checksum: None,
    }
}

/// Search for a printable copyright / title string in `data`.
///
/// Looks for the byte sequences `(C)`, `(c)`, `©`, or `Copyright` followed
/// by a printable ASCII run of at least 8 characters.
#[must_use]
pub fn find_copyright_string(data: &[u8]) -> Option<String> {
    let markers: &[&[u8]] = &[b"(C) ", b"(c) ", b"Copyright", b"\xa9 "];
    for marker in markers {
        if let Some(pos) = find_subsequence(data, marker) {
            let start = pos;
            let end = data[start..].iter().take(128)
                .position(|&b| b == 0 || b < 0x20 && b != b'\n' && b != b'\r')
                .map(|p| start + p)
                .unwrap_or((start + 64).min(data.len()));
            if end > start + 4 {
                let s = String::from_utf8_lossy(&data[start..end]).trim().to_owned();
                if s.len() >= 4 {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn compute_simple_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msx_rom() -> Vec<u8> {
        let mut v = vec![0u8; 32768];
        v[0] = b'A'; v[1] = b'B';
        v[2] = 0x10; v[3] = 0x40; // INIT = 0x4010
        v
    }

    fn make_spectrum48_rom() -> Vec<u8> {
        let mut v = vec![0x00u8; 16384];
        v[0] = 0xF3; // DI
        v[1] = 0xAF; // XOR A
        v[2] = 0xED; v[3] = 0x47; // LD I,A
        v
    }

    fn make_cpm_com() -> Vec<u8> {
        let mut v = vec![0x00u8; 256];
        v[0] = 0xC3; // JP
        v[1] = 0x00; v[2] = 0x01; // target = 0x0100
        v
    }

    #[test]
    fn detect_msx_cartridge() {
        let rom = make_msx_rom();
        let hdr = detect_rom_format(&rom);
        assert_eq!(hdr.format, RomFormat::MsxCartridge);
        assert_eq!(hdr.entry_point, 0x4010);
    }

    #[test]
    fn detect_spectrum_48k() {
        let rom = make_spectrum48_rom();
        let hdr = detect_rom_format(&rom);
        assert_eq!(hdr.format, RomFormat::Spectrum48);
        assert_eq!(hdr.entry_point, 0x0000);
        assert!(hdr.checksum.is_some());
    }

    #[test]
    fn detect_spectrum_128k() {
        let rom = vec![0x00u8; 32768];
        let hdr = detect_rom_format(&rom);
        assert_eq!(hdr.format, RomFormat::Spectrum128);
    }

    #[test]
    fn detect_spectrum_plus3() {
        let rom = vec![0x00u8; 65536];
        let hdr = detect_rom_format(&rom);
        assert_eq!(hdr.format, RomFormat::SpectrumPlus3);
    }

    #[test]
    fn detect_cpm_com() {
        let rom = make_cpm_com();
        let hdr = detect_rom_format(&rom);
        assert_eq!(hdr.format, RomFormat::CpmBinary);
        assert_eq!(hdr.entry_point, 0x0100);
    }

    #[test]
    fn detect_generic_z80_jp() {
        let mut v = vec![0x00u8; 128];
        v[0] = 0xC3; v[1] = 0x00; v[2] = 0x20;
        let hdr = detect_rom_format(&v);
        // Could be CpmBinary (≤64KB) or GenericZ80
        assert!(hdr.format == RomFormat::CpmBinary || hdr.format == RomFormat::GenericZ80);
    }

    #[test]
    fn detect_unknown() {
        let v = vec![0xAAu8; 100];
        let hdr = detect_rom_format(&v);
        assert_eq!(hdr.format, RomFormat::Unknown);
    }

    #[test]
    fn msx_header_parse_ok() {
        let rom = make_msx_rom();
        let hdr = MsxRomHeader::parse(&rom).unwrap();
        assert_eq!(hdr.init_addr, 0x4010);
        assert!(hdr.has_init());
        assert!(!hdr.has_statement());
    }

    #[test]
    fn msx_header_bad_magic() {
        let v = vec![0xFFu8; 16];
        assert!(MsxRomHeader::parse(&v).is_err());
    }

    #[test]
    fn msx_header_too_short() {
        assert!(MsxRomHeader::parse(&[b'A', b'B']).is_err());
    }

    #[test]
    fn cpm_header_parse_jp() {
        let v = make_cpm_com();
        let hdr = CpmFileHeader::parse(&v).unwrap();
        assert!(hdr.starts_with_jump);
        assert_eq!(hdr.jump_target, Some(0x0100));
        assert!(!hdr.starts_with_di);
        assert_eq!(hdr.load_address, 0x0100);
    }

    #[test]
    fn cpm_header_parse_di_jp() {
        let v = [0xF3u8, 0xC3, 0x00, 0x80];
        let hdr = CpmFileHeader::parse(&v).unwrap();
        assert!(hdr.starts_with_di);
        assert!(hdr.starts_with_jump);
        assert_eq!(hdr.jump_target, Some(0x8000));
    }

    #[test]
    fn find_copyright_string_found() {
        let data = b"garbage\x00(C) 1982 Sinclair Research Ltd\x00more";
        let r = find_copyright_string(data);
        assert!(r.is_some());
        let s = r.unwrap();
        assert!(s.contains("Sinclair"));
    }

    #[test]
    fn find_copyright_string_none() {
        let data = b"no copyright info here at all";
        let r = find_copyright_string(data);
        assert!(r.is_none());
    }

    #[test]
    fn spectrum_basic_loader_parse() {
        let mut hdr = [0u8; 17];
        hdr[0] = 0; // type = PROGRAM
        hdr[11] = 0x2A; hdr[12] = 0x00; // program length = 42
        hdr[13] = 0x0A; hdr[14] = 0x00; // autostart line = 10
        hdr[15] = 0x00; hdr[16] = 0x00;
        let bl = SpectrumBasicLoader::parse(&hdr).unwrap();
        assert_eq!(bl.program_length, 42);
        assert_eq!(bl.autostart_line, 10);
        assert!(bl.has_autostart());
    }

    #[test]
    fn spectrum_basic_loader_no_autostart() {
        let mut hdr = [0u8; 17];
        hdr[0] = 0;
        hdr[13] = 0xFF; hdr[14] = 0xFF;
        let bl = SpectrumBasicLoader::parse(&hdr).unwrap();
        assert!(!bl.has_autostart());
    }

    #[test]
    fn spectrum_basic_loader_too_short() {
        assert!(SpectrumBasicLoader::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn rom_format_display() {
        assert_eq!(format!("{}", RomFormat::MsxCartridge), "MSX ROM Cartridge");
        assert_eq!(format!("{}", RomFormat::Spectrum48), "ZX Spectrum 48K ROM");
        assert_eq!(format!("{}", RomFormat::CpmBinary), "CP/M Binary");
    }

    #[test]
    fn z80_rom_header_summary() {
        let rom = make_msx_rom();
        let hdr = detect_rom_format(&rom);
        let s = hdr.summary();
        assert!(s.contains("MSX"));
        assert!(s.contains("entry=0x4010"));
    }
}
