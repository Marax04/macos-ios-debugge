//! `hex_exporter` — Export hex buffer data in various formats.
//!
//! Provides [`HexExporter`], [`ExportFormat`], and the free functions
//! [`export_to_c_array`] and [`export_to_intel_hex`].

use std::fmt;
use std::fmt::Write as FmtWrite;

// ─────────────────────────────────────────────────────────────────────────────
// ExportFormat
// ─────────────────────────────────────────────────────────────────────────────

/// Output format for the hex exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// C/C++ `unsigned char` array literal.
    CArray,
    /// Intel HEX (IHEX) record format.
    IntelHex,
    /// Motorola S-Record format.
    SRecord,
    /// Raw binary (passthrough, returned as bytes).
    RawBinary,
    /// `xxd`-style hex dump.
    XxdHexDump,
    /// Python `bytes` literal.
    PythonBytes,
    /// Rust `[u8; N]` array literal.
    RustArray,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CArray => write!(f, "C Array"),
            Self::IntelHex => write!(f, "Intel HEX"),
            Self::SRecord => write!(f, "S-Record"),
            Self::RawBinary => write!(f, "Raw Binary"),
            Self::XxdHexDump => write!(f, "xxd Hex Dump"),
            Self::PythonBytes => write!(f, "Python Bytes"),
            Self::RustArray => write!(f, "Rust Array"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Options that control export formatting.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Base address for address-bearing formats (Intel HEX, S-Record, xxd).
    pub base_address: u64,
    /// Number of bytes per line in text formats.
    pub bytes_per_line: usize,
    /// Variable or symbol name for C/Rust/Python array exports.
    pub symbol_name: String,
    /// Whether to emit uppercase hex digits.
    pub uppercase: bool,
    /// Whether to include a byte-count comment in C/Rust arrays.
    pub include_count_comment: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            base_address: 0,
            bytes_per_line: 16,
            symbol_name: "data".to_owned(),
            uppercase: true,
            include_count_comment: true,
        }
    }
}

impl ExportOptions {
    /// Builder: set the base address.
    #[must_use]
    pub const fn with_base(mut self, addr: u64) -> Self {
        self.base_address = addr;
        self
    }

    /// Builder: set the symbol name.
    #[must_use]
    pub fn with_symbol(mut self, name: impl Into<String>) -> Self {
        self.symbol_name = name.into();
        self
    }

    /// Builder: set bytes per line.
    #[must_use]
    pub fn with_bpl(mut self, bpl: usize) -> Self {
        self.bytes_per_line = bpl.max(1);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// export_to_c_array
// ─────────────────────────────────────────────────────────────────────────────

/// Export `data` as a C `unsigned char` array literal.
///
/// ```text
/// /* 4 bytes */
/// unsigned char data[] = {
///     0xDE, 0xAD, 0xBE, 0xEF
/// };
/// ```
#[must_use]
pub fn export_to_c_array(data: &[u8], opts: &ExportOptions) -> String {
    let mut out = String::with_capacity(data.len() * 6 + 64);
    if opts.include_count_comment {
        let _ = writeln!(out, "/* {} bytes */", data.len());
    }
    let _ = writeln!(out, "unsigned char {}[] = {{", opts.symbol_name);
    let bpl = opts.bytes_per_line.max(1);
    for (i, chunk) in data.chunks(bpl).enumerate() {
        out.push_str("    ");
        for (j, &b) in chunk.iter().enumerate() {
            if opts.uppercase {
                let _ = write!(out, "0x{b:02X}");
            } else {
                let _ = write!(out, "0x{b:02x}");
            }
            let global_idx = i * bpl + j;
            if global_idx + 1 < data.len() {
                out.push_str(", ");
            }
        }
        out.push('\n');
    }
    out.push_str("};\n");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Intel HEX helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Intel HEX checksum byte for a record body (without the `:` and
/// without the checksum byte itself).
fn ihex_checksum(body: &[u8]) -> u8 {
    let sum: u32 = body.iter().map(|&b| u32::from(b)).sum();
    ((0x100 - (sum & 0xFF)) & 0xFF) as u8
}

/// Format a single Intel HEX data record.
fn ihex_data_record(address: u16, data: &[u8], uppercase: bool) -> String {
    // Intel HEX data records cannot exceed 255 bytes; callers must clamp first.
    debug_assert!(data.len() <= 255, "ihex_data_record: chunk too large ({})", data.len());
    let byte_count = data.len().min(255) as u8;
    let addr_hi = (address >> 8) as u8;
    let addr_lo = (address & 0xFF) as u8;
    let record_type = 0x00u8;

    let mut body: Vec<u8> = vec![byte_count, addr_hi, addr_lo, record_type];
    body.extend_from_slice(data);
    let checksum = ihex_checksum(&body);

    let mut s = String::with_capacity(body.len() * 2 + 12);
    s.push(':');
    for b in &body {
        if uppercase {
            let _ = write!(s, "{b:02X}");
        } else {
            let _ = write!(s, "{b:02x}");
        }
    }
    if uppercase {
        let _ = write!(s, "{checksum:02X}");
    } else {
        let _ = write!(s, "{checksum:02x}");
    }
    s.push('\n');
    s
}

/// Format an Intel HEX extended linear address record.
fn ihex_extended_linear_address(upper: u16, uppercase: bool) -> String {
    let body: Vec<u8> = vec![
        0x02, // byte count
        0x00,
        0x00, // address
        0x04, // record type: extended linear address
        (upper >> 8) as u8,
        (upper & 0xFF) as u8,
    ];
    let checksum = ihex_checksum(&body);
    let mut s = String::with_capacity(20);
    s.push(':');
    for b in &body {
        if uppercase {
            let _ = write!(s, "{b:02X}");
        } else {
            let _ = write!(s, "{b:02x}");
        }
    }
    if uppercase {
        let _ = writeln!(s, "{checksum:02X}");
    } else {
        let _ = writeln!(s, "{checksum:02x}");
    }
    s
}

/// Format the Intel HEX end-of-file record.
const fn ihex_eof(uppercase: bool) -> &'static str {
    if uppercase { ":00000001FF\n" } else { ":00000001ff\n" }
}

// ─────────────────────────────────────────────────────────────────────────────
// export_to_intel_hex
// ─────────────────────────────────────────────────────────────────────────────

/// Export `data` in Intel HEX (IHEX) format starting at `base_address`.
///
/// Supports addresses beyond 64 KiB by emitting extended linear address records.
#[must_use]
pub fn export_to_intel_hex(data: &[u8], opts: &ExportOptions) -> String {
    let bpl = opts.bytes_per_line.clamp(1, 255);
    let mut out = String::with_capacity(data.len() * 6 + 64);
    let base = opts.base_address;

    let mut last_upper = u16::MAX; // sentinel: no upper segment emitted yet

    let mut offset = 0usize;
    while offset < data.len() {
        let addr64 = base + offset as u64;
        let upper = (addr64 >> 16) as u16;
        let lower = (addr64 & 0xFFFF) as u16;

        // Emit extended linear address record when upper word changes.
        if upper != last_upper {
            out.push_str(&ihex_extended_linear_address(upper, opts.uppercase));
            last_upper = upper;
        }

        let chunk_max = bpl.min(data.len() - offset);
        // Clamp to 16-bit address boundary.
        let remaining_in_page = (0x10000usize).saturating_sub(lower as usize);
        let chunk_len = chunk_max.min(remaining_in_page).max(1);

        let chunk = &data[offset..offset + chunk_len];
        out.push_str(&ihex_data_record(lower, chunk, opts.uppercase));
        offset += chunk_len;
    }

    out.push_str(ihex_eof(opts.uppercase));
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Motorola S-Record
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the S-Record checksum: one's complement of the low byte of the
/// sum of all bytes in the record (byte count + address + data).
fn srec_checksum(body: &[u8]) -> u8 {
    let sum: u32 = body.iter().map(|&b| u32::from(b)).sum();
    !(sum as u8)
}

/// Export `data` as Motorola S-Records (S0 header, S3 data, S7 end).
#[must_use]
pub fn export_to_srecord(data: &[u8], opts: &ExportOptions) -> String {
    let bpl = opts.bytes_per_line.clamp(1, 252);
    let mut out = String::with_capacity(data.len() * 6 + 64);
    let up = opts.uppercase;

    // S0: header record (module name from symbol_name).
    {
        let name_bytes = &opts.symbol_name.as_bytes()[..opts.symbol_name.len().min(252)];
        let byte_count = (3 + name_bytes.len()) as u8; // addr(2) + data + checksum (max 255)
        let mut body = vec![byte_count, 0x00, 0x00];
        body.extend_from_slice(name_bytes);
        let ck = srec_checksum(&body);
        out.push_str("S0");
        for b in &body {
            if up { let _ = write!(out, "{b:02X}"); } else { let _ = write!(out, "{b:02x}"); }
        }
        if up { let _ = writeln!(out, "{ck:02X}"); } else { let _ = writeln!(out, "{ck:02x}"); }
    }

    // S3: 32-bit address data records.
    let mut record_count = 0u32;
    let mut offset = 0usize;
    while offset < data.len() {
        let addr = opts.base_address + offset as u64;
        let chunk_len = bpl.min(data.len() - offset);
        let chunk = &data[offset..offset + chunk_len];

        // S3 record byte_count = addr(4) + data bytes + checksum; chunk_len <= 252 due to bpl.clamp(1,252) above
        let byte_count = (5u16 + chunk_len as u16).min(255) as u8;
        let a3 = ((addr >> 24) & 0xFF) as u8;
        let a2 = ((addr >> 16) & 0xFF) as u8;
        let a1 = ((addr >> 8) & 0xFF) as u8;
        let a0 = (addr & 0xFF) as u8;
        let mut body = vec![byte_count, a3, a2, a1, a0];
        body.extend_from_slice(chunk);
        let ck = srec_checksum(&body);

        out.push_str("S3");
        for b in &body {
            if up { let _ = write!(out, "{b:02X}"); } else { let _ = write!(out, "{b:02x}"); }
        }
        if up { let _ = writeln!(out, "{ck:02X}"); } else { let _ = writeln!(out, "{ck:02x}"); }

        offset += chunk_len;
        record_count += 1;
    }

    // S5: record count.
    {
        let byte_count = 0x03u8;
        let ch = ((record_count >> 8) & 0xFF) as u8;
        let cl = (record_count & 0xFF) as u8;
        let body = vec![byte_count, ch, cl];
        let ck = srec_checksum(&body);
        out.push_str("S5");
        for b in &body {
            if up { let _ = write!(out, "{b:02X}"); } else { let _ = write!(out, "{b:02x}"); }
        }
        if up { let _ = writeln!(out, "{ck:02X}"); } else { let _ = writeln!(out, "{ck:02x}"); }
    }

    // S7: 32-bit start address (= base_address).
    {
        let start = opts.base_address;
        let byte_count = 0x05u8;
        let s3 = ((start >> 24) & 0xFF) as u8;
        let s2 = ((start >> 16) & 0xFF) as u8;
        let s1 = ((start >> 8) & 0xFF) as u8;
        let s0 = (start & 0xFF) as u8;
        let body = vec![byte_count, s3, s2, s1, s0];
        let ck = srec_checksum(&body);
        out.push_str("S7");
        for b in &body {
            if up { let _ = write!(out, "{b:02X}"); } else { let _ = write!(out, "{b:02x}"); }
        }
        if up { let _ = writeln!(out, "{ck:02X}"); } else { let _ = writeln!(out, "{ck:02x}"); }
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// xxd-style hex dump
// ─────────────────────────────────────────────────────────────────────────────

/// Export `data` in `xxd` hex dump style.
///
/// ```text
/// 00000000: dead beef cafe babe  0102 0304  ................
/// ```
#[must_use]
pub fn export_to_xxd(data: &[u8], opts: &ExportOptions) -> String {
    let bpl = opts.bytes_per_line.max(1);
    let mut out = String::with_capacity((data.len() / bpl + 1) * (bpl * 4 + 20));
    for (row, chunk) in data.chunks(bpl).enumerate() {
        let addr = opts.base_address + (row * bpl) as u64;
        if opts.uppercase {
            let _ = write!(out, "{addr:08X}: ");
        } else {
            let _ = write!(out, "{addr:08x}: ");
        }
        for (i, &b) in chunk.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                out.push(' ');
            }
            if opts.uppercase {
                let _ = write!(out, "{b:02X}");
            } else {
                let _ = write!(out, "{b:02x}");
            }
        }
        // Pad to full width.
        let hex_printed = chunk.len() * 2 + (chunk.len().saturating_sub(1) / 2);
        let hex_full = bpl * 2 + (bpl.saturating_sub(1) / 2);
        for _ in 0..hex_full.saturating_sub(hex_printed) {
            out.push(' ');
        }
        out.push_str("  ");
        for &b in chunk {
            out.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
        }
        out.push('\n');
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Python bytes literal
// ─────────────────────────────────────────────────────────────────────────────

/// Export `data` as a Python `bytes` literal assignment.
///
/// ```text
/// data = (
///     b"\xde\xad\xbe\xef"
/// )
/// ```
#[must_use]
pub fn export_to_python_bytes(data: &[u8], opts: &ExportOptions) -> String {
    let bpl = opts.bytes_per_line.max(1);
    let mut out = String::with_capacity(data.len() * 5 + 32);
    let _ = writeln!(out, "{} = (", opts.symbol_name);
    for chunk in data.chunks(bpl) {
        out.push_str("    b\"");
        for &b in chunk {
            let _ = write!(out, "\\x{b:02x}");
        }
        out.push_str("\"\n");
    }
    out.push_str(")\n");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust array literal
// ─────────────────────────────────────────────────────────────────────────────

/// Export `data` as a Rust `[u8; N]` array literal.
///
/// ```text
/// const DATA: [u8; 4] = [
///     0xDE, 0xAD, 0xBE, 0xEF,
/// ];
/// ```
#[must_use]
pub fn export_to_rust_array(data: &[u8], opts: &ExportOptions) -> String {
    let bpl = opts.bytes_per_line.max(1);
    let sym = opts.symbol_name.to_uppercase();
    let mut out = String::with_capacity(data.len() * 6 + 64);
    let _ = writeln!(
        out,
        "const {sym}: [u8; {}] = [",
        data.len()
    );
    for chunk in data.chunks(bpl) {
        out.push_str("    ");
        for (j, &b) in chunk.iter().enumerate() {
            if opts.uppercase {
                let _ = write!(out, "0x{b:02X}");
            } else {
                let _ = write!(out, "0x{b:02x}");
            }
            if j + 1 < chunk.len() {
                out.push_str(", ");
            }
        }
        out.push_str(",\n");
    }
    out.push_str("];\n");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// HexExporter
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful hex exporter that holds a data buffer and export options.
pub struct HexExporter {
    /// The data to export.
    pub data: Vec<u8>,
    /// Export options.
    pub options: ExportOptions,
}

impl HexExporter {
    /// Create a new exporter with default options.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            options: ExportOptions::default(),
        }
    }

    /// Create an exporter with custom options.
    #[must_use]
    pub const fn with_options(data: Vec<u8>, options: ExportOptions) -> Self {
        Self { data, options }
    }

    /// Export in the requested format.  Returns a text string for all text
    /// formats and the raw bytes encoded as a hex string for `RawBinary`.
    #[must_use]
    pub fn export(&self, format: ExportFormat) -> String {
        match format {
            ExportFormat::CArray => export_to_c_array(&self.data, &self.options),
            ExportFormat::IntelHex => export_to_intel_hex(&self.data, &self.options),
            ExportFormat::SRecord => export_to_srecord(&self.data, &self.options),
            ExportFormat::RawBinary => self
                .data
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
            ExportFormat::XxdHexDump => export_to_xxd(&self.data, &self.options),
            ExportFormat::PythonBytes => export_to_python_bytes(&self.data, &self.options),
            ExportFormat::RustArray => export_to_rust_array(&self.data, &self.options),
        }
    }

    /// Export and return the byte length of the output.
    #[must_use]
    pub fn export_len(&self, format: ExportFormat) -> usize {
        self.export(format).len()
    }

    /// Return the data length.
    #[must_use]
    pub const fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Replace the stored data without changing options.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    /// Update the base address.
    pub const fn set_base_address(&mut self, addr: u64) {
        self.options.base_address = addr;
    }
}

impl fmt::Debug for HexExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HexExporter")
            .field("data_len", &self.data.len())
            .field("base_address", &format_args!("{:#x}", self.options.base_address))
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ExportOptions {
        ExportOptions::default()
    }

    fn simple_data() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    }

    // ── C Array ───────────────────────────────────────────────────────────────

    #[test]
    fn c_array_contains_values() {
        let out = export_to_c_array(&simple_data(), &opts());
        assert!(out.contains("0xDE"));
        assert!(out.contains("0xEF"));
        assert!(out.contains("unsigned char data[]"));
    }

    #[test]
    fn c_array_has_comment() {
        let out = export_to_c_array(&simple_data(), &opts());
        assert!(out.contains("4 bytes"));
    }

    #[test]
    fn c_array_no_comment() {
        let o = ExportOptions { include_count_comment: false, ..opts() };
        let out = export_to_c_array(&simple_data(), &o);
        assert!(!out.contains("bytes"));
    }

    #[test]
    fn c_array_custom_symbol() {
        let o = ExportOptions { symbol_name: "payload".to_owned(), ..opts() };
        let out = export_to_c_array(&simple_data(), &o);
        assert!(out.contains("unsigned char payload[]"));
    }

    #[test]
    fn c_array_lowercase() {
        let o = ExportOptions { uppercase: false, ..opts() };
        let out = export_to_c_array(&simple_data(), &o);
        assert!(out.contains("0xde"));
    }

    // ── Intel HEX ─────────────────────────────────────────────────────────────

    #[test]
    fn intel_hex_starts_with_colon() {
        let out = export_to_intel_hex(&simple_data(), &opts());
        assert!(out.lines().next().unwrap().starts_with(':'));
    }

    #[test]
    fn intel_hex_ends_with_eof() {
        let out = export_to_intel_hex(&simple_data(), &opts());
        assert!(out.contains(":00000001FF"));
    }

    #[test]
    fn intel_hex_contains_data() {
        let out = export_to_intel_hex(&[0xDE, 0xAD], &opts());
        assert!(out.contains("DEAD"));
    }

    #[test]
    fn intel_hex_high_address() {
        let o = ExportOptions { base_address: 0x0001_0000, ..opts() };
        let out = export_to_intel_hex(&simple_data(), &o);
        // Extended linear address record should appear.
        assert!(out.contains(":02000004"));
    }

    #[test]
    fn intel_hex_checksum_valid() {
        // For ":04000000DEADBEEF" the checksum should be correct.
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let rec = ihex_data_record(0x0000, &data, true);
        assert!(rec.starts_with(':'));
        // The last two hex digits are the checksum; verify by re-computing.
        let hex_body = &rec[1..rec.trim_end().len() - 2];
        let bytes: Vec<u8> = (0..hex_body.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_body[i..i + 2], 16).unwrap())
            .collect();
        let sum: u32 = bytes.iter().map(|&b| b as u32).sum();
        let ck_str = &rec.trim_end()[rec.trim_end().len() - 2..];
        let ck = u8::from_str_radix(ck_str, 16).unwrap();
        assert_eq!((sum + ck as u32) & 0xFF, 0);
    }

    // ── S-Record ──────────────────────────────────────────────────────────────

    #[test]
    fn srecord_has_s0_header() {
        let out = export_to_srecord(&simple_data(), &opts());
        assert!(out.starts_with("S0"));
    }

    #[test]
    fn srecord_has_s3_records() {
        let out = export_to_srecord(&[0xAA; 32], &opts());
        assert!(out.contains("S3"));
    }

    #[test]
    fn srecord_ends_with_s7() {
        let out = export_to_srecord(&simple_data(), &opts());
        assert!(out.contains("S7"));
    }

    // ── xxd ───────────────────────────────────────────────────────────────────

    #[test]
    fn xxd_contains_hex_values() {
        let out = export_to_xxd(&simple_data(), &opts());
        assert!(out.contains("DEAD"));
    }

    #[test]
    fn xxd_contains_address() {
        let o = ExportOptions { base_address: 0x100, ..opts() };
        let out = export_to_xxd(&simple_data(), &o);
        assert!(out.contains("00000100"));
    }

    #[test]
    fn xxd_ascii_column() {
        let out = export_to_xxd(b"Hello", &opts());
        assert!(out.contains("Hello"));
    }

    // ── Python ────────────────────────────────────────────────────────────────

    #[test]
    fn python_bytes_assignment() {
        let out = export_to_python_bytes(&simple_data(), &opts());
        assert!(out.starts_with("data = ("));
        assert!(out.contains("\\xde"));
    }

    #[test]
    fn python_bytes_custom_symbol() {
        let o = ExportOptions { symbol_name: "buf".to_owned(), ..opts() };
        let out = export_to_python_bytes(&simple_data(), &o);
        assert!(out.starts_with("buf = ("));
    }

    // ── Rust Array ────────────────────────────────────────────────────────────

    #[test]
    fn rust_array_const_decl() {
        let out = export_to_rust_array(&simple_data(), &opts());
        assert!(out.contains("const DATA: [u8; 4]"));
    }

    #[test]
    fn rust_array_values() {
        let out = export_to_rust_array(&simple_data(), &opts());
        assert!(out.contains("0xDE"));
    }

    // ── HexExporter ───────────────────────────────────────────────────────────

    #[test]
    fn exporter_c_array() {
        let exp = HexExporter::new(simple_data());
        let out = exp.export(ExportFormat::CArray);
        assert!(out.contains("unsigned char data[]"));
    }

    #[test]
    fn exporter_intel_hex() {
        let exp = HexExporter::new(simple_data());
        let out = exp.export(ExportFormat::IntelHex);
        assert!(out.contains(':'));
    }

    #[test]
    fn exporter_raw_binary() {
        let exp = HexExporter::new(vec![0xDE, 0xAD]);
        let out = exp.export(ExportFormat::RawBinary);
        assert_eq!(out, "DEAD");
    }

    #[test]
    fn exporter_python_bytes() {
        let exp = HexExporter::new(simple_data());
        let out = exp.export(ExportFormat::PythonBytes);
        assert!(out.contains("data = ("));
    }

    #[test]
    fn exporter_rust_array() {
        let exp = HexExporter::new(simple_data());
        let out = exp.export(ExportFormat::RustArray);
        assert!(out.contains("[u8; 4]"));
    }

    #[test]
    fn exporter_set_data() {
        let mut exp = HexExporter::new(vec![0u8; 4]);
        exp.set_data(vec![0xFF; 8]);
        assert_eq!(exp.data_len(), 8);
    }

    #[test]
    fn exporter_set_base_address() {
        let mut exp = HexExporter::new(simple_data());
        exp.set_base_address(0x1000);
        let out = exp.export(ExportFormat::XxdHexDump);
        assert!(out.contains("00001000"));
    }

    #[test]
    fn exporter_debug_format() {
        let exp = HexExporter::new(simple_data());
        let s = format!("{exp:?}");
        assert!(s.contains("HexExporter"));
    }

    #[test]
    fn export_format_display() {
        assert_eq!(ExportFormat::CArray.to_string(), "C Array");
        assert_eq!(ExportFormat::IntelHex.to_string(), "Intel HEX");
        assert_eq!(ExportFormat::SRecord.to_string(), "S-Record");
    }

    #[test]
    fn ihex_checksum_known_vector() {
        // :020000040001F9 — extended linear address to segment 0x0001
        // body bytes: 02 00 00 04 00 01
        let body = [0x02u8, 0x00, 0x00, 0x04, 0x00, 0x01];
        let ck = ihex_checksum(&body);
        assert_eq!(ck, 0xF9);
    }
}
