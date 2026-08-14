//! FLIRT PAT and SIG binary format serializer/deserializer.
//!
//! Implements:
//! - `PatRecord` (one line in a .pat file)
//! - `PatFile` generator
//! - `SigHeader` (IDA .sig binary header)
//! - `SigModule` (one function entry in a .sig file)
//! - `SigFile` binary serializer/deserializer
//! - Trie-to-SIG conversion

pub use std::io::Read;
use std::io::Write;

use serde::{Deserialize, Serialize};

// ── CRC-16 (FLIRT variant) ────────────────────────────────────────────────────

/// Compute CRC-16/MCRF4XX (FLIRT poly 0x8408) over `data`.
#[must_use] 
pub fn crc16(data: &[u8]) -> u16 {
    rustre_flirt::crc::flirt_tail(data)
}

// ── PatRecord ─────────────────────────────────────────────────────────────────

/// One record in a FLIRT .pat file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatRecord {
    /// Hex pattern without spaces (e.g. `"558BEC83EC10"`).
    pub hex_pattern: String,
    /// CRC-16 of the region after the pattern.
    pub crc16: u16,
    /// Length of the CRC region in bytes.
    pub crc_len: u8,
    /// Total function length in bytes.
    pub total_len: u32,
    /// Primary function name.
    pub name: String,
    /// Secondary names (refs): `[(offset, "name"), ...]`.
    pub references: Vec<(u32, String)>,
    /// Local (private) names.
    pub local_names: Vec<(u32, String)>,
}

impl PatRecord {
    pub fn new(
        hex_pattern: impl Into<String>,
        crc16: u16,
        crc_len: u8,
        total_len: u32,
        name: impl Into<String>,
    ) -> Self {
        Self {
            hex_pattern: hex_pattern.into(),
            crc16,
            crc_len,
            total_len,
            name: name.into(),
            references: Vec::new(),
            local_names: Vec::new(),
        }
    }

    /// Build a `PatRecord` from raw function bytes.
    pub fn from_bytes(
        func_bytes: &[u8],
        name: impl Into<String>,
        min_pattern_len: usize,
        crc_window: usize,
    ) -> Self {
        let pat_len = func_bytes.len().min(min_pattern_len);
        let hex_pattern: String = {
            use std::fmt::Write;
            let mut acc = String::with_capacity(pat_len * 2);
            for b in &func_bytes[..pat_len] {
                let _ = write!(acc, "{b:02X}");
            }
            acc
        };
        let crc_start = pat_len;
        let crc_end = (crc_start + crc_window).min(func_bytes.len());
        let crc16 = crc16(&func_bytes[crc_start..crc_end]);
        let crc_len = u8::try_from(crc_end - crc_start).unwrap_or(255);
        Self::new(hex_pattern, crc16, crc_len, u32::try_from(func_bytes.len()).unwrap_or(u32::MAX), name)
    }

    /// Render this record as a .pat file line.
    #[must_use] 
    pub fn to_pat_line(&self) -> String {
        let line = format!(
            "{} {:04X} {:02X} {:04X} {}",
            self.hex_pattern, self.crc16, self.crc_len, self.total_len, self.name,
        );
        line
    }

    /// Parse a .pat file line.
    #[must_use] 
    pub fn from_pat_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }
        let hex_pattern = parts[0].to_string();
        let crc16 = u16::from_str_radix(parts[1], 16).ok()?;
        let crc_len = u8::from_str_radix(parts[2], 16).ok()?;
        let total_len = u32::from_str_radix(parts[3], 16).ok()?;
        let name = parts[4..].join(" ");
        Some(Self::new(hex_pattern, crc16, crc_len, total_len, name))
    }
}

impl std::fmt::Display for PatRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} crc={:04X} name={}",
            self.hex_pattern, self.crc16, self.name
        )
    }
}

// ── PatFile ───────────────────────────────────────────────────────────────────

/// Generator for FLIRT .pat text files.
#[derive(Debug, Clone, Default)]
pub struct PatFile {
    pub records: Vec<PatRecord>,
}

impl PatFile {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, record: PatRecord) {
        self.records.push(record);
    }

}

/// Render the whole .pat file as a string.
impl std::fmt::Display for PatFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lines: Vec<String> = self.records.iter().map(PatRecord::to_pat_line).collect();
        lines.push("---".to_string());
        write!(f, "{}", lines.join("\n"))
    }
}

impl PatFile {

    /// Parse a .pat file string into a `PatFile`.
    #[must_use]
    pub fn parse_str(s: &str) -> Self {
        let mut pf = Self::new();
        for line in s.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == "---" || trimmed.starts_with(';') {
                continue;
            }
            if let Some(r) = PatRecord::from_pat_line(trimmed) {
                pf.add(r);
            }
        }
        pf
    }

    /// Write to a `Write` sink.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if writing fails.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(self.to_string().as_bytes())
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.records.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ── SigHeader ─────────────────────────────────────────────────────────────────

/// IDA .sig binary file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigHeader {
    pub magic: [u8; 6],
    pub version: u8,
    pub arch: u8,
    pub file_types: u32,
    pub os_types: u16,
    pub app_types: u16,
    pub feature_flags: u16,
    pub old_num_funcs: u16,
    pub crc16: u16,
    pub ctypes_crc: [u8; 12],
    pub num_functions: u32,
    pub pattern_size: u16,
    pub lib_name: String,
}

impl SigHeader {
    pub const MAGIC: [u8; 6] = *b"IDASGN";
    pub const VERSION: u8 = 9;
    /// Deprecated: the IDA header is variable length. Use
    /// `rustre_flirt::sig_header::SigFileHeader::len_bytes()`.
    #[deprecated(note = "the IDA header is variable length; use len_bytes()")]
    pub const HEADER_FIXED_SIZE: usize = 104;

    /// Byte length of this header once encoded — where the module list starts.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        rustre_flirt::sig_header::OFF_NAME + self.lib_name.len().min(usize::from(u8::MAX))
    }

    pub fn new(lib_name: impl Into<String>) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            arch: 0, // x86
            file_types: 0,
            os_types: 0,
            app_types: 0,
            feature_flags: 0,
            old_num_funcs: 0,
            crc16: 0,
            ctypes_crc: [0u8; 12],
            num_functions: 0,
            pattern_size: 32,
            lib_name: lib_name.into(),
        }
    }

    /// Serialize the header in the published IDA layout.
    ///
    /// BUG FIX: this emitted a fixed 104 bytes with `num_functions` as a `u32`
    /// at offset 34 and the name in a fixed 40..104 window. Offset 34 is IDA's
    /// one-byte `library_name_len`. Now delegated to the single codec in
    /// [`rustre_flirt::sig_header`]; the result is **variable length**.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.to_canonical().encode()
    }

    /// View this header as the canonical one.
    fn to_canonical(&self) -> rustre_flirt::sig_header::SigFileHeader {
        rustre_flirt::sig_header::SigFileHeader {
            version: self.version,
            arch: self.arch,
            file_types: self.file_types,
            os_types: self.os_types,
            app_types: self.app_types,
            feature_flags: self.feature_flags,
            old_n_functions: self.old_num_funcs,
            crc16: self.crc16,
            ctype: self.ctypes_crc,
            n_functions: self.num_functions,
            pattern_size: self.pattern_size,
            lib_name: self.lib_name.clone(),
            ..rustre_flirt::sig_header::SigFileHeader::default()
        }
    }

    /// Deserialize from the start of a `.sig` buffer.
    ///
    /// Returns `None` on anything the canonical codec rejects (bad magic,
    /// unsupported version, truncated buffer, or a `library_name_len` that runs
    /// past the end — a `.sig` is untrusted input).
    #[must_use]
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let h = rustre_flirt::sig_header::SigFileHeader::decode(data).ok()?;
        Some(Self {
            magic: Self::MAGIC,
            version: h.version,
            arch: h.arch,
            file_types: h.file_types,
            os_types: h.os_types,
            app_types: h.app_types,
            feature_flags: h.feature_flags,
            old_num_funcs: h.old_n_functions,
            crc16: h.crc16,
            ctypes_crc: h.ctype,
            num_functions: h.n_functions,
            pattern_size: h.pattern_size,
            lib_name: h.lib_name,
        })
    }
}

// ── SigModule ─────────────────────────────────────────────────────────────────

/// One function module entry in a .sig file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigModule {
    pub name: String,
    pub feature_flags: u8,
    pub crc16: u16,
    pub crc_len: u8,
    pub first_bytes: Vec<u8>,
    pub total_len: u32,
    pub references: Vec<SigRef>,
}

/// A reference embedded in a `SigModule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRef {
    pub offset: u32,
    pub name: String,
    pub negative: bool,
}

impl SigModule {
    pub fn new(
        name: impl Into<String>,
        first_bytes: Vec<u8>,
        crc16: u16,
        crc_len: u8,
        total_len: u32,
    ) -> Self {
        Self {
            name: name.into(),
            feature_flags: 0,
            crc16,
            crc_len,
            first_bytes,
            total_len,
            references: Vec::new(),
        }
    }

    /// Build a `SigModule` from raw function bytes.
    pub fn from_bytes(
        func_bytes: &[u8],
        name: impl Into<String>,
        pat_len: usize,
        crc_window: usize,
    ) -> Self {
        let take = pat_len.min(func_bytes.len());
        let first_bytes = func_bytes[..take].to_vec();
        let crc_start = take;
        let crc_end = (crc_start + crc_window).min(func_bytes.len());
        let crc16 = crc16(&func_bytes[crc_start..crc_end]);
        let crc_len = u8::try_from(crc_end - crc_start).unwrap_or(255);
        Self::new(name, first_bytes, crc16, crc_len, u32::try_from(func_bytes.len()).unwrap_or(u32::MAX))
    }

    /// Serialize module to bytes (simplified format).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Name length (1 byte) + name bytes.
        let name_bytes = self.name.as_bytes();
        buf.push(u8::try_from(name_bytes.len().min(255)).unwrap_or(255));
        buf.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);
        // Feature flags.
        buf.push(self.feature_flags);
        // CRC16 (LE).
        buf.extend_from_slice(&self.crc16.to_le_bytes());
        // CRC len.
        buf.push(self.crc_len);
        // Total len (LE u32).
        buf.extend_from_slice(&self.total_len.to_le_bytes());
        // Pattern length + first bytes.
        buf.push(u8::try_from(self.first_bytes.len().min(255)).unwrap_or(255));
        buf.extend_from_slice(&self.first_bytes[..self.first_bytes.len().min(255)]);
        // Reference count.
        buf.push(u8::try_from(self.references.len().min(255)).unwrap_or(255));
        for r in &self.references {
            buf.extend_from_slice(&r.offset.to_le_bytes());
            let rn = r.name.as_bytes();
            buf.push(u8::try_from(rn.len().min(255)).unwrap_or(255));
            buf.extend_from_slice(&rn[..rn.len().min(255)]);
            buf.push(u8::from(r.negative));
        }
        buf
    }

    /// Deserialize one module from `data` starting at `pos`. Returns bytes consumed.
    #[must_use] 
    pub fn deserialize(data: &[u8], pos: usize) -> Option<(Self, usize)> {
        let mut p = pos;
        let name_len = *data.get(p)? as usize;
        p += 1;
        if p + name_len > data.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&data[p..p + name_len]).to_string();
        p += name_len;
        let feature_flags = *data.get(p)?;
        p += 1;
        if p + 2 > data.len() {
            return None;
        }
        let crc16 = u16::from_le_bytes(data[p..p + 2].try_into().ok()?);
        p += 2;
        let crc_len = *data.get(p)?;
        p += 1;
        if p + 4 > data.len() {
            return None;
        }
        let total_len = u32::from_le_bytes(data[p..p + 4].try_into().ok()?);
        p += 4;
        let pat_len = *data.get(p)? as usize;
        p += 1;
        if p + pat_len > data.len() {
            return None;
        }
        let first_bytes = data[p..p + pat_len].to_vec();
        p += pat_len;
        let ref_count = *data.get(p)? as usize;
        p += 1;
        let mut references = Vec::new();
        for _ in 0..ref_count {
            if p + 4 > data.len() {
                break;
            }
            let offset = u32::from_le_bytes(data[p..p + 4].try_into().ok()?);
            p += 4;
            let rn_len = *data.get(p)? as usize;
            p += 1;
            if p + rn_len > data.len() {
                break;
            }
            let rname = String::from_utf8_lossy(&data[p..p + rn_len]).to_string();
            p += rn_len;
            let negative = *data.get(p)? != 0;
            p += 1;
            references.push(SigRef {
                offset,
                name: rname,
                negative,
            });
        }
        let module = Self {
            name,
            feature_flags,
            crc16,
            crc_len,
            first_bytes,
            total_len,
            references,
        };
        Some((module, p - pos))
    }
}

// ── SigFile ───────────────────────────────────────────────────────────────────

/// A complete IDA .sig file (header + modules).
#[derive(Debug, Clone)]
pub struct SigFile {
    pub header: SigHeader,
    pub modules: Vec<SigModule>,
}

impl SigFile {
    pub fn new(lib_name: impl Into<String>) -> Self {
        Self {
            header: SigHeader::new(lib_name),
            modules: Vec::new(),
        }
    }

    pub fn add_module(&mut self, module: SigModule) {
        self.modules.push(module);
        self.header.num_functions = u32::try_from(self.modules.len()).unwrap_or(u32::MAX);
    }

    /// Serialize the entire .sig file to bytes.
    #[must_use] 
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.header.serialize());
        for module in &self.modules {
            buf.extend_from_slice(&module.serialize());
        }
        // End-of-trie sentinel.
        buf.push(0);
        buf
    }

    /// Deserialize a .sig file from bytes.
    #[must_use] 
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let header = SigHeader::deserialize(data)?;
        let mut modules = Vec::new();
        // The header is variable length: the module list starts where the
        // library name ends, not at a constant 104.
        let mut pos = header.encoded_len();
        while pos < data.len() {
            if data[pos] == 0 {
                break;
            }
            match SigModule::deserialize(data, pos) {
                Some((m, consumed)) => {
                    pos += consumed;
                    modules.push(m);
                }
                None => break,
            }
        }
        Some(Self { header, modules })
    }

    /// Write to any `Write` sink.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if writing fails.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.serialize())
    }

    #[must_use] 
    pub const fn module_count(&self) -> usize {
        self.modules.len()
    }
}

// ── Trie to SIG conversion ────────────────────────────────────────────────────

/// Build a `SigFile` from a list of `PatRecord`s (trie-to-SIG conversion).
#[must_use] 
pub fn pat_records_to_sig(records: &[PatRecord], lib_name: &str) -> SigFile {
    let mut sig = SigFile::new(lib_name);
    for record in records {
        let first_bytes: Vec<u8> = (0..record.hex_pattern.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&record.hex_pattern[i..i + 2], 16).unwrap_or(0))
            .collect();
        let module = SigModule::new(
            &record.name,
            first_bytes,
            record.crc16,
            record.crc_len,
            record.total_len,
        );
        sig.add_module(module);
    }
    sig
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── crc16 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_single_byte() {
        let v = crc16(&[0x55]);
        assert_ne!(v, 0xFFFF);
    }

    #[test]
    fn test_crc16_known() {
        // Simple sanity: two different inputs produce different CRCs.
        let a = crc16(b"hello");
        let b = crc16(b"world");
        assert_ne!(a, b);
    }

    // ── PatRecord ─────────────────────────────────────────────────────────────

    #[test]
    fn test_pat_record_new() {
        let r = PatRecord::new("558BEC", 0xABCD, 4, 0x20, "main");
        assert_eq!(r.hex_pattern, "558BEC");
        assert_eq!(r.crc16, 0xABCD);
        assert_eq!(r.name, "main");
    }

    #[test]
    fn test_pat_record_from_bytes() {
        let bytes = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let r = PatRecord::from_bytes(&bytes, "fn", 4, 2);
        assert_eq!(r.hex_pattern, "558BEC83");
        assert_eq!(r.crc_len, 2);
        assert_eq!(r.total_len, 6);
    }

    #[test]
    fn test_pat_record_to_line_roundtrip() {
        let r = PatRecord::new("558BEC", 0x1234, 2, 0x30, "test_fn");
        let line = r.to_pat_line();
        let parsed = PatRecord::from_pat_line(&line).unwrap();
        assert_eq!(parsed.hex_pattern, "558BEC");
        assert_eq!(parsed.crc16, 0x1234);
        assert_eq!(parsed.crc_len, 2);
        assert_eq!(parsed.name, "test_fn");
    }

    #[test]
    fn test_pat_record_display() {
        let r = PatRecord::new("AABBCC", 0, 0, 3, "fn");
        let s = r.to_string();
        assert!(s.contains("AABBCC"));
        assert!(s.contains("fn"));
    }

    #[test]
    fn test_pat_record_from_line_too_short() {
        assert!(PatRecord::from_pat_line("ABC").is_none());
    }

    // ── PatFile ───────────────────────────────────────────────────────────────

    #[test]
    fn test_patfile_add_and_len() {
        let mut pf = PatFile::new();
        pf.add(PatRecord::new("558BEC", 0, 0, 3, "fn"));
        assert_eq!(pf.len(), 1);
    }

    #[test]
    fn test_patfile_to_string_contains_separator() {
        let pf = PatFile::new();
        let s = pf.to_string();
        assert!(s.contains("---"));
    }

    #[test]
    fn test_patfile_roundtrip() {
        let mut pf = PatFile::new();
        pf.add(PatRecord::new("558BEC83EC10", 0x1234, 4, 0x20, "main"));
        pf.add(PatRecord::new("5541574156", 0x5678, 3, 0x40, "helper"));
        let s = pf.to_string();
        let parsed = PatFile::parse_str(&s);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.records[0].name, "main");
        assert_eq!(parsed.records[1].name, "helper");
    }

    #[test]
    fn test_patfile_empty() {
        let pf = PatFile::new();
        assert!(pf.is_empty());
    }

    #[test]
    fn test_patfile_write_to() {
        let mut pf = PatFile::new();
        pf.add(PatRecord::new("558BEC", 0, 0, 3, "fn"));
        let mut buf = Vec::new();
        pf.write_to(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("558BEC"));
    }

    // ── SigHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sig_header_serialize_size_is_variable() {
        // The IDA header ends where the library name ends. A fixed 104 was the
        // defect: it forced the name into a padded window nobody else reads.
        let h = SigHeader::new("mylib");
        assert_eq!(h.serialize().len(), 43 + 5);
        assert_eq!(h.serialize().len(), h.encoded_len());
        assert_eq!(SigHeader::new("").serialize().len(), 43);
    }

    #[test]
    fn test_sig_header_magic() {
        let h = SigHeader::new("mylib");
        let bytes = h.serialize();
        assert_eq!(&bytes[0..6], b"IDASGN");
    }

    #[test]
    fn test_sig_header_roundtrip() {
        let h = SigHeader::new("testlib");
        let bytes = h.serialize();
        let h2 = SigHeader::deserialize(&bytes).unwrap();
        assert_eq!(h2.lib_name, "testlib");
        assert_eq!(h2.version, 9);
    }

    #[test]
    fn test_sig_header_truncated() {
        assert!(SigHeader::deserialize(&[0u8; 50]).is_none());
    }

    #[test]
    fn test_sig_header_wrong_magic() {
        let mut bytes = [0u8; 104];
        bytes[0..6].copy_from_slice(b"NOTIDA");
        assert!(SigHeader::deserialize(&bytes).is_none());
    }

    // ── SigModule ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sig_module_new() {
        let m = SigModule::new("main", vec![0x55, 0x8B, 0xEC], 0x1234, 3, 32);
        assert_eq!(m.name, "main");
        assert_eq!(m.first_bytes, vec![0x55, 0x8B, 0xEC]);
    }

    #[test]
    fn test_sig_module_from_bytes() {
        let bytes = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let m = SigModule::from_bytes(&bytes, "fn", 4, 2);
        assert_eq!(m.first_bytes, vec![0x55, 0x8B, 0xEC, 0x83]);
        assert_eq!(m.crc_len, 2);
    }

    #[test]
    fn test_sig_module_roundtrip() {
        let m = SigModule::new("testfn", vec![0x55, 0x8B, 0xEC], 0xABCD, 4, 48);
        let bytes = m.serialize();
        let (parsed, consumed) = SigModule::deserialize(&bytes, 0).unwrap();
        assert_eq!(parsed.name, "testfn");
        assert_eq!(parsed.crc16, 0xABCD);
        assert_eq!(consumed, bytes.len());
    }

    // ── SigFile ───────────────────────────────────────────────────────────────

    #[test]
    fn test_sigfile_new() {
        let sf = SigFile::new("lib");
        assert_eq!(sf.module_count(), 0);
    }

    #[test]
    fn test_sigfile_add_module() {
        let mut sf = SigFile::new("lib");
        sf.add_module(SigModule::new("fn1", vec![0x55], 0, 0, 16));
        assert_eq!(sf.module_count(), 1);
        assert_eq!(sf.header.num_functions, 1);
    }

    #[test]
    fn test_sigfile_serialize_starts_with_header() {
        let sf = SigFile::new("mylib");
        let bytes = sf.serialize();
        // The header no longer has a fixed size, so the file is only bounded
        // below by the header it actually wrote.
        assert!(bytes.len() >= sf.header.encoded_len());
        assert_eq!(&bytes[0..6], b"IDASGN");
        // And it must decode with the canonical codec, not merely start with
        // the right magic — a magic check alone passed for years while the rest
        // of the header was in the wrong layout.
        let h = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("il file serializzato deve essere decodificabile");
        assert_eq!(h.lib_name, "mylib");
    }

    #[test]
    fn test_sigfile_roundtrip_empty() {
        let sf = SigFile::new("emptylib");
        let bytes = sf.serialize();
        let parsed = SigFile::deserialize(&bytes).unwrap();
        assert_eq!(parsed.header.lib_name, "emptylib");
        assert_eq!(parsed.module_count(), 0);
    }

    #[test]
    fn test_sigfile_roundtrip_with_modules() {
        let mut sf = SigFile::new("testlib");
        sf.add_module(SigModule::new("func_a", vec![0x55, 0x48], 0x1111, 2, 20));
        sf.add_module(SigModule::new("func_b", vec![0x53, 0x55], 0x2222, 2, 30));
        let bytes = sf.serialize();
        let parsed = SigFile::deserialize(&bytes).unwrap();
        assert_eq!(parsed.module_count(), 2);
        assert_eq!(parsed.modules[0].name, "func_a");
        assert_eq!(parsed.modules[1].name, "func_b");
    }

    // ── pat_records_to_sig ────────────────────────────────────────────────────

    #[test]
    fn test_pat_to_sig_conversion() {
        let records = vec![
            PatRecord::new("558BEC", 0x1234, 3, 16, "main"),
            PatRecord::new("5541", 0x5678, 2, 32, "helper"),
        ];
        let sig = pat_records_to_sig(&records, "mylib");
        assert_eq!(sig.module_count(), 2);
        assert_eq!(sig.modules[0].name, "main");
        assert_eq!(sig.modules[1].name, "helper");
    }

    #[test]
    fn test_pat_to_sig_bytes_parsed() {
        let records = vec![PatRecord::new("558BEC", 0, 0, 3, "fn")];
        let sig = pat_records_to_sig(&records, "lib");
        assert_eq!(sig.modules[0].first_bytes, vec![0x55, 0x8B, 0xEC]);
    }
}
