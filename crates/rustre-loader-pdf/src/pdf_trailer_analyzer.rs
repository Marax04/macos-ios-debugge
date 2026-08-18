//! PDF trailer analysis — parse the trailer dictionary and extract structural
//! metadata such as document ID, encryption parameters, and root / info refs.

use std::fmt;

// ─── EncryptionAlgorithm ──────────────────────────────────────────────────────

/// PDF encryption algorithm identifiers (from the `/V` entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    /// V=1 — 40-bit RC4.
    Rc4_40,
    /// V=2 — variable-length RC4 (40–128 bit).
    Rc4Variable,
    /// V=3 — unpublished.
    Unpublished,
    /// V=4 — AES-128 (PDF 1.5+).
    Aes128,
    /// V=5 — AES-256 (PDF 1.7 ext. level 3+).
    Aes256,
    /// Unknown / unsupported.
    Unknown(i64),
}

impl EncryptionAlgorithm {
    /// Derive from the `/V` integer.
    #[must_use]
    pub const fn from_v(v: i64) -> Self {
        match v {
            1 => Self::Rc4_40,
            2 => Self::Rc4Variable,
            3 => Self::Unpublished,
            4 => Self::Aes128,
            5 => Self::Aes256,
            n => Self::Unknown(n),
        }
    }

    /// Returns `true` if the algorithm is considered strong (AES).
    #[must_use]
    pub const fn is_strong(&self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes256)
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rc4_40 => write!(f, "RC4-40"),
            Self::Rc4Variable => write!(f, "RC4-variable"),
            Self::Unpublished => write!(f, "unpublished"),
            Self::Aes128 => write!(f, "AES-128"),
            Self::Aes256 => write!(f, "AES-256"),
            Self::Unknown(n) => write!(f, "unknown(V={n})"),
        }
    }
}

// ─── EncryptionInfo ───────────────────────────────────────────────────────────

/// Encryption metadata extracted from the `/Encrypt` dictionary.
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,
    /// Key length in bits (from `/Length`).
    pub key_length_bits: u32,
    /// Filter name (typically `Standard`).
    pub filter: String,
    /// Revision number (`/R`).
    pub revision: u32,
    /// `P` permissions flags.
    pub permissions: i64,
    /// Whether metadata is encrypted (`/EncryptMetadata`).
    pub encrypt_metadata: bool,
    /// `O` (owner password hash, 32 or 40 bytes).
    pub owner_hash: Vec<u8>,
    /// `U` (user password hash, 32 or 40 bytes).
    pub user_hash: Vec<u8>,
}

impl EncryptionInfo {
    /// Returns `true` if the document allows printing.
    #[must_use]
    pub const fn allows_printing(&self) -> bool {
        self.permissions & (1 << 2) != 0
    }

    /// Returns `true` if the document allows modification.
    #[must_use]
    pub const fn allows_modification(&self) -> bool {
        self.permissions & (1 << 3) != 0
    }

    /// Returns `true` if the document allows copying.
    #[must_use]
    pub const fn allows_copying(&self) -> bool {
        self.permissions & (1 << 4) != 0
    }
}

impl fmt::Display for EncryptionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Encrypted({}, {} bits, rev={})",
            self.algorithm, self.key_length_bits, self.revision
        )
    }
}

// ─── DocumentId ───────────────────────────────────────────────────────────────

/// The PDF document ID pair (`/ID` in the trailer dictionary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentId {
    /// First element — permanent ID assigned at creation.
    pub permanent: Vec<u8>,
    /// Second element — changes each time the document is modified.
    pub changing: Vec<u8>,
}

impl DocumentId {
    /// Format the permanent ID as a lowercase hex string.
    #[must_use]
    pub fn permanent_hex(&self) -> String {
        self.permanent.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Format the changing ID as a lowercase hex string.
    #[must_use]
    pub fn changing_hex(&self) -> String {
        self.changing.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for DocumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}; {}]", self.permanent_hex(), self.changing_hex())
    }
}

// ─── TrailerInfo ─────────────────────────────────────────────────────────────

/// Structural information extracted from a PDF trailer.
#[derive(Debug, Clone, Default)]
pub struct TrailerInfo {
    /// `/Size` — total number of objects including free objects.
    pub size: u32,
    /// `/Root` — indirect reference to the document catalog.
    pub root_ref: Option<(u32, u32)>,
    /// `/Info` — indirect reference to the document information dictionary.
    pub info_ref: Option<(u32, u32)>,
    /// `/Prev` — byte offset of the previous xref table (for incremental updates).
    pub prev_xref_offset: Option<u64>,
    /// `/XRefStm` — byte offset of a hybrid xref stream.
    pub xref_stm_offset: Option<u64>,
    /// Document ID pair.
    pub document_id: Option<DocumentId>,
    /// Encryption info (only present if `/Encrypt` found).
    pub encryption: Option<EncryptionInfo>,
    /// Number of incremental updates detected (via `/Prev` chain length).
    pub incremental_update_count: u32,
}

impl TrailerInfo {
    /// Returns `true` if the document is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Returns `true` if the document has multiple revisions (incremental updates).
    #[must_use]
    pub const fn has_incremental_updates(&self) -> bool {
        self.incremental_update_count > 0
    }

    /// Returns the root object number, or `None`.
    #[must_use]
    pub fn root_obj_num(&self) -> Option<u32> {
        self.root_ref.map(|(n, _)| n)
    }

    /// Returns the info object number, or `None`.
    #[must_use]
    pub fn info_obj_num(&self) -> Option<u32> {
        self.info_ref.map(|(n, _)| n)
    }
}

impl fmt::Display for TrailerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trailer(size={}, root={:?}, enc={})",
            self.size,
            self.root_ref,
            self.is_encrypted()
        )
    }
}

// ─── PdfTrailerAnalyzer ───────────────────────────────────────────────────────

/// Analyzes PDF trailer bytes and extracts structural metadata.
pub struct PdfTrailerAnalyzer<'a> {
    data: &'a [u8],
}

impl<'a> PdfTrailerAnalyzer<'a> {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns `true` if the PDF data contains an encryption dictionary.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.data.windows(8).any(|w| w == b"/Encrypt")
    }

    /// Locate the last trailer dictionary bytes and extract metadata.
    #[must_use]
    pub fn analyze(&self) -> TrailerInfo {
        let mut info = TrailerInfo::default();

        // Find the last "trailer" keyword.
        let trailer_pos = self.find_last_keyword(b"trailer");
        if let Some(pos) = trailer_pos {
            self.parse_trailer_dict(&mut info, pos);
        }

        // Count incremental updates by scanning for `startxref`.
        let startxref_count = self
            .data
            .windows(9)
            .filter(|w| *w == b"startxref")
            .count();
        info.incremental_update_count = startxref_count.saturating_sub(1) as u32;

        // Detect encryption.
        if self.is_encrypted() {
            info.encryption = self.extract_encryption_info();
        }

        // Extract document ID if present.
        info.document_id = self.extract_document_id();

        info
    }

    fn find_last_keyword(&self, keyword: &[u8]) -> Option<usize> {
        self.data
            .windows(keyword.len())
            .enumerate()
            .filter(|(_, w)| *w == keyword)
            .map(|(i, _)| i)
            .next_back()
    }

    fn parse_trailer_dict(&self, info: &mut TrailerInfo, trailer_pos: usize) {
        let start = trailer_pos + 7; // skip "trailer"
        // Skip whitespace to '<<'.
        let mut pos = start;
        while pos < self.data.len() && matches!(self.data[pos], b' ' | b'\t' | b'\n' | b'\r') {
            pos += 1;
        }
        if self.data.get(pos..pos + 2) != Some(b"<<") {
            return;
        }
        let dict_end = find_dict_end(self.data, pos);
        let dict_bytes = &self.data[pos..dict_end.min(self.data.len())];

        // Extract /Size.
        if let Some(n) = extract_int_value(dict_bytes, b"/Size") {
            info.size = n as u32;
        }

        // Extract /Root indirect ref.
        if let Some((obj, gen_val)) = extract_indirect_ref(dict_bytes, b"/Root") {
            info.root_ref = Some((obj, gen_val));
        }

        // Extract /Info indirect ref.
        if let Some((obj, gen_val)) = extract_indirect_ref(dict_bytes, b"/Info") {
            info.info_ref = Some((obj, gen_val));
        }

        // Extract /Prev.
        if let Some(n) = extract_int_value(dict_bytes, b"/Prev") {
            info.prev_xref_offset = Some(n as u64);
        }

        // Extract /XRefStm.
        if let Some(n) = extract_int_value(dict_bytes, b"/XRefStm") {
            info.xref_stm_offset = Some(n as u64);
        }
    }

    fn extract_encryption_info(&self) -> Option<EncryptionInfo> {
        // Find the /Encrypt dictionary.
        let encrypt_pos = self.data.windows(8).position(|w| w == b"/Encrypt")?;
        let after = &self.data[encrypt_pos + 8..];
        // Skip to the dictionary start.
        let dict_start = after.windows(2).position(|w| w == b"<<")?;
        let dict_bytes = &after[dict_start..];

        let v = extract_int_from_slice(dict_bytes, b"/V").unwrap_or(1);
        let key_length = extract_int_from_slice(dict_bytes, b"/Length").unwrap_or(40) as u32;
        let revision = extract_int_from_slice(dict_bytes, b"/R").unwrap_or(2) as u32;
        let permissions = extract_int_from_slice(dict_bytes, b"/P").unwrap_or(-1);
        let filter = extract_name_from_slice(dict_bytes, b"/Filter")
            .unwrap_or_else(|| "Standard".to_string());
        let encrypt_metadata = extract_bool_from_slice(dict_bytes, b"/EncryptMetadata")
            .unwrap_or(true);

        Some(EncryptionInfo {
            algorithm: EncryptionAlgorithm::from_v(v),
            key_length_bits: key_length,
            filter,
            revision,
            permissions,
            encrypt_metadata,
            owner_hash: Vec::new(),
            user_hash: Vec::new(),
        })
    }

    fn extract_document_id(&self) -> Option<DocumentId> {
        // Find /ID [ ... ]
        let id_pos = self
            .data
            .windows(3)
            .position(|w| w == b"/ID")?;
        let after = &self.data[id_pos + 3..];
        let bracket = after.iter().position(|&b| b == b'[')?;
        let array_slice = &after[bracket + 1..];
        // Extract two hex strings <...><...>.
        let mut strings = Vec::new();
        let mut pos = 0;
        while pos < array_slice.len() && strings.len() < 2 {
            let b = array_slice[pos];
            if b == b']' {
                break;
            }
            if b == b'<' {
                pos += 1;
                let end = array_slice[pos..].iter().position(|&b| b == b'>')?;
                let hex = &array_slice[pos..pos + end];
                let decoded: Vec<u8> = hex
                    .chunks(2)
                    .filter_map(|c| {
                        let s = std::str::from_utf8(c).ok()?;
                        u8::from_str_radix(s.trim(), 16).ok()
                    })
                    .collect();
                strings.push(decoded);
                pos += end + 1;
            } else {
                pos += 1;
            }
        }
        if strings.len() == 2 {
            Some(DocumentId {
                permanent: strings.remove(0),
                changing: strings.remove(0),
            })
        } else {
            None
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn find_dict_end(data: &[u8], start: usize) -> usize {
    let mut depth = 0i32;
    let mut pos = start;
    while pos + 1 < data.len() {
        if data[pos] == b'<' && data[pos + 1] == b'<' {
            depth += 1;
            pos += 2;
        } else if data[pos] == b'>' && data[pos + 1] == b'>' {
            depth -= 1;
            pos += 2;
            if depth == 0 {
                return pos;
            }
        } else {
            pos += 1;
        }
    }
    data.len()
}

fn extract_int_value(dict: &[u8], key: &[u8]) -> Option<i64> {
    let pos = dict.windows(key.len()).position(|w| w == key)?;
    extract_int_from_slice(&dict[pos + key.len()..], &[])
}

fn extract_int_from_slice(data: &[u8], key: &[u8]) -> Option<i64> {
    let start = if key.is_empty() {
        0
    } else {
        data.windows(key.len()).position(|w| w == key)? + key.len()
    };
    let slice = &data[start..];
    let skip = slice.iter().take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')).count();
    let num_slice = &slice[skip..];
    let neg = num_slice.first() == Some(&b'-');
    let start_digit = if neg { 1 } else { 0 };
    let digits: &[u8] = &num_slice[start_digit..];
    let len = digits.iter().take_while(|&&b| b.is_ascii_digit()).count();
    if len == 0 {
        return None;
    }
    let s = std::str::from_utf8(&digits[..len]).ok()?;
    let n: i64 = s.parse().ok()?;
    Some(if neg { -n } else { n })
}

fn extract_indirect_ref(dict: &[u8], key: &[u8]) -> Option<(u32, u32)> {
    let pos = dict.windows(key.len()).position(|w| w == key)?;
    let after = &dict[pos + key.len()..];
    let skip = after.iter().take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')).count();
    let rest = &after[skip..];
    // Parse "N G R"
    let n1_len = rest.iter().take_while(|&&b| b.is_ascii_digit()).count();
    if n1_len == 0 {
        return None;
    }
    let n1: u32 = std::str::from_utf8(&rest[..n1_len]).ok()?.parse().ok()?;
    let rest2 = &rest[n1_len..];
    let skip2 = rest2.iter().take_while(|&&b| b == b' ').count();
    let rest3 = &rest2[skip2..];
    let n2_len = rest3.iter().take_while(|&&b| b.is_ascii_digit()).count();
    let n2: u32 = if n2_len > 0 {
        std::str::from_utf8(&rest3[..n2_len]).ok()?.parse().ok()?
    } else {
        0
    };
    Some((n1, n2))
}

fn extract_name_from_slice(data: &[u8], key: &[u8]) -> Option<String> {
    let pos = data.windows(key.len()).position(|w| w == key)?;
    let after = &data[pos + key.len()..];
    let skip = after.iter().take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')).count();
    let rest = &after[skip..];
    if rest.first() != Some(&b'/') {
        return None;
    }
    let name_bytes = &rest[1..];
    let end = name_bytes
        .iter()
        .take_while(|&&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>'))
        .count();
    Some(String::from_utf8_lossy(&name_bytes[..end]).into_owned())
}

fn extract_bool_from_slice(data: &[u8], key: &[u8]) -> Option<bool> {
    let pos = data.windows(key.len()).position(|w| w == key)?;
    let after = &data[pos + key.len()..];
    let skip = after.iter().take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')).count();
    let rest = &after[skip..];
    if rest.starts_with(b"true") {
        Some(true)
    } else if rest.starts_with(b"false") {
        Some(false)
    } else {
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pdf_with_trailer(encrypt: bool) -> Vec<u8> {
        let mut d: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n".to_vec();
        let xref_off = d.len();
        d.extend_from_slice(b"xref\n0 2\n0000000000 65535 f \r\n0000000009 00000 n \r\n");
        if encrypt {
            d.extend_from_slice(
                b"trailer\n<<\n/Size 2\n/Root 1 0 R\n/Encrypt << /Filter /Standard /V 2 /Length 128 /R 3 /P -3904 >>\n>>\n",
            );
        } else {
            d.extend_from_slice(b"trailer\n<<\n/Size 2\n/Root 1 0 R\n/Info 2 0 R\n>>\n");
        }
        d.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        d
    }

    #[test]
    fn test_is_encrypted_false() {
        let data = make_pdf_with_trailer(false);
        let analyzer = PdfTrailerAnalyzer::new(&data);
        assert!(!analyzer.is_encrypted());
    }

    #[test]
    fn test_is_encrypted_true() {
        let data = make_pdf_with_trailer(true);
        let analyzer = PdfTrailerAnalyzer::new(&data);
        assert!(analyzer.is_encrypted());
    }

    #[test]
    fn test_analyze_size() {
        let data = make_pdf_with_trailer(false);
        let info = PdfTrailerAnalyzer::new(&data).analyze();
        assert_eq!(info.size, 2);
    }

    #[test]
    fn test_analyze_root_ref() {
        let data = make_pdf_with_trailer(false);
        let info = PdfTrailerAnalyzer::new(&data).analyze();
        assert_eq!(info.root_ref, Some((1, 0)));
    }

    #[test]
    fn test_analyze_info_ref() {
        let data = make_pdf_with_trailer(false);
        let info = PdfTrailerAnalyzer::new(&data).analyze();
        assert_eq!(info.info_ref, Some((2, 0)));
    }

    #[test]
    fn test_analyze_encryption_present() {
        let data = make_pdf_with_trailer(true);
        let info = PdfTrailerAnalyzer::new(&data).analyze();
        assert!(info.is_encrypted());
        let enc = info.encryption.unwrap();
        assert_eq!(enc.algorithm, EncryptionAlgorithm::Rc4Variable);
        assert_eq!(enc.key_length_bits, 128);
    }

    #[test]
    fn test_incremental_update_count() {
        let mut data = make_pdf_with_trailer(false);
        // Append a second revision.
        data.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \r\ntrailer\n<<\n/Size 2\n>>\nstartxref\n0\n%%EOF\n");
        let info = PdfTrailerAnalyzer::new(&data).analyze();
        assert!(info.incremental_update_count >= 1);
    }

    #[test]
    fn test_trailer_info_display() {
        let info = TrailerInfo { size: 10, root_ref: Some((1, 0)), ..Default::default() };
        let s = info.to_string();
        assert!(s.contains("10"));
    }

    #[test]
    fn test_encryption_algorithm_strong() {
        assert!(!EncryptionAlgorithm::Rc4_40.is_strong());
        assert!(EncryptionAlgorithm::Aes128.is_strong());
        assert!(EncryptionAlgorithm::Aes256.is_strong());
    }

    #[test]
    fn test_document_id_hex() {
        let id = DocumentId {
            permanent: vec![0xDE, 0xAD],
            changing: vec![0xBE, 0xEF],
        };
        assert_eq!(id.permanent_hex(), "dead");
        assert_eq!(id.changing_hex(), "beef");
    }
}
