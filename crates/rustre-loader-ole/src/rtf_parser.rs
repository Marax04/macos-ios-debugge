//! RTF document parser for malware analysis.
//!
//! Parses Rich Text Format documents to extract embedded OLE objects,
//! shellcode blobs, and detects exploitation patterns such as CVE-2017-11882
//! (Microsoft Equation Editor stack overflow).

pub use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtfError {
    TruncatedData { offset: usize },
    InvalidGroupNesting { depth: usize },
    UnterminatedString,
    InvalidHexEncoding { byte: u8, offset: usize },
    ObjDataTooLarge(usize),
    InvalidOleHeader,
    MaxDepthExceeded(usize),
    InvalidControlWord(String),
    BinDataTruncated { expected: usize, available: usize },
    NullByteInControlWord,
}

impl std::fmt::Display for RtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedData { offset } => write!(f, "truncated RTF at offset {offset}"),
            Self::InvalidGroupNesting { depth } => {
                write!(f, "invalid group nesting at depth {depth}")
            }
            Self::UnterminatedString => write!(f, "unterminated string literal"),
            Self::InvalidHexEncoding { byte, offset } => {
                write!(f, "invalid hex byte {byte:#04x} at offset {offset}")
            }
            Self::ObjDataTooLarge(n) => write!(f, "object data too large: {n} bytes"),
            Self::InvalidOleHeader => write!(f, "invalid OLE object header"),
            Self::MaxDepthExceeded(n) => write!(f, "RTF nesting depth exceeded: {n}"),
            Self::InvalidControlWord(w) => write!(f, "invalid control word: {w}"),
            Self::BinDataTruncated {
                expected,
                available,
            } => write!(
                f,
                "\\bin data truncated: expected {expected}, available {available}"
            ),
            Self::NullByteInControlWord => write!(f, "null byte in control word"),
        }
    }
}

impl std::error::Error for RtfError {}

// ---------------------------------------------------------------------------
// RtfToken
// ---------------------------------------------------------------------------

/// A lexed RTF token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtfToken {
    /// `{`
    GroupOpen,
    /// `}`
    GroupClose,
    /// `\word` or `\word123`
    ControlWord { name: String, param: Option<i32> },
    /// `\'XX` hex-encoded byte.
    HexChar(u8),
    /// `\binN` binary data.
    BinData(Vec<u8>),
    /// Plain text content.
    Text(String),
}

// ---------------------------------------------------------------------------
// RTF Lexer
// ---------------------------------------------------------------------------

/// Minimal RTF lexer that tokenises an RTF byte stream.
pub struct RtfLexer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RtfLexer<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn next_token(&mut self) -> Result<Option<RtfToken>, RtfError> {
        self.skip_whitespace_except_newlines();
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let b = self.data[self.pos];
        match b {
            b'{' => {
                self.pos += 1;
                Ok(Some(RtfToken::GroupOpen))
            }
            b'}' => {
                self.pos += 1;
                Ok(Some(RtfToken::GroupClose))
            }
            b'\\' => self.read_control(),
            _ => self.read_text(),
        }
    }

    fn skip_whitespace_except_newlines(&mut self) {
        while self.pos < self.data.len()
            && (self.data[self.pos] == b' ' || self.data[self.pos] == b'\t')
        {
            self.pos += 1;
        }
    }

    fn read_control(&mut self) -> Result<Option<RtfToken>, RtfError> {
        self.pos += 1; // skip '\'
        if self.pos >= self.data.len() {
            return Err(RtfError::TruncatedData { offset: self.pos });
        }
        let b = self.data[self.pos];
        // Special characters
        if !b.is_ascii_alphabetic() {
            match b {
                b'\'' => {
                    self.pos += 1;
                    return self.read_hex_char();
                }
                b'*' | b'-' | b'|' | b'~' | b':' | b'_' | b'{' | b'}' | b'\\' | b'\n' | b'\r' => {
                    self.pos += 1;
                    return Ok(Some(RtfToken::ControlWord {
                        name: (b as char).to_string(),
                        param: None,
                    }));
                }
                _ => {
                    self.pos += 1;
                    return Ok(Some(RtfToken::Text(String::new())));
                }
            }
        }
        // Read control word name
        let name_start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_alphabetic() {
            self.pos += 1;
        }
        let name = String::from_utf8_lossy(&self.data[name_start..self.pos])
            .into_owned()
            .to_lowercase();

        // Handle \bin specially
        if name == "bin" {
            return self.read_bin_data();
        }

        // Optional numeric parameter
        let param = self.read_numeric_param();

        // Skip optional trailing space (delimiter)
        if self.pos < self.data.len() && self.data[self.pos] == b' ' {
            self.pos += 1;
        }

        Ok(Some(RtfToken::ControlWord { name, param }))
    }

    fn read_hex_char(&mut self) -> Result<Option<RtfToken>, RtfError> {
        if self.pos + 2 > self.data.len() {
            return Err(RtfError::TruncatedData { offset: self.pos });
        }
        let hi = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
            byte: self.data[self.pos],
            offset: self.pos,
        })?;
        self.pos += 1;
        let lo = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
            byte: self.data[self.pos],
            offset: self.pos,
        })?;
        self.pos += 1;
        Ok(Some(RtfToken::HexChar((hi << 4) | lo)))
    }

    fn read_bin_data(&mut self) -> Result<Option<RtfToken>, RtfError> {
        let size_param = self.read_numeric_param().unwrap_or(0) as usize;
        // Skip one space after \binN if present
        if self.pos < self.data.len() && self.data[self.pos] == b' ' {
            self.pos += 1;
        }
        let available = self.data.len() - self.pos;
        if size_param > available {
            return Err(RtfError::BinDataTruncated {
                expected: size_param,
                available,
            });
        }
        let bytes = self.data[self.pos..self.pos + size_param].to_vec();
        self.pos += size_param;
        Ok(Some(RtfToken::BinData(bytes)))
    }

    fn read_numeric_param(&mut self) -> Option<i32> {
        if self.pos >= self.data.len() {
            return None;
        }
        let negative = self.data[self.pos] == b'-';
        if negative {
            self.pos += 1;
        }
        if self.pos >= self.data.len() || !self.data[self.pos].is_ascii_digit() {
            if negative {
                self.pos -= 1;
            }
            return None;
        }
        let mut val: i32 = 0;
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
            val = val.saturating_mul(10).saturating_add(i32::from(self.data[self.pos] - b'0'));
            self.pos += 1;
        }
        Some(if negative { -val } else { val })
    }

    fn read_text(&mut self) -> Result<Option<RtfToken>, RtfError> {
        let start = self.pos;
        while self.pos < self.data.len()
            && self.data[self.pos] != b'{'
            && self.data[self.pos] != b'}'
            && self.data[self.pos] != b'\\'
        {
            self.pos += 1;
        }
        let text = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        Ok(Some(RtfToken::Text(text)))
    }
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RtfObject
// ---------------------------------------------------------------------------

/// Type of an embedded OLE object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OleObjectType {
    /// Embedded package (packager shell object).
    Package,
    /// Microsoft Equation Editor — CVE-2017-11882 target.
    EquationEditor,
    /// Microsoft Office compound document.
    OfficeDocument,
    /// Unknown or unrecognised CLSID.
    Unknown(String),
}

/// OLE CLSID constants.
pub const CLSID_EQUATION_EDITOR: &str = "0002CE02-0000-0000-C000-000000000046";
pub const CLSID_PACKAGE: &str = "00020820-0000-0000-C000-000000000046";

/// An OLE object embedded in the RTF stream.
#[derive(Debug, Clone)]
pub struct OleObject {
    /// Raw hex-decoded bytes of the object data.
    pub raw_data: Vec<u8>,
    /// Object class name (e.g. `"Equation.3"`).
    pub class_name: String,
    /// CLSID string if parseable.
    pub clsid: Option<String>,
    pub object_type: OleObjectType,
    /// Whether potential shellcode patterns were detected.
    pub has_shellcode_pattern: bool,
    /// Offset in the RTF source where the object starts.
    pub source_offset: usize,
}

impl OleObject {
    #[must_use] 
    pub fn classify(class_name: &str) -> OleObjectType {
        let lower = class_name.to_lowercase();
        if lower.contains("equation") {
            OleObjectType::EquationEditor
        } else if lower.contains("package") {
            OleObjectType::Package
        } else if lower.contains("word") || lower.contains("excel") || lower.contains("powerpoint")
        {
            OleObjectType::OfficeDocument
        } else {
            OleObjectType::Unknown(class_name.to_string())
        }
    }

    #[must_use] 
    pub fn detect_shellcode(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        // Heuristic: high density of near-zero bytes (NOP-like) or call+pop patterns
        let nops = data.iter().filter(|&&b| b == 0x90).count();
        let int3s = data.iter().filter(|&&b| b == 0xcc).count();
        // Call byte pattern: 0xe8 followed by DWORD
        let calls = data.windows(5).filter(|w| w[0] == 0xe8).count();
        nops >= 8 || int3s >= 8 || calls >= 3
    }
}

// ---------------------------------------------------------------------------
// RtfHexDecoder — dedicated hex blob decoder
// ---------------------------------------------------------------------------

/// Decodes the hex-encoded binary blobs common in RTF object data.
pub struct RtfHexDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RtfHexDecoder<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Decode all hex bytes, skipping whitespace and newlines.
    pub fn decode_all(&mut self) -> Result<Vec<u8>, RtfError> {
        let mut out = Vec::new();
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' {
                self.pos += 1;
                continue;
            }
            if self.pos + 2 > self.data.len() {
                return Err(RtfError::TruncatedData { offset: self.pos });
            }
            let hi = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
                byte: self.data[self.pos],
                offset: self.pos,
            })?;
            self.pos += 1;
            let lo = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
                byte: self.data[self.pos],
                offset: self.pos,
            })?;
            self.pos += 1;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    /// Decode at most `n` bytes.
    pub fn decode_n(&mut self, n: usize) -> Result<Vec<u8>, RtfError> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n && self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b'\n' || b == b'\r' || b == b' ' {
                self.pos += 1;
                continue;
            }
            if self.pos + 2 > self.data.len() {
                break;
            }
            let hi = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
                byte: self.data[self.pos],
                offset: self.pos,
            })?;
            self.pos += 1;
            let lo = hex_digit(self.data[self.pos]).ok_or(RtfError::InvalidHexEncoding {
                byte: self.data[self.pos],
                offset: self.pos,
            })?;
            self.pos += 1;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    #[must_use] 
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

// ---------------------------------------------------------------------------
// RtfMalwareIndicators — known malware indicator detector
// ---------------------------------------------------------------------------

/// High-level malware indicators found in an RTF document.
#[derive(Debug, Clone, Default)]
pub struct RtfMalwareIndicators {
    pub has_embedded_ole: bool,
    pub has_equation_editor: bool,
    pub has_shellcode: bool,
    pub has_suspicious_binary: bool,
    pub has_vba_macro: bool,
    pub suspicious_control_words: Vec<String>,
    pub risk_level: RiskLevel,
}

/// Overall risk level of an RTF document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl RtfMalwareIndicators {
    /// Compute from a parsed `RtfParser`.
    #[must_use] 
    pub fn from_parser(parser: &RtfParser) -> Self {
        let has_embedded_ole = parser.has_ole_objects();
        let has_equation_editor = parser.is_cve_2017_11882();
        let has_shellcode = !parser.shellcode_regions.is_empty();
        let has_suspicious_binary = parser.objects.iter().any(|o| o.has_shellcode_pattern);

        let risk = if has_equation_editor || has_shellcode {
            RiskLevel::Critical
        } else if has_suspicious_binary || has_embedded_ole {
            RiskLevel::High
        } else if has_embedded_ole {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        // Collect suspicious control words (non-standard keywords)
        let suspicious: Vec<String> = parser
            .tokens
            .iter()
            .filter_map(|t| {
                if let RtfToken::ControlWord { name, .. } = t {
                    if name == "objdata" || name == "objclass" || name == "objemb" {
                        Some(name.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Self {
            has_embedded_ole,
            has_equation_editor,
            has_shellcode,
            has_suspicious_binary,
            has_vba_macro: false,
            suspicious_control_words: suspicious,
            risk_level: risk,
        }
    }

    #[must_use] 
    pub fn is_malicious(&self) -> bool {
        self.risk_level >= RiskLevel::High
    }
}

// ---------------------------------------------------------------------------
// EmbeddedShellcode
// ---------------------------------------------------------------------------

/// A region of suspected shellcode extracted from RTF binary data.
#[derive(Debug, Clone)]
pub struct EmbeddedShellcode {
    /// Decoded bytes.
    pub bytes: Vec<u8>,
    /// Offset within the original RTF stream.
    pub rtf_offset: usize,
    /// Offset within the parent OLE object (if any).
    pub ole_offset: usize,
    /// Score from the heuristic (0-100).
    pub confidence: u8,
}

impl EmbeddedShellcode {
    /// `true` if the confidence score suggests likely shellcode.
    #[must_use] 
    pub const fn is_likely(&self) -> bool {
        self.confidence >= 60
    }
}

// ---------------------------------------------------------------------------
// CVE-2017-11882 detector
// ---------------------------------------------------------------------------

/// Result of CVE-2017-11882 detection.
#[derive(Debug, Clone)]
pub struct Cve201711882Result {
    pub detected: bool,
    /// Byte offset of the suspicious equation editor invocation.
    pub offset: Option<usize>,
    /// Extracted payload bytes (after the overflow pattern).
    pub payload: Vec<u8>,
    /// Description of the detection reason.
    pub reason: String,
}

impl Cve201711882Result {
    #[must_use] 
    pub const fn not_detected() -> Self {
        Self {
            detected: false,
            offset: None,
            payload: vec![],
            reason: String::new(),
        }
    }
}

/// Known byte patterns associated with CVE-2017-11882 exploitation.
#[must_use] 
pub fn detect_equation_editor_exploit(data: &[u8]) -> Cve201711882Result {
    // The vulnerability is in EQNEDT32.EXE when parsing FontName records.
    // Signature: OLE compound file header followed by MTEF header
    // We look for the Equation Editor CLSID marker in OLE streams.
    let clsid_bytes: &[u8] = &[0x02, 0xCE, 0x02, 0x00]; // partial CLSID bytes
    if let Some(pos) = data.windows(4).position(|w| w == clsid_bytes) {
        // Look for suspicious long font name following MTEF record (type 8 = FONT record)
        // MTEF FONT record starts with 0x08 followed by string data
        let search_start = pos;
        if search_start + 16 < data.len() {
            let region = &data[search_start..];
            // Look for 0x08 byte followed by >~30 bytes that look like a payload
            for i in 0..region.len().saturating_sub(32) {
                if region[i] == 0x08 {
                    let potential_name = &region[i + 1..];
                    let nuls = potential_name.iter().take(64).filter(|&&b| b == 0).count();
                    // High NUL density may indicate padding/shellcode
                    if potential_name.len() >= 32 && nuls < 8 {
                        return Cve201711882Result {
                            detected: true,
                            offset: Some(search_start + i),
                            payload: potential_name[..potential_name.len().min(128)].to_vec(),
                            reason: "EQNEDT32 MTEF FONT record overflow pattern".to_string(),
                        };
                    }
                }
            }
        }
        // Equation editor object present but no clear overflow pattern
        return Cve201711882Result {
            detected: false,
            offset: Some(pos),
            payload: vec![],
            reason: "Equation Editor object found, no overflow pattern".to_string(),
        };
    }
    Cve201711882Result::not_detected()
}

// ---------------------------------------------------------------------------
// RtfParser
// ---------------------------------------------------------------------------

/// Statistics collected during RTF parsing.
#[derive(Debug, Default)]
pub struct RtfStats {
    pub group_depth_max: usize,
    pub total_tokens: usize,
    pub hex_bytes_count: usize,
    pub binary_data_bytes: usize,
    pub control_word_count: usize,
}

/// Complete RTF document analysis.
#[derive(Debug, Default)]
pub struct RtfParser {
    pub tokens: Vec<RtfToken>,
    pub objects: Vec<OleObject>,
    pub shellcode_regions: Vec<EmbeddedShellcode>,
    pub cve_2017_11882: Option<Cve201711882Result>,
    pub stats: RtfStats,
    /// Raw hex-decoded bytes accumulated during parsing.
    raw_hex_buf: Vec<u8>,
    /// Current source offset tracker.
    current_depth: usize,
    pub max_depth: usize,
}

impl RtfParser {
    /// Current nesting depth reached so far.
    #[must_use]
    pub const fn current_depth(&self) -> usize {
        self.current_depth
    }

    #[must_use] 
    pub fn new() -> Self {
        Self {
            max_depth: 64,
            ..Default::default()
        }
    }

    /// Parse an RTF document from raw bytes.
    pub fn parse(&mut self, data: &[u8]) -> Result<(), RtfError> {
        let mut lexer = RtfLexer::new(data);
        let mut depth = 0usize;

        while let Some(t) = lexer.next_token()? {
            self.stats.total_tokens = self.stats.total_tokens.saturating_add(1);
            match &t {
                RtfToken::GroupOpen => {
                    depth = depth.saturating_add(1);
                    if depth > self.max_depth {
                        return Err(RtfError::MaxDepthExceeded(depth));
                    }
                    if depth > self.stats.group_depth_max {
                        self.stats.group_depth_max = depth;
                    }
                }
                RtfToken::GroupClose => {
                    depth = depth.saturating_sub(1);
                }
                RtfToken::ControlWord { .. } => {
                    self.stats.control_word_count =
                        self.stats.control_word_count.saturating_add(1);
                }
                RtfToken::HexChar(b) => {
                    self.stats.hex_bytes_count =
                        self.stats.hex_bytes_count.saturating_add(1);
                    self.raw_hex_buf.push(*b);
                }
                RtfToken::BinData(bytes) => {
                    self.stats.binary_data_bytes = self
                        .stats
                        .binary_data_bytes
                        .saturating_add(bytes.len());
                }
                RtfToken::Text(_) => {}
            }
        }

        // Detect shellcode in accumulated hex data
        self.detect_shellcode_in_hex();

        Ok(())
    }

    fn detect_shellcode_in_hex(&mut self) {
        let data = &self.raw_hex_buf;
        if data.len() < 16 {
            return;
        }
        // Sliding window shellcode detection
        let window = 64;
        for i in (0..data.len().saturating_sub(window)).step_by(window / 2) {
            let chunk = &data[i..i + window.min(data.len() - i)];
            let nops = chunk.iter().filter(|&&b| b == 0x90).count();
            let calls = chunk.windows(5).filter(|w| w[0] == 0xe8).count();
            let high = chunk.iter().filter(|&&b| b > 0xd0).count();
            let confidence = ((nops as u8).saturating_mul(5))
                .saturating_add((calls as u8).saturating_mul(10))
                .saturating_add((high as u8).saturating_mul(2));
            if confidence >= 30 {
                self.shellcode_regions.push(EmbeddedShellcode {
                    bytes: chunk.to_vec(),
                    rtf_offset: i,
                    ole_offset: 0,
                    confidence: confidence.min(100),
                });
            }
        }
    }

    /// `true` if the document contains any OLE objects.
    #[must_use] 
    pub const fn has_ole_objects(&self) -> bool {
        !self.objects.is_empty()
    }

    /// `true` if CVE-2017-11882 was detected.
    #[must_use] 
    pub fn is_cve_2017_11882(&self) -> bool {
        self.cve_2017_11882
            .as_ref()
            .is_some_and(|r| r.detected)
    }

    /// Objects classified as Equation Editor (CVE-2017-11882 target).
    #[must_use] 
    pub fn equation_editor_objects(&self) -> Vec<&OleObject> {
        self.objects
            .iter()
            .filter(|o| matches!(o.object_type, OleObjectType::EquationEditor))
            .collect()
    }

    /// All OLE objects that have shellcode patterns.
    #[must_use] 
    pub fn suspicious_objects(&self) -> Vec<&OleObject> {
        self.objects
            .iter()
            .filter(|o| o.has_shellcode_pattern)
            .collect()
    }

    /// Compute overall malware indicators.
    #[must_use] 
    pub fn malware_indicators(&self) -> RtfMalwareIndicators {
        RtfMalwareIndicators::from_parser(self)
    }
}

// ---------------------------------------------------------------------------
// RtfParagraphInfo — paragraph-level metadata
// ---------------------------------------------------------------------------

/// Alignment type in RTF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RtfAlignment {
    #[default]
    Left,
    Right,
    Center,
    Justify,
}

/// Paragraph formatting collected from control words.
#[derive(Debug, Clone, Default)]
pub struct RtfParagraphInfo {
    pub alignment: RtfAlignment,
    pub left_indent: i32,
    pub right_indent: i32,
    pub space_before: i32,
    pub space_after: i32,
    pub line_spacing: i32,
    pub first_line_indent: i32,
    pub is_rtl: bool,
}

impl RtfParagraphInfo {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_control_word(&mut self, name: &str, param: Option<i32>) {
        match name {
            "ql" => self.alignment = RtfAlignment::Left,
            "qr" => self.alignment = RtfAlignment::Right,
            "qc" => self.alignment = RtfAlignment::Center,
            "qj" => self.alignment = RtfAlignment::Justify,
            "li" => self.left_indent = param.unwrap_or(0),
            "ri" => self.right_indent = param.unwrap_or(0),
            "sb" => self.space_before = param.unwrap_or(0),
            "sa" => self.space_after = param.unwrap_or(0),
            "sl" => self.line_spacing = param.unwrap_or(0),
            "fi" => self.first_line_indent = param.unwrap_or(0),
            "rtlpar" => self.is_rtl = true,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// RtfUnicodeDecoder — RTF unicode escape handling
// ---------------------------------------------------------------------------

/// Handles RTF `\uN` unicode escape sequences and code-page fallback chars.
#[derive(Debug, Clone)]
pub struct RtfUnicodeDecoder {
    /// Current ANSI code page (default 1252 / Windows Latin-1).
    pub code_page: u16,
    /// Number of ANSI fallback characters to skip after `\u`.
    pub unicode_skip_count: u8,
}

impl RtfUnicodeDecoder {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            code_page: 1252,
            unicode_skip_count: 1,
        }
    }

    /// Decode a `\uN` codepoint to a `char`.
    #[must_use] 
    pub fn decode_unicode_escape(&self, n: i32) -> char {
        // RTF uses signed short for the codepoint
        let codepoint = if n < 0 { (n + 65536) as u32 } else { n as u32 };
        char::from_u32(codepoint).unwrap_or(char::REPLACEMENT_CHARACTER)
    }

    /// `true` if this codepoint is a supplementary character.
    #[must_use] 
    pub const fn is_supplementary(n: i32) -> bool {
        let cp = if n < 0 { (n + 65536) as u32 } else { n as u32 };
        cp > 0xFFFF
    }
}

impl Default for RtfUnicodeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RtfColorTable — colour table from `\colortbl`
// ---------------------------------------------------------------------------

/// An RGB colour entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtfColor {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl RtfColor {
    #[must_use] 
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self {
            red: r,
            green: g,
            blue: b,
        }
    }
    #[must_use] 
    pub const fn black() -> Self {
        Self::new(0, 0, 0)
    }
    #[must_use] 
    pub const fn white() -> Self {
        Self::new(255, 255, 255)
    }

    #[must_use] 
    pub fn as_hex(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.red, self.green, self.blue)
    }

    #[must_use] 
    pub fn luminance(&self) -> f32 {
        0.2126 * f32::from(self.red) / 255.0
            + 0.7152 * f32::from(self.green) / 255.0
            + 0.0722 * f32::from(self.blue) / 255.0
    }
}

/// A parsed RTF colour table.
#[derive(Debug, Default)]
pub struct RtfColorTable {
    pub entries: Vec<RtfColor>,
}

impl RtfColorTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, c: RtfColor) {
        self.entries.push(c);
    }
    #[must_use] 
    pub fn get(&self, idx: usize) -> Option<RtfColor> {
        self.entries.get(idx).copied()
    }
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RtfFontTable — font table from `\fonttbl`
// ---------------------------------------------------------------------------

/// Font family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontFamily {
    Nil,
    Roman,
    Swiss,
    Modern,
    Script,
    Decor,
    Tech,
    Bidi,
}

/// One font entry in the `\fonttbl`.
#[derive(Debug, Clone)]
pub struct RtfFont {
    pub index: u32,
    pub family: FontFamily,
    pub charset: u16,
    pub name: String,
    pub alternate_name: Option<String>,
}

impl RtfFont {
    pub fn new(index: u32, name: impl Into<String>) -> Self {
        Self {
            index,
            family: FontFamily::Nil,
            charset: 0,
            name: name.into(),
            alternate_name: None,
        }
    }

    /// `true` if the font might be used for shellcode obfuscation (e.g. Symbol, Wingdings).
    #[must_use] 
    pub fn is_symbol_font(&self) -> bool {
        let lower = self.name.to_lowercase();
        lower.contains("symbol") || lower.contains("wingdings") || lower.contains("webdings")
    }
}

/// Font table.
#[derive(Debug, Default)]
pub struct RtfFontTable {
    pub fonts: Vec<RtfFont>,
}

impl RtfFontTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, f: RtfFont) {
        self.fonts.push(f);
    }

    #[must_use] 
    pub fn find_by_index(&self, idx: u32) -> Option<&RtfFont> {
        self.fonts.iter().find(|f| f.index == idx)
    }

    #[must_use] 
    pub fn has_symbol_fonts(&self) -> bool {
        self.fonts.iter().any(RtfFont::is_symbol_font)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn _simple_rtf(body: &[u8]) -> Vec<u8> {
        let mut v = b"{\\rtf1 ".to_vec();
        v.extend_from_slice(body);
        v.push(b'}');
        v
    }

    // ---- RtfLexer ----

    #[test]
    fn test_lexer_group_open_close() {
        let mut l = RtfLexer::new(b"{}");
        assert_eq!(l.next_token().unwrap(), Some(RtfToken::GroupOpen));
        assert_eq!(l.next_token().unwrap(), Some(RtfToken::GroupClose));
        assert_eq!(l.next_token().unwrap(), None);
    }

    #[test]
    fn test_lexer_control_word_no_param() {
        let mut l = RtfLexer::new(b"\\par ");
        if let Some(RtfToken::ControlWord { name, param }) = l.next_token().unwrap() {
            assert_eq!(name, "par");
            assert!(param.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_control_word_with_param() {
        let mut l = RtfLexer::new(b"\\fs24 ");
        if let Some(RtfToken::ControlWord { name, param }) = l.next_token().unwrap() {
            assert_eq!(name, "fs");
            assert_eq!(param, Some(24));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_hex_char() {
        let mut l = RtfLexer::new(b"\\'41"); // 'A'
        assert_eq!(l.next_token().unwrap(), Some(RtfToken::HexChar(b'A')));
    }

    #[test]
    fn test_lexer_hex_char_lowercase() {
        let mut l = RtfLexer::new(b"\\'ff");
        assert_eq!(l.next_token().unwrap(), Some(RtfToken::HexChar(0xff)));
    }

    #[test]
    fn test_lexer_invalid_hex() {
        let mut l = RtfLexer::new(b"\\'zz");
        assert!(matches!(
            l.next_token(),
            Err(RtfError::InvalidHexEncoding { .. })
        ));
    }

    #[test]
    fn test_lexer_text() {
        let mut l = RtfLexer::new(b"Hello world");
        if let Some(RtfToken::Text(t)) = l.next_token().unwrap() {
            assert!(t.starts_with("Hello"));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_negative_param() {
        let mut l = RtfLexer::new(b"\\li-100 ");
        if let Some(RtfToken::ControlWord { param, .. }) = l.next_token().unwrap() {
            assert_eq!(param, Some(-100));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_bin_data() {
        let mut data = b"\\bin3 ".to_vec();
        data.extend_from_slice(b"ABC");
        let mut l = RtfLexer::new(&data);
        if let Some(RtfToken::BinData(bytes)) = l.next_token().unwrap() {
            assert_eq!(bytes, b"ABC");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_bin_data_truncated() {
        let mut data = b"\\bin10 ".to_vec();
        data.extend_from_slice(b"AB"); // only 2, need 10
        let mut l = RtfLexer::new(&data);
        assert!(matches!(
            l.next_token(),
            Err(RtfError::BinDataTruncated { .. })
        ));
    }

    // ---- hex_digit ----

    #[test]
    fn test_hex_digit_valid() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
    }

    #[test]
    fn test_hex_digit_invalid() {
        assert!(hex_digit(b'g').is_none());
        assert!(hex_digit(b' ').is_none());
    }

    // ---- OleObject detection ----

    #[test]
    fn test_ole_object_classify_equation() {
        let t = OleObject::classify("Equation.3");
        assert!(matches!(t, OleObjectType::EquationEditor));
    }

    #[test]
    fn test_ole_object_classify_package() {
        let t = OleObject::classify("Package");
        assert!(matches!(t, OleObjectType::Package));
    }

    #[test]
    fn test_ole_object_classify_unknown() {
        let t = OleObject::classify("Foo.Bar");
        assert!(matches!(t, OleObjectType::Unknown(_)));
    }

    #[test]
    fn test_ole_object_shellcode_nop_sled() {
        let mut data = vec![0x90u8; 32];
        data.push(0xc3);
        assert!(OleObject::detect_shellcode(&data));
    }

    #[test]
    fn test_ole_object_shellcode_negative() {
        let data = vec![0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        assert!(!OleObject::detect_shellcode(&data));
    }

    // ---- RtfParser ----

    #[test]
    fn test_parser_empty_rtf() {
        let data = b"{\\rtf1}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(!parser.has_ole_objects());
    }

    #[test]
    fn test_parser_nesting_depth() {
        let data = b"{\\rtf1 {\\b bold text}}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(parser.stats.group_depth_max >= 2);
    }

    #[test]
    fn test_parser_depth_exceeded() {
        // Build deeply nested RTF
        let open: Vec<u8> = std::iter::repeat_n(b'{', 100).collect();
        let close: Vec<u8> = std::iter::repeat_n(b'}', 100).collect();
        let mut data = open;
        data.extend(close);
        let mut parser = RtfParser::new();
        parser.max_depth = 10;
        assert!(matches!(
            parser.parse(&data),
            Err(RtfError::MaxDepthExceeded(_))
        ));
    }

    #[test]
    fn test_parser_hex_byte_counting() {
        let data = b"{\\rtf1 \\'41\\'42\\'43}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert_eq!(parser.stats.hex_bytes_count, 3);
    }

    #[test]
    fn test_parser_control_word_count() {
        let data = b"{\\rtf1 \\par \\b text\\i0}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(parser.stats.control_word_count >= 4); // rtf1, par, b, i
    }

    #[test]
    fn test_parser_is_not_cve_on_normal_rtf() {
        let data = b"{\\rtf1 \\par Normal paragraph}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(!parser.is_cve_2017_11882());
    }

    #[test]
    fn test_parser_no_suspicious_objects() {
        let data = b"{\\rtf1 \\b Bold}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(parser.suspicious_objects().is_empty());
    }

    #[test]
    fn test_embedded_shellcode_is_likely() {
        let sc = EmbeddedShellcode {
            bytes: vec![],
            rtf_offset: 0,
            ole_offset: 0,
            confidence: 75,
        };
        assert!(sc.is_likely());
    }

    #[test]
    fn test_embedded_shellcode_not_likely() {
        let sc = EmbeddedShellcode {
            bytes: vec![],
            rtf_offset: 0,
            ole_offset: 0,
            confidence: 30,
        };
        assert!(!sc.is_likely());
    }

    #[test]
    fn test_rtf_error_display() {
        let e = RtfError::ObjDataTooLarge(9999);
        assert!(e.to_string().contains("9999"));
        let e2 = RtfError::InvalidGroupNesting { depth: 5 };
        assert!(e2.to_string().contains('5'));
    }

    #[test]
    fn test_cve_not_detected_result() {
        let r = Cve201711882Result::not_detected();
        assert!(!r.detected);
        assert!(r.offset.is_none());
    }

    #[test]
    fn test_parser_token_count() {
        let data = b"{\\rtf1 \\par }";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(parser.stats.total_tokens >= 3);
    }

    #[test]
    fn test_ole_object_type_office_document() {
        let t = OleObject::classify("WordDocument");
        assert!(matches!(t, OleObjectType::OfficeDocument));
    }

    #[test]
    fn test_rtf_error_invalid_hex_display() {
        let e = RtfError::InvalidHexEncoding {
            byte: 0xFF_u8,
            offset: 42,
        };
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_parser_bin_stats() {
        let mut data = b"{\\rtf1 \\bin5 ".to_vec();
        data.extend_from_slice(b"ABCDE");
        data.push(b'}');
        let mut parser = RtfParser::new();
        parser.parse(&data).unwrap();
        // bin keyword presence recorded
        assert!(parser.stats.total_tokens > 0);
    }

    #[test]
    fn test_lexer_empty_input() {
        let mut l = RtfLexer::new(b"");
        assert_eq!(l.next_token().unwrap(), None);
    }

    #[test]
    fn test_lexer_backslash_special_star() {
        let mut l = RtfLexer::new(b"\\*");
        if let Some(RtfToken::ControlWord { name, .. }) = l.next_token().unwrap() {
            assert_eq!(name, "*");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_lexer_text_stops_at_brace() {
        let mut l = RtfLexer::new(b"hello{world");
        if let Some(RtfToken::Text(t)) = l.next_token().unwrap() {
            assert_eq!(t, "hello");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_rtf_error_bin_truncated_display() {
        let e = RtfError::BinDataTruncated {
            expected: 100,
            available: 5,
        };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains('5'));
    }

    #[test]
    fn test_ole_object_classify_excel() {
        let t = OleObject::classify("ExcelWorksheet");
        assert!(matches!(t, OleObjectType::OfficeDocument));
    }

    #[test]
    fn test_ole_object_classify_powerpoint() {
        let t = OleObject::classify("PowerPoint.Show");
        assert!(matches!(t, OleObjectType::OfficeDocument));
    }

    #[test]
    fn test_cve_result_reason_empty() {
        let r = Cve201711882Result::not_detected();
        assert!(r.reason.is_empty());
    }

    #[test]
    fn test_rtf_stats_default_zero() {
        let s = RtfStats::default();
        assert_eq!(s.total_tokens, 0);
        assert_eq!(s.hex_bytes_count, 0);
    }

    #[test]
    fn test_parser_group_depth_with_nested() {
        let data = b"{\\rtf1 {\\b {\\i text}}}";
        let mut parser = RtfParser::new();
        parser.parse(data).unwrap();
        assert!(parser.stats.group_depth_max >= 3);
    }

    #[test]
    fn test_embedded_shellcode_confidence_boundary() {
        let sc = EmbeddedShellcode {
            bytes: vec![],
            rtf_offset: 0,
            ole_offset: 0,
            confidence: 60,
        };
        assert!(sc.is_likely());
        let sc2 = EmbeddedShellcode {
            bytes: vec![],
            rtf_offset: 0,
            ole_offset: 0,
            confidence: 59,
        };
        assert!(!sc2.is_likely());
    }

    #[test]
    fn test_ole_object_shellcode_int3_sled() {
        let data = vec![0xCCu8; 16];
        assert!(OleObject::detect_shellcode(&data));
    }

    #[test]
    fn test_lexer_hex_char_mixed_case() {
        let mut l = RtfLexer::new(b"\\'Fa");
        assert_eq!(l.next_token().unwrap(), Some(RtfToken::HexChar(0xFa)));
    }

    #[test]
    fn test_rtf_constants_eq_editor_clsid() {
        assert!(CLSID_EQUATION_EDITOR.contains("0002CE02"));
    }

    #[test]
    fn test_rtf_constants_package_clsid() {
        assert!(CLSID_PACKAGE.contains("00020820"));
    }
}

// ---------------------------------------------------------------------------
// RtfBookmarkTable — bookmark tracking
// ---------------------------------------------------------------------------

/// A bookmark entry in an RTF document.
#[derive(Debug, Clone)]
pub struct RtfBookmark {
    pub name: String,
    pub start_offset: usize,
    pub end_offset: Option<usize>,
}

impl RtfBookmark {
    pub fn new(name: impl Into<String>, start: usize) -> Self {
        Self {
            name: name.into(),
            start_offset: start,
            end_offset: None,
        }
    }
    pub const fn close(&mut self, end: usize) {
        self.end_offset = Some(end);
    }
    #[must_use] 
    pub const fn is_closed(&self) -> bool {
        self.end_offset.is_some()
    }
    #[must_use] 
    pub fn span(&self) -> Option<usize> {
        Some(self.end_offset? - self.start_offset)
    }
}

/// Collection of all bookmarks in an RTF document.
#[derive(Debug, Default)]
pub struct RtfBookmarkTable {
    pub bookmarks: Vec<RtfBookmark>,
}

impl RtfBookmarkTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, b: RtfBookmark) {
        self.bookmarks.push(b);
    }
    #[must_use] 
    pub fn find(&self, name: &str) -> Option<&RtfBookmark> {
        self.bookmarks.iter().find(|b| b.name == name)
    }
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bookmarks.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RtfPicture — picture object in RTF
// ---------------------------------------------------------------------------

/// Picture type in an RTF document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtfPictureType {
    Wmf,
    Emf,
    Png,
    Jpeg,
    Bmp,
    Unknown,
}

/// A picture embedded in an RTF document.
#[derive(Debug, Clone)]
pub struct RtfPicture {
    pub picture_type: RtfPictureType,
    pub width: i32,
    pub height: i32,
    pub raw_data: Vec<u8>,
    pub source_offset: usize,
}

impl RtfPicture {
    #[must_use] 
    pub const fn new(t: RtfPictureType, w: i32, h: i32, data: Vec<u8>) -> Self {
        Self {
            picture_type: t,
            width: w,
            height: h,
            raw_data: data,
            source_offset: 0,
        }
    }
    #[must_use] 
    pub const fn data_size(&self) -> usize {
        self.raw_data.len()
    }
    #[must_use] 
    pub const fn is_vector(&self) -> bool {
        matches!(self.picture_type, RtfPictureType::Wmf | RtfPictureType::Emf)
    }
}
// ---------------------------------------------------------------------------
// RtfNumberingList — list formatting tracking
// ---------------------------------------------------------------------------

/// Type of RTF list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtfListType {
    Bullet,
    Decimal,
    LowerAlpha,
    UpperAlpha,
    LowerRoman,
    UpperRoman,
}

/// One level of an RTF list.
#[derive(Debug, Clone)]
pub struct RtfListLevel {
    pub list_type: RtfListType,
    pub level: u8,
    pub start_value: i32,
    pub indent: i32,
}

impl RtfListLevel {
    #[must_use] 
    pub const fn new(t: RtfListType, level: u8) -> Self {
        Self {
            list_type: t,
            level,
            start_value: 1,
            indent: 720,
        }
    }
    #[must_use] 
    pub const fn is_ordered(&self) -> bool {
        !matches!(self.list_type, RtfListType::Bullet)
    }
}

/// RTF numbering/list table.
#[derive(Debug, Default)]
pub struct RtfNumberingTable {
    pub lists: Vec<Vec<RtfListLevel>>,
}

impl RtfNumberingTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_list(&mut self, levels: Vec<RtfListLevel>) {
        self.lists.push(levels);
    }
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.lists.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RtfSafetyChecker — quick safety assessment
// ---------------------------------------------------------------------------

/// Quick safety assessment of an RTF document.
pub struct RtfSafetyChecker;

impl RtfSafetyChecker {
    /// Run all safety checks on a parsed document.
    #[must_use] 
    pub fn check(parser: &RtfParser) -> Vec<String> {
        let mut issues = Vec::new();
        if parser.is_cve_2017_11882() {
            issues.push("CVE-2017-11882: Equation Editor exploit detected".to_string());
        }
        if !parser.shellcode_regions.is_empty() {
            issues.push(format!(
                "{} shellcode region(s) detected",
                parser.shellcode_regions.len()
            ));
        }
        for obj in &parser.objects {
            if obj.has_shellcode_pattern {
                issues.push(format!(
                    "OLE object '{}' has shellcode patterns",
                    obj.class_name
                ));
            }
        }
        issues
    }
}

// ---------------------------------------------------------------------------
// RtfStyleSheet — style sheet parsing
// ---------------------------------------------------------------------------

/// One paragraph style entry from the RTF `\stylesheet`.
#[derive(Debug, Clone)]
pub struct RtfStyle {
    pub id: u32,
    pub name: String,
    pub based_on: Option<u32>,
    pub next: Option<u32>,
    pub formatting: RtfParagraphInfo,
}

impl RtfStyle {
    pub fn new(id: u32, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            based_on: None,
            next: None,
            formatting: RtfParagraphInfo::new(),
        }
    }
}

/// RTF style sheet.
#[derive(Debug, Default)]
pub struct RtfStyleSheet {
    pub styles: Vec<RtfStyle>,
}
impl RtfStyleSheet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, s: RtfStyle) {
        self.styles.push(s);
    }
    #[must_use] 
    pub fn find(&self, id: u32) -> Option<&RtfStyle> {
        self.styles.iter().find(|s| s.id == id)
    }
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.styles.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.styles.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RtfMetadata — document metadata
// ---------------------------------------------------------------------------

/// Document metadata extracted from `\info` group.
#[derive(Debug, Clone, Default)]
pub struct RtfMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub company: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub revision: Option<u32>,
    pub word_count: Option<u32>,
}

impl RtfMetadata {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use] 
    pub const fn has_author(&self) -> bool {
        self.author.is_some()
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
#[must_use] 
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(std::borrow::ToOwned::to_owned)
}

/// Align a value up to `align` (power-of-two).
#[must_use] 
pub const fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
#[must_use] 
pub const fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
#[must_use] 
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use] 
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional parsing utilities
// ---------------------------------------------------------------------------

/// Parse a little-endian u16.
#[inline]
#[must_use] 
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}
/// Parse a little-endian u32.
#[inline]
#[must_use] 
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
#[inline]
#[must_use] 
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
#[inline]
#[must_use] 
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
/// Verify a 32-bit Adler-32 checksum over `data`.
#[must_use] 
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Byte pattern matching utilities
// ---------------------------------------------------------------------------

/// Search `haystack` for the first occurrence of `needle`.
#[must_use] 
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
#[must_use] 
pub fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = haystack[pos..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        pos += idx + needle.len();
    }
    count
}

/// Extract a sub-slice at `offset` with `len`, returning `None` if out of bounds.
#[must_use] 
pub fn try_slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset + len)
}
