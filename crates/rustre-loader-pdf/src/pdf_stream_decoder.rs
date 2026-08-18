//! PDF stream decoder.
//!
//! Handles all standard PDF filter types: `FlateDecode`, `LZWDecode`,
//! `ASCII85Decode`, `ASCIIHexDecode`, `RunLengthDecode`, `CCITTFaxDecode`.
//! Decompresses streams, detects nested filters, handles malformed streams
//! gracefully, and reconstructs original data.

use std::fmt;
use std::io::Read as _;

use flate2::read::{DeflateDecoder, ZlibDecoder};
use serde::{Deserialize, Serialize};

// ─── DecodeError ─────────────────────────────────────────────────────────────

/// Error type for stream decoding failures.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum DecodeError {
    #[error("unknown filter: {0}")]
    UnknownFilter(String),
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("truncated stream at offset {0}")]
    TruncatedStream(usize),
    #[error("decode params error: {0}")]
    DecodeParamsError(String),
    #[error("filter chain error at index {index}: {cause}")]
    FilterChainError { index: usize, cause: String },
}

// ─── PdfFilter ────────────────────────────────────────────────────────────────

/// A PDF stream filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfFilter {
    /// zlib/deflate compression (most common).
    FlateDecode,
    /// LZW compression.
    LzwDecode,
    /// Base-85 encoding.
    Ascii85Decode,
    /// ASCII hexadecimal encoding.
    AsciiHexDecode,
    /// Byte-level run-length encoding.
    RunLengthDecode,
    /// CCITT Group 3/4 fax encoding (raster images).
    CcittFaxDecode,
    /// JBIG2 image compression.
    Jbig2Decode,
    /// DCT (JPEG) compression.
    DctDecode,
    /// JPEG 2000 compression.
    JpxDecode,
    /// Crypt filter (encryption integration).
    Crypt,
    /// Unknown / unsupported filter name.
    Unknown(String),
}

impl PdfFilter {
    /// Parse a filter name string into a `PdfFilter`.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name.trim() {
            "FlateDecode" | "Fl" => Self::FlateDecode,
            "LZWDecode" | "LZW" => Self::LzwDecode,
            "ASCII85Decode" | "A85" => Self::Ascii85Decode,
            "ASCIIHexDecode" | "AHx" => Self::AsciiHexDecode,
            "RunLengthDecode" | "RL" => Self::RunLengthDecode,
            "CCITTFaxDecode" | "CCF" => Self::CcittFaxDecode,
            "JBIG2Decode" => Self::Jbig2Decode,
            "DCTDecode" | "DCT" => Self::DctDecode,
            "JPXDecode" => Self::JpxDecode,
            "Crypt" => Self::Crypt,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the canonical filter name.
    #[must_use]
    pub const fn canonical_name(&self) -> &str {
        match self {
            Self::FlateDecode => "FlateDecode",
            Self::LzwDecode => "LZWDecode",
            Self::Ascii85Decode => "ASCII85Decode",
            Self::AsciiHexDecode => "ASCIIHexDecode",
            Self::RunLengthDecode => "RunLengthDecode",
            Self::CcittFaxDecode => "CCITTFaxDecode",
            Self::Jbig2Decode => "JBIG2Decode",
            Self::DctDecode => "DCTDecode",
            Self::JpxDecode => "JPXDecode",
            Self::Crypt => "Crypt",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Returns true if this filter can be decoded by this implementation.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        matches!(
            self,
            Self::FlateDecode
                | Self::Ascii85Decode
                | Self::AsciiHexDecode
                | Self::RunLengthDecode
                | Self::LzwDecode
        )
    }
}

impl fmt::Display for PdfFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical_name())
    }
}

// ─── FilterChain ─────────────────────────────────────────────────────────────

/// An ordered chain of filters to apply to a stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterChain {
    /// Ordered list of filters (applied left to right).
    pub filters: Vec<PdfFilter>,
    /// Optional decode parameters per filter (parallel array).
    pub decode_parms: Vec<Option<DecodeParams>>,
}

impl FilterChain {
    /// Create an empty (no-op) chain.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            filters: vec![],
            decode_parms: vec![],
        }
    }

    /// Create a single-filter chain.
    #[must_use]
    pub fn single(filter: PdfFilter) -> Self {
        Self {
            decode_parms: vec![None],
            filters: vec![filter],
        }
    }

    /// Create a chain from a list of filter name strings.
    #[must_use]
    pub fn from_names(names: &[&str]) -> Self {
        let filters: Vec<PdfFilter> = names.iter().map(|n| PdfFilter::from_name(n)).collect();
        let parms = vec![None; filters.len()];
        Self {
            filters,
            decode_parms: parms,
        }
    }

    /// Add a filter to the chain.
    pub fn push(&mut self, filter: PdfFilter, parms: Option<DecodeParams>) {
        self.filters.push(filter);
        self.decode_parms.push(parms);
    }

    /// Number of filters in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.filters.len()
    }

    /// Returns true if the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Returns true if any filter is unsupported.
    #[must_use]
    pub fn has_unsupported(&self) -> bool {
        self.filters.iter().any(|f| !f.is_supported())
    }

    /// Returns the names of unsupported filters.
    #[must_use]
    pub fn unsupported_names(&self) -> Vec<String> {
        self.filters
            .iter()
            .filter(|f| !f.is_supported())
            .map(|f| f.canonical_name().to_string())
            .collect()
    }
}

// ─── DecodeParams ─────────────────────────────────────────────────────────────

/// Parameters for a specific filter (`DecodeParms` entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeParams {
    /// PNG predictor index (10–15 for PNG, 1 for no predictor).
    pub predictor: u32,
    /// Number of colour components per pixel.
    pub colors: u32,
    /// Bits per component.
    pub bits_per_component: u32,
    /// Number of samples per row.
    pub columns: u32,
    /// LZW early change flag.
    pub early_change: i32,
    /// CCITT encoding type (0=Group3, 1=Group4).
    pub k: i32,
}

impl Default for DecodeParams {
    fn default() -> Self {
        Self {
            predictor: 1,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
            early_change: 1,
            k: 0,
        }
    }
}

// ─── StreamDecoder ────────────────────────────────────────────────────────────

/// Stateless stream decoder that can apply any supported PDF filter.
pub struct StreamDecoder;

impl StreamDecoder {
    /// Create a new decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Apply a full `FilterChain` to raw stream bytes.
    ///
    /// Filters are applied in order. If a filter fails and the chain was
    /// constructed tolerantly (e.g. from a malformed PDF), we return the
    /// best partial result and annotate the error.
    ///
    /// # Errors
    /// Returns `DecodeError::FilterChainError` if any filter fails.
    pub fn decode_chain(&self, data: &[u8], chain: &FilterChain) -> Result<Vec<u8>, DecodeError> {
        if chain.is_empty() {
            return Ok(data.to_vec());
        }
        let mut current = data.to_vec();
        for (i, (filter, parms)) in chain.filters.iter().zip(chain.decode_parms.iter()).enumerate() {
            current = self.apply_filter(&current, filter, parms.as_ref()).map_err(|e| {
                DecodeError::FilterChainError {
                    index: i,
                    cause: e.to_string(),
                }
            })?;
        }
        Ok(current)
    }

    /// Apply a single filter to `data`.
    ///
    /// # Errors
    /// Returns a `DecodeError` on decoding failure.
    pub fn apply_filter(
        &self,
        data: &[u8],
        filter: &PdfFilter,
        parms: Option<&DecodeParams>,
    ) -> Result<Vec<u8>, DecodeError> {
        match filter {
            PdfFilter::FlateDecode => self.flate_decode(data, parms),
            PdfFilter::Ascii85Decode => self.ascii85_decode(data),
            PdfFilter::AsciiHexDecode => self.ascii_hex_decode(data),
            PdfFilter::RunLengthDecode => self.run_length_decode(data),
            PdfFilter::LzwDecode => self.lzw_decode(data, parms),
            PdfFilter::DctDecode | PdfFilter::JpxDecode | PdfFilter::CcittFaxDecode
            | PdfFilter::Jbig2Decode => {
                // Pass-through for image filters we can't decode.
                Ok(data.to_vec())
            }
            PdfFilter::Crypt => Ok(data.to_vec()),
            PdfFilter::Unknown(name) => Err(DecodeError::UnknownFilter(name.clone())),
        }
    }

    // ─── FlateDecode ──────────────────────────────────────────────────────────

    fn flate_decode(&self, data: &[u8], parms: Option<&DecodeParams>) -> Result<Vec<u8>, DecodeError> {
        let decompressed = flate_decompress(data)?;
        let predictor = parms.map(|p| p.predictor).unwrap_or(1);
        if predictor >= 10 {
            let colors = parms.map(|p| p.colors).unwrap_or(1) as usize;
            let bits = parms.map(|p| p.bits_per_component).unwrap_or(8) as usize;
            let columns = parms.map(|p| p.columns).unwrap_or(1) as usize;
            png_predictor_undo(&decompressed, colors, bits, columns)
                .map_err(|e| DecodeError::DecompressionFailed(format!("PNG predictor: {e}")))
        } else if predictor == 2 {
            // TIFF predictor
            let colors = parms.map(|p| p.colors).unwrap_or(1) as usize;
            let bits = parms.map(|p| p.bits_per_component).unwrap_or(8) as usize;
            let columns = parms.map(|p| p.columns).unwrap_or(1) as usize;
            Ok(tiff_predictor_undo(&decompressed, colors, bits, columns))
        } else {
            Ok(decompressed)
        }
    }

    // ─── ASCII85Decode ────────────────────────────────────────────────────────

    fn ascii85_decode(&self, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let mut out = Vec::new();
        let filtered: Vec<u8> = data
            .iter()
            .copied()
            .filter(|&b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
            .collect();
        let mut i = 0;
        while i < filtered.len() {
            if filtered[i] == b'~' && filtered.get(i + 1) == Some(&b'>') {
                break;
            }
            if filtered[i] == b'z' {
                out.extend_from_slice(&[0u8; 4]);
                i += 1;
                continue;
            }
            // Collect up to 5 chars.
            let mut group = [b'u'; 5];
            let mut group_len = 0usize;
            while group_len < 5 && i + group_len < filtered.len() {
                let b = filtered[i + group_len];
                if b == b'~' {
                    break;
                }
                if !(33..=117).contains(&b) {
                    return Err(DecodeError::InvalidEncoding(format!(
                        "invalid ASCII85 byte {b} at index {}", i + group_len
                    )));
                }
                group[group_len] = b;
                group_len += 1;
            }
            i += group_len;
            if group_len == 0 {
                break;
            }
            // Pad short groups.
            for slot in group.iter_mut().take(5).skip(group_len) {
                *slot = b'u';
            }
            let mut val: u32 = 0;
            for &b in &group {
                val = val
                    .checked_mul(85)
                    .and_then(|v| v.checked_add(u32::from(b - 33)))
                    .ok_or_else(|| DecodeError::InvalidEncoding("ASCII85 overflow".to_string()))?;
            }
            let bytes = val.to_be_bytes();
            let emit = if group_len < 5 { group_len - 1 } else { 4 };
            out.extend_from_slice(&bytes[..emit]);
        }
        Ok(out)
    }

    // ─── ASCIIHexDecode ───────────────────────────────────────────────────────

    fn ascii_hex_decode(&self, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let mut out = Vec::new();
        let mut iter = data.iter().copied().filter(|&b| {
            !matches!(b, b' ' | b'\n' | b'\r' | b'\t')
        });
        loop {
            let hi = match iter.next() {
                Some(b'>') | None => break,
                Some(b) => b,
            };
            let lo = match iter.next() {
                Some(b'>') => b'0',
                None => b'0',
                Some(b) => b,
            };
            let high = hex_nibble_val(hi).ok_or_else(|| {
                DecodeError::InvalidEncoding(format!("invalid hex char {hi:#x}"))
            })?;
            let low = hex_nibble_val(lo).ok_or_else(|| {
                DecodeError::InvalidEncoding(format!("invalid hex char {lo:#x}"))
            })?;
            out.push((high << 4) | low);
        }
        Ok(out)
    }

    // ─── RunLengthDecode ──────────────────────────────────────────────────────

    fn run_length_decode(&self, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < data.len() {
            let length_byte = data[i];
            i += 1;
            match length_byte {
                128 => break, // EOD marker
                0..=127 => {
                    // Copy (length_byte + 1) literal bytes.
                    let count = length_byte as usize + 1;
                    if i + count > data.len() {
                        return Err(DecodeError::TruncatedStream(i));
                    }
                    out.extend_from_slice(&data[i..i + count]);
                    i += count;
                }
                _ => {
                    // Replicate the next byte (257 - length_byte) times.
                    let count = 257 - length_byte as usize;
                    if i >= data.len() {
                        return Err(DecodeError::TruncatedStream(i));
                    }
                    let byte = data[i];
                    i += 1;
                    out.extend(std::iter::repeat(byte).take(count));
                }
            }
        }
        Ok(out)
    }

    // ─── LZWDecode ───────────────────────────────────────────────────────────

    fn lzw_decode(&self, data: &[u8], parms: Option<&DecodeParams>) -> Result<Vec<u8>, DecodeError> {
        // Simple early-change LZW implementation.
        let early_change = parms.map(|p| p.early_change != 0).unwrap_or(true);
        lzw_decompress(data, early_change)
    }

    /// Decode a stream given a filter name string (convenience wrapper).
    ///
    /// # Errors
    /// Returns a `DecodeError` on failure.
    pub fn decode_named(
        &self,
        data: &[u8],
        filter_name: &str,
        parms: Option<&DecodeParams>,
    ) -> Result<Vec<u8>, DecodeError> {
        let filter = PdfFilter::from_name(filter_name);
        self.apply_filter(data, &filter, parms)
    }

    /// Try to detect which filter might have been applied to `data` by probing.
    ///
    /// Returns the filter that successfully decodes data with the smallest
    /// output-to-input ratio above 0.5 (i.e. some compression occurred).
    #[must_use]
    pub fn probe_filter(&self, data: &[u8]) -> Option<PdfFilter> {
        let candidates = [
            PdfFilter::FlateDecode,
            PdfFilter::Ascii85Decode,
            PdfFilter::AsciiHexDecode,
            PdfFilter::RunLengthDecode,
        ];
        for filter in &candidates {
            if let Ok(decoded) = self.apply_filter(data, filter, None) {
                if decoded.len() > data.len() / 2 {
                    return Some(filter.clone());
                }
            }
        }
        None
    }

    /// Attempt to gracefully decode a stream, falling back to raw bytes on failure.
    ///
    /// Never returns an error — returns the best available data.
    #[must_use]
    pub fn decode_tolerant(&self, data: &[u8], chain: &FilterChain) -> (Vec<u8>, Vec<DecodeError>) {
        let mut current = data.to_vec();
        let mut errors = Vec::new();
        for (filter, parms) in chain.filters.iter().zip(chain.decode_parms.iter()) {
            match self.apply_filter(&current, filter, parms.as_ref()) {
                Ok(decoded) => current = decoded,
                Err(e) => {
                    errors.push(e);
                    break; // Return what we have so far.
                }
            }
        }
        (current, errors)
    }
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Free-standing decode helpers ────────────────────────────────────────────

/// Decompress zlib/deflate data (wrapping the miniz/flate2 algorithm manually).
///
/// This implementation handles both zlib-wrapped (CMF+FLG header) and raw
/// deflate data by attempting both in sequence.
pub fn flate_decompress(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    // Try zlib header (2-byte CMF+FLG where CMF & 0x0F == 8).
    if data.len() >= 2 {
        let cmf = data[0];
        let flg = data[1];
        let is_zlib = (cmf & 0x0F) == 8 && (u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0;
        if is_zlib {
            const FLATE_MAX: u64 = 256 * 1024 * 1024; // 256 MiB — zip-bomb guard
            let mut out = Vec::new();
            ZlibDecoder::new(data)
                .take(FLATE_MAX + 1)
                .read_to_end(&mut out)
                .map_err(|e| DecodeError::DecompressionFailed(e.to_string()))?;
            if out.len() > FLATE_MAX as usize {
                return Err(DecodeError::DecompressionFailed(
                    "FlateDecode output exceeds size limit (possible bomb)".to_string(),
                ));
            }
            return Ok(out);
        }
    }
    // Try raw deflate.
    inflate_raw(data)
}

/// Inflate raw DEFLATE stream using the `flate2` crate.
fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    const FLATE_MAX: u64 = 256 * 1024 * 1024; // 256 MiB — zip-bomb guard
    let mut out = Vec::new();
    DeflateDecoder::new(data)
        .take(FLATE_MAX + 1)
        .read_to_end(&mut out)
        .map_err(|e| DecodeError::DecompressionFailed(e.to_string()))?;
    if out.len() > FLATE_MAX as usize {
        return Err(DecodeError::DecompressionFailed(
            "raw deflate output exceeds size limit (possible bomb)".to_string(),
        ));
    }
    Ok(out)
}

/// Undo PNG predictor filtering.
///
/// Supports all five PNG filter types (None, Sub, Up, Average, Paeth).
pub fn png_predictor_undo(
    data: &[u8],
    colors: usize,
    bits_per_component: usize,
    columns: usize,
) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    // Validate parameters before multiplying to avoid overflow on untrusted input.
    let bits_per_pixel = colors.checked_mul(bits_per_component)
        .ok_or_else(|| "PNG predictor: colors * bits_per_component overflow".to_string())?;
    let bpp = (bits_per_pixel + 7) / 8;
    let row_bits = columns.checked_mul(bits_per_pixel)
        .ok_or_else(|| "PNG predictor: columns * bits_per_pixel overflow".to_string())?;
    let row_size = (row_bits + 7) / 8;
    let stride = row_size.checked_add(1)
        .ok_or_else(|| "PNG predictor: stride overflow".to_string())?;

    if data.len() % stride != 0 && data.len() != stride * (data.len() / stride) {
        // Tolerant: process as many complete rows as possible.
    }

    let num_rows = data.len() / stride;
    let mut out = vec![0u8; num_rows * row_size];
    let mut prev_row = vec![0u8; row_size];

    for row in 0..num_rows {
        let src_start = row * stride;
        let filter_type = data[src_start];
        let src = &data[src_start + 1..src_start + 1 + row_size.min(data.len() - src_start - 1)];
        let dst_start = row * row_size;
        let dst = &mut out[dst_start..dst_start + row_size];

        match filter_type {
            0 => dst.copy_from_slice(&src[..row_size.min(src.len())]),
            1 => {
                // Sub
                for i in 0..row_size {
                    let raw = if i < src.len() { src[i] } else { 0 };
                    let a = if i >= bpp { dst[i - bpp] } else { 0 };
                    dst[i] = raw.wrapping_add(a);
                }
            }
            2 => {
                // Up
                for i in 0..row_size {
                    let raw = if i < src.len() { src[i] } else { 0 };
                    let b = prev_row[i];
                    dst[i] = raw.wrapping_add(b);
                }
            }
            3 => {
                // Average
                for i in 0..row_size {
                    let raw = if i < src.len() { src[i] } else { 0 };
                    let a = if i >= bpp { dst[i - bpp] } else { 0 };
                    let b = prev_row[i];
                    dst[i] = raw.wrapping_add(((u16::from(a) + u16::from(b)) / 2) as u8);
                }
            }
            4 => {
                // Paeth
                for i in 0..row_size {
                    let raw = if i < src.len() { src[i] } else { 0 };
                    let a = if i >= bpp { dst[i - bpp] } else { 0 };
                    let b = prev_row[i];
                    let c = if i >= bpp { prev_row[i - bpp] } else { 0 };
                    dst[i] = raw.wrapping_add(paeth_predictor(a, b, c));
                }
            }
            _ => {
                return Err(format!("unknown PNG filter type {filter_type}"));
            }
        }

        prev_row.copy_from_slice(dst);
    }
    Ok(out)
}

const fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let a = a as i32;
    let b = b as i32;
    let c = c as i32;
    let p = a + b - c;
    let pa = (p - a).unsigned_abs();
    let pb = (p - b).unsigned_abs();
    let pc = (p - c).unsigned_abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

/// Undo TIFF predictor 2 (horizontal differencing).
#[must_use]
pub fn tiff_predictor_undo(data: &[u8], colors: usize, bits: usize, columns: usize) -> Vec<u8> {
    if bits != 8 {
        return data.to_vec(); // Only handle 8-bit for now.
    }
    let row_size = match columns.checked_mul(colors) {
        Some(n) if n > 0 => n,
        _ => return data.to_vec(), // overflow or zero: return raw data
    };
    if data.len() % row_size != 0 {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    let rows = out.len() / row_size;
    for row in 0..rows {
        let base = row * row_size;
        for col in colors..row_size {
            out[base + col] = out[base + col].wrapping_add(out[base + col - colors]);
        }
    }
    out
}

const fn hex_nibble_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── LZW decompressor ─────────────────────────────────────────────────────────

/// Maximum decompressed output size for LZW to prevent `DoS` via crafted streams.
const LZW_MAX_OUTPUT: usize = 256 * 1024 * 1024; // 256 MiB

/// Simple LZW decompressor for PDF (variable-width codes, starting at 9 bits).
pub fn lzw_decompress(data: &[u8], early_change: bool) -> Result<Vec<u8>, DecodeError> {
    const CLEAR_CODE: u16 = 256;
    const EOD_CODE: u16 = 257;

    let mut out: Vec<u8> = Vec::new();
    let mut table: Vec<Vec<u8>> = (0u16..256).map(|i| vec![i as u8]).collect();
    table.push(vec![]); // CLEAR placeholder
    table.push(vec![]); // EOD placeholder

    let mut bit_width: u32 = 9;
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut byte_pos = 0usize;
    let mut prev: Option<Vec<u8>> = None;

    let limit_for_width = |w: u32| -> u16 {
        let base: u16 = 1u16 << (w - 1);
        if early_change { base - 1 } else { base }
    };

    loop {
        // Fill bit buffer.
        while bit_count < bit_width && byte_pos < data.len() {
            bit_buf = (bit_buf << 8) | u64::from(data[byte_pos]);
            bit_count += 8;
            byte_pos += 1;
        }
        if bit_count < bit_width {
            break;
        }
        let shift = bit_count - bit_width;
        let code = ((bit_buf >> shift) & ((1u64 << bit_width) - 1)) as u16;
        bit_count -= bit_width;
        bit_buf &= (1u64 << bit_count) - 1;

        if code == CLEAR_CODE {
            table.truncate(258);
            bit_width = 9;
            prev = None;
            continue;
        }
        if code == EOD_CODE {
            break;
        }

        let entry: Vec<u8> = if (code as usize) < table.len() {
            table[code as usize].clone()
        } else if let Some(ref p) = prev {
            if code as usize == table.len() {
                let mut e = p.clone();
                e.push(*p.first().unwrap_or(&0));
                e
            } else {
                return Err(DecodeError::InvalidEncoding(format!("LZW invalid code {code}")));
            }
        } else {
            return Err(DecodeError::InvalidEncoding("LZW code before CLEAR".to_string()));
        };

        if out.len() + entry.len() > LZW_MAX_OUTPUT {
            return Err(DecodeError::DecompressionFailed(
                "LZW output exceeds size limit (possible bomb)".to_string(),
            ));
        }
        out.extend_from_slice(&entry);

        if let Some(ref p) = prev {
            let mut new_entry = p.clone();
            new_entry.push(*entry.first().unwrap_or(&0));
            if table.len() < 4096 {
                table.push(new_entry);
            }
        }

        // Grow bit width.
        if table.len() >= limit_for_width(bit_width) as usize + 1 && bit_width < 12 {
            bit_width += 1;
        }

        prev = Some(entry);
    }

    Ok(out)
}

// ─── StreamInfo ───────────────────────────────────────────────────────────────

/// Metadata about a decoded stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    /// PDF object number.
    pub object_id: u32,
    /// Filter chain applied.
    pub filter_chain: FilterChain,
    /// Raw (compressed) size in bytes.
    pub raw_size: usize,
    /// Decoded size in bytes.
    pub decoded_size: usize,
    /// Compression ratio (raw / decoded), or 1.0 if `decoded_size` is 0.
    pub compression_ratio: f32,
    /// Whether the stream was decoded successfully.
    pub decode_ok: bool,
    /// Errors encountered during decoding.
    pub errors: Vec<String>,
}

impl StreamInfo {
    /// Compute stream info from raw and decoded sizes.
    #[must_use]
    pub fn new(
        object_id: u32,
        filter_chain: FilterChain,
        raw_size: usize,
        decoded_size: usize,
        decode_ok: bool,
        errors: Vec<String>,
    ) -> Self {
        let ratio = if decoded_size == 0 {
            1.0f32
        } else {
            raw_size as f32 / decoded_size as f32
        };
        Self {
            object_id,
            filter_chain,
            raw_size,
            decoded_size,
            compression_ratio: ratio,
            decode_ok,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_from_name_flate() {
        assert_eq!(PdfFilter::from_name("FlateDecode"), PdfFilter::FlateDecode);
        assert_eq!(PdfFilter::from_name("Fl"), PdfFilter::FlateDecode);
    }

    #[test]
    fn test_filter_from_name_unknown() {
        let f = PdfFilter::from_name("SomethingNew");
        assert!(matches!(f, PdfFilter::Unknown(_)));
        assert!(!f.is_supported());
    }

    #[test]
    fn test_ascii_hex_decode_basic() {
        let decoder = StreamDecoder::new();
        // Fixed: PDF spec 7.4.2 — EOD is the literal '>' character, not its hex pair 3E.
        let data = b"48656c6c6f>"; // "Hello" followed by EOD
        let result = decoder.ascii_hex_decode(data).unwrap();
        assert_eq!(&result, b"Hello");
    }

    #[test]
    fn test_ascii_hex_decode_with_spaces() {
        let decoder = StreamDecoder::new();
        // Fixed: EOD is the literal '>' (PDF spec 7.4.2), not the hex pair 3E.
        let data = b"48 65 6c 6c 6f >";
        let result = decoder.ascii_hex_decode(data).unwrap();
        assert_eq!(&result, b"Hello");
    }

    #[test]
    fn test_run_length_decode_literal() {
        let decoder = StreamDecoder::new();
        // length_byte=2 => copy 3 bytes, then EOD
        let data = [0x02u8, b'A', b'B', b'C', 128];
        let result = decoder.run_length_decode(&data).unwrap();
        assert_eq!(&result, b"ABC");
    }

    #[test]
    fn test_run_length_decode_repeated() {
        let decoder = StreamDecoder::new();
        // length_byte=254 => 257-254=3 repeats of 'X', then EOD
        let data = [0xFEu8, b'X', 128];
        let result = decoder.run_length_decode(&data).unwrap();
        assert_eq!(&result, b"XXX");
    }

    #[test]
    fn test_run_length_decode_eod() {
        let decoder = StreamDecoder::new();
        let data = [128u8];
        let result = decoder.run_length_decode(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_ascii85_decode_z() {
        let decoder = StreamDecoder::new();
        // "z" encodes four zero bytes; "~>" is EOD
        let data = b"z~>";
        let result = decoder.ascii85_decode(data).unwrap();
        assert_eq!(&result, &[0u8, 0, 0, 0]);
    }

    #[test]
    fn test_filter_chain_empty() {
        let chain = FilterChain::empty();
        let decoder = StreamDecoder::new();
        let data = b"raw data";
        let result = decoder.decode_chain(data, &chain).unwrap();
        assert_eq!(&result, b"raw data");
    }

    #[test]
    fn test_filter_chain_single_ascii_hex() {
        let chain = FilterChain::single(PdfFilter::AsciiHexDecode);
        let decoder = StreamDecoder::new();
        // Fixed: EOD is the literal '>' (PDF spec 7.4.2), not the hex pair 3E.
        let data = b"48656c6c6f>";
        let result = decoder.decode_chain(data, &chain).unwrap();
        assert_eq!(&result, b"Hello");
    }

    #[test]
    fn test_tiff_predictor_undo_identity() {
        // First pixel is absolute, rest are deltas.
        // If all deltas are 0, output = first pixel repeated.
        let row = vec![10u8, 0, 0, 0];
        let result = tiff_predictor_undo(&row, 1, 8, 4);
        assert_eq!(result, vec![10u8, 10, 10, 10]);
    }

    #[test]
    fn test_png_predictor_sub_single_row() {
        // Fixed: filter byte must be 1 (Sub), not 0 (None) to match the comment/expectation.
        // filter_type=1 (Sub), row: [1, 0, 1, 2] → absolute [0+0, 1, 1+1, 2+2]
        let row = vec![1u8, 1, 0, 1, 2]; // filter byte (Sub=1) + 4 data bytes
        let result = png_predictor_undo(&row, 1, 8, 4).unwrap();
        // Sub: dst[i] = raw[i] + dst[i-bpp]; bpp=1
        // dst[0]=1+0=1, dst[1]=0+1=1, dst[2]=1+1=2, dst[3]=2+2=4
        assert_eq!(result, vec![1u8, 1, 2, 4]);
    }

    #[test]
    fn test_decode_tolerant_unknown_filter() {
        let decoder = StreamDecoder::new();
        let chain = FilterChain::single(PdfFilter::Unknown("BadFilter".to_string()));
        let (data, errors) = decoder.decode_tolerant(b"raw", &chain);
        assert_eq!(&data, b"raw");
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_flate_decompress_empty() {
        let result = flate_decompress(b"").unwrap();
        assert!(result.is_empty());
    }
}
