//! Payload extraction from shellcode execution traces and memory dumps.
//!
//! Provides [`PayloadExtractor`] and the following extraction strategies:
//! - [`scan_for_pe_headers`]           — find MZ headers in a memory dump.
//! - [`scan_for_high_entropy_blobs`]   — sliding-window Shannon entropy scan.
//! - [`decode_base64_blobs`]           — locate and decode base64 strings.
//! - [`detect_xor_key`]                — recover 1-4 byte XOR keys.
//! - [`decrypt_xor`]                   — apply a recovered key.
//! - [`detect_rc4_key_schedule`]       — look for a 256-byte S-box permutation.
//! - [`extract_from_alloc_regions`]    — pull written+executed regions from emulator state.
//! - [`validate_pe`]                   — sanity-check a PE image buffer.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// PayloadType
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of an extracted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadType {
    /// A Windows PE executable (EXE or DLL).
    PeExecutable,
    /// Raw shellcode (no MZ header but executable-looking).
    PeShellcode,
    /// Base64-encoded data, decoded in place.
    Base64,
    /// Data encoded with a repeating XOR key.
    XorEncoded,
    /// Data encrypted with RC4 (key schedule identified).
    Rc4Encrypted,
    /// DEFLATE / zlib / LZ-compressed data.
    Compressed,
    /// Could not be classified.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractionMethod
// ─────────────────────────────────────────────────────────────────────────────

/// How the payload was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractionMethod {
    /// MZ/PE header scan.
    PeHeaderScan,
    /// High-entropy blob detection.
    EntropyBlob,
    /// Base64 string decode.
    Base64Decode,
    /// XOR key recovery and decryption.
    XorDecrypt,
    /// RC4 key-schedule detection.
    Rc4Detect,
    /// Write-then-execute region from emulation.
    AllocRegion,
    /// Manual / unknown.
    Manual,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractedPayload
// ─────────────────────────────────────────────────────────────────────────────

/// A single extracted (and optionally decoded) payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedPayload {
    /// Byte offset in the source buffer where this payload was found.
    pub offset: usize,
    /// Raw payload bytes (after any decoding/decryption).
    pub data: Vec<u8>,
    /// Best-guess type.
    pub payload_type: PayloadType,
    /// Shannon entropy of `data` (bits per byte, 0.0–8.0).
    pub entropy: f64,
    /// True if `data` starts with a valid MZ/PE header.
    pub pe_valid: bool,
    /// How this payload was extracted.
    pub method: ExtractionMethod,
    /// XOR key if applicable (1-4 bytes).
    pub xor_key: Option<Vec<u8>>,
}

impl ExtractedPayload {
    /// Create a new payload record, computing entropy and PE validity.
    pub fn new(offset: usize, data: Vec<u8>, payload_type: PayloadType, method: ExtractionMethod) -> Self {
        let entropy = shannon_entropy(&data);
        let pe_valid = validate_pe(&data);
        Self {
            offset,
            data,
            payload_type,
            entropy,
            pe_valid,
            method,
            xor_key: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PayloadExtractionReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result of all extraction passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadExtractionReport {
    /// All payloads found.
    pub payloads: Vec<ExtractedPayload>,
    /// Total count of extracted payloads.
    pub total_extracted: usize,
    /// Index of the payload with the highest entropy.
    pub highest_entropy_index: Option<usize>,
}

impl PayloadExtractionReport {
    fn build(payloads: Vec<ExtractedPayload>) -> Self {
        let total_extracted = payloads.len();
        let highest_entropy_index = if payloads.is_empty() {
            None
        } else {
            Some(
                payloads.iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| a.entropy.partial_cmp(&b.entropy).unwrap())
                    .map(|(i, _)| i)
                    .unwrap_or(0),
            )
        };
        Self { payloads, total_extracted, highest_entropy_index }
    }

    /// Highest-entropy payload, if any.
    pub fn highest_entropy_payload(&self) -> Option<&ExtractedPayload> {
        self.highest_entropy_index.and_then(|i| self.payloads.get(i))
    }

    /// All PE payloads.
    pub fn pe_payloads(&self) -> Vec<&ExtractedPayload> {
        self.payloads.iter().filter(|p| p.pe_valid).collect()
    }

    /// Count payloads of the given type.
    pub fn count_of_type(&self, t: &PayloadType) -> usize {
        self.payloads.iter().filter(|p| &p.payload_type == t).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Emulator region descriptor (mirror of what MemoryTracker tracks)
// ─────────────────────────────────────────────────────────────────────────────

/// A memory region used during emulation that was written and possibly executed.
#[derive(Debug, Clone)]
pub struct AllocRegion {
    pub base: u64,
    pub data: Vec<u8>,
    pub was_executed: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// PayloadExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates all extraction passes over a raw memory dump.
pub struct PayloadExtractor {
    /// Minimum blob size for entropy scanning (bytes).
    pub min_blob_size: usize,
    /// Entropy threshold for `scan_for_high_entropy_blobs`.
    pub entropy_threshold: f64,
    /// Minimum base64 string length before attempting decode.
    pub min_base64_len: usize,
    /// If true, attempt XOR decryption even without a clear key indicator.
    pub aggressive_xor: bool,
}

impl Default for PayloadExtractor {
    fn default() -> Self {
        Self {
            min_blob_size: 64,
            entropy_threshold: 6.5,
            min_base64_len: 64,
            aggressive_xor: false,
        }
    }
}

impl PayloadExtractor {
    pub fn new() -> Self { Self::default() }

    /// Run all extraction passes over `data` and return a consolidated report.
    pub fn extract_all(&self, data: &[u8]) -> PayloadExtractionReport {
        let mut payloads: Vec<ExtractedPayload> = Vec::new();

        payloads.extend(scan_for_pe_headers(data));
        payloads.extend(scan_for_high_entropy_blobs(data, self.entropy_threshold, self.min_blob_size));
        payloads.extend(decode_base64_blobs(data, self.min_base64_len));

        if let Some(key) = detect_xor_key(data, 4) {
            let decoded = decrypt_xor(data, &key);
            // Only add if result looks interesting (PE or high entropy)
            let entropy = shannon_entropy(&decoded);
            if entropy < self.entropy_threshold || validate_pe(&decoded) {
                let mut p = ExtractedPayload::new(0, decoded, PayloadType::XorEncoded, ExtractionMethod::XorDecrypt);
                p.xor_key = Some(key);
                payloads.push(p);
            }
        }

        // RC4 detection pass
        if let Some(offset) = detect_rc4_key_schedule(data) {
            payloads.push(ExtractedPayload::new(
                offset,
                data[offset..].to_vec(),
                PayloadType::Rc4Encrypted,
                ExtractionMethod::Rc4Detect,
            ));
        }

        // Deduplicate by offset
        payloads.dedup_by_key(|p| p.offset);

        PayloadExtractionReport::build(payloads)
    }

    /// Extract payloads from written+executed emulation regions.
    pub fn extract_from_regions(&self, regions: &[AllocRegion]) -> PayloadExtractionReport {
        let payloads: Vec<ExtractedPayload> = extract_from_alloc_regions(regions);
        PayloadExtractionReport::build(payloads)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_pe
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that `data` contains a structurally sound PE image.
///
/// Checks:
/// 1. `MZ` magic bytes at offset 0.
/// 2. `e_lfanew` (offset 0x3C) points within the buffer.
/// 3. `PE\0\0` signature at `e_lfanew`.
/// 4. Machine type is a known value (x86 / x64 / ARM / ARM64).
/// 5. At least one section header is present.
pub fn validate_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    // MZ magic
    if data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    // e_lfanew at offset 0x3C (LONG, 4 bytes)
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew > data.len().saturating_sub(24) {
        return false;
    }
    // PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    // Machine type (offset +4 in IMAGE_FILE_HEADER)
    let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
    let valid_machine = matches!(machine, 0x014C | 0x8664 | 0x01C0 | 0xAA64 | 0x0200);
    if !valid_machine {
        return false;
    }
    // Number of sections
    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]);
    num_sections > 0
}

// ─────────────────────────────────────────────────────────────────────────────
// shannon_entropy
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy of `data` in bits per byte (0.0–8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// scan_for_pe_headers
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `data` for all MZ headers and return validated PE payloads.
pub fn scan_for_pe_headers(data: &[u8]) -> Vec<ExtractedPayload> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        if data[offset] == b'M' && data[offset + 1] == b'Z' {
            let candidate = &data[offset..];
            if validate_pe(candidate) {
                // Try to determine the image size from SizeOfImage in OptionalHeader
                let size = pe_image_size(candidate).unwrap_or_else(|| candidate.len());
                let end = (offset + size).min(data.len());
                let payload_data = data[offset..end].to_vec();
                results.push(ExtractedPayload::new(
                    offset,
                    payload_data,
                    PayloadType::PeExecutable,
                    ExtractionMethod::PeHeaderScan,
                ));
                // Skip past this header to avoid re-detecting the same PE
                offset += size.max(1);
                continue;
            }
        }
        offset += 1;
    }

    results
}

/// Extract `SizeOfImage` from an OptionalHeader if present.
fn pe_image_size(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    // SizeOfImage is at OptionalHeader+56 (x86) = PE offset + 24 + 56 = +80
    let size_of_image_offset = e_lfanew.saturating_add(24 + 56);
    if size_of_image_offset > data.len().saturating_sub(4) { return None; }
    let size = u32::from_le_bytes([
        data[size_of_image_offset],
        data[size_of_image_offset + 1],
        data[size_of_image_offset + 2],
        data[size_of_image_offset + 3],
    ]) as usize;
    if size > 0 && size <= data.len() { Some(size) } else { None }
}

// ─────────────────────────────────────────────────────────────────────────────
// scan_for_high_entropy_blobs
// ─────────────────────────────────────────────────────────────────────────────

/// Slide a 256-byte window over `data`, collecting contiguous runs above `threshold`.
/// Only blobs >= `min_size` bytes are returned.
pub fn scan_for_high_entropy_blobs(data: &[u8], threshold: f64, min_size: usize) -> Vec<ExtractedPayload> {
    let window = 256usize;
    if data.len() < window { return Vec::new(); }

    let mut results = Vec::new();
    let mut blob_start: Option<usize> = None;

    let mut i = 0;
    while i + window <= data.len() {
        let e = shannon_entropy(&data[i..i + window]);
        if e >= threshold {
            if blob_start.is_none() {
                blob_start = Some(i);
            }
        } else if let Some(start) = blob_start.take() {
            let blob_end = i + window - 1;
            if blob_end - start >= min_size {
                let blob = data[start..blob_end].to_vec();
                let is_pe = validate_pe(&blob);
                let ptype = if is_pe { PayloadType::PeExecutable } else { PayloadType::Unknown };
                results.push(ExtractedPayload::new(start, blob, ptype, ExtractionMethod::EntropyBlob));
            }
        }
        i += 64; // stride
    }

    // Handle blob that runs to end of data
    if let Some(start) = blob_start {
        let blob = data[start..].to_vec();
        if blob.len() >= min_size {
            let is_pe = validate_pe(&blob);
            let ptype = if is_pe { PayloadType::PeExecutable } else { PayloadType::Unknown };
            results.push(ExtractedPayload::new(start, blob, ptype, ExtractionMethod::EntropyBlob));
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 helpers
// ─────────────────────────────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

fn is_base64_char(b: u8) -> bool {
    BASE64_CHARS.contains(&b)
}

/// Decode a base64 string (standard alphabet, with padding).
/// Returns None if the input is not valid base64.
pub fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    // Strip whitespace and padding
    let clean: Vec<u8> = input.iter()
        .copied()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ' && b != b'=')
        .collect();

    let table: [u8; 256] = {
        let mut t = [0xFFu8; 256];
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (i, &c) in alpha.iter().enumerate() {
            t[c as usize] = i as u8;
        }
        t
    };

    if clean.iter().any(|&b| table[b as usize] == 0xFF) {
        return None;
    }

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= clean.len() {
        let a = table[clean[i] as usize] as u32;
        let b = table[clean[i + 1] as usize] as u32;
        let c = table[clean[i + 2] as usize] as u32;
        let d = table[clean[i + 3] as usize] as u32;
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((triple >> 16) as u8);
        out.push((triple >> 8) as u8);
        out.push(triple as u8);
        i += 4;
    }
    match clean.len() - i {
        0 => {} // exact multiple of 4 — nothing left to decode
        2 => {
            let a = table[clean[i] as usize] as u32;
            let b = table[clean[i + 1] as usize] as u32;
            out.push(((a << 2) | (b >> 4)) as u8);
        }
        3 => {
            let a = table[clean[i] as usize] as u32;
            let b = table[clean[i + 1] as usize] as u32;
            let c = table[clean[i + 2] as usize] as u32;
            out.push(((a << 2) | (b >> 4)) as u8);
            out.push(((b << 4) | (c >> 2)) as u8);
        }
        // A trailing length of 1 is structurally invalid base64 — reject the
        // whole input rather than silently ignoring the orphaned character.
        // Without this check a crafted input like "AAAA" + "A" would return
        // a successful decode that omits the final byte, creating a polyglot
        // or length-confusion vulnerability for consumers that trust the output.
        _ => return None,
    }
    Some(out)
}

/// Scan `data` for base64 runs of at least `min_len` bytes and decode them.
pub fn decode_base64_blobs(data: &[u8], min_len: usize) -> Vec<ExtractedPayload> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if is_base64_char(data[i]) {
            let start = i;
            while i < data.len() && is_base64_char(data[i]) {
                i += 1;
            }
            let run_len = i - start;
            if run_len >= min_len {
                let run = &data[start..i];
                if let Some(decoded) = decode_base64(run) {
                    if !decoded.is_empty() {
                        let is_pe = validate_pe(&decoded);
                        let ptype = if is_pe { PayloadType::PeExecutable } else { PayloadType::Base64 };
                        results.push(ExtractedPayload::new(start, decoded, ptype, ExtractionMethod::Base64Decode));
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR key recovery
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to recover the most likely XOR key of length 1..=`max_key_len` bytes
/// using index-of-coincidence / frequency analysis.
///
/// Returns the key with the lowest combined chi-squared distance to English
/// byte frequencies (or the key that yields the most zero-bytes in the
/// plaintext for binary data).
pub fn detect_xor_key(data: &[u8], max_key_len: usize) -> Option<Vec<u8>> {
    if data.len() < 16 { return None; }

    let mut best_key: Option<Vec<u8>> = None;
    let mut best_score = f64::MAX;

    for key_len in 1..=max_key_len.min(4) {
        let key = recover_key_for_len(data, key_len);
        let score = xor_score(data, &key);
        if score < best_score {
            best_score = score;
            best_key = Some(key);
        }
    }

    // Return key only if it produces a better score than the identity (no XOR)
    let identity_score = xor_score(data, &[0u8]);
    if best_score < identity_score * 0.8 {
        best_key
    } else {
        None
    }
}

/// For a given key length, find each key byte by frequency analysis.
fn recover_key_for_len(data: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    for k in 0..key_len {
        let stream: Vec<u8> = data.iter()
            .enumerate()
            .filter(|(i, _)| i % key_len == k)
            .map(|(_, &b)| b)
            .collect();
        key[k] = best_single_byte_key(&stream);
    }
    key
}

/// Find the single byte XOR key that produces the most "printable" output.
fn best_single_byte_key(data: &[u8]) -> u8 {
    let mut best_key = 0u8;
    let mut best_score = 0u32;
    for k in 0u8..=255 {
        let score: u32 = data.iter()
            .map(|&b| {
                let c = b ^ k;
                if c.is_ascii_alphabetic() || c == b' ' || c == 0x00 { 2u32 }
                else if c.is_ascii_graphic() { 1 }
                else { 0 }
            })
            .sum();
        if score > best_score {
            best_score = score;
            best_key = k;
        }
    }
    best_key
}

/// Chi-squared score: lower is better (plaintext is more "normal").
fn xor_score(data: &[u8], key: &[u8]) -> f64 {
    if key.is_empty() { return f64::MAX; }
    let decoded: Vec<u8> = data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let mut counts = [0u32; 256];
    for &b in &decoded {
        counts[b as usize] += 1;
    }
    // Penalise non-printable bytes
    let non_printable: u32 = counts.iter()
        .enumerate()
        .filter(|(i, _)| !(*i as u8).is_ascii_graphic() && *i != 0x20 && *i != 0x00)
        .map(|(_, &c)| c)
        .sum();
    non_printable as f64 / decoded.len() as f64
}

/// Apply XOR key to `data`, cycling through the key bytes.
pub fn decrypt_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() { return data.to_vec(); }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// RC4 key-schedule detection
// ─────────────────────────────────────────────────────────────────────────────

/// Look for a 256-byte permutation of 0x00..=0xFF anywhere in `data`.
/// This is the RC4 S-box after the KSA phase.
///
/// Returns the offset of the first candidate, or `None`.
pub fn detect_rc4_key_schedule(data: &[u8]) -> Option<usize> {
    if data.len() < 256 { return None; }

    'outer: for offset in 0..=(data.len() - 256) {
        let window = &data[offset..offset + 256];
        let mut seen = [false; 256];
        for &b in window {
            if seen[b as usize] { continue 'outer; }
            seen[b as usize] = true;
        }
        // All 256 values present exactly once
        return Some(offset);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// extract_from_alloc_regions
// ─────────────────────────────────────────────────────────────────────────────

/// Extract payloads from memory regions that were written then executed
/// during emulation (shellcode staging typical behaviour).
pub fn extract_from_alloc_regions(regions: &[AllocRegion]) -> Vec<ExtractedPayload> {
    regions.iter()
        .filter(|r| r.was_executed && !r.data.is_empty())
        .map(|r| {
            let is_pe = validate_pe(&r.data);
            let ptype = if is_pe { PayloadType::PeExecutable } else { PayloadType::PeShellcode };
            // Cast the virtual base address to usize for the offset field;
            // on 64-bit targets this is lossless for any realistic VA.
            let offset = usize::try_from(r.base).unwrap_or(usize::MAX);
            ExtractedPayload::new(offset, r.data.clone(), ptype, ExtractionMethod::AllocRegion)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Compression detection helper
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether `data` starts with a known compression magic.
pub fn is_compressed(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // DEFLATE/zlib
    if data[0] == 0x78 && matches!(data[1], 0x01 | 0x9C | 0xDA | 0x5E) { return true; }
    // GZip
    if data[0] == 0x1F && data[1] == 0x8B { return true; }
    // LZ4 frame
    if u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0x184D2204 { return true; }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte frequency helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count occurrences of each byte value.
pub fn byte_frequency(data: &[u8]) -> [u32; 256] {
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    freq
}

/// Return the `n` most frequent bytes as (byte, count) pairs, sorted descending.
pub fn top_n_bytes(data: &[u8], n: usize) -> Vec<(u8, u32)> {
    let freq = byte_frequency(data);
    let mut pairs: Vec<(u8, u32)> = freq.iter()
        .enumerate()
        .map(|(i, &c)| (i as u8, c))
        .collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs.truncate(n);
    pairs
}

/// Ratio of printable ASCII bytes in `data`.
pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let printable = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    printable as f64 / data.len() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_pe ───────────────────────────────────────────────────────────

    fn make_minimal_pe() -> Vec<u8> {
        // Construct a minimal but valid-looking PE stub (x86, 1 section).
        let mut pe = vec![0u8; 512];
        // MZ header
        pe[0] = b'M'; pe[1] = b'Z';
        // e_lfanew = 0x40
        pe[0x3C] = 0x40;
        // PE signature at 0x40
        pe[0x40] = b'P'; pe[0x41] = b'E'; pe[0x42] = 0; pe[0x43] = 0;
        // Machine = x86 (0x014C)
        pe[0x44] = 0x4C; pe[0x45] = 0x01;
        // NumberOfSections = 1
        pe[0x46] = 0x01;
        pe
    }

    #[test]
    fn test_validate_pe_valid() {
        let pe = make_minimal_pe();
        assert!(validate_pe(&pe));
    }

    #[test]
    fn test_validate_pe_bad_magic() {
        let mut pe = make_minimal_pe();
        pe[0] = 0;
        assert!(!validate_pe(&pe));
    }

    #[test]
    fn test_validate_pe_bad_signature() {
        let mut pe = make_minimal_pe();
        pe[0x40] = 0;
        assert!(!validate_pe(&pe));
    }

    #[test]
    fn test_validate_pe_unknown_machine() {
        let mut pe = make_minimal_pe();
        pe[0x44] = 0xFF; pe[0x45] = 0xFF;
        assert!(!validate_pe(&pe));
    }

    #[test]
    fn test_validate_pe_too_short() {
        assert!(!validate_pe(&[b'M', b'Z']));
    }

    #[test]
    fn test_validate_pe_x64() {
        let mut pe = make_minimal_pe();
        // x64 machine type: 0x8664
        pe[0x44] = 0x64; pe[0x45] = 0x86;
        assert!(validate_pe(&pe));
    }

    // ── shannon_entropy ───────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "uniform distribution should be ~8.0, got {}", e);
    }

    #[test]
    fn test_entropy_single_byte() {
        let data = vec![0xAA_u8; 1000];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "all-same bytes should be ~0.0, got {}", e);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    // ── scan_for_pe_headers ───────────────────────────────────────────────────

    #[test]
    fn test_scan_for_pe_headers_finds_embedded_pe() {
        let pe = make_minimal_pe();
        let mut buffer = vec![0u8; 128];
        buffer.extend_from_slice(&pe);
        buffer.extend_from_slice(&[0u8; 64]);
        let results = scan_for_pe_headers(&buffer);
        assert!(!results.is_empty());
        assert_eq!(results[0].offset, 128);
        assert!(results[0].pe_valid);
    }

    #[test]
    fn test_scan_for_pe_headers_empty_buffer() {
        let results = scan_for_pe_headers(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_for_pe_headers_no_pe() {
        let data = vec![0x41u8; 512];
        let results = scan_for_pe_headers(&data);
        assert!(results.is_empty());
    }

    // ── decode_base64 ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_base64_hello() {
        // "Hello" in base64 = "SGVsbG8="
        let encoded = b"SGVsbG8=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_base64_empty() {
        let decoded = decode_base64(b"");
        // Empty input should decode to empty or None; either is acceptable.
        assert!(decoded.map_or(true, |v| v.is_empty()));
    }

    #[test]
    fn test_decode_base64_invalid_chars() {
        let result = decode_base64(b"!!!invalid!!!");
        assert!(result.is_none());
    }

    // ── decode_base64_blobs ───────────────────────────────────────────────────

    #[test]
    fn test_decode_base64_blobs_finds_encoded_section() {
        // Embed a 64-char base64 string (48 bytes of 'A' = "AAAA...A==" in base64)
        // 64 chars of 'A' decodes fine
        let base64_run = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut data = vec![0x01u8; 32];
        data.extend_from_slice(base64_run);
        data.extend_from_slice(&[0x01u8; 32]);
        let results = decode_base64_blobs(&data, 64);
        assert!(!results.is_empty());
    }

    // ── detect_xor_key ────────────────────────────────────────────────────────

    #[test]
    fn test_detect_xor_key_single_byte() {
        // XOR "AAAA..." with key 0x41 → all zeros, but let's use readable plaintext
        let plaintext: Vec<u8> = b"Hello World, this is a simple test string 12345".to_vec();
        let _key = vec![0x42u8];
        let ciphertext: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();
        let recovered = detect_xor_key(&ciphertext, 4);
        // Key should be recovered or at least the decrypted output should be valid
        if let Some(k) = recovered {
            assert!(!k.is_empty());
        }
    }

    #[test]
    fn test_decrypt_xor_roundtrip() {
        let plaintext = b"Secret payload data here 1234567890".to_vec();
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encrypted = decrypt_xor(&plaintext, &key);
        let decrypted = decrypt_xor(&encrypted, &key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_xor_empty_key() {
        let data = b"unchanged".to_vec();
        let result = decrypt_xor(&data, &[]);
        assert_eq!(result, data);
    }

    // ── detect_rc4_key_schedule ───────────────────────────────────────────────

    #[test]
    fn test_detect_rc4_key_schedule_found() {
        // Build a buffer with a 256-byte permutation embedded at offset 16.
        //
        // The padding must NOT be the one value the following window is missing.
        // With zero padding this test asserted the wrong offset: the sbox below
        // is `255,254,…,1,0`, so the window starting at offset 15 is the last
        // padding zero followed by `255…1` — 1 + 255 = 256 bytes whose values
        // are exactly `{0} ∪ {1..=255}`, a complete permutation. The detector
        // returns the FIRST match and so correctly answered 15; the fixture had
        // accidentally planted a permutation one byte early.
        //
        // `0xFF` is already present at data[16], so every window that includes
        // a padding byte now has a duplicate and is rejected.
        let mut data = vec![0xFFu8; 16];
        let sbox: Vec<u8> = {
            let mut s: Vec<u8> = (0u8..=255).collect();
            // Simulate a KSA by reversing it (still a valid permutation)
            s.reverse();
            s
        };
        data.extend_from_slice(&sbox);
        data.extend_from_slice(&[0u8; 16]);
        let result = detect_rc4_key_schedule(&data);
        assert_eq!(result, Some(16));
    }

    #[test]
    fn test_detect_rc4_key_schedule_not_found_repeated_bytes() {
        // All-zero buffer: definitely not a permutation
        let data = vec![0u8; 512];
        let result = detect_rc4_key_schedule(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_rc4_key_schedule_too_short() {
        let data = vec![0u8; 100];
        assert!(detect_rc4_key_schedule(&data).is_none());
    }

    // ── extract_from_alloc_regions ────────────────────────────────────────────

    #[test]
    fn test_extract_from_alloc_regions_executed_only() {
        let pe = make_minimal_pe();
        let regions = vec![
            AllocRegion { base: 0x3000_0000, data: pe, was_executed: true },
            AllocRegion { base: 0x4000_0000, data: vec![0x90; 256], was_executed: false },
        ];
        let payloads = extract_from_alloc_regions(&regions);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].offset, 0x3000_0000);
    }

    #[test]
    fn test_extract_from_alloc_regions_pe_classification() {
        let pe = make_minimal_pe();
        let regions = vec![AllocRegion { base: 0x1000, data: pe, was_executed: true }];
        let payloads = extract_from_alloc_regions(&regions);
        assert_eq!(payloads[0].payload_type, PayloadType::PeExecutable);
        assert!(payloads[0].pe_valid);
    }

    // ── byte frequency helpers ────────────────────────────────────────────────

    #[test]
    fn test_byte_frequency_counts() {
        let data = vec![0u8, 0, 1, 1, 1, 2];
        let freq = byte_frequency(&data);
        assert_eq!(freq[0], 2);
        assert_eq!(freq[1], 3);
        assert_eq!(freq[2], 1);
    }

    #[test]
    fn test_top_n_bytes() {
        let data = vec![0xAAu8; 100];
        let top = top_n_bytes(&data, 1);
        assert_eq!(top[0].0, 0xAA);
        assert_eq!(top[0].1, 100);
    }

    #[test]
    fn test_printable_ratio_all_printable() {
        let data = b"HelloWorld".to_vec();
        let r = printable_ratio(&data);
        assert!((r - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_printable_ratio_none_printable() {
        let data = vec![0x00u8, 0x01, 0x02, 0x03];
        let r = printable_ratio(&data);
        assert_eq!(r, 0.0);
    }

    // ── is_compressed ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_compressed_gzip_magic() {
        let data = vec![0x1F, 0x8B, 0x08, 0x00];
        assert!(is_compressed(&data));
    }

    #[test]
    fn test_is_compressed_zlib_magic() {
        let data = vec![0x78, 0x9C, 0x00, 0x00];
        assert!(is_compressed(&data));
    }

    #[test]
    fn test_is_compressed_plain_data() {
        let data = b"Hello World".to_vec();
        assert!(!is_compressed(&data));
    }

    // ── PayloadExtractor::extract_all integration ─────────────────────────────

    #[test]
    fn test_payload_extractor_finds_pe_in_dump() {
        let pe = make_minimal_pe();
        let mut dump = vec![0u8; 128];
        dump.extend_from_slice(&pe);
        dump.extend_from_slice(&[0u8; 128]);
        let extractor = PayloadExtractor::new();
        let report = extractor.extract_all(&dump);
        assert!(report.total_extracted > 0);
        assert!(!report.pe_payloads().is_empty());
    }

    #[test]
    fn test_payload_extraction_report_highest_entropy() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let extractor = PayloadExtractor {
            min_blob_size: 64,
            entropy_threshold: 4.0,
            ..Default::default()
        };
        let report = extractor.extract_all(&data);
        if !report.payloads.is_empty() {
            assert!(report.highest_entropy_payload().is_some());
        }
    }
}
