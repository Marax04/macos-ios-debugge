//! Static analysis utilities for 6502 family binaries.
//!
//! Provides:
//!
//! * [`scan_functions`] — scan a byte buffer for JSR/RTS call sequences and
//!   identify function entry points.
//! * [`read_vector_table`] — read the standard 6502 hardware vector table at
//!   `$FFFA–$FFFF` (NMI, RESET, IRQ/BRK).
//! * [`scan_strings`] — scan a byte buffer for printable ASCII and PETSCII
//!   strings above a minimum length.
//! * [`detect_data_sections`] — use byte-entropy analysis to flag regions that
//!   are unlikely to contain executable code.

// ── Function detection ────────────────────────────────────────────────────────

/// A detected function with its entry-point address and call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedFunction {
    /// Virtual address of the function's entry point.
    pub entry: u16,
    /// List of JSR call-site addresses (callers).
    pub call_sites: Vec<u16>,
    /// Whether an RTS was found reachable from this entry (heuristic).
    pub has_rts: bool,
}

/// Scan `data` (starting at virtual address `base_addr`) for JSR instructions
/// and use them to identify called function entry points.
///
/// The algorithm performs a single linear pass:
/// 1. Every `JSR abs` (0x20) is recorded; the absolute target is added to a
///    set of known function entry points, and the call site is recorded.
/// 2. Every `RTS` (0x60) marks that a function _may_ end here.
/// 3. For each discovered entry point, a second pass checks whether the bytes
///    reachable from that address contain an `RTS`.
///
/// This is a best-effort linear scan that does **not** follow control flow.
/// It will produce false positives for data bytes that happen to match 0x20.
///
/// Returns the list of detected functions sorted by entry address.
#[must_use]
pub fn scan_functions(data: &[u8], base_addr: u16) -> Vec<DetectedFunction> {
    use std::collections::{BTreeMap, BTreeSet};

    // Pass 1: find all JSR targets and RTS addresses.
    let mut call_map: BTreeMap<u16, Vec<u16>> = BTreeMap::new(); // entry → callers
    let mut rts_addrs: BTreeSet<u16> = BTreeSet::new();

    let mut i = 0usize;
    while i < data.len() {
        let byte = data[i];
        let vaddr = base_addr.wrapping_add(u16::try_from(i & 0xFFFF).unwrap_or(u16::MAX));
        match byte {
            // JSR abs – 3 bytes
            0x20 if i + 2 < data.len() => {
                let target = u16::from_le_bytes([data[i + 1], data[i + 2]]);
                call_map.entry(target).or_default().push(vaddr);
                i += 3;
            }
            // RTS – 1 byte
            0x60 => {
                rts_addrs.insert(vaddr);
                i += 1;
            }
            // Standard 1/2/3-byte advancement heuristic.
            _ => {
                let skip = opcode_size(byte);
                i += skip;
            }
        }
    }

    // Pass 2: for each discovered entry, check whether any RTS falls within a
    // simple forward-scan window of 256 bytes.
    let mut functions: Vec<DetectedFunction> = call_map
        .into_iter()
        .map(|(entry, call_sites)| {
            let has_rts = rts_addrs
                .range(entry..)
                .next()
                .is_some_and(|&rts| rts.wrapping_sub(entry) < 256);
            DetectedFunction {
                entry,
                call_sites,
                has_rts,
            }
        })
        .collect();

    functions.sort_by_key(|f| f.entry);
    functions
}

/// Best-guess instruction size for a byte (used to advance the scan).
const fn opcode_size(b: u8) -> usize {
    match b {
        // 1-byte implied/accumulator (common set)
        0x00 | 0x08 | 0x18 | 0x28 | 0x38 | 0x40 | 0x48 | 0x58 | 0x60 | 0x68 | 0x78 | 0x88
        | 0x8A | 0x98 | 0x9A | 0xA8 | 0xAA | 0xB8 | 0xBA | 0xC8 | 0xCA | 0xD8 | 0xE8 | 0xEA
        | 0xF8 => 1,
        // 2-byte: immediate, zero-page, relative
        0x09 | 0x05 | 0x15 | 0x69 | 0x65 | 0x75 | 0xA9 | 0xA5 | 0xB5 | 0xA2 | 0xA6 | 0xB6
        | 0xA0 | 0xA4 | 0xB4 | 0xC9 | 0xC5 | 0xD5 | 0xE0 | 0xE4 | 0xC0 | 0xC4 | 0xE9 | 0xE5
        | 0xF5 | 0x49 | 0x45 | 0x55 | 0x29 | 0x25 | 0x35 | 0x85 | 0x95 | 0x86 | 0x96 | 0x84
        | 0x94 | 0x24 | 0xC6 | 0xD6 | 0xE6 | 0xF6 | 0x06 | 0x16 | 0x46 | 0x56 | 0x26 | 0x36
        | 0x66 | 0x76 | 0x90 | 0xB0 | 0xF0 | 0x30 | 0xD0 | 0x10 | 0x50 | 0x70 | 0xA1 | 0xB1
        | 0x01 | 0x11 | 0x21 | 0x31 | 0x41 | 0x51 | 0x61 | 0x71 | 0x81 | 0x91 => 2,
        // 3-byte: absolute, absolute-indexed
        _ => 3,
    }
}

// ── Vector table ─────────────────────────────────────────────────────────────

/// The standard 6502 hardware interrupt vector table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorTable {
    /// Non-maskable interrupt vector (`$FFFA`–`$FFFB`).
    pub nmi: u16,
    /// Reset vector (`$FFFC`–`$FFFD`).
    pub reset: u16,
    /// IRQ / BRK vector (`$FFFE`–`$FFFF`).
    pub irq: u16,
}

/// Read the 6502 hardware vector table from `mem`.
///
/// `mem` is expected to be exactly 65536 bytes (a full 6502 address space),
/// but this function will read from whichever region is available.
///
/// Returns `None` if `mem` is shorter than 65536 bytes (truncated image).
#[must_use]
pub fn read_vector_table(mem: &[u8]) -> Option<VectorTable> {
    if mem.len() < 65536 {
        return None;
    }
    let nmi = u16::from_le_bytes([mem[0xFFFA], mem[0xFFFB]]);
    let reset = u16::from_le_bytes([mem[0xFFFC], mem[0xFFFD]]);
    let irq = u16::from_le_bytes([mem[0xFFFE], mem[0xFFFF]]);
    Some(VectorTable { nmi, reset, irq })
}

/// Read the 6502 hardware vector table from a partial memory slice.
///
/// `base` is the virtual address corresponding to `mem[0]`.  Useful for
/// ROM images that cover only the upper part of the address space.
///
/// Returns `None` if the vectors are not fully contained in `mem`.
#[must_use]
pub fn read_vector_table_at(mem: &[u8], base: u16) -> Option<VectorTable> {
    // If base > 0xFFFA the subtraction wraps, producing a garbage offset.
    if base > 0xFFFA {
        return None;
    }
    let start = (0xFFFAu16 - base) as usize;
    if mem.len() < start + 6 {
        return None;
    }
    let nmi = u16::from_le_bytes([mem[start], mem[start + 1]]);
    let reset = u16::from_le_bytes([mem[start + 2], mem[start + 3]]);
    let irq = u16::from_le_bytes([mem[start + 4], mem[start + 5]]);
    Some(VectorTable { nmi, reset, irq })
}

// ── String scanner ────────────────────────────────────────────────────────────

/// Character set for string scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StringCharset {
    /// 7-bit printable ASCII (0x20–0x7E) plus common control codes (\n, \r, \t).
    #[default]
    Ascii,
    /// PETSCII: printable characters in ranges 0x20–0x5F and 0xA0–0xBF.
    Petscii,
    /// Both ASCII and PETSCII.
    Both,
}

/// A string found in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    /// Byte offset from the start of `data`.
    pub offset: usize,
    /// Virtual address (offset + `base_addr`).
    pub addr: u64,
    /// The string text (lossily decoded as UTF-8).
    pub text: String,
    /// Character set detected.
    pub charset: StringCharset,
}

/// Scan `data` for embedded strings.
///
/// * `base_addr` — virtual address of `data[0]`.
/// * `min_len`   — minimum string length to report (typical value: 4).
/// * `charset`   — which character set(s) to recognise.
///
/// Returns strings sorted by byte offset.
#[must_use]
pub fn scan_strings(
    data: &[u8],
    base_addr: u64,
    min_len: usize,
    charset: StringCharset,
) -> Vec<FoundString> {
    // Cap the pre-allocation: an attacker supplying a huge buffer with min_len=1
    // would otherwise cause Vec::with_capacity to reserve data.len() slots
    // (each a FoundString) before a single byte is examined, exhausting memory.
    const MAX_PREALLOC_STRINGS: usize = 4096;
    let estimated = data.len() / min_len.max(1);
    let mut results = Vec::with_capacity(estimated.min(MAX_PREALLOC_STRINGS));
    let mut i = 0usize;

    while i < data.len() {
        let start = i;
        let mut buf = String::with_capacity(min_len + 8);
        let mut detected = StringCharset::Ascii;

        while i < data.len() {
            let b = data[i];
            if is_ascii_printable(b, charset) {
                buf.push(b as char);
                i += 1;
            } else if is_petscii_printable(b, charset) {
                buf.push(petscii_to_char(b));
                detected = StringCharset::Petscii;
                i += 1;
            } else {
                // Null terminator is acceptable to end a string.
                if b == 0x00 {
                    i += 1;
                }
                break;
            }
        }

        // All push paths produce ASCII chars (<0x80), so byte length equals char count.
        if buf.len() >= min_len {
            results.push(FoundString {
                offset: start,
                addr: base_addr + u64::try_from(start).unwrap_or(0),
                text: buf,
                charset: detected,
            });
        }

        // If no progress was made (non-printable, non-null byte that was not
        // consumed by the inner loop), advance by one byte to prevent an
        // infinite loop on adversarial input.
        if i == start {
            i += 1;
        }
    }

    results
}

const fn is_ascii_printable(b: u8, charset: StringCharset) -> bool {
    if !matches!(charset, StringCharset::Ascii | StringCharset::Both) {
        return false;
    }
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

const fn is_petscii_printable(b: u8, charset: StringCharset) -> bool {
    if !matches!(charset, StringCharset::Petscii | StringCharset::Both) {
        return false;
    }
    matches!(b, 0x20..=0x5F | 0xA0..=0xBF)
}

const fn petscii_to_char(b: u8) -> char {
    match b {
        0x20..=0x5F => (b as char).to_ascii_lowercase(),
        0xA0..=0xBF => (b - 0x80) as char,
        _ => '.',
    }
}

// ── Data-section detector ─────────────────────────────────────────────────────

/// A detected data section (high-entropy region unlikely to be code).
#[derive(Debug, Clone, PartialEq)]
pub struct DataSection {
    /// Byte offset from the start of the scanned buffer.
    pub offset: usize,
    /// Virtual address of the first byte.
    pub addr: u64,
    /// Length of the region in bytes.
    pub length: usize,
    /// Entropy estimate (0.0 = all same byte, 8.0 = maximum entropy).
    pub entropy: f64,
}

impl DataSection {
    /// Entropy as a floating-point value between 0.0 and 8.0.
    #[must_use]
    pub const fn entropy(&self) -> f64 {
        self.entropy
    }
}

/// Scan `data` for regions whose byte-value entropy suggests non-code content.
///
/// The function divides `data` into non-overlapping windows of `window_size`
/// bytes and computes the Shannon entropy of each window.  Windows whose
/// entropy exceeds `threshold` (0.0–8.0) are flagged as potential data
/// sections.  Adjacent data windows are merged.
///
/// Typical thresholds:
/// * `>= 7.0` — compressed/encrypted data.
/// * `>= 5.5` — general data tables, graphics data.
/// * `<= 3.5` — typical 6502 code.
///
/// Returns sections sorted by offset.
#[must_use]
pub fn detect_data_sections(
    data: &[u8],
    base_addr: u64,
    window_size: usize,
    threshold: f64,
) -> Vec<DataSection> {
    if window_size == 0 || data.is_empty() {
        return vec![];
    }

    let mut sections: Vec<DataSection> = Vec::new();
    let mut current: Option<(usize, usize, f64)> = None; // (start_offset, len, entropy_sum)

    let chunks = data.chunks(window_size);
    let mut offset = 0usize;

    for chunk in chunks {
        let entropy = shannon_entropy(chunk);
        let is_data = entropy >= threshold;

        if is_data {
            let e = entropy.clamp(0.0, 8.0);
            match &mut current {
                Some(c) => {
                    c.1 += chunk.len();
                    c.2 += e;
                }
                None => {
                    current = Some((offset, chunk.len(), e));
                }
            }
        } else if let Some((start, len, esum)) = current.take() {
            let n_windows = u32::try_from(len.div_ceil(window_size)).unwrap_or(1).max(1);
            let avg = esum / f64::from(n_windows);
            sections.push(DataSection {
                offset: start,
                addr: base_addr + u64::try_from(start).unwrap_or(0),
                length: len,
                entropy: avg,
            });
        }

        offset += chunk.len();
    }

    // Flush remaining.
    if let Some((start, len, esum)) = current {
        let n_windows = u32::try_from(len.div_ceil(window_size)).unwrap_or(1).max(1);
        let avg = esum / f64::from(n_windows);
        sections.push(DataSection {
            offset: start,
            addr: base_addr + u64::try_from(start).unwrap_or(0),
            length: len,
            entropy: avg,
        });
    }

    sections
}

/// Compute the Shannon entropy of a byte slice.
///
/// Returns a value in `[0.0, 8.0]`.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let n: f64 = freq.iter().map(|&c| f64::from(c)).sum();
    let entropy: f64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum();
    entropy
}

// ── Entry-point candidate heuristics ─────────────────────────────────────────

/// Heuristic criteria for entry-point candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EntryPointHints {
    /// Include entries referenced by the hardware vector table.
    pub from_vectors: bool,
    /// Include entries targeted by JSR instructions.
    pub from_jsr: bool,
    /// Include the reset vector from the vector table.
    pub reset_vector: bool,
}

impl EntryPointHints {
    /// Return hints that find all likely entry points.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            from_vectors: true,
            from_jsr: true,
            reset_vector: true,
        }
    }
}

/// Collect all entry-point candidate addresses from `data`.
///
/// Combines the hardware vector table (if the full 64 KiB is present) with
/// JSR targets found by [`scan_functions`].
///
/// The returned list is deduplicated and sorted.
#[must_use]
pub fn collect_entry_points(data: &[u8], base_addr: u16, hints: EntryPointHints) -> Vec<u16> {
    let mut entries: Vec<u16> = Vec::new();

    if (hints.from_vectors || hints.reset_vector) && let Some(vt) = read_vector_table(data) {
        if hints.from_vectors {
            entries.push(vt.nmi);
            entries.push(vt.irq);
        }
        if hints.reset_vector {
            entries.push(vt.reset);
        }
    }

    if hints.from_jsr {
        entries.extend(scan_functions(data, base_addr).into_iter().map(|f| f.entry));
    }

    entries.sort_unstable();
    entries.dedup();
    entries
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Vector table ──────────────────────────────────────────────────────────

    #[test]
    fn test_read_vector_table_full() {
        let mut mem = vec![0u8; 65536];
        mem[0xFFFA] = 0x00;
        mem[0xFFFB] = 0x03; // NMI  = $0300
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02; // RESET = $0200
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0x04; // IRQ  = $0400
        let vt = read_vector_table(&mem).unwrap();
        assert_eq!(vt.nmi, 0x0300);
        assert_eq!(vt.reset, 0x0200);
        assert_eq!(vt.irq, 0x0400);
    }

    #[test]
    fn test_read_vector_table_too_short() {
        let mem = vec![0u8; 100];
        assert!(read_vector_table(&mem).is_none());
    }

    #[test]
    fn test_read_vector_table_at() {
        // ROM image starting at $F000
        let mut rom = vec![0u8; 0x1000];
        // $FFFA is at offset $FFA from $F000
        let off = 0xFFFA - 0xF000;
        rom[off] = 0x00;
        rom[off + 1] = 0x03;
        rom[off + 2] = 0x00;
        rom[off + 3] = 0x02;
        rom[off + 4] = 0x00;
        rom[off + 5] = 0x04;
        let vt = read_vector_table_at(&rom, 0xF000).unwrap();
        assert_eq!(vt.nmi, 0x0300);
        assert_eq!(vt.reset, 0x0200);
        assert_eq!(vt.irq, 0x0400);
    }

    // ── Function scanner ──────────────────────────────────────────────────────

    #[test]
    fn test_scan_functions_basic() {
        // JSR $0210 at $0200
        let mut data = vec![0u8; 0x100];
        data[0] = 0x20;
        data[1] = 0x10;
        data[2] = 0x02; // JSR $0210
        data[0x10] = 0x60; // RTS at $0210
        let fns = scan_functions(&data, 0x0200);
        assert!(!fns.is_empty());
        let f = fns
            .iter()
            .find(|f| f.entry == 0x0210)
            .expect("should find $0210");
        assert_eq!(f.call_sites, vec![0x0200]);
    }

    #[test]
    fn test_scan_functions_no_code() {
        let data = vec![0xEAu8; 16]; // all NOPs
        assert!(scan_functions(&data, 0x0200).is_empty());
    }

    // ── String scanner ────────────────────────────────────────────────────────

    #[test]
    fn test_scan_strings_ascii() {
        let data = b"\x00HELLO WORLD\x00\xAB";
        let strings = scan_strings(data, 0x1000, 4, StringCharset::Ascii);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "HELLO WORLD");
        assert_eq!(strings[0].addr, 0x1001);
    }

    #[test]
    fn test_scan_strings_min_len_filter() {
        let data = b"HI\x00HELLO\x00";
        let strings = scan_strings(data, 0, 4, StringCharset::Ascii);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "HELLO");
    }

    #[test]
    fn test_scan_strings_petscii() {
        // PETSCII bytes 0x41–0x5A map to lowercase a–z in our conversion.
        let data = &[0x48u8, 0x45, 0x4C, 0x4C, 0x4F]; // "hello" in PETSCII
        let strings = scan_strings(data, 0, 4, StringCharset::Petscii);
        assert_eq!(strings.len(), 1);
    }

    #[test]
    fn test_scan_strings_empty() {
        assert!(scan_strings(&[], 0, 4, StringCharset::Ascii).is_empty());
    }

    // ── Entropy / data section detector ──────────────────────────────────────

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same byte → entropy = 0.
        let data = vec![0xABu8; 256];
        assert!((shannon_entropy(&data) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_max() {
        // All 256 possible values exactly once → entropy ≈ 8.0.
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.001, "entropy was {e}");
    }

    #[test]
    fn test_detect_data_sections_high_entropy() {
        // Build a buffer: 64 bytes of zeros (code-like) then 64 bytes of high entropy.
        let mut data = vec![0u8; 64];
        let high: Vec<u8> = (0..64u8).map(|i| i * 4).collect();
        data.extend_from_slice(&high);

        let sections = detect_data_sections(&data, 0x1000, 32, 4.0);
        assert!(!sections.is_empty(), "should detect the high-entropy half");
        let s = &sections[0];
        assert_eq!(s.offset, 64);
        assert_eq!(s.addr, 0x1040);
        assert!(s.entropy() >= 4.0);
    }

    #[test]
    fn test_detect_data_sections_no_high_entropy() {
        // All zeros → no data sections above threshold 4.0.
        let data = vec![0u8; 256];
        let sections = detect_data_sections(&data, 0, 32, 4.0);
        assert!(sections.is_empty());
    }

    // ── Entry-point collection ────────────────────────────────────────────────

    #[test]
    fn test_collect_entry_points() {
        let mut mem = vec![0u8; 65536];
        // Vector table
        mem[0xFFFA] = 0x00;
        mem[0xFFFB] = 0x03; // NMI  = $0300
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02; // RESET = $0200
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0x04; // IRQ  = $0400
        // A JSR at 0x0200 calling $0210
        mem[0x0200] = 0x20;
        mem[0x0201] = 0x10;
        mem[0x0202] = 0x02;

        let entries = collect_entry_points(&mem, 0x0000, EntryPointHints::all());
        assert!(entries.contains(&0x0200));
        assert!(entries.contains(&0x0210));
        assert!(entries.contains(&0x0300));
        assert!(entries.contains(&0x0400));
    }

    // ── Opcode-size helper ────────────────────────────────────────────────────

    #[test]
    fn test_opcode_size_nop() {
        assert_eq!(opcode_size(0xEA), 1); // NOP
    }

    #[test]
    fn test_opcode_size_lda_imm() {
        assert_eq!(opcode_size(0xA9), 2); // LDA #
    }

    #[test]
    fn test_opcode_size_jmp_abs() {
        assert_eq!(opcode_size(0x4C), 3); // JMP abs → falls through to default 3
    }
}
