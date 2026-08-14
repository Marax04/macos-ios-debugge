//! Structured / grammar-based fuzzer.
//!
//! Generates type-aware inputs for common binary and text formats, applies
//! format-specific interesting values, and implements a simplified LangFuzz-
//! style token recombination strategy.
//!
//! Supported formats:
//! * [`Format::Json`]  — JSON object / array / value generation.
//! * [`Format::Xml`]   — XML element / attribute generation.
//! * [`Format::Pe`]    — Partial PE header with interesting field values.
//! * [`Format::Elf`]   — Partial ELF header with interesting field values.
//! * [`Format::Raw`]   — Pass-through (falls back to random bytes).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{FuzzRng, MutationEngine, MutationStrategy};

// ── Format ────────────────────────────────────────────────────────────────────

/// File format targeted by the structured fuzzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Format {
    /// JSON text.
    Json,
    /// XML text.
    Xml,
    /// Portable Executable (PE/COFF).
    Pe,
    /// ELF binary.
    Elf,
    /// Raw binary (no structure awareness).
    Raw,
}

impl Format {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::Raw => "raw",
        }
    }

    /// Return all defined formats.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Json, Self::Xml, Self::Pe, Self::Elf, Self::Raw]
    }
}

// ── InterestingValues ─────────────────────────────────────────────────────────

/// Format-specific interesting values used to trigger edge cases.
pub struct InterestingValues;

impl InterestingValues {
    /// Interesting JSON number values.
    pub const JSON_NUMBERS: &'static [&'static str] = &[
        "0", "-1", "1", "2147483647", "-2147483648",
        "9999999999999999999", "-9999999999999999999",
        "1e308", "-1e308", "1e-308", "0.0", "null",
        "true", "false", "\"\"", "1.7976931348623157e+308",
    ];

    /// Interesting string values for JSON / XML.
    pub const INTERESTING_STRINGS: &'static [&'static str] = &[
        "",
        "A",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "\x00",
        "\n",
        "null",
        "undefined",
        "NaN",
        "Infinity",
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../etc/passwd",
        "%n%n%n%n",
        "\u{FF}\u{FE}\u{FD}",
    ];

    /// Interesting byte values for binary formats.
    pub const BINARY_BOUNDARY: &'static [u8] = &[
        0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE, 0xAA, 0x55,
    ];

    /// Interesting 32-bit values for binary fields.
    pub const INTERESTING_U32: &'static [u32] = &[
        0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
        0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 0x1000_0000,
    ];
}

// ── Schema ────────────────────────────────────────────────────────────────────

/// A simple type schema inferred from sample inputs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Schema {
    /// Field names → observed value samples.
    pub fields: HashMap<String, Vec<Vec<u8>>>,
    /// Overall format guess.
    pub format: Option<String>,
    /// Maximum observed input length.
    pub max_len: usize,
    /// Minimum observed input length.
    pub min_len: usize,
}

impl Schema {
    /// Create an empty schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            format: None,
            max_len: 0,
            min_len: usize::MAX,
        }
    }

    /// Ingest a sample input to update the schema.
    pub fn ingest(&mut self, sample: &[u8]) {
        let len = sample.len();
        if len > self.max_len {
            self.max_len = len;
        }
        if len < self.min_len {
            self.min_len = len;
        }
        // Format detection heuristic.
        if sample.starts_with(b"{") || sample.starts_with(b"[") {
            self.format = Some("json".to_string());
        } else if sample.starts_with(b"<") {
            self.format = Some("xml".to_string());
        } else if sample.starts_with(b"MZ") {
            self.format = Some("pe".to_string());
        } else if sample.starts_with(b"\x7FELF") {
            self.format = Some("elf".to_string());
        }
    }

    /// Return the inferred [`Format`], falling back to [`Format::Raw`].
    #[must_use]
    pub fn inferred_format(&self) -> Format {
        match self.format.as_deref() {
            Some("json") => Format::Json,
            Some("xml") => Format::Xml,
            Some("pe") => Format::Pe,
            Some("elf") => Format::Elf,
            _ => Format::Raw,
        }
    }

    /// Add a field observation.
    pub fn add_field_sample(&mut self, field: impl Into<String>, value: Vec<u8>) {
        self.fields.entry(field.into()).or_default().push(value);
    }

    /// Return a sample value for a field (randomly selected).
    #[must_use]
    pub fn sample_field<'a>(&'a self, field: &str, rng: &mut FuzzRng) -> Option<&'a Vec<u8>> {
        let samples = self.fields.get(field)?;
        if samples.is_empty() {
            return None;
        }
        Some(&samples[rng.next_usize(samples.len())])
    }
}

// ── JsonGenerator ─────────────────────────────────────────────────────────────

/// Generates JSON documents of varying structure.
pub struct JsonGenerator {
    /// Maximum nesting depth.
    pub max_depth: usize,
    /// Maximum array / object length.
    pub max_width: usize,
}

impl Default for JsonGenerator {
    fn default() -> Self {
        Self { max_depth: 4, max_width: 8 }
    }
}

impl JsonGenerator {
    /// Create with the given depth and width limits.
    #[must_use]
    pub const fn new(max_depth: usize, max_width: usize) -> Self {
        Self { max_depth, max_width }
    }

    /// Generate a random JSON document.
    #[must_use]
    pub fn generate(&self, rng: &mut FuzzRng) -> Vec<u8> {
        let s = self.gen_value(rng, 0);
        s.into_bytes()
    }

    fn gen_value(&self, rng: &mut FuzzRng, depth: usize) -> String {
        if depth >= self.max_depth {
            return self.gen_scalar(rng);
        }
        match rng.next_usize(4) {
            0 => self.gen_object(rng, depth + 1),
            1 => self.gen_array(rng, depth + 1),
            _ => self.gen_scalar(rng),
        }
    }

    fn gen_scalar(&self, rng: &mut FuzzRng) -> String {
        let idx = rng.next_usize(InterestingValues::JSON_NUMBERS.len());
        InterestingValues::JSON_NUMBERS[idx].to_string()
    }

    fn gen_object(&self, rng: &mut FuzzRng, depth: usize) -> String {
        let n = rng.next_usize(self.max_width) + 1;
        let mut pairs: Vec<String> = Vec::new();
        for i in 0..n {
            let key = format!("\"key{i}\"");
            let val = self.gen_value(rng, depth);
            pairs.push(format!("{key}:{val}"));
        }
        format!("{{{}}}", pairs.join(","))
    }

    fn gen_array(&self, rng: &mut FuzzRng, depth: usize) -> String {
        let n = rng.next_usize(self.max_width) + 1;
        let items: Vec<String> = (0..n).map(|_| self.gen_value(rng, depth)).collect();
        format!("[{}]", items.join(","))
    }

    /// Generate a JSON document seeded from `schema` samples.
    #[must_use]
    pub fn generate_from_schema(&self, schema: &Schema, rng: &mut FuzzRng) -> Vec<u8> {
        if schema.fields.is_empty() {
            return self.generate(rng);
        }
        let mut pairs: Vec<String> = Vec::new();
        for (field, samples) in &schema.fields {
            if samples.is_empty() {
                continue;
            }
            let idx = rng.next_usize(samples.len());
            let val = String::from_utf8_lossy(&samples[idx]).to_string();
            pairs.push(format!("\"{field}\":{val}"));
        }
        if pairs.is_empty() {
            return self.generate(rng);
        }
        format!("{{{}}}", pairs.join(",")).into_bytes()
    }
}

// ── XmlGenerator ──────────────────────────────────────────────────────────────

/// Generates XML documents.
pub struct XmlGenerator {
    /// Maximum element nesting depth.
    pub max_depth: usize,
}

impl Default for XmlGenerator {
    fn default() -> Self {
        Self { max_depth: 4 }
    }
}

impl XmlGenerator {
    /// Generate an XML document.
    #[must_use]
    pub fn generate(&self, rng: &mut FuzzRng) -> Vec<u8> {
        let root = format!("root{}", rng.next_usize(100));
        let body = self.gen_element(rng, &root, 0);
        format!("<?xml version=\"1.0\"?>{body}").into_bytes()
    }

    fn gen_element(&self, rng: &mut FuzzRng, tag: &str, depth: usize) -> String {
        // Random attribute
        let attr_val_idx = rng.next_usize(InterestingValues::INTERESTING_STRINGS.len());
        let attr_val = InterestingValues::INTERESTING_STRINGS[attr_val_idx].replace('"', "&quot;");
        let attrs = if rng.next_usize(2) == 0 {
            format!(" id=\"{attr_val}\"")
        } else {
            String::new()
        };

        if depth >= self.max_depth || rng.next_usize(3) == 0 {
            // Leaf: text content
            let text_idx = rng.next_usize(InterestingValues::INTERESTING_STRINGS.len());
            let text = InterestingValues::INTERESTING_STRINGS[text_idx]
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            format!("<{tag}{attrs}>{text}</{tag}>")
        } else {
            // Branch: child elements
            let n = rng.next_usize(4) + 1;
            let children: Vec<String> = (0..n)
                .map(|i| {
                    let child_tag = format!("el{i}");
                    self.gen_element(rng, &child_tag, depth + 1)
                })
                .collect();
            format!("<{tag}{attrs}>{}</{tag}>", children.join(""))
        }
    }
}

// ── PeGenerator ───────────────────────────────────────────────────────────────

/// Generates partial PE (Portable Executable) headers with interesting values.
pub struct PeGenerator;

impl PeGenerator {
    /// Generate a minimal PE binary skeleton with interesting field values.
    #[must_use]
    pub fn generate(rng: &mut FuzzRng) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // DOS header magic "MZ"
        buf.extend_from_slice(b"MZ");
        // e_cblp (bytes on last page): interesting value
        let cblp_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        let cblp = InterestingValues::INTERESTING_U32[cblp_idx] as u16;
        buf.extend_from_slice(&cblp.to_le_bytes());
        // Fill remainder of DOS header to offset 0x3C (60 bytes total so far)
        buf.resize(0x3C, 0u8);

        // e_lfanew: pointer to PE header — set to 0x40 (right after DOS header)
        let pe_offset: u32 = 0x40;
        buf.extend_from_slice(&pe_offset.to_le_bytes());
        buf.resize(0x40, 0u8);

        // PE signature "PE\0\0"
        buf.extend_from_slice(b"PE\x00\x00");

        // COFF header
        let machine: u16 = if rng.next_usize(2) == 0 { 0x8664 } else { 0x014C }; // x64 / i386
        buf.extend_from_slice(&machine.to_le_bytes());
        let num_sections = rng.next_usize(8) as u16;
        buf.extend_from_slice(&num_sections.to_le_bytes());
        let timestamp_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        buf.extend_from_slice(&InterestingValues::INTERESTING_U32[timestamp_idx].to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        buf.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        let opt_hdr_size: u16 = 0xE0; // standard PE32+ optional header size
        buf.extend_from_slice(&opt_hdr_size.to_le_bytes());
        let characteristics_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        let chars = InterestingValues::INTERESTING_U32[characteristics_idx] as u16;
        buf.extend_from_slice(&chars.to_le_bytes());

        // Pad to 512 bytes
        buf.resize(512, 0u8);
        buf
    }
}

// ── ElfGenerator ──────────────────────────────────────────────────────────────

/// Generates partial ELF headers with interesting field values.
pub struct ElfGenerator;

impl ElfGenerator {
    /// Generate a minimal ELF binary skeleton.
    #[must_use]
    pub fn generate(rng: &mut FuzzRng) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // ELF magic
        buf.extend_from_slice(b"\x7FELF");
        // EI_CLASS: 1=32-bit, 2=64-bit
        buf.push(if rng.next_usize(2) == 0 { 2 } else { 1 });
        // EI_DATA: 1=LSB, 2=MSB
        buf.push(if rng.next_usize(2) == 0 { 1 } else { 2 });
        // EI_VERSION = 1
        buf.push(1);
        // EI_OSABI + padding
        buf.push(rng.next_u8());
        buf.resize(16, 0u8);

        // e_type: interesting value
        let etype_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        let etype = InterestingValues::INTERESTING_U32[etype_idx] as u16;
        buf.extend_from_slice(&etype.to_le_bytes());

        // e_machine
        let machine_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        let machine = InterestingValues::INTERESTING_U32[machine_idx] as u16;
        buf.extend_from_slice(&machine.to_le_bytes());

        // e_version = 1
        buf.extend_from_slice(&1u32.to_le_bytes());

        // e_entry (entry point): interesting address
        let entry_idx = rng.next_usize(InterestingValues::INTERESTING_U32.len());
        buf.extend_from_slice(&InterestingValues::INTERESTING_U32[entry_idx].to_le_bytes());
        buf.extend_from_slice(&InterestingValues::INTERESTING_U32[entry_idx].to_le_bytes());

        // Pad to 256 bytes
        buf.resize(256, 0u8);
        buf
    }
}

// ── TokenBank ─────────────────────────────────────────────────────────────────

/// A bank of tokens extracted from valid corpus samples, used for LangFuzz-
/// style recombination mutations.
#[derive(Debug, Clone, Default)]
pub struct TokenBank {
    /// Raw token byte sequences collected from corpus samples.
    pub tokens: Vec<Vec<u8>>,
    /// Maximum number of tokens to store.
    pub capacity: usize,
}

impl TokenBank {
    /// Create an empty token bank with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            tokens: Vec::new(),
            capacity,
        }
    }

    /// Extract tokens from `input` and add them to the bank.
    ///
    /// Tokenisation strategy: split on common delimiters (whitespace, `,`, `:`,
    /// `{`, `}`, `[`, `]`, `<`, `>`) and keep non-empty tokens.
    pub fn ingest(&mut self, input: &[u8]) {
        const DELIMITERS: &[u8] = b" \t\n\r,:{}<>[]()";
        let mut current: Vec<u8> = Vec::new();
        for &b in input {
            if DELIMITERS.contains(&b) {
                if !current.is_empty() && current.len() <= 64 {
                    if self.tokens.len() < self.capacity {
                        self.tokens.push(current.clone());
                    }
                    current.clear();
                }
            } else {
                current.push(b);
            }
        }
        if !current.is_empty() && self.tokens.len() < self.capacity {
            self.tokens.push(current);
        }
    }

    /// Recombine: pick a random token and splice it into `input` at a random
    /// position, replacing a same-length (or shorter) region.
    #[must_use]
    pub fn recombine(&self, input: &[u8], rng: &mut FuzzRng) -> Vec<u8> {
        if self.tokens.is_empty() || input.is_empty() {
            return input.to_vec();
        }
        let token = &self.tokens[rng.next_usize(self.tokens.len())];
        let n = token.len().min(input.len());
        let start = rng.next_usize(input.len().saturating_sub(n) + 1);
        let end = (start + n).min(input.len());

        let mut out = input.to_vec();
        out[start..end].copy_from_slice(&token[..end - start]);
        out
    }

    /// Number of tokens stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// True when the bank is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

// ── StructuredFuzzer ──────────────────────────────────────────────────────────

/// Grammar-based / type-aware fuzzer that generates structured inputs and
/// applies format-specific mutations on top of the base mutation engine.
pub struct StructuredFuzzer {
    /// Target format.
    pub format: Format,
    /// Token bank for LangFuzz-style recombination.
    pub token_bank: TokenBank,
    /// Inferred schema from corpus samples.
    pub schema: Schema,
    /// Base mutation engine (used for byte-level mutations after structural
    /// generation).
    pub engine: MutationEngine,
    /// JSON generator.
    json_gen: JsonGenerator,
    /// XML generator.
    xml_gen: XmlGenerator,
    /// PRNG.
    rng: FuzzRng,
    /// Total inputs generated.
    pub total_generated: u64,
}

impl StructuredFuzzer {
    /// Create a new structured fuzzer targeting `format`.
    #[must_use]
    pub fn new(format: Format) -> Self {
        Self {
            format,
            token_bank: TokenBank::new(4096),
            schema: Schema::new(),
            engine: MutationEngine::new(),
            json_gen: JsonGenerator::default(),
            xml_gen: XmlGenerator::default(),
            rng: FuzzRng::new(0x5721_FACE),
            total_generated: 0,
        }
    }

    /// Ingest a corpus sample: update schema and token bank.
    pub fn ingest_sample(&mut self, sample: &[u8]) {
        self.schema.ingest(sample);
        self.token_bank.ingest(sample);
    }

    /// Ingest many corpus samples.
    pub fn ingest_corpus(&mut self, samples: &[Vec<u8>]) {
        for s in samples {
            self.ingest_sample(s);
        }
    }

    /// Generate a fresh structured input from scratch.
    #[must_use]
    pub fn generate(&mut self) -> Vec<u8> {
        self.total_generated += 1;
        match self.format {
            Format::Json => self.json_gen.generate(&mut self.rng),
            Format::Xml => self.xml_gen.generate(&mut self.rng),
            Format::Pe => PeGenerator::generate(&mut self.rng),
            Format::Elf => ElfGenerator::generate(&mut self.rng),
            Format::Raw => {
                let len = self.rng.next_usize(256) + 4;
                (0..len).map(|_| self.rng.next_u8()).collect()
            }
        }
    }

    /// Mutate an existing input using a combination of structural and byte-level
    /// strategies.
    ///
    /// Strategy mix:
    /// - 30% — generate a fresh structured input (ignores `input`).
    /// - 30% — token recombination (LangFuzz).
    /// - 40% — base mutation engine on `input`.
    #[must_use]
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        self.total_generated += 1;
        let roll = self.rng.next_usize(10);
        if roll < 3 {
            self.generate()
        } else if roll < 6 {
            self.token_bank.recombine(input, &mut self.rng)
        } else {
            let all = MutationStrategy::all();
            let strategy = all[self.rng.next_usize(all.len())];
            self.engine.mutate(input, strategy)
        }
    }

    /// Inject interesting format-specific values into `input` at a random
    /// offset.
    #[must_use]
    pub fn inject_interesting(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        match self.format {
            Format::Json | Format::Xml => {
                // Replace a segment with an interesting string.
                let s_idx =
                    self.rng.next_usize(InterestingValues::INTERESTING_STRINGS.len());
                let token = InterestingValues::INTERESTING_STRINGS[s_idx].as_bytes();
                let _ = self.token_bank.recombine(input, &mut self.rng);
                let mut out = input.to_vec();
                let n = token.len().min(out.len());
                let start = self.rng.next_usize(out.len().saturating_sub(n) + 1);
                out[start..start + n].copy_from_slice(&token[..n]);
                out
            }
            Format::Pe | Format::Elf => {
                // Overwrite a 4-byte field with an interesting u32.
                if input.len() < 4 {
                    return input.to_vec();
                }
                let idx =
                    self.rng.next_usize(InterestingValues::INTERESTING_U32.len());
                let val = InterestingValues::INTERESTING_U32[idx];
                let start = self.rng.next_usize(input.len() - 3);
                let mut out = input.to_vec();
                out[start..start + 4].copy_from_slice(&val.to_le_bytes());
                out
            }
            Format::Raw => self.engine.mutate(input, MutationStrategy::Havoc),
        }
    }

    /// Infer the format from corpus samples and reconfigure the fuzzer.
    pub fn auto_detect_format(&mut self) {
        self.format = self.schema.inferred_format();
    }

    /// Statistics: number of tokens in the bank.
    #[must_use]
    pub fn token_count(&self) -> usize {
        self.token_bank.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rng() -> FuzzRng {
        FuzzRng::new(0xDEAD_BEEF)
    }

    #[test]
    fn json_generator_produces_valid_looking_output() {
        let jgen = JsonGenerator::default();
        let mut rng = make_rng();
        let output = jgen.generate(&mut rng);
        assert!(!output.is_empty());
        let s = String::from_utf8(output).unwrap();
        assert!(s.starts_with('{') || s.starts_with('[') || !s.is_empty());
    }

    #[test]
    fn xml_generator_produces_valid_looking_output() {
        let xgen = XmlGenerator::default();
        let mut rng = make_rng();
        let output = xgen.generate(&mut rng);
        let s = String::from_utf8(output).unwrap();
        assert!(s.starts_with("<?xml"));
    }

    #[test]
    fn pe_generator_starts_with_mz() {
        let mut rng = make_rng();
        let output = PeGenerator::generate(&mut rng);
        assert!(output.starts_with(b"MZ"));
        assert_eq!(output.len(), 512);
    }

    #[test]
    fn elf_generator_starts_with_magic() {
        let mut rng = make_rng();
        let output = ElfGenerator::generate(&mut rng);
        assert!(output.starts_with(b"\x7FELF"));
        assert_eq!(output.len(), 256);
    }

    #[test]
    fn token_bank_ingest_and_recombine() {
        let mut bank = TokenBank::new(100);
        bank.ingest(b"{\"key\":\"value\",\"num\":42}");
        assert!(!bank.is_empty());
        let mut rng = make_rng();
        let input = b"original_input_here";
        let out = bank.recombine(input, &mut rng);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn token_bank_empty_ingest() {
        let mut bank = TokenBank::new(10);
        bank.ingest(b"");
        assert!(bank.is_empty());
    }

    #[test]
    fn token_bank_respects_capacity() {
        let mut bank = TokenBank::new(2);
        bank.ingest(b"a b c d e f g h i j");
        assert!(bank.len() <= 2);
    }

    #[test]
    fn schema_ingest_json_detection() {
        let mut schema = Schema::new();
        schema.ingest(b"{\"key\":1}");
        assert_eq!(schema.inferred_format(), Format::Json);
    }

    #[test]
    fn schema_ingest_pe_detection() {
        let mut schema = Schema::new();
        schema.ingest(b"MZ\x00\x00");
        assert_eq!(schema.inferred_format(), Format::Pe);
    }

    #[test]
    fn schema_ingest_elf_detection() {
        let mut schema = Schema::new();
        schema.ingest(b"\x7FELF...");
        assert_eq!(schema.inferred_format(), Format::Elf);
    }

    #[test]
    fn structured_fuzzer_generate_json() {
        let mut fuzz = StructuredFuzzer::new(Format::Json);
        let out = fuzz.generate();
        assert!(!out.is_empty());
    }

    #[test]
    fn structured_fuzzer_mutate_does_not_panic() {
        let mut fuzz = StructuredFuzzer::new(Format::Raw);
        let input = vec![1u8, 2, 3, 4, 5];
        let _ = fuzz.mutate(&input);
    }

    #[test]
    fn structured_fuzzer_inject_interesting_pe() {
        let mut fuzz = StructuredFuzzer::new(Format::Pe);
        let input = vec![0u8; 64];
        let out = fuzz.inject_interesting(&input);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn structured_fuzzer_ingest_corpus() {
        let mut fuzz = StructuredFuzzer::new(Format::Json);
        let corpus = vec![
            b"{\"a\":1}".to_vec(),
            b"{\"b\":\"hello\"}".to_vec(),
        ];
        fuzz.ingest_corpus(&corpus);
        assert!(fuzz.token_count() > 0);
    }

    #[test]
    fn structured_fuzzer_auto_detect() {
        let mut fuzz = StructuredFuzzer::new(Format::Raw);
        fuzz.ingest_sample(b"<root><el>val</el></root>");
        fuzz.auto_detect_format();
        assert_eq!(fuzz.format, Format::Xml);
    }

    #[test]
    fn interesting_values_boundary_bytes_nonempty() {
        assert!(!InterestingValues::BINARY_BOUNDARY.is_empty());
        assert!(!InterestingValues::JSON_NUMBERS.is_empty());
    }
}
