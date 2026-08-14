# rustre-triage-entropy — Analysis

## Purpose
Shannon entropy analysis for binary triage: per-file / per-section / per-block entropy, byte histogram + chi-square randomness test, semantic content classification (text/code/data/compressed/encrypted/random), PE packing heuristics (UPX magic, packer section names, low import count, overlay), and a one-shot `survey_binary` aggregator combining file-kind detection (rustre-triage), PE parsing (rustre-pe-tools), and crypto-constant scan (rustre-crypto-id).

## Public functions / types (from lib.rs)

### Core entropy
- `shannon_entropy(data: &[u8]) -> f64`
  - In: byte buffer. Out: Shannon entropy in [0.0, 8.0].
  - Ground truth: verifiable in Python via `-sum(p*log2(p) for p in Counter(data).values()/len)`.
- `shannon_entropy_f32(data: &[u8]) -> f32` — same, f32.
- `analyze_blocks(data, block_size) -> Vec<EntropyBlock>` — entropy per non-overlapping chunk; verifiable by recomputing per-chunk python entropy.
- `analyze_with_sections(data, &[SectionDescriptor]) -> Vec<EntropyBlock>` — entropy per described region + whole, sorted desc.

### Classification
- `EntropyRating::from_entropy(h: f64) -> EntropyRating` — deterministic bucket: <1 VeryLow, <3 Low, <5 Medium, <7 High, else VeryHigh. Verifiable by table.
- `EntropyCategory::classify(e: f32)` — buckets Empty<1, Text<4, Code<5, Data<6, Compressed<7, Encrypted<7.5, Random>=7.5. Verifiable by table.

### Sections
- `SectionEntropy::new(name, data, offset)` → struct {name, entropy, size, offset, rating}.
- `SectionEntropy::is_packed()` → entropy > 7.0.
- `SectionEntropy::is_encrypted()` → entropy > 7.5.
- `EntropyAnalyzer::new(chunk_size)`, `.analyze(data)`, `.analyze_sections(data, &[(name,off,size)])` → `EntropyResult{overall, rating, sections, chunks}`.
- `EntropyResult::packed_sections()`, `.max_chunk_entropy()`.

### Histogram / randomness
- `ByteHistogram::new(data)` → counts[256] + total. Verifiable via `collections.Counter`.
- `.count_of(byte) -> u32`.
- `.chi_square_statistic() -> f64` — χ² vs uniform (E = n/256). Verifiable in Python: `sum((o-e)**2/e for o in counts)`.
- `.is_likely_random()` — true when χ² ∈ [200, 310].
- `.most_common_bytes(n)` → top-n (byte, count) desc.

### Heatmap / visualization
- `HeatmapData::from_data(data, block_size)`, `::from_blocks(Vec<EntropyBlock>)`.
- `.to_ascii_heatmap(width) -> String` — palette `" .:;+=xX$#"` linear 0..8.
- `HeatmapData::color_rgb(e) -> [u8;3]` — fixed thresholded ramp. Verifiable by table.
- `.to_rgb_colors() -> Vec<[u8;3]>`.

### PE packing detection
- `PackingDetector::detect_packing_indicators(pe_data) -> Vec<String>` — checks high-entropy `.text`, low imports (<5 via real import descriptor walk), UPX magic bytes & section names, known packer section names, overlay.
- `PackingDetector::detect_packing_indicators_from_path(path) -> io::Result<Vec<String>>`.

### Report aggregator
- `EntropyReport::generate(data)` / `::generate_with_block_size(data, n)` → {overall_entropy, category, is_likely_packed, packing_indicators, sections (blocks), histogram}.
- `.heatmap()`, `.high_entropy_blocks(threshold)`, `.summary()`.
- Implements `Display`.

### Survey
- `survey_binary(data: &[u8]) -> SurveyResult` — file_kind (via rustre-triage), size, is_pe, overall_entropy, packing_indicators, import_count (real PE imports), sections (name/VA/size/entropy), crypto_hits (rustre-crypto-id).

### Errors
- `EntropyError::{EmptyInput, InvalidChunk(usize)}`.

## Existing MCP tools (wire_tools.rs)
- `triage_entropy_packing_indicators` — wraps `PackingDetector::detect_packing_indicators[_from_path]`.
- `survey_binary` — aggregator MCP tool reusing `shannon_entropy`, `EntropyRating`, `analyze_section_entropy` (from rustre-triage) plus this crate.
- Internal reuse: many other wire_tools call `rustre_triage_entropy::shannon_entropy(...)` (entropy field of multiple aggregators).

## Externally verifiable (ground-truth-friendly) functions
- `shannon_entropy` / `shannon_entropy_f32` — Python `math.log2` + `Counter`.
- `EntropyRating::from_entropy`, `EntropyCategory::classify` — pure threshold tables.
- `ByteHistogram::new` / `count_of` / `most_common_bytes` — `collections.Counter`.
- `ByteHistogram::chi_square_statistic` — closed-form formula.
- `analyze_blocks` — slice + per-chunk Shannon.
- `HeatmapData::color_rgb` — fixed threshold table.
- `SectionEntropy::is_packed/is_encrypted` — thresholds (>7.0 / >7.5).
- `PackingDetector::detect_packing_indicators` — testable on synthetic minimal PEs + real UPX-packed sample.
- `survey_binary` — cross-check overall_entropy & is_pe against independent tools.

## Validator strategy
1. **Golden-vector Shannon entropy**: feed known inputs (all-zero buffer → 0; uniform 0..=255 → 8.0; balanced two-symbol → 1.0; random os.urandom(64KB) → cross-check Python). Compare f64 within 1e-9.
2. **Histogram + chi-square**: random 64KB buffer; compare counts to Python `Counter`; compare χ² to closed-form; check `is_likely_random()` true for PRNG output, false for all-zero/text.
3. **Classification tables**: enumerate boundary values (0.99, 1.0, 3.99, 5.0, 6.99, 7.0, 7.49, 7.5, 8.0) for both `EntropyRating::from_entropy` and `EntropyCategory::classify`; compare to expected enum variants.
4. **Block analysis**: split known data into blocks, verify each block entropy independently matches Python computation; verify offsets are i * block_size.
5. **Color ramp**: table-driven check of `HeatmapData::color_rgb` at boundary entropies.
6. **PE packing detector**: build minimal synthetic PE (DOS+PE header, one section). (a) Plain `.text` low-entropy → empty indicators. (b) Inject "UPX!" bytes → expect UPX magic indicator with correct occurrence count. (c) Section named "UPX0" → expect "UPX magic in section name". (d) High-entropy `.text` (random payload) → expect ">7.0" indicator. (e) Append trailing bytes after last section → expect overlay indicator. Run against real UPX-packed PE if available in fixtures.
7. **survey_binary**: on a known PE (e.g. cargo-zyphora.exe), assert is_pe=true, file_kind="PE", size matches `len(bytes)`, overall_entropy matches independently-computed Shannon, sections list length and names match independent PE parser (pefile in Python), import_count > 0.
