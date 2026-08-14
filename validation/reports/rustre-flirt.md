# rustre-flirt — Analysis

## Purpose
FLIRT (Fast Library Identification and Recognition Technology) signature engine,
modelled on IDA's FLIRT format. Provides:
- IDA `.sig` v6–v10 header/file parser
- IDA `.pat` text-format parser/writer
- In-memory pattern + library + matcher with Patricia/trie lookup
- CRC-16/CCITT (poly 0x8408, init 0xFFFF) and CRC-16/IBM (poly 0xA001)
- A custom line-oriented FlirtLibrary text format (serialize/deserialize)
- Function hashing/normalization for x86 (wildcarding relocation operands)
- A high-level FlirtMatcher: load libraries, match functions or full address ranges, return named hits with confidence

## Public surface (selected from `lib.rs` + modules)

### CRC helpers
- `crc16_flirt(data: &[u8]) -> u16` — CRC-16/CCITT reversed poly 0x8408, init 0xFFFF, no final XOR.
  - **Ground truth**: reference impl in Python (`crcmod`/manual loop) over arbitrary bytes; for empty input must return 0xFFFF.
- `crc16_ibm(data: &[u8]) -> u16` — CRC-16/IBM poly 0xA001, init 0.
  - **Ground truth**: Python `crcmod.predefined.mkCrcFun('modbus')`-style (without init 0xFFFF) or manual loop.

### Pattern primitives
- `FlirtPattern::new(bytes)` — minimal pattern from `Vec<PatternByte>`.
- `FlirtPattern::matches_initial(buf) -> bool` — wildcard-aware byte match of initial bytes.
- `FlirtPattern::matches_crc16(buf) -> bool` — verifies CRC-16/CCITT over `[initial.len() .. initial.len()+crc_length]`.
- `FlirtPattern::matches_tail(buf) -> bool` — all tail-byte (offset,value) pairs match.
- `FlirtPattern::matches_all(buf) -> bool` — conjunction of the three.
- `FlirtPattern::primary_name() -> Option<&str>` — name with offset 0 & is_public.
- `FlirtPattern::pattern_hex() -> String` — hex string with `..` for wildcards.
- `FlirtPattern::wildcard_ratio() -> f32` — fraction of wildcard positions.
  - **Ground truth**: build a synthetic pattern, verify each predicate manually.

### `.sig` parser
- `parse_sig_header(data) -> Result<(SigHeader, usize)>` — parses IDASGN/v6+ headers, returns header + offset where tree starts.
- `FlirtSigFile::parse(data) -> Result<FlirtSigFile>` — best-effort sig parser (header + flat function list).
  - **Ground truth**: feed a real IDA `.sig` and check `header.version`, `header.arch`, `header.library_name`, `header.n_functions` against `flair` tool output or hex inspection.

### FlirtArch / FlirtFileType / FlirtOs
- `FlirtArch::from_u8/to_u8/as_str/from_str` — enum round-trips between numeric arch and string form.
  - **Ground truth**: table-driven test (0→X86, 128→Arm64, 132→X64, 255→Unknown, etc.).
- `FlirtFileType::from_u32/bits/contains` — bitflag-style ops.

### FlirtLibrary text format
- `FlirtLibrary::new(name, arch, os)`, `add_pattern`, `pattern_count`
- `FlirtLibrary::serialize() -> String` — line-oriented text dump.
- `FlirtLibrary::deserialize(s) -> Result<FlirtLibrary>` — inverse.
  - **Ground truth**: round-trip property — `deserialize(serialize(lib)) == lib` for arbitrary libraries.

### Trie / Matcher
- `FlirtTrie::build(library) -> FlirtTrie`, `find_candidates(buf) -> Vec<usize>`, `total_patterns() -> usize`.
- `FlirtMatcher::new`, `add_library`, `library_count`, `libraries`, `pattern_count`, `min_bytes_needed`.
- `FlirtMatcher::match_function(addr, bytes) -> Vec<FlirtMatch>` — full match (initial + CRC + tail), yields one `FlirtMatch` per name.
- `FlirtMatcher::match_all(base, bytes, fn_starts) -> Vec<FlirtMatch>` — bulk match over address list.
- `FlirtMatcher::best_match(addr, bytes) -> Option<FlirtMatch>` — top-confidence hit.
  - **Ground truth**: handcraft a library with a single known pattern, run matcher on bytes containing/not containing it, verify name & confidence.

### FlirtDatabase
- `FlirtDatabase::new/add_module/candidate_modules/total_patterns` — 4-byte-prefix index over modules.

### Other modules (pub modules, not enumerated in detail)
- `pat_parser`, `pat_parser_v2` — IDA `.pat` text parsing.
- `flirt_signature_writer` — write `.pat` files, FlirtStats.
- `function_hasher` — normalize x86 bytes wildcarding relocs, build FLIRT hashes.
- `flirt_index` — JSON-serializable trie index + collision detection.
- `flirt_engine`, `signature_matcher`, `signature_matcher_new`, `sig_matcher`, `flirt_matcher_v2` — alternative matcher fronts.
- `flirt_database`, `flirt_library_database`, `flirt_db_builder` — DB management.
- `flirt_auto_apply` — auto-apply matches to a project.
- `library_detector`, `function_recognition`, `version_info` — higher-level recognition wrappers.

## Existing MCP tools (rustre-mcp-tools/src/wire_tools.rs)
- `flirt_apply_auto` — applies built-in baseline FLIRT packs (MSVC CRT etc.) to current project, renaming functions; depends on `rustre-loader-pe::flirt_autoname` and `rustre-flirt-apply::LibraryMark`.
- A second `apply` variant (~line 1305) reusing `flirt_autoname::baseline_packs` + `apply_packs`.
- Note: these tools wrap **`rustre-flirt-apply`** / **`rustre-loader-pe`**, not `rustre-flirt` directly. The lower-level `rustre-flirt` primitives (CRC, trie, parser, matcher) are NOT directly exposed as MCP tools.

## Testable Functions (externally verifiable ground truth)
1. `crc16_flirt` — verifiable against independent Python implementation of CRC-16/CCITT reversed-poly 0x8408 init 0xFFFF.
2. `crc16_ibm` — verifiable against Python CRC-16/IBM poly 0xA001 init 0.
3. `FlirtArch::from_u8` / `to_u8` round-trip — table-driven.
4. `FlirtPattern::matches_initial/matches_crc16/matches_tail/matches_all` — predicate-truth-table tests.
5. `FlirtPattern::pattern_hex` — deterministic string from byte/wildcard list.
6. `FlirtPattern::wildcard_ratio` — count/len arithmetic.
7. `FlirtLibrary::serialize → deserialize` — round-trip equality.
8. `FlirtTrie::find_candidates` — given a library with N patterns where pattern k matches a known buffer, candidate set must contain k.
9. `FlirtMatcher::match_function` on a hand-built single-pattern library — must return the embedded name when bytes match, empty otherwise.
10. `parse_sig_header` — magic-byte and version validation; reject obvious malformed inputs.
11. `FlirtFileType::contains` — bitflag semantics (truth table).

## Validator Strategy
For each testable function, write a Rust integration test under
`crates/rustre-flirt/tests/validation_*.rs` that:
- For CRCs: compares against precomputed reference values (computed offline with Python `crcmod`) for ~20 fixed input vectors including empty, single-byte, all-zero, all-0xFF, and random.
- For arch/file-type/OS enums: exhaustive table of (numeric, string) pairs.
- For pattern predicates: handcraft `FlirtPattern` instances with specific wildcards/CRC/tail bytes; assert true/false on chosen buffers.
- For library text format: construct a non-trivial `FlirtLibrary` (multiple patterns, names with +pub/+local, tail bytes, referenced names), serialize, deserialize, structurally compare.
- For trie/matcher: build a library from a known pattern, scan a synthetic byte buffer containing the pattern at a known offset, assert the returned `FlirtMatch.name`/`confidence`/`address`.
- For `.sig` parsing: malformed buffers must yield specific `FlirtError` variants; if an IDA-flair generated `.sig` is available at a fixed test-data path, parse it and assert known header fields.

Optional cross-check: run IDA's `sigmake` to generate `.pat`/`.sig` for the same input, compare names/CRCs against `rustre-flirt`'s parser output.
