# rustre-flirt-gen

FLIRT signature generator for the RustRE suite. Builds FLIRT patterns from raw
function bytes + relocation tables, parses ELF `.o` objects to extract function
samples, and serialises IDA `.sig` v9 files.

## Cargo.toml

- name: `rustre-flirt-gen`, version 0.1.0, edition 2024
- deps: `rustre-flirt`, `rustre-core`, `serde`, `serde_json`, `thiserror`,
  `anyhow`, `object`, `goblin`, `rustc-demangle`
- dev-deps: `tempfile`
- bins:
  - `rust-stdlib-sigs` (`src/bin/rust_stdlib_sigs.rs`)
  - `msvcrt-sigs` (`src/bin/msvcrt_sigs.rs`)

## Public modules

`batch_processor`, `compiler_profile`, `pattern_extractor`, `sig_writer`,
`lib_crawler`, `database_builder`, `lib_analyzer`, `library_scanner`,
`pat_sig_format`, `pat_writer`, `pattern_optimizer`, `serializer`,
`sig_database`, `sig_generator`, `signature_extractor`, `signature_index`,
`trie_structure`, `variance_analyzer`, `pat_file_writer`,
`signature_deduplicator`.

Re-export: `library_scanner::FunctionSample`.

## Public API (lib.rs)

### Errors and types
- `enum GenError { InvalidPattern(String), Parse(String), Serialize(String) }`
  with `From<FlirtError>`.
- `struct RelocationEntry { offset: u16, size: u8 }` — byte-relative reloc
  description used to mask wildcards inside a function body.

### PatternGenerator
- `struct PatternGenerator { initial_length: usize=32, crc_length: usize=16 }`
- `const fn new()` / `Default`
- `fn generate(&self, bytes, relocs, names) -> Result<FlirtPattern, FlirtError>`
  - Builds initial masked block (`apply_relocations`), CRC-16 over the next
    `crc_length` bytes, tail bytes (up to 8 non-reloc bytes beyond initial).
  - Empty `bytes` -> `FlirtError::InvalidPattern`.
- `fn generate_from_ranges(&self, bytes, masked_ranges: &[(u16,u8)], names, referenced)
   -> Result<FlirtPattern, FlirtError>`
  - Variant that accepts wildcard `(start,len)` ranges (typically from a
    disassembler) instead of object-file relocs. CRC computed over the stable
    region skipping masked offsets so the value stays invariant under
    relocation. Sets `referenced_names`.
- `fn generate_batch(&self, functions: Vec<(name,bytes,relocs)>) -> Vec<FlirtPattern>`
  - Silently drops entries that fail to generate. Names marked `is_public=true`.
- `fn generate_pattern_with_quality(&self, bytes, name) -> Result<PatternWithQuality,FlirtError>`
  - Uses `scan_x86_masks` to derive wildcards, returns telemetry
    (`masked_bytes`, `total_bytes`, `mask_ratio`, `quality`).

### Quality
- `enum PatternQuality { High, Medium, Low }` with `as_str()`.
  - High: `mask_ratio <= 0.20`; Medium: `<= 0.40`; Low: otherwise.
- `struct PatternWithQuality { pattern, masked_bytes, total_bytes, mask_ratio, quality }`.

### x86 mask scanner
- `fn scan_x86_masks(bytes: &[u8]) -> Vec<(u16,u8)>`
  - Recognises CALL/JMP rel32 (`E8`/`E9`), Jcc rel32 (`0F 8x`), short
    JMP/Jcc/loop rel8 (`EB`, `7x`, `E0..E3`), RIP-relative `mod=00 rm=101`
    disp32, and `REX.W MOV r64, imm64` (`B8+r`). Walks one byte forward on
    unknown opcodes (conservative).

### ELF parser
- `struct ElfObjectParser;`
- `fn ElfObjectParser::parse(elf_bytes) -> Result<Vec<(String,Vec<u8>,Vec<RelocationEntry>)>, FlirtError>`
  - No external deps. Magic check `\x7fELF`, dispatches on `EI_CLASS` (1=ELF32,
    2=ELF64), supports either endian (`EI_DATA`). Locates `.symtab`/`.strtab`,
    builds reloc map keyed by section index from `SHT_REL`(9) and `SHT_RELA`(4)
    (ELF32 incorporates RELA addends). Emits one entry per `STT_FUNC` symbol
    with size>0 and a valid section, slicing `[sec_off+st_value .. +st_size]`
    and converting reloc absolute offsets to function-relative `u16`.
  - Bounds-checked at every step, returns structured `FlirtError::ParseError`.

### Library builder
- `struct GenerationStats { functions_processed, patterns_generated,
   patterns_skipped, duplicates_removed }`.
- `struct LibraryBuilder { name, arch: FlirtArch, os: FlirtOs, generator, patterns, stats }`.
- `fn new(name, arch, os)`
- `fn add_function(&mut self, name: String, bytes: &[u8], relocs: impl Into<Vec<RelocationEntry>>)`
  - Generates a pattern with a public `FlirtName` and pushes to the library.
- `fn add_elf_object(&mut self, elf_bytes) -> Result<usize, FlirtError>` —
  parses the ELF and adds every function; returns count parsed.
- `fn dedup_patterns(&mut self)` — drops patterns with identical
  `(pattern_hex, crc16, crc_length, primary_name)`.
- `fn build(self) -> (FlirtLibrary, GenerationStats)`.

### IDA .sig v9 writer
- `fn crc16_sig_header(data: &[u8]) -> u16` — non-reflected CRC-16/IBM
  (poly 0x8005, init 0xFFFF) used in the header CRC field.
- `enum SigTrieNode { Branch { prefix, children }, Leaf { prefix, crc_len,
   crc16, module_offset, func_name } }`
  - `fn encode(&self, buf: &mut Vec<u8>)` serialises into the .sig trie format
    (length-prefixed prefix; `0x00` child sentinel; flags>0 leaf marker
    followed by crc_len/crc16 LE/module_offset LE/length-prefixed name).
- `struct SigWriter { arch: u8 (75=x86_64), file_types: u32, os_types: u16,
   app_types: u16, feature_flags: u16 }`, with `Default`.
- `fn build(&self, sigs: &[FlirtPattern], lib_name: &str) -> Vec<u8>` —
  emits the 104-byte IDASGN v9 header (with `crc16_sig_header` over the first
  20 bytes) plus the encoded trie.
- `fn write_sig_file(path: &Path, sigs, lib_name, writer: &SigWriter) -> io::Result<()>`
  (free function near EOF) — convenience writer to disk.

## I/O behaviour

- Inputs: raw byte slices, relocation tuples, ELF object bytes (in-memory).
- Outputs: in-memory `FlirtPattern` / `FlirtLibrary` graphs, .sig v9 byte
  vectors, and `.sig` files when `write_sig_file` is invoked.
- No network. Filesystem I/O limited to `write_sig_file` and the auxiliary
  modules (`pat_writer`, `pat_file_writer`, `sig_writer`, `database_builder`,
  `lib_crawler`, `library_scanner`, …) which crawl/scan installed toolchains
  for the two binaries.
- All errors are propagated as `FlirtError` / `GenError` / `io::Error`;
  generation never panics on malformed input (bounds-checked, `try_from`
  saturating where required).

## Testable

Yes — pure library with deterministic byte-level transforms; `tempfile`
dev-dep and `tests/` directory present.
