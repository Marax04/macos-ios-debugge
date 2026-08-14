# rustre-loader-elf — Analysis

## Purpose
Comprehensive ELF binary loader (backed by `goblin`). Parses ELF32/ELF64 of any endianness across many architectures (x86, x86_64, ARM, AArch64, MIPS, RISC-V, PPC, SPARC, S390), exposes headers, segments, sections, static + dynamic symbols, dynamic linking metadata (NEEDED libs, SONAME, RPATH, interpreter), GNU build-id, `.gnu_debuglink`, PLT/GOT entries, relocations, DWARF/eh_frame helpers, GNU hash tables, ELF notes, version info (verdef/verneed), security mitigations, and implements the generic `Loader` trait so an ELF file becomes a `BinaryView` with mapped `PT_LOAD` segments and entry points.

## Public functions / types (interface-level, not implementation)

### Top-level (lib.rs)

- **`ElfInfo::parse(data: &[u8]) -> Result<ElfInfo, String>`**
  - Input: raw bytes of an ELF file.
  - Output: structured metadata (arch, bits, endian, type, entry, segments, sections, symbols, dynamic_symbols, needed_libs, rpath, soname, build_id, interpreter, plt_entries, debug_link, relocation_count, stripped).
  - Behavior: full parse via goblin; populates all metadata; returns error string on malformed ELF.
  - Ground truth: comparable against `readelf -a`, `objdump`, `eu-readelf`, Python `pyelftools`, or `lief`.

- **`ElfInfo::plt_entries() -> &[PltEntry]`** — accessor, list of `{name, address (PLT stub VA), got_address}`. Verify with `objdump -d -j .plt` + `readelf -r`.

- **`ElfInfo::build_id() -> Option<&[u8]>`** — raw GNU build-id bytes. Verify with `readelf -n` or `file <bin>`.

- **`ElfInfo::debug_link() -> Option<&str>`** — separate debug filename from `.gnu_debuglink`. Verify with `readelf --string-dump=.gnu_debuglink`.

- **`ElfInfo::is_stripped() -> bool`** — true iff no `.symtab` present. Verify with `readelf -S | grep symtab`.

- **`ElfInfo::relocation_count() -> usize`** — total RELA + REL + PLT relocations. Verify with `readelf -r | wc`.

- **`ElfLoader`** (`impl Loader`):
  - `name() -> "elf"`.
  - `can_load(input) -> bool` — true iff first 4 bytes equal `\x7fELF`. Verify trivially.
  - `load(input) -> LoadResult` — produces a `BinaryView` with PT_LOAD segments mapped at their VAs, zero-padded to `mem_size`, with permissions derived from `p_flags`; entry-point list from `e_entry`. Verifiable: segment VAs/sizes/permissions match `readelf -l`.
  - `find_nested(_) -> []` — always empty.

### Re-exports (module-level public APIs)

- **`gnu_hash(name: &[u8]) -> u32`** / **`gnu_hash_str(name: &str) -> u32`** — DJB-derived GNU hash for ELF symbol lookup. Ground truth: well-known algorithm, reference impls in glibc, lld, pyelftools (`GNUHashSection.gnu_hash`).
- **`GnuHashTable::parse64(bytes, le) -> Result<Self, _>`**, `lookup(name)`, `symbol_count()`, `scan_all_symbols() -> Vec<u32>` — parse and query a `.gnu.hash` table. Verify against pyelftools `GNUHashSection`.
- **`GnuBloomFilter::might_contain(hash) -> bool`**, `false_positive_rate(n)` — bloom-filter probe used by GNU hash; deterministic from words/shift2.
- **`parse_note_section(...) -> ElfNoteSection`** — parses an ELF `.note.*` section into typed notes (build-id, ABI tag, prpsinfo, prstatus). Verify with `readelf -n`.
- **`parse_verdef`, `parse_verneed`** — parse `.gnu.version_d` / `.gnu.version_r`. Verify with `readelf -V`.
- **DWARF helpers**: `parse_debug_abbrev`, `parse_debug_info_headers`, `parse_eh_frame`, `parse_line_table_prolog`, `debug_str_get` — produce structured DWARF/eh_frame info. Verify with `llvm-dwarfdump` / `readelf --debug-dump`.
- **Relocation types**: `Aarch64Reloc, ArmReloc, MipsReloc, Ppc64Reloc, PpcReloc, RelEntry, RelaEntry, RelocTable, RiscVReloc, SparcReloc, X86_64Reloc, X86Reloc` — typed wrappers for arch-specific relocation kinds.
- **Dynamic linking surface**: `DynamicEntry, DynamicSection, DynamicSymbolTable, DynlibDeps, ElfDynamicAnalysis, GotEntry, GotPltAnalysis, GotSlotState, PltEntry (DynPltEntry), RelocRecord, RelocationApplier` — exposed from `elf_dynamic_analysis`. Verify against `readelf -d`, `-r`, `objdump -R`.

### Public data types
`ElfArch`, `ElfType`, `ElfSegment`, `ElfSection`, `SymbolType`, `SymbolBinding`, `SymbolVisibility`, `ElfSymbol`, `PltEntry`, `ElfInfo`, constant `STV_DEFAULT`.

## Existing MCP tools for this crate
No ELF-specific MCP tool found in `crates/rustre-mcp-tools/src/wire_tools.rs` (grep for `loader_elf`, `ElfLoader`, `ElfInfo`, `gnu_hash`, `parse_verdef`, `parse_note_section` returned zero matches). ELF support is exposed indirectly: the generic `project.open` / loader registry path uses `ElfLoader` to produce a `BinaryView`, after which all generic binary/analysis/disasm/decompile tools operate on it. Comments at lines 645 and 1949 of `wire_tools.rs` mention "PE/ELF/Mach-O" as accepted inputs to generic tools (code-caves, executable-segment scan, etc.).

## Testable functions (externally verifiable ground truth)

| Function | Verification oracle |
|---|---|
| `ElfLoader::can_load` | first 4 bytes == `7f 45 4c 46` |
| `ElfInfo::parse` (arch / bits / endian / type / entry) | `readelf -h` |
| `ElfInfo::parse` (segments) | `readelf -l` |
| `ElfInfo::parse` (sections) | `readelf -S` |
| `ElfInfo::parse` (symbols / dynamic_symbols) | `readelf -s` / `nm` |
| `ElfInfo::parse` (needed_libs / rpath / soname / interpreter) | `readelf -d`, `patchelf --print-needed/--print-rpath/--print-soname/--print-interpreter` |
| `ElfInfo::build_id` | `readelf -n` (GNU build-id hex) |
| `ElfInfo::debug_link` | `readelf --string-dump=.gnu_debuglink` |
| `ElfInfo::relocation_count` | `readelf -r` line count by type |
| `ElfInfo::is_stripped` | `readelf -S \| grep symtab` absence |
| `ElfInfo::plt_entries` | `objdump -d -j .plt` + `readelf -r .rela.plt` |
| `gnu_hash` / `gnu_hash_str` | reference algorithm — Python: `h=5381; for b in name: h=(h*33+b)&0xffffffff` |
| `GnuHashTable::lookup` | pyelftools `GNUHashSection.get_symbol()` |
| `parse_note_section` (build-id) | `readelf -n` |
| `parse_verdef` / `parse_verneed` | `readelf -V` |
| `parse_eh_frame` / `parse_debug_*` | `llvm-dwarfdump`, `readelf --debug-dump` |
| `ElfLoader::load` (segment VA/size/perm) | matches `readelf -l` PT_LOAD entries |

## Validator strategy
1. **Corpus**: collect a small fixture set under `validation/fixtures/elf/` — e.g. `/bin/ls` (x86_64 dyn exec), `/bin/cat` (stripped variant), a 32-bit MIPS BE binary, an AArch64 shared library, and the crate's two synthetic fixtures from `tests/blitz.rs` / `tests/blitz2.rs`.
2. **Oracle**: for each fixture, pre-compute ground truth using `readelf -h -l -S -s -d -n -r -V`, `objdump -d -j .plt`, and `pyelftools` (Python script dumping JSON: header, segments list, sections list, dynsyms, needed, soname, rpath, interpreter, build_id hex, gnu_hash bucket layout, relocation counts).
3. **Driver**: a Rust integration test (or external Python harness invoking `cargo run --example` / a tiny CLI) that calls `ElfInfo::parse`, then asserts:
   - scalar equality (bits, endian, arch enum, elf_type, entry_point),
   - set equality on `needed_libs`,
   - exact match on `interpreter`, `soname`, `rpath`, `build_id` hex, `debug_link`,
   - `relocation_count` equals sum from `readelf -r`,
   - `segments` count and (vaddr, filesz, memsz, perms) per PT_LOAD identical to `readelf -l`,
   - `is_stripped()` matches symtab presence,
   - For PLT: every name in our `plt_entries` ∈ names from `readelf -r .rela.plt`; `got_address` equals `r_offset` of the matching relocation.
4. **Algorithmic checks** (no fixture required): property-test `gnu_hash`/`gnu_hash_str` against the canonical 5381/33 recursion in Python for random byte strings; verify `GnuBloomFilter::might_contain` returns true for every hash inserted into a freshly built bloom of known params.
5. **Loader contract**: assert `ElfLoader::load` produces a `BinaryView` whose mapped segments equal the `ElfInfo::segments` filtered to `PT_LOAD`, with permissions per ELF flags; assert `can_load` matches a magic-byte check on random byte strings.
6. **Failure paths**: feed truncated / non-ELF buffers; expect `parse` to error and `load` to return `CoreError::LoaderError`.
