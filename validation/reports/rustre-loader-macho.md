# rustre-loader-macho — Analysis

## Purpose
Production-grade Mach-O binary loader/parser for the RustRE suite. Parses 32/64-bit Mach-O (LE/BE), fat/universal binaries, all standard load commands, segments, sections, symbols, imports, exports, dyld info (rebase/bind/exports trie/chained fixups), function starts, data-in-code, code signature, entitlements, Objective-C and Swift metadata, dylib analysis, and macOS security posture (SIP, Gatekeeper, notarization).

## Top-level modules
- `lib.rs` — main Mach-O parser, loader trait, sub-parsers (FunctionStarts, DyldInfo, DataInCode, Rebase, ChainedFixups, CodeSignature, ObjcMetadata, SwiftMetadata, FatBinary, MachoAnalyzer).
- `macho_analyzer.rs` — higher-level analysis result aggregation.
- `macho_code_sign.rs` — CodeDirectory / SuperBlob / Requirement / Entitlements blobs.
- `macho_dyld_info.rs` — ULEB/SLEB, rebase/bind opcode VM, export trie, chained fixups.
- `macho_dylib_analysis.rs` — dylib versions, dependency kinds, two-level namespace, weak/lazy binding.
- `macho_objc.rs` / `objc_metadata.rs` — ObjC class/method/ivar/protocol/property parsing, type-encoding decoder, Swift mangled-name hint.
- `macho_security.rs` — code-signing summary, SIP, Gatekeeper, notarization ticket detection, risk scoring.
- `casts.rs` — small lossless integer casts.

## Key public functions (semantic view)

### Top-level parsers (lib.rs)
- **MachoParser::parse(bytes)** → MachoInfo. Auto-detects thin vs fat; returns parsed header/segments/sections/symbols/imports/exports/load-commands. Ground truth: compare against `otool -hlL`, `nm`, `llvm-objdump --macho`.
- **MachoParser::parse_fat(bytes)** → Vec<UniversalBinaryEntry>. Enumerates slices of a FAT binary. GT: `lipo -info`, `lipo -detailed_info`.
- **MachoParser::select_best_slice(entries)** → best slice (arch preference). GT: deterministic policy check.
- **MachoParser::parse_single(bytes)** → MachoInfo for a single thin slice. GT: as parse().
- **FatBinaryParser::detect_fat(data)** → bool. GT: check magic 0xCAFEBABE/0xBEBAFECA at offset 0.
- **FatBinaryParser::list_arches(data)** → Vec<FatArch>. GT: `lipo -info`.
- **FatBinaryParser::extract_arch(data, arch)** → Vec<u8>. Slice out one architecture. GT: `lipo -thin <arch>`.
- **FunctionStartsParser::parse(data, base_addr)** → Vec<u64> of function VAs from LC_FUNCTION_STARTS uleb128 deltas. GT: `otool -function_starts`.
- **DyldInfoParser::parse_exports(data)** → Vec<ExportEntry>. Walks export trie. GT: `dyld_info -exports`.
- **DyldInfoParser::parse_bind(data)** → Vec<BindEntry>. GT: `dyld_info -bind`, `dyld_info -lazy_bind`.
- **DataInCodeParser::parse(data)** → Vec<DataInCodeEntry>. GT: `otool -data_in_code` or `llvm-objdump --macho --data-in-code`.
- **DataInCodeParser::total_data_bytes(entries)** → u64 sum of lengths.
- **RebaseParser::parse(data)** → Vec<RebaseEntry>. GT: `dyld_info -fixups` (legacy).
- **ChainedFixupsParser::parse_imports(data)** → Vec<ChainedFixupImport>. GT: `dyld_info -imports`.
- **ChainedFixupsParser::parse_segment_starts(data)** → Vec<ChainedStartsInSegment>. GT: `dyld_info -fixup_chains`.
- **CodeSignatureParser::parse(data)** → CodeSignatureInfo (CodeDirectory hashes, entitlements blob, requirement). GT: `codesign -d --verbose=4`, `jtool2 --sig`.
- **ObjcMetadataParser::extract_from_segments(...)** → classes/methods/categories. GT: `class-dump`, `otool -ov`.
- **SwiftMetadataParser::extract_from_segments(...)** → Swift type descriptors / protocol conformances. GT: `swift-demangle`, `jtool2`.
- **SwiftMetadataParser::resolve_relative_ptr(entry_addr, relative)** → u64. GT: simple `entry_addr + relative as i64`.
- **MachoAnalyzer::analyze(data)** → MachoReport (aggregate). GT: compose of above.
- **MachoAnalyzer::detect_swift(segments)** → bool (presence of `__swift5_*` sections). GT: section name scan.
- **MachoLoadCommandEnum::parse_all(bytes, lc_start, ncmds, big_endian)** → Vec parsed LCs. GT: `otool -l`.
- **AnalyzerSymbol::parse_symtab(data, symoff, nsyms, stroff)** → symbols. GT: `nm -ap`.

### MachoInfo accessors (lib.rs)
- text_segment / data_segment / section_named / symbol_at(addr) / find_symbol(name) / uuid_string / function_start_at(idx) / is_signed_with_cms / entitlements / objc_class_names / chained_import_names. All are deterministic getters over already-parsed structures; GT via `otool`/`nm`/`codesign`.

### macho_dyld_info.rs (low-level)
- **read_uleb128(data, pos)** → (u64, new_pos). GT: standard LEB128 decoding (matches `llvm` impl).
- **read_sleb128(data, pos)** → (i64, new_pos). GT: standard signed LEB128.
- **decode_rebase(data, ptr_size)** → Vec<RebaseAction>. GT: `dyld_info -fixups`.
- **decode_bind(stream, kind, ptr_size, ...)** → Vec<BindAction>. GT: `dyld_info -bind`.
- **decode_export_trie(trie)** → Vec<ExportEntry>. GT: `dyld_info -exports`.
- **decode_chained_fixups(data)** → ChainedFixups. GT: `dyld_info -fixup_chains`.

### macho_code_sign.rs
- **rbe64(b, off)** → Option<u64> (read big-endian u64). GT: trivial bit math.
- **CodeSignParser** (struct) — parses SuperBlob, CodeDirectory, Requirement, Entitlements. GT: `codesign -d -vvvv`.

### macho_dylib_analysis.rs
- **decode_bind_opcodes(stream, max_entries)** → Vec<BindingOpcode>. GT: `dyld_info -bind`.

### macho_objc.rs / objc_metadata.rs
- **parse_method_list / parse_ivar_list / parse_property_list / parse_protocol_list_names / parse_class_ro / parse_class_t / parse_classlist / parse_category / parse_catlist / parse_selrefs** — ObjC runtime structure parsers. GT: `class-dump -H`, `otool -ov`.
- **decode_type_enc(enc, pos)** / **decode_method_signature(enc)** / **parse_type_encoding(enc)** — ObjC `@encode` decoder. GT: matches Apple `@encode` table (e.g. `i`→int, `@`→id, `:`→SEL).
- **decode_swift_mangled_name(mangled)** → Option<String>. GT: `swift-demangle` (partial; hint-level).
- **is_swift_mangled(name)** → bool (starts with `_$s`, `$s`, `_T0`). GT: prefix test.
- **swift_class_hint(mangled)** → &str. GT: substring extraction.
- **class_inheritance_chain(objc, class_name)** → Vec<&str>. GT: graph walk over parsed classes.
- **inheritance_depth(objc, class_name)** → usize. GT: len of chain.
- **resolve_vm(vm, segments)** → Option<usize> file offset. GT: `(vm - seg.vmaddr) + seg.fileoff` if within range.
- **read_cstring(data, offset)** → Option<String>. GT: read until NUL, UTF-8 decode.
- **byte_entropy(data)** → f64 Shannon entropy 0..8. GT: Python `scipy.stats.entropy` over byte histogram (log2).
- **adler32(data)** → u32. GT: `zlib.adler32` in Python — strong external GT.
- **le_u16/le_u32/le_u64/be_u32** → integer reads. GT: `struct.unpack`.
- **read_u8 / read_le_u16** (objc_metadata) → bounds-checked integer reads. GT: trivial.

### macho_security.rs
- **has_notarization_ticket_magic(data)** → bool. GT: byte signature scan.
- Structs `MachoSecurity`, `SecurityFinding`, `GatekeeperInfo`, `Notarization`, `SIPProtection` — risk-level aggregation. GT: composition.

### casts.rs
- u64_to_usize, usize_to_u32, u64_to_u32, u64_to_u16, u64_to_u8, usize_to_u8, usize_to_i64, i64_to_usize, i64_to_u64, u32_to_i32, u64_to_i32, u8_to_i8, usize_to_f64. GT: trivial bit-pattern / lossless cast checks against Python integer arithmetic.

### Loader trait
- **MachoLoader** implements rustre-core `Loader` (async). GT: integration test loading a known macOS executable.

## Existing MCP tools
Search of `rustre-mcp-tools/src/` finds:
- **`macho_info`** — manifest declared in `tool_schemas.rs:858` (registered at `:398`). Tag: "macho", "macos".

No other Mach-O-specific MCP tools exposed in the wire layer for this crate (only the generic `macho_info`).

## Functions best suited for external-ground-truth validation
1. **read_uleb128 / read_sleb128** — vs Python `leb128` package.
2. **adler32** — vs Python `zlib.adler32`.
3. **byte_entropy** — vs Python Shannon entropy formula.
4. **le_u16/le_u32/le_u64/be_u32** — vs `struct.unpack`.
5. **read_cstring** — vs Python `data.split(b'\x00',1)[0].decode()`.
6. **FatBinaryParser::detect_fat / list_arches / extract_arch** — vs `lipo -info` / `lipo -thin`.
7. **FunctionStartsParser::parse** — vs `otool -function_starts` / `llvm-objdump --syms`.
8. **DyldInfoParser::parse_exports / parse_bind** — vs `dyld_info -exports` / `-bind`.
9. **DataInCodeParser::parse** — vs `otool -data_in_code`.
10. **CodeSignatureParser::parse** — vs `codesign -d -vvvv` (CDHash, team id, entitlements).
11. **MachoParser::parse** end-to-end — vs `otool -hlL` for a fixture binary.
12. **casts::*** — vs Python integer wrap/truncate operations.

## Validator strategy
- Build a small fixture set of Mach-O binaries: (a) thin x86_64 LE, (b) thin arm64, (c) fat universal x86_64+arm64, (d) signed+notarized binary, (e) ObjC-heavy binary, (f) Swift binary.
- For each crate function above, drive it through the `macho_info` MCP tool (or a thin Rust test harness binary) and capture JSON output.
- Compute ground truth in Python:
  - LEB128 via `leb128` lib; adler32 via `zlib`; entropy via manual `-sum(p*log2(p))`.
  - Run `otool -hlL`, `otool -l`, `otool -function_starts`, `otool -data_in_code`, `nm -ap`, `lipo -info`, `lipo -detailed_info`, `codesign -d --entitlements :- --xml -vvvv`, `dyld_info -exports -bind -fixup_chains` and parse outputs to canonical structures.
  - For ObjC, run `class-dump -H` and compare class/method/ivar names.
  - For Swift, run `swift-demangle` over extracted mangled names.
- Compare structured fields with tolerances: exact for counts/names/offsets/VAs; set-equality for unordered lists (symbols, classes); checksum match for raw byte-blob extractions (e.g., fat slice = `lipo -thin` output).
- Report per-function pass/fail with concrete divergence diffs.
