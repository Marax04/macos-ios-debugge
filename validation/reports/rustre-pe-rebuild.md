# rustre-pe-rebuild — Public API

Crate per la ricostruzione di file PE da dump di memoria o immagini parzialmente corrotte: IAT, relocation, export, OEP, import directory, overlay, section/header fixup.

Conteggio funzioni pubbliche elencate: ~401 (free + inherent + const fn).

---

## Modulo `lib.rs` (root)

### `RebuildSection`
- `new(name: String, virtual_address: u32, data: Vec<u8>, characteristics: u32) -> Self` — costruisce sezione, virtual_size inferito da `data.len()`.
- `code(name: String, virtual_address: u32, data: Vec<u8>) -> Self` — sezione eseguibile (CODE|EXEC|READ).
- `data(name: String, virtual_address: u32, data: Vec<u8>) -> Self` — sezione data RW.
- `rdata(name: String, virtual_address: u32, data: Vec<u8>) -> Self` — sezione read-only.
- `entropy(&self) -> f64` — entropia Shannon della sezione.
- `is_executable(&self) -> bool` / `is_writable(&self) -> bool` — query flag.
- `virtual_end(&self) -> u32` — fine range VA.
- `contains_rva(&self, rva: u32) -> bool` — verifica appartenenza RVA.
- `rva_to_offset(&self, rva: u32) -> Option<usize>` — RVA → offset interno a `data`.

### `RebuildFlags`
- `contains(self, flag: Self) -> bool`, `is_64bit/is_dll/fix_checksum/fix_imports/fix_relocations/strip_overlay(self) -> bool` — query bitflag su opzioni rebuild.

### `IatEntry`
- `is_resolved(&self) -> bool` — true se nome o ordinal noti.
- `import_description(&self) -> String` — stringa "DLL!name" o "DLL!#ord".

### `IatFixer`
- `new(options: IatFixOptions) -> Self` — costruttore.
- `add_entry(&mut self, entry: IatEntry)` — aggiunge slot IAT.
- `register_import(&mut self, address: u64, dll: String, name: String)` — mappa indirizzo runtime → simbolo.
- `fix(&mut self) -> Result<usize, RebuildError>` — risolve tutte le entry registrate.
- `entries(&self) -> &[IatEntry]` — accesso slice entry.
- `resolved_count(&self) -> usize` — numero risolte.
- `apply_to_image(&self, pe_data: &mut [u8], image_base: u64) -> Result<usize, RebuildError>` — scrive thunk risolti nel buffer PE.

### `RelocationEntry`
- `absolute() -> Self` — entry padding tipo 0.
- `dir64(rva: u32) -> Self` / `highlow(rva: u32) -> Self` — costruttori per tipo 10/3.
- `is_meaningful(&self) -> bool` — non-padding.

### `RelocationRebuilder`
- `new(options: RelocationOptions) -> Self`
- `add_entry(&mut self, entry: RelocationEntry)`, `add_dir64(&mut self, rva: u32)`, `add_highlow(&mut self, rva: u32)` — registra rilocazioni.
- `entry_count(&self) -> usize` — entry significative.
- `delta(&self) -> i64` — delta new_base − original_base.
- `build_reloc_section(&self) -> Result<Vec<u8>, RebuildError>` — serializza sezione `.reloc`.
- `apply_to_image(&self, image: &mut [u8]) -> Result<usize, RebuildError>` — patcha buffer applicando il delta.

### `ExportEntry`
- `named(name: String, ordinal: u32, rva: u32) -> Self`
- `ordinal_only(ordinal: u32, rva: u32) -> Self`
- `forwarder(name: String, ordinal: u32, target: String) -> Self`
- `has_name(&self) -> bool`

### `ExportRebuilder`
- `new(dll_name: String, ordinal_base: u32) -> Self`
- `add_entry(&mut self, entry: ExportEntry)`
- `export_count(&self) -> usize`
- `build(&self, section_rva: u32) -> Result<Vec<u8>, RebuildError>` — costruisce blob IMAGE_EXPORT_DIRECTORY completo.
- `dll_name(&self) -> &str`

### `OepDetector`
- `new() -> Self`
- `detect(&mut self, sections: &[RebuildSection], known_ep_rva: Option<u32>) -> Result<OepResult, RebuildError>` — euristiche (prologhi, entropia, EP esplicito).
- `candidates(&self) -> &[OepResult]`

### `OverlayInfo` / `OverlayHandler`
- `OverlayInfo::has_overlay(&self) -> bool`
- `OverlayHandler::detect(pe_bytes: &[u8]) -> Result<OverlayInfo, RebuildError>` — rileva byte dopo l'ultima sezione raw.
- `OverlayHandler::extract(pe_bytes: &[u8]) -> Result<Vec<u8>, RebuildError>` — estrae overlay.
- `OverlayHandler::preserve(pe_bytes: &[u8], rebuilt: &mut Vec<u8>) -> Result<OverlayInfo, RebuildError>` — appende overlay al PE ricostruito.

### Funzioni libere
- `apply_fixups(image: &mut [u8], opts: &PeFixupOptions) -> Result<Vec<String>, RebuildError>` — orchestratore fixup (EP, signature, checksum, DLL flag).
- `is_memory_pe(data: &[u8]) -> bool` — verifica magic MZ.
- `compute_entropy(data: &[u8]) -> f64` — entropia Shannon.
- `crc16_ccitt(data: &[u8]) -> u16` — CRC16.
- `compute_imphash(entries: &[IatEntry]) -> String` — imphash stile VT.
- `detect_oep_heuristics(dump: &[u8], base: u64) -> Vec<OepCandidate>` — scan euristico OEP su dump.

### `PeRebuilder` (root)
- `new(config: RebuildConfig) -> Self`
- `add_section(&mut self, section: RebuildSection) -> &mut Self`
- `section_by_name(&self, name: &str) -> Option<&RebuildSection>`
- `section_at_rva(&self, rva: u32) -> Option<&RebuildSection>`
- `virtual_end(&self) -> u32`
- `rebuild(&self) -> Result<RebuildResult, RebuildError>` — assembla PE valido.
- `from_memory_dump(data: &[u8], base_addr: u64, config: RebuildConfig) -> Result<RebuildResult, RebuildError>` — ricostruzione da dump.
- `align_up(value: u32, align: u32) -> u32` — utility.
- `config(&self) -> &RebuildConfig`, `section_count(&self) -> usize`, `sections(&self) -> &[RebuildSection]`
- `sort_sections(&mut self)`, `clear_sections(&mut self)`
- `rebuild_with_oep_detection(&mut self) -> Result<RebuildResult, RebuildError>` — rebuild + auto-OEP.

### IAT scanning helpers (root, modulo "scan/IatRegion")
- `IatRegion::slot_count(&self) -> usize`, `is_non_empty(&self) -> bool`
- `scan_for_iat(dump: &[u8], base: u64) -> Vec<IatRegion>` — trova cluster IAT in dump.
- `resolve_pointer(...)` / `resolve_batch(...)` — risoluzione puntatori IAT.
- `build_valid_pe(dump: &[u8], base: u64, oep: u64) -> Result<Vec<u8>, RebuildError>` — pipeline completa.
- `auto_build(dump: &[u8], base: u64) -> Result<Vec<u8>, RebuildError>` — variante con autodetect OEP.
- `find_iat_regions(dump: &[u8], base: u64) -> Vec<IatRegion>`
- `total_entries(&self) -> usize`, `resolved_count(&self) -> usize`
- `rebuild_iat_from_memory(...)` — ricostruisce IAT da snapshot processo.
- `verify_pe_validity(pe_data: &[u8]) -> Vec<String>` — checklist diagnostica.
- `fix_iat(dump: &mut [u8], base_addr: u64) -> Result<(), RebuildError>`
- `fix_section_flags(dump: &mut [u8]) -> Result<(), RebuildError>`

### `IatEntry2` / `LoadedModule` / `MemoryRebuilder` (root)
- `IatEntry2::named(rva: u64, dll: impl Into<String>, fn: impl Into<String>) -> Self`
- `IatEntry2::ordinal(rva: u64, dll: impl Into<String>, ord: u16) -> Self`
- `IatEntry2::display_name(&self) -> String`
- `LoadedModule::new(name: impl Into<String>, base: u64, size: u64) -> Self`
- `LoadedModule::contains(&self, addr: u64) -> bool`
- `MemoryRebuilder::new_x64/new_x86(process_memory: Vec<u8>, image_base: u64, modules: Vec<LoadedModule>) -> Self`
- `MemoryRebuilder::va_to_offset(&self, va: u64) -> Option<usize>`
- `MemoryRebuilder::scan_for_iat(&self) -> Vec<u64>`
- `MemoryRebuilder::rebuild_import_directory(&self, entries: &[IatEntry2]) -> Vec<u8>`
- `MemoryRebuilder::fix_pe_checksum(&mut self) -> Result<u32, RebuildError>`
- `MemoryRebuilder::find_oep_heuristic(&self) -> Vec<u64>`
- `MemoryRebuilder::dump_process_memory(&self, base: u64, size: usize, memory: &[u8]) -> Vec<u8>`

---

## Modulo `iat_rebuilder.rs`
- `PointerSize::byte_len(self) -> usize` — dimensione puntatore (4/8).
- `PointerSize::read_ptr(self, data: &[u8], offset: usize) -> Option<u64>` — lettura LE.
- `ExportedSymbol::is_forwarder(&self) -> bool`, `is_ordinal_only(&self) -> bool`
- `LoadedModule::new(name, base, image_size) -> Self`, `add_export(&mut self, sym)`, `contains_va(&self, va) -> bool`, `resolve_va(&self, va) -> Option<&ExportedSymbol>`
- `ResolvedIatEntry::is_by_name(&self) -> bool`, `hint_name_bytes(&self) -> Vec<u8>`
- `IatScanner::new(ptr_size, image_base) -> Self`, `image_base(&self) -> u64`, `va_to_rva(&self, va) -> Option<u32>`, `add_module(&mut self, module)`
- `IatScanner::scan_iat(...)` — scan range IAT.
- `IatScanner::scan_sections(...)` — scan sezioni.
- `IatScanner::rebuild_import_section(...)` — costruisce .idata.
- `ImportSection::import_dir_rva(&self) -> u32`, `import_dir_size(&self) -> u32`
- `DelayLoadDescriptor::new(dll_name, ordinal) -> Self`, `int_entry(&self, ptr_size) -> u64`
- `detect_iat_clusters(...)` — euristica cluster.
- `rebuild_delay_import_section(...)` — sezione delay-load.
- `merge_resolved_entries(...)`, `sort_resolved_entries(entries: &mut [ResolvedIatEntry])`
- `IatStatistics::from_entries(&[ResolvedIatEntry]) -> Self`

## Modulo `import_rebuilder.rs`
- `ImportThunk::by_name_pe32(hint_name_rva: u32) -> Self`, `by_ordinal_pe32(ordinal: u16) -> Self`, `ordinal(&self) -> Option<u16>`
- `OrdinalToName::new()`, `insert(dll, ordinal, name)`, `lookup(dll, ordinal) -> Option<&str>`, `dll_count() -> usize`, `total_entries() -> usize`, `resolve_thunks(dll, thunks: &mut [ImportThunk])`
- `ImportByHash::new(algo)`, `hash(name) -> u32`, `register(dll, name)`, `resolve(hash) -> Option<(&str,&str)>`, `len/is_empty`
- `IatPatcher::new(image_base, is_pe32plus)`, `image_base() -> u64`, `patch_slot(...)`, `wipe_slot(buf, iat_rva) -> Result<(), ImportRebuildError>`
- `DelayLoadBuilder::new()`, `add_entry(entry)`, `entries() -> &[DelayLoadEntry]`, `serialize() -> Vec<u8>`, `entry_count() -> usize`
- `BoundImportStripper::new()`, `apply(buf: &mut [u8]) -> Result<usize, ImportRebuildError>`
- `ImportDirectoryBuilder::new()`, `add_entry(e)`, `with_ordinal_db(db)`, `with_hash_resolver(r)`, `resolve_ordinals()`, `grouped() -> HashMap<&str, Vec<&ImportEntry>>`, `build_directory() -> Vec<u8>`, `dll_count()/entry_count()`

## Modulo `oep_finder.rs`
- `SectionInfo::is_executable(&self) -> bool`, `contains_rva(&self, rva) -> bool`
- `OepFinder::from_bytes(data: Vec<u8>, image_base: u64) -> Result<Self, RebuildError>`
- `OepFinder::sections() -> &[SectionInfo]`, `executable_sections() -> impl Iterator`, `section_containing_rva(rva) -> Option<&SectionInfo>`, `rva_to_file_offset(rva) -> Option<usize>`
- `scan_prologue_patterns() -> Vec<OepCandidate>` — pattern di prologo.
- `scan_crt_stubs() -> Vec<OepCandidate>` — stub CRT.
- `first_executable_section_oep() -> Option<OepCandidate>`
- `validate_candidate(...)` — verifica candidato.
- `detect_entropy_transition() -> Vec<OepCandidate>` — transizione entropia (unpack).
- `record_hwbp_oep(rva) -> OepCandidate` — registra OEP da HW breakpoint.
- `scan_all() -> Result<Vec<OepCandidate>, RebuildError>`
- `best_candidate<'a>(...)` — selezione migliore.
- `valid(&self) -> bool`
- `recover_stolen_bytes(...)` — recupero stolen bytes.

## Modulo `oep_detection.rs`
- `StolenBytesFragment::is_confident(&self) -> bool`, `has_prologue(&self) -> bool`
- `StolenBytesScanner::new()`, `scan(&mut self, data, range)`, `best_candidate() -> Option<&StolenBytesFragment>`, `clear()`, `count() -> usize`
- `OepDetectionEngine::new(base: u64)`, `run_all(&mut self, dump)`, `run_on_sections(&mut self, sections)`, `set_known_oep(ep_rva)`, `best() -> Option<&OepCandidate>`, `filtered_candidates() -> Vec<&OepCandidate>`, `candidate_count() -> usize`

## Modulo `pe_dump_fixer.rs`
- `FixerFlags::contains/repair_signatures/recalc_size_of_image/recalc_size_fields/convert_virtual_to_raw/strip_security_dir/rebase_to_default(self) -> bool` — bitflag.
- `PeDumpFixer::new(data: Vec<u8>, cfg: DumpFixerConfig) -> Result<Self, RebuildError>`
- `section_name_histogram() -> HashMap<String,usize>`
- `overwrite_section_field(...)` — patch campo header sezione.
- `fix(mut self) -> Result<FixResult, RebuildError>` — esegue tutti i fix.
- `fix_dump_default(data) -> Result<FixResult, RebuildError>` — wrapper.
- `fix_dump_with_base(data, actual_base) -> Result<FixResult, RebuildError>` — wrapper con base.

## Modulo `pe_fixup.rs`
- `PatchInfo::new(...)`, `VerifyResult::is_ok() -> bool`
- `PeFixupVerifier::verify(image: &[u8]) -> VerifyResult` — verifica PE.
- `PeFixup::new(image: Vec<u8>) -> Self`, `image() -> &[u8]`, `finish(self) -> (Vec<u8>, Vec<PatchInfo>)`, `patches() -> &[PatchInfo]`
- `fix_checksum/fix_bound_imports/strip_signature/clear_debug_dir(&mut self) -> Result<(), FixupError>`
- `set_entry_point(&mut self, ep_rva: u32) -> Result<(), FixupError>`
- `set_dll_flag(&mut self, is_dll: bool) -> Result<(), FixupError>`
- `align_section_virtual_sizes(...) -> Result<(), FixupError>`
- `sort_section_table(&mut self) -> Result<usize, FixupError>`
- `fix_size_of_image(&mut self) -> Result<(), FixupError>`
- `apply_all(&mut self) -> Result<Vec<String>, FixupError>` — pipeline completa.

## Modulo `pe_header_fixer.rs`
- `DataDirectoryEntry::is_present(&self) -> bool`, `from_bytes(b) -> Option<Self>`, `to_bytes(self) -> [u8; 8]`
- `FixerReport::is_clean(&self) -> bool`, `change_count(&self) -> usize`
- `ValidationResult::ok(...)`, `fail(...)` — costruttori esito.
- `FixerFlags::fix_checksum/fix_size_of_image/fix_size_of_headers/fix_timestamp/fix_image_base/fix_data_directories/fix_num_sections(self) -> bool`
- `PeHeaderFixer::new(config: FixerConfig) -> Self`
- `parse_layout(&self, pe: &[u8]) -> Option<PeLayout>`
- `compute_checksum(pe: &[u8], checksum_off: usize) -> u32` — checksum PE standard.
- `validate(&self, pe: &[u8]) -> Vec<ValidationResult>`
- `fix(&self, pe: &mut [u8]) -> FixResult`

## Modulo `pe_section_rebuilder.rs`
- `SectionRebuildFlags::align_sections/recalculate_checksums/fix_rva_mismatches/pad_to_file_alignment(self) -> bool`
- `SectionRebuildInfo::name_str() -> String`, `virtual_end() -> u32`, `raw_end() -> u32`
- `PeSectionRebuilder::new(data: Vec<u8>) -> Result<Self, SectionRebuildError>`
- `config(self, cfg) -> Self` — builder.
- `scan_implicit_sections(&mut self)` — trova sezioni non dichiarate.
- `fix_section_alignment(&mut self)`, `rebuild_section_table() -> Result<(),_>`, `merge_overlapping_sections()`, `split_large_sections()`, `reorder_by_rva()`, `reassign_raw_offsets()`
- `rebuild_all(&mut self) -> Result<(), SectionRebuildError>`
- `recalculate_checksum(&mut self)`
- `generate_rebuild_report(&self) -> Vec<String>`
- `validate_rebuilt_pe(&self) -> Vec<ValidationIssue>`
- `finish(mut self) -> Result<Vec<u8>, SectionRebuildError>`
- `sections() -> &[SectionRebuildInfo]`, `is_pe32_plus() -> bool`, `section_table_offset_from_nt() -> usize`
- `characteristics_histogram() -> HashMap<u32,usize>`, `sections_mut() -> &mut Vec<SectionRebuildInfo>`
- `infer_characteristics(name: &str) -> u32` — euristica flag da nome sezione.

## Modulo `pe_reconstructor.rs`
- `SectionEntry::is_executable/is_writable/is_code(&self) -> bool`, `rva_to_file_off(&self, rva) -> Option<usize>`
- `find_pe_candidates(dump: &[u8]) -> Vec<usize>` — offset candidati PE.
- `calculate_pe_checksum(data: &[u8], checksum_offset: usize) -> u32`
- `PeReconstructor::new(config: ReconstructConfig) -> Self`, `with_defaults() -> Self`
- `reconstruct(&self, dump: &[u8]) -> Result<(Vec<u8>, ReconstructStats)>`
- `analyze(&self, dump: &[u8]) -> Result<HeaderAnalysis>`
- `patch_u16_le(data: &mut [u8], off: usize, v: u16)`
- `parse_imports(pe_data: &[u8]) -> Result<Vec<ImportEntry>>`

## Modulo `pe_dumper.rs`
- `DumpFlags::fix_pe_header/realign_sections/rebuild_imports/dump_overlay/include_certificate(self) -> bool`
- `PeContext::name_str(&self) -> String`
- `PeDumper::new(options: DumpOptions) -> Self`
- `dump_from_memory(&self, source: DumpSource) -> Result<PeDumpResult, DumpError>`
- `fix_nt_header(...)` — patch header NT.
- `realign_sections(...)` — riallinea sezioni.
- `pe_from_module_handle(...)` — costruisce PE da HMODULE.
- `detect_unmap_protection(...)` — euristica anti-unmap.
- `overlay_data(data, ctx) -> Vec<u8>`
- `PeContext::parse(data: &[u8]) -> Result<Self, DumpError>`
- `opt_magic() -> u16`, `pointer_size() -> usize`, `checksum_field_offset() -> usize`
- `section_characteristics_histogram() -> HashMap<u32,usize>`

## Modulo `relocation_rebuilder.rs`
- `RelocationType::value(self) -> u8`, `size_bytes(self) -> usize`, `from_nibble(n) -> Option<Self>`
- `RelocationEntry::highlow(rva) -> Self`, `dir64(rva) -> Self`, `is_padding() -> bool`, `encode_word(page_base) -> u16`
- `RelocationBlock::new(page_rva)`, `add_entry(&mut self, entry) -> Result<(), String>`, `sort()`, `serialised_size() -> usize`, `to_bytes() -> Vec<u8>`, `real_entry_count() -> usize`
- `RelocationTableBuilder::new_x64(image_base)`, `new_x86(image_base)`, `add_fixup(rva) -> bool`, `add_fixup_typed(rva, type) -> bool`, `add_fixups(rvas)`, `remove_fixup(rva) -> bool`, `clear()`, `fixup_count() -> usize`, `stats() -> &RelocationStatistics`, `blocks() -> Vec<RelocationBlock>`, `build() -> Vec<u8>`, `import_reloc_section(data) -> Result<usize, String>`, `heuristic_scan_x64(...)` — scan euristico x64.
- `rebuild_relocs(rvas, image_base, is_x64) -> Vec<u8>` — funzione libera.

## Modulo `scylla_iat_rebuilder.rs` (porting Scylla)
- `FunctionPointer::null()`, `unresolved(va)`, `resolved(...)`, `by_ordinal(va, module, ordinal)`, `is_resolved() -> bool`
- `IATEntry::new(rva, pointer)`, `terminator(rva)`, `is_null() -> bool`
- `ModuleMapping::new(name, base, size)`, `add_export(va, ord, name)`, `contains(va) -> bool`, `resolve(va) -> Option<FunctionPointer>`, `export_count() -> usize`
- `IatWriter::new_pe32(image_base, iat_rva)`, `new_pe64(image_base, iat_rva)`, `write_iat(...)`, `ensure_capacity(buf, required)`
- `ScyllaReport::success() -> bool`, `resolution_rate() -> f64`
- `ScyllaIatRebuilder::new(image_base, ptr_size)`, `new_pe32(image_base)`, `new_pe64(image_base)`, `add_module(mapping) -> IatResult<()>`, `add_raw_entry(rva, va)`, `scan_flat_iat(buf, iat_rva)`, `resolve_all() -> Vec<IATEntry>`, `group_by_module<'a>(...)`, `rebuild(pe_buf, iat_file_offset) -> IatResult<ScyllaReport>`

## Modulo `import_table_rebuilder.rs`
- `ResolvedImport::named(iat_rva, dll, fn) -> Self`, `by_ordinal(iat_rva, dll, ord) -> Self`, `has_name() -> bool`, `description() -> String`
- `IatReference::new(insn_addr, iat_rva, is_call, is_rip_relative) -> Self`
- `ImageThunkData::by_name(name_rva)`, `by_ordinal64(ord)`, `by_ordinal32(ord)`, `to_le_bytes() -> [u8;8]`, `to_le_bytes32() -> [u8;4]`
- `ImportDescriptor::new(dll_name, first_thunk)`, `function_count() -> usize`, `write_descriptor(buf: &mut Vec<u8>)`
- `ImportTableRebuilder::new()`, `with_config(config) -> Self`
- `add_export(va, dll, fn)`, `load_exports(&[(u64,&str,&str)])`
- `scan_code(code, code_rva)` — trova IAT refs in disassembly.
- `resolve_from_image(image)` — risolve usando export delle DLL caricate.
- `register_entry(IatEntry)`
- `build_descriptors() -> Vec<ImportDescriptor>`
- `build_idata_blob(section_rva) -> (Vec<u8>, usize)`
- `hint_count() -> usize`, `resolved_count() -> usize`, `resolved_entries() -> Vec<&IatEntry>`, `config() -> &ImportRebuilderConfig`

## Modulo `section_aligner.rs`
- `AlignmentFix::has_change(&self) -> bool`
- `AlignmentReport::actual_fixes() -> Vec<&AlignmentFix>`, `corrected_count() -> usize`, `needs_correction() -> bool`
- `SectionDescriptor::new(...)`
- `SectionAligner::new(file_alignment, section_alignment) -> Self`, `default_pe() -> Self`, `align_up(value, align) -> u32`
- `fix_section(index, section: &SectionDescriptor) -> AlignmentFix`
- `align_all(sections: &[SectionDescriptor]) -> AlignmentReport`
- `repack_offsets(...)`

## Modulo `section_realigner.rs`
- `RawSectionHeader::name_str() -> String`, `is_code/is_writable/is_readable(&self) -> bool`, `aligned_raw_size(virtual_size, file_align) -> u32`, `from_bytes(b) -> Option<Self>`, `to_bytes() -> [u8;40]`
- `align_up(val, align) -> u32`, `align_down(val, align) -> u32` — utility libere.
- `AlignResult::is_clean() -> bool`, `sections_modified() -> usize`
- `SectionRealigner::new(config: RealignConfig) -> Self`
- `parse_sections(pe_bytes, section_table_off, count)` — parse table.
- `realign(headers, current_headers_size, ...)` — calcola layout riallineato.
- `characteristics_histogram(&self, result) -> HashMap<u32,usize>`
- `apply(pe_bytes: &mut [u8], section_table_off, ...)` — applica al buffer.

---

Note:
- Conteggio totale grep `pub fn|pub const fn` nei sorgenti: 401.
- Non sono incluse impl `Default`, `Display`, `Debug`, `From`, ops (`BitOr`/`BitAnd`).
- Tests sotto `tests/blitz.rs`, `tests/blitz2.rs` non esposti come API pubblica.
