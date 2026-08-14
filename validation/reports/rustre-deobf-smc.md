# rustre-deobf-smc — Public API

Crate per analisi e deobfuscation di Self-Modifying Code (SMC) e unpacking:
rilevamento regioni write-then-execute, recupero chiavi/algoritmi di decryption,
emulazione di loop di decrypt, layered/polymorphic unpacking, ricostruzione PE.

Tutte le signature sono raccolte dai moduli pubblici esposti da `lib.rs`.
Conteggio totale `pub fn` (inclusi `const fn`): **500**.

---

## `lib.rs` — API principale e tipi condivisi

### `SmcRegion` (regione SMC con chiave/algoritmo)
- `const fn len(&self) -> u64` — lunghezza in byte della regione.
- `const fn is_empty(&self) -> bool` — true se vuota.

### `SmcDecryptor` (emula decrypt data una regione)
- `const fn new() -> Self`
- `fn decrypt(&self, data: &[u8], region: &SmcRegion) -> Vec<u8>` — applica XOR/ADD/SUB/ROL/ROR/Rolling/Custom secondo `region`.

### `SmcDetector` (rilevamento statico pattern SMC)
- `const fn new() -> Self`
- `fn detect(&self, data: &[u8]) -> Vec<SmcRegion>` — scansiona pattern XOR-loop, ADD-loop, rolling XOR, PUSH/POP+XOR.

### `SmcPatcher` (genera `Patch` pre-decifrati)
- `const fn new() -> Self`
- `fn build_patches(&self, data: &[u8], region: &SmcRegion, file_offset: usize) -> Result<Vec<Patch>, DeobfError>`

### `LayeredSmc` (decrypt iterativo multilayer)
- `const fn new(max_layers: usize) -> Self`
- `fn decrypt_all(&self, data: &[u8]) -> (Vec<u8>, usize)` — ritorna bytes finali e n. layer processati.

### `EmuRegisters` (registri minimi emulatore)
- `fn read(&self, reg: u8) -> u64`
- `fn write(&mut self, reg: u8, val: u64)`

### `EmulatedDecrypt` (trace XOR/ADD/ROL loops)
- `const fn new() -> Self`
- `fn trace(&self, code: &[u8], max_iter: usize) -> EmulationTrace`

### `SmcPass` (impl `DeobfPass`)
- `const fn new() -> Self`

### `DynamicSmcDetector` (legacy, dynamic write log)
- `fn new() -> Self`
- `fn add_write(&mut self, pc: u64, address: u64, value: u8)`
- `fn is_smc_execution(&self, exec_pc: u64) -> bool`
- `fn events(&self) -> &[WriteEvent]`
- `fn to_memory_map(&self) -> HashMap<u64, u8>`

### `DynamicSmcReconstructor`
- `const fn new(memory_map: HashMap<u64, u8>) -> Self`
- `fn from_detector(detector: &DynamicSmcDetector) -> Self`
- `fn reconstruct(&self, base_addr: u64, original_bytes: &[u8]) -> Vec<u8>` — overlay scritture su bytes originali.

### `PolymorphicEngineAnalyzer`
- `const fn new() -> Self`
- `fn analyze(&self, before: &[u8], after: &[u8]) -> Vec<MutationEvent>` — diff e classifica mutazioni (NOP, reg-sub, junk, …).

### `CodeMutationTracker`
- `fn new(initial: Vec<u8>) -> Self`
- `fn add_snapshot(&mut self, snapshot: Vec<u8>)`
- `const fn generation_count(&self) -> usize`
- `fn mutations_at(&self, from: usize) -> &[MutationEvent]`
- `fn all_mutations(&self) -> Vec<&MutationEvent>`
- `fn count_by_type(&self) -> HashMap<String, usize>`
- `fn snapshot(&self, generation: usize) -> Option<&[u8]>`

### `UnpackedRegion`
- `const fn len(&self) -> usize`
- `const fn is_empty(&self) -> bool`

### `UnpackedRegionDetector` (rileva regioni a entropia bassa)
- `const fn new(window_size: usize, entropy_threshold: f64) -> Self`
- `fn detect(&self, data: &[u8]) -> Vec<UnpackedRegion>`

### Funzioni libere
- `fn shannon_entropy(data: &[u8]) -> f64`
- `fn looks_like_code(data: &[u8]) -> bool`
- `fn detect_smc_indicators(code: &[u8]) -> Vec<SmcIndicator>`

### `XorChainStep`
- `fn apply(&self, byte: u8) -> u8`
- `fn reverse(&self, byte: u8) -> u8`

### `XorChain`
- `fn new() -> Self`
- `fn push(&mut self, step: XorChainStep)`
- `fn encrypt(&self, data: &[u8]) -> Vec<u8>`
- `fn decrypt(&self, data: &[u8]) -> Vec<u8>`
- `const fn len(&self) -> usize`
- `const fn is_empty(&self) -> bool`

### `XorChainDetector`
- `const fn new() -> Self`
- `fn detect(&self, code: &[u8]) -> Option<XorChain>`
- `fn from_regions(regions: &[SmcRegion]) -> Self`

### `WriteExecTracker`
- `fn new() -> Self`
- `fn add_write(&mut self, pc: u64, addr: u64, size: u8)`
- `fn add_execution(&mut self, pc: u64, target: u64)`
- `fn find_write_then_execute(&self) -> Vec<(MemWrite, Execution)>`
- `fn clear(&mut self)`

### `SmcPatchManager`
- `fn new() -> Self`
- `fn add_patch(&mut self, patch: Patch)`
- `const fn patch_count(&self) -> usize`
- `fn apply(&self, data: &[u8]) -> Result<Vec<u8>, DeobfError>`
- `fn overlapping_patches(&self) -> Vec<(usize, usize)>`

### `AddRolCipher`
- `const fn new(add_key: u8, rol_amount: u8, add_first: bool) -> Self`
- `fn encrypt_byte(&self, b: u8) -> u8` / `fn decrypt_byte(&self, b: u8) -> u8`
- `fn decrypt(&self, data: &[u8]) -> Vec<u8>` / `fn encrypt(&self, data: &[u8]) -> Vec<u8>`

### `SmcStats` (statistiche aggregate)
- `fn analyze(data: &[u8]) -> Self`
- `const fn with_write_execute_pairs(mut self, count: usize) -> Self`
- `fn with_mutations(mut self, mutations: Vec<MutationEvent>) -> Self`

### `TraceWriteEvent`
- `const fn new(pc: u64, addr: u64, value: u64, size: u8, ts: u64) -> Self`
- `const fn target_end(&self) -> u64`
- `const fn overlaps_range(&self, start: u64, end: u64) -> bool`

### `CodeGenerationTimeline`
- `const fn new() -> Self`
- `fn add_event(&mut self, event: TraceWriteEvent)`
- `fn add_snapshot(&mut self, ts: u64, memory: Vec<u8>)`
- `fn sort_by_time(&mut self)`
- `fn bytes_written_to_range(&self, start: u64, end: u64) -> Vec<&TraceWriteEvent>`
- `fn total_bytes_written(&self) -> usize`
- `fn start_time(&self) -> Option<u64>` / `fn end_time(&self) -> Option<u64>`
- `fn snapshot_at_or_before(&self, ts: u64) -> Option<&(u64, Vec<u8>)>`

### `UnpackStage`
- `const fn duration_ms(&self) -> u64`
- `fn bytes_written(&self) -> usize`
- `fn min_write_addr(&self) -> Option<u64>` / `fn max_write_addr(&self) -> Option<u64>`
- `const fn len(&self) -> usize` / `const fn is_empty(&self) -> bool`

### `UnpackStageAnalyzer`
- `const fn new() -> Self`
- `fn identify_stages(timeline: &CodeGenerationTimeline) -> Vec<UnpackStage>`
- `fn find_oep(stage: &UnpackStage) -> Option<u64>`
- `fn reconstruct_from_snapshot(timeline, stage, ...) -> ...`

### `SmcIndicator`
- `const fn new(offset: usize, kind: SmcKind, confidence: f32) -> Self`

### `CodeGenerationTracer`
- `const fn new() -> Self`
- `fn trace_binary(binary: &[u8], entry: u64) -> CodeGenerationTimeline`

### `UnpackReport`
- `fn generate(timeline: &CodeGenerationTimeline, stages: &[UnpackStage]) -> Self`
- `const fn recommendation_count(&self) -> usize`

---

## `write_monitor.rs` — tracking write/exec runtime

### `CodeWrite`
- `fn new(dest_addr: u64, bytes: &[u8], writer_pc: u64, seq: u64, tick: u64) -> Self`
- `fn is_uniform(&self) -> bool`

### `WrittenBuffer`
- `fn new(region_start: u64, region_end: u64) -> Self`
- `fn apply_event(&mut self, ev: WriteEvent)`
- `fn coverage(&self) -> usize` / `fn as_bytes(&self) -> &[u8]` / `fn size(&self) -> usize`

### `DecryptionLoop` (struct)
- `const fn new(...) -> Self`
- `const fn tick_iteration(&mut self, tick: u64)`
- `const fn span(&self) -> u64`

### `KeyCandidate` (write_monitor)
- `const fn xor(value, operand_bits, insn_addr, confidence) -> Self`
- `const fn add(value, operand_bits, insn_addr, confidence) -> Self`
- `const fn sub(value, operand_bits, insn_addr, confidence) -> Self`
- `const fn is_byte_xor(&self) -> bool`

### `WriteMonitor`
- `fn new() -> Self` / `fn with_config(WriteMonitorConfig) -> Self`
- `fn add_exec_region(&mut self, start: u64, end: u64)`
- `fn remove_exec_region(&mut self, start: u64)`
- `fn is_executable(&self, addr: u64) -> bool`
- `fn on_write(&mut self, dest_addr: u64, bytes: &[u8], writer_pc: u64, tick: u64)`
- `fn on_execute(&mut self, exec_pc: u64)`
- `fn add_key_candidate(&mut self, loop_entry: u64, candidate: KeyCandidate)`
- `fn executed_writes(&self) -> Vec<&CodeWrite>`
- `fn ranked_loops(&self) -> Vec<&DecryptionLoop>`
- `fn drain_events(&mut self) -> Vec<WriteEvent>`
- `fn top_writers(&self, n: usize) -> Vec<(u64, u64)>`
- `fn reset(&mut self)`
- `const fn stats(&self) -> &WriteMonitorStats`

---

## `unpacker_engine.rs` — motore unpacking generico

### `UnpackAlgo`
- `const fn label(self) -> &'static str` / `const fn is_stream(self) -> bool`

### `DecryptionLoop` (unpacker)
- `fn new(offset, algo, confidence) -> Self`
- `const fn with_stride(s) -> Self` / `with_body_size(s)` / `with_key_update()`

### Top-level
- `fn detect_decryption_loops(data: &[u8]) -> Vec<DecryptionLoop>`

### `KeyExtraction`
- `const fn from_immediate(key, algo) -> Self`
- `const fn from_memory(key, addr, algo) -> Self`
- `fn single_byte_key(&self) -> u8`

### Top-level
- `fn extract_key(data: &[u8], loop_offset: usize, algo: UnpackAlgo) -> Option<KeyExtraction>`

### `UnpackedRegion` (unpacker)
- `fn new(offset, decrypted, algorithm, key) -> Self`
- `fn looks_like_code(&self) -> bool`
- `const fn has_low_entropy(&self) -> bool`

### `UnpackingSession`
- `const fn new(layer: usize, data: Vec<u8>) -> Self`
- `fn run(&mut self)`
- `fn best_region(&self) -> Option<&UnpackedRegion>`

### Top-level
- `fn apply_decryption(data: &[u8], key: &[u8], algo: UnpackAlgo) -> Vec<u8>`

### `UnpackingReport`
- `fn from_session(session: &UnpackingSession) -> Self`
- `fn summary(&self) -> String`

### `MultiLayerUnpacker`
- `fn new() -> Self` / `const fn with_max_layers(n) -> Self`
- `fn unpack(&self, data: Vec<u8>) -> (Vec<UnpackingSession>, Vec<UnpackingReport>)`
- `fn final_payload(sessions: &[UnpackingSession]) -> Option<&[u8]>`

### `KeyRecord`
- `fn new(key, algo, found_at, confidence) -> Self`
- `fn hex(&self) -> String`
- `const fn is_high_confidence(&self) -> bool`

### `KeyDatabase`
- `fn new() -> Self` / `fn insert(&mut self, KeyRecord)`
- `fn high_confidence(&self) -> Vec<&KeyRecord>`
- `fn by_algo(&self, algo) -> Vec<&KeyRecord>`
- `const fn len/is_empty`, `fn best(&self) -> Option<&KeyRecord>`

### `PackerDetector`
- `fn new() -> Self`
- `fn detect(&self, data: &[u8]) -> Vec<PackedCandidate>`
- `fn is_packed(&self, data: &[u8]) -> bool`

### `UnpackerEngine`
- `fn new() -> Self` / `const fn with_config(UnpackerConfig)`
- `fn run(&self, data: Vec<u8>) -> Vec<UnpackingReport>`
- `fn has_decryption_loop(&self, data: &[u8]) -> bool`
- `fn algorithm_summary(reports: &[UnpackingReport]) -> HashMap<String, usize>`

---

## `smc_detector.rs`

### `SmcPattern`
- `fn new(region: SmcRegion, pattern_name: impl Into<String>) -> Self`
- `const fn high_confidence(self) -> Self`
- `const fn makes_executable(&self) -> bool`
- `const fn has_exec(&self) -> bool`

### `SmcCluster`
- `fn new(index: u32, region: SmcRegion) -> Self`

### `SmcDetector` (modulo)
- `const fn new() -> Self`
- `fn detect_all(&self, data: &[u8], base_addr: u64) -> SmcDetectionResult`

### `SmcDetectionResult`
- `const fn total_patterns(&self) -> usize`
- `const fn has_smc(&self) -> bool`
- `fn summary(&self) -> String`

---

## `smc_write_tracker.rs`

### Tipi regione
- `const fn len/is_empty/contains(addr) -> ...`

### `SmcWriteTracker`
- `fn new() -> Self`
- `fn record_write(&mut self, write_pc, target_addr, value)`
- `fn record_exec(&mut self, pc, exec_addr)`
- `fn is_written(addr) / is_executed(addr) -> bool`
- `fn confirmed_pairs(&self) -> &[WriteXorExecute]`
- `fn compute_regions(&self, gap_threshold: u64) -> Vec<SmcRegion>`
- `fn page_state(&self, addr: u64) -> PageState`
- `fn smc_pages(&self) -> Vec<u64>`
- `fn clear(&mut self)`
- `fn event_log(&self) -> &[SmcEvent]`
- `fn memory_snapshot(&self) -> HashMap<u64, u8>`

---

## `key_recovery.rs`

### `KeyAlgorithm`
- `const fn name(&self) -> &'static str`
- `const fn key_len(&self) -> Option<usize>`

### `KeyCandidate`
- `const fn new(...) -> Self`
- `fn with_provenance(p) -> Self`
- `fn hex(&self) -> String`
- `fn fingerprint(&self) -> u64`

### `KeyHarvester`
- `fn new() -> Self` / `const fn with_min_confidence(c) -> Self`
- `fn harvest(&self, data: &[u8], base_addr: u64) -> Vec<KeyCandidate>`

### `KeySet`
- `fn new() -> Self`
- `fn add(KeyCandidate)` / `add_all(Vec<KeyCandidate>)`
- `fn len/is_empty`
- `fn all_sorted(&self) -> Vec<&KeyCandidate>`
- `fn by_algorithm(algo) -> Vec<&KeyCandidate>`
- `fn best(&self) -> Option<&KeyCandidate>`
- `fn clear(&mut self)`

### `KeyRecovery`
- `fn new() -> Self` / `const fn with_min_confidence(c)`
- `fn scan_region(&mut self, data, base_addr)`
- `fn recover_keys(&self) -> Vec<&KeyCandidate>`
- `fn best_key_for(&self, algo) -> Option<&KeyCandidate>`
- `fn key_count(&self) -> usize`

---

## `smc_decryptor_extractor.rs`

### `KeySchedule`
- `fn static_key(bytes: Vec<u8>) -> Self`
- `fn to_hex(&self) -> String`
- `fn step(&self) -> Vec<u8>`

### `DecryptorLoop`
- `const fn new(offset, size, kind, key_schedule) -> Self`
- `const fn with_confidence(c)`
- `fn add_note(&mut self, note)`
- `fn decrypt(&self, data: &[u8]) -> Vec<u8>`

### `DecryptorExtractor`
- `const fn new()` / `with_min_size/max_size/min_confidence`
- `fn extract(&self, code: &[u8]) -> Vec<DecryptorLoop>`

---

## `smc_extractor.rs`

### `SmcLayer`
- `fn new(id, base_va, encrypted, decryptor_entry, depth) -> Self`
- `fn set_decrypted(&mut self, bytes)`
- `const fn size(&self) -> usize`
- `fn entropy(&self) -> f64`
- `fn diff(&self) -> Vec<(usize, u8, u8)>`

### `ExtractedFunction`
- `fn placeholder(va, len) -> Self`
- `const fn new(entry: u64) -> Self`
- `const fn insn_count(&self) -> usize`

### `ExtractedCode`
- `const fn new(layer_id) -> Self`
- `fn from_linear_sweep(layer_id, base_va, bytes) -> Self`
- `fn identify_functions(&mut self, base_va: u64)`
- `const fn insn_count(&self) -> usize`
- `fn call_targets(&self) -> Vec<u64>`

### `LayerStack`
- `const fn new() -> Self`
- `fn push_layer(...)`
- `fn set_decrypted(id, bytes) -> bool`
- `fn get(id) / get_mut(id) -> Option<...>`
- `fn all_layers(&self) -> &[SmcLayer]`
- `const fn depth(&self) -> usize`
- `fn innermost_decrypted(&self) -> Option<&SmcLayer>`

### `LayerDecryption`
- `fn new(layer_id, algorithm, key, ticks) -> Self`
- `const fn mark_complete(self) -> Self`

### `ExtractionRegistry`
- `fn new() -> Self`
- `fn add_stack(&mut self, base_va) -> &mut LayerStack`
- `fn record_extraction(&mut self, code)`
- `fn record_decryption(&mut self, dec)`
- `fn update_total_layers(&mut self)`
- `fn all_functions(&self) -> Vec<&ExtractedFunction>`
- `fn deepest_layer(&self) -> Option<&SmcLayer>`

### `SmcExtractor`
- `fn new() -> Self`
- `fn begin_layer(base_va, bytes, decryptor_entry) -> LayerId`
- `fn finalize_layer(base_va, id, decrypted: &[u8])`
- `fn record_decryption(dec)`
- `const fn finish(&mut self)`
- `fn total_functions(&self) -> usize`

---

## `smc_patched_code_reconstructor.rs`

### `ReconstructResult`
- `const fn is_usable(&self) -> bool`

### `PatchedCode`
- `fn new(base, original, bytes, result) -> Self`
- `fn is_unchanged(&self) -> bool`
- `fn diff_count(&self) -> usize`
- `fn add_note(note)`
- `fn to_hex(&self) -> String`

### `WriteRecord`
- `const fn new(region_offset, bytes, seq) -> Self`

### `DecryptSpec`
- `const fn new(kind, key) -> Self`
- `fn decrypt_inplace(&self, data: &mut [u8])`

### `PatchedCodeReconstructor`
- `const fn new() -> Self`
- `const fn with_entropy_range(min, max) -> Self`
- `fn reconstruct(...) -> ...`
- `fn reconstruct_batch(...) -> ...`
- `fn is_likely_code(&self, bytes: &[u8]) -> bool`

---

## `smc_region_tracker.rs`

### `ModificationEvent`
- `const fn write(address, size, bytes, seq) -> Self`
- `const fn execute(address, size, seq) -> Self`
- `fn with_tag(self, tag)`

### `SmcRegion` (tracker)
- `const fn new(id, base, size) -> Self`
- `const fn contains(addr) -> bool` / `overlaps(other) -> bool`
- `fn push_event(event)`
- `fn write_count/execute_count/total_bytes_written -> usize`
- `fn reconstruct_bytes(&self) -> Vec<u8>`

### `SmcRegionTracker`
- `fn new() -> Self`
- `const fn with_byte_capture(self) -> Self`
- `fn register(base, size) -> u64`
- `fn record_write(address, bytes) -> Option<u64>`
- `fn record_execute(address, size) -> Option<u64>`
- `fn confirmed_regions(&self) -> Vec<&SmcRegion>`
- `fn all_regions(&self) -> &[SmcRegion]`
- `fn get_by_base(base) / get_by_id(id) -> Option<&SmcRegion>`
- `const fn len/is_empty`
- `fn report(&self) -> String`

---

## `pe_unpacker.rs`

### Misc
- `fn display(&self) -> String`
- `const fn base_score(self) -> f32`

### `PeSection`
- `const fn is_executable/is_writable/contains(va) -> bool`

### `IatReconstructor`
- `fn new(iat_base, iat_size) -> Self`
- `fn register_export(func_va, module, symbol)`
- `fn scan(memory, is_64bit) -> Vec<IatEntry>`
- `fn auto_detect_bounds(memory, image_base, is_64bit) -> (u64, u64)`

### `OepDetector`
- `const fn new(config, sections) -> Self`
- `fn submit_candidate(va, method)`
- `fn best(&self) -> Option<&OepCandidate>`
- `fn check_upx_tail(data, image_base)`
- `fn all_candidates(&self) -> Vec<&OepCandidate>`

### `Relocator`
- `const fn new(old_base, new_base) -> Self`
- `const fn delta(&self) -> i64`
- `fn apply(memory, entry) -> bool`
- `fn apply_all(memory, entries) -> usize`

### `PeDump`
- `const fn is_valid(&self) -> bool`
- `fn summary(&self) -> String`

### `PeUnpacker`
- `fn new(...) -> Self`
- `fn detect_oep_static(&mut self)`
- `fn submit_oep_candidate(va, method)`
- `fn dump(&mut self) -> Option<PeDump>`
- `const fn oep_detector(&self) -> &OepDetector`

### `PackerSignatureDb`
- `fn default_db() -> Self`
- `fn scan(data, image_base) -> Vec<(String, u64)>`

---

## `smc_emulator.rs`

### `EmulationStep`
- `fn new(step, pc) -> Self`
- `fn with_annotation(s)`

### `WriteMap`
- `fn read(addr) -> Option<u8>`
- `fn extract(base, len, fill) -> Vec<u8>`
- `fn len/is_empty`

### `FinalRegion`
- `const fn len/is_empty/end -> ...`

### `SmcEmulator`
- `fn new(config) -> Self`
- `fn push_write(...) -> Result<...>`
- `fn push_writes<I>(iter) -> Result<...>`
- `fn attach_regs(regs)`
- `fn request_capture(...)`
- `fn run_full(&mut self) -> Result<&[PayloadCapture], EmulatorError>`
- `fn step_once(&mut self) -> Option<&EmulationWrite>`
- `fn step_until_pc(target_pc) -> Option<usize>`
- `fn reset_replay()`
- `fn read_byte(addr) -> Option<u8>`
- `fn read_range(base, len, fill) -> Vec<u8>`
- `fn capture_now(label) -> PayloadCapture`
- `fn final_regions(&self) -> Vec<FinalRegion>`
- `fn captures(&self) -> &[PayloadCapture]`
- `fn capture_by_label(label) -> Option<&PayloadCapture>`
- `fn capture_at_or_before(step) -> Option<&PayloadCapture>`
- `fn stats(&self) -> EmulatorStats`
- `const fn replay_cursor/total_writes -> usize`
- `fn unique_address_count(&self) -> usize`

### Top-level
- `fn diff_captures(before, after) -> Vec<CaptureDiff>`
- `fn detect_decrypt_rounds(...) -> ...`

### `EmulatorQueue`
- `fn new(config) -> Self`
- `fn enqueue(target_addr, value, write_pc)`
- `fn drain(n) -> Result<usize, EmulatorError>`
- `fn drain_all() -> Result<usize, EmulatorError>`
- `fn pending_count(&self) -> usize`
- `const fn emulator/emulator_mut -> &SmcEmulator`

---

## `emulation_harness.rs`

### `ApiHookEvent`
- `fn new(pc, hook_type, args) -> Self`

### `WrittenRegion`
- `fn new(base, bytes) -> Self`
- `const fn len/is_empty`

### `HarnessResult`
- `fn total_decoded_bytes(&self) -> usize`
- `const fn region_count/has_keys`
- `fn summary(&self) -> String`

### `ImportPatcher`
- `fn new() -> Self`
- `fn register_stub(import_name, stub_addr)`
- `fn patch_iat(iat_addr, stub_addr)`
- `fn apply(data: &mut [u8], image_base: u64)`
- `fn patch_count(&self) -> usize`

### `MemorySpace`
- `fn new(page_size) -> Self`
- `fn map(base, data)`
- `fn read_byte(addr) -> Option<u8>`
- `fn write_byte(addr, val)`
- `fn read_range(start, len) -> Vec<u8>`
- `fn written_region(start, len) -> Option<WrittenRegion>`

### `EmulationHarness`
- `fn new() -> Self`
- `fn load_binary(data, base_addr)`
- `fn add_region(region: SmcRegion)`
- `fn restart(binary, base_addr)`
- `fn run(base_addr) -> HarnessResult`
- `fn patch_import(name, iat_addr, stub_addr)`
- `fn written_regions(&self) -> Vec<WrittenRegion>`

---

## `layer_extractor.rs`

### `EmulationConfig`
- `fn fast() -> Self`

### `ExtractedLayer`
- `fn new(...) -> Self`
- `fn entropy_dropped(&self) -> bool`
- `const fn len/is_empty`

### serde helpers
- `fn serialize<S>(arr, ser) -> Result<...>`
- `fn deserialize<'de, D>(de) -> Result<[u32; 256], D::Error>`

### `LayerAnalysis`
- `fn compute(index, before, after) -> Self`
- `fn entropy_delta(&self) -> f64`

### `LayerExtractor`
- `fn new() -> Self`
- `const fn with_config(config, max_layers) -> Self`
- `fn extract(data, regions) -> Vec<ExtractedLayer>`
- `fn emulate_decrypt(data, region) -> Vec<u8>`
- `fn extract_with_analysis(...) -> ...`
- `fn extract_recursive(...) -> ...`

### Top-level
- `fn total_bytes(layers) -> usize`
- `fn best_layer(layers) -> Option<&ExtractedLayer>`

---

## `smc_monitor.rs`

### `MonitoredRegion`
- `fn new(start, end, label) -> Self`
- `const fn size/contains`

### `DecryptedPayload`
- `fn entropy_reduction(&self) -> f64`
- `fn looks_like_code(&self) -> bool`

### `SmcEventLog`
- `fn new() -> Self`
- `fn record(...)`
- `fn duration_ms(&self) -> u64`
- `fn layer_count(&self) -> usize`

### `SmcMonitorReport`
- `fn new() -> Self`
- `fn add_payload(payload)`
- `fn text_summary(&self) -> String`

### `SmcMonitor` (multilayer driver)
- `const fn new() -> Self` / `const fn with_max_layers(n)`
- `fn decrypt_all(data) -> SmcMonitorReport`

### `RuntimeSmcMonitor`
- `const fn new() -> Self`
- `fn add_region(region)`
- `fn on_write(addr, data)`
- `fn on_execute(addr) -> bool`
- `fn write_before_exec_pairs(&self) -> Vec<(u64, u64)>`
- `fn memory_snapshot(&self) -> HashMap<u64, u8>`
- `const fn alert_count/write_count/exec_count`

### `SmcAddressDetector`
- `fn new() -> Self`
- `fn is_smc(exec_addr, write_log) -> bool`
- `fn find_smc_addresses(exec_log, write_log) -> Vec<u64>`

---

## `decryption_loop_analyzer.rs`

### `Insn`
- `const fn is_branch(&self) -> bool`
- `fn branch_target(&self, base_offset: u64) -> Option<u64>`

### `Decoder<'a>`
- `const fn new(data, base, x64) -> Self`
- `fn decode_one(&mut self) -> Result<Insn>`
- `fn decode_all(&mut self) -> Vec<Insn>`

### Top-level
- `fn emulate_decrypt(data, loop_info) -> EmulatedResult`

### `LoopAnalyzer`
- `const fn new(x64, base_address) -> Self`
- `fn analyze(code) -> AnalysisResult`
- `fn analyze_and_decrypt(code, data) -> Vec<EmulatedResult>`
- `fn brute_force_xor_key(encrypted) -> Option<u8>`
- `fn brute_force_add_key(encrypted) -> Option<u8>`

### Top-level
- `fn reconstruct_key_schedule(initial_key, length, step) -> KeySchedule`
- `fn identify_xor_key_from_frequency(ciphertext, key_len) -> Vec<u8>`

---

## `smc_reconstructor.rs`

### `Snapshot`
- `fn diff_bytes(&self, prev: &Self) -> usize`
- `fn has_function_prologue(&self) -> bool`
- `fn entropy(&self) -> f64`
- `fn merge(self, other) -> Self`

### `AlgorithmInverse`
- `fn apply_inverse(&self, ciphertext: &[u8]) -> Vec<u8>`

### `SmcReconstructor`
- `const fn new(config, base_addr, encrypted) -> Self`
- `fn with_defaults(base_addr, encrypted) -> Self`
- `fn record_write(event: WriteEvent)`
- `fn commit_snapshot(tick: u64)`
- `fn peel_layer(algorithm, key, region) -> bool`
- `fn detect_re_encryption(&self) -> bool`
- `fn assemble_fragments(&self) -> Vec<CodeFragment>`
- `fn report(&self) -> ReconstructionReport`
- `fn current_bytes(&self) -> &[u8]`
- `fn write_log(&self) -> &[WriteEvent]`
- `fn is_complete(&self) -> bool`
- `fn total_bytes_recovered(&self) -> usize`
- `fn summary(&self) -> String`

### `Stride`
- `fn from_region(region_size, stride) -> Self`
- `const fn dynamic(self) -> Self`
- `fn with_register(self, reg) -> Self`

### `TaintMap`
- `fn taint_range(base, bytes)`
- `fn is_tainted(addr) -> bool`
- `fn tainted_count(&self) -> usize`
- `fn contiguous_ranges(&self) -> Vec<(u64, Vec<u8>)>`
- `fn clear(&mut self)`

---

## `smc_payload_extractor.rs`

### `WritePatch`
- `const fn new(addr, value, write_pc, timestamp) -> Self`

### `MemorySnapshot`
- `const fn new() -> Self`
- `fn apply(&mut self, patch: &WritePatch) -> Result<(), ExtractorError>`
- `fn read(addr) -> Option<u8>`
- `fn len/is_empty`
- `fn iter(&self) -> impl Iterator<Item = (u64, u8)>`
- `fn written_addresses(&self) -> Vec<u64>`
- `fn extract_range(base, len, fill) -> Vec<u8>`

### `ReconstructedRegion`
- `const fn len/is_empty`
- `fn byte_at(off) -> Option<u8>`
- `const fn end(&self) -> u64`

### `ReconstructedCode`
- `fn region_containing(addr) -> Option<&ReconstructedRegion>`
- `fn read_byte(addr) -> Option<u8>`
- `fn executed_regions(&self) -> Vec<&ReconstructedRegion>`

### `SmcPayloadExtractor`
- `fn new(config) -> Self`
- `fn add_patch(patch) -> Result<...>`
- `fn add_patches<I>(patches) -> Result<...>`
- `fn mark_executed(addr)` / `mark_executed_batch(addrs)`
- `const fn snapshot(&self) -> &MemorySnapshot`
- `const fn stats(&self) -> &ExtractorStats`
- `fn distinct_write_pcs(&self) -> usize`
- `fn reconstruct(&mut self) -> Result<ReconstructedCode, ExtractorError>`
- `fn clear(&mut self)`
- `fn from_tuples(...) -> ...`
