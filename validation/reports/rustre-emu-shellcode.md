# rustre-emu-shellcode

Crate per l'emulazione, analisi euristica e classificazione di shellcode x86/x64.
Dipende da `rustre-emu` (motore di emulazione core), `serde`/`serde_json`, `thiserror`.

---

## Moduli e funzioni pubbliche

### lib.rs — punto d'ingresso principale

| Funzione | Firma | Descrizione |
|---|---|---|
| `ShellcodeEmulator::run` | `(&self, shellcode: &[u8]) -> Result<ExecutionResult, EmulatorError>` | Esegue lo shellcode nell'emulatore e restituisce il risultato dell'esecuzione (API calls, memoria, ecc.) |
| `BehaviorAnalyzer::detect_api_hashing` | `(result: &ExecutionResult) -> bool` | Rileva se lo shellcode usa API hashing (es. ROR-13) |
| `BehaviorAnalyzer::detect_decode_loop` | `(result: &ExecutionResult) -> bool` | Rileva loop di decodifica/decifrazione nel trace di esecuzione |
| `BehaviorAnalyzer::detect_network_stub` | `(result: &ExecutionResult) -> bool` | Rileva presenza di stub di rete (WSAStartup, connect, send, ecc.) |
| `BehaviorAnalyzer::extract_strings` | `(result: &ExecutionResult) -> Vec<String>` | Estrae stringhe prodotte a runtime dopo l'emulazione |
| `ShellcodeHook::new` | `(address: u64, name: impl Into<String>, return_value: u64) -> Self` | Crea un hook sintetico per un indirizzo (intercetta chiamata API) |
| `ShellcodeRunner::run_sc` | `(shellcode: &[u8], arch: &str) -> Result<ShellcodeRunResult, EmulatorError>` | Esegue shellcode specificando architettura ("x86", "x64") |
| `ShellcodeRunner::run_with_hooks` | `(shellcode: &[u8], arch: &str, hooks: Vec<ShellcodeHook>) -> Result<ShellcodeRunResult, EmulatorError>` | Esegue shellcode con hook personalizzati per API |
| `ShellcodeRunner::convert_result` | `(result: ExecutionResult, hooks: &[ShellcodeHook]) -> ShellcodeRunResult` | Converte `ExecutionResult` in `ShellcodeRunResult` annotando le API rilevate |
| `ShellcodeRunner::arch_from_str` | `(arch: &str) -> EmulatorArch` | Converte stringa architettura in enum `EmulatorArch` |
| `ApiDatabase::new` | `() -> Self` | Crea un database vuoto di API note |
| `ApiDatabase::stubs` | `(&self) -> &[ApiStub]` | Restituisce gli stub API registrati |
| `ApiDatabase::annotate` | `(&self, calls: &mut [ApiCall])` | Annota le chiamate API con nomi simbolici |
| `ApiDatabase::scan_for_api_names` | `(&self, bytes: &[u8]) -> Vec<(usize, &str)>` | Scansiona byte grezzi cercando nomi API noti |

---

### x86_emulator.rs — emulatore x86 a basso livello

| Funzione | Firma | Descrizione |
|---|---|---|
| `X86Mem::new` | `() -> Self` | Crea mappa di memoria vuota |
| `X86Mem::read_u8/u16/u32/u64` | `(&self, addr: u64) -> Option<uN>` | Legge N bit da indirizzo virtuale |
| `X86Mem::write_u8/u16/u32/u64` | `(&mut self, addr: u64, val: uN)` | Scrive N bit a indirizzo virtuale |
| `X86Mem::map_bytes` | `(&mut self, addr: u64, data: &[u8])` | Mappa un buffer in memoria a un indirizzo base |
| `X86Mem::stack_push` | `(&mut self, cpu: &mut X86Cpu, val: u64)` | Push di un valore nello stack emulato |
| `X86Mem::stack_pop` | `(&mut self, cpu: &mut X86Cpu) -> Option<u64>` | Pop dallo stack emulato |
| `X86Emulator::new` | `(max_steps: usize) -> Self` | Crea emulatore con limite di step |
| `X86Emulator::load_shellcode` | `(&mut self, code: &[u8], base: u64)` | Carica shellcode all'indirizzo base specificato |
| `X86Emulator::step` | `(&mut self) -> Result<(), EmulatorError>` | Esegue una singola istruzione |
| `X86Emulator::run` | `(&mut self) -> Result<usize, EmulatorError>` | Esegue finché stop condition o max_steps; ritorna numero di step eseguiti |

---

### x86_emulator_hooks.rs — sistema di hook e tracciamento

| Funzione | Firma | Descrizione |
|---|---|---|
| `HookDispatcher::new` | `() -> Self` | Crea dispatcher hook vuoto |
| `HookDispatcher::register` | `(&mut self, hook: Box<dyn HookCallback>)` | Registra un callback hook |
| `HookDispatcher::dispatch` | `(&mut self, event: &HookEvent) -> HookResult` | Notifica tutti gli hook registrati di un evento |
| `HookDispatcher::get_hook` | `(&self, name: &str) -> Option<&dyn HookCallback>` | Cerca hook per nome |
| `HookDispatcher::hook_count` | `(&self) -> usize` | Numero di hook registrati |
| `DebugHook::new` | `(verbose: bool) -> Self` | Hook di debug con output opzionale verbose |
| `WinApiStub::new` | `() -> Self` | Stub per API Windows sintetiche |
| `WinApiStub::resolve_name` | `(&self, name: &str) -> Option<u64>` | Risolve nome API a indirizzo stub |
| `WinApiStub::handle_call` | `(&mut self, name: &str, regs: &RegisterSnapshot) -> Option<u32>` | Gestisce una chiamata API simulata, ritorna valore di ritorno |
| `SyscallTable::new` | `(os_version: OsVersion) -> Self` | Crea tabella syscall per versione OS specificata |
| `SyscallTable::resolve` | `(&self, number: u32) -> Option<&'static str>` | Risolve numero syscall a nome simbolico |
| `MemRegion::contains` | `(&self, addr: u64) -> bool` | Verifica se addr cade nella regione |
| `MemRegion::overlaps` | `(&self, other: &MemRegion) -> bool` | Verifica sovrapposizione tra regioni |
| `SelfModificationTracker::new` | `() -> Self` | Tracker per rilevare auto-modifica del codice |
| `SelfModificationTracker::has_self_modification` | `(&self) -> bool` | True se rilevata scrittura su pagine eseguibili |
| `ApiCallLog::new` | `() -> Self` | Crea log chiamate API vuoto |
| `ApiCallLog::calls_to` | `(&self, api: &str) -> Vec<&ApiCallRecord>` | Filtra chiamate per nome API |
| `ApiCallLog::was_called` | `(&self, api: &str) -> bool` | True se l'API è stata chiamata |
| `ApiCallLog::unique_apis` | `(&self) -> Vec<String>` | Lista API univoche chiamate |
| `NetworkActivity::new` | `() -> Self` | Struttura riassuntiva attività di rete |
| `NetworkActivity::has_network_activity` | `(&self) -> bool` | True se rilevate chiamate di rete |
| `PcTrace::with_capacity` | `(capacity: usize) -> Self` | Trace PC con capacità preallocata |
| `PcTrace::new` | `() -> Self` | Trace PC con capacità default |
| `PcTrace::push` | `(&mut self, pc: u64)` | Aggiunge un PC al trace |
| `PcTrace::snapshot` | `(&self) -> Vec<u64>` | Copia del trace corrente |
| `PcTrace::contains` | `(&self, pc: u64) -> bool` | True se PC è nel trace |
| `PcTrace::detect_loops` | `(&self, threshold: usize) -> Vec<(u64, usize)>` | Rileva indirizzi visitati piu di threshold volte (loop) |
| `PcTrace::last_pc` | `(&self) -> Option<u64>` | Ultimo PC nel trace |
| `ror13_hash` | `(s: &str) -> u32` | Calcola hash ROR-13 di una stringa (comune in shellcode per API hashing) |

---

### shellcode_analysis.rs — analisi statica + euristica integrata

| Funzione | Firma | Descrizione |
|---|---|---|
| `ShellcodeAnalyzer::analyze` | `(&self, data: &[u8], _base: u64) -> ShellcodeProfile` | Analisi completa: arch, tecniche, indicatori di rete, OS probabile |
| `ShellcodeAnalyzer::detect_arch` | `(&self, data: &[u8]) -> ShellcodeArch` | Rileva architettura (x86/x64/ARM/...) da pattern opcode |
| `ShellcodeAnalyzer::detect_techniques` | `(&self, data: &[u8]) -> Vec<ShellcodeTechnique>` | Identifica tecniche (PEB walk, GetProcAddress hash, XOR decode, ecc.) |
| `ShellcodeAnalyzer::find_xor_loops` | `(&self, data: &[u8]) -> Vec<DecodedPayload>` | Trova e tenta di decodificare loop XOR nel payload |
| `ShellcodeAnalyzer::extract_network_indicators` | `(&self, data: &[u8]) -> Vec<String>` | Estrae URL, IP, hostname embedded staticamente |
| `ShellcodeAnalyzer::detect_os` | `(&self, data: &[u8], techniques: &[ShellcodeTechnique]) -> ProbableOs` | Stima OS target in base a tecniche rilevate |

---

### shellcode_classifier.rs — classificazione shellcode

| Funzione | Firma | Descrizione |
|---|---|---|
| `ShellcodeType::as_str` | `(&self) -> &'static str` | Nome stringa del tipo shellcode |
| `ObfuscationKind::as_str` | `(&self) -> &'static str` | Nome stringa del tipo di offuscamento |
| `Platform::as_str` | `(&self) -> &'static str` | Nome stringa della piattaforma |
| `Stage::as_str` | `(&self) -> &'static str` | Stadio shellcode (stager, payload, loader, ecc.) |
| `ClassificationResult::unknown` | `(size: usize) -> Self` | Crea risultato "sconosciuto" per dati non classificabili |
| `ClassificationResult::is_likely_malicious` | `(&self) -> bool` | True se classificazione indica probabilità malware alta |
| `ClassificationResult::summary` | `(&self) -> String` | Stringa riassuntiva della classificazione |
| `ShellcodeClassifier::classify` | `(data: &[u8]) -> ClassificationResult` | Classifica shellcode in tipo, piattaforma, offuscamento, stadio |
| `compute_entropy` | `(data: &[u8]) -> f64` | Entropia di Shannon dei byte (0..8) |
| `scan` | `(data: &[u8], pattern: &[u8]) -> Option<usize>` | Scansione lineare per pattern di byte |
| `detect_xor_key` | `(data: &[u8]) -> Option<u8>` | Tenta di identificare chiave XOR a singolo byte |
| `detect_api_hashing` | `(data: &[u8]) -> bool` | Rileva pattern bytecode tipici di API hashing |
| `ByteDistribution::new` | `(data: &[u8]) -> Self` | Calcola distribuzione frequenza byte |
| `ByteDistribution::most_common` | `(&self) -> (u8, u32)` | Byte piu frequente e il suo conteggio |
| `ByteDistribution::null_ratio` | `(&self) -> f32` | Frazione di byte 0x00 |
| `ByteDistribution::printable_ratio` | `(&self) -> f32` | Frazione di byte ASCII stampabili |
| `ByteDistribution::unique_bytes` | `(&self) -> usize` | Numero di valori byte distinti |
| `ByteDistribution::entropy` | `(&self) -> f64` | Entropia della distribuzione |
| `classify_layers` | `(layers: &[Vec<u8>]) -> Vec<ClassificationResult>` | Classifica ogni strato (output unpacker) separatamente |

---

### shellcode_decoder.rs — decodifica multistadio

| Funzione | Firma | Descrizione |
|---|---|---|
| `DecoderLoop::detect` | `(code: &[u8]) -> Vec<DecoderLoop>` | Rileva loop di decodifica nel bytecode (XOR, ADD, ROT, ecc.) |
| `DecodedStage::new` | `(...)  -> Self` | Crea uno stadio decodificato con dati e metadati algoritmo |
| `DecodedStage::entropy_drop` | `(&self) -> f64` | Differenza di entropia prima/dopo la decodifica |
| `StageChain::new` | `() -> Self` | Catena di stadi decodificati vuota |
| `StageChain::push` | `(&mut self, stage: DecodedStage)` | Aggiunge uno stadio alla catena |
| `StageChain::final_payload` | `(&self) -> &[u8]` | Payload dell'ultimo stadio decodificato |
| `StageChain::has_pe_payload` | `(&self) -> bool` | True se il payload finale ha magic MZ/PE |
| `StageChain::algorithm_chain` | `(&self) -> Vec<DecoderAlgorithm>` | Sequenza di algoritmi usati nella catena |
| `StageChain::total_entropy_reduction` | `(&self) -> f64` | Riduzione totale di entropia attraverso gli stadi |
| `DecoderStub::hash` | `(stub: &[u8]) -> u64` | Hash FNV64 dello stub di decodifica |
| `DecoderStub::hash_hex` | `(stub: &[u8]) -> String` | Hash hex dello stub |
| `DecoderStub::structural_hash` | `(stub: &[u8]) -> u64` | Hash strutturale (ignora costanti) per similarità |
| `ShellcodeFamily::classify` | `(shellcode: &[u8]) -> ShellcodeFamily` | Classifica famiglia shellcode (Metasploit, CobaltStrike, custom, ecc.) |
| `MultiStageDecoder::new` | `() -> Self` | Decoder multistadio con algoritmi default |
| `MultiStageDecoder::decode_layer` | `(&self, data: &[u8], stage_idx: usize) -> Option<DecodedStage>` | Tenta decodifica di uno strato |
| `MultiStageDecoder::decode_all` | `(&self, shellcode: &[u8]) -> StageChain` | Decodifica tutti gli stadi in cascata |
| `MultiStageDecoder::classify` | `(&self, shellcode: &[u8]) -> ShellcodeFamily` | Classifica famiglia dopo decodifica |
| `MultiStageDecoder::find_decoder_loops` | `(&self, shellcode: &[u8]) -> Vec<DecoderLoop>` | Trova loop di decodifica nel codice grezzo |
| `MultiStageDecoder::decoder_hash` | `(&self, shellcode: &[u8]) -> String` | Hash identificativo del decoder usato |
| `MultiStageDecoder::decode_and_run` | `(&self, shellcode: &[u8], ...) -> Result<...>` | Decodifica e poi esegue il payload nell'emulatore |

---

### shellcode_emulator.rs — contesto di emulazione di alto livello

| Funzione | Firma | Descrizione |
|---|---|---|
| `EmulatedMemoryRegion::new` | `(base: u64, size: usize, tag: impl Into<String>) -> Self` | Crea regione di memoria emulata con tag descrittivo |
| `EmulatedMemoryRegion::write_at` | `(&mut self, offset: usize, bytes: &[u8]) -> usize` | Scrive bytes alla regione a offset specificato |
| `EmulatedMemoryRegion::read_at` | `(&self, offset: usize, len: usize) -> &[u8]` | Legge slice dalla regione |
| `ShellcodeContext::new` | `() -> Self` | Contesto di emulazione vuoto |
| `ShellcodeContext::set_reg` | `(&mut self, name: impl Into<String>, value: u64)` | Imposta registro dell'emulatore per nome |
| `ShellcodeContext::get_reg` | `(&self, name: &str) -> u64` | Legge valore registro dell'emulatore |
| `ShellcodeContext::region_at` | `(&self, addr: u64) -> Option<&EmulatedMemoryRegion>` | Restituisce regione che contiene addr |
| `ShellcodeContext::region_at_mut` | `(&mut self, addr: u64) -> Option<&mut EmulatedMemoryRegion>` | Mutabile: regione che contiene addr |
| `ShellcodeContext::add_region` | `(&mut self, region: EmulatedMemoryRegion)` | Aggiunge regione di memoria al contesto |
| `ShellcodeContext::read_va` | `(&self, addr: u64, len: usize) -> Vec<u8>` | Legge byte da indirizzo virtuale |
| `ShellcodeContext::write_va` | `(&mut self, addr: u64, bytes: &[u8]) -> usize` | Scrive byte a indirizzo virtuale |
| `ShellcodeContext::total_mapped_bytes` | `(&self) -> usize` | Totale byte mappati in memoria |
| `ApiHook::new` | `(name: impl Into<String>, address: u64, return_value: u64) -> Self` | Crea hook API a un indirizzo specifico |
| `ApiHook::virtual_alloc` | `(address: u64, alloc_base: u64) -> Self` | Hook preconfigurato per VirtualAlloc |
| `ApiHook::load_library` | `(address: u64, module_handle: u64) -> Self` | Hook preconfigurato per LoadLibrary |
| `ApiHook::get_proc_address` | `(address: u64, proc_address: u64) -> Self` | Hook preconfigurato per GetProcAddress |
| `MemoryDump::from_context` | `(ctx: &ShellcodeContext, label: impl Into<String>) -> Self` | Snapshot di tutta la memoria emulata con etichetta |
| `MemoryDump::region` | `(&self, base: u64) -> Option<&[u8]>` | Restituisce regione da snapshot per indirizzo base |
| `MemoryDump::total_bytes` | `(&self) -> usize` | Byte totali nel dump |
| `MemoryDump::extract_strings` | `(&self, min_len: usize) -> Vec<String>` | Estrae stringhe ASCII/UTF-16 dal dump di memoria |
| `MemoryDump::diff` | `(before: &Self, after: &Self) -> Vec<(u64, Vec<Option<u8>>)>` | Differenza tra due snapshot (byte modificati) |
| `EmulationResult::new` | `(exit_reason: impl Into<String>) -> Self` | Risultato di un'emulazione con motivo di uscita |
| `EmulationResult::called_api` | `(&self, name: &str) -> bool` | True se l'API è stata chiamata durante l'emulazione |
| `EmulationResult::calls_to` | `(&self, name: &str) -> Vec<&ApiCallRecord>` | Lista chiamate all'API specificata |
| `EmulationResult::distinct_apis_called` | `(&self) -> usize` | Numero API distinte chiamate |
| `EmulationResult::dump` | `(&self, label: &str) -> Option<&MemoryDump>` | Dump di memoria per etichetta (pre/post) |
| `HighLevelEmulator::new` | `() -> Self` | Emulatore di alto livello con API Windows simulate |
| `HighLevelEmulator::load_shellcode` | `(&mut self, base: u64, code: &[u8])` | Carica shellcode all'indirizzo specificato |
| `HighLevelEmulator::add_stack` | `(&mut self, base: u64, size: usize)` | Alloca regione stack |
| `HighLevelEmulator::add_heap` | `(&mut self, base: u64, size: usize)` | Alloca regione heap |
| `HighLevelEmulator::add_hook` | `(&mut self, hook: ApiHook)` | Aggiunge hook API personalizzato |
| `HighLevelEmulator::add_common_windows_hooks` | `(&mut self)` | Aggiunge hook per VirtualAlloc, LoadLibrary, GetProcAddress, ecc. |
| `HighLevelEmulator::hook_at` | `(&self, addr: u64) -> Option<&ApiHook>` | Trova hook all'indirizzo addr |
| `HighLevelEmulator::hook_at_mut` | `(&mut self, addr: u64) -> Option<&mut ApiHook>` | Trova hook mutabile all'indirizzo addr |
| `HighLevelEmulator::simulate` | `<I>(&mut self, instruction_pcs: I) -> EmulationResult` | Simula una sequenza di PC (modalita step-by-step) |
| `HighLevelEmulator::run` | `(&mut self, steps: Vec<(u64, Vec<u64>)>) -> EmulationResult` | Esegue piu step con argomenti per hook |
| `HighLevelEmulator::dump` | `(&self, label: impl Into<String>) -> MemoryDump` | Snapshot della memoria corrente |

---

### shellcode_heuristics.rs — scoring euristico

| Funzione | Firma | Descrizione |
|---|---|---|
| `ShellcodeScore::is_shellcode` | `(&self) -> bool` | True se score supera soglia "shellcode" |
| `ShellcodeScore::is_high_confidence` | `(&self) -> bool` | True se score supera soglia "alta confidenza" |
| `ShellcodeScore::label` | `(&self) -> &'static str` | Etichetta testuale ("Shellcode", "Likely Shellcode", "Benign", ecc.) |
| `HeuristicScorer::new` | `() -> Self` | Scorer con set di euristiche default |
| `HeuristicScorer::feature_descriptions` | `(&self) -> Vec<&'static str>` | Descrizioni testuali delle euristiche attive |
| `HeuristicScorer::analyse` | `(&self, data: &[u8]) -> ShellcodeScore` | Calcola score euristico per i dati in input |
| `ShellcodeCategory::classify` | `(score: &ShellcodeScore) -> ShellcodeCategory` | Mappa score in categoria (Benign/Suspicious/Shellcode/HighConfidence) |
| `shannon_entropy` | `(data: &[u8]) -> f64` | Entropia di Shannon (funzione libera) |
| `ascii_ratio` | `(data: &[u8]) -> f64` | Rapporto byte ASCII su totale |
| `unique_byte_count` | `(data: &[u8]) -> usize` | Numero di valori byte unici |
| `EmbeddedBlock::analyse` | `(data: &[u8], offset: usize, base_address: u64) -> Self` | Analizza un blocco embedded (PE, shellcode annidato, ecc.) |
| `EmbeddedBlock::should_flag` | `(&self) -> bool` | True se il blocco merita un flag di attenzione |
| `scan_for_shellcode` | `(data: &[u8], ...) -> Vec<ShellcodeHit>` | Scansione di un buffer per trovare shellcode embedded |

---

### shellcode_loader.rs — caricamento e IAT sintetica

| Funzione | Firma | Descrizione |
|---|---|---|
| `MemFlags::contains` | `(self, other: Self) -> bool` | Test flag permessi memoria (R/W/X) |
| `MemFlags::bits` | `(self) -> u8` | Valore bitmask permessi |
| `MemoryRegion::new` | `(base: u64, data: Vec<u8>, flags: MemFlags, tag: impl Into<String>) -> Self` | Crea regione di memoria con dati e permessi |
| `MemoryRegion::end` | `(&self) -> u64` | Indirizzo fine regione |
| `MemoryRegion::contains_addr` | `(&self, addr: u64) -> bool` | True se addr appartiene alla regione |
| `MemoryRegion::read` | `(&self, addr: u64, len: usize) -> Option<&[u8]>` | Legge slice dalla regione |
| `MemoryRegion::write` | `(&mut self, addr: u64, bytes: &[u8]) -> bool` | Scrive bytes nella regione (verifica permessi W) |
| `MemoryMap::new` | `() -> Self` | Mappa di memoria vuota |
| `MemoryMap::add_region` | `(&mut self, region: MemoryRegion)` | Aggiunge regione alla mappa |
| `MemoryMap::alloc` | `(&mut self, base: u64, size: usize, flags: MemFlags, tag: impl Into<String>)` | Alloca regione zeroed con permessi |
| `MemoryMap::region_at` | `(&self, addr: u64) -> Option<&MemoryRegion>` | Regione che contiene addr |
| `MemoryMap::region_at_mut` | `(&mut self, addr: u64) -> Option<&mut MemoryRegion>` | Regione mutabile che contiene addr |
| `MemoryMap::read` | `(&self, addr: u64, len: usize) -> Option<Vec<u8>>` | Legge attraverso regioni multiple |
| `MemoryMap::write` | `(&mut self, addr: u64, bytes: &[u8]) -> bool` | Scrive attraverso regioni multiple |
| `MemoryMap::is_executable` | `(&self, addr: u64) -> bool` | True se addr ha permessi X |
| `MemoryMap::total_size` | `(&self) -> usize` | Totale byte allocati |
| `MemoryMap::regions` | `(&self) -> &[MemoryRegion]` | Slice di tutte le regioni |
| `DetectionResult::from_signals` | `(signals: Vec<DetectionSignal>) -> Self` | Costruisce risultato da segnali di rilevamento |
| `DetectionResult::analyze` | `(bytes: &[u8]) -> DetectionResult` | Analisi statica per rilevamento shellcode |
| `ShellcodeLoader::new` | `(config: LoadConfig) -> Self` | Loader con configurazione personalizzata |
| `ShellcodeLoader::with_defaults` | `() -> Self` | Loader con configurazione default |
| `ShellcodeLoader::load` | `(&self, shellcode: &[u8]) -> LoadedShellcode` | Carica shellcode in memoria emulata con stack/heap/IAT |
| `FakeIat::new` | `(base: u64) -> Self` | IAT sintetica a indirizzo base |
| `FakeIat::register` | `(&mut self, dll: impl Into<String>, function: impl Into<String>) -> u64` | Registra entry IAT e ritorna l'indirizzo stub assegnato |
| `FakeIat::lookup` | `(&self, dll: &str, function: &str) -> Option<u64>` | Risolve dll+funzione a indirizzo stub |
| `FakeIat::map_into` | `(&self, memory: &mut MemoryMap)` | Scrive gli stub della IAT in memoria |
| `FakeIat::entries` | `(&self) -> &[IatEntry]` | Lista entries IAT registrate |
| `build_default_iat` | `(base: u64) -> FakeIat` | Crea IAT predefinita con funzioni Windows comuni (VirtualAlloc, LoadLibrary, ecc.) |

---

### shellcode_tracer.rs — coverage, taint, trace

| Funzione | Firma | Descrizione |
|---|---|---|
| `CoverageBitmap::new` | `(base: u64, range: usize) -> Self` | Bitmap di copertura per un range di indirizzi |
| `CoverageBitmap::mark` | `(&mut self, addr: u64)` | Marca addr come visitato |
| `CoverageBitmap::is_covered` | `(&self, addr: u64) -> bool` | True se addr e stato eseguito |
| `CoverageBitmap::covered_count` | `(&self) -> usize` | Byte coperti |
| `CoverageBitmap::coverage_pct` | `(&self) -> f64` | Percentuale di copertura |
| `CoverageBitmap::merge` | `(&mut self, other: &CoverageBitmap)` | Union di due bitmap (multi-run) |
| `BasicBlock::new` | `(start: u64) -> Self` | Blocco base da indirizzo start |
| `BasicBlock::instruction_count` | `(&self) -> usize` | Numero istruzioni nel blocco |
| `BasicBlock::byte_size` | `(&self) -> u64` | Dimensione in byte del blocco |
| `BlockTracer::new` | `() -> Self` | Tracer di basic block |
| `BlockTracer::record_instruction` | `(&mut self, pc: u64, size: usize, opcode_hint: u8)` | Registra esecuzione di un'istruzione |
| `BlockTracer::flush_block` | `(&mut self, end_addr: u64)` | Finalizza il blocco corrente |
| `BlockTracer::blocks` | `(&self) -> &HashMap<u64, BasicBlock>` | Tutti i blocchi tracciati |
| `BlockTracer::block_count` | `(&self) -> usize` | Numero blocchi |
| `BlockTracer::hottest_block` | `(&self) -> Option<&BasicBlock>` | Blocco piu eseguito |
| `BlockTracer::total_instruction_executions` | `(&self) -> u64` | Totale esecuzioni istruzioni |
| `TaintByte::clean` | `() -> Self` | Byte non tainted |
| `TaintByte::from_input` | `(byte_index: usize) -> Self` | Byte tainted da input offset specificato |
| `TaintByte::add_label` | `(&mut self, label: TaintLabel)` | Aggiunge etichetta taint |
| `TaintRegisters::new` | `() -> Self` | Stato taint dei registri vuoto |
| `TaintRegisters::set` | `(&mut self, reg_id: u32, taint: TaintByte)` | Imposta taint per registro |
| `TaintRegisters::get` | `(&self, reg_id: u32) -> &TaintByte` | Legge taint di un registro |
| `TaintRegisters::clear` | `(&mut self, reg_id: u32)` | Rimuove taint da registro |
| `TaintRegisters::tainted_registers` | `(&self) -> Vec<u32>` | Lista registri tainted |
| `TaintMemory::new` | `() -> Self` | Mappa taint memoria vuota |
| `TaintMemory::taint_range` | `(&mut self, addr: u64, len: usize, label: TaintLabel)` | Applica taint a range di memoria |
| `TaintMemory::taint_input` | `(&mut self, base_addr: u64, input: &[u8])` | Taint di un intero buffer di input |
| `TaintMemory::clear_range` | `(&mut self, addr: u64, len: usize)` | Rimuove taint da range |
| `TaintMemory::is_tainted` | `(&self, addr: u64) -> bool` | True se addr e tainted |
| `TaintMemory::get` | `(&self, addr: u64) -> &TaintByte` | Legge TaintByte per addr |
| `TaintMemory::tainted_byte_count` | `(&self) -> usize` | Numero di byte tainted |
| `TaintMemory::input_bytes_for` | `(&self, addr: u64) -> Vec<usize>` | Offset input che influenzano addr |
| `ShellcodeTracer::new` | `(base: u64, range: usize) -> Self` | Tracer principale per shellcode |
| `ShellcodeTracer::set_max_events` | `(&mut self, max: usize)` | Limita numero massimo eventi registrati |
| `ShellcodeTracer::seed_input_taint` | `(&mut self, base: u64, shellcode: &[u8])` | Inizializza taint da input shellcode |
| `ShellcodeTracer::on_instruction` | `(&mut self, pc: u64, opcode_byte: u8, size: u8)` | Callback istruzione eseguita |
| `ShellcodeTracer::on_mem_read` | `(&mut self, addr: u64, size: u8, value: u64)` | Callback lettura memoria |
| `ShellcodeTracer::on_mem_write` | `(&mut self, addr: u64, size: u8, value: u64)` | Callback scrittura memoria |
| `ShellcodeTracer::on_api_call` | `(&mut self, name: impl Into<String>, args: Vec<u64>, ret: u64)` | Callback chiamata API |
| `ShellcodeTracer::on_exception` | `(&mut self, kind: impl Into<String>, addr: u64)` | Callback eccezione emulata |
| `ShellcodeTracer::on_reg_change` | `(&mut self, reg_id: u32, old_val: u64, new_val: u64)` | Callback cambio registro |
| `ShellcodeTracer::hit_count` | `(&self, addr: u64) -> u64` | Numero esecuzioni di addr |
| `ShellcodeTracer::total_instructions` | `(&self) -> u64` | Totale istruzioni eseguite |
| `ShellcodeTracer::hot_addresses` | `(&self) -> Vec<(u64, u64)>` | Indirizzi piu eseguiti ordinati |
| `ShellcodeTracer::addresses_with_min_hits` | `(&self, min_hits: u64) -> Vec<u64>` | Indirizzi con almeno N esecuzioni |
| `ShellcodeTracer::is_tainted_by_input` | `(&self, addr: u64) -> bool` | True se addr in memoria e tainted dall'input |
| `ShellcodeTracer::summary` | `(&self) -> TraceSummary` | Riassunto statistico del trace |
| `TraceDiff::compute` | `(before: &TraceSummary, after: &TraceSummary) -> Self` | Differenza tra due summary |
| `TraceDiff::is_interesting` | `(&self) -> bool` | True se la diff mostra comportamento significativo |
| `TaintInfluenceReport::new` | `(tracer: &'a ShellcodeTracer, stack_range: (u64, u64), heap_range: (u64, u64)) -> Self` | Report sull'influenza del taint su stack/heap/API |
| `TaintInfluenceReport::influenced_api_call` | `(&self, input_byte_idx: usize) -> bool` | True se il byte di input N ha influenzato una chiamata API |
| `TaintInfluenceReport::influenced_stack_write` | `(&self, input_byte_idx: usize) -> bool` | True se il byte N ha influenzato una scrittura nello stack |
| `TaintInfluenceReport::influenced_heap_write` | `(&self, input_byte_idx: usize) -> bool` | True se il byte N ha influenzato una scrittura nell'heap |

---

### shellcode_unpacker.rs — unpacking multistrato

| Funzione | Firma | Descrizione |
|---|---|---|
| `UnpackResult::layer_count` | `(&self) -> usize` | Numero di strati decompattati |
| `UnpackResult::packer_summary` | `(&self) -> Vec<String>` | Descrizione testuale di ogni strato (algoritmo, dimensione) |
| `ShellcodeUnpacker::new` | `() -> Self` | Unpacker con rilevatori default |
| `ShellcodeUnpacker::unpack` | `(&self, bytes: &[u8]) -> UnpackResult` | Tenta unpacking iterativo finche entropia non diminuisce |
| `ShellcodeUnpacker::apply_layer` | `(bytes: &[u8], packer: &PackerKind) -> Vec<u8>` | Applica un singolo strato di decompressione/decifratura |
| `unpack` | `(bytes: &[u8]) -> UnpackResult` | Funzione libera: unpacker con configurazione default |
| `PackerHypothesizer::new` | `() -> Self` | Ipotizza il tipo di packer da analisi statistica |
| `PackerHypothesizer::analyse` | `(&mut self, bytes: &[u8])` | Analizza bytes e aggiorna le ipotesi |
| `PackerHypothesizer::top_hypothesis` | `(&self) -> Option<&(String, f64)>` | Ipotesi con confidenza piu alta |
| `PackerHypothesizer::hypotheses` | `(&self) -> &[(String, f64)]` | Tutte le ipotesi ordinate per confidenza |
| `UnpackStats::from_results` | `(results: &[UnpackResult]) -> Self` | Statistiche aggregate su piu sessioni di unpacking |
| `UnpackStats::success_rate` | `(&self) -> f64` | Tasso di successo (strati > 1) |

---

### shellcode_report_generator.rs — generazione report

| Funzione | Firma | Descrizione |
|---|---|---|
| `BehaviorFlag::new` | `(tag: impl Into<String>, description: impl Into<String>, severity: Severity) -> Self` | Crea flag comportamentale con severita |
| `BehaviorFlag::with_evidence` | `(mut self, evidence: impl Into<String>) -> Self` | Builder: aggiunge evidenza al flag |
| `BehaviorFlagSet::new` | `() -> Self` | Insieme vuoto di flag comportamentali |
| `BehaviorFlagSet::add_flag` | `(&mut self, flag: BehaviorFlag)` | Aggiunge un flag |
| `BehaviorFlagSet::flags_at_or_above` | `(&self, min: Severity) -> Vec<&BehaviorFlag>` | Filtra flag per severita minima |
| `BehaviorFlagSet::is_critical` | `(&self) -> bool` | True se presente almeno un flag Critical |
| `BehaviorFlagSet::unique_tag_count` | `(&self) -> usize` | Numero tag unici |
| `ShellcodeReport::overall_severity` | `(&self) -> Severity` | Severita massima nel report |
| `ShellcodeReport::verdict_line` | `(&self) -> String` | Linea riassuntiva del verdetto (es. "CRITICAL: Reverse Shell") |
| `ShellcodeReport::to_json` | `(&self) -> Result<String, serde_json::Error>` | Serializzazione JSON del report |
| `ReportGenerator::new` | `() -> Self` | Generatore report vuoto |
| `ReportGenerator::with_label` | `(mut self, label: impl Into<String>) -> Self` | Builder: imposta etichetta report |
| `ReportGenerator::generate` | `(&self, ...) -> ShellcodeReport` | Genera report completo da risultati analisi/emulazione |

---

### api_emulation.rs — emulazione API Windows

| Funzione | Firma | Descrizione |
|---|---|---|
| `ApiStubTable::new` | `(base: u64) -> Self` | Tabella stub API con indirizzo base |
| `ApiStubTable::find_by_address` | `(&self, addr: u64) -> Option<&str>` | Risolve indirizzo stub a nome API |
| `ApiStubTable::find_by_name` | `(&self, name: &str) -> Option<u64>` | Risolve nome API a indirizzo stub |
| `WindowsApiEmulator::new` | `() -> Self` | Emulatore API Windows con stub preconfigurati |
| `WindowsApiEmulator::handle_call` | `(&mut self, cpu: &mut X86Cpu, mem: &mut X86Mem, call_addr: u64) -> bool` | Intercetta e gestisce chiamata API; ritorna true se gestita |
| `WindowsApiEmulator::call_log` | `(&self) -> &[ApiCallResult]` | Log di tutte le chiamate API gestite |

---

### api_resolver_emu.rs — risoluzione API con hashing

| Funzione | Firma | Descrizione |
|---|---|---|
| `hash_api_name` | `(name: &str, algo: HashAlgorithm) -> u32` | Calcola hash di nome API con algoritmo specificato (ROR13, DJB2, ecc.) |
| `PebWalker::new` | `() -> Self` | Simulatore PEB walk per risoluzione dinamica API |
| `PebWalker::add_module` | `(&mut self, name: &str, exports: &[&str])` | Aggiunge modulo con export al PEB simulato |
| `PebWalker::module_base` | `(&self, name: &str) -> Option<u64>` | Base address simulata di un modulo |
| `PebWalker::all_exports` | `(&self) -> Vec<&ModuleExport>` | Tutti gli export di tutti i moduli |
| `PebWalker::find_export` | `(&self, name: &str) -> Option<&ModuleExport>` | Cerca export per nome |
| `HashApiResolver::new` | `() -> Self` | Resolver con PEB default (kernel32, ntdll, ecc.) |
| `HashApiResolver::with_walker` | `(walker: PebWalker) -> Self` | Resolver con PEB custom |
| `HashApiResolver::resolve` | `(&mut self, hash: u32, algo: HashAlgorithm) -> Result<ResolvedApi, ApiResolveError>` | Risolve hash con algoritmo specificato |
| `HashApiResolver::resolve_any` | `(&mut self, hash: u32) -> Result<ResolvedApi, ApiResolveError>` | Prova tutti gli algoritmi noti per risolvere hash |
| `HashApiResolver::build_lookup_table` | `(&self, algo: HashAlgorithm) -> HashMap<u32, String>` | Tabella hash→nome per un algoritmo |
| `ApiEmulatorResolver::new` | `() -> Self` | Resolver integrato con log e stub |
| `ApiEmulatorResolver::resolve_hash` | `(&mut self, hash: u32) -> Result<ResolvedApi, ApiResolveError>` | Risolve hash e aggiunge al log |
| `ApiEmulatorResolver::resolve_name` | `(&mut self, name: &str) -> Result<ResolvedApi, ApiResolveError>` | Risolve nome API e aggiunge al log |
| `ApiEmulatorResolver::stub_return` | `(&self, name: &str) -> u64` | Valore di ritorno simulato per API nota |
| `ApiEmulatorResolver::resolution_log` | `(&self) -> &[ResolvedApi]` | Log di tutte le risoluzioni effettuate |
| `ApiEmulatorResolver::add_stub` | `(&mut self, name: impl Into<String>, value: u64)` | Aggiunge stub personalizzato |

---

### memory_layout_tracker.rs — tracciamento layout memoria

| Funzione | Firma | Descrizione |
|---|---|---|
| `MemoryRegion::new` | `(base: u64, size: usize, kind: RegionKind, label: impl Into<String>, perms: u8) -> Self` | Crea regione con tipo (stack/heap/code/data) e permessi |
| `MemoryRegion::end` | `(&self) -> u64` | Indirizzo fine |
| `MemoryRegion::contains` | `(&self, addr: u64) -> bool` | True se addr appartiene alla regione |
| `MemoryRegion::record_read` | `(&mut self)` | Incrementa contatore letture |
| `MemoryRegion::record_write` | `(&mut self, written_bytes: usize)` | Incrementa contatore scritture |
| `MemoryLayoutTracker::new` | `() -> Self` | Tracker layout vuoto |
| `MemoryLayoutTracker::add_region` | `(&mut self, region: MemoryRegion)` | Aggiunge regione al tracker |
| `MemoryLayoutTracker::remove_region` | `(&mut self, base: u64)` | Rimuove regione per indirizzo base |
| `MemoryLayoutTracker::find_region` | `(&self, addr: u64) -> Option<&MemoryRegion>` | Regione che contiene addr |
| `MemoryLayoutTracker::record_read` | `(&mut self, addr: u64, _size: usize)` | Registra accesso lettura |
| `MemoryLayoutTracker::record_write` | `(&mut self, addr: u64, size: usize)` | Registra accesso scrittura con bitmap aggiornata |
| `MemoryLayoutTracker::record_execution` | `(&mut self, addr: u64)` | Registra esecuzione istruzione (per rilevare WX) |
| `MemoryLayoutTracker::regions` | `(&self) -> &[MemoryRegion]` | Tutte le regioni |
| `MemoryLayoutTracker::regions_of_kind` | `(&self, kind: RegionKind) -> Vec<&MemoryRegion>` | Regioni filtrate per tipo |
| `MemoryLayoutTracker::wx_regions` | `(&self) -> Vec<&MemoryRegion>` | Regioni con flag Write+Execute (indicatore sospetto) |
| `MemoryLayoutTracker::write_bitmap` | `(&self, base_addr: u64) -> Option<&[bool]>` | Bitmap byte scritti per regione |
| `MemoryLayoutTracker::write_coverage` | `(&self, base_addr: u64) -> f64` | Percentuale byte scritti in una regione |
| `MemoryLayoutTracker::layout_summary` | `(&self) -> String` | Stringa riassuntiva del layout memoria |
| `HeapSprayDetector::new` | `(config: HeapSprayConfig) -> Self` | Detector heap spray con configurazione |
| `HeapSprayDetector::default_config` | `() -> Self` | Detector con soglie default |
| `HeapSprayDetector::detect` | `(&self, tracker: &MemoryLayoutTracker) -> HeapSprayResult` | Analizza pattern allocazioni per rilevare heap spray |
| `AllocationTracker::new` | `() -> Self` | Tracker eventi allocazione/free/protect |
| `AllocationTracker::record_alloc` | `(&mut self, address: u64, size: usize)` | Registra VirtualAlloc/malloc |
| `AllocationTracker::record_free` | `(&mut self, address: u64)` | Registra VirtualFree/free |
| `AllocationTracker::record_protect` | `(&mut self, address: u64, old_perms: u8, new_perms: u8)` | Registra VirtualProtect con cambio permessi |
| `AllocationTracker::events` | `(&self) -> &[AllocationEvent]` | Tutti gli eventi registrati |
| `AllocationTracker::freed_addresses` | `(&self) -> Vec<u64>` | Indirizzi che hanno avuto una free |
| `AllocationTracker::wx_transitions` | `(&self) -> Vec<u64>` | Indirizzi che hanno avuto transizione W→X (shellcode injection) |
| `AllocationTracker::live_allocations` | `(&self) -> Vec<(u64, usize)>` | Allocazioni ancora attive (non liberate) |

---

### payload_extractor.rs — estrazione payload

| Funzione | Firma | Descrizione |
|---|---|---|
| `ExtractedPayload::new` | `(offset: usize, data: Vec<u8>, payload_type: PayloadType, method: ExtractionMethod) -> Self` | Payload estratto con metadati |
| `PayloadExtractionReport::highest_entropy_payload` | `(&self) -> Option<&ExtractedPayload>` | Payload con entropia piu alta |
| `PayloadExtractionReport::pe_payloads` | `(&self) -> Vec<&ExtractedPayload>` | Filtra payload di tipo PE |
| `PayloadExtractionReport::count_of_type` | `(&self, t: &PayloadType) -> usize` | Numero payload di un certo tipo |
| `PayloadExtractor::new` | `() -> Self` | Estrattore con metodi default |
| `PayloadExtractor::extract_all` | `(&self, data: &[u8]) -> PayloadExtractionReport` | Applica tutti i metodi di estrazione su raw bytes |
| `PayloadExtractor::extract_from_regions` | `(&self, regions: &[AllocRegion]) -> PayloadExtractionReport` | Estrazione da regioni di memoria emulate |
| `validate_pe` | `(data: &[u8]) -> bool` | True se i dati hanno un PE valido (magic + struttura base) |
| `shannon_entropy` | `(data: &[u8]) -> f64` | Entropia di Shannon |
| `scan_for_pe_headers` | `(data: &[u8]) -> Vec<ExtractedPayload>` | Cerca magic MZ+PE nel buffer |
| `scan_for_high_entropy_blobs` | `(data: &[u8], threshold: f64, min_size: usize) -> Vec<ExtractedPayload>` | Trova blob ad alta entropia (payload cifrati/compressi) |
| `decode_base64` | `(input: &[u8]) -> Option<Vec<u8>>` | Decodifica base64 |
| `decode_base64_blobs` | `(data: &[u8], min_len: usize) -> Vec<ExtractedPayload>` | Trova e decodifica blob base64 nel buffer |
| `detect_xor_key` | `(data: &[u8], max_key_len: usize) -> Option<Vec<u8>>` | Identifica chiave XOR (singolo byte o multibyte) con analisi frequenza |
| `decrypt_xor` | `(data: &[u8], key: &[u8]) -> Vec<u8>` | Applica decifratura XOR con chiave |
| `detect_rc4_key_schedule` | `(data: &[u8]) -> Option<usize>` | Rileva key schedule RC4 nel buffer (S-box init) |
| `extract_from_alloc_regions` | `(regions: &[AllocRegion]) -> Vec<ExtractedPayload>` | Funzione libera: estrae da regioni allocate |
| `is_compressed` | `(data: &[u8]) -> bool` | Heuristica: true se dati sembrano compressi (magic bytes noti) |
| `byte_frequency` | `(data: &[u8]) -> [u32; 256]` | Tabella frequenza di ogni valore byte |
| `top_n_bytes` | `(data: &[u8], n: usize) -> Vec<(u8, u32)>` | Top N byte piu frequenti |
| `printable_ratio` | `(data: &[u8]) -> f64` | Frazione byte stampabili ASCII |

---

### network_behavior_simulator.rs — simulazione comportamento di rete

| Funzione | Firma | Descrizione |
|---|---|---|
| `SocketType::from_raw` | `(v: u32) -> Self` | Converte valore numerico in tipo socket |
| `AddressFamily::from_raw` | `(v: u32) -> Self` | Converte valore numerico in famiglia indirizzo |
| `CapturedTraffic::total_bytes` | `(&self) -> usize` | Totale byte send/recv simulati |
| `CapturedTraffic::was_connected` | `(&self) -> bool` | True se e stata effettuata una connect |
| `NetworkTrafficSummary::new` | `() -> Self` | Sommario traffico di rete vuoto |
| `NetworkTrafficSummary::has_connections` | `(&self) -> bool` | True se il summary contiene connessioni |
| `NetworkTrafficSummary::primary_remote` | `(&self) -> Option<IpAddr>` | Primo indirizzo remoto connesso |
| `NetworkTrafficSummary::outbound_strings` | `(&self) -> Vec<String>` | Stringhe inviate in chiaro |
| `NetworkBehaviorSimulator::new` | `() -> Self` | Simulatore comportamento di rete vuoto |
| `NetworkBehaviorSimulator::with_recv_response` | `(mut self, resp: Vec<u8>) -> Self` | Builder: imposta risposta simulata per recv |
| `NetworkBehaviorSimulator::simulate` | `(&self, calls: &[(String, u64, Vec<u64>)]) -> CapturedTraffic` | Simula sequenza chiamate socket API e cattura traffico |
| `NetworkIndicators::from_traffic` | `(traffic: &CapturedTraffic) -> Self` | Estrae indicatori (IP, porte, URL) dal traffico catturato |

---

## Riepilogo tecnico

`rustre-emu-shellcode` e una libreria di emulazione e analisi specializzata per shellcode che opera su tre livelli:

1. **Basso livello** (`x86_emulator`, `x86_emulator_hooks`): emulatore x86 step-by-step con memoria a regioni, registri, stack, sistema hook event-driven, trace PC e tabella syscall sintetica.

2. **Medio livello** (`shellcode_loader`, `shellcode_emulator`, `api_emulation`, `api_resolver_emu`): contesto di emulazione completo con IAT sintetica, hook API Windows (VirtualAlloc, LoadLibrary, GetProcAddress, socket, ecc.), risoluzione hash API (ROR13, DJB2), PEB walk simulato.

3. **Alto livello** (`shellcode_analysis`, `shellcode_classifier`, `shellcode_heuristics`, `shellcode_decoder`, `shellcode_unpacker`, `shellcode_tracer`, `payload_extractor`, `network_behavior_simulator`, `shellcode_report_generator`): analisi statica+dinamica, scoring euristico, classificazione famiglia, decodifica multistadio, unpacking automatico, taint analysis, rilevamento heap spray, estrazione payload PE/base64/XOR/RC4, simulazione rete, generazione report strutturati JSON.

Totale funzioni pubbliche: **384**
