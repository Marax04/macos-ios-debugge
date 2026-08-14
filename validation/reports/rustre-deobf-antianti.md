# rustre-deobf-antianti

Crate che raggruppa rilevamento, analisi e neutralizzazione di tecniche anti-debug, anti-VM e anti-analisi presenti nei binari. Dipende da `rustre-deobf` per le primitive di patching; espone sia patch binarie dirette sia generazione di script Frida.

**fn pubbliche totali: 235**

---

## src/lib.rs — tipi e scanner di alto livello

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `signature_database() -> Vec<TechniqueSignature>` | — | `Vec<TechniqueSignature>` | Restituisce il database statico di firme byte per tecnica anti-analisi. |
| `AntiAnalysisScanner::new() -> Self` | — | `Self` | Costruisce lo scanner multi-tecnica con firme built-in. |
| `AntiAnalysisScanner::scan(&self, data: &[u8]) -> Vec<AntiAnalysisHit>` | byte slice | `Vec<AntiAnalysisHit>` | Scansione completa: rileva tutte le tecniche anti-analisi nel buffer. |
| `generate_frida_script(hits: &[AntiAnalysisHit]) -> String` | slice di hit | `String` | Genera script Frida JS per intercettare i pattern trovati. |
| `AntiDebugScanner::new(…) -> Self` | firme opzionali | `Self` | Costruisce scanner anti-debug con firme personalizzabili. |
| `AntiDebugScanner::scan(&self, data: &[u8]) -> Vec<AntiDebugDetection>` | byte slice | `Vec<AntiDebugDetection>` | Rileva pattern IsDebuggerPresent, NtQueryInformationProcess, heap flags ecc. |
| `AntiVmScanner::new(…) -> Self` | config | `Self` | Costruisce scanner anti-VM. |
| `AntiVmScanner::scan(&self, data: &[u8]) -> Vec<AntiVmDetection>` | byte slice | `Vec<AntiVmDetection>` | Rileva CPUID hypervisor, VMware backdoor, RDTSC delta, artefatti registry. |
| `Bypass::new(…) -> Self` | metadati bypass | `Self` | Crea un descrittore di bypass (offset, bytes originali/sostitutivi). |
| `Bypass::with_effectiveness(mut self, eff: u32) -> Self` | efficacia 0-100 | `Self` | Builder: imposta il grado di efficacia stimato. |
| `Bypass::to_patch(&self, original: Vec<u8>) -> Patch` | bytes originali | `Patch` | Converte il bypass in una `Patch` applicabile al binario. |
| `TimingBypassGenerator::new() -> Self` | — | `Self` | Costruisce il generatore di bypass per controlli temporali. |
| `TimingBypassGenerator::frida_gettickcount_hook(&self) -> String` | — | `String` | Emette hook Frida per `GetTickCount`/`GetTickCount64`. |
| `TimingBypassGenerator::frida_rdtsc_stalker_snippet(&self) -> String` | — | `String` | Emette snippet Frida Stalker per NOPpare/ridurre delta RDTSC. |
| `BypassRegistry::new() -> Self` | — | `Self` | Registro vuoto tecnica→bypass. |
| `BypassRegistry::register(&mut self, technique, bypass)` | nome tecnica, `Bypass` | `()` | Registra un bypass per una tecnica. |
| `BypassRegistry::get(&self, technique: &str) -> &[Bypass]` | nome tecnica | `&[Bypass]` | Recupera i bypass registrati per la tecnica. |
| `BypassRegistry::total(&self) -> usize` | — | `usize` | Numero totale di bypass registrati. |
| `BypassRegistry::is_empty(&self) -> bool` | — | `bool` | Vero se il registro è vuoto. |
| `BypassRegistry::techniques(&self) -> Vec<&str>` | — | `Vec<&str>` | Elenco delle tecniche registrate. |
| `SleepBypassGenerator::scan_large_sleeps(&self, data: &[u8]) -> Vec<(usize, u32)>` | byte slice | `Vec<(offset, ms)>` | Trova chiamate Sleep con argomento > soglia. |
| `SleepBypassGenerator::generate_bypasses(&self, data: &[u8]) -> Vec<Bypass>` | byte slice | `Vec<Bypass>` | Genera bypass (NOP/patch argomento) per ogni sleep trovato. |
| `CombinedReport::new(…) -> Self` | dati, config | `Self` | Costruisce il report combinato anti-debug + anti-VM. |
| `CombinedReport::from_data(data: &[u8]) -> Self` | byte slice | `Self` | Factory: esegue entrambe le scansioni e compila il report. |
| `CombinedReport::high_confidence_debug(&self) -> Vec<&AntiDebugDetection>` | — | `Vec<&AntiDebugDetection>` | Filtra rilevamenti anti-debug con confidenza alta. |
| `CombinedReport::high_confidence_vm(&self) -> Vec<&AntiVmDetection>` | — | `Vec<&AntiVmDetection>` | Filtra rilevamenti anti-VM con confidenza alta. |
| `AntiDebugSigDb::new() -> Self` | — | `Self` | Database di firme anti-debug (firme byte + maschera). |
| `AntiDebugSigDb::signatures(&self) -> &[AntiDebugSig]` | — | `&[AntiDebugSig]` | Accesso alla lista firme. |
| `AntiDebugSigDb::scan_for_anti_debug(&self, bytes: &[u8]) -> Vec<AntiDebugMatch>` | byte slice | `Vec<AntiDebugMatch>` | Scansione byte-pattern di firme anti-debug nel binario. |

---

## src/antidbg_bypass.rs — bypass anti-debug a livello di patch

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `AntiDebugDetector::new() -> Self` | — | `Self` | Detector con pattern built-in (IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent…). |
| `AntiDebugDetector::detect(&self, data: &[u8]) -> Vec<DetectionHit>` | byte slice | `Vec<DetectionHit>` | Trova tutte le occorrenze di pattern anti-debug. |
| `BypassPatch::apply(&self, data: &mut [u8]) -> Result<(), BypassError>` | buffer mutabile | `Result` | Applica la patch al buffer in-place. |
| `BypassPatch::revert(&self, data: &mut [u8]) -> Result<(), BypassError>` | buffer mutabile | `Result` | Ripristina i byte originali. |
| `BypassPatch::is_applied(&self, data: &[u8]) -> bool` | byte slice | `bool` | Verifica se la patch è già applicata. |
| `PatchSet::new() -> Self` | — | `Self` | Insieme vuoto di patch. |
| `PatchSet::add(&mut self, patch: BypassPatch) -> Result<(), BypassError>` | patch | `Result` | Aggiunge patch con controllo sovrapposizione. |
| `PatchSet::add_unchecked(&mut self, patch: BypassPatch)` | patch | `()` | Aggiunge senza controllo (veloce). |
| `PatchSet::patches(&self) -> &[BypassPatch]` | — | `&[BypassPatch]` | Accesso alle patch. |
| `PatchSet::apply_all(&self, data: &mut [u8]) -> Result<(), BypassError>` | buffer mutabile | `Result` | Applica tutte le patch in ordine. |
| `PatchSet::revert_all(&self, data: &mut [u8]) -> Result<(), BypassError>` | buffer mutabile | `Result` | Reverte tutte le patch. |
| `PatchSet::for_technique(&self, t: AntiDebugTechnique) -> Vec<&BypassPatch>` | tecnica | `Vec<&BypassPatch>` | Filtra patch per tecnica. |
| `PatchSet::to_frida_script(&self) -> String` | — | `String` | Genera script Frida per applicare le patch a runtime. |
| `BypassGenerator::new() -> Self` | — | `Self` | Generatore con strategie di bypass di default. |
| `BypassGenerator::set_strategy(&mut self, technique, strategy)` | tecnica, strategia | `()` | Imposta la strategia per una tecnica specifica. |
| `BypassGenerator::generate(&self, hit: &DetectionHit, data: &[u8]) -> Result<BypassPatch, BypassError>` | hit, bytes | `Result<BypassPatch>` | Genera una patch per un singolo hit. |
| `BypassGenerator::generate_all(&self, hits: &[DetectionHit], data: &[u8]) -> PatchSet` | slice hit, bytes | `PatchSet` | Genera e raccoglie patch per tutti gli hit. |

---

## src/anti_analysis_patterns.rs — pattern anti-analisi generici

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `AntiAnalysisPatternScanner::new() -> Self` | — | `Self` | Scanner con pattern built-in (self-modifying code, code caves, import obfuscation…). |
| `AntiAnalysisPatternScanner::detect(&self, data: &[u8]) -> Vec<PatternHit>` | byte slice | `Vec<PatternHit>` | Rileva pattern anti-analisi nel buffer. |
| `RegionDensity::compute(hits, region_size) -> Self` | slice hit, dim. regione | `Self` | Calcola densità di hit per regione (utile per individuare zone offuscate). |
| `BinaryDensity::compute(hits, binary_size) -> Self` | slice hit, dim. binario | `Self` | Densità globale di anti-analisi nel binario. |
| `BinaryDensity::is_obfuscated(&self) -> bool` | — | `bool` | Vero se la densità supera la soglia di offuscamento. |
| `CleaningStrategy::for_pattern(pattern) -> Self` | pattern | `Self` | Restituisce la strategia di pulizia raccomandata per il pattern. |
| `strategies_for_hits(hits) -> Vec<CleaningStrategy>` | slice hit | `Vec<CleaningStrategy>` | Mappa ogni hit alla sua strategia di pulizia. |

---

## src/anti_debug_patcher.rs — patcher ad alto livello con pattern engine

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `DetectionPattern::matches_at(&self, data: &[u8], offset: usize) -> bool` | bytes, offset | `bool` | Verifica se il pattern matcha all'offset dato. |
| `DetectionPattern::scan(&self, data: &[u8]) -> Vec<usize>` | byte slice | `Vec<usize>` | Trova tutti gli offset in cui il pattern matcha. |
| `PatchBytes::nop_sled(len: usize) -> Self` | lunghezza | `Self` | Crea una sequenza NOP di `len` byte. |
| `PatchBytes::xor_eax_eax_nops(total_len: usize) -> Self` | lunghezza totale | `Self` | `XOR EAX,EAX` seguito da NOP per riempire. |
| `PatchBytes::xor_rax_rax_nops(total_len: usize) -> Self` | lunghezza totale | `Self` | Variante 64-bit con `XOR RAX,RAX`. |
| `PatchBytes::short_jump_over(pattern_len, skip) -> Self` | len pattern, skip | `Self` | Genera un JMP corto che salta `skip` byte oltre il pattern. |
| `PatchEntry::new(…) -> Self` | offset, tecnica, bytes | `Self` | Crea una voce di patch. |
| `PatchEntry::apply(&self, data: &mut [u8]) -> bool` | buffer mutabile | `bool` | Applica la patch; false se fuori range. |
| `PatchEntry::rollback(&self, data: &mut [u8]) -> bool` | buffer mutabile | `bool` | Ripristina i byte originali. |
| `PatchEntry::byte_count(&self) -> usize` | — | `usize` | Numero di byte modificati. |
| `AntiDebugPatcher::builtin_patterns() -> Vec<DetectionPattern>` | — | `Vec<DetectionPattern>` | Pattern built-in per IsDebuggerPresent, NtQuery, CheckRemote, OutputDebugString, heap flags. |
| `AntiDebugPatcher::new() -> Self` | — | `Self` | Patcher con pattern built-in e soglia di confidenza di default. |
| `AntiDebugPatcher::with_min_confidence(mut self, threshold: u8) -> Self` | soglia 0-100 | `Self` | Builder: imposta soglia confidenza minima. |
| `AntiDebugPatcher::add_pattern(&mut self, pattern)` | `DetectionPattern` | `()` | Aggiunge pattern personalizzato. |
| `AntiDebugPatcher::set_custom_patch_len(&mut self, technique, len)` | tecnica, len | `()` | Sovrascrive la lunghezza di patch per una tecnica. |
| `AntiDebugPatcher::scan(&self, data: &[u8]) -> Vec<PatchEntry>` | byte slice | `Vec<PatchEntry>` | Trova tutte le occorrenze patchabili. |
| `AntiDebugPatcher::patch_all(&self, data: &[u8]) -> (Vec<u8>, usize)` | byte slice | `(Vec<u8>, count)` | Restituisce il binario patchato e il numero di patch applicate. |
| `AntiDebugPatcher::patch_technique(&self, data, technique) -> (Vec<u8>, usize)` | bytes, tecnica | `(Vec<u8>, count)` | Patcha solo la tecnica indicata. |
| `AntiDebugPatcher::report(&self, data: &[u8]) -> PatchReport` | byte slice | `PatchReport` | Genera report dettagliato senza applicare patch. |
| `AntiDebugPatcher::pattern_count(&self) -> usize` | — | `usize` | Numero di pattern attivi. |
| `AntiDebugPatcher::verify_original(entry, data) -> bool` | entry, bytes | `bool` | Verifica che i byte originali dell'entry siano ancora presenti. |
| `PatchReport::detected_techniques(&self) -> Vec<AntiDebugTechnique>` | — | `Vec<AntiDebugTechnique>` | Elenco tecniche rilevate. |
| `PatchReport::hits_for(&self, technique) -> usize` | tecnica | `usize` | Conteggio hit per tecnica. |
| `PatchReport::format_text(&self) -> String` | — | `String` | Report testuale human-readable. |
| `IsDebuggerPresentScanner::patch_bytes() -> PatchBytes` | — | `PatchBytes` | Bytes di patch specifica per IsDebuggerPresent (XOR AL,AL + RET). |
| `IsDebuggerPresentScanner::scan(data) -> Vec<PatchEntry>` | byte slice | `Vec<PatchEntry>` | Scansione rapida per IsDebuggerPresent. |
| `NtQueryScanner::scan(data) -> Vec<PatchEntry>` | byte slice | `Vec<PatchEntry>` | Scansione per NtQueryInformationProcess (ProcessDebugPort). |
| `HeapFlagScanner::scan(data) -> Vec<PatchEntry>` | byte slice | `Vec<PatchEntry>` | Scansione per controllo heap flags (NtGlobalFlag/ForceFlags). |

---

## src/bypasser.rs — bypasser generico (DetectionSite → patch/Frida)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `BypassPatch::apply(&self, buf: &mut [u8]) -> bool` | buffer mutabile | `bool` | Applica la patch; false se offset fuori range. |
| `BypassPatch::revert(&self, buf: &mut [u8]) -> bool` | buffer mutabile | `bool` | Ripristina i byte originali. |
| `Bypasser::generate_patches(&self, data: &[u8], sites: &[DetectionSite]) -> Vec<BypassPatch>` | bytes, siti rilevati | `Vec<BypassPatch>` | Genera patch per ogni sito di rilevamento. |
| `Bypasser::generate_frida_hooks(&self, sites: &[DetectionSite]) -> Vec<FridaHookScript>` | bytes, siti rilevati | `Vec<FridaHookScript>` | Genera hook Frida per intercettare ogni sito. |

---

## src/detector.rs — detector di tecniche anti-debug/anti-analisi

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `Detector::new(…) -> Self` | config | `Self` | Detector configurabile con tecniche e soglie. |
| `Detector::scan(&self, data: &[u8]) -> Vec<DetectionSite>` | byte slice | `Vec<DetectionSite>` | Scansione completa, restituisce tutti i siti con tecnica e confidenza. |
| `Detector::summarize(&self, sites: &[DetectionSite]) -> Vec<(DetectedTechnique, usize)>` | slice siti | `Vec<(tecnica, count)>` | Raggruppa e conta siti per tecnica. |

---

## src/environment_spoofer.rs — spoofing ambiente per eludere anti-VM/anti-debug

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `VmProduct::display_name(self) -> &'static str` | — | `&'static str` | Nome leggibile del prodotto VM (VMware, VirtualBox…). |
| `EnvironmentSpoofer::new(config: SpooferConfig) -> Self` | config | `Self` | Spoofing di variabili d'ambiente, registry e PEB. |
| `EnvironmentSpoofer::with_defaults() -> Self` | — | `Self` | Factory con configurazione di default (nascondi tutti i VM noti). |
| `EnvironmentSpoofer::generate_frida_script(&self) -> String` | — | `String` | Genera script Frida per intercettare e falsificare le query di ambiente a runtime. |
| `EnvironmentSpoofer::generate_binary_patches(&self, iat_map: &HashMap<String, u64>) -> Vec<BinaryPatch>` | mappa IAT | `Vec<BinaryPatch>` | Genera patch statiche per le entry IAT che fanno query sull'ambiente. |
| `EnvironmentSpoofer::summary(&self) -> String` | — | `String` | Riepilogo testuale dello spoofing configurato. |
| `patch_peb_fields(peb_data: &mut [u8], layout: PebLayout)` | buffer PEB, layout | `()` | Patcha in-memory i campi del PEB (NtGlobalFlag, BeingDebugged…). |

---

## src/evasion_patterns.rs — pattern di evasione per categoria

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `EvasionPattern::matches_at(&self, data: &[u8], offset: usize) -> bool` | bytes, offset | `bool` | Verifica match di un pattern di evasione. |
| `EvasionScanner::new() -> Self` | — | `Self` | Scanner con libreria pattern built-in. |
| `EvasionScanner::scan(&self, data: &[u8]) -> Vec<EvasionMatch>` | byte slice | `Vec<EvasionMatch>` | Scansione completa su tutte le categorie. |
| `EvasionScanner::scan_category(&self, data, cat) -> Vec<EvasionMatch>` | bytes, categoria | `Vec<EvasionMatch>` | Scansione limitata a una categoria. |
| `EvasionScanner::category_count(&self, cat) -> usize` | categoria | `usize` | Numero di pattern nella categoria. |
| `EvasionStats::new() -> Self` | — | `Self` | Statistiche vuote. |
| `EvasionStats::record(&mut self, category, confidence)` | categoria, confidenza | `()` | Registra un match nelle statistiche. |
| `EvasionStats::from_matches(matches) -> Self` | `&[EvasionMatch]` | `Self` | Calcola statistiche da un insieme di match. |
| `EvasionStats::max_confidence(&self) -> u8` | — | `u8` | Confidenza massima osservata. |
| `EvasionFilter::new() -> Self` | — | `Self` | Filtro vuoto (passa tutto). |
| `EvasionFilter::only_category(mut self, cat) -> Self` | categoria | `Self` | Builder: limita ai pattern della categoria. |
| `EvasionFilter::passes(&self, p: &EvasionPattern) -> bool` | pattern | `bool` | Vero se il pattern supera il filtro. |
| `EvasionFilter::apply<'a>(&self, patterns) -> Vec<&'a EvasionPattern>` | slice pattern | `Vec<&EvasionPattern>` | Applica il filtro alla libreria. |
| `EvasionPatternLibrary::build() -> Self` | — | `Self` | Costruisce la libreria completa di pattern built-in. |
| `EvasionPatternLibrary::get_by_name(&self, name) -> Option<&EvasionPattern>` | nome | `Option<&EvasionPattern>` | Lookup per nome. |
| `EvasionPatternLibrary::get_by_category(&self, category) -> Vec<&EvasionPattern>` | categoria | `Vec<&EvasionPattern>` | Tutti i pattern della categoria. |
| `EvasionPatternLibrary::categories(&self) -> Vec<&str>` | — | `Vec<&str>` | Categorie presenti nella libreria. |
| `EvasionReport::from_matches(matches) -> Self` | `&[EvasionMatch]` | `Self` | Report aggregato da match. |
| `BypassSuggestionEngine::generate(&self, matches) -> Vec<BypassSuggestion>` | `&[EvasionMatch]` | `Vec<BypassSuggestion>` | Genera suggerimenti di bypass per ogni pattern trovato. |
| `EvasionSummary::from_matches(matches) -> Self` | `&[EvasionMatch]` | `Self` | Riepilogo (conteggi, categorie predominanti). |
| `EvasionSummary::is_evasive(&self) -> bool` | — | `bool` | Vero se il binario è considerato evasivo. |
| `AntiDebugEvasion::scan(&self, data) -> Vec<EvasionMatch>` | byte slice | `Vec<EvasionMatch>` | Scansione pattern anti-debug specifici. |
| `AntiDebugEvasion::is_present(&self, data) -> bool` | byte slice | `bool` | Vero se almeno un pattern anti-debug è presente. |
| `TimingEvasion::scan(&self, data) -> Vec<EvasionMatch>` | byte slice | `Vec<EvasionMatch>` | Scansione pattern timing (RDTSC, Sleep…). |
| `TimingEvasion::has_rdtsc(&self, data) -> bool` | byte slice | `bool` | Vero se RDTSC è presente. |
| `ProcessEvasion::scan(&self, data) -> Vec<EvasionMatch>` | byte slice | `Vec<EvasionMatch>` | Pattern di rilevamento processi (tool list, parent PID…). |
| `ProcessEvasion::has_process_check(&self, data) -> bool` | byte slice | `bool` | Vero se è presente un process check. |
| `SyscallEvasion::scan(&self, data) -> Vec<EvasionMatch>` | byte slice | `Vec<EvasionMatch>` | Syscall dirette ed evasione SSDT. |
| `SyscallEvasion::has_direct_syscall(&self, data) -> bool` | byte slice | `bool` | Vero se ci sono syscall dirette. |
| `SyscallEvasion::has_int2e(&self, data) -> bool` | byte slice | `bool` | Vero se è presente la tecnica INT 2E. |
| `comprehensive_scan(data: &[u8]) -> ComprehensiveEvasionResult` | byte slice | `ComprehensiveEvasionResult` | Scansione completa su tutte le categorie di evasione. |
| `filter_by_confidence(matches, min_conf) -> Vec<&EvasionMatch>` | matches, soglia | `Vec<&EvasionMatch>` | Filtra per confidenza minima. |
| `group_by_category(matches) -> …` | `&[EvasionMatch]` | `HashMap<EvasionCategory, Vec<&EvasionMatch>>` | Raggruppa match per categoria. |

---

## src/exception_based_antidebug.rs — tecniche SEH/VEH anti-debug

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `SehTrick::new(…) -> Self` | offset, kind, bytes | `Self` | Descrive un trucco SEH rilevato. |
| `SehPatch::new(…) -> Self` | from, to, label | `Self` | Patch per neutralizzare un trucco SEH (redirige il flusso). |
| `SehPatch::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer binario | `Result` | Applica la patch SEH al buffer. |
| `SehPatch::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer binario | `Result` | Rollback della patch SEH. |
| `ExceptionRoute::new(from, to, label) -> Self` | offset inizio, fine, etichetta | `Self` | Descrive un percorso eccezione rilevato. |
| `SehDetector::new() -> Self` | — | `Self` | Detector di trucchi SEH/VEH con pattern built-in. |
| `SehDetector::scan(&self, binary: &[u8]) -> Vec<SehTrick>` | byte slice | `Vec<SehTrick>` | Trova tutti i trucchi SEH nel binario. |
| `SehDetector::generate_patches(&self, binary: &[u8]) -> Vec<SehPatch>` | byte slice | `Vec<SehPatch>` | Genera le patch per neutralizzare i trucchi trovati. |
| `SehDetector::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)` | buffer mutabile | `(count, log)` | Neutralizza tutti i trucchi in-place. |
| `SehDetector::extract_routes(tricks) -> Vec<ExceptionRoute>` | `&[SehTrick]` | `Vec<ExceptionRoute>` | Estrae il grafo dei percorsi eccezionali. |
| `SehDetector::frida_script(tricks) -> String` | `&[SehTrick]` | `String` | Script Frida per intercettare i percorsi eccezionali a runtime. |
| `SehDetector::trick_histogram(tricks) -> HashMap<ExceptionCheckKind, usize>` | `&[SehTrick]` | `HashMap` | Istogramma dei tipi di trucco SEH. |

---

## src/timing_attack_neutralizer.rs — neutralizzazione controlli temporali

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TimingCheck::new(…) -> Self` | offset, kind, contesto | `Self` | Descrive un controllo temporale rilevato. |
| `NeutralizePatch::new(…) -> Self` | offset, bytes originali/sostitutivi | `Self` | Patch per neutralizzare il controllo. |
| `NeutralizePatch::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer | `Result` | Applica la patch. |
| `NeutralizePatch::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer | `Result` | Rollback della patch. |
| `TimingNeutralizer::new() -> Self` | — | `Self` | Neutralizzatore con pattern RDTSC, GetTickCount, QPC, Sleep. |
| `TimingNeutralizer::scan(&self, binary: &[u8]) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Trova tutti i controlli temporali. |
| `TimingNeutralizer::generate_patches(&self, binary: &[u8]) -> Vec<NeutralizePatch>` | byte slice | `Vec<NeutralizePatch>` | Genera patch per ogni controllo. |
| `TimingNeutralizer::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)` | buffer mutabile | `(count, log)` | Neutralizza tutti i controlli in-place. |
| `TimingNeutralizer::frida_script(&self, checks: &[TimingCheck]) -> String` | slice checks | `String` | Script Frida per intercettare e falsificare le API temporali. |
| `TimingNeutralizer::patch_summary(patches) -> HashMap<TimingCheckKind, usize>` | `&[NeutralizePatch]` | `HashMap` | Istogramma dei tipi di patch applicati. |

---

## src/timing_bypass.rs — bypass timing ad alto livello

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TimingTechnique::label(self) -> String` | — | `String` | Nome human-readable della tecnica (RDTSC, QPC, Sleep…). |
| `TimingBypassScanner::new(…) -> Self` | config | `Self` | Scanner con soglie configurabili. |
| `TimingBypassReport::from_hits(hits: Vec<TimingHit>) -> Self` | hit | `Self` | Costruisce il report dagli hit. |
| `TimingBypassReport::high_confidence_hits(&self) -> Vec<&TimingHit>` | — | `Vec<&TimingHit>` | Hit con confidenza alta. |
| `TimingBypassReport::patchable_hits(&self) -> Vec<&TimingHit>` | — | `Vec<&TimingHit>` | Hit per cui esiste un bypass binario noto. |
| `TimingBypassScanner::with_min_confidence(mut self, min: u32) -> Self` | soglia | `Self` | Builder: soglia confidenza minima. |
| `TimingBypassScanner::scan(&self, data: &[u8]) -> TimingBypassReport` | byte slice | `TimingBypassReport` | Esegue la scansione e produce il report. |
| `apply_patches(…) -> …` | buffer, patch | risultato | Applica un insieme di patch timing al buffer. |

---

## src/timing_check_detector.rs — detector granulare per controlli temporali

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ImmediateValue::new(value, offset, size) -> Self` | valore, offset, size | `Self` | Valore immediato estratto da un'istruzione (argomento Sleep ecc.). |
| `TimingCheck::patch_byte_count(&self) -> usize` | — | `usize` | Numero di byte da patchare per neutralizzare il check. |
| `TimingCheck::affected_offsets(&self) -> Vec<usize>` | — | `Vec<usize>` | Offset nel binario coinvolti dalla patch. |
| `TimingCheckDetector::new() -> Self` | — | `Self` | Detector con parametri di default. |
| `TimingCheckDetector::with_params(sleep_threshold_ms, rdtsc_window) -> Self` | soglia Sleep, finestra RDTSC | `Self` | Detector con parametri personalizzati. |
| `TimingCheckDetector::scan(&self, data: &[u8]) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Scansione completa (RDTSC + GetTickCount + Sleep + QPC + import). |
| `TimingCheckDetector::scan_rdtsc(&self, data) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Solo pattern RDTSC (0F 31) con analisi del delta. |
| `TimingCheckDetector::scan_gettickcount(&self, data) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Solo pattern GetTickCount/GetTickCount64. |
| `TimingCheckDetector::scan_sleep(&self, data) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Solo chiamate Sleep con argomento > soglia. |
| `TimingCheckDetector::scan_qpc(&self, data) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Solo QueryPerformanceCounter. |
| `TimingCheckDetector::scan_string_imports(&self, data) -> Vec<TimingCheck>` | byte slice | `Vec<TimingCheck>` | Riferimenti stringa a API temporali (import per stringa). |
| `TimingCheckDetector::rdtsc_checks(&self, data) -> Vec<RdtscCheck>` | byte slice | `Vec<RdtscCheck>` | RDTSC con contesto arricchito (delta, confronto). |
| `TimingCheckDetector::sleep_checks(&self, data) -> Vec<SleepCheck>` | byte slice | `Vec<SleepCheck>` | Sleep con argomento esplicito. |
| `TimingCheckDetector::report(&self, data: &[u8]) -> TimingReport` | byte slice | `TimingReport` | Report completo con conteggi per pattern. |
| `TimingReport::total(&self) -> usize` | — | `usize` | Totale check trovati. |
| `TimingReport::is_clean(&self) -> bool` | — | `bool` | Vero se nessun check timing trovato. |
| `TimingReport::count_for(&self, pattern) -> usize` | `TimingPattern` | `usize` | Conteggio per pattern specifico. |
| `TimingReport::high_confidence(&self) -> Vec<&TimingCheck>` | — | `Vec<&TimingCheck>` | Check ad alta confidenza. |
| `TimingReport::all_patches(&self) -> Vec<(usize, Vec<u8>)>` | — | `Vec<(offset, bytes)>` | Tutte le patch raccomandate. |
| `TimingReport::apply_patches(&self, data: &[u8]) -> Vec<u8>` | byte slice | `Vec<u8>` | Restituisce il binario con tutte le patch applicate. |

---

## src/timing_patchers.rs — database di firme timing + patcher

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TimingSignatureDb::default_db() -> Self` | — | `Self` | Database built-in (RDTSC, GetTickCount, QPC, Sleep). |
| `TimingSignatureDb::scan<'a>(&'a self, data: &[u8]) -> Vec<(usize, &'a TimingSignature)>` | byte slice | `Vec<(offset, firma)>` | Scansione multi-firma, restituisce offset e firma corrispondente. |
| `TimingSignatureDb::apply_patch_template(…)` | bytes, firma, offset | `Vec<u8>` | Applica il template di patch della firma all'offset. |
| `TimingPatcher::new(config: TimingPatchConfig) -> Self` | config | `Self` | Patcher configurabile. |
| `TimingPatcher::with_defaults() -> Self` | — | `Self` | Factory con config di default. |
| `TimingPatcher::patch(&self, data: &mut Vec<u8>) -> TimingPatchResult` | buffer mutabile | `TimingPatchResult` | Patcha tutte le occorrenze in-place. |
| `TimingPatcher::frida_script(&self) -> String` | — | `String` | Script Frida per intercettare tutte le API timing configurate. |
| `detect_rdtsc_delta_checks(data: &[u8]) -> Vec<RdtscDeltaCheck>` | byte slice | `Vec<RdtscDeltaCheck>` | Individua pattern RDTSC→confronto delta (classico anti-debug timing). |

---

## src/vm_check_neutralizer.rs — neutralizzazione check VM (CPUID, I/O port, SIDT)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `CpuidCheck::is_hypervisor_leaf(&self) -> bool` | — | `bool` | Vero se il check legge il leaf hypervisor (40000000h). |
| `CpuidCheck::is_vmware_backdoor(&self) -> bool` | — | `bool` | Vero se si tratta del backdoor VMware (IN EAX, 'VX'). |
| `NeutralizationPatch::apply(&self, data: &mut [u8]) -> bool` | buffer | `bool` | Applica la patch di neutralizzazione. |
| `NeutralizationPatch::rollback(&self, data: &mut [u8]) -> bool` | buffer | `bool` | Rollback patch. |
| `NeutralizationPatch::size(&self) -> usize` | — | `usize` | Dimensione in byte della patch. |
| `VmNeutralizer::new() -> Self` | — | `Self` | Neutralizzatore VM con pattern built-in. |
| `VmNeutralizer::with_min_confidence(mut self, threshold: u8) -> Self` | soglia | `Self` | Builder: soglia di confidenza minima. |
| `VmNeutralizer::scan_cpuid(&self, data: &[u8]) -> Vec<CpuidCheck>` | byte slice | `Vec<CpuidCheck>` | Trova pattern CPUID usati come check VM. |
| `VmNeutralizer::scan_vmware_io_port(&self, data: &[u8]) -> Vec<IoPortCheck>` | byte slice | `Vec<IoPortCheck>` | Trova accessi alla porta I/O VMware (0x5658). |
| `VmNeutralizer::scan_sidt_sgdt(&self, data: &[u8]) -> Vec<NeutralizationPatch>` | byte slice | `Vec<NeutralizationPatch>` | Trova SIDT/SGDT usati per rilevare VM (Red Pill). |
| `VmNeutralizer::scan_memory_artefacts(&self, data: &[u8]) -> Vec<MemoryArtifact>` | byte slice | `Vec<MemoryArtifact>` | Riferimenti a stringhe/path VM (VMware, VirtualBox…). |
| `VmNeutralizer::scan(&self, data: &[u8]) -> VmNeutralizationReport` | byte slice | `VmNeutralizationReport` | Scansione completa multi-vettore. |
| `VmNeutralizer::neutralize_all(&self, data: &[u8]) -> (Vec<u8>, usize)` | byte slice | `(Vec<u8>, count)` | Neutralizza tutto, restituisce binario patchato e conteggio. |
| `VmNeutralizationReport::total_checks(&self) -> usize` | — | `usize` | Totale check VM trovati. |
| `VmNeutralizationReport::is_clean(&self) -> bool` | — | `bool` | Vero se nessun check VM rilevato. |
| `VmNeutralizationReport::product_summary(&self) -> HashMap<VmProduct, usize>` | — | `HashMap` | Conteggio check per prodotto VM. |
| `VmNeutralizationReport::high_confidence_cpuid(&self) -> Vec<&CpuidCheck>` | — | `Vec<&CpuidCheck>` | CPUID check ad alta confidenza. |
| `VmNeutralizationReport::format_text(&self) -> String` | — | `String` | Report testuale. |

---

## src/vm_detection.rs — rilevamento e bypass check VM (livello alto)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `VmDetector::scan(&self, data: &[u8]) -> Vec<VmDetectionSite>` | byte slice | `Vec<VmDetectionSite>` | Rileva siti di rilevamento VM nel binario. |
| `VmDetector::generate_patches(&self, data, sites) -> Vec<BypassPatch>` | bytes, siti | `Vec<BypassPatch>` | Genera patch per ogni sito rilevato. |
| `VmDetector::patch_registry_checks(&self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Patcha tutti i check su chiavi registry VM. |
| `VmDetector::patch_process_name_checks(&self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Patcha controlli su nomi processo VM (vmtoolsd.exe, vboxservice.exe…). |
| `VmDetector::patch_cpuid_checks(&self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Patcha check CPUID. |

---

## src/vm_detection_bypass.rs — bypass VM a livello byte e CPUID spoofing

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `VmBypassScanner::new() -> Self` | — | `Self` | Scanner rilevamento VM con pattern built-in. |
| `VmBypassScanner::scan(&self, data: &[u8]) -> Vec<DetectionHit>` | byte slice | `Vec<DetectionHit>` | Scansione completa. |
| `StringReplacementBypass::with_common_rules() -> Self` | — | `Self` | Bypass con regole predefinite (sostituisce stringhe VM con stringhe banali). |
| `StringReplacementBypass::add_string_rule(&mut self, find, replace, desc)` | stringa cerca, sostituto, descr. | `()` | Aggiunge regola di sostituzione stringa. |
| `StringReplacementBypass::apply(&self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Applica tutte le sostituzioni; restituisce il numero di sostituzioni. |
| `RdtscPatcher::patch_rdtsc(&mut self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Patcha RDTSC con NOP o MOV EAX,0. |
| `CpuidSpoofer::hide_hypervisor() -> Self` | — | `Self` | Spoofer preconfigurato per nascondere il bit hypervisor. |
| `CpuidSpoofer::execute(&self, leaf: u32, sub_leaf: u32) -> Option<CpuidResult>` | leaf CPUID | `Option<CpuidResult>` | Esegue CPUID simulato con output falsificato. |
| `CpuidSpoofer::patch_cpuid(&self, data: &mut [u8]) -> usize` | buffer mutabile | `usize` | Patcha istruzioni CPUID nel binario per restituire valori non-VM. |
| `VmArtifactMasker::new() -> Self` | — | `Self` | Maschera artefatti VM (stringhe, mutex, device path). |
| `VmArtifactMasker::apply(&mut self, data: &mut [u8]) -> MaskReport` | buffer mutabile | `MaskReport` | Applica mascheramento e restituisce report. |
| `HypervisorFamilyMasker::new() -> Self` | — | `Self` | Mascheratore per famiglia di hypervisor. |
| `HypervisorFamilyMasker::process(&mut self, data: &mut [u8]) -> MaskReport` | buffer mutabile | `MaskReport` | Processa il buffer e maschera la famiglia. |
| `HypervisorFamilyMasker::artifacts_for(&self, family) -> Vec<&VmArtifact>` | `&HypervisorFamily` | `Vec<&VmArtifact>` | Elenca gli artefatti noti per la famiglia. |

---

## src/vm_detection_neutralizer.rs — neutralizzazione artefatti VM (stringhe/path)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `VmArtifact::new(…) -> Self` | offset, kind, bytes | `Self` | Descrive un artefatto VM trovato. |
| `SpoofRule::new(…) -> Self` | offset, bytes originali/sostitutivi | `Self` | Regola di spoofing per un artefatto. |
| `SpoofRule::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer | `Result` | Applica la regola di spoofing. |
| `SpoofRule::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>` | buffer | `Result` | Rollback. |
| `VmArtifactNeutralizer::new() -> Self` | — | `Self` | Neutralizzatore con database artefatti built-in (VMware, VirtualBox, Hyper-V, QEMU). |
| `VmArtifactNeutralizer::scan(&self, binary: &[u8]) -> Vec<VmArtifact>` | byte slice | `Vec<VmArtifact>` | Trova tutti gli artefatti VM. |
| `VmArtifactNeutralizer::generate_spoof_rules(&self, binary: &[u8]) -> Vec<SpoofRule>` | byte slice | `Vec<SpoofRule>` | Genera regole di spoofing per ogni artefatto. |
| `VmArtifactNeutralizer::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)` | buffer mutabile | `(count, log)` | Neutralizza tutti gli artefatti in-place. |
| `VmArtifactNeutralizer::frida_script(&self, artifacts: &[VmArtifact]) -> String` | slice artefatti | `String` | Script Frida per falsificare gli artefatti a runtime. |
| `VmArtifactNeutralizer::environment_histogram(artifacts) -> HashMap<VmEnvironment, usize>` | `&[VmArtifact]` | `HashMap` | Conteggio artefatti per ambiente VM. |
| `VmArtifactNeutralizer::kind_histogram(artifacts) -> HashMap<VmArtifactKind, usize>` | `&[VmArtifact]` | `HashMap` | Conteggio artefatti per tipo. |

---

## Note architetturali

- Ogni modulo segue il pattern **scan → generate_patches/rules → apply/neutralize**, con un'alternativa Frida per il bypass dinamico a runtime.
- I tipi di patch sono tutti reversibili (metodi `revert`/`rollback`).
- La generazione di script Frida copre tutti i vettori: hook di funzioni API, intercettazione CPUID, intercettazione SEH, spoofing PEB.
- La dipendenza da `rustre-deobf` fornisce le primitive di basso livello (scan byte, apply patch, strutture `Patch`).
