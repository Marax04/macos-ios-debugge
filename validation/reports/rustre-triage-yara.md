# rustre-triage-yara

**Crate:** `rustre-triage-yara` v0.1.0  
**Dipendenze chiave:** `rustre-triage`, `anyhow`, `thiserror`, `serde`, `serde_json`

Motore YARA puro-Rust per triage di binari: parsing e compilazione di regole, VM bytecode per l'esecuzione delle condizioni, scanner multi-target con parallelismo, gestione ruleset, ottimizzatore di regole, cache dei risultati, profiler delle performance, modulo PE, estrazione IOC, tagging threat e attribuzione famiglia malware.

---

## Moduli e funzioni pubbliche

### `yara_vm.rs` — VM bytecode + Aho-Corasick

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `MatchContext::new(n_strings, filesize)` | numero pattern, dimensione file | `MatchContext` | Inizializza il contesto di match con slot per N pattern |
| `MatchContext::record_hit(idx, offset, len)` | indice pattern, offset, lunghezza | `()` | Registra un hit per il pattern `idx` all'offset dato |
| `MatchContext::matched(idx)` | indice pattern | `bool` | Verifica se il pattern `idx` ha avuto almeno un hit |
| `MatchContext::count(idx)` | indice pattern | `usize` | Numero di hit per il pattern `idx` |
| `MatchContext::hit_at(idx, offset)` | indice, offset | `bool` | Verifica hit esatto all'offset specificato |
| `MatchContext::hit_in(idx, lo, hi)` | indice, range [lo, hi) | `bool` | Verifica se esiste un hit nell'intervallo di offset |
| `VmStack::push(v)` | `StackValue` | `()` | Inserisce un valore nello stack VM |
| `VmStack::pop(pc)` | program counter | `Result<StackValue, VmError>` | Estrae un valore dallo stack |
| `VmStack::peek(pc)` | program counter | `Result<&StackValue, VmError>` | Legge il top senza consumarlo |
| `VmStack::depth()` | — | `usize` | Profondità corrente dello stack |
| `VmStack::pop2(pc)` | program counter | `Result<(StackValue, StackValue), VmError>` | Estrae i due elementi in cima |
| `YaraVm::execute(...)` | bytecode + contesto | `bool` | Esegue il bytecode YARA e restituisce il risultato della condizione |
| `AhoCorasick::build(patterns)` | slice di pattern byte | `AhoCorasick` | Costruisce l'automa Aho-Corasick per la ricerca multi-pattern |
| `AhoCorasick::search(data)` | slice di byte | `Vec<(usize, usize)>` | Restituisce coppie (pattern_idx, offset) per tutti i match |
| `AhoCorasick::fill_context(data, ctx)` | dati, `MatchContext` mutabile | `()` | Popola un `MatchContext` con tutti i match trovati |
| `CompiledRule::new(name, bytecode)` | nome, bytecode | `CompiledRule` | Crea una regola compilata con nome e sequenza di opcode |
| `CompiledRule::add_pattern(pattern)` | `Vec<u8>` | `StringIndex` | Aggiunge un pattern binario e restituisce il suo indice |
| `CompiledRule::add_meta(key, value)` | chiave, valore | `()` | Aggiunge metadato alla regola |
| `CompiledRule::evaluate(data)` | `&[u8]` | `bool` | Esegue la regola sul buffer e restituisce il verdetto |

---

### `yara_scanner.rs` — Scanner multi-target

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ScanTarget::buffer(data, label)` | dati, etichetta | `ScanTarget` | Target da buffer in memoria |
| `ScanTarget::file(path)` | percorso | `ScanTarget` | Target da file su disco |
| `ScanTarget::memory(base, data, label)` | indirizzo base, dati, etichetta | `ScanTarget` | Target con base virtuale (dump memoria) |
| `ScanTarget::label()` | — | `String` | Restituisce l'etichetta descrittiva del target |
| `ScanTarget::read_bytes()` | — | `Result<Vec<u8>, ScanError>` | Legge i byte (da file o buffer) |
| `ScanResult::severity()` | — | `&str` | Severità massima tra tutti i match |
| `ScanResult::highest_severity()` | — | `&str` | Alias per la severità complessiva del risultato |
| `ScanStats::new()` | — | `ScanStats` | Crea statistiche azzerata |
| `ScanStats::merge(other)` | `&ScanStats` | `()` | Unisce statistiche da un altro contatore |
| `ScanStats::throughput_bytes_per_sec()` | — | `f64` | Calcola la velocità di scansione in byte/secondo |
| `ScanStats::record(result)` | `&ScanResult` | `()` | Aggiorna le statistiche con un risultato |
| `YaraScanner::with_chunk_size(chunk_size)` | dimensione chunk | `YaraScanner` | Imposta la dimensione dei chunk per scansione incrementale |
| `YaraScanner::new()` | — | `YaraScanner` | Scanner vuoto senza regole |
| `YaraScanner::add_rule(rule)` | `CompiledRule` | `()` | Aggiunge una regola compilata |
| `YaraScanner::add_rule_arc(rule)` | `Arc<CompiledRule>` | `()` | Aggiunge una regola condivisa (Arc) |
| `YaraScanner::clear_rules()` | — | `()` | Rimuove tutte le regole caricate |
| `YaraScanner::scan_buffer(data, label)` | `&[u8]`, etichetta | `Result<ScanResult, ScanError>` | Scansiona un buffer in memoria |
| `YaraScanner::scan_file(path)` | percorso file | `Result<ScanResult, ScanError>` | Scansiona un file su disco |
| `YaraScanner::scan_incremental(target)` | `&ScanTarget` | `Result<ScanResult, ScanError>` | Scansione a chunk per target grandi |
| `YaraScanner::scan_all(targets)` | `&[ScanTarget]` | `Result<Vec<ScanResult>, ScanError>` | Scansiona tutti i target in sequenza |
| `YaraScanner::scan_parallel(targets)` | `&[ScanTarget]` | `Result<Vec<ScanResult>, ScanError>` | Scansione parallela multi-thread dei target |
| `YaraScanner::stats()` | — | `ScanStats` | Restituisce le statistiche cumulative |
| `YaraScanner::reset_stats()` | — | `()` | Azzera le statistiche |
| `YaraScannerBuilder::new()` | — | `YaraScannerBuilder` | Costruttore builder per YaraScanner |
| `YaraScannerBuilder::rule(rule)` | `CompiledRule` | `Self` | Aggiunge regola al builder |
| `YaraScannerBuilder::build()` | — | `YaraScanner` | Costruisce lo scanner configurato |
| `BatchScanSummary::from_results(results)` | `&[ScanResult]` | `BatchScanSummary` | Aggrega risultati di scansione multipla |

---

### `yara_ruleset_manager.rs` — Gestione ruleset

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `RulesetEntry::new(name, description)` | nome, descrizione | `RulesetEntry` | Crea una voce di ruleset |
| `RulesetEntry::add_pattern(id, bytes)` | id pattern, byte | `()` | Aggiunge un pattern binario alla regola |
| `RulesetEntry::add_tag(tag)` | tag | `()` | Associa un tag alla regola |
| `RulesetEntry::set_meta(key, value)` | chiave, valore | `()` | Imposta metadato |
| `RulesetEntry::severity()` | — | `&str` | Severità dichiarata nei metadati |
| `RulesetEntry::has_tag(tag)` | tag | `bool` | Verifica presenza di un tag |
| `RulesetEntry::record_match()` | — | `()` | Incrementa il contatore di match |
| `RulesetEntry::total_pattern_bytes()` | — | `usize` | Dimensione totale dei pattern in byte |
| `YaraRulesetManager::new()` | — | `YaraRulesetManager` | Manager vuoto |
| `YaraRulesetManager::with_duplicate_policy(policy)` | `DuplicatePolicy` | `Self` | Imposta la politica per i duplicati |
| `YaraRulesetManager::add_entry(entry)` | `RulesetEntry` | `Result<(), RulesetManagerError>` | Aggiunge una regola al manager |
| `YaraRulesetManager::load_directory(dir)` | `&Path` | `Result<LoadStats, RulesetManagerError>` | Carica tutte le regole `.yar` da una directory |
| `YaraRulesetManager::get(name)` | nome | `Option<&RulesetEntry>` | Recupera una regola per nome |
| `YaraRulesetManager::get_mut(name)` | nome | `Option<&mut RulesetEntry>` | Recupera una regola mutabile per nome |
| `YaraRulesetManager::by_prefix(prefix)` | prefisso | `Vec<&RulesetEntry>` | Filtra regole per prefisso del nome |
| `YaraRulesetManager::by_tag(tag)` | tag | `Vec<&RulesetEntry>` | Filtra regole per tag |
| `YaraRulesetManager::by_severity(severity)` | livello | `Vec<&RulesetEntry>` | Filtra regole per severità |
| `YaraRulesetManager::enabled_rules()` | — | `Vec<&RulesetEntry>` | Tutte le regole abilitate |
| `YaraRulesetManager::disable(name)` | nome | `bool` | Disabilita una regola |
| `YaraRulesetManager::enable(name)` | nome | `bool` | Abilita una regola |
| `YaraRulesetManager::remove(name)` | nome | `Option<RulesetEntry>` | Rimuove una regola |
| `YaraRulesetManager::clear()` | — | `()` | Svuota il manager |
| `YaraRulesetManager::rule_count()` | — | `usize` | Numero totale di regole |
| `YaraRulesetManager::enabled_count()` | — | `usize` | Numero di regole abilitate |
| `YaraRulesetManager::total_match_count()` | — | `u64` | Match cumulativi su tutte le regole |
| `YaraRulesetManager::loaded_directories()` | — | `&[PathBuf]` | Directory caricate |
| `YaraRulesetManager::iter()` | — | `impl Iterator<Item = &RulesetEntry>` | Iteratore sulle voci |
| `YaraRulesetManager::all_tags()` | — | `Vec<String>` | Tutti i tag presenti nel ruleset |
| `YaraRulesetManager::record_match(name)` | nome regola | `()` | Aggiorna il contatore match di una regola |
| `YaraRulesetManager::top_matched(n)` | n | `Vec<&RulesetEntry>` | Top-N regole per numero di match |
| `YaraRulesetManager::with_builtin_rules()` | — | `YaraRulesetManager` | Manager precaricato con regole built-in |
| `YaraRulesetManager::summary()` | — | `RulesetSummary` | Sommario statistico del ruleset |
| `parse_yar_text(text, path)` | testo `.yar`, percorso | `Result<RulesetEntry, String>` | Parsa il testo di una regola YARA in `RulesetEntry` |
| `load_directory(dir)` | `&Path` | `Result<(YaraRulesetManager, LoadStats), RulesetManagerError>` | Funzione standalone per caricare una directory |

---

### `yara_rule_optimizer.rs` — Ottimizzatore AST regole

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `YaraString::new(id, pattern)` | id, pattern hex/testo | `YaraString` | Crea una stringa YARA per l'AST |
| `YaraString::pattern_eq(other)` | `&YaraString` | `bool` | Confronto di uguaglianza del pattern |
| `YaraString::pattern_byte_len()` | — | `usize` | Lunghezza in byte del pattern |
| `YaraRuleAst::new(name, condition)` | nome, condizione | `YaraRuleAst` | Crea un AST di regola YARA |
| `YaraRuleAst::referenced_ids()` | — | `HashSet<String>` | Identificatori di pattern referenziati nella condizione |
| `YaraRuleAst::to_yara_text()` | — | `String` | Serializza l'AST in testo YARA valido |
| `YaraRuleOptimizer::new()` | — | `YaraRuleOptimizer` | Ottimizzatore con tutti i pass default |
| `YaraRuleOptimizer::with_passes(passes)` | `Vec<OptimizationPass>` | `Self` | Ottimizzatore con pass personalizzati |
| `YaraRuleOptimizer::optimize_all(rule)` | `&YaraRuleAst` | `(YaraRuleAst, OptimizationResult)` | Applica tutti i pass di ottimizzazione |
| `YaraRuleOptimizer::deduplicate_strings(rule)` | `&YaraRuleAst` | regola + report | Rimuove pattern duplicati |
| `YaraRuleOptimizer::remove_unused_strings(rule)` | `&YaraRuleAst` | regola + report | Elimina pattern non referenziati nella condizione |
| `YaraRuleOptimizer::merge_alternatives(rule)` | `&YaraRuleAst` | `(YaraRuleAst, String)` | Unisce pattern alternativi simili |
| `YaraRuleOptimizer::optimize_condition(rule)` | `&YaraRuleAst` | `(YaraRuleAst, String)` | Semplifica la condizione logica |
| `YaraRuleOptimizer::add_anchors(rule)` | `&YaraRuleAst` | `(YaraRuleAst, u32, String)` | Aggiunge ancoraggi per migliorare le performance |
| `YaraRuleOptimizer::estimate_speedup(...)` | regola originale + ottimizzata | `f64` | Stima il guadagno di performance |

---

### `rule_optimizer.rs` — Ranking e analisi regole

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `PatternQuality::is_fast()` | — | `bool` | Il pattern è adatto a ricerca veloce |
| `PatternQuality::is_high_fp()` | — | `bool` | Il pattern ha alto rischio di falsi positivi |
| `PatternScorer::score(pattern)` | `&[u8]` | `f64` | Punteggio di qualità per pattern binario |
| `PatternScorer::score_hex(pattern)` | `&[Option<u8>]` | `f64` | Punteggio per pattern hex con wildcard |
| `LiteralExtractor::extract_from_bytes(pattern)` | `&[u8]` | `Option<Vec<u8>>` | Estrae letterale ottimale per pre-filtro |
| `LiteralExtractor::extract_from_hex(pattern)` | `&[Option<u8>]` | `Option<Vec<u8>>` | Estrae letterale da pattern hex |
| `LiteralExtractor::extract_from_text(text)` | `&str` | `Option<Vec<u8>>` | Estrae letterale da pattern testuale |
| `LiteralExtractor::extract_from_named_pattern(np)` | `&NamedPattern` | `Option<Vec<u8>>` | Estrae letterale da pattern nominato |
| `RuleRanker::stats_for_rule(rule)` | `&EnhancedYaraRule` | `RuleStats` | Calcola statistiche per una regola |
| `RuleRanker::rank(rules)` | `&[EnhancedYaraRule]` | `Vec<(&EnhancedYaraRule, RuleStats)>` | Classifica le regole per specificità |
| `RuleRanker::rank_by_speed(rules)` | `&[EnhancedYaraRule]` | `Vec<(&EnhancedYaraRule, RuleStats)>` | Classifica per velocità di esecuzione attesa |
| `RuleRanker::find_overlaps(rules, min_similarity)` | slice regole, soglia | `Vec<RuleOverlap>` | Trova coppie di regole con pattern sovrapposti |
| `RuleRanker::find_duplicate_indices(rules)` | `&[EnhancedYaraRule]` | `Vec<usize>` | Indici delle regole duplicate |
| `RuleRanker::group_by_family(rules)` | `&[EnhancedYaraRule]` | `HashMap<String, Vec<...>>` | Raggruppa per famiglia (dal nome della regola) |
| `RuleRanker::group_by_meta_family(...)` | regole + chiave meta | `HashMap<String, Vec<...>>` | Raggruppa per campo metadato famiglia |
| `RuleRanker::sorted_groups(...)` | regole + chiave meta | gruppi ordinati | Gruppi ordinati per numero di regole |
| `RuleCollection::all_stats()` | — | `Vec<RuleStats>` | Statistiche per tutte le regole della collezione |
| `RuleCollection::ranked_by_specificity()` | — | `Vec<(&EnhancedYaraRule, RuleStats)>` | Classifica per specificità |
| `RuleCollection::ranked_by_speed()` | — | `Vec<(&EnhancedYaraRule, RuleStats)>` | Classifica per velocità |
| `RuleCollection::find_overlaps(min_similarity)` | soglia | `Vec<RuleOverlap>` | Overlap nella collezione |
| `RuleCollection::deduplicate()` | — | `Vec<&EnhancedYaraRule>` | Regole de-duplicate |
| `RuleCollection::group_by_family()` | — | `HashMap<String, Vec<...>>` | Raggruppa per famiglia |
| `RuleCollection::report()` | — | `OptimizationReport` | Report di ottimizzazione completo |
| `OptimizationReport::summary()` | — | `String` | Sommario testuale del report |

---

### `yara_cache.rs` — Cache risultati LRU/TTL

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `CacheKey::from_hex(file_hex, rules_hex)` | hash file, hash ruleset | `Option<CacheKey>` | Crea una chiave di cache da due hash esadecimali |
| `CacheKey::short_display()` | — | `String` | Visualizzazione abbreviata della chiave |
| `CacheEntry::memory_bytes()` | — | `u64` | Stima memoria occupata dall'entry |
| `CacheStats::hit_rate()` | — | `f64` | Tasso di hit (0.0–1.0) |
| `CacheStats::miss_rate()` | — | `f64` | Tasso di miss (0.0–1.0) |
| `YaraResultCache::new(max_entries, max_memory_bytes, policy)` | limiti e policy | `YaraResultCache` | Crea cache con limiti di capacità e memoria |
| `YaraResultCache::get(key, now)` | chiave, timestamp Unix | `Option<&Vec<YaraMatch>>` | Recupera risultati dalla cache (aggiorna LRU) |
| `YaraResultCache::peek(key)` | chiave | `Option<&CacheEntry>` | Legge senza aggiornare la posizione LRU |
| `YaraResultCache::insert(key, matches, ...)` | chiave, risultati | `()` | Inserisce risultati con eventuale eviction |
| `YaraResultCache::evict_one()` | — | `bool` | Espelle un'entry secondo la policy |
| `YaraResultCache::evict_expired(now, max_age_secs)` | timestamp, TTL | `usize` | Rimuove tutte le entry scadute |
| `YaraResultCache::remove(key)` | chiave | `bool` | Rimuove una entry specifica |
| `YaraResultCache::clear()` | — | `()` | Svuota la cache |
| `YaraResultCache::cache_hit_rate()` | — | `f64` | Hit rate corrente |
| `YaraResultCache::stats()` | — | `CacheStats` | Statistiche complete della cache |
| `YaraResultCache::len()` | — | `usize` | Numero di entry presenti |
| `YaraResultCache::is_empty()` | — | `bool` | True se la cache è vuota |
| `YaraResultCache::estimate_entry_memory(result)` | `&[YaraMatch]` | `u64` | Stima memoria per un insieme di match |

---

### `yara_performance_profiler.rs` — Profiling per-regola

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `RuleProfile::new(name)` | nome regola | `RuleProfile` | Crea profilo per una regola |
| `RuleProfile::record(elapsed, matched)` | `Duration`, bool | `()` | Registra una misurazione |
| `RuleProfile::mean_time()` | — | `Duration` | Tempo medio di esecuzione |
| `RuleProfile::p95_time()` | — | `Duration` | Percentile 95 del tempo di esecuzione |
| `RuleProfile::match_rate()` | — | `f64` | Frazione di esecuzioni che hanno prodotto match |
| `ProfileSession::time_rule(rule_name, matched, f)` | nome, bool, closure | `()` | Esegue la closure misurandone il tempo |
| `ProfileSession::record_rule(rule_name, elapsed, matched)` | nome, durata, bool | `()` | Registra manualmente una misurazione |
| `ProfileSession::finish()` | — | `Duration` | Termina la sessione e restituisce la durata totale |
| `YaraProfiler::new()` | — | `YaraProfiler` | Profiler globale vuoto |
| `YaraProfiler::record_evaluation(rule_name, elapsed, matched)` | nome, durata, bool | `()` | Registra una valutazione nel profiler globale |
| `YaraProfiler::start_session(source_uri)` | URI sorgente | `ProfileSession<'_>` | Avvia una sessione di profiling |
| `YaraProfiler::get_profile(rule_name)` | nome | `Option<&RuleProfile>` | Recupera il profilo di una regola |
| `YaraProfiler::total_rule_time()` | — | `Duration` | Tempo cumulativo su tutte le regole |
| `YaraProfiler::rule_count()` | — | `usize` | Numero di regole profilate |
| `YaraProfiler::results()` | — | `Vec<ProfileResult>` | Tutti i risultati di profiling |
| `YaraProfiler::top_slow(n)` | n | `Vec<ProfileResult>` | Top-N regole più lente |
| `YaraProfiler::hotspots(threshold_pct)` | percentuale soglia | `Vec<ProfileResult>` | Regole che consumano oltre la soglia del tempo totale |
| `YaraProfiler::global_mean_time()` | — | `Duration` | Tempo medio globale per regola |
| `YaraProfiler::reset()` | — | `()` | Azzera tutti i profili |
| `YaraProfiler::report_text()` | — | `String` | Report testuale formattato |
| `PatternBenchmark::new(iterations)` | numero iterazioni | `PatternBenchmark` | Benchmark per pattern singoli |
| `PatternBenchmark::bench_pattern(name, pattern, data)` | nome, pattern, dati | `u64` | Misura ns/iter per il pattern sul buffer dato |
| `PatternBenchmark::results()` | — | `Vec<ProfileResult>` | Risultati del benchmark |
| `PatternBenchmark::report_text()` | — | `String` | Report testuale del benchmark |

---

### `yara_module_pe.rs` — Modulo PE per condizioni YARA

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `PeModule::new(data)` | `&PeModuleData` | `PeModule` | Crea il modulo PE da dati pre-parsati |
| `PeModule::section_entropy(index)` | indice sezione | `Option<f64>` | Entropia di Shannon della sezione |
| `PeModule::section_by_name(name)` | nome sezione | `Option<&SectionInfo>` | Sezione PE per nome (es. `.text`) |
| `PeModule::imphash()` | — | `&str` | Import hash del PE |
| `PeModule::imports(func)` | nome funzione | `bool` | Verifica se il PE importa la funzione |
| `PeModule::imports_from(dll, func)` | dll, funzione | `bool` | Verifica importazione da DLL specifica |
| `PeModule::import_count()` | — | `usize` | Numero totale di import |
| `PeModule::exports(name)` | nome export | `bool` | Verifica se il PE esporta il simbolo |
| `PeModule::version_info(key)` | chiave versione | `Option<&str>` | Valore dal PE VersionInfo resource |
| `PeModuleParser::new()` | — | `PeModuleParser` | Parser PE per il modulo YARA |
| `PeModuleParser::parse(data)` | `&[u8]` | `Result<PeModuleData, PeModuleError>` | Parsa un binario PE estraendo metadati |

---

### `ioc_extractor.rs` — Estrazione IOC

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ExtractedIoc::value()` | — | `&str` | Valore stringa dell'IOC estratto |
| `IocReport::new(label)` | etichetta | `IocReport` | Crea un report IOC vuoto |
| `IocReport::add(ioc)` | `ExtractedIoc` | `()` | Aggiunge un IOC al report |
| `IocReport::build_summary()` | — | `()` | Calcola il sommario aggregato |
| `IocReport::deduplicate()` | — | `()` | Rimuove IOC duplicati |
| `IocReport::ip_addresses()` | — | `Vec<&str>` | Indirizzi IP estratti |
| `IocReport::domains()` | — | `Vec<&str>` | Domini estratti |
| `IocExtractor::new()` | — | `IocExtractor` | Estrattore con regex predefinite |
| `IocExtractor::extract(data, label)` | `&[u8]`, etichetta | `IocReport` | Estrae IOC da un buffer |
| `IocExtractor::extract_with_rules(data, label, ...)` | buffer + regole YARA match | `IocReport` | Estrae IOC arricchiti con contesto YARA |
| `extract_printable_strings(data, min_len)` | `&[u8]`, lunghezza minima | `Vec<(u64, String)>` | Estrae stringhe ASCII stampabili con offset |
| `extract_wide_strings(data, min_len)` | `&[u8]`, lunghezza minima | `Vec<(u64, String)>` | Estrae stringhe UTF-16LE con offset |

---

### `verdict.rs` — Verdetto e scoring

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `YaraScore::new(value)` | score 0–100 | `YaraScore` | Crea uno score YARA |
| `YaraScore::with_signals(value, count)` | score, numero segnali | `YaraScore` | Score con conteggio segnali contributori |
| `FamilyAttribution::new(family)` | nome famiglia | `FamilyAttribution` | Attribuzione a famiglia malware |
| `FamilyAttribution::add_match(severity, score)` | severità, punteggio | `()` | Registra un match contribuente |
| `VerdictEngine::new()` | — | `VerdictEngine` | Motore di verdetto con pesi default |
| `VerdictEngine::compute(matches, ...)` | match YARA + contesto | `VerdictResult` | Calcola il verdetto finale dal set di match |
| `VerdictResult::clean()` | — | `VerdictResult` | Verdetto "pulito" (nessuna minaccia) |
| `VerdictResult::top_family()` | — | `Option<&FamilyAttribution>` | Famiglia malware con punteggio più alto |
| `VerdictResult::family_names()` | — | `Vec<&str>` | Tutti i nomi di famiglia rilevati |
| `VerdictResult::summary()` | — | `String` | Sommario testuale del verdetto |
| `BatchVerdictStats::new()` | — | `BatchVerdictStats` | Statistiche per scansioni batch |
| `BatchVerdictStats::add(result)` | `&VerdictResult` | `()` | Aggiunge un verdetto alle statistiche |
| `BatchVerdictStats::average_score()` | — | `f64` | Score medio del batch |
| `BatchVerdictStats::malicious_rate()` | — | `f64` | Percentuale di file classificati malevoli |
| `BatchVerdictStats::top_n_families(n)` | n | `Vec<(&str, u32)>` | Top-N famiglie per frequenza |
| `VerdictOverrideTable::new()` | — | `VerdictOverrideTable` | Tabella di override manuali per regola |
| `VerdictOverrideTable::apply(result, matched_rules)` | verdetto mutabile, nomi regole | `()` | Applica override ai verdetti |
| `severity_weight(s)` | stringa severità | `u8` | Converte severità testuale in peso numerico |
| `weighted_verdict_score(contributions)` | `&[(&str, u32)]` | `u8` | Calcola score pesato da contributi multipli |
| `VerdictTransition::new(from, to, reason, delta)` | due verdetti, motivo, delta | `VerdictTransition` | Rappresenta una transizione di verdetto |
| `VerdictTransition::is_escalation()` | — | `bool` | True se il verdetto è peggiorato |
| `VerdictTransition::is_deescalation()` | — | `bool` | True se il verdetto è migliorato |
| `VerdictChain::new()` | — | `VerdictChain` | Catena di verdetti evolutivi |
| `VerdictChain::push(verdict, score, reason)` | verdetto, score, motivo | `()` | Aggiunge un passo alla catena |
| `VerdictChain::final_verdict()` | — | `YaraVerdict` | Verdetto finale della catena |
| `VerdictChain::final_score()` | — | `u8` | Score finale della catena |
| `VerdictChain::transitions()` | — | `Vec<VerdictTransition>` | Tutte le transizioni della catena |
| `SeverityOverrideMap::new()` | — | `SeverityOverrideMap` | Mappa di override severità per regola |
| `SeverityOverrideMap::insert(rule_name, severity)` | nome, severità | `()` | Inserisce un override |
| `SeverityOverrideMap::get(rule_name)` | nome | `Option<&str>` | Recupera l'override per una regola |
| `SeverityOverrideMap::apply(matches)` | `&mut [YaraTriageMatch]` | `()` | Applica gli override ai match |
| `VerdictSummary::from_result(r)` | `&VerdictResult` | `VerdictSummary` | Crea un sommario serializzabile |
| `VerdictSummary::to_json()` | — | `serde_json::Result<String>` | Serializza in JSON |

---

### `yara_threat_tagger.rs` — Tagging minacce

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ThreatTag::new(...)` | categoria, label, confidence | `ThreatTag` | Crea un tag di minaccia |
| `ThreatTag::is_high_confidence()` | — | `bool` | True se la confidence è alta |
| `TaggingRule::new(rule_name)` | nome regola YARA | `TaggingRule` | Regola di tagging associata a un match YARA |
| `TaggingRule::with_namespace(ns)` | namespace | `Self` | Aggiunge namespace alla regola |
| `TaggingRule::matches_rule(rule_name)` | nome | `bool` | True se la regola corrisponde al nome dato |
| `builtin_tagging_rules()` | — | `Vec<TaggingRule>` | Regole di tagging predefinite |
| `ThreatProfile::is_high_threat()` | — | `bool` | True se il profilo indica alta pericolosità |
| `ThreatProfile::high_confidence_tags()` | — | `Vec<&ThreatTag>` | Tag ad alta confidence nel profilo |
| `ThreatTagger::new()` | — | `ThreatTagger` | Tagger con regole default |
| `ThreatTagger::with_rules(rules)` | `Vec<TaggingRule>` | `Self` | Tagger con regole personalizzate |
| `ThreatTagger::add_rule(rule)` | `TaggingRule` | `()` | Aggiunge una regola di tagging |
| `ThreatTagger::tag_match_results(matches)` | `&[YaraMatch]` | `Vec<ThreatTag>` | Produce tag dai match YARA |
| `ThreatTagger::build_profile(file_sha256, matches)` | SHA256, match | `ThreatProfile` | Costruisce il profilo di minaccia per un file |
| `ThreatTagger::derive_mitre_ttps(tags, matches)` | tag, match | `Vec<String>` | Deriva TTP MITRE ATT&CK dai tag e dai match |
| `tag_to_mitre(category)` | `&TagCategory` | `Vec<String>` | Mappa una categoria di tag a TTP MITRE |
| `rule_name_to_mitre(rule_name)` | nome regola | `Vec<String>` | Deriva TTP MITRE dal nome della regola YARA |

---

### `yara_threat_intel.rs` — Intelligence sulle minacce

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ThreatFamily::new(id, description)` | id, descrizione | `ThreatFamily` | Famiglia malware con metadati |
| `ThreatFamily::associated_with_actor(actor)` | nome attore | `bool` | Verifica associazione con threat actor |
| `FamilyAttribution::from_match_ratio(matches, total)` | match trovati, totale | `Self` | Attribuzione da ratio di match |
| `ThreatCluster::new(id, description)` | id, descrizione | `ThreatCluster` | Cluster di famiglie correlate |
| `ThreatCluster::contains_family(family)` | nome famiglia | `bool` | Verifica se il cluster contiene la famiglia |
| `ThreatCluster::is_reliable()` | — | `bool` | Cluster con sufficiente confidenza |
| `MalpediaDb::entries()` | — | `Vec<MalpediaEntry>` | Tutte le entry del database Malpedia built-in |
| `MalpediaDb::lookup(name)` | nome | `Option<MalpediaEntry>` | Ricerca per nome nel database |
| `MalpediaDb::by_kind(kind)` | `&ThreatFamilyKind` | `Vec<MalpediaEntry>` | Filtra per tipo di malware |
| `ThreatIntelRule::new(...)` | pattern, metadati | `ThreatIntelRule` | Regola di intelligence con pattern di firma |
| `ThreatIntelRule::scan(data)` | `&[u8]` | `Vec<(usize, u64)>` | Scansiona dati e restituisce (pattern_idx, offset) |
| `ThreatIntelRule::fires(data)` | `&[u8]` | `bool` | True se la regola ha almeno un hit |
| `ThreatIntelEngine::with_builtin_rules()` | — | `ThreatIntelEngine` | Motore con regole built-in |
| `ThreatIntelEngine::add_rule(rule)` | `ThreatIntelRule` | `()` | Aggiunge una regola al motore |
| `ThreatIntelEngine::add_cluster(cluster)` | `ThreatCluster` | `()` | Aggiunge un cluster al motore |
| `ThreatIntelEngine::scan(data)` | `&[u8]` | `Vec<ThreatIntelMatch>` | Scansiona e restituisce tutti i match intel |
| `ThreatIntelEngine::attribute(data)` | `&[u8]` | `Vec<FamilyAttribution>` | Attribuisce il binario a famiglie malware |

---

### `match_report.rs`, `scanner.rs`, `family_classifier.rs` — Strutture di supporto

Questi moduli espongono principalmente tipi di dato (`MatchReport`, `YaraMatch`, `YaraTriageMatch`, `FamilyClassifier`) con metodi `new`, serializzazione JSON e accessori; non contengono logica algoritmica autonoma rispetto ai moduli sopra.

---

## Riepilogo

| Modulo | Funzioni pub |
|--------|-------------|
| `yara_vm.rs` | 19 |
| `yara_scanner.rs` | 23 |
| `yara_ruleset_manager.rs` | 32 |
| `yara_rule_optimizer.rs` | 15 |
| `rule_optimizer.rs` | 25 |
| `yara_cache.rs` | 18 |
| `yara_performance_profiler.rs` | 22 |
| `yara_module_pe.rs` | 11 |
| `ioc_extractor.rs` | 12 |
| `verdict.rs` | 33 |
| `yara_threat_tagger.rs` | 16 |
| `yara_threat_intel.rs` | 16 |
| **Totale** | **242** |
