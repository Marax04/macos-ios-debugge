# rustre-triage

Crate di triage automatizzato: classifica un binario, assegna un livello di minaccia e produce un report strutturato. Espone una pipeline a stadi, un motore euristico, un aggregatore di punteggi, un mapper MITRE ATT&CK, un classificatore di famiglie malware e analizzatori specializzati per PE/ELF/Mach-O.

**Dipendenze principali:** `rustre-pe-tools`, `rustre-loader-pe`, `rustre-crypto-id`, `sha2`, `md-5`, `serde_json`, `thiserror`.

---

## Moduli pubblici

| Modulo | Responsabilità |
|---|---|
| `lib` | Tipi core, pipeline semplice (plugin-based), StringHeuristics, ElfTriageAnalyzer, MachOTriageAnalyzer, PeTriageAnalyzer, TriageCoordinator |
| `triage_pipeline` | Pipeline a stadi (`PipelineStage`), stadi built-in, `TriagePipeline`, `PipelineRunResult` |
| `triage_report` | Rendering multi-formato (text/markdown/CSV/JSON/HTML), `ReportSection`, `TriageReport2`, `TriageReportBuilder` |
| `score_aggregator` | Aggregazione punteggi ponderati, trend temporale, diff, preset `TriageScore` |
| `heuristic_engine` | Trait `Heuristic`, `HeuristicEngine` con regole built-in, `HeuristicReport` |
| `analyzer_registry` | Trait `TriageAnalyzer`, `AnalyzerRegistry`, `AnalysisResult`, `RegistryRunResult` |
| `rapid_classifier` | Classificazione rapida del tipo di file/famiglia |
| `file_classifier` | Classificazione estesa del file con metadati |
| `malware_classification` | Fuzzy hash, imphash, classificatore per famiglia, `MalwareClassifier` |
| `mitre_mapper` | Mapping indicatori → tecniche MITRE ATT&CK, `AttackMatrix`, `MitreMapper` |
| `pe_triage_extended` | Analisi PE estesa: features, anomalie, sezioni, `PeTriageReport` |
| `static_analysis_triage` | Analisi statica pesata per feature, `StaticTriageEngine` |
| `findcrypt` | Riconoscimento costanti crittografiche inline (Crypto++ style) |
| `family_db` | Database famiglie malware con IoC e API matching |

---

## Funzioni e metodi pubblici (104 totali)

### `lib.rs` — tipi core e coordinatore

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `detect_file_kind(data: &[u8]) -> FileKind` | slice di byte grezzi | `FileKind` enum | Identifica il formato del file tramite magic bytes (MZ, ELF, Mach-O, ZIP/APK, DEX, PDF, DOC). |
| `analyze_section_entropy(data: &[u8]) -> Vec<SectionEntropy>` | slice di byte | `Vec<SectionEntropy>` | Divide i dati in blocchi da 4 KiB, calcola l'entropia di Shannon per ciascun blocco. |
| `EntropyRating::from_entropy(e: f64) -> Self` | valore entropia 0.0–8.0 | `EntropyRating` | Classifica l'entropia in 5 livelli (VeryLow / Low / Normal / High / VeryHigh). |
| `TriageResult::new(file_kind: FileKind, data: &[u8]) -> Self` | tipo file + byte | `TriageResult` | Costruisce un risultato iniziale calcolando SHA-256, MD5 e entropia. |
| `TriageResult::add_indicator(&mut self, indicator: TriageIndicator)` | `TriageIndicator` | `()` | Aggiunge un indicatore e aggiorna score (0–100) e threat_level. |
| `TriageResult::is_malicious(&self) -> bool` | — | `bool` | Vero se `threat_level >= ThreatLevel::High`. |
| `TriageResult::to_report(&self, strings: Vec<SuspiciousString>) -> TriageReport` | stringhe sospette | `TriageReport` | Produce un report JSON-serializzabile dalla struttura interna. |
| `TriageResult::to_json(&self) -> Result<String, serde_json::Error>` | — | `Result<String, …>` | Serializza il risultato come JSON pretty-printed. |
| `TriageReport::render_text(&self) -> String` | — | `String` | Produce un sommario testuale leggibile (tipo file, score, indicatori, stringhe). |
| `TriageReport::render_json(&self) -> Result<String, serde_json::Error>` | — | `Result<String, …>` | Serializza il report come JSON pretty-printed. |
| `TriageFinding::new(kind, description) -> Self` | stringhe | `TriageFinding` | Crea un finding leggero con kind e descrizione. |
| `ThreatScorer::score(findings: &[TriageFinding]) -> u32` | slice di finding | `u32` (0–100) | Calcola uno score aggregato mappando i kind su `ThreatLevel` e sommando i delta. |
| `TriagePipeline::new() -> Self` | — | `TriagePipeline` | Pipeline vuota (plugin-based, API legacy). |
| `TriagePipeline::add_plugin(&mut self, p: Box<dyn TriagePlugin>)` | plugin boxed | `()` | Aggiunge un plugin alla coda della pipeline. |
| `TriagePipeline::run(&self, bytes: &[u8]) -> TriageReport` | byte grezzi | `TriageReport` | Esegue tutti i plugin, aggrega i finding e restituisce il report (API legacy). |
| `StringHeuristics::extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString>` | byte + lunghezza minima | `Vec<ExtractedString>` | Estrae run ASCII e UTF-16 LE di almeno `min_len` caratteri. |
| `StringHeuristics::extract_strings_with_va(data, min_len, sections) -> Vec<ExtractedString>` | byte + sezioni PE | `Vec<ExtractedString>` | Come `extract_strings` ma risolve l'indirizzo virtuale per ogni hit. |
| `StringHeuristics::extract_strings_with_sections(data, min_len, sections) -> Vec<ExtractedString>` | byte + `SectionInfo[]` | `Vec<ExtractedString>` | Variante con descriptor semplificato `(file_offset, file_size, virtual_address)`. |
| `StringHeuristics::extract_strings_from_pe(path, min_len) -> Result<Vec<ExtractedString>, TriageError>` | path + lunghezza | `Result<Vec<…>, TriageError>` | Legge un PE da disco, effettua il parsing e estrae stringhe con VA. |
| `StringHeuristics::extract_strings_auto_va(data, min_len) -> Vec<ExtractedString>` | byte + lunghezza | `Vec<ExtractedString>` | Auto-rileva formato PE per popolare le VA; fallback a `extract_strings`. |
| `StringHeuristics::classify(strings: &[ExtractedString]) -> Vec<SuspiciousString>` | stringhe estratte | `Vec<SuspiciousString>` | Categorizza le stringhe (URL, IP, registry key, cripto, base64, malware, ecc.). |
| `ElfTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)` | byte ELF + risultato | `()` | Analizza header ELF, sezioni, PHDR, librerie dinamiche, simboli sospetti. |
| `MachOTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)` | byte Mach-O + risultato | `()` | Analizza header Mach-O, load commands, librerie e entitlements. |
| `PeTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)` | byte PE + risultato | `()` | Analizza header PE, import table, sezioni, TLS, risorse. |
| `TriageCoordinator::new() -> Self` | — | `TriageCoordinator` | Costruisce il coordinatore con pipeline di default. |
| `TriageCoordinator::analyze(&self, data: &[u8]) -> Result<TriageResult, TriageError>` | byte grezzi | `Result<TriageResult, TriageError>` | Esegue l'analisi completa tramite la pipeline interna. |
| `TriageCoordinator::analyze_with_config(&self, data, config) -> Result<TriageResult, TriageError>` | byte + `TriageConfig` | `Result<TriageResult, TriageError>` | Come `analyze` ma con configurazione personalizzata (flag, limiti). |

### `triage_pipeline.rs` — pipeline a stadi

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `StageOutput::empty(stage_name) -> Self` | nome stadio | `StageOutput` | Output di successo senza indicatori. |
| `StageOutput::skipped(stage_name, reason) -> Self` | nome + motivo | `StageOutput` | Output che segnala che lo stadio è stato saltato. |
| `StageOutput::failed(stage_name, error) -> Self` | nome + errore | `StageOutput` | Output di fallimento con messaggio di errore. |
| `EntropyStage::new(threshold: f64) -> Self` | soglia entropia | `EntropyStage` | Crea lo stadio di rilevamento alta entropia. |
| `StringAnalysisStage::new(min_length, max_scan_bytes) -> Self` | parametri | `StringAnalysisStage` | Crea lo stadio di analisi stringhe sospette (URL, API, chiavi). |
| `AllStringExtractionStage::new(min_length, max_scan_bytes) -> Self` | parametri | `AllStringExtractionStage` | Popola `TriageResult::all_strings` con tutte le stringhe printable. |
| `TriagePipeline::new() -> Self` | — | `TriagePipeline` | Pipeline vuota (stadi). |
| `TriagePipeline::default_pipeline() -> Self` | — | `TriagePipeline` | Pipeline precaricat con stadi: FileKind, Entropy, Packer, String, AllString, Compiler, AntiAnalysis, Shellcode, CryptoConstant. |
| `TriagePipeline::add_stage(&mut self, stage: Box<dyn PipelineStage>)` | stadio boxed | `()` | Aggiunge uno stadio alla coda della pipeline. |
| `TriagePipeline::stop_at(&mut self, level: ThreatLevel)` | livello | `()` | Configura early-exit quando viene raggiunto il livello specificato. |
| `TriagePipeline::run(&self, data: &[u8]) -> Result<PipelineRunResult, TriageError>` | byte grezzi | `Result<PipelineRunResult, TriageError>` | Esegue tutti gli stadi applicabili, rispettando i limiti di indicatori e l'early-exit. |
| `PipelineRunResult::indicator_count(&self) -> usize` | — | `usize` | Numero totale di indicatori trovati. |
| `PipelineRunResult::stage_indicators(&self, stage_name) -> Vec<&TriageIndicator>` | nome stadio | `Vec<&TriageIndicator>` | Indicatori prodotti da uno stadio specifico. |
| `PipelineRunResult::ran_stages(&self) -> Vec<&str>` | — | `Vec<&str>` | Nomi degli stadi che hanno eseguito con successo. |
| `PipelineRunResult::total_stage_time_us(&self) -> u64` | — | `u64` | Somma dei tempi di esecuzione degli stadi in microsecondi. |
| `PipelineRunResult::summary(&self) -> String` | — | `String` | Riassunto conciso: tipo file, threat level, score, conteggio indicatori, tempo. |

### `triage_report.rs` — rendering report

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `ReportSection::new(title) -> Self` | titolo | `ReportSection` | Crea una sezione vuota con titolo. |
| `ReportSection::push(&mut self, line)` | riga | `()` | Aggiunge una riga di testo alla sezione. |
| `ReportSection::push_kv(&mut self, key, value)` | chiave + valore | `()` | Aggiunge una riga in formato `key: value`. |
| `ReportSection::render_text(&self) -> String` | — | `String` | Rendering testuale della sezione. |
| `ReportSection::render_markdown(&self) -> String` | — | `String` | Rendering Markdown della sezione. |
| `TriageReport2::from_result(title, result: &TriageResult) -> Self` | titolo + risultato | `TriageReport2` | Costruisce un report strutturato da un `TriageResult`. |
| `TriageReport2::indicators_by_level(&self) -> HashMap<String, usize>` | — | `HashMap<String, usize>` | Conteggio indicatori raggruppati per livello di minaccia. |
| `TriageReport2::render_text(&self) -> String` | — | `String` | Rendering testuale completo. |
| `TriageReport2::render_markdown(&self) -> String` | — | `String` | Rendering Markdown completo. |
| `TriageReport2::render_csv(&self) -> String` | — | `String` | Rendering CSV degli indicatori. |
| `TriageReport2::render_json(&self) -> Result<String, serde_json::Error>` | — | `Result<String, …>` | Serializzazione JSON. |
| `TriageReport2::render_html(&self) -> String` | — | `String` | Rendering HTML con tabelle. |
| `render_html(report: &TriageReport2) -> String` (libera) | report | `String` | Funzione libera di rendering HTML. |
| `TriageReportBuilder::new(title) -> Self` | titolo | `TriageReportBuilder` | Avvia la costruzione fluente di un report. |
| `TriageReportBuilder::sha256(self, sha) -> Self` | hash | `Self` | Imposta SHA-256. |
| `TriageReportBuilder::md5(self, md5) -> Self` | hash | `Self` | Imposta MD5. |
| `TriageReportBuilder::add_section(self, section) -> Self` | sezione | `Self` | Aggiunge una sezione. |
| `TriageReportBuilder::add_indicator(self, ind) -> Self` | indicatore | `Self` | Aggiunge un indicatore. |
| `TriageReportBuilder::build(self) -> TriageReport2` | — | `TriageReport2` | Finalizza e restituisce il report. |

### `score_aggregator.rs` — aggregazione punteggi

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `ScoreSignal::new(kind, raw, reason) -> Self` | tipo analizzatore + score grezzo + motivo | `ScoreSignal` | Crea un segnale di score. |
| `ScoreSignal::add_signal(&mut self, s)` | segnale | `()` | Accumula un segnale nella lista interna. |
| `ScoreSignal::weighted(&self) -> f64` | — | `f64` | Calcola il peso ponderato del segnale. |
| `AnalyzerScore::new(name, value, description) -> Self` | nome + valore + desc | `AnalyzerScore` | Crea uno score con nome e descrizione. |
| `AggregatedScore::compute(scores: &[f64]) -> Self` | slice di score | `AggregatedScore` | Media pesata e classificazione finale. |
| `AggregatedScore::is_malicious(&self) -> bool` | — | `bool` | Vero se lo score supera la soglia malevola. |
| `AggregatedScore::is_suspicious(&self) -> bool` | — | `bool` | Vero se lo score è in zona sospetta. |
| `AggregatedScore::is_clean(&self) -> bool` | — | `bool` | Vero se il file sembra pulito. |
| `AggregatedScore::summary(&self) -> String` | — | `String` | Testo breve con score e classificazione. |
| `ScoreAggregator::new() -> Self` | — | `ScoreAggregator` | Aggregatore con pesi di default. |
| `ScoreAggregator::set_weight(&mut self, kind, weight)` | categoria + peso | `()` | Sovrascrive il peso di una categoria. |
| `ScoreAggregator::aggregate(&self, scores) -> AggregatedScore` | slice di `TriageScore` | `AggregatedScore` | Aggregazione ponderata degli score. |
| `ScoreAggregator::aggregate_with_entropy_penalty(&self, scores, entropy) -> AggregatedScore` | score + entropia | `AggregatedScore` | Aggregazione con penalità aggiuntiva per alta entropia. |
| `ScoreAggregator::aggregate_with_yara_boost(&self, scores, yara_hits) -> AggregatedScore` | score + hit YARA | `AggregatedScore` | Aggregazione con boost per match YARA. |
| `ScoreNormaliser::normalise(value, lo, hi) -> u8` | valore + range | `u8` (0–100) | Normalizzazione lineare a 0–100. |
| `ScoreNormaliser::max_normalise(scores, max_possible) -> u8` | scores + massimo | `u8` | Normalizzazione sul massimo possibile. |
| `ScoreNormaliser::from_entropy(entropy) -> u8` | entropia | `u8` | Converte entropia in score 0–100. |
| `ScoreNormaliser::from_import_count(suspicious, total) -> u8` | conteggi | `u8` | Score basato sul rapporto import sospetti / totale. |
| `ScoreTimeline::new(capacity) -> Self` | capacità | `ScoreTimeline` | Buffer circolare per storico temporale degli score. |
| `ScoreTimeline::push(&mut self, timestamp, score)` | timestamp + score | `()` | Aggiunge un punto allo storico. |
| `ScoreTimeline::average(&self) -> f64` | — | `f64` | Media degli score nello storico. |
| `ScoreTimeline::trend(&self) -> f64` | — | `f64` | Tendenza (positiva = peggioramento). |
| `ScoreTimeline::max_score(&self) -> u8` | — | `u8` | Score massimo osservato. |
| `BatchScoreStats::new() -> Self` | — | `BatchScoreStats` | Statistiche batch vuote. |
| `BatchScoreStats::add(&mut self, result)` | `AggregatedScore` | `()` | Accumula un risultato nel batch. |
| `BatchScoreStats::average_score(&self) -> f64` | — | `f64` | Media degli score del batch. |
| `BatchScoreStats::malicious_rate(&self) -> f64` | — | `f64` | Percentuale di file classificati malevoli. |
| `BatchScoreStats::summary(&self) -> String` | — | `String` | Riassunto testuale delle statistiche batch. |
| `ScoreDiff::new(before, after) -> Self` | due `AggregatedScore` | `ScoreDiff` | Calcola la differenza tra due run successivi. |
| `TriageScore::clean() -> TriageScore` | — | `TriageScore` | Preset: file pulito. |
| `TriageScore::upx_packed() -> TriageScore` | — | `TriageScore` | Preset: packing UPX rilevato. |
| `TriageScore::vmprotect() -> TriageScore` | — | `TriageScore` | Preset: protezione VMProtect rilevata. |
| `TriageScore::high_entropy(entropy) -> TriageScore` | entropia | `TriageScore` | Preset: alta entropia. |
| `TriageScore::yara_matches(count, max_severity) -> TriageScore` | conteggio + severità | `TriageScore` | Preset: match YARA. |
| `TriageScore::suspicious_imports(suspicious, total) -> TriageScore` | conteggi | `TriageScore` | Preset: import table sospetta. |
| `filter_scores(scores, min_raw) -> Vec<&TriageScore>` | score + soglia | `Vec<&TriageScore>` | Filtra gli score sotto la soglia. |
| `dedup_scores(scores) -> Vec<TriageScore>` | score | `Vec<TriageScore>` | Deduplicazione per categoria. |
| `ScoreCard::from_aggregated(a) -> Self` | `AggregatedScore` | `ScoreCard` | Crea una scorecard da un risultato aggregato. |
| `ScoreCard::to_json(&self) -> serde_json::Result<String>` | — | `Result<String, …>` | Serializza la scorecard. |
| `ScoreCard::to_text(&self) -> String` | — | `String` | Rendering testuale della scorecard. |

### `heuristic_engine.rs` — motore euristico

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `HeuristicResult::fired(id, name, threat, evidence) -> Self` | parametri | `HeuristicResult` | Crea un risultato per una regola che ha scattato. |
| `HeuristicResult::clean(id) -> Self` | id | `HeuristicResult` | Risultato per una regola che non ha trovato nulla. |
| `HeuristicReport::from_results(all: Vec<HeuristicResult>) -> Self` | risultati | `HeuristicReport` | Aggrega i risultati in un report. |
| `HeuristicReport::grouped_by_level(&self) -> HashMap<…>` | — | `HashMap<String, Vec<&HeuristicResult>>` | Raggruppa i risultati per livello di minaccia. |
| `HeuristicReport::summary(&self) -> String` | — | `String` | Sommario testuale del report euristico. |
| `HeuristicEngine::empty() -> Self` | — | `HeuristicEngine` | Motore senza regole. |
| `HeuristicEngine::with_defaults() -> Self` | — | `HeuristicEngine` | Motore con tutte le regole predefinite (packing, anti-debug, rete, cripto, shellcode, ecc.). |
| `HeuristicEngine::add(&mut self, h: Box<dyn Heuristic>)` | regola | `()` | Aggiunge una regola personalizzata. |
| `HeuristicEngine::check_count(&self) -> usize` | — | `usize` | Numero di regole registrate. |
| `HeuristicEngine::run(&self, bytes) -> HeuristicReport` | byte | `HeuristicReport` | Esegue tutte le regole e produce il report. |
| `HeuristicEngine::run_category(&self, prefix, bytes) -> HeuristicReport` | prefisso + byte | `HeuristicReport` | Esegue solo le regole il cui ID inizia con `prefix`. |
| `HeuristicEngine::check_ids(&self) -> Vec<&str>` | — | `Vec<&str>` | Lista degli ID di tutte le regole registrate. |

### `analyzer_registry.rs` — registro analizzatori

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `AnalysisResult::ok(analyzer, score) -> Self` | nome + score | `AnalysisResult` | Risultato di successo. |
| `AnalysisResult::err(analyzer, msg) -> Self` | nome + messaggio | `AnalysisResult` | Risultato di errore. |
| `AnalysisResult::add_indicator(&mut self, ind)` | indicatore | `()` | Aggiunge un indicatore al risultato. |
| `AnalysisResult::with_meta(self, key, val) -> Self` | chiave + valore | `Self` | Aggiunge metadati al risultato (builder). |
| `AnalysisResult::is_high_risk(&self) -> bool` | — | `bool` | Vero se lo score supera la soglia di alto rischio. |
| `AnalyzerRegistry::new() -> Self` | — | `AnalyzerRegistry` | Registro vuoto. |
| `AnalyzerRegistry::register(&mut self, a: Box<dyn TriageAnalyzer>)` | analizzatore | `()` | Registra un analizzatore. |
| `AnalyzerRegistry::len(&self) -> usize` | — | `usize` | Numero di analizzatori registrati. |
| `AnalyzerRegistry::is_empty(&self) -> bool` | — | `bool` | Vero se il registro è vuoto. |
| `AnalyzerRegistry::names(&self) -> Vec<&str>` | — | `Vec<&str>` | Nomi degli analizzatori registrati. |
| `AnalyzerRegistry::run_all(&self, bytes) -> Vec<AnalysisResult>` | byte | `Vec<AnalysisResult>` | Esegue tutti gli analizzatori. |
| `AnalyzerRegistry::run_fast(&self, bytes) -> Vec<AnalysisResult>` | byte | `Vec<AnalysisResult>` | Esegue solo gli analizzatori marcati "fast". |
| `AnalyzerRegistry::run_deep(&self, bytes) -> Vec<AnalysisResult>` | byte | `Vec<AnalysisResult>` | Esegue solo gli analizzatori marcati "deep". |
| `AnalyzerRegistry::run_tagged(&self, bytes, tags) -> Vec<AnalysisResult>` | byte + tag | `Vec<AnalysisResult>` | Esegue gli analizzatori che corrispondono ai tag specificati. |
| `AnalyzerRegistry::run_and_aggregate(&self, bytes) -> RegistryRunResult` | byte | `RegistryRunResult` | Esegue tutti e aggrega in un unico risultato. |
| `AnalyzerRegistry::aggregate_results(&self, results) -> RegistryRunResult` | risultati | `RegistryRunResult` | Aggrega risultati già calcolati. |
| `RegistryRunResult::is_malicious(&self) -> bool` | — | `bool` | Vero se il risultato aggregato è malevolo. |
| `RegistryRunResult::is_clean(&self) -> bool` | — | `bool` | Vero se il file sembra pulito. |
| `RegistryRunResult::summary(&self) -> String` | — | `String` | Riassunto testuale. |
| `RegistryRunResult::by_analyzer(&self, name) -> Option<&AnalysisResult>` | nome | `Option<&AnalysisResult>` | Risultato di un singolo analizzatore. |
| `default_registry() -> AnalyzerRegistry` | — | `AnalyzerRegistry` | Registro pre-popolato con gli analizzatori built-in. |

### `malware_classification.rs` — classificazione famiglie

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `Family::name(&self) -> String` | — | `String` | Nome leggibile della famiglia malware. |
| `ClassificationResult::new(family, confidence) -> Self` | famiglia + confidenza | `ClassificationResult` | Risultato di classificazione primario. |
| `ClassificationResult::top_alternative(&self) -> Option<(&Family, u8)>` | — | `Option<…>` | Famiglia alternativa con confidenza maggiore. |
| `FuzzyHash::compute(data: &[u8]) -> String` | byte | `String` | Calcola un fuzzy hash del binario. |
| `FuzzyHash::similarity(a, b) -> u8` | due hash | `u8` (0–100) | Similarità tra due fuzzy hash. |
| `ImpHash::compute(imports: &[(String, String)]) -> String` | coppie DLL/funzione | `String` | Calcola l'import hash. |
| `StringHash::from_string(s) -> String` | stringa | `String` | Hash di una stringa. |
| `StringHash::equal(a, b) -> bool` | due hash | `bool` | Confronto esatto di hash. |
| `FamilyDatabase::new() -> Self` | — | `FamilyDatabase` | Database vuoto. |
| `FamilyDatabase::add_imphash(&mut self, hash, family, confidence)` | hash + famiglia | `()` | Aggiunge un imphash noto. |
| `FamilyDatabase::add_fuzzy(&mut self, hash, family, confidence)` | hash + famiglia | `()` | Aggiunge un fuzzy hash noto. |
| `FamilyDatabase::add_string_hash(&mut self, hash, family, confidence)` | hash + famiglia | `()` | Aggiunge un string hash noto. |
| `FamilyDatabase::add_name(&mut self, name, family)` | nome + famiglia | `()` | Aggiunge un nome noto di famiglia. |
| `FamilyDatabase::lookup_imphash(&self, hash) -> Option<(&Family, u8)>` | hash | `Option<…>` | Cerca per imphash. |
| `FamilyDatabase::lookup_name(&self, name) -> Option<&Family>` | nome | `Option<…>` | Cerca per nome. |
| `FamilyDatabase::lookup_fuzzy(&self, hash, min_similarity) -> Option<(&Family, u8)>` | hash + soglia | `Option<…>` | Cerca per fuzzy hash con soglia di similarità. |
| `MalwareClassifier::new() -> Self` | — | `MalwareClassifier` | Classificatore con database vuoto. |
| `MalwareClassifier::classify(&self, data, …) -> ClassificationResult` | byte + metadati | `ClassificationResult` | Classifica il binario combinando imphash, fuzzy hash e string hash. |
| `MalwareClassifier::classify_by_imphash(&self, imphash) -> Option<ClassificationResult>` | imphash | `Option<…>` | Classificazione basata solo sull'imphash. |
| `MalwareClassifier::database_size(&self) -> usize` | — | `usize` | Numero di entry nel database. |

### `mitre_mapper.rs` — mapping MITRE ATT&CK

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `MitreTechnique::new(id, name, tactic) -> Self` | id + nome + tattica | `MitreTechnique` | Crea una tecnica ATT&CK. |
| `MitreTechnique::with_sub(self, sub) -> Self` | sub-tecnica | `Self` | Aggiunge una sub-tecnica (builder). |
| `TechniqueMatch::new(technique, indicator, confidence) -> Self` | tecnica + indicatore + confidenza | `TechniqueMatch` | Crea un match tra indicatore e tecnica. |
| `TechniqueMatch::with_evidence(self, ev) -> Self` | evidenza | `Self` | Aggiunge evidenza al match (builder). |
| `AttackMatrix::new() -> Self` | — | `AttackMatrix` | Matrice ATT&CK vuota. |
| `AttackMatrix::add(&mut self, m: TechniqueMatch)` | match | `()` | Aggiunge un match alla matrice. |
| `AttackMatrix::tactics(&self) -> Vec<&str>` | — | `Vec<&str>` | Lista delle tattiche presenti nella matrice. |
| `AttackMatrix::techniques_for_tactic(&self, tactic) -> Vec<&TechniqueMatch>` | tattica | `Vec<&TechniqueMatch>` | Match per una tattica specifica. |
| `AttackMatrix::top_match(&self) -> Option<&TechniqueMatch>` | — | `Option<&TechniqueMatch>` | Match con confidenza più alta. |
| `AttackMatrix::summary(&self) -> String` | — | `String` | Sommario testuale della matrice. |
| `AttackMatrix::to_json(&self) -> serde_json::Result<String>` | — | `Result<String, …>` | Serializzazione JSON. |
| `MitreMapper::new() -> Self` | — | `MitreMapper` | Mapper con regole built-in. |
| `MitreMapper::build_attack_matrix(&self, result: &TriageResult) -> AttackMatrix` | risultato triage | `AttackMatrix` | Costruisce la matrice ATT&CK dagli indicatori del risultato. |
| `MitreMapper::build_from_strings(&self, indicators: &[&str]) -> AttackMatrix` | slice di stringhe | `AttackMatrix` | Costruisce la matrice da nomi di indicatori testuali. |
| `MitreMapper::lookup_technique(&self, id) -> Option<&MitreTechnique>` | id tecnica | `Option<…>` | Cerca una tecnica per ID. |
| `MitreMapper::technique_ids(&self) -> Vec<&str>` | — | `Vec<&str>` | Lista degli ID di tutte le tecniche. |

### `pe_triage_extended.rs` — analisi PE estesa

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `PeFeatures::from_bytes(data: &[u8]) -> Self` | byte PE | `PeFeatures` | Estrae feature PE: sezioni, import, risorse, TLS, overlay, entropia. |
| `PeFeatures::normalised_import_risk(&self) -> f64` | — | `f64` | Rischio normalizzato basato sulle import sospette. |
| `PeFeatures::looks_packed(&self) -> bool` | — | `bool` | Vero se le feature suggeriscono packing (alta entropia, poche sezioni, ecc.). |
| `detect_anomalies(data, features) -> Vec<PeAnomaly>` | byte + feature | `Vec<PeAnomaly>` | Rileva anomalie PE: header malformati, overlay, risorse sospette. |
| `SectionFeatures::from_bytes(data: &[u8]) -> Self` | byte PE | `SectionFeatures` | Estrae dati per ogni sezione (nome, entropia, flags, VA). |
| `detect_section_anomalies(features) -> Vec<SectionAnomaly>` | `PeFeatures` | `Vec<SectionAnomaly>` | Rileva anomalie nelle sezioni (nomi insoliti, sezioni eseguibili/scrivibili, alta entropia). |
| `PeTriageReport::from_bytes(data: &[u8]) -> Self` | byte PE | `PeTriageReport` | Costruisce un report PE completo (feature + anomalie + indicatori). |
| `PeTriageReport::analyze(data: &[u8]) -> PeTriageReport` | byte PE | `PeTriageReport` | Alias funzionale per `from_bytes`. |

### `static_analysis_triage.rs` — analisi statica pesata

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `StaticFeature::description(&self) -> String` | — | `String` | Descrizione testuale della feature rilevata. |
| `FeatureWeight::new(feature, weight, evidence) -> Self` | feature + peso + evidenza | `FeatureWeight` | Feature con peso e evidenza. |
| `FeatureWeight::effective_weight(&self) -> u32` | — | `u32` | Peso effettivo considerando il livello della feature. |
| `StaticScore::new(raw: u32) -> Self` | score grezzo | `StaticScore` | Wrappa uno score raw con classificazione. |
| `StaticTriageReport::to_json(&self) -> Result<String, String>` | — | `Result<String, …>` | Serializzazione JSON del report statico. |
| `StaticTriageReport::summary(&self) -> String` | — | `String` | Sommario testuale del report statico. |
| `StringFeatureAnalyzer::analyze(&self, data) -> Vec<FeatureWeight>` | byte | `Vec<FeatureWeight>` | Analizza le stringhe del binario e produce feature pesate. |
| `BinaryFeatureAnalyzer::analyze(&self, data) -> Vec<FeatureWeight>` | byte | `Vec<FeatureWeight>` | Analizza i byte grezzi (entropia, magic, packer) e produce feature pesate. |
| `StaticTriageEngine::new() -> Self` | — | `StaticTriageEngine` | Motore con analizzatori di default. |
| `StaticTriageEngine::triage(&self, data) -> StaticTriageReport` | byte | `StaticTriageReport` | Analisi completa: feature + score + classificazione. |
| `StaticTriageEngine::quick_triage(&self, data) -> StaticTriageReport` | byte | `StaticTriageReport` | Versione rapida (subset di feature). |
| `StaticTriageEngine::batch_triage<'a>(&self, inputs) -> Vec<StaticTriageReport>` | iteratore di slice | `Vec<StaticTriageReport>` | Analisi batch su più binari. |
| `StaticTriageEngine::classify_features(&self, features) -> StaticTriageReport` | feature pre-calcolate | `StaticTriageReport` | Classificazione da feature già estratte. |

### `findcrypt.rs` — riconoscimento costanti crittografiche

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `scan(buf: &[u8]) -> Vec<CryptoHit>` | byte grezzi | `Vec<CryptoHit>` | Scansiona il buffer alla ricerca di costanti crittografiche note (AES S-box, SHA, MD5, RC4, ecc.). |

### `family_db.rs` — database famiglie malware

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `FamilyDb::new() -> Self` | — | `FamilyDb` | Database con entry built-in. |
| `FamilyDb::get(&self, name) -> Option<&FamilyEntry>` | nome famiglia | `Option<&FamilyEntry>` | Ricerca per nome esatto. |
| `FamilyDb::all(&self) -> &[FamilyEntry]` | — | `&[FamilyEntry]` | Tutte le entry del database. |
| `FamilyDb::by_category(&self, cat) -> Vec<&FamilyEntry>` | categoria | `Vec<&FamilyEntry>` | Entry filtrate per categoria. |
| `FamilyDb::match_iocs<'a>(&'a self, haystack) -> Vec<(&'a FamilyEntry, Vec<&'a Ioc>)>` | byte | `Vec<(…)>` | Cerca IoC di tutte le famiglie nel buffer. |
| `FamilyDb::match_apis<'a>(&'a self, apis) -> Vec<(&'a FamilyEntry, Vec<&'static str>)>` | lista API | `Vec<(…)>` | Abbina le API importate alle famiglie note. |
| `FamilyDb::top_n(&self, n) -> Vec<&FamilyEntry>` | n | `Vec<&FamilyEntry>` | Le n famiglie con priorità più alta. |

### `rapid_classifier.rs` — classificazione rapida

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `RapidClassifier::classify(&self, data) -> ClassificationResult` | byte | `ClassificationResult` | Classificazione rapida basata su magic bytes, entropia e pattern di stringhe. |
| `import_family_similarity(data: &[u8]) -> Vec<(&'static str, f32)>` | byte PE | `Vec<(&str, f32)>` | Calcola la similarità dell'import table con famiglie malware note. |

### `file_classifier.rs` — classificatore file

| Firma | Input | Output | Descrizione |
|---|---|---|---|
| `FileClassification::new(…) -> Self` | parametri | `FileClassification` | Costruisce una classificazione con tutti i metadati. |
| `FileClassification::is_high_risk(&self) -> bool` | — | `bool` | Vero se il file è ad alto rischio. |
| `FileClassification::summary_line(&self) -> String` | — | `String` | Riassunto su una riga. |
| `FileClassifier::new() -> Self` | — | `FileClassifier` | Classificatore con regole di default. |
| `FileClassifier::classify(&self, data, …) -> FileClassification` | byte + metadati | `FileClassification` | Classifica il file considerando tipo, entropia, dimensione e firma. |

---

## Tipi chiave

| Tipo | Descrizione |
|---|---|
| `FileKind` | Enum formato file: Pe32, Pe64, Elf32, Elf64, MachO, Apk, Dex, Zip, Pdf, Doc, Unknown |
| `ThreatLevel` | Enum severità: Clean < Informational < Low < Medium < High < Critical |
| `TriageIndicator` | Singolo indicatore con nome, descrizione, livello, categoria, evidenza |
| `TriageResult` | Risultato aggregato con score, hash, entropia, stringhe, crypto_hits |
| `TriageReport` | Report JSON-serializzabile (layout piatto per il consumatore MCP) |
| `TriageReport2` | Report strutturato con sezioni per il rendering multi-formato |
| `ExtractedString` | Stringa estratta con offset, encoding (ASCII/UTF16LE/UTF16BE), VA opzionale |
| `SuspiciousString` | Stringa categorizzata con livello di minaccia |
| `PipelineRunResult` | Output completo di una pipeline run: risultato + output per stadio |
| `AttackMatrix` | Mapping indicatori → tecniche MITRE ATT&CK con tattiche raggruppate |
| `AggregatedScore` | Score aggregato ponderato con classificazione Clean/Suspicious/Malicious |
| `TriageError` | Errori: TooSmall, Pe(PeError), Io(io::Error), Other(String) |
