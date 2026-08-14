# rustre-forensics

**Versione:** 0.1.0  
**Edizione:** Rust 2024  
**Dipendenze:** `thiserror`, `serde`, `serde_json`, `rustre-sysinternals`

Libreria di digital forensics e incident response per il progetto RustRE. Fornisce strumenti per acquisizione memoria, analisi dump, carving filesystem, parsing di artefatti Windows (prefetch, registry hive), gestione prove digitali con chain-of-custody, correlazione temporale di eventi e analisi malware.

---

## Totale funzioni pubbliche: 489

Le funzioni sono distribuite su 15 sorgenti principali.

---

## lib.rs (123 funzioni pubbliche)

Contiene i tipi fondamentali condivisi: `MemoryDump`, `ProcessList`, `NetworkConnections`, `PluginRegistry`, `EvidenceHash`, `EvidenceRecord`, `TimelineEvent`, `Timeline`, e le funzioni di hashing.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `MemoryDump::from_file(path, arch, os)` | `&Path`, `ArchBits`, `OsType` | `Result<Self, ForensicsError>` | Carica un dump di memoria da file rilevando automaticamente il formato (LiME, ELF core, Windows crash dump, hiberfil) |
| `MemoryDump::as_bytes()` | `&self` | `&[u8]` | Ritorna il contenuto grezzo del dump |
| `ProcessList::from_bytes(data)` | `&[u8]` | `Result<Self, ForensicsError>` | Decodifica una lista di processi da dati binari |
| `NetworkConnections::from_bytes(data)` | `&[u8]` | `Result<Self, ForensicsError>` | Decodifica connessioni di rete da dati binari |
| `PluginRegistry::new()` | - | `Self` | Crea un registry vuoto per plugin forensici |
| `PluginRegistry::register(plugin)` | `Box<dyn ForensicsPlugin>` | `()` | Registra un plugin nel registry |
| `PluginRegistry::get(name)` | `&str` | `Option<&dyn ForensicsPlugin>` | Recupera un plugin per nome |
| `PluginRegistry::names()` | `&self` | `Vec<&str>` | Elenca i nomi dei plugin registrati |
| `PluginRegistry::run(name, ctx)` | `&str`, `PluginContext` | `Result<PluginOutput>` | Esegue un plugin per nome con contesto dato |
| `EvidenceHash::compute(data, algorithm)` | `&[u8]`, `HashAlgorithm` | `Self` | Calcola un hash dell'evidence con algoritmo specificato (MD5/SHA1/SHA256/SHA512) |
| `EvidenceHash::verify(data)` | `&[u8]` | `Result<(), ForensicsError>` | Verifica che i dati corrispondano all'hash memorizzato |
| `EvidenceRecord::new(...)` | id, path, ts, etype | `Self` | Crea un record di evidence con metadati |
| `EvidenceRecord::add_hash(hash)` | `EvidenceHash` | `()` | Aggiunge un hash al record |
| `EvidenceRecord::add_custody(ts, actor, action, notes)` | `u64`, `String`, `String`, `Option<String>` | `()` | Aggiunge una voce alla chain of custody |
| `EvidenceRecord::add_tag(tag)` | `impl Into<String>` | `()` | Aggiunge un tag classificatorio al record |
| `EvidenceRecord::verify(data)` | `&[u8]` | `Result<(), ForensicsError>` | Verifica l'integrità dell'evidence tramite hash |
| `TimelineEvent::new(ts, actor, artifact)` | `u64`, `String`, `String` | `Self` | Crea un evento timeline con timestamp in ms |
| `TimelineEvent::with_artifact(artifact)` | `impl Into<String>` | `Self` | Builder: imposta l'artefatto associato |
| `TimelineEvent::with_actor(actor)` | `impl Into<String>` | `Self` | Builder: imposta l'attore dell'evento |
| `Timeline::new()` | - | `Self` | Crea una timeline vuota |
| `Timeline::add_event(event)` | `TimelineEvent` | `()` | Aggiunge un evento alla timeline |
| `Timeline::sort()` | `&mut self` | `()` | Ordina gli eventi per timestamp crescente |
| `Timeline::events_in_range(start, end)` | `u64`, `u64` | `Vec<&TimelineEvent>` | Filtra eventi nel range temporale specificato (ms) |
| `Timeline::events_by_type(et)` | `&TimelineEventType` | `Vec<&TimelineEvent>` | Filtra eventi per tipo |
| `compute_md5(data)` | `&[u8]` | `String` | Calcola MD5 e restituisce stringa esadecimale |
| `compute_sha1(data)` | `&[u8]` | `String` | Calcola SHA-1 e restituisce stringa esadecimale |
| `compute_sha256(data)` | `&[u8]` | `String` | Calcola SHA-256 e restituisce stringa esadecimale |
| `compute_sha512(data)` | `&[u8]` | `String` | Calcola SHA-512 e restituisce stringa esadecimale |
| Vari tipi helper (`PluginContext`, `TabularData`, `ForensicRow`) | - | - | Strutture di supporto con `new`, `set`, `get`, `add_row`, `to_csv` |

---

## artifact_extractor.rs (13 funzioni pubbliche)

Estrazione di artefatti forensici da buffer di memoria raw.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ExtractionResult::merge(other)` | `Self` | `()` | Unisce due risultati di estrazione in uno |
| `carve_urls_from_memory(mem)` | `&[u8]` | `Vec<String>` | Scansiona la memoria alla ricerca di URL (http/https) tramite pattern matching |
| `extract_chromium_history(mem, profile)` | `&[u8]`, `Option<&str>` | `Vec<BrowserHistoryEntry>` | Estrae la cronologia Chromium da dump di memoria, opzionalmente filtrando per profilo |
| `extract_firefox_history(mem, profile)` | `&[u8]`, `Option<&str>` | `Vec<BrowserHistoryEntry>` | Estrae la cronologia Firefox da dump di memoria |
| `extract_ntlm_hashes(mem)` | `&[u8]` | `Vec<CredentialEntry>` | Ricerca pattern di hash NTLM nella memoria (strutture LM/NT) |
| `extract_ssh_private_keys(mem)` | `&[u8]` | `Vec<CredentialEntry>` | Individua chiavi private SSH (PEM header) nella memoria |
| `extract_clipboard_text(mem)` | `&[u8]` | `Vec<ClipboardEntry>` | Estrae testo dalla memoria degli appunti di sistema |
| `extract_typed_urls(mem)` | `&[u8]` | `Vec<TypedUrl>` | Estrae URL digitati dalla memoria (chiave TypedURLs di IE/Edge) |
| `extract_mft_entries(mem)` | `&[u8]` | `Vec<MftEntry>` | Individua e decodifica record MFT (Master File Table NTFS) dalla memoria |
| `extract_thumbnails(mem)` | `&[u8]` | `Vec<ThumbnailEntry>` | Estrae miniature di immagini dalla memoria |
| `ArtifactExtractor::extract(mem)` | `&[u8]` | `ExtractionResult` | Esegue tutti gli estrattori configurati su un buffer continuo |
| `ArtifactExtractor::extract_chunks(chunks)` | `&[(&[u8], u64)]` | `ExtractionResult` | Estrae da segmenti non contigui (slice + offset fisico) |
| `ArtifactExtractor::extract_window(mem, offset, len)` | `&[u8]`, `u64`, `usize` | `ExtractionResult` | Estrae da una finestra specifica del buffer |

---

## artifact_store.rs (31 funzioni pubbliche)

Storage thread-safe di artefatti forensici con indice e query.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ForensicArtifact::new(...)` | id, atype, source, ts, confidence | `Self` | Crea un artefatto con tipo, sorgente, timestamp e livello di confidenza |
| `ForensicArtifact::with_data(data)` | `Vec<u8>` | `Self` | Builder: allega dati binari raw all'artefatto |
| `ForensicArtifact::set_data(data)` | `Vec<u8>` | `()` | Imposta i dati binari dell'artefatto |
| `ForensicArtifact::add_meta(key, value)` | `String`, `String` | `()` | Aggiunge una coppia chiave-valore ai metadati |
| `ForensicArtifact::get_meta(key)` | `&str` | `Option<&str>` | Legge un metadato per chiave |
| `ForensicArtifact::add_tag(tag)` | `String` | `()` | Aggiunge un tag classificatorio |
| `ForensicArtifact::add_technique(id)` | `String` | `()` | Aggiunge un ID tecnica MITRE ATT&CK |
| `ForensicArtifact::is_high_confidence()` | `&self` | `bool` | Ritorna `true` se confidenza >= soglia predefinita |
| `ForensicArtifact::sha256_hex()` | `&self` | `Option<&str>` | Restituisce SHA-256 dei dati allegati se presenti |
| `ArtifactBuilder::tag(tag)` | `String` | `Self` | Builder: aggiunge tag |
| `ArtifactBuilder::technique(id)` | `String` | `Self` | Builder: aggiunge tecnica MITRE |
| `ArtifactQuery::new()` | - | `Self` | Crea una query vuota (match-all) |
| `ArtifactQuery::of_type(t)` | `ArtifactType` | `Self` | Filtra per tipo artefatto |
| `ArtifactQuery::from_source(s)` | `String` | `Self` | Filtra per sorgente |
| `ArtifactQuery::with_tag(tag)` | `String` | `Self` | Filtra per tag |
| `ArtifactQuery::with_technique(id)` | `String` | `Self` | Filtra per tecnica MITRE |
| `ArtifactStore::new(name)` | `String` | `Self` | Crea uno store con nome identificativo |
| `ArtifactStore::store(artifact)` | `ForensicArtifact` | `Result<String, ArtifactStoreError>` | Salva un artefatto e ritorna il suo ID; errore se duplicato |
| `ArtifactStore::upsert(artifact)` | `ForensicArtifact` | `String` | Salva o aggiorna un artefatto, ritorna ID |
| `ArtifactStore::remove(id)` | `&str` | `Result<ForensicArtifact, ArtifactStoreError>` | Rimuove e ritorna l'artefatto per ID |
| `ArtifactStore::verify(id)` | `&str` | `Result<(), ArtifactStoreError>` | Verifica l'integrità dell'artefatto tramite hash SHA-256 |
| `ArtifactStore::get(id)` | `&str` | `Option<ForensicArtifact>` | Recupera una copia dell'artefatto per ID |
| `ArtifactStore::query(q)` | `&ArtifactQuery` | `Vec<ForensicArtifact>` | Interroga lo store con filtri multipli |
| `ArtifactStore::by_type()` | `&self` | `HashMap<String, Vec<ForensicArtifact>>` | Raggruppa tutti gli artefatti per tipo |
| `ArtifactStore::type_counts()` | `&self` | `HashMap<String, usize>` | Conteggio artefatti per tipo |
| `ArtifactStore::high_confidence(threshold)` | `f32` | `Vec<ForensicArtifact>` | Ritorna artefatti con confidenza sopra soglia |
| `ArtifactStore::count()` | `&self` | `usize` | Numero totale di artefatti nello store |
| `ArtifactStore::is_empty()` | `&self` | `bool` | Vero se lo store non contiene artefatti |
| `ArtifactStore::avg_confidence()` | `&self` | `f32` | Media dei livelli di confidenza |
| `ArtifactStore::export(format, path)` | `ExportFormat`, `&Path` | `Result<()>` | Esporta lo store in JSON/CSV su file |
| `ArtifactStore::clear()` | `&self` | `()` | Rimuove tutti gli artefatti dallo store |

---

## collection_engine.rs (16 funzioni pubbliche)

Engine plug-in per orchestrare job di raccolta forense.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `CollectionJob::new(id, plugins)` | `String`, `Vec<String>` | `Self` | Crea un job di raccolta specificando ID e plugin da eseguire |
| `CollectionJob::all_plugins(id)` | `String` | `Self` | Crea un job che esegue tutti i plugin registrati |
| `CollectionJob::with_arg(key, value)` | `String`, `String` | `Self` | Builder: aggiunge un argomento al job |
| `CollectionJob::for_case(case_id)` | `String` | `Self` | Builder: associa il job a un case ID |
| `JobStatus::start()` | `&mut self` | `()` | Transizione di stato: imposta il job come in esecuzione |
| `JobStatus::complete(artifacts)` | `usize` | `()` | Transizione di stato: segna completato con conteggio artefatti |
| `JobStatus::fail(reason)` | `String` | `()` | Transizione di stato: segna fallito con motivazione |
| `CollectionEngine::new(store)` | `Arc<ArtifactStore>` | `Self` | Crea l'engine collegato a uno store |
| `CollectionEngine::register_plugin(plugin)` | `Arc<dyn ForensicsPlugin>` | `()` | Registra un plugin nell'engine |
| `CollectionEngine::plugin_names()` | `&self` | `Vec<String>` | Elenca i nomi dei plugin registrati |
| `CollectionEngine::plugin_count()` | `&self` | `usize` | Numero di plugin registrati |
| `CollectionEngine::submit_job(job)` | `CollectionJob` | `String` | Accoda un job e ritorna il suo ID |
| `CollectionEngine::job_status(id)` | `&str` | `Option<JobStatus>` | Recupera lo stato corrente di un job |
| `CollectionEngine::run_job(job, ctx)` | `CollectionJob`, `PluginContext` | `Result<Vec<ForensicArtifact>>` | Esegue un job in modo sincrono e ritorna gli artefatti raccolti |
| `CollectionEngine::run_isolated(plugin_name, ctx)` | `&str`, `PluginContext` | `Result<Vec<ForensicArtifact>>` | Esegue un singolo plugin in isolamento |
| `CollectionEngine::stats()` | `&self` | `EngineStats` | Statistiche aggregate sull'engine (job eseguiti, artefatti, errori) |

---

## evidence_collector.rs (43 funzioni pubbliche)

Raccolta, hash e chain-of-custody di prove digitali.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `Evidence::new(id, etype, path, analyst)` | `String`, `EvidenceType`, `String`, `String` | `Self` | Crea un'evidence con metadati iniziali |
| `Evidence::from_bytes(id, etype, data, analyst)` | `String`, `EvidenceType`, `Vec<u8>`, `String` | `Self` | Crea evidence da dati binari calcolando automaticamente gli hash |
| `Evidence::from_hashes(id, etype, md5, sha1, sha256)` | id, etype, `String`x3 | `Self` | Crea evidence da hash già noti (senza dati raw) |
| `Evidence::verify(data)` | `&[u8]` | `bool` | Verifica che i dati corrispondano agli hash memorizzati |
| `Evidence::tag(t)` | `String` | `()` | Aggiunge un tag |
| `Evidence::set_meta(key, value)` | `String`, `String` | `()` | Imposta un metadato key-value |
| `Evidence::summary()` | `&self` | `String` | Stringa leggibile con id, tipo, hash principali |
| `ChainOfCustodyEntry::new(ts, actor, action)` | `u64`, `String`, `String` | `Self` | Crea una voce della catena di custodia |
| `ChainOfCustodyEntry::with_hash(hash)` | `String` | `Self` | Builder: aggiunge hash di verifica |
| `ChainOfCustodyEntry::with_notes(notes)` | `String` | `Self` | Builder: aggiunge note descrittive |
| `ChainOfCustodyEntry::with_location(loc)` | `String` | `Self` | Builder: aggiunge posizione fisica/logica |
| `ChainOfCustody::new(evidence_id)` | `String` | `Self` | Crea una catena di custodia per un'evidence |
| `ChainOfCustody::add(entry)` | `ChainOfCustodyEntry` | `()` | Aggiunge una voce alla catena |
| `ChainOfCustody::is_unbroken()` | `&self` | `bool` | Verifica che la catena non abbia interruzioni temporali |
| `ChainOfCustody::latest()` | `&self` | `Option<&ChainOfCustodyEntry>` | Restituisce l'ultima voce della catena |
| `ChainOfCustody::to_log()` | `&self` | `String` | Genera un log testuale della catena |
| `EvidenceChain::new(evidence)` | `Evidence` | `Self` | Crea una catena (evidence + custody) |
| `EvidenceChain::log_action(ts, actor, action)` | `u64`, `String`, `String` | `()` | Registra un'azione nella chain of custody |
| `EvidenceChain::is_intact()` | `&self` | `bool` | Verifica che l'evidence non sia stata alterata e la catena sia integra |
| `EvidenceDatabase::new()` | - | `Self` | Crea un database evidence vuoto |
| `EvidenceDatabase::insert(chain)` | `EvidenceChain` | `()` | Inserisce una catena nel database |
| `EvidenceDatabase::get(id)` | `&str` | `Option<&EvidenceChain>` | Recupera una catena per ID |
| `EvidenceDatabase::get_mut(id)` | `&str` | `Option<&mut EvidenceChain>` | Recupera una catena mutabile per ID |
| `EvidenceDatabase::remove(id)` | `&str` | `Option<EvidenceChain>` | Rimuove e ritorna una catena per ID |
| `EvidenceDatabase::len()` | `&self` | `usize` | Numero di catene nel database |
| `EvidenceDatabase::is_empty()` | `&self` | `bool` | Vero se il database non contiene evidence |
| `EvidenceDatabase::all()` | `&self` | `Vec<&EvidenceChain>` | Lista di tutte le catene |
| `EvidenceDatabase::find_by_sha256(sha256)` | `&str` | `Option<&EvidenceChain>` | Cerca per hash SHA-256 |
| `EvidenceDatabase::by_type(et)` | `&EvidenceType` | `Vec<&EvidenceChain>` | Filtra per tipo di evidence |
| `EvidenceDatabase::high_confidence(threshold)` | `u8` | `Vec<&EvidenceChain>` | Filtra per confidenza sopra soglia |
| `EvidenceDatabase::verified()` | `&self` | `Vec<&EvidenceChain>` | Ritorna solo le catene verificate |
| `EvidenceCollector::new(analyst)` | `String` | `Self` | Crea un collettore con nome analista |
| `EvidenceCollector::next_id()` | `&mut self` | `String` | Genera un ID univoco progressivo per la prossima evidence |
| `EvidenceCollector::collect_bytes(etype, data, path)` | `EvidenceType`, `Vec<u8>`, `String` | `String` | Raccoglie evidence da byte, calcola hash, ritorna ID assegnato |
| `EvidenceCollector::collect_hashes(etype, md5, sha1, sha256, path)` | ... | `String` | Raccoglie evidence da hash già noti |
| `EvidenceCollector::verify(id, data)` | `&str`, `&[u8]` | `bool` | Verifica integrità di un'evidence per ID |
| `EvidenceCollector::log_transfer(id, ts_ms, recipient)` | `&str`, `u64`, `String` | `()` | Registra un trasferimento di custody |
| `EvidenceCollector::mark_verified(id)` | `&str` | `()` | Marca un'evidence come verificata |
| `EvidenceCollector::count()` | `&self` | `usize` | Numero di evidence raccolte |
| `EvidenceReporter::to_json(db)` | `&EvidenceDatabase` | `String` | Serializza il database in JSON |
| `EvidenceReporter::to_csv(db)` | `&EvidenceDatabase` | `String` | Esporta il database in CSV |
| `EvidenceReporter::chain_log(chain)` | `&EvidenceChain` | `String` | Genera log testuale per una singola catena |
| `EvidenceReporter::dfir_summary(db, case_id)` | `&EvidenceDatabase`, `&str` | `String` | Genera un report DFIR completo con statistiche per case ID |

---

## filesystem_carver.rs (28 funzioni pubbliche)

Carving di file da immagini disco raw tramite magic bytes.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `CarvingRule::new(magic, ext, max_size)` | `Vec<u8>`, `String`, `u64` | `Self` | Definisce una regola di carving con magic number, estensione e dimensione massima |
| `CarvingRule::jpeg()` | - | `Self` | Regola predefinita per file JPEG (FF D8 FF) |
| `CarvingRule::png()` | - | `Self` | Regola predefinita per PNG (89 50 4E 47) |
| `CarvingRule::pdf()` | - | `Self` | Regola predefinita per PDF (%PDF-) |
| `CarvingRule::zip()` | - | `Self` | Regola predefinita per ZIP (PK\x03\x04) |
| `CarvingRule::pe()` | - | `Self` | Regola predefinita per PE (MZ) |
| `CarvingRule::elf()` | - | `Self` | Regola predefinita per ELF (7F 45 4C 46) |
| `CarvingRule::gif()` | - | `Self` | Regola predefinita per GIF (GIF8) |
| `CarvingRule::sqlite()` | - | `Self` | Regola predefinita per SQLite (SQLite format 3) |
| `CarvedFile::suggested_filename()` | `&self` | `String` | Suggerisce un nome file basato su offset ed estensione |
| `CarvedFile::save(dir)` | `&Path` | `Result<PathBuf, ForensicsError>` | Salva il file estratto in una directory |
| `CarvingStats::record(file)` | `&CarvedFile` | `()` | Aggiorna le statistiche con un file trovato |
| `FileCarver::with_default_rules()` | - | `Self` | Crea un carver con regole predefinite per tutti i tipi comuni |
| `FileCarver::add_rule(rule)` | `CarvingRule` | `()` | Aggiunge una regola di carving personalizzata |
| `FileCarver::clear_rules()` | `&mut self` | `()` | Rimuove tutte le regole |
| `FileCarver::carve(data)` | `&[u8]` | `(Vec<CarvedFile>, CarvingStats)` | Esegue il carving su un buffer, ritorna file trovati e statistiche |
| `carve_raw_image(image_path)` | `&Path` | `Result<(Vec<CarvedFile>, CarvingStats), ForensicsError>` | Funzione libera: esegue carving su immagine disco con regole di default |
| `carve_raw_image_with_rules(image_path, rules)` | `&Path`, `Vec<CarvingRule>` | `Result<(Vec<CarvedFile>, CarvingStats), ForensicsError>` | Carving con regole personalizzate |
| `SectorCarver::new()` | - | `Self` | Crea un carver settore-per-settore |
| `SectorCarver::carve_sectors(data)` | `&[u8]` | `(Vec<CarvedFile>, CarvingStats)` | Carving allineato ai settori (512 B) |
| `SectorCarver::deduplicate(files)` | `Vec<CarvedFile>` | `Vec<CarvedFile>` | Rimuove duplicati per hash |
| `SectorCarver::count_duplicates(files)` | `&[CarvedFile]` | `usize` | Conta i duplicati senza rimuoverli |
| `MagicScanner::add(magic, name)` | `Vec<u8>`, `String` | `()` | Aggiunge una firma magic personalizzata |
| `MagicScanner::default_scanner()` | - | `Self` | Crea scanner con firme predefinite |
| `MagicScanner::scan_sectors(data, sector_size)` | `&[u8]`, `usize` | `Vec<(usize, String)>` | Scansiona trovando offset e tipo per ogni settore |
| `MagicScanner::scan_raw(data)` | `&[u8]` | `Vec<(usize, String)>` | Scansiona un buffer raw restituendo tutti i match |
| `CarvingReport::build(source, files, stats)` | `String`, `&[CarvedFile]`, `CarvingStats` | `Self` | Costruisce un report di carving |
| `CarvingReport::to_text_table()` | `&self` | `String` | Formatta il report come tabella testuale |

---

## incident_timeline.rs (36 funzioni pubbliche)

Timeline strutturata per incident response con fasi di attacco MITRE.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `AttackPhase::infer_from_category(category)` | `&str` | `Self` | Inferisce la fase di attacco MITRE dalla categoria dell'evento |
| `Event::new(ts_ms, source, category, description, confidence)` | ... | `Self` | Crea un evento con tutti i campi principali |
| `Event::with_ioc(ioc)` | `String` | `Self` | Builder: aggiunge un Indicator of Compromise |
| `Event::with_host(host)` | `String` | `Self` | Builder: aggiunge hostname target |
| `Event::with_user(user)` | `String` | `Self` | Builder: aggiunge utente coinvolto |
| `Event::with_meta(key, value)` | `String`, `String` | `Self` | Builder: aggiunge metadato arbitrario |
| `EventCorrelator::from_events(events)` | `Vec<Event>` | `Self` | Crea un correlatore precaricando eventi |
| `EventCorrelator::unique_iocs()` | `&self` | `Vec<String>` | Lista deduplicata di tutti gli IOC presenti |
| `EventCorrelator::mean_confidence()` | `&self` | `f64` | Media dei livelli di confidenza degli eventi |
| `EventCorrelator::add_event(event)` | `Event` | `()` | Aggiunge un evento e ricalcola le correlazioni |
| `EventCorrelator::add_events(events)` | `impl IntoIterator<Item=Event>` | `()` | Aggiunge più eventi |
| `EventCorrelator::sort()` | `&mut self` | `()` | Ordina per timestamp |
| `EventCorrelator::cluster()` | `&self` | `Vec<EventCluster>` | Raggruppa eventi correlati in cluster temporali |
| `EventCorrelator::events()` | `&self` | `&[Event]` | Riferimento alla lista eventi |
| `EventCorrelator::events_by_source(source)` | `&EventSource` | `Vec<&Event>` | Filtra per sorgente |
| `EventCorrelator::events_by_phase(phase)` | `AttackPhase` | `Vec<&Event>` | Filtra per fase di attacco |
| `EventCorrelator::events_in_range(start, end)` | `u64`, `u64` | `Vec<&Event>` | Filtra per intervallo temporale |
| `EventCorrelator::count_by_source()` | `&self` | `HashMap<String, usize>` | Conteggio eventi per sorgente |
| `EventCorrelator::count_by_phase()` | `&self` | `HashMap<AttackPhase, usize>` | Conteggio eventi per fase MITRE |
| `EventCorrelator::all_iocs()` | `&self` | `Vec<String>` | Tutti gli IOC (con duplicati) |
| `IncidentTimeline::new(case_id, analyst)` | `String`, `String` | `Self` | Crea una timeline di incidente |
| `IncidentTimeline::add_event(event)` | `Event` | `()` | Aggiunge un evento alla timeline |
| `IncidentTimeline::merge_from(other)` | `EventCorrelator` | `()` | Fonde un correlatore esterno nella timeline |
| `IncidentTimeline::sort()` | `&mut self` | `()` | Ordina la timeline |
| `IncidentTimeline::clusters()` | `&mut self` | `&[EventCluster]` | Calcola e ritorna i cluster di eventi |
| `IncidentTimeline::events()` | `&self` | `&[Event]` | Tutti gli eventi |
| `IncidentTimeline::iocs()` | `&self` | `Vec<String>` | Tutti gli IOC deduplicati |
| `IncidentTimeline::start_time_ms()` | `&self` | `Option<u64>` | Timestamp del primo evento |
| `IncidentTimeline::end_time_ms()` | `&self` | `Option<u64>` | Timestamp dell'ultimo evento |
| `IncidentTimeline::duration_ms()` | `&self` | `u64` | Durata totale in millisecondi |
| `IncidentTimeline::observed_phases()` | `&self` | `Vec<AttackPhase>` | Fasi di attacco osservate (dedup) |
| `IncidentTimeline::events_for_phase(phase)` | `AttackPhase` | `Vec<&Event>` | Filtra eventi per fase |
| `TimelineExporter::to_json(timeline)` | `&IncidentTimeline` | `Result<String, TimelineError>` | Serializza la timeline in JSON |
| `TimelineExporter::to_csv(timeline)` | `&IncidentTimeline` | `Result<String, TimelineError>` | Esporta in CSV |
| `TimelineExporter::to_html(timeline)` | `&IncidentTimeline` | `Result<String, TimelineError>` | Genera report HTML interattivo |
| `TimelineExporter::to_text(timeline)` | `&IncidentTimeline` | `String` | Genera output testuale leggibile |

---

## malware_forensics.rs (32 funzioni pubbliche)

Analisi strutturata di malware: persistence, lateral movement, C2, esfiltrazione.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `MalwareTimeline::add_event(event)` | `TimelineEvent` | `()` | Aggiunge un evento alla timeline malware |
| `MalwareTimeline::filter_by_category(cat)` | `EventCategory` | `Vec<&TimelineEvent>` | Filtra eventi per categoria |
| `MalwareTimeline::first_event()` | `&self` | `Option<&TimelineEvent>` | Primo evento (inizio attività) |
| `MalwareTimeline::last_event()` | `&self` | `Option<&TimelineEvent>` | Ultimo evento |
| `MalwareTimeline::duration_secs()` | `&self` | `Option<u64>` | Durata totale dell'attività in secondi |
| `MalwareTimeline::category_counts()` | `&self` | `HashMap<EventCategory, usize>` | Conteggio per categoria |
| `PersistenceMechanism::new(mtype, location, value)` | ... | `Self` | Crea un meccanismo di persistence |
| `PersistenceMechanism::with_host(host)` | `String` | `Self` | Builder: aggiunge hostname |
| `PersistenceMechanism::with_mitre(technique)` | `String` | `Self` | Builder: aggiunge tecnica MITRE |
| `PersistenceMechanism::with_evidence(evidence)` | `Vec<String>` | `Self` | Builder: aggiunge riferimenti a evidence |
| `MalwareCase::new(case_id, host)` | `String`, `String` | `Self` | Crea un case di analisi malware |
| `MalwareCase::add_persistence(p)` | `PersistenceMechanism` | `()` | Aggiunge meccanismo di persistence trovato |
| `MalwareCase::add_lateral_movement(lm)` | `LateralMovement` | `()` | Aggiunge movimento laterale osservato |
| `MalwareCase::add_credential_dump(cd)` | `CredentialDump` | `()` | Aggiunge dump credenziali osservato |
| `MalwareCase::add_c2(c2)` | `C2Channel` | `()` | Aggiunge canale C2 identificato |
| `MalwareCase::add_exfiltration(ex)` | `DataExfil` | `()` | Aggiunge evento di data exfiltration |
| `MalwareCase::add_event(ev)` | `TimelineEvent` | `()` | Aggiunge evento generico alla timeline |
| `MalwareCase::overall_severity()` | `&self` | `Severity` | Calcola la severity complessiva del case |
| `MalwareCase::unique_mitre_techniques()` | `&self` | `Vec<String>` | Lista deduplicata delle tecniche MITRE coinvolte |
| `MalwareCase::has_registry_persistence()` | `&self` | `bool` | Vero se il malware utilizza registry run key |
| `MalwareCase::successful_lateral_movements()` | `&self` | `Vec<&LateralMovement>` | Filtra i movimenti laterali riusciti |
| `MalwareCase::total_exfiltrated_bytes()` | `&self` | `u64` | Somma dei byte esfiltrati |
| `MalwareCase::c2_protocols()` | `&self` | `Vec<C2Protocol>` | Protocolli C2 usati (dedup) |
| `MalwareCase::rootkit_persistence()` | `&self` | `Vec<&RootkitPersistence>` | Persistence di tipo rootkit |
| `MalwareCase::mitre_coverage_score()` | `&self` | `u8` | Score 0-100 della copertura MITRE ATT&CK |
| `MalwareCase::report()` | `&self` | `String` | Genera un report testuale strutturato del case |
| `PersistenceMechanism::run_key(hive, path, value)` | `String`, `String`, `String` | `Self` | Factory: crea persistence di tipo Registry Run Key |
| `PersistenceMechanism::mechanism(mtype, location)` | `PersistenceType`, `String` | `Self` | Factory generica per meccanismo di persistence |
| `C2Channel::http(remote, port)` | `String`, `u16` | `Self` | Factory: canale C2 HTTP |
| `C2Channel::https(remote)` | `String` | `Self` | Factory: canale C2 HTTPS (porta 443) |
| `C2Channel::dns(domain)` | `String` | `Self` | Factory: C2 via DNS tunneling |
| `C2Channel::add_indicator(ioc)` | `String` | `()` | Aggiunge un IOC al canale C2 |

---

## memory_acquisition.rs (16 funzioni pubbliche)

Parsing di formati dump memoria: LiME, ELF core, Windows crash dump, hiberfil.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `LimeHeader::parse(data)` | `&[u8]` | `Option<Self>` | Tenta di parsare un header LiME (Linux Memory Extractor) |
| `parse_lime_dump(data)` | `&[u8]` | `Result<Vec<MemorySegment>, ForensicsError>` | Decodifica un dump LiME in segmenti fisici |
| `ElfProgramHeader::parse(data)` | `&[u8]` | `Option<Self>` | Parsa un program header ELF |
| `WindowsCrashDumpHeader::parse(data)` | `&[u8]` | `Option<Self>` | Parsa l'header di un Windows crash dump (PAGEDUMP64) |
| `parse_elf_core(data)` | `&[u8]` | `Result<Vec<MemorySegment>, ForensicsError>` | Estrae segmenti fisici da un ELF core dump |
| `PfnEntry::parse(data)` | `&[u8]` | `Option<Self>` | Parsa una voce della Page Frame Number Database |
| `parse_crash_dump_segments(data)` | `&[u8]` | `Result<Vec<MemorySegment>, ForensicsError>` | Estrae segmenti da dump Windows (full/kernel) usando PFN |
| `HibernationHeader::parse(data)` | `&[u8]` | `Option<Self>` | Parsa l'header di hiberfil.sys |
| `parse_hiberfil(data)` | `&[u8]` | `Result<HibernationParseResult, ForensicsError>` | Analizza hiberfil.sys estraendo metadati e segmenti |
| `DumpAnalyser::analyse_file(data)` | `&[u8]` | `Result<Vec<MemorySegment>, ForensicsError>` | Auto-rileva il formato del dump e ritorna i segmenti |
| `DumpAnalyser::build_result(segments, metadata)` | `Vec<MemorySegment>`, `DumpMetadata` | `HibernationParseResult` | Assembla il risultato di parsing con segmenti e metadati |
| `StreamingAcquirer::process_chunk(data, is_last)` | `&[u8]`, `bool` | `AcquisitionChunk` | Processa un chunk di acquisizione streaming |
| `StreamingAcquirer::segments()` | `&self` | `&[MemorySegment]` | Ritorna i segmenti acquisiti finora |
| `merge_adjacent_segments(segments, gap_threshold)` | `Vec<MemorySegment>`, `u64` | `Vec<MemorySegment>` | Fonde segmenti adiacenti entro una soglia di gap (byte) |
| `total_coverage(segments)` | `&[MemorySegment]` | `u64` | Calcola la copertura totale in byte di un insieme di segmenti |
| `find_segment(segments, phys_addr)` | `&[MemorySegment]`, `u64` | `Option<&MemorySegment>` | Trova il segmento che contiene un indirizzo fisico dato |

---

## memory_dump_analyzer.rs (52 funzioni pubbliche)

Analisi strutturata di dump di memoria: processi, moduli, handle, connessioni di rete.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `DumpImage::read_bytes(offset, len)` | `u64`, `usize` | `Result<&[u8], DumpAnalyzerError>` | Legge bytes a un offset assoluto nel dump |
| `DumpImage::read_u32_le(offset)` | `u64` | `Result<u32, DumpAnalyzerError>` | Legge un u32 little-endian dal dump |
| `DumpImage::read_u64_le(offset)` | `u64` | `Result<u64, DumpAnalyzerError>` | Legge un u64 little-endian dal dump |
| `ProcessRecord::new(pid, parent_pid, name)` | `u32`, `u32`, `String` | `Self` | Crea un record di processo |
| `ProcessRecord::is_suspicious()` | `&self` | `bool` | Euristica di sospetto (parent insolito, nome mascherato) |
| `ProcessRecord::display_path()` | `&self` | `String` | Percorso immagine formattato per display |
| `ModuleRecord::new(name, base, size)` | `String`, `u64`, `u64` | `Self` | Crea un record di modulo caricato |
| `ModuleRecord::path_buf()` | `&self` | `PathBuf` | Converte il path del modulo in `PathBuf` |
| `NetworkConnectionRecord::with_name(name)` | `String` | `Self` | Builder: imposta nome del processo owner |
| `NetworkConnectionRecord::tcp(...)` | pid, local, remote, state | `Self` | Factory: crea record connessione TCP |
| `NetworkConnectionRecord::endpoint_str()` | `&self` | `String` | Stringa `local->remote` per display |
| `ProcessWalker::new()` | - | `Self` | Crea un walker di lista processi |
| `ProcessWalker::load_synthetic(procs)` | `Vec<ProcessRecord>` | `()` | Carica processi sintetici (per test) |
| `ProcessWalker::walk(image)` | `&DumpImage` | `Result<usize, DumpAnalyzerError>` | Enumera processi dal dump, ritorna conteggio |
| `ProcessWalker::all()` | `&self` | `&[ProcessRecord]` | Lista di tutti i processi trovati |
| `ProcessWalker::by_pid(pid)` | `u32` | `Option<&ProcessRecord>` | Cerca processo per PID |
| `ProcessWalker::by_name(name)` | `&str` | `Vec<&ProcessRecord>` | Cerca processi per nome |
| `ProcessWalker::suspicious_processes()` | `&self` | `Vec<&ProcessRecord>` | Filtra processi sospetti |
| `ProcessWalker::pid_tree()` | `&self` | `HashMap<u32, Vec<u32>>` | Mappa pid->figli per ricostruire l'albero di processi |
| `ModuleWalker::new()` | - | `Self` | Crea un walker di moduli |
| `ModuleWalker::load_synthetic(mods)` | `Vec<ModuleRecord>` | `()` | Carica moduli sintetici |
| `ModuleWalker::walk(image)` | `&DumpImage` | `Result<usize, DumpAnalyzerError>` | Enumera moduli dal dump |
| `ModuleWalker::all()` | `&self` | `&[ModuleRecord]` | Lista di tutti i moduli |
| `ModuleWalker::find_by_addr(addr)` | `u64` | `Option<&ModuleRecord>` | Trova il modulo che contiene un indirizzo |
| `ModuleWalker::find_by_name(name)` | `&str` | `Option<&ModuleRecord>` | Cerca modulo per nome |
| `ModuleWalker::kernel_modules()` | `&self` | `Vec<&ModuleRecord>` | Filtra solo i moduli kernel |
| `ModuleWalker::orphan_addresses(addrs)` | `&[u64]` | `Vec<u64>` | Indirizzi non mappati in nessun modulo noto |
| `HandleWalker::new()` | - | `Self` | Crea un walker di handle |
| `HandleWalker::load_synthetic(handles)` | `Vec<HandleRecord>` | `()` | Carica handle sintetici |
| `HandleWalker::all()` | `&self` | `&[HandleRecord]` | Lista di tutti gli handle |
| `HandleWalker::by_pid(pid)` | `u32` | `Vec<&HandleRecord>` | Filtra handle per PID |
| `HandleWalker::by_type(htype)` | `HandleType` | `Vec<&HandleRecord>` | Filtra handle per tipo (File, Process, Thread, ecc.) |
| `HandleWalker::named_handles()` | `&self` | `Vec<&HandleRecord>` | Filtra handle con nome non vuoto |
| `HandleWalker::mutant_names()` | `&self` | `Vec<String>` | Nomi dei mutex/mutant (spesso IOC malware) |
| `HandleWalker::handle_count_by_type()` | `&self` | `HashMap<String, usize>` | Conteggio handle per tipo |
| `NetworkWalker::new()` | - | `Self` | Crea un walker di connessioni di rete |
| `NetworkWalker::load_synthetic(conns)` | `Vec<NetworkConnectionRecord>` | `()` | Carica connessioni sintetiche |
| `NetworkWalker::all()` | `&self` | `&[NetworkConnectionRecord]` | Tutte le connessioni |
| `NetworkWalker::by_pid(pid)` | `u32` | `Vec<&NetworkConnectionRecord>` | Filtra per PID |
| `NetworkWalker::tcp_connections()` | `&self` | `Vec<&NetworkConnectionRecord>` | Solo connessioni TCP |
| `NetworkWalker::udp_connections()` | `&self` | `Vec<&NetworkConnectionRecord>` | Solo connessioni UDP |
| `NetworkWalker::unique_remote_ips()` | `&self` | `Vec<String>` | IP remoti unici (potenziali C2) |
| `DumpReport::threat_score()` | `&self` | `u32` | Score di minaccia 0-100 basato sugli IOC trovati |
| `DumpAnalyzer::new()` | - | `Self` | Crea un analizzatore dump vuoto |
| `DumpAnalyzer::load_processes(procs)` | `Vec<ProcessRecord>` | `()` | Carica lista processi pre-estratta |
| `DumpAnalyzer::load_modules(mods)` | `Vec<ModuleRecord>` | `()` | Carica lista moduli pre-estratta |
| `DumpAnalyzer::load_handles(handles)` | `Vec<HandleRecord>` | `()` | Carica lista handle pre-estratta |
| `DumpAnalyzer::load_network(conns)` | `Vec<NetworkConnectionRecord>` | `()` | Carica lista connessioni pre-estratta |
| `DumpAnalyzer::analyze_image(image)` | `&DumpImage` | `Result<(), DumpAnalyzerError>` | Esegue l'analisi completa del dump (processi, moduli, handle, rete) |
| `DumpAnalyzer::errors()` | `&self` | `&[String]` | Errori non fatali incontrati durante l'analisi |
| `DumpAnalyzer::generate_report()` | `&self` | `DumpReport` | Genera il report completo con IOC, score di minaccia e statistiche |
| `DumpReport::has_ioc()` | `&self` | `bool` | Vero se il report contiene almeno un IOC |

---

## os_adapter.rs (14 funzioni pubbliche)

Adattatore OS-agnostico per accesso a processi, file, registro, rete e memoria. Usato principalmente nei test e come stub.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ProcessInfo::new(pid, name)` | `u32`, `String` | `Self` | Crea info di processo |
| `FileInfo::new(path, size)` | `String`, `u64` | `Self` | Crea info di file con percorso e dimensione |
| `RegistryEntry::new(key_path, value_name, data_str)` | `String`, `String`, `String` | `Self` | Crea una voce di registro |
| `LoadedModule::new(name, base_address, size)` | `String`, `u64`, `u64` | `Self` | Crea info di modulo caricato in memoria |
| `OsAdapter::new()` | - | `Self` | Crea un adattatore per il sistema corrente (Linux: `/proc`) |
| `OsAdapter::with_proc_root(proc_root)` | `String` | `Self` | Crea adattatore con root procfs personalizzata (per test) |
| `MockOsAdapter::new(platform)` | `String` | `Self` | Crea un adattatore mock per test con nome piattaforma |
| `MockOsAdapter::add_process(p)` | `ProcessInfo` | `()` | Aggiunge un processo simulato |
| `MockOsAdapter::add_files(path, files)` | `String`, `Vec<FileInfo>` | `()` | Aggiunge file simulati sotto un percorso |
| `MockOsAdapter::add_registry(key, entries)` | `String`, `Vec<RegistryEntry>` | `()` | Aggiunge chiavi registro simulate |
| `MockOsAdapter::add_connection(conn)` | `NetworkConnection` | `()` | Aggiunge connessione di rete simulata |
| `MockOsAdapter::set_memory(pid, address, data)` | `u32`, `u64`, `Vec<u8>` | `()` | Imposta memoria simulata per un processo |
| `MockOsAdapter::add_modules(pid, modules)` | `u32`, `Vec<LoadedModule>` | `()` | Aggiunge moduli simulati per un processo |
| `MockOsAdapter::fail_next()` | `&self` | `()` | Configura il mock per fallire alla prossima chiamata (test di errore) |

---

## prefetch_analyzer.rs (20 funzioni pubbliche)

Analisi di file Windows Prefetch (.pf) versioni 17, 23, 26, 30.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `FileMetric::is_dll()` | `&self` | `bool` | Vero se il file referenziato è una DLL |
| `FileMetric::is_exe()` | `&self` | `bool` | Vero se il file referenziato è un eseguibile |
| `FileMetric::base_name()` | `&self` | `&str` | Nome file senza percorso |
| `VolumeInfo::serial_hex()` | `&self` | `String` | Numero seriale del volume in esadecimale |
| `PrefetchFile::most_recent_run()` | `&self` | `u64` | Timestamp FILETIME dell'ultima esecuzione |
| `PrefetchFile::filetime_to_utc(filetime)` | `u64` | `String` | Converte un FILETIME Windows in stringa UTC leggibile |
| `PrefetchFile::referenced_dlls()` | `&self` | `Vec<&FileMetric>` | Lista delle DLL referenziate |
| `PrefetchFile::referenced_executables()` | `&self` | `Vec<&FileMetric>` | Lista degli eseguibili referenziati |
| `PrefetchFile::extension_counts()` | `&self` | `HashMap<String, usize>` | Conteggio file referenziati per estensione |
| `PrefetchFile::from_bytes(data)` | `&[u8]` | `Result<Self, ForensicsError>` | Parsa un file prefetch da byte grezzi (auto-rileva versione) |
| `PrefetchFile::from_file(path)` | `&Path` | `Result<Self, ForensicsError>` | Carica e parsa un file prefetch da disco |
| `PrefetchFile::summary()` | `&self` | `String` | Riepilogo testuale: nome exe, run count, last run, volumi |
| `PrefetchFile::files_with_extension(ext)` | `&str` | `Vec<&str>` | Percorsi di file referenziati con una data estensione |
| `PrefetchFile::most_loaded_dll()` | `&self` | `Option<&FileMetric>` | DLL con il maggior numero di load count |
| `parse_prefetch(data)` | `&[u8]` | `Result<PrefetchFile, ForensicsError>` | Funzione libera: alias di `from_bytes` |
| `PrefetchDirectory::load(dir)` | `&Path` | `Result<Self, ForensicsError>` | Carica tutti i file `.pf` da una directory |
| `PrefetchDirectory::most_executed()` | `&self` | `Option<&PrefetchFile>` | Eseguibile con il maggior run count |
| `PrefetchDirectory::frequent_apps(threshold)` | `u32` | `Vec<&PrefetchFile>` | Eseguibili eseguiti almeno `threshold` volte |
| `PrefetchDirectory::dll_frequency()` | `&self` | `HashMap<String, usize>` | Frequenza di caricamento DLL su tutti i prefetch |
| `build_execution_timeline(prefetch_files)` | `&[PrefetchFile]` | `Vec<PrefetchTimelineEvent>` | Costruisce una timeline di esecuzione ordinata per tutti i prefetch |

---

## registry_hive_analyzer.rs (18 funzioni pubbliche)

Parsing raw di hive di registro Windows (REGF format).

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `HiveValue::as_string()` | `&self` | `Option<String>` | Converte valore REG_SZ / REG_EXPAND_SZ in stringa |
| `HiveValue::as_dword()` | `&self` | `Option<u32>` | Converte valore REG_DWORD in u32 |
| `HiveValue::as_qword()` | `&self` | `Option<u64>` | Converte valore REG_QWORD in u64 |
| `HiveValue::as_multi_sz()` | `&self` | `Option<Vec<String>>` | Converte REG_MULTI_SZ in lista di stringhe |
| `HiveValue::hex_preview()` | `&self` | `String` | Preview esadecimale dei dati grezzi |
| `HiveKey::get_value(name)` | `&str` | `Option<&HiveValue>` | Recupera un valore per nome nella chiave |
| `HiveKey::last_write_utc_approx()` | `&self` | `String` | Timestamp di ultima modifica in formato UTC approssimato |
| `RegistryHiveAnalyzer::from_bytes(data)` | `Vec<u8>` | `Result<Self, ForensicsError>` | Parsa un hive da byte (signature REGF verificata) |
| `RegistryHiveAnalyzer::from_file(path)` | `&Path` | `Result<Self, ForensicsError>` | Carica e parsa un hive da file |
| `RegistryHiveAnalyzer::root_key()` | `&self` | `Result<HiveKey, ForensicsError>` | Ritorna la root key del hive |
| `RegistryHiveAnalyzer::enumerate_all_keys()` | `&self` | `Vec<HiveKey>` | Enumera ricorsivamente tutte le chiavi del hive |
| `RegistryHiveAnalyzer::find_key(path_suffix)` | `&str` | `Option<HiveKey>` | Cerca una chiave per suffisso di percorso |
| `RegistryHiveAnalyzer::query_values(path_suffix)` | `&str` | `Vec<HiveValue>` | Legge i valori di una chiave per percorso |
| `RegistryHiveAnalyzer::all_values_by_path()` | `&self` | `HashMap<String, Vec<HiveValue>>` | Mappa completa percorso->valori per tutte le chiavi |
| `parse_hive(path)` | `&Path` | `Result<RegistryHiveAnalyzer, ForensicsError>` | Funzione libera: carica e parsa un hive da file |
| `parse_hive_bytes(data)` | `Vec<u8>` | `Result<RegistryHiveAnalyzer, ForensicsError>` | Funzione libera: parsa un hive da byte |
| `HiveValueFormatter::format(value)` | `&HiveValue` | `String` | Formatta un valore per display leggibile |
| `HiveDiff::compute(a, b)` | `&RegistryHiveAnalyzer`, `&RegistryHiveAnalyzer` | `Self` | Calcola le differenze tra due snapshot dello stesso hive |

---

## timeline_builder.rs (24 funzioni pubbliche)

Builder e filtri per timeline forensiche generiche.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `EventSeverity::new(v)` | `u8` | `Self` | Crea un livello di severity da valore numerico |
| `TimelineEvent::new(ts, source, description, severity)` | ... | `Self` | Crea evento timeline con timestamp ms, sorgente e severity |
| `TimelineEvent::with_actor(actor)` | `String` | `Self` | Builder: imposta attore |
| `TimelineEvent::with_artifact(id)` | `String` | `Self` | Builder: imposta ID artefatto |
| `TimelineFilter::new()` | - | `Self` | Crea filtro neutro (accetta tutto) |
| `TimelineFilter::with_category(cat)` | `EventCategory` | `Self` | Filtra per categoria |
| `TimelineFilter::with_source(src)` | `String` | `Self` | Filtra per sorgente |
| `TimelineFilter::matches(event)` | `&TimelineEvent` | `bool` | Testa se un evento soddisfa il filtro |
| `ForensicTimeline::new()` | - | `Self` | Crea una timeline forense vuota |
| `ForensicTimeline::add_event(event)` | `TimelineEvent` | `()` | Aggiunge un evento |
| `ForensicTimeline::sort()` | `&mut self` | `()` | Ordina per timestamp |
| `ForensicTimeline::events()` | `&self` | `&[TimelineEvent]` | Riferimento agli eventi |
| `ForensicTimeline::filter(f)` | `&TimelineFilter` | `Vec<&TimelineEvent>` | Filtra eventi con un filtro |
| `ForensicTimeline::events_in_range(start_ms, end_ms)` | `u64`, `u64` | `Vec<&TimelineEvent>` | Filtra per intervallo temporale |
| `ForensicTimeline::high_severity(threshold)` | `EventSeverity` | `Vec<&TimelineEvent>` | Filtra eventi ad alta severity |
| `ForensicTimeline::events_from_source(source)` | `&str` | `Vec<&TimelineEvent>` | Filtra per sorgente |
| `ForensicTimeline::to_json()` | `&self` | `String` | Serializza in JSON |
| `ForensicTimeline::to_csv()` | `&self` | `String` | Serializza in CSV (header + righe) |
| `ForensicTimeline::merge(other)` | `Self` | `()` | Fonde un'altra timeline in questa |
| `TimelineBuilder::new()` | - | `Self` | Crea un builder di timeline |
| `TimelineBuilder::with_default_source(src)` | `String` | `Self` | Imposta la sorgente di default per gli eventi |
| `TimelineBuilder::add_artifact(entry)` | `ArtifactEntry` | `()` | Aggiunge una voce artefatto da convertire in evento |
| `TimelineBuilder::add_artifacts(entries)` | `impl IntoIterator<Item=ArtifactEntry>` | `()` | Aggiunge multiple voci artefatto |
| `TimelineBuilder::build(self)` | - | `ForensicTimeline` | Costruisce la timeline dagli artefatti accumulati |

---

## timeline_correlator.rs (23 funzioni pubbliche)

Correlazione avanzata di eventi multi-sorgente con normalizzazione temporale.

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TimelineEvent::timestamp_seconds()` | `&self` | `f64` | Timestamp in secondi floating-point |
| `TimestampNormaliser::new()` | - | `Self` | Crea un normalizzatore senza offset |
| `TimestampNormaliser::set_offset(source, offset_ms)` | `EventSource`, `i64` | `()` | Imposta l'offset di skew per una sorgente |
| `TimestampNormaliser::normalise(raw_ms, source)` | `i64`, `EventSource` | `i64` | Applica l'offset di normalizzazione a un timestamp raw |
| `TimestampNormaliser::compute_skew(source_a, ts_a, source_b, ts_b)` | ... | `()` | Calcola e memorizza lo skew tra due sorgenti sincronizzando timestamp noti |
| `TimelineEvent::to_csv_line()` | `&self` | `String` | Serializza l'evento in una riga CSV |
| `CorrelatedTimeline::new()` | - | `Self` | Crea una timeline correlata vuota |
| `CorrelatedTimeline::with_normaliser(normaliser)` | `TimestampNormaliser` | `Self` | Builder: imposta il normalizzatore |
| `CorrelatedTimeline::add_event(ev)` | `TimelineEvent` | `()` | Aggiunge e normalizza un evento |
| `CorrelatedTimeline::record(source, ts_ms, description, severity)` | ... | `()` | Shortcut per aggiungere un evento da componenti |
| `CorrelatedTimeline::sort()` | `&mut self` | `()` | Ordina per timestamp normalizzato |
| `CorrelatedTimeline::events()` | `&self` | `&[TimelineEvent]` | Slice degli eventi |
| `CorrelatedTimeline::events_sorted()` | `&mut self` | `&[TimelineEvent]` | Ordina e ritorna lo slice (lazy sort) |
| `CorrelatedTimeline::filter_by_source(source)` | `EventSource` | `Vec<&TimelineEvent>` | Filtra per sorgente |
| `CorrelatedTimeline::filter_by_severity(min_severity)` | `EventSeverity` | `Vec<&TimelineEvent>` | Filtra per severity minima |
| `CorrelatedTimeline::filter_by_window(start_ms, end_ms)` | `i64`, `i64` | `Vec<&TimelineEvent>` | Filtra per finestra temporale |
| `CorrelatedTimeline::detect_gaps(min_gap_ms)` | `i64` | `()` | Rileva gap temporali sospetti (assenza di eventi) |
| `CorrelatedTimeline::gaps()` | `&self` | `&[TimelineGap]` | Tutti i gap rilevati |
| `CorrelatedTimeline::suspicious_gaps()` | `&self` | `Vec<&TimelineGap>` | Solo i gap classificati come sospetti |
| `CorrelatedTimeline::detect_patterns(window_ms)` | `i64` | `()` | Individua pattern temporali (burst, periodicità) in una finestra |
| `CorrelatedTimeline::patterns()` | `&self` | `&[TemporalPattern]` | Pattern rilevati |
| `CorrelatedTimeline::export_plaso_csv()` | `&self` | `String` | Esporta in formato CSV compatibile con Plaso/log2timeline |
| `CorrelatedTimeline::summary()` | `&mut self` | `TimelineSummary` | Genera un riepilogo statistico della timeline (eventi, gap, pattern, durata) |
