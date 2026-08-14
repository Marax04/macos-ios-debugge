# rustre-sandbox-extract

Crate per l'estrazione e l'analisi di artefatti da report di sandbox malware. Fornisce strutture dati normalizzate, estrattori di IOC, analisi di ransomware, dropper, credenziali, chiavi crittografiche e comunicazioni C2 a partire da dump di memoria, log API, file scartati e report JSON di sandbox note (Cuckoo, AnyRun, Triage, JoeSandbox, Hybrid Analysis, VirusTotal).

Dipende da: `rustre-sandbox`, `serde`, `serde_json`, `thiserror`, `anyhow`, `regex`, `hex`, `sha2`, `md-5`, `windows-sys` (solo Windows).

---

## Funzioni pubbliche libere (modulo-level)

| Funzione | Firma sintetica | Descrizione |
|---|---|---|
| `file_op_histogram` | `(events: &[NormalizedFileEvent]) -> HashMap<FileOp, usize>` | Conta le operazioni su file per tipo (read/write/delete/…) da una slice di eventi normalizzati. |
| `reg_op_histogram` | `(events: &[NormalizedRegistryEvent]) -> HashMap<RegOp, usize>` | Istogramma delle operazioni di registro per tipo. |
| `classify_ip` | `(s: &str) -> Option<IpClass>` | Classifica un indirizzo IP come loopback, privato, CGNAT, pubblico, multicast ecc. Ritorna `None` se non parsabile. |
| `group_paths_by_parent` | `(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<PathBuf>>` | Raggruppa percorsi di file per directory padre: utile per correlare file droppati nella stessa cartella. |
| `extract_iocs` | `(sandbox_result: &SandboxResult) -> IocCollection` | Entry-point di alto livello: estrae tutti gli IOC (IP, domìni, URL, hash, percorsi) da un `SandboxResult`. |
| `extract_config` | `(family: &str, memory_dump: &[u8]) -> Option<MalwareConfig>` | Cerca e restituisce la configurazione per una famiglia malware nota nel dump di memoria grezzo. |
| `collect_artifacts` | `(report_dir: &Path) -> Result<Vec<SandboxArtifact>>` | Scansiona una directory di report sandbox e raccoglie tutti gli artefatti classificandoli per tipo (PE, script, pcap, …). |

---

## Moduli e metodi pubblici principali

### `sandbox_report_normalizer` — Normalizzazione report sandbox

| Struct/fn | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `NormalizedReport` | `summary()` | `(&self) -> String` | Stringa riassuntiva del report (score, famiglia, firme). |
| | `has_signature_containing()` | `(&self, keyword: &str) -> bool` | Verifica se almeno una firma contiene la sottostringa. |
| | `unique_dst_ips()` | `(&self) -> Vec<&str>` | IP di destinazione distinti estratti dal traffico di rete. |
| | `dns_queries()` | `(&self) -> Vec<&str>` | Hostname risolti durante l'esecuzione. |
| `SandboxNormalizer` | `normalize()` | `(&self, json_str: &str) -> Result<NormalizedReport, String>` | Rileva il formato sandbox dal JSON e chiama il normalizzatore specifico. |
| | `normalize_cuckoo()` | `(&self, v: &Value) -> NormalizedReport` | Parser per report Cuckoo Sandbox. |
| | `normalize_anyrun()` | `(&self, v: &Value) -> NormalizedReport` | Parser per report ANY.RUN. |
| | `normalize_triage()` | `(&self, v: &Value) -> NormalizedReport` | Parser per report Hatching Triage. |
| | `normalize_joe()` | `(&self, v: &Value) -> NormalizedReport` | Parser per report JoeSandbox. |
| | `normalize_hybrid()` | `(&self, v: &Value) -> NormalizedReport` | Parser per report Hybrid Analysis. |
| | `normalize_vt_behavior()` | `(&self, v: &Value) -> NormalizedReport` | Parser per il behavior report di VirusTotal. |
| | `normalize_generic()` | `(&self, v: &Value) -> NormalizedReport` | Fallback per JSON con struttura sconosciuta. |
| `ThreatLevel` | `from_score()` | `(score: f64) -> Self` | Converte uno score numerico (0–10) in enum `ThreatLevel`. |
| `FileOp` | `from_str()` | `(s: &str) -> Self` | Parsing da stringa (es. `"WriteFile"` → `FileOp::Write`). |
| `RegOp` | `from_str()` | `(s: &str) -> Self` | Parsing da stringa (es. `"RegSetValue"` → `RegOp::Set`). |

---

### `behavior_extractor` — Estrazione comportamentale

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `BehaviorExtractor` | `detect_format()` | `(json_str: &str) -> SandboxLogFormat` | Riconosce il formato sandbox dal contenuto JSON (campo-chiave heuristic). |
| | `extract()` | `(&self, json_str: &str) -> ExtractionReport` | Dispatcher: rileva formato e chiama il parser corretto. |
| | `parse_cuckoo_report()` | `(&self, json_str: &str) -> ExtractionReport` | Estrae artefatti comportamentali da un report Cuckoo. |
| | `parse_anyrun_report()` | `(&self, json_str: &str) -> ExtractionReport` | Estrae artefatti da un report ANY.RUN. |
| | `parse_triage_report()` | `(&self, json_str: &str) -> ExtractionReport` | Estrae artefatti da un report Triage. |
| | `parse_joe_report()` | `(&self, json_str: &str) -> ExtractionReport` | Estrae artefatti da un report JoeSandbox. |
| | `parse_generic_json()` | `(&self, json_str: &str) -> ExtractionReport` | Parser generico best-effort. |
| | `extract_network_iocs()` | `(artifacts: &[BehaviorArtifact]) -> Vec<Ioc>` | Filtra artefatti di tipo rete e li converte in IOC. |
| | `extract_file_iocs()` | `(artifacts: &[BehaviorArtifact]) -> Vec<Ioc>` | Filtra artefatti di tipo file e li converte in IOC. |
| | `extract_persistence()` | `(artifacts: &[BehaviorArtifact]) -> Vec<&BehaviorArtifact>` | Restituisce gli artefatti classificati come persistenza. |
| `BehaviorArtifact` | `new()` | `(artifact_type, value, confidence) -> Self` | Costruttore con tipo, valore stringa e confidence 0–1. |
| | `with_meta()` | `(mut self, key, val) -> Self` | Builder per aggiungere metadati chiave-valore. |

---

### `c2_extractor` — Rilevamento C2

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `C2Channel` | `new()` | `(host, port, protocol) -> Self` | Costruisce un canale C2 con host, porta e protocollo. |
| | `with_uri()` | `(mut self, uri) -> Self` | Aggiunge URI opzionale (path HTTP, topic MQTT, ecc.). |
| | `with_user_agent()` | `(mut self, ua) -> Self` | Imposta lo User-Agent HTTP. |
| | `address()` | `(&self) -> String` | Restituisce `"host:port"`. |
| | `is_ip()` | `(&self) -> bool` | True se `host` è un indirizzo IP. |
| | `is_domain()` | `(&self) -> bool` | True se `host` è un nome dominio. |
| `C2Config` | `new()` | `(family) -> Self` | Nuova configurazione C2 per famiglia malware. |
| | `add_channel()` | `(&mut self, ch)` | Aggiunge un canale C2. |
| | `primary_channel()` | `(&self) -> Option<&C2Channel>` | Restituisce il primo canale. |
| | `domain_channels()` | `(&self) -> Vec<&C2Channel>` | Filtra i canali con host dominio. |
| | `ip_channels()` | `(&self) -> Vec<&C2Channel>` | Filtra i canali con host IP. |
| `DgaDetector` | `new()` | `() -> Self` | Istanzia il rilevatore DGA (Domain Generation Algorithm). |
| | `entropy()` | `(s: &str) -> f64` | Entropia di Shannon del nome dominio. |
| | `is_dga()` | `(&self, domain: &str) -> bool` | True se il dominio ha caratteristiche DGA (alto N-gram, basso ratio vocali). |
| | `filter_dga()` | `(&self, domains: &[&str]) -> Vec<&str>` | Filtra un elenco di domini restituendo solo quelli DGA. |
| | `vowel_ratio()` | `(s: &str) -> f64` | Ratio vocali/totale caratteri — feature DGA. |
| `FastFluxDetector` | `new()` | `() -> Self` | Istanzia il rilevatore fast-flux. |
| | `add_record()` | `(&mut self, domain, ip, ttl)` | Registra una risposta DNS. |
| | `is_fast_flux()` | `(&self, domain: &str) -> bool` | True se il dominio ha mostrato fast-flux (molti IP distinti, TTL basso). |
| | `fast_flux_domains()` | `(&self) -> Vec<String>` | Lista di tutti i domini fast-flux osservati. |
| | `ip_count()` | `(&self, domain: &str) -> usize` | Numero di IP distinti per dominio. |
| | `unique_ips()` | `(&self, domain: &str) -> Vec<Ipv4Addr>` | IP distinti per dominio. |
| `ExtractedString` | `new()` | `(value, offset, encoding) -> Self` | Stringa estratta da memoria con offset e encoding. |
| | `looks_like_domain()` | `(&self) -> bool` | Euristica: la stringa assomiglia a un FQDN. |
| | `looks_like_ip()` | `(&self) -> bool` | Euristica: la stringa assomiglia a un IP. |
| | `looks_like_url()` | `(&self) -> bool` | Euristica: la stringa assomiglia a un URL. |
| `C2Extractor` | `new()` | `() -> Self` | Costruttore con parametri di default. |
| | `extract_strings()` | `(&self, data: &[u8]) -> Vec<ExtractedString>` | Estrae stringhe ASCII (min 4 char) da blob grezzo. |
| | `extract_utf16le()` | `(&self, data: &[u8]) -> Vec<ExtractedString>` | Estrae stringhe UTF-16 LE da blob grezzo. |
| | `try_xor_decode()` | `(&self, data: &[u8], key: u8) -> Vec<u8>` | Decodifica XOR single-byte e restituisce i byte decodificati. |
| | `extract_xor_strings()` | `(&self, data: &[u8]) -> Vec<ExtractedString>` | Prova tutti i 255 key XOR e raccoglie le stringhe risultanti. |
| | `extract_urls()` | `(&self, text: &str) -> Vec<&str>` | Estrae URL (http/https/ftp) da testo con regex. |
| | `extract_ip_ports()` | `(&self, text: &str) -> Vec<(String, u16)>` | Estrae coppie `(ip, port)` da testo. |
| | `extract()` | `(&self, data: &[u8]) -> Result<C2Config, C2Error>` | Pipeline completa: estrae stringhe → riconosce pattern C2 → restituisce `C2Config`. |
| | `detect_dga_channels()` | `(&self, config: &C2Config) -> Vec<&C2Channel>` | Filtra i canali con dominio DGA. |

---

### `credential_harvester` — Furto credenziali

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `HarvestEvent` | `new()` | `(kind, target, pid, api_name) -> Self` | Evento di harvesting: tipo tecnica, store target, PID, API usata. |
| | `with_value()` | `(mut self, value) -> Self` | Aggiunge la credenziale recuperata. |
| | `tag()` | `(mut self, t) -> Self` | Builder per tag libero. |
| | `at_least()` | `(&self, min: HarvestSeverity) -> bool` | True se severità >= soglia. |
| `ApiCall` | `new()` | `(name, args) -> Self` | Costruisce una chiamata API da nome e argomenti. |
| `CredentialHarvester` | `new()` | `() -> Self` | Istanzia l'harvester con tutte le signature predefinite (DPAPI, LSA, CryptProtectData, SSPI, Mimikatz-like, ecc.). |
| | `process_call()` | `(&mut self, call: &ApiCall)` | Analizza una singola chiamata API e registra harvesting se rilevato. |
| | `process_trace()` | `(&mut self, calls: &[ApiCall])` | Elabora un'intera traccia API. |
| | `events()` | `(&self) -> &[HarvestEvent]` | Tutti gli eventi rilevati. |
| | `events_at_least()` | `(&self, min) -> Vec<&HarvestEvent>` | Filtra per severità minima. |
| | `max_severity()` | `(&self) -> Option<HarvestSeverity>` | Severità massima osservata. |
| | `has_critical()` | `(&self) -> bool` | True se esiste almeno un evento Critical. |
| | `targeted_stores()` | `(&self) -> Vec<&CredentialTarget>` | Store di credenziali distinti presi di mira. |
| | `technique_counts()` | `(&self) -> HashMap<String, usize>` | Conteggio per tecnica (DPAPI, LSA dump, token impersonation, …). |
| | `report()` | `(&self) -> String` | Report testuale con sommario delle tecniche e store colpiti. |
| `HarvesterReport` | `from_harvester()` | `(h: &CredentialHarvester) -> Self` | Costruisce un report strutturato serializzabile dall'harvester. |
| `CredentialScanner` | `scan()` | `(&self, input: &str) -> Vec<CandidateCredential>` | Cerca credential candidate (password, token, chiavi API) in un blob testuale con regex. |
| `CompositeHarvester` | `new()` | `() -> Self` | Harvester composito con tutti i sotto-moduli abilitati. |
| | `high_confidence()` | `() -> Self` | Variante con solo signature ad alta precisione. |
| | `ingest_api_calls()` | `(&mut self, calls: &[ApiCall])` | Alimenta tutti i moduli con la traccia API. |
| | `scan_strings()` | `(&self, blobs: &[&str]) -> Vec<CandidateCredential>` | Scansiona blob di stringhe per credential. |
| | `report()` | `(&self) -> HarvesterReport` | Report aggregato. |
| | `events()` | `(&self) -> &[HarvestEvent]` | Tutti gli eventi da tutti i sotto-moduli. |

---

### `crypto_key_finder` — Ricerca chiavi crittografiche

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `FoundCryptoKey` | `add_meta()` | `(&mut self, key, value)` | Aggiunge metadati (es. offset, algoritmo inferito). |
| `AesKeyFinder` | `find_aes128()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Cerca chiavi AES-128 mediante Rijndael key schedule detection. |
| | `find_raw_aes_keys()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Ricerca raw entropy-based per blocchi da 16/24/32 byte. |
| `PemKeyFinder` | `find_private_keys()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Cerca header PEM di chiavi private (RSA, EC, PKCS8). |
| | `find_public_keys()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Cerca header PEM di chiavi pubbliche e certificati X.509. |
| `CryptoKeyFinder` | `find()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Scanner multi-algoritmo: AES + PEM + pattern custom. |
| `XorKeyRecovery` | `recover_single_byte()` | `(&self, data: &[u8]) -> Option<FoundCryptoKey>` | Recupera chiave XOR a singolo byte per frequency analysis. |
| | `recover_key_of_length()` | `(&self, data: &[u8], key_len: usize) -> Option<FoundCryptoKey>` | Recupera chiave XOR multi-byte con Index of Coincidence. |
| | `auto_recover()` | `(&self, data: &[u8]) -> Option<FoundCryptoKey>` | Tenta il recovery automatico testando lunghezze 1–32. |
| | `known_plaintext()` | `(&self, ciphertext: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>` | Known-plaintext attack: XOR tra cifrato e plaintext noto per ricavare la chiave. |
| `KeyScanPipeline` | `scan_all()` | `(&self, data: &[u8]) -> Vec<FoundCryptoKey>` | Esegue tutti i finder disponibili sul dato grezzo. |
| | `scan_high_confidence()` | `(&self, data: &[u8], threshold: f32) -> Vec<FoundCryptoKey>` | Filtra solo i risultati con confidence >= threshold. |
| | `summary()` | `(keys: &[FoundCryptoKey]) -> String` | Stringa riassuntiva (algoritmo, offset, lunghezza) per ogni chiave trovata. |

---

### `dropper_analysis` — Analisi dropper

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `EncryptedPayload` | `new()` | `(offset, raw_bytes, scheme) -> Self` | Payload cifrato con schema di encoding (XOR, RC4, AES-CBC, …). |
| | `effective_len()` | `(&self) -> usize` | Lunghezza decodificata stimata. |
| | `add_note()` | `(&mut self, note)` | Aggiunge nota di analisi. |
| `DroppedFile` | `new()` | `(path, content) -> Self` | File droppato con contenuto grezzo. |
| | `sha256_hex()` | `(&self) -> String` | Digest SHA-256 hex del contenuto. |
| | `md5_hex()` | `(&self) -> String` | Digest MD5 hex del contenuto. |
| `DroppedProcess` | `new()` | `(image_path, command_line) -> Self` | Processo lanciato dal dropper. |
| `PayloadType` | `from_magic()` | `(bytes: &[u8]) -> Self` | Identifica il tipo payload da magic bytes (PE, ELF, ZIP, PDF, …). |
| `PayloadFinder` | `new()` | `() -> Self` | Istanzia il finder con pattern predefiniti. |
| | `find_payloads()` | `(&self, data: &[u8]) -> DropperResult<Vec<EncryptedPayload>>` | Cerca payload nascosti (XOR, base64, overlay PE) nel blob. |
| | `decrypt()` | `(&self, payload: &mut EncryptedPayload) -> DropperResult<()>` | Tenta la decifratura del payload in-place. |
| `DropperAnalyzer` | `new()` | `() -> Self` | Analizzatore completo dropper. |
| | `with_sample()` | `(mut self, path) -> Self` | Builder: imposta il percorso del campione. |
| | `analyse()` | `(&mut self, data: &[u8]) -> DropperResult<DropperReport>` | Pipeline completa: trova payload → decifra → classifica → costruisce report. |
| `DropperReport` | `add_dropped_file()` | `(&mut self, file: DroppedFile)` | Aggiunge file droppato al report. |
| | `add_dropped_process()` | `(&mut self, proc: DroppedProcess)` | Aggiunge processo droppato al report. |
| | `is_high_risk()` | `(&self) -> bool` | True se contiene PE eseguibili o processi. |
| | `executable_count()` | `(&self) -> usize` | Numero di eseguibili droppati. |
| | `has_persistence()` | `(&self) -> bool` | True se rilevato meccanismo di persistenza. |
| | `summary()` | `(&self) -> String` | Sommario testuale del report dropper. |
| | `to_json()` | `(&self) -> Result<String, serde_json::Error>` | Serializzazione JSON del report. |
| | `all_hashes()` | `(&self) -> Vec<String>` | Tutti gli hash SHA-256 dei file droppati. |

---

### `dropped_file_collector` — Raccolta file scartati

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `DroppedFileType` | `detect()` | `(header: &[u8], ext: &str) -> Self` | Identifica tipo da magic bytes e/o estensione. |
| `DroppedFile` | `new()` | `(path, pid, size, sha256, entropy) -> Self` | Costruttore completo. |
| | `set_header()` | `(&mut self, header: Vec<u8>)` | Imposta i primi N byte (magic). |
| | `extension()` | `(&self) -> &str` | Estensione del file. |
| | `file_name()` | `(&self) -> &str` | Nome file senza percorso. |
| | `is_high_entropy()` | `(&self) -> bool` | True se entropia > 7.2 (probabile cifratura/compressione). |
| | `tag()` | `(&mut self, t)` | Aggiunge tag classificatorio. |
| | `has_tag()` | `(&self, t: &str) -> bool` | Verifica presenza tag. |
| `DroppedFileCollector` | `new()` | `(config: CollectorConfig) -> Self` | Costruttore con configurazione. |
| | `default_config()` | `() -> Self` | Costruttore con policy predefinite (escludi .log, .tmp, ecc.). |
| | `ingest_raw()` | `(&mut self, line: &str) -> Result<bool, CollectorError>` | Interpreta una riga di log sandbox e aggiorna lo stato. |
| | `ingest_file()` | `(&mut self, f: &mut DroppedFile) -> Result<bool, CollectorError>` | Processa un file droppato già costruito. |
| | `collect()` | `(mut self) -> Vec<DroppedFile>` | Consuma il collector e restituisce tutti i file accettati. |
| | `ingest_log()` | `(&mut self, log: &str) -> HashMap<usize, CollectorError>` | Processa un intero log multi-riga; mappa riga→errore per i fallimenti. |
| | `ingest_directory()` | `(&mut self, dir: &Path) -> Result<(), CollectorError>` | Legge e processa tutti i file in una directory. |

---

### `file_artifact_collector` — Raccolta artefatti da filesystem

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `ArtifactKind` | `classify_by_path()` | `(path: &Path) -> Self` | Classifica l'artefatto (PE, script, config, data, …) dal percorso. |
| `FileArtifact` | `new()` | `(path, kind, pid) -> Self` | Artefatto su filesystem con percorso, tipo e PID proprietario. |
| | `detect_type_from_magic()` | `(magic: &[u8]) -> String` | Identifica tipo MIME/descrizione da magic bytes. |
| | `populate_from_content()` | `(&mut self, content: &[u8])` | Compila hash, entropia e magic a partire dai byte. |
| | `add_tag()` | `(&mut self, tag)` | Aggiunge tag libero. |
| | `is_executable()` | `(&self) -> bool` | True se PE, ELF o script eseguibile. |
| `MonitorRule` | `include_prefix()` | `(prefix) -> Self` | Regola di inclusione per prefisso percorso. |
| | `exclude_prefix()` | `(prefix) -> Self` | Regola di esclusione per prefisso percorso. |
| `FileMonitor` | `new()` | `() -> Self` | Monitor vuoto senza regole. |
| | `add_rule()` | `(&mut self, rule: MonitorRule)` | Aggiunge regola include/exclude. |
| | `record()` | `(&mut self, artifact: FileArtifact)` | Registra un artefatto se soddisfa le regole. |
| | `record_drop()` | `(&mut self, path, pid, content)` | Costruisce e registra un artefatto da path + bytes raw. |
| | `artifacts()` | `(&self) -> impl Iterator<Item = &FileArtifact>` | Iteratore su tutti gli artefatti registrati. |
| | `count()` | `(&self) -> usize` | Numero di artefatti. |
| | `executables()` | `(&self) -> Vec<&FileArtifact>` | Filtra solo gli eseguibili. |
| | `scripts()` | `(&self) -> Vec<&FileArtifact>` | Filtra solo gli script. |
| `FileArtifactCollector` | `new()` | `() -> Self` | Collector principale con lista monitor. |
| | `add_windows_exclusions()` | `(&mut self)` | Aggiunge esclusioni standard Windows (System32, WinSxS, …). |
| | `add_monitor()` | `(&mut self, monitor: FileMonitor)` | Aggiunge un monitor con le sue regole. |
| | `create_monitor()` | `(&mut self) -> &mut FileMonitor` | Crea e registra un nuovo monitor vuoto. |
| | `collect()` | `(&self) -> ArtifactReport` | Esegue la raccolta e produce il report aggregato. |
| `ArtifactReport` | `pe_artifacts()` | `(&self) -> Vec<&FileArtifact>` | Filtra artefatti di tipo PE. |
| | `with_tag()` | `(&self, tag: &str) -> Vec<&FileArtifact>` | Filtra per tag. |

---

### `memory_artifact_dumper` — Dump di memoria

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `MemoryArtifact` | `new()` | `(base_address, data, pid, prot) -> Self` | Regione di memoria con indirizzo base, dati, PID e protezione (R/W/X). |
| | `shannon_entropy()` | `(data: &[u8]) -> f64` | Entropia di Shannon del buffer. |
| | `detect_content()` | `(data: &[u8]) -> String` | Identifica il tipo di contenuto (PE header, shellcode, heap, stack, …). |
| | `add_tag()` | `(&mut self, t)` | Aggiunge tag. |
| | `is_high_entropy()` | `(&self) -> bool` | True se entropia > 7.0. |
| | `is_executable_content()` | `(&self) -> bool` | True se la regione ha permesso X o inizia con MZ/ELF. |
| | `read_cstring()` | `(&self, offset: usize) -> Option<String>` | Legge una C-string null-terminated dall'offset. |
| `StringContext` | `classify()` | `(s: &str) -> StringContext` | Classifica una stringa estratta (URL, path, registry key, IP, base64, …). |
| `MemoryDump` | `new()` | `(pid, process_name) -> Self` | Dump completo di un processo. |
| | `add_region()` | `(&mut self, region: MemoryArtifact)` | Aggiunge una regione al dump. |
| | `total_bytes()` | `(&self) -> usize` | Totale byte in tutte le regioni. |
| | `executable_regions()` | `(&self) -> Vec<&MemoryArtifact>` | Regioni con permesso di esecuzione. |
| `MemoryArtifactDumper` | `new()` | `(config: DumperConfig) -> Self` | Dumper con configurazione personalizzata. |
| | `with_defaults()` | `() -> Self` | Dumper con soglie di default (min_size=0x1000, min_entropy=6.5). |
| | `ingest_region()` | `(&mut self, base, data, pid, prot) -> Option<MemoryArtifact>` | Analizza e opzionalmente accetta una regione di memoria. |
| | `extract_strings()` | `(&self, artifact: &MemoryArtifact) -> Vec<HeapString>` | Estrae stringhe ASCII e UTF-16 con classificazione. |
| | `dumps()` | `(&self) -> impl Iterator<Item = &MemoryDump>` | Iteratore su tutti i dump. |
| | `dump_for_pid()` | `(&self, pid: u32) -> Option<&MemoryDump>` | Trova il dump per PID. |
| | `total_regions()` | `(&self) -> usize` | Numero totale di regioni ingested. |
| | `build_summary()` | `(&self) -> String` | Sommario: N processi, M regioni, byte totali, regioni high-entropy. |

---

### `network_artifact_extractor` — Artefatti di rete

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `NetworkArtifact` | `new()` | `(kind, pid) -> Self` | Evento di rete con tipo (DNS/TCP/HTTP/HTTPS) e PID. |
| | `with_payload()` | `(mut self, payload) -> Self` | Aggiunge payload grezzo. |
| | `add_tag()` | `(&mut self, t)` | Aggiunge tag. |
| `C2Pattern` | `new()` | `(name, family) -> Self` | Pattern di riconoscimento C2 (nome famiglia, pattern URL/UA/host/port). |
| | `matches_url()` | `(&self, url: &str) -> bool` | True se il pattern regex corrisponde all'URL. |
| | `matches_ua()` | `(&self, ua: &str) -> bool` | True se il pattern corrisponde allo User-Agent. |
| | `matches_host()` | `(&self, host: &str) -> bool` | True se il pattern corrisponde all'host. |
| | `matches_port()` | `(&self, port: u16) -> bool` | True se la porta è nel set C2. |
| `NetworkPayload` | `detect_type()` | `(data: &[u8]) -> (&'static str, u8)` | Identifica il protocollo applicativo e confidence (0–100). |
| | `new()` | `(session_id, dir, data, offset) -> Self` | Payload di rete con sessione, direzione e offset in pcap. |
| `NetworkArtifactExtractor` | `new()` | `() -> Self` | Estractor vuoto. |
| | `add_c2_pattern()` | `(&mut self, p)` | Aggiunge un pattern C2. |
| | `add_default_patterns()` | `(&mut self)` | Aggiunge pattern per famiglie note (Cobalt Strike, Emotet, Ursnif, …). |
| | `record()` | `(&mut self, event)` | Registra un artefatto di rete. |
| | `record_dns()` | `(&mut self, hostname, resolved, pid)` | Scorciatoia per eventi DNS. |
| | `record_tcp_connect()` | `(&mut self, dst_ip, dst_port, pid)` | Scorciatoia per TCP connect. |
| | `record_http()` | `(&mut self, method, url, host, pid)` | Scorciatoia per HTTP. |
| | `build_report()` | `(&mut self) -> NetworkReport` | Costruisce il report finale con C2 rilevati, IOC di rete e statistiche. |

---

### `malware_config_db` — Database configurazioni malware

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `FamilyExtractor` (trait) | `matches()` | `(&self, data: &[u8]) -> bool` | True se il dato sembra appartenere alla famiglia. |
| `ExtractedConfig` | `field()` | `(&self, name: &str) -> Option<&ConfigField>` | Recupera un campo per nome. |
| | `unique_c2s()` | `(&self) -> Vec<&str>` | Server C2 distinti presenti nella configurazione. |
| `ConfigDb` | `new()` | `() -> Self` | Database con tutti gli estrattori built-in (AgentTesla, Remcos, NjRAT, RedLine, …). |
| | `extractor_count()` | `(&self) -> usize` | Numero di estrattori registrati. |
| | `family_names()` | `(&self) -> Vec<&'static str>` | Nomi delle famiglie supportate. |
| | `identify()` | `(&self, data: &[u8]) -> Vec<&'static str>` | Identifica la/le famiglie che il dato potrebbe contenere. |
| | `extract_all()` | `(&self, data: &[u8]) -> Vec<Result<ExtractedConfig, ConfigDbError>>` | Prova tutti gli estrattori e raccoglie i risultati. |
| | `extract_for_family()` | `(&self, family, data) -> Result<ExtractedConfig, ConfigDbError>` | Estrae la configurazione per la famiglia specifica. |
| | `register()` | `(&mut self, extractor: Box<dyn FamilyExtractor>)` | Registra un estrattore personalizzato. |

---

### `ransomware_detector` — Rilevamento ransomware (comportamentale)

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `RansomwareDetector` | `new()` | `(thresholds, api_sig, str_sig) -> Self` | Costruttore con soglie e signature personalizzate. |
| | `finalize()` | `(&mut self)` | Calcola il punteggio finale dopo l'ingestione degli eventi. |
| | `analyze_strings()` | `(&self, strings: &[&str]) -> RansomwareDetectionResult` | Analizza stringhe (es. da dump) per pattern ransomware. |
| | `analyze_binary()` | `(&self, data: &[u8]) -> RansomwareDetectionResult` | Analisi statica del binario per feature ransomware. |
| | `analyze_api_calls()` | `(&self, api_names: &[&str]) -> RansomwareDetectionResult` | Rileva pattern API tipici di ransomware (CryptEncrypt, NtQuerySystemInformation, shadow delete). |
| `ExtensionPatterns` | `encrypted_extension_patterns()` | `(&self) -> &[&'static str]` | Elenco di pattern regex per estensioni cifrate note (.locky, .ryuk, …). |
| | `matches_encrypted_extension()` | `(&self, name: &str) -> bool` | True se il nome file matcha un'estensione cifrata nota. |

---

### `ransomware_analysis` — Analisi ransomware (strutturale)

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `RansomwareFamily` | `extensions()` | `(&self) -> Vec<&'static str>` | Estensioni file usate dalla famiglia. |
| `EncryptionDetector` | `detect()` | `(&self, api_calls, affected_files) -> EncryptionDetectionResult` | Rileva attività di cifratura correlando API e file modificati. |
| | `is_high_entropy()` | `(data: &[u8]) -> bool` | True se entropia Shannon > 7.5 (statica). |
| | `entropy()` | `(data: &[u8]) -> f64` | Calcola l'entropia di Shannon. |
| `ExtensionChangeDetector` | `new()` | `(known_families, threshold) -> Self` | Costruttore con famiglie note e soglia minima di cambi. |
| | `detect_changes()` | `(&self, before, after) -> Vec<ExtensionChange>` | Confronta snapshot prima/dopo e restituisce i cambi di estensione. |
| | `extension_frequency()` | `(changes: &[ExtensionChange]) -> HashMap<String, usize>` | Frequenza delle nuove estensioni. |
| | `identify_family()` | `(changes: &[ExtensionChange]) -> Option<RansomwareFamily>` | Identifica la famiglia ransomware dalla firma estensioni. |
| `ShadowDeletionDetector` | `detect_in_cmdlines()` | `(&self, cmdlines: &[&str]) -> Vec<ShadowDeletionEvidence>` | Cerca comandi di cancellazione VSS (vssadmin, wmic shadowcopy, bcdedit). |
| `ShadowDeletionEvidence` | `high_confidence()` | `(cmdline, tool) -> Self` | Costruttore per evidenza ad alta confidenza. |
| `RansomNoteParser` | `new()` | `(content, source_path) -> Self` | Parser per ransom note con contenuto e percorso sorgente. |
| | `is_valid_format()` | `(&self) -> bool` | True se il contenuto sembra una ransom note (parole chiave BTC, decrypt, contact). |
| `WalletExtractor` | `extract()` | `(&self, strings: &[&str]) -> Vec<WalletAddress>` | Estrae indirizzi wallet Bitcoin/Monero/Ethereum con regex. |
| `RansomNoteAnalyzer` | `new()` | `(notes, wallets, deadline_ts) -> Self` | Analizzatore di ransom note con deadline e wallet. |
| | `has_deadline()` | `(&self) -> bool` | True se la nota contiene un countdown o data limite. |
| | `mentions_data_leak()` | `(&self) -> bool` | True se la nota menziona pubblicazione dati (double extortion). |
| | `summary()` | `(&self) -> String` | Sommario: wallet, deadline, double extortion flag. |
| `RansomwareAnalysisReport` | `compute_confidence()` | `(&mut self)` | Calcola il punteggio di confidenza aggregato da tutti i sotto-segnali. |
| | `mock()` | `() -> Self` | Report fittizio per test. |

---

### `lib.rs` — Tipi core e pipeline principale

| Struct | Metodo | Firma sintetica | Descrizione |
|---|---|---|---|
| `DroppedFile` | `new()` | `(path, size, sha256) -> Self` | File droppato con percorso, dimensione e hash. |
| | `extension()` | `(&self) -> &str` | Estensione del file. |
| | `is_pe()` | `(&self) -> bool` | True se SHA256 o magic suggerisce PE. |
| | `is_elf()` | `(&self) -> bool` | True se ELF. |
| | `is_zip()` | `(&self) -> bool` | True se ZIP. |
| | `is_executable()` | `(&self) -> bool` | True se PE o ELF o script. |
| | `preview_entropy()` | `(&self) -> f64` | Entropia stimata dai primi byte disponibili. |
| `MemoryDump` | `new()` | `(pid, label, start_va, data) -> Self` | Dump di una regione con label e indirizzo base. |
| | `has_pe_header()` | `(&self) -> bool` | True se inizia con `MZ`. |
| | `entropy()` | `(&self) -> f64` | Entropia di Shannon del dump. |
| | `is_high_entropy()` | `(&self) -> bool` | True se entropia > 7.0. |
| | `extract_strings()` | `(&self, min_len: usize) -> Vec<String>` | Estrae stringhe ASCII di lunghezza minima. |
| `NetworkCapture` | `is_external()` | `(&self) -> bool` | True se destinazione è IP pubblico. |
| | `is_likely_c2()` | `(&self) -> bool` | True se porta o pattern suggerisce traffico C2. |
| `RegistryOp` | `is_persistence()` | `(&self) -> bool` | True se la chiave è in Run/RunOnce/Services/Startup. |
| `ProcessSpawn` | `is_shell()` | `(&self) -> bool` | True se l'immagine è cmd.exe o powershell.exe. |
| | `is_lolbin()` | `(&self) -> bool` | True se l'immagine è un Living-off-the-Land binary noto. |
| `PackerLayer` | `new()` | `(name, entropy, base_va, size) -> Self` | Layer packer con nome, entropia e posizione. |
| | `is_high_entropy()` | `(&self) -> bool` | True se entropia > 7.2. |
| `PackerDetector` | `new()` | `() -> Self` | Detector multi-packer (UPX, Themida, MPRESS, custom). |
| | `detect()` | `(&self, data: &[u8]) -> Vec<PackerLayer>` | Restituisce i layer packer trovati nel PE. |
| `ExtractedConfig` | `new()` | `(family, source) -> Self` | Configurazione estratta con famiglia e fonte. |
| | `add_field()` | `(&mut self, key, value)` | Aggiunge coppia chiave-valore. |
| | `field()` | `(&self, key: &str) -> Option<&str>` | Recupera valore per chiave. |
| `ConfigExtractor` | `extract_from_strings()` | `(&self, strings, family_hint) -> ExtractedConfig` | Estrae configurazione da slice di stringhe con hint famiglia. |
| | `extract_from_dump()` | `(&self, dump, family_hint) -> ExtractedConfig` | Estrae configurazione da dump di memoria. |
| `Artifact` | `new()` | `(kind, pid, desc) -> Self` | Artefatto generico con tipo, PID e descrizione. |
| `SandboxResult` | `add_artifact()` | `(&mut self, a)` | Aggiunge artefatto generico. |
| | `add_file()` | `(&mut self, f)` | Aggiunge file droppato. |
| | `add_network()` | `(&mut self, n)` | Aggiunge cattura di rete. |
| | `add_registry()` | `(&mut self, r)` | Aggiunge operazione di registro. |
| | `add_process()` | `(&mut self, p)` | Aggiunge processo spawnato. |
| | `add_memory_dump()` | `(&mut self, d)` | Aggiunge dump di memoria. |
| | `add_credential()` | `(&mut self, c)` | Aggiunge credenziale harvested. |
| | `add_packer_layer()` | `(&mut self, l)` | Aggiunge layer packer. |
| | `add_config()` | `(&mut self, c)` | Aggiunge configurazione estratta. |
| | `external_connections()` | `(&self) -> Vec<&NetworkCapture>` | Connessioni verso IP pubblici. |
| | `dropped_executables()` | `(&self) -> Vec<&DroppedFile>` | File droppati eseguibili. |
| | `persistence_ops()` | `(&self) -> Vec<&RegistryOp>` | Operazioni di registro verso chiavi di persistenza. |
| | `shell_spawns()` | `(&self) -> Vec<&ProcessSpawn>` | Lanci di shell. |
| | `lolbin_spawns()` | `(&self) -> Vec<&ProcessSpawn>` | Lanci di LOLBin. |
| | `high_entropy_dumps()` | `(&self) -> Vec<&MemoryDump>` | Dump ad alta entropia. |
| | `pe_dumps()` | `(&self) -> Vec<&MemoryDump>` | Dump con header PE. |
| | `mock()` | `() -> Self` | Istanza mock per test. |
| `ApiCall` | `new()` | `(name, args) -> Self` | Chiamata API con nome e argomenti. |
| `SandboxSession` | `new()` | `(sample_name, sha256) -> Self` | Sessione sandbox per un campione. |
| | `mock()` | `() -> Self` | Sessione mock. |
| `IocCollection` | `new()` | `() -> Self` | Collezione IOC vuota. |
| | `deduplicate()` | `(&mut self)` | Rimuove IOC duplicati. |
| | `merge()` | `(&mut self, other: Self)` | Fonde un'altra collezione. |
| | `from_api_trace()` | `(calls: &[ApiCall]) -> Self` | Costruisce da una traccia API. |
| | `from_network_pcap()` | `(pcap_bytes: &[u8]) -> Self` | Costruisce da dati pcap grezzi (parsing minimale). |
| | `from_dropped_files()` | `(files: &[DroppedFile]) -> Self` | Costruisce da file droppati. |
| `MalwareConfig` | `new()` | `(family) -> Self` | Configurazione malware con famiglia. |
| | `add_c2()` | `(&mut self, server)` | Aggiunge server C2. |
| | `set_extra()` | `(&mut self, key, value)` | Imposta campo extra. |
| | `key_hex()` | `(&self) -> Option<String>` | Chiave crittografica in hex se presente. |
| `SandboxArtifact` | `new()` | `(path, kind, pid, size) -> Self` | Artefatto sandbox con percorso, tipo, PID e dimensione. |
| | `kind_from_extension()` | `(ext: &str) -> SandboxArtifactKind` | Mappa estensione → tipo artefatto. |
| `SandboxEvent` | `new()` | `(ts_ms, pid, kind, detail) -> Self` | Evento sandbox con timestamp ms, PID, tipo e dettaglio. |
| `ArtifactExtractor` | `extract_dropped_files()` | `(&self, events) -> Vec<ExtractedDroppedFile>` | Estrae file droppati dagli eventi sandbox. |
| | `extract_network_payloads()` | `(&self, events) -> Vec<NetworkPayload>` | Estrae payload di rete dagli eventi. |
| | `extract_injected_code()` | `(&self, events) -> Vec<InjectedCode>` | Estrae codice iniettato (shellcode, PE reflective, …) dagli eventi. |
| `MemoryRegion` | `new()` | `(pid, start_addr, size, perms) -> Self` | Regione di memoria con permessi stringa (es. `"rwx"`). |
| | `is_executable()` | `(&self) -> bool` | True se `perms` contiene `x`. |
| | `dump_executable_regions()` | `(regions, reader_fn) -> Vec<MemoryDump>` | Legge e dumpa tutte le regioni eseguibili tramite callback. |

---

## Conteggio funzioni pubbliche

| Modulo | fn pub |
|---|---|
| `lib.rs` | 65 |
| `sandbox_report_normalizer` | 15 |
| `behavior_extractor` | 11 |
| `c2_extractor` | 35 |
| `credential_harvester` | 20 |
| `crypto_key_finder` | 13 |
| `dropper_analysis` | 19 |
| `dropped_file_collector` | 16 |
| `file_artifact_collector` | 22 |
| `malware_config_db` | 11 |
| `memory_artifact_dumper` | 20 |
| `network_artifact_extractor` | 19 |
| `ransomware_analysis` | 17 |
| `ransomware_detector` | 8 |
| **Totale** | **291** |
