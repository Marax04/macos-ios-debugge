# rustre-forensics-plugins

Crate di plugin forensici Volatility-style costruiti sopra `rustre-forensics` e `rustre-forensics-mem`.
Ogni plugin implementa `ForensicsPlugin` e può essere registrato in un `PluginRegistry` per dispatch uniforme.
Fornisce anche parser standalone per artefatti Windows (Registry, Prefetch, LNK, EVTX, MFT, browser, credenziali, rete, memoria).

**Dipendenze principali:** `rustre-forensics`, `rustre-core`, `rustre-forensics-mem`, `serde`, `serde_json`, `thiserror`, `subtle`

---

## Moduli top-level

| Modulo | Descrizione |
|--------|-------------|
| `volatility_plugins` | Plugin Volatility-style: process list, netstat, VAD, driver scan, injection detection |
| `memory_dump_plugin` | Parser di memory dump (raw/crash/minidump): range, stream, processi, moduli, PE header carving |
| `network_artifacts` | Strutture TCP/UDP/DNS/HTTP con query e filtraggio per stato, PID, host |
| `registry_hive_plugin` | Parser binario di hive di registro Windows con walker e ricerca |
| `prefetch_analyzer_plugin` | (re-export/wrapper) analisi .pf |
| `plugins::*` | Parser standalone per artefatti specifici (vedi sotto) |

---

## Funzioni pubbliche per modulo

### `volatility_plugins`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `ProcessEntry::is_system(&self) -> bool` | `&self` | `bool` | True se il processo è un processo di sistema (PID 4 o nome noto) |
| `ProcessEntry::is_alive(&self) -> bool` | `&self` | `bool` | True se il processo è ancora in esecuzione |
| `PluginOutput::to_json(&self) -> Result<String, serde_json::Error>` | `&self` | `Result<String, Error>` | Serializza l'output del plugin in JSON compatto |
| `PluginOutput::to_json_pretty(&self) -> Result<String, serde_json::Error>` | `&self` | `Result<String, Error>` | Serializza l'output del plugin in JSON indentato |
| `PluginArgs::new() -> Self` | — | `Self` | Crea un insieme di argomenti vuoto |
| `PluginArgs::set(self, key, value) -> Self` | `key: impl Into<String>`, `value: impl Into<String>` | `Self` (builder) | Aggiunge una coppia chiave/valore agli argomenti |
| `PluginArgs::get(&self, key: &str) -> Option<&str>` | `key: &str` | `Option<&str>` | Recupera il valore per chiave |
| `ProcessList::build(entries: Vec<ProcessEntry>) -> Self` | `Vec<ProcessEntry>` | `Self` | Costruisce la lista processi da un vettore di entry |
| `ProcessList::total_count(&self) -> usize` | `&self` | `usize` | Numero totale di processi |
| `ProcessList::find_pid(&self, pid: u32) -> Option<&ProcessEntry>` | `pid: u32` | `Option<&ProcessEntry>` | Cerca un processo per PID |
| `PluginRegistry::new() -> Self` | — | `Self` | Crea un registro plugin vuoto |
| `PluginRegistry::register(&mut self, plugin: Box<dyn VolatilityPlugin>)` | `Box<dyn VolatilityPlugin>` | — | Registra un plugin nel registry |
| `PluginRegistry::run(&self, name: &str, image: &dyn MemoryImage, args: &PluginArgs) -> ...` | nome plugin, immagine memoria, argomenti | `Result<PluginOutput, ForensicsError>` | Esegue il plugin per nome sull'immagine di memoria |
| `PluginRegistry::plugin_names(&self) -> Vec<&str>` | `&self` | `Vec<&str>` | Lista i nomi di tutti i plugin registrati |
| `PluginRegistry::count(&self) -> usize` | `&self` | `usize` | Numero di plugin registrati |
| `default_registry() -> PluginRegistry` | — | `PluginRegistry` | Crea un registry con tutti i plugin built-in pre-registrati |

---

### `registry_hive_plugin`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `RegCell::parse_data(&self, hbin_data: &[u8]) -> RegValue` | slice dati hbin | `RegValue` | Decodifica il contenuto raw di una cella di registro nel tipo corretto |
| `parse_hive_bytes(data: &[u8]) -> Result<RegistryHive, HiveError>` | slice bytes hive | `Result<RegistryHive, HiveError>` | Parsa un'intera hive di registro da bytes raw |
| `HiveWalker::new(hive: &'a RegistryHive) -> Self` | `&RegistryHive` | `Self` | Crea un walker per iterare ricorsivamente sulle chiavi |
| `walk_keys(hive: &RegistryHive) -> HiveWalker<'_>` | `&RegistryHive` | `HiveWalker` | Scorciatoia per creare un HiveWalker |
| `search_by_name<'a>(hive: &'a RegistryHive, query: &str) -> Vec<&'a RegistryKey>` | hive, query stringa | `Vec<&RegistryKey>` | Cerca chiavi il cui nome contiene la query (case-insensitive) |
| `search_by_value_data<'a>(hive: &'a RegistryHive, query: &str) -> Vec<&'a RegistryKey>` | hive, query stringa | `Vec<&RegistryKey>` | Cerca chiavi con valori che contengono la stringa query |
| `export_to_json(hive: &RegistryHive) -> String` | `&RegistryHive` | `String` (JSON) | Esporta l'intera hive come JSON strutturato |
| `deleted_key_scanner(data: &[u8]) -> Vec<NkCell>` | slice bytes raw | `Vec<NkCell>` | Cerca celle NK (Named Key) eliminate/orfane nei dati raw della hive |

---

### `memory_dump_plugin`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `DumpParser::detect_format(data: &[u8]) -> DumpFormat` | slice bytes | `DumpFormat` | Rileva il formato del dump (Raw/CrashDump/MiniDump) dal magic |
| `RawDumpParser::new(data: &'a [u8]) -> Self` | slice bytes | `Self` | Crea un parser per dump raw |
| `RawDumpParser::parse_ranges(&self) -> Vec<MemoryRange>` | `&self` | `Vec<MemoryRange>` | Estrae i range di memoria validi dal dump raw |
| `MiniDumpParser::parse_streams(&self, hdr: &MiniDumpHeader) -> Vec<MiniDumpStream>` | header minidump | `Vec<MiniDumpStream>` | Parsa tutti gli stream presenti nell'header MiniDump |
| `CrashDumpParser::extract_processes(&self) -> Vec<ProcessEntry>` | `&self` | `Vec<ProcessEntry>` | Estrae la lista processi da un crash dump Windows |
| `CrashDumpParser::extract_modules(&self) -> Vec<KernelModuleEntry>` | `&self` | `Vec<KernelModuleEntry>` | Estrae la lista moduli kernel dal crash dump |
| `CrashDumpParser::search_pattern(&self, pattern: &[u8]) -> Vec<u64>` | pattern bytes | `Vec<u64>` (offset) | Cerca un pattern di bytes nell'intero dump, restituisce offset |
| `CrashDumpParser::carve_strings(&self, min_len: usize) -> Vec<(u64, String)>` | lunghezza minima | `Vec<(u64, String)>` | Estrae stringhe ASCII/UTF-16 dal dump con il loro indirizzo |
| `CrashDumpParser::find_pe_headers(&self) -> Vec<u64>` | `&self` | `Vec<u64>` | Individua gli offset dei magic MZ (PE header) nel dump |
| `CrashDumpParser::compute_statistics(&self) -> DumpStats` | `&self` | `DumpStats` | Calcola statistiche sul dump (entropia, distribuzione byte, ecc.) |
| `DumpAnalyzer::analyze(&self, data: &[u8]) -> DumpStats` | slice bytes dump | `DumpStats` | Analizza un singolo dump |
| `DumpAnalyzer::analyze_all<'a>(&self, dumps: &[&'a [u8]]) -> Vec<DumpStats>` | slice di slice dump | `Vec<DumpStats>` | Analizza più dump in batch |

---

### `network_artifacts` (top-level)

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `TcpEntry::with_process(self, name) -> Self` | nome processo | `Self` | Associa un nome processo all'entry TCP |
| `TcpEntry::is_established(&self) -> bool` | — | `bool` | True se lo stato è ESTABLISHED |
| `TcpEntry::is_listening(&self) -> bool` | — | `bool` | True se lo stato è LISTEN |
| `TcpTable::new() -> Self` | — | `Self` | Crea una tabella TCP vuota |
| `TcpTable::add(&mut self, entry: TcpEntry)` | `TcpEntry` | — | Aggiunge una entry alla tabella |
| `TcpTable::all(&self) -> &[TcpEntry]` | — | `&[TcpEntry]` | Restituisce tutte le entry |
| `TcpTable::established(&self) -> Vec<&TcpEntry>` | — | `Vec<&TcpEntry>` | Filtra le connessioni ESTABLISHED |
| `TcpTable::listening(&self) -> Vec<&TcpEntry>` | — | `Vec<&TcpEntry>` | Filtra le porte in ascolto |
| `TcpTable::by_pid(&self, pid: u32) -> Vec<&TcpEntry>` | PID | `Vec<&TcpEntry>` | Filtra per PID |
| `TcpTable::by_state(&self, state: ConnectionState) -> Vec<&TcpEntry>` | stato | `Vec<&TcpEntry>` | Filtra per stato di connessione |
| `TcpTable::unique_remote_ips(&self) -> Vec<IpAddr>` | — | `Vec<IpAddr>` | IP remoti univoci |
| `TcpTable::unique_pids(&self) -> Vec<u32>` | — | `Vec<u32>` | PID univoci con connessioni TCP |
| `TcpTable::outbound_count(&self) -> usize` | — | `usize` | Numero di connessioni outbound |
| `UdpEntry::with_process(self, name) -> Self` | nome processo | `Self` | Associa nome processo all'entry UDP |
| `UdpTable::new() -> Self` | — | `Self` | Crea tabella UDP vuota |
| `UdpTable::add(&mut self, entry: UdpEntry)` | `UdpEntry` | — | Aggiunge entry UDP |
| `UdpTable::all(&self) -> &[UdpEntry]` | — | `&[UdpEntry]` | Tutte le entry UDP |
| `UdpTable::by_pid(&self, pid: u32) -> Vec<&UdpEntry>` | PID | `Vec<&UdpEntry>` | Filtra per PID |
| `UdpTable::listening_ports(&self) -> Vec<u16>` | — | `Vec<u16>` | Porte UDP in ascolto |
| `UdpTable::unique_pids(&self) -> Vec<u32>` | — | `Vec<u32>` | PID univoci |
| `DnsCacheEntry::new(hostname, rtype) -> Self` | hostname, tipo record | `Self` | Crea entry DNS cache |
| `DnsCacheEntry::with_ip(self, ip: IpAddr) -> Self` | IP | `Self` | Aggiunge indirizzo IP all'entry |
| `DnsCacheEntry::is_a_record(&self) -> bool` | — | `bool` | True se è un record A (IPv4) |
| `DnsCache::new() -> Self` | — | `Self` | Crea cache DNS vuota |
| `DnsCache::add(&mut self, entry: DnsCacheEntry)` | `DnsCacheEntry` | — | Aggiunge entry |
| `DnsCache::all(&self) -> &[DnsCacheEntry]` | — | `&[DnsCacheEntry]` | Tutte le entry |
| `DnsCache::lookup(&self, hostname: &str) -> Option<&DnsCacheEntry>` | hostname | `Option<&DnsCacheEntry>` | Cerca per hostname esatto |
| `DnsCache::a_records(&self) -> Vec<&DnsCacheEntry>` | — | `Vec<&DnsCacheEntry>` | Solo record A |
| `DnsCache::for_ip(&self, ip: IpAddr) -> Vec<&DnsCacheEntry>` | IP | `Vec<&DnsCacheEntry>` | Entry che risolvono a quell'IP |
| `DnsCache::unique_hostnames(&self) -> Vec<String>` | — | `Vec<String>` | Hostname univoci |
| `HttpCacheEntry::new(url, method) -> Self` | URL, metodo HTTP | `Self` | Crea entry cache HTTP |
| `HttpCacheEntry::with_user_agent(self, ua) -> Self` | User-Agent | `Self` | Imposta user agent |
| `HttpCacheEntry::is_post(&self) -> bool` | — | `bool` | True se metodo è POST |
| `HttpCacheEntry::is_get(&self) -> bool` | — | `bool` | True se metodo è GET |
| `HttpCacheEntry::is_success(&self) -> bool` | — | `bool` | True se status 2xx |
| `HttpCache::new() -> Self` | — | `Self` | Crea cache HTTP vuota |
| `HttpCache::add(&mut self, entry: HttpCacheEntry)` | `HttpCacheEntry` | — | Aggiunge entry |
| `HttpCache::all(&self) -> &[HttpCacheEntry]` | — | `&[HttpCacheEntry]` | Tutte le entry |
| `HttpCache::by_host(&self, host: &str) -> Vec<&HttpCacheEntry>` | hostname | `Vec<&HttpCacheEntry>` | Filtra per host |
| `HttpCache::post_requests(&self) -> Vec<&HttpCacheEntry>` | — | `Vec<&HttpCacheEntry>` | Solo richieste POST |
| `HttpCache::unique_hosts(&self) -> Vec<String>` | — | `Vec<String>` | Host univoci |
| `HttpCache::suspicious_user_agents(&self) -> Vec<&HttpCacheEntry>` | — | `Vec<&HttpCacheEntry>` | Entry con user agent sospetti (pattern malware noti) |
| `NetworkReport::build(entries: ...) -> Self` | TCP+UDP+DNS+HTTP | `Self` | Costruisce report completo da tutte le sorgenti |
| `NetworkCorrelator::new() -> Self` | — | `Self` | Crea correlatore rete vuoto |
| `NetworkCorrelator::add_tcp(&mut self, entry: TcpEntry)` | `TcpEntry` | — | Aggiunge entry TCP |
| `NetworkCorrelator::add_udp(&mut self, entry: UdpEntry)` | `UdpEntry` | — | Aggiunge entry UDP |
| `NetworkCorrelator::add_dns(&mut self, entry: DnsCacheEntry)` | `DnsCacheEntry` | — | Aggiunge entry DNS |
| `NetworkCorrelator::add_http(&mut self, entry: HttpCacheEntry)` | `HttpCacheEntry` | — | Aggiunge entry HTTP |
| `NetworkCorrelator::report(&self) -> NetworkReport` | — | `NetworkReport` | Genera report aggregato |
| `NetworkCorrelator::external_tcp(&self) -> Vec<&TcpEntry>` | — | `Vec<&TcpEntry>` | Connessioni TCP verso IP pubblici (non RFC1918) |
| `NetworkCorrelator::suspicious_pids(&self) -> Vec<u32>` | — | `Vec<u32>` | PID con pattern di rete sospetti |
| `NetworkCorrelator::resolve_tcp_ip(&self, entry: &TcpEntry) -> Vec<String>` | `&TcpEntry` | `Vec<String>` | Risolve l'IP remoto tramite DNS cache incrociata |
| `NetworkCorrelator::processes_with_tcp_and_udp(&self) -> Vec<u32>` | — | `Vec<u32>` | PID che usano sia TCP che UDP |

---

### `lib.rs` (plugin Volatility inline)

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `HookDetector::looks_hooked(bytes: &[u8]) -> bool` | bytes del prologo funzione | `bool` | True se i primi byte contengono un JMP/CALL tipico di hooking |
| `VadRegion::perms_string(p: u8) -> String` | byte permessi VAD | `String` | Converte i bit di permesso VAD in stringa leggibile (es. "r-x") |
| `StringExtractor::extract_strings(data: &[u8], min_len: usize) -> Vec<String>` | dati, lunghezza minima | `Vec<String>` | Estrae stringhe ASCII e UTF-16 da un blocco di memoria |
| `ByteRule::new(name: &str, description: &str, patterns: Vec<Vec<u8>>) -> Self` | nome, descrizione, pattern bytes | `Self` | Crea una regola di rilevamento basata su pattern byte |
| `ByteRule::matches(&self, data: &[u8]) -> bool` | slice dati | `bool` | True se almeno un pattern corrisponde nei dati |
| `builtin_rules() -> Vec<ByteRule>` | — | `Vec<ByteRule>` | Restituisce le regole built-in (shellcode, packer, crypto stubs ecc.) |
| `ByteScanner::with_builtin_rules() -> Self` | — | `Self` | Crea uno scanner con tutte le regole built-in caricate |
| `TokenPrivileges::priv_name(luid: u32) -> &'static str` | LUID privilegio | `&'static str` | Nome testuale del privilegio Windows (es. "SeDebugPrivilege") |
| `PathHeuristics::is_suspicious_path(path: &str) -> bool` | path stringa | `bool` | True se il path è in una posizione sospetta (Temp, AppData, ecc.) |
| `EntropyScanner::scan_high_entropy(&self, image, threshold) -> Vec<MemoryRegion>` | immagine, soglia entropia | `Vec<MemoryRegion>` | Trova regioni di memoria con entropia Shannon sopra soglia |
| `VadPlugin::run(image: &dyn MemoryImage) -> Vec<VadEntry>` | immagine memoria | `Vec<VadEntry>` | Elenca tutti i VAD node del processo corrente |
| `VadPlugin::find_suspicious_vads(vads: &[VadEntry]) -> Vec<VadEntry>` | slice VAD | `Vec<VadEntry>` | Filtra VAD con combinazione sospetta (RWX, no nome, alta entropia) |
| `SamPlugin::extract_sam_hashes(image: &dyn MemoryImage) -> Vec<SamEntry>` | immagine memoria | `Vec<SamEntry>` | Estrae hash NTLM/LM dal database SAM in memoria |
| `InjectionScanner::scan(image, processes) -> Vec<InjectionFinding>` | immagine, lista processi | `Vec<InjectionFinding>` | Rileva code injection (DLL injection, process hollowing, reflective) |
| `DriverPlugin::list_drivers(image: &dyn MemoryImage) -> Vec<DriverInfo>` | immagine memoria | `Vec<DriverInfo>` | Lista tutti i driver kernel caricati |
| `DriverPlugin::is_suspicious_driver(d: &DriverInfo) -> bool` | `&DriverInfo` | `bool` | True se il driver è senza firma, in path anomalo o con nome mascherato |
| `HivePlugin::find_hives(image: &dyn MemoryImage) -> Vec<HiveInfo>` | immagine memoria | `Vec<HiveInfo>` | Individua le hive di registro mappate in memoria |
| `StringsPlugin::scan_strings_in_process(image, pid, min_len) -> Vec<String>` | immagine, PID, lunghezza min | `Vec<String>` | Estrae stringhe da tutte le regioni di un processo specifico |
| `register_all(registry: &mut rustre_forensics::PluginRegistry)` | `&mut PluginRegistry` | — | Registra tutti i plugin di questo crate nel registry globale |

---

### `plugins::browser_history`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `BrowserProfile::from_path(path: &str) -> Self` | path directory profilo | `Self` | Crea un profilo browser dal path del profilo utente |
| `is_sqlite(data: &[u8]) -> bool` | slice bytes | `bool` | True se il magic corrisponde a un database SQLite |
| `sqlite_page_size(data: &[u8]) -> Option<u16>` | slice bytes SQLite | `Option<u16>` | Legge la page size dall'header SQLite |
| `sqlite_user_version(data: &[u8]) -> Option<u32>` | slice bytes SQLite | `Option<u32>` | Legge il user_version dall'header SQLite |
| `HistoryEntry::is_potentially_malicious(&self) -> bool` | — | `bool` | True se l'URL corrisponde a pattern di download malware o C2 |
| `FormData::looks_like_credential(&self) -> bool` | — | `bool` | True se i dati form sembrano credenziali (campo password/user) |
| `BrowserScanner::scan_urls(data: &[u8]) -> Vec<String>` | dati grezzi | `Vec<String>` | Estrae URL da dati grezzi tramite regex/pattern matching |
| `BrowserScanner::scan_cookie_strings(data: &[u8]) -> Vec<CookieRecord>` | dati grezzi | `Vec<CookieRecord>` | Estrae record cookie da dati browser grezzi |
| `BrowserScanner::summarize(data, browser) -> BrowserArtifactSummary` | dati, tipo browser | `BrowserArtifactSummary` | Produce un riepilogo completo degli artefatti browser |
| `extract_domains(urls: &[String]) -> Vec<String>` | lista URL | `Vec<String>` | Estrae il dominio da ciascun URL (deduplicato) |
| `PasswordEntry::is_insecure(&self) -> bool` | — | `bool` | True se la password è salvata su HTTP |
| `FirefoxScanner::scan_login_origins(data: &[u8]) -> Vec<String>` | dati grezzi | `Vec<String>` | Estrae origini login da file Firefox |
| `ChromeScanner::scan_domains(data: &[u8]) -> Vec<String>` | dati grezzi | `Vec<String>` | Estrae domini visitati da artefatti Chrome |
| `EdgeDetector::looks_like_edge(data: &[u8]) -> bool` | dati grezzi | `bool` | Euristiche per riconoscere artefatti Edge |
| `BrowserAnalyzer::analyze(data, hint_path) -> BrowserArtifactSummary` | dati, path opzionale | `BrowserArtifactSummary` | Analisi unificata auto-detecting il tipo browser |
| `BrowserAnalyzer::classify_urls(urls) -> HashMap<String, Vec<String>>` | slice URL | `HashMap<categoria, Vec<URL>>` | Classifica URL per categoria (social, mail, cloud, sospetti, ecc.) |

---

### `plugins::credential_artifacts`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `NtlmHash::from_slice(s: &[u8]) -> Result<Self, CredentialError>` | 16 bytes | `Result<Self, Error>` | Crea un hash NTLM da 16 byte raw |
| `NtlmHash::from_hex(hex: &str) -> Result<Self, CredentialError>` | stringa hex | `Result<Self, Error>` | Parsa hash NTLM da stringa esadecimale |
| `NtlmHash::to_hex(&self) -> String` | — | `String` | Converte l'hash NTLM in stringa hex lowercase |
| `NtlmHash::is_blank_password(&self) -> bool` | — | `bool` | True se corrisponde all'hash NTLM di stringa vuota |
| `NtlmHash::is_lm_disabled(&self) -> bool` | — | `bool` | True se il campo LM indica hash disabilitato (aad3b...) |
| `SamEntry::parse(line: &str) -> Option<Self>` | riga formato pwdump | `Option<Self>` | Parsa una riga in formato `user:RID:LM:NT:::` |
| `SamEntry::has_valid_nt_hash(&self) -> bool` | — | `bool` | True se l'hash NT è presente e non è quello di password vuota |
| `SamEntry::lm_enabled(&self) -> bool` | — | `bool` | True se l'hash LM è diverso dal placeholder di disabilitato |
| `LsassCredential::has_cleartext(&self) -> bool` | — | `bool` | True se la credenziale include password in chiaro (wdigest) |
| `LsassCredential::severity(&self) -> u8` | — | `u8` | Livello di criticità (0-3) in base al tipo di credenziale trovata |
| `LsassScanner::scan_wdigest(data: &[u8]) -> Vec<LsassCredential>` | dati memoria LSASS | `Vec<LsassCredential>` | Cerca strutture WDigest con credenziali in chiaro |
| `LsassScanner::scan_nt_hashes(data: &[u8]) -> Vec<(u64, NtlmHash)>` | dati memoria | `Vec<(u64, NtlmHash)>` | Trova hash NTLM con il loro offset in memoria |
| `LsassScanner::scan(data: &[u8]) -> Vec<LsassCredential>` | dati dump LSASS | `Vec<LsassCredential>` | Scan completo LSASS per tutti i tipi di credenziale |
| `KerberosScanner::scan(data: &[u8]) -> Vec<KerberosTicket>` | dati memoria | `Vec<KerberosTicket>` | Estrae ticket Kerberos (TGT/TGS) da memoria |
| `DpapiBlob::is_default_provider(&self) -> bool` | — | `bool` | True se il blob usa il provider DPAPI default |
| `DpapiBlob::is_browser_credential(&self) -> bool` | — | `bool` | True se il blob è associato a un browser (Chrome/Edge credential) |
| `DpapiScanner::scan(data: &[u8]) -> Vec<DpapiBlob>` | dati raw | `Vec<DpapiBlob>` | Cerca strutture DPAPI blob nei dati |
| `DpapiScanner::find_masterkey_guids(data: &[u8]) -> Vec<String>` | dati raw | `Vec<String>` (GUID) | Estrae GUID di master key DPAPI |
| `CredentialReport::cleartext_creds(&self) -> Vec<&LsassCredential>` | — | `Vec<&LsassCredential>` | Solo credenziali con password in chiaro |
| `CredentialReport::to_row_map(&self) -> HashMap<String, String>` | — | `HashMap<String,String>` | Esporta il report come mappa chiave-valore per output tabellare |
| `CredentialReport::from_bytes(data: &[u8]) -> Self` | dati dump | `Self` | Costruisce il report completo analizzando il dump in ingresso |

---

### `plugins::file_timeline`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `Timestamps::earliest(&self) -> i64` | — | `i64` (Unix ts) | Il timestamp più antico tra Created/Modified/Access/MFT |
| `Timestamps::latest(&self) -> i64` | — | `i64` (Unix ts) | Il timestamp più recente |
| `MftEntry::parse(data: &[u8], record_number: u64) -> Result<Self, TimelineError>` | 1024 bytes record MFT, numero record | `Result<Self, Error>` | Parsa un singolo record MFT |
| `MftScanner::scan(data: &[u8]) -> Vec<MftEntry>` | immagine MFT raw | `Vec<MftEntry>` | Estrae tutti i record MFT validi da un dump MFT |
| `MftScanner::scan_small(data: &[u8]) -> Vec<MftEntry>` | slice dati | `Vec<MftEntry>` | Variante ottimizzata per piccoli frammenti MFT |
| `TimelineBuilder::from_mft(entries: &[MftEntry]) -> Vec<TimelineEvent>` | slice entry MFT | `Vec<TimelineEvent>` | Converte entry MFT in eventi timeline ordinati per timestamp |
| `TimelineBuilder::group_by_day(events: &[TimelineEvent]) -> HashMap<String, Vec<&TimelineEvent>>` | slice eventi | `HashMap<data, Vec<evento>>` | Raggruppa gli eventi per giorno (chiave "YYYY-MM-DD") |
| `UsnScanner::parse(data: &[u8]) -> Vec<UsnRecord>` | dati USN Journal | `Vec<UsnRecord>` | Parsa record dal Change Journal NTFS (USN) |
| `UsnScanner::to_timeline_events(records: &[UsnRecord]) -> Vec<TimelineEvent>` | slice record USN | `Vec<TimelineEvent>` | Converte record USN in eventi timeline |

---

### `plugins::memory_strings`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `ExtractedString::new(address: u64, value: String, encoding: &str) -> Self` | indirizzo, valore, encoding | `Self` | Crea una stringa estratta con metadati |
| `AsciiExtractor::extract(&self, data: &[u8], base_addr: u64) -> Vec<ExtractedString>` | dati, indirizzo base | `Vec<ExtractedString>` | Estrae stringhe ASCII dalla regione |
| `Utf16Extractor::extract(&self, data: &[u8], base_addr: u64) -> Vec<ExtractedString>` | dati, indirizzo base | `Vec<ExtractedString>` | Estrae stringhe UTF-16LE dalla regione |
| `StringClassifier::classify(s: &str) -> StringClass` | stringa | `StringClass` | Classifica la stringa (URL, IP, path, credential, GUID, ecc.) |
| `StringClassifier::is_url(s: &str) -> bool` | stringa | `bool` | True se la stringa è un URL |
| `StringClassifier::is_ipv4(s: &str) -> bool` | stringa | `bool` | True se la stringa è un IPv4 valido |
| `StringClassifier::is_ipv6(s: &str) -> bool` | stringa | `bool` | True se la stringa è un IPv6 valido |
| `StringClassifier::is_email(s: &str) -> bool` | stringa | `bool` | True se la stringa è un indirizzo email |
| `StringClassifier::is_guid(s: &str) -> bool` | stringa | `bool` | True se la stringa è un GUID nel formato standard |
| `StringClassifier::is_registry_key(s: &str) -> bool` | stringa | `bool` | True se la stringa sembra un percorso di registro (HKLM\...) |
| `StringClassifier::is_windows_path(s: &str) -> bool` | stringa | `bool` | True se sembra un path Windows |
| `StringClassifier::is_unix_path(s: &str) -> bool` | stringa | `bool` | True se sembra un path Unix/Linux |
| `StringClassifier::is_credential(s: &str) -> bool` | stringa | `bool` | True se contiene pattern di credenziale (password=, token:, ecc.) |
| `StringClassifier::is_command_line(s: &str) -> bool` | stringa | `bool` | True se sembra una command line con flag/opzioni |
| `StringClassifier::is_hex_blob(s: &str) -> bool` | stringa | `bool` | True se è una sequenza hex pura |
| `StringClassifier::is_base64(s: &str) -> bool` | stringa | `bool` | True se sembra base64 valido |
| `StringClassifier::is_domain(s: &str) -> bool` | stringa | `bool` | True se è un dominio DNS valido |
| `StringClassifier::is_pe_symbol(s: &str) -> bool` | stringa | `bool` | True se è un simbolo PE (mangled/thunk/export naming) |
| `StringClassifier::classify_batch(strings: &[ExtractedString]) -> HashMap<String, usize>` | slice stringhe | `HashMap<classe, conteggio>` | Classifica in batch e restituisce conteggi per categoria |
| `IpExtractor::extract_from_bytes(data: &[u8]) -> Vec<String>` | dati raw | `Vec<String>` | Estrae indirizzi IP leggibili dai dati raw |
| `IpExtractor::from_strings(strings: &[ExtractedString]) -> Vec<String>` | slice stringhe estratte | `Vec<String>` | Filtra IP da un insieme di stringhe già estratte |
| `IpExtractor::extract_ipv4_from_str(s: &str) -> Vec<String>` | stringa | `Vec<String>` | Estrae tutti gli IPv4 da una singola stringa |
| `IpExtractor::is_private_ipv4(s: &str) -> bool` | indirizzo IP | `bool` | True se l'IP è in RFC1918 (10/8, 172.16/12, 192.168/16) |
| `CredentialPatternDetector::detect(strings: &[ExtractedString]) -> Vec<CredentialPattern>` | slice stringhe | `Vec<CredentialPattern>` | Rileva pattern di credenziali nelle stringhe estratte |
| `NtHashScanner::scan_nt_hashes(data: &[u8]) -> Vec<(u64, String)>` | dati raw | `Vec<(u64, String)>` | Trova hash NTLM a 32 char hex con i loro offset |
| `MemoryStringAnalysis::analyze(data, base_addr, min_len) -> Self` | dati, addr base, lunghezza min | `Self` | Analisi completa: estrae, classifica e correla tutte le stringhe |

---

### `plugins::network_artifacts`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `MacAddress::from_slice(s: &[u8]) -> Result<Self, NetworkArtifactError>` | 6 bytes | `Result<Self, Error>` | Crea un MAC address da 6 byte |
| `MacAddress::to_string_colon(&self) -> String` | — | `String` | Formato "AA:BB:CC:DD:EE:FF" |
| `MacAddress::oui(&self) -> String` | — | `String` | Restituisce i primi 3 byte come OUI (vendor) |
| `MacAddress::is_broadcast(&self) -> bool` | — | `bool` | True se è l'indirizzo broadcast FF:FF:FF:FF:FF:FF |
| `ArpScanner::scan(data: &[u8]) -> Vec<ArpEntry>` | dati memoria/cache | `Vec<ArpEntry>` | Estrae entry dalla cache ARP |
| `DnsCacheEntry::as_str(&self) -> String` | — | `String` | Rappresentazione testuale dell'entry DNS |
| `DnsCacheScanner::scan(data: &[u8]) -> Vec<DnsCacheEntry>` | dati raw | `Vec<DnsCacheEntry>` | Estrae entry dalla cache DNS di sistema |
| `DomainAnalyzer::is_suspicious_domain(name: &str) -> bool` | nome dominio | `bool` | True se il dominio ha caratteristiche sospette (DGA, typosquatting, TLD rari) |
| `NetstatEntry::is_suspicious(&self) -> bool` | — | `bool` | True se la connessione è verso porta/IP sospetto |
| `NetstatDiff::diff(before, after) -> Self` | due snapshot netstat | `Self` | Calcola differenza tra due snapshot (connessioni nuove/chiuse) |
| `UrlScanner::scan(data: &[u8]) -> Vec<String>` | dati raw | `Vec<String>` | Estrae URL da dati grezzi di memoria/cache |

---

### `plugins::event_log`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `EvtxChunkHeader::parse(data: &[u8]) -> Result<Self, EvtxError>` | 512 bytes header chunk | `Result<Self, Error>` | Parsa l'header di un chunk EVTX |
| `EventRecord::parse(data: &[u8], offset: usize) -> Result<Self, EvtxError>` | dati, offset | `Result<Self, Error>` | Parsa un singolo record evento EVTX |
| `EventRecord::summary(&self) -> String` | — | `String` | Descrizione testuale breve dell'evento |
| `parse_records_from_chunk(chunk_data: &[u8]) -> Vec<EventRecord>` | dati chunk | `Vec<EventRecord>` | Parsa tutti i record in un chunk EVTX |
| `event_id_description(provider: &str, event_id: u32) -> &'static str` | provider, event ID | `&'static str` | Descrizione testuale per event ID noti (Security, System, Application) |
| `EvtxParser::find_chunk_offsets(data: &[u8]) -> Vec<usize>` | file EVTX raw | `Vec<usize>` | Trova gli offset di tutti i chunk nel file |
| `EvtxParser::parse_file(data: &[u8]) -> Result<Vec<EventRecord>, EvtxError>` | file EVTX raw | `Result<Vec<EventRecord>, Error>` | Parsa un intero file EVTX |
| `EvtxParser::summarize(records: &[EventRecord]) -> HashMap<String, usize>` | slice record | `HashMap<event_id, conteggio>` | Conta gli eventi per Event ID |
| `EvtxParser::filter_by_event_id(records, event_id) -> Vec<&EventRecord>` | slice record, ID | `Vec<&EventRecord>` | Filtra per Event ID specifico |
| `EvtxParser::filter_by_provider<'a>(records, provider) -> Vec<&'a EventRecord>` | slice record, provider | `Vec<&EventRecord>` | Filtra per provider (es. "Microsoft-Windows-Security-Auditing") |
| `EvtxParser::find_suspicious(records: &[EventRecord]) -> Vec<&EventRecord>` | slice record | `Vec<&EventRecord>` | Filtra eventi sospetti (4624/4625/4688/7045/ecc.) |
| `EventLevel::from_str(s: &str) -> Self` | stringa livello | `Self` | Parsa il livello da stringa ("Error", "Warning", ecc.) |

---

### `plugins::lnk_parser`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `ShellLinkHeader::parse(data: &[u8]) -> Result<Self, LnkError>` | 76 byte header | `Result<Self, Error>` | Parsa l'header di un file .lnk (Shell Link) |
| `LinkTargetIdList::parse(data: &[u8]) -> Result<Self, LnkError>` | dati .lnk | `Result<Self, Error>` | Parsa la ID List del target |
| `LinkTargetIdList::target_path(&self) -> String` | — | `String` | Ricostruisce il path del target dalla ID List |
| `StringData::parse(data, offset, flags, is_unicode) -> Self` | dati, offset, flags, encoding | `Self` | Parsa un blocco StringData (nome, args, working dir, ecc.) |
| `ExtraDataBlock::parse_all(data: &[u8], offset: usize) -> Vec<Self>` | dati, offset | `Vec<Self>` | Parsa tutti i blocchi extra dati (TrackerData, SpecialFolder, ecc.) |
| `LnkFile::parse(data: &[u8]) -> Result<Self, LnkError>` | file .lnk raw | `Result<Self, Error>` | Parsa un intero file .lnk |
| `LnkFile::target_path(&self) -> String` | — | `String` | Path assoluto del target del collegamento |
| `LnkFile::to_row(&self) -> HashMap<String, String>` | — | `HashMap<String,String>` | Esporta tutti i campi come mappa per output tabellare |
| `LnkFile::is_suspicious(&self) -> bool` | — | `bool` | True se il .lnk punta a path sospetti, usa argomenti PowerShell/cmd, ecc. |

---

### `plugins::process_artifacts`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `EprocessEntry::has_suspicious_name(&self) -> bool` | — | `bool` | True se il nome processo è mascherato o somiglia a un processo di sistema |
| `EprocessWalker::walk(&self, memory, base_addr, start_addr) -> Vec<EprocessEntry>` | memoria, addr base, addr start | `Vec<EprocessEntry>` | Cammina la lista doppiamente collegata EPROCESS in memoria |
| `HandleTable::parse_page(data: &[u8], pid: u32) -> Vec<HandleEntry>` | pagina handle table, PID | `Vec<HandleEntry>` | Parsa una pagina della handle table di un processo |
| `HandleTable::summarize(entries: &[HandleEntry]) -> HashMap<String, usize>` | slice handle | `HashMap<tipo, conteggio>` | Conta gli handle per tipo (File, Registry, Process, ecc.) |
| `LdrModuleEntry::is_suspicious_path(&self) -> bool` | — | `bool` | True se il modulo è caricato da un path inusuale |
| `LdrScanner::scan(data: &[u8]) -> Vec<LdrModuleEntry>` | dati PEB/LDR | `Vec<LdrModuleEntry>` | Parsa la lista moduli caricati (LDR_DATA_TABLE_ENTRY) dal PEB |

---

### `plugins::registry_artifacts`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `NkRecord::parse(data: &[u8]) -> Result<Self, RegistryError>` | bytes record NK | `Result<Self, Error>` | Parsa una Named Key cell (NK) dalla hive |
| `VkRecord::parse(data: &[u8], offset: usize) -> Result<Self, RegistryError>` | bytes, offset | `Result<Self, Error>` | Parsa una Value Key cell (VK) |
| `RegValueData::as_string(&self) -> Option<String>` | — | `Option<String>` | Interpreta il valore come REG_SZ/REG_EXPAND_SZ |
| `RegValueData::as_dword(&self) -> Option<u32>` | — | `Option<u32>` | Interpreta il valore come REG_DWORD |
| `RegValueData::as_qword(&self) -> Option<u64>` | — | `Option<u64>` | Interpreta il valore come REG_QWORD |
| `RegValueData::as_multi_sz(&self) -> Vec<String>` | — | `Vec<String>` | Interpreta il valore come REG_MULTI_SZ |
| `SamUser::has_blank_password(&self) -> bool` | — | `bool` | True se l'hash corrisponde a password vuota |
| `SamUser::lm_disabled(&self) -> bool` | — | `bool` | True se LM hash è disabilitato |
| `UserAssistDecoder::rot13_decode(input: &str) -> String` | stringa ROT13 | `String` | Decodifica ROT13 (usato per offuscare i path in UserAssist) |
| `UserAssistDecoder::parse_value(encoded_name, data) -> Option<Self>` | nome codificato, data | `Option<Self>` | Parsa una entry UserAssist dal nome e dal payload |
| `ShellbagDecoder::decode_shitemid(data: &[u8]) -> String` | ShItemID raw | `String` | Decodifica un ShItemID da Shellbags a path leggibile |
| `RunKeyAnalyzer::is_suspicious(command: &str) -> bool` | comando Run key | `bool` | True se il comando ha pattern di persistence sospetti |
| `RunKeyAnalyzer::from_key_path(path: &str) -> Self` | path chiave Run | `Self` | Crea un analyzer per una chiave Run/RunOnce specifica |
| `UserAssistReport::new(username: &str) -> Self` | username | `Self` | Crea report UserAssist per un utente |
| `UserAssistReport::suspicious_count(&self) -> usize` | — | `usize` | Numero di esecuzioni classificate come sospette |
| `UserAssistReport::top_programs(&self, limit: usize) -> Vec<&UserAssistEntry>` | limite | `Vec<&UserAssistEntry>` | Programmi più eseguiti per frequenza |
| `RegistryScanner::scan_run_commands(data: &[u8]) -> Vec<String>` | hive raw | `Vec<String>` | Estrae tutti i comandi dalle chiavi Run/RunOnce |
| `RegistryScanner::scan_typed_urls(data: &[u8]) -> Vec<String>` | hive raw | `Vec<String>` | Estrae URL digitati da Internet Explorer/Edge (TypedURLs) |
| `RegistryScanner::find_hive_offsets(data: &[u8]) -> Vec<usize>` | dati raw memoria | `Vec<usize>` | Trova i magic "regf" per individuare hive mappate in memoria |
| `RegistryScanner::scan_sam_rids(data: &[u8]) -> Vec<u32>` | hive SAM raw | `Vec<u32>` | Estrae i RID degli utenti dalla hive SAM |

---

### `plugins::prefetch_analyzer`

| Firma | Input | Output | Descrizione |
|-------|-------|--------|-------------|
| `is_mam_compressed(data: &[u8]) -> bool` | dati .pf | `bool` | True se il file è compresso con MAM (Windows 10+ Prefetch) |
| `decompress_mam(data: &[u8]) -> Result<Vec<u8>, PrefetchError>` | dati compressi MAM | `Result<Vec<u8>, Error>` | Decomprime un file Prefetch compresso MAM |
| `PrefetchHeader::parse(data: &[u8]) -> Result<Self, PrefetchError>` | file .pf raw | `Result<Self, Error>` | Parsa l'header Prefetch (versione, hash, nome exe, run count) |
| `PrefetchHeader::all_run_times_unix(&self) -> Vec<i64>` | — | `Vec<i64>` (Unix ts) | Lista di tutti i timestamp di esecuzione salvati |
| `FileMetrics::parse_v17(data, strings) -> Option<Self>` | dati sezione, sezione stringhe | `Option<Self>` | Parsa la file metrics section formato v17 (XP/Vista) |
| `FileMetrics::parse_v26(data, strings) -> Option<Self>` | dati sezione, sezione stringhe | `Option<Self>` | Parsa la file metrics section formato v26 (Win7/8) |
| `VolumeInfo::parse(data, vol_section) -> Option<Self>` | dati, sezione volumi | `Option<Self>` | Parsa info volume (device path, serial, creation time) |
| `compute_prefetch_hash_xp(path: &str) -> u32` | path exe | `u32` | Calcola l'hash Prefetch algoritmo XP/Vista per verifica |
| `compute_prefetch_hash_win8(path: &str) -> u32` | path exe | `u32` | Calcola l'hash Prefetch algoritmo Windows 8+ per verifica |
| `verify_hash(header: &PrefetchHeader, exe_path: &str) -> bool` | header, path exe | `bool` | True se l'hash nell'header corrisponde al path calcolato |
| `PrefetchFile::parse(data: &[u8]) -> Result<Self, PrefetchError>` | file .pf raw | `Result<Self, Error>` | Parsa un intero file Prefetch con header, file metrics e volumi |
| `PrefetchFile::summary(&self) -> HashMap<String, String>` | — | `HashMap<String,String>` | Riepilogo in formato chiave-valore (nome, hash, run count, last run, ecc.) |

---

## Conteggio totale funzioni pubbliche

**250 funzioni pubbliche** (metodi `pub fn` su struct/enum + funzioni libere `pub fn`), distribuite su 15 file sorgente.
