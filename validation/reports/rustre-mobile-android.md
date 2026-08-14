# rustre-mobile-android

Crate per l'analisi statica di applicazioni Android (APK/DEX/OAT/ART). Fornisce parser, analisi di sicurezza, rilevamento malware, inferenza JNI, e deobfuscation per file Android.

**Versione:** 0.1.0  
**Dipendenze principali:** serde, serde_json, thiserror, zip, bitflags

---

## Moduli e funzioni pubbliche

### `lib.rs` — Core APK / Manifest / DEX

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `Permission::uses` | `name: impl Into<String>, level: ProtectionLevel` | `Self` | Costruisce un'istanza Permission |
| `Permission::is_location` | `&self` | `bool` | Verifica se il permesso riguarda la geolocalizzazione |
| `Permission::is_telephony` | `&self` | `bool` | Verifica se il permesso riguarda la telefonia |
| `Permission::is_av_recording` | `&self` | `bool` | Verifica se il permesso riguarda audio/video |
| `Permission::is_spyware_relevant` | `&self` | `bool` | True se il permesso è tipico di spyware |
| `Component::is_launcher` | `&self` | `bool` | Verifica se il componente è un launcher |
| `Component::is_boot_receiver` | `&self` | `bool` | Verifica se il componente si attiva al boot |
| `Component::is_sms_receiver` | `&self` | `bool` | Verifica se il componente intercetta SMS |
| `Receiver::is_boot_receiver` | `&self` | `bool` | Specifico per BroadcastReceiver al boot |
| `Receiver::is_sms_interceptor` | `&self` | `bool` | Verifica se il receiver intercetta SMS |
| `AndroidManifest::mock` | `pkg: impl Into<String>` | `Self` | Crea un manifest fittizio per test |
| `AndroidManifest::exported_activities` | `&self` | `Vec<&Activity>` | Restituisce le activity esposte |
| `AndroidManifest::dangerous_permissions` | `&self` | `Vec<&Permission>` | Permessi classificati come pericolosi |
| `AndroidManifest::spyware_permissions` | `&self` | `Vec<&Permission>` | Permessi tipici di spyware |
| `AndroidManifest::exposed_components` | `&self` | `Vec<&Component>` | Componenti esportati (activity/service/receiver) |
| `AndroidManifest::boot_receivers` | `&self` | `Vec<&Component>` | Componenti attivati al boot |
| `AndroidManifest::sms_interceptors` | `&self` | `Vec<&Component>` | Componenti che intercettano SMS |
| `AndroidManifest::threat_score` | `&self` | `f64` | Punteggio di rischio 0.0–1.0 |
| `ApkEntry::is_dex` | `&self` | `bool` | True se l'entry è un file DEX |
| `ApkEntry::is_native_lib` | `&self` | `bool` | True se è una libreria nativa (.so) |
| `ApkEntry::is_xml` | `&self` | `bool` | True se è XML |
| `ApkEntry::is_resources` | `&self` | `bool` | True se è resources.arsc |
| `ApkEntry::is_asset` | `&self` | `bool` | True se è un asset generico |
| `ApkEntry::is_certificate` | `&self` | `bool` | True se è un certificato |
| `ApkEntry::compression_ratio` | `&self` | `f64` | Rapporto compressione (compressed/uncompressed) |
| `ApkEntry::abi` | `&self` | `Option<&str>` | ABI della libreria nativa (arm64-v8a, x86, ecc.) |
| `Apk::package_name` | `&self` | `&str` | Nome del pacchetto APK |
| `Apk::is_obfuscated` | `&self` | `bool` | True se il codice DEX sembra obfuscato |
| `StringEntry::is_url` | `&self` | `bool` | True se la stringa è un URL |
| `StringEntry::is_ip_address` | `&self` | `bool` | True se è un indirizzo IP |
| `StringEntry::is_base64_like` | `&self` | `bool` | True se sembra base64 |
| `StringEntry::is_suspicious_command` | `&self` | `bool` | True se sembra un comando shell sospetto |
| `NativeAnalysis::uses_ptrace` | `&self` | `bool` | True se la lib nativa usa ptrace (anti-debug) |
| `NativeAnalysis::uses_crypto` | `&self` | `bool` | True se usa funzioni crittografiche |
| `NativeAnalysis::references_shell` | `&self` | `bool` | True se fa riferimento a shell/exec |
| `SigningCert::is_debug_cert` | `&self` | `bool` | True se è un certificato di debug |
| `SigningCert::has_weak_key` | `&self` | `bool` | True se la chiave è debole (< 2048 bit RSA) |
| `SigningCert::appears_expired` | `&self` | `bool` | True se il certificato sembra scaduto |
| `DexStats::is_obfuscated` | `&self` | `bool` | True se le statistiche DEX indicano obfuscation |
| `DexStats::summary` | `&self` | `String` | Testo riassuntivo delle statistiche DEX |
| `ApkEntry::is_dex` (v2) | `&self` | `bool` | Variante su tipo diverso |
| `ApkEntry::is_native_lib` (v2) | `&self` | `bool` | Variante su tipo diverso |
| `ApkEntry::compression_ratio` (v2) | `&self` | `f64` | Variante su tipo diverso |
| `ApkInfo::mock` | `()` | `Self` | Crea un ApkInfo fittizio per test |
| `ApkInfo::find_entry` | `name: &str` | `Option<&ApkEntry>` | Cerca un entry per nome |
| `ApkInfo::dex_entries` | `&self` | `Vec<&ApkEntry>` | Tutti i file DEX nell'APK |
| `ApkInfo::native_lib_entries` | `&self` | `Vec<&ApkEntry>` | Tutte le librerie native |
| `ApkInfo::certificate_entries` | `&self` | `Vec<&ApkEntry>` | Tutti i certificati |
| `ApkInfo::total_size` | `&self` | `usize` | Dimensione totale APK in byte |
| `ApkInfo::classes_in_package` | `pkg: &str` | `Vec<&DexClass>` | Classi DEX in un package specifico |
| `ApkInfo::obfuscated_classes` | `&self` | `Vec<&DexClass>` | Classi con nomi obfuscati |
| `ApkInfo::url_strings` | `&self` | `Vec<&StringEntry>` | Stringhe che sembrano URL |
| `ApkInfo::ip_strings` | `&self` | `Vec<&StringEntry>` | Stringhe che sembrano IP |
| `ApkInfo::supported_abis` | `&self` | `Vec<&str>` | ABI supportate dall'APK |
| `ApkInfo::is_debug_signed` | `&self` | `bool` | True se firmato con certificato debug |
| `ApkInfo::is_obfuscated` | `&self` | `bool` | True se il codice è obfuscato |
| `ApkAnalysisResult::from_apk` | `apk: Apk` | `Self` | Costruisce un risultato completo da un Apk |
| `AndroidAnalyzer::analyze` | `apk: Apk` | `ApkAnalysisResult` | Analisi completa di un APK |
| `AndroidAnalyzer::parse_bytes` | `data: &[u8]` | `Result<Apk, AndroidError>` | Parsing di raw bytes in struttura Apk |
| `PermissionGroup::known_groups` | `()` | `Vec<Self>` | Lista di tutti i gruppi di permessi noti |
| `PermissionGroup::used_by` | `manifest: &AndroidManifest` | `Vec<&str>` | Permessi del gruppo usati dal manifest |
| `ApkParser::open` | `path: &Path` | `Result<Self, AndroidError>` | Apre un APK dal filesystem |
| `ApkParser::list_files` | `&self` | `Vec<String>` | Lista tutti i file nell'APK |
| `ApkParser::read_file` | `name: &str` | `Result<Vec<u8>, AndroidError>` | Legge il contenuto di un file dell'APK |
| `ApkParser::has_file` | `name: &str` | `bool` | Verifica se un file esiste nell'APK |
| `ApkParser::entry_count` | `&self` | `usize` | Numero di entry nell'archivio ZIP |
| `decode_binary_xml` | `data: &[u8]` | `Result<String, AndroidError>` | Decodifica XML binario Android (AXML) in testo |
| `AndroidManifestParser::parse` | `axml_data: &[u8]` | `Result<AndroidManifest, AndroidError>` | Parsing completo di un manifest AXML binario |
| `DexParser::verify_magic` | `data: &[u8]` | `bool` | Verifica il magic number DEX |
| `DexParser::parse_header` | `data: &[u8]` | `Result<DexHeader, AndroidError>` | Parsing dell'header DEX |
| `extract_signing_info` | `apk: &mut ApkParser` | `SigningInfo` | Estrae informazioni di firma dall'APK |
| `ApkReport::analyze` | `path: &Path` | `Result<ApkReport, AndroidError>` | Analisi completa con report da percorso file |
| `ApkReport::suspicious_permissions` | `perms: &[String]` | `Vec<String>` | Filtra la lista di permessi sospetti |

---

### `android_manifest_parser.rs` — Parser binario AXML

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ManifestPermission::is_dangerous` | `&self` | `bool` | True se il permesso è di livello dangerous |
| `ComponentDecl::is_exposed` | `&self` | `bool` | True se il componente è esportato |
| `ReceiverDecl::is_boot_receiver` | `&self` | `bool` | True se il receiver gestisce BOOT_COMPLETED |
| `ParsedManifest::uses_permissions` | `&self` | `Vec<&ManifestPermission>` | Tutti i permessi richiesti |
| `ParsedManifest::dangerous_permissions` | `&self` | `Vec<&ManifestPermission>` | Solo i permessi pericolosi |
| `ParsedManifest::exposed_services` | `&self` | `Vec<&ServiceDecl>` | Service con exported=true |
| `ParsedManifest::boot_receivers` | `&self` | `Vec<&ReceiverDecl>` | Receiver che si attivano al boot |
| `ParsedManifest::threat_score` | `&self` | `f64` | Punteggio di rischio aggregato |
| `ResChunkHeader::parse` | `data: &[u8], offset: usize` | `(Self, usize)` | Parsing di un chunk header AXML |
| `StringPool::get` | `idx: u32` | `&str` | Recupera una stringa dal pool per indice |
| `AXmlParser::parse` | `data: &[u8]` | `ParsedManifest` | Parse completo di un manifest binario |

---

### `android_permissions.rs` — Analisi permessi e manifest

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ProtectionLevel::from_permission` | `name: &str` | `Self` | Inferisce il livello di protezione da nome permesso |
| `Permission::new` | `name: impl Into<String>, protection_level: ProtectionLevel` | `Self` | Crea un nuovo permesso |
| `IntentFilter::has_action` | `action: &str` | `bool` | Verifica se il filtro contiene una specifica action |
| `IntentFilter::is_main_launcher` | `&self` | `bool` | True se è il launcher principale |
| `ManifestXmlParser::parse_elements` | `&mut self` | `PermissionResult<Vec<(String, HashMap<String, String>)>>` | Parsing degli elementi XML del manifest |
| `ManifestAnalysis::dangerous_permissions` | `&self` | `Vec<&Permission>` | Permessi pericolosi trovati |
| `ManifestAnalysis::high_risk_permissions` | `&self` | `Vec<&Permission>` | Permessi ad alto rischio |
| `ManifestAnalysis::custom_permissions` | `&self` | `Vec<&Permission>` | Permessi personalizzati (non standard Android) |
| `ManifestAnalysis::exported_components` | `&self` | `Vec<&ManifestComponent>` | Componenti esportati |
| `ManifestAnalysis::unprotected_exported_components` | `&self` | `Vec<&ManifestComponent>` | Componenti esportati senza protezione permessi |
| `ManifestAnalysis::permissions_by_group` | `&self` | `HashMap<String, Vec<&Permission>>` | Permessi raggruppati per categoria |
| `ManifestAnalysis::risk_score` | `&self` | `u32` | Punteggio di rischio numerico |
| `parse_manifest_axml` | `data: &[u8]` | `PermissionResult<ManifestAnalysis>` | Parsing di manifest AXML binario |
| `parse_manifest_text` | `xml: &str` | `ManifestAnalysis` | Parsing di manifest XML testuale |
| `PermissionSummary::from_analysis` | `a: &ManifestAnalysis` | `Self` | Crea un sommario da ManifestAnalysis |

---

### `android_security.rs` — Analisi sicurezza rete/crypto/anti-reversing

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `NetworkConfig::is_insecure` | `&self` | `bool` | True se la configurazione di rete è insicura (cleartext) |
| `AntiReverseDetection::sophistication_score` | `&self` | `u32` | Punteggio di sofisticazione delle tecniche anti-reverse |
| `AntiReverseDetection::mock` | `()` | `Self` | Istanza mock per test |
| `SecurityFindings::has_critical` | `&self` | `bool` | True se ci sono finding critici |
| `SecurityFindings::recompute` | `&mut self` | `()` | Ricalcola i finding aggregati |
| `SecurityAnalyzer::analyze_manifest_xml` | `xml: &str` | `NetworkSecurity` | Analizza la network security config dall'XML |
| `SecurityAnalyzer::analyze_dex_strings` | `strings: &[String]` | `CryptographyUsage` | Rileva uso di primitive crittografiche nelle stringhe DEX |
| `SecurityAnalyzer::detect_anti_reverse` | `strings: &[String]` | `AntiReverseDetection` | Rileva tecniche di anti-reversing dalle stringhe |

---

### `apk_security_full.rs` — Report di sicurezza completo APK

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `PermissionRisk::from_manifest` | `manifest: &AndroidManifest` | `Self` | Valuta i rischi dei permessi dal manifest |
| `PermissionRisk::is_high_risk` | `&self` | `bool` | True se i permessi indicano alto rischio |
| `PermissionRisk::summary` | `&self` | `String` | Testo riassuntivo del rischio permessi |
| `ComponentExposure::from_apk` | `apk: &Apk` | `Self` | Analizza l'esposizione dei componenti |
| `NetworkSecurity::from_apk` | `apk: &Apk` | `Self` | Analizza la sicurezza di rete dall'APK |
| `CodeQuality::from_apk` | `apk: &Apk` | `Self` | Valuta la qualità/sicurezza del codice |
| `DataStorage::from_apk` | `apk: &Apk` | `Self` | Analizza pratiche di storage dei dati |
| `SignatureAnalysis::from_apk` | `apk: &Apk` | `Self` | Analizza le firme crittografiche dell'APK |
| `ApkSecurityAnalyzer::analyze` | `apk: &Apk` | `SecurityReport` | Esegue analisi di sicurezza completa |
| `ApkSecurityAnalyzer::quick_score` | `apk: &Apk` | `f64` | Calcola un punteggio rapido senza analisi completa |

---

### `android_malware.rs` — Classificazione malware

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `Ransomware::risk_score` | `&self` | `u8` | Punteggio di rischio ransomware (0–100) |
| `Spyware::risk_score` | `&self` | `u8` | Punteggio di rischio spyware |
| `NetworkActivity::is_high_frequency` | `&self` | `bool` | True se la frequenza di rete è sospettosamente alta |
| `NetworkActivity::risk_score` | `&self` | `u8` | Punteggio di rischio attività di rete |
| `Dropper::risk_score` | `&self` | `u8` | Punteggio di rischio dropper |
| `Rootkit::risk_score` | `&self` | `u8` | Punteggio di rischio rootkit |
| `EvasionTechniques::evasion_score` | `&self` | `u8` | Punteggio complessivo di evasione |
| `BankingTrojan::new` | `()` | `Self` | Crea un nuovo BankingTrojan vuoto |
| `BankingTrojan::risk_score` | `&self` | `u8` | Punteggio di rischio banking trojan |
| `MalwareReport::new` | `package_name: impl Into<String>, app_name: impl Into<String>` | `Self` | Crea un nuovo report malware |
| `MalwareReport::add_category` | `cat: MalwareCategory` | `()` | Aggiunge una categoria malware al report |
| `MalwareReport::risk_score` | `&self` | `u8` | Punteggio di rischio aggregato |
| `MalwareReport::has_dangerous_permission_combo` | `&self` | `bool` | True se ha combinazioni di permessi pericolose |
| `MalwareReport::is_banking_threat` | `&self` | `bool` | True se è classificato come banking threat |
| `MalwareReport::threat_summary` | `&self` | `String` | Testo riassuntivo della minaccia |
| `MalwareReport::can_intercept_sms` | `&self` | `bool` | True se può intercettare SMS |
| `MalwareReport::dangerous_permission_count` | `&self` | `usize` | Numero di permessi pericolosi rilevati |

---

### `dex_analysis.rs` — Analisi bytecode DEX

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `StringEntry::new` | `class: impl Into<String>, name: impl Into<String>` | `Self` | Crea una nuova entry stringa |
| `StringEntry::qualified_name` | `&self` | `String` | Nome qualificato class.field |
| `DexMethod::new` | `...` | `Self` | Costruisce un DexMethod |
| `DexMethod::qualified` | `&self` | `String` | Firma qualificata del metodo |
| `DexCallGraph::new` | `()` | `Self` | Grafo di chiamate vuoto |
| `DexCallGraph::add_edge` | `caller: impl Into<String>, callee: impl Into<String>` | `()` | Aggiunge un arco chiamante→chiamato |
| `DexCallGraph::callees_of` | `method: &str` | `Vec<&str>` | Metodi chiamati da un metodo dato |
| `DexCallGraph::callers_of` | `method: &str` | `Vec<&str>` | Metodi che chiamano un metodo dato |
| `DexCallGraph::edge_count` | `&self` | `usize` | Numero totale di archi nel grafo |
| `DexCallGraph::from_methods` | `methods: &[DexMethod]` | `Self` | Costruisce il grafo da lista di metodi |
| `PermissionMapper::new` | `()` | `Self` | Crea un mapper permessi vuoto |
| `PermissionMapper::required_permissions` | `api_calls: &[String]` | `HashSet<String>` | Permessi richiesti da una lista di API call |
| `PermissionMapper::requires_permission` | `api_calls: &[String], permission: &str` | `bool` | Verifica se le API call richiedono un permesso specifico |
| `StringAnalyzer::extract_categorised` | `strings: &[StringEntry]` | `HashMap<String, Vec<String>>` | Classifica stringhe per categoria |
| `StringAnalyzer::find_c2_indicators` | `strings: &[StringEntry]` | `Vec<&StringEntry>` | Trova indicatori di C2 (command & control) |
| `StringAnalyzer::find_crypto_strings` | `strings: &[StringEntry]` | `Vec<&StringEntry>` | Trova stringhe legate a crittografia |
| `ObfuscationDetector::detect` | `classes: &[DexClass]` | `(Vec<ObfuscationIndicator>, f64)` | Rileva tecniche di obfuscation |
| `ObfuscationDetector::is_obfuscated` | `classes: &[DexClass], threshold: f64` | `bool` | True se l'obfuscation supera la soglia |
| `DexAnalyzer::new` | `()` | `Self` | Crea un analizzatore DEX |
| `DexAnalyzer::build_call_graph` | `methods: &[DexMethod]` | `DexCallGraph` | Costruisce il call graph |
| `DexAnalyzer::map_permissions` | `api_calls: &[String]` | `HashSet<String>` | Mappa API→permessi |
| `DexAnalyzer::detect_obfuscation` | `classes: &[DexClass]` | `(Vec<ObfuscationIndicator>, f64)` | Rileva obfuscation |
| `DexAnalyzer::extract_strings` | `strings: &[StringEntry]` | `HashMap<String, Vec<String>>` | Estrae stringhe classificate |
| `DexAnalyzer::analyze` | `...` | (report) | Analisi completa DEX |
| `DexAnalysisResult::is_obfuscated` | `&self` | `bool` | True se il risultato indica obfuscation |

---

### `dex_class_hierarchy.rs` — Gerarchia classi DEX

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `InterfaceSet::new` | `()` | `Self` | Set di interfacce vuoto |
| `InterfaceSet::add` | `iface: String` | `()` | Aggiunge un'interfaccia |
| `InterfaceSet::contains` | `iface: &str` | `bool` | Verifica presenza interfaccia |
| `ClassNode::simple_name` | `&self` | `&str` | Nome semplice della classe |
| `ClassNode::package_name` | `&self` | `String` | Nome del package |
| `ClassHierarchyBuilder::new` | `()` | `Self` | Builder vuoto |
| `ClassHierarchyBuilder::add_class` | `node: ClassNode` | `()` | Aggiunge un nodo classe |
| `ClassHierarchyBuilder::parse_class_defs` | `data: &[u8], ...` | (result) | Parsing delle definizioni di classe da raw DEX |
| `ClassHierarchyBuilder::build` | `self` | `ClassHierarchy` | Costruisce la gerarchia finale |
| `ClassHierarchy::new` | `()` | `Self` | Gerarchia vuota |
| `ClassHierarchy::from_nodes` | `nodes: Vec<ClassNode>` | `Self` | Costruisce da lista di nodi |
| `ClassHierarchy::add_node` | `node: ClassNode` | `()` | Aggiunge un nodo |
| `ClassHierarchy::get` | `descriptor: &str` | `Option<&ClassNode>` | Recupera un nodo per descriptor JVM |
| `ClassHierarchy::direct_subclasses` | `descriptor: &str` | `&[String]` | Sottoclassi dirette |
| `ClassHierarchy::all_subclasses` | `descriptor: &str` | `Vec<String>` | Tutte le sottoclassi (ricorsivo) |
| `ClassHierarchy::implementors_of` | `interface_descriptor: &str` | `&[String]` | Classi che implementano un'interfaccia |
| `ClassHierarchy::ancestors` | `descriptor: &str` | `Vec<String>` | Catena di antenati della classe |
| `ClassHierarchy::is_subtype_of` | `sub: &str, sup: &str` | `bool` | Verifica relazione di subtipo |
| `ClassHierarchy::class_count` | `&self` | `usize` | Numero totale di classi |
| `ClassHierarchy::all_descriptors` | `&self` | `Vec<&str>` | Tutti i descriptor JVM |
| `ClassHierarchy::search_by_name` | `substr: &str` | `Vec<&ClassNode>` | Ricerca classi per sottostringa |
| `ClassHierarchy::all_implementors` | `interface_descriptor: &str` | `Vec<String>` | Tutti gli implementatori (incluse sottoclassi) |

---

### `dex_obfuscation.rs` — Rilevamento e analisi obfuscation

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `shannon_entropy` | `data: &[u8]` | `f64` | Calcola l'entropia di Shannon su byte |
| `name_entropy` | `name: &str` | `f64` | Calcola l'entropia di un nome (classe/metodo) |
| `ProguardMapping::parse` | `mapping_txt: &str` | `Self` | Parsing di un file mapping.txt ProGuard/R8 |
| `ProguardMapping::deobfuscate_class` | `obf: &str` | `Option<&str>` | Traduce nome classe obfuscato→originale |
| `ProguardMapping::deobfuscate_method` | `obf_class: &str, obf_method: &str` | `Option<&str>` | Traduce nome metodo obfuscato→originale |
| `DexClassStat::from_descriptor` | `descriptor: &str, method_count: u32, field_count: u32` | `Self` | Crea statistiche di classe da descriptor |
| `detect_string_encryption` | `strings: &[String]` | `Vec<StringEncryptionKind>` | Rileva pattern di cifratura sulle stringhe |
| `ObfuscationReport::is_obfuscated` | `&self` | `bool` | True se il report indica obfuscation |
| `ObfuscationReport::risk_summary` | `&self` | `String` | Testo riassuntivo del rischio obfuscation |
| `DexObfuscationAnalyzer::extract_strings` | `&self` | `ObfuscationResult<Vec<String>>` | Estrae le stringhe dal DEX |
| `DexObfuscationAnalyzer::extract_type_descriptors` | `&self` | `ObfuscationResult<Vec<String>>` | Estrae i descriptor di tipo |
| `DexObfuscationAnalyzer::method_counts_per_class` | `&self` | `ObfuscationResult<HashMap<u32, u32>>` | Metodi per classe (usato per rilevare obfuscation) |
| `DexObfuscationAnalyzer::detect_reflection` | `strings: &[String]` | `ReflectionUsage` | Rileva uso di reflection |
| `DexObfuscationAnalyzer::detect_dexguard` | `strings: &[String]` | `bool` | Verifica se è stato usato DexGuard |
| `DexObfuscationAnalyzer::detect_proguard_or_r8` | `class_stats: &[DexClassStat]` | `ObfuscationTool` | Distingue ProGuard da R8 |
| `DexObfuscationAnalyzer::analyze` | `&self` | `ObfuscationResult<ObfuscationReport>` | Analisi obfuscation completa |
| `apply_mapping` | `report: &mut ObfuscationReport, mapping: &ProguardMapping` | `()` | Applica un mapping ProGuard al report |
| `analyze_dex_obfuscation` | `dex_data: &[u8]` | `ObfuscationResult<ObfuscationReport>` | Entry point: analisi obfuscation da raw DEX |
| `parse_proguard_mapping` | `mapping_txt: &str` | `ProguardMapping` | Parsing di un file mapping ProGuard |

---

### `jni_inference.rs` — Inferenza JNI

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `JniDescriptorType::java_name` | `&self` | `String` | Nome Java del tipo JNI (es. `int`, `String`) |
| `JniDescriptorParser::parse_method_descriptor` | `descriptor: &str` | `Result<..., String>` | Parsing di un descriptor JNI di metodo |
| `JniDescriptorParser::parse_type_list` | `s: &str` | `Result<Vec<JniDescriptorType>, String>` | Parsing di lista di tipi JNI |
| `JniDescriptorParser::parse_single_type` | `s: &str` | `Result<JniDescriptorType, String>` | Parsing di un singolo tipo JNI |
| `JniSignature::from_jni_export` | `export: &str, descriptor: Option<&str>` | `Result<Self, String>` | Costruisce una firma da un simbolo export JNI |
| `JniSignature::qualified_name` | `&self` | `String` | Nome qualificato classe.metodo |
| `JniNativeMethod::new` | `...` | `Self` | Costruisce un metodo nativo JNI |
| `JniNativeMethod::addr_hex` | `&self` | `String` | Indirizzo del metodo in esadecimale |
| `JniScanner::new` | `()` | `Self` | Crea un nuovo scanner JNI |
| `JniScanner::add_descriptor_hint` | `...` | `()` | Aggiunge un hint di descriptor per inferenza |
| `JniScanner::is_jni_export` | `symbol: &str` | `bool` | True se il simbolo è un export JNI statico |
| `JniScanner::is_jni_onload` | `symbol: &str` | `bool` | True se il simbolo è JNI_OnLoad |
| `JniScanner::scan` | `exports: &[(u64, String)], library: &str` | `Vec<JniMapping>` | Scansiona export e produce mapping JNI |
| `JniScanner::extract_classes` | `mappings: &[JniMapping]` | `Vec<String>` | Estrae i nomi delle classi Java dai mapping |
| `JniAnalyzer::analyze_args` | `sig: &JniSignature` | `Vec<JniArgInfo>` | Analizza gli argomenti di una firma JNI |
| `JniAnalyzer::infer_prototype` | `mapping: &JniMapping` | `String` | Inferisce il prototipo C della funzione JNI |
| `JniAnalyzer::group_by_class` | `mappings: &[JniMapping]` | `HashMap<String, Vec<String>>` | Raggruppa i metodi JNI per classe Java |
| `DynamicJniRegistration::new` | `...` | `Self` | Crea una registrazione JNI dinamica |
| `DynamicJniRegistration::qualified_name` | `&self` | `String` | Nome qualificato della registrazione |
| `DynamicRegistrationScanner::analyze` | `exports: &[(u64, String)]` | `Vec<DynamicJniRegistration>` | Analizza export per registrazioni JNI dinamiche |
| `JniReport::from_exports` | `library: impl Into<String>, exports: &[(u64, String)]` | `Self` | Costruisce un report JNI completo dagli export |

---

### `art_runtime.rs` — Parser ART/OAT runtime

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ArtMethod::full_signature` | `&self` | `String` | Firma completa del metodo ART |
| `OatDexFile::all_methods` | `&self` | `impl Iterator<Item = &ArtMethod>` | Iteratore su tutti i metodi nel file OAT |
| `OatDexFile::hot_methods` | `&self` | `Vec<&ArtMethod>` | Metodi marcati come "hot" (JIT) |
| `OatDexFile::aot_methods` | `&self` | `Vec<&ArtMethod>` | Metodi compilati AOT |
| `BinaryReader::read_u8` | `&mut self` | `ArtResult<u8>` | Legge un byte |
| `BinaryReader::read_u16_le` | `&mut self` | `ArtResult<u16>` | Legge u16 little-endian |
| `BinaryReader::read_length_prefixed_string` | `&mut self` | `ArtResult<String>` | Legge stringa con lunghezza prefissa |
| `OatParser::parse` | `&mut self` | `ArtResult<OatFile>` | Parsing completo di un file OAT |
| `ClassLoadTracer::new` | `()` | `Self` | Crea un tracer vuoto |
| `ClassLoadTracer::from_log` | `log: &str` | `Self` | Popola il tracer da log ART |
| `ClassLoadTracer::classes_by_loader` | `&self` | `HashMap<&str, Vec<&ClassLoadEvent>>` | Raggruppa eventi per class loader |
| `ClassLoadTracer::dynamic_classes` | `&self` | `Vec<&ClassLoadEvent>` | Classi caricate dinamicamente (sospette) |
| `ClassLoadTracer::suspicious_loads` | `&self` | `Vec<&ClassLoadEvent>` | Caricamenti sospetti di classi |
| `ArtAnalysisReport::from_oat` | `oat: &OatFile` | `Self` | Costruisce report da file OAT |
| `parse_oat` | `data: &[u8]` | `ArtResult<(OatFile, ArtAnalysisReport)>` | Entry point: parse OAT + analisi |
| `layout_for_api` | `api: u32` | `Option<ArtMethodLayout>` | Restituisce il layout ArtMethod per livello API |

---

### `smali_lifter.rs` — Lifting bytecode Dalvik→IR

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `BasicBlock::is_unconditional` | `&self` | `bool` | True se il blocco termina con jump incondizionato |
| `BasicBlock::is_exit` | `&self` | `bool` | True se il blocco è un exit (return/throw) |
| `BasicBlock::terminator` | `&self` | `Option<&DalvikInstr>` | Istruzione terminatrice del blocco |
| `LiftedMethod::block_count` | `&self` | `usize` | Numero di basic block nel metodo |
| `LiftedMethod::invocations` | `&self` | `Vec<&IrInstr>` | Tutte le istruzioni di invocazione |
| `LiftedMethod::string_constants` | `&self` | `Vec<&str>` | Costanti stringa nel metodo |
| `DexContext::set_strings` | `strings: Vec<String>` | `()` | Imposta il pool di stringhe DEX |
| `DexContext::set_types` | `types: Vec<String>` | `()` | Imposta il pool di tipi DEX |
| `DexContext::set_methods` | `methods: Vec<String>` | `()` | Imposta il pool di metodi DEX |
| `SmaliLifter::lift` | `...` | (lifted IR) | Converte bytecode Dalvik in IR intermedio |

---

## Conteggio funzioni pubbliche

Totale funzioni `pub fn` (incluse associate e di istanza): **249**

---

## Note architetturali

- Il crate è **puro Rust**, senza FFI o dipendenze da SDK Android.
- Il parsing AXML (manifest binario) è implementato internamente senza librerie Java.
- Il modello dati distingue tra `AndroidManifest` (struttura core) e `ParsedManifest` (output del parser AXML raw).
- Il lifter Smali produce una rappresentazione IR intermedia (basic blocks + istruzioni tipizzate) adatta ad analisi di flusso.
- `ApkParser` usa `zip` per l'accesso agli archivi APK; il parsing DEX e OAT è completamente custom.
- I punteggi di rischio (`risk_score`, `threat_score`) sono normalizzati: u8 (0–100) o f64 (0.0–1.0).
