# rustre-mobile-ios — Documentazione funzioni pubbliche

Crate: `rustre-mobile-ios` v0.1.0  
Dipendenze principali: `goblin`, `zip`, `serde`, `serde_json`, `thiserror`

---

## bundle.rs — IPA / .app Bundle

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `Platform::parse_platform(s)` | `&str` | `Option<Platform>` | Converte stringa piattaforma (es. "iphoneos") in enum `Platform` |
| `AppBinary::supports_arm64(&self)` | `&self` | `bool` | Controlla se il binario supporta l'architettura arm64 |
| `AppBinary::supports_x86_64(&self)` | `&self` | `bool` | Controlla se il binario supporta x86_64 (simulatore) |
| `IosBundle::open(path)` | `&Path` | `Result<Self, IosError>` | Apre e parsa un bundle .ipa o .app da disco |
| `IosBundle::mock()` | — | `Self` | Costruisce un bundle fittizio per i test |
| `IosBundle::is_catalyst(&self)` | `&self` | `bool` | Rileva se l'app è un'app Mac Catalyst |
| `IosBundle::minimum_os_version(&self)` | `&self` | `&str` | Restituisce la versione iOS minima richiesta |
| `IosBundle::supports_arm64(&self)` | `&self` | `bool` | Controlla il supporto arm64 a livello di bundle |
| `IosBundle::executable_path(&self)` | `&self` | `Option<PathBuf>` | Percorso dell'eseguibile principale del bundle |

---

## info_plist.rs — Parsing Info.plist

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `InfoPlist::bundle_id(&self)` | `&self` | `Option<&str>` | Legge CFBundleIdentifier |
| `InfoPlist::bundle_version(&self)` | `&self` | `Option<&str>` | Legge CFBundleVersion |
| `InfoPlist::bundle_short_version(&self)` | `&self` | `Option<&str>` | Legge CFBundleShortVersionString |
| `InfoPlist::display_name(&self)` | `&self` | `Option<&str>` | Nome visualizzato dell'app |
| `InfoPlist::minimum_os_version(&self)` | `&self` | `Option<&str>` | MinimumOSVersion |
| `InfoPlist::bundle_executable(&self)` | `&self` | `Option<&str>` | CFBundleExecutable |
| `InfoPlist::background_modes(&self)` | `&self` | `Vec<&str>` | UIBackgroundModes dichiarati |
| `InfoPlist::privacy_usage_descriptions(&self)` | `&self` | `HashMap<&str, &str>` | Chiavi NSxxx UsageDescription e testi |
| `InfoPlist::supported_interface_orientations(&self)` | `&self` | `Vec<&str>` | Orientamenti supportati |
| `InfoPlist::app_transport_security(&self)` | `&self` | `Option<AtsConfig>` | Config NSAppTransportSecurity |
| `InfoPlist::url_schemes(&self)` | `&self` | `Vec<&str>` | Schemi URL custom registrati |
| `InfoPlist::queried_url_schemes(&self)` | `&self` | `Vec<&str>` | LSApplicationQueriesSchemes |
| `InfoPlist::url_types(&self)` | `&self` | `Vec<UrlType>` | CFBundleURLTypes strutturati |
| `InfoPlist::document_types(&self)` | `&self` | `Vec<DocumentType>` | CFBundleDocumentTypes |
| `InfoPlist::required_device_capabilities(&self)` | `&self` | `Vec<&str>` | UIRequiredDeviceCapabilities |
| `InfoPlist::allowed_callers(&self)` | `&self` | `Vec<&str>` | NSExtensionActivationRule o simili |
| `InfoPlist::has_any_privacy_key(&self)` | `&self` | `bool` | Verifica presenza di almeno una chiave privacy |
| `InfoPlist::targets_ios(&self)` | `&self` | `bool` | Controlla se piattaforma target è iOS |
| `InfoPlist::is_catalyst(&self)` | `&self` | `bool` | Indica app Mac Catalyst |

---

## plist.rs — Parser plist binario/XML generico

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `PlistValue::get(&self, key)` | `&str` | `Option<&Self>` | Accesso per chiave in un dizionario plist |
| `PlistValue::string_array(&self)` | `&self` | `Vec<&str>` | Estrae array di stringhe da un valore plist |
| `parse_binary_plist(data)` | `&[u8]` | `Result<PlistValue, PlistError>` | Parsa un plist in formato binario Apple (bplist00) |
| `parse_xml_plist(data)` | `&[u8]` | `Result<PlistValue, PlistError>` | Parsa un plist XML da bytes |
| `parse_xml_plist_str(xml)` | `&str` | `Result<PlistValue, PlistError>` | Parsa un plist XML da stringa |
| `plist_auto_detect(data)` | `&[u8]` | `Result<PlistValue, PlistError>` | Auto-rileva il formato (binario o XML) e lo parsa |

---

## pac.rs — ARM64 Pointer Authentication (PAC)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `PacInstruction::assembly(&self)` | `&self` | `String` | Restituisce la stringa assembly dell'istruzione PAC |
| `decode_pac_instruction(encoding, address)` | `u32`, `u64` | `Option<PacInstruction>` | Decodifica una parola di 32 bit in istruzione PAC se applicabile |
| `PacScanResult::scan(code, base_address)` | `&[u8]`, `u64` | `Result<Self, PacError>` | Scansiona sequenza di codice ARM64 e raccoglie istruzioni PAC |
| `PacScanResult::authenticated_returns(&self)` | `&self` | `Vec<&PacInstruction>` | Filtra solo RETAA/RETAB (return authenticati) |
| `PacScanResult::sign_instructions(&self)` | `&self` | `Vec<&PacInstruction>` | Filtra istruzioni di firma (PACIA/PACIB/...) |
| `PacScanResult::instructions_by_key(&self, key)` | `PacKey` | `Vec<&PacInstruction>` | Filtra per chiave PAC (A o B) |

---

## swift_metadata.rs — Metadati Swift5

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `read_u8(data, off)` | `&[u8]`, `usize` | `Result<u8>` | Lettura byte con controllo bounds |
| `lookup_str(pool, off)` | hashmap + offset | `Option<&str>` | Ricerca nel pool di stringhe Swift |
| `SwiftTypeDescriptor::fully_qualified_name(&self)` | `&self` | `String` | Restituisce `Module.TypeName` |
| `SwiftTypeDescriptor::conforms_to(&self, protocol)` | `&str` | `bool` | Verifica conformance a un protocollo |
| `SwiftTypeDescriptor::mock_struct/class/enum/protocol` | `name, module: &str` | `Self` | Costruttori fittizi per test |
| `SwiftBuiltinTypeDescriptor::to_swift_type(&self)` | `&self` | `String` | Converte in nome tipo Swift leggibile |
| `demangle_swift_name(mangled)` | `&str` | `String` | Demangling base del nome mangled Swift |
| `decode_mangled_type(mangled)` | `&str` | `MangledNode` | Albero sintattico da nome mangled |
| `mangled_to_display(mangled)` | `&str` | `String` | Forma leggibile da nome mangled |
| `parse_string_pool(sec)` | `&SectionData` | `HashMap<u64, String>` | Costruisce mappa VA→stringa dalla sezione strings |
| `parse_fieldmd(...)` | sezione + pool | `Vec<SwiftFieldDescriptor>` | Parsa sezione `__swift5_fieldmd` |
| `parse_proto(...)` | sezione + pool | `Vec<SwiftProtocolDescriptor>` | Parsa sezione `__swift5_proto` |
| `parse_assocty(...)` | sezione + pool | `Vec<SwiftAssocType>` | Parsa sezione `__swift5_assocty` |
| `parse_replace(sec)` | `&SectionData` | `Vec<SwiftReplacementRecord>` | Parsa sezione `__swift5_replace` (dynamic replacement) |
| `parse_entry(sec)` | `&SectionData` | `Option<SwiftEntryPoint>` | Legge entry point Swift dal Mach-O |
| `parse_types(...)` | sezione + pool | `Vec<SwiftTypeDescriptor>` | Parsa sezione `__swift5_types` |
| `ObjcMetadataSection::parse(data, data_base_va, address)` | `&[u8]`, `u64`, `u64` | `Option<Self>` | Parsa stub ObjC da sezione Swift |
| `ObjcMetadataSection::all_strings(&self)` | `&self` | `HashMap<u64, String>` | Tutte le stringhe della sezione |
| `ObjcMetadataSection::objc_stubs(&self)` | `&self` | `Vec<&ObjcMetadataStub>` | Lista stub ObjC |
| `ObjcMetadataSection::find_type(&self, name)` | `&str` | `Option<&SwiftTypeDescriptor>` | Ricerca tipo per nome |
| `parse_swift_metadata(sections)` | `&Swift5Sections` | `SwiftMetadataResult` | Parsa tutti i metadati Swift5 da sezioni Mach-O |
| `SwiftMetadataResult::add_types/add_conformances/add_builtins` | Vec<...> | `()` | Popolamento builder |
| `SwiftMetadataResult::all_types/all_conformances` | `&self` | `&[...]` | Accesso alle collezioni |
| `SwiftMetadataResult::find_type(&self, name)` | `&str` | `Option<&SwiftTypeDescriptor>` | Ricerca tipo per nome |
| `SwiftMetadataResult::types_conforming_to(&self, protocol)` | `&str` | `Vec<&SwiftTypeDescriptor>` | Tipi che implementano un protocollo |
| `SwiftMetadataResult::conformances_for(&self, type_name)` | `&str` | `Vec<&SwiftProtocolConformance>` | Conformanze di un tipo |
| `SwiftMetadataResult::types_by_kind(&self)` | `&self` | `HashMap<String, Vec<...>>` | Raggruppa tipi per kind (struct/class/enum/...) |
| `SwiftMetadataResult::mock()` | — | `Self` | Istanza fittizia per test |

---

## objc_runtime.rs — Runtime ObjC (livello basso)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `decode_type_encoding(enc)` | `&str` | `Vec<ObjcType>` | Decodifica encoding ObjC (es. `@:i`) in lista tipi |
| `ObjcMethodSignature::from_encoding(enc)` | `&str` | `Self` | Costruisce firma da stringa encoding |
| `ObjcMethodSignature::signature_string(&self)` | `&self` | `String` | Stringa leggibile della firma |
| `ObjcProperty::from_attrs(name, attrs)` | `&str, &str` | `Self` | Costruisce proprietà da attributi runtime |
| `ObjcClass::conforms_to(&self, protocol)` | `&str` | `bool` | Verifica adozione protocollo |
| `ObjcClass::find_method(&self, selector)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo per selettore |
| `ObjcClass::find_property(&self, name)` | `&str` | `Option<&ObjcProperty>` | Ricerca proprietà per nome |
| `ObjcClass::all_selectors(&self)` | `&self` | `Vec<&str>` | Tutti i selettori della classe |
| `ObjcClass::mock(name)` | `&str` | `Self` | Classe fittizia per test |
| `ObjcRuntimeSection::new(methname, classname, methtype)` | `Vec<u8>` × 3 | `Self` | Costruisce sezione runtime |
| `ObjcRuntimeSection::add_classes(&mut self, classes)` | `Vec<ObjcClass>` | `()` | Aggiunge classi alla sezione |
| `ObjcRuntimeSection::all_classes(&self)` | `&self` | `&[ObjcClass]` | Lista completa classi |
| `ObjcRuntimeSection::find_class_by_address(&self, addr)` | `u64` | `Option<&ObjcClass>` | Ricerca classe per indirizzo IMP |
| `ObjcRuntimeSection::find_method_by_address(&self, addr)` | `u64` | `Option<(&ObjcClass, &ObjcMethod)>` | Ricerca metodo e classe proprietaria per VA |
| `ObjcRuntimeSection::all_method_names(&self)` | `&self` | `Vec<String>` | Tutti i nomi metodo |
| `ObjcRuntimeSection::all_class_names(&self)` | `&self` | `Vec<String>` | Tutti i nomi classe |

---

## objc_runtime_analysis.rs — Analisi runtime ObjC (livello alto)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ObjcMethod::is_init(&self)` | `&self` | `bool` | Rileva se il selettore è un init* |
| `ObjcMethod::is_dealloc(&self)` | `&self` | `bool` | Rileva se è dealloc |
| `ObjcMethod::selector_parts(&self)` | `&self` | `Vec<&str>` | Spezza selettore in componenti |
| `ObjcIvar::is_object_type(&self)` | `&self` | `bool` | Verifica se ivar ha tipo oggetto |
| `ObjcClass::implements(&self, proto)` | `&str` | `bool` | Adozione protocollo |
| `ObjcClass::find_method(&self, sel)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo |
| `ObjcClass::find_ivar(&self, name)` | `&str` | `Option<&ObjcIvar>` | Ricerca ivar |
| `ObjcClass::swizzle_candidates(&self)` | `&self` | `Vec<&ObjcMethod>` | Metodi candidati a method swizzling |
| `ObjcClass::mock()` | — | `Self` | Classe fittizia per test |
| `ObjcRuntimeReport::find_class(&self, name)` | `&str` | `Option<&ObjcClass>` | Ricerca classe per nome |
| `ObjcRuntimeReport::classes_implementing(&self, proto)` | `&str` | `Vec<&ObjcClass>` | Classi che implementano un protocollo |
| `ObjcRuntimeReport::analyze_binary(data)` | `&[u8]` | `Result<ObjcRuntimeReport, ObjcAnalysisError>` | Parsa Mach-O e produce report runtime ObjC completo |
| `ObjcRuntimeReport::decode_type_encoding(enc)` | `&str` | `Vec<String>` | Wrapper decodifica encoding (nomi leggibili) |

---

## macho_objc_runtime.rs — Parsing Mach-O ObjC runtime diretto

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ObjcMethod::new(name, type_encoding, imp_addr)` | `String, String, u64` | `Self` | Costruttore metodo |
| `ObjcMethod::is_void_return(&self)` | `&self` | `bool` | Controlla se encoding restituisce void |
| `ObjcMethod::param_count(&self)` | `&self` | `usize` | Numero parametri dal type encoding |
| `ObjcIvar::new(name, type_encoding, offset, size)` | vari | `Self` | Costruttore ivar |
| `ObjcIvar::is_object(&self)` | `&self` | `bool` | Verifica se ivar è tipo oggetto |
| `ObjcProtocol::new(name)` | `String` | `Self` | Costruttore protocollo |
| `ObjcClass::new(name)` | `String` | `Self` | Costruttore classe |
| `ObjcClass::adopts_protocol(&self, proto)` | `&str` | `bool` | Verifica adozione protocollo |
| `ObjcClass::find_instance_method(&self, sel)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo istanza |
| `ObjcClass::find_class_method(&self, sel)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo di classe |
| `ObjcClass::find_ivar(&self, name)` | `&str` | `Option<&ObjcIvar>` | Ricerca ivar |
| `MachoObjcRuntime::parse(binary, config)` | `&[u8]`, `&ParseConfig` | `Result<Self, MachoObjcError>` | Parsa strutture ObjC dal Mach-O (classlist, catlist, protolist) |
| `MachoObjcRuntime::get_class(&self, name)` | `&str` | `Option<&ObjcClass>` | Ricerca classe per nome |
| `MachoObjcRuntime::all_class_names(&self)` | `&self` | `Vec<&str>` | Tutti i nomi classe |
| `MachoObjcRuntime::classes_adopting_protocol(&self, proto)` | `&str` | `Vec<&ObjcClass>` | Classi che adottano un protocollo |
| `MachoObjcRuntime::method_counts(&self)` | `&self` | `HashMap<&str, usize>` | Numero metodi per classe |
| `parse_objc_runtime(binary)` | `&[u8]` | `Result<MachoObjcRuntime, MachoObjcError>` | Funzione top-level: parsa runtime ObjC da Mach-O con config default |

---

## ios_malware.rs — Rilevamento malware iOS

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `SpywareIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio spyware (0-100) |
| `DataTheftIndicators::stolen_data_types(&self)` | `&self` | `Vec<&'static str>` | Categorie dati a rischio furto |
| `DataTheftIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio furto dati |
| `RansomwareIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio ransomware |
| `BackdoorIndicators::malicious_count(&self)` | `&self` | `usize` | Numero di indicatori backdoor trovati |
| `BackdoorIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio backdoor |
| `AdwareIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio adware |
| `CryptoMinerIndicators::risk_score(&self)` | `&self` | `u8` | Punteggio rischio crypto-miner |
| `ExploitKit::new(bundle_id, app_name)` | `String, String` | `Self` | Costruttore kit exploit per un'app |
| `ExploitKit::add_exploit(&mut self, exploit)` | `JailbreakExploit` | `()` | Aggiunge exploit al kit |
| `ExploitKit::has_zero_click_exploit(&self)` | `&self` | `bool` | Verifica presenza di exploit zero-click |
| `ExploitKit::max_exploit_severity(&self)` | `&self` | `Option<ExploitSeverity>` | Gravità massima tra gli exploit trovati |
| `ExploitKit::risk_score(&self)` | `&self` | `u8` | Punteggio rischio complessivo |
| `MalwareReport::is_spyware(&self)` | `&self` | `bool` | Classificazione come spyware |
| `MalwareReport::threat_summary(&self)` | `&self` | `String` | Riepilogo testuale delle minacce rilevate |

---

## ios_jailbreak_detector.rs — Rilevamento jailbreak detection nel binario

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `JailbreakReport::high_confidence_indicators(&self)` | `&self` | `Vec<&ExtendedIndicator>` | Indicatori ad alta confidenza |
| `JailbreakReport::indicators_by_method(&self, method)` | `DetectionMethod` | `Vec<&ExtendedIndicator>` | Filtra indicatori per tecnica di rilevamento |
| `IosJailbreakDetector::new()` | — | `Self` | Costruttore detector con euristiche predefinite |
| `IosJailbreakDetector::scan(&self, binary)` | `&[u8]` | `JailbreakReport` | Scansiona binario Mach-O e produce report jailbreak detection |
| `has_jailbreak_detection(binary)` | `&[u8]` | `bool` | Risposta rapida: il binario implementa jailbreak detection? |
| `jailbreak_risk_score(binary)` | `&[u8]` | `u8` | Punteggio 0-100 qualità detection jailbreak |
| `scan_indicators(binary)` | `&[u8]` | `Vec<JailbreakIndicator>` | Lista raw di indicatori trovati |

---

## jailbreak_detection.rs — Scanner jailbreak multi-sorgente

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `JailbreakScanner::scan_strings(&mut self, strings)` | `&[String]` | `()` | Scansiona lista di stringhe per pattern jailbreak |
| `JailbreakScanner::scan_symbols(&mut self, symbols)` | `&[String]` | `()` | Scansiona simboli per pattern jailbreak |
| `JailbreakScanner::scan_selectors(&mut self, selectors)` | `&[String]` | `()` | Scansiona selettori ObjC per pattern jailbreak |
| `JailbreakScanner::scan_disassembly(&mut self, disasm, fn_name)` | `&str, &str` | `()` | Scansiona output disassembler per pattern |
| `JailbreakScanner::finish(self)` | `self` | `JailbreakReport` | Finalizza e produce il report |
| `JailbreakReport::techniques_used(&self)` | `&self` | `Vec<&str>` | Tecniche di detection identificate |
| `JailbreakReport::generate_frida_bypass(&self)` | `&self` | `String` | Genera script Frida per bypassare la detection trovata |
| `analyze_strings(strings)` | `&[String]` | `JailbreakReport` | Analisi rapida solo su stringhe |
| `analyze_binary(...)` | binario + metadati | `JailbreakReport` | Analisi completa da dati estratti da binario |

---

## fairplay.rs — FairPlay DRM

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `detect_fairplay_in_slice(data)` | `&[u8]` | `Result<FairPlayStatus>` | Rileva FairPlay in singola slice Mach-O |
| `detect_fairplay(data)` | `&[u8]` | `Result<FairPlayStatus>` | Rileva FairPlay in Mach-O (fat o thin) |
| `FairPlayInfo::from_status(status)` | `FairPlayStatus` | `Self` | Costruisce info strutturate dallo status |
| `FairPlayInfo::assert_can_disassemble(&self)` | `&self` | `Result<()>` | Errore se il binario è ancora cifrato |
| `DecryptionSession::new(device_udid, bundle_id)` | `String, String` | `Self` | Nuova sessione di decifrazione |
| `DecryptionSession::advance(&mut self)` | `&mut self` | `()` | Avanza allo step successivo della decifrazione |
| `DecryptionSession::add_page(&mut self, page)` | `MemoryPage` | `()` | Aggiunge pagina di memoria decifrata |
| `DecryptionSession::reassemble(&self)` | `&self` | `Result<Vec<u8>>` | Riassembla il binario decifrato |
| `patch_cryptid(data, new_cryptid)` | `&mut [u8]`, `u32` | `()` | Patch in-place del campo cryptid nel LC_ENCRYPTION_INFO |
| `check_binary(data)` | `&[u8]` | `LoaderDecision` | Decide se il binario necessita decifrazione |
| `mark_as_decrypted(data, tool_name)` | `&mut [u8]`, `&str` | `()` | Segna il binario come decifrato (zeroing cryptid + note) |

---

## ios_swift_metadata_parser.rs — Parser Swift metadata (versione iOS)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `SwiftTypeRecord::has_stored_fields(&self)` | `&self` | `bool` | Il tipo ha campi stored? |
| `SwiftTypeRecord::stored_field_count(&self)` | `&self` | `usize` | Numero campi stored |
| `SwiftTypeRecord::find_field(&self, name)` | `&str` | `Option<&SwiftField>` | Ricerca campo per nome |
| `SwiftMetadataParser::parse_types(&self, binary)` | `&[u8]` | `Result<Vec<SwiftTypeRecord>, IosError>` | Estrae tipi Swift dal Mach-O |
| `SwiftMetadataParser::parse_conformances(&self, binary)` | `&[u8]` | `Result<Vec<ProtocolConformance>, IosError>` | Estrae conformanze di protocollo |
| `SwiftMetadataParser::parse_all(&self, binary)` | `&[u8]` | `Result<SwiftMetadataSummary, IosError>` | Estrae tutto: tipi, conformanze e metadati ausiliari |
| `parse_swift_types(binary)` | `&[u8]` | `Result<Vec<SwiftTypeRecord>, IosError>` | Funzione top-level per tipi Swift |
| `parse_protocol_conformances(binary)` | `&[u8]` | `Result<Vec<ProtocolConformance>, IosError>` | Funzione top-level per conformanze |
| `has_swift_metadata(binary)` | `&[u8]` | `bool` | Presenza di sezioni `__swift5_*` nel Mach-O |
| `has_swift_symbols(binary)` | `&[u8]` | `bool` | Presenza di simboli Swift nella symbol table |

---

## ios_codesign_verifier.rs — Verifica firma codice

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `CodeDirectory::parse(buf, offset)` | `&[u8]`, `usize` | `Result<Self, CodesignError>` | Parsa struttura CodeDirectory dalla LC_CODE_SIGNATURE |
| `SuperBlob::parse(buf)` | `&[u8]` | `Result<Self, CodesignError>` | Parsa SuperBlob (contenitore principale code sign) |
| `CodeSignVerifier::verify(binary)` | `&[u8]` | `VerificationResult` | Verifica hash slot del binario contro CodeDirectory |
| `verify_signature(binary)` | `&[u8]` | `VerificationResult` | Funzione top-level per verifica firma codice |

---

## ios_entitlements_parser.rs — Parser entitlements

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `EntitlementKind::from_key(key)` | `&str` | `Self` | Classifica una chiave entitlement per categoria |
| `EntitlementValue::display_string(&self)` | `&self` | `String` | Rappresentazione leggibile del valore |
| `Entitlement::new(key, value)` | `String`, `EntitlementValue` | `Self` | Costruttore entitlement |
| `Entitlement::is_debug(&self)` | `&self` | `bool` | Indica se è un entitlement debug (get-task-allow ecc.) |
| `EntitlementSet::is_debuggable(&self)` | `&self` | `bool` | L'app ha entitlement di debug attivi? |
| `EntitlementSet::by_kind(&self, kind)` | `EntitlementKind` | `Vec<&Entitlement>` | Filtra per categoria |
| `EntitlementSet::get(&self, key)` | `&str` | `Option<&Entitlement>` | Ricerca per chiave |
| `EntitlementSet::sensitive(&self)` | `&self` | `Vec<&Entitlement>` | Entitlement sensibili/privilegiati |
| `EntitlementSet::kind_summary(&self)` | `&self` | `HashMap<EntitlementKind, usize>` | Conteggio per categoria |
| `EntitlementParser::parse(data)` | `&[u8]` | `EntitlementParseResult` | Parsa XML entitlements dal blob code sign |
| `parse_entitlements(data)` | `&[u8]` | `EntitlementParseResult` | Funzione top-level per parsing entitlements |
| `EntitlementSummary::from_result(result)` | `&EntitlementParseResult` | `Self` | Costruisce summary aggregato dal risultato del parsing |

---

## ios_dylib_injector_detector.rs — Rilevamento dylib injection

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `DetectionResult::suspicious_dylibs(&self)` | `&self` | `Vec<&InjectedDylib>` | Dylib ritenute sospette |
| `DetectionResult::highest_risk_dylib(&self)` | `&self` | `Option<&InjectedDylib>` | Dylib col rischio più alto |
| `DylibInjectorDetector::scan(&self, binary)` | `&[u8]` | `Result<DetectionResult, IosError>` | Scansiona binary Mach-O per dylib iniettate |
| `DylibInjectorDetector::scan_frameworks(&self, frameworks)` | `&[IosFramework]` | `Vec<InjectedDylib>` | Controlla lista framework per anomalie |
| `has_injection_evidence(binary)` | `&[u8]` | `bool` | Risposta rapida: ci sono evidenze di injection? |
| `injection_risk_score(binary)` | `&[u8]` | `u8` | Punteggio rischio injection 0-100 |

---

## entitlements.rs — Analisi entitlements (livello alto)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `IosEntitlements::application_groups(&self)` | `&self` | `Vec<&str>` | App groups dichiarati |
| `IosEntitlements::keychain_groups(&self)` | `&self` | `Vec<&str>` | Keychain access groups |
| `IosEntitlements::team_id(&self)` | `&self` | `Option<&str>` | Team ID Apple Developer |
| `IosEntitlements::has_debugger_entitlement(&self)` | `&self` | `bool` | Presence di entitlement debug |
| `IosEntitlements::has_get_task_allow(&self)` | `&self` | `bool` | get-task-allow (debuggable in dev) |
| `IosEntitlements::has_platform_application(&self)` | `&self` | `bool` | Platform application entitlement |
| `IosEntitlements::has_task_for_pid(&self)` | `&self` | `bool` | task_for_pid-allow |
| `IosEntitlements::network_client(&self)` | `&self` | `bool` | com.apple.security.network.client |
| `IosEntitlements::push_notifications(&self)` | `&self` | `bool` | Push notifications entitlement |
| `IosEntitlements::apple_pay(&self)` | `&self` | `bool` | Apple Pay entitlement |
| `IosEntitlements::health_kit(&self)` | `&self` | `bool` | HealthKit entitlement |
| `IosEntitlements::homekit(&self)` | `&self` | `bool` | HomeKit entitlement |
| `IosEntitlements::inter_app_audio(&self)` | `&self` | `bool` | Inter-App Audio entitlement |
| `IosEntitlements::has_file_access_entitlements(&self)` | `&self` | `Vec<FileAccessEntitlement>` | Entitlement di accesso file |
| `IosEntitlements::sandbox_entitlements(&self)` | `&self` | `Vec<SandboxEntitlement>` | Entitlement sandbox |
| `IosEntitlements::suspicious_entitlements(&self)` | `&self` | `Vec<&str>` | Chiavi entitlement sospette o privilegiate |
| `IosEntitlements::has_suspicious_entitlements(&self)` | `&self` | `bool` | Presenza di almeno un entitlement sospetto |
| `IosEntitlements::all_keys(&self)` | `&self` | `Vec<&str>` | Tutte le chiavi entitlement presenti |
| `IosEntitlements::key_count(&self)` | `&self` | `usize` | Numero totale di entitlement |

---

## codesign.rs — Parsing code signature

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `CodeSignInfo::mock()` | — | `Self` | Istanza fittizia per test |
| `CodeSignBlob::parse(data)` | `&[u8]` | `Result<Self, CodeSignError>` | Parsa blob code signature dal Mach-O |
| `CodeSignBlob::identifier(&self)` | `&self` | `&str` | Identificatore bundle dalla firma |
| `CodeSignBlob::team_id(&self)` | `&self` | `Option<&str>` | Team ID dalla firma |

---

## lib.rs — API pubblica principale del crate

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `IosEntitlements::has(&self, key)` | `&str` | `bool` | Presenza di una chiave entitlement |
| `IosEntitlements::get(&self, key)` | `&str` | `Option<&EntitlementValue>` | Valore di un entitlement per chiave |
| `IosEntitlements::mock()` | — | `Self` | Istanza fittizia per test |
| `IosAppBinary::is_debuggable(&self)` | `&self` | `bool` | Il binario ha simboli debug o entitlement debug? |
| `IosAppBinary::system_frameworks(&self)` | `&self` | `Vec<&IosFramework>` | Framework di sistema linkati |
| `IosObjcClass::adopts_protocol(&self, proto)` | `&str` | `bool` | Adozione protocollo ObjC |
| `IosObjcClass::find_instance_method(&self, sel)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo istanza |
| `IosObjcClass::find_class_method(&self, sel)` | `&str` | `Option<&ObjcMethod>` | Ricerca metodo di classe |
| `decode_type_encoding(enc)` | `&str` | `Vec<String>` | Decodifica type encoding ObjC in nomi leggibili |
| `scan_objc_selectors(binary)` | `&[u8]` | `Vec<String>` | Estrae selettori ObjC dalla sezione `__objc_selrefs` |
| `scan_objc_classes(binary)` | `&[u8]` | `Vec<String>` | Estrae nomi classi ObjC dal binario |
| `SwiftDemangler::is_swift_mangled(name)` | `&str` | `bool` | Verifica prefisso mangling Swift (`_$s`, `_T0`, ecc.) |
| `SwiftDemangler::demangle(mangled)` | `&str` | `Option<String>` | Demangling nome Swift |
| `IosSwiftInfo::from_macho(binary)` | `&[u8]` | `Self` | Estrae info Swift (tipi, conformanze) dal Mach-O |
| `IosAppInfo::extract_app_info(ipa_bytes)` | `&[u8]` | `Option<IosAppInfo>` | Estrae metadati app da IPA (zip) |
| `IosAppInfo::parse_plist(raw)` | `&[u8]` | `Option<IosAppInfo>` | Estrae metadati da raw Info.plist |
| `IosSecurityChecker::check_arc_usage(macho_bytes)` | `&[u8]` | `bool` | Verifica uso ARC (Automatic Reference Counting) |
| `IosSecurityChecker::check_pie_enabled(macho_bytes)` | `&[u8]` | `bool` | Verifica flag PIE nel Mach-O header |
| `IosSecurityChecker::check_stack_canary(macho_bytes)` | `&[u8]` | `bool` | Verifica presenza stack canary (`___stack_chk_guard`) |
| `IosSecurityChecker::check_debug_symbols(macho_bytes)` | `&[u8]` | `bool` | Verifica presenza simboli debug |
| `IosSecurityChecker::report(macho_bytes)` | `&[u8]` | `IosSecurityReport` | Report sicurezza base (ARC, PIE, canary, debug) |
| `IosSecurityChecker::full_report(macho_bytes)` | `&[u8]` | `IosSecurityReport` | Report sicurezza esteso con analisi ObjC/Swift |
| `IosSecurityChecker::extract_objc_classes(macho_bytes)` | `&[u8]` | `Vec<String>` | Estrae nomi classi ObjC |
| `IosSecurityChecker::extract_swift_types(macho_bytes)` | `&[u8]` | `Vec<String>` | Estrae nomi tipi Swift |
| `JailbreakDetectionScanner::scan(binary)` | `&[u8]` | `Vec<JailbreakIndicator>` | Scansiona il binario per tecniche di jailbreak detection |
| `JailbreakDetectionScanner::has_jailbreak_detection(binary)` | `&[u8]` | `bool` | Risposta rapida presenza detection |
| `JailbreakDetectionScanner::technique_summary(indicators)` | `&[JailbreakIndicator]` | `Vec<(&'static str, usize)>` | Riepilogo tecniche per frequenza |
| `SslPinningScanner::scan(binary)` | `&[u8]` | `Vec<SslPinningIndicator>` | Scansiona per tecniche SSL pinning |
| `SslPinningScanner::has_ssl_pinning(binary)` | `&[u8]` | `bool` | Risposta rapida presenza SSL pinning |
| `SwizzlingScanner::scan(binary)` | `&[u8]` | `Vec<SwizzlingIndicator>` | Scansiona per uso di method swizzling |
| `SwizzlingScanner::has_swizzling(binary)` | `&[u8]` | `bool` | Risposta rapida presenza swizzling |
| `IosRuntimeAnalysis::analyse(binary)` | `&[u8]` | `Self` | Analisi runtime completa (ObjC + Swift + sicurezza) |
| `IosRuntimeAnalysis::summary(&self)` | `&self` | `String` | Riepilogo testuale dell'analisi runtime |

---

## Riepilogo

| Modulo | Funzioni pub |
|---|---|
| bundle.rs | 9 |
| info_plist.rs | 19 |
| plist.rs | 6 |
| pac.rs | 6 |
| swift_metadata.rs | 27 |
| objc_runtime.rs | 17 |
| objc_runtime_analysis.rs | 13 |
| macho_objc_runtime.rs | 17 |
| ios_malware.rs | 15 |
| ios_jailbreak_detector.rs | 7 |
| jailbreak_detection.rs | 9 |
| fairplay.rs | 11 |
| ios_swift_metadata_parser.rs | 10 |
| ios_codesign_verifier.rs | 4 |
| ios_entitlements_parser.rs | 12 |
| ios_dylib_injector_detector.rs | 6 |
| entitlements.rs | 19 |
| codesign.rs | 4 |
| lib.rs | 34 |
| **Totale** | **245** |
