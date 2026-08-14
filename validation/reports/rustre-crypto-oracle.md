# rustre-crypto-oracle

Crate per l'interazione con oracoli crittografici e l'implementazione di attacchi crittografici classici. Fornisce padding oracle (decrypt CBC completo), ECB byte-at-a-time, rilevamento riuso nonce, predizione IV, key-reuse OTP, replay attack, side-channel (DPA/timing), attacchi whitebox (DFA/BGE), hash length extension, analisi key schedule, rilevamento costanti crittografiche, e automazione HTTP degli attacchi.

**Versione:** 0.1.0  
**Edizione:** 2024  
**Dipendenze principali:** anyhow, thiserror, serde, serde_json, reqwest, tokio, subtle, getrandom, ahash

---

## Moduli

| Modulo | Descrizione |
|--------|-------------|
| `lib` (root) | Tipi base, OracleCallable/Oracle trait, attacchi CBC/ECB/OTP/RSA/timing in-process |
| `padding_oracle` | PaddingOracleAttacker con config + progress callback |
| `padding_oracle_attack` | Attacco padding oracle generico con F: Fn(&[u8])->bool |
| `padding_oracle_detector` | Scanner statico binario per rilevamento oracle PKCS#7 |
| `ecb_oracle` | Rilevamento ECB, prefix-len, suffix recovery, cut-and-paste |
| `oracle_query_engine` | Engine generico di query con cache, batch, statistiche |
| `oracle_exploitation` | Exploit CBC/ECB/timing orchestrati con log timeline |
| `oracle_detection` | Tester differenziale, classificatore oracle, validatore |
| `oracle_automation` | Client HTTP automatizzato per padding/ECB/timing oracle |
| `hash_attacks` | Sha1/SHA-512 puri + length extension SHA-256/SHA-512 |
| `hash_length_extension` | Length extension MD5/SHA-1/SHA-256 + forgery MAC |
| `key_schedule_analyzer` | Rilevamento espansione chiave AES/DES/RC4 in binari |
| `crypto_constant_finder` | Scanner costanti crittografiche (S-box, IV, k-SHA, ecc.) |
| `side_channel` | DPA su tracce di potenza, allineamento, filtraggio, SNR, EM |
| `timing_oracle_full` | Timing oracle con Welch t-test, outlier removal, cache |
| `stream_cipher_attacks` | RC4 bias, ChaCha20 fault, LFSR/Berlekamp-Massey, statistiche keystream |
| `whitebox_attacks` | DFA AES, BGE encoding recovery, GF(2) solver, analisi S-box |

---

## Funzioni pubbliche — lib.rs (root)

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `OracleDiscovery::probe_suite` | `block_size: usize` | `Result<Vec<OracleProbe>, OracleError>` | Genera suite di probe per rilevamento tipo oracle (ECB, CBC, padding, timing) |
| `OracleDiscovery::analyze_outcomes` | `block_size: usize, outcomes: &[OracleProbeOutcome]` | `OracleDiscoveryReport` | Analizza esiti probe e produce findings con confidenza |
| `OracleDiscovery::discover_with_oracle` | `block_size: usize, oracle: &dyn Oracle` | `Result<OracleDiscoveryReport, OracleError>` | Esegue probe suite su oracle live e ritorna report |
| `PaddingOracleAttack::detect_padding_error` | `oracle: &dyn OracleCallable, input: &[u8]` | `bool` | Rileva errore di padding tramite oracle |
| `PaddingOracleAttack::decrypt_block` | `ciphertext: &[u8], prev_block: &[u8], oracle: &dyn Oracle` | `Result<Vec<u8>, OracleError>` | Decripta un singolo blocco CBC 16-byte via padding oracle |
| `PaddingOracleAttack::decrypt_cbc` | `ciphertext: &[u8], iv: &[u8], oracle: &dyn Oracle` | `Result<Vec<u8>, OracleError>` | Decripta intero ciphertext CBC, rimuove padding PKCS#7 |
| `PaddingOracleAttack::decrypt_block_callable` | `ciphertext: &[u8], prev_block: &[u8], oracle: &dyn OracleCallable` | `Result<Vec<u8>, OracleError>` | Variante di decrypt_block che accetta OracleCallable |
| `EcbByteAtATime::detect_ecb` | `oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>` | `bool` | Rileva ECB con input ripetuto da 48 byte |
| `EcbByteAtATime::determine_block_size` | `oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>` | `usize` | Determina block size aumentando input finché la lunghezza output salta |
| `EcbByteAtATime::recover_unknown_suffix` | `oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>, block_size: usize` | `Vec<u8>` | Recupera il suffisso sconosciuto appendato dall'oracle (ECB byte-at-a-time) |
| `NonceReuseDetection::collect_ciphertexts` | `query_fn: NonceCiphertextQuery, plaintexts: &[&[u8]]` | `Vec<NonceCiphertext>` | Raccoglie coppie (nonce, ciphertext) da un oracle |
| `NonceReuseDetection::find_nonce_reuse` | `pairs: &[NonceCiphertext]` | `Vec<(usize, usize)>` | Trova coppie con lo stesso nonce |
| `NonceReuseDetection::attack_nonce_reuse` | `ct1: &[u8], ct2: &[u8], known_p1: &[u8]` | `Vec<u8>` | Recupera P2 dato riuso nonce e P1 noto (P2 = C1 XOR C2 XOR P1) |
| `NonceReuseDetection::xor_ciphertexts` | `ct1: &[u8], ct2: &[u8]` | `Vec<u8>` | XOR di due ciphertext (P1 XOR P2 per nonce-reuse) |
| `NonceReuseDetection::analyze_xor_for_english` | `xored: &[u8]` | `f64` | Score di stampabilità ASCII dello XOR (indice di riuso nonce con testo inglese) |
| `IvPredictionAttack::detect_counter_iv` | `ivs: &[Vec<u8>]` | `bool` | Rileva IV a contatore (incremento +1 little-endian u128) |
| `IvPredictionAttack::predict_next_iv` | `current_iv: &[u8]` | `Vec<u8>` | Predice il prossimo IV da contatore |
| `IvPredictionAttack::forge_chosen_plaintext` | `current_iv: &[u8], known_plaintext: &[u8], desired_plaintext: &[u8]` | `Vec<u8>` | Forgia plaintext scelto sfruttando IV predicibile |
| `OtpKeyReuse::xor_ciphertexts` | `ct1: &[u8], ct2: &[u8]` | `Vec<u8>` | XOR di due ciphertext con stessa chiave OTP |
| `OtpKeyReuse::analyze_xor_distribution` | `xored: &[u8]` | `f64` | Percentuale di caratteri ASCII stampabili nello XOR |
| `OtpKeyReuse::recover_p2` | `p1_xor_p2: &[u8], known_p1: &[u8]` | `Vec<u8>` | Recupera P2 dati P1 XOR P2 e P1 noto |
| `OtpKeyReuse::recover_key_byte` | `stream_byte_col: &[u8]` | `u8` | Brute-force del byte di chiave per colonna con scoring lingua inglese |
| `ReplayAttack::detect_stateless` | `oracle: &dyn OracleCallable, ciphertext: &[u8]` | `bool` | Rileva oracle stateless inviando lo stesso ciphertext due volte |
| `ReplayAttack::replay` | `oracle: &dyn OracleCallable, captured_ct: &[u8]` | `OracleResult` | Riproduce un ciphertext catturato sull'oracle |
| `ReplayAttack::collect_responses` | `oracle: &dyn OracleCallable, ciphertext: &[u8], count: usize` | `Vec<OracleResult>` | Raccoglie N risposte oracle allo stesso ciphertext |
| `EmulatorOracle::new` | `config: EmulatorOracleConfig` | `EmulatorOracle` | Crea oracle emulato (stub Unicorn) |
| `EmulatorOracle::decrypt` | `ciphertext: &[u8], _key: &[u8]` | `Result<Vec<u8>, OracleError>` | Emula funzione di decrypt (stub; ritorna input come placeholder) |
| `CbcBitFlippingAttack::flip` | `ciphertext: &[u8], iv: &[u8], target_offset: usize, known_plain: u8, desired: u8` | `Result<(Vec<u8>, Vec<u8>), OracleError>` | Applica bit-flip CBC al byte target forgiando plaintext desiderato |
| `EcbCutAndPasteAttack::detect_ecb` | `ciphertext: &[u8], block_size: usize` | `bool` | Rileva ECB cercando blocchi ripetuti |
| `EcbCutAndPasteAttack::reorder_blocks` | `ciphertext: &[u8], block_size: usize, order: &[usize]` | `Result<Vec<u8>, OracleError>` | Riordina blocchi ECB secondo indici forniti |
| `TimingAttack::median_duration` | `measurements: &[TimingMeasurement]` | `Option<u64>` | Calcola mediana dei tempi di risposta |
| `TimingAttack::find_max_duration` | `measurements: &[TimingMeasurement]` | `Option<&TimingMeasurement>` | Trova la misurazione con durata massima |
| `TimingAttack::byte_timing_attack` | `oracle_fn: F: Fn(u8)->u64, samples: usize` | `u8` | Attacco timing per un byte: trova candidato con media massima |
| `AesCracker::is_weak_key` | `key: &[u8]` | `bool` | Verifica se la chiave è debole (tutti 0x00, 0xFF, crescente, decrescente) |
| `AesCracker::weak_keys` | — | `Vec<Vec<u8>>` | Ritorna lista di chiavi AES-128 deboli predefinite |
| `AesCracker::brute_force_short` | `key_len: usize, verify_fn: F: Fn(&[u8])->bool` | `Option<Vec<u8>>` | Brute-force chiavi fino a 3 byte (max 16M tentativi) |
| `RsaAttacks::small_exponent_attack` | `ciphertext_bytes: &[u8], exponent: u32` | `Option<Vec<u8>>` | Attacco esponente piccolo RSA (e=3) con radice cubica intera |
| `RsaAttacks::wiener_attack` | `e: u64, n: u64` | `Option<u64>` | Attacco di Wiener via frazioni continue per d piccolo |
| `RsaAttacks::fermat_factor` | `modulus: u64` | `Option<(u64, u64)>` | Fattorizzazione di Fermat per p, q vicini |
| `RsaAttacks::common_modulus_attack` | `c1: u64, e1: i64, c2: u64, e2: i64, n: u64` | `Option<u64>` | Attacco common modulus RSA con Bezout (GCD=1) |
| `HttpRequestTemplate::render` | `values: &HashMap<String, Vec<u8>>` | `HttpRequest` | Costruisce richiesta HTTP risolvendo campi (con sort topologico per HMAC/Derived) |
| `HttpRequestTemplate::randomize_field` | `field: &ProtocolField` | `Vec<u8>` | Genera valore casuale/statico per un campo protocollo |
| `ProtocolSynthesizer::infer_fields` | `samples: &[Vec<u8>]` | `Vec<ProtocolField>` | Inferisce tipo di campo (Static/Random/Counter) da campioni osservati |
| `ProtocolSynthesizer::export_python_server` | `template: &HttpRequestTemplate` | `String` | Genera server Flask Python dal template di richiesta |
| `OracleVerifier::verify_oracle` | `oracle_url: &str, sample_request: &[u8]` | `anyhow::Result<bool>` | Async: invia POST e verifica raggiungibilità oracle remoto (2xx = true) |
| `RequestFieldAnalyzer::analyze_field_across_samples` | `samples: &[Vec<u8>]` | `FieldCharacteristics` | Classifica campo protocollo (costante/random/incrementale/timestamp) con entropia |
| `FieldFlags::from_tuple` | `(bool, bool, bool, bool)` | `FieldFlags` | Costruisce bitmask da tuple (is_constant, is_random, is_incrementing, is_timestamp) |
| `FieldFlags::is_constant` | `self` | `bool` | Bit 0: valore costante |
| `FieldFlags::is_random` | `self` | `bool` | Bit 1: distribuzione casuale |
| `FieldFlags::is_incrementing` | `self` | `bool` | Bit 2: monotonamente crescente |
| `FieldFlags::is_timestamp` | `self` | `bool` | Bit 3: formato timestamp Unix |

---

## Funzioni pubbliche — padding_oracle.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `PaddingOracleAttacker::new` | `config: PaddingOracleConfig` | `Self` | Crea attaccante con configurazione |
| `PaddingOracleAttacker::with_progress` | `f: ProgressFn` | `Self` | Imposta callback di progresso |
| `PaddingOracleAttacker::decrypt` | `ciphertext: &[u8], iv: &[u8], oracle: &dyn Oracle` | `Result<Vec<u8>, OracleError>` | Decripta ciphertext CBC completo |
| `PaddingOracleAttacker::decrypt_block` | `ct_block: &[u8], prev_block: &[u8], oracle: &dyn Oracle` | `Result<Vec<u8>, OracleError>` | Decripta un singolo blocco |
| `PaddingOracleAttacker::bit_flip_attack` | `ciphertext: &[u8], iv: &[u8], offset: usize, from: u8, to: u8` | `Result<(Vec<u8>, Vec<u8>), OracleError>` | Bit-flip CBC per modificare plaintext in posizione offset |
| `validate_pkcs7` | `data: &[u8]` | `bool` | Valida padding PKCS#7 |
| `strip_pkcs7` | `data: &[u8]` | `Option<Vec<u8>>` | Rimuove padding PKCS#7, None se invalido |
| `add_pkcs7` | `data: &[u8], block_size: usize` | `Vec<u8>` | Aggiunge padding PKCS#7 |
| `detect_block_size` | `encrypt_fn: F: Fn(&[u8])->Vec<u8>` | `Option<usize>` | Rileva block size da oracle di encryption |

---

## Funzioni pubbliche — padding_oracle_attack.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `PaddingOracleAttacker::new` | `block_size: usize, oracle: F: Fn(&[u8])->bool` | `Self` | Crea attaccante con closure oracle |
| `PaddingOracleAttacker::with_progress` | `cb: P: Fn(&AttackProgress)` | `Self` | Aggiunge callback di progresso |
| `PaddingOracleAttacker::decrypt_ciphertext` | `ciphertext: &[u8]` | `Result<Vec<u8>, AttackError>` | Decripta ciphertext completo con oracle bool |
| `pkcs7_pad` | `data: &[u8], block_size: usize` | `Vec<u8>` | Aggiunge padding PKCS#7 |
| `decrypt_with_oracle` | `oracle: F: Fn(&[u8])->bool, ciphertext: &[u8], block_size: usize` | `Result<Vec<u8>, AttackError>` | Shortcut: decripta senza istanziare struct |

---

## Funzioni pubbliche — padding_oracle_detector.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `pkcs7_validate` | `block: &[u8]` | `Option<usize>` | Valida PKCS#7, ritorna lunghezza padding |
| `pkcs7_pad` | `data: &[u8], block_size: usize` | `Vec<u8>` | Padding PKCS#7 |
| `pkcs7_unpad` | `data: &[u8]` | `Option<Vec<u8>>` | Rimuove padding, None se invalido |
| `OracleVulnerability::with_function` | `name: impl Into<String>` | `Self` | Builder: imposta funzione sorgente |
| `OracleVulnerability::with_confidence` | `c: u8` | `Self` | Builder: imposta confidenza |
| `OracleVulnerability::add_note` | `note: impl Into<String>` | `()` | Aggiunge nota testuale |
| `OracleVulnerability::from_check` | `check: PaddingCheck` | `Self` | Costruisce vulnerabilità da check di padding |
| `OracleVulnerability::with_timing_side_channel` | `self` | `Self` | Marca la vulnerabilità come side-channel timing |
| `OracleVulnerability::is_critical` | `&self` | `bool` | True se confidenza >= 80 |
| `OracleVulnerability::summary` | `&self` | `String` | Descrizione testuale della vulnerabilità |
| `PaddingOracleScanner::new` | — | `Self` | Crea scanner con pattern built-in |
| `PaddingOracleScanner::emit_signal` | `addr: u64, st: SignalType, strength: u8, desc` | `()` | Aggiunge segnale di rilevamento |
| `PaddingOracleScanner::scan_binary` | `data: &[u8], base_address: u64` | `()` | Scansiona binario per pattern PKCS#7 |
| `PaddingOracleScanner::scan_with_hints` | `data: &[u8], base_address: u64, hints: &[u64]` | `()` | Scansione guidata da indirizzi hint |
| `PaddingOracleScanner::record_check` | `check: PaddingCheck` | `()` | Registra un check di padding osservato |
| `PaddingOracleScanner::finalize` | `&mut self` | `()` | Consolida i check in vulnerabilità |
| `PaddingOracleScanner::checks` | `&self` | `&[PaddingCheck]` | Ritorna i check registrati |
| `PaddingOracleScanner::vulnerabilities` | `&self` | `&[OracleVulnerability]` | Ritorna le vulnerabilità trovate |
| `PaddingOracleScanner::signals` | `&self` | `&[DetectionSignal]` | Ritorna i segnali emessi |
| `PaddingOracleScanner::critical_vulnerabilities` | `&self` | `Vec<&OracleVulnerability>` | Filtra vulnerabilità critiche |
| `PaddingOracleScanner::report` | `&self` | `String` | Report testuale completo |
| `MockCbcOracle::encrypt` | `plaintext: &[u8]` | `Vec<u8>` | Cifra CBC con XOR semplificato (test) |
| `MockCbcOracle::decrypt_and_check_padding` | `ciphertext: &[u8]` | `Result<Vec<u8>, String>` | Decifra e valida padding (mock oracle) |

---

## Funzioni pubbliche — ecb_oracle.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `EcbOracleAnalyzer::new` | — | `Self` | Crea analizzatore ECB |
| `EcbOracleAnalyzer::detect_ecb` | `oracle: &dyn EcbOracle` | `bool` | Rileva ECB con input ripetuto |
| `EcbOracleAnalyzer::determine_block_size` | `oracle: &dyn EcbOracle` | `Result<usize, EcbOracleError>` | Determina block size da salti di lunghezza |
| `EcbOracleAnalyzer::detect_prefix_len` | `oracle: &dyn EcbOracle, block_size: usize` | `Result<usize, EcbOracleError>` | Rileva lunghezza prefix oracle ECB |
| `EcbOracleAnalyzer::recover_unknown_suffix` | `oracle: &dyn EcbOracle, block_size: usize, prefix_len: usize` | `Result<Vec<u8>, EcbOracleError>` | Recupera suffisso sconosciuto ECB byte-at-a-time |
| `EcbOracleAnalyzer::cut_and_paste_attack` | `oracle: &dyn EcbOracle, block_size: usize, ...` | `Result<Vec<u8>, EcbOracleError>` | Cut-and-paste ECB per forgiare ciphertext |
| `build_byte_dictionary` | `oracle: &dyn EcbOracle, block_size: usize, known_prefix: &[u8]` | `HashMap<Vec<u8>, u8>` | Costruisce dizionario blocco→byte per byte-at-a-time |
| `check_ecb_in_ciphertext` | `ciphertext: &[u8], block_size: usize` | `bool` | Cerca blocchi duplicati nel ciphertext |
| `detect_block_size_from_pairs` | `pairs: &[(usize, usize)]` | `Option<usize>` | Stima block size da coppie (input_len, output_len) |

---

## Funzioni pubbliche — oracle_query_engine.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `OracleQuery::probe` | `payload: Vec<u8>, byte_offset: usize, candidate: u8` | `OracleQuery` | Costruisce query di probe |
| `OracleStats::accept_rate` | `&self` | `f64` | Percentuale di risposte accettate |
| `OracleEngine::new` | `oracle: F, kind: OracleKind, block_size: usize` | `Self` | Crea engine con oracle closure |
| `OracleEngine::query` | `q: OracleQuery` | `OracleResponse` | Esegue query singola con caching |
| `OracleEngine::probe_byte` | `byte_offset: usize, build_payload: G` | `Vec<u8>` | Proba tutti i 256 valori per un byte |
| `OracleEngine::recover_bytes` | `num_bytes: usize, build_payload: G` | `Vec<u8>` | Recupera N byte usando probe_byte iterativamente |
| `OracleEngine::detect_block_size` | `encrypt: E: Fn(&[u8])->Vec<u8>` | `Option<usize>` | Rileva block size da oracle di encryption |
| `OracleEngine::detect_ecb_mode` | `encrypt: E: Fn(&[u8])->Vec<u8>` | `bool` | Rileva ECB tramite blocchi ripetuti |
| `OracleEngine::query_batch` | `queries: Vec<OracleQuery>` | `Vec<OracleResponse>` | Esegue batch di query |
| `OracleEngine::query_all_candidates` | `byte_offset: usize, build_payload: G` | `Vec<OracleResponse>` | Query per tutti 256 candidati a byte_offset |
| `OracleEngine::clear_cache` | `&mut self` | `()` | Svuota la cache delle query |
| `OracleEngine::reset_stats` | `&mut self` | `()` | Azzera le statistiche |
| `query_oracle` | `oracle: &mut F: Fn(&[u8])->bool, payload: &[u8]` | `bool` | Helper funzionale per query singola |

---

## Funzioni pubbliche — oracle_exploitation.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ExploitResult::success_plaintext` | `exploit_type, plaintext, queries, bytes_per_query` | `ExploitResult` | Costruisce risultato positivo con plaintext |
| `ExploitResult::failure` | `exploit_type, reason, queries` | `ExploitResult` | Costruisce risultato negativo |
| `ExploitResult::queries_per_byte` | `&self` | `f64` | Efficienza: query per byte decriptato |
| `ExploitTimeline::new` | — | `Self` | Crea timeline vuota |
| `ExploitTimeline::record` | `payload: Vec<u8>, result: bool, note: Option<String>` | `()` | Registra evento timeline |
| `ExploitTimeline::total_queries` | `&self` | `u64` | Totale query eseguite |
| `ExploitTimeline::accepted_count` | `&self` | `u64` | Query accettate dall'oracle |
| `ExploitTimeline::rejected_count` | `&self` | `u64` | Query rifiutate dall'oracle |
| `ExploitTimeline::acceptance_ratio` | `&self` | `f64` | Rapporto accettate/totale |
| `ExploitTimeline::first_accepted` | `&self` | `Option<&TimelineEntry>` | Prima query accettata |
| `ExploitTimeline::slice` | `from: usize, to: usize` | `&[TimelineEntry]` | Slice della timeline |
| `CbcDecryptExploit::new` | `oracle: &'a dyn Oracle, block_size: usize` | `Self` | Crea exploit CBC |
| `CbcDecryptExploit::decrypt_block` | `ct_block: &[u8], prev_block: &[u8]` | `Result<Vec<u8>, OracleError>` | Decripta un blocco CBC con log timeline |
| `CbcDecryptExploit::decrypt_all` | `ciphertext: &[u8], iv: &[u8]` | `ExploitResult` | Decripta tutto il ciphertext CBC |
| `TimingExploit::new` | `timing_fn: impl Fn(&[u8])->u64, samples: usize` | `Self` | Crea exploit timing |
| `TimingExploit::attack_byte` | `prefix: &[u8], suffix: &[u8]` | `(u8, u64)` | Attacca un byte con timing (restituisce (guess, avg_time)) |
| `TimingExploit::attack_secret` | `secret_len: usize, prefix: &[u8]` | `Vec<u8>` | Recupera secret byte per byte con timing |
| `TimingExploit::compare_payloads` | `a: &[u8], b: &[u8]` | `i64` | Confronta durate medie di due payload |
| `EcbSuffixExploit::new` | `encrypt_fn: impl Fn(&[u8])->Vec<u8>` | `Self` | Crea exploit ECB suffix |
| `EcbSuffixExploit::detect_block_size` | `&mut self` | `usize` | Rileva block size |
| `EcbSuffixExploit::confirm_ecb` | `&mut self` | `bool` | Conferma modalità ECB |
| `EcbSuffixExploit::recover_suffix` | `&mut self` | `ExploitResult` | Recupera il suffisso sconosciuto |
| `EcbSuffixExploit::suffix_length` | `&mut self` | `usize` | Stima lunghezza del suffisso |
| `ExploitSession::run_padding_oracle` | `oracle: &dyn Oracle, ciphertext: &[u8], iv: &[u8], block_size: usize` | `ExploitResult` | Esegue sessione completa padding oracle |
| `ExploitSession::run_ecb_attack` | `encrypt_fn: impl Fn(&[u8])->Vec<u8>` | `ExploitResult` | Esegue sessione completa attacco ECB |
| `ExploitSession::successful_results` | `&self` | `Vec<&ExploitResult>` | Filtra risultati positivi |
| `ExploitSession::last_result` | `&self` | `Option<&ExploitResult>` | Ultimo risultato della sessione |
| `ExploitSession::summary` | `&self` | `String` | Sommario testuale della sessione |
| `ExploitReport::from_results` | `results: &[ExploitResult]` | `ExploitReport` | Costruisce report aggregato da lista risultati |
| `ExploitReport::success_rate` | `&self` | `f64` | Tasso di successo degli exploit |

---

## Funzioni pubbliche — oracle_detection.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ResponseProfile::add_sample` | `time_us: u64, length: usize, status: u16, error: Option<String>` | `()` | Aggiunge campione di risposta oracle |
| `ResponseProfile::mean_time_us_int` | `&self` | `Option<u64>` | Media temporale intera (µs) |
| `ResponseProfile::mean_time_us` | `&self` | `Option<f64>` | Media temporale float (µs) |
| `ResponseProfile::std_dev_time_us` | `&self` | `Option<f64>` | Deviazione standard temporale |
| `ResponseProfile::mean_length` | `&self` | `Option<f64>` | Media lunghezze risposta |
| `ResponseProfile::distinct_status_codes` | `&self` | `Vec<u16>` | Status code distinti osservati |
| `ResponseProfile::distinct_lengths` | `&self` | `Vec<usize>` | Lunghezze risposta distinte |
| `ResponseProfile::is_length_bimodal` | `&self` | `bool` | True se esistono 2+ lunghezze distinte |
| `ResponseProfile::is_status_bimodal` | `&self` | `bool` | True se esistono 2+ status code distinti |
| `OracleSignature::new` | `label: impl Into<String>` | `Self` | Crea firma oracle da etichetta |
| `OracleSignature::matches` | `status: u16, length: usize, error: Option<&str>` | `bool` | Verifica match con risposta osservata |
| `DifferentialTester::record_valid` | `time_us: u64, len: usize, status: u16, error: Option<String>` | `()` | Registra risposta oracle a input valido |
| `DifferentialTester::record_invalid` | `time_us: u64, len: usize, status: u16, error: Option<String>` | `()` | Registra risposta oracle a input invalido |
| `DifferentialTester::timing_delta_us` | `&self` | `Option<f64>` | Delta temporale float valido/invalido (µs) |
| `DifferentialTester::timing_delta_us_int` | `&self` | `Option<u64>` | Delta temporale intero valido/invalido (µs) |
| `DifferentialTester::has_timing_difference` | `threshold_us: f64` | `bool` | True se delta supera soglia |
| `DifferentialTester::has_length_difference` | `&self` | `bool` | True se lunghezze valido/invalido differiscono |
| `DifferentialTester::has_status_difference` | `&self` | `bool` | True se status code differiscono |
| `OracleClassifier::classify` | `tester: &DifferentialTester` | `OracleClass` | Classifica tipo oracle da risultati differenziali |
| `OracleDetector::detect_ecb` | `ciphertexts: &[Vec<u8>], block_size: usize` | `bool` | Rileva ECB in lista ciphertext |
| `OracleDetector::estimate_block_size` | `response_lengths: &[usize]` | `Option<usize>` | Stima block size da variazioni di lunghezza output |
| `OracleDetector::validate` | `target: &str, probes: &[OracleProbe], oracle_fn: F` | `OracleDiscoveryReport` | Valida oracle con suite di probe |
| `OracleDetectionReport::no_oracle` | `target: impl Into<String>` | `Self` | Report negativo: nessun oracle trovato |
| `OracleDetectionReport::run` | `target: &str, oracle_fn: F, block_size: usize` | `Self` | Esegue rilevamento completo e produce report |
| `OracleDetectionReport::add_note` | `note: impl Into<String>` | `()` | Aggiunge nota al report |
| `OracleDetectionReport::is_oracle_found` | `&self` | `bool` | True se almeno una finding con confidenza >= 70 |

---

## Funzioni pubbliche — oracle_automation.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `OracleHttpConfig::new` | `target_url, cipher_param` | `Self` | Crea config HTTP per oracle remoto |
| `OracleHttpConfig::with_param` | `k, v` | `Self` | Aggiunge parametro HTTP extra |
| `OracleHttpConfig::with_auth` | `header` | `Self` | Imposta header di autenticazione |
| `QueryRateLimiter::new` | `qps: f64` | `Self` | Crea rate limiter a N query/s |
| `QueryRateLimiter::unlimited` | — | `Self` | Rate limiter senza limite |
| `QueryRateLimiter::throttle` | `&mut self` | `()` | Attende per rispettare QPS |
| `QueryRateLimiter::effective_qps` | `&self` | `f64` | QPS effettivo misurato |
| `AutoPaddingOracle::query` | `ciphertext: &[u8]` | `Option<bool>` | Query HTTP con detection automatica padding validity |
| `AutoPaddingOracle::decrypt_block` | `ct_block: &[u8], prev_block: &[u8]` | `Option<Vec<u8>>` | Decripta blocco via oracle HTTP |
| `AutoPaddingOracle::decrypt_cbc` | `ciphertext: &[u8], iv: &[u8]` | `Option<PaddingOracleResult>` | Decripta CBC completo via oracle HTTP |
| `AutoEcbOracle::detect_block_size` | `&mut self` | `usize` | Rileva block size via oracle HTTP |
| `AutoEcbOracle::detect_ecb` | `&mut self` | `bool` | Rileva ECB via oracle HTTP |
| `AutoEcbOracle::recover_suffix` | `&mut self` | `Vec<u8>` | Recupera suffisso ECB via oracle HTTP |
| `AutoTimingOracle::recover_bytes` | `num_bytes: usize, build_payload: G` | `TimingOracleResult` | Recupera N byte via timing oracle HTTP |
| `Finding::new` | `title, severity, description` | `Self` | Crea finding di vulnerabilità |
| `Finding::with_poc` | `poc` | `Self` | Aggiunge proof-of-concept |
| `Finding::with_remediation` | `r` | `Self` | Aggiunge remediation |
| `AuditReport::new` | `target` | `Self` | Crea report di audit |
| `AuditReport::add_finding` | `f: Finding` | `()` | Aggiunge finding al report |
| `AuditReport::critical_count` | `&self` | `usize` | Conta finding critiche |
| `AuditReport::high_or_above` | `&self` | `usize` | Conta finding high+ |
| `AuditReport::text_summary` | `&self` | `String` | Sommario testuale del report |
| `AuditReport::to_json` | `&self` | `String` | Serializzazione JSON del report |
| `AuditReport::padding_oracle_finding` | `result: &PaddingOracleResult` | `Finding` | Crea finding da risultato padding oracle |

---

## Funzioni pubbliche — hash_attacks.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `sha512` | `data: &[u8]` | `[u8; 64]` | SHA-512 puro (implementazione interna) |
| `sha1` | `data: &[u8]` | `[u8; 20]` | SHA-1 puro (implementazione interna) |
| `LengthExtensionState::extension_bytes` | `original_len: usize, secret_len: usize` | `&[u8]` | Calcola bytes di estensione per il messaggio forgiato |
| `HashLengthExtensionAttack::extend_sha256` | `mac: &[u8; 32], orig_msg_len: usize, secret_len: usize, extension: &[u8]` | `Result<([u8; 32], Vec<u8>)>` | Attacco length extension su SHA-256: ritorna (new_mac, forged_msg) |
| `HashLengthExtensionAttack::extend_sha512` | `mac: &[u8; 64], orig_msg_len: usize, secret_len: usize, extension: &[u8]` | `Result<([u8; 64], Vec<u8>)>` | Attacco length extension su SHA-512 |
| `HashLengthExtensionAttack::forge_mac` | `known_mac: &[u8], orig_msg_len: usize, secret_len: usize, extension: &[u8], algo: HashAlgorithm, verify_fn: F` | `Result<Vec<u8>>` | Forgia MAC via length extension e verifica con oracle |

---

## Funzioni pubbliche — hash_length_extension.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `HashLengthExtension::attack` | `known_hash: &[u8], original_msg: &[u8], secret_len: usize, extension: &[u8], algo: HashAlgorithm` | `Result<HashForgeResult>` | Esegue length extension generico (MD5/SHA-1/SHA-256) |
| `md_padding` | `msg_len: usize, algo: HashAlgorithm` | `Vec<u8>` | Calcola padding Merkle-Damgård per la lunghezza data |
| `md5` | `data: &[u8]` | `Vec<u8>` | MD5 puro (implementazione interna) |
| `sha1` | `data: &[u8]` | `Vec<u8>` | SHA-1 puro (implementazione interna) |
| `sha256` | `data: &[u8]` | `Vec<u8>` | SHA-256 puro (implementazione interna) |

---

## Funzioni pubbliche — key_schedule_analyzer.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `KeySchedulePattern::aes_ni` | — | `Self` | Pattern AES-NI (costanti hardware) |
| `KeySchedulePattern::aes_software` | — | `Self` | Pattern AES software (S-box, rcon) |
| `KeySchedulePattern::des` | — | `Self` | Pattern DES (PC-1, PC-2, permutation tables) |
| `KeySchedulePattern::rc4` | — | `Self` | Pattern RC4 (KSA identity init) |
| `KeySchedulePattern::count_constant_hits` | `binary_data: &[u8]` | `usize` | Conta occorrenze di costanti nel binario |
| `KeySchedulePattern::evaluate` | `binary_data: &[u8], opcodes: &[String]` | `Confidence` | Valuta confidenza di match del pattern |
| `KeySchedule::expand_aes128` | `key: &[u8; 16]` | `Self` | Espande chiave AES-128 (11 round key × 16 byte) |
| `KeySchedule::expand_aes256` | `key: &[u8; 32]` | `Self` | Espande chiave AES-256 (15 round key × 16 byte) |
| `KeySchedule::expand_rc4` | `key: &[u8]` | `Self` | Genera stato iniziale KSA RC4 |
| `KeySchedule::round_key` | `round: usize` | `Option<&[u8]>` | Ritorna round key per indice |
| `KeyScheduleMatch::is_high_confidence` | `&self` | `bool` | True se confidenza > 70% |
| `KeyScheduleMatch::summary` | `&self` | `String` | Sommario testuale del match |
| `KeyScheduleAnalyzer::new` | — | `Self` | Crea analyzer con pattern predefiniti |
| `KeyScheduleAnalyzer::strict` | — | `Self` | Crea analyzer con soglia alta |
| `KeyScheduleAnalyzer::add_pattern` | `pattern: KeySchedulePattern` | `()` | Aggiunge pattern custom |
| `KeyScheduleAnalyzer::scan` | `data: &[u8], base_address: u64, opcodes: &[String]` | `()` | Scansiona binario per pattern key schedule |
| `KeyScheduleAnalyzer::try_expand_aes128` | `data: &[u8], base_address: u64, key_offset: usize` | `()` | Tenta espansione AES-128 da offset candidato |
| `KeyScheduleAnalyzer::matches` | `&self` | `&[KeyScheduleMatch]` | Ritorna tutti i match trovati |
| `KeyScheduleAnalyzer::matches_above` | `threshold: Confidence` | `Vec<&KeyScheduleMatch>` | Filtra match sopra soglia di confidenza |
| `KeyScheduleAnalyzer::matches_by_cipher` | `&self` | `HashMap<String, Vec<&KeyScheduleMatch>>` | Raggruppa match per nome cifrario |
| `KeyScheduleAnalyzer::reset` | `&mut self` | `()` | Azzera risultati |
| `KeyScheduleAnalyzer::report` | `&self` | `String` | Report testuale dei match |
| `verify_aes128_expansion` | — | `bool` | Self-test: verifica correttezza key expansion AES-128 |

---

## Funzioni pubbliche — crypto_constant_finder.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ConstantPattern::builtin_patterns` | — | `Vec<Self>` | Restituisce pattern built-in (SHA-256 IV/K, AES S-box, MD5 init, ecc.) |
| `ConstantMatch::summary` | `&self` | `String` | Sommario testuale del match |
| `CryptoConstantFinder::new` | — | `Self` | Crea finder con pattern built-in |
| `CryptoConstantFinder::empty` | — | `Self` | Crea finder senza pattern |
| `CryptoConstantFinder::add_pattern` | `pattern: ConstantPattern` | `()` | Aggiunge pattern custom |
| `CryptoConstantFinder::scan` | `data: &[u8], base_address: u64` | `()` | Scansiona binario per costanti crittografiche |
| `CryptoConstantFinder::matches` | `&self` | `&[ConstantMatch]` | Ritorna tutti i match |
| `CryptoConstantFinder::high_confidence_matches` | `&self` | `Vec<&ConstantMatch>` | Filtra match ad alta confidenza |
| `CryptoConstantFinder::by_algorithm` | `&self` | `HashMap<String, Vec<&ConstantMatch>>` | Raggruppa match per algoritmo |
| `CryptoConstantFinder::by_category` | `&self` | `HashMap<String, Vec<&ConstantMatch>>` | Raggruppa match per categoria |
| `CryptoConstantFinder::for_algorithm` | `alg: &CryptoAlgorithm` | `Vec<&ConstantMatch>` | Filtra match per algoritmo specifico |
| `CryptoConstantFinder::clear_matches` | `&mut self` | `()` | Azzera i match |
| `CryptoConstantFinder::report` | `&self` | `String` | Report testuale completo |
| `test_blob_with_sha256_iv` | `offset: usize` | `Vec<u8>` | Genera blob di test con IV SHA-256 all'offset dato |
| `test_blob_with_sha1_iv` | `offset: usize` | `Vec<u8>` | Genera blob di test con IV SHA-1 all'offset dato |

---

## Funzioni pubbliche — side_channel.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `PowerTrace::mean` | `&self` | `f64` | Media dei campioni di potenza |
| `PowerTrace::variance` | `&self` | `f64` | Varianza dei campioni |
| `PowerTrace::std_dev` | `&self` | `f64` | Deviazione standard |
| `PowerTrace::subtract` | `other: &Self` | `Self` | Differenza punto-per-punto tra tracce |
| `PowerTrace::energy` | `&self` | `f64` | Energia (somma quadrati) della traccia |
| `PowerTrace::normalize` | `&self` | `Self` | Normalizza la traccia (media 0, std 1) |
| `DpaKeyByteResult::top_candidates` | `n: usize` | `Vec<(u8, f64)>` | Top-N candidati chiave per correlazione |
| `DpaAnalyzer::add_trace` | `trace: PowerTrace` | `()` | Aggiunge traccia di potenza con chiave osservata |
| `DpaAnalyzer::pearson_correlation` | `x: &[f64], y: &[f64]` | `f64` | Correlazione di Pearson tra due vettori |
| `DpaAnalyzer::correlate_traces` | `key_guess: u8` | `Vec<f64>` | Correlazione tracce con modello Hamming per key_guess |
| `DpaAnalyzer::dpa_attack_aes_key_byte` | `byte_pos: usize` | `DpaKeyByteResult` | Attacco DPA su un byte della chiave AES |
| `TraceAligner::dtw_distance` | `a: &PowerTrace, b: &PowerTrace` | `f64` | Distanza DTW tra due tracce |
| `TraceAligner::align` | `reference: &PowerTrace, trace: &PowerTrace, max_shift: usize` | `PowerTrace` | Allinea traccia a riferimento per correlazione massima |
| `TraceAligner::shift_trace` | `trace: &PowerTrace, shift: i64` | `PowerTrace` | Applica shift temporale alla traccia |
| `TraceAligner::align_batch` | `reference: &PowerTrace, traces: &[PowerTrace], max_shift: usize` | `Vec<PowerTrace>` | Allinea batch di tracce |
| `TraceAligner::average_trace` | `traces: &[PowerTrace]` | `PowerTrace` | Media punto-per-punto di tracce |
| `TraceFilter::low_pass` | `trace: &PowerTrace, window_size: usize` | `PowerTrace` | Filtro passa-basso (media mobile) |
| `TraceFilter::high_pass` | `trace: &PowerTrace, window_size: usize` | `PowerTrace` | Filtro passa-alto (differenza) |
| `TraceFilter::notch` | `trace: &PowerTrace, notch_period_samples: usize` | `PowerTrace` | Filtro notch a periodo specifico |
| `TraceFilter::smooth` | `trace: &PowerTrace` | `PowerTrace` | Smoothing gaussiano 5-tap |
| `PowerPeakDetector::find_peaks` | `trace: &PowerTrace, threshold: f64, min_distance: usize` | `Vec<PowerPeak>` | Rileva picchi di potenza sopra soglia |
| `PowerPeakDetector::classify_aes_rounds` | `peaks: &[PowerPeak]` | `Option<Vec<(usize, usize)>>` | Classifica picchi come round AES (10 round attesi) |
| `PowerPeakDetector::snr` | `traces_class0, traces_class1` | `Vec<f64>` | SNR punto-per-punto tra due classi di tracce |
| `EmTraceMap::add_trace` | `trace: EmTrace` | `()` | Aggiunge traccia EM con coordinate fisiche |
| `EmTraceMap::traces_near` | `x: f64, y: f64, radius: f64` | `Vec<&EmTrace>` | Tracce EM nell'intorno di punto fisico |
| `EmTraceMap::best_probe_position` | `target_byte: u8, ...` | `Option<(f64, f64)>` | Trova posizione sonda EM ottimale per byte target |

---

## Funzioni pubbliche — timing_oracle_full.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TimingStats::from_measurements` | `measurements: &[TimingMeasurement]` | `Result<Self, TimingError>` | Calcola statistiche (mean, std, cv) da misurazioni |
| `TimingStats::from_durations` | `durations: &[u64]` | `Result<Self, TimingError>` | Statistiche da vettore di durate |
| `TimingStats::cv` | `&self` | `f64` | Coefficiente di variazione |
| `TimingStats::is_constant_time` | `&self` | `bool` | True se CV < 0.05 (timing costante) |
| `TimingTest::welch_t_test` | `class0: &[u64], class1: &[u64]` | `Result<f64, TimingError>` | Welch t-test tra due distribuzioni temporali |
| `TimingTest::from_distributions` | `class0: &[u64], class1: &[u64]` | `Result<Self, TimingError>` | Costruisce test con t-statistic e gradi di libertà |
| `TimingTest::is_exploitable` | `&self` | `bool` | True se t-statistic > soglia (vulnerabile) |
| `TimingTest::constant_time_report` | — | `Self` | Report negativo (timing costante) |
| `TimingOracleAttack::new` | — | `Self` | Crea attacco timing con default |
| `TimingOracleAttack::with_params` | `samples_per_byte: usize, alpha: f64` | `Self` | Crea con parametri custom |
| `TimingOracleAttack::collect_measurements` | `oracle_fn: F, byte_val: u8, n: usize` | `Vec<TimingMeasurement>` | Raccoglie N misurazioni per un valore byte |
| `TimingOracleAttack::attack_byte` | `oracle_fn: F, prefix: &[u8], suffix: &[u8]` | `(u8, TimingTest)` | Attacca singolo byte con Welch t-test per ogni candidato |
| `TimingOracleAttack::run_attack` | `oracle_fn: F, secret_len: usize` | `Vec<u8>` | Recupera secret completo byte-per-byte |
| `TimingOracleAttack::estimate_query_count` | `byte_len: usize` | `u64` | Stima totale query necessarie |
| `CachedTimingOracle::new` | `inner: O, max_cache_size: usize` | `Self` | Wrap oracle con cache LRU |
| `CachedTimingOracle::cache_hit_count` | `&self` | `usize` | Contatore hit cache |
| `remove_outliers` | `measurements: &[TimingMeasurement]` | `Vec<TimingMeasurement>` | Rimuove outlier IQR 1.5× |
| `median` | `values: &mut [u64]` | `Option<u64>` | Calcola mediana su slice mutabile |

---

## Funzioni pubbliche — stream_cipher_attacks.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `ByteBiasAccumulator::record` | `byte: u8` | `()` | Registra un byte di keystream |
| `ByteBiasAccumulator::most_likely_byte` | `&self` | `u8` | Byte con frequenza massima |
| `ByteBiasAccumulator::bias_ratio` | `value: u8` | `f64` | Rapporto osservato/atteso per un valore |
| `ByteBiasAccumulator::max_bias_ratio` | `&self` | `f64` | Massimo bias ratio su tutti i byte |
| `Rc4BiasAttack::new` | `tracked_bytes: usize` | `Self` | Crea attacco bias RC4 per N posizioni |
| `Rc4BiasAttack::add_keystream` | `keystream: &[u8]` | `()` | Accumula campioni di keystream |
| `Rc4BiasAttack::collect` | `num_samples: usize, key_oracle: F` | `()` | Raccoglie campioni dall'oracle |
| `Rc4BiasAttack::recover_plaintext_bytes` | `ciphertext: &[u8]` | `Vec<u8>` | Recupera plaintext sfruttando bias RC4 |
| `Rc4BiasAttack::exploit_invariance_bias` | `ciphertext_byte: u8, position: usize` | `u8` | Sfrutta bias invariant RC4 in posizione fissa |
| `ChaCha20FaultAnalyzer::add_fault_triple` | `correct: Vec<u8>, faulty: Vec<u8>, spec: ChaCha20FaultSpec` | `()` | Aggiunge tripla (corretto, faultato, spec) |
| `ChaCha20FaultAnalyzer::differentials` | `&self` | `Vec<Vec<u8>>` | Ritorna differenziali (XOR corretto/faultato) |
| `ChaCha20FaultAnalyzer::recover_key_word` | `word_idx: usize` | `Vec<u32>` | Candidati per word di chiave ChaCha20 da DFA |
| `Lfsr64::from_key` | `key_bits: u64` | `Self` | Crea LFSR 64-bit da valore iniziale |
| `Lfsr64::generate` | `n: usize` | `Vec<u8>` | Genera N byte di keystream LFSR |
| `Lfsr64::precompute_table` | `known_ks: &[u8], n_guesses: usize` | `()` | Precomputa tabella per time-memory tradeoff |
| `GenericLfsr::generate` | `initial_state: &[u8], length: usize` | `Vec<u8>` | Genera keystream da stato iniziale generico |
| `LfsrAnalysis::berlekamp_massey` | `seq: &[u8]` | `BerlekampMasseyResult` | Algoritmo Berlekamp-Massey per LFSR minimo |
| `LfsrAnalysis::detect_lfsr` | `seq: &[u8]` | `bool` | True se sequenza è di tipo LFSR |
| `LfsrAnalysis::linear_complexity_profile` | `seq: &[u8]` | `Vec<(usize, usize)>` | Profilo complessità lineare al crescere della lunghezza |
| `LfsrAnalysis::bytes_to_bits` | `data: &[u8]` | `Vec<u8>` | Converte bytes in vettore di bit |
| `LfsrAnalysis::bits_to_bytes` | `bits: &[u8]` | `Vec<u8>` | Converte vettore di bit in bytes |
| `KeystreamTestSuite::analyze` | `keystream: &[u8]` | `KeystreamTestResult` | Esegue suite di test statistici sul keystream |
| `KeystreamTestSuite::monobit_test` | `bits: &[u8]` | `f64` | Test monobit NIST (p-value) |
| `KeystreamTestSuite::runs_test` | `bits: &[u8]` | `f64` | Test delle run (p-value) |
| `KeystreamTestSuite::autocorrelation` | `bits: &[u8], lag: usize` | `f64` | Autocorrelazione a lag dato |
| `KeystreamTestSuite::byte_entropy` | `data: &[u8]` | `f64` | Entropia di Shannon sui byte |
| `KeystreamTestSuite::longest_run` | `bits: &[u8]` | `usize` | Lunghezza della run più lunga |
| `KeystreamTestSuite::chi_squared_byte` | `data: &[u8]` | `f64` | Chi-quadro su distribuzione byte |
| `KeystreamTestSuite::estimate_period` | `keystream: &[u8], max_lag: usize` | `Option<usize>` | Stima periodo del keystream |

---

## Funzioni pubbliche — whitebox_attacks.rs

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `DFAResult::empty` | — | `Self` | Risultato DFA vuoto |
| `DFAResult::resolved_bytes` | `&self` | `usize` | Numero byte di chiave recuperati |
| `DFAResult::try_finalize` | `&mut self` | `()` | Tenta di finalizzare il recupero chiave |
| `DFAAnalyzer::with_key_size` | `key_size: usize` | `Self` | Crea analizzatore DFA per dimensione chiave |
| `DFAAnalyzer::add_fault_pair` | `pair: DfaFaultPair` | `()` | Aggiunge coppia (corretto, faultato) per analisi DFA |
| `DFAAnalyzer::analyze` | `&self` | `DFAResult` | Esegue DFA AES per recupero chiave da fault injection |
| `SBoxAnalyzer::decompose` | `table: &[u8; 256]` | `TableClass` | Classifica S-box (Linear/Affine/Nonlinear/Identity/AesSbox) |
| `SBoxAnalyzer::extract_linear_part` | `table: &[u8; 256]` | `u8` | Estrae la parte lineare della S-box |
| `SBoxAnalyzer::inverse_table` | `table: &[u8; 256]` | `Option<[u8; 256]>` | Calcola S-box inversa (None se non biettiva) |
| `SBoxAnalyzer::compose` | `outer: &[u8; 256], inner: &[u8; 256]` | `[u8; 256]` | Composizione di due S-box |
| `SBoxAnalyzer::difference_distribution_table` | `table: &[u8; 256]` | `Vec<Vec<u16>>` | Tabella distribuzione differenziale (DDT) |
| `SBoxAnalyzer::is_affine` | `table: &[u8; 256]` | `bool` | True se la S-box è affine |
| `SBoxAnalyzer::is_linear` | `table: &[u8; 256]` | `bool` | True se la S-box è lineare (affine con costante 0) |
| `SBoxAnalyzer::affine_rank` | `table: &[u8; 256]` | `u8` | Rango della parte lineare (0=lineare pura) |
| `SBoxAnalyzer::check_additive_linearity` | `table: &[u8; 256]` | `bool` | Verifica linearità additiva completa |
| `SBoxAnalyzer::best_linear_approximation` | `table: &[u8; 256]` | `(u8, f64)` | Migliore approssimazione lineare (coefficiente, correlazione) |
| `WalshHadamardTransform::compute` | `table: &[u8; 256]` | `Self` | Calcola WHT della S-box |
| `WalshHadamardTransform::compute_nonlinearity` | `table: &[u8; 256]` | `u32` | Non-linearità della S-box (distanza da funzioni lineari) |
| `WalshHadamardTransform::max_walsh_coefficient` | `table: &[u8; 256]` | `u32` | Massimo coefficiente WHT |
| `WalshHadamardTransform::compute_branch_number` | `table: &[u8; 256]` | `u32` | Branch number della S-box (diffusion measure) |
| `WalshHadamardTransform::compute_max_correlation` | `table: &[u8; 256]` | `f64` | Correlazione massima con funzioni lineari |
| `WalshHadamardTransform::compute_algebraic_degree` | `table: &[u8; 256]` | `u8` | Grado algebrico della S-box |
| `WalshHadamardTransform::compute_differential_uniformity` | `table: &[u8; 256]` | `u16` | Uniformità differenziale (AES = 4) |
| `WalshHadamardTransform::compute_output_entropy` | `table: &[u8; 256]` | `f64` | Entropia dell'output della S-box |
| `BgeAttack::is_complete_aes128` | `&self` | `bool` | True se tutti i 10 round key AES-128 sono recuperati |
| `BgeAttack::initial_key` | `&self` | `Option<&[u8; 16]>` | Chiave AES-128 iniziale recuperata (da round key 0) |
| `BgeAttack::add_tbox` | `tbox: TBox` | `()` | Aggiunge T-box da implementazione whitebox |
| `BgeAttack::extract_round_keys` | `&self` | `BgeRoundKeyResult` | Estrae round key da T-box (attacco BGE) |
| `BgeAttack::recover_encoding` | `tb_a: &TBox, tb_b: &TBox` | `Option<(u8, u8)>` | Recupera encoding esterno da coppia T-box |
| `GF2LinearSystem::add_equation` | `eq: GF2Equation` | `()` | Aggiunge equazione GF(2) al sistema |
| `GF2LinearSystem::build_matrix` | `&self` | `(Vec<Vec<u8>>, Vec<u8>)` | Costruisce matrice e vettore noti in GF(2) |
| `GF2LinearSystem::solve` | `&self` | `Option<Vec<u8>>` | Risolve sistema lineare GF(2) (Gauss) |
| `WhiteboxKeyExtractor::add_sbox_observation` | `input: u8, output: u8, key_byte_offset: usize` | `()` | Aggiunge osservazione S-box per recupero byte chiave |

---

## Totale funzioni pubbliche: ~250
