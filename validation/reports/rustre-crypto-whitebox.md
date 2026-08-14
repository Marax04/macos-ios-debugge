# rustre-crypto-whitebox

Crate per l'analisi crittografica whitebox: attacchi DFA/DCA/BGE, estrazione di lookup table, analisi di T-box, recupero chiave AES da implementazioni whitebox.

**Versione:** 0.1.0  
**Edizione:** Rust 2024  
**Dipendenze principali:** thiserror, serde/serde_json, rusqlite, mysql, rayon, parking_lot

---

## Moduli e funzioni pubbliche (totale: 333)

### `src/lib.rs` — Nucleo principale

#### `KeyScheduleReverser` (AES-128)
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `reverse_128(round_keys)` | `&[u8]` | `Result<Vec<u8>, CryptoError>` | Inverte l'intera key schedule AES-128 per ricavare la chiave originale |
| `from_last_round_key(last_rk)` | `&[u8]` | `Result<Vec<u8>, CryptoError>` | Ricava la chiave originale dall'ultimo round key AES-128 |

#### `KeyScheduleUtils`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `looks_like_key_schedule(data)` | `&[u8]` | `bool` | Euristica: verifica se i dati assomigliano a una key schedule AES |
| `is_permutation(data)` | `&[u8]` | `bool` | Verifica se i dati formano una permutazione su 256 valori |

#### `ResultDb` (SQLite)
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `open(path)` | `Option<&str>` | `Result<Self, CryptoError>` | Apre/crea un database SQLite per i risultati whitebox |
| `store(name, result)` | `&str, &WhiteboxResult` | `Result<i64, CryptoError>` | Salva un risultato di analisi nel DB |
| `list()` | — | `Result<Vec<StoredResult>, CryptoError>` | Elenca tutti i risultati salvati |

#### `FaultCollector` / DFA base
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `add_faulty(ct)` | `Vec<u8>` | `()` | Aggiunge un ciphertext faulty alla collezione |
| `set_reference(ct)` | `Vec<u8>` | `()` | Imposta il ciphertext di riferimento (corretto) |
| `xor_diff(a, b)` | `&[u8], &[u8]` | `Option<Vec<u8>>` | Calcola la differenza XOR tra due ciphertext |
| `is_valid_fault_pattern(diff)` | `&[u8]` | `bool` | Verifica se il pattern di differenza è valido per DFA su AES round 9 |
| `recover_round10_key()` | — | `Option<Vec<u8>>` | Recupera il round 10 key dai fault pairs accumulati |
| `exhaustive_key_search(faulty_pairs)` | `&[(Vec<u8>, Vec<u8>)]` | `Option<Vec<u8>>` | Ricerca esaustiva della chiave sui candidati DFA |

#### `BgeAttackImpl` (Billet-Gilbert-Ech'er)
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `attack_chow_implementation(tables, ...)` | `&[LookupTable]` | `Result<...>` | Attacca un'implementazione whitebox Chow/Karroumi via BGE |
| `is_chow_compatible(tables)` | `&[LookupTable]` | `bool` | Verifica se le tabelle sono compatibili con il modello Chow |
| `strip_outer_encoding(table)` | `&LookupTable` | `Result<LookupTable, CryptoError>` | Rimuove l'encoding esterno da una tabella encoded |
| `find_sbox_candidates(data)` | `&[u8]` | `Vec<(u64, [u8; 256])>` | Cerca S-box candidate nei dati binari |
| `is_bijective(table)` | `&[u8; 256]` | `bool` | Verifica biettività di una tabella 256-byte |
| `is_affinely_equivalent_to_sbox(table)` | `&[u8; 256]` | `bool` | Verifica equivalenza affine con la S-box AES |

#### `DcaAttacker` (Differential Computation Analysis)
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `add_trace(input, samples)` | `Vec<u8>, Vec<f64>` | `()` | Aggiunge una traccia di computazione (input + campioni di potenza) |
| `compute_correlation(byte_pos, target_round)` | `usize, u8` | `DcaResult` | Calcola la correlazione per un byte di chiave e un round |
| `full_attack()` | — | `Result<Vec<DcaKeyByteResult>, CryptoError>` | Esegue l'attacco DCA completo su tutti i 16 byte della chiave |
| `pearson_correlation(x, y)` | `&[f64], &[f64]` | `f64` | Calcola la correlazione di Pearson tra due serie di campioni |
| `hamming_weight_model(input_byte, key_guess, round)` | `u8, u8, u8` | `f64` | Modello Hamming weight per ipotesi di chiave DCA |

#### `Aes256KeySchedule`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `expand(key)` | `&[u8; 32]` | `Vec<u8>` | Espande una chiave AES-256 in 15 round keys (240 byte) |
| `reverse_from_all(round_keys)` | `&[u8]` | `Result<Vec<u8>, CryptoError>` | Inverte la key schedule AES-256 da tutti i round keys |
| `from_last_round_key(last_rk)` | `&[u8]` | `Result<Vec<u8>, CryptoError>` | Ricava la chiave AES-256 dall'ultimo round key |

#### `Sm4Analyzer`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `is_sm4_sbox(data)` | `&[u8]` | `bool` | Riconosce la S-box SM4 nei dati |
| `find_fk_constants(binary)` | `&[u8]` | `Vec<u64>` | Cerca le costanti FK di SM4 nel binario |

#### `MySqlResultDb`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new(url)` | `&str` | `Result<Self, CryptoError>` | Connette a un DB MySQL per i risultati |
| `create_table()` | — | `Result<(), CryptoError>` | Crea la tabella risultati se non esiste |
| `store(name, result)` | `&str, &WhiteboxResult` | `Result<u64, CryptoError>` | Salva un risultato nel DB MySQL |
| `list()` | — | `Result<Vec<StoredResult>, CryptoError>` | Elenca tutti i risultati MySQL |
| `find_by_algorithm(...)` | algoritmo, filtri | risultati filtrati | Cerca risultati per algoritmo |

#### Funzioni libere — Operazioni AES
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `scan_crypto_constants(binary)` | `&[u8]` | `Vec<CryptoConstantHit>` | Scansiona il binario per costanti crittografiche note |
| `sub_bytes(state)` | `&mut [u8; 16]` | `()` | Applica SubBytes AES (S-box) sullo stato |
| `inv_sub_bytes(state)` | `&mut [u8; 16]` | `()` | Applica InvSubBytes AES (S-box inversa) |
| `aes_mix_columns(state)` | `&mut [u8; 16]` | `()` | Applica MixColumns AES |
| `aes_mix_columns_inverse(state)` | `&mut [u8; 16]` | `()` | Applica InvMixColumns AES |
| `aes_round_key_reverse_128(last_round_key)` | `[u8; 16]` | `[u8; 16]` | Inverte un singolo step della key schedule AES-128 |
| `build_aes_sbox_from_gf()` | — | `[u8; 256]` | Costruisce la S-box AES da GF(2^8) |
| `build_aes_sbox_inv_from_gf()` | — | `[u8; 256]` | Costruisce la S-box inversa AES da GF(2^8) |
| `sub_bytes_full(state)` | `&mut [u8; 16]` | `()` | SubBytes con S-box calcolata dinamicamente |
| `inv_sub_bytes_full(state)` | `&mut [u8; 16]` | `()` | InvSubBytes con S-box inversa dinamica |
| `mix_columns_full(state)` | `&mut [u8; 16]` | `()` | MixColumns completo |
| `inv_mix_columns_full(state)` | `&mut [u8; 16]` | `()` | InvMixColumns completo |
| `add_round_key(state, rk)` | `&mut [u8; 16], &[u8; 16]` | `()` | XOR round key sullo stato AES |
| `aes_encrypt_128(key, plaintext)` | `&[u8; 16], &[u8; 16]` | `[u8; 16]` | Cifra AES-128 reference |
| `aes_decrypt_128(key, ciphertext)` | `&[u8; 16], &[u8; 16]` | `[u8; 16]` | Decifra AES-128 reference |
| `aes128_verify_roundtrip(key, plaintext)` | `&[u8; 16], &[u8; 16]` | `bool` | Verifica encrypt/decrypt roundtrip AES-128 |
| `key_schedule_inverse_128(...)` | round key, round | chiave precedente | Inverte un passo key schedule AES-128 |
| `simulate_dfa_attack(key, plaintext)` | `[u8; 16], [u8; 16]` | `Option<([u8;16],[u8;16]))` | Simula un attacco DFA completo su AES-128 |

#### `FaultPairAnalyzer` / `DfaOracle`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `delta()` | — | `[u8; 16]` | Differenza XOR tra ct corretto e faulted |
| `diff_count()` | — | `usize` | Numero di byte che differiscono |
| `is_valid_round9_pattern()` | — | `bool` | Verifica pattern di fault a round 9 |
| `add_pair(correct, faulty)` | `[u8;16], [u8;16]` | `()` | Aggiunge una coppia correct/faulty |
| `add_pair_with_position(...)` | coppia + posizione | `()` | Aggiunge coppia con info sulla posizione del fault |
| `valid_pair_count()` | — | `usize` | Numero di coppie valide accumulate |
| `recover_last_round_key()` | — | `Option<[u8; 16]>` | Recupera il round 10 key via DFA |
| `recover_full_key_from_round10(round10_key)` | `&[u8; 16]` | `Option<[u8; 16]>` | Recupera la chiave originale dal round 10 key |
| `candidates_for_byte(byte_pos)` | `usize` | `Vec<u8>` | Candidati per un singolo byte di chiave |
| `full_attack()` | — | `Option<([u8;16],[u8;16])>` | Attacco DFA completo: restituisce (round10_key, original_key) |

#### `SimulatedAes` / `FaultSimulator`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `simulate_faulted_encrypt(...)` | plaintext, key, fault_pos, fault_val | `[u8; 16]` | Simula AES-128 con fault iniettato al round 9 |
| `simulate_faulted_encrypt_with_value(...)` | + valore specifico | `[u8; 16]` | Simula con valore di fault preciso |
| `recover_key_from_pairs(correct_ct, faulted_ct)` | `[u8;16], [u8;16]` | `Option<u8>` | Recupera un byte di chiave da una coppia DFA |
| `hamming_distance(a, b)` | `&[u8], &[u8]` | `u32` | Distanza di Hamming tra due slice |
| `correct_encrypt(plaintext, key)` | `[u8;16], [u8;16]` | `[u8; 16]` | Cifra AES-128 corretta (reference) |
| `generate_fault_pairs(...)` | key, plaintexts, params | Vec di coppie | Genera batch di coppie fault/correct per DFA |
| `narrow_candidates(pairs, pos)` | `&[([u8;16],[u8;16])]`, byte_pos | `Vec<u8>` | Riduce i candidati chiave per un byte usando più coppie |

#### `WhiteboxTable` / `LookupTable` / `AffineMap`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `from_bytes(bytes)` | `&[u8]` | `Result<Self, CryptoError>` | Costruisce una tabella a 32-bit da slice di byte |
| `lookup(x)` | `u8` | `u32` | Lookup nella tabella a 32-bit |
| `to_bytes()` | — | `Vec<u8>` | Serializza la tabella in byte |
| `low_bytes()` | — | `[u8; 256]` | Estrae i byte bassi di ogni entry 32-bit |
| `high_byte_is_bijective()` | — | `bool` | Verifica biettività dei byte alti |
| `identity()` | — | `Self` | Crea una mappa affine identità |
| `apply(x)` | `u8` | `u8` | Applica la mappa affine a un byte |
| `from_input_output_pairs(pairs)` | `&[(u8, u8)]` | `Option<Self>` | Ricostruisce una mappa affine da coppie I/O |
| `is_identity()` | — | `bool` | Verifica se la mappa è l'identità |

#### `BgeAnalyzer`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `recover_round_key_material(round)` | `usize` | `Option<Vec<u8>>` | Recupera il materiale chiave per un round specifico |
| `find_affine_equivalence(...)` | due tabelle | equivalenza affine | Trova la relazione affine tra due tabelle |
| `recover_xor_difference(t_i, t_j)` | due `&WhiteboxTable` | `u8` | Recupera la differenza XOR tra due tabelle adiacenti |
| `full_attack()` | — | `Result<Vec<Vec<u8>>, CryptoError>` | Attacco BGE completo su tutte le tabelle whitebox |

#### `SquareAttack` (attacco integrale)
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `attack_4_round_aes(oracle)` | `&dyn AesOracle` | `Option<[u8; 16]>` | Attacco Square su AES a 4 round tramite oracle |
| `construct_lambda_set(constant_part, active_byte)` | `&[u8;15], usize` | `Vec<[u8; 16]>` | Costruisce il lambda set per l'attacco integrale |
| `construct_lambda_set_byte0(constant_part)` | `&[u8; 15]` | `Vec<[u8; 16]>` | Lambda set con byte attivo in posizione 0 |
| `check_balanced(bytes)` | `&[u8]` | `bool` | Verifica la proprietà di bilanciamento del lambda set |
| `attack_single_byte(lambda_outputs, byte_pos)` | `&[[u8;16]], usize` | `Vec<u8>` | Recupera i candidati per un byte tramite Square |
| `candidate_count_for_lambda_set(...)` | lambda outputs | conteggio candidati | Stima il numero di candidati chiave |
| `verify_square_distinguisher(...)` | outputs, chiave | verifica | Verifica il distinguisher Square |

#### `CryptoIdentifier`
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `identify_constants(binary)` | `&[u8]` | `Vec<CryptoConstantHit>` | Identifica costanti crittografiche note nel binario |
| `identify_by_structure(func_bytes)` | `&[u8]` | `Vec<CryptoAlgorithmHit>` | Identifica algoritmi per struttura del codice |
| `classify_by_entropy(func_bytes)` | `&[u8]` | `f64` | Classifica per entropia (alta = cifrato) |
| `best_match(hits)` | `&[CryptoAlgorithmHit]` | `Option<&CryptoAlgorithmHit>` | Restituisce la corrispondenza migliore |
| `find_poly1305_prime(binary)` | `&[u8]` | `Vec<u64>` | Cerca il primo di Poly1305 nel binario |
| `find_sha256_k_table(binary)` | `&[u8]` | `Vec<u64>` | Cerca la tabella K di SHA-256 |
| `find_chacha_expa(binary)` | `&[u8]` | `Vec<u64>` | Cerca la costante "expa" di ChaCha20 |
| `full_scan(binary)` | `&[u8]` | `Vec<CryptoAlgorithmHit>` | Scansione completa di tutti gli algoritmi supportati |

#### Funzioni libere — Analisi S-box
| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `boolean_nonlinearity(truth_table)` | `&[u8]` | `u32` | Calcola la non-linearità booleana tramite Walsh-Hadamard |
| `differential_uniformity(sbox)` | `&[u8; 256]` | `u32` | Calcola l'uniformità differenziale (DDT max) |
| `algebraic_degree(sbox)` | `&[u8; 256]` | `u32` | Calcola il grado algebrico via ANF |
| `compute_lat(sbox)` | `&[u8; 256]` | `Vec<Vec<i32>>` | Calcola la Linear Approximation Table completa |
| `lat_max_bias(sbox)` | `&[u8; 256]` | `i32` | Massimo bias nella LAT |
| `compute_ddt(sbox)` | `&[u8; 256]` | `Vec<Vec<u32>>` | Calcola la Difference Distribution Table |

---

### `src/whitebox_aes_full.rs` — Analizzatore AES Whitebox Completo

| Funzione (struct) | Input | Output | Descrizione |
|---|---|---|---|
| `RoundTableSet::new(round)` | `usize` | `Self` | Crea un set di tabelle per un round AES |
| `RoundTableSet::fill_canonical_t0()` | — | `()` | Riempie con i valori canonici T0 |
| `RoundTableSet::is_canonical(t)` | `usize` | `bool` | Verifica se la tabella t è canonica |
| `RoundTableSet::total_bytes()` | — | `usize` | Numero totale di byte nelle tabelle |
| `RoundTableSet::table_confidence()` | — | `f32` | Score di confidenza che sia AES |
| `Bijection256::identity()` | — | `Self` | Identità su 256 elementi |
| `Bijection256::is_identity()` | — | `bool` | Verifica identità |
| `Bijection256::strip_xor_encoding()` | — | `Option<u8>` | Rimuove encoding XOR, restituisce la costante |
| `Bijection256::differential()` | — | `Vec<u8>` | Calcola il profilo differenziale |
| `GF256LinearMap::new(matrix)` | `[u8; 8]` | `Option<Self>` | Crea mappa lineare su GF(2^8) da matrice 8x8 bit |
| `GF256LinearMap::apply(b)` | `u8` | `u8` | Applica la mappa lineare a un byte |
| `GF256LinearMap::apply_inverse(b)` | `u8` | `u8` | Applica la mappa inversa |
| `GF256LinearMap::compose(other)` | `&Self` | `Option<Self>` | Compone due mappe lineari GF(2^8) |
| `GF256LinearMap::is_identity()` | — | `bool` | Verifica identità |
| `RecoveredKey::new(key_bytes, method, confidence)` | Vec + enum + f32 | `Self` | Costruisce un risultato di chiave recuperata |
| `RecoveredKey::as_hex()` | — | `String` | Chiave come stringa esadecimale |
| `RecoveredKey::is_high_confidence(threshold)` | `f32` | `bool` | Verifica se la confidenza supera la soglia |
| `RecoveredKey::merge_with(other)` | `&Self` | `()` | Unisce due risultati parziali di chiave |
| `AnalysisEvidenceSet::is_strong()` | — | `bool` | Verifica se l'evidenza è forte abbastanza |
| `WhiteboxAesAnalyzer::analyze()` | — | `Result<AnalysisResult, CryptoError>` | Analisi completa AES whitebox; restituisce chiave + round keys |
| `RoundEncodingPair::identity(round)` | `usize` | `Self` | Coppia di encoding identità per un round |
| `RoundEncodingPair::is_identity()` | — | `bool` | Verifica se entrambi gli encoding sono identità |
| `RoundEncodingPair::apply_input(col, x)` | `usize, u8` | `u8` | Applica encoding di input alla colonna col |
| `RoundEncodingPair::apply_output(col, x)` | `usize, u8` | `u8` | Applica encoding di output |
| `RoundEncodingPair::invert_table(table)` | `&[u8; 256]` | `[u8; 256]` | Inverte una tabella di permutazione |
| `RoundEncodingPair::is_bijection(table)` | `&[u8]` | `bool` | Verifica biettività |
| `AnalysisConfidence::compute(result, binary)` | risultato + binario | `Self` | Calcola la confidenza globale dell'analisi |

---

### `src/wb_key_recovery.rs` — Recupero Chiave Whitebox

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FaultPair::new(correct, faulty, model)` | due `[u8;16]` + enum | `Self` | Crea una coppia fault con modello specificato |
| `FaultPair::dominant_column()` | — | `usize` | Colonna AES più affetta dal fault |
| `FaultPair::is_valid_r9_fault()` | — | `bool` | Verifica se il fault è valido per round 9 DFA |
| `FaultOracle::generate_fault_pair(plaintext, fault_byte, fault_pos)` | — | `FaultPair` | Genera una coppia fault/correct da un oracle |
| `FaultOracle::recover_round10_key()` | — | `Option<[u8; 16]>` | Recupera round 10 key dall'oracle |
| `DcaTraceBuffer::mem_to_samples()` | — | `()` | Converte accessi memoria in campioni DCA |
| `DcaTraceBuffer::add_table_access(table_base, access_addr)` | `u64, u64` | `()` | Registra un accesso a tabella per DCA |
| `DcaCorrelator::add_trace(trace)` | `ExecutionTrace` | `()` | Aggiunge traccia di esecuzione |
| `DcaCorrelator::compute_correlation_matrix()` | — | `Vec<Vec<f64>>` | Matrice di correlazione tra ipotesi chiave e tracce |
| `DcaCorrelator::attack()` | — | `DcaResult` | Esegue l'attacco DCA e restituisce i byte di chiave |
| `DcaCorrelator::estimate_snr()` | — | `f64` | Stima il rapporto segnale/rumore delle tracce |
| `CpaAttacker::confidence()` | — | `f64` | Confidenza del risultato CPA |
| `CpaAttacker::synthetic_from_key(plaintext, key, noise)` | `&[u8;16], &[u8;16], f64` | `Self` | Crea tracce sintetiche per test CPA |
| `CpaAttacker::add_trace(trace)` | `PowerTrace` | `()` | Aggiunge traccia di potenza |
| `CpaAttacker::attack_byte(byte_pos)` | `usize` | `CpaByteResult` | Attacca un singolo byte di chiave via CPA |
| `CpaAttacker::full_attack()` | — | `CpaKeyRecovery` | Attacco CPA completo su tutti i 16 byte |
| `CpaKeyRecovery::is_high_confidence()` | — | `bool` | Verifica confidenza alta del risultato CPA |
| `CpaKeyRecovery::key_hex()` | — | `String` | Chiave recuperata in esadecimale |
| `recover_key_from_tables(tables)` | `&[LookupTable]` | `Vec<KeyTableResult>` | Recupera chiave da un set di lookup table |
| `assemble_key(results, min_confidence)` | `&[KeyTableResult], f32` | `Option<[u8; 16]>` | Assembla la chiave finale dai risultati parziali |
| `aes128_key_schedule(key)` | `&[u8; 16]` | `Vec<u8>` | Genera l'intera key schedule AES-128 (176 byte) |

---

### `src/tbox_analysis.rs` — Analisi T-Box

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TBox::from_slice(data, byte_pos, round)` | `&[u8], Option<u8>, Option<u8>` | `Option<Self>` | Costruisce una T-box da slice di 256 byte |
| `TBox::is_bijective()` | — | `bool` | Verifica biettività della T-box |
| `TBox::non_linearity()` | — | `u32` | Calcola la non-linearità via Walsh-Hadamard |
| `TBox::is_affinely_equivalent_to_sbox()` | — | `bool` | Verifica equivalenza affine con S-box AES |
| `TBox::find_xor_equivalence()` | — | `Option<(u8, u8)>` | Trova costanti XOR di input/output equivalenti |
| `TBox::to_lookup_table(offset)` | `u64` | `LookupTable` | Converte T-box in LookupTable con indirizzo |
| `TBoxSet::mean_non_linearity()` | — | `f64` | Non-linearità media del set |
| `TBoxSet::any_bijective()` | — | `bool` | Verifica se almeno una T-box è biiettiva |
| `TBoxSet::count_sbox_equivalent()` | — | `usize` | Conta le T-box equivalenti alla S-box AES |
| `TBoxScanner::new()` | — | `Self` | Crea un nuovo scanner |
| `TBoxScanner::scan(binary)` | `&[u8]` | `Vec<(u64, TBox)>` | Scansiona il binario per T-box candidate |
| `TBoxScanner::detect_structure(tables)` | `&[TBox]` | `bool` | Rileva struttura whitebox AES nel set di T-box |
| `TBoxScanner::score_tbox(tbox)` | `&TBox` | `f32` | Assegna uno score di probabilità AES alla T-box |
| `TBoxScanner::find_affine_equivalences(tables)` | `&[TBox]` | `Vec<AffineEquivalence>` | Trova equivalenze affini tra T-box nel set |
| `TBoxScanner::estimate_byte_positions(tables)` | `&[TBox]` | `Vec<Option<u8>>` | Stima le posizioni di byte chiave per ogni T-box |
| `TBoxDecomposer::strip_encoding(tbox)` | `&TBox` | `Result<TBox, CryptoError>` | Rimuove l'encoding esterno da una T-box |
| `TBoxDecomposer::decompose_set(tboxes)` | `&[TBox]` | `Vec<Result<TBox, CryptoError>>` | Decompone un intero set di T-box |
| `TBoxDecomposer::estimate_input_encoding(tbox)` | `&TBox` | `Option<u8>` | Stima l'encoding di input come costante XOR |
| `TBoxDecomposer::extract_key_byte(stripped)` | `&TBox` | `Option<u8>` | Estrae un byte di chiave da T-box stripped |
| `TBoxDecomposer::extract_round_key(stripped_boxes)` | `&[TBox]` | `Vec<Option<u8>>` | Estrae il round key da un set di T-box stripped |
| `TBoxDecomposer::verify_key(key, stripped_boxes)` | `&[u8], &[TBox]` | `f32` | Verifica la chiave candidata, restituisce score |
| `TBoxDecomposer::recover_key_from_tbox_set(tboxes)` | `&[TBox]` | `Result<Vec<u8>, CryptoError>` | Pipeline completa: scan → decompose → recover key |

---

### `src/table_decomposer.rs` — Decomposizione Tabelle

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TableDecomposer::new()` | — | `Self` | Crea un nuovo decomposer |
| `TableDecomposer::decompose(table)` | `&[u8; 256]` | `TableDecomposition` | Decompone una singola tabella 256-byte in componenti AES |
| `TableDecomposer::decompose_all(tables)` | `&[[u8; 256]]` | `Vec<TableDecomposition>` | Decompone un set di tabelle in parallelo |
| `TableDecomposer::identify_round_from_tboxes(tables)` | `&[[u8; 256]]` | `Option<usize>` | Identifica il round AES da un set di T-box |
| `is_aes_t_table(table)` | `&[u32; 256]` | `bool` | Verifica se una tabella a 32-bit è una T-table AES standard |
| `extract_tbox_key(table)` | `&[u8; 256]` | `Option<u8>` | Estrae il byte di chiave XORato in una T-box |
| `aes_likeness_score(tables)` | `&[[u8; 256]]` | `f64` | Score globale di somiglianza con struttura AES |

---

### `src/lookup_table_extractor.rs` — Estrazione Lookup Table

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ExtractedTable::to_lookup_table()` | — | `LookupTable` | Converte in LookupTable standard |
| `ExtractedTable::as_bytes()` | — | `Option<&[u8]>` | Vista come slice di byte (solo tabelle a 8-bit) |
| `ExtractedTable::as_u32s()` | — | `Option<Vec<u32>>` | Vista come slice di u32 (tabelle a 32-bit) |
| `LookupTableExtractor::new()` | — | `Self` | Crea estrattore con configurazione di default |
| `LookupTableExtractor::extract(binary)` | `&[u8]` | `Vec<ExtractedTable>` | Estrae tutte le lookup table dal binario |
| `classify_des_sbox(data)` | `&[u8]` | `Option<usize>` | Classifica una tabella come S-box DES (0-7) |
| `ExtractionReport::from_tables(tables)` | `Vec<ExtractedTable>` | `Self` | Costruisce un report da tabelle estratte |
| `ExtractionReport::by_class(class)` | `&TableClass` | `Vec<&ExtractedTable>` | Filtra tabelle per classe |
| `ExtractionReport::high_confidence(threshold)` | `f32` | `Vec<&ExtractedTable>` | Tabelle con confidenza sopra soglia |
| `ExtractionReport::summary()` | — | `String` | Riepilogo testuale dell'estrazione |
| `extract_and_report(binary)` | `&[u8]` | `ExtractionReport` | Pipeline completa: estrai + classifica + rapporto |

---

### `src/linear_attack.rs` — Attacco Lineare (Crittanalisi)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `LinearApproximation::compute(sbox, input_mask, output_mask)` | S-box + maschere | `Result<Self, LinearAttackError>` | Calcola un'approssimazione lineare per la S-box |
| `LinearApproximation::probability()` | — | `f64` | Probabilità dell'approssimazione lineare |
| `LinearApproximation::is_trivial()` | — | `bool` | Verifica se l'approssimazione è banale (prob = 1/2) |
| `LinearHull::add_trail(approx)` | `LinearApproximation` | `()` | Aggiunge un trail all'hull lineare |
| `LinearHull::required_pairs()` | — | `u64` | Numero di coppie necessarie per l'attacco |
| `LinearDistinguisher::from_per_round(pt_mask, ct_mask, biases)` | maschere + bias per round | `Self` | Costruisce distinguisher da bias per round |
| `LinearDistinguisher::pairs_needed()` | — | `u64` | Coppie necessarie per vantaggio statistico |
| `LinearCryptanalysis::new(target_cipher, block_bits, rounds)` | nome + dimensioni | `Self` | Inizializza analisi lineare per un cifrario |
| `LinearCryptanalysis::add_hull(hull)` | `LinearHull` | `()` | Aggiunge un hull all'analisi |
| `LinearCryptanalysis::finalize()` | — | `()` | Finalizza l'analisi selezionando il miglior hull |
| `SboxLinearAnalyzer::new(sbox, cipher_name, block_bits)` | S-box + parametri | `Result<Self, LinearAttackError>` | Crea analizzatore per una S-box specifica |
| `SboxLinearAnalyzer::build_lat()` | — | `()` | Costruisce la LAT completa della S-box |
| `SboxLinearAnalyzer::bias(alpha, beta)` | `usize, usize` | `f64` | Bias per la coppia di maschere (alpha, beta) |
| `SboxLinearAnalyzer::best_approximation()` | — | `Option<LinearApproximation>` | Migliore approssimazione lineare trovata |
| `SboxLinearAnalyzer::strong_approximations(threshold)` | `f64` | `Vec<LinearApproximation>` | Tutte le approssimazioni con bias > threshold |
| `LinearKeyRecovery::add_pair(plaintext, ciphertext)` | `u64, u64` | `()` | Aggiunge una coppia plaintext/ciphertext |
| `LinearKeyRecovery::add_pairs(pairs)` | `&[(u64, u64)]` | `()` | Aggiunge batch di coppie |
| `LinearKeyRecovery::recover_key_byte(...)` | posizione + params | byte candidati | Recupera un byte di chiave via crittanalisi lineare |
| `LinearKeyRecovery::build_hull(input_mask, output_mask, rounds)` | maschere + rounds | `LinearHull` | Costruisce hull lineare per maschere date |
| `LinearKeyRecovery::generate_report(rounds)` | `u32` | `LinearReport` | Genera report dell'analisi lineare |
| `LinearKeyRecovery::lat_as_biases()` | — | `Vec<Vec<f64>>` | LAT come matrice di bias floating-point |
| `LinearKeyRecovery::average_abs_bias()` | — | `f64` | Bias assoluto medio della LAT |

---

### `src/dfa_full.rs` — DFA Completo

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FaultPair::xor_diff()` | — | `Option<Vec<u8>>` | Differenza XOR tra ct corretto e faulted |
| `FaultPair::diff_weight()` | — | `usize` | Peso (numero di byte diversi) della differenza |
| `FaultPair::is_valid_round9_pattern()` | — | `bool` | Pattern valido per fault al round 9 AES |
| `DfaKeyExtractor::extract_round10_key(pairs)` | `&[FaultPair]` | `Option<[u8; 16]>` | Estrae round 10 key dai fault pair |
| `DfaKeyExtractor::prev_round_key(rk, round)` | `&[u8;16], u8` | `Option<[u8; 16]>` | Calcola il round key precedente |
| `DfaKeyExtractor::all_round_keys(rk10)` | `&[u8; 16]` | `Option<Vec<[u8; 16]>>` | Genera tutti i round keys invertendo la schedule |
| `DfaSession::add_pair(pair)` | `FaultPair` | `()` | Aggiunge coppia alla sessione DFA |
| `DfaSession::simulate_fault(...)` | plaintext + key + params | `FaultPair` | Simula un fault e restituisce la coppia |
| `DfaSession::collect_simulated_pairs(plaintext, key, num_pairs)` | — | `()` | Raccoglie N coppie simulate |
| `DfaSession::run_attack()` | — | `DfaReport` | Esegue l'attacco DFA e genera il report |
| `DfaSession::valid_pair_count()` | — | `usize` | Coppie valide accumulate |
| `DfaVerifier::verify(key, test_vectors)` | `&[u8], &[(&[u8],&[u8])]` | `VerifyResult` | Verifica la chiave recuperata con vettori di test |
| `aes128_ecb_encrypt_reference(plaintext, key)` | `&[u8], &[u8; 16]` | `Vec<u8>` | Cifratura AES-128 ECB reference pura Rust |

---

### `src/dfa_attacker.rs` — Attaccante DFA Avanzato

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `DfaAttacker::key_byte_confidence(pairs)` | `&[FaultPair]` | `Vec<HashMap<u8, u32>>` | Confidenza per ogni candidato di byte di chiave |
| `DfaAttacker::recover_last_round_key(pairs)` | `&[FaultPair]` | `DfaResult` | Recupera il round 10 key con analisi statistica |
| `DfaAttacker::attack_with_oracle(...)` | oracle fault + encrypt | `DfaResult` | Attacca con oracle generico (closure) |
| `DfaAttacker::reverse_key_schedule_128(last_round_key)` | `&[u8; 16]` | `Vec<[u8; 16]>` | Inverte la key schedule AES-128 da round 10 key |
| `DfaAttacker::attack_progress(result)` | `&DfaResult` | `f64` | Percentuale di bytes chiave recuperati |
| `DfaAttacker::brute_force_remaining(...)` | risultato parziale + oracle | chiave completa | Forza bruta i byte non recuperati |
| `FaultStatistics::compute(pairs)` | `&[FaultPair]` | `Self` | Calcola statistiche sui fault pair |
| `validate_key(key, pairs)` | `&[u8;16], &[(&[u8;16],&[u8;16])]` | `bool` | Valida la chiave recuperata contro coppie note |

---

### `src/dfa_attack.rs` — Infrastruttura DFA

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FaultInjection::diff()` | — | `Option<Vec<u8>>` | Differenza XOR del fault injection |
| `FaultInjection::is_valid_round9_pattern()` | — | `bool` | Validità pattern round 9 |
| `FaultInjection::diagonal_index()` | — | `Option<usize>` | Indice della diagonale AES affetta |
| `DfaResult::is_fully_recovered()` | — | `bool` | Verifica se tutti i 16 byte chiave sono stati recuperati |
| `DfaResult::last_rk_hex()` | — | `String` | Round 10 key in esadecimale |
| `DfaResult::original_key_hex()` | — | `String` | Chiave originale in esadecimale |
| `DfaAttackEngine::new()` | — | `Self` | Crea motore DFA |
| `DfaAttackEngine::add_fault(fi)` | `FaultInjection` | `()` | Aggiunge fault injection al motore |
| `DfaAttackEngine::register_reference(pt, ct)` | `Vec<u8>, Vec<u8>` | `()` | Registra coppia reference |
| `DfaAttackEngine::valid_fault_count()` | — | `usize` | Fault validi accumulati |
| `DfaAttackEngine::run()` | — | `Result<DfaResult, CryptoError>` | Esegue l'attacco DFA |
| `DfaAttackEngine::estimate_required_faults(diagonals_needed)` | `usize` | `usize` | Stima fault necessari per N diagonali |
| `DfaAttackEngine::faults_by_diagonal()` | — | `[Vec<&FaultInjection>; 4]` | Raggruppa fault per diagonale |
| `DfaAttackEngine::summary()` | — | `DfaAttackSummary` | Riepilogo dell'attacco |
| `SimulatedAesDfa::inject_fault(pt, fault_byte, fault_value)` | `&[u8;16], usize, u8` | `FaultInjection` | Simula fault injection su AES |
| `round_key_to_lookup_table(round_key, round)` | `&[u8], u8` | `LookupTable` | Converte round key in lookup table per analisi |

---

### `src/dca_fault_model.rs` — Modello DCA con Fault

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ComputationTrace::with_label(label)` | `impl Into<String>` | `Self` | Builder: aggiunge etichetta alla traccia |
| `DcaResult::distinguishing_ratio()` | — | `f64` | Rapporto segnale/rumore del risultato DCA |
| `DcaResult::recovered_key()` | — | `[Option<u8>; 16]` | Array di byte chiave recuperati (None = non certo) |
| `DcaResult::recovered_count()` | — | `usize` | Numero di byte chiave recuperati con certezza |
| `DcaResult::full_key_recovered()` | — | `bool` | Verifica se tutti i 16 byte sono stati recuperati |
| `DcaAnalyzer::with_defaults()` | — | `Self` | Analizzatore DCA con configurazione default |
| `DcaAnalyzer::analyze(traces)` | `&[ComputationTrace]` | `DcaResult` | Esegue analisi DCA sulle tracce |
| `FaultExperiment::new(...)` | parametri | `Self` | Crea un esperimento di fault |
| `FaultExperiment::delta()` | — | `[u8; 16]` | Differenza tra ct corretto e faulted |
| `FaultCampaign::add_experiment(exp)` | `FaultExperiment` | `()` | Aggiunge esperimento alla campagna |
| `FaultCampaign::effective_experiments()` | — | `Vec<&FaultExperiment>` | Esperimenti con fault effettivo |
| `FaultCampaign::effective_count()` | — | `usize` | Numero di esperimenti effettivi |
| `FaultCampaign::infer_key_candidates()` | — | `HashMap<u8, Vec<u8>>` | Inferisce candidati di chiave dalla campagna |
| `FaultCampaign::summary()` | — | `CampaignSummary` | Riepilogo statistico della campagna |
| `SyntheticTraceGenerator::generate(plaintexts, rng_seed)` | `&[[u8;16]], u64` | `Vec<ComputationTrace>` | Genera tracce sintetiche per test/benchmark |

---

### `src/bge_attack.rs` — Attacco BGE (Billet-Gilbert-Ech'er)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `ExternalEncoding::new(linear_lut, constant)` | `[u8;256], u8` | `Self` | Crea encoding esterno (affine su GF(2^8)) |
| `ExternalEncoding::identity()` | — | `Self` | Encoding identità |
| `ExternalEncoding::inverse()` | — | `Option<Self>` | Encoding inverso |
| `ExternalEncoding::compose(inner)` | `&Self` | `Self` | Compone due encoding esterni |
| `ExternalEncoding::find_xor_equivalence(table)` | `&[u8;256]` | `Option<(u8, u8)>` | Trova costanti XOR equivalenti all'encoding |
| `RoundEncoding::identity(round)` | `usize` | `Self` | Encoding identità per un round |
| `RoundEncoding::strip_table(encoded_table, byte_pos)` | `&[u8;256], usize` | `Option<[u8;256]>` | Rimuove encoding da una tabella |
| `RoundEncoding::is_valid()` | — | `bool` | Verifica validità dell'encoding |
| `BgeAttacker::new(encoded_tboxes)` | `Vec<LookupTable>` | `Self` | Crea attaccante BGE con T-box encoded |
| `BgeAttacker::attack()` | — | `Result<BgeResult, CryptoError>` | Esegue attacco BGE completo |
| `BgeAttacker::encoded_tboxes()` | — | `&[LookupTable]` | Vista delle T-box encoded |
| `BgeAttacker::recovered_encodings()` | — | `&[ExternalEncoding]` | Encoding esterni recuperati |
| `BgeAttacker::refine_encodings_inverse()` | — | `Vec<HashMap<u8, usize>>` | Raffina gli encoding usando l'inversione |
| `BgeAttacker::validate_tbox_set(tables)` | `&[LookupTable]` | `TBoxValidation` | Valida un set di T-box per compatibilità BGE |
| `BgeResult::round1_key()` | — | `Vec<u8>` | Chiave del primo round recuperata |
| `BgeResult::recovered_count()` | — | `usize` | Numero di encoding recuperati |
| `BgeResult::key_hex()` | — | `String` | Chiave in formato esadecimale |
| `BgeResult::is_complete()` | — | `bool` | Attacco BGE completato con successo |
| `xor_differential_distribution(table)` | `&[u8;256]` | `Vec<Vec<u32>>` | Calcola distribuzione differenziale XOR |
| `has_aes_like_differential_profile(table)` | `&[u8;256]` | `bool` | Verifica profilo differenziale simile ad AES |
| `linear_bias(table)` | `&[u8;256]` | `f64` | Bias lineare massimo della tabella |
| `recover_single_key_byte(encoded_table)` | `&[u8;256]` | `Option<u8>` | Recupera un byte di chiave da una T-box encoded |
| `recover_all_key_bytes(tables)` | `&[LookupTable]` | `Vec<Option<u8>>` | Recupera tutti i byte di chiave da un set di T-box |

---

### `src/bge_attacker.rs` — Attaccante BGE Avanzato (oracle-based)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `Permutation256::identity()` | — | `Self` | Permutazione identità |
| `Permutation256::compose(other)` | `&Self` | `Self` | Composizione di permutazioni |
| `Permutation256::invert()` | — | `Option<Self>` | Permutazione inversa |
| `Permutation256::is_affine()` | — | `bool` | Verifica se la permutazione è affine su GF(2^8) |
| `Permutation256::affine_components()` | — | `Option<([u8; 8], u8)>` | Estrae matrice + costante dell'affine |
| `CombinedLut::from_combined(combined)` | `LookupTable` | `Self` | Costruisce da LookupTable combinata |
| `SampleSet::new()` | — | `Self` | Nuovo set di campioni I/O |
| `SampleSet::add(input, output)` | `u8, u8` | `()` | Aggiunge coppia input/output |
| `SampleSet::reconstruct_table()` | — | `Option<LookupTable>` | Ricostruisce la tabella dai campioni |
| `BgeOracleAttacker::phase1_collect(oracle)` | closure oracle | `Vec<SampleSet>` | Fase 1: raccoglie campioni dall'oracle |
| `BgeOracleAttacker::phase2_find_affine_relation(...)` | SampleSet | relazione affine | Fase 2: trova relazione affine tra tabelle |
| `BgeOracleAttacker::phase3_recover_encoding(...)` | relazione affine | encoding | Fase 3: recupera encoding esterno |
| `BgeOracleAttacker::phase4_recover_key(...)` | encoding | byte chiave | Fase 4: recupera chiave da encoding |
| `BgeOracleAttacker::attack(oracle)` | closure oracle | `BgeResult` | Attacco BGE completo oracle-based in 4 fasi |
| `table_correlation(t1, t2)` | due `&LookupTable` | `f64` | Correlazione tra due lookup table |

---

### `src/aes_wb_analyzer.rs` — Analizzatore Whitebox AES

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `TBoxCandidate::new(box_index, round, table)` | `usize, usize, Vec<u32>` | `Self` | Candidato T-box a 32-bit |
| `TBoxCandidate::extract_key_candidate()` | — | `Option<u8>` | Estrae byte di chiave dal candidato |
| `TBoxCandidate::column_entropy(byte_col)` | `usize` | `f64` | Entropia di Shannon per una colonna di byte |
| `TBoxScanner32::new()` | — | `Self` | Scanner per T-box a 32-bit |
| `TBoxScanner32::scan(binary)` | `&[u8]` | `Vec<TBoxCandidate>` | Scansiona il binario per T-box a 32-bit |
| `TBoxCandidate32::to_lookup_table()` | — | `LookupTable` | Converte in LookupTable |
| `TBoxCandidate32::column(col)` | `usize` | `Vec<u8>` | Estrae una colonna byte dalla T-box 32-bit |
| `TBoxCandidate32::column_entropy(col)` | `usize` | `f64` | Entropia della colonna |
| `TBoxCandidate32::estimate_round(all_candidates)` | `&[Self]` | `Option<usize>` | Stima il round AES dal contesto |
| `TBoxPairFinder::new()` | — | `Self` | Trova coppie duali di T-box |
| `TBoxPairFinder::is_dual_pair(t1, t2)` | due candidati | `bool` | Verifica se due T-box sono una coppia duale |
| `TBoxPairFinder::find_pairs(candidates)` | `&[TBoxCandidate]` | coppie | Trova tutte le coppie duali |
| `TBoxPairFinder::recover_key_xor(t1, t2)` | coppia duale | `Option<Vec<u8>>` | Recupera XOR di chiave da coppia duale |
| `TableStats::compute(offset, data)` | `u64, &[u8]` | `Self` | Calcola statistiche su una tabella |
| `TableStats::likely_sbox()` | — | `bool` | Alta probabilità che sia una S-box |
| `TableStats::likely_encoded_bijection()` | — | `bool` | Alta probabilità di biiezione encoded |
| `WbAnalyzer::new()` | — | `Self` | Analizzatore whitebox AES |
| `WbAnalyzer::analyze(binary)` | `&[u8]` | `WbAnalysisReport` | Analisi completa del binario |
| `WbAnalyzer::recover_key_schedule(candidates)` | `&[TBoxCandidate]` | `Option<Vec<u8>>` | Recupera key schedule dai candidati |
| `shannon_entropy_u32(freq, n)` | `&[u32;256], usize` | `f64` | Entropia di Shannon da frequenze |
| `bytes_entropy(data)` | `&[u8]` | `f64` | Entropia di Shannon di uno slice di byte |
| `compute_chi_squared(freq, n)` | `&[u32;256], usize` | `f64` | Statistica chi-quadro per uniformità |
| `is_permutation_bytes(data)` | `&[u8]` | `bool` | Verifica permutazione su byte |
| `recover_tbox(encoded)` | `&[u32; 256]` | `TBoxRecovery` | Recupera T-box da versione encoded a 32-bit |
| `extract_round_key_from_tboxes(tboxes)` | `&[TBoxCandidate]` | `Option<[u8; 16]>` | Estrae round key da set di candidati |
| `uniformity_deviation(freq, n)` | `&[u32;256], usize` | `f64` | Deviazione dall'uniformità della distribuzione |
| `reference_t0_row()` | — | `[u32; 256]` | Riga T0 di riferimento AES (lookup table standard) |
| `batch_analyze(chunks)` | `&[(&[u8], u64)]` | `Vec<WbAnalysisReport>` | Analisi parallela di più chunk binari (rayon) |
| `merge_reports(reports)` | `&[WbAnalysisReport]` | `WbAnalysisReport` | Unisce più report in uno solo |

---

## Riepilogo per modulo

| Modulo | Funzioni pub |
|---|---|
| `lib.rs` | ~90 |
| `whitebox_aes_full.rs` | ~29 |
| `wb_key_recovery.rs` | ~22 |
| `tbox_analysis.rs` | ~22 |
| `table_decomposer.rs` | 7 |
| `lookup_table_extractor.rs` | 11 |
| `linear_attack.rs` | ~22 |
| `dfa_full.rs` | ~13 |
| `dfa_attacker.rs` | ~8 |
| `dfa_attack.rs` | ~16 |
| `dca_fault_model.rs` | ~16 |
| `bge_attack.rs` | ~25 |
| `bge_attacker.rs` | ~16 |
| `aes_wb_analyzer.rs` | ~36 |
| **Totale** | **~333** |
