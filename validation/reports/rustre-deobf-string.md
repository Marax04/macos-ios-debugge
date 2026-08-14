# Crate: rustre-deobf-string

Passi di analisi per detect/isolate/recovery di stringhe offuscate: stack-string recovery, XOR/RC4/ChaCha20/AES decryption, split-string reconstruction, encoded-string detection, brute-force key recovery, classificazione, annotazione, pipeline multi-stage.

## Funzioni pubbliche free-standing

### Modulo `lib.rs`

- `xor_brute_force_top3(data: &[u8]) -> Vec<XorBruteforceCandidate>` — Brute force di tutte le 256 chiavi single-byte XOR, score per printability, ritorna top 3 candidati con confidence e decode UTF-8/lossy.
- `detect_xor_key_length_ic(data: &[u8], max_key_len: usize) -> Vec<(usize, f64)>` — Rileva la lunghezza probabile della chiave XOR ripetuta tramite Index of Coincidence sui sub-stream.
- `recover_multibyte_xor(data: &[u8], max_key_len: usize) -> Vec<MultiByteXorResult>` — Recupera chiave XOR multi-byte usando IC + frequency analysis (Kasiski-style) sulle top-3 lunghezze.
- `detect_rc4_ksa_in_mlil(instructions: &[LlilInstruction]) -> Vec<Rc4KsaPattern>` — Riconosce il pattern di RC4 KSA (loop 0..256 con swap) in IR MLIL.
- `rc4_inverse_ksa(s_final: &[u8; 256]) -> Vec<Vec<u8>>` — Tentativo di inversione KSA RC4 dato lo stato finale dell'S-box (no-op senza known-plaintext, ritorna lista vuota).
- `detect_base64_variant(data: &[u8]) -> Option<Base64Variant>` — Determina se i bytes sono Base64 Standard / URL-safe / Custom (alfabeto su 64-65 simboli).
- `decode_base64_urlsafe(input: &str) -> Result<Vec<u8>, StringDeobfError>` — Decodifica Base64 URL-safe normalizzando `-`/`_` in `+`/`/`.
- `decode_base64_custom(input: &[u8], alphabet: &[u8; 64]) -> Result<Vec<u8>, StringDeobfError>` — Decodifica Base64 con alfabeto custom fornito.
- `caesar_brute_force(input: &str) -> Vec<CaesarBruteforceResult>` — Prova tutte le 25 rotazioni Caesar e le ordina per English frequency score.
- `detect_arith_obf_in_mlil(instructions: &[LlilInstruction], ciphertext: &[u8]) -> Vec<ArithDeobfResult>` — Rileva offuscamento aritmetico (ADD/SUB/ROL/ROR/XOR con costante) nel MLIL e tenta inversione + brute force.
- `detect_mlil_stack_strings(instructions: &[LlilInstruction]) -> Vec<MlilStackString>` — Ricostruisce stack-string da store consecutivi di costanti byte in MLIL.
- `detect_string_decoder_helpers(func_addr: u64, instructions: &[LlilInstruction]) -> Vec<StringDecoderSignature>` — Riconosce funzioni helper di decode stringhe (XOR loop o RC4 256-loop) da firma MLIL.
- `batch_decrypt_string_table<F>(entries: &[StringTableEntry], data_provider: F, algorithm: StringAlgorithm) -> Vec<StringTableResult>` — Decifra in batch una tabella di stringhe applicando l'algoritmo specificato (`F: Fn(u64, usize) -> Option<Vec<u8>>`).
- `compute_confidence(decrypted: &[u8]) -> u8` — Calcola score di confidence [0,100] sulla base di printability + pattern noti (URL, http, null-term, freq EN).
- `recover_stack_strings(instructions: &[LlilInstruction]) -> Vec<RecoveredString>` — API legacy: ricostruisce stack-string da store di byte consecutivi via offset rsp/rbp.
- `detect_xor_encryption(instructions: &[LlilInstruction]) -> bool` — Heuristic: true se MLIL contiene XOR con operando costante.
- `run_pass()` — No-op const (placeholder).

### Modulo `xor_string_decoder`

- `score_plaintext(data: &[u8]) -> f64` — Score di plausibilità plaintext (printability + frequenze).
- `to_display_string(data: &[u8]) -> String` — Converte bytes in stringa display-friendly con escape.
- `brute_force_xor(data: &[u8]) -> Vec<(XorKey, f64, Vec<u8>)>` — Brute-force XOR a chiave singola; ritorna chiave, score, plaintext.
- `brute_force_xor_multi(data: &[u8], max_key_len: usize) -> Vec<(XorKey, f64)>` — Brute-force XOR multi-byte fino a max_key_len.

### Modulo `xor_decryptor`

- `brute_force_single_byte_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate>` — Brute-force XOR single-byte, ritorna tutti i candidati scorati.
- `best_single_byte_xor(ciphertext: &[u8]) -> Option<XorKeyCandidate>` — Miglior candidato XOR single-byte.
- `index_of_coincidence(data: &[u8]) -> f64` — Calcola IC della stream.
- `detect_key_length_ic(ciphertext: &[u8], max_key_len: usize) -> Vec<(usize, f64)>` — Detection di key length via IC, output ordinato.
- `kasiski_trigrams(ciphertext: &[u8]) -> Vec<(Vec<u8>, Vec<usize>)>` — Kasiski analysis: trova trigrammi ripetuti e posizioni.
- `kasiski_key_length(ciphertext: &[u8], max_key_len: usize) -> Vec<(usize, usize)>` — Stima key length da Kasiski (lunghezza, frequenza).
- `xor_decrypt_multibyte(ciphertext: &[u8], key: &[u8]) -> Vec<u8>` — Decifra XOR ciclico con chiave multi-byte.
- `recover_multibyte_key(ciphertext: &[u8], key_len: usize) -> Vec<u8>` — Recupera chiave multi-byte data la lunghezza nota.
- `attack_multibyte_xor(...)` — Attacco completo multi-byte XOR (IC + frequency).
- `brute_force_rol_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate>` — Brute-force XOR + ROL constant.
- `brute_force_ror_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate>` — Brute-force XOR + ROR constant.
- `brute_force_xor_add(ciphertext: &[u8]) -> Vec<XorKeyCandidate>` — Brute-force XOR + ADD constant.
- `decrypt_rolling_xor(ciphertext: &[u8], initial_key: u8) -> Vec<u8>` — Decifra XOR rolling key (chiave incrementata).
- `brute_force_rolling_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate>` — Brute-force rolling XOR.

### Modulo `unicode_obfuscation_detector`

- `homoglyph_check(s: &str) -> Vec<ObfuscationFinding>` — Trova caratteri Unicode che impersonano ASCII.
- `mixed_script_check(s: &str) -> Option<ObfuscationFinding>` — Rileva mixing di script Unicode sospetto.
- `normalize_homoglyphs(s: &str) -> String` — Sostituisce omoglifi con equivalenti ASCII.
- `strip_invisible(s: &str) -> String` — Rimuove caratteri invisibili (ZWSP, ZWJ, ecc.).
- `count_non_ascii_unicode(s: &str) -> usize` — Conta i code point non-ASCII.
- `has_bidi_override(s: &str) -> bool` — Rileva presenza di char di override bidi (RTL/LTR attacks).
- `has_invisible_char(s: &str) -> bool` — True se contiene caratteri invisibili.

### Modulo `string_encryption_bruteforcer`

- `result_to_candidate(result: &BruteforceResult) -> KeyCandidate` — Converte risultato bruteforce in `KeyCandidate`.
- `bruteforce(ciphertext: &[u8]) -> Vec<BruteforceResult>` — Esegue bruteforce su tutti gli algoritmi supportati.
- `bruteforce_top_n(ciphertext: &[u8], n: usize) -> Vec<KeyCandidate>` — Top-N candidati cross-algorithm.
- `printability_score(data: &[u8]) -> f64` — Score printability per ranking.

### Modulo `string_classifier`

- `classify_string(s: &str) -> ClassificationResult` — Classifica una stringa per categoria (URL, IP, email, UUID, indirizzo crypto, ecc.).
- `looks_like_url(s: &str) -> bool`
- `looks_like_ipv4(s: &str) -> bool`
- `looks_like_ipv6(s: &str) -> bool`
- `looks_like_email(s: &str) -> bool`
- `looks_like_uuid(s: &str) -> bool`
- `looks_like_btc_address(s: &str) -> bool`
- `looks_like_eth_address(s: &str) -> bool`
- `looks_like_iban(s: &str) -> bool`
- `looks_like_credit_card(s: &str) -> bool`
- `luhn_check(digits: &[u8]) -> bool` — Validazione Luhn per credit card.
- `looks_like_domain(s: &str) -> bool`
- `looks_like_pe_header(s: &str) -> bool` — Riconosce signature PE/MZ.
- `looks_like_shellcode_hex(s: &str) -> bool`

### Modulo `string_annotation`

- `export_tsv(strings: &[AnnotatedString]) -> String` — Esporta stringhe annotate in formato TSV.

### Modulo `stack_string_asm_detector`

- `detect_stack_strings(instrs: &[(u64, String, String)]) -> Vec<StackStringHit>` — Rileva stack-string da istruzioni assembly (tuple addr, mnemonic, operands).

### Modulo `custom_encoding_detector`

- `detect_encoding(data: &[u8]) -> Vec<EncodingPattern>` — Rileva pattern di encoding custom (alfabeti non-standard).

### Modulo `stack_string_decoder`

- `decode_stack_string(...) -> ...` — Decodifica singola stack-string da char pushes.
- `batch_decode(...) -> ...` — Decodifica batch di stack-string.
- `is_likely_stack_string(pushes: &[CharPush], min_count: usize) -> bool` — Heuristic se una sequenza di push e' una stack-string.
- `reconstruct_from_bytes(bytes: &[u8]) -> Option<String>` — Ricostruisce stringa UTF-8 da bytes (best-effort).
- `count_chars_from(pushes: &[CharPush], base_offset: i64) -> usize` — Conta char pushes a partire da un base offset.

### Modulo `chacha20`

- `quarter_round(state: &mut [u32; 16], a, b, c, d: usize)` — Quarter-round in-place su stato ChaCha20.
- `quarter_round_pure(a, b, c, d: u32) -> (u32, u32, u32, u32)` — Quarter-round puro.
- `chacha20_block(initial_state: &ChaCha20State) -> [u8; 64]` — Genera un blocco keystream ChaCha20.
- `chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8>` — Encrypt ChaCha20.
- `chacha20_decrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8>` — Decrypt ChaCha20 (simmetrico).
- `detect_chacha20_in_mlil(instructions: &[LlilInstruction]) -> Vec<ChaCha20Detection>` — Detection ChaCha20 in MLIL via costanti "expand 32-byte k" e pattern di quarter-round.
- Costanti: `CHACHA20_CONST_0..3: u32`, `CHACHA20_CONSTANTS: [u32; 4]`.

### Modulo `encoding_detector`

- `decode_url_percent(s: &str) -> Option<Vec<u8>>` — Decodifica URL percent-encoding.
- `is_url_encoded(s: &str) -> bool`
- `decode_unicode_escapes(s: &str) -> Option<String>` — Decodifica `\uXXXX` Unicode escapes.
- `has_unicode_escapes(s: &str) -> bool`
- `rot13(s: &str) -> String`
- `rot47(s: &str) -> String`
- `looks_like_rot13(s: &str) -> bool`
- `looks_like_rot47(s: &str) -> bool`

### Modulo `crypto_string_decrypt`

- `rc4_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8>` — RC4 decrypt one-shot.
- `aes128_ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16]` — AES-128 ECB single-block encrypt.
- `aes128_ecb_decrypt_padded(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8>` — AES-128 ECB decrypt con PKCS7 unpad.
- `aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8>` — AES-128 CBC decrypt.
- `chacha20_crypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8>` — ChaCha20 crypt (re-export).
- `custom_xor_cipher_decrypt(key: &[u8], ciphertext: &[u8], rounds: u32) -> Vec<u8>` — XOR ciclico ripetuto in N round.
- `brute_force_rc4_1byte(ciphertext: &[u8]) -> Option<(u8, Vec<u8>, f64)>` — Brute-force RC4 con chiave 1 byte.
- `brute_force_rc4_2byte(ciphertext: &[u8]) -> Option<([u8; 2], Vec<u8>, f64)>` — Brute-force RC4 con chiave 2 byte.
- `analyse_ciphertext(data: &[u8]) -> CipherAnalysis` — Analizza ciphertext (entropy, freq, plausibili cipher).

### Modulo `stack_string_reconstructor`

- `dedup_stack_strings(strings: Vec<StackString>) -> Vec<StackString>` — Deduplica stack-string per contenuto/offset.

### Modulo `deobf_pipeline`

- `run_pipeline_anyhow(...) -> anyhow::Result<...>` — Esegue pipeline di deobfuscation gestendo errori via anyhow.
- `auto_build_pipeline(data: &[u8], max_depth: usize) -> DeobfPipeline` — Costruisce automaticamente pipeline multi-stage in base ai bytes di input fino a `max_depth` stadi.

---

**Nota**: il crate espone anche numerosi `pub struct` / `pub enum` (es. `StringAlgorithm`, `StringDeobfuscator`, `XorDecryptor`, `Rc4`, `RotN`, `Base64Decoder`, `HexDecoder`, `ApiHasher`, `DecryptionChain`, `StringObfuscationReport`, `AiStringRecovery`, `DeobfPipeline`, ecc.) con i propri metodi `impl`. Sopra sono elencate solo le funzioni pubbliche free-standing al livello dei moduli.
