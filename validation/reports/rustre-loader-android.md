# rustre-loader-android — Public Functions

Crate: `rustre-loader-android` — parsing per APK (ZIP+DEX), DEX bytecode, ART VDEX/OAT, blocchi di firma APK, AXML manifest, e dispatcher di caricamento Android.

Solo funzioni libere `pub fn` / `pub const fn` (esclusi metodi `impl`).

## src/lib.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `is_apk` | `data: &[u8]` | `bool` | Riconosce header ZIP + presenza di `classes.dex`. |
| `is_dex` | `data: &[u8]` | `bool` | Riconosce magic `dex\n` + cifra di versione. |
| `is_vdex` | `data: &[u8]` | `bool` | Riconosce magic `vdex` + cifra di versione ART. |
| `adler32` | `data: &[u8]` | `u32` | Calcola Adler-32 (formato checksum DEX). |
| `verify_dex_checksum` | `data: &[u8]` | `Result<(), AndroidLoaderError>` | Verifica il checksum Adler-32 memorizzato nei byte 8..12 del DEX. |
| `read_string_table` | `data: &[u8], hdr: &DexHeader` | `Vec<String>` | Decodifica l'intera tabella `string_id` (MUTF-8 + ULEB128). |
| `read_dex_string` | `data: &[u8], off: usize` | `String` | Legge una singola stringa MUTF-8 DEX a un offset dato. |
| `read_type_ids` | `data: &[u8], hdr: &DexHeader` | `Vec<TypeIdItem>` | Parsa la tabella `type_id_item`. |
| `read_proto_ids` | `data: &[u8], hdr: &DexHeader` | `Vec<ProtoIdItem>` | Parsa la tabella `proto_id_item` (prototipi metodo). |
| `read_field_ids` | `data: &[u8], hdr: &DexHeader` | `Vec<FieldIdItem>` | Parsa la tabella `field_id_item`. |
| `read_method_ids` | `data: &[u8], hdr: &DexHeader` | `Vec<MethodIdItem>` | Parsa la tabella `method_id_item`. |
| `read_class_defs` | `data: &[u8], hdr: &DexHeader` | `Vec<ClassDefItem>` | Parsa tutte le `class_def_item` (32 byte ciascuna). |
| `read_uleb128` | `data: &[u8], pos: &mut usize` | `u32` | Decodifica un valore ULEB128 avanzando il cursore. |
| `parse_encoded_methods` | `data: &[u8], class_data_off: u32` | `Vec<EncodedMethod>` | Estrae lista metodi (direct+virtual) dal `class_data_item`. |
| `parse_apk_entries` | `data: &[u8]` | `Result<Vec<ApkEntry>, AndroidLoaderError>` | Localizza l'EOCD e legge tutte le entry della Central Directory ZIP. |
| `extract_entry_data<'a>` | `data: &'a [u8], entry: &ApkEntry` | `Result<&'a [u8], AndroidLoaderError>` | Restituisce slice dei byte (eventualmente compressi) di una entry APK. |
| `detect_signing_schemes` | `data: &[u8]` | `Vec<ApkSigningScheme>` | Rileva schemi di firma APK v1/v2/v3 (JAR + APK Sig Block). |
| `extract_vdex_dex_files` | `data: &[u8]` | `Result<Vec<DexFile>, AndroidLoaderError>` | Estrae i DEX consecutivi incorporati in un'immagine VDEX. |
| `parse_manifest` | `bytes: &[u8]` | `Result<AndroidManifest, AndroidLoaderError>` | Parsa AXML binario di `AndroidManifest.xml` (chunk stream + string pool). |
| `list_dex_classes` | `dex_bytes: &[u8]` | `Vec<String>` | Convenience: lista i nomi classe completi del DEX. |
| `collect_all_bytecode` | `dex_bytes: &[u8]` | `Vec<u8>` | Concatena il bytecode Dalvik di tutti i metodi del DEX. |
| `dalvik_opcode_class` (const) | `opcode: u8` | `DalvikOpcodeClass` | Classifica un opcode Dalvik nella sua macro-categoria. |
| `opcode_histogram` | `insns: &[u16]` | `HashMap<DalvikOpcodeClass, usize>` | Istogramma di categorie di opcode su una sequenza di insn. |

## src/manifest_binary.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `parse_string_pool` | `data: &[u8], offset: usize` | `Result<AxmlStringPool, AxmlError>` | Parsa il chunk `ResStringPool` di AXML/ARSC. |
| `parse_android_manifest_binary` | `data: &[u8]` | `Result<BinaryManifest, AxmlError>` | Parser AXML completo che produce un manifesto strutturato. |

## src/signing_v4.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `detect_v4_signature` | `data: &[u8]` | `bool` | Rileva la presenza del sidecar `.idsig` (firma v4). |
| `verify_v4_signature` | `idsig_data: &[u8], _apk_data: &[u8]` | `Result<bool, V4SignatureError>` | Verifica la firma APK v4 a partire dai byte del file `.idsig`. |

## src/dex.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `read_uleb128` | `data: &[u8], pos: &mut usize` | `u32` | Decodifica ULEB128 (variante del modulo `dex`). |
| `read_string` | `data: &[u8], string_ids: &[u32], idx: u32` | `String` | Risolve un `string_idx` in una stringa MUTF-8. |
| `is_public` (const) | `flags: u32` | `bool` | Test flag `ACC_PUBLIC`. |
| `is_private` (const) | `flags: u32` | `bool` | Test flag `ACC_PRIVATE`. |
| `is_static` (const) | `flags: u32` | `bool` | Test flag `ACC_STATIC`. |
| `is_final` (const) | `flags: u32` | `bool` | Test flag `ACC_FINAL`. |
| `is_interface` (const) | `flags: u32` | `bool` | Test flag `ACC_INTERFACE`. |
| `is_abstract` (const) | `flags: u32` | `bool` | Test flag `ACC_ABSTRACT`. |
| `is_annotation` (const) | `flags: u32` | `bool` | Test flag `ACC_ANNOTATION`. |
| `is_enum` (const) | `flags: u32` | `bool` | Test flag `ACC_ENUM`. |
| `access_flags_string` | `flags: u32` | `String` | Rappresentazione testuale dei flag di accesso DEX. |

## src/apk.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `crc32_table` | — | `[u32; 256]` | Genera la tabella di lookup CRC-32 (polinomio ZIP). |
| `compute_crc32` | `data: &[u8]` | `u32` | Calcola CRC-32 su un buffer (validazione entry ZIP). |
| `detect_apk` | `data: &[u8]` | `bool` | Heuristica di riconoscimento APK. |
| `find_apk_v2_signing_block` | `data: &[u8]` | `Option<ApkSignatureBlock>` | Individua e parsa l'APK Signing Block v2 prima dell'EOCD. |

## src/apk_zip_reader.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `crc32` | `data: &[u8]` | `u32` | CRC-32 indipendente per l'estrattore ZIP. |
| `build_test_zip` | `name: &str, payload: &[u8]` | `Vec<u8>` | Costruisce uno ZIP minimo (un'entry stored) per test. |

## src/art_analysis.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `read_cstring` | `data: &[u8], offset: usize` | `Option<String>` | Legge una C-string NUL-terminata. |
| `align_up` (const) | `val: u64, align: u64` | `u64` | Allinea verso l'alto a `align`. |
| `align_down` (const) | `val: u64, align: u64` | `u64` | Allinea verso il basso a `align`. |
| `is_power_of_two` (const) | `val: u64` | `bool` | Verifica se è potenza di due. |
| `byte_entropy` | `data: &[u8]` | `f64` | Entropia di Shannon (0..8) di un buffer. |
| `le_u16` | `data: &[u8], off: usize` | `u16` | Lettura little-endian u16 a offset. |
| `le_u32` | `data: &[u8], off: usize` | `u32` | Lettura little-endian u32 a offset. |
| `le_u64` | `data: &[u8], off: usize` | `u64` | Lettura little-endian u64 a offset. |
| `be_u32` | `data: &[u8], off: usize` | `u32` | Lettura big-endian u32 a offset. |
| `adler32` | `data: &[u8]` | `u32` | Variante locale di Adler-32 per ART. |
| `find_bytes` | `haystack: &[u8], needle: &[u8]` | `Option<usize>` | Cerca la prima occorrenza di una sequenza. |
| `count_bytes` | `haystack: &[u8], needle: &[u8]` | `usize` | Conta tutte le occorrenze di una sequenza. |
| `try_slice` | `data: &[u8], offset: usize, len: usize` | `Option<&[u8]>` | Slice sicura con bound-check. |
| `is_zeroed` | `data: &[u8]` | `bool` | True se tutti i byte sono zero. |
| `reverse_bytes` (const) | `data: &mut [u8]` | `()` | Inverte in-place i byte di uno slice. |
| `xor_bytes` | `data: &mut [u8], key: u8` | `()` | XOR in-place con una chiave a byte singolo. |
| `rol32` (const) | `val: u32, n: u32` | `u32` | Rotate left a 32 bit. |
| `ror32` (const) | `val: u32, n: u32` | `u32` | Rotate right a 32 bit. |

## src/art_method_resolver.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `build_oat_stub` | `isa: InstructionSet, dex_count: u32` | `Vec<u8>` | Genera bytes stub di un file OAT minimale per test/fixture. |

## src/dex_optimizer_detector.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `shannon_entropy` | `data: &[u8]` | `f64` | Entropia di Shannon usata per riconoscere DEX ottimizzati/compressi. |

## src/android_binary_loader.rs

| Funzione | Argomenti | Ritorno | Descrizione |
|---|---|---|---|
| `detect_format` | `data: &[u8]` | `AndroidFormat` | Dispatch del formato (APK/DEX/VDEX/OAT/ART/ELF). |
| `load_android_binary` | `data: &[u8]` | `Result<(AndroidLoadedComponent, Vec<u8>)>` | Carica un binario Android in-memory, restituendo componente parsato + payload primario estratto. |
| `load_android_file` | `path: &Path` | `Result<(AndroidLoadedComponent, Vec<u8>)>` | Wrapper su `load_android_binary` che legge da filesystem. |
| `default_output_dir` | `comp: &AndroidLoadedComponent` | `PathBuf` | Calcola directory di output di default per un componente caricato. |
| `extract_all_components` | (dispatcher su APK) | `…` | Estrae tutti i componenti interessanti di un APK (DEX, native libs, manifest). |
| `summarise` | `data: &[u8], comp: &AndroidLoadedComponent` | `AndroidLoadSummary` | Produce un sommario testuale/strutturato dopo il caricamento. |

---
Totale funzioni libere `pub fn` / `pub const fn`: **70**.
