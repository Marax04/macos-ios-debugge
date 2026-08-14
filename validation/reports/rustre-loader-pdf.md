# rustre-loader-pdf

**Crate:** `rustre-loader-pdf` v0.1.0  
**Dipendenze principali:** `rustre-core`, `flate2`, `serde`, `anyhow`, `thiserror`, `tokio`

Libreria per parsing, analisi di sicurezza e rilevamento malware su file PDF. Copre parsing completo della struttura PDF (xref, oggetti, stream, trailer), decodifica dei filtri di compressione (Flate/LZW/PNG-predictor/TIFF-predictor), estrazione e analisi del codice JavaScript embeddato, rilevamento exploit, heap spray, shellcode e file embeddati.

---

## Funzioni pubbliche (modulo-level)

### `lib.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `is_pdf(data: &[u8]) -> bool` | slice di byte grezzi | `bool` | Verifica la firma magic `%PDF-` all'inizio del file |
| `pdf_version(data: &[u8]) -> Option<String>` | slice di byte | `Option<String>` | Estrae la versione PDF dall'header (es. `"1.7"`) |
| `has_javascript(data: &[u8]) -> bool` | slice di byte | `bool` | Rileva la presenza di stream JavaScript nel PDF |
| `has_embedded_files(data: &[u8]) -> bool` | slice di byte | `bool` | Rileva file embeddati nel PDF |
| `xref_offsets(bytes: &[u8]) -> Vec<(u32, u64)>` | slice di byte | `Vec<(object_num, file_offset)>` | Estrae le entry xref (numero oggetto, offset nel file) |
| `extract_streams(bytes: &[u8]) -> Vec<PdfStream>` | slice di byte | `Vec<PdfStream>` | Estrae tutti gli stream raw dal PDF |
| `decode_percent_encoding(s: &str) -> Vec<u8>` | stringa URL-encoded | `Vec<u8>` | Decodifica encoding percentuale (`%XX`) |
| `deobfuscate_js_simple(js: &str) -> String` | sorgente JS offuscato | `String` | Deoffuscazione semplice (unescape, eval layers) |
| `extract_urls_from_js(js: &str) -> Vec<String>` | sorgente JS | `Vec<String>` | Estrae URL/URI dal codice JavaScript |

### `metadata.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `extract_metadata(data: &[u8]) -> PdfMetadata` | slice di byte | `PdfMetadata` | Estrae autore, titolo, creatore, date dall'Info dictionary |
| `detect_linearized(data: &[u8]) -> bool` | slice di byte | `bool` | Rileva se il PDF è linearizzato (fast web view) |
| `count_updates(data: &[u8]) -> u32` | slice di byte | `u32` | Conta le revisioni incrementali (numero di `%%EOF`) |
| `count_objects(data: &[u8]) -> usize` | slice di byte | `usize` | Conta le entry `obj` nel file |
| `detect_xref_stream(data: &[u8]) -> bool` | slice di byte | `bool` | Rileva se la xref è in formato stream (PDF 1.5+) |
| `compute_forensics(data: &[u8]) -> PdfForensics` | slice di byte | `PdfForensics` | Calcola hash, dimensione, entropia e anomalie forensi |

### `security.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `scan_pdf(data: &[u8]) -> SecurityReport` | slice di byte | `SecurityReport` | Scansione completa: aggrega tutti i sotto-scanner in un report |
| `scan_javascript(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva stream JS e segnala come minaccia |
| `scan_embedded_files(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva file embeddati sospetti (EmbeddedFile, FileAttachment) |
| `scan_launch_actions(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva azioni `/Launch` (esecuzione di comandi) |
| `scan_uri_actions(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva azioni `/URI` potenzialmente pericolose |
| `scan_openactions(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva `/OpenAction` automatici all'apertura |
| `scan_obfuscation(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva tecniche di offuscamento nel PDF |
| `scan_xfa(data: &[u8]) -> Vec<ThreatEntry>` | slice di byte | `Vec<ThreatEntry>` | Rileva form XFA (vettore d'attacco noto) |
| `calculate_risk_score(threats: &[ThreatEntry]) -> u8` | slice di ThreatEntry | `u8` (0–100) | Calcola punteggio di rischio aggregato pesato |

### `structures.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `extract_catalog(doc: &PdfDocument) -> PdfCatalog` | riferimento a PdfDocument | `PdfCatalog` | Estrae il Catalog dictionary (root del PDF) |
| `extract_info(doc: &PdfDocument) -> PdfInfo` | riferimento a PdfDocument | `PdfInfo` | Estrae l'Info dictionary (metadati documento) |
| `extract_encrypt(doc: &PdfDocument) -> Option<PdfEncrypt>` | riferimento a PdfDocument | `Option<PdfEncrypt>` | Estrae il dictionary di cifratura, se presente |
| `enumerate_streams(doc: &PdfDocument) -> Vec<PdfStream>` | riferimento a PdfDocument | `Vec<PdfStream>` | Enumera tutti gli stream del documento con metadati |

### `pdf_stream_decoder.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `flate_decompress(data: &[u8]) -> Result<Vec<u8>, DecodeError>` | dati compressi | `Result<Vec<u8>>` | Decompressione Deflate/zlib (filtro FlateDecode) |
| `png_predictor_undo(data: &[u8], colors, bits, columns, predictor) -> Vec<u8>` | dati predittore PNG | `Vec<u8>` | Annulla predittore PNG (sub/up/average/Paeth) per FlateDecode |
| `tiff_predictor_undo(data: &[u8], colors, bits, columns) -> Vec<u8>` | dati predittore TIFF | `Vec<u8>` | Annulla predittore TIFF orizzontale |
| `lzw_decompress(data: &[u8], early_change: bool) -> Result<Vec<u8>, DecodeError>` | dati LZW | `Result<Vec<u8>>` | Decompressione LZW (filtro LZWDecode, con flag EarlyChange) |

### `pdf_full_parser.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `parse_pdf_from_reader<R: Read>(reader: R) -> Result<PdfDocument>` | reader generico `Read` | `Result<PdfDocument>` | Parsing completo del PDF da qualsiasi reader |
| `parse_pdf_from_buf_reader<R: BufRead>(reader: R) -> Result<PdfDocument>` | reader bufferizzato `BufRead` | `Result<PdfDocument>` | Parsing completo del PDF da reader bufferizzato |

### `pdf_js_extractor.rs`

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `detect_obfuscation(source: &str) -> Vec<ObfuscationPattern>` | sorgente JS | `Vec<ObfuscationPattern>` | Rileva pattern di offuscamento (eval, unescape, hex encoding, ecc.) |
| `detect_heap_spray(source: &str) -> HeapSprayDetect` | sorgente JS | `HeapSprayDetect` | Analisi heap spray: NOP sled, shellcode pattern, ripetizioni |
| `detect_shellcode_hints(data: &[u8]) -> Vec<ShellcodeHint>` | byte grezzi | `Vec<ShellcodeHint>` | Rileva pattern tipici di shellcode nei byte |
| `find_suspicious_calls(source: &str) -> Vec<String>` | sorgente JS | `Vec<String>` | Individua chiamate JS sospette (Collab.getIcon, util.printf, ecc.) |
| `compute_risk(obf, heap, shellcode, calls) -> RiskScore` | vari risultati di analisi | `RiskScore` | Calcola punteggio di rischio aggregato degli script JS |

---

## Strutture principali

- **`PdfDocument`** — rappresentazione completa del PDF (oggetti, xref, trailer)
- **`PdfParser`** — parser stateful con accesso a oggetti e stream
- **`PdfMalwareReport`** — report malware con indicatori, CVE, punteggio
- **`SecurityReport`** — report sicurezza con lista `ThreatEntry` e `risk_score`
- **`PdfObjectGraph`** — grafo degli oggetti con rilevamento cicli e orphan
- **`FilterChain` / `StreamDecoder`** — catena di filtri PDF decodificabili
- **`PdfJsExtractor`** — estrattore unificato di script JavaScript da PDF
- **`PdfExploitAnalyzer`** — aggregatore di tutti gli scanner exploit

---

## Note tecniche

- Il crate non usa `lopdf` o altre librerie PDF esterne: tutto il parsing è scritto da zero in Rust puro.
- Il modulo `pdf_stream_decoder` implementa FlateDecode (via `flate2`), LZWDecode (impl interna), ASCIIHexDecode, ASCII85Decode con predictor PNG/TIFF.
- `pdf_malware_analyzer` coordina gli scanner su due livelli: byte-level (security.rs) e DOM-level (strutture PDF già parsate).
- `pdf_exploit_analysis` include firme CVE hard-coded per vulnerabilità note dei viewer PDF.
