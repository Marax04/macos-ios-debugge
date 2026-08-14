# rustre-analysis-string

## Purpose
String detection, decoding, classification and similarity analysis for binary reverse engineering. Scans raw byte buffers for human-readable strings across ASCII, UTF-8, UTF-16 LE/BE, UTF-32 LE/BE, Latin-1, Shift-JIS; provides a queryable StringDatabase, encoding/XOR/Base64/Hex/ROT detection and decoding, classification (URL/IP/email/format-string/crypto/obfuscation), edit-distance/clustering similarity, stack-string reconstruction from LLIL.

## Public Functions / Types (top-level API)

### Scanning core
- `StringScanner::scan(base: Address, bytes: &[u8]) -> Vec<FoundString>` — scan a slice loaded at `base` for all configured encodings. Externally verifiable: against Python `strings`-equivalent (regex `[\x20-\x7e]{n,}` for ASCII; codecs for UTF-16).
- `StringScanner::scan_ascii / scan_utf8 / scan_utf16_le` — per-encoding scans returning FoundString with absolute virtual addresses. Verifiable by hand-crafted byte buffers.
- `StringScanner::read_cstring(base, bytes, addr) -> Option<FoundString>` — read null-terminated C string at a given virtual address. Verifiable: pass `b"foobar\0hello\0"`, expect "hello" at offset 7.
- `StringScanner::scan_pascal_strings(base, bytes) -> Vec<FoundString>` — 1-byte length-prefixed strings. Verifiable: `[5,'h','e','l','l','o']` → "hello".

### Database
- `StringDatabase::from_scan / add / at(addr) / iter / count / filter_by_encoding / interesting_strings / longest(n) / search(q) / stats() -> StringStats`. All verifiable by oracle Python: count, longest by len, case-insensitive substring.

### Heuristics on FoundString
- `is_printable`, `looks_like_path`, `looks_like_url`, `looks_like_format_string`, `looks_like_registry_key`, `entropy() -> f64` (Shannon entropy over UTF-8 bytes), `is_interesting`. Verifiable: entropy of "aaaa" = 0.0; "ab" = 1.0; comparable to Python implementation.

### Top-level free function
- `detect_xor_key(data: &[u8]) -> Option<u8>` — finds single-byte XOR key making >70% of bytes printable ASCII. Verifiable: XOR a known plaintext with key K, function must return Some(K).

### Re-exported modules
- `encoding_detect::{auto_decode, base64_decode, hex_decode, detect_base64, detect_hex_encoded, detect_rot_n, detect_rot13, detect_xor_single_byte, xor_decode_single, xor_decode_multibyte, recover_xor_multibyte_key, estimate_xor_key_length, xor_key_candidates, rot_decode, rot13_decode, rot_byte, encoding_summary}` — all individually verifiable against Python `base64`, `binascii`, `codecs.rot_13`, manual XOR.
- `decrypt::{auto_decrypt, decrypt_base64, decrypt_hex, decrypt_rot_n, decrypt_xor_byte, decrypt_xor_key, BulkDecryptor, decrypt_string_blobs, group_by_algorithm, identify_stub_pattern, extract_xor_key_from_instrs, extract_multibyte_key_from_instrs}` — decoding wrappers and stub pattern identification.
- `classify::{StringClassifier, classify, extract_urls, extract_ips, extract_emails, extract_format_strings, extract_crypto_constants, extract_obfuscated, detect_crypto_constant, detect_format_string, detect_obfuscation, is_private_ipv4, looks_like_base64, looks_like_hex, parse_ipv4, shannon_entropy}` — verifiable via regex/Python ipaddress/base64.
- `similarity::{levenshtein, levenshtein_similarity, jaro, jaro_winkler, lcs_length, lcs_similarity, jaccard_ngram, ngrams, cluster_strings, extract_template}` — verifiable with `python-Levenshtein`/`jellyfish`.
- `stackstring::{StackStore, reconstruct_stack_strings, reconstruct_stack_strings_from_llil, link_string_xrefs, most_referenced}` — recovers strings built byte-by-byte on stack. Requires LLIL input.
- `string_xref::{StringRecord, StringXref, string_xrefs}` — link strings to code references.

### Analysis pass
- `StringRecoveryPass: AnalysisPass` — scans all memory segments of a `BinaryView` and returns `strings_found` count in `AnalysisResult`.

## Existing MCP tools
- `analysis_string_scan_path` (rustre-mcp-tools/wire_tools.rs:5168) — path-based wrapper around `StringScanner`. Input: binary path + config. Output: list of FoundString.

NOTE: many free functions (xor/rot/base64 decode, levenshtein, jaro_winkler, detect_xor_key, classify::*) are NOT exposed via MCP tools — only the scan wrapper exists.

## Testable functions (high-value for validation)
1. `StringScanner::scan_ascii` — oracle: Python regex `[\x20-\x7e]{>=min}\x00`.
2. `StringScanner::scan_utf16_le` — oracle: `bytes.decode('utf-16-le')` split on NUL.
3. `StringScanner::read_cstring` — oracle: manual offset + read until 0.
4. `StringScanner::scan_pascal_strings` — oracle: parse `[len][bytes]` loop.
5. `FoundString::entropy` — oracle: Python `-sum(p*log2(p))` over byte freq.
6. `detect_xor_key` — oracle: XOR plaintext with known key, expect recovery.
7. `encoding_detect::base64_decode` / `hex_decode` — oracle: Python `base64.b64decode`, `bytes.fromhex`.
8. `encoding_detect::xor_decode_single` / `xor_decode_multibyte` — oracle: trivial XOR in Python.
9. `encoding_detect::rot13_decode` / `rot_decode` — oracle: `codecs.encode(s,'rot_13')`.
10. `similarity::levenshtein` / `jaro_winkler` / `lcs_length` — oracle: `jellyfish` / `python-Levenshtein`.
11. `classify::shannon_entropy`, `is_private_ipv4`, `parse_ipv4`, `extract_urls/ips/emails` — oracle: `ipaddress`, regex.
12. `StringDatabase::longest/search/stats` — oracle: trivial Python equivalents on the same FoundString list.

## Validator strategy
Two-tier validator:

**Tier A — pure-data oracle (no binary needed):**
Build synthetic byte buffers in Python with known string content/encoding/XOR/Base64. Drive the Rust crate via a thin CLI (or unit-test harness writing JSON results) and compare against Python ground truth:
- For scanners: assert {address, length, encoding, value} set equality.
- For decoders (base64/hex/rot/xor): assert byte-level equality with stdlib `base64`/`binascii`/`codecs`.
- For similarity: assert numeric equality (within 1e-6) with `jellyfish.jaro_winkler_similarity`, `Levenshtein.distance`.
- For `detect_xor_key`: brute-force XOR a 256-byte ASCII pangram with each key 1..=255 and verify recovery.
- For `entropy` / `shannon_entropy`: numpy/scipy entropy on the same byte distribution.

**Tier B — real binary cross-check (cargo-zyphora.exe baseline):**
Run `analysis_string_scan_path` on the IDA baseline binary; count strings per encoding and spot-check the top-N longest against IDA's Strings window (memory/MEMORY.md baseline: 1456 functions / 395 named; strings count not yet recorded). Acceptance: ≥95% overlap with IDA's ASCII string list at min_length=4, null-terminated.

Persist results to `validation/reports/rustre-analysis-string.json` with per-function pass/fail and numeric deltas.
