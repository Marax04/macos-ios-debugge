# rustre-crypto-id — Analysis

## Purpose
Cryptographic algorithm identification in raw binary data. Scans byte slices for known cryptographic constants (S-boxes, init vectors, round constants, polynomial tables) and algorithmic instruction patterns to identify which crypto algorithm a binary uses. Also produces ranked assessments, key-candidate detection (high-entropy regions), and active-probe plans for downstream validation.

## Public Functions (top-level / lib.rs surface)

### `BinaryScanner::scan(&self, data: &[u8]) -> Vec<CryptoHit>`
- Input: arbitrary byte slice.
- Output: list of hits `{offset, algorithm, constant_name, confidence}`.
- Behavior: linear search for each known constant (MD5/SHA1/SHA256/SHA512 H0, SHA256-K, AES-SBOX, AES-INV-SBOX, SM4-SBOX, CRC32 table, RIPEMD-160 anchor) at every offset. Confidence scaled by constant size.
- External truth: deterministic; given a buffer containing exactly the AES S-box at offset N, expect a hit `AES-SBOX` at offset N, algorithm=Aes128, confidence ≈ 0.95.

### `CryptoScanner::full_scan(&self, data: &[u8]) -> Result<CryptoReport, CryptoIdError>`
- Input: bytes (≥ 4 bytes else `TooShort`).
- Output: `CryptoReport { algorithms_found, possible_keys, recommendations }`.
- Behavior: runs BinaryScanner + finds 16/24/32-byte windows with Shannon entropy > 0.9, builds textual recommendations.
- External truth: empty data → `TooShort`. Buffer of pure 0x00s → no algorithms, no keys (entropy=0).

### `CryptoScanner::identify_active(&self, data, config) -> Result<ActiveIdentificationPlan>`
- Input: bytes + IdentificationConfig.
- Output: ranked AlgorithmAssessments + ActiveProbe payloads.
- Behavior: full_scan, then groups evidence per algorithm, combines confidence via `1 - Π(1-p)`, filters by min_confidence, and emits canonical probe payloads (ECB-repetition 64×'A', padding mutations, block-size sweeps, avalanche stream probes).
- External truth: combined confidence formula is deterministic; for two pieces of evidence at 0.95 and 0.95 → combined ≈ 1 - 0.05² = 0.9975, clamped to 0.99.

### `FunctionScanner::analyze(code: &[u8]) -> Vec<PatternHit>`
- Input: byte slice (function body, x86 opcodes).
- Output: heuristic pattern hits.
- Behavior: counts XOR (0x31/0x33), ROL (0xC1 ..C0), XCHG (0x86/0x87), MUL (0xF7 ..E0) byte occurrences; emits ChaCha20/RC4/RSA hits over thresholds.
- External truth: handcrafted byte sequence with N XOR opcodes + M ROL opcodes is deterministically classified.

### `shannon_entropy(data: &[u8]) -> f64`
- Input: bytes.
- Output: Shannon entropy in [0, 8] (bits/byte).
- External truth: `[0u8;N]` → 0.0; uniform random → ~8.0. Comparable to Python `scipy.stats.entropy` over a 256-bin histogram (base 2).

### Standalone scanners — `scan_for_aes_sbox / sha256_constants / crc32_table / chacha_magic / md5_constants / sha256_init / tea_delta / sha512_init / sha1_init / md5_init / blowfish_p / bcrypt_magic / camellia_sigma / des_sbox(binary: &[u8]) -> Vec<BinaryCryptoHit>`
- Input: bytes.
- Output: per-algorithm offset hits.
- External truth: each function detects a specific public constant table. E.g. `scan_for_aes_sbox` on a buffer containing the AES Rijndael S-box (256 bytes, well-known constant) returns exactly the offsets where it appears.

### `scan_binary_for_crypto_constants(binary: &[u8]) -> Vec<BinaryCryptoHit>`
- Aggregate of all `scan_for_*` scanners above.

### `scan_and_summarize(binary: &[u8]) -> CryptoScanSummary`
- Aggregate + per-algorithm count summary.

### `identify_in_binary(data: &[u8]) -> Vec<CryptoFinding>`
- Top-level convenience: returns all findings on a binary.

### Exported constants (verifiable):
- `MD5_H` = `[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]` — FIPS published IVs.
- `SHA1_H` — RFC 3174 IVs.
- `SHA256_H` / `SHA256_K` — FIPS 180-4.
- `AES_SBOX` / `AES_INV_SBOX` / `AES_RCON` — FIPS 197.
- `CRC32_POLY` = `0xEDB88320` — reversed ISO-HDLC polynomial.
- `SM4_SBOX` — GB/T 32907-2016.
- `BUILTIN_TEST_VECTORS` — at least 5 KATs (AES-128-ECB FIPS-197 Appx B, SHA-256 of "", MD5 of "", CRC32 of "hello world", ChaCha20 RFC 8439 §2.4.2, SHA-256 of "abc"). Each independently verifiable with standard libraries (hashlib, zlib, pycryptodome).

## Existing MCP tools (rustre-mcp-tools)
- `analysis_crypto_scan_path` (AnalysisCryptoScanPathTool, wire_tools.rs:5286) — path-based findcrypt scanning every loader section using `constant_scanner::ConstantScanner` with section-resolved VAs.
- `crypto_xor_decode` (CryptoXorDecodeTool, wire_tools.rs:5799) — XOR-region decode utility (IDA xor_decode_at_addr parity).
- Aggregated usage: `scan_binary_for_crypto_constants` is invoked in the `analyze_full` / `survey_binary` pipelines to populate `crypto_hits` and `crypto.by_algorithm` JSON fields (wire_tools.rs:4266, 4526).

## Validator strategy
Use known public constants as ground-truth inputs:
1. **Constant detection**: embed AES S-box / SHA-256 init / CRC32 table at a known offset inside a random buffer → assert corresponding `scan_for_*` returns that offset; assert `BinaryScanner::scan` reports algorithm + name.
2. **Hash-init isolation**: feed only `SHA256_H` bytes (big-endian) → expect Sha256 hit at offset 0.
3. **Entropy bounds**: `shannon_entropy([0u8;1024])` ≈ 0.0; `shannon_entropy(os.urandom(4096))` ≈ ~7.99. Cross-check with Python `scipy.stats.entropy`.
4. **Built-in KATs**: validate each `BUILTIN_TEST_VECTORS` entry against `hashlib`/`zlib`/`Crypto.Cipher.AES`/`Crypto.Cipher.ChaCha20` — confirms correctness of the embedded test vectors (not the scanner itself, but the reference data).
5. **Confidence combine**: feed synthetic evidence list and verify `combined = 1 − Π(1−pᵢ)` clamped to 0.99.
6. **Error path**: `full_scan(&[1,2,3])` → `Err(TooShort)`.
7. **MCP parity**: invoke `analysis_crypto_scan_path` on `cargo-zyphora.exe` (IDA baseline: 43 findcrypt hits) → compare counts and offsets.
