# Crypto and Triage Subsystems — Unified Analysis

> This document merges the three sub-analyses that cover the cryptographic
> identification/attack pipeline and the static triage/YARA stack of RustRE.
>
> **Sub-files (kept for individual reference):**
> - `11a-crypto.md` — `rustre-crypto-id`, `rustre-crypto-oracle`, `rustre-crypto-whitebox`
> - `11b-triage.md` — `rustre-triage`, `rustre-triage-die`, `rustre-triage-entropy`, `rustre-triage-peid`, `rustre-triage-yara`
> - `11c-yara.md` — `rustre-yara`, `rustre-yara-engine`, `rustre-yara-rules`

---

# Part A — Crypto Crates

# 11a — Crypto Crates Analysis

Covers three crates that together form the cryptographic analysis pipeline of RustRE:
`rustre-crypto-id`, `rustre-crypto-oracle`, and `rustre-crypto-whitebox`.

---

## 1. rustre-crypto-id

### Purpose

Passive identification of cryptographic algorithms in binary data.  The crate
scans raw bytes for known constants and S-boxes, performs function-level
heuristic pattern analysis, and ranks findings into a deterministic
`AlgorithmAssessment` list.  It does **not** attack or decrypt; it is the
detection layer that feeds oracle and whitebox crates downstream.

### Dependencies

| Crate | Role |
|-------|------|
| `serde` / `serde_json` | Serialise all public result types |
| `thiserror` | `CryptoIdError` |
| `parking_lot` | `RwLock` on `SignatureDatabase` |

No async, no I/O, no network.

### Modules

| Module | Content |
|--------|---------|
| `lib.rs` | Constants, `SignatureDatabase`, `BinaryScanner`, `FunctionScanner`, `CryptoScanner`, `AlgorithmId`, `TestVector`, probe planning, `IdentificationConfig` |
| `algorithm_db` | Extended algorithm metadata store |
| `cipher_detection` | Block / stream cipher heuristics |
| `constant_scanner` | Low-level byte-pattern search helpers |
| `constant_db` | Built-in constant registry (hash IVs, S-boxes) |
| `hash_identifier` | Hash-specific signatures |
| `hash_function_detector` | Structural hash-function pattern matching |
| `impl_detector` | Implementation-style detection (table-based vs bitsliced) |
| `protocol_analysis` | Protocol-layer crypto detection |
| `protocol_crypto` | Protocol-specific crypto constants |
| `active_prober` | Active probe generation |
| `side_channel_hints` | Operand-pattern side-channel hints |
| `stream_cipher_detector` | RC4 / ChaCha20 / Salsa20 structural patterns |
| `asymmetric_detector` | RSA / ECDSA structural patterns |

### Key Public API (lib.rs)

```rust
// Enum — 24 recognised algorithms
pub enum CryptoAlgorithm { Md5, Sha1, Sha256, Sha512, Sha3_256, Blake2b,
    Aes128, Aes256, Des, TripleDes, Rc4, ChaCha20, Salsa20, Rsa, Ecdsa,
    Ed25519, X25519, Crc32, Adler32, Sm3, Sm4, Whirlpool, Tiger, Ripemd160 }

// Richer variant including AEAD modes and Custom
pub enum AlgorithmId { Aes128, Aes192, Aes256, AesGcm, ChaCha20,
    ChaCha20Poly1305, Sha1, Sha256, Sha512, Blake2b, Md5, Crc32, Rc4,
    Des, TripleDes, Rsa, Ed25519, Custom(String) }

pub struct SignatureDatabase   // Arc<RwLock<Vec<CryptoConstant>>>
    fn new() -> Self           // loads built-in constants
    fn add(&self, CryptoConstant)
    fn constants(&self) -> Vec<CryptoConstant>

pub struct BinaryScanner
    fn new() -> Self
    fn with_database(SignatureDatabase) -> Self
    fn scan(&self, data: &[u8]) -> Vec<CryptoHit>

pub struct FunctionScanner
    fn analyze(code: &[u8]) -> Vec<PatternHit>   // x86 opcode heuristics

pub struct CryptoScanner
    fn new() -> Self
    fn full_scan(&self, data: &[u8]) -> Result<CryptoReport, CryptoIdError>
    fn identify_active(&self, data, config) -> Result<ActiveIdentificationPlan, _>

impl CryptoReport
    fn evidence(&self, config) -> Vec<IdentificationEvidence>
    fn assessments(&self, config) -> Vec<AlgorithmAssessment>
    fn active_identification_plan(&self, config) -> ActiveIdentificationPlan
```

### Built-in Signatures (SignatureDatabase::load_builtins)

| Constant | Algorithm | Size | Confidence |
|----------|-----------|------|------------|
| MD5-H0 | MD5 | 16 B | 0.70 |
| SHA1-H0 | SHA-1 | 20 B | 0.70 |
| SHA256-H0 | SHA-256 | 32 B | 0.80 |
| SHA256-K0 | SHA-256 | 64 B | 0.80 |
| AES-SBOX | AES-128 | 256 B | 0.95 |
| AES-INV-SBOX | AES-128 | 256 B | 0.95 |
| SM4-SBOX | SM4 | 256 B | 0.95 |
| CRC32-TABLE | CRC32 | 1024 B | 0.95 |
| SHA512-H0 | SHA-512 | 64 B | 0.80 |
| RIPEMD160-ANCHOR | RIPEMD-160 | 8 B | 0.80 |

### FunctionScanner Heuristics

Pattern matching operates directly on x86 byte sequences:

```
XOR density > 30 + ROL count > 8        → ChaCha20 (0.65)
XCHG opcode count > 10                  → RC4 KSA  (0.55)
MUL (F7 /4) count > 20                  → RSA modexp (0.50)
```

These are coarse and architecture-specific (x86 only).  No RISC-V, ARM, or
x86-64 prefixes are accounted for beyond byte values.

### Active Probe Generation

`CryptoReport::active_identification_plan` maps each assessed algorithm to
`ActiveProbe` structs that downstream tooling can execute against a live
oracle:

| Probe Kind | Trigger | Expected observation |
|------------|---------|----------------------|
| `EcbRepetition` | AES-128/256, SM4 | Identical 16-byte CT blocks → ECB mode |
| `PaddingMutation` | AES-128/256, SM4 | Padding validity delta → CBC oracle |
| `BlockSizeSweep` | DES, 3DES | Length jump every 8 bytes |
| `KnownPlaintextAvalanche` | RC4, ChaCha20, Salsa20 | 1-bit delta propagation |

### Test Vectors (BUILTIN_TEST_VECTORS)

Five complete NIST/RFC known-answer test vectors are embedded as `static`:
AES-128-ECB (FIPS 197 Appendix B), SHA-256 of empty string, MD5 of empty
string, CRC32 of `b"hello world"`, ChaCha20 (RFC 8439 §2.4.2), and SHA-256 of
`b"abc"`.

### Completeness

**Complete** — no `todo!` or `unimplemented!` in any source file.  All 14
modules compile.  The heuristics in `FunctionScanner` are intentionally coarse
(documented); the confidence scores reflect this.

### Gaps

- `FunctionScanner` patterns are x86-only byte values; no x86-64 REX prefix
  handling or ARM/AArch64 patterns.
- No SHA-3 / BLAKE3 constants in `SignatureDatabase` despite `CryptoAlgorithm`
  listing `Sha3_256` and `Blake2b`.
- No Blowfish, Twofish, or BLAKE2b constants in the built-in set (though
  `scan_symmetric_constants` in the whitebox crate does cover Blowfish).
- `KeyCandidate` detection uses a fixed step-by-4 stride; overlapping
  high-entropy regions can be missed.

---

## 2. rustre-crypto-oracle

### Purpose

Active cryptographic attack implementations against black-box oracles.  The
crate provides full CBC padding-oracle decryption, ECB byte-at-a-time suffix
recovery, nonce-reuse exploitation, CBC IV prediction, OTP key-reuse analysis,
replay detection, CBC bit-flipping, ECB cut-and-paste, timing attack harness,
AES brute-force, RSA textbook attacks, protocol field synthesis, and async
oracle connectivity verification.

### Dependencies

| Crate | Role |
|-------|------|
| `serde` / `serde_json` | All result/config types |
| `anyhow` | `OracleVerifier::verify_oracle` errors |
| `thiserror` | `OracleError` |
| `reqwest` | Async HTTP oracle verification |
| `tokio` | Async runtime for reqwest |
| `subtle` | (imported, for constant-time comparisons in submodules) |
| `getrandom` | CSPRNG for `ProtocolField::Random` generation |
| `ahash` | (imported, fast hashing in submodules) |

### Modules

| Module | Content |
|--------|---------|
| `lib.rs` | Core traits + all major attack structs (4000+ lines) |
| `padding_oracle` | Additional padding-oracle helpers |
| `padding_oracle_attack` | Variant implementations |
| `padding_oracle_detector` | Automated oracle detection probes |
| `ecb_oracle` | ECB-specific probing |
| `hash_attacks` | Hash-specific attack utilities |
| `hash_length_extension` | SHA-1 / SHA-256 length extension |
| `key_schedule_analyzer` | Key-schedule pattern detection |
| `oracle_automation` | Automated oracle interaction scripts |
| `oracle_detection` | Protocol-level oracle detection |
| `oracle_exploitation` | High-level exploit orchestration |
| `oracle_query_engine` | Async query batching |
| `side_channel` | Side-channel measurement helpers |
| `timing_oracle_full` | Timing attack full implementation |
| `stream_cipher_attacks` | Stream-cipher-specific attacks |
| `whitebox_attacks` | Bridge to whitebox crate attacks |

### Key Public API (lib.rs)

```rust
// Traits
pub trait OracleCallable: Send + Sync { fn call(&self, input: &[u8]) -> OracleResult; }
pub trait Oracle: Send + Sync { fn query(&self, ciphertext: &[u8]) -> bool; }
pub struct BoolOracleAdapter<'a>(pub &'a dyn Oracle);

// Oracle discovery
pub struct OracleDiscovery
    fn probe_suite(block_size: usize) -> Result<Vec<OracleProbe>, OracleError>
    fn analyze_outcomes(block_size, outcomes) -> OracleDiscoveryReport
    fn discover_with_oracle(block_size, oracle) -> Result<OracleDiscoveryReport, OracleError>

// Full CBC padding-oracle attack
pub struct PaddingOracleAttack
    fn decrypt_block(ct, prev, oracle) -> Result<Vec<u8>, OracleError>
    fn decrypt_cbc(ct, iv, oracle) -> Result<Vec<u8>, OracleError>
    fn decrypt_block_callable(ct, prev, oracle) -> Result<Vec<u8>, OracleError>

// ECB byte-at-a-time
pub struct EcbByteAtATime
    fn detect_ecb(oracle_encrypt) -> bool
    fn determine_block_size(oracle_encrypt) -> usize
    fn recover_unknown_suffix(oracle_encrypt, block_size) -> Vec<u8>

// Nonce reuse
pub struct NonceReuseDetection
    fn collect_ciphertexts(query_fn, plaintexts) -> Vec<NonceCiphertext>
    fn find_nonce_reuse(pairs) -> Vec<(usize, usize)>
    fn attack_nonce_reuse(ct1, ct2, known_p1) -> Vec<u8>
    fn analyze_xor_for_english(xored) -> f64

// IV prediction
pub struct IvPredictionAttack
    fn detect_counter_iv(ivs) -> bool
    fn predict_next_iv(current_iv) -> Vec<u8>
    fn forge_chosen_plaintext(current_iv, known_pt, desired_pt) -> Vec<u8>

// OTP key reuse
pub struct OtpKeyReuse
    fn recover_key_byte(stream_byte_col) -> u8

// Replay
pub struct ReplayAttack
    fn detect_stateless(oracle, ciphertext) -> bool
    fn replay(oracle, captured_ct) -> OracleResult

// Timing
pub struct TimingAttack
    fn median_duration(measurements) -> Option<u64>
    fn byte_timing_attack<F>(oracle_fn, samples) -> u8

// AES weak-key utilities
pub struct AesCracker
    fn is_weak_key(key) -> bool
    fn weak_keys() -> Vec<Vec<u8>>
    fn brute_force_short<F>(key_len, verify_fn) -> Option<Vec<u8>>

// RSA attacks (u64/u128 toy-modulus scale)
pub struct RsaAttacks
    fn small_exponent_attack(ciphertext_bytes, exponent) -> Option<Vec<u8>>
    fn wiener_attack(e, n) -> Option<u64>
    fn fermat_factor(modulus) -> Option<(u64, u64)>
    fn common_modulus_attack(c1, e1, c2, e2, n) -> Option<u64>

// CBC bit-flip / ECB cut-and-paste
pub struct CbcBitFlippingAttack
    fn flip(ct, iv, target_offset, known_plain, desired) -> Result<(Vec<u8>, Vec<u8>), OracleError>
pub struct EcbCutAndPasteAttack
    fn reorder_blocks(ct, block_size, order) -> Result<Vec<u8>, OracleError>

// Protocol synthesis
pub struct HttpRequestTemplate
    fn render(&self, values) -> HttpRequest
    fn export_python_server(template) -> String
pub struct ProtocolSynthesizer
    fn infer_fields(samples) -> Vec<ProtocolField>

// Async oracle probe
pub struct OracleVerifier
    async fn verify_oracle(oracle_url, sample_request) -> anyhow::Result<bool>

// Field classification
pub struct RequestFieldAnalyzer
    fn analyze_field_across_samples(samples) -> FieldCharacteristics

// Constant scan (mirrors whitebox crate)
pub fn scan_crypto_constants(binary) -> Vec<CryptoConstantHit>
```

### Padding Oracle Attack — Implementation Notes

`PaddingOracleAttack::decrypt_block` implements the standard PKCS#7 CBC
padding-oracle byte recovery with an important disambiguation step: when a
valid-padding guess is found at `byte_idx > 0`, the preceding byte is flipped
to confirm it is not an accidental multi-byte-pad false positive:

```rust
let mut verify = crafted_prev;
verify[byte_idx - 1] ^= 1;
let mut vp = verify.to_vec();
vp.extend_from_slice(ciphertext);
if !oracle.query(&vp) { continue; }
```

`decrypt_cbc` chains `decrypt_block` across all 16-byte blocks and strips
PKCS#7 padding from the result.  Total oracle queries: up to 256 × 16 per block.

### RSA Attacks — Scope Limitation

All RSA attack methods (`wiener_attack`, `fermat_factor`, `common_modulus_attack`)
operate on `u64` moduli for Wiener/Fermat and `u128` intermediates for
`small_exponent_attack`.  These are teaching/CTF-scale implementations; they
cannot attack production-size moduli (2048-bit).

### Protocol Synthesizer — SHA-256 Inline

`HttpRequestTemplate::hmac_sha256` contains a complete, self-contained SHA-256
implementation (no dependency on external crate) to allow HMAC generation for
protocol field synthesis without pulling in a hash crate.

### EmulatorOracle Stub

`EmulatorOracle::decrypt` is a documented stub that returns the input unchanged
(identity transform) with a comment describing the Unicorn-engine integration
that would be needed:

```rust
// Stub: in real implementation, set up Unicorn context, map memory,
// write ciphertext to input_buf_addr, write key, set registers,
// start emulation at func_addr, read output_buf_addr after return.
```

This is the only substantive stub in the file; it is not marked `todo!` but the
function body does no real emulation.

### Test Coverage

The crate includes a full `#[cfg(test)]` section in `lib.rs` with a
`TestOracle` that wraps a real AES-128 CBC implementation (key schedule +
`SubBytes` + `ShiftRows` + `MixColumns` + `AddRoundKey`, all inlined) used to
verify end-to-end `PaddingOracleAttack::decrypt_cbc` correctness.

### Completeness

**Effectively complete** — no `todo!` or `unimplemented!` anywhere in the
crate.  `EmulatorOracle::decrypt` is the only placeholder logic (does not
emulate), documented explicitly as a stub.

### Gaps

- `EmulatorOracle` requires Unicorn-engine integration to be functional.
- RSA attacks are limited to toy-size moduli (u64/u128).
- `OtpKeyReuse::recover_key_byte` scores only ASCII letters/spaces; no
  frequency-table approach for non-English corpora.
- `IvPredictionAttack` assumes counter IVs only; no timestamp or PRNG-seed
  prediction modes.
- `ProtocolSynthesizer::infer_fields` is a very simple heuristic (unique-ratio
  threshold 0.3) — no HMM or entropy-based inference.

---

## 3. rustre-crypto-whitebox

### Purpose

Whitebox cryptography analysis: detect, decompose, and extract keys from
whitebox AES/RC4/SM4/DES implementations embedded in binary blobs.  Implements
DFA (Differential Fault Analysis), BGE (Billet-Gilbert-Ech-Idrissi) attack,
DCA (Differential Computation Analysis), AES T-table scanning, key-schedule
reversal, and both SQLite and MySQL persistent result storage.

### Dependencies

| Crate | Role |
|-------|------|
| `serde` / `serde_json` / `serde-big-array` | Serialise tables and results |
| `rusqlite` | SQLite-backed `WhiteboxDatabase` |
| `mysql` | MySQL-backed `MysqlWhiteboxDb` |
| `parking_lot` | `Mutex<Connection>` for SQLite |
| `rayon` | Parallel table scanning (in submodules) |
| `thiserror` | `CryptoError` |

### Modules

| Module | Content |
|--------|---------|
| `lib.rs` | All core types, AES helpers, `AesWhiteboxExtractor`, `Rc4WhiteboxDetector`, `Sm4WhiteboxDetector`, `WhiteboxDatabase`, `MysqlWhiteboxDb`, `AesDfaAttack`, `BgeAttack`, `DcaAnalyzer`, `Aes256KeySchedule`, `AesKeyScheduleReverse`, `scan_crypto_constants` (5495 lines) |
| `dfa_full` | Full multi-fault DFA campaign orchestrator |
| `dfa_attack` | Additional DFA primitives |
| `dfa_attacker` | DFA result aggregation |
| `bge_attack` | Additional BGE implementation details |
| `bge_attacker` | BGE campaign orchestration |
| `whitebox_aes_full` | Full AES whitebox analysis pipeline |
| `aes_wb_analyzer` | AES whitebox structural analysis |
| `tbox_analysis` | T-box / encoded T-table analysis |
| `table_decomposer` | Lookup table decomposition |
| `lookup_table_extractor` | Raw binary table extraction |
| `wb_key_recovery` | Key recovery coordination |
| `dca_fault_model` | DCA fault modelling |
| `linear_attack` | Linear analysis of whitebox tables |

### Key Public API (lib.rs)

```rust
// Core trait
pub trait WhiteboxAnalyzer: Send + Sync {
    fn analyze(&self, binary: &[u8]) -> Result<WhiteboxResult, CryptoError>;
}

// Concrete analyzers
pub struct AesWhiteboxExtractor   // T-table + S-box + key-schedule detection
pub struct Rc4WhiteboxDetector    // permutation scan + greedy KSA key recovery
pub struct Sm4WhiteboxDetector    // S-box + FK/CK constant scan

// Key schedule tools
pub struct AesKeyScheduleReverse
    fn reverse_128(round_keys: &[u8]) -> Result<Vec<u8>, CryptoError>
    fn from_last_round_key(last_rk: &[u8]) -> Result<Vec<u8>, CryptoError>
pub struct Aes256KeySchedule
    fn expand(key: &[u8; 32]) -> Vec<u8>
    fn reverse_from_all(round_keys) -> Result<Vec<u8>, CryptoError>
    fn from_last_round_key(last_rk) -> Result<Vec<u8>, CryptoError>

// DFA
pub struct AesDfaAttack
    fn new() -> Self
    fn add_faulty(&mut self, ct: Vec<u8>)
    fn set_reference(&mut self, ct: Vec<u8>)
    fn xor_diff(a, b) -> Option<Vec<u8>>
    fn is_valid_fault_pattern(diff) -> bool
    fn recover_round10_key(&self) -> Option<Vec<u8>>
    fn exhaustive_key_search(faulty_pairs) -> Option<Vec<u8>>

// BGE
pub struct BgeAttack
    fn attack_chow_implementation(encoded_tables) -> Result<Vec<u8>, CryptoError>
    fn is_chow_compatible(tables) -> bool
    fn strip_outer_encoding(table) -> Result<LookupTable, CryptoError>
    fn find_sbox_candidates(data) -> Vec<(u64, [u8; 256])>
    fn is_bijective(table) -> bool
    fn is_affinely_equivalent_to_sbox(table) -> bool

// DCA
pub struct DcaAnalyzer
    fn new() -> Self
    fn add_trace(&mut self, input: Vec<u8>, samples: Vec<f64>)
    fn compute_correlation(&self, byte_pos, target_round) -> DcaResult
    fn full_attack(&self) -> Result<Vec<DcaKeyByteResult>, CryptoError>
    fn pearson_correlation(x, y) -> f64
    fn hamming_weight_model(input_byte, key_guess, round) -> f64

// Storage
pub struct WhiteboxDatabase      // SQLite, Arc<Mutex<Connection>>
    fn open(path: Option<&str>) -> Result<Self, CryptoError>
    fn store(&self, name, result) -> Result<i64, CryptoError>
    fn list(&self) -> Result<Vec<StoredResult>, CryptoError>

pub struct MysqlWhiteboxDb       // MySQL pool-per-call
    fn new(url) -> Result<Self, CryptoError>
    fn create_table(&self) -> Result<(), CryptoError>
    fn store(&self, name, result) -> Result<u64, CryptoError>
    fn list(&self) -> Result<Vec<StoredResult>, CryptoError>
    fn find_by_algorithm(&self, algo) -> Result<Vec<StoredResult>, CryptoError>

// Standalone scan (re-exported from lib)
pub fn scan_crypto_constants(binary: &[u8]) -> Vec<CryptoConstantHit>

// AES state primitives (used by DFA simulator)
pub fn sub_bytes(state: &mut [u8; 16])
pub fn inv_sub_bytes(state: &mut [u8; 16])
pub const fn aes_shift_rows(state: &mut [u8; 16])
pub const fn aes_shift_rows_inverse(state: &mut [u8; 16])
```

### AES T-table Detection

`find_t_tables` scans for all four rotations of the AES T0 table in 4-byte
aligned windows:

```rust
fn is_aes_t_table(words: &[u32; 256]) -> bool {
    let t0 = build_t0_table();
    for shift in 0u32..4 {
        if words.iter().zip(t0.iter())
            .all(|(&w, &t)| w == t.rotate_right(shift * 8)) { return true; }
    }
    false
}
```

T0 is built from `AES_SBOX` via GF(2^8) multiplication: `T[i] = [2s, s, s, 3s]`
where `s = sbox[i]`.  This handles all four T-table variants (T0–T3) in a
single pass.

### AES Key Schedule Reversal

`AesKeyScheduleReverse::from_last_round_key` fully inverts all 10 rounds of
the AES-128 key schedule from the 16-byte round-10 key, recovering the original
128-bit key.  `Aes256KeySchedule::from_last_round_key` explicitly returns an
error noting that AES-256 inversion from the last round key alone is impossible
(requires 2 round keys due to the interleaved schedule).

### DFA Implementation

`AesDfaAttack::exhaustive_key_search` implements the per-position DFA
constraint with a cross-pair locking step: for each of 256 key byte candidates,
it computes `InvSBox[ct[pos] ^ k] XOR InvSBox[ct'[pos] ^ k]` across all fault
pairs.  A candidate is rejected if the delta is zero (no fault propagation) or
if the delta is inconsistent across pairs sharing the same fault injection.
This is stronger than naive "delta != 0" filtering.

`is_valid_fault_pattern` verifies that a 16-byte XOR difference has exactly 4
non-zero bytes in one of the four AES diagonal patterns
(`[0,5,10,15]`, `[1,6,11,12]`, `[2,7,8,13]`, `[3,4,9,14]`).

### BGE Attack

`BgeAttack::attack_chow_implementation` models Chow's whitebox AES by:
1. Verifying Chow compatibility (≥4 tables, each ≥256 bytes)
2. Attempting to strip outer affine encodings via XOR-constant search
   (`is_affinely_equivalent_to_sbox` tests all 256 input XOR constants)
3. Recovering each key byte by comparing stripped table against all 256 XOR
   offsets of `AES_SBOX`

The affine equivalence test handles only XOR-class encodings (additive/linear),
not general affine (GF(2^8) matrix multiplication).  Full BGE requires more.

### DCA

`DcaAnalyzer::compute_correlation` implements CPA (Correlation Power Analysis)
with a Hamming-weight model: `HW(SubBytes(input XOR key_guess))`.  Pearson
correlation is computed between this model and each sample column across all
traces.  `full_attack` requires ≥10 traces and returns 16 `DcaKeyByteResult`
entries.  The Pearson implementation is numerically stable (two-pass mean
subtraction).

### RC4 Key Recovery

`Rc4WhiteboxDetector::recover_key_from_state` performs a greedy KSA inversion:
for each key length 1–32 and each key slot, it tries all 256 byte candidates,
selecting the one that maximises agreement between the simulated KSA output and
the observed S-array.  Recovery is accepted when >200/256 state bytes match.
This is a heuristic; it can fail for complex whitebox encodings that obscure the
raw S-array.

### Storage

Two independent persistence backends:

- **SQLite** (`WhiteboxDatabase`): `Arc<Mutex<Connection>>`, in-memory or file.
  Schema: `whitebox_impl(id, name, algorithm, confidence, analysis, key_hex, created_at)`.
- **MySQL** (`MysqlWhiteboxDb`): pool-per-call (no connection reuse), schema
  mirrors SQLite with `BIGINT AUTO_INCREMENT` and `TIMESTAMP DEFAULT`.

### Completeness

**Complete** — no `todo!` or `unimplemented!` in any source file.  All 14
modules compile.  The BGE affine-equivalence test is noted as a simplification
in comments; the key-byte extraction uses XOR-only encoding stripping, not
general matrix-class affine.

### Gaps

- `BgeAttack::strip_outer_encoding` only handles XOR (additive) encodings;
  full BGE requires GF(2^8) affine matrix inversion.
- `Aes256KeySchedule::from_last_round_key` is intentionally unimplemented
  (returns error); only `reverse_from_all` works for AES-256.
- `Sm4WhiteboxDetector` has no key recovery path — `scan_for_sm4_artifacts`
  always returns `None` for the key.
- `DcaAnalyzer` has no noise filtering or trace alignment; in practice, DCA on
  software traces benefits from mean-trace subtraction and DTW alignment.
- `MysqlWhiteboxDb` creates a new pool on every method call; for high-volume
  use this is inefficient.
- `rayon` is listed as a dependency but appears in submodules; the `lib.rs`
  T-table scan is single-threaded.

---

## Cross-Crate Integration Points

```
rustre-crypto-id
    ↓  CryptoHit / AlgorithmAssessment / ActiveProbe
rustre-crypto-oracle          (oracle interaction)
rustre-crypto-whitebox        (table-level key extraction)
```

`rustre-crypto-oracle::scan_crypto_constants` is a parallel implementation of
the same constant-scanning logic in `rustre-crypto-id::BinaryScanner`.  These
are currently independent copies; they should be unified or one should re-export
the other to avoid divergence.

The `EmulatorOracle` stub in `rustre-crypto-oracle` is the intended bridge to
an emulation crate (Unicorn-based); when that crate is wired in, oracle calls
can be driven against isolated binary code rather than live network endpoints.

---

## Summary Table

| Crate | Lines (lib.rs) | Modules | todo!/unimpl! | Completeness |
|-------|---------------|---------|---------------|--------------|
| rustre-crypto-id | 3999 | 13 | 0 | Complete |
| rustre-crypto-oracle | 2599 | 16 | 0 | Complete (EmulatorOracle stub) |
| rustre-crypto-whitebox | 5495 | 13 | 0 | Complete (BGE partial, SM4 no key) |

---

# Part B — Triage Crate Group

# Triage Crate Group Analysis

**Crates covered:** `rustre-triage`, `rustre-triage-die`, `rustre-triage-entropy`,
`rustre-triage-peid`, `rustre-triage-yara`

**Date:** 2026-07-02

---

## 1. Group Overview

The five triage crates form a layered static-analysis stack that classifies
a binary, assigns a threat score, and produces a structured JSON report — all
without executing the target.  The dependency graph is:

```
rustre-triage          (coordinator, defines shared types)
    ├── rustre-triage-die       (Detect-It-Easy style detection)
    ├── rustre-triage-entropy   (Shannon entropy analysis)
    ├── rustre-triage-peid      (PEiD pattern matching)
    └── rustre-triage-yara      (YARA-like rule engine)
```

`rustre-triage` owns `TriageResult`, `ThreatLevel`, and the pipeline
orchestration.  The sub-crates are independent engines that can be used
standalone or slotted into the pipeline as `PipelineStage` implementations.

---

## 2. `rustre-triage` — Triage Coordinator

### 2.1 Purpose

Quick automated analysis to classify a binary, compute hashes, measure entropy,
detect packers and suspicious strings, and assign an initial threat score
(0–100) with a qualitative `ThreatLevel`.  Acts as the entry point consumed
by `rustre-mcp-server` through `triage_core_run_pipeline`.

### 2.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-pe-tools` | `PeFile`, `compute_entropy` |
| `rustre-loader-pe` | PE parsing backend |
| `rustre-crypto-id` | `BinaryCryptoHit`, constant-scan stage |
| `sha2` / `md-5` | Hash computation |
| `serde` / `serde_json` | Report serialization |
| `thiserror` | Typed errors |

### 2.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `TriageError` | `enum` | `TooSmall`, `Pe`, `Io`, `Other` |
| `FileKind` | `enum` | 13 variants: `Pe32`, `Pe64`, `Elf32`, `Elf64`, `MachO`, `Apk`, `Dex`, `Zip`, `Pdf`, `Doc`, `Exe`, `Dll`, `Sys`, `Unknown` |
| `ThreatLevel` | `enum` | `Clean` → `Informational` → `Low` → `Medium` → `High` → `Critical` |
| `TriageIndicator` | `struct` | Named finding with `threat_level`, `category`, `evidence` |
| `TriageResult` | `struct` | Accumulates all findings; has `add_indicator`, `is_malicious`, `to_report`, `to_json` |
| `TriageReport` | `struct` | Flat JSON view with `all_strings` and `crypto_hits` |
| `ExtractedString` | `struct` | Printable string with offset and encoding |
| `SuspiciousString` | `struct` | String with reason/category |
| `detect_file_kind` | `fn` | Magic-byte classifier |
| `compute_sha256` / `compute_md5` | `fn` | Hash helpers |

`TriageResult::add_indicator` implements the scoring formula:

```rust
let delta: u8 = match indicator.threat_level {
    ThreatLevel::Clean         => 0,
    ThreatLevel::Informational => 2,
    ThreatLevel::Low           => 10,
    ThreatLevel::Medium        => 20,
    ThreatLevel::High          => 35,
    ThreatLevel::Critical      => 50,
};
self.score = self.score.saturating_add(delta).min(100);
```

### 2.4 Internal Modules

| Module | Role |
|---|---|
| `triage_pipeline` | `PipelineStage` trait + `TriagePipeline` orchestrator |
| `file_classifier` | Magic-byte → `FileKind` mapping |
| `heuristic_engine` | Rule-based heuristics (API suspicious-ness, etc.) |
| `score_aggregator` | Combines per-stage scores |
| `rapid_classifier` | Fast pre-check before deep analysis |
| `analyzer_registry` | Registry of named analyzer functions |
| `pe_triage_extended` | PE-specific checks (sections, imports, overlay) |
| `static_analysis_triage` | String + import scanning |
| `findcrypt` | Delegates to `rustre-crypto-id` |
| `mitre_mapper` | Maps indicator categories to ATT&CK technique IDs |
| `malware_classification` | Family/type classification |
| `family_db` | Known-family database |
| `triage_report` | Report formatting helpers |

### 2.5 Pipeline Architecture (`triage_pipeline.rs`)

```
PipelineStage trait (Send + Sync)
  ├── fn name() -> &'static str
  ├── fn run(data, &mut TriageResult) -> StageOutput
  └── fn applicable(FileKind) -> bool   // default: true

TriagePipeline
  ├── stages: Vec<Box<dyn PipelineStage>>
  ├── fn new() -> Self
  ├── fn default_pipeline() -> Self     // registers all built-in stages
  ├── fn add_stage(Box<dyn PipelineStage>)
  └── fn run(&[u8]) -> Result<PipelineRunResult, TriageError>
```

Built-in stages registered by `default_pipeline()`:

| Stage | What it does |
|---|---|
| `FileKindStage` | Sets `result.file_kind` from magic bytes |
| `EntropyStage` | Flags overall entropy above threshold |
| `PackerDetectionStage` | Searches for UPX!, `UPX0`/`UPX1`, MPRESS sections |
| `StringAnalysisStage` | Extracts suspicious strings (URLs, IPs, paths, APIs) |
| `AntiAnalysisStage` | Detects `IsDebuggerPresent`, `NtQueryInformationProcess`, etc. |
| `ShellcodeDetectionStage` | Heuristic shellcode patterns |
| `CryptoConstantScanStage` | `rustre_crypto_id::scan_binary_for_crypto_constants` |
| `AllStringExtractionStage` | Full ASCII+UTF-16 string extraction into `result.all_strings` |
| `CompilerDetectionStage` | Sets `result.compiler_hint` |

### 2.6 Completeness

**COMPLETE.** No `todo!` or `unimplemented!` calls. All stages have inline unit
tests covering entropy flagging, packer detection, URL strings, anti-analysis
APIs, and the pipeline summary. The `all_strings` + `crypto_hits` fields were a
known gap (noted in field doc-comments) and are now wired.

---

## 3. `rustre-triage-die` — Detect-It-Easy Style Detection

### 3.1 Purpose

Replicates Detect-It-Easy (DIE) packer/protector/compiler identification using
two complementary detection layers: a YAML structured-rule DSL evaluated against
PE headers/sections/imports, and a byte-pattern engine for EP and full-file
matching.

### 3.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `FileKind`, `TriageError` |
| `serde` / `serde_json` | Rule/result serialization |
| `thiserror` | Typed errors |

No external packer-detection library; all logic is native Rust.

### 3.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `DieCondition` | `enum` | 14 condition variants (see below) |
| `RuleCondition` | `enum` | `All`, `Any`, `Not` combinators over `DieCondition` |
| `BUILTIN_RULES` | `const &str` | Embedded YAML rule database (25+ rules) |
| `DieDetector` | `struct` | Parses YAML rules and evaluates them |
| `DetectKind` | `enum` | `Compiler`, `Packer`, `Protector`, `Installer`, `Tool` |
| `Detection` | `struct` | Match result with name/version/confidence |
| `DieError` | `enum` | Parse and evaluation errors |

`DieCondition` variants:

| Variant | Checks |
|---|---|
| `SectionName(String)` | PE section with given name exists |
| `SectionCount { min, max }` | Section count in range |
| `BytePattern { offset, hex }` | Hex bytes (with `??` wildcards) at offset |
| `EntryPointHex(String)` | Bytes at PE entry point |
| `EntropyRange { section, min, max }` | Section entropy in range |
| `ImportPresent { dll, func }` | Import present (case-insensitive) |
| `ImportCount { min, max }` | Import count in range |
| `ExportPresent(String)` | Named export present |
| `SubsystemType(u16)` | PE subsystem field |
| `StringPresent(String)` | Raw string in file bytes |
| `MachineType(u16)` | COFF machine field |
| `OverlayPresent` | Data past last section |
| `ResourcePresent(String)` | Named resource type |
| `Dotnet` | CLR data directory non-zero |
| `Manifest` | RT_MANIFEST resource |

### 3.4 Internal Modules

| Module | Role |
|---|---|
| `die_scanner` | `DieScanner` + `DieRuleEngine` — EP-aware, per-rule EP control, rich `DieReport` (~24 rules) |
| `rule_db_extended` | `ExtendedRuleDb` — 200+ entries, `Platform` flags, `DieRuleEntry` |
| `scanner` | Alternative `DieScanner` (SignatureDb + DieDetector combined) |
| `signature_db` | Binary pattern signature store |
| `die_signature_db` | Second signature database variant |
| `die_signatures` | Static signature definitions |
| `die_database` | Persistent signature database |
| `die_script_engine` | Lightweight script rule evaluator |
| `detector_engine` | High-level orchestration (`DetectorEngine`) |
| `die_extended` | Extended detection results with metadata |
| `compiler_detector` | Compiler fingerprinting (MSVC, GCC, Clang, Rust, Go, etc.) |
| `packer_detector` | Packer-specific heuristics |
| `packer_signature_db` | Packer-only signature subset |
| `overlay_analyzer` | Bytes-after-last-section analysis |
| `entropy_based_classifier` | Entropy-assisted detection |
| `heuristic_detector` | General heuristics fallback |

Two scanner implementations exist with different rule schemas:
- `die_scanner::DieScanner` uses `DieRuleEngine` with `builtin_rules()` (~24 rules); supports `ep_only`, `unpacked_only`, `platform` per rule.
- `scanner::DieScanner` uses `SignatureDb + DieDetector`; intended for the larger `rule_db_extended::EXTENDED_RULES` (~200 entries).

The YAML `BUILTIN_RULES` embedded in `lib.rs` covers UPX 3.x/4.x, MPRESS, ASPack, PECompact, MEW, Themida/WinLicense, VMProtect, MSVC, GCC/MinGW, Clang, Go, Rust, .NET, Delphi, NSIS, InnoSetup, and more.

### 3.5 Completeness

**COMPLETE.** No stubs found. The dual-scanner architecture is intentional (documented in `die_scanner.rs` doc-comment). Rule count in `BUILTIN_RULES` is ~25; `ExtendedRuleDb` reaches ~200. Integration with `rustre-triage`'s pipeline requires a wrapper `PipelineStage` (not present in this crate — expected to live in the MCP server layer).

---

## 4. `rustre-triage-entropy` — Shannon Entropy Analysis

### 4.1 Purpose

Computes Shannon entropy at multiple granularities (whole file, per-PE-section,
fixed-size chunks) to detect packed, encrypted, or compressed regions.
Provides visualization data structures for heatmaps and entropy profiles.

### 4.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `TriageError` (indirect, via type aliases) |
| `rustre-pe-tools` | Section table parsing |
| `rustre-crypto-id` | Crypto algorithm identification |
| `serde` / `serde-big-array` | Serialization incl. large arrays |
| `thiserror` | Typed errors |

### 4.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `shannon_entropy(data: &[u8]) -> f64` | `fn` | H = -Σ p·log₂(p), returns 0.0–8.0 |
| `EntropyError` | `enum` | `EmptyInput`, `InvalidChunk` |
| `EntropyRating` | `enum` | `VeryLow` (<1.0) / `Low` / `Medium` / `High` / `VeryHigh` (≥7.0) |
| `SectionEntropy` | `struct` | name, entropy, size, offset, rating; `is_packed()`, `is_encrypted()` |
| `EntropyResult` | `struct` | overall + per-section + per-chunk; `packed_sections()`, `max_chunk_entropy()` |
| `EntropyAnalyzer` | `struct` | chunk-based analyzer; `analyze(data)` → `EntropyResult` |

`SectionEntropy` thresholds:

```rust
pub fn is_packed(&self) -> bool  { self.entropy > 7.0 }
pub fn is_encrypted(&self) -> bool { self.entropy > 7.5 }
```

### 4.4 Internal Modules

| Module | Role |
|---|---|
| `shannon` | Core Shannon formula variants |
| `section_entropy` | PE section table parsing + `HighEntropyBlock` detection |
| `section_entropy_analyzer` | Orchestrates per-section analysis |
| `byte_histogram` | 256-bucket byte frequency histogram |
| `histogram_analysis` | Chi-squared uniformity test, mode analysis |
| `classify` | Threshold-based region classifier |
| `anomaly` | Statistical anomaly detection |
| `randomness` | NIST-style randomness indicators |
| `compression_detector` | Compression magic byte detection |
| `compression_oracle` | Heuristic compression vs encryption disambiguation |
| `packer_detector` | Entropy-profile-based packer hints |
| `packer_entropy_profile` | Per-packer entropy profiles (UPX, MPRESS, Themida) |
| `packer_identifier` | Maps profiles to packer names |
| `entropy_heuristics` | Combined heuristic rules |
| `file_entropy_report` | `FileEntropyReport` — full per-file result |
| `entropy_viz_data` | Data model for visualization |
| `entropy_visualization` | ASCII/text entropy graph |
| `entropy_visualizer` | Higher-level visualizer |
| `heatmap_data` | 2-D heatmap data structure |
| `visual_entropy_map` | Colour-mapped entropy output |
| `casts` | Safe numeric casts (`usize_to_f64`, `f64_to_f32`, etc.) |

### 4.5 Completeness

**COMPLETE.** No stubs. The module count (21) is high relative to the surface
area; many secondary modules (`entropy_visualizer`, `visual_entropy_map`,
`heatmap_data`) are data-carrying types without network or OS dependencies.
Unit tests exist in `section_entropy` and `shannon`.

---

## 5. `rustre-triage-peid` — PEiD Signature Matching

### 5.1 Purpose

Identifies known packers, compilers, protectors, and runtimes in PE binaries
using the PEiD byte-pattern signature format.  Includes a built-in database
of 300+ signatures, a userdb.txt parser for community databases, an entry-point
analyzer, and a stub network updater.

### 5.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `TriageError` |
| `rayon` | Parallel signature scanning |
| `serde` / `serde_json` | Signature and result serialization |
| `thiserror` | Typed errors |

Optional `network` feature (disabled by default): reserved for future
`reqwest`/`ureq` integration in `signature_updater`.

### 5.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `PeidError` | `enum` | `InvalidPattern`, `EmptyData` |
| `PeidCategory` | `enum` | `Packer`, `Protector`, `Compiler`, `Linker`, `Installer`, `Runtime`, `Other`, `Unknown` |
| `PeidSignature` | `struct` | name, version, `Vec<Option<u8>>` pattern, `ep_only`, category; `matches(data, offset)`, `confidence() -> f32` |
| `PeidMatch` | `struct` | signature_name, version, offset, ep_only, confidence, category |
| `ScanOptions` | `struct` | max_matches, ep_only_strict, scan_sections, min_pattern_length |
| `make_sig` / `b()` / `wc()` | `fn` | Internal helpers (fixed byte `Some(v)`, wildcard `None`) |

`PeidSignature::confidence()` formula:

```rust
let specificity = fixed_bytes as f32 / len as f32;
let length_bonus = (len as f32 / 64.0).min(1.0);
0.5f32.mul_add(specificity, 0.5 * length_bonus).min(1.0)
```

### 5.4 Internal Modules

| Module | Role |
|---|---|
| `peid_db` | `PeidDb` — 300+ built-in signatures; `scan(data, ep_offset)`, `scan_ep(data, ep_offset)` |
| `peid_signature_matcher` | Pattern matching engine |
| `userdb_parser` | Parses community `userdb.txt` files |
| `ep_analyzer` | Entry-point detection and validation |
| `linker_detector` | Linker fingerprinting from PE rich header |
| `compiler_detector` | Compiler identification (MSVC, GCC, Clang, Rust, Go, Delphi, etc.) |
| `section_analyzer` | Section name + characteristic fingerprinting |
| `overlay_extractor` | Extracts and categorizes overlay data |
| `pe_anomaly_detector` | Header anomaly detection (mismatched sizes, invalid offsets) |
| `peid_extended` | Extended result type with multi-layer hits |
| `peid_deep_scan` | Multi-pass deep scan combining all sub-analyzers |
| `signature_updater` | Network downloader (STUB, `#[cfg(feature = "network")]`) |

**Gap — network updater:**

```rust
// signature_updater.rs
/// Download raw text from a URL (requires a network-capable runtime).
/// This is a stub — in a real implementation, use reqwest or ureq.
#[cfg(feature = "network")]
// Stub: would use reqwest::blocking::get(url).
```

The `network` feature is declared in `Cargo.toml` but `reqwest`/`ureq` are not
in `[dependencies]`; the download path is never compiled in a default build.
All other modules are functional.

### 5.5 Completeness

**PARTIAL** (network updating stub).  Core scanning (built-in db + userdb.txt)
is complete. The `network` feature is a planned extension, not a regression.
Rayon parallelism is wired in `peid_db::PeidDb::scan`.

---

## 6. `rustre-triage-yara` — YARA-like Rule Engine

### 6.1 Purpose

A pure-Rust YARA-compatible rule engine: text/hex/regex string matching,
boolean conditions, metadata, tags, PE module integration, and a stack-based
bytecode VM backed by Aho-Corasick for multi-pattern acceleration.

### 6.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | Shared triage types |
| `anyhow` | Error propagation in `rule_compiler` |
| `thiserror` | Typed VM/scanner errors |
| `serde` / `serde_json` | Rule/match serialization |

No `yara-sys` / `yara` C bindings — fully native implementation.

### 6.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `YaraRule` | `struct` | Legacy rule: name + `Vec<Pattern>` (kept for compatibility) |
| `Pattern` | `enum` | `Hex(Vec<u8>)` or `Text(String)` |
| `YaraMatch` | `struct` | Legacy match: rule_name, pattern_index, offset |
| `scan_data(rules, data)` | `fn` | Non-overlapping legacy scan |
| `YaraError` | `enum` | `EmptyPattern`, `DuplicateRule`, `Other` |
| `YaraTriageRule` | `struct` | Extended rule with strings, condition_all, metadata, tags |
| `YaraTriageMatch` | `struct` | Extended match with metadata, tags, severity |
| `YaraTriageEngine` | `struct` | Manages `YaraTriageRule` set; `add_rule`, `scan` |

`scan_data` uses non-overlapping semantics (advances by `needle.len()` after
match) to prevent O(n·m) output growth on large inputs.

### 6.4 Internal Modules

| Module | Role |
|---|---|
| `yara_vm` | Stack-based bytecode VM; `YaraOpcode`, `YaraVm`, `AhoCorasick`, `CompiledRule`, `MatchContext` |
| `rule_compiler` | Tokenizer + AST + compiler: `YaraToken`, `YaraAst`, `RuleCompiler` |
| `yara_scanner` | `YaraScanner` — rayon parallel, file/buffer/memory targets, `ScanStats` |
| `yara_cache` | LRU rule cache |
| `yara_ruleset_manager` | Load/save/update rule sets |
| `yara_rule_optimizer` | Dead-string elimination, pattern deduplication |
| `rule_optimizer` | Alternative optimizer (string interning) |
| `yara_module_pe` | PE module: section table, imports, exports for condition context |
| `yara_performance_profiler` | Per-rule timing and hit-rate tracking |
| `yara_match_reporter` | Structured match report formatting |
| `match_report` | `MatchReport` aggregate type |
| `verdict` | `Verdict` enum: `Clean` / `Suspicious` / `Malicious` |
| `family_classifier` | Maps rule tags to malware family names |
| `ioc_extractor` | Extracts IPs, URLs, hashes from matches |
| `yara_threat_intel` | Threat intelligence enrichment |
| `yara_threat_tagger` | Auto-tag rules from pattern content |

The VM opcode set (`yara_vm::YaraOpcode`):

```
Literals:  PushInt, PushBool, PushFilesize, PushEntrypoint
Strings:   StringMatch, StringCount, StringAt, StringIn
Arithmetic: AddInt, SubInt, MulInt, DivInt, ModInt
Boolean:   And, Or, Not
Compare:   Eq, NEq, Lt, Le, Gt, Ge
Control:   Jump, JumpIfFalse, Halt
```

Aho-Corasick is used to accelerate multi-pattern search; `MatchContext` carries
string match tables so the VM does not re-scan for each opcode.

### 6.5 Completeness

**COMPLETE.** No stubs. The legacy `YaraRule`/`scan_data` API is preserved for
backward compatibility alongside the extended `YaraTriageEngine`. The rule
compiler supports the full YARA token set including `HexString` with wildcards,
`RegexString`, `for`/`of`/`them` operators, and all comparison tokens. The
`anyhow` dependency in `rule_compiler` (vs `thiserror` elsewhere) is the only
minor inconsistency.

---

## 7. Cross-Cutting Analysis

### 7.1 Dependency Matrix

| Crate | rustre-triage | rustre-pe-tools | rustre-crypto-id | rayon | anyhow |
|---|:---:|:---:|:---:|:---:|:---:|
| rustre-triage | — | yes | yes | — | — |
| rustre-triage-die | yes | — | — | — | — |
| rustre-triage-entropy | yes | yes | yes | — | — |
| rustre-triage-peid | yes | — | — | yes | — |
| rustre-triage-yara | yes | — | — | — | yes |

### 7.2 Completeness Summary

| Crate | Status | Stubs / Gaps |
|---|---|---|
| `rustre-triage` | **Complete** | None |
| `rustre-triage-die` | **Complete** | None; dual-scanner intentional |
| `rustre-triage-entropy` | **Complete** | None |
| `rustre-triage-peid` | **Partial** | `signature_updater` network path is a stub behind `network` feature (no HTTP dep) |
| `rustre-triage-yara` | **Complete** | None; `anyhow` inconsistency in `rule_compiler` |

### 7.3 Integration Points with MCP Server

The MCP server (`rustre-mcp-server`) consumes this group primarily through
`rustre-triage`:

- `triage_core_run_pipeline` → `TriagePipeline::default_pipeline().run(data)`
- `triage_core_extract_strings` → `AllStringExtractionStage` result in `TriageResult::all_strings`
- `triage_core_crypto_scan` → `CryptoConstantScanStage` result in `TriageResult::crypto_hits`

The sub-crates (`die`, `entropy`, `peid`, `yara`) are **not yet wired** as
`PipelineStage` implementations inside `rustre-triage`. Each has its own
scanning API but no `impl PipelineStage for ...` bridge. Wiring them would
require adapter types in either `rustre-triage` or the MCP server.

### 7.4 Known Architectural Tensions

1. **Dual DIE scanners** — `rustre-triage-die` has two `DieScanner` structs in
   separate modules with incompatible rule schemas. The `die_scanner` module
   is the canonical EP-aware implementation; `scanner` is an alternative.
   Callers must pick one explicitly.

2. **PEiD type duplication** — `PeidSignature` is defined twice: once in
   `lib.rs` (with `Vec<Option<u8>> pattern` and `ep_only`) and again in
   `peid_db.rs` (with `bytes` and `at_ep`). The `peid_db` variant is the
   production one; the `lib.rs` variant appears to be a simplified API copy.

3. **No `todo!`/`unimplemented!`** — confirmed via workspace grep; all branches
   return real values or propagate errors.

4. **Missing `PipelineStage` bridges** — to fully integrate `die`, `entropy`,
   `peid`, and `yara` into the default pipeline, each needs a thin
   `PipelineStage` wrapper. This is the main extension gap for the group.

### 7.5 IDA Pro Comparison Relevance

| IDA capability | Covered by | Status |
|---|---|---|
| Packer/compiler ID (DIE-style) | `rustre-triage-die` | Complete |
| Entropy analysis | `rustre-triage-entropy` | Complete |
| PEiD signatures | `rustre-triage-peid` | Complete (no network update) |
| YARA scanning | `rustre-triage-yara` | Complete |
| Crypto constant detection | `rustre-triage` + `rustre-crypto-id` | Complete (wired) |
| Threat scoring | `rustre-triage` | Complete |
| Family classification | `rustre-triage-yara::family_classifier` | Present |
| MITRE ATT&CK mapping | `rustre-triage::mitre_mapper` | Present |

---

# Part C — YARA Subsystem

# YARA Subsystem Analysis — `rustre-yara`, `rustre-yara-engine`, `rustre-yara-rules`

**Date:** 2026-07-02  
**Crates analyzed:** three crates, ~47 k lines of Rust total

---

## 1. Overview and Crate Hierarchy

```
rustre-yara          (foundation — AST, parser, matcher primitives)
    ↑
rustre-yara-engine   (execution layer — depends on rustre-yara + yara-x)
    ↑
rustre-yara-rules    (repository layer — depends on rustre-yara)
```

The three crates form a layered YARA stack. `rustre-yara` is the pure-Rust
foundation: AST types, hand-written recursive-descent parser, and byte-level
string matcher. `rustre-yara-engine` sits above it and provides two parallel
scan paths — a native Rust scanner and a `yara-x`-backed scanner — plus a
multi-threaded scan engine, distributed coordinator, performance profiler, PE
module, and VM. `rustre-yara-rules` is the repository manager: it ingests
`.yar` files from local/Git/HTTP sources, stores rules in an in-memory DB
keyed by `(source:name)`, compiles them, and scans binaries through its own
internal rule executor from `rule_compiler.rs`.

No `todo!` or `unimplemented!` macro calls exist anywhere in the three crates.
All modules contain substantive, compilable implementations.

---

## 2. `rustre-yara` — Foundation Crate

### 2.1 Purpose

Pure-Rust YARA-compatible rule language library. No FFI, no external libyara.
Provides the AST, parser, string-pattern matcher, and condition evaluator used
downstream. Also contains sub-parsers and alternative compiler implementations
that were kept alongside to avoid breaking callers.

### 2.2 Source Map (~15 k lines)

| Module | Lines (approx) | Role |
|---|---|---|
| `lib.rs` | 3116 | Core types + `YaraParser` (recursive-descent) + `StringMatcher` |
| `rule_parser.rs` | ~800 | Alternate parser entry (delegates to `compiler_ast`) |
| `rule_parser/compiler_ast.rs` | ~500 | Compiler-facing AST re-export |
| `condition_eval.rs` | ~600 | Condition tree evaluator |
| `yara_condition_evaluator.rs` | ~700 | Second evaluator variant (used by `yara_scanner`) |
| `rule_compiler.rs` | ~600 | Rule-to-IR compiler |
| `yara_compiler.rs` | ~700 | Second compiler variant |
| `scanner_engine.rs` | ~900 | Single-threaded scan engine |
| `yara_scanner.rs` | ~900 | Second scanner variant |
| `scan_context.rs` | ~600 | Scan state / variable bindings |
| `rule_optimizer.rs` | ~600 | Pattern optimizer (Aho-Corasick, petgraph) |
| `rule_language.rs` | ~500 | Language-level utilities |
| `match_correlator.rs` | ~600 | Correlate multi-rule matches |
| `module_elf.rs` | ~600 | ELF module types |
| `yara_module_elf.rs` | ~700 | ELF module query API |
| `yara_integration.rs` | ~500 | Integration helpers |

### 2.3 Core Public Types

```rust
pub enum YaraError { ParseError{line, message}, CompileError(String),
                     ScanError(String), UnknownIdentifier(String), TypeError(String) }

pub struct StringModifiers { encoding: StringEncodingOpts, output: StringOutputOpts,
                              xor: Option<(u8,u8)> }   // nocase/wide/ascii/fullword/private/base64/xor

pub enum HexToken { Byte(u8), Wildcard, Masked(u8,u8), Jump(u32,u32), Alternation(Vec<Vec<Self>>) }

pub enum YaraPattern { Text(String), Hex(Vec<HexToken>), Regex(String) }

pub struct YaraString { identifier: String, pattern: YaraPattern, modifiers: StringModifiers }

pub struct YaraRule { name, tags, meta, strings, condition, is_private, is_global }

pub struct YaraRuleSet { rules: Vec<YaraRule>, imports: Vec<String> }

pub enum YaraCondition { True, False, Any, All, None_, StringMatch, StringMatchAt,
                          StringMatchIn, StringCount, StringOffset, StringLength,
                          For, Not, And, Or, Comparison, Expr }

pub enum YaraExpr { Integer, Float, Bool, String, Identifier, At, FileSize,
                    Add, Sub, Mul, Div, Mod, BitAnd, BitOr, BitXor, BitNot, Shl, Shr,
                    Neg, FuncCall }
```

### 2.4 `YaraParser` — Recursive-Descent

The main `YaraParser::parse(input)` is a hand-written recursive-descent parser
implemented entirely in `lib.rs`. It handles:

- Multi-rule files, `import` directives, `private`/`global` rule modifiers
- Tags (`rule Foo : tag1 tag2 { … }`)
- `meta:`, `strings:`, `condition:` sections
- Text strings with `\"…\"` escapes, hex patterns `{…}` (including `??`, `?X`,
  `X?`, `[n-m]`, alternations `(…|…)`), regex patterns `/…/`
- All string modifiers: `nocase`, `wide`, `ascii`, `fullword`, `private`,
  `base64`, `xor`, `xor(lo-hi)`
- Conditions: `or`, `and`, `not`, comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`),
  `$str`, `$str at offset`, `$str in (lo..hi)`, `#count`, `for N of them : (…)`,
  `all of them`, `any of them`, `none of them`, arithmetic/bitwise expressions,
  `filesize`, function calls

### 2.5 `StringMatcher` — Byte-Level Matching

| Method | Description |
|---|---|
| `match_hex(pattern, data)` | Full hex pattern with Jump/Alternation (recursive) |
| `match_text(text, modifiers, data)` | Dispatches nocase/wide/ascii/fullword/xor |
| `match_nocase(text, data)` | Case-insensitive ASCII search |
| `match_wide(text, data)` | UTF-16 LE encoding then exact match |
| `match_xor(text, xor_min, xor_max, data)` | XOR-keyed search returning (offset, key) |
| `check_fullword(data, offset, len)` | Boundary check (non-alnum around match) |
| `match_masked_byte(value, mask, data_byte)` | Nibble-masked byte comparison |

Brute-force O(n·m) searches — no Aho-Corasick in this layer. The `rule_optimizer`
module does use Aho-Corasick (via the `aho-corasick` crate listed in Cargo.toml).

### 2.6 Duplicate Architecture

`rustre-yara` exhibits intentional (or evolutionary) duplication:

| Concern | Primary (lib.rs) | Secondary |
|---|---|---|
| Parser | `YaraParser` in `lib.rs` | `rule_parser.rs` / `rule_parser/compiler_ast.rs` |
| Compiler | `rule_compiler.rs` | `yara_compiler.rs` |
| Scanner | `scanner_engine.rs` | `yara_scanner.rs` |
| Condition eval | `condition_eval.rs` | `yara_condition_evaluator.rs` |

Both paths are wired into `lib.rs` as `pub mod`. The secondary variants
appear to be earlier drafts kept to avoid breaking callers; callers in the
workspace do not appear to unify on a single path.

### 2.7 Completeness

**COMPLETE** — No stubs. Every parsing branch returns a real result. All
`StringMatcher` methods are fully implemented. The rule optimizer (`petgraph` +
`aho-corasick`) and ELF module are also complete. The main gap is the
brute-force search — the optimizer exists but its integration back into the main
scan path is not verified at this reading.

---

## 3. `rustre-yara-engine` — Execution Layer

### 3.1 Purpose

High-performance multi-path YARA execution engine. Wraps both the pure-Rust
parser/evaluator from `rustre-yara` and the external `yara-x` crate (VirusTotal's
next-generation YARA implementation). Provides a multi-threaded scan engine, a
distributed job coordinator, a PE module, a performance profiler, and a VM.

### 3.2 Dependencies Notable

- `rustre-yara` (path dep)
- `yara-x` (workspace dep) — full external YARA engine; enables YARA 4.x
  feature-complete compilation and scanning via FFI-free Rust
- `parking_lot` — `RwLock<Vec<YaraRule>>` in the main `YaraScanner`
- `num-traits`, `bitflags`, `regex`

### 3.3 Source Map (~16 k lines)

| Module | Lines (approx) | Role |
|---|---|---|
| `lib.rs` | 3847 | Types + `YaraScanner` (pure-Rust) + `YaraRuleSet`/`YaraEngineScanner` (yara-x) |
| `scan_engine.rs` | ~1400 | Multi-threaded scan engine with worker pool |
| `distributed_scan.rs` | ~1600 | Distributed coordinator, job queue, result aggregation |
| `yara_vm.rs` | ~1200 | YARA bytecode VM |
| `module_pe.rs` | ~1500 | PE header parser (sections, imports, exports) |
| `condition_evaluator.rs` | ~900 | Condition tree evaluator |
| `condition_expr_eval.rs` | ~700 | Expression evaluator used by condition_evaluator |
| `string_matcher.rs` | ~600 | String matching (mirrors rustre-yara, refined) |
| `string_match_engine.rs` | ~700 | Multi-pattern match engine |
| `string_modifier_engine.rs` | ~600 | Modifier application pipeline |
| `rule_compiler.rs` | ~800 | Rule compiler for pure-Rust path |
| `rule_parser_ext.rs` | ~700 | Extended parser |
| `match_context.rs` | ~600 | Match context for scanning |
| `performance_profiler.rs` | ~700 | Per-rule timing and throughput profiler |

### 3.4 Dual Scanner Architecture

**Path A — Pure-Rust scanner (`YaraScanner`):**

```rust
pub struct YaraScanner { rules: RwLock<Vec<YaraRule>> }

impl YaraScanner {
    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch>   // dispatches text/hex/regex per string
    pub fn scan_names(&self, data: &[u8]) -> Vec<String>
}
```

Uses internal `find_all_bytes`, `find_all_nocase`, `is_fullword`, and
`match_hex_tokens` helpers. `evaluate_condition` handles: `True/False`, `All`,
`Any`, `None`, `StringMatch`, `StringCount`, `StringAt`, `StringIn`, `FileSize`,
`EntryPoint` (stub: MZ magic only), `And/Or/Not`, `ForAll`, `IntAt`.

**Path B — yara-x-backed scanner (`YaraEngineScanner`):**

```rust
pub struct YaraRuleSet { rules: Vec<YaraRuleDefinition>, compiled: Option<yara_x::Rules> }

impl YaraRuleSet {
    pub fn add_rule(&mut self, source: &str) -> Result<(), YaraError>
    pub fn add_file(&mut self, path: &Path) -> Result<u32, YaraError>
    pub fn add_directory(&mut self, dir: &Path) -> Result<u32, YaraError>
    pub fn compile(&mut self) -> Result<(), YaraError>   // calls yara_x::Compiler
}

pub struct YaraEngineScanner { rules: Arc<yara_x::Rules> }

impl YaraEngineScanner {
    pub fn new(ruleset: &mut YaraRuleSet) -> Result<Self, YaraError>
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch>
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError>
    pub fn scan_directory(&self, dir: &Path) -> Result<HashMap<PathBuf, Vec<YaraMatch>>, YaraError>
}
```

This path compiles rules through `yara_x::Compiler` and scans via
`yara_x::Scanner`, giving full YARA 4.x compatibility.

### 3.5 Multi-threaded Scan Engine (`scan_engine.rs`)

```rust
pub enum ScanTarget { File(PathBuf), Memory{data,label}, Process{pid}, Directory{root,recursive} }
pub struct ScanOptions { match_limit, timeout, workers, scan_archives, max_archive_depth, ... }
pub struct ScanJob { id, targets, options, rules, ... }
```

Implements a worker pool with atomics for match count, elapsed time, abort flag,
and per-job timeout. Supports archive recursion (ZIP/RAR/Cabinet noted in
comments). Process scanning (`ScanTarget::Process`) is wired as a target variant
but platform-specific memory-read code is not visible in the first 60 lines.

### 3.6 Distributed Scan (`distributed_scan.rs`)

Priority-queued job bus with:

```
Coordinator → JobQueue → Worker(0..N) → ResultBus → Aggregator → DeduplicatedReport
```

`Priority` enum (`Low=0`, `Normal=1`, `High=2`, `Critical=3`). Uses `Arc<Mutex<VecDeque>>`,
`AtomicBool/U32/U64` for coordination. Full deduplication of overlapping results.

### 3.7 PE Module (`module_pe.rs`)

Parses PE headers from raw bytes: DOS header, PE signature, COFF header,
optional header (PE32/PE32+), sections, imports (IAT walk), exports, resources.
Exposes `pe.*` namespace fields compatible with standard YARA PE module.
No external `goblin` or `object` crate — self-contained.

### 3.8 Condition-Level Gaps

`EntryPoint` evaluation in `lib.rs` is a known stub:
```rust
Condition::EntryPoint => {
    // Check for a simple PE/ELF magic at offset 0 (stub).
    data.len() >= 2 && (data[0] == 0x4D && data[1] == 0x5A)
}
```
This only checks for the MZ signature, not the actual PE entry point VA. The
full PE module in `module_pe.rs` provides the proper parsing; wiring it into
condition evaluation is an open gap.

Similarly, `Condition::IntAt(offset)` only checks that 4 bytes are readable at
the given offset — it does not return the integer value, which means it cannot
support the full `uint32(0) == 0x5A4D` condition form.

### 3.9 Completeness

**PARTIAL/COMPLETE** — Core scanning is complete for both pure-Rust and yara-x
paths. Worker pool, distributed coordinator, PE module, and profiler are all
substantive. Two specific condition variants (`EntryPoint`, `IntAt`) are
implemented as behaviorally simplified forms that pass structural tests but
do not reproduce full YARA semantics. No `todo!` anywhere.

---

## 4. `rustre-yara-rules` — Repository Layer

### 4.1 Purpose

YARA rule repository manager. Provides rule ingestion from multiple source
types, an in-memory indexed database, enable/disable controls, category-based
compilation, scanning, export/import, and a curated library of ~40 built-in
rules covering malware families, packers, and crypto constants. Also contains
threat-specific rule modules (APT, ransomware, packer detection).

### 4.2 Dependencies Notable

- `rustre-yara` (path dep) — used for rule parsing in `rule_compiler.rs`
- `parking_lot::RwLock` — thread-safe in-memory DB
- `sha2` — SHA-256 hashing for change detection on rule text
- No `yara-x` dependency — the repository layer uses its own self-contained
  `rule_compiler.rs` (pure Rust), not the yara-x engine

### 4.3 Source Map (~15.8 k lines)

| Module | Lines (approx) | Role |
|---|---|---|
| `lib.rs` | 3670 | Types, `RuleRepository`, `InMemoryDb`, ~40 built-in rule constants |
| `rule_compiler.rs` | ~900 | Self-contained YARA parser+executor for scan path |
| `rule_db.rs` | ~700 | DB query layer |
| `rule_repository.rs` | ~646 | Additional repository operations |
| `rule_testing.rs` | ~1192 | Rule test harness |
| `rule_validator.rs` | ~801 | Rule validation |
| `sync.rs` | ~722 | Sync scheduling and reporting |
| `rule_generator.rs` | ~600 | Rule generation utilities |
| `rule_metadata.rs` | ~500 | Metadata parsing |
| `rule_optimizer_pass.rs` | ~500 | Optimizer pass for rule sets |
| `rule_coverage_tracker.rs` | ~500 | Coverage tracking |
| `apt_detection_rules.rs` | ~700 | APT-specific YARA rules |
| `packer_detection_rules.rs` | ~700 | Packer detection rules |
| `ransomware_rules.rs` | ~700 | Ransomware family rules |
| `builtin_rules.rs` | ~500 | Built-in rule registry |
| `casts.rs` | ~100 | Safe cast helpers |

### 4.4 `RuleRepository` — Main API

```rust
pub struct RuleRepository {
    sources: Vec<RuleSource>,
    db: Arc<RwLock<InMemoryDb>>,
    compiled_rules: HashMap<String, CompiledRuleSet>,
    last_sync: HashMap<String, SystemTime>,
    builtin_loaded: bool,
}
```

| Method | Description |
|---|---|
| `new()` | Creates repo and immediately loads built-in rules |
| `add_source(RuleSource)` | Register Git/HTTP/Local source |
| `sync_source(source)` → `SyncReport` | Ingest from one source |
| `sync_all()` → `Vec<SyncReport>` | Ingest from all sources |
| `list_rules()` / `list_enabled_rules()` | Query all/enabled rules |
| `filter_rules(RuleFilter)` | Filtered query (category, severity, tags, source, name) |
| `enable(id)` / `disable(id)` | Toggle individual rules |
| `enable_category(cat)` / `disable_category(cat)` | Bulk toggle |
| `compile_enabled()` → `CompiledRuleSet` | Concatenate enabled rules |
| `compile_category(cat)` → `CompiledRuleSet` | Compile one category |
| `scan(data)` → `Vec<Match>` | Scan byte slice against enabled compiled rules |
| `scan_file(path)` → `Result<Vec<Match>>` | Scan file |
| `export_rules(ids, dest)` | Write selected rules to `.yar` file |
| `export_category(cat, dest)` | Export category to file |
| `export_all_enabled(dest)` | Export all enabled rules |
| `import_yar_file(path)` | Import and index rules from file |
| `stats()` → `RepoStats` | Count by category/severity/source |
| `delete_rule(id)` | Remove rule from DB |

### 4.5 Rule Sources

```rust
pub enum RuleSource {
    Git { url, branch, local_path, enabled },
    Http { url, refresh_secs, enabled },
    Local { path, enabled },
}
```

**Local** source: fully functional — walks directories recursively, reads
`.yar`/`.yara` files, parses via `parse_yar_text`, SHA-256 hashes each rule,
upserts into DB tracking added/updated/unchanged counts.

**Git** source: partial stub — falls back to reading `local_path` if it exists,
emitting a warning that `git pull` is not integrated. Clone is not implemented.

**HTTP** source: stub — always returns an error noting no HTTP client is linked.

```rust
fn sync_git(...) {
    report.errors.push(format!(
        "Git sync (pull) skipped — no git binary integration in this build. \
         Falling back to reading existing local_path: {}", local_path.display()
    ));
}
fn sync_http(url, report) {
    report.errors.push(format!(
        "HTTP sync for {url} skipped — no HTTP client linked in this build."
    ));
}
```

`popular_public_sources()` returns pre-configured Git sources for
yara-rules/signature-base/reversinglabs/elastic/bartblaze, but none can clone
without external integration.

### 4.6 Scan Path in `rustre-yara-rules`

The scan path **does not use** `rustre-yara-engine`'s `YaraEngineScanner`.
Instead it goes through its own `rule_compiler::RuleExecutor::from_text(text).scan(data)`:

```rust
fn simple_scan(data: &[u8], crs: &CompiledRuleSet, db: &InMemoryDb) -> Vec<Match> {
    let executor = rule_compiler::RuleExecutor::from_text(&crs.rules_text);
    let rule_matches = executor.scan(data);
    // ... map to Match with category/severity from DB
}
```

This is a third independent pure-Rust execution path (after `rustre-yara`'s
`YaraParser`+`StringMatcher` and `rustre-yara-engine`'s `YaraScanner`). The
scan result is enriched with `RuleCategory`, `Severity`, and metadata from the
DB via the `// rule_id: {id}` comment markers embedded in compiled rule text.

### 4.7 Built-in Rule Library

`lib.rs` contains ~40 inline YARA rules as `const &str` constants loaded at
startup. Coverage:

| Category | Rules included |
|---|---|
| Malware / C2 | CobaltStrike Beacon, CobaltStrike Shellcode, Emotet, TrickBot, Qakbot, IcedID, Dridex, AsyncRAT, NjRAT, AgentTesla, FormBook, Remcos, AZORult, RedLine, Raccoon, Vidar |
| Ransomware | Ryuk, LockBit, Conti, BlackCat/ALPHV |
| Loader | GuLoader |
| Packers | UPX 3.x, UPX 4.x, Themida, VMProtect 2.x, VMProtect 3.x, MPRESS, PECompact, ASPack, PESpin, Enigma Protector, nSPack, FSG, WWPack32, Morphine |
| Crypto constants | AES S-Box, AES Inverse S-Box, AES RCON, ChaCha20 SIGMA, RC4 KSA, SHA-256 K |

Additional threat-specific rules are in `apt_detection_rules.rs`,
`packer_detection_rules.rs`, and `ransomware_rules.rs`.

### 4.8 `RuleFilter`

Builder-pattern filter:

```rust
RuleFilter::new()
    .enabled_only()
    .category(RuleCategory::Ransomware)
    .severity_min(Severity::High)
```

Supports: `category`, `severity_min`, `tags`, `enabled_only`, `source`, `name_contains`.

### 4.9 Completeness

**PARTIAL** — Core functionality (Local source ingestion, built-in rules, compile,
scan, enable/disable, export/import) is complete. Git and HTTP sync are stubs.
`rule_compiler::RuleExecutor` condition evaluation is a third independent
implementation that may have feature gaps relative to the full YARA condition
language (not fully audited here). Rule validation (`rule_validator.rs`) and
testing harness (`rule_testing.rs`) are substantive (~2 k lines combined).

---

## 5. Cross-Crate Integration Gaps

| Gap | Location | Severity |
|---|---|---|
| Three independent pure-Rust scan paths, none sharing code | all three crates | Medium — maintenance burden |
| `EntryPoint` condition only checks MZ magic, not actual PE EP | `rustre-yara-engine/src/lib.rs:572` | Medium |
| `IntAt(offset)` checks readability only, not integer value | `rustre-yara-engine/src/lib.rs:601` | High — `uint32(0) == 0x5A4D` rules broken |
| Git sync not implemented (no git binary integration) | `rustre-yara-rules/src/lib.rs:490` | Medium |
| HTTP sync not implemented (no HTTP client) | `rustre-yara-rules/src/lib.rs:507` | Medium |
| `rustre-yara-rules` does not use `YaraEngineScanner` (yara-x path) | `rustre-yara-rules/src/lib.rs:1046` | Medium |
| `ScanTarget::Process` (process memory scanning) — implementation not confirmed complete | `rustre-yara-engine/src/scan_engine.rs:46` | Low–Medium |
| `rule_optimizer.rs` uses Aho-Corasick but integration into main scan loop not confirmed | `rustre-yara/src/rule_optimizer.rs` | Low |
| Duplicate condition evaluators (3 implementations) may diverge on edge cases | all three crates | Medium |

---

## 6. Dependency Summary

| Crate | Key external deps |
|---|---|
| `rustre-yara` | `aho-corasick`, `petgraph`, `regex`, `rayon`, `sha2`, `hex`, `bitflags`, `tokio`, `tracing` |
| `rustre-yara-engine` | `rustre-yara`, `yara-x`, `parking_lot`, `bitflags`, `num-traits`, `regex` |
| `rustre-yara-rules` | `rustre-yara`, `parking_lot`, `sha2` |

Notable: `rustre-yara-engine` pulls in `yara-x` (the full VirusTotal rewrite)
as a workspace dependency. This gives the engine complete YARA 4.x compatibility
via `YaraEngineScanner` but adds a heavy transitive dependency tree.

---

## 7. Completeness Summary

| Crate | Verdict | Notes |
|---|---|---|
| `rustre-yara` | **Complete** | Full parser + matcher, no stubs. Duplicate modules are wired-in redundancy, not missing code. |
| `rustre-yara-engine` | **Partial → Complete** | yara-x path is complete; pure-Rust path has 2 condition stubs (`EntryPoint`, `IntAt`). Scan engine and distributed coordinator are substantive. |
| `rustre-yara-rules` | **Partial** | Local source and built-in rules complete; Git/HTTP sync stubbed. Own scan executor is a 3rd independent implementation. |
