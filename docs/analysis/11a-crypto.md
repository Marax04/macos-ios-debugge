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
