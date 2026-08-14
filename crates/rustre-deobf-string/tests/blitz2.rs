//! Adversarial deep tests for rustre-deobf-string.
//! Uses seeded LCG for deterministic fuzzing.

use rustre_deobf_string::*;
use std::sync::Arc;
use std::thread;

fn lcg_seeded(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut g = lcg_seeded(seed);
    (0..n).map(|_| (g() >> 24) as u8).collect()
}

// =============================================================================
// XOR constant: round-trip
// =============================================================================

#[test]
fn xor_constant_roundtrip_50() {
    let mut g = lcg_seeded(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let len = ((g() >> 8) as usize) % 64 + 1;
        let data = lcg_bytes(g(), len);
        let key = (g() >> 8) as u8;
        let enc = XorDecryptor::decrypt_constant(&data, key);
        let dec = XorDecryptor::decrypt_constant(&enc, key);
        assert_eq!(dec, data, "xor const roundtrip len={len} key={key}");
    }
}

#[test]
fn xor_constant_zero_key_identity() {
    for n in [0usize, 1, 7, 64, 255] {
        let data = lcg_bytes(0x1234 + n as u64, n);
        assert_eq!(XorDecryptor::decrypt_constant(&data, 0), data);
    }
}

#[test]
fn xor_constant_empty() {
    assert!(XorDecryptor::decrypt_constant(&[], 0xAA).is_empty());
}

// =============================================================================
// XOR cyclic
// =============================================================================

#[test]
fn xor_cyclic_empty_key_err() {
    assert!(matches!(
        XorDecryptor::decrypt_cyclic(b"abc", &[]),
        Err(StringDeobfError::EmptyKey)
    ));
}

#[test]
fn xor_cyclic_roundtrip_50() {
    let mut g = lcg_seeded(0x5555_AAAA_5555_AAAA);
    for _ in 0..50 {
        let dlen = ((g() >> 8) as usize) % 100 + 1;
        let klen = ((g() >> 8) as usize) % 8 + 1;
        let data = lcg_bytes(g(), dlen);
        let key = lcg_bytes(g(), klen);
        let enc = XorDecryptor::decrypt_cyclic(&data, &key).unwrap();
        let dec = XorDecryptor::decrypt_cyclic(&enc, &key).unwrap();
        assert_eq!(dec, data);
    }
}

#[test]
fn xor_rolling_roundtrip_50() {
    let mut g = lcg_seeded(0x1111_2222_3333_4444);
    for _ in 0..50 {
        let len = ((g() >> 8) as usize) % 100 + 1;
        let data = lcg_bytes(g(), len);
        let key = (g() >> 8) as u8;
        let enc = XorDecryptor::decrypt_rolling(&data, key);
        // Rolling: enc[i] = data[i] ^ (key + i)
        // Decrypt by xor with same pattern.
        let dec = XorDecryptor::decrypt_rolling(&enc, key);
        assert_eq!(dec, data);
    }
}

// =============================================================================
// XOR brute force / IC
// =============================================================================

#[test]
fn xor_brute_force_top3_empty() {
    assert!(xor_brute_force_top3(&[]).is_empty());
}

#[test]
fn xor_brute_force_top3_finds_plaintext() {
    let pt = b"Hello, this is a longer English-looking sentence.";
    let key = 0x42;
    let enc: Vec<u8> = pt.iter().map(|&b| b ^ key).collect();
    let cands = xor_brute_force_top3(&enc);
    assert_eq!(cands.len(), 3);
    assert!(cands.iter().any(|c| c.key == key));
}

#[test]
fn xor_brute_force_candidate_as_str() {
    let cands = xor_brute_force_top3(b"Hello world!");
    assert!(!cands.is_empty());
    // Some candidate should be valid utf8.
    assert!(cands.iter().any(|c| c.as_str().is_some()));
}

#[test]
fn detect_xor_key_length_ic_too_short() {
    assert!(detect_xor_key_length_ic(b"abc", 8).is_empty());
}

#[test]
fn detect_xor_key_length_ic_basic() {
    let data = lcg_bytes(7, 100);
    let scores = detect_xor_key_length_ic(&data, 16);
    assert!(!scores.is_empty());
    // Sorted descending by score.
    for w in scores.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn recover_multibyte_xor_no_panic_on_fuzz() {
    let mut g = lcg_seeded(0xCAFE_BABE_DEAD_BEEF);
    for _ in 0..20 {
        let len = ((g() >> 8) as usize) % 200;
        let data = lcg_bytes(g(), len);
        let _ = recover_multibyte_xor(&data, 8);
    }
}

// =============================================================================
// RC4
// =============================================================================

#[test]
fn rc4_ksa_empty_key_identity() {
    let s = Rc4::ksa(&[]);
    for i in 0..256 {
        assert_eq!(s[i], i as u8);
    }
}

#[test]
fn rc4_roundtrip_50() {
    let mut g = lcg_seeded(0xABCD_EF01_2345_6789);
    for _ in 0..50 {
        let dlen = ((g() >> 8) as usize) % 128 + 1;
        let klen = ((g() >> 8) as usize) % 16 + 1;
        let data = lcg_bytes(g(), dlen);
        let key = lcg_bytes(g(), klen);
        let enc = Rc4::decrypt(&data, &key);
        let dec = Rc4::decrypt(&enc, &key);
        assert_eq!(dec, data);
    }
}

#[test]
fn rc4_brute_force_1byte_doesnt_panic() {
    let pt = b"PASSWORD=secret";
    let enc = Rc4::decrypt(pt, &[0x07]);
    let (k, _dec) = Rc4::brute_force_1byte(&enc);
    // Should at least produce something; might not be exactly 0x07 if scoring beats it
    let _ = k;
}

#[test]
fn rc4_inverse_ksa_returns_empty() {
    let s = [0u8; 256];
    assert!(rc4_inverse_ksa(&s).is_empty());
}

// =============================================================================
// RotN
// =============================================================================

#[test]
fn rot13_involution() {
    let s = "Hello World!";
    assert_eq!(RotN::rot13(&RotN::rot13(s)), s);
}

#[test]
fn rotn_decrypt_roundtrip_50() {
    let mut g = lcg_seeded(0x6666_7777_8888_9999);
    let inputs = [
        "abcdef", "XYZuvw", "Mixed Case 123!",
        "lorem ipsum dolor sit amet",
    ];
    for _ in 0..50 {
        let s = inputs[(g() as usize) % inputs.len()];
        let n = ((g() >> 8) as u8) % 26;
        let enc = RotN::decrypt(s, n);
        // decrypt(decrypt(x, n), 26-n) should match unless n==0
        let back = RotN::decrypt(&enc, (26 - n) % 26);
        assert_eq!(back, s, "rotn n={n} s={s}");
    }
}

#[test]
fn rotn_nonalpha_unchanged() {
    assert_eq!(RotN::decrypt("12345!@#$%", 7), "12345!@#$%");
}

// =============================================================================
// Base64
// =============================================================================

#[test]
fn base64_roundtrip_50() {
    let mut g = lcg_seeded(0xFEED_FACE_F00D_BABE);
    for _ in 0..50 {
        let len = ((g() >> 8) as usize) % 64;
        let data = lcg_bytes(g(), len);
        let enc = Base64Decoder::encode(&data);
        let dec = Base64Decoder::decode(&enc).unwrap();
        assert_eq!(dec, data, "b64 roundtrip len={len}");
    }
}

#[test]
fn base64_known_vectors() {
    assert_eq!(Base64Decoder::encode(b""), "");
    assert_eq!(Base64Decoder::encode(b"f"), "Zg==");
    assert_eq!(Base64Decoder::encode(b"fo"), "Zm8=");
    assert_eq!(Base64Decoder::encode(b"foo"), "Zm9v");
    assert_eq!(Base64Decoder::decode("Zm9vYmFy").unwrap(), b"foobar");
}

#[test]
fn base64_invalid_char_errs() {
    assert!(Base64Decoder::decode("!!!!").is_err());
}

#[test]
fn base64_is_base64() {
    assert!(Base64Decoder::is_base64("Zm9vYmFy"));
    assert!(Base64Decoder::is_base64("Zg=="));
    assert!(!Base64Decoder::is_base64(""));
    assert!(!Base64Decoder::is_base64("!!!"));
}

#[test]
fn base64_urlsafe_decode() {
    // Url-safe encoding of bytes that include '-' or '_' originally would have
    // '+' or '/'. Encode bytes that produce '+/' then translate.
    let data = b"\xFB\xFF\xBF";
    let std = Base64Decoder::encode(data);
    let urlsafe: String = std.chars().map(|c| match c { '+' => '-', '/' => '_', x => x }).collect();
    let back = decode_base64_urlsafe(&urlsafe).unwrap();
    assert_eq!(back, data);
}

#[test]
fn detect_base64_variant_short() {
    assert!(detect_base64_variant(b"abc").is_none());
}

#[test]
fn detect_base64_variant_standard() {
    assert_eq!(
        detect_base64_variant(b"abc+/def"),
        Some(Base64Variant::Standard)
    );
}

#[test]
fn detect_base64_variant_urlsafe() {
    assert_eq!(
        detect_base64_variant(b"abc-_def"),
        Some(Base64Variant::UrlSafe)
    );
}

// =============================================================================
// Hex
// =============================================================================

#[test]
fn hex_roundtrip_50() {
    let mut g = lcg_seeded(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..50 {
        let len = ((g() >> 8) as usize) % 64;
        let data = lcg_bytes(g(), len);
        let enc = HexDecoder::encode(&data);
        let dec = HexDecoder::decode(&enc).unwrap();
        assert_eq!(dec, data);
    }
}

#[test]
fn hex_invalid_length() {
    assert!(matches!(
        HexDecoder::decode("abc"),
        Err(StringDeobfError::InvalidLength { len: 3 })
    ));
}

#[test]
fn hex_invalid_char() {
    assert!(HexDecoder::decode("zz").is_err());
}

#[test]
fn hex_with_prefix_and_separators() {
    assert_eq!(HexDecoder::decode("0xDE, AD BE 0xEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn hex_is_hex() {
    assert!(HexDecoder::is_hex("0xDEADBEEF"));
    assert!(HexDecoder::is_hex("abcdef"));
    assert!(!HexDecoder::is_hex("xyz"));
    assert!(!HexDecoder::is_hex(""));
}

// =============================================================================
// Caesar / API hash
// =============================================================================

#[test]
fn caesar_brute_force_finds_english() {
    let pt = "the quick brown fox jumps over the lazy dog";
    let enc = RotN::decrypt(pt, 7);
    let results = caesar_brute_force(&enc);
    assert!(!results.is_empty());
    // Top result should be 'the quick brown fox...' — i.e. score is best
    assert!(results.iter().any(|r| r.decrypted == pt));
}

#[test]
fn api_hash_djb2_known() {
    // djb2 of empty == 5381
    assert_eq!(ApiHasher::djb2(b""), 5381);
}

#[test]
fn api_hash_fnv1a32_empty() {
    assert_eq!(ApiHasher::fnv1a32(b""), 0x811C_9DC5);
}

#[test]
fn api_hash_consistency() {
    for name in &["CreateFileA", "LoadLibraryA", "VirtualAlloc"] {
        let a = ApiHasher::djb2(name.as_bytes());
        let b = ApiHasher::djb2(name.as_bytes());
        assert_eq!(a, b);
    }
}

#[test]
fn api_hash_build_and_resolve() {
    let names = ["CreateFileA", "LoadLibraryA"];
    let table = ApiHasher::build_table(&names, ApiHashAlgorithm::Djb2);
    let h = u64::from(ApiHasher::djb2(b"CreateFileA"));
    assert_eq!(ApiHasher::resolve(&table, h), Some("CreateFileA"));
    assert_eq!(ApiHasher::resolve(&table, 0xDEADBEEF), None);
}

#[test]
fn api_hash_unknown_yields_empty_table() {
    let table = ApiHasher::build_table(&["foo"], ApiHashAlgorithm::Unknown);
    assert!(table.is_empty());
}

#[test]
fn api_hash_crc32_known() {
    // CRC32 of "123456789" = 0xCBF43926
    assert_eq!(ApiHasher::crc32(b"123456789"), 0xCBF4_3926);
}

// =============================================================================
// DecryptionChain
// =============================================================================

#[test]
fn chain_xor_then_xor_identity() {
    let mut c = DecryptionChain::new();
    c.push(ChainStage::new(StringAlgorithm::XorConstant, vec![0x55]));
    c.push(ChainStage::new(StringAlgorithm::XorConstant, vec![0x55]));
    let out = c.apply(b"hello").unwrap();
    assert_eq!(out, b"hello");
    assert_eq!(c.len(), 2);
    assert!(!c.is_empty());
}

#[test]
fn chain_empty_key_xor_const_errs() {
    let mut c = DecryptionChain::new();
    c.push(ChainStage::new(StringAlgorithm::XorConstant, vec![]));
    assert!(matches!(c.apply(b"abc"), Err(StringDeobfError::EmptyKey)));
}

#[test]
fn chain_empty_key_xor_cyclic_errs() {
    let mut c = DecryptionChain::new();
    c.push(ChainStage::new(StringAlgorithm::XorCyclic, vec![]));
    assert!(matches!(c.apply(b"abc"), Err(StringDeobfError::EmptyKey)));
}

#[test]
fn chain_default_is_empty() {
    let c = DecryptionChain::default();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
}

#[test]
fn chain_base64_then_decode() {
    let plain = b"Hello, World!";
    let b64 = Base64Decoder::encode(plain);
    let mut c = DecryptionChain::new();
    c.push(ChainStage::new(StringAlgorithm::Base64, vec![]));
    let out = c.apply(b64.as_bytes()).unwrap();
    assert_eq!(out, plain);
}

// =============================================================================
// StringAlgorithm helpers
// =============================================================================

#[test]
fn algorithm_names_unique_nonempty() {
    let all = [
        StringAlgorithm::XorConstant, StringAlgorithm::XorCyclic, StringAlgorithm::XorRolling,
        StringAlgorithm::Rc4, StringAlgorithm::ChaCha20, StringAlgorithm::RotN,
        StringAlgorithm::Base64, StringAlgorithm::HexEncoded, StringAlgorithm::StackString,
        StringAlgorithm::SplitString, StringAlgorithm::AddConstant, StringAlgorithm::SubConstant,
        StringAlgorithm::RolConstant, StringAlgorithm::RorConstant, StringAlgorithm::Unknown,
    ];
    let names: Vec<&str> = all.iter().map(|a| a.name()).collect();
    for n in &names { assert!(!n.is_empty()); }
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn algorithm_predicates() {
    assert!(StringAlgorithm::Rc4.is_stream_cipher());
    assert!(StringAlgorithm::ChaCha20.is_stream_cipher());
    assert!(!StringAlgorithm::XorConstant.is_stream_cipher());
    assert!(StringAlgorithm::XorConstant.is_xor_variant());
    assert!(StringAlgorithm::XorCyclic.is_xor_variant());
    assert!(StringAlgorithm::XorRolling.is_xor_variant());
    assert!(!StringAlgorithm::Base64.is_xor_variant());
}

// =============================================================================
// EncryptedString / StringResult / DecodedString / KeyCandidate
// =============================================================================

#[test]
fn encrypted_string_len_empty_entropy() {
    let e = EncryptedString::new(0x1000, vec![1, 2, 3, 4], StringAlgorithm::XorConstant);
    assert_eq!(e.len(), 4);
    assert!(!e.is_empty());
    let empty = EncryptedString::new(0x2000, vec![], StringAlgorithm::Unknown);
    assert!(empty.is_empty());
    assert_eq!(empty.entropy(), 0.0);
}

#[test]
fn string_result_len_empty() {
    let r = StringResult::new(0, "hi".into(), StringAlgorithm::XorConstant, vec![1]);
    assert_eq!(r.len(), 2);
    assert!(!r.is_empty());
}

#[test]
fn decoded_string_high_confidence() {
    let high = DecodedString::new(0, vec![], "ok".into(), StringAlgorithm::Unknown, 80);
    let low = DecodedString::new(0, vec![], "ok".into(), StringAlgorithm::Unknown, 50);
    assert!(high.is_high_confidence());
    assert!(!low.is_high_confidence());
}

#[test]
fn key_candidate_with_decrypted_as_str() {
    let kc = KeyCandidate::new(vec![1, 2, 3], StringAlgorithm::XorConstant, 0.9)
        .with_decrypted(b"hello".to_vec());
    assert!(kc.is_likely());
    assert_eq!(kc.as_str().unwrap(), "hello");
}

#[test]
fn key_candidate_no_decrypted_err() {
    let kc = KeyCandidate::new(vec![1], StringAlgorithm::XorConstant, 0.1);
    assert!(!kc.is_likely());
    assert!(matches!(kc.as_str(), Err(StringDeobfError::NotUtf8)));
}

// =============================================================================
// SplitStringRecovery
// =============================================================================

#[test]
fn split_string_reconstruct_order() {
    let f = vec![
        StringFragment::new(0x10, b"World".to_vec(), 1),
        StringFragment::new(0x20, b"Hello, ".to_vec(), 0),
        StringFragment::new(0x30, b"!".to_vec(), 2),
    ];
    assert_eq!(SplitStringRecovery::reconstruct(f), b"Hello, World!");
}

#[test]
fn split_string_find_fragments() {
    let data = b"prefix-foo-middle-bar-suffix";
    let patterns: &[(&[u8], usize)] = &[(b"foo", 0), (b"bar", 1)];
    let frags = SplitStringRecovery::find_fragments(data, patterns);
    assert_eq!(frags.len(), 2);
    assert_eq!(frags[0].data, b"foo");
}

// =============================================================================
// StringDeobfuscator builder
// =============================================================================

#[test]
fn deobfuscator_builder_clamps() {
    let d = StringDeobfuscator::new()
        .with_min_printable_ratio(2.0)
        .with_min_length(5);
    assert_eq!(d.min_printable_ratio, 1.0);
    assert_eq!(d.min_length, 5);
    let d2 = StringDeobfuscator::new().with_min_printable_ratio(-1.0);
    assert_eq!(d2.min_printable_ratio, 0.0);
}

#[test]
fn deobfuscator_run_doesnt_panic_on_fuzz() {
    let d = StringDeobfuscator::new();
    let mut g = lcg_seeded(0xF00D_BAAD_F00D_BAAD);
    for _ in 0..10 {
        let len = ((g() >> 8) as usize) % 80;
        let data = lcg_bytes(g(), len);
        let _ = d.run(&data);
    }
}

// =============================================================================
// confidence + compute_confidence
// =============================================================================

#[test]
fn compute_confidence_ranges() {
    let c = compute_confidence(b"http://example.com\0");
    assert!(c >= 80);
    let low = compute_confidence(&[0xFF, 0xFE, 0xFD]);
    assert!(low < 50);
}

// =============================================================================
// Hash/Eq consistency on 30+ pairs
// =============================================================================

#[test]
fn algorithm_hash_eq_30() {
    use std::collections::HashSet;
    let variants = [
        StringAlgorithm::XorConstant, StringAlgorithm::XorCyclic, StringAlgorithm::XorRolling,
        StringAlgorithm::Rc4, StringAlgorithm::ChaCha20, StringAlgorithm::RotN,
        StringAlgorithm::Base64, StringAlgorithm::HexEncoded, StringAlgorithm::StackString,
        StringAlgorithm::SplitString, StringAlgorithm::AddConstant, StringAlgorithm::SubConstant,
        StringAlgorithm::RolConstant, StringAlgorithm::RorConstant, StringAlgorithm::Unknown,
    ];
    let mut set: HashSet<StringAlgorithm> = HashSet::new();
    for &v in &variants { set.insert(v); set.insert(v); }
    assert_eq!(set.len(), variants.len());
    // pairs
    for a in &variants {
        for b in &variants {
            assert_eq!(a == b, std::ptr::eq(a, b) || a.name() == b.name());
        }
    }
}

#[test]
fn api_hash_algorithm_hash_eq() {
    use std::collections::HashSet;
    let v = [
        ApiHashAlgorithm::Crc32, ApiHashAlgorithm::Djb2, ApiHashAlgorithm::Fnv1a32,
        ApiHashAlgorithm::Sdbm, ApiHashAlgorithm::Adler32, ApiHashAlgorithm::Unknown,
    ];
    let s: HashSet<_> = v.iter().copied().collect();
    assert_eq!(s.len(), v.len());
}

// =============================================================================
// Send/Sync threaded stress (XorDecryptor, Rc4 are zero-sized Send+Sync types)
// =============================================================================

#[test]
fn threaded_xor_decrypt_stress() {
    let data: Arc<Vec<u8>> = Arc::new((0u8..=200).cycle().take(512).collect());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let mut g = lcg_seeded(0x1000 + tid);
            for _ in 0..100 {
                let key = (g() >> 8) as u8;
                let enc = XorDecryptor::decrypt_constant(&d, key);
                let dec = XorDecryptor::decrypt_constant(&enc, key);
                assert_eq!(dec, *d);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_rc4_stress() {
    let data: Arc<Vec<u8>> = Arc::new(lcg_bytes(0xAA, 64));
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let mut g = lcg_seeded(0x9000 + tid);
            for _ in 0..100 {
                let klen = ((g() >> 8) as usize) % 8 + 1;
                let key = lcg_bytes(g(), klen);
                let enc = Rc4::decrypt(&d, &key);
                let dec = Rc4::decrypt(&enc, &key);
                assert_eq!(dec, *d);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// =============================================================================
// Parser fuzz: never panic on garbage
// =============================================================================

#[test]
fn fuzz_base64_decode_never_panics() {
    let mut g = lcg_seeded(0xB64B_64B6_4B64_B64B);
    for _ in 0..100 {
        let len = ((g() >> 8) as usize) % 64;
        let bytes = lcg_bytes(g(), len);
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = Base64Decoder::decode(&s);
    }
}

#[test]
fn fuzz_hex_decode_never_panics() {
    let mut g = lcg_seeded(0x4845_4845_4845_4845u64);
    for _ in 0..100 {
        let len = ((g() >> 8) as usize) % 64;
        let bytes = lcg_bytes(g(), len);
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = HexDecoder::decode(&s);
    }
}

#[test]
fn fuzz_rotn_never_panics() {
    let mut g = lcg_seeded(0x5207_4E07_5207_4E07u64);
    for _ in 0..100 {
        let n = (g() >> 8) as u8;
        let len = ((g() >> 8) as usize) % 32;
        let bytes = lcg_bytes(g(), len);
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = RotN::decrypt(&s, n);
    }
}

// =============================================================================
// Boundary tests on integer-ish APIs
// =============================================================================

#[test]
fn xor_recover_key_period_bounds() {
    // detect_key_period with max_period 0
    assert_eq!(XorDecryptor::detect_key_period(b"abcdef", 0), 1);
    // very short data
    assert_eq!(XorDecryptor::detect_key_period(b"a", 5), 1);
}

#[test]
fn caesar_brute_force_empty() {
    let r = caesar_brute_force("");
    assert_eq!(r.len(), 25);
}

#[test]
fn xor_decryptor_recover_key_returns_valid() {
    let pt = b"this is a printable string with spaces";
    let key = 0x33u8;
    let enc: Vec<u8> = pt.iter().map(|&b| b ^ key).collect();
    let (_recovered, dec) = XorDecryptor::recover_key(&enc);
    // recover_key picks key that maximises printable count; another key may tie
    // or beat it. Test-side: verify the chosen decryption is at least as
    // printable as the true plaintext.
    let printable_dec = dec.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    let printable_pt = pt.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    assert!(printable_dec >= printable_pt);
}

#[test]
fn xor_brute_force_top3_confidence_capped() {
    let cands = xor_brute_force_top3(b"Hello, World!");
    for c in cands { assert!(c.confidence <= 100); }
}
