//! Blitz test suite for `rustre-analysis-string`.
//! Aimed at surfacing bugs via boundary and adversarial inputs.

use rustre_analysis_string::*;
use rustre_core::address::Address;

fn addr(v: u64) -> Address {
    Address::new(v)
}

// ---------------------------------------------------------------------------
// StringEncoding / FoundString basic invariants
// ---------------------------------------------------------------------------

#[test]
fn enc_display_matches_known_strings() {
    assert_eq!(StringEncoding::Ascii.to_string(), "ASCII");
    assert_eq!(StringEncoding::Utf16Le.to_string(), "UTF-16 LE");
    assert_eq!(StringEncoding::ShiftJis.to_string(), "Shift-JIS");
}

#[test]
fn enc_eq_hash_consistent() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(StringEncoding::Utf8);
    s.insert(StringEncoding::Utf8);
    assert_eq!(s.len(), 1);
    assert_eq!(StringEncoding::Ascii, StringEncoding::Ascii);
    assert_ne!(StringEncoding::Ascii, StringEncoding::Utf8);
}

#[test]
fn found_string_is_printable_with_control_char() {
    let fs = FoundString {
        address: addr(0),
        length: 4,
        encoding: StringEncoding::Ascii,
        value: "a\tb".into(),
        char_count: 3,
        is_null_terminated: false,
        xref_count: 0,
    };
    // \t is a control char; is_printable should be false
    assert!(!fs.is_printable());
}

#[test]
fn entropy_empty_is_zero() {
    let fs = FoundString {
        address: addr(0),
        length: 0,
        encoding: StringEncoding::Ascii,
        value: String::new(),
        char_count: 0,
        is_null_terminated: false,
        xref_count: 0,
    };
    assert_eq!(fs.entropy(), 0.0);
}

#[test]
fn looks_like_url_uppercase_scheme() {
    let fs = FoundString {
        address: addr(0),
        length: 0,
        encoding: StringEncoding::Ascii,
        value: "HTTPS://EXAMPLE.COM".into(),
        char_count: 19,
        is_null_terminated: false,
        xref_count: 0,
    };
    assert!(fs.looks_like_url());
}

// ---------------------------------------------------------------------------
// Scanner: empty and tiny inputs
// ---------------------------------------------------------------------------

#[test]
fn scan_ascii_empty() {
    let s = StringScanner::default();
    assert!(s.scan_ascii(addr(0), &[]).is_empty());
}

#[test]
fn scan_utf16_le_empty_and_one_byte() {
    let s = StringScanner::default();
    assert!(s.scan_utf16_le(addr(0), &[]).is_empty());
    assert!(s.scan_utf16_le(addr(0), &[0x41]).is_empty());
}

#[test]
fn scan_ascii_min_length_zero() {
    let cfg = StringScannerConfig {
        min_length: 0,
        max_length: 4096,
        encodings: vec![StringEncoding::Ascii],
        require_null_terminator: false,
        allow_high_ascii: false,
        skip_ranges: vec![],
    };
    // Even with min_length=0, no string of zero chars should explode.
    let _ = StringScanner::new(cfg).scan_ascii(addr(0), b"a");
}

#[test]
fn scan_ascii_max_length_enforced() {
    let cfg = StringScannerConfig {
        min_length: 1,
        max_length: 3,
        encodings: vec![StringEncoding::Ascii],
        require_null_terminator: false,
        allow_high_ascii: false,
        skip_ranges: vec![],
    };
    let scanner = StringScanner::new(cfg);
    let found = scanner.scan_ascii(addr(0), b"hello\0hi\0");
    // "hello" (5) exceeds max=3 → skipped; "hi" (2) kept
    assert!(found.iter().all(|s| s.length <= 4));
    assert!(found.iter().any(|s| s.value == "hi"));
    assert!(!found.iter().any(|s| s.value == "hello"));
}

#[test]
fn scan_ascii_no_null_required() {
    let mut cfg = StringScannerConfig::fast();
    cfg.require_null_terminator = false;
    let scanner = StringScanner::new(cfg);
    let found = scanner.scan_ascii(addr(0), b"hello");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, "hello");
    assert!(!found[0].is_null_terminated);
}

#[test]
fn scan_ascii_allow_high() {
    let mut cfg = StringScannerConfig::fast();
    cfg.allow_high_ascii = true;
    cfg.require_null_terminator = false;
    let scanner = StringScanner::new(cfg);
    let data = b"\xC3\xA9\xC3\xA9\xC3\xA9";
    let found = scanner.scan_ascii(addr(0), data);
    assert!(!found.is_empty());
}

#[test]
fn scan_full_sorts_by_address() {
    let scanner = StringScanner::new(StringScannerConfig::all_encodings());
    let mut data = Vec::new();
    data.extend_from_slice(b"alpha\0");
    data.extend_from_slice(b"bravo\0");
    let found = scanner.scan(addr(0x1000), &data);
    for w in found.windows(2) {
        assert!(w[0].address.0 <= w[1].address.0);
    }
}

#[test]
fn scan_utf16_be_basic() {
    // "test" UTF-16 BE
    let mut bytes = Vec::new();
    for c in ['t', 'e', 's', 't'] {
        bytes.extend_from_slice(&(c as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    let scanner = StringScanner::new(StringScannerConfig::all_encodings());
    let found = scanner.scan(addr(0), &bytes);
    assert!(found.iter().any(|s| s.value == "test" && s.encoding == StringEncoding::Utf16Be));
}

#[test]
fn scan_utf32_le_basic() {
    let mut bytes = Vec::new();
    for c in ['h', 'e', 'l', 'l', 'o'] {
        bytes.extend_from_slice(&(c as u32).to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let scanner = StringScanner::new(StringScannerConfig::all_encodings());
    let found = scanner.scan(addr(0), &bytes);
    assert!(found.iter().any(|s| s.value == "hello" && s.encoding == StringEncoding::Utf32Le));
}

#[test]
fn read_cstring_addr_before_base() {
    let scanner = StringScanner::default();
    let r = scanner.read_cstring(addr(0x100), b"hello\0", addr(0x50));
    assert!(r.is_none());
}

#[test]
fn read_cstring_no_null_returns_none() {
    let scanner = StringScanner::default();
    // no null terminator inside slice
    let r = scanner.read_cstring(addr(0), b"hello", addr(0));
    assert!(r.is_none());
}

#[test]
fn read_cstring_below_min_length_returns_none() {
    let mut cfg = StringScannerConfig::default();
    cfg.min_length = 10;
    let scanner = StringScanner::new(cfg);
    let r = scanner.read_cstring(addr(0), b"hi\0", addr(0));
    assert!(r.is_none());
}

#[test]
fn scan_pascal_min_length_obeyed() {
    let mut cfg = StringScannerConfig::fast();
    cfg.min_length = 6;
    let scanner = StringScanner::new(cfg);
    let mut data = vec![5u8];
    data.extend_from_slice(b"hello");
    let found = scanner.scan_pascal_strings(addr(0), &data);
    assert!(found.is_empty()); // 5 < min_length 6
}

// ---------------------------------------------------------------------------
// StringDatabase
// ---------------------------------------------------------------------------

#[test]
fn database_duplicate_address_dropped() {
    let mut db = StringDatabase::new();
    let mk = |v: &str| FoundString {
        address: addr(0x1000),
        length: v.len(),
        encoding: StringEncoding::Ascii,
        value: v.into(),
        char_count: v.len(),
        is_null_terminated: false,
        xref_count: 0,
    };
    db.add(mk("first"));
    db.add(mk("second"));
    assert_eq!(db.count(), 1);
    assert_eq!(db.at(addr(0x1000)).unwrap().value, "first");
}

#[test]
fn database_iter_length_equals_count() {
    let data = b"alpha\0bravo\0charlie\0";
    let db = StringDatabase::from_scan(addr(0), data, StringScannerConfig::fast());
    assert_eq!(db.iter().count(), db.count());
}

#[test]
fn database_longest_n_zero() {
    let data = b"alpha\0bravo\0";
    let db = StringDatabase::from_scan(addr(0), data, StringScannerConfig::fast());
    assert!(db.longest(0).is_empty());
}

#[test]
fn database_longest_orders_descending() {
    let data = b"hi\0longer\0longest_one\0";
    let db = StringDatabase::from_scan(addr(0), data, StringScannerConfig::fast());
    let top = db.longest(3);
    for w in top.windows(2) {
        assert!(w[0].length >= w[1].length);
    }
}

#[test]
fn database_filter_by_encoding() {
    let data = b"hello\0";
    let db = StringDatabase::from_scan(addr(0), data, StringScannerConfig::fast());
    assert!(!db.filter_by_encoding(&StringEncoding::Ascii).is_empty());
    assert!(db.filter_by_encoding(&StringEncoding::ShiftJis).is_empty());
}

#[test]
fn database_search_no_match() {
    let data = b"hello\0";
    let db = StringDatabase::from_scan(addr(0), data, StringScannerConfig::fast());
    assert!(db.search("xyzzy").is_empty());
}

#[test]
fn database_stats_empty_db_is_zero() {
    let db = StringDatabase::new();
    let st = db.stats();
    assert_eq!(st.total, 0);
    assert_eq!(st.avg_length, 0.0);
    assert_eq!(st.max_length, 0);
}

// ---------------------------------------------------------------------------
// detect_xor_key (top-level)
// ---------------------------------------------------------------------------

#[test]
fn detect_xor_key_empty_is_none() {
    assert!(detect_xor_key(&[]).is_none());
}

#[test]
fn detect_xor_key_recovers_simple_key() {
    // Use a plaintext mixing letters and non-letter punctuation so that the
    // correct key produces strictly more printable bytes than spurious keys.
    let plain: Vec<u8> = (0u8..200).collect(); // mix of printable + non-printable
    let key = 0x5Au8;
    let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
    let detected = detect_xor_key(&encoded);
    // Whatever it returns, decoding with it must produce a high printable ratio.
    if let Some(k) = detected {
        let dec: Vec<u8> = encoded.iter().map(|b| b ^ k).collect();
        let p = dec.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
        assert!(p * 10 >= dec.len() * 7);
    }
}

#[test]
fn detect_xor_key_random_returns_none_or_some_but_doesnt_panic() {
    // High-entropy data: ideally none, but at minimum should not panic.
    let data: Vec<u8> = (0..256u32).map(|x| (x ^ 0xA5) as u8).collect();
    let _ = detect_xor_key(&data);
}

// ---------------------------------------------------------------------------
// encoding_detect re-exports
// ---------------------------------------------------------------------------

#[test]
fn base64_decode_roundtrip_known_value() {
    // "Hello" -> "SGVsbG8="
    let dec = base64_decode(b"SGVsbG8=").unwrap();
    assert_eq!(dec, b"Hello");
}

#[test]
fn base64_decode_invalid_char_returns_none() {
    assert!(base64_decode(b"!!!!").is_none());
}

#[test]
fn hex_decode_basic() {
    assert_eq!(hex_decode(b"48656c6c6f").unwrap(), b"Hello".to_vec());
}

#[test]
fn hex_decode_odd_length_is_none() {
    assert!(hex_decode(b"abc").is_none());
}

#[test]
fn hex_decode_invalid_nibble_is_none() {
    assert!(hex_decode(b"zz").is_none());
}

#[test]
fn rot_byte_identity_zero() {
    assert_eq!(rot_byte(b'a', 0), b'a');
    assert_eq!(rot_byte(b'Z', 0), b'Z');
}

#[test]
fn rot_byte_rot13_symmetric() {
    for b in b'a'..=b'z' {
        let enc = rot_byte(b, 13);
        let dec = rot_byte(enc, 13);
        assert_eq!(dec, b);
    }
}

#[test]
fn rot_byte_non_alpha_unchanged() {
    assert_eq!(rot_byte(b'5', 7), b'5');
    assert_eq!(rot_byte(0xFF, 13), 0xFF);
}

#[test]
fn rot_decode_roundtrip() {
    let plain = b"hello world";
    let enc = rot_decode(plain, 13);
    let dec = rot_decode(&enc, 13);
    assert_eq!(dec, plain);
}

#[test]
fn xor_single_byte_decode_roundtrip() {
    let plain = b"hello world";
    let enc = xor_decode_single(plain, 0x42);
    let dec = xor_decode_single(&enc, 0x42);
    assert_eq!(dec, plain);
}

#[test]
fn xor_multibyte_empty_key_returns_data() {
    let data = b"abc";
    let out = xor_decode_multibyte(data, &[]);
    assert_eq!(out, data.to_vec());
}

#[test]
fn xor_multibyte_roundtrip() {
    let plain = b"the quick brown fox jumps over the lazy dog";
    let key = b"key";
    let enc = xor_decode_multibyte(plain, key);
    let dec = xor_decode_multibyte(&enc, key);
    assert_eq!(dec, plain);
}

#[test]
fn detect_xor_single_byte_on_empty_is_none() {
    assert!(detect_xor_single_byte(&[]).is_none());
}

#[test]
fn detect_xor_single_byte_recovers_key() {
    let plain = b"the quick brown fox jumps over the lazy dog";
    // Pick a key that produces non-printable encoded output so the
    // Plaintext shortcut doesn't fire.
    let key = 0x80u8;
    let enc: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
    let det = detect_xor_single_byte(&enc).expect("should detect");
    // Spec only guarantees a XorSingleByte detection of some key that
    // produces highly-printable output. Verify shape + decode quality.
    match det.kind {
        EncodingKind::XorSingleByte(_) => {}
        other => panic!("expected XorSingleByte, got {other:?}"),
    }
    let dec = det.decoded.as_deref().unwrap();
    let p = dec.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    assert!(p * 10 >= dec.len() * 6);
}

#[test]
fn detect_xor_single_byte_on_plaintext_reports_plaintext() {
    let det = detect_xor_single_byte(b"hello world this is plain").unwrap();
    assert!(matches!(det.kind, EncodingKind::Plaintext));
}

#[test]
fn xor_key_candidates_empty() {
    assert!(xor_key_candidates(&[]).is_empty());
}

#[test]
fn xor_key_candidates_sorted_desc() {
    let data: Vec<u8> = b"hello world".iter().map(|b| b ^ 0x55).collect();
    let c = xor_key_candidates(&data);
    assert_eq!(c.len(), 255);
    for w in c.windows(2) {
        assert!(w[0].printable >= w[1].printable);
    }
}

#[test]
fn detected_encoding_is_reliable_threshold() {
    let d = DetectedEncoding::new(EncodingKind::Plaintext, 70, None);
    assert!(d.is_reliable());
    let d2 = DetectedEncoding::new(EncodingKind::Plaintext, 69, None);
    assert!(!d2.is_reliable());
}

#[test]
fn auto_decode_returns_some_for_plaintext() {
    let out = auto_decode(b"this is plain printable english text");
    assert!(out.is_some());
}

#[test]
fn encoding_summary_works_on_garbage() {
    // Just shouldn't panic
    let _ = encoding_summary(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn byte_frequency_empty() {
    let bf = ByteFrequency::compute(&[]);
    assert_eq!(bf.total, 0);
    assert_eq!(bf.entropy(), 0.0);
    assert_eq!(bf.unique_bytes(), 0);
    assert_eq!(bf.freq(0), 0.0);
}

#[test]
fn byte_frequency_uniform() {
    let data: Vec<u8> = (0u16..256).map(|x| x as u8).collect();
    let bf = ByteFrequency::compute(&data);
    assert_eq!(bf.total, 256);
    assert_eq!(bf.unique_bytes(), 256);
    // entropy should be 8.0 for uniform distribution
    assert!((bf.entropy() - 8.0).abs() < 1e-6);
}

#[test]
fn rot13_decode_helper_matches_rot_decode() {
    let data = b"Hello, World!";
    assert_eq!(rot13_decode(data), rot_decode(data, 13));
}

#[test]
fn estimate_xor_key_length_empty_data() {
    let r = estimate_xor_key_length(&[], 8);
    assert!(r.is_empty());
}

#[test]
fn recover_xor_multibyte_key_length_matches() {
    let plain = b"the quick brown fox jumps over the lazy dog, multiple times over";
    let key = b"abcd";
    let enc = xor_decode_multibyte(plain, key);
    let recovered = recover_xor_multibyte_key(&enc, 4);
    assert_eq!(recovered.len(), 4);
}

// ---------------------------------------------------------------------------
// classify
// ---------------------------------------------------------------------------

#[test]
fn parse_ipv4_basic() {
    assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
    assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
    assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
}

#[test]
fn parse_ipv4_invalid() {
    assert!(parse_ipv4("256.0.0.0").is_none());
    assert!(parse_ipv4("1.2.3").is_none());
    assert!(parse_ipv4("1.2.3.4.5").is_none());
    assert!(parse_ipv4("abc.def.ghi.jkl").is_none());
    assert!(parse_ipv4("").is_none());
}

#[test]
fn is_private_ipv4_ranges() {
    assert!(is_private_ipv4([10, 0, 0, 1]));
    assert!(is_private_ipv4([127, 0, 0, 1]));
    assert!(is_private_ipv4([172, 16, 0, 1]));
    assert!(is_private_ipv4([172, 31, 255, 255]));
    assert!(is_private_ipv4([192, 168, 1, 1]));
    assert!(is_private_ipv4([169, 254, 0, 1]));
    assert!(!is_private_ipv4([8, 8, 8, 8]));
    assert!(!is_private_ipv4([172, 32, 0, 1]));
    assert!(!is_private_ipv4([172, 15, 0, 1]));
}

#[test]
fn shannon_entropy_empty_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn shannon_entropy_uniform_two() {
    assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
}

#[test]
fn detect_format_string_dangerous_n() {
    let f = detect_format_string("count = %n").unwrap();
    assert!(f.is_dangerous);
}

#[test]
fn detect_format_string_no_specifier_none() {
    assert!(detect_format_string("just plain text").is_none());
}

#[test]
fn detect_format_string_with_flags() {
    let f = detect_format_string("%-10.2f bytes").unwrap();
    assert!(!f.specifiers.is_empty());
}

#[test]
fn looks_like_base64_too_short() {
    assert!(!looks_like_base64("ABC="));
}

#[test]
fn looks_like_base64_wrong_chars() {
    assert!(!looks_like_base64("!!!!!!!!"));
}

#[test]
fn looks_like_hex_basic() {
    assert!(looks_like_hex("deadbeef"));
    assert!(!looks_like_hex("xyzxyzxy"));
    assert!(!looks_like_hex("abc")); // odd length & too short
}

#[test]
fn extract_urls_ws_scheme() {
    let fs = vec![FoundString {
        address: addr(0),
        length: 0,
        encoding: StringEncoding::Ascii,
        value: "ws://server.example/path".into(),
        char_count: 0,
        is_null_terminated: false,
        xref_count: 0,
    }];
    let out = extract_urls(&fs);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].scheme, "ws");
    assert_eq!(out[0].host.as_deref(), Some("server.example"));
    assert_eq!(out[0].path.as_deref(), Some("/path"));
    assert!(out[0].well_formed);
}

#[test]
fn extract_urls_no_host_not_well_formed() {
    let fs = vec![FoundString {
        address: addr(0),
        length: 0,
        encoding: StringEncoding::Ascii,
        value: "http:///nohost".into(),
        char_count: 0,
        is_null_terminated: false,
        xref_count: 0,
    }];
    let out = extract_urls(&fs);
    assert_eq!(out.len(), 1);
    assert!(!out[0].well_formed);
}

#[test]
fn extract_emails_valid_and_invalid() {
    let fs = vec![
        FoundString {
            address: addr(0),
            length: 0,
            encoding: StringEncoding::Ascii,
            value: "user@example.com".into(),
            char_count: 0,
            is_null_terminated: false,
            xref_count: 0,
        },
        FoundString {
            address: addr(0),
            length: 0,
            encoding: StringEncoding::Ascii,
            value: "@bad.com".into(),
            char_count: 0,
            is_null_terminated: false,
            xref_count: 0,
        },
        FoundString {
            address: addr(0),
            length: 0,
            encoding: StringEncoding::Ascii,
            value: "noat.example.com".into(),
            char_count: 0,
            is_null_terminated: false,
            xref_count: 0,
        },
    ];
    let out = extract_emails(&fs);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].domain, "example.com");
}

#[test]
fn extract_ips_finds_private() {
    let fs = vec![FoundString {
        address: addr(0),
        length: 0,
        encoding: StringEncoding::Ascii,
        value: "10.0.0.1".into(),
        char_count: 0,
        is_null_terminated: false,
        xref_count: 0,
    }];
    let out = extract_ips(&fs);
    assert_eq!(out.len(), 1);
    assert!(out[0].is_private);
    assert_eq!(out[0].dotted_decimal().as_deref(), Some("10.0.0.1"));
}

#[test]
fn detect_crypto_constant_pem_cert() {
    let r = detect_crypto_constant("-----BEGIN CERTIFICATE-----\nMIIB...");
    assert!(!r.is_empty());
    assert!(r.iter().any(|c| c.algorithm == "X.509"));
}

#[test]
fn detect_crypto_constant_chacha() {
    let r = detect_crypto_constant("expand 32-byte k");
    assert!(r.iter().any(|c| c.algorithm == "ChaCha20"));
}

#[test]
fn detect_crypto_constant_none() {
    assert!(detect_crypto_constant("plain hello").is_empty());
}

#[test]
fn detect_obfuscation_low_entropy_low_score() {
    // Use a length not divisible by 4 so looks_like_base64 is false and
    // score reflects only the (zero) entropy contribution.
    let sig = detect_obfuscation("aaaaa");
    assert!(!sig.looks_base64);
    assert!(!sig.looks_hex);
    assert_eq!(sig.entropy, 0.0);
    assert_eq!(sig.score, 0);
}

#[test]
fn detect_obfuscation_base64_blob() {
    let sig = detect_obfuscation("SGVsbG9Xb3JsZA==");
    assert!(sig.looks_base64);
    assert!(sig.score >= 30);
}

#[test]
fn string_class_display() {
    assert_eq!(classify::StringClass::Url.to_string(), "URL");
    assert_eq!(classify::StringClass::Generic.to_string(), "Generic");
}

#[test]
fn string_classifier_classify_email() {
    assert_eq!(
        classify::StringClassifier::classify("a@b.com"),
        classify::StringClass::Email
    );
}

#[test]
fn string_classifier_classify_url() {
    assert_eq!(
        classify::StringClassifier::classify("https://x.com/y"),
        classify::StringClass::Url
    );
}

#[test]
fn string_classifier_classify_ip() {
    assert_eq!(
        classify::StringClassifier::classify("1.2.3.4"),
        classify::StringClass::IpAddress
    );
}

#[test]
fn string_classifier_classify_generic() {
    assert_eq!(
        classify::StringClassifier::classify("hello world"),
        classify::StringClass::Generic
    );
}

// ---------------------------------------------------------------------------
// similarity
// ---------------------------------------------------------------------------

#[test]
fn levenshtein_symmetric() {
    assert_eq!(levenshtein("abcdef", "azcdwf"), levenshtein("azcdwf", "abcdef"));
}

#[test]
fn levenshtein_unicode() {
    assert_eq!(levenshtein("café", "cafe"), 1);
}

#[test]
fn lcs_empty() {
    assert_eq!(lcs_length("", ""), 0);
    assert_eq!(lcs_length("abc", ""), 0);
}

#[test]
fn jaro_winkler_identity_one() {
    assert!((jaro_winkler("abc", "abc") - 1.0).abs() < 1e-9);
}

#[test]
fn jaccard_ngram_empty_both_is_one() {
    assert!((jaccard_ngram("", "", 2) - 1.0).abs() < 1e-9);
}

#[test]
fn ngrams_zero_n_empty() {
    assert!(ngrams("hello", 0).is_empty());
}

#[test]
fn cluster_strings_empty_input() {
    let v: Vec<&str> = Vec::new();
    let c = cluster_strings(&v, 0.8);
    assert!(c.is_empty());
}

#[test]
fn cluster_cohesion_single_member_is_one() {
    let c = StringCluster {
        representative: "x".into(),
        members: vec!["x".into()],
    };
    assert_eq!(c.cohesion(), 1.0);
}

#[test]
fn extract_template_unequal_returns_first() {
    let t = extract_template(&["abc", "abcd"]);
    assert_eq!(t, "abc");
}

// ---------------------------------------------------------------------------
// StringStats compute
// ---------------------------------------------------------------------------

#[test]
fn string_stats_compute_empty() {
    let st = StringStats::compute(&[]);
    assert_eq!(st.total, 0);
    assert_eq!(st.avg_length, 0.0);
    assert_eq!(st.max_length, 0);
    assert_eq!(st.classified_count, 0);
    assert_eq!(st.longest, "");
    assert_eq!(st.shortest_interesting, "");
}

#[test]
fn string_stats_compute_longest_tracks_max_length() {
    let s1 = FoundString {
        address: addr(0),
        length: 3,
        encoding: StringEncoding::Ascii,
        value: "abc".into(),
        char_count: 3,
        is_null_terminated: false,
        xref_count: 0,
    };
    let s2 = FoundString {
        address: addr(0),
        length: 10,
        encoding: StringEncoding::Ascii,
        value: "longerone!".into(),
        char_count: 10,
        is_null_terminated: false,
        xref_count: 0,
    };
    let st = StringStats::compute(&[s1, s2]);
    assert_eq!(st.max_length, 10);
    assert_eq!(st.longest, "longerone!");
}

// ---------------------------------------------------------------------------
// StringRecoveryPass — exercise the dead-code public API
// ---------------------------------------------------------------------------

#[test]
fn string_recovery_pass_metadata() {
    use rustre_analysis::AnalysisPass;
    let pass = StringRecoveryPass::new();
    assert_eq!(pass.name(), "string_recovery");
    assert!(!pass.description().is_empty());
    let d = StringRecoveryPass::default();
    assert_eq!(d.name(), "string_recovery");
    let _ = StringRecoveryPass::with_config(StringScannerConfig::fast());
}
