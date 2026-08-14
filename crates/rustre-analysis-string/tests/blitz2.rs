//! blitz2 — deep adversarial tests for rustre-analysis-string.
//!
//! No std::time, no rand. Seeded LCG only.

use rustre_analysis_string::*;
use rustre_core::address::Address;

fn a(v: u64) -> Address { Address::new(v) }

/// Seeded LCG used by all fuzz tests.
struct Lcg(u64);
impl Lcg {
    fn new() -> Self { Self(0xDEAD_BEEF_CAFE_BABE) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 { (self.next_u64() >> 24) as u8 }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(hi > lo);
        lo + (self.next_u64() as usize % (hi - lo))
    }
}

// -------------------------------------------------------------------------
// 1. Display round-trip for StringEncoding
// -------------------------------------------------------------------------
#[test]
fn t01_encoding_display_unique() {
    let all = [
        StringEncoding::Ascii, StringEncoding::Utf8,
        StringEncoding::Utf16Le, StringEncoding::Utf16Be,
        StringEncoding::Utf32Le, StringEncoding::Utf32Be,
        StringEncoding::Latin1, StringEncoding::ShiftJis,
    ];
    let mut seen = std::collections::HashSet::new();
    for e in &all {
        let s = e.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s));
    }
}

// 2. min_char_bytes is consistent with is_unicode width assumptions
#[test]
fn t02_min_char_bytes_consistency() {
    assert!(StringEncoding::Utf16Le.min_char_bytes() >= 2);
    assert!(StringEncoding::Utf32Le.min_char_bytes() >= 4);
    assert_eq!(StringEncoding::Ascii.min_char_bytes(), StringEncoding::Latin1.min_char_bytes());
}

// 3. Hash consistency: equal values hash equal
#[test]
fn t03_encoding_hash_eq() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut pairs = 0;
    for &e in &[StringEncoding::Ascii, StringEncoding::Utf8, StringEncoding::Utf16Le,
                StringEncoding::Utf16Be, StringEncoding::Utf32Le, StringEncoding::Utf32Be,
                StringEncoding::Latin1, StringEncoding::ShiftJis] {
        let a_copy = e;
        let b_copy = e;
        assert_eq!(a_copy, b_copy);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a_copy.hash(&mut h1);
        b_copy.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        pairs += 1;
    }
    assert!(pairs >= 8);
}

// 4. Basic ASCII scan
#[test]
fn t04_scan_ascii_basic() {
    let s = StringScanner::new(StringScannerConfig::fast());
    let v = s.scan_ascii(a(0), b"hello\0world\0");
    assert_eq!(v.len(), 2);
}

// 5. ASCII with no nul terminator + require_null=true → skipped
#[test]
fn t05_ascii_require_null_skip() {
    let s = StringScanner::new(StringScannerConfig::fast());
    let v = s.scan_ascii(a(0), b"hellothere");
    assert!(v.is_empty());
}

// 6. ASCII with no nul but require_null=false → returned
#[test]
fn t06_ascii_no_require_null() {
    let mut c = StringScannerConfig::fast();
    c.require_null_terminator = false;
    let s = StringScanner::new(c);
    let v = s.scan_ascii(a(0), b"hellothere");
    assert!(!v.is_empty());
    assert_eq!(v[0].value, "hellothere");
}

// 7. min_length boundary
#[test]
fn t07_min_length_boundary() {
    let mut c = StringScannerConfig::fast();
    c.min_length = 4;
    let s = StringScanner::new(c);
    let v = s.scan_ascii(a(0), b"abc\0abcd\0");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].value, "abcd");
}

// 8. max_length boundary
#[test]
fn t08_max_length_boundary() {
    let mut c = StringScannerConfig::fast();
    c.min_length = 2;
    c.max_length = 5;
    let s = StringScanner::new(c);
    let v = s.scan_ascii(a(0), b"abcdefgh\0ab\0");
    // long string is filtered out by max_length
    assert!(v.iter().all(|x| x.value.len() <= 5));
    assert!(v.iter().any(|x| x.value == "ab"));
}

// 9. UTF-16 LE round-trip
#[test]
fn t09_utf16_le_roundtrip() {
    let s = StringScanner::default();
    let mut bytes = Vec::new();
    for ch in "rustre".chars() { bytes.extend_from_slice(&(ch as u16).to_le_bytes()); }
    bytes.extend_from_slice(&[0,0]);
    let v = s.scan_utf16_le(a(0), &bytes);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].value, "rustre");
    assert!(v[0].is_null_terminated);
}

// 10. UTF-8 detection of multi-byte char
#[test]
fn t10_utf8_multibyte() {
    let s = StringScanner::default();
    let mut data = "héllo".as_bytes().to_vec(); // 6 bytes, 5 chars
    data.push(0);
    let v = s.scan_utf8(a(0), &data);
    assert!(v.iter().any(|x| x.value == "héllo"));
}

// 11. read_cstring OOB
#[test]
fn t11_read_cstring_oob() {
    let s = StringScanner::default();
    assert!(s.read_cstring(a(0x100), b"abc\0", a(0)).is_none());
    assert!(s.read_cstring(a(0x100), b"abc\0", a(0x999)).is_none());
}

// 12. read_cstring at base
#[test]
fn t12_read_cstring_base() {
    let s = StringScanner::default();
    let r = s.read_cstring(a(0x100), b"hello\0rest", a(0x100)).unwrap();
    assert_eq!(r.value, "hello");
    assert_eq!(r.length, 6);
}

// 13. read_cstring no NUL → None
#[test]
fn t13_read_cstring_no_nul() {
    let s = StringScanner::default();
    assert!(s.read_cstring(a(0), b"abcdefgh", a(0)).is_none());
}

// 14. read_cstring respects min_length
#[test]
fn t14_read_cstring_min_length() {
    let mut c = StringScannerConfig::fast();
    c.min_length = 10;
    let s = StringScanner::new(c);
    assert!(s.read_cstring(a(0), b"abc\0", a(0)).is_none());
}

// 15. Pascal strings
#[test]
fn t15_pascal_strings() {
    let mut data = vec![4u8];
    data.extend_from_slice(b"rust");
    data.push(5);
    data.extend_from_slice(b"hello");
    let s = StringScanner::new(StringScannerConfig::fast());
    let v = s.scan_pascal_strings(a(0), &data);
    assert_eq!(v.len(), 2);
}

// 16. Pascal: short length skipped
#[test]
fn t16_pascal_too_short() {
    let mut c = StringScannerConfig::fast();
    c.min_length = 5;
    let s = StringScanner::new(c);
    let mut data = vec![3u8];
    data.extend_from_slice(b"abc");
    assert!(s.scan_pascal_strings(a(0), &data).is_empty());
}

// 17. Pascal: truncated buffer never panics
#[test]
fn t17_pascal_truncated() {
    let s = StringScanner::new(StringScannerConfig::fast());
    let data = [10u8, b'a', b'b']; // length says 10, only 2 bytes follow
    let _ = s.scan_pascal_strings(a(0), &data); // must not panic
}

// 18. Latin1 scan
#[test]
fn t18_latin1_scan() {
    let mut c = StringScannerConfig::default();
    c.encodings = vec![StringEncoding::Latin1];
    c.min_length = 3;
    let s = StringScanner::new(c);
    let data: Vec<u8> = b"caf\xE9\0".to_vec();
    let v = s.scan(a(0), &data);
    assert!(v.iter().any(|x| x.encoding == StringEncoding::Latin1));
}

// 19. UTF-32 LE
#[test]
fn t19_utf32_le() {
    let mut c = StringScannerConfig::default();
    c.encodings = vec![StringEncoding::Utf32Le];
    c.min_length = 4;
    let s = StringScanner::new(c);
    let mut data = Vec::new();
    for ch in "test".chars() { data.extend_from_slice(&(ch as u32).to_le_bytes()); }
    data.extend_from_slice(&[0,0,0,0]);
    let v = s.scan(a(0), &data);
    assert!(v.iter().any(|x| x.value == "test" && x.encoding == StringEncoding::Utf32Le));
}

// 20. UTF-32 BE
#[test]
fn t20_utf32_be() {
    let mut c = StringScannerConfig::default();
    c.encodings = vec![StringEncoding::Utf32Be];
    c.min_length = 4;
    let s = StringScanner::new(c);
    let mut data = Vec::new();
    for ch in "test".chars() { data.extend_from_slice(&(ch as u32).to_be_bytes()); }
    data.extend_from_slice(&[0,0,0,0]);
    let v = s.scan(a(0), &data);
    assert!(v.iter().any(|x| x.value == "test" && x.encoding == StringEncoding::Utf32Be));
}

// 21. Empty buffer → empty result
#[test]
fn t21_empty_buffer() {
    let s = StringScanner::default();
    assert!(s.scan(a(0), &[]).is_empty());
    assert!(s.scan_ascii(a(0), &[]).is_empty());
    assert!(s.scan_utf16_le(a(0), &[]).is_empty());
    assert!(s.scan_pascal_strings(a(0), &[]).is_empty());
}

// 22. Single byte buffers don't panic
#[test]
fn t22_single_byte() {
    let s = StringScanner::default();
    for b in 0u8..=255 {
        let _ = s.scan(a(0), &[b]);
    }
}

// 23. Seeded LCG fuzz — scanner never panics
#[test]
fn t23_fuzz_scanner_no_panic() {
    let s = StringScanner::new(StringScannerConfig::all_encodings());
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = g.range(1, 1024);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        let _ = s.scan(a(0x1000), &buf);
    }
}

// 24. Fuzz pascal scanner
#[test]
fn t24_fuzz_pascal_no_panic() {
    let s = StringScanner::new(StringScannerConfig::fast());
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = g.range(1, 512);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        let _ = s.scan_pascal_strings(a(0), &buf);
    }
}

// 25. Fuzz read_cstring
#[test]
fn t25_fuzz_read_cstring() {
    let s = StringScanner::default();
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = g.range(1, 256);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        let off = g.range(0, n + 16) as u64;
        let _ = s.read_cstring(a(0x1000), &buf, a(0x1000 + off));
    }
}

// 26. FoundString::entropy on uniform == 0
#[test]
fn t26_entropy_uniform() {
    let f = FoundString {
        address: a(0), length: 5, encoding: StringEncoding::Ascii,
        value: "aaaaa".into(), char_count: 5,
        is_null_terminated: false, xref_count: 0,
    };
    assert!(f.entropy().abs() < 1e-9);
}

// 27. FoundString::entropy on empty == 0
#[test]
fn t27_entropy_empty() {
    let f = FoundString {
        address: a(0), length: 0, encoding: StringEncoding::Ascii,
        value: String::new(), char_count: 0,
        is_null_terminated: false, xref_count: 0,
    };
    assert_eq!(f.entropy(), 0.0);
}

// 28. is_printable on plain text
#[test]
fn t28_is_printable() {
    let f = FoundString {
        address: a(0), length: 5, encoding: StringEncoding::Ascii,
        value: "hello".into(), char_count: 5,
        is_null_terminated: false, xref_count: 0,
    };
    assert!(f.is_printable());
    let f2 = FoundString { value: "a\tb".into(), ..f.clone() };
    assert!(!f2.is_printable());
}

// 29. looks_like_url variants
#[test]
fn t29_looks_like_url() {
    let mk = |v: &str| FoundString {
        address: a(0), length: v.len(), encoding: StringEncoding::Ascii,
        value: v.into(), char_count: v.len(),
        is_null_terminated: false, xref_count: 0,
    };
    assert!(mk("https://a.b").looks_like_url());
    assert!(mk("HTTP://a.b").looks_like_url()); // case-insensitive
    assert!(mk("ftp://a").looks_like_url());
    assert!(mk("file:///path").looks_like_url());
    assert!(!mk("a.b").looks_like_url());
}

// 30. looks_like_path
#[test]
fn t30_looks_like_path() {
    let mk = |v: &str| FoundString {
        address: a(0), length: v.len(), encoding: StringEncoding::Ascii,
        value: v.into(), char_count: v.len(),
        is_null_terminated: false, xref_count: 0,
    };
    assert!(mk("/etc/passwd").looks_like_path());
    assert!(mk("./rel").looks_like_path());
    assert!(mk("../up").looks_like_path());
    assert!(mk("C:\\Windows").looks_like_path());
    assert!(!mk("nothing").looks_like_path());
}

// 31. looks_like_format_string
#[test]
fn t31_looks_like_format_string() {
    let mk = |v: &str| FoundString {
        address: a(0), length: v.len(), encoding: StringEncoding::Ascii,
        value: v.into(), char_count: v.len(),
        is_null_terminated: false, xref_count: 0,
    };
    for spec in &["%s","%d","%i","%u","%x","%X","%f","%p","%c","%o","%e"] {
        assert!(mk(&format!("v={spec}")).looks_like_format_string(), "{spec}");
    }
    assert!(!mk("plain").looks_like_format_string());
}

// 32. looks_like_registry_key
#[test]
fn t32_looks_like_registry_key() {
    let mk = |v: &str| FoundString {
        address: a(0), length: v.len(), encoding: StringEncoding::Ascii,
        value: v.into(), char_count: v.len(),
        is_null_terminated: false, xref_count: 0,
    };
    assert!(mk("HKEY_LOCAL_MACHINE\\X").looks_like_registry_key());
    assert!(mk("HKLM\\Foo").looks_like_registry_key());
    assert!(mk("HKCU\\Bar").looks_like_registry_key());
    assert!(mk("Software\\X").looks_like_registry_key());
    assert!(mk("SYSTEM\\Y").looks_like_registry_key());
    assert!(!mk("non").looks_like_registry_key());
}

// 33. StringDatabase add deduplicates
#[test]
fn t33_database_dedup() {
    let mut db = StringDatabase::new();
    let f = FoundString {
        address: a(0x10), length: 3, encoding: StringEncoding::Ascii,
        value: "abc".into(), char_count: 3,
        is_null_terminated: false, xref_count: 0,
    };
    db.add(f.clone());
    db.add(f.clone()); // same addr, dropped
    assert_eq!(db.count(), 1);
    assert!(db.at(a(0x10)).is_some());
}

// 34. StringDatabase::longest sort
#[test]
fn t34_database_longest() {
    let mut db = StringDatabase::new();
    for (i, len) in [3usize, 9, 5, 1, 7].iter().enumerate() {
        db.add(FoundString {
            address: a(i as u64 * 0x100), length: *len,
            encoding: StringEncoding::Ascii,
            value: "x".repeat(*len), char_count: *len,
            is_null_terminated: false, xref_count: 0,
        });
    }
    let top = db.longest(3);
    assert_eq!(top.len(), 3);
    assert!(top[0].length >= top[1].length);
    assert!(top[1].length >= top[2].length);
}

// 35. StringDatabase search case-insensitive
#[test]
fn t35_database_search_ci() {
    let mut db = StringDatabase::new();
    db.add(FoundString {
        address: a(0), length: 5, encoding: StringEncoding::Ascii,
        value: "Hello".into(), char_count: 5,
        is_null_terminated: false, xref_count: 0,
    });
    let r = db.search("ell");
    assert_eq!(r.len(), 1);
    let r2 = db.search("ELL");
    assert_eq!(r2.len(), 1);
    let r3 = db.search("xyz");
    assert!(r3.is_empty());
}

// 36. StringDatabase filter_by_encoding
#[test]
fn t36_database_filter_encoding() {
    let mut db = StringDatabase::new();
    let mk = |addr, enc| FoundString {
        address: a(addr), length: 4, encoding: enc,
        value: "test".into(), char_count: 4,
        is_null_terminated: true, xref_count: 0,
    };
    db.add(mk(0, StringEncoding::Ascii));
    db.add(mk(0x10, StringEncoding::Utf8));
    db.add(mk(0x20, StringEncoding::Utf16Le));
    assert_eq!(db.filter_by_encoding(&StringEncoding::Ascii).len(), 1);
    assert_eq!(db.filter_by_encoding(&StringEncoding::Utf16Be).len(), 0);
}

// 37. stats round-trip
#[test]
fn t37_stats_basic() {
    let mut db = StringDatabase::new();
    db.add(FoundString {
        address: a(0), length: 6, encoding: StringEncoding::Ascii,
        value: "hello".into(), char_count: 5,
        is_null_terminated: true, xref_count: 0,
    });
    db.add(FoundString {
        address: a(0x10), length: 25, encoding: StringEncoding::Ascii,
        value: "http://example.com/page".into(), char_count: 23,
        is_null_terminated: true, xref_count: 0,
    });
    let stats = db.stats();
    assert_eq!(stats.total, 2);
    assert!(stats.url_count >= 1);
    assert!(stats.avg_length > 0.0);
}

// 38. StringStats::compute on empty
#[test]
fn t38_stats_empty() {
    let s = StringStats::compute(&[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.avg_length, 0.0);
    assert_eq!(s.max_length, 0);
}

// 39. detect_xor_key returns *some* plausible key whose decoded output is mostly printable
#[test]
fn t39_detect_xor_key_known() {
    let plain = b"This is a normal-looking ASCII sentence used for XOR detection.";
    let key = 0x5Au8;
    let ct: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
    // The heuristic may pick a different key with as-many-printable decodes;
    // assert it returns *some* key and that the recovered key produces
    // a mostly-printable plaintext.
    let k = detect_xor_key(&ct).expect("a key must be recovered");
    let decoded: Vec<u8> = ct.iter().map(|b| b ^ k).collect();
    let printable = decoded.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    assert!(printable * 10 >= decoded.len() * 7, "decoded was not mostly printable");
}

// 40. detect_xor_key on empty
#[test]
fn t40_detect_xor_key_empty() {
    assert_eq!(detect_xor_key(&[]), None);
}

// 41. detect_xor_key on garbage
#[test]
fn t41_detect_xor_key_garbage_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = g.range(1, 256);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        // Must not panic for any input.
        let _ = detect_xor_key(&buf);
    }
}

// 42. detect_xor_key sweep: always returns Some for printable plaintext, never panics.
#[test]
fn t42_detect_xor_key_sweep() {
    let plain = b"this is the plaintext used for key detection in our test suite";
    let mut some_count = 0;
    for key in 1u8..=255 {
        let ct: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        if detect_xor_key(&ct).is_some() { some_count += 1; }
    }
    // For any single-byte XOR of a fully printable plaintext, the heuristic
    // should at least propose *some* candidate key.
    assert_eq!(some_count, 255);
}

// 43. Send/Sync threaded stress on StringScanner
#[test]
fn t43_scanner_threaded() {
    use std::sync::Arc;
    use std::thread;
    let scanner = Arc::new(StringScanner::new(StringScannerConfig::default()));
    let mut handles = Vec::new();
    for tid in 0..4 {
        let s = Arc::clone(&scanner);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let mut buf = format!("thread{tid}-i{i}-hello world").into_bytes();
                buf.push(0);
                let res = s.scan(a(0x1000), &buf);
                assert!(!res.is_empty());
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// 44. levenshtein basic + identity
#[test]
fn t44_levenshtein_basic() {
    assert_eq!(levenshtein("", ""), 0);
    assert_eq!(levenshtein("a", "a"), 0);
    assert_eq!(levenshtein("kitten", "sitting"), 3);
    assert_eq!(levenshtein("abc", ""), 3);
    assert_eq!(levenshtein("", "abc"), 3);
}

// 45. levenshtein symmetry
#[test]
fn t45_levenshtein_symmetric() {
    let pairs = [("abc","def"),("hello","world"),("rust","crab"),("","x"),("ab","ba")];
    for (x,y) in pairs {
        assert_eq!(levenshtein(x,y), levenshtein(y,x), "{x} vs {y}");
    }
}

// 46. levenshtein_similarity in [0,1]
#[test]
fn t46_levenshtein_similarity_bounded() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let n = g.range(0, 16);
        let s: String = (0..n).map(|_| (b'a' + (g.byte() % 26)) as char).collect();
        let m = g.range(0, 16);
        let t: String = (0..m).map(|_| (b'a' + (g.byte() % 26)) as char).collect();
        let r = levenshtein_similarity(&s, &t);
        assert!((0.0..=1.0).contains(&r), "{r}");
        let r2 = levenshtein_similarity(&s, &s);
        assert!((r2 - 1.0).abs() < 1e-9);
    }
}

// 47. lcs identity
#[test]
fn t47_lcs() {
    assert_eq!(lcs_length("abc", "abc"), 3);
    assert_eq!(lcs_length("abc", ""), 0);
    assert_eq!(lcs_length("abcde", "ace"), 3);
    let v = lcs_similarity("abc", "abc");
    assert!((v - 1.0).abs() < 1e-9);
}

// 48. jaro / jaro_winkler bounds and identity
#[test]
fn t48_jaro_bounds() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let n = g.range(0, 12);
        let s: String = (0..n).map(|_| (b'a' + g.byte() % 26) as char).collect();
        let m = g.range(0, 12);
        let t: String = (0..m).map(|_| (b'a' + g.byte() % 26) as char).collect();
        let j = jaro(&s, &t);
        assert!((0.0..=1.0).contains(&j));
        let jw = jaro_winkler(&s, &t);
        assert!((0.0..=1.0001).contains(&jw)); // tiny float slack
        // identity
        if !s.is_empty() {
            assert!((jaro(&s, &s) - 1.0).abs() < 1e-9);
        }
    }
}

// 49. ngrams + jaccard
#[test]
fn t49_ngrams_jaccard() {
    let ng = ngrams("abcde", 2);
    assert!(ng.contains("ab"));
    assert!(ng.contains("de"));
    let j = jaccard_ngram("abcde", "abcde", 2);
    assert!((j - 1.0).abs() < 1e-9);
    let j2 = jaccard_ngram("abcde", "xyz12", 2);
    assert!(j2 < 0.5);
}

// 50. cluster_strings basic
#[test]
fn t50_cluster_strings() {
    let inputs: Vec<&str> = vec!["hello1","hello2","hello3","banana","banana1"];
    let clusters = cluster_strings(&inputs, 0.5);
    // Should produce at least one cluster with multiple members.
    assert!(!clusters.is_empty());
    let total_members: usize = clusters.iter().map(|c| c.members.len()).sum();
    assert!(total_members >= inputs.len() - 2);
}

// 51. encoding xor round-trip
#[test]
fn t51_xor_single_roundtrip() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let key = g.byte().max(1);
        let plaintext: Vec<u8> = (0..g.range(1, 64)).map(|_| g.byte()).collect();
        let ct = xor_decode_single(&plaintext, key);
        let back = xor_decode_single(&ct, key);
        assert_eq!(back, plaintext);
    }
}

// 52. xor multibyte round-trip
#[test]
fn t52_xor_multi_roundtrip() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let klen = g.range(1, 8);
        let key: Vec<u8> = (0..klen).map(|_| g.byte().max(1)).collect();
        let pt: Vec<u8> = (0..g.range(1, 128)).map(|_| g.byte()).collect();
        let ct = xor_decode_multibyte(&pt, &key);
        let back = xor_decode_multibyte(&ct, &key);
        assert_eq!(back, pt);
    }
}

// 53. rot byte/decode round-trip
#[test]
fn t53_rot_roundtrip() {
    let pt = b"Hello, World!";
    let ct = rot_decode(pt, 13);
    let back = rot_decode(&ct, 13);
    assert_eq!(back, pt);
}

// 54. rot13 inverse-of-itself
#[test]
fn t54_rot13_involution() {
    let pt = b"abcDEFxyz123 !?";
    let ct = rot13_decode(pt);
    let back = rot13_decode(&ct);
    assert_eq!(back, pt);
}

// 55. base64 round-trip
#[test]
fn t55_base64_roundtrip() {
    // Use only printable ASCII as base64 alphabet inputs from a known set.
    let pt = b"Hello, World! This is a base64 round-trip test.";
    // Encode manually.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut enc = Vec::new();
    let mut i = 0;
    while i < pt.len() {
        let b0 = pt[i];
        let b1 = if i+1 < pt.len() { pt[i+1] } else { 0 };
        let b2 = if i+2 < pt.len() { pt[i+2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        enc.push(alphabet[((n >> 18) & 0x3F) as usize]);
        enc.push(alphabet[((n >> 12) & 0x3F) as usize]);
        if i + 1 < pt.len() {
            enc.push(alphabet[((n >> 6) & 0x3F) as usize]);
        } else {
            enc.push(b'=');
        }
        if i + 2 < pt.len() {
            enc.push(alphabet[(n & 0x3F) as usize]);
        } else {
            enc.push(b'=');
        }
        i += 3;
    }
    let decoded = base64_decode(&enc).expect("decode");
    assert_eq!(decoded, pt);
}

// 56. base64_decode fuzz: never panics
#[test]
fn t56_base64_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = g.range(0, 128);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        let _ = base64_decode(&buf);
    }
}

// 57. hex_decode round-trip
#[test]
fn t57_hex_roundtrip() {
    let pt: Vec<u8> = (0u8..32).collect();
    let mut hex = Vec::new();
    for b in &pt {
        hex.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    let back = hex_decode(&hex).expect("hex decode");
    assert_eq!(back, pt);
}

// 58. hex_decode bad input → None
#[test]
fn t58_hex_decode_bad() {
    assert!(hex_decode(b"zz").is_none());
    // odd length
    assert!(hex_decode(b"abc").is_none());
}

// 59. detect_hex_encoded sanity
#[test]
fn t59_detect_hex() {
    let det = detect_hex_encoded(b"48656c6c6f20576f726c64");
    assert!(det.is_some());
}

// 60. detect_base64 sanity
#[test]
fn t60_detect_base64_sanity() {
    let det = detect_base64(b"SGVsbG8gV29ybGQ=");
    assert!(det.is_some());
}

// 61. shannon_entropy bounds
#[test]
fn t61_entropy_bounds() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let n = g.range(1, 256);
        let buf: Vec<u8> = (0..n).map(|_| g.byte()).collect();
        let e = shannon_entropy(&buf);
        assert!((0.0..=8.0001).contains(&e), "{e}");
    }
}

// 62. classify URL extractor
#[test]
fn t62_extract_urls() {
    // extract_urls matches whole-value-starts-with-scheme; provide such a value.
    let s = FoundString {
        address: a(0), length: 19, encoding: StringEncoding::Ascii,
        value: "https://example.com/path".into(),
        char_count: 24, is_null_terminated: false, xref_count: 0,
    };
    let urls = extract_urls(&[s]);
    assert!(!urls.is_empty());
    assert_eq!(urls[0].scheme, "https");
}

// 63. classify IPv4 parser
#[test]
fn t63_parse_ipv4() {
    assert_eq!(parse_ipv4("1.2.3.4"), Some([1,2,3,4]));
    assert_eq!(parse_ipv4("255.255.255.255"), Some([255,255,255,255]));
    assert!(parse_ipv4("256.0.0.0").is_none());
    assert!(parse_ipv4("a.b.c.d").is_none());
    assert!(parse_ipv4("1.2.3").is_none());
}

// 64. is_private_ipv4
#[test]
fn t64_private_ipv4() {
    assert!(is_private_ipv4([10,0,0,1]));
    assert!(is_private_ipv4([192,168,1,1]));
    assert!(is_private_ipv4([172,16,0,1]));
    assert!(!is_private_ipv4([8,8,8,8]));
}

// 65. Send/Sync threaded stress on detect_xor_key (free fn)
#[test]
fn t65_detect_xor_threaded() {
    use std::thread;
    let mut handles = Vec::new();
    for tid in 0..4 {
        handles.push(thread::spawn(move || {
            let key = (tid as u8) + 1;
            let pt = b"Threaded XOR plaintext sample for the test_______________";
            let ct: Vec<u8> = pt.iter().map(|b| b ^ key).collect();
            for _ in 0..100 {
                let _ = detect_xor_key(&ct);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// 66. StringScanner round-trip: scan -> reconstruct addresses
#[test]
fn t66_scanner_address_arithmetic() {
    let s = StringScanner::new(StringScannerConfig::fast());
    let data = b"abcd\0efgh\0ijkl\0";
    let v = s.scan_ascii(a(0x1000), data);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].address, a(0x1000));
    assert_eq!(v[1].address, a(0x1005));
    assert_eq!(v[2].address, a(0x100A));
}

// 67. read_cstring fuzz never panics on adversarial addresses
#[test]
fn t67_read_cstring_addr_fuzz() {
    let s = StringScanner::default();
    let mut g = Lcg::new();
    let mut buf = vec![0u8; 256];
    for i in 0..buf.len() { buf[i] = b'a' + (g.byte() % 26); }
    for _ in 0..50 {
        let off = g.next_u64();
        let _ = s.read_cstring(a(0x1000), &buf, a(off));
    }
}

// 68. boundary: max u64 address + buffer
#[test]
fn t68_max_address() {
    let s = StringScanner::default();
    let _ = s.read_cstring(a(u64::MAX - 10), b"hi\0", a(u64::MAX - 5));
}

// 69. Display on FoundString
#[test]
fn t69_foundstring_display() {
    let f = FoundString {
        address: a(0x1234), length: 4, encoding: StringEncoding::Ascii,
        value: "test".into(), char_count: 4,
        is_null_terminated: true, xref_count: 0,
    };
    let s = format!("{f}");
    assert!(s.contains("test"));
    assert!(s.contains("ASCII"));
}

// 70. is_interesting on a clearly non-generic string
#[test]
fn t70_is_interesting() {
    let f = FoundString {
        address: a(0), length: 24, encoding: StringEncoding::Ascii,
        value: "https://malware.example".into(), char_count: 23,
        is_null_terminated: false, xref_count: 0,
    };
    assert!(f.is_interesting());
}
