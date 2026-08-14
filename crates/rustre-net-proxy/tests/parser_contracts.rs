//! Contracts the proxy's parsers state about themselves, checked rather than trusted.
//!
//! These functions sit on untrusted input: `base64_decode` feeds JWT parsing and
//! `Authorization: Basic` credential extraction and is re-exported as an MCP
//! tool, and `glob_match` decides whether a URL matches an access-control
//! pattern. Both document universal claims — "Returns `None` on invalid input",
//! "`**` matches any run of characters including `/`" — and a universal claim is
//! a specification the author already wrote down.

use rustre_net_proxy::{base64_decode, glob_match, hex_decode, hex_encode};

// ─── base64_decode ───────────────────────────────────────────────────────────

/// Well-formed input must still decode, padded or not.
#[test]
fn valid_base64_still_decodes() {
    assert_eq!(base64_decode("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
    assert_eq!(base64_decode("TWFu").as_deref(), Some(&b"Man"[..]));
    assert_eq!(base64_decode("YQ==").as_deref(), Some(&b"a"[..]));
    assert_eq!(base64_decode("").as_deref(), Some(&b""[..]));
    // Unpadded, as JWT segments are: 2 and 3 character remainders are legal.
    assert_eq!(base64_decode("aGVsbG8").as_deref(), Some(&b"hello"[..]));
    assert_eq!(base64_decode("YQ").as_deref(), Some(&b"a"[..]));
}

/// `=` is padding, so it is only valid at the end and only once or twice.
///
/// Accepting it mid-string means two different strings decode to the same bytes,
/// which for `Authorization: Basic` parsing means a filter keyed on the encoded
/// form can be bypassed while the decoded credentials stay the same.
#[test]
fn misplaced_padding_is_rejected() {
    for bad in ["AB=CD", "=AAA", "A=AA", "aGV=sbG8=", "AAAA===", "===="] {
        assert!(
            base64_decode(bad).is_none(),
            "{bad:?} places `=` outside the trailing padding but was accepted as \
             {:?}",
            base64_decode(bad)
        );
    }
}

/// A length leaving one character over cannot encode anything.
///
/// Four base64 characters carry 24 bits — three bytes. One leftover character
/// carries six bits, too few for a byte, so no encoder can emit such a string.
#[test]
fn an_impossible_length_is_rejected() {
    for bad in ["A", "ABCDE", "ABCDEFGHI", "aGVsbG8gd28xy"] {
        let stripped = bad.trim_end_matches('=').len();
        assert_eq!(stripped % 4, 1, "test fixture {bad:?} is not a 1-char remainder");
        assert!(
            base64_decode(bad).is_none(),
            "{bad:?} has a one-character remainder but decoded to {:?}",
            base64_decode(bad)
        );
    }
}

/// Characters outside the standard alphabet are invalid.
#[test]
fn a_non_alphabet_character_is_rejected() {
    for bad in ["!!!!", "AB CD", "ab-_", "AAA\n", "√©√©√©√©"] {
        assert!(
            base64_decode(bad).is_none(),
            "{bad:?} is outside the standard base64 alphabet but was accepted"
        );
    }
}

/// Decoding never returns more bytes than the input could carry.
#[test]
fn output_length_follows_from_input_length() {
    for s in ["", "YQ", "YQ==", "TWFu", "aGVsbG8=", "aGVsbG8gd29ybGQ="] {
        if let Some(out) = base64_decode(s) {
            let chars = s.trim_end_matches('=').len();
            assert!(
                out.len() <= chars * 3 / 4,
                "{s:?} ({chars} chars) produced {} bytes, more than 3/4 of the input",
                out.len()
            );
        }
    }
}

// ─── glob_match ──────────────────────────────────────────────────────────────

/// The documented distinction between `*` and `**`.
#[test]
fn the_two_wildcards_differ_on_separators() {
    // `*` stays inside one path segment.
    assert!(glob_match("*.txt", "file.txt"));
    assert!(!glob_match("*.txt", "dir/file.txt"));

    // `**` crosses them — at any depth, which needs a backtrack point per star.
    assert!(glob_match("**/README.md", "a/b/c/README.md"));
    assert!(glob_match("src/**/*.rs", "src/foo/bar/lib.rs"));
    assert!(glob_match("src/**/*.rs", "src/a/b/c/d/e/f/g.rs"));

    // `**/` may also match no directory at all.
    assert!(glob_match("src/**/*.rs", "src/lib.rs"));
}

/// A pattern with no wildcard matches exactly one string: itself.
#[test]
fn a_literal_pattern_matches_only_itself() {
    for lit in ["hello", "a/b/c.txt", ""] {
        assert!(glob_match(lit, lit), "{lit:?} does not match itself");
        assert!(
            !glob_match(lit, &format!("{lit}x")),
            "{lit:?} matched a longer string"
        );
    }
    assert!(!glob_match("hello", "world"));
}

/// `?` stands for exactly one character — never zero, never two.
#[test]
fn a_question_mark_is_exactly_one_character() {
    assert!(glob_match("file?.txt", "file1.txt"));
    assert!(!glob_match("file?.txt", "file10.txt"));
    assert!(!glob_match("file?.txt", "file.txt"));
}

/// A bare `*` cannot match across a separator, so it cannot be used to widen an
/// access-control pattern past a path boundary.
#[test]
fn a_single_star_never_escapes_its_segment() {
    assert!(!glob_match("/api/*", "/api/v1/admin"));
    assert!(glob_match("/api/*", "/api/users"));
    assert!(!glob_match("http://host/*", "http://host/a/b"));
}

/// Matching a pathological pattern must stay fast.
///
/// The matcher recurses at every star. Without memoisation a pattern holding
/// several stars is exponential in the length of the text — and the text is an
/// attacker-supplied URL, so this is a denial-of-service bound, not a
/// micro-optimisation. Twelve stars against 400 characters would not finish in
/// any reasonable time unrolled.
#[test]
fn a_pathological_pattern_does_not_blow_up() {
    let pattern = "*a*a*a*a*a*a*a*a*a*a*a*b";
    let text = "a".repeat(400);

    let start = std::time::Instant::now();
    let matched = glob_match(pattern, &text);
    let elapsed = start.elapsed();

    assert!(!matched, "the text has no 'b', so it cannot match");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "matching took {elapsed:?} — the search is not bounded"
    );
}

// ─── hex round-trip ──────────────────────────────────────────────────────────

/// Encoding then decoding returns the original bytes, for every byte value.
#[test]
fn hex_round_trips_every_byte() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(hex_decode(&hex_encode(&all)).as_deref(), Some(&all[..]));

    for b in 0..=255u8 {
        let s = hex_encode(&[b]);
        assert_eq!(s.len(), 2, "{b:#04x} encoded to {s:?}, expected two digits");
        assert_eq!(hex_decode(&s).as_deref(), Some(&[b][..]));
    }
}

/// Hex decoding accepts either case but rejects odd lengths and non-digits.
#[test]
fn hex_decoding_rejects_what_it_documents() {
    assert_eq!(hex_decode("ff").as_deref(), Some(&[0xFFu8][..]));
    assert_eq!(hex_decode("FF").as_deref(), Some(&[0xFFu8][..]));
    assert_eq!(hex_decode("aF").as_deref(), Some(&[0xAFu8][..]));

    for bad in ["f", "fff", "gg", "0x", " f", "ff "] {
        assert!(
            hex_decode(bad).is_none(),
            "{bad:?} is not valid hex but was accepted as {:?}",
            hex_decode(bad)
        );
    }
}
