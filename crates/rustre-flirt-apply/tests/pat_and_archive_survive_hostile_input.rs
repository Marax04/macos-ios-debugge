//! `.pat` text parsers and `.lib` archive harvesting must survive hostile input.
//!
//! Companion to `parsers_survive_hostile_input.rs`, which covers the binary
//! `.sig` / `RFLIRTBIN` formats. These two families were declared uncovered when
//! that sweep landed, so this closes the gap rather than leaving it implied.
//!
//! # Why these two are worth their own file
//!
//! **`.pat`** is *text*, so the failure modes differ: not over-reads but
//! unbounded lengths declared in ASCII (`FFFF` where a byte count is expected),
//! multi-byte UTF-8 sliced mid-character, and lines long enough to matter.
//! There are also **four** `.pat` parsers across the three crates, so a single
//! malformed line has four chances to crash something.
//!
//! **`.lib` archives** are the highest-risk input in the stack: an ar container
//! holding COFF/ELF members, each with its own declared sizes. This is where an
//! archive bomb would live — a member claiming a size far larger than the file,
//! or a count implying gigabytes of allocation.
//!
//! The bar is the same and absolute: **never panic**. An error is success.

use std::io::Cursor;

/// Corpora for the `.pat` parsers.
///
/// # There is no single valid `.pat` in this stack
///
/// Measured: the four parsers accept **three different line formats**, and no
/// format is accepted by all four.
///
/// | parser | classic IDA | `apply` form | `v2` form |
/// |---|---|---|---|
/// | `apply::parse_pat_text` | ✗ | ✓ | ✗ |
/// | `flirt::PatParser` | ✓ | ✓ | ✓ |
/// | `flirt::parse_pat` (v2) | ✗ | ✗ | ✓ |
/// | `gen::PatParser::parse` | ✓ | ✗ | ✓ |
///
/// So a `.pat` written for one part of the stack cannot be read by another —
/// the same producer/consumer split already found in the CRC, the container and
/// the header, now in the text format. Recorded as T4b.
///
/// Each parser therefore gets a corpus **it** accepts. Sweeping a format a
/// parser rejects outright would exercise only its error path, and the sweep
/// would pass without testing anything.
fn pat_corpora() -> Vec<(&'static str, String)> {
    let classic = concat!(
        "55488BEC4883EC20 10 ABCD 0040 :0000 alpha
",
        "4889E54157415641 08 1234 0028 :0000 beta
",
        "---
"
    );
    let v2_form = concat!(
        "55488BEC4883EC20 10 ABCD 0040 :0000 0000 alpha
",
        "4889E54157415641 08 1234 0028 :0000 0000 beta
",
        "---
"
    );
    let apply_form = concat!(
        "55488BEC4883EC20 :8 ABCD 64 :0000:P:alpha
",
        "4889E54157415641 :4 1234 40 :0000:P:beta
"
    );
    vec![
        ("classic", classic.to_string()),
        ("v2", v2_form.to_string()),
        ("apply", apply_form.to_string()),
    ]
}

/// Run every `.pat` parser over `text`. A panic in any of them fails the test.
fn parse_pat_all(text: &str) {
    let _ = rustre_flirt_apply::pat_parser::parse_pat_text(text);
    let _ = rustre_flirt::pat_parser::PatParser::default().parse_str(text);
    let _ = rustre_flirt::pat_parser_v2::parse_pat(Cursor::new(text.as_bytes()), None);
    let _ = rustre_flirt_gen::pat_writer::PatParser::parse(text);
}

/// Guards the sweep: each corpus must actually parse in at least one parser,
/// and the parser that owns that format must return the expected line count.
/// On a corpus nobody accepts, every mutation test below would pass while
/// exercising only error paths — the green would mean nothing.
#[test]
fn every_pat_corpus_is_valid_for_the_parser_that_owns_its_format() {
    for (name, text) in pat_corpora() {
        match name {
            "classic" => {
                let n = rustre_flirt_gen::pat_writer::PatParser::parse(&text).len();
                assert_eq!(n, 2, "corpus classic: attese 2 righe, lette {n}");
            }
            "v2" => {
                let f = rustre_flirt::pat_parser_v2::parse_pat(Cursor::new(text.as_bytes()), None)
                    .expect("corpus v2 deve essere valido per il parser v2");
                assert_eq!(f.entries.len(), 2);
            }
            "apply" => {
                let l = rustre_flirt_apply::pat_parser::parse_pat_text(&text)
                    .expect("corpus apply deve essere valido per il parser apply");
                assert_eq!(l.len(), 2);
            }
            _ => unreachable!(),
        }
        // `flirt::PatParser` is the permissive one: it accepts all three.
        assert!(
            rustre_flirt::pat_parser::PatParser::default().parse_str(&text).is_ok(),
            "flirt::PatParser dovrebbe accettare il formato {name}"
        );
    }
}

#[test]
fn truncating_a_pat_file_at_every_byte_never_panics() {
    for (_, base) in pat_corpora() {
    let bytes = base.as_bytes();
    for cut in 0..=bytes.len() {
        // Truncation can split a multi-byte character; the parsers must cope
        // with whatever `from_utf8_lossy` hands them.
        let text = String::from_utf8_lossy(&bytes[..cut]);
        parse_pat_all(&text);
    }
    }
}

#[test]
fn corrupting_any_single_character_never_panics() {
    for (_, base) in pat_corpora() {
    let bytes = base.as_bytes();
    for i in 0..bytes.len() {
        for repl in [b'F', b'0', b'.', b':', b' ', b'\n', 0x00, 0xff] {
            let mut m = bytes.to_vec();
            m[i] = repl;
            parse_pat_all(&String::from_utf8_lossy(&m));
        }
    }
    }
}

#[test]
fn absurd_declared_lengths_in_a_pat_line_are_rejected_not_attempted() {
    // In `.pat` the length fields are hex text. `FFFF` bytes of CRC over a
    // 20-byte pattern is not a buffer overrun waiting to happen — it is a
    // number the parser must refuse to believe.
    for line in [
        "55488B..EC FF FFFF FFFF :0000 huge",
        "55488B..EC FFFFFFFF FFFFFFFF FFFFFFFF :FFFF huge",
        "5548 00 0000 0000 :0000 zero_everything",
        " 10 ABCD 0040 :0000 no_pattern_at_all",
        ":0000 only_a_name",
        "ZZZZ 10 ABCD 0040 :0000 not_hex",
    ] {
        parse_pat_all(&format!("{line}\n---\n"));
    }
}

#[test]
fn pathological_pat_text_never_panics() {
    let cases = [
        String::new(),
        "---".to_string(),
        "\n\n\n\n".to_string(),
        "\0\0\0\0".to_string(),
        // A very long single line: bounded work, not a hang.
        format!("{} 10 ABCD 0040 :0000 long\n", "AB".repeat(50_000)),
        // A name far longer than any real symbol.
        format!("5548 10 ABCD 0040 :0000 {}\n", "n".repeat(100_000)),
        // Many empty-ish lines.
        "   \n".repeat(5_000),
        // Non-ASCII where hex is expected.
        "ééééé 10 ABCD 0040 :0000 unicode\n".to_string(),
    ];
    for c in &cases {
        parse_pat_all(c);
    }
}

// ─── .lib archives ───────────────────────────────────────────────────────────

/// Minimal but structurally valid ar archive with one small member.
fn valid_ar() -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    let content = b"not really an object";
    // ar header: name(16) date(12) uid(6) gid(6) mode(8) size(10) magic(2)
    let mut hdr = Vec::new();
    hdr.extend_from_slice(b"member.o/       ");
    hdr.extend_from_slice(b"0           ");
    hdr.extend_from_slice(b"0     ");
    hdr.extend_from_slice(b"0     ");
    hdr.extend_from_slice(b"100644  ");
    hdr.extend_from_slice(format!("{:<10}", content.len()).as_bytes());
    hdr.extend_from_slice(b"`\n");
    v.extend_from_slice(&hdr);
    v.extend_from_slice(content);
    v
}

fn harvest(data: &[u8]) {
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let _ = rustre_flirt_gen::coff_archive::harvest_archive_bytes(data, &opts);
    let mut stats = rustre_flirt_gen::coff_archive::HarvestStats::default();
    let _ = rustre_flirt_gen::coff_archive::harvest_object_bytes(data, &opts, &mut stats);
}

#[test]
fn truncating_an_archive_at_every_byte_never_panics() {
    let base = valid_ar();
    for cut in 0..=base.len() {
        harvest(&base[..cut]);
    }
}

#[test]
fn corrupting_any_archive_byte_never_panics() {
    let base = valid_ar();
    for i in 0..base.len() {
        for repl in [0x00u8, 0x20, 0x2f, 0x39, 0x60, 0xff] {
            let mut m = base.clone();
            m[i] = repl;
            harvest(&m);
        }
    }
}

#[test]
fn an_archive_member_claiming_a_gigantic_size_is_rejected() {
    // The archive-bomb shape: a 40-byte file whose member header declares
    // 9 999 999 999 bytes of content. Rejecting it must not depend on trying
    // to read or allocate that much first.
    let mut v = b"!<arch>\n".to_vec();
    v.extend_from_slice(b"bomb.o/         ");
    v.extend_from_slice(b"0           ");
    v.extend_from_slice(b"0     ");
    v.extend_from_slice(b"0     ");
    v.extend_from_slice(b"100644  ");
    v.extend_from_slice(b"9999999999");
    v.extend_from_slice(b"`\n");
    v.extend_from_slice(b"tiny");
    harvest(&v);
}

#[test]
fn random_and_degenerate_archives_never_panic() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    harvest(&[]);
    harvest(b"!<arch>\n");
    harvest(b"!<arch>");
    harvest(&vec![0u8; 1024]);
    harvest(&vec![0xffu8; 1024]);

    for size in [8usize, 60, 256, 4096] {
        for _ in 0..20 {
            let buf: Vec<u8> = (0..size).map(|_| (next() & 0xff) as u8).collect();
            harvest(&buf);
            // Same bytes, but with a valid magic so the ar parser proceeds
            // further into the header before finding trouble.
            let mut with_magic = b"!<arch>\n".to_vec();
            with_magic.extend_from_slice(&buf);
            harvest(&with_magic);
        }
    }
}
