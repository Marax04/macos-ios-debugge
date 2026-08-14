//! Why do the two IDA-format `.pat` parsers reject an IDA-format line? (T4)
//!
//! `apply::pat_parser` implements a bespoke dialect (leading `:`, decimal
//! `crc_len`), so its rejection is expected. `flirt::pat_parser_v2` and
//! `flirt::SimpleFlirtDatabase::parse_pat_text` claim the classic IDA format —
//! the one both writers emit — and reject it anyway. This prints the actual
//! error per line, so the cause is read rather than guessed.

fn main() {
    // Exactly what `gen::pat_file_writer` emits, plus real-world variants to
    // locate the boundary: a shorter pattern, and IDA's `:0000` name prefix.
    let lines = [
        ("writer, esatto", "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 exact_fn"),
        ("writer, wildcard", "404142........4748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 wildcard_fn"),
        ("writer, con CRC", "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 08 BEEF 0040 crc_fn"),
        ("con prefisso :0000", "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 :0000 exact_fn"),
        ("pattern corto (16B)", "404142434445464748494A4B4C4D4E4F 00 0000 0040 short_fn"),
        ("IDA reale (doc)", "5589E5 83EC08 00 0000 0010 _start"),
    ];

    for (label, line) in lines {
        let v2 = rustre_flirt::pat_parser_v2::parse_pat_line(line, 0);
        let simple = rustre_flirt::SimpleFlirtDatabase::parse_pat_text(line).len();
        println!("{label:<22} v2={:<48} parse_pat_text={simple}",
            match &v2 {
                Ok(e) => format!("OK ({} refs)", e.refs.len()),
                Err(e) => format!("{e:?}").chars().take(46).collect::<String>(),
            });
    }
}
