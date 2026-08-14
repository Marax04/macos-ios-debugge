//! A CSV row must survive the characters that occur in the data it carries.
//!
//! These rows interpolate file paths, process names and strings extracted from
//! a binary. A comma is legal in a Windows filename and guaranteed in extracted
//! strings; unquoted, it silently shifts every later column, so a reader
//! attributes one record's fields to the wrong headings.

use rustre_sysinternals::csv_field;

#[test]
fn ordinary_fields_are_returned_untouched() {
    // Minimal quoting is the point: rows that were already safe must be
    // byte-for-byte what they were.
    for s in ["explorer.exe", r"C:\Windows\System32", "", "no-specials_123"] {
        assert_eq!(csv_field(s), s, "quoted a field that needed no quoting: {s:?}");
    }
}

#[test]
fn fields_needing_quotes_are_quoted_per_rfc4180() {
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
    assert_eq!(csv_field("cr\rhere"), "\"cr\rhere\"");
}

#[test]
fn a_quoted_field_parses_back_as_one_field() {
    // Parse the way a minimal RFC 4180 reader would: a quoted field runs to the
    // next unescaped quote, so the embedded comma must not split the record.
    let row = format!("{},{}", csv_field("Program Files, Old"), csv_field("42"));
    assert!(row.starts_with('"'));
    let closing = row[1..].find('"').expect("closing quote") + 1;
    assert_eq!(&row[1..closing], "Program Files, Old");
    assert_eq!(&row[closing + 2..], "42");
}
