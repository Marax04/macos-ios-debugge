//! Adversarial deep test suite for `rustre-cli` (blitz2).
//!
//! Targets the public API in `lib.rs`: argument parser, output format parsing,
//! config file loader, table renderer, ANSI color helpers, hex/ascii/count
//! formatters, SHA-256, file-type detection, Shannon entropy, byte histogram,
//! packing indicators, progress bar, and high-level run_* handlers.
//!
//! Uses a seeded LCG fuzzer — never panic, only Ok or specific Err.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use rustre_cli::{
    ArgParser, CliConfig, CliError, ColAlign, Color, ConfigValue, InteractiveSession,
    OutputFormat, ProgressBar, SubCommand, Table, build_help_text, byte_histogram, colorize,
    detect_file_type, detect_packing_indicators, fmt_addr, fmt_ascii, fmt_count, fmt_hex_bytes,
    run_analyze, run_diff, run_triage, sha256_hex, shannon_entropy,
};

// ── seeded LCG fuzz helper ──────────────────────────────────────────────────
struct Lcg {
    s: u64,
}
impl Lcg {
    fn new() -> Self {
        Self { s: 0xDEAD_BEEF_CAFE_BABE }
    }
    fn next_u64(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.s
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let x = self.next_u64();
            for i in 0..8 {
                if v.len() == n {
                    break;
                }
                v.push(((x >> (i * 8)) & 0xFF) as u8);
            }
        }
        v
    }
}

fn tmp_path(tag: &str, salt: u64) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rustre_cli_blitz2_{}_{}_{salt}",
        std::process::id(),
        tag
    ));
    p
}
fn tmp_file(tag: &str, salt: u64, data: &[u8]) -> PathBuf {
    let p = tmp_path(tag, salt);
    let mut f = std::fs::File::create(&p).expect("create tmp");
    f.write_all(data).expect("write tmp");
    p
}

// ──────────────── 1: OutputFormat round-trip ────────────────
#[test]
fn t01_output_format_display_fromstr_roundtrip() {
    let all = [
        OutputFormat::Table,
        OutputFormat::Json,
        OutputFormat::JsonPretty,
        OutputFormat::Csv,
        OutputFormat::Lines,
        OutputFormat::Html,
        OutputFormat::Sarif,
    ];
    for fmt in all {
        let s = fmt.to_string();
        let parsed: OutputFormat = s.parse().expect("roundtrip");
        assert_eq!(parsed, fmt);
        assert_eq!(s, fmt.name());
    }
}

#[test]
fn t02_output_format_unknown_err_variant() {
    for bad in ["", " ", "JSON", "Table", "yaml", "xml", "binary"] {
        let r: Result<OutputFormat, _> = bad.parse();
        assert!(r.is_err(), "expected err for {bad:?}");
        match r.unwrap_err() {
            CliError::InvalidValue { arg, .. } => assert_eq!(arg, "--format"),
            other => panic!("unexpected err {other:?}"),
        }
    }
}

#[test]
fn t03_output_format_all_names_complete() {
    let names = OutputFormat::all_names();
    assert_eq!(names.len(), 7);
    for n in names {
        let p: OutputFormat = n.parse().expect("known name parses");
        assert_eq!(p.name(), *n);
    }
}

// ──────────────── 2: ArgParser ────────────────
#[test]
fn t04_argparser_combined_short_flags() {
    let args = ArgParser::new(vec!["-vvq".into()]).parse().unwrap();
    assert_eq!(args.verbosity, 3);
    assert!(args.quiet);
}

#[test]
fn t05_argparser_double_dash_terminator() {
    // After `--`, everything is positional. The first positional is the
    // subcommand, so `--quiet`-after-`--` is treated as an unknown command.
    let r = ArgParser::new(vec!["--".into(), "--quiet".into()]).parse();
    assert!(r.is_err());
    match r.unwrap_err() {
        CliError::UnknownCommand(s) => assert_eq!(s, "--quiet"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn t06_argparser_unknown_long() {
    let r = ArgParser::new(vec!["--no-such-flag".into()]).parse();
    assert!(matches!(r, Err(CliError::UnknownCommand(_))));
}

#[test]
fn t07_argparser_unknown_short() {
    let r = ArgParser::new(vec!["-z".into()]).parse();
    assert!(matches!(r, Err(CliError::UnknownCommand(_))));
}

#[test]
fn t08_argparser_format_invalid_value_err() {
    let r = ArgParser::new(vec!["--format=garbage".into()]).parse();
    assert!(matches!(r, Err(CliError::InvalidValue { .. })));
}

#[test]
fn t09_argparser_disassemble_with_count() {
    let args = ArgParser::new(vec![
        "disassemble".into(),
        "/tmp/x".into(),
        "x86_64".into(),
        "0x1000".into(),
        "32".into(),
    ])
    .parse()
    .unwrap();
    match args.subcommand {
        SubCommand::Disassemble { count, base_addr, arch, .. } => {
            assert_eq!(count, Some(32));
            assert_eq!(base_addr, 0x1000);
            assert_eq!(arch, "x86_64");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn t10_argparser_disassemble_default_arch() {
    let args = ArgParser::new(vec!["disassemble".into(), "/tmp/x".into()])
        .parse()
        .unwrap();
    match args.subcommand {
        SubCommand::Disassemble { arch, base_addr, .. } => {
            assert_eq!(arch, "x86_64");
            assert_eq!(base_addr, 0);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn t11_argparser_export_missing_output() {
    let r = ArgParser::new(vec!["export".into(), "in".into()]).parse();
    assert!(matches!(r, Err(CliError::MissingArgument(_))));
}

#[test]
fn t12_argparser_analyse_alias() {
    for cmd in ["analyse", "analyze"] {
        let args = ArgParser::new(vec![cmd.into(), "/tmp/x".into()])
            .parse()
            .unwrap();
        assert!(matches!(args.subcommand, SubCommand::Analyse { .. }));
    }
}

#[test]
fn t13_argparser_count_not_integer_err() {
    let r = ArgParser::new(vec![
        "disassemble".into(),
        "/tmp/x".into(),
        "arm".into(),
        "0".into(),
        "abc".into(),
    ])
    .parse();
    assert!(matches!(r, Err(CliError::InvalidValue { .. })));
}

#[test]
fn t14_argparser_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let pool: &[&str] = &[
        "-v", "-q", "-h", "-V", "--help", "--version", "--quiet", "--verbose",
        "--format", "json", "csv", "table", "--format=json", "--config=/tmp/x",
        "--config", "analyse", "/tmp/foo", "x86_64", "0x10", "0", "5", "garbage",
        "--", "-z", "--unknown", "graph-smoke", "interactive", "config",
        "disassemble", "symbols", "import", "export", "script",
    ];
    for _ in 0..60 {
        let len = (lcg.next_u64() % 8) as usize;
        let mut argv: Vec<String> = Vec::with_capacity(len);
        for _ in 0..len {
            let idx = (lcg.next_u64() as usize) % pool.len();
            argv.push(pool[idx].to_string());
        }
        // Must return Result, never panic.
        let _ = ArgParser::new(argv).parse();
    }
}

#[test]
fn t15_parse_addr_boundary_overflow() {
    // 0xFFFFFFFFFFFFFFFF parses, but a 17-digit hex must error.
    let args = ArgParser::new(vec![
        "analyse".into(),
        "/tmp/x".into(),
        "x86".into(),
        "0xFFFFFFFFFFFFFFFF".into(),
    ])
    .parse()
    .unwrap();
    match args.subcommand {
        SubCommand::Analyse { base_addr, .. } => assert_eq!(base_addr, Some(u64::MAX)),
        other => panic!("{other:?}"),
    }

    let r = ArgParser::new(vec![
        "analyse".into(),
        "/tmp/x".into(),
        "x86".into(),
        "0x1FFFFFFFFFFFFFFFF".into(),
    ])
    .parse();
    assert!(matches!(r, Err(CliError::InvalidValue { .. })));
}

// ──────────────── 3: CliConfig ────────────────
#[test]
fn t16_config_load_file_basic() {
    let p = tmp_file(
        "cfg_basic",
        1,
        b"# comment\noutput.format = json\nverbosity = 2\nflag = true\nname = \"hello\"\n\n",
    );
    let cfg = CliConfig::load_from_file(&p).expect("parse");
    assert_eq!(cfg.get_str("output.format"), Some("json"));
    assert_eq!(cfg.get_int("verbosity"), Some(2));
    assert_eq!(cfg.get_bool("flag"), Some(true));
    assert_eq!(cfg.get_str("name"), Some("hello"));
    let _ = std::fs::remove_file(p);
}

#[test]
fn t17_config_load_duplicate_key_err() {
    let p = tmp_file("cfg_dup", 2, b"k = 1\nk = 2\n");
    let r = CliConfig::load_from_file(&p);
    assert!(matches!(r, Err(CliError::Config(_))));
    let _ = std::fs::remove_file(p);
}

#[test]
fn t18_config_load_malformed_line_err() {
    // Line without any `=` must be rejected.
    let p = tmp_file("cfg_bad", 3, b"this_line_has_no_equals_sign\n");
    let r = CliConfig::load_from_file(&p);
    assert!(matches!(r, Err(CliError::Config(_))));
    let _ = std::fs::remove_file(p);
}

#[test]
fn t19_config_load_empty_file_ok() {
    let p = tmp_file("cfg_empty", 4, b"");
    let cfg = CliConfig::load_from_file(&p).expect("empty ok");
    assert!(cfg.is_empty());
    assert_eq!(cfg.len(), 0);
    let _ = std::fs::remove_file(p);
}

#[test]
fn t20_config_get_typed_wrong_type_returns_none() {
    let mut cfg = CliConfig::new();
    cfg.set_str("a", "hello");
    cfg.set_int("b", 10);
    cfg.set_bool("c", true);
    assert_eq!(cfg.get_str("b"), None);
    assert_eq!(cfg.get_int("a"), None);
    assert_eq!(cfg.get_bool("a"), None);
    assert!(cfg.get("missing").is_none());
}

#[test]
fn t21_config_output_format_fallback() {
    let mut cfg = CliConfig::new();
    assert_eq!(cfg.output_format(OutputFormat::Csv), OutputFormat::Csv);
    cfg.set_str("output.format", "junk");
    assert_eq!(cfg.output_format(OutputFormat::Csv), OutputFormat::Csv);
    cfg.set_str("output.format", "json-pretty");
    assert_eq!(
        cfg.output_format(OutputFormat::Csv),
        OutputFormat::JsonPretty
    );
}

#[test]
fn t22_config_fuzz_loader_never_panics() {
    let mut lcg = Lcg::new();
    for i in 0..40 {
        let n = (lcg.next_u64() % 200) as usize;
        let raw = lcg.bytes(n);
        let p = tmp_file("cfg_fuzz", 100 + i, &raw);
        // Must not panic.
        let _ = CliConfig::load_from_file(&p);
        let _ = std::fs::remove_file(p);
    }
}

// ──────────────── 4: Table renderer ────────────────
#[test]
fn t23_table_json_escapes_quotes_and_backslash() {
    let mut t = Table::new(vec!["k"]);
    t.push_row(vec!["a\"b\\c"]);
    let j = t.render_json(false);
    // serde_json must escape the embedded quote and backslash.
    assert!(j.contains("\\\""), "json={j}");
    assert!(j.contains("\\\\"), "json={j}");
}

#[test]
fn t24_table_csv_quotes_newline_and_quote() {
    let mut t = Table::new(vec!["c"]);
    t.push_row(vec!["he said \"hi\""]);
    t.push_row(vec!["line1\nline2"]);
    let csv = t.render_csv();
    assert!(csv.contains("\"he said \"\"hi\"\"\""));
    assert!(csv.contains("\"line1\nline2\""));
}

#[test]
fn t25_table_alignments_apply() {
    let mut t = Table::new(vec!["h"]);
    t.set_align(0, ColAlign::Right);
    t.push_row(vec!["x"]);
    let r = t.render_table();
    assert!(r.contains("x"));
}

#[test]
fn t26_table_render_dispatch_all_formats() {
    let mut t = Table::new(vec!["k", "v"]);
    t.push_row(vec!["a", "1"]);
    for fmt in [
        OutputFormat::Table,
        OutputFormat::Json,
        OutputFormat::JsonPretty,
        OutputFormat::Csv,
        OutputFormat::Lines,
        OutputFormat::Html,
        OutputFormat::Sarif,
    ] {
        let out = t.render(fmt);
        assert!(!out.is_empty(), "empty for {fmt:?}");
    }
}

#[test]
fn t27_table_empty_renders_without_panic() {
    let t = Table::new(vec!["a", "b"]);
    let _ = t.render_table();
    let _ = t.render_json(true);
    let _ = t.render_csv();
}

// ──────────────── 5: Hex/ascii/count formatters ────────────────
#[test]
fn t28_fmt_addr_all_widths_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let v = lcg.next_u64();
        for bits in [16u32, 32, 64, 7, 0] {
            let s = fmt_addr(v, bits);
            assert!(s.starts_with("0x"));
            // The hex digits after 0x must round-trip with u64.
            let hex = &s[2..];
            let parsed = u64::from_str_radix(hex, 16);
            assert!(parsed.is_ok(), "fmt_addr produced non-hex: {s}");
        }
    }
}

#[test]
fn t29_fmt_hex_bytes_and_ascii_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = (lcg.next_u64() % 64) as usize;
        let data = lcg.bytes(n);
        let hex = fmt_hex_bytes(&data);
        let ascii = fmt_ascii(&data);
        if !data.is_empty() {
            // hex tokens count == byte count
            let parts: Vec<&str> = hex.split(' ').filter(|p| !p.is_empty()).collect();
            assert_eq!(parts.len(), data.len());
        }
        assert_eq!(ascii.chars().count(), data.len());
    }
}

#[test]
fn t30_fmt_count_boundary() {
    assert_eq!(fmt_count(0), "0");
    assert_eq!(fmt_count(1), "1");
    assert_eq!(fmt_count(999), "999");
    assert_eq!(fmt_count(1_000), "1_000");
    assert_eq!(fmt_count(u64::MAX), "18_446_744_073_709_551_615");
}

// ──────────────── 6: SHA-256 ────────────────
#[test]
fn t31_sha256_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn t32_sha256_lcg_determinism_and_length() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = (lcg.next_u64() % 256) as usize;
        let data = lcg.bytes(n);
        let h1 = sha256_hex(&data);
        let h2 = sha256_hex(&data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ──────────────── 7: detect_file_type & friends ────────────────
#[test]
fn t33_detect_all_magic_branches() {
    let mut data = vec![0u8; 64];
    data[0] = b'M';
    data[1] = b'Z';
    assert_eq!(detect_file_type(&data).0, "PE");

    // ELF — exercise multiple machine values.
    for (m, expect) in [
        (0x03u8, "x86"),
        (0x3E, "x86_64"),
        (0x28, "ARM"),
        (0xB7, "AArch64"),
        (0x08, "MIPS"),
        (0x14, "PowerPC"),
        (0xF3, "RISC-V"),
        (0x00, "unknown"),
    ] {
        let mut d = vec![0u8; 32];
        d[..4].copy_from_slice(b"\x7fELF");
        d[18] = m;
        let (fmt, arch) = detect_file_type(&d);
        assert_eq!(fmt, "ELF");
        assert_eq!(arch, expect);
    }

    assert_eq!(detect_file_type(b"\xCE\xFA\xED\xFE").0, "Mach-O");
    assert_eq!(detect_file_type(b"\xFE\xED\xFA\xCF").0, "Mach-O");
    assert_eq!(detect_file_type(b"\xCA\xFE\xBA\xBE").0, "Mach-O Fat");
    assert_eq!(detect_file_type(b"PK\x03\x04").0, "ZIP/APK/JAR");
    assert_eq!(detect_file_type(b"%PDF-1.4").0, "PDF");
    assert_eq!(detect_file_type(b"\x89PNG\r\n").0, "PNG");
    assert_eq!(detect_file_type(b"!<arch>").0, "Archive");
}

#[test]
fn t34_detect_file_type_truncated_safe() {
    // Truncated must not panic.
    for n in 0..5 {
        let data = vec![0u8; n];
        let _ = detect_file_type(&data);
    }
}

#[test]
fn t35_detect_file_type_lcg_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 128) as usize;
        let data = lcg.bytes(n);
        let (fmt, _) = detect_file_type(&data);
        assert!(!fmt.is_empty());
    }
}

// ──────────────── 8: Shannon entropy ────────────────
#[test]
fn t36_entropy_bounds_lcg() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = ((lcg.next_u64() % 512) + 1) as usize;
        let data = lcg.bytes(n);
        let e = shannon_entropy(&data);
        assert!(e >= -1e-9, "negative entropy {e}");
        assert!(e <= 8.0 + 1e-6, "entropy too high {e}");
    }
}

#[test]
fn t37_entropy_uniform_and_constant() {
    let uniform: Vec<u8> = (0..=255u8).collect();
    let e1 = shannon_entropy(&uniform);
    assert!((e1 - 8.0).abs() < 0.01);
    let constant = vec![0u8; 4096];
    let e2 = shannon_entropy(&constant);
    assert!(e2 < 1e-9);
    assert!((shannon_entropy(b"") - 0.0).abs() < f64::EPSILON);
}

// ──────────────── 9: byte_histogram ────────────────
#[test]
fn t38_byte_histogram_sum_matches_len() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let n = (lcg.next_u64() % 300) as usize;
        let data = lcg.bytes(n);
        let h = byte_histogram(&data);
        assert_eq!(h.len(), 256);
        let sum: u64 = h.iter().map(|&c| u64::from(c)).sum();
        assert_eq!(sum as usize, data.len());
    }
}

// ──────────────── 10: detect_packing_indicators ────────────────
#[test]
fn t39_packing_indicators_signatures() {
    // UPX magic
    let mut d = vec![0x42u8; 256];
    d.extend_from_slice(b"UPX!\x00\x00\x00");
    let ind = detect_packing_indicators(&d, shannon_entropy(&d));
    assert!(ind.iter().any(|s| s.contains("UPX")));

    // ASPack
    let mut d = vec![0x42u8; 64];
    d.extend_from_slice(b"ASPack");
    let ind = detect_packing_indicators(&d, 1.0);
    assert!(ind.iter().any(|s| s.contains("ASPack")));

    // Themida
    let mut d = vec![0x10u8; 32];
    d.extend_from_slice(b"Themida");
    let ind = detect_packing_indicators(&d, 1.0);
    assert!(ind.iter().any(|s| s.contains("Themida")));
}

#[test]
fn t40_packing_never_empty() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let n = ((lcg.next_u64() % 200) + 1) as usize;
        let data = lcg.bytes(n);
        let e = shannon_entropy(&data);
        let ind = detect_packing_indicators(&data, e);
        assert!(!ind.is_empty());
    }
}

// ──────────────── 11: ProgressBar ────────────────
#[test]
fn t41_progress_bar_state_machine() {
    let mut pb = ProgressBar::new("x", 100).quiet();
    assert!((pb.fraction() - 0.0).abs() < f64::EPSILON);
    pb.advance(25);
    pb.advance(25);
    pb.advance(25);
    assert!((pb.fraction() - 0.75).abs() < 1e-9);
    pb.finish();
    assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
    // Elapsed is monotonic-non-negative.
    assert!(pb.elapsed().as_nanos() < u128::from(u64::MAX));
}

#[test]
fn t42_progress_bar_saturates_no_overflow() {
    let mut pb = ProgressBar::new("y", 10).quiet().with_width(20);
    pb.advance(u64::MAX);
    assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
}

// ──────────────── 12: Colors ────────────────
#[test]
fn t43_colorize_no_color_passthrough_lcg() {
    let mut lcg = Lcg::new();
    let palette = [
        Color::Reset, Color::Red, Color::Green, Color::Yellow, Color::Blue,
        Color::Magenta, Color::Cyan, Color::White, Color::BrightRed,
        Color::BrightGreen, Color::BrightYellow, Color::BrightBlue,
        Color::BrightCyan, Color::Bold, Color::Dim,
    ];
    for _ in 0..30 {
        let len = (lcg.next_u64() % 20) as usize;
        let s: String = (0..len)
            .map(|_| ((lcg.next_u64() & 0x7F) as u8 | 0x20) as char)
            .collect();
        let c = palette[(lcg.next_u64() as usize) % palette.len()];
        assert_eq!(colorize(&s, c, false), s);
        let with = colorize(&s, c, true);
        assert!(with.contains(&s));
        assert!(with.ends_with("\x1b[0m"));
    }
}

// ──────────────── 13: Hash/Eq consistency ────────────────
#[test]
fn t44_output_format_eq_hash_consistency() {
    use std::collections::HashSet;
    let pairs = [
        (OutputFormat::Table, OutputFormat::Table),
        (OutputFormat::Json, OutputFormat::Json),
        (OutputFormat::JsonPretty, OutputFormat::JsonPretty),
        (OutputFormat::Csv, OutputFormat::Csv),
        (OutputFormat::Lines, OutputFormat::Lines),
        (OutputFormat::Html, OutputFormat::Html),
        (OutputFormat::Sarif, OutputFormat::Sarif),
    ];
    let mut set: HashSet<String> = HashSet::new();
    for (a, b) in pairs {
        assert_eq!(a, b);
        set.insert(a.name().to_string());
    }
    assert_eq!(set.len(), 7);
    // Cross-format inequality (30+ pairs total via pairwise).
    let all = [
        OutputFormat::Table,
        OutputFormat::Json,
        OutputFormat::JsonPretty,
        OutputFormat::Csv,
        OutputFormat::Lines,
        OutputFormat::Html,
        OutputFormat::Sarif,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn t45_clierror_eq_consistency() {
    let pairs = [
        CliError::UnknownCommand("a".into()),
        CliError::UnknownCommand("a".into()),
        CliError::MissingArgument("x".into()),
        CliError::MissingArgument("x".into()),
        CliError::Config("c".into()),
        CliError::Config("c".into()),
        CliError::Output("o".into()),
        CliError::Output("o".into()),
        CliError::Interactive("i".into()),
        CliError::Interactive("i".into()),
    ];
    for i in (0..pairs.len()).step_by(2) {
        assert_eq!(pairs[i], pairs[i + 1]);
    }
    // Cross-variant inequality.
    assert_ne!(
        CliError::UnknownCommand("a".into()),
        CliError::MissingArgument("a".into())
    );
}

// ──────────────── 14: Help/Version/Subcommand ────────────────
#[test]
fn t46_build_help_text_contains_inputs() {
    let h = build_help_text("rustre", "9.9.9", "About!");
    assert!(h.contains("rustre"));
    assert!(h.contains("9.9.9"));
    assert!(h.contains("About!"));
    assert!(h.contains("Usage"));
}

#[test]
fn t47_subcommand_descriptions_nonempty() {
    let cmds = [
        SubCommand::Help,
        SubCommand::Version,
        SubCommand::Interactive,
        SubCommand::Config,
        SubCommand::GraphSmoke,
        SubCommand::Script { path: PathBuf::from("x") },
        SubCommand::Analyse { path: PathBuf::from("x"), arch: None, base_addr: None },
        SubCommand::Disassemble { path: PathBuf::from("x"), arch: "x86_64".into(), base_addr: 0, count: None },
        SubCommand::Symbols { path: PathBuf::from("x") },
        SubCommand::Export { path: PathBuf::from("a"), out: PathBuf::from("b"), format: OutputFormat::Json },
        SubCommand::Import { path: PathBuf::from("x") },
    ];
    for c in cmds {
        assert!(!c.description().is_empty());
    }
}

// ──────────────── 15: InteractiveSession ────────────────
#[test]
fn t48_interactive_dispatch_state_transitions() {
    // Empty / unknown / help all continue; quit/exit/q stop.
    assert!(InteractiveSession::dispatch_line(""));
    assert!(InteractiveSession::dispatch_line("help"));
    assert!(InteractiveSession::dispatch_line("h"));
    assert!(InteractiveSession::dispatch_line("?"));
    assert!(InteractiveSession::dispatch_line("rumple"));
    assert!(!InteractiveSession::dispatch_line("quit"));
    assert!(!InteractiveSession::dispatch_line("exit"));
    assert!(!InteractiveSession::dispatch_line("q"));
    let s = InteractiveSession::new(">>> ").with_color(false);
    assert!(s.history().is_empty());
}

// ──────────────── 16: run_analyze / run_triage / run_diff ────────────────
#[test]
fn t49_run_analyze_synthetic_pe() {
    // MZ + minimal PE header.
    let mut data = vec![0u8; 0x200];
    data[0] = b'M';
    data[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    data[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF: machine x86_64, 1 section, opt header size 0xE0
    let coff = 0x84;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
    let p = tmp_file("pe_in", 10, &data);
    let r = run_analyze(p.clone(), None, OutputFormat::Json);
    assert!(r.is_ok(), "{:?}", r.err());
    let _ = std::fs::remove_file(p);
}

#[test]
fn t50_run_triage_and_diff_files() {
    let p1 = tmp_file("tr1", 20, &vec![0xAAu8; 1024]);
    let p2 = tmp_file("tr2", 21, &vec![0xBBu8; 1024]);
    let r = run_triage(p1.clone(), false);
    assert!(r.is_ok());
    let r2 = run_triage(p1.clone(), true);
    assert!(r2.is_ok());
    let r3 = run_diff(p1.clone(), p2.clone(), None);
    assert!(r3.is_ok());
    let _ = std::fs::remove_file(p1);
    let _ = std::fs::remove_file(p2);
}

#[test]
fn t51_run_analyze_missing_file_err() {
    let r = run_analyze(
        PathBuf::from("/definitely/does/not/exist/zzz9999"),
        None,
        OutputFormat::Json,
    );
    assert!(r.is_err());
}

// ──────────────── 17: Send/Sync threaded stress ────────────────
#[test]
fn t52_table_send_sync_threaded() {
    // Build once, share immutably across threads.
    let mut t = Table::new(vec!["k", "v"]);
    for i in 0..16 {
        t.push_row(vec![format!("row{i}"), format!("{i}")]);
    }
    let t = Arc::new(t);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let t = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let s = t.render_json(false);
                assert!(s.starts_with('['));
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

#[test]
fn t53_config_send_sync_threaded() {
    let mut cfg = CliConfig::new();
    for i in 0..32 {
        cfg.set_int(format!("k{i}"), i as i64);
        cfg.set_str(format!("s{i}"), format!("v{i}"));
    }
    let cfg = Arc::new(cfg);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cfg = Arc::clone(&cfg);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = cfg.get_int("k0");
                let _ = cfg.get_str("s10");
                let _ = cfg.len();
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

// ──────────────── 18: Misc small parsers ────────────────
#[test]
fn t54_config_value_display_roundtrip() {
    let cases = [
        (ConfigValue::String("abc".into()), "abc"),
        (ConfigValue::Int(-5), "-5"),
        (ConfigValue::Bool(true), "true"),
        (ConfigValue::Bool(false), "false"),
    ];
    for (v, expect) in cases {
        assert_eq!(v.to_string(), expect);
    }
}

#[test]
fn t55_apply_overrides_typed_inference() {
    let mut cfg = CliConfig::new();
    let mut o = HashMap::new();
    o.insert("a".into(), "true".into());
    o.insert("b".into(), "42".into());
    o.insert("c".into(), "3.5".into());
    o.insert("d".into(), "\"quoted\"".into());
    cfg.apply_overrides(&o).unwrap();
    assert_eq!(cfg.get_bool("a"), Some(true));
    assert_eq!(cfg.get_int("b"), Some(42));
    assert_eq!(cfg.get_str("d"), Some("quoted"));
    // Float stored as Float, not int or string.
    match cfg.get("c") {
        Some(ConfigValue::Float(_)) => {}
        other => panic!("expected Float, got {other:?}"),
    }
}

#[test]
fn t56_path_in_export_subcommand() {
    let args = ArgParser::new(vec![
        "export".into(),
        "in.db".into(),
        "out.csv".into(),
        "csv".into(),
    ])
    .parse()
    .unwrap();
    match args.subcommand {
        SubCommand::Export { path, out, format } => {
            assert_eq!(path, Path::new("in.db"));
            assert_eq!(out, Path::new("out.csv"));
            assert_eq!(format, OutputFormat::Csv);
        }
        other => panic!("{other:?}"),
    }
}
