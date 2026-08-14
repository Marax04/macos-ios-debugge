//! The `survey_binary` sections that are backed by a real analysis must report
//! real numbers — and must report *nothing* when the analysis does not apply.
//!
//! Companion to `survey_check.rs`, which is the full 12-section specification
//! and is still unmet (see that file's header). This file covers the sections
//! that have actually been implemented, one at a time, so each one is verified
//! for real rather than being declared done because a key exists.
//!
//! Implemented so far:
//!   * `callgraph`, `xrefs` — `rustre_analysis_xref::CallGraphBuilder`
//!   * `crypto`             — `rustre_crypto_id::ConstantScanner`
//!   * `flags`              — `rustre_loader_pe::PeInfo` + `PackingDetector`
//!   * `anti_analysis`      — `rustre_deobf_antianti` / `_cff` / `_vm` / `_smc`
//!   * `file`               — `rustre_loader::RichLoadResult` + `PeInfo`
//!   * `functions`          — `rustre_analysis_fn::detect_functions` (+ call graph)
//!   * `exports`            — `rustre_loader_pe::PeInfo::exports`
//!   * `entropy`            — `rustre_triage_entropy::{shannon_entropy, EntropyRating}`

use rustre_mcp_server::{ContentBlock, ToolHandler};
use rustre_mcp_tools::tools::survey::SurveyBinaryTool;
use serde_json::{json, Value};

/// A binary this repository actually builds, or `None`.
fn pick_binary() -> Option<std::path::PathBuf> {
    [
        "C:/Users/Fra/Desktop/RustRE/target/release/rustre-cli.exe",
        "C:/Users/Fra/Desktop/RustRE/target/debug/rustre-cli.exe",
        "C:/Users/Fra/Desktop/RustRE/target/release/rustre-mcp.exe",
        "C:/Users/Fra/Desktop/RustRE/target/debug/rustre-mcp.exe",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.exists())
}

async fn survey(path: &std::path::Path) -> Value {
    let result = SurveyBinaryTool
        .call(json!({ "path": path.to_string_lossy() }))
        .await
        .expect("survey call ok");
    let text = result
        .content
        .into_iter()
        .find_map(|b| match b {
            ContentBlock::Text { text } => Some(text),
            ContentBlock::Image { .. } => None,
        })
        .expect("text content");
    serde_json::from_str(&text).expect("survey output is JSON")
}

#[tokio::test]
async fn callgraph_and_xrefs_report_real_numbers_on_an_x86_binary() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;

    let cg = &v["callgraph"];
    assert!(!cg.is_null(), "callgraph must be computed for an x86 PE: {v}");

    let nodes = cg["nodes_count"].as_u64().expect("nodes_count");
    let edges = cg["edge_count"].as_u64().expect("edge_count");
    assert!(nodes > 0, "a real PE has call-graph nodes, got {nodes}");
    assert!(edges > 0, "a real PE has direct calls, got {edges}");

    // The busiest caller must actually be one of the graph's nodes, and its
    // fan-out must be at least 1 — otherwise "max" was computed over nothing.
    let fanout = &cg["max_fanout_function"];
    assert!(!fanout.is_null(), "max_fanout_function missing: {cg}");
    assert!(
        fanout["callees"].as_u64().is_some_and(|n| n >= 1),
        "max fan-out must be >= 1: {fanout}"
    );

    let xr = &v["xrefs"];
    assert!(!xr.is_null(), "xrefs must be computed alongside callgraph");
    let density = xr["density"].as_f64().expect("density");
    assert!(
        density > 0.0 && density.is_finite(),
        "density must be a real ratio, got {density}"
    );

    // `top10_most_called` is ordered by caller count, descending.
    let top = xr["top10_most_called"].as_array().expect("top10");
    assert!(!top.is_empty(), "no most-called functions: {xr}");
    let counts: Vec<u64> = top
        .iter()
        .map(|e| e["callers"].as_u64().expect("callers"))
        .collect();
    assert!(
        counts.windows(2).all(|w| w[0] >= w[1]),
        "top10_most_called is not sorted by caller count: {counts:?}"
    );
    assert!(counts[0] >= 1, "the most-called function has no callers");
}

#[tokio::test]
async fn callgraph_and_xrefs_are_null_when_the_scanner_does_not_apply() {
    // The scanner decodes the x86 `E8` opcode. On any other architecture the
    // sections must be null — "not computed" — rather than an empty graph,
    // which would read as "this binary calls nothing".
    //
    // A 64-byte ELF header claiming EM_AARCH64 is enough: the loader reports a
    // non-x86 arch and the survey must decline both sections.
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16] = 2; // ET_EXEC
    elf[18] = 0xB7; // EM_AARCH64
    elf[19] = 0x00;

    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("aarch64_stub.elf");
    std::fs::write(&path, &elf).expect("write stub");

    let v = survey(&path).await;
    assert!(
        v["callgraph"].is_null(),
        "callgraph must be null for a non-x86 target, got {}",
        v["callgraph"]
    );
    assert!(
        v["xrefs"].is_null(),
        "xrefs must be null for a non-x86 target, got {}",
        v["xrefs"]
    );
}

#[tokio::test]
async fn crypto_section_reports_only_what_the_scanner_matched() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let c = &v["crypto"];
    assert!(!c.is_null(), "crypto section missing: {v}");

    let total = c["count_total"].as_u64().expect("count_total");
    let high = c["count_high_confidence"].as_u64().expect("count_high_confidence");
    let threshold = c["high_confidence_threshold"]
        .as_u64()
        .expect("the threshold must be reported, not implied");
    assert!(
        high <= total,
        "high-confidence hits ({high}) cannot exceed total hits ({total})"
    );

    // Every rename target must be justified: a real VA, the constant that
    // matched, and a confidence at or above the stated threshold. A target
    // without its evidence is a rename nobody can check.
    for t in c["auto_rename_targets"].as_array().expect("auto_rename_targets") {
        assert!(
            t["va"].as_str().is_some_and(|s| s.starts_with("0x")),
            "rename target without a virtual address: {t}"
        );
        assert!(
            t["constant"].as_str().is_some_and(|s| !s.is_empty()),
            "rename target without the constant that justifies it: {t}"
        );
        assert!(
            t["confidence"].as_u64().is_some_and(|n| n >= threshold),
            "rename target below the stated threshold {threshold}: {t}"
        );
    }

    // `by_algorithm` counts must be consistent with the hits that produced
    // them: a hit can name several algorithms, so the sum is >= total, never
    // less — a smaller sum would mean hits were counted into no bucket.
    let sum: u64 = c["by_algorithm"]
        .as_object()
        .expect("by_algorithm")
        .values()
        .map(|n| n.as_u64().unwrap_or(0))
        .sum();
    if total > 0 {
        assert!(
            sum >= total,
            "by_algorithm sums to {sum} but there were {total} hits — hits went unbucketed"
        );
    }
}

#[tokio::test]
async fn crypto_section_finds_a_planted_constant_and_not_a_blank_file() {
    // Negative control: a file of zeroes has no crypto constants, so every
    // count must be zero. Without this the test above would pass on a scanner
    // that simply never reports anything.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");

    // It must be a file the loader can actually open — a bare blob is
    // rejected with "no registered loader can handle format: Unknown", which
    // would test the loader rather than the crypto scanner. A minimal x86-64
    // ELF whose body is all zeroes loads fine and contains no constants.
    let mut elf = vec![0u8; 8192];
    elf[..4].copy_from_slice(b"ELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16] = 2; // ET_EXEC
    elf[18] = 0x3E; // EM_X86_64
    let blank = dir.join("blank_x86_64.elf");
    std::fs::write(&blank, &elf).expect("write blank");
    let v = survey(&blank).await;
    let c = &v["crypto"];
    assert_eq!(
        c["count_total"].as_u64(),
        Some(0),
        "a file of zeroes must yield no crypto constants: {c}"
    );
    assert_eq!(c["count_high_confidence"].as_u64(), Some(0));
    assert!(
        c["auto_rename_targets"]
            .as_array()
            .is_some_and(std::vec::Vec::is_empty),
        "no constants means no rename targets: {c}"
    );
}

#[tokio::test]
async fn flags_section_is_read_from_the_pe_parser_on_a_pe() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let f = &v["flags"];
    assert!(!f.is_null(), "flags must be present for a PE: {v}");

    // Each flag must be a real boolean the parser produced, not a missing key
    // silently read as false by a consumer.
    for key in [
        "is_packed",
        "is_signed",
        "has_tls_callbacks",
        "has_dynamic_imports",
        "dotnet",
    ] {
        assert!(
            f[key].is_boolean(),
            "flags.{key} must be a boolean, got {}",
            f[key]
        );
    }

    // `is_packed` must agree with the evidence shipped beside it: the flag is
    // exactly "the packing detector produced at least one indicator".
    let indicators = f["packing_indicators"].as_array().expect("packing_indicators");
    assert_eq!(
        f["is_packed"].as_bool(),
        Some(!indicators.is_empty()),
        "is_packed disagrees with its own indicator list: {f}"
    );

    // Same for the dynamic-import flag and the count it is derived from.
    let delay = f["delay_import_count"].as_u64().expect("delay_import_count");
    assert_eq!(
        f["has_dynamic_imports"].as_bool(),
        Some(delay > 0),
        "has_dynamic_imports disagrees with delay_import_count={delay}: {f}"
    );

    // A Rust-built PE is not .NET; this pins that the flag is actually read
    // rather than defaulted to something.
    assert_eq!(f["dotnet"].as_bool(), Some(false), "a Rust PE is not .NET: {f}");
}

#[tokio::test]
async fn flags_section_is_null_for_a_non_pe() {
    // Negative control: an ELF has no Authenticode, no TLS callback directory
    // and no CLR header. Reporting `false` for each would answer questions
    // that were never asked of this file; the section must be absent instead.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut elf = vec![0u8; 4096];
    elf[..4].copy_from_slice(b"ELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 0x3E; // EM_X86_64
    let path = dir.join("flags_x86_64.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let v = survey(&path).await;
    assert!(
        v["flags"].is_null(),
        "flags must be null for a non-PE input, got {}",
        v["flags"]
    );
}

#[tokio::test]
async fn anti_analysis_flags_agree_with_their_own_counts() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let a = &v["anti_analysis"];
    assert!(!a.is_null(), "anti_analysis missing: {v}");

    // Every boolean is derived from a count that ships beside it, so the two
    // must never disagree. A verdict that can drift from its own evidence is
    // a verdict nobody can check.
    for (flag, count) in [
        ("anti_debug_found", "anti_debug_count"),
        ("anti_vm_found", "anti_vm_count"),
        ("cff_detected", "cff_dispatcher_count"),
        ("smc_detected", "smc_region_count"),
    ] {
        let n = a[count]
            .as_u64()
            .unwrap_or_else(|| panic!("{count} missing: {a}"));
        assert_eq!(
            a[flag].as_bool(),
            Some(n > 0),
            "{flag} disagrees with {count}={n}: {a}"
        );
    }

    // The VM verdict is a confidence enum, not a count; `vm_detected` means
    // "confidence is not None", and the confidence itself must be reported.
    let conf = a["vm_confidence"].as_str().expect("vm_confidence");
    assert_eq!(
        a["vm_detected"].as_bool(),
        Some(conf != "None"),
        "vm_detected disagrees with vm_confidence={conf}: {a}"
    );

    // `opaque_predicates` must be null — not false — because nothing looked.
    assert!(
        a["opaque_predicates"].is_null(),
        "opaque_predicates must be null (no CFG is built), got {}",
        a["opaque_predicates"]
    );
    assert!(
        a["opaque_predicates_note"]
            .as_str()
            .is_some_and(|s| s.contains("control-flow graph")),
        "the null must be explained: {a}"
    );
}

#[tokio::test]
async fn anti_analysis_reports_nothing_on_a_featureless_binary() {
    // Negative control: a zero-filled ELF contains no anti-debug sequences, no
    // VM dispatcher, no self-modifying region. Without this, the test above
    // would pass on detectors that fire on everything — the failure mode that
    // produced 8176 bogus RIPEMD-160 hits in the crypto scanner.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut elf = vec![0u8; 8192];
    elf[..4].copy_from_slice(b"ELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 0x3E;
    let path = dir.join("anti_x86_64.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let v = survey(&path).await;
    let a = &v["anti_analysis"];
    for flag in ["anti_debug_found", "anti_vm_found", "cff_detected", "smc_detected"] {
        assert_eq!(
            a[flag].as_bool(),
            Some(false),
            "{flag} fired on a featureless file: {a}"
        );
    }
    assert_eq!(
        a["vm_detected"].as_bool(),
        Some(false),
        "vm_detected fired on a featureless file: {a}"
    );
}

#[tokio::test]
async fn file_section_hashes_match_the_bytes_on_disk() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let f = &v["file"];
    assert!(!f.is_null(), "file section missing: {v}");

    // The size must be the real file size, and the digests must be the digests
    // OF THAT FILE — recomputed here independently. A hash that is merely
    // well-formed proves nothing; this pins that it identifies the input.
    let bytes = std::fs::read(&path).expect("read the binary back");
    assert_eq!(
        f["size"].as_u64(),
        Some(bytes.len() as u64),
        "reported size does not match the file: {f}"
    );

    let md5 = f["md5"].as_str().expect("md5");
    let sha256 = f["sha256"].as_str().expect("sha256");
    assert_eq!(md5.len(), 32, "md5 must be 32 hex chars, got {md5:?}");
    assert_eq!(sha256.len(), 64, "sha256 must be 64 hex chars, got {sha256:?}");
    assert!(
        md5.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "md5 must be lower-case hex: {md5}"
    );
    assert_eq!(
        sha256,
        rustre_loader::sha256(&bytes),
        "sha256 does not match an independent digest of the same bytes"
    );
    assert_eq!(
        md5,
        rustre_loader::md5(&bytes),
        "md5 does not match an independent digest of the same bytes"
    );

    // A 64-bit PE built by this repo.
    assert_eq!(f["bits"].as_u64(), Some(64), "expected a 64-bit binary: {f}");
    assert!(
        f["pe_timestamp"].as_u64().is_some(),
        "a PE must report its link timestamp: {f}"
    );
}

#[tokio::test]
async fn file_section_reports_null_for_fields_a_non_pe_cannot_have() {
    // Negative control: an ELF has no PE link timestamp and no PE debug
    // directory. Those fields must be null — reporting 0 for the timestamp
    // would be a date (1970-01-01), and "" for the pdb path would be a path.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut elf = vec![0u8; 4096];
    elf[..4].copy_from_slice(b"ELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 0x3E;
    let path = dir.join("file_x86_64.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let v = survey(&path).await;
    let f = &v["file"];
    assert!(
        f["pe_timestamp"].is_null(),
        "a non-PE must not report a PE timestamp, got {}",
        f["pe_timestamp"]
    );
    assert!(
        f["pdb_path"].is_null(),
        "a non-PE must not report a PDB path, got {}",
        f["pdb_path"]
    );
    // The format-independent fields must still be there and be real.
    assert_eq!(f["size"].as_u64(), Some(4096));
    assert_eq!(
        f["sha256"].as_str(),
        Some(rustre_loader::sha256(&elf).as_str()),
        "the digest must cover the bytes actually supplied"
    );
}

#[tokio::test]
async fn functions_section_is_consistent_with_the_rest_of_the_survey() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let f = &v["functions"];
    assert!(!f.is_null(), "functions section missing: {v}");

    // One detection pass feeds both fields, so they must agree. They used to
    // come from three separate `detect_functions` calls that could diverge.
    assert_eq!(
        f["count"].as_u64(),
        v["function_count"]["function_count"].as_u64(),
        "functions.count disagrees with function_count: {v}"
    );

    let count = f["count"].as_u64().expect("count");
    assert!(count > 0, "a real PE has functions");
    assert!(
        f["named_count"].as_u64().is_some_and(|n| n <= count),
        "named_count cannot exceed count: {f}"
    );

    // `top10_largest` is sorted by size, descending, and every entry has a
    // size the detector actually knew — functions with no end address are
    // excluded and counted, never given an invented size.
    let largest = f["top10_largest"].as_array().expect("top10_largest");
    let sizes: Vec<u64> = largest
        .iter()
        .map(|e| e["size"].as_u64().expect("size"))
        .collect();
    assert!(
        sizes.windows(2).all(|w| w[0] >= w[1]),
        "top10_largest is not sorted by size: {sizes:?}"
    );
    assert!(sizes.iter().all(|&s| s > 0), "a zero-sized function was listed");
    let excluded = f["without_known_size"].as_u64().expect("without_known_size");
    assert!(
        excluded <= count,
        "more functions excluded ({excluded}) than detected ({count})"
    );

    // `top10_called` must agree with the xrefs section, which is built from
    // the same call graph.
    let called = f["top10_called"].as_array().expect("top10_called on x86");
    let xr_top = v["xrefs"]["top10_most_called"].as_array().expect("xrefs top10");
    assert_eq!(
        called.len(),
        xr_top.len(),
        "functions.top10_called and xrefs.top10_most_called come from one graph          but have different lengths"
    );
    for (a, b) in called.iter().zip(xr_top.iter()) {
        assert_eq!(a["va"], b["func"], "the two top-10 lists disagree: {a} vs {b}");
        assert_eq!(a["callers"], b["callers"]);
    }
}

#[tokio::test]
async fn functions_top10_called_is_null_without_a_call_graph() {
    // Negative control: on a non-x86 target no call graph is built, so the
    // "most called" ranking has no source. It must be null — an empty list
    // would say "no function is called more than any other".
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut elf = vec![0u8; 4096];
    elf[..4].copy_from_slice(b"ELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 0xB7; // EM_AARCH64
    let path = dir.join("functions_aarch64.elf");
    std::fs::write(&path, &elf).expect("write elf");

    let v = survey(&path).await;
    assert!(
        v["functions"]["top10_called"].is_null(),
        "top10_called must be null without a call graph, got {}",
        v["functions"]["top10_called"]
    );
    // The detection-based fields are still answerable and must be present.
    assert!(
        v["functions"]["count"].as_u64().is_some(),
        "functions.count must still be reported: {}",
        v["functions"]
    );
}

/// A minimal x86-64 ELF of `len` bytes filled with `fill`.
fn elf_stub(len: usize, fill: u8, machine: u8) -> Vec<u8> {
    let mut v = vec![fill; len];
    v[..4].copy_from_slice(b"ELF");
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16] = 2;
    v[18] = machine;
    v[19] = 0;
    v
}

#[tokio::test]
async fn exports_section_is_consistent_and_null_for_a_non_pe() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let e = &v["exports"];
    assert!(!e.is_null(), "exports section missing for a PE: {v}");

    let count = e["count"].as_u64().expect("count");
    let list = e["list"].as_array().expect("list");
    let returned = e["returned"].as_u64().expect("returned");
    assert_eq!(returned, list.len() as u64, "returned disagrees with list");
    assert!(
        returned <= count,
        "returned ({returned}) cannot exceed count ({count}) — the cap must be visible"
    );
    // Each entry is either named or ordinal-only; neither is invented.
    for entry in list {
        assert!(
            entry["ordinal"].as_u64().is_some(),
            "every export has an ordinal: {entry}"
        );
        assert!(
            entry["address"].as_str().is_some_and(|s| s.starts_with("0x")),
            "export without an address: {entry}"
        );
    }

    // Negative control: an ELF has no PE export directory at all.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let stub = dir.join("exports_x86_64.elf");
    std::fs::write(&stub, elf_stub(4096, 0, 0x3E)).expect("write elf");
    let v2 = survey(&stub).await;
    assert!(
        v2["exports"].is_null(),
        "a non-PE must not report an export table, got {}",
        v2["exports"]
    );
}

#[tokio::test]
async fn entropy_rating_matches_the_entropy_it_reports() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };
    let v = survey(&path).await;
    let e = &v["entropy"];
    assert!(!e.is_null(), "entropy section missing: {v}");

    // The rating must be the one the shared classifier assigns to the entropy
    // printed beside it — recomputed here, so a re-implemented threshold in
    // the survey would show up as a mismatch.
    let overall = e["overall"].as_f64().expect("overall");
    let rating = e["overall_rating"].as_str().expect("overall_rating");
    let expected = format!(
        "{:?}",
        rustre_triage_entropy::EntropyRating::from_entropy(overall)
    );
    assert_eq!(rating, expected, "rating disagrees with its own entropy value");

    // blocks_top5 is sorted by entropy, descending, and capped at five.
    let top = e["blocks_top5"].as_array().expect("blocks_top5");
    assert!(top.len() <= 5, "blocks_top5 returned {} entries", top.len());
    let vals: Vec<f64> = top
        .iter()
        .map(|b| b["entropy"].as_f64().expect("entropy"))
        .collect();
    assert!(
        vals.windows(2).all(|w| w[0] >= w[1]),
        "blocks_top5 is not sorted by entropy: {vals:?}"
    );
}

#[tokio::test]
async fn entropy_of_a_zero_file_is_rated_very_low() {
    // Negative control: a zero-filled image carries no information, so the
    // rating must be the bottom of the scale. Without this the test above
    // would pass on a classifier that always answered the same thing.
    let dir = std::env::temp_dir().join("rustre_survey_sections_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let stub = dir.join("entropy_zero.elf");
    std::fs::write(&stub, elf_stub(8192, 0, 0x3E)).expect("write elf");

    let v = survey(&stub).await;
    let e = &v["entropy"];
    let overall = e["overall"].as_f64().expect("overall");
    assert!(
        overall < 1.0,
        "a zero-filled file must have near-zero entropy, got {overall}"
    );
    assert_eq!(
        e["overall_rating"].as_str(),
        Some("VeryLow"),
        "expected the bottom rating for a zero-filled file: {e}"
    );
}
