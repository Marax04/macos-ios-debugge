//! One-shot validation that `survey_binary` returns every required field
//! when invoked on a real PE. Used by the implementation task as the
//! authoritative "all fields present" check.

use rustre_mcp_tools::tools::survey::SurveyBinaryTool;
use rustre_mcp_server::ToolHandler;
use serde_json::{json, Value};

/// The full 12-section survey contract. **Met as of 2026-07-28.**
///
/// This began as a specification written ahead of the code ("used by the
/// implementation task as the authoritative 'all fields present' check",
/// above) and went unmet for a long time — `SurveyBinaryTool` emitted a flat
/// 10-key schema. It was `#[ignore]`d rather than left red, because a
/// permanently failing target masks NEW failures behind it (`cargo test` stops
/// at the first failing target — that is how this file went unrun for so
/// long). The ignore is now removed: the contract holds.
///
/// **The sections were filled one per tick, each backed by a real analysis and
/// each with a positive AND a negative control in `survey_sections.rs`:**
///   * `callgraph`, `xrefs`  — `rustre_analysis_xref::CallGraphBuilder`
///   * `crypto`              — `rustre_crypto_id::ConstantScanner`
///   * `flags`               — `rustre_loader_pe::PeInfo` + `PackingDetector`
///   * `anti_analysis`       — `rustre_deobf_antianti` / `_cff` / `_vm` / `_smc`
///   * `file`                — `RichLoadResult` digests + `PeInfo`
///   * `functions`           — `rustre_analysis_fn::detect_functions`
///   * `exports`             — `PeInfo::exports`
///   * `entropy`             — `rustre_triage_entropy::EntropyRating`
///   * `sections`/`imports`/`strings` — reshaped from data already computed
///
/// ⚠ **This test only checks that KEYS EXIST.** It must never be satisfied by
/// emitting an empty section: `crypto: {count_high_confidence: 0}` without
/// running a scan would turn it green while telling every caller "no crypto
/// found" about a binary nothing examined. Sections that genuinely cannot be
/// computed report `null` and say why (see `anti_analysis.opaque_predicates`,
/// which needs a per-function CFG this whole-file survey does not build).
/// `survey_sections.rs` is what proves the values are real; this file only
/// proves the shape.
#[tokio::test]
async fn survey_binary_emits_all_required_fields() {
    let path = "C:\\Users\\Fra\\Desktop\\Zyphora\\target\\release\\cargo-zyphora.exe";
    if !std::path::Path::new(path).exists() {
        eprintln!("SKIP: target not present");
        return;
    }
    let tool = SurveyBinaryTool;
    let res = tool.call(json!({ "path": path })).await.expect("call ok");
    let text = match res.content.into_iter().next().expect("content") {
        rustre_mcp_server::ContentBlock::Text { text } => text,
        _ => panic!("expected text content"),
    };
    let obj: Value = serde_json::from_str(&text).expect("json");

    let required: Vec<(&str, Vec<&str>)> = vec![
        ("file", vec!["kind","size","md5","sha256","image_base","arch","bits","pe_timestamp","pdb_path"]),
        ("sections", vec!["count","list"]),
        ("imports", vec!["count","by_dll"]),
        ("exports", vec!["count","list"]),
        ("functions", vec!["count","named_count","top10_largest","top10_called"]),
        ("strings", vec!["count","top20"]),
        ("crypto", vec!["count_high_confidence","by_algorithm","auto_rename_targets"]),
        ("entropy", vec!["overall_rating","blocks_top5"]),
        ("callgraph", vec!["nodes_count","max_fanout_function"]),
        ("xrefs", vec!["density","top10_most_called"]),
        ("anti_analysis", vec!["anti_debug_found","anti_vm_found","opaque_predicates","cff_detected","vm_detected","smc_detected"]),
        ("flags", vec!["is_packed","is_signed","has_tls_callbacks","has_dynamic_imports","dotnet"]),
    ];
    let mut missing: Vec<String> = vec![];
    for (k, subs) in &required {
        match obj.get(*k) {
            None => missing.push((*k).to_string()),
            Some(v) => {
                for s in subs {
                    if v.get(*s).is_none() {
                        missing.push(format!("{k}.{s}"));
                    }
                }
            }
        }
    }
    println!("MISSING_FIELDS={}", serde_json::to_string(&missing).unwrap());
    assert!(missing.is_empty(), "missing fields: {missing:?}");
}
