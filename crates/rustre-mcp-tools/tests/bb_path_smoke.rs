//! Smoke-test `analysis_basic_blocks_path` against a real binary on disk.
//!
//! Updated 2026-07-28: this test used to point at
//! `C:/Users/Fra/Desktop/Zyphora/target/release/cargo-zyphora.exe` — a binary
//! belonging to a different project — and at a hard-coded function address
//! inside it. Both were unreachable here, so the test skipped even when it
//! compiled; and it referenced a tool that had since been removed, so the whole
//! test target failed to BUILD and every test in it silently stopped running.
//!
//! It now picks a binary produced by THIS repository and derives the function
//! address from the detector instead of hard-coding one, so the assertions
//! below actually execute.

use rustre_mcp_server::{ContentBlock, ToolHandler};
use serde_json::json;

/// First binary this repo has actually built, or `None` if nothing is built.
fn pick_binary() -> Option<std::path::PathBuf> {
    let candidates = [
        "C:/Users/Fra/Desktop/RustRE/target/release/rustre-cli.exe",
        "C:/Users/Fra/Desktop/RustRE/target/debug/rustre-cli.exe",
        "C:/Users/Fra/Desktop/RustRE/target/release/rustre-mcp.exe",
        "C:/Users/Fra/Desktop/RustRE/target/debug/rustre-mcp.exe",
    ];
    candidates
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
}

#[tokio::test]
async fn basic_blocks_path_smoke() {
    let Some(path) = pick_binary() else {
        eprintln!("skip: no binary built in this repo yet");
        return;
    };

    // Take a real function address from the detector rather than hard-coding
    // one, which would rot the moment the binary is rebuilt.
    let load = rustre_decompiler::load_binary(&path).expect("load");
    let bounds = rustre_decompiler::detect_functions_in_load(&load);
    let Some(func) = bounds.iter().map(|b| b.start.as_u64()).find(|&v| v != 0) else {
        eprintln!("skip: detector found no function in {}", path.display());
        return;
    };

    let tool = rustre_mcp_tools::wire_tools::AnalysisBasicBlocksPathTool;
    let res = tool
        .call(json!({
            "path": path.to_string_lossy(),
            "function_address": func,
        }))
        .await
        .expect("call ok");
    let txt = res
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Text { text } => Some(text.clone()),
            ContentBlock::Image { .. } => None,
        })
        .expect("text content");
    let v: serde_json::Value = serde_json::from_str(&txt).expect("json");

    let bc = v.get("block_count").and_then(|x| x.as_u64()).unwrap_or(0);
    let blocks = v.get("blocks").and_then(|x| x.as_array()).expect("blocks");
    assert!(bc >= 1, "expected at least one block: {v}");
    assert_eq!(bc as usize, blocks.len(), "block_count disagrees with blocks");

    // Every block must carry both adjacency lists — that is the field the old
    // `analyze_cfg` tool never produced, and the reason this wrapper exists.
    for b in blocks {
        assert!(b.get("preds").is_some(), "block without preds: {b}");
        assert!(b.get("succs").is_some(), "block without succs: {b}");
    }

    // The edges must be internally consistent: if A lists B as a successor,
    // B must list A as a predecessor. A one-sided edge means the graph is
    // wrong, and no count-based assertion would notice.
    for b in blocks {
        let id = b["id"].as_u64().expect("id");
        for s in b["succs"].as_array().expect("succs") {
            let sid = usize::try_from(s.as_u64().expect("succ id")).expect("succ id fits");
            let preds = blocks[sid]["preds"].as_array().expect("preds");
            assert!(
                preds.iter().any(|p| p.as_u64() == Some(id)),
                "edge {id} -> {sid} is not mirrored in {sid}'s preds"
            );
        }
    }
}
