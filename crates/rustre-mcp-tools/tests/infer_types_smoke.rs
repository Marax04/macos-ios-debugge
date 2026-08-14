//! Smoke test for `analysis_infer_types_path`: load this very crate's test
//! binary and check the tool returns a non-empty signature.

use rustre_mcp_server::ToolHandler;
use rustre_mcp_tools::infer_types_path::InferTypesPathTool;
use serde_json::{json, Value};

#[tokio::test(flavor = "current_thread")]
async fn infer_types_smoke() {
    // Use the rustre-mcp.exe binary built in target/debug; if absent, skip.
    let candidates = [
        "target/debug/rustre-mcp.exe",
        "../../target/debug/rustre-mcp.exe",
    ];
    let mut path = None;
    for c in candidates {
        if std::path::Path::new(c).exists() {
            path = Some(c.to_string());
            break;
        }
    }
    let Some(path) = path else {
        eprintln!("test binary not present, skipping");
        return;
    };

    // Read PE entry point.
    let data = std::fs::read(&path).expect("read pe");
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe + 24;
    let entry_rva = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().unwrap()) as u64;
    let image_base = u64::from_le_bytes(data[opt + 24..opt + 32].try_into().unwrap());
    let entry_va = image_base + entry_rva;

    let tool = InferTypesPathTool;
    let result = tool
        .call(json!({"path": path, "function_address": entry_va}))
        .await
        .expect("tool call");
    let text = match result.content.first() {
        Some(rustre_mcp_server::ContentBlock::Text { text }) => text.clone(),
        _ => String::new(),
    };
    let v: Value = serde_json::from_str(&text).expect("json");
    let sig = v
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(!sig.is_empty(), "signature empty: {text}");
    assert!(sig.contains('('), "signature missing parens: {sig}");
    eprintln!("signature: {sig}");
}
