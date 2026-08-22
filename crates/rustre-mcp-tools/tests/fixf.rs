//! FIX F regression: `triage_entropy_packing_indicators` must not falsely report
//! "Few imports" on cargo-zyphora.exe which has 106 imports.

#[tokio::test]
async fn fixf_cargo_zyphora_no_few_imports() {
    let path = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    use rustre_mcp_server::{ContentBlock, ToolHandler};
    let tool = rustre_mcp_tools::tools::triage_entropy::TriageEntropyPackingIndicatorsTool;
    let args = serde_json::json!({ "path": path });
    let res = tool.call(args).await.expect("tool call");
    let text = res.content.iter().find_map(|c| match c {
        ContentBlock::Text { text } => Some(text.clone()),
        _ => None,
    }).expect("text content");
    println!("RESULT={text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ic = v["imports_count"].as_u64().unwrap_or(0);
    let indicators = v["indicators"].as_array().unwrap().clone();
    let has_few = indicators
        .iter()
        .any(|s| s.as_str().unwrap_or("").contains("Few imports"));
    println!("IMPORTS_COUNT={ic} HAS_FEW={has_few}");
    assert!(ic >= 5, "expected >=5 imports got {ic}");
    assert!(!has_few, "spurious Few imports indicator: {indicators:?}");
}
