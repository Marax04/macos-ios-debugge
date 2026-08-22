//! Smoke-test the new `analysis_trace_data_flow_path` handler against
//! a real binary on disk.
use serde_json::json;
use rustre_mcp_tools::wire_tools::AnalysisTraceDataFlowPathTool;
use rustre_mcp_server::ToolHandler;

fn pick_binary() -> Option<std::path::PathBuf> {
    let candidates = [
        "C:/Users/Fra/Desktop/RustRE/target/release/msvcrt-sigs.exe",
        "C:/Users/Fra/Desktop/RustRE/target/release/rustre-cli.exe",
        "C:/Users/Fra/Desktop/RustRE/target/debug/rustre-mcp.exe",
    ];
    for c in candidates {
        let p = std::path::PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[tokio::test]
async fn trace_forward_from_entry_point_emits_something() {
    let Some(path) = pick_binary() else {
        eprintln!("no test binary present; skipping");
        return;
    };
    let load = rustre_decompiler::load_binary(&path).expect("load");
    let entry = load.entry_point.expect("PE has entry point");
    eprintln!("path={} entry={:#x}", path.display(), entry);

    // Detect a real function with several call-sites: pick the busiest VA.
    let bounds = rustre_decompiler::detect_functions_in_load(&load);
    eprintln!("detected {} functions", bounds.len());
    // Pick the first detected function as a stable test address.
    let pick_va = bounds
        .iter()
        .map(|b| b.start.as_u64())
        .find(|&v| v != 0)
        .unwrap_or(entry);
    eprintln!("pick_va={pick_va:#x}");

    let tool = AnalysisTraceDataFlowPathTool;
    let result = tool
        .call(json!({
            "path": path.to_string_lossy(),
            "address": pick_va,
            "direction": "backward",
            "max_depth": 4,
        }))
        .await
        .expect("call ok");
    let dbg = format!("{result:?}");
    eprintln!("RESULT: {}", &dbg.chars().take(400).collect::<String>());
    // Extract count from the JSON-as-text payload.
    let n = dbg
        .split("\\\"count\\\":")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);
    eprintln!("TRACE_COUNT={n}");
    assert!(n > 0, "expected at least one trace entry");
}
