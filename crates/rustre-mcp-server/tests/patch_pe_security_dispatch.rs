//! Integration test verifying that the rmcp dispatch surface actually invokes
//! the `rustre_patch::pe_security_summary_from_path` analyzer when the
//! `patch_pe_security_summary` tool is called with a `path` argument.
//!
//! Regression: previously the tool was defined in `rustre-mcp-tools::wire_tools`
//! but never wired into `RustREMcpServer`, so the rmcp dispatch returned either
//! `NotFound` or a stub instead of the parsed PE summary.

use rustre_mcp_server::RustREMcpServer;
use serde_json::{Value, json};

/// Construct a tiny PE32+ buffer with a known `DllCharacteristics`.
fn make_minimal_pe(dllchar: u16, is_64: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 0x200];
    buf[0..2].copy_from_slice(b"MZ");
    let e_lfanew = 0x80u32;
    buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe = e_lfanew as usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let size_opt: u16 = 240;
    buf[pe + 20..pe + 22].copy_from_slice(&size_opt.to_le_bytes());
    let opt = pe + 24;
    let magic: u16 = if is_64 { 0x20b } else { 0x10b };
    buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    buf[opt + 70..opt + 72].copy_from_slice(&dllchar.to_le_bytes());
    buf
}

#[test]
fn patch_pe_security_summary_dispatch_returns_real_flags() {
    // ASLR | DEP | CFG
    let dllchar: u16 = 0x0040 | 0x0100 | 0x4000;
    let buf = make_minimal_pe(dllchar, true);
    let path = std::env::temp_dir().join("rustre_mcp_pe_security_dispatch_test.bin");
    std::fs::write(&path, &buf).expect("write fake PE");

    let srv = RustREMcpServer::new();
    let result = srv.dispatch_tool(
        "patch_pe_security_summary",
        json!({ "path": path.to_string_lossy() }),
    );

    // CallToolResult should be a success with one text block holding JSON.
    assert!(
        !result.is_error.unwrap_or(false),
        "dispatch returned error: {result:?}"
    );
    let text = result
        .content
        .iter()
        .find_map(|c| {
            // rmcp Content wraps a RawContent enum; extract text via its Debug
            // surface — every variant we care about exposes `as_text()`.
            c.as_text().map(|t| t.text.clone())
        })
        .expect("no text content");

    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    // Reject stub responses — this is the regression we're guarding.
    assert!(
        parsed.get("stub").is_none(),
        "dispatch returned stub instead of calling analyzer: {parsed}"
    );
    assert_eq!(parsed["aslr"], json!(true), "ASLR flag should be set");
    assert_eq!(parsed["dep"], json!(true), "DEP flag should be set");
    assert_eq!(parsed["cfg"], json!(true), "CFG flag should be set");
    assert_eq!(parsed["is_64bit"], json!(true));
    assert_eq!(parsed["dll_characteristics"], json!(dllchar));

    let _ = std::fs::remove_file(&path);
}
