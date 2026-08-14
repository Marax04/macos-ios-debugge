//! The Mach-O wire tools are present, and none of them invents a parse result
//! for input that is not Mach-O.
//!
//! Updated 2026-07-28. The test looked for five tools named `macho_*` and
//! found zero. Two separate things had happened, and neither was a missing
//! capability:
//!
//! 1. The richest Mach-O group, `tools::debug_macos` (49 tools, including
//!    `macho_header_parse`, `parse_load_commands`, `extract_dylibs`), is
//!    **deliberately disabled** — `tools/mod.rs:47` carries
//!    `// [DISABLED 2026-07-12] rustre-debug-macos dep disabled.` Those tools
//!    are compiled out, so no test may assume them.
//! 2. What remains live is the loader-side group, `loader_macho_*` /
//!    `loader_is_macho`, backed by `rustre-loader-macho`. That is what this
//!    test now covers — five tools, exactly the count the original expected.
//!
//! The original assertion ("empty bytes must return `Err`") is also not the
//! right shape any more, and the current design is better: these tools return
//! `Ok` with a **null / false** payload, which distinguishes "parsed nothing"
//! from "the call failed". The property that matters is kept and made
//! explicit: **on non-Mach-O input the tool must not report a structure.**
//!
//! This binary had never run: `cargo test` stops at the first failing target,
//! so a red earlier target hid it for a long time. Run crate sweeps with
//! `--no-fail-fast`.

use rustre_mcp_server::ContentBlock;
use rustre_mcp_tools::wire_tools::all_wire_handlers;
use serde_json::{json, Value};

/// The live Mach-O tools, under their current names.
const MACHO_TOOLS: &[&str] = &[
    "loader_is_macho",
    "loader_macho_parse",
    "loader_macho_parse_fat",
    "loader_macho_parse_summary",
    "loader_macho_arch_from_cputype",
];

/// The subset that parses bytes (so it can be fed non-Mach-O input).
const MACHO_PARSERS: &[&str] = &[
    "loader_macho_parse",
    "loader_macho_parse_fat",
    "loader_macho_parse_summary",
];

fn payload(result: &rustre_mcp_server::ToolResult) -> Value {
    let text = result
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Text { text } => Some(text.clone()),
            ContentBlock::Image { .. } => None,
        })
        .expect("tool returned text content");
    serde_json::from_str(&text).expect("tool output is JSON")
}

/// True when the payload asserts something beyond "nothing found".
///
/// `null`, `false`, zero, empty arrays/objects and the always-present `source`
/// provenance field all count as "nothing". A zero count with an empty list is
/// a truthful "no slices here", not an invented structure — the defect this
/// guards against is a REPORTED header or slice that the input never
/// contained.
fn claims_a_result(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => a.iter().any(claims_a_result),
        Value::Object(o) => o
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "source" | "error" | "reason"))
            .any(|(_, v)| claims_a_result(v)),
        Value::Bool(true) => true,
    }
}

/// A minimal, well-formed 64-bit Mach-O header (`MH_MAGIC_64`, x86_64,
/// `MH_EXECUTE`, no load commands).
fn minimal_macho64_hex() -> &'static str {
    concat!(
        "cffaedfe", // magic 0xFEEDFACF, little-endian
        "07000001", // cputype  CPU_TYPE_X86_64
        "03000000", // cpusubtype
        "02000000", // filetype MH_EXECUTE
        "00000000", // ncmds
        "00000000", // sizeofcmds
        "00000000", // flags
        "00000000", // reserved
    )
}

#[tokio::test(flavor = "current_thread")]
async fn macho_tools_are_registered() {
    let handlers = all_wire_handlers();
    let names: Vec<&str> = handlers.iter().map(|(d, _)| d.name.as_str()).collect();
    for want in MACHO_TOOLS {
        assert!(
            names.contains(want),
            "Mach-O tool '{want}' is not registered in all_wire_handlers"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn macho_parsers_do_not_invent_results_for_non_macho_input() {
    let handlers = all_wire_handlers();
    let mut checked = 0usize;

    for (def, handler) in &handlers {
        if !MACHO_PARSERS.contains(&def.name.as_str()) {
            continue;
        }
        // Empty, then bytes that are definitely not a Mach-O magic.
        for args in [json!({"bytes": []}), json!({"hex": "deadbeefdeadbeef"})] {
            match handler.call(args.clone()).await {
                // An explicit error is also "did not invent an answer".
                Err(_) => {}
                Ok(result) => {
                    let body = payload(&result);
                    assert!(
                        !claims_a_result(&body),
                        "{} reported a parse for non-Mach-O input {args}: {body}",
                        def.name
                    );
                }
            }
        }
        checked += 1;
    }

    assert_eq!(
        checked,
        MACHO_PARSERS.len(),
        "not every Mach-O parser was exercised"
    );
}

/// Positive control for the test above: on a REAL Mach-O header the parser
/// must report something.
///
/// Without this, `macho_parsers_do_not_invent_results_for_non_macho_input`
/// would still pass if the parsers were broken and returned nothing for
/// everything — the classic way an anti-fabrication test goes vacuous.
#[tokio::test(flavor = "current_thread")]
async fn macho_parser_does_report_a_real_header() {
    let handlers = all_wire_handlers();
    let (_, handler) = handlers
        .iter()
        .find(|(d, _)| d.name == "loader_macho_parse")
        .expect("loader_macho_parse is registered");

    let result = handler
        .call(json!({ "hex": minimal_macho64_hex() }))
        .await
        .expect("parsing a valid header must not fail");
    let body = payload(&result);
    assert!(
        claims_a_result(&body),
        "a well-formed Mach-O header produced no result: {body}"
    );
}
