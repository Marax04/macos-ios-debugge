//! Comprehensive integration tests for the `rustre-mcp-tools` public API.
//!
//! These tests exercise public tool structs (via the `ToolHandler` and `McpTool`
//! traits re-exported from `rustre_mcp_server`), the two registry types, the
//! `register_*_tools` builders, and the value types `BinarySpec` / `SectionSpec`
//! / `ToolInput` / `ToolOutput` / `ToolError`.

use rustre_mcp_server::{ContentBlock, ToolHandler, ToolResult};
use rustre_mcp_tools::*;
use serde_json::{Value, json};

// --- helpers ----------------------------------------------------------------

fn bytes_arg(data: &[u8]) -> Value {
    json!({ "bytes": data.iter().map(|&b| u64::from(b)).collect::<Vec<_>>() })
}

fn text_of(r: &ToolResult) -> String {
    match &r.content[0] {
        ContentBlock::Text { text } => text.clone(),
        ContentBlock::Image { .. } => panic!("expected text content"),
    }
}

fn json_of(r: &ToolResult) -> Value {
    serde_json::from_str(&text_of(r)).unwrap()
}

async fn call<H: ToolHandler>(h: &H, args: Value) -> ToolResult {
    h.call(args).await.expect("tool call failed")
}

// --- value types ------------------------------------------------------------

#[test]
fn binary_spec_construct_and_clone() {
    let s = BinarySpec {
        data: vec![1, 2, 3],
        base_address: 0x400000,
    };
    let c = s.clone();
    assert_eq!(c.data, vec![1, 2, 3]);
    assert_eq!(c.base_address, 0x400000);
    // Debug is derived.
    let _ = format!("{s:?}");
}

#[test]
fn section_spec_construct_and_clone() {
    let s = SectionSpec {
        name: ".text".into(),
        offset: 0x1000,
        size: 0x200,
        flags: 0x60_00_00_20,
    };
    let c = s;
    assert_eq!(c.name, ".text");
    assert_eq!(c.offset, 0x1000);
    assert_eq!(c.size, 0x200);
    assert_eq!(c.flags, 0x60_00_00_20);
}

#[test]
fn tool_input_new_constructor() {
    let ti = ToolInput::new("hexdump", json!({"bytes": [0u8]}));
    assert_eq!(ti.name, "hexdump");
    assert!(ti.params.get("bytes").is_some());
    let cloned = ti;
    assert_eq!(cloned.name, "hexdump");
}

#[test]
fn tool_output_ok_constructor() {
    let out = ToolOutput::ok(json!({"k": 1}));
    assert!(out.success);
    assert_eq!(out.data, json!({"k": 1}));
}

#[test]
fn tool_error_display_variants() {
    let e1 = ToolError::Hexdump("x".into());
    let e2 = ToolError::InvalidInput("y".into());
    let e3 = ToolError::Execution("z".into());
    assert!(format!("{e1}").contains("hexdump"));
    assert!(format!("{e2}").contains("invalid input"));
    assert!(format!("{e3}").contains("execution"));
}

/// Every tool the server actually registers must have a unique name.
///
/// `definitions_have_unique_nonempty_names` below promises this invariant but
/// checks a **hand-written list of 26 builtin tools**, never touching
/// `all_wire_handlers()` — the collection that serves real MCP clients. That is
/// why two distinct tools shipped for a long time under the single name
/// `ttd_replay_engine_step_forward` (and two more under
/// `ttd_replay_watchpoint_overlaps`) with different payload shapes: whichever
/// registered second decided what a client received, and nothing complained.
///
/// A duplicate here is not cosmetic. The MCP surface is a map from name to
/// behaviour; two entries for one key make the answer depend on registration
/// order, which no caller can see.
#[tokio::test]
async fn wire_handler_names_are_unique_and_nonempty() {
    use std::collections::HashMap;

    // Full path on purpose: the crate-root glob may or may not re-export this,
    // and the point of the test is to check a specific collection.
    let handlers = rustre_mcp_tools::wire_tools::all_wire_handlers();
    assert!(
        handlers.len() > 1000,
        "the wire surface should be in the thousands, got {}",
        handlers.len()
    );

    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (def, _) in &handlers {
        assert!(
            !def.name.trim().is_empty(),
            "a registered tool has an empty name"
        );
        *seen.entry(def.name.as_str()).or_insert(0) += 1;
    }

    let mut dupes: Vec<(&str, usize)> = seen
        .into_iter()
        .filter(|&(_, n)| n > 1)
        .collect();
    dupes.sort_unstable();
    assert!(
        dupes.is_empty(),
        "tool names must be unique across all_wire_handlers(); duplicates: {dupes:?}"
    );
}

// --- ToolDefinition smoke tests for every public tool struct ---------------

#[test]
fn definitions_have_unique_nonempty_names() {
    let names = [
        HexDumpTool::definition().name,
        SearchBytesTool::definition().name,
        SearchStringsTool::definition().name,
        DisassemblyTool::definition().name,
        AnalyzeCfgTool::definition().name,
        XrefsTool::definition().name,
        DecompileFunctionTool::definition().name,
        YaraScanTool::definition().name,
        HashTool::definition().name,
        EntropyTool::definition().name,
        StringDecodeTool::definition().name,
        PatchAnalyzerTool::definition().name,
        PatchBytesTool::definition().name,
        CommentTool::definition().name,
        RenameFunctionTool::definition().name,
        Md5Tool::definition().name,
        Crc32Tool::definition().name,
        PackerDetectorTool::definition().name,
        ArchitectureTool::definition().name,
        ImportExportTool::definition().name,
        ConvertAddressTool::definition().name,
        SectionDumpTool::definition().name,
        DemangleTool::definition().name,
        XorDecryptTool::definition().name,
        RotDecryptTool::definition().name,
        BinaryDiffTool::definition().name,
    ];
    let mut sorted = names.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "tool names must be unique");
    for n in &names {
        assert!(!n.is_empty());
    }
}

// --- HexDumpTool ------------------------------------------------------------

#[tokio::test]
async fn hexdump_basic() {
    let r = call(&HexDumpTool, bytes_arg(b"ABC")).await;
    let t = text_of(&r);
    assert!(t.contains("41"));
    assert!(t.contains("|ABC|"));
}

#[tokio::test]
async fn hexdump_empty_input() {
    let r = call(&HexDumpTool, bytes_arg(b"")).await;
    assert_eq!(text_of(&r), "");
}

#[tokio::test]
async fn hexdump_offset_and_length() {
    let data: Vec<u8> = (0..32u8).collect();
    let r = call(
        &HexDumpTool,
        json!({"bytes": data.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
               "offset": 16, "length": 8}),
    )
    .await;
    let t = text_of(&r);
    assert!(t.contains("00000010"));
    assert!(t.contains("10 11 12 13 14 15 16 17"));
}

// --- SearchBytesTool -------------------------------------------------------

#[tokio::test]
async fn search_bytes_simple_match() {
    let data = [0u8, 0xDE, 0xAD, 0xBE, 0xEF, 0];
    let v = json_of(
        &call(
            &SearchBytesTool,
            json!({"bytes": data.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "pattern": "DE AD BE EF"}),
        )
        .await,
    );
    assert_eq!(v["count"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn search_bytes_wildcard_multiple_matches() {
    let data = [0xAAu8, 0x00, 0xBB, 0xAA, 0xFF, 0xBB];
    let v = json_of(
        &call(
            &SearchBytesTool,
            json!({"bytes": data.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "pattern": "AA ?? BB"}),
        )
        .await,
    );
    assert_eq!(v["count"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn search_bytes_no_match() {
    let v = json_of(
        &call(
            &SearchBytesTool,
            json!({"bytes": [0u8, 0u8, 0u8], "pattern": "FF FF FF"}),
        )
        .await,
    );
    assert_eq!(v["count"].as_u64().unwrap(), 0);
}

// --- SearchStringsTool -----------------------------------------------------

#[tokio::test]
async fn search_strings_finds_ascii() {
    let mut data = Vec::new();
    data.extend_from_slice(b"\x00hello\x00world\x00");
    let v = json_of(&call(&SearchStringsTool, bytes_arg(&data)).await);
    // strings field should be present; at least one of hello/world should appear
    let s = serde_json::to_string(&v).unwrap();
    assert!(s.contains("hello") || s.contains("world"));
}

// --- HashTool / Md5Tool / Crc32Tool ----------------------------------------

#[tokio::test]
async fn hash_tool_empty_input() {
    let v = json_of(&call(&HashTool, bytes_arg(b"")).await);
    // sha256 of empty
    assert_eq!(
        v["sha256"].as_str().unwrap().to_lowercase(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(v["bytes"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn md5_tool_known_vector() {
    let v = json_of(&call(&Md5Tool, bytes_arg(b"abc")).await);
    assert_eq!(
        v["md5"].as_str().unwrap().to_lowercase(),
        "900150983cd24fb0d6963f7d28e17f72"
    );
}

#[tokio::test]
async fn crc32_tool_known_vector() {
    let v = json_of(&call(&Crc32Tool, bytes_arg(b"123456789")).await);
    assert_eq!(v["crc32"].as_u64().unwrap(), 0xCBF4_3926);
    assert_eq!(v["hex"].as_str().unwrap(), "CBF43926");
}

// --- EntropyTool -----------------------------------------------------------

#[tokio::test]
async fn entropy_tool_constant_data_low() {
    let v = json_of(&call(&EntropyTool, bytes_arg(&vec![0u8; 64])).await);
    assert_eq!(v["entropy"].as_f64().unwrap(), 0.0);
    assert_eq!(v["rating"].as_str().unwrap(), "low");
}

#[tokio::test]
async fn entropy_tool_uniform_data_very_high() {
    let data: Vec<u8> = (0..=255u8).collect();
    let v = json_of(&call(&EntropyTool, bytes_arg(&data)).await);
    let e = v["entropy"].as_f64().unwrap();
    assert!((e - 8.0).abs() < 0.01, "entropy={e}");
    assert_eq!(v["rating"].as_str().unwrap(), "very high");
}

// --- StringDecodeTool -----------------------------------------------------

#[tokio::test]
async fn string_decode_default_utf8() {
    let v = json_of(&call(&StringDecodeTool, bytes_arg(b"hi")).await);
    assert_eq!(v["encoding"].as_str().unwrap(), "utf8");
    assert_eq!(v["decoded"].as_str().unwrap(), "hi");
    assert_eq!(v["length"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn string_decode_latin1() {
    let v = json_of(
        &call(
            &StringDecodeTool,
            json!({"bytes": [0xC0u8, 0xE9], "encoding": "latin1"}),
        )
        .await,
    );
    assert_eq!(v["encoding"].as_str().unwrap(), "latin1");
    let s = v["decoded"].as_str().unwrap();
    assert_eq!(s.chars().count(), 2);
}

#[tokio::test]
async fn string_decode_utf16le() {
    // "Hi" in UTF-16LE: 48 00 69 00
    let v = json_of(
        &call(
            &StringDecodeTool,
            json!({"bytes": [0x48u8, 0x00, 0x69, 0x00], "encoding": "utf16le"}),
        )
        .await,
    );
    assert_eq!(v["decoded"].as_str().unwrap(), "Hi");
}

// --- PatchAnalyzerTool / BinaryDiffTool ------------------------------------

#[tokio::test]
async fn patch_analyzer_reports_diff_ranges() {
    let v = json_of(
        &call(
            &PatchAnalyzerTool,
            json!({"original": [1u8, 2, 3, 4, 5], "patched": [1u8, 9, 9, 4, 5]}),
        )
        .await,
    );
    assert_eq!(v["diff_count"].as_u64().unwrap(), 1);
    assert_eq!(v["diffs"][0]["offset"].as_u64().unwrap(), 1);
    assert_eq!(v["diffs"][0]["length"].as_u64().unwrap(), 2);
    assert_eq!(v["original_size"].as_u64().unwrap(), 5);
}

#[tokio::test]
async fn patch_analyzer_identical_inputs_zero_diffs() {
    let v = json_of(
        &call(
            &PatchAnalyzerTool,
            json!({"original": [1u8, 2, 3], "patched": [1u8, 2, 3]}),
        )
        .await,
    );
    assert_eq!(v["diff_count"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn binary_diff_reports_changes() {
    let v = json_of(
        &call(
            &BinaryDiffTool,
            json!({"original": [0u8, 1, 2, 3], "modified": [0u8, 9, 2, 8]}),
        )
        .await,
    );
    assert_eq!(v["diff_count"].as_u64().unwrap(), 2);
}

// --- PatchBytesTool --------------------------------------------------------

#[tokio::test]
async fn patch_bytes_applies_correctly() {
    let v = json_of(
        &call(
            &PatchBytesTool,
            json!({"bytes": [0u8, 0, 0, 0], "offset": 1, "patch": "AABB"}),
        )
        .await,
    );
    assert_eq!(v["bytes_patched"].as_u64().unwrap(), 2);
    assert_eq!(v["result_hex"].as_str().unwrap().to_uppercase(), "00AABB00");
}

#[tokio::test]
async fn patch_bytes_out_of_bounds_errors() {
    let r = PatchBytesTool
        .call(json!({"bytes": [0u8, 0], "offset": 1, "patch": "AABB"}))
        .await;
    assert!(r.is_err());
}

#[tokio::test]
async fn patch_bytes_missing_offset_errors() {
    let r = PatchBytesTool
        .call(json!({"bytes": [0u8], "patch": "AA"}))
        .await;
    assert!(r.is_err());
}

// --- ArchitectureTool ------------------------------------------------------

#[tokio::test]
async fn architecture_detect_pe() {
    let v = json_of(&call(&ArchitectureTool, bytes_arg(b"MZ\x00\x00")).await);
    assert_eq!(v["architecture"].as_str().unwrap(), "PE/Windows");
}

#[tokio::test]
async fn architecture_detect_elf_x86_64() {
    let mut d = vec![0u8; 64];
    d[..4].copy_from_slice(b"\x7FELF");
    d[18] = 0x3e;
    d[19] = 0x00;
    let v = json_of(&call(&ArchitectureTool, bytes_arg(&d)).await);
    assert_eq!(v["architecture"].as_str().unwrap(), "x86_64");
}

/// Negative control for the two tests above: on input whose architecture is
/// NOT determinable, the tool must say so rather than guess.
///
/// Added 2026-07-29 (pass 6 of the crate review). `detect_arch` already
/// behaves correctly, but nothing pinned it: both existing tests feed a valid
/// magic and assert the matching architecture, so replacing the `"unknown"`
/// fallback with a plausible guess — `"x86_64"` is the obvious one on a
/// 64-bit host — would leave this suite fully green while every downstream
/// consumer (disassembler, lifter, call-graph scanner) silently decoded the
/// wrong instruction set.
///
/// Three ways of not knowing, kept distinct on purpose:
///   * too few bytes to hold any magic,
///   * enough bytes but no recognised magic,
///   * a real ELF whose `e_machine` this table does not list — which must
///     report `ELF/unknown`, not fall back to a default architecture.
#[tokio::test]
async fn architecture_says_unknown_when_it_cannot_tell() {
    // Fewer than 4 bytes: no magic can be present.
    for short in [&b""[..], &b"M"[..], &b"MZ"[..], &b"\x7FEL"[..]] {
        let v = json_of(&call(&ArchitectureTool, bytes_arg(short)).await);
        assert_eq!(
            v["architecture"].as_str().unwrap(),
            "unknown",
            "{} byte(s) cannot identify an architecture",
            short.len()
        );
    }

    // Enough bytes, but no recognised magic. Includes 0x00/0xFF/0xAA runs and
    // a fixed pseudo-random block: featureless input must stay featureless.
    let mut prng: u32 = 0x1234_5678;
    let random: Vec<u8> = (0..256)
        .map(|_| {
            prng = prng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (prng >> 24) as u8
        })
        .collect();
    for junk in [
        vec![0x00u8; 256],
        vec![0xFFu8; 256],
        vec![0xAAu8; 256],
        random,
        b"not a binary at all, just prose".to_vec(),
    ] {
        let v = json_of(&call(&ArchitectureTool, bytes_arg(&junk)).await);
        assert_eq!(
            v["architecture"].as_str().unwrap(),
            "unknown",
            "featureless input must not be assigned an architecture"
        );
    }

    // A well-formed ELF header carrying an e_machine the table does not know
    // (0x7777 is unassigned). The ELF-ness is real, the machine is not known:
    // the answer must say exactly that much and no more.
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7FELF");
    elf[18] = 0x77;
    elf[19] = 0x77;
    let v = json_of(&call(&ArchitectureTool, bytes_arg(&elf)).await);
    assert_eq!(
        v["architecture"].as_str().unwrap(),
        "ELF/unknown",
        "an unlisted e_machine must not be reported as a known architecture"
    );
}

// --- PackerDetectorTool ----------------------------------------------------

#[tokio::test]
async fn packer_detector_finds_upx() {
    let v = json_of(&call(&PackerDetectorTool, bytes_arg(b"UPX!\x00\x00")).await);
    assert!(v["detected"].as_bool().unwrap());
    let names: Vec<String> = v["packers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(names.iter().any(|s| s.contains("UPX")));
}

#[tokio::test]
async fn packer_detector_clean_input() {
    let v = json_of(&call(&PackerDetectorTool, bytes_arg(&[0x90u8; 64])).await);
    assert!(!v["detected"].as_bool().unwrap());
}

/// Prose that merely NAMES a packer is not a packed file.
///
/// Added 2026-07-29 (pass 3b). `packer_detector_clean_input` above feeds
/// featureless bytes, which cannot tell a precise detector from a promiscuous
/// one — 0x90 padding matches no table entry whatever the table says. The
/// input that discriminates is plausible-but-not-packed: ordinary ASCII that
/// happens to contain a product name.
///
/// `detect_packers_detailed` searches the whole buffer for each magic as a
/// substring, so before the strong/weak split every one of these strings set
/// `detected: true`. They must still be *reported* — silently dropping a hit
/// would trade one wrong answer for another — but under `weak_name_matches`,
/// with the offset that justifies them.
#[tokio::test]
async fn packer_detector_does_not_call_prose_packed() {
    // Sliced explicitly: byte-string literals have distinct array types
    // (`&[u8; 54]`, `&[u8; 44]`, …), so an array of them only type-checks once
    // each element is coerced to `&[u8]`.
    let prose: &[&[u8]] = &[
        &b"This archive was extracted with 7-Zip before analysis."[..],
        &b"Error: WinRAR is required to open this file."[..],
        &b"see also: MPRESS, ASPack and Themida in the packer survey"[..],
    ];
    for &text in prose {
        let v = json_of(&call(&PackerDetectorTool, bytes_arg(text)).await);
        assert!(
            !v["detected"].as_bool().unwrap(),
            "prose naming a packer must not be reported as packed: {}",
            String::from_utf8_lossy(text)
        );
        assert!(
            v["packers"].as_array().unwrap().is_empty(),
            "no strong signature is present in prose"
        );
        // Nothing is lost: the mention is still reported, with its offset.
        let weak = v["weak_name_matches"].as_array().unwrap();
        assert!(
            !weak.is_empty(),
            "the name mention must still be reported, just not as a verdict"
        );
        assert!(
            weak.iter().all(|w| w["offset"].as_u64().is_some()),
            "every weak match must carry the offset that justifies it"
        );
    }

    // Positive control for the split: a strong marker still sets `detected`,
    // and still does so when weak names sit in the same buffer.
    let mixed = b"UPX!\x00 packed, unpack with 7-Zip".to_vec();
    let v = json_of(&call(&PackerDetectorTool, bytes_arg(&mixed)).await);
    assert!(v["detected"].as_bool().unwrap(), "UPX! is a strong marker");
    assert!(
        !v["weak_name_matches"].as_array().unwrap().is_empty(),
        "the weak match alongside it is still reported"
    );
    assert!(
        v["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["offset"].as_u64().is_some()),
        "every strong detection must carry its offset"
    );
}

// --- DemangleTool ----------------------------------------------------------

#[tokio::test]
async fn demangle_itanium() {
    let v = json_of(&call(&DemangleTool, json!({"name": "_Z3foov"})).await);
    assert!(v["demangled"].as_str().unwrap().contains("foo"));
    assert_eq!(v["mangled"].as_str().unwrap(), "_Z3foov");
}

#[tokio::test]
async fn demangle_missing_name_errors() {
    let r = DemangleTool.call(json!({})).await;
    assert!(r.is_err());
}

// --- ConvertAddressTool ----------------------------------------------------

#[tokio::test]
async fn convert_address_va_to_offset() {
    let v = json_of(
        &call(
            &ConvertAddressTool,
            json!({"base": 0x400000, "address": 0x401234u64}),
        )
        .await,
    );
    assert_eq!(v["rva"].as_u64().unwrap(), 0x1234);
    assert_eq!(v["file_offset"].as_u64().unwrap(), 0x1234);
}

#[tokio::test]
async fn convert_address_offset_to_va() {
    let v = json_of(
        &call(
            &ConvertAddressTool,
            json!({"base": 0x400000, "file_offset": 0x200u64}),
        )
        .await,
    );
    assert_eq!(v["virtual_address"].as_u64().unwrap(), 0x400200);
}

#[tokio::test]
async fn convert_address_default_base_used() {
    let v = json_of(
        &call(&ConvertAddressTool, json!({"address": 0x400010u64})).await,
    );
    assert_eq!(v["base"].as_u64().unwrap(), 0x400000);
    assert_eq!(v["rva"].as_u64().unwrap(), 0x10);
}

#[tokio::test]
async fn convert_address_missing_both_errors() {
    let r = ConvertAddressTool.call(json!({"base": 0u64})).await;
    assert!(r.is_err());
}

// --- SectionDumpTool -------------------------------------------------------

#[tokio::test]
async fn section_dump_basic_slice() {
    let data: Vec<u8> = (0..16u8).collect();
    let v = json_of(
        &call(
            &SectionDumpTool,
            json!({"bytes": data.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "offset": 4, "length": 4}),
        )
        .await,
    );
    assert_eq!(v["offset"].as_u64().unwrap(), 4);
    assert_eq!(v["length"].as_u64().unwrap(), 4);
    assert_eq!(v["hex"].as_str().unwrap().to_uppercase(), "04050607");
}

#[tokio::test]
async fn section_dump_out_of_bounds_errors() {
    let r = SectionDumpTool
        .call(json!({"bytes": [0u8, 1, 2], "offset": 1, "length": 10}))
        .await;
    assert!(r.is_err());
}

#[tokio::test]
async fn section_dump_missing_length_errors() {
    let r = SectionDumpTool
        .call(json!({"bytes": [0u8, 1, 2], "offset": 0}))
        .await;
    assert!(r.is_err());
}

// --- XorDecryptTool --------------------------------------------------------

#[tokio::test]
async fn xor_decrypt_single_byte_key_roundtrip() {
    let plain = b"hello";
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5A).collect();
    let v = json_of(
        &call(
            &XorDecryptTool,
            json!({"bytes": cipher.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "key": 0x5Au64}),
        )
        .await,
    );
    let out: Vec<u8> = v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(out, plain);
}

#[tokio::test]
async fn xor_decrypt_multi_byte_key_hex() {
    let plain = b"abcd";
    let key = [0x11u8, 0x22];
    let cipher: Vec<u8> = plain
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 2])
        .collect();
    let v = json_of(
        &call(
            &XorDecryptTool,
            json!({"bytes": cipher.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "key_hex": "1122"}),
        )
        .await,
    );
    let out: Vec<u8> = v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(out, plain);
}

#[tokio::test]
async fn xor_decrypt_missing_key_errors() {
    let r = XorDecryptTool.call(json!({"bytes": [0u8]})).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn xor_decrypt_key_out_of_range_errors() {
    let r = XorDecryptTool
        .call(json!({"bytes": [0u8], "key": 500u64}))
        .await;
    assert!(r.is_err());
}

// --- RotDecryptTool --------------------------------------------------------

#[tokio::test]
async fn rot_decrypt_rot13_default() {
    let v = json_of(&call(&RotDecryptTool, json!({"text": "Hello"})).await);
    assert_eq!(v["result"].as_str().unwrap(), "Uryyb");
    assert_eq!(v["n"].as_u64().unwrap(), 13);
}

#[tokio::test]
async fn rot_decrypt_custom_n_and_preserves_non_alpha() {
    let v = json_of(
        &call(&RotDecryptTool, json!({"text": "ABC xyz!", "n": 1u64})).await,
    );
    assert_eq!(v["result"].as_str().unwrap(), "BCD yza!");
}

#[tokio::test]
async fn rot_decrypt_missing_text_errors() {
    let r = RotDecryptTool.call(json!({})).await;
    assert!(r.is_err());
}

// --- ImportExportTool ------------------------------------------------------

#[tokio::test]
async fn import_export_extracts_symbol_like_strings() {
    let mut d = Vec::new();
    d.extend_from_slice(b"\x00CreateFileA\x00ExitProcess\x00 spacey words \x00");
    let v = json_of(&call(&ImportExportTool, bytes_arg(&d)).await);
    let syms: Vec<String> = v["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(syms.iter().any(|s| s == "CreateFileA"));
    assert!(syms.iter().any(|s| s == "ExitProcess"));
    assert!(!syms.iter().any(|s| s.contains(' ')));
}

// --- ToolRegistry ----------------------------------------------------------

#[test]
fn tool_registry_new_is_empty() {
    let r = ToolRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.list().is_empty());
}

#[test]
fn tool_registry_default_equals_new() {
    let r: ToolRegistry = ToolRegistry::default();
    assert!(r.is_empty());
}

#[tokio::test]
async fn tool_registry_register_and_get() {
    let mut r = ToolRegistry::new();
    r.register(HexDumpTool::definition(), Box::new(HexDumpTool));
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
    assert_eq!(r.list(), vec!["hexdump"]);
    let h = r.get("hexdump").expect("registered");
    let out = h.call(bytes_arg(b"A")).await.unwrap();
    assert!(text_of(&out).contains("41"));
    assert!(r.get("nope").is_none());
}

#[test]
fn register_all_tools_populates_registry() {
    let r = register_all_tools();
    assert!(r.len() >= 12);
    for must in [
        "hexdump",
        "search_bytes",
        "hash",
        "entropy",
        "string_decode",
        "patch_analyzer",
    ] {
        assert!(r.list().contains(&must), "missing {must}");
    }
}

#[test]
fn register_extended_tools_superset_of_all_tools() {
    let base = register_all_tools().len();
    let ext = register_extended_tools().len();
    assert!(ext > base);
    let ext = register_extended_tools();
    let names: Vec<&str> = ext.list();
    for must in ["md5", "crc32", "demangle", "xor_decrypt", "rot_decrypt", "binary_diff"] {
        assert!(names.contains(&must), "missing {must}");
    }
}

#[test]
fn register_advanced_tools_nonempty() {
    let r = register_advanced_tools();
    assert!(!r.is_empty());
}

#[test]
fn register_all_advanced_tools_superset_of_advanced() {
    let base = register_advanced_tools().len();
    let combined = register_all_advanced_tools().len();
    assert!(combined >= base);
}

// --- SpecToolRegistry + McpTool trait --------------------------------------

#[test]
fn spec_registry_default_is_empty() {
    let r = SpecToolRegistry::default();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[tokio::test]
async fn spec_registry_add_and_lookup_hexdump() {
    let mut r = SpecToolRegistry::new();
    r.add(Box::new(HexdumpTool));
    r.add(Box::new(EntropySpecTool));
    r.add(Box::new(HashSpecTool));
    r.add(Box::new(StringsTool));
    r.add(Box::new(Base64Tool));
    assert_eq!(r.len(), 5);
    assert!(!r.is_empty());
    let listed = r.list();
    for n in ["hexdump", "entropy", "hash", "strings", "base64"] {
        assert!(listed.contains(&n), "missing {n}");
    }
    let t = r.get("hexdump").expect("present");
    let out = t
        .invoke(ToolInput::new("hexdump", bytes_arg(b"AB")))
        .await
        .unwrap();
    assert!(out.success);
    assert!(out.data.as_str().unwrap().contains("41 42"));
    assert!(r.get("missing").is_none());
}

#[tokio::test]
async fn spec_hexdump_missing_bytes_returns_invalid_input() {
    let err = HexdumpTool
        .invoke(ToolInput::new("hexdump", json!({})))
        .await
        .unwrap_err();
    match err {
        ToolError::InvalidInput(_) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
async fn spec_hexdump_bad_byte_value_returns_invalid_input() {
    let err = HexdumpTool
        .invoke(ToolInput::new("hexdump", json!({"bytes": [9999u64]})))
        .await
        .unwrap_err();
    matches!(err, ToolError::InvalidInput(_));
}

#[tokio::test]
async fn spec_entropy_rates_constant_low() {
    let out = EntropySpecTool
        .invoke(ToolInput::new("entropy", bytes_arg(&vec![0u8; 32])))
        .await
        .unwrap();
    assert_eq!(out.data["entropy"].as_f64().unwrap(), 0.0);
    assert_eq!(out.data["rating"].as_str().unwrap(), "low");
}

#[tokio::test]
async fn spec_entropy_rates_uniform_high() {
    let data: Vec<u8> = (0..=255u8).collect();
    let out = EntropySpecTool
        .invoke(ToolInput::new("entropy", bytes_arg(&data)))
        .await
        .unwrap();
    // Spec rating tops out at "high" (>7.5).
    assert_eq!(out.data["rating"].as_str().unwrap(), "high");
}

#[tokio::test]
async fn spec_hash_known_vector_abc() {
    let out = HashSpecTool
        .invoke(ToolInput::new("hash", bytes_arg(b"abc")))
        .await
        .unwrap();
    assert_eq!(
        out.data["sha256"].as_str().unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        out.data["md5"].as_str().unwrap(),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(out.data["size"].as_u64().unwrap(), 3);
}

#[tokio::test]
async fn spec_strings_default_min_len() {
    let mut d = Vec::new();
    d.extend_from_slice(b"\x00hello\x00hi\x00longer_string\x00");
    let out = StringsTool
        .invoke(ToolInput::new("strings", bytes_arg(&d)))
        .await
        .unwrap();
    let strs: Vec<String> = out.data["strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(strs.iter().any(|s| s == "hello"));
    // "hi" is below the default min_len of 4
    assert!(!strs.iter().any(|s| s == "hi"));
}

#[tokio::test]
async fn spec_strings_custom_min_len() {
    let mut d = Vec::new();
    d.extend_from_slice(b"\x00hi\x00ok\x00\x00");
    let out = StringsTool
        .invoke(ToolInput::new(
            "strings",
            json!({"bytes": d.iter().map(|&b| u64::from(b)).collect::<Vec<_>>(),
                   "min_len": 2u64}),
        ))
        .await
        .unwrap();
    let n = out.data["count"].as_u64().unwrap();
    assert!(n >= 2);
}

#[tokio::test]
async fn spec_base64_encode_known_vector() {
    let out = Base64Tool
        .invoke(ToolInput::new("base64", bytes_arg(b"Man")))
        .await
        .unwrap();
    assert_eq!(out.data.as_str().unwrap(), "TWFu");
}

#[tokio::test]
async fn spec_base64_encode_padding() {
    let out = Base64Tool
        .invoke(ToolInput::new("base64", bytes_arg(b"Ma")))
        .await
        .unwrap();
    assert_eq!(out.data.as_str().unwrap(), "TWE=");
}

#[tokio::test]
async fn spec_base64_decode_roundtrip() {
    let encoded = Base64Tool
        .invoke(ToolInput::new("base64", bytes_arg(b"hello")))
        .await
        .unwrap();
    let s = encoded.data.as_str().unwrap().to_string();
    let decoded = Base64Tool
        .invoke(ToolInput::new(
            "base64",
            json!({"op": "decode", "input": s}),
        ))
        .await
        .unwrap();
    let bytes: Vec<u8> = decoded.data["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn spec_base64_decode_bad_char_errors() {
    let err = Base64Tool
        .invoke(ToolInput::new(
            "base64",
            json!({"op": "decode", "input": "!!!!"}),
        ))
        .await
        .unwrap_err();
    matches!(err, ToolError::InvalidInput(_));
}

#[tokio::test]
async fn spec_base64_decode_missing_input_errors() {
    let err = Base64Tool
        .invoke(ToolInput::new("base64", json!({"op": "decode"})))
        .await
        .unwrap_err();
    matches!(err, ToolError::InvalidInput(_));
}

// --- name() consistency on McpTool impls ----------------------------------

#[test]
fn spec_tools_report_expected_names() {
    assert_eq!(HexdumpTool.name(), "hexdump");
    assert_eq!(EntropySpecTool.name(), "entropy");
    assert_eq!(HashSpecTool.name(), "hash");
    assert_eq!(StringsTool.name(), "strings");
    assert_eq!(Base64Tool.name(), "base64");
}

// --- Send + Sync bound for the McpTool trait ------------------------------

#[test]
fn mcp_tool_trait_object_is_send_sync() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn McpTool>();
    assert_send_sync::<dyn ToolHandler>();
}

// --- runtime: triage_entropy_packing_indicators with `path` parameter -----

/// Build a minimal valid PE32+ on disk with `n` import descriptors, then call
/// `TriageEntropyPackingIndicatorsTool` via the `ToolHandler` trait with a
/// `path` argument. Asserts that the handler walks the *real* PE import
/// directory and does NOT emit "Few imports (<5)" when n >= 5.
#[tokio::test]
async fn triage_entropy_packing_indicators_via_path_counts_real_imports() {
    // Build the PE bytes (mirrors `make_pe_with_imports` from
    // rustre-triage-entropy's unit tests).
    let n_imports: usize = 20;
    let mut buf = vec![0u8; 0x2000];
    buf[0..2].copy_from_slice(b"MZ");
    let e_lfanew = 0x80u32;
    buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe = e_lfanew as usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
    let opt = pe + 24;
    buf[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    let section_va: u32 = 0x1000;
    let section_raw: u32 = 0x200;
    let import_rva = section_va;
    buf[opt + 120..opt + 124].copy_from_slice(&import_rva.to_le_bytes());
    buf[opt + 124..opt + 128]
        .copy_from_slice(&(((n_imports + 1) * 20) as u32).to_le_bytes());
    let sec = opt + 240;
    buf[sec..sec + 8].copy_from_slice(b".idata\0\0");
    buf[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes());
    buf[sec + 12..sec + 16].copy_from_slice(&section_va.to_le_bytes());
    buf[sec + 16..sec + 20].copy_from_slice(&0x800u32.to_le_bytes());
    buf[sec + 20..sec + 24].copy_from_slice(&section_raw.to_le_bytes());
    for i in 0..n_imports {
        let off = section_raw as usize + i * 20;
        buf[off..off + 4].copy_from_slice(
            &((section_va + 0x400) + i as u32 * 4).to_le_bytes(),
        );
        let name_rva: u32 = section_va + 0x200 + (i as u32) * 16;
        buf[off + 12..off + 16].copy_from_slice(&name_rva.to_le_bytes());
    }
    let path = std::env::temp_dir().join("rustre_mcp_tools_packing_indicators_runtime.bin");
    std::fs::write(&path, &buf).unwrap();

    let handler = rustre_mcp_tools::tools::triage_entropy::TriageEntropyPackingIndicatorsTool;
    let res = call(&handler, json!({ "path": path.to_str().unwrap() })).await;
    let v = json_of(&res);
    let inds = v
        .get("indicators")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !inds.iter().any(|s| s.as_str().is_some_and(|t| t.contains("Few imports"))),
        "handler with `path` must walk real import table and not flag Few imports; got: {inds:?}"
    );

    let _ = std::fs::remove_file(&path);
}
