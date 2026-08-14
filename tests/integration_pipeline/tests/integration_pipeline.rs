//! End-to-end integration tests for the RustRE pipeline:
//! core (binary bytes) -> loader -> analysis (CFG) -> decompiler -> mcp.
//!
//! These tests intentionally use ONLY the public APIs exported by each
//! crate's `lib.rs`. They are designed to lock in the integration contracts
//! between layers and to ensure the pipeline can be exercised end-to-end
//! without touching private implementation details.
//!
//! ## What is covered
//! 1. Raw bytes -> `RawBinaryLoader` (a tiny x86 `push rbp; mov rbp,rsp; ret`).
//! 2. Architecture auto-detection from raw content.
//! 3. CFG analysis (basic-block splitting + dominator tree) on a synthetic
//!    LLIL instruction stream representing a single function body.
//! 4. Decompiler stub via `DecompiledFunction` / `DecompilerContext`
//!    (the publicly exposed builder surface).
//! 5. MCP tool invocation via `rustre_mcp_tools::tool_executor::ToolExecutor`
//!    against a built-in tool (`list_functions`).
//!
//! ## What is NOT covered (and why)
//! - We do NOT construct a full `rustre_core::binary_view::BinaryView` because
//!   that requires an `Arc<dyn Architecture>` trait object, and the concrete
//!   architecture handles are not re-exported as constructors from
//!   `rustre-core`. Building one would require touching crate internals.
//! - We do NOT exercise PE/ELF loaders because crafting a header-valid blob
//!   that survives `goblin`/`pelite` parsing is out of scope for a smoke test;
//!   `RawBinaryLoader::load_bytes` is the canonical "any-bytes" entry point.
//! - We do NOT invoke the full `DecompilerPipeline::run` because it requires
//!   a populated `BinaryView` (see above). We exercise the publicly available
//!   `DecompilerContext` / `DecompiledFunction` builder API instead, which is
//!   the same surface the pipeline produces.
//! - We do NOT exercise tools that require a `BinaryView` in `ExecutionContext`
//!   (e.g. real `disassemble_at`). The built-in MCP tools in
//!   `rustre_mcp_tools::builtin_tools` are self-contained (they synthesize
//!   responses), which is exactly what we want for a wiring test.

use std::sync::Arc;

use rustre_analysis_cfg::{DominatorTree, compute_leaders, split_basic_blocks};
use rustre_core::address::Address;
use rustre_decompiler::{
    DecompOptions, DecompVariable, DecompilerContext, DecompiledFunction, IrLevel, VarStorage,
};
use rustre_il_llil::LlilInstruction;
use rustre_loader::raw_binary_loader::{
    ArchHint, LoadConfig, RawBinaryLoader, detect_arch_from_content,
};
use rustre_mcp_tools::builtin_tools::ListFunctionsTool;
use rustre_mcp_tools::tool_executor::{ToolExecutor, ToolHandler, ToolInvocation};
use serde_json::json;

/// `push rbp; mov rbp, rsp; ret` — minimal x86-64 function body.
const TINY_X86_FN: &[u8] = &[0x55, 0x48, 0x89, 0xE5, 0xC3];

// ─── Step 1: loader ───────────────────────────────────────────────────────────

#[test]
fn step1_raw_loader_loads_tiny_x86_blob() {
    // Drive the loader with x86_64 config and a known base address.
    let loader = RawBinaryLoader::new();
    let cfg = LoadConfig::x86_64(0x4000);
    let loaded = loader.load(TINY_X86_FN, &cfg);

    // The loader must accept the bytes and expose them at the configured base.
    assert_eq!(loaded.size(), TINY_X86_FN.len(), "size mismatch");
    assert_eq!(
        loaded.read_u8(0x4000),
        Some(0x55),
        "first byte (push rbp) must be readable at base"
    );
    assert_eq!(
        loaded.read_u8(0x4000 + (TINY_X86_FN.len() as u64) - 1),
        Some(0xC3),
        "last byte (ret) must be readable at base+len-1"
    );
    // Anything outside the loaded region is unreadable.
    assert_eq!(loaded.read_u8(0xDEAD_BEEF), None);
}

// ─── Step 2: arch detection ───────────────────────────────────────────────────

#[test]
fn step2_arch_detection_on_raw_bytes() {
    // The pure-bytes detector cannot magically recognise x86 from 5 bytes,
    // but the public API must at least classify it without panicking and
    // return a valid `ArchHint` variant.
    let hint = detect_arch_from_content(TINY_X86_FN);
    let s = hint.as_str();
    let known = matches!(
        hint,
        ArchHint::X86
            | ArchHint::X86_64
            | ArchHint::Arm
            | ArchHint::Arm64
            | ArchHint::Mips
            | ArchHint::Z80
            | ArchHint::Avr
            | ArchHint::Raw
    );
    assert!(known, "unknown ArchHint variant: {s}");
    // Empty content must still be classified (Raw fallback).
    let empty = detect_arch_from_content(&[]);
    assert!(matches!(empty, ArchHint::Raw));
}

// ─── Step 3: analysis (CFG on a synthetic function body) ─────────────────────

#[test]
fn step3_cfg_basic_block_split_and_dominators() {
    // Construct a synthetic LLIL stream: three Nop instructions followed by a
    // terminating Ret. The CFG splitter must produce exactly one basic block
    // covering all four instructions.
    let instrs: Vec<(Address, LlilInstruction)> = vec![
        (Address(0x1000), LlilInstruction::Nop),
        (Address(0x1001), LlilInstruction::Nop),
        (Address(0x1002), LlilInstruction::Nop),
        (Address(0x1003), LlilInstruction::Ret),
    ];

    // `compute_leaders` must identify the entry as a leader.
    let leaders = compute_leaders(&instrs);
    assert!(
        leaders.contains(&Address(0x1000)),
        "entry address must be a leader"
    );

    // `split_basic_blocks` must yield at least one block, starting at entry.
    let blocks = split_basic_blocks(&instrs);
    assert!(!blocks.is_empty(), "expected at least one basic block");
    assert!(
        blocks.contains_key(&Address(0x1000)),
        "block table must be keyed by leader address"
    );

    // Dominator tree on a single-block CFG: the entry dominates itself and has
    // no proper dominator.
    let entry = Address(0x1000);
    let edges: Vec<rustre_analysis_cfg::CfgEdge> = Vec::new();
    let dom = DominatorTree::compute(&blocks, &edges, entry);
    // The entry must appear in the idom map (mapped to None — dominates self).
    assert!(
        dom.idom.contains_key(&entry),
        "dominator tree missing entry block"
    );
    assert_eq!(
        dom.idom.get(&entry),
        Some(&None),
        "entry node must have no proper dominator"
    );
}

// ─── Step 4: decompiler stub ──────────────────────────────────────────────────

#[test]
fn step4_decompiler_context_builds_function() {
    // Exercise the public `DecompilerContext` builder surface — the same
    // surface the full `DecompilerPipeline` produces a `DecompiledFunction`
    // through.
    let opts = DecompOptions::default();
    let mut ctx = DecompilerContext::new(0x4000, "tiny_fn", opts);
    ctx.advance_ir_level(IrLevel::Llil);
    ctx.emit_line("int tiny_fn(void) {");
    ctx.emit_line("    return 0;");
    ctx.emit_line("}");
    ctx.add_variable(DecompVariable {
        name: "rax".to_string(),
        type_str: "int".to_string(),
        is_parameter: false,
        storage: VarStorage::Register("rax".to_string()),
    });
    ctx.add_call_site(0x4010);
    ctx.annotate("origin", "integration-test");

    let decompiled: DecompiledFunction = ctx.finish();
    assert_eq!(decompiled.address, 0x4000);
    assert_eq!(decompiled.name, "tiny_fn");
    assert!(
        decompiled.line_count() >= 3,
        "expected at least 3 lines of pseudo-code, got {}",
        decompiled.line_count()
    );
    // The standalone builder constructor must also work.
    let direct = DecompiledFunction::new(0x5000, "other", "return 1;")
        .with_confidence(80)
        .with_call_site(0x5040);
    assert_eq!(direct.address, 0x5000);
    assert_eq!(direct.name, "other");
}

// ─── Step 5: MCP tool invocation ──────────────────────────────────────────────

#[test]
fn step5_mcp_executor_runs_builtin_tool() {
    // Build an executor and register a built-in tool. `ListFunctionsTool`
    // is self-contained (synthesizes a list of functions) and does not
    // require a populated BinaryView, so it is suitable as a pipeline
    // smoke test of the MCP layer.
    let mut exec = ToolExecutor::new();
    let tool: Arc<dyn ToolHandler> = Arc::new(ListFunctionsTool);
    let tool_name = tool.name().to_string();
    exec.register(tool);

    assert!(exec.has_tool(&tool_name), "tool should be registered");

    let invocation = ToolInvocation::new(&tool_name, json!({})).with_id("itest");
    let result = exec.execute(invocation);

    assert!(
        result.success,
        "tool '{tool_name}' should succeed, got error: {:?}",
        result.error
    );
    assert!(
        result.result.is_some(),
        "successful tool must return a JSON payload"
    );
}
