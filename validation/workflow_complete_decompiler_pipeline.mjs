export const meta = {
  name: 'complete-decompiler-mcp-pipeline',
  description: 'Add MCP tool wrappers for il_hlil, il_mlil, analysis_typerecov, analysis_cfg (expand), analysis_fn (expand), decompiler_expr. Goal: 100% pipeline visible via MCP (LLIL→MLIL→HLIL→C).',
  phases: [
    { title: 'AnalyzeAPIs', detail: 'read the public API of each target crate — list every pub fn/pub struct method wrapping-worthy' },
    { title: 'WriteWrappers', detail: 'generate 5 new tools/*.rs files with 10-20 wrappers each' },
    { title: 'WireOrchestrator', detail: 'add pub mod entries in tools/mod.rs + extend calls in wire_tools.rs' },
    { title: 'Build', detail: 'cargo build --release iteratively fix' },
    { title: 'Verify', detail: 'exercise_v3 + live MCP calls to newly-added tools + delta report' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const CRATE = `${CWD}/crates/rustre-mcp-tools`

const NEW_MODULES = [
  {
    file: 'il_hlil',
    crate: 'rustre-il-hlil',
    rust_import: 'rustre_il_hlil',
    n_tools: 15,
    hint: 'HLIL structuring layer: MlilBasicBlock → HlilStatement. Look for: HlilLifter, HlilBuilder, HlilStatement, HlilExpression, HlilStructurer, loop/if reconstruction, pseudo-C emission (that fills DecompiledFunction.hlil_pseudo_code). Wrappers should expose: lift_from_mlil, structure_analysis, get_pseudo_code, statement counts, expression tree walk, dominator info if present.',
  },
  {
    file: 'il_mlil',
    crate: 'rustre-il-mlil',
    rust_import: 'rustre_il_mlil',
    n_tools: 15,
    hint: 'MLIL layer: LLIL → MLIL lifting. Look for: MlilBasicBlock, MlilAnnotatedInstr, MlilInstruction::lift_llil, MlilExpression, register/stack promotion, SSA form. Wrappers should expose: lift_from_llil, basic_block_summary, annotated_instr_dump, ssa_state, expression_depth, register_reads_writes.',
  },
  {
    file: 'analysis_typerecov',
    crate: 'rustre-analysis-typerecov',
    rust_import: 'rustre_analysis_typerecov',
    n_tools: 12,
    hint: 'Type recovery: from access-size + usage patterns → concrete types. Look for: TypeRecovery, TypeInference, TypeFact, TypeLattice, TypePropagation, StructFieldDetector. Wrappers should expose: infer_from_access_size, propagate_types, get_type_at, list_facts, join_lattice, struct_layout_detect.',
  },
  {
    file: 'decompiler_expr',
    crate: 'rustre-decompiler-expr',
    rust_import: 'rustre_decompiler_expr',
    n_tools: 15,
    hint: 'Expression tree operations: simplification, folding, canonicalization. Look for: Expression, ExprSimplifier, ConstantFolder, ExprBuilder, ExprPrinter, BinaryOp, UnaryOp. Wrappers should expose: simplify_expr, fold_constants, expr_depth, expr_to_c_string, canonicalize, count_operations.',
  },
]

const EXPANDED_MODULES = [
  {
    file: 'analysis_cfg',
    crate: 'rustre-analysis-cfg',
    rust_import: 'rustre_analysis_cfg',
    n_tools: 18,
    hint: 'CFG has ~50 public APIs. Existing tools/analysis_cfg.rs has only 2. Add 18 more: dominator_tree, immediate_dominator, dominance_frontier, iterated_dominance_frontier, post_dominator_tree, back_edges, natural_loops, is_reducible, reachable_from, strictly_dominates, post_dominates, join_branch_count, cfg_stats_is_complex, cfg_stats_entry_exit_blocks, dot_export_annotated, full_json_export, scc_components, reverse_post_order.',
    additive: true,
  },
  {
    file: 'analysis_fn',
    crate: 'rustre-analysis-fn',
    rust_import: 'rustre_analysis_fn',
    n_tools: 10,
    hint: 'Function analysis under-used. Add: detect_functions_path, detect_extra_features, prologue_scan, function_boundary, split_by_call_targets, linear_sweep_functions, recursive_descent_functions, boundary_info, call_target_scan, cross_function_refs.',
    additive: true,
  },
]

phase('AnalyzeAPIs')
const analyze = await agent(
  `Read the public API of each target crate:
- ${CWD}/crates/rustre-il-hlil/src/lib.rs
- ${CWD}/crates/rustre-il-mlil/src/lib.rs
- ${CWD}/crates/rustre-analysis-typerecov/src/lib.rs
- ${CWD}/crates/rustre-decompiler-expr/src/lib.rs
- ${CWD}/crates/rustre-analysis-cfg/src/lib.rs
- ${CWD}/crates/rustre-analysis-fn/src/lib.rs

For each crate, list every wrapping-worthy public item:
- pub fn <name>(...) -> ...
- pub struct <Name> with pub methods (constructors + interesting queries)
- Ignore internal helpers, error types, and re-exports.

Filter to items that make sense to expose over MCP: those that take small serializable inputs (bytes, hex, address, integer, string) and produce serializable output (JSON-able structs, numbers, strings, arrays).

Write manifest to ${CWD}/validation/decompiler_pipeline_api.json:
{
  "il_hlil": [{"name":"...", "signature":"...", "wrapper_name":"IlHlilXxxTool"}],
  "il_mlil": [...],
  "analysis_typerecov": [...],
  "decompiler_expr": [...],
  "analysis_cfg_extra": [...],
  "analysis_fn_extra": [...]
}
Aim for ~15 per crate.

RULES: read-only, no modifications yet.
Return JSON {crates_analyzed:6, total_wrappers_planned:int, manifest_file:string, notes:string}.`,
  { label: 'analyze-apis', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      crates_analyzed:{type:'integer'},
      total_wrappers_planned:{type:'integer'},
      manifest_file:{type:'string'},
      notes:{type:'string'},
    },
    required:['crates_analyzed']
  }}
)

phase('WriteWrappers')
const write = await agent(
  `Write the MCP wrapper files based on ${CWD}/validation/decompiler_pipeline_api.json.

For each of 4 NEW modules (il_hlil, il_mlil, analysis_typerecov, decompiler_expr):
1. Create ${CRATE}/src/tools/<module>.rs.
2. Header:
   \`\`\`rust
   //! MCP wrappers for the rustre-<module-dashed> crate.
   //! Manually authored 2026-07-12 to close the decompiler pipeline gap.

   use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
   use serde_json::{json, Value};
   use async_trait::async_trait;
   \`\`\`
3. For EACH wrapper in the manifest for that module, emit a compressed 2-line pattern:
   \`\`\`rust
   pub struct <WrapperName>;
   impl <WrapperName> { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "<snake_name>".to_string(), description: "<short desc>".to_string(), input_schema: json!({...}), parameters: Value::Null } } }
   #[async_trait::async_trait] impl ToolHandler for <WrapperName> { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { <body: call underlying crate fn and return json>  } }
   \`\`\`
4. At end of file:
   \`\`\`rust
   pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
       vec![
           (<WrapperName>::definition(), Box::new(<WrapperName>)),
           ...
       ]
   }
   \`\`\`

For 2 EXPANDED modules (analysis_cfg, analysis_fn):
- APPEND new wrappers to existing files (don't overwrite existing ones).
- Update existing handlers() vec to include new entries.

Also update ${CRATE}/Cargo.toml — ensure these deps are present (add if missing, un-comment if commented):
  rustre-il-hlil, rustre-il-mlil (they should already exist as workspace members).

Return JSON {files_created:4, files_expanded:2, total_new_wrappers:int, cargo_deps_added:[string], notes:string}.`,
  { label: 'write-wrappers', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_created:{type:'integer'},
      files_expanded:{type:'integer'},
      total_new_wrappers:{type:'integer'},
      cargo_deps_added:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['files_created']
  }}
)

phase('WireOrchestrator')
const wire = await agent(
  `Wire the new tool modules into the MCP server.

1. Read ${CRATE}/src/tools/mod.rs. Add:
   \`\`\`rust
   pub mod il_hlil;
   pub mod il_mlil;
   pub mod analysis_typerecov;
   pub mod decompiler_expr;
   \`\`\`
   (analysis_cfg and analysis_fn already have mod entries)

2. Read ${CRATE}/src/wire_tools.rs. Find \`pub fn all_wire_handlers()\`. Add \`all.extend(crate::tools::<x>::handlers());\` for each of the 4 new modules. Do NOT duplicate for analysis_cfg / analysis_fn if they already have extend calls.

3. cd ${CWD} && cargo check --release -p rustre-mcp-tools --message-format=short (Bash timeout 900000ms). Iterate fixes if errors.

Return JSON {mod_entries_added:int, extend_calls_added:int, cargo_check_ok:bool, errors_final:int, notes:string}.`,
  { label: 'wire', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      mod_entries_added:{type:'integer'},
      extend_calls_added:{type:'integer'},
      cargo_check_ok:{type:'boolean'},
      errors_final:{type:'integer'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Build')
const build = await agent(
  `Full release build.
cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server > /tmp/pipeline_build.log 2>&1 (Bash timeout 1800000ms).
If errors: iterate up to 5 rounds. Never touch the target crate SOURCES (rustre-il-hlil, rustre-il-mlil, rustre-analysis-typerecov, rustre-decompiler-expr, rustre-analysis-cfg, rustre-analysis-fn) — only the wrapper file. If a wrapper calls a non-existent function, correct the wrapper (probably needs a different function name).
Report {build_ok:bool, iterations:int, warnings:int, build_time_min:number}.`,
  { label: 'build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      iterations:{type:'integer'},
      warnings:{type:'integer'},
      build_time_min:{type:'number'},
    },
    required:['build_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Verify the new pipeline coverage.
1. taskkill /F /IM rustre-mcp.exe; sleep 2.
2. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/pipeline_ex.log 2>&1 (Bash timeout 600000ms).
3. Parse FINAL. Baseline before: 3705 OK. Expected after: ~3775-3820 OK (drop-in of ~70-115 new tools).
4. Sample-invoke via subprocess a few of the newly added tools directly, verify they return non-error results:
   - il_mlil_lift_from_llil (or similar name from manifest)
   - il_hlil_get_pseudo_code (or similar)
   - analysis_typerecov_infer_from_access_size (or similar)
   - analysis_cfg_dominator_tree (or similar)
5. Report {ok:int, tool_error:int, delta_from_baseline:int, new_tools_sampled:int, new_tools_ok:int, new_tools_errored:[string], verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      delta_from_baseline:{type:'integer'},
      new_tools_sampled:{type:'integer'},
      new_tools_ok:{type:'integer'},
      new_tools_errored:{type:'array', items:{type:'string'}},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'pipeline-complete', analyze, write, wire, build, verify }
