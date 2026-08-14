export const meta = {
  name: 'integrate-dataflow-vsa-vtable-into-decompiler',
  description: 'Wire rustre-analysis-dataflow, -vsa, -vtable into rustre-decompiler orchestrator. Additive changes only — no logic rewrite.',
  phases: [
    { title: 'PrepDeps', detail: 'add 3 deps to rustre-decompiler/Cargo.toml' },
    { title: 'PipelineHooks', detail: 'add integration hook fns to rustre-decompiler/src/lib.rs (additive, behind opts flags)' },
    { title: 'Build', detail: 'cargo build --release iterative fix' },
    { title: 'VerifyDecompile', detail: 'call decompile_function via MCP, confirm no regressions + compute quality delta' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('PrepDeps')
const deps = await agent(
  `Add 3 dependencies to ${CWD}/crates/rustre-decompiler/Cargo.toml.
Steps:
1. Read the file.
2. Under [dependencies] section, after existing rustre-analysis-* entries, ADD (do not overwrite):
   \`\`\`toml
   rustre-analysis-dataflow = { path = "../rustre-analysis-dataflow" }
   rustre-analysis-vsa = { path = "../rustre-analysis-vsa" }
   rustre-analysis-vtable = { path = "../rustre-analysis-vtable", optional = true }
   \`\`\`
3. Add [features] section if not present:
   \`\`\`toml
   [features]
   default = []
   cpp_support = ["rustre-analysis-vtable"]
   \`\`\`
4. Verify with: cd ${CWD} && cargo check --release -p rustre-decompiler --message-format=short (Bash timeout 300000ms).

RULES: additive only, don't remove existing deps. Return JSON {deps_added:3, cargo_check_ok:bool, notes:string}.`,
  { label: 'prep-deps', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      deps_added:{type:'integer'},
      cargo_check_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('PipelineHooks')
const hooks = await agent(
  `Add integration hooks to ${CWD}/crates/rustre-decompiler/src/lib.rs. Additive only — do not modify existing pipeline logic.

Approach: add a new module \`analysis_bridge\` that exposes small helper functions the pipeline CAN call. Do not force them into the main decompile flow yet — expose them so the user can opt-in.

Steps:
1. Create a new file ${CWD}/crates/rustre-decompiler/src/analysis_bridge.rs with content:
   \`\`\`rust
   //! Analysis integration bridge — 2026-07-12.
   //!
   //! Thin adapters that expose rustre-analysis-{dataflow,vsa,vtable} to the
   //! decompiler pipeline. All fns here are ADDITIVE — they can be called
   //! opportunistically by the orchestrator but the main pipeline still works
   //! without them. This module exists to unblock future integration without
   //! rewriting the core decompile() logic.

   use rustre_analysis_dataflow as adf;
   use rustre_analysis_vsa as vsa;

   /// Placeholder: run dataflow reaching-definitions on a linear CFG.
   /// Returns the count of reaching-def sets computed. Callers can replace
   /// with a richer signature once the pipeline is wired.
   #[must_use]
   pub fn compute_reaching_defs_count() -> usize {
       // Zero-arg smoke call — chosen so the crate is genuinely linked.
       adf::linear_cfg_size()
   }

   /// Placeholder VSA smoke call. Returns 0 as a bottom valueset marker to
   /// prove the crate is linked. Replace with a real evaluation once callers exist.
   #[must_use]
   pub fn vsa_bottom_marker() -> u64 {
       let vs = vsa::ValueSet::bottom();
       vs.contains(0) as u64
   }

   #[cfg(feature = "cpp_support")]
   pub mod cpp {
       use rustre_analysis_vtable as vt;
       /// Placeholder vtable scan count when the cpp_support feature is on.
       #[must_use]
       pub fn vtable_pass_name() -> String {
           vt::pass_name()
       }
   }
   \`\`\`

2. In ${CWD}/crates/rustre-decompiler/src/lib.rs, add near the top (after other pub mod declarations):
   \`\`\`rust
   pub mod analysis_bridge;
   \`\`\`

3. VERY IMPORTANT: if any of the placeholder call signatures I wrote don't exist in the real crates (e.g. \`adf::linear_cfg_size()\`, \`vsa::ValueSet::bottom()\`, \`vt::pass_name()\`), replace them with the CLOSEST equivalent zero-arg / trivial call from the real API. Grep the target crates for pub fn to find real signatures. The goal is a compile-clean, zero-work smoke call per crate — proof of linkage, not a real pipeline yet.

4. cd ${CWD} && cargo check --release -p rustre-decompiler --message-format=short (Bash timeout 300000ms). Iterate fixes if errors — replace with real API calls that compile.

RULES: NEVER modify existing decompile logic. Never touch rustre-il-hlil / rustre-il-mlil / rustre-il-llil sources. Only ADD the new analysis_bridge.rs file and one pub mod line.

Return JSON {new_file_created:bool, cargo_check_ok:bool, api_adjustments:[string], notes:string}.`,
  { label: 'hooks', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      new_file_created:{type:'boolean'},
      cargo_check_ok:{type:'boolean'},
      api_adjustments:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['cargo_check_ok']
  }}
)

phase('Build')
const build = await agent(
  `Full release build.
1. taskkill /F /IM rustre-mcp.exe (ignore not found).
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server > /tmp/int3_build.log 2>&1 (Bash timeout 1800000ms).
3. Grep for errors. If any: iterate fixes on analysis_bridge.rs only.
Report {build_ok:bool, warnings:int, build_time_min:number, errors_if_any:[string]}.`,
  { label: 'build', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      build_ok:{type:'boolean'},
      warnings:{type:'integer'},
      build_time_min:{type:'number'},
      errors_if_any:{type:'array', items:{type:'string'}},
    },
    required:['build_ok']
  }}
)

phase('VerifyDecompile')
const verify = await agent(
  `Verify decompile_function still works AND the 3 new crates are now in the decompiler dep chain.

1. taskkill /F /IM rustre-mcp.exe.
2. Verify with cargo tree: cd ${CWD} && cargo tree -p rustre-decompiler --format "{p}" 2>&1 | grep -E "rustre-analysis-(dataflow|vsa|vtable)" (Bash timeout 60000ms). Should show all 3 (vtable only if cpp_support flag on — that's OK if absent).
3. Run exercise_v3: cd ${CWD}/validation && python3 exercise_v3.py > /tmp/int3_ex.log 2>&1 (Bash timeout 600000ms). Baseline before: 3705 OK. Expected after: 3705 or slightly higher (no drops).
4. Sample-invoke decompile_function via subprocess against ${CWD}/../Zyphora/target/release/cargo-zyphora.exe on address 0x140001000. Confirm pseudo_code is non-empty and has \`__int64\`, \`struct\`, JUMPOUT-style output.
5. Report {ok:int, tool_error:int, dep_chain_dataflow_present:bool, dep_chain_vsa_present:bool, dep_chain_vtable_optional:bool, decompile_function_works:bool, sample_confidence:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      dep_chain_dataflow_present:{type:'boolean'},
      dep_chain_vsa_present:{type:'boolean'},
      dep_chain_vtable_optional:{type:'boolean'},
      decompile_function_works:{type:'boolean'},
      sample_confidence:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'integration-complete', deps, hooks, build, verify }
