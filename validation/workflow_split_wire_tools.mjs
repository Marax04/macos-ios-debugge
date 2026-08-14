export const meta = {
  name: 'split-wire-tools-monolith',
  description: 'Split 5.5MB / 91k-line wire_tools.rs (3914 tools) into ~80 per-crate files under tools/. Verify compile.',
  phases: [
    { title: 'Catalog', detail: 'parse wire_tools.rs, produce {crate_prefix -> [tool struct blocks]} manifest' },
    { title: 'Split', detail: 'generate tools/*.rs files + slim wire_tools.rs orchestrator' },
    { title: 'BuildAndFix', detail: 'cargo build --release, fix compile errors iteratively' },
    { title: 'Verify', detail: 'confirm tool count matches pre-split (~3914) and MCP works' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const CRATE = `${CWD}/crates/rustre-mcp-tools`
const FILE = `${CRATE}/src/wire_tools.rs`
const TOOLS_DIR = `${CRATE}/src/tools`

const COMPOUND_PREFIXES = [
  'il_lift','pe_editor','arch_wasm','symb_z3','emu_unicorn','dotnet_edit','dotnet_metadata',
  'triage_entropy','triage_die','ti_misp','ti_malpedia','ti_vt','ti_opencti','ti_otx',
  'decomp2','decompiler_type','hex_pattern','hex_template','hex_tplx','hex_tply','hex_view',
  'trace_navigate','trace_coverage','trace_pt','trace_cov','debug_macos','debug_unicorn',
  'debug_windows','debug_windbg','fuzz_cov','fuzz_afl','fuzz_libfuzzer','fuzz_net','fuzz_san',
  'forensics_fs','forensics_mem','rs_sym','rustre_symb','rustre_symbols_core',
  'rustre_symbols_ext','rustre_symbols_v3','rustre_decompiler','rustre_vsa','rustre_analysis',
  'arch_x86','arch_riscv','arch_sparc','arch_mips','arch_z80','arch_avr','arch_msp430',
  'arch_ppc','arch_arm','arch_arm64','arch_m68k','arch_bpf','arch_lua','arch_luajit',
  'arch_jvm','arch_dex','arch_cil','arch_6502','arch_68k',
  'script_lua','script_python','script_rhai','an_cfg','analysis_cfg','ghidra_pcode',
  'ghidra_backend','ttd_query','ttd_recorder','ttd_replay','ttd_replayer',
  'net_dns','net_dissect','net_pcap','net_proxy','net_rules',
  'mem_diff','mem_ma','mem_kx7','mobile_apktool','mobile_dyld','mobile_ios','mobile_ipa',
  'mobile_jadx','mobile_smali','sandbox_report','symbols_pdb','symbols_v6','symbols_v7',
  'symbols_stabs','syscalls_linux','syscalls_windows','threatintel_group',
  'threatintel_indicator','threatintel_ioc','flirt_apply','flirt_gen','il_passes','il_llil',
  'rlib_dec','rlib_dec2','db_base_migrations'
]

phase('Catalog')
const catalog = await agent(
  `Analyze ${FILE} (91k lines, 5.5MB, ~3914 pub struct XxxTool declarations).
Write a Python script at ${CWD}/validation/catalog_wire_tools.py that:
1. Reads the file line by line.
2. Finds every line starting with 'pub struct ' AND ending with 'Tool;'. Extracts the name (without 'Tool;' suffix).
3. Also extracts the following block for each tool:
   - the impl <Name>Tool { ... definition() ... } line (usually 1 line right after)
   - the #[async_trait::async_trait] impl ToolHandler for <Name>Tool { ... } line (usually the next line)
   - Blank line separator
4. Converts CamelCase name to snake_case (e.g. DeobfCrc32ChecksumTool -> deobf_crc32_checksum).
5. Determines crate prefix:
   - If snake_case starts with any of these COMPOUND prefixes (2+ tokens), use the compound prefix:
   ${JSON.stringify(COMPOUND_PREFIXES)}
   - Otherwise, use the FIRST underscore-token as prefix.
6. Groups tools by prefix. Writes JSON manifest to ${CWD}/validation/wire_tools_catalog.json:
   {
     "total_tools": N,
     "prefixes": {
       "deobf": {"count": 14, "tools":[{"name":"DeobfCrc32ChecksumTool","start_line":7,"end_line":8}, ...]},
       "il_lift": {"count": 146, ...},
       ...
     }
   }
7. Also keeps the ORCHESTRATOR portion (from line where 'pub fn all_wire_handlers' appears onward) — save it verbatim to ${CWD}/validation/wire_tools_orchestrator_original.txt.

Run the script. Verify total_tools ~= 3914.

Return JSON {total_tools:int, prefixes_count:int, top_10_prefixes:[{prefix,count}], catalog_file:string, orchestrator_saved:bool}.`,
  { label: 'catalog', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_tools:{type:'integer'},
      prefixes_count:{type:'integer'},
      top_10_prefixes:{type:'array',items:{type:'object'}},
      catalog_file:{type:'string'},
      orchestrator_saved:{type:'boolean'},
    },
    required:['total_tools']
  }}
)

phase('Split')
const split = await agent(
  `Split ${FILE} into per-crate sub-modules under ${TOOLS_DIR}/, using the catalog at ${CWD}/validation/wire_tools_catalog.json.

Write and run ${CWD}/validation/do_split_wire_tools.py that:
1. Read the catalog.
2. Read the entire ${FILE} into memory as a list of lines.
3. Create directory ${TOOLS_DIR}/.
4. For each prefix group:
   a. Create ${TOOLS_DIR}/<prefix>.rs.
   b. Write header:
      //! MCP wrappers for the rustre-<prefix> crate.
      //! Extracted from wire_tools.rs by workflow_split_wire_tools.

      use rustre_mcp_server::{ToolDefinition, ToolHandler};
      use serde_json::json;
   c. For each tool in group, copy verbatim the lines from start_line to end_line (which include the 3 lines of struct+impl+impl-handler), and a blank line.
   d. At end of file:
      pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
          vec![
              (DeobfCrc32ChecksumTool::definition(), Box::new(DeobfCrc32ChecksumTool)),
              // ... one per tool
          ]
      }
5. Create ${TOOLS_DIR}/mod.rs with:
   //! MCP tool sub-modules, one per rustre-* crate.
   pub mod deobf;
   pub mod il_lift;
   ... (all prefixes, sorted alphabetically)
6. Rewrite ${FILE} with slim orchestrator:
   //! Cross-cutting MCP tool wrappers — orchestrator.
   //! The actual tools live under crate::tools::<prefix>.

   use rustre_mcp_server::{ToolDefinition, ToolHandler, RustReMcpServer};

   pub fn all_wire_handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
       let mut all = Vec::new();
       all.extend(crate::tools::deobf::handlers());
       all.extend(crate::tools::il_lift::handlers());
       // ... one per prefix
       all
   }

   pub fn wire_into_server(server: &mut RustReMcpServer) {
       for (def, handler) in all_wire_handlers() {
           // preserve the exact registration call the original used — look at the original wire_into_server body in wire_tools_orchestrator_original.txt and mirror it
           let _ = server;
           let _ = def;
           let _ = handler;
       }
   }
7. Preserve any OTHER pub fn from wire_tools_orchestrator_original.txt that is not all_wire_handlers/wire_into_server — append them verbatim at the bottom of the new wire_tools.rs.
8. Add pub mod tools; to ${CRATE}/src/lib.rs (right after existing mod declarations, once — check idempotently).

RULES:
- Do NOT rename or reformat any struct or impl body.
- Preserve compressed 2-line format inside per-crate files.
- Use Python — mechanical text extraction, not LLM inference.
- If a tool struct spans MORE than 3 lines (unusual), copy all of them.

Return JSON {files_created:int, total_tools_moved:int, orchestrator_lines_before:int, orchestrator_lines_after:int, notes:string}.`,
  { label: 'split', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      files_created:{type:'integer'},
      total_tools_moved:{type:'integer'},
      orchestrator_lines_before:{type:'integer'},
      orchestrator_lines_after:{type:'integer'},
      notes:{type:'string'},
    },
    required:['files_created','total_tools_moved']
  }}
)

phase('BuildAndFix')
const buildFix = await agent(
  `Build and iteratively fix compile errors after the split.
Steps:
1. cd ${CWD} && cargo build --release -p rustre-mcp-tools --message-format=short 2>&1  (Bash timeout 900000ms). Capture output.
2. Categorize errors:
   - "cannot find X in this scope" — missing import in a tools/*.rs file. Common: crate::args_to_bytes, crate::hex_encode, crate::args_to_bytes_v2, ToolResult, McpError. Add appropriate use statements.
   - "unresolved import rustre_mcp_server::..." — expand to full: use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
   - Missing use for async_trait — add use async_trait::async_trait; (or leave as full path #[async_trait::async_trait]).
   - Missing use for serde_json::json — already imported per file, verify.
3. When a fix is applied, re-run cargo build --release -p rustre-mcp-tools and count errors again. Iterate up to 8 times.
4. Once rustre-mcp-tools builds clean: cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).
5. Report {compile_ok:bool, errors_final:int, iterations:int, common_fixes:[string], build_time_min:number, notes:string}.

RULES: only add/fix imports. Do NOT touch tool logic. Do NOT modify decompiler crates.`,
  { label: 'build-fix', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      compile_ok:{type:'boolean'},
      errors_final:{type:'integer'},
      iterations:{type:'integer'},
      common_fixes:{type:'array',items:{type:'string'}},
      build_time_min:{type:'number'},
      notes:{type:'string'},
    },
    required:['compile_ok']
  }}
)

phase('Verify')
const verify = await agent(
  `Verify the split preserves behavior end-to-end.
Steps:
1. Verify ${CWD}/target/release/rustre-mcp.exe mtime is fresh (today).
2. taskkill /F /IM rustre-mcp.exe (Bash) so harness respawns with fresh binary. Ignore "process not found".
3. cd ${CWD}/validation && python3 exercise_v3.py 2>&1 | grep -E "FINAL|Total" (Bash timeout 600000ms).
4. Parse output: {OK, TOOL_ERROR, STUB} counts. Total should still be ~4130 exercised tools.
5. Diff vs baseline (pre-split): baseline was OK=4100, TOOL_ERROR=29, STUB=1.
6. Also measure new build size: file listing of ${CRATE}/src/tools/*.rs — sum of bytes vs old wire_tools.rs (5.5MB).
7. Report {binary_fresh:bool, tools_total:int, tools_ok:int, tools_error:int, delta_vs_baseline:{ok,err}, tools_dir_bytes:int, verdict:string}.`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      binary_fresh:{type:'boolean'},
      tools_total:{type:'integer'},
      tools_ok:{type:'integer'},
      tools_error:{type:'integer'},
      delta_vs_baseline:{type:'object'},
      tools_dir_bytes:{type:'integer'},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'split-complete', catalog, split, build:buildFix, verify }
