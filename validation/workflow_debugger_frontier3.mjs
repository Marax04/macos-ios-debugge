export const meta = {
  name: 'debugger-frontier3',
  description: 'Implement the 3 remaining frontier features 100%: TTD real backend, Retroactive print (Pernosco-style), Natural-language LLM query end-to-end',
  phases: [
    { title: 'ResearchDeep', detail: 'Deep dive on WinDbg TTD format (.run/.idx), rr trace format v9, Pernosco retroactive print semantics, LLM tool-call dispatch patterns' },
    { title: 'TtdRealBackend', detail: 'Parse+replay WinDbg TTD .run files AND rr traces — expose forward/backward navigation via existing TtdSession, real memory queries at any position' },
    { title: 'RetroactivePrint', detail: 'Annotate any address/line with printf-expr, replay trace offline, collect results without re-run (Pernosco-style)' },
    { title: 'NaturalLanguageQuery', detail: 'End-to-end: NL question → LLM translate to debug DSL → execute against session → return structured result' },
    { title: 'Integrate', detail: 'Wire all 3 into MCP + scripting_api + live_script_context, tests, docs' },
    { title: 'Verify', detail: 'cargo test Win+Linux + MCP live probe of the 3 new features on real trace + real notepad session' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('ResearchDeep')
const research = await agent(
  `Deep-dive research on 3 topics. WebFetch these + read local sources.

TOPIC 1 — TTD real backend:
- WinDbg TTD trace file format: .run and .idx binary layout. WebFetch: learn.microsoft.com articles about TTDReplay.dll, IndexTraceFile, ITimelineDeltaEnumerator. Also check github repos like TTDCore, ttd-2-reven, rr-project docs on trace format v9.
- rr trace directory layout: mmap_lookup, cloned_file_data, syscallbuf, latest-trace pointer. Read rr wiki + Robert O'Callahan's papers.
- ${CWD}/crates/rustre-debug/src/time_travel_debug.rs — existing TtdSession abstract API. Read it.
- ${CWD}/crates/rustre-debug/src/rr_trace.rs (if just added) — existing parser status.

TOPIC 2 — Retroactive print:
- pernos.co blog posts / talks by Robert O'Callahan / Kyle Huey on "condition and print expressions". How they evaluate expressions symbolically over the write-log.
- ${CWD}/crates/rustre-debug/src/omniscient_query.rs — current who_wrote/trace_origin infrastructure.
- ${CWD}/crates/rustre-debug/src/dataflow_dsl.rs — TRACE/FIND DSL that must be extended.

TOPIC 3 — Natural-language LLM query:
- CodeTalker 2024 paper if reachable.
- Anthropic tool_use / function-calling docs (docs.anthropic.com).
- ${CWD}/crates/rustre-debug/src/scripting_api.rs + live_script_context.rs — current LLM dispatch surface.

For each topic return:
- Existing rustre-debug modules that partially cover it
- Missing pieces to build
- Data-structure design (be specific: types, fields, byte layouts)
- Concrete file paths to create/edit
- ~5-line skeleton of the core function/impl for each

Return {ttd_analysis:{existing,missing,design,files_to_edit,skeleton}, retro_print_analysis:{...}, nl_query_analysis:{...}, notes:string}`,
  { label: 'research', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ttd_analysis:{type:'object'},
      retro_print_analysis:{type:'object'},
      nl_query_analysis:{type:'object'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('TtdRealBackend')
const ttd = await agent(
  `Implement TTD real backend. Support BOTH WinDbg TTD (.run/.idx) AND rr trace directories.

Research: ${JSON.stringify(research.ttd_analysis || {}).slice(0, 3000)}

STEPS:
1. Extend ${CWD}/crates/rustre-debug/src/time_travel_debug.rs. Add trait TtdBackend with:
   - open(path: &Path) -> Result<Self>
   - trace_length() -> u64
   - seek(pos: TracePosition) -> Result<()>
   - read_memory(addr: u64, len: usize) -> Result<Vec<u8>>
   - read_registers() -> Result<RegisterSet>
   - next_event() / prev_event() -> Option<Event>
   - modules_at(pos) -> Vec<ModuleInfo>
2. Impl 1: WindbgTtdBackend in windbg_ttd.rs. Parse .idx header (magic bytes, version, page table), open .run as random-access memory-mapped byte stream. Use bytemuck for zero-cost struct casts.
3. Impl 2: RrTraceBackend in rr_trace_backend.rs (extend existing rr_trace.rs). Parse events/mmap/syscallbuf directories, expose per-task event stream.
4. Integrate into TtdSession: replace snapshot-simulation with real backend when path is passed.
5. MCP tools:
   - debug.ttd_open{path} — auto-detects .run vs rr dir
   - debug.ttd_seek{session_id, position}
   - debug.ttd_read_memory{session_id, addr, len}
   - debug.ttd_next / debug.ttd_prev
   - debug.ttd_modules_at{session_id, position}
6. Tests: use synthetic trace fixtures (create small .run+.idx via helper). Include integration test that loads and reads a trace end-to-end.
7. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15. Iterate max 5 times.
8. cargo test --release -p rustre-debug --lib time_travel 2>&1 | tail -5.

Return {backends_implemented:[string], files_created:[string], mcp_tools_added:[string], tests_added:int, tests_passing:int, build_ok:bool, notes:string}`,
  { label: 'ttd', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      backends_implemented:{type:'array', items:{type:'string'}},
      files_created:{type:'array', items:{type:'string'}},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      tests_added:{type:'integer'},
      tests_passing:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('RetroactivePrint')
const retro = await agent(
  `Implement Retroactive Print (Pernosco-style).

Research: ${JSON.stringify(research.retro_print_analysis || {}).slice(0, 3000)}

DEFINITION: user annotates address X with expression E (e.g. "printf %d %d {*(int*)0x1000} {\\$rax}"), system replays the trace and returns a list of (position, evaluated_string) — WITHOUT re-running the target.

STEPS:
1. Create ${CWD}/crates/rustre-debug/src/retroactive_print.rs:
   - struct RetroactivePrintAnnotation { addr: u64, format: String, args: Vec<Expression> }
   - fn evaluate_over_trace(session: &TtdSession, ann: &Annotation) -> Vec<(TracePosition, String)>
   - fn evaluate_line(session: &TtdSession, source_line: (path, line), ann) -> Vec<...> — via source_map
2. Use existing expression_evaluator for expression parsing, ttd_evaluate for state resolution at position.
3. For efficiency: use omniscient_query index to jump-fast to positions where addr's IP is reached, don't scan whole trace.
4. Add stub-run integration: if TtdBackend is available, use real trace scan; else use recorded write-log heuristic.
5. MCP tools:
   - debug.retroactive_print{session_id, addr, format, args?} — returns [{position, output}]
   - debug.retroactive_print_line{session_id, source_file, line, format} — via source_map
   - debug.retroactive_print_list{session_id} — list active annotations
   - debug.retroactive_print_remove{session_id, annotation_id}
6. Tests: mock TtdSession, annotate address, verify N evaluations returned.
7. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15.
8. cargo test --release -p rustre-debug --lib retro 2>&1 | tail -5.

Return {file_created:string, mcp_tools_added:[string], tests_added:int, tests_passing:int, build_ok:bool, notes:string}`,
  { label: 'retro', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      file_created:{type:'string'},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      tests_added:{type:'integer'},
      tests_passing:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('NaturalLanguageQuery')
const nl = await agent(
  `Implement Natural-Language LLM query end-to-end.

Research: ${JSON.stringify(research.nl_query_analysis || {}).slice(0, 3000)}

FLOW: user asks "when did the return value of sub_401000 become negative?" → LLM translates to debug DSL → executes against session → returns structured result with citation.

STEPS:
1. Create ${CWD}/crates/rustre-debug/src/nl_query.rs:
   - fn nl_to_dsl(question: &str, session_context: &SessionContext) -> Result<Query>
   - fn execute_query(session: &Session, query: Query) -> QueryResult
   - Query variants: TraceScan, InvariantCheck, WhoWrote, CausalRank, SemanticDiff, ExecutionHeatmap, InstructionSearch.
   - Optional: use anthropic API via env var ANTHROPIC_API_KEY. If key absent, fall back to a rule-based translator that handles ~10 common templates.
2. The rule-based translator handles NL patterns:
   - "when did X become Y" → InvariantCheck(X, Y)
   - "who wrote to X" → WhoWrote(addr)
   - "trace origin of X" → CausalRank(X, hops=5)
   - "diff between run A and run B" → SemanticDiff(A, B)
   - "hot addresses" → ExecutionHeatmap top-N
   - "find instruction NAME" → InstructionSearch
   - "call chain to sub_X" → CallGraph reverse from X
3. LLM path: build a system prompt describing the DSL grammar + session tools. Send question + prompt to claude API. Parse response as JSON {query_type, params}. Route to executor.
4. MCP tools:
   - debug.nl_query{session_id, question} — returns {dsl:Query, result:QueryResult, explanation:string}
   - debug.nl_translate{session_id, question} — return just DSL (for preview without executing)
   - debug.nl_capabilities{session_id} — return list of supported query patterns
5. Tests:
   - Rule-based path: "who wrote to 0x1234" → WhoWrote(0x1234) → 3 writes returned
   - "when did rax become negative" → InvariantCheck(rax, <0) execution
6. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15.
7. cargo test --release -p rustre-debug --lib nl_query 2>&1 | tail -5.

Return {file_created:string, mcp_tools_added:[string], rule_based_patterns:int, llm_optional:bool, tests_added:int, build_ok:bool, notes:string}`,
  { label: 'nl', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      file_created:{type:'string'},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      rule_based_patterns:{type:'integer'},
      llm_optional:{type:'boolean'},
      tests_added:{type:'integer'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('Integrate')
const integrate = await agent(
  `Integrate the 3 features into scripting_api and live_script_context so they work end-to-end.

STEPS:
1. Read ${CWD}/crates/rustre-debug/src/scripting_api.rs — add dispatch cases for ttd_open, retroactive_print, nl_query.
2. Read ${CWD}/crates/rustre-debug/src/live_script_context.rs — bind live session to nl_query executor + retroactive_print backend.
3. Add cross-cutting scenario test: open real trace (or synthetic) → set retroactive_print annotation → run nl_query "what did address X print during the trace" → verify result cites the print annotation.
4. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -15.
5. cargo test --release -p rustre-debug --lib 2>&1 | tail -3.

Return {scripting_api_updated:bool, live_context_updated:bool, cross_scenario_test_added:bool, build_ok:bool, all_tests_passing:int, notes:string}`,
  { label: 'integrate', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      scripting_api_updated:{type:'boolean'},
      live_context_updated:{type:'boolean'},
      cross_scenario_test_added:{type:'boolean'},
      build_ok:{type:'boolean'},
      all_tests_passing:{type:'integer'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('Verify')
const verify = await agent(
  `Full verification of the 3 frontier features.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Windows tests: cargo test --release -p rustre-debug --lib 2>&1 | tail -3.
4. Linux tests: wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/Fra/Desktop/RustRE && /home/marax/.cargo/bin/cargo test --release -p rustre-debug --lib 2>&1 | tail -3".
5. MCP live probes:
   a. debug.ttd_open with a small synthetic trace path (generate one during test if needed) → verify session_id returned
   b. debug.retroactive_print on notepad live session with addr=entry_point, format="%d" — expect at least 1 evaluation
   c. debug.nl_query with question "who wrote to entry point" — verify returns WhoWrote DSL + result
6. Count MCP debug.* tools now (should be 77 baseline + ~10 new = ~85+).
7. Report:
   - windows_tests: {passed, failed}
   - linux_tests: {passed, failed}
   - mcp_debug_tools_count
   - ttd_backend_live_result: {ok, backend_type, position}
   - retroactive_print_live_result: {annotations, evaluations_count}
   - nl_query_live_result: {question, dsl_translated, result_type}
   - verdict: string
   - competitor_gap_closed: string
   - remaining_gaps: [string]`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      windows_tests:{type:'object'},
      linux_tests:{type:'object'},
      mcp_debug_tools_count:{type:'integer'},
      ttd_backend_live_result:{type:'object'},
      retroactive_print_live_result:{type:'object'},
      nl_query_live_result:{type:'object'},
      verdict:{type:'string'},
      competitor_gap_closed:{type:'string'},
      remaining_gaps:{type:'array', items:{type:'string'}},
    },
    required:['verdict']
  }}
)

return { status:'frontier3-complete', research, ttd, retro, nl, integrate, verify }
