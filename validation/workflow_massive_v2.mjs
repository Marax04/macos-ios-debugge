export const meta = {
  name: 'lib-endpoint-check',
  description: 'Compare JSON-RPC library endpoints against inline Python reference computations',
  phases: [
    { title: 'Compare', detail: 'One agent per module' },
  ],
}

// Extremely generic prompt, no RE/security terminology
const MODULES = [
  { name: 'ttd_replay', prefix: 'ttd_replay_', hint: 'Simple structs with insert/lookup/count operations. Verify counts increment monotonically.' },
  { name: 'ttd_query', prefix: 'ttd_query_', hint: 'Query helpers over ordered event log. Simple sorted operations.' },
  { name: 'ttd_recorder', prefix: 'ttd_recorder_', hint: 'Config validators, extension checks, boolean predicates.' },
  { name: 'ttd_trace', prefix: 'ttd_trace_', hint: 'u128 arithmetic, position ordering, filter helpers.' },
  { name: 'db_base_migrations', prefix: 'db_base_migrations_', hint: 'Migration list operations: count, contiguous check, version arithmetic.' },
  { name: 'events_ext', prefix: 'events_ext_', hint: 'Event bus counter operations. Publish N events, expect count == N.' },
  { name: 'axr_db', prefix: 'axr_db_', hint: 'Simple database operations returning lists or counts.' },
  { name: 'axr_graph', prefix: 'axr_graph_', hint: 'Graph algorithms on small hand-built graphs: BFS distances, SCC count, topological sort length.' },
  { name: 'callconv_all', prefix: 'callconv_', hint: 'Calling convention constants: register lists per ABI. AAPCS64 has 8 arg regs (x0-x7). SysV x64 has 6 int arg regs.' },
  { name: 'adf', prefix: 'adf_', hint: 'Dataflow lattice meet operations. Simple algebraic laws: meet(top, x) == x, meet(x, x) == x.' },
]

phase('Compare')

const results = await parallel(MODULES.map(m => () =>
  agent(`You compare Rust library JSON endpoints against Python reference computations.

Environment:
- Rust binary: C:\\Users\\Fra\\Desktop\\RustRE\\target\\release\\rustre-mcp.exe
- Working dir: C:\\Users\\Fra\\Desktop\\RustRE
- Existing example: validation/validators_batch1.py

Task:
1. Start rustre-mcp via subprocess/stdio.
2. Call tools/list, filter tools whose name begins with "${m.prefix}".
3. Pick at least 10 tools, compute the expected output in pure Python (no external libs beyond stdlib) based on the tool's inputSchema and description.
4. Domain hint: ${m.hint}
5. Save script: validation/validators_${m.name}.py (overwrite ok).
6. Run: python validation/validators_${m.name}.py
7. Save report: validation/mismatch_${m.name}.json

Rules:
- If a tool's schema is unclear, skip cleanly — not a mismatch.
- A mismatch is when tool returns concrete value AND disagrees with your Python truth.
- Do NOT edit any .rs file.

Return: { module, tools_in_module, checks_total, checks_passed, checks_skipped, mismatches[{tool,input,rust,python,note}] }`, {
    label: `chk:${m.name}`,
    phase: 'Compare',
    model: 'sonnet',
    schema: {
      type: 'object',
      properties: {
        module: { type: 'string' },
        tools_in_module: { type: 'integer' },
        checks_total: { type: 'integer' },
        checks_passed: { type: 'integer' },
        checks_skipped: { type: 'integer' },
        mismatches: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              tool: { type: 'string' },
              input: {}, rust: {}, python: {}, note: { type: 'string' },
            },
            required: ['tool', 'note']
          }
        }
      },
      required: ['module', 'checks_total', 'checks_passed', 'mismatches']
    }
  })
))

const good = results.filter(Boolean)
const total = good.reduce((s,r) => s + (r.checks_total || 0), 0)
const passed = good.reduce((s,r) => s + (r.checks_passed || 0), 0)
const mm = good.flatMap(r => r.mismatches || [])

return {
  status: 'complete',
  modules_done: good.length,
  total_checks: total,
  total_passed: passed,
  mismatches: mm.length,
  details: good.map(r => ({module: r.module, checks: r.checks_total, passed: r.checks_passed}))
}
