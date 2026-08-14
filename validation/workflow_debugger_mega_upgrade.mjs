export const meta = {
  name: 'debugger-mega-upgrade',
  description: 'Mega upgrade rustre-debug: research SOTA, wire dead code, add novel features (Windows + Linux), optimize, beat WinDbg/GDB/x64dbg/IDA',
  phases: [
    { title: 'ResearchSOTA', detail: 'Web research on cutting-edge debugger features (TTD, omniscient, race detection, causal debugging, hot-patch, differential debugging)' },
    { title: 'DeadCodeAudit', detail: 'Find all dead pub items in rustre-debug (~2000L stimate) — categorize by intended use' },
    { title: 'WireDeadCode', detail: 'Wire every dead pub item to its call site (MCP tools, tests, or removal justified)' },
    { title: 'WindowsInnovation', detail: 'New Windows features: TTD real backend, PDB deep integration, heap tracker, minidump analysis, ETW correlation' },
    { title: 'LinuxInnovation', detail: 'New Linux features: rr integration, perf events, eBPF probes, /proc snapshots, LTO-aware stepping' },
    { title: 'CrossCuttingOptimize', detail: 'Performance: arena allocation, SIMD watchpoint scan, parallel unwind, memory-mapped session snapshots' },
    { title: 'NovelFeatures', detail: 'Features never seen: LLM-assisted root cause, semantic diff between runs, live invariant tracking, causal slice ranking' },
    { title: 'Verify', detail: 'cargo test Win + Linux WSL, MCP live regression, benchmark before/after' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'

phase('ResearchSOTA')
const research = await agent(
  `Research state-of-the-art debugger features. WebFetch on these key sources:
1. Pernosco (omniscient debugging) — what they do beyond rr replay.
2. Microsoft TTD blog + WinDbg TTD docs — trace format, IThreadStatePost/Pre, memory queries.
3. rr project (Mozilla) — checkpointing, chaos mode, backward continue.
4. Undo.io LiveRecorder — reversible runtime.
5. eBPF for debugging (bpftrace, bcc) — kernel-side tracepoints.
6. Nsight Systems / VTune — sampling profiler correlation.
7. GDB rr integration, LLDB reverse.
8. Papers: RecPlay (record-replay), Chronon (Java time-travel), CodeTalker (LLM+debugger), FlowChecker (static+dynamic).
9. Novel research: causal slicing (Wang), invariant learning (Daikon), root cause via ML.
10. Hot-patch/live-patch: kpatch, kGraft, LivePatch API.

For each source, extract:
- What they do that debuggers in Rust don't have
- Data model (trace format, memory model)
- Trigger points (breakpoint semantics, watchpoint aggregation)
- UX innovations (query language, timeline UI)
- Performance tricks

Then synthesize:
- Top 10 features that would beat WinDbg/GDB/x64dbg/IDA on real reverse-engineering workflows
- Which of these are ALREADY in rustre-debug source (even if not wired)
- Which are pure new frontier (novel)

Return {sources_reviewed:[string], top_features_to_add:[{name, description, difficulty, novelty:1-10, competitor_gap}], already_in_source:[string], pure_frontier:[string], notes:string}`,
  { label: 'research', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      sources_reviewed:{type:'array', items:{type:'string'}},
      top_features_to_add:{type:'array'},
      already_in_source:{type:'array', items:{type:'string'}},
      pure_frontier:{type:'array', items:{type:'string'}},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('DeadCodeAudit')
const dead = await agent(
  `Audit all dead code in ${CWD}/crates/rustre-debug.

STEPS:
1. cd ${CWD} && cargo build --release -p rustre-debug 2>&1 | grep -E "dead_code|unused" | head -100
2. Also: cargo clippy --release -p rustre-debug -- -W dead_code -W unused 2>&1 | grep -E "warning:" | head -100
3. Glob src/**/*.rs — for each file, count pub items with grep and cross-reference call sites.
4. Categorize dead items:
   - "trait-only" (implementation absent)
   - "wire-missing" (no MCP wrapper, no test using it)
   - "prototype" (partial impl, needs completion)
   - "obsolete" (superseded by newer variant)
5. For each dead item, report file:line, category, and suggested action (wire to MCP tool / complete impl / remove).

Return {total_dead_lines:int, categorized:{trait_only:int, wire_missing:int, prototype:int, obsolete:int}, items:[{file, line, name, category, action, priority:high|med|low}], notes:string}`,
  { label: 'dead-audit', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      total_dead_lines:{type:'integer'},
      categorized:{type:'object'},
      items:{type:'array'},
      notes:{type:'string'},
    },
    required:['notes']
  }}
)

phase('WireDeadCode')
const wire = await agent(
  `Wire every dead pub item to its proper call site.

Research: ${JSON.stringify(research).slice(0, 2000)}
Dead audit: ${JSON.stringify(dead).slice(0, 3000)}

STEPS:
1. For each item in dead.items where action = "wire to MCP tool":
   - Add MCP wrapper in ${CWD}/crates/rustre-mcp-tools/src/tools/debug.rs following existing SyncFnTool pattern.
   - Wire the debug session context if the tool needs live state.
2. For items where action = "complete impl":
   - Read the trait definition or interface it belongs to.
   - Implement the missing body.
3. NEVER remove code — the user's rule is "wire it, don't delete".
4. For each new wrapper add a smoke test in the debug.rs test module.
5. cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp-server -p rustre-mcp 2>&1 | tail -15. Iterate max 5 times on errors.
6. cargo test --release -p rustre-debug --lib 2>&1 | tail -3.

Return {items_wired:int, mcp_tools_added:[string], impls_completed:[string], build_ok:bool, tests_passing:int, tests_failing:int, notes:string}`,
  { label: 'wire', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      items_wired:{type:'integer'},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      impls_completed:{type:'array', items:{type:'string'}},
      build_ok:{type:'boolean'},
      tests_passing:{type:'integer'},
      tests_failing:{type:'integer'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('WindowsInnovation')
const win = await agent(
  `Add high-impact Windows-specific features.

Research context: ${JSON.stringify(research).slice(0, 2000)}

Priority additions (pick top 3-4 to implement fully):
1. **TTD trace replay** — parse WinDbg TTD .run/.idx files, expose forward/backward navigation via existing time_travel_debug API.
2. **PDB deep integration** — download from Microsoft Symbol Server (SSL, cache in ~/.rustre/pdb), auto-load on module load event.
3. **ETW correlation** — subscribe to Microsoft-Windows-Kernel-Process/Thread/Memory ETW providers, correlate to debug events.
4. **Heap tracker (RtlAllocateHeap hooks)** — instrument heap functions via inline patch, track alloc/free with stack traces.
5. **Minidump analysis** — load .dmp files, expose registers/threads/memory as read-only "attached" session.
6. **Structured exception handling (SEH) traversal** — walk .pdata for exception handler chain, decode filter/handler expressions.
7. **Kernel dump (Bugcheck) analysis** — parse full/kernel memory .dmp, expose KUSER_SHARED_DATA, PsActiveProcessHead traversal.
8. **JIT-emitted code recognition** — detect .NET/CLR/JVM JIT regions, map via ICorProfilerCallback / JVMTI.

For each implemented feature:
- Full code in ${CWD}/crates/rustre-debug/src/ (new file for major features).
- MCP wrapper in tools/debug.rs.
- 1+ test with real Windows resources (notepad.exe, or minidumps generated).
- Doc comment explaining what it does vs WinDbg/x64dbg.

cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools -p rustre-mcp 2>&1 | tail -15. Iterate.

Return {features_implemented:[string], new_files:[string], mcp_tools_added:[string], tests_added:int, build_ok:bool, competitor_gap_closed:string, notes:string}`,
  { label: 'win', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      features_implemented:{type:'array', items:{type:'string'}},
      new_files:{type:'array', items:{type:'string'}},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      tests_added:{type:'integer'},
      build_ok:{type:'boolean'},
      competitor_gap_closed:{type:'string'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('LinuxInnovation')
const lin = await agent(
  `Add high-impact Linux-specific features.

Research context: ${JSON.stringify(research).slice(0, 2000)}

Priority additions (pick top 3-4):
1. **rr trace integration** — parse rr traces, expose forward/backward via time_travel_debug.
2. **perf events subscription** — perf_event_open for hw counters (branches, cache-misses), correlate to debug events.
3. **eBPF tracepoints** — attach kprobes/uprobes via libbpf-sys, expose events as debug tracepoints.
4. **/proc snapshots** — capture /proc/pid/{maps,status,stat,syscall,wchan}, expose as memory_layout_view enhancement.
5. **LTO/inlining-aware stepping** — DWARF inlined_subroutine walking, "step into inlined function" support.
6. **Systemtap DTrace probes** — attach to userspace/kernel USDT probes.
7. **Container-aware debug** — attach to processes in another PID namespace, cgroup boundary handling.
8. **Live-patching detection** — track kpatch/livepatch replacement, warn when instrumented function is patched.

For each implemented feature: full code + MCP wrapper + test + doc.

cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools 2>&1 | tail -15. Iterate.
Also wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/Fra/Desktop/RustRE && /home/marax/.cargo/bin/cargo build --release -p rustre-debug 2>&1 | tail -10". (Some Linux features are cfg-gated and only compile on Linux.)

Return {features_implemented:[string], new_files:[string], mcp_tools_added:[string], tests_added:int, build_ok_win:bool, build_ok_linux:bool, notes:string}`,
  { label: 'lin', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      features_implemented:{type:'array', items:{type:'string'}},
      new_files:{type:'array', items:{type:'string'}},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      tests_added:{type:'integer'},
      build_ok_win:{type:'boolean'},
      build_ok_linux:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok_win','notes']
  }}
)

phase('CrossCuttingOptimize')
const opt = await agent(
  `Performance optimizations across rustre-debug.

Targets:
1. **Arena-allocate trace events** (bumpalo) — replace Vec<Box<T>> with arena for TTD/session_recorder events. Measure allocator pressure with jemalloc stats.
2. **SIMD watchpoint scan** — parallel comparison of DR0-DR3 against fault addresses using AVX2/NEON.
3. **Parallel stack unwind** — walk N frames concurrently via rayon when CFI info is pre-resolved.
4. **Memory-mapped session snapshots** — mmap large snapshot pages instead of alloc+copy.
5. **Bitmap-based tracepoint hit counting** — replace HashMap<addr, count> with roaring bitmap when hit rate high.
6. **Zero-copy PDB parsing** — mmap the .pdb, avoid copying stream contents; use bytemuck for zero-cost casts.
7. **Cached CodeView type lookups** — LRU cache TypeIndex → parsed type record.
8. **Cold-path attributes** — mark error paths #[cold], hint branch prediction.

For each optimization:
- Actual code change (no just comments).
- Bench macro or #[cfg(bench)] test proving before/after speedup.
- No API break — internal only.

cd ${CWD} && cargo build --release -p rustre-debug 2>&1 | tail -10.
cargo test --release -p rustre-debug --lib 2>&1 | tail -3.

Return {optimizations_applied:[string], expected_speedup_pct:{opt:number}, api_break:bool, build_ok:bool, tests_still_passing:int, notes:string}`,
  { label: 'opt', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      optimizations_applied:{type:'array', items:{type:'string'}},
      expected_speedup_pct:{type:'object'},
      api_break:{type:'boolean'},
      build_ok:{type:'boolean'},
      tests_still_passing:{type:'integer'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('NovelFeatures')
const novel = await agent(
  `Add features that DON'T exist in WinDbg/GDB/x64dbg/IDA. Frontier.

Research: ${JSON.stringify(research).slice(0, 3000)}

Frontier ideas (implement TOP 3):
1. **Live invariant tracking** — user marks "invariant X" at breakpoint; system continuously watches value, triggers when violated. Extension of watchpoint but with expression.
2. **Semantic diff between runs** — record 2 runs, compute divergence point (address + variable value where they differ). Chronon-inspired.
3. **Causal slice ranking** — given a bad value at time T, walk the writer chain backward, rank writes by "how much did this write CONTRIBUTE to the bug". Use Wang's causal slicing metric.
4. **LLM root-cause suggest** — session snapshot + user-provided symptom → prompt Claude API for hypothesis. Cache prompts. Optional feature (behind flag).
5. **Timeline query language** — "when did register RAX contain a heap address >= 0x1000?" — translates to trace scan, returns list of positions.
6. **Comparative execution** — run same code path with 2 different inputs, diff which branches were taken.
7. **Watchpoint aggregation** — set watchpoints on a "family" (all fields of struct X in all instances). Auto-manage DR slots via time-multiplexing.
8. **Backward step-into inlined** — go BACKWARD across inlined function boundaries in one step.
9. **Anti-tamper detection debug** — detect when code being debugged tries to detect debugger (IsDebuggerPresent, NtGlobalFlag, PEB.BeingDebugged) and log without disabling.
10. **Auto-decode structured memory** — given a pointer, auto-detect if it's a pointer to a struct + auto-render tree of dereferenced pointers.

For top 3: full code + MCP wrapper + example usage + doc explaining "why no one else has this".

cd ${CWD} && cargo build --release -p rustre-debug -p rustre-mcp-tools 2>&1 | tail -15. Iterate.

Return {top_3_implemented:[string], mcp_tools_added:[string], competitor_analysis:string, build_ok:bool, notes:string}`,
  { label: 'novel', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      top_3_implemented:{type:'array', items:{type:'string'}},
      mcp_tools_added:{type:'array', items:{type:'string'}},
      competitor_analysis:{type:'string'},
      build_ok:{type:'boolean'},
      notes:{type:'string'},
    },
    required:['build_ok','notes']
  }}
)

phase('Verify')
const verify = await agent(
  `Full verification.

STEPS:
1. taskkill //F //IM rustre-mcp.exe. sleep 3.
2. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server 2>&1 | tail -10.
3. Windows tests: cargo test --release -p rustre-debug --lib 2>&1 | tail -3.
4. Linux tests: wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/Fra/Desktop/RustRE && /home/marax/.cargo/bin/cargo test --release -p rustre-debug --lib 2>&1 | tail -3".
5. MCP live probe: spawn rustre-mcp.exe stdio. Test at least:
   - debug_launch on notepad.exe → live=true
   - New MCP tools added by this workflow (list them and call each with sensible args)
   - Novel features (invariant/semantic-diff/causal — one of top 3)
6. Count total MCP debug_* tools (should be significantly higher than baseline ~55).
7. Report:
   - tools_count_before / after
   - windows_tests: {passed, failed}
   - linux_tests: {passed, failed}
   - features_working_live: [{feature, live_result}]
   - competitor_gap_closed: string summary
   - verdict: string
   - remaining_issues: [string]`,
  { label: 'verify', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      tools_count_before:{type:'integer'},
      tools_count_after:{type:'integer'},
      windows_tests:{type:'object'},
      linux_tests:{type:'object'},
      features_working_live:{type:'array'},
      competitor_gap_closed:{type:'string'},
      verdict:{type:'string'},
      remaining_issues:{type:'array', items:{type:'string'}},
    },
    required:['verdict']
  }}
)

return { status:'debugger-mega-upgrade-complete', research, dead, wire, win, lin, opt, novel, verify }
