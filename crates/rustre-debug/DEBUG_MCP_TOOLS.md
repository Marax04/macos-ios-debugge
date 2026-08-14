# `debug.*` MCP tool reference

The live-wired debugger surface exposed by `crates/rustre-mcp-tools`
(`src/tools/debug.rs::handlers()` + the `debug_*.rs` capability modules), served
identically by both MCP entry points (the stdio server via
`wire_tools::all_wire_handlers()` and the `McpToolRegistry` used by
`rustre-mcp/src/subcrates.rs`, which delegates to `handlers()`).

**58 tools** (verified against `handlers().len()`, 2026-07-20 — re-check this
count whenever tools are added/removed, it drifts easily). Every stateful
tool takes a `session_id` and reports a `live`
boolean plus a `source` naming the real module; when there is no live session it
falls back to a mock and adds a `hint`. Live behaviour is driven by the concrete
`WindowsDebugger` / `LinuxDebugger` backends. All tools have `#[cfg(windows)]`
live tests against a real `cmd.exe`.

> **To reflect code changes, rebuild AND restart the served `rustre-mcp` binary**
> — a running server keeps serving the binary it started from.

## Session lifecycle & execution
| Tool | Purpose |
|---|---|
| `debug.launch` | Launch a process (live when `path`/`binary_id` names a real file, via `normalize_exe_path`). |
| `debug.attach` | Attach to a running pid. |
| `debug.detach` / `debug.kill` | Detach from / terminate the debuggee. |
| `debug.continue` | Resume until the next breakpoint/event. |
| `debug.single_step` / `debug.step_into` / `debug.step_over` / `debug.step_out` | Instruction / call-granular stepping. |
| `debug.pause` | Interrupt a running process. |
| `debug.is_attached` / `debug.target_pid` | Session status. |

## Registers, memory, threads, modules
| Tool | Purpose |
|---|---|
| `debug.get_register` / `debug.read_registers` | Read one / all registers (incl. DR0-7). |
| `debug.set_register` / `debug.set_registers` | Write registers (GP registers round-trip live). |
| `debug.read_memory` / `debug.write_memory` | Read / write process memory (writes auto-record into the omniscient log). |
| `debug.memory_maps` / `debug.modules` | Address-space regions / loaded modules. |
| `debug.threads` / `debug.current_thread` | Thread list / current thread. |
| `debug.backtrace` | Call stack; frames are named from loaded CodeView symbols when the backend leaves them unnamed. Unwinds past the first frame via real CFI once frame-pointer unwinding runs out (common against system code that doesn't preserve `rbp`): x64 `.pdata`/`UNWIND_INFO` on Windows, DWARF `.eh_frame` on Linux — both live-verified. On Linux, hand-written asm startup code (e.g. `ld.so`'s `_start`) commonly has no `.eh_frame` coverage at all and correctly stops there rather than guessing; real compiler-generated C code (the common case once execution moves past process startup) has full coverage. |
| `debug.memory_search` | Pattern search over a buffer. |
| `debug.heap_chunks` | Walk a ptmalloc2 arena into a chunk graph. |

## Breakpoints & watchpoints
| Tool | Purpose |
|---|---|
| `debug.set_breakpoint` / `debug.remove_breakpoint` | Software breakpoints. |
| `debug.enable_breakpoint` / `debug.disable_breakpoint` / `debug.breakpoints` | Toggle / list. |
| `debug.continue_until` | Conditional breakpoint: run until an expression is non-zero (steps over its own int3, skips benign OS events). |
| `debug.set_conditional_breakpoint` | Evaluate a register condition (against live registers when `session_id` is live). |
| `debug.add_tracepoint` / `debug.tracepoints_fire` | Register / fire tracepoints (live registers when a session is given). |
| `debug.set_watchpoint` | Hardware watchpoint; a per-session engine allocates distinct DR0-DR3 slots. |
| `debug.watchpoints` / `debug.set_watchpoint_enabled` / `debug.remove_watchpoint` | List / enable-disable / remove. |

## Expression evaluator
`debug.evaluate` / `debug.watch` use the session's registers, memory, loaded
symbols and struct types. Correct C-expression semantics: typed pointer-cast
derefs at the right element width, sign-extension for signed ints, float reads
(`value_f64`), array indexing at element stride, struct field access,
arbitrarily nested `->a.b.c`, and address-of (`&x->y` yields the address).
| Tool | Purpose |
|---|---|
| `debug.evaluate` | Evaluate one expression. |
| `debug.watch` | Evaluate a list of expressions (watch window). |
| `debug.define_struct` | Register a struct type by hand so `((Foo*)p)->field` resolves (also registers `Foo*`). |
| `debug.load_types` | Auto-import structs from a CodeView type-stream (`.debug$T` accepted): parses LF_FIELDLIST for ACCURATE per-member offsets/types — scalars, nested structs, unions, arrays, pointer-to-struct, self/mutually-referential pointers, enums, and bitfields — so `((Foo*)p)->a.b`, `->arr[i]`, `->next->val` resolve without hand-defining. |
| `debug.load_symbols` / `debug.resolve_symbol` | Load CodeView symbols; resolve name↔address. |

## Omniscient provenance (backward dataflow)
Over the session's recorded write log (`debug.write_memory` auto-records;
`debug.record_write` adds explicit provenance).
| Tool | Purpose |
|---|---|
| `debug.record_write` | Append a write with `writer_pc` / `source_address`. |
| `debug.who_wrote` | Every writer of an address, most-recent-first. |
| `debug.trace_origin` | Walk the copy chain back to the origin. |
| `debug.dataflow_query` | Declarative DSL (`TRACE … BACKWARD`, `FIND WRITES TO …`). |
| `debug.root_cause` | Rank the PCs most likely responsible for a bad value. |

## Time-travel (over the concrete `SnapshotReplayBackend`)
`debug.ttd_record` captures real registers + a stack memory window at each
position; the reverse/seek tools return real recorded state.
| Tool | Purpose |
|---|---|
| `debug.ttd_record` | Snapshot the live state at the next trace position. |
| `debug.reverse_step` / `debug.reverse_continue` | Reverse execution (real recorded registers). |
| `debug.ttd_seek` / `debug.ttd_run_to_previous_call` / `debug.ttd_history` | Navigate / inspect the trace. |
| `debug.ttd_diff` | Register diff between two positions ("what changed"). |
| `debug.ttd_evaluate` | Evaluate an expression against a past position's recorded registers + stack memory. |
| `debug.execution_heatmap` | Bucket per-address hit counts across a TTD position-history sample and rank the hottest addresses; live over a session's real recorded history when `session_id` is given, otherwise computed from a supplied `history` array. |

## Not yet available (need external inputs)
- **Real WinDbg-TTD / rr `.run` trace loader** — proprietary format; the in-crate
  `SnapshotReplayBackend` covers the replay contract (fed by `debug.ttd_record`).
- **macOS backend** — a first draft exists (`crates/rustre-debug/src/macos_debugger.rs`,
  BSD ptrace + Mach VM/thread APIs, wired into `make_backend()`), but it has
  **never been compiled or run** — no macOS host has been available to verify
  it. Struct layouts (`VmRegionSubmapInfo64`, `TaskDyldInfo`,
  `DyldAllImageInfosHead`, `DyldImageInfo`, `ThreadIdentifierInfo`,
  `X86ThreadState64`) are the most likely source of compile errors on a real
  Mac. Needs a macOS-host compile-and-fix pass, then `live_tests` mirroring
  `linux_debugger.rs`'s, before it can be trusted.

`debug.load_types` covers the whole PDB story now: it accepts a raw
CodeView type-stream / `.debug$T` section directly, OR a full `.pdb` file
via `container: "pdb-msf"` (`codeview/msf_reader.rs::MsfReader` extracts the
TPI stream), verified end-to-end against a real MSVC-produced `.pdb`.
