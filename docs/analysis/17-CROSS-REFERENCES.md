# 17 — Cross-References: Subsystem Interconnections

> **Purpose.** This document synthesises all 15 preceding analysis files into
> nine cross-cutting views of the RustRE (~210-crate) workspace. Each section
> traces relationships *across* subsystem boundaries that are invisible when
> reading individual crate analyses. ASCII diagrams are provided throughout.
>
> **Date:** 2026-07-01  
> **Baseline target:** IDA Pro 9.x on `cargo-zyphora.exe` (1 456 funcs / 395
> named, 43 findcrypt hits, 13 735 xrefs).

---

## Table of Contents

1. [Full Data-Flow Pipeline: Binary on Disk → Output](#1-full-data-flow-pipeline)
2. [MCP Tool Surface: How Each Subsystem Is Exposed](#2-mcp-tool-surface)
3. [Agent / LLM Integration Surface](#3-agent--llm-integration-surface)
4. [Plugin and Scripting Extension Points](#4-plugin-and-scripting-extension-points)
5. [Debug / Emulation / TTD Flow](#5-debug--emulation--ttd-flow)
6. [Obfuscation-Resistant Paths: Deobf + Symbolic Execution](#6-obfuscation-resistant-paths)
7. [Mobile and .NET Dedicated Pipelines](#7-mobile-and-net-dedicated-pipelines)
8. [Forensics / Sandbox / Threat-Intel Side-Flows](#8-forensics--sandbox--threat-intel-side-flows)
9. [Integration Gaps and Completeness Matrix](#9-integration-gaps-and-completeness-matrix)

---

## 1. Full Data-Flow Pipeline

### 1.1 Conceptual Overview

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        BINARY ON DISK                                       ║
║              (PE / ELF / Mach-O / DEX / APK / Wasm / Lua …)               ║
╚══════════════════════════════╦═════════════════════════════════════════════╝
                               ║  path   ║  bytes
                               ▼
              ┌────────────────────────────────────────┐
              │         rustre-loader-registry         │
              │  Loader::probe(magic) → priority sort  │
              │  15 loaders: PE / ELF / Mach-O /       │
              │  .NET / Java / DEX / APK / Wasm /      │
              │  Lua / LuaJIT / Firmware / ROM /        │
              │  OLE / PDF / raw                        │
              └──────────────────┬─────────────────────┘
                                 │ Loader::load(bytes) -> BinaryView
                                 ▼
              ┌────────────────────────────────────────┐
              │       rustre-core :: BinaryView         │
              │  SegmentMapping, SectionMap,            │
              │  Address space (VA ↔ file offset),      │
              │  rustre-mem memory providers,           │
              │  EventBus (CoreEvent broadcast)         │
              └──┬───────────────┬────────────────┬────┘
                 │               │                │
                 ▼               ▼                ▼
     ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
     │ arch-registry│  │  symbols     │  │   rustre-graph   │
     │ detect ISA:  │  │  PDB / DWARF │  │  KnowledgeGraph  │
     │ ELF e_machine│  │  CodeView /  │  │  (15 tables,     │
     │ PE Machine   │  │  STABS       │  │   SQLite/MySQL)  │
     │ Mach-O cpu   │  │  FLIRT match │  │                  │
     └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
            │                 │                    │
            ▼                 │                    │
  ┌─────────────────┐         │ symbol names       │ store funcs/xrefs
  │  ISA backend:   │         │                    │
  │  iced-x86 /     │◄────────┘                    │
  │  yaxpeax-arm /  │                              │
  │  hand-written   │                              │
  │  (18 ISAs)      │                              │
  └────────┬────────┘                              │
           │ raw disassembly                        │
           ▼                                        │
  ┌─────────────────────────────────────────────┐  │
  │             rustre-il-lift                  │  │
  │  x86Lifter / AArch64Lifter / …             │  │
  │  ~58 000 lines, 277 todo!/unimpl            │  │
  │  Output: IrExpr / Effect (Lift tier)        │  │
  └────────────────┬────────────────────────────┘  │
                   │ Lift tier IR                   │
                   ▼                                │
  ┌─────────────────────────────────────────────┐  │
  │             rustre-il-llil                  │  │
  │  LlilExpr: Add/AddT, Jump/JumpDest …        │  │
  │  (dual-form legacy variants)                │  │
  │  12 todo! — register resolution partial     │  │
  └────────────────┬────────────────────────────┘  │
                   │ LLIL                           │
                   ▼                                │
  ┌─────────────────────────────────────────────┐  │
  │          rustre-il-mlil (SSA form)          │  │
  │  llil_to_mlil_bridge:                       │  │
  │   4 calling conventions supported:          │  │
  │   sysv_amd64, ms_x64,                       │  │
  │   arm64_aapcs, riscv64_lp64d               │  │
  │  7 todo! — MLIL not yet connected to        │  │
  │  decompiler SSA                             │  │
  └────────────────┬────────────────────────────┘  │
                   │ MLIL SSA                       │
                   ▼                                │
  ┌─────────────────────────────────────────────┐  │
  │             rustre-il-hlil                  │  │
  │  HlilExpr — high-level IL                   │  │
  │  0 explicit todo! but silent stubs          │  │
  └────────────────┬────────────────────────────┘  │
                   │ HLIL                           │
                   ▼                                ▼
  ┌─────────────────────────────────────────────────────────┐
  │                   Analysis Passes                       │
  │  (all 11 rustre-analysis-* crates: COMPLETE at lib.rs)  │
  │                                                         │
  │  CFG (Cooper+L-T dominators)  ──────────────────────►   │
  │  rustre-analysis-fn (+ .pdata RUNTIME_FUNCTION)  ────►  │
  │  rustre-analysis-dataflow (SSA, Andersen ptr)  ──────►  │
  │  rustre-analysis-vsa (strided intervals, taint)  ────►  │
  │  rustre-analysis-vtable (MSVC+Itanium RTTI)  ────────►  │
  │  rustre-analysis-xref (13 kinds, O(1) bidir)  ───────►  │
  │  rustre-analysis-callconv  ──────────────────────────►  │
  │  rustre-analysis-type, -string, -loop, -dominators  ►  │
  └──────────────────────────┬──────────────────────────────┘
                             │ enriched IL + CFG
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │                    Decompiler                           │
  │  rustre-decompiler-cfs (DREAM CFS algorithm)            │
  │  rustre-decompiler-expr (expression trees)              │
  │  rustre-decompiler-type (type system)                   │
  │  rustre-decompiler-c   (C emitter)                      │
  │  rustre-decompiler      (hub, SSA not wired to passes)  │
  │  Fallback: Ghidra headless / P-Code bridge (skeleton)   │
  └──────────────────────────┬──────────────────────────────┘
                             │ C pseudocode / AST
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │               Output Consumers                          │
  │  rustre-gui  (GPUI / "Zyphora Reversing" desktop app)   │
  │  rustre-daemon (HTTP JSON-RPC :7878 / IPC :7777)        │
  │  rustre-mcp-server (MCP JSON-RPC-2.0 over stdio/SSE)    │
  │  rustre-project (.rustre-project/ SQLite, FTS5 strings)  │
  └─────────────────────────────────────────────────────────┘
```

### 1.2 Loader → Core Wiring

The loader subsystem follows a diamond dependency pattern:

```
rustre-loader (hub)
      ↑
rustre-loader-registry
      ↑
rustre-loader-pe ──► rustre-flirt-apply (FLIRT autoname at load time)
rustre-loader-elf
rustre-loader-macho
rustre-loader-dotnet ──► rustre-arch-cil
rustre-loader-dex    ──► rustre-arch-dex
rustre-loader-apk    ──► rustre-loader-dex (APK contains DEX files)
rustre-loader-wasm   ──► rustre-arch-wasm
rustre-loader-lua    ──► rustre-arch-lua
rustre-loader-luajit ──► rustre-arch-luajit
rustre-loader-firmware
rustre-loader-ole    (CVE-2017-11882 detection built-in)
rustre-loader-pdf    (JS extraction for malware analysis)
rustre-loader-rom    (console ROMs)
rustre-loader-raw    (fallback — all binary formats)
```

Only `rustre-loader-pe` integrates FLIRT at load time. All other loaders rely on a
post-load pass invocation for symbol naming.

### 1.3 IL Tier Transitions

The 4-tier IR ladder with known gap points:

```
Lift tier (IrExpr / Effect)
   │   277 todo!/unimpl across 21 files in rustre-il-lift
   │   Lua/LuaJIT: have NO LLIL lift at all
   ▼
LLIL (LlilExpr)
   │   12 todo! — partial register resolution
   │   dual-form variants (AddT vs Add) = tech debt
   ▼
MLIL SSA
   │   7 todo!
   │   CRITICAL GAP: llil_to_mlil_bridge only supports 4 calling conventions
   │   CRITICAL GAP: MLIL not fed into decompiler SSA pass (broken bridge)
   ▼
HLIL
   │   0 explicit todo! but uses silent stubs
   ▼
C pseudocode (decompiler-c emitter)
   │   IrreducibleLoopHandler: no node-splitting, falls to Goto residue
   │   BinaryNinja / RetDec backend variants: no implementing struct
   │   SSA form disconnected from analysis pass pipeline
   ▼
Output (GUI panel / MCP tool / daemon endpoint)
```

### 1.4 Symbol Resolution Path

```
Binary loads
     │
     ├──► PDB (custom MSF parser)
     │     S_PUB32/S_GPROC32/S_LPROC32/S_GPROC32_ID/S_LPROC32_ID
     │     S_GDATA32/S_LDATA32 supported
     │     TPI field members synthesised as field_0..N
     │     rustre-symbols-codeview stub in rustre-project::import_binary_with_debug
     │     (let _ = pdb_path; — MISSING CALL)
     │
     ├──► DWARF 4/5 (rustre-symbols-dwarf)
     │
     ├──► CodeView (rustre-symbols-codeview)
     │
     ├──► STABS (rustre-symbols-stabs)
     │
     ├──► FLIRT pattern match (rustre-flirt-apply)
     │     CRITICAL GAP: IDA .sig binary tree walker is a stub
     │     → real IDA .sig files cannot be loaded
     │
     └──► Demangling (rustre-demangle)
           Itanium + MSVC (hand-written) + Rust v0/legacy + Swift (heuristic)
```

### 1.5 Analysis → Knowledge Graph Round-Trip

```
AnalysisPass::run(BinaryView)
         │
         │  emits CoreEvent via rustre-events EventBus
         │  (~50 CoreEvent variants, FilteredSubscription, ring buffer)
         ▼
rustre-graph::KnowledgeGraph
         │  add_function / add_xref / add_symbol / add_patch …
         │  15 tables (SQLite or MySQL)
         │  query_sql — SELECT/WITH only (safety gate)
         │  petgraph in-memory view (analysis_graph)
         │  DOT / GraphML / GEXF / Cytoscape / Neo4j export
         ▼
rustre-project (.rustre-project/ directory)
         │  4 migration versions
         │  FTS5 for strings
         │  undo log
         │  layout_state SQL: KNOWN GAP — updated_at column absent from v1 DDL
         ▼
rustre-daemon (HTTP :7878 / IPC :7777)
```

---

## 2. MCP Tool Surface

### 2.1 Architecture

```
External client (Claude Desktop / claude.ai / custom LLM client)
     │  JSON-RPC 2.0 over stdio  OR  SSE HTTP
     ▼
rustre-mcp-server (RustReMcpServer via rmcp SDK)
     │  486+ tools registered
     │  wire_tools() → ToolHandler trait
     ▼
rustre-mcp-tools (ToolHandler implementations)
     │
     ├──► Disassembly tools  ──► rustre-arch-* / iced-x86
     ├──► IL tools           ──► rustre-il-llil / mlil / hlil
     ├──► Decompiler tools   ──► rustre-decompiler-*
     ├──► Function tools     ──► rustre-analysis-fn
     ├──► CFG tools          ──► rustre-analysis-cfg
     ├──► Xref tools         ──► rustre-analysis-xref
     ├──► String tools       ──► rustre-analysis-string
     ├──► Symbol tools       ──► rustre-symbols-{pdb,dwarf,codeview,stabs}
     ├──► FLIRT tools        ──► rustre-flirt-{apply,gen,index}
     ├──► YARA tools         ──► rustre-yara-{engine,rules,gen}
     ├──► Hex tools          ──► rustre-hex / rustre-hex-pattern
     ├──► PE tools           ──► rustre-pe-tools / rustre-pe-editor
     ├──► Patch tools        ──► rustre-patch
     ├──► Network tools      ──► rustre-net / rustre-net-dissect
     ├──► Crypto tools       ──► rustre-crypto / rustre-findcrypt
     ├──► Triage tools       ──► rustre-triage-{entropy,peid,die}
     ├──► Mobile tools       ──► rustre-mobile-{android,ios,jadx,smali}
     ├──► .NET tools         ──► rustre-dotnet / rustre-dotnet-decompile
     ├──► Debug tools        ──► rustre-debug-registry::all()
     ├──► Emulation tools    ──► rustre-emu / rustre-emu-shellcode
     ├──► Fuzz tools         ──► rustre-fuzz-{afl,libfuzzer}
     ├──► Trace tools        ──► rustre-trace / rustre-trace-coverage
     ├──► TTD tools          ──► rustre-ttd / rustre-ttd-query
     ├──► Diff tools         ──► rustre-diff-{bindiff,semantic}
     ├──► Forensics tools    ──► rustre-forensics / rustre-forensics-plugins
     ├──► Sandbox tools      ──► rustre-sandbox / rustre-sandbox-report
     ├──► ThreatIntel tools  ──► rustre-ti-{vt,misp,shodan,otx}
     ├──► Syscall tools      ──► rustre-syscalls / -linux / -windows
     ├──► Script tools       ──► rustre-script (Rhai/Lua/Python)
     ├──► Graph tools        ──► rustre-graph::KnowledgeGraph
     └──► Agent tools        ──► rustre-agent (workflow trigger)
```

### 2.2 Known MCP Wiring Gaps

| Subsystem | Gap |
|-----------|-----|
| `rustre-mcp-federation` | `FederationManager::simulate_call` always returns stub — remote async dispatch not wired |
| `McpCoordinator` | middleware / rate-limiting / audit log not active in running binary (binary uses `RustReMcpServer` directly via rmcp SDK) |
| `rustre-debug-registry` | wiring to MCP server unclear — `all()` may not be enumerated |
| `rustre-net-proxy` / `rustre-net-rules` | only reachable via MCP wrappers, not wired to GUI directly |

### 2.3 Tool Naming Convention

Tools follow the pattern `<subsystem>_<verb>_<noun>`:

```
disasm_function_at          → arch backend
lift_to_llil                → rustre-il-lift + rustre-il-llil
decompile_function          → rustre-decompiler-cfs + rustre-decompiler-c
find_functions              → rustre-analysis-fn
get_xrefs_to / get_xrefs_from  → rustre-analysis-xref (O(1) bidir lookup)
search_strings              → rustre-analysis-string (FTS5 in rustre-project)
apply_flirt_sigs            → rustre-flirt-apply
scan_yara                   → rustre-yara-engine
analyze_apk                 → rustre-mobile-android
decompile_dotnet            → rustre-dotnet-decompile
debug_attach                → rustre-debug-registry / DebugSession
emulate_shellcode           → rustre-emu-shellcode
fuzz_afl                    → rustre-fuzz-afl
query_ttd_trace             → rustre-ttd-query
diff_binary                 → rustre-diff-bindiff
lookup_vt                   → rustre-ti-vt
run_script_rhai             → rustre-script-rhai
```

---

## 3. Agent / LLM Integration Surface

### 3.1 Crate Map

```
rustre-agent-llm (AnthropicClient)
     │  streaming SSE, tool use, vision
     │  exponential backoff retry
     │  prompt caching beta (Anthropic)
     │  per-model pricing table + atomic cost accumulator
     │  models: claude-3-5-sonnet, claude-3-opus, claude-3-haiku, claude-3-5-haiku
     ▼
rustre-agent (AgentOrchestrator)
     │  orchestrates multi-step RE tasks
     │  uses few-shot SQLite DB for prompt examples
     │  subscribes to rustre-events::CoreEvent for live analysis events
     ▼
rustre-agent-workflow (WorkflowEngine)
     │  YAML DSL: steps, retry, backoff, parallel branches
     │  SQLite + MySQL checkpointing
     │  20+ named RE workflow templates:
     │    malware_triage / function_rename / vuln_discovery /
     │    binary_comparison / deobfuscation / rop_chain_analysis …
     ▼
rustre-agent-prompts (prompt library)
     │  few-shot examples per task category
     │  system prompts for each RE domain
     ▼
rustre-mcp-tools ──► 486+ tools exposed to the LLM as callable functions
```

### 3.2 Tool-Use Loop

```
User query / trigger
        │
        ▼
AnthropicClient::stream_with_tools()
        │  sends: [system prompt, few-shot examples, user message, tools list]
        │
        ▼
Claude API response (may contain tool_use blocks)
        │
        ├─► tool call: disasm_function_at(address=0x1400…)
        │         ↓
        │   McpCoordinator::dispatch(tool_name, params)
        │         ↓
        │   ToolHandler::handle() → JSON result
        │         ↓
        │   injected back as tool_result into next API call
        │
        └─► final text response → UI / daemon response
```

### 3.3 WorkflowEngine DSL (YAML)

```yaml
# Example: malware_triage workflow
name: malware_triage
steps:
  - id: load
    tool: load_binary
    params:
      path: "{{ input.path }}"

  - id: triage
    tool: analyze_entropy
    depends_on: [load]
    retry: { max: 3, backoff: exponential }

  - id: strings_and_imports
    parallel:
      - tool: search_strings
      - tool: list_imports
    depends_on: [load]

  - id: yara_scan
    tool: scan_yara
    depends_on: [triage]
    params:
      ruleset: malware_hunting

  - id: vt_lookup
    tool: lookup_vt
    depends_on: [triage]
    params:
      hash: "{{ steps.triage.output.sha256 }}"

  - id: report
    tool: generate_report
    depends_on: [strings_and_imports, yara_scan, vt_lookup]
```

Checkpointing: each completed step is persisted to SQLite/MySQL so the workflow
survives daemon restarts.

### 3.4 Federation (Multi-Server Routing)

```
McpCoordinator
     │
     ├──► Local RustReMcpServer (primary — rmcp SDK)
     │
     └──► FederationManager
               │  health monitoring per server
               │  ClientConnection: stdio / HTTP / WebSocket
               │
               ├──► Remote MCP server A (e.g. Ghidra bridge)
               ├──► Remote MCP server B (e.g. cloud sandbox)
               └──► Remote MCP server C (e.g. MISP instance)

CRITICAL GAP: FederationManager::simulate_call returns a static stub result.
Real async dispatch to remote servers is not implemented.
```

### 3.5 GUI AI Panel

```
rustre-gui / ui/panels/ai_panel.rs
     │  uses rustre-agent-llm::AnthropicClient directly
     │  shows streaming token output
     │  user can invoke "AI Annotation" on selected function
     ▼
AnthropicClient::stream_with_tools()
     │  tool: get_function_decompilation
     │  tool: get_xrefs
     │  tool: rename_function
     ▼
Results applied back to rustre-graph::KnowledgeGraph
     (via rustre-gui's analysis/ sub-modules — wiring completeness unknown)
```

---

## 4. Plugin and Scripting Extension Points

### 4.1 Plugin Architecture

```
rustre-plugin-api            ← ABI definitions, PluginCapability (22 variants)
     │                         PLUGIN_MAGIC = b"RUSTREP\0"
     │                         PluginRegisterFn = unsafe extern "C" fn(*mut PluginRegistry)
     │                         PluginPermissions: Memory / IO / Runtime / Analysis
     │
     ├──► rustre-plugin-host ← runtime orchestrator
     │         │  SQLite: plugin_entries + plugin_settings tables
     │         │  PluginSandbox: path glob allow-list, host allow-list
     │         │  DependencyGraph: topological sort + cycle detection
     │         │  PluginHealth: error_count, heartbeat, status
     │         │  ExtensionPoint::McpTool{tool_name} — MCP-aware
     │         │  ExtensionPoint::LlmBackend — LLM-aware
     │         │
     │         │  CRITICAL GAP: DynLib arm → Err("not yet implemented")
     │         │  CRITICAL GAP: BuiltIn arm → Err("not found")
     │         │  Only Inline plugins actually load
     │         │
     ├──► rustre-plugin-loader ← file-system discovery + manifest parsing
     │         (FilePluginLoader, ManifestLoader, LoaderRegistry)
     │
     ├──► rustre-plugin-native ← libloading FFI bridge
     │         (NativeAbiBridge, NativePluginLoader, NativeSymbolResolver)
     │         CRITICAL GAP: plugin-host never calls into plugin-native
     │         → no .dll / .so plugin can load end-to-end
     │
     ├──► rustre-plugin-python ← pyo3 adapter (PythonReModule)
     │
     └──► rustre-plugin-lua   ← mlua 5.4 adapter (LuaApiProvider, LuaStateManager)
```

### 4.2 Scripting Architecture

```
rustre-script               ← unified ScriptEngine trait + ScriptPipeline
     │
     │  ScriptValue: Null|Bool|Int|Float|String|Bytes|List|Map|Address|Callable
     │  Address(u64) — RE-domain extension
     │
     │  re_module() built-ins:
     │    disassemble(addr, count)
     │    read_bytes(addr, len)
     │    find_pattern(hex_pattern)
     │    get_function_name(addr)
     │    xrefs_to/from(addr)
     │    get_strings()
     │    entropy(addr, len)
     │    get_imports() / get_exports()
     │
     │  SandboxPolicy: fs read/write, network, subprocess, max_steps
     │
     ├──► rustre-script-rhai    ← MOST COMPLETE (real rhai 1.20 engine)
     │         find_pattern with ?? wildcards
     │         entropy + entropy_classify (5 tiers)
     │         SHA-256 hashing
     │         EventBus + EventHookSystem (dual — one is dead code)
     │         rustre.actions / rustre.events / rustre.utils modules
     │
     ├──► rustre-script-lua     ← pure-Rust Lua 5.x interpreter (mlua unused at eval)
     │         rustre.* (20+ fns) / re.* (10 fns) / dbg.* (15 fns, sentinels)
     │         sandbox gate: canonical path must start_with(cwd)
     │         magic-byte format detection: PE / ELF / WASM / DEX
     │         max_steps=100_000 / call_depth=200
     │
     └──► rustre-script-python  ← pyo3 CPython + pure-Rust Python subset
               CPython: rustre module (log / version / current_binary)
               BinaryView stub — functions() and strings() return empty vecs
               Pure-Rust: 13 PyStmt / 12 PyExpr / 17 PyBinOp variants
               CRITICAL GAP: BinaryView not connected to real analysis layer
```

### 4.3 ScriptPipeline Multi-Engine Chaining

```
ScriptPipeline::execute_all()
     step 1: RhaiEngine  — binary pattern search → JSON result
          ↓  result injected as _prev into next step
     step 2: LuaEngine   — re.disasm on suspicious addresses
          ↓  result injected as _prev
     step 3: PythonEngine — classify / post-process
          ↓
     Vec<ScriptValue>
```

### 4.4 Plugin Capability Coverage of RE Pipeline

| PluginCapability | Wired Backend | Status |
|-----------------|---------------|--------|
| Loader | rustre-loader-* | Complete (inline) |
| Architecture | rustre-arch-* | Complete (inline) |
| AnalysisPass | rustre-analysis-* | Complete (inline) |
| Decompiler | rustre-decompiler-* | Complete (inline) |
| DebugBackend | rustre-debug-* | Complete (inline) |
| MlilTransform | rustre-il-mlil | Partial (inline) |
| HlilTransform | rustre-il-hlil | Partial (inline) |
| ScriptExtension | rustre-script | Substantial (inline) |
| TypeProvider | rustre-decompiler-type | Partial (inline) |
| SignatureProvider | rustre-flirt-* | Partial (inline) |
| UiPanel | rustre-gui panels | Partial (inline) |
| Workflow | rustre-agent-workflow | Complete (inline) |
| CallingConvention | rustre-analysis-callconv | Complete (inline) |
| **DynLib (external .dll/.so)** | rustre-plugin-native | **BROKEN — not wired** |
| **BuiltIn (file-system)** | rustre-plugin-loader | **BROKEN — load returns Err** |

---

## 5. Debug / Emulation / TTD Flow

### 5.1 Debugger Backend Selection

```
Consumer (MCP server / GUI debug panel / CLI)
     │
     ▼
rustre-debug-registry::all()
     │  returns Vec<Box<dyn Debugger>> — 8 backends:
     │
     ├──► FridaDebugSession    (simulated by default; frida-gum feature off)
     │      FridaHook, InterceptorRecord, stalker_engine (pure-Rust sim)
     │      ScriptTemplates: 30+ Frida JS templates
     │
     ├──► GdbDebugger          (RSP framing complete; some qXfer/vFile → Unsupported)
     │      GdbConnection (TCP), GdbPacket ($data#XX with RLE)
     │      xml_target_desc: built-in targets i386/x86-64/arm/aarch64/mips
     │      gdb_python_api bridge
     │
     ├──► KgdbSession          (simulated — models RSP exchange, no serial/net transport)
     │      kernel_struct_parser: EPROCESS/ETHREAD/PEB/TEB/KPCR/KPRCB
     │      kernel_symbols: /proc/kallsyms reader
     │
     ├──► LinuxDebugger        (real ptrace/nix on Linux; Unsupported elsewhere)
     │      ptrace_advanced: PTRACE_SINGLEBLOCK, seccomp BPF inspection
     │      perf_event_debug: PMU counters per step
     │      elf_coredump_parser: PT_LOAD/PT_NOTE, NT_PRSTATUS, NT_FILE
     │
     ├──► MacosDebugger        (Mach port types defined; real calls behind cfg(macos))
     │      mach_exception_handler, dyld_debugger, ios_debugger (Mach)
     │      dsym_reader, dtrace_integration, macos_crash_analyzer
     │
     ├──► UnicornDebugger      (simulated — wraps rustre-emu SimpleInterpreter)
     │
     ├──► WinDbgSession        (simulated — pure in-memory, explicitly no Win32)
     │      windbg_command_parser, kdump_analyzer, minidump reader
     │      IDebugControl / IDebugSymbols simulation
     │
     └──► WindowsDebugger      (real Win32 on Windows; Unsupported fallback elsewhere)
            win32_debug_api: DebugActiveProcess, WaitForDebugEvent,
                             ReadProcessMemory, GetThreadContext
            windows_internals: PEB/TEB parser, HeapWalk, ExceptionRecord
            win_heap_debug: PageHeap, HPDA, double-free/UAF/overflow detection
            pe_loader_simulation: pure-Rust PE section map + IAT patch (static)
```

### 5.2 Debugger → Emulator Bridge

```
rustre-debug-unicorn (UnicornDebugger)
     │  implements Debugger trait
     │  wraps rustre-emu::SimpleInterpreter
     ▼
rustre-emu (Emulator trait)
     │  SimpleInterpreter: x86/x86-64 partial ISA (arith/cmp/branch/push-pop/2-byte)
     │  arm_interpreter (Thumb/Thumb-2)
     │  mips_interpreter (MIPS32 LE/BE)
     │  os_emulation: Linux x86-64 + Windows x86-64 syscalls
     │  fuzzing_integration: AFL-style bitmap, snapshot-reset fuzz loop
     │  taint_emulation: taint-tracking wrapper
     │  heap_emulator: guest malloc/free simulation
     │
     ├──► rustre-emu-unicorn   (native feature OFF by default; unicorn-engine commented out)
     │      CRITICAL GAP: real libunicorn FFI requires CMake + C toolchain
     │
     ├──► rustre-emu-qiling    (Qiling-inspired OS layer)
     │      RootfsPath (dot-dot safe), SyscallTable, FdTable, ProcessEnv
     │      OsTarget: Linux / Windows / MacOs / FreeBsd / BareMetal
     │      CRITICAL GAP: syscall dispatch partially implemented
     │
     └──► rustre-emu-shellcode (sandboxed shellcode analysis)
            SHELLCODE_BASE=0x1000 / STACK_BASE=0x100000 / HEAP_BASE=0x200000
            ExitReason: RetInstruction / MaxInstructions / Timeout / InvalidMem
            api_resolver_emu: API hash resolution (common shellcode loaders)
            shellcode_unpacker, network_behavior_simulator
```

### 5.3 Time Travel Debugging (TTD) Flow

```
Process execution
     │
     ▼ (Linux: ptrace via nix; Windows: ETW stub)
rustre-ttd-recorder
     │  RecorderEngine, TtdRingBuffer (lock-free), TtdIndexBuilder
     │  EtwRecorder → TtdRecordError::NotAvailable (STUB on Windows)
     │  KernelTraceHooks: Linux ptrace-backed (real on Linux)
     │  chacha20poly1305 encryption of trace files
     │  SnapshotManager: periodic process snapshots
     ▼
rustre-ttd (core data model)
     │  TtdTrace: Arc<RwLock<Vec<TraceEvent>>>
     │  TracePosition: (seq: u64, step: u64) — Ord, Display
     │  EventKind: Instruction/MemRead/MemWrite/Call/Return/Syscall/Exception/…
     │  TtdIndex: SQLite-backed position/event-type/address-range queries
     │  TraceFilter: composable predicates
     ▼
     ├──► rustre-ttd-replay (deterministic replay)
     │         ForwardStepper / BackwardStepper (events, not CPU emulation)
     │         MemorySnapshot: 4 KiB page-granular + dirty-page diffing
     │         TtdBreakpointManager / TtdWatchpointManager
     │         CRITICAL GAP: CPU state not reconstructed (no emulator wired to stepper)
     │
     ├──► rustre-ttd-replayer (high-level time-travel)
     │         TtdReplayer: seek_to_tick / step_forward / step_backward
     │         RegisterTimeline / MemoryDiffViewer / DifferentialReplay
     │         TtdDatabase: SQLite-backed persistent replay state
     │         DEFAULT_SNAPSHOT_INTERVAL = 256 steps
     │
     └──► rustre-ttd-query (query engine)
               TtdSqlEngine: SQLite event query + BTreeIndex
               QueryEngine: tenet_navigator() — bridges rustre-trace-navigate
               TemporalQuery, MemoryTimeline, RegisterHistory, TtdCallQuery
               Re-exports: TenetBookmark, TenetNavEvent, TenetStackFrame
```

### 5.4 Trace Recording Flow

```
Hardware trace source
     │
     ├──► Intel PT (rustre-trace-pt)
     │         PtPacketKind: PSB/TNT/TIP/FUP/OVF/MODE/CYC/MTC/TSC/TMA/PIP/CBR/PAD
     │         IpCompression: SEXT48/UPDATE32/UPDATE16/SUPPR/FULL
     │         PtFlowReconstructor: stateful flow reconstruction via TNT bits
     │         pt_perf_integration: structural (not wired to live perf fd)
     │
     ├──► ARM CoreSight ETM4/ETE (rustre-trace-coresight)
     │         ExceptionType: Reset/Svc/IRQ/FIQ/HVC/SMC/SError/Debug
     │         EtmVersion: Etm3/Etm4/Ete
     │         TpiuSink: TPIU de-framing
     │         coresight_topology: ROM table discovery (structural)
     │
     ├──► DRcov / LCOV import (rustre-trace-coverage)
     │         DrcovModule + DrcovBbEntry: DynamoRIO format
     │         CoverageDatabase: multi-run aggregation
     │         EdgeCoverage / BlockCoverage / BranchCoverage / FunctionCoverage
     │         DifferentialCoverage: A-only / B-only / A∩B
     │         CoverageTimeline: coverage growth over time
     │
     └──► Tenet-style navigation (rustre-trace-navigate)
               TraceEntry: index, ip, EntryKind, registers, mem accesses
               TraceNavigator: step_forward/back, jump_to, run_until (bidirectional)
               Bookmark manager, call tree navigator
               rusqlite + bincode for persistent trace index
```

### 5.5 Fuzz ↔ Trace ↔ TTD Integration

```
rustre-fuzz-afl::AflFuzzer::fuzz_one()
     │  AflShmCoverage: 64 KiB AFL bitmap
     │  CmplogMap: Redqueen-style comparison mutations
     │  ForkServer state machine
     │  10 concrete Mutators (Havoc, Dictionary, Splice, …)
     │
     ▼ crash found
rustre-fuzz-cov (coverage feedback)
     │  DECLARED: pt_integration → rustre-trace-pt
     │  DECLARED: qemu_tcg_cov → QEMU TCG
     │  NOT WIRED to live PT/TCG sources (gap P1)
     │
     ▼ crash input
rustre-ttd-recorder (record crash reproduction)
     │  snapshot-based fuzz loop (gap — rustre-fuzz → rustre-ttd not wired)
     │
     ▼
rustre-ttd-replay → rustre-ttd-query
     (query register/memory state at crash point)
```

### 5.6 Android Debug Bridge

```
rustre-adb (standalone — no debug/emu deps)
     │  ADB host wire protocol (TCP :5037)
     │  24-byte AdbMessage low-level USB/transport
     │  RSA auth handshake (make_auth_public_key / make_auth_signature)
     │
     ├──► pull_file / push_file (real async TcpStream)
     ├──► logcat parsing (threadtime/brief/binary formats)
     ├──► package manager: parse_pm_list / parse_pm_dump
     └──► android_package_analyzer: APK static analysis
     │
     ▼ (feeds into)
rustre-mobile-android (ApkAnalyzer)
rustre-mobile-apktool (CliApktoolRunner — spawns apktool subprocess)
rustre-mobile-jadx   (CliJadxRunner — spawns jadx subprocess)
```

---

## 6. Obfuscation-Resistant Paths

### 6.1 Deobfuscation Subsystem Overview

```
Obfuscated binary
     │
     ├──► Static deobfuscation
     │         rustre-deobf (hub)
     │         rustre-deobf-string      (XOR/ROT/RC4 string decryptor)
     │         rustre-deobf-control     (opaque predicate removal, CFG normalisation)
     │         rustre-deobf-vm          (VM-based protector devirtualisation)
     │         rustre-deobf-pack        (UPX/MPRESS/custom unpacker stubs)
     │         rustre-deobf-anti        (anti-analysis trick bypasses)
     │
     │         Input: rustre-il-llil / rustre-il-mlil IL
     │         Output: normalised IL fed back into analysis passes
     │
     ├──► Dynamic deobfuscation (via emulation)
     │         rustre-emu-shellcode::shellcode_unpacker
     │         → emulate packing loop → extract decrypted payload
     │         → restart pipeline with decrypted bytes
     │
     └──► Cryptographic constant detection
               rustre-findcrypt / rustre-crypto
               → identifies AES S-boxes, RSA primes, ECDSA curves, hash IVs
               IDA baseline: 43 crypto constants on cargo-zyphora.exe (tied)
```

### 6.2 Symbolic Execution Path

```
Function under analysis
     │
     ▼
rustre-il-mlil (SSA form)
     │  SymExpr AST mirrored in rustre-symb
     │
     ▼
rustre-symb-engine
     │  SymbolicState: register file + memory map of SymExpr
     │  CRITICAL GAP: x86-64 instruction transfer functions missing
     │    → engine cannot step x86-64 concretely
     │
     ▼
rustre-symb-z3 (Z3 SMT backend)
     │  CRITICAL GAP: rustre-symb-z3::SymExpr duplicates rustre-symb::SymExpr
     │    with NO CONVERSION BRIDGE
     │    → Z3 solver unreachable from engine
     │
     ▼ (intended output — not yet functional end-to-end)
Path condition ──► constraint solving ──► input generation
     │
     ├──► vulnerability discovery (buffer overflow preconditions)
     ├──► deobfuscation (opaque predicate resolution)
     └──► property verification (memory safety)
```

### 6.3 Taint Analysis Path

```
rustre-symb-taint
     │  TaintBitmask: 64-bit bitmask (64 independent taint sources)
     │  TaintState: per-register + per-address taint tracking
     │  TaintPolicy: source / sink / sanitiser rules
     │
     ├──► rustre-emu::taint_emulation
     │     TaintEmulator wraps any Emulator impl
     │     propagates taint through arithmetic/memory ops
     │
     └──► rustre-analysis-vsa
           strided intervals + taint metadata per VSA cell
           feeds into rustre-analysis-dataflow (Andersen pointer analysis)
```

### 6.4 Decompiler Deobfuscation Integration

```
rustre-decompiler
     │
     ├──► rustre-mobile-jadx::deobfuscation_pass (Android only)
     │     renames obfuscated identifiers (ProGuard reversal)
     │
     ├──► rustre-dotnet::obfuscation_remover (.NET only)
     │     renames ConfuserEx / SmartAssembly obfuscated names
     │
     └──► rustre-deobf-vm (native)
           devirtualises VM-protected code
           produces LLIL-equivalent output
           feeds rustre-il-llil → full decompile path
```

### 6.5 Anti-Analysis Bypass Table

| Technique | RustRE Countermeasure | Status |
|-----------|----------------------|--------|
| String encryption (XOR/RC4) | rustre-deobf-string | declared |
| Opaque predicates | rustre-deobf-control | declared |
| VM protection (VMP/Themida) | rustre-deobf-vm | declared |
| UPX/MPRESS packing | rustre-deobf-pack | declared |
| Anti-debug (IsDebuggerPresent etc.) | rustre-debug-frida::AntiAntiDebugScript | simulated |
| Anti-VM checks | rustre-sandbox-vm::evasion_detection | partial |
| .NET obfuscation (ConfuserEx) | rustre-dotnet::dotnet_packer_detection | partial |
| Packed .NET (SmartAssembly) | rustre-dotnet-decompile (LINQ/async recovery) | partial |
| Android ProGuard | rustre-mobile-jadx::deobfuscation_pass | partial |
| Android DexGuard | rustre-mobile-android::dex_obfuscation | partial |
| FLIRT function renaming | rustre-flirt-apply (IDA .sig stub!) | **broken** |
| Symbolic deobf | rustre-symb-engine | **broken (no x86 xfer funcs)** |

---

## 7. Mobile and .NET Dedicated Pipelines

### 7.1 Android Pipeline

```
APK file
     │
     ├──► rustre-loader-apk → rustre-loader-dex
     │         DEX class model, native lib list, permissions, certs
     │         BinaryView with rustre-arch-dex backend
     │
     ├──► rustre-mobile-android::ApkAnalyzer::parse_bytes()
     │         ZIP walk → AndroidManifest, DexClass, Certificate, ObfuscationReport
     │         threat_score (0-10), ApkAnalysisResult
     │         GAPS: AXML only extracts package name; DEX class parse is one-per-file
     │
     ├──► rustre-mobile-apktool::CliApktoolRunner::decode()
     │         spawns apktool subprocess → smali/ directories on disk
     │         ARSC parser, AXML parser, DEX parser (sub-module depth varies)
     │         ApkSignatureVerifier: v1/v2/v3 schemes
     │
     ├──► rustre-mobile-smali (Smali IR)
     │         DalvikOpcode: complete 256-entry const-fn table
     │         SmaliClass / SmaliMethod / SmaliInstr / SmaliReg
     │         instruction_size_bytes, opcode_to_smali
     │         Lexer, parser, assembler, disassembler, control-flow
     │
     ├──► rustre-mobile-jadx::CliJadxRunner::decompile()
     │         spawns jadx subprocess → DecompiledProject (JavaClass / JavaMethod)
     │         NativeDexDecompiler: ~40 opcodes fully (fallback if jadx absent)
     │         jadx_call_graph_builder (petgraph)
     │         kotlin_support, lambda_recovery
     │
     └──► rustre-adb (live device analysis)
               ADB over TCP :5037, USB ADB protocol
               logcat, pm list/dump, shell, file sync
               Feeds into rustre-mobile-android for live APK pull+analyse
```

### 7.2 iOS / macOS Pipeline

```
IPA / Mach-O file
     │
     ├──► rustre-loader-macho → rustre-arch-{x86_64, aarch64}
     │
     ├──► rustre-mobile-ipa::IpaExtractor
     │         ZIP walk → BundleEntry, IpaBundle, FairPlayDetect
     │         SwiftDemangler (links rustre-demangle)
     │         SimplePlistReader (heuristic)
     │         GAPS: bplist00 not parsed; provisioning heuristic
     │
     ├──► rustre-mobile-ios::IpaInfo::from_macho()
     │         goblin: ARC / PIE / stack canary / debug symbols
     │         scan_objc_selectors / scan_objc_classes (__TEXT sections)
     │         SwiftDemangler (heuristic _$s prefix)
     │         GAPS: bplist; full ivar layout walk
     │
     └──► rustre-mobile-dyld (dyld shared cache)
               DyldCacheParser: magic-based arch detect (real)
               CacheArch::from_magic(), ImageInfo, MappingInfo
               SlideInfo (ASLR v1–v5), SubCacheInfo (iOS 16+ split caches)
               DyldExportsTrie, ObjcSelectorDb
               GAPS: bind/rebase opcode parsing varies
```

### 7.3 .NET Pipeline

```
.NET PE (EXE / DLL / NuGet)
     │
     ├──► rustre-loader-dotnet → rustre-arch-cil
     │         BinaryView with CIL instruction set
     │
     ├──► rustre-dotnet-metadata::MetadataReader
     │         ECMA-335: all 45 metadata table row types
     │         PE parsing: metadata root, streams, heaps
     │         TypeDefRow, MethodDefRow, FieldRow, ParamRow, AssemblyRow …
     │         MetadataResolver: token-to-row, cross-table navigation
     │         GenericResolver: generic type/method instantiation
     │         CustomAttributeReader, AssemblyResolver (follows AssemblyRef)
     │         CIL disassembler (il_disassembler)
     │
     ├──► rustre-dotnet (high-level model)
     │         CilInstruction: opcode + CilOperand
     │         CilOperand: None/Int8/Int32/Int64/Float/String/Token/Branch/Switch
     │         MethodBody, DotnetType, DotnetMethod, AssemblyFile
     │         il_decoder (byte stream → Vec<CilInstruction>)
     │         cil_control_flow (CFG from CIL)
     │         dotnet_packer_detection (ConfuserEx, SmartAssembly, etc.)
     │         dotnet_string_decrypt
     │         obfuscation_remover
     │
     ├──► rustre-dotnet-decompile (CIL → C#)
     │         linq_recovery / linq_recovery_full (LINQ expression trees)
     │         async_recovery (async/await state-machine reversal)
     │         csharp_patterns
     │         GAPS: core decompiler loop in sub-modules (depth unknown)
     │
     └──► rustre-dotnet-edit (assembly mutation — dnSpy-style)
               assembly_patcher, metadata_editor, method_body_editor
               cil_injector, cil_patcher, cil_optimizer, il_recompile
               type_injector, resource_editor, strong_name_editor
               assembly_signer, assembly_merger
               GAPS: write-back to PE bytes (il_recompile) partially done
```

### 7.4 Mobile + .NET MCP Exposure

```
MCP tool: analyze_apk
     → rustre-mobile-android::ApkAnalyzer
     → returns: manifest, threat_score, obfuscation_flags

MCP tool: decompile_apk
     → rustre-mobile-jadx::CliJadxRunner (or NativeDexDecompiler fallback)
     → returns: DecompiledProject (JavaClass list)

MCP tool: analyze_ios_binary
     → rustre-mobile-ios::IosSecurityChecker
     → returns: IosSecurityReport (ARC/PIE/canary/debug)

MCP tool: decompile_dotnet
     → rustre-dotnet::il_decoder + rustre-dotnet-decompile
     → returns: C# pseudocode per method

MCP tool: edit_dotnet_assembly
     → rustre-dotnet-edit::assembly_patcher
     → applies rename/inject/strip/merge
```

---

## 8. Forensics / Sandbox / Threat-Intel Side-Flows

### 8.1 Complete Side-Flow Architecture

```
╔═══════════════════════════════════════════════════════════════════╗
║                    BINARY UNDER ANALYSIS                         ║
╚═════════════════════╦═════════════════════╦═══════════════════════╝
                      │                     │
            Static Side                Dynamic Side
                      │                     │
            ┌─────────▼──────┐    ┌─────────▼──────────────┐
            │ rustre-forensics│    │    rustre-sandbox       │
            │  MemoryImage    │    │  SandboxPolicy          │
            │  trait:         │    │  BehaviorEventType (16) │
            │  RawMemory      │    │  NetworkCapture          │
            │  ElfCoredump    │    │  SandboxOrchestrator     │
            │  Minidump       │    └────┬───────────────┬─────┘
            │  hash (MD5-     │         │               │
            │  SHA512 inline) │    ┌────▼────┐    ┌─────▼──────┐
            │  ForensicsReport│    │-monitor │    │  -vm        │
            │  ForensicsDb    │    │ApiMonitor│   │ QEMU/QMP   │
            │  timeline +     │    │eBPF stub │   │ VmConfig   │
            │  CaseManager    │    │TCP guest │   │VmSnapshot  │
            └────────┬────────┘    │agent srv │   │ (stubs)    │
                     │             └────┬─────┘   └─────┬──────┘
              ┌──────▼──────┐          │                 │
              │ -mem         │     ┌────▼──────┐   ┌─────▼──────┐
              │ WindowsAnal  │     │ -extract  │   │  -report   │
              │ LinuxAnalyz  │     │ SandboxArt│   │ MITRE map  │
              │ VAD tree     │     │ c2_extrac │   │ IOC extract│
              │ EPROCESS walk│     │ config_db │   │ HTML/JSON  │
              │ task_struct  │     │ ransomware│   │ PDF stub   │
              └──────┬───────┘     └──────┬────┘   └──────┬─────┘
                     │                    │                │
              ┌──────▼───────┐            │    ┌──────────▼──────┐
              │ -fs           │            │    │ rustre-sysintern│
              │ MemFsNode     │            │    │ ProcMon equiv.  │
              │ FUSE (Unix)   │            │    │ Autoruns equiv. │
              │ NTFS/FAT32/   │            │    │ TCPView equiv.  │
              │ ext4 parsers  │            │    │ Sigcheck equiv. │
              │ .lnk parser   │            │    │ VMMap equiv.    │
              └──────┬────────┘            │    └─────────────────┘
                     │                     │
              ┌──────▼────────────────────▼─────────────────────┐
              │              rustre-forensics-plugins            │
              │  ForensicsPlugin trait + PluginRegistry          │
              │  browser_history / registry_artifacts /          │
              │  prefetch / lnk / event_log / network_artifacts /│
              │  memory_strings / process_artifacts /            │
              │  file_timeline / credential_artifacts            │
              └─────────────────────┬───────────────────────────┘
                                    │  ForensicsArtifact / IoC
                                    ▼
                    ┌───────────────────────────────────┐
                    │        rustre-threatintel         │
                    │  IoC / IoCType / ThreatActor      │
                    │  MalwareFamily / MITRE ATT&CK     │
                    │  TiProvider trait (async)         │
                    │  IoCStore (SQLite + MySQL option) │
                    │  EnrichmentPipeline (GeoIP/WHOIS) │
                    │  STIX 2.1 / MISP feed parsing     │
                    └───────┬──────────────────┬────────┘
                            │                  │
               ┌────────────▼──┐    ┌──────────▼──────────┐
               │ ti-vt          │    │  ti-correlate        │
               │ VtClient +     │    │  petgraph IOC graph  │
               │ rate limiter + │    │  HungarianMatcher    │
               │ SQLite cache   │    │  BehavioralClusterer │
               │ petgraph VT    │    │  CampaignCorrelation │
               │ graph API      │    │  TtpAnalysis         │
               │ retrohunt      │    │  ActorAttributor     │
               ├────────────────┤    └─────────────────────┘
               │ ti-misp         │
               │ 100+ MispAttr  │
               │ STIX round-trip│
               │ MISP automation│
               ├────────────────┤
               │ ti-malpedia    │
               │ YARA download  │
               │ tokio-rustls   │
               ├────────────────┤
               │ ti-otx         │
               │ pulse parser   │
               ├────────────────┤
               │ ti-shodan      │
               │ ICS protocols  │
               │ (S7/Modbus/EIP)│
               └────────────────┘
```

### 8.2 Static Analysis → TI Round-Trip

```
rustre-loader-pe / rustre-analysis-string
     │  extract SHA256, embedded IPs, domains, URLs
     │
     ▼
rustre-threatintel::IoC
     │  ioc_extractor: pattern-based extraction from raw text
     │  ioc_normalizer: canonicalise values
     │
     ▼
TiProvider::query(&ioc) ──► rustre-ti-vt / rustre-ti-misp / rustre-ti-otx
     │
     ▼
TiResult { verdict: Malicious, score: 85, tags: ["emotet", "c2"] }
     │
     ▼
rustre-ti-correlate::IocCorrelator
     │  CorrelationKind: SharedThreatActor / SharedMalwareFamily /
     │    SimilarHash / NetworkInfrastructure / TemporalProximity
     │
     ▼
rustre-sandbox-report::SandboxReportBuilder + mitre_mapping_full
     │
     ▼
HTML / JSON / Markdown report via MCP tool: generate_threat_report
```

### 8.3 Dynamic Analysis → Forensics Feed

```
rustre-sandbox-vm (QEMU/QMP)
     │  VmInstance with QMP socket
     │  GAPS: no tokio::process::Command for QEMU spawn visible
     │
     ▼ behavioral events via TCP guest agent
rustre-sandbox-monitor
     │  ApiCall: name / category / pid / tid / timestamp / args / ret
     │  ApiCategory: FileSystem/Network/Registry/Process/Memory/Crypto/…
     │  BehaviorClassifier + AnomalyDetector
     │
     ▼
rustre-sandbox-extract
     │  SandboxArtifact: DroppedFile / NetworkConn / MemoryDump / Config
     │  crypto_key_finder: AES/RSA key material in memory
     │  c2_extractor: regex-based C2 config extraction
     │  ransomware_analysis / ransomware_detector
     │
     ▼
rustre-forensics
     │  ForensicsTimeline: merge sandbox events with static timeline
     │  EvidenceHash: multi-algorithm (MD5/SHA1/SHA256/SHA512 inline)
     │  ChainOfCustody log
     │
     ▼
rustre-forensics-plugins (Volatility-style)
     │  credential_artifacts (LSASS / SAM / Kerberos / DPAPI)
     │  memory_strings (multi-encoding)
     │  file_timeline (MFT / MACB / USN Journal)
```

### 8.4 Threat Intel Completeness

| Provider | Implementation | Rate Limit | Cache |
|----------|---------------|-----------|-------|
| VirusTotal v3 | PARTIAL-COMPLETE | token bucket (4 req/min free) | SQLite TTL |
| MISP REST | PARTIAL-COMPLETE | reqwest client | none visible |
| Malpedia | PARTIAL | tokio-rustls | SQLite |
| AlienVault OTX | PARTIAL | reqwest | none visible |
| Shodan | PARTIAL | reqwest | none visible |
| OpenCTI GraphQL | PARTIAL-STUB | reqwest | none visible |
| MalwareBazaar | thin wrapper in rustre-threatintel | none | none |

---

## 9. Integration Gaps and Completeness Matrix

### 9.1 Scoring Rubric

```
0 = absent / not started
1 = type stubs / declarations only
2 = partial — core algorithms implemented but key paths missing
3 = substantial — end-to-end for common cases; edge cases missing
4 = mostly complete — known gaps are minor or non-critical
5 = complete and tested
```

### 9.2 Subsystem Completeness Matrix

```
┌─────────────────────────────────┬───────┬────────────────────────────────────┐
│ Subsystem                       │ Score │ Critical Gaps                      │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Core (BinaryView, EventBus,     │   4   │ grpc_server module declared but     │
│ rustre-db, rustre-mem, daemon)  │       │ tonic absent from Cargo.toml;       │
│                                 │       │ layout_state SQL missing updated_at  │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Loader subsystem (15 loaders)   │   4   │ FLIRT autoname only in PE loader;   │
│                                 │       │ OLE/PDF parsers are bespoke         │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Architecture backends (20 ISAs) │   3   │ Lua/LuaJIT: NO LLIL lift;          │
│                                 │       │ ARM/MIPS/PPC/RISC-V partial;        │
│                                 │       │ only x86/AArch64 complete           │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ IL lifting (rustre-il-lift)     │   2   │ 277 todo!/unimpl across 21 files;   │
│                                 │       │ largest gap in the entire pipeline  │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ LLIL                            │   3   │ 12 todo!, dual-form tech debt       │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ MLIL SSA                        │   2   │ Only 4 calling conventions; bridge  │
│                                 │       │ to decompiler SSA BROKEN            │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ HLIL                            │   2   │ Silent stubs; no explicit todo! but │
│                                 │       │ completeness unverified             │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ IL passes (rustre-il-passes)    │   3   │ 17 todo!                            │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Analysis passes (11 crates)     │   4   │ All COMPLETE at lib.rs level;       │
│                                 │       │ .pdata integration for IDA parity   │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Decompiler (6 crates)           │   3   │ SSA not wired to passes; BinNinja / │
│                                 │       │ RetDec backends: no impl struct;     │
│                                 │       │ IrreducibleLoopHandler: no splitting │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Symbols: PDB / DWARF / CV /     │   3   │ PDB: TPI field members synthesised; │
│ STABS / demangling              │       │ import_binary_with_debug stub        │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ FLIRT                           │   2   │ IDA .sig binary tree walker STUB —  │
│                                 │       │ real IDA .sig files unloadable      │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Symbolic execution              │   1   │ No x86-64 xfer funcs in engine;    │
│                                 │       │ SymExpr bridge to Z3 MISSING;       │
│                                 │       │ solver unreachable end-to-end       │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ MCP server + tools              │   4   │ FederationManager::simulate_call    │
│                                 │       │ stub; McpCoordinator middleware off │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Agent / LLM / Workflow          │   4   │ AnthropicClient complete; workflow  │
│                                 │       │ 20+ templates; federation BROKEN    │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Plugin system                   │   2   │ Native plugin loading BROKEN end-   │
│                                 │       │ to-end; only inline plugins work    │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Scripting (Rhai/Lua/Python)     │   3   │ Rhai most complete; Python BinaryView│
│                                 │       │ stub; Lua mlua unused               │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Debug subsystem (8 backends)    │   3   │ Win32 real on Windows; GDB RSP     │
│                                 │       │ partial; Frida/Unicorn simulated    │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Emulation (emu / emu-*)         │   2   │ SimpleInterpreter partial ISA;      │
│                                 │       │ Unicorn native feature OFF;         │
│                                 │       │ Qiling syscall dispatch partial     │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ TTD (recorder / replay / query) │   2   │ ETW recorder STUB on Windows;      │
│                                 │       │ CPU state not reconstructed in      │
│                                 │       │ replay; Nirvana format partial      │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Trace (PT / CoreSight / cov)    │   3   │ PT packet decoder complete; perf   │
│                                 │       │ integration structural; CoreSight   │
│                                 │       │ ROM table structural                │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Fuzz (AFL++ / libFuzzer / net)  │   4   │ AFL++ and libFuzzer COMPLETE;      │
│                                 │       │ PT→fuzz coverage not wired;         │
│                                 │       │ corpus persistence gap (libFuzzer)  │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Diff (core / bindiff / semantic)│   3   │ WL hash + Hungarian complete;       │
│                                 │       │ SMT equivalence not wired           │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Mobile: Android                 │   3   │ ZIP/magic parse real; AXML only     │
│                                 │       │ extracts package name; no full DEX  │
│                                 │       │ class parse                         │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Mobile: iOS / dyld              │   3   │ goblin-based security real; bplist  │
│                                 │       │ heuristic; ObjC ivar walk partial   │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ .NET (metadata / decompile)     │   3   │ All 45 table rows; CIL IR complete; │
│                                 │       │ C# decompiler body depth unknown;   │
│                                 │       │ write-back to PE partial            │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Forensics (core / mem / fs /    │   3   │ Core COMPLETE with real hash impls; │
│ plugins)                        │       │ ForensicsDb.with_url not connected; │
│                                 │       │ kernel profile offsets unknown      │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Sandbox (core / monitor /       │   2   │ Framework types COMPLETE; eBPF stub;│
│ extract / report / vm)          │       │ DLL injection stub; QEMU not spawned│
│                                 │       │ PDF report stub                     │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ ThreatIntel (core + 7 providers)│   3   │ VT + MISP most complete; OpenCTI   │
│                                 │       │ stub; mysql feature off; custody    │
│                                 │       │ timestamp hardcoded zero            │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Syscalls (core / linux / win)   │   3   │ Rich type system + tables; largest  │
│                                 │       │ files (311KB/361KB) not fully read  │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ GUI (rustre-gui "Zyphora")      │   3   │ Window + main panels wired; no unit │
│                                 │       │ tests; analysis→graph wiring untested│
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Hex editor (hex / view / pat /  │   5   │ COMPLETE with 100-200+ tests each   │
│ template)                       │       │                                     │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Network (net / dissect / pcap / │   5   │ COMPLETE; C2 sig list static only   │
│ proxy / rules)                  │       │                                     │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Patch / PE tools / PE rebuild   │   5   │ COMPLETE; assemble_simple is minimal│
│                                 │       │ assembler (JMP/NOP/INT3 only)       │
├─────────────────────────────────┼───────┼────────────────────────────────────┤
│ Knowledge graph (rustre-graph)  │   4   │ COMPLETE CRUD; no schema migration  │
└─────────────────────────────────┴───────┴────────────────────────────────────┘
```

### 9.3 Priority Gap Summary (Ranked by Pipeline Impact)

```
P0 — IL LIFT (score 2)
     277 todo!/unimpl in rustre-il-lift across 21 files
     Lua/LuaJIT lifters absent entirely
     Every decompile, analysis, and symbolic path depends on this
     → Fix: complete x86-64 lifter first (highest usage)

P0 — MLIL-to-DECOMPILER SSA BRIDGE (score 2)
     MLIL SSA output not consumed by decompiler SSA pass
     Only 4 calling conventions in llil_to_mlil_bridge
     → Fix: wire mlil_ssa → decompiler::ssa_form; add ms_x64 fallback first

P1 — IDA .sig LOADER STUB (score 2)
     rustre-flirt: binary tree walker for IDA .sig files is a stub
     Prevents importing any existing IDA FLIRT signature library
     Directly impacts IDA parity for function naming
     IDA baseline: 1456 functions named via FLIRT on cargo-zyphora.exe
     → Fix: implement sig_binary_tree_walker in rustre-flirt-index

P1 — SYMBOLIC EXECUTION BRIDGE (score 1)
     rustre-symb-z3::SymExpr has NO bridge to rustre-symb::SymExpr
     rustre-symb-engine has NO x86-64 instruction transfer functions
     Deobfuscation, vulnerability discovery, property verification all blocked
     → Fix: (a) add From<rustre_symb::SymExpr> for rustre_symb_z3::SymExpr
             (b) implement x86-64 semantics in symb_engine::step_x86_64

P1 — NATIVE PLUGIN LOADING BROKEN (score 2)
     rustre-plugin-host DynLib arm → Err("not yet implemented")
     rustre-plugin-native never called by plugin-host
     No external .dll/.so plugin can load
     → Fix: enable dynamic-plugins feature; wire NativePluginLoader into
             PluginHost::load_plugin DynLib arm

P2 — TTD CPU RECONSTRUCTION (score 2)
     rustre-ttd-replay::ForwardStepper steps events but not CPU instructions
     Register state at arbitrary positions not reconstructable
     Windows ETW recorder returns NotAvailable
     → Fix: wire rustre-emu (or unicorn native feature) into ForwardStepper

P2 — PYTHON BINARYVIEW STUB (score 2)
     rustre-script-python BinaryView.functions() / .strings() return empty
     Python scripts cannot read any binary analysis data
     → Fix: connect BinaryView to rustre-core::BinaryView via pyo3 Arc wrapper

P2 — UNICORN NATIVE FEATURE OFF (score 2)
     rustre-emu-unicorn: unicorn-engine = "2" commented out in Cargo.toml
     All emulation falls back to SimpleInterpreter (partial x86 ISA only)
     → Fix: add unicorn-engine dep + CMake feature flag

P3 — FLIRT + PDB INTEGRATION IN PROJECT (score 3)
     rustre-project::import_binary_with_debug:
       let _ = pdb_path; — actual rustre-symbols-codeview call missing
     → Fix: call rustre_symbols_codeview::load_pdb(pdb_path) and populate
             KnowledgeGraph with extracted names

P3 — FEDERATION DISPATCH STUB (score 3)
     FederationManager::simulate_call always returns static stub
     No real async HTTP/stdio dispatch to remote MCP servers
     → Fix: implement ClientConnection::call() for HTTP transport

P3 — DEOBF SUBSYSTEM WIRING (score 2→3)
     rustre-deobf-* crates declared but IL↔deobf round-trip unverified
     → Fix: wire rustre-deobf-control::remove_opaque_predicates(mlil) →
             feed cleaned MLIL back into analysis passes

P4 — SANDBOX VM (score 2)
     rustre-sandbox-vm has no visible tokio::process::Command for QEMU spawn
     Dynamic analysis requires a running QEMU instance
     → Fix: implement VmOrchestrator::spawn_qemu() via tokio::process::Command

P4 — AXML FULL PARSER (score 3)
     rustre-mobile-android: only package name extracted from binary AXML
     All permission/component/SDK-level data stays zero in real parses
     → Fix: implement full AXML attribute decoder in android_manifest_parser
```

### 9.4 IDA Pro Parity Scorecard

| Capability | IDA Pro (baseline) | RustRE | Delta | Blocker |
|-----------|-------------------|--------|-------|---------|
| Functions found | 1 456 | 1 726 (+18.5%) | **RustRE wins** | — |
| Named functions | 395 | ~unknown | gap likely | FLIRT .sig stub |
| Crypto constants | 43 | 43 (tied) | even | — |
| Xrefs | 13 735 | 13 735 (tied) | even | — |
| C pseudocode | full | partial | IDA wins | SSA bridge broken |
| Type reconstruction | full | partial | IDA wins | HLIL stubs |
| PDB import | full | partial | IDA wins | import_binary_with_debug stub |
| FLIRT autoname | full | broken | IDA wins | .sig tree walker stub |
| Python scripting | full IDAPython | partial (BinaryView stub) | IDA wins | — |
| IL / microcode | full | 4-tier (partial) | IDA wins | lift todo!s |
| Decompiler quality | mature | DREAM CFS + HLIL (young) | IDA wins | — |
| Mobile analysis | plugin-only | 7 dedicated crates | **RustRE wins scope** | AXML/DEX gaps |
| .NET decompile | ILSpy-level | CIL→C# partial | IDA wins | decompiler body |
| LLM/MCP integration | none | 486+ MCP tools | **RustRE wins** | — |
| Fuzzing | none | AFL++ + libFuzzer | **RustRE wins** | — |
| Sandbox | none | framework (partial) | **RustRE wins scope** | VM spawn stub |
| ThreatIntel | none | 7 providers | **RustRE wins** | provider stubs |
| Forensics | none | Volatility-style | **RustRE wins scope** | profile offsets |
| TTD / time travel | WinDbg-style | modelled | IDA wins (impl) | CPU recon stub |
| Diff (BinDiff) | BinDiff plugin | WL+Hungarian | comparable | reporting partial |

### 9.5 Wiring Graph: Cross-Subsystem Dependencies Not Yet Connected

```
rustre-fuzz-cov::pt_integration
     ──────────────────────────────── NOT CONNECTED ──► rustre-trace-pt

rustre-ttd-replay::ForwardStepper
     ──────────────────────────────── NOT CONNECTED ──► rustre-emu (CPU)

rustre-plugin-host::DynLib
     ──────────────────────────────── NOT CONNECTED ──► rustre-plugin-native

rustre-symb-engine
     ──────────────────────────────── NOT CONNECTED ──► rustre-symb-z3

rustre-project::import_binary_with_debug
     ──────────────────────────────── NOT CONNECTED ──► rustre-symbols-codeview

rustre-diff-semantic::SemanticEquivalenceChecker
     ──────────────────────────────── NOT CONNECTED ──► z3 crate

rustre-script-python::BinaryView
     ──────────────────────────────── NOT CONNECTED ──► rustre-core::BinaryView

rustre-sandbox-vm::VmOrchestrator
     ──────────────────────────────── NOT CONNECTED ──► QEMU binary (no spawn)

FederationManager::simulate_call
     ──────────────────────────────── NOT CONNECTED ──► remote MCP servers

rustre-debug-registry
     ──────────────────────────────── MAY NOT BE WIRED ──► rustre-mcp-server
```

### 9.6 Stable Public Integration Points

The following cross-subsystem contracts are stable and implemented:

```
rustre-core :: BinaryView + SegmentMapping
     → consumed by all loaders, all arch backends, all analysis passes

rustre-events :: CoreEvent (50 variants) + FilteredSubscription
     → produced by analysis passes, consumed by rustre-agent + rustre-project

rustre-mem :: MemoryProvider trait (35 modules)
     → consumed by rustre-debug, rustre-emu, rustre-forensics-mem

rustre-il :: IrExpr + Effect (Lift tier)
     → produced by rustre-il-lift, consumed by rustre-il-llil

rustre-debug :: Debugger trait (27 async methods)
     → implemented by 8 backends, consumed via rustre-debug-registry::all()

rustre-emu :: Emulator trait (14 methods)
     → implemented by SimpleInterpreter (partial), rustre-emu-unicorn (stub)

rustre-forensics :: MemoryImage trait
     → implemented by RawMemoryImage / ElfCoredumpImage / MinidumpImage
     → consumed by rustre-forensics-{mem,fs,plugins}

rustre-threatintel :: TiProvider trait
     → implemented by 7 provider crates
     → consumed by EnrichmentPipeline + ti-correlate

rustre-script :: ScriptEngine trait
     → implemented by Rhai / Lua / Python engines
     → consumed by rustre-script::ScriptPipeline

rustre-fuzz :: TargetExecutor trait + CoverageMap
     → consumed by rustre-fuzz-afl, rustre-fuzz-libfuzzer

rustre-plugin-api :: Plugin trait
     → consumed by rustre-plugin-host (inline plugins only, currently)

rustre-graph :: KnowledgeGraph (15-table SQLite/MySQL)
     → consumed by rustre-gui, rustre-daemon, rustre-agent
```

---

*End of document. All nine cross-cutting views are complete.*
