# RustRE — Workspace Architecture Overview

> Generated: 2026-07-01
> Total workspace members: 210 crates (plus 3 GUI crates removed from project)
> Target: modular, IDA Pro-surpassing reverse-engineering platform written entirely in Rust
> License: AGPL-3.0-or-later

---

## Table of Contents

1. [Project Identity and Goals](#1-project-identity-and-goals)
2. [Build System and Workspace Layout](#2-build-system-and-workspace-layout)
3. [Key Third-Party Dependencies](#3-key-third-party-dependencies)
4. [Subsystem Map — All Crates by Domain](#4-subsystem-map--all-crates-by-domain)
   - 4.01 Core Foundation
   - 4.02 Intermediate Language (IL)
   - 4.03 Architecture Backends
   - 4.04 Loaders
   - 4.05 Analysis
   - 4.06 Decompiler
   - 4.07 Deobfuscation
   - 4.08 MCP (Model Context Protocol) Server
   - 4.09 Agents / LLM
   - 4.10 Debugging
   - 4.11 Forensics
   - 4.12 Sandbox
   - 4.13 Symbols and Debug Info
   - 4.14 Crypto Identification
   - 4.15 Mobile (Android / iOS)
   - 4.16 .NET / CIL
   - 4.17 Plugins
   - 4.18 Scripting
   - 4.19 Time-Travel Debugging (TTD)
   - 4.20 Binary Diffing
   - 4.21 Fuzzing
   - 4.22 Triage
   - 4.23 Threat Intelligence
   - 4.24 GUI
   - 4.25 Hex / Binary View
   - 4.26 Network
   - 4.27 Patching
   - 4.28 PE Tools
   - 4.29 FLIRT Signatures
   - 4.30 Emulation
   - 4.31 Symbolic Execution
   - 4.32 Syscalls
   - 4.33 Execution Trace
   - 4.34 Project Management
   - 4.35 Events
   - 4.36 Knowledge Graph
   - 4.37 Database / Persistence
   - 4.38 ADB (Android Debug Bridge)
   - 4.39 YARA
   - 4.40 Graph
   - 4.41 Demangle
   - 4.42 Memory
   - 4.43 Daemon / CLI / Binary Entry
5. [Data-Flow and Dependency Relationships](#5-data-flow-and-dependency-relationships)
6. [Size and Quality Tier Summary](#6-size-and-quality-tier-summary)
7. [Feature Flags and Conditional Compilation](#7-feature-flags-and-conditional-compilation)
8. [Removed / Deferred Crates](#8-removed--deferred-crates)
9. [Integration Test Infrastructure](#9-integration-test-infrastructure)
10. [IDA Pro Comparison Context](#10-ida-pro-comparison-context)

---

## 1. Project Identity and Goals

**RustRE** is a full-featured, modular reverse-engineering platform written in Rust, designed as a direct competitor to — and eventual replacement for — IDA Pro. The primary stated goal is to match or surpass IDA Pro across every category of static and dynamic analysis while exposing all functionality through an MCP (Model Context Protocol) server so that AI agents (Claude and similar) can drive analysis tasks programmatically.

The workspace repository is at `C:/Users/Fra/Desktop/RustRE`. The project is licensed AGPL-3.0-or-later and targets a public GitHub repository at `https://github.com/rustre/rustre`.

Key design decisions:
- **Everything in Rust.** No C wrappers where avoidable; third-party C libraries (Unicorn, Z3, Lua, Python) are linked via bindgen/FFI crates and behind optional features.
- **Workspace-first.** All components live in a single Cargo workspace with `resolver = "2"` and a shared `[workspace.dependencies]` table to prevent version skew.
- **Subsystem decomposition.** Each major analysis domain (loaders, IL, analysis, deobf, decompiler, debug, etc.) gets its own hierarchy of crates: one `rustre-<domain>` facade crate that re-exports a clean public API, plus multiple `rustre-<domain>-<sub>` implementation crates.
- **MCP as the integration boundary.** External consumers (AI agents, IDE plugins, scripts) do not call crate APIs directly — they speak MCP over stdio or SSE transport to `rustre-mcp-server`.
- **Plugin system for extensibility.** Native shared libraries, Lua scripts, and Python scripts can all extend the platform at runtime via `rustre-plugin-*` and `rustre-script-*`.

---

## 2. Build System and Workspace Layout

### Cargo Workspace

File: `Cargo.toml` (workspace root)

- `resolver = "2"` — enables the modern feature-unification algorithm which avoids pulling dev-only features into release builds.
- `[workspace.package]` — shared metadata (version `0.1.0`, edition `2024`, AGPL-3.0-or-later, keywords, categories, authors).
- `[workspace.dependencies]` — all major third-party dependencies pinned at the workspace level. Individual crates inherit these versions with `{ workspace = true }` to guarantee a single resolved version across the whole graph.
- `[workspace.lints]` — workspace-wide lint configuration:
  - `unsafe_code = "warn"` — unsafe blocks are permitted but must be visible.
  - `unused_must_use = "deny"` — no silently dropped `Result`/`Future`.
  - Clippy `all + pedantic + nursery + cargo` all set to `warn`; `multiple_crate_versions = "allow"` carved out because transitive deps force some duplicates.
- `[profile.release]` — `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip=true`. Maximally-optimized, stripped release binary.
- `[profile.dev]` — `opt-level=1`, `debug=true`. Fast iteration with some optimization.
- `[patch.crates-io]` — patches `z3-sys` with a local vendor copy that adds `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` for CMake >= 4.x compatibility.

### Directory Structure

```
RustRE/
├── Cargo.toml                   # Workspace root
├── Cargo.lock
├── vendor/
│   └── z3-sys/                  # Patched z3-sys for CMake 4.x
├── crates/
│   └── rustre-*/                # ~210 crate directories
├── tests/
│   └── integration_pipeline/    # End-to-end integration test crate
└── docs/
    ├── AUDIT.md                 # Line-count audit, tier classification
    ├── full-analysis-report.md  # Zyphora analysis sample report
    ├── README.md                # Workspace skeleton note
    └── analysis/
        └── 00-OVERVIEW.md      # This file
```

### Workspace Members (full list — 210 crates)

All members are under `crates/`. The integration test suite at `tests/integration_pipeline` is also a workspace member so it can depend on workspace crates without path-hackery.

---

## 3. Key Third-Party Dependencies

| Dependency | Version | Role |
|---|---|---|
| `tokio` | =1.40.0 (pinned) | Async runtime — all network and I/O |
| `serde` + `serde_json` + `serde_yaml` | 1.x | Serialization everywhere |
| `anyhow` / `thiserror` | 1.x / 2.x | Error handling |
| `petgraph` | 0.6 | Control-flow graphs, call graphs, dominators |
| `iced-x86` | 1.21 | Fast x86/x86-64 decoder (used in arch-x86) |
| `capstone` | 0.13 | Multi-arch disassembly fallback |
| `bad64` | 0.4 | AArch64 disassembly |
| `goblin` | 0.9 | ELF / Mach-O / PE parsing |
| `pelite` | 0.10 | PE-specific parsing and rich header analysis |
| `gimli` | 0.31 | DWARF debug info parsing |
| `object` | 0.36 | Unified object file abstraction |
| `pdb` | 0.8 | PDB symbol file parsing |
| `addr2line` | 0.22 | DWARF address-to-line lookup |
| `wasmparser` | 0.221 | WebAssembly module parsing |
| `z3` | 0.12 (static) | SMT solving for symbolic execution |
| `yara-x` | 0.9 | YARA pattern matching |
| `mlua` | 0.10 (lua54, vendored) | Lua 5.4 embedding |
| `pyo3` | 0.23 | Python embedding |
| `rmcp` | 0.1 | MCP server/client framework |
| `reqwest` | 0.12 (rustls-tls) | HTTP client for threat-intel APIs |
| `clap` | 4.x | CLI argument parsing |
| `frida-gum` | 0.14 (auto-download) | Frida instrumentation |
| `nix` | 0.29 | Linux ptrace / signal / process debugging |
| `windows-sys` | 0.59 | Windows debug/memory/thread APIs |
| `mach2` | 0.4 | macOS Mach kernel APIs for debugging |
| `rusqlite` | 0.32 (bundled) | SQLite — embedded project database |
| `sqlx` | 0.8 (sqlite + tokio-rustls) | Async SQLite for knowledge graph |
| `mysql` | 25 | Optional MySQL backend |
| `dashmap` | 6 | Concurrent hash maps |
| `rayon` | 1.x | Data-parallel analysis passes |
| `nucleo` | 0.5 | Fuzzy matching / function name search |
| `plotters` | 0.3 | Graph rendering / entropy charts |
| `fuser` | 0.14 | FUSE filesystem for forensics-fs |
| `sha2`, `md-5`, `blake2`, `aes`, `chacha20poly1305` | RustCrypto | Crypto primitives for crypto-id |
| `regex` / `aho-corasick` | 1.x | Pattern search in strings/bytes |
| `lapper` | 1.x | Interval tree for address ranges |
| `siphasher` | 1.x | Fast hashing for FLIRT |
| `rcgen` / `rustls` / `tokio-rustls` | 0.13 / 0.23 / 0.26 | TLS for MCP SSE transport |
| `hyper` / `hyper-util` / `http-body-util` | 1.x | HTTP server for SSE MCP |
| `zip`, `flate2`, `lz4_flex`, `zstd`, `xz2` | various | Decompression for loaders and sandbox |
| `criterion` | 0.5 | Benchmarking |
| `cpp_demangle` / `rustc-demangle` | 0.4 / 0.1 | Symbol demangling |
| `bincode` | 1.x | Binary serialization for caches |
| `crossbeam-channel` | 0.5 | Inter-thread event channels |

---

## 4. Subsystem Map — All Crates by Domain

### 4.01 Core Foundation

The bedrock layer. Every other crate in the workspace can depend on these.

| Crate | Role |
|---|---|
| `rustre-core` | Central type definitions: `Address`, `Segment`, `Binary`, `Function`, `Block`, `Instruction`, `Symbol`, `Xref`. Trait definitions for all major extension points. ~15,000 lines, 18 files. |
| `rustre-mem` | Memory abstraction layer: `MemoryProvider` trait, segment-mapped virtual address spaces, sparse memory maps, byte-range views, endianness helpers. ~13,000 lines, 27 files. |
| `rustre-db` | Persistence layer wrapping SQLite (`rusqlite` bundled) and SQLx for async access. Stores analysis results, function metadata, symbol tables, xrefs, type info. |
| `rustre-events` | Publish/subscribe event bus using `crossbeam-channel`. Carries analysis lifecycle events (function-discovered, xref-added, type-resolved) that decouple subsystems. |
| `rustre-graph` | Knowledge graph and call-graph infrastructure. Uses `petgraph` internally. Exports DOT, JSON, supports community detection. ~10,200 lines, 5 files. |
| `rustre-project` | Project file format (save/load an analysis session), tracks binaries, settings, bookmarks, comments, named structures. Uses SQLite via `rustre-db`. |
| `rustre-knowledge` | Semantic knowledge base: maps function hashes to known library names, links analysis results to FLIRT matches, YARA hits, threat-intel records. |
| `rustre-daemon` | Long-running background daemon that owns the analysis state and serves multiple clients (CLI, MCP server, GUI) over IPC. |
| `rustre-bin` | Workspace binary crate — the compiled `rustre` executable entry point. Bootstraps daemon or CLI depending on invocation. |
| `rustre-cli` | Command-line interface using `clap`. Sub-commands for analysis, disasm, decompile, script, diff, etc. |
| `rustre-demangle` | Unified demangling facade: routes C++ symbols through `cpp_demangle`, Rust symbols through `rustc-demangle`. |

### 4.02 Intermediate Language (IL)

The IR pipeline is the most complex and central subsystem. It defines four progressive IR levels inspired by Binary Ninja's IL hierarchy, plus a lifter that translates native code up to the lowest level.

| Crate | Role |
|---|---|
| `rustre-il` | Facade: re-exports all IL types and traits. Consumers use only this crate. |
| `rustre-il-llil` | Low-Level IL (LLIL): near-machine representation. SSA-capable register-based IR with explicit memory reads/writes, flags, and side effects. ~9,558 lines, 4 files. |
| `rustre-il-mlil` | Medium-Level IL (MLIL): variables replace registers, memory accesses are typed, calling conventions are applied. ~9,181 lines, 5 files. |
| `rustre-il-hlil` | High-Level IL (HLIL): structured control flow (if/while/for), array accesses, field accesses, typed expressions. ~8,235 lines, 4 files. |
| `rustre-il-lift` | The lifter engine: translates arch-specific decoded instructions into LLIL. Contains per-architecture lifting tables for x86, x86-64, ARM, AArch64, MIPS, RISC-V, PPC, SPARC, AVR, MSP430, 6502, Z80, BPF, WASM, DEX, CIL, JVM, Lua, LuaJIT. **The largest crate in the workspace at ~58,000 lines across 45 files.** |
| `rustre-il-passes` | Optimization and normalization passes that run on the IL: dead-code elimination, constant folding, copy propagation, SSA construction, phi-node insertion, reaching-definitions, use-def chains. ~10,230 lines, 5 files. |

**Data flow:** `arch-*` decode → `il-lift` → LLIL → `il-passes` normalize → MLIL (via `analysis-type`, `analysis-callconv`) → HLIL (via `decompiler-cfs`) → `decompiler-c` emit.

### 4.03 Architecture Backends

Each architecture crate implements the `Architecture` trait from `rustre-core`: decoding, operand classification, register sets, calling conventions, branch analysis.

| Crate | Architecture | Notable detail |
|---|---|---|
| `rustre-arch` | Facade + trait definitions | Registry integration point |
| `rustre-arch-registry` | Runtime registry | Dispatches to correct backend by machine type |
| `rustre-arch-x86` | x86 / x86-64 | Uses `iced-x86` for decoding. ~8,834 lines, 10 files. Full operand semantics including VEX/EVEX. |
| `rustre-arch-arm` | ARMv4–ARMv8 (32-bit) | Uses `capstone` ARM mode. Thumb/Thumb2 interwork. ~9,192 lines, 5 files. |
| `rustre-arch-arm64` | AArch64 | Uses `bad64`. SVE/NEON coverage. |
| `rustre-arch-mips` | MIPS32/64, MIPS16e | Uses `capstone`. Delay-slot handling. ~7,352 lines, 3 files. |
| `rustre-arch-ppc` | PowerPC 32/64, POWER ISA | Capstone-based. AltiVec/VMX. |
| `rustre-arch-riscv` | RISC-V 32/64, C, M, A, F, D extensions | Near-monolithic, needs decomposition. ~7,266 lines, 2 files. |
| `rustre-arch-sparc` | SPARC v8/v9 | Capstone-based. Register windows. |
| `rustre-arch-msp430` | MSP430 / MSP430X | Embedded microcontroller. ~7,527 lines, 8 files. |
| `rustre-arch-avr` | AVR (8-bit microcontroller) | Harvard architecture with separate code/data address spaces. |
| `rustre-arch-6502` | MOS 6502 and variants (65C02, 65816) | Used for retro / console RE. ~8,347 lines, 8 files. |
| `rustre-arch-z80` | Zilog Z80 / GB-Z80 | Game Boy ROM analysis. |
| `rustre-arch-68k` | Motorola 68000 family | Console and early workstation RE. |
| `rustre-arch-bpf` | eBPF / classic BPF | Linux kernel bytecode analysis. ~7,283 lines, 3 files. |
| `rustre-arch-wasm` | WebAssembly | Backed by `wasmparser`. |
| `rustre-arch-jvm` | JVM bytecode | Class-file instruction set. ~7,669 lines, 5 files. |
| `rustre-arch-cil` | .NET CIL / MSIL | Common Intermediate Language. |
| `rustre-arch-dex` | Android DEX bytecode | Dalvik/ART instruction set. |
| `rustre-arch-lua` | Lua 5.x bytecode | Vanilla Lua VM opcodes. |
| `rustre-arch-luajit` | LuaJIT bytecode | LuaJIT-specific opcode set. ~7,270 lines, 5 files. |

### 4.04 Loaders

Loaders parse binary formats and populate the `rustre-core` `Binary` model: segments, sections, imports, exports, relocations, symbols, entry points.

| Crate | Format |
|---|---|
| `rustre-loader` | Facade + `Loader` trait definition |
| `rustre-loader-registry` | Auto-detects format and dispatches |
| `rustre-loader-pe` | PE / PE+ (Windows executables, DLLs, drivers). Uses `goblin` + `pelite`. ~11,022 lines, 16 files. Rich header, import table, export table, TLS, resources, debug directory. |
| `rustre-loader-elf` | ELF 32/64. Uses `goblin` + `object`. ~10,678 lines, 15 files. Dynamic linking, GNU hash, version info. |
| `rustre-loader-macho` | Mach-O (macOS/iOS). Uses `goblin`. Fat binaries, dyld info, code signature. ~7,631 lines, 4 files. |
| `rustre-loader-wasm` | WebAssembly modules. Uses `wasmparser`. |
| `rustre-loader-elf` | (already listed) |
| `rustre-loader-dotnet` | .NET assemblies (CLI image). Delegates to `rustre-dotnet-metadata`. |
| `rustre-loader-android` | APK + DEX loading. Integrates with `rustre-mobile-android`. |
| `rustre-loader-java` | JAR / class files. Uses `rustre-arch-jvm`. |
| `rustre-loader-lua` | Lua bytecode chunk files. |
| `rustre-loader-luajit` | LuaJIT dump format. |
| `rustre-loader-firmware` | Raw firmware blobs: flat binary, Intel HEX, Motorola SREC, UF2. Auto-detects ROM base address. ~7,689 lines, 8 files. |
| `rustre-loader-console` | Game console ROMs: NES, SNES, GB/GBC, GBA, N64, Mega Drive. Header-based detection. |
| `rustre-loader-ole` | OLE2 compound documents (DOC, XLS, PPT, MSI). |
| `rustre-loader-pdf` | PDF with embedded JS or shellcode extraction. |

### 4.05 Analysis

Static analysis passes that run on the loaded `Binary` and populated IL.

| Crate | Role |
|---|---|
| `rustre-analysis` | Facade: orchestrates analysis pipeline, exposes unified `Analyzer` trait. ~7,439 lines, 6 files. |
| `rustre-analysis-cfg` | Control-flow graph reconstruction: basic block splitting, edge classification (fall-through, conditional, unconditional, call, return, indirect). Uses `petgraph`. ~8,330 lines, 11 files. |
| `rustre-analysis-dataflow` | Dataflow framework: gen/kill sets, worklist solver, liveness, reaching definitions, available expressions. ~9,091 lines, 11 files. (Borderline TOP tier.) |
| `rustre-analysis-fn` | Function discovery: prologue scanning, call-target seeding, .pdata / unwind-table harvesting, recursive descent. |
| `rustre-analysis-xref` | Cross-reference database: code→code, code→data, data→code xrefs. Query by address or symbol. ~6,767 lines, 7 files. |
| `rustre-analysis-string` | String extraction: ASCII, UTF-16LE, UTF-8 with entropy filtering. C-string detection, pascal-string detection. ~7,042 lines, 9 files. |
| `rustre-analysis-type` | Type recovery from IL patterns, calling-convention hints, and debug symbols. ~10,917 lines, 12 files. **TOP tier.** |
| `rustre-analysis-typerecov` | Extended type recovery: propagation through pointer arithmetic, struct field inference, vtable typing. |
| `rustre-analysis-vsa` | Value-Set Analysis: over-approximate set of values at each program point. Used to resolve indirect calls and memory access ranges. ~9,770 lines, 7 files. |
| `rustre-analysis-vtable` | C++ virtual table detection and class hierarchy reconstruction. ~6,645 lines, 9 files. |
| `rustre-analysis-callconv` | Calling-convention identification per platform (System V AMD64, Microsoft x64, ARM AAPCS, etc.). Annotates MLIL with param/return types. |

### 4.06 Decompiler

Transforms HLIL into human-readable C pseudocode.

| Crate | Role |
|---|---|
| `rustre-decompiler` | Facade. Exposes `decompile(function) -> String`. |
| `rustre-decompiler-cfs` | Control-flow structuring: converts CFG back into structured statements (if/else, loops, switch). Implements region-based structuring algorithm. ~8,736 lines, 4 files. |
| `rustre-decompiler-expr` | Expression simplification: algebraic identities, strength reduction, bitfield extraction. |
| `rustre-decompiler-type` | Type annotation of HLIL nodes for C emission: pointer casts, struct member access, array indexing. |
| `rustre-decompiler-c` | C pseudocode emitter: renders typed, structured HLIL as C source with configurable formatting. |
| `rustre-decompiler-ghidra` | Optional bridge: calls Ghidra's headless decompiler as a subprocess and parses its output as a fallback or comparison baseline. |

### 4.07 Deobfuscation

Detects and removes obfuscation layers to restore clean code for analysis.

| Crate | Role |
|---|---|
| `rustre-deobf` | Facade and orchestrator. ~7,175 lines, 8 files. |
| `rustre-deobf-string` | String decryption: pattern-matches common string-encryption stubs and emulates them to recover plaintext. |
| `rustre-deobf-cff` | Control-flow flattening removal: detects state-machine dispatch patterns and reconstructs the original CFG. |
| `rustre-deobf-mba` | Mixed Boolean-Arithmetic simplification: rewrites opaque arithmetic expressions to canonical form using Z3 and symbolic rewriting rules. |
| `rustre-deobf-opaque` | Opaque-predicate elimination: proves constant-condition branches via SMT and removes dead paths. |
| `rustre-deobf-smc` | Self-modifying code handling: traces write-then-execute patterns, snapshots and re-analyzes modified pages. |
| `rustre-deobf-vm` | Virtualizer-based obfuscation: handles VM-protected code (Themida, VMP, Code Virtualizer). ~10,020 lines, 9 files. **TOP tier.** |
| `rustre-deobf-vmlift` | VM lifter: reconstructs a guest IL from bytecode handlers of detected virtualizers. ~7,386 lines, 10 files. |
| `rustre-deobf-iadl` | Import-address-table deobfuscation: resolves dynamically-resolved imports (GetProcAddress chains). |
| `rustre-deobf-mhcde` | Multi-handler control-dispatch elimination: handles OLLVM-style dispatch tables. |
| `rustre-deobf-antianti` | Anti-anti-debug: detects and neutralizes common anti-debugging tricks (IsDebuggerPresent, timing checks, hardware breakpoint detection). |

### 4.08 MCP (Model Context Protocol) Server

Exposes all RustRE capabilities as MCP tools callable by AI agents over stdio or SSE.

| Crate | Role |
|---|---|
| `rustre-mcp` | Facade and tool registry. ~7,203 lines, 7 files. Maintains the master list of 486+ MCP tools. |
| `rustre-mcp-server` | Transport layer: stdio transport and SSE/HTTP transport. Uses `rmcp` crate + `hyper` + `tokio-rustls`. ~7,291 lines, 3 files. |
| `rustre-mcp-tools` | Tool implementations: each MCP tool is a thin wrapper that validates JSON arguments, calls into the relevant crate, and serializes the result back to JSON. |
| `rustre-mcp-federation` | Multi-instance federation: allows multiple RustRE daemons (possibly on different machines) to be queried as a unified MCP server with namespace routing. |

**MCP tool categories exposed:** disasm, decompile, xrefs, strings, functions, imports, exports, sections, symbols, types, vtables, CFG, dataflow, crypto-id, FLIRT match, YARA scan, triage, diff, TTD replay, debug attach, sandbox report, threat-intel lookup, script execution, patch apply, PE rebuild, dotnet decompile, mobile apk info, emulator run, symbolic solve.

### 4.09 Agents / LLM

AI-agent orchestration layer that drives multi-step analysis workflows using Claude or other LLMs.

| Crate | Role |
|---|---|
| `rustre-agent` | Core agent loop: plan → act → observe → repeat. Maintains tool-call history and context window budget. ~7,619 lines, 7 files. |
| `rustre-agent-llm` | LLM client abstraction: Claude API (Anthropic), OpenAI-compatible endpoints. Handles streaming, token counting, context management. |
| `rustre-agent-prompts` | Prompt library: system prompts, few-shot examples, chain-of-thought templates for common RE tasks (find vulnerability, explain function, name anonymous struct). |
| `rustre-agent-workflow` | Named, reusable agent workflows: `auto-analyze`, `find-cves`, `name-functions`, `extract-iocs`, `compare-versions`. Sequence of agent steps with inter-step data passing. |

### 4.10 Debugging

Live debugger integration — attaches to running processes and drives dynamic analysis.

| Crate | Role |
|---|---|
| `rustre-debug` | Facade: `Debugger` trait — attach, detach, continue, step, breakpoint, read/write memory/registers, backtrace. ~7,965 lines, 5 files. |
| `rustre-debug-registry` | Runtime registry: selects correct backend based on platform and target. |
| `rustre-debug-linux` | Linux ptrace backend. Uses `nix` crate. Hardware and software breakpoints, watchpoints, PTRACE_SINGLESTEP. ~6,945 lines, 5 files. |
| `rustre-debug-windows` | Windows debug API backend. Uses `windows-sys`. `DebugActiveProcess`, `WaitForDebugEvent`, hardware breakpoints via DR registers. |
| `rustre-debug-windbg` | WinDbg / DbgEng integration: drives `dbgeng.dll` via COM interfaces for kernel and user-mode debugging. |
| `rustre-debug-kgdb` | KGDB protocol backend for remote Linux kernel debugging. |
| `rustre-debug-gdb` | GDB remote serial protocol (RSP) client: connects to gdbserver or QEMU's GDB stub. |
| `rustre-debug-macos` | macOS Mach exception-port debugger. Uses `mach2` crate. |
| `rustre-debug-frida` | Frida-based dynamic instrumentation. Uses `frida-gum`. Injects hooks, intercepts calls, reads memory without debugger privileges. |
| `rustre-debug-unicorn` | Unicorn Engine integration for single-step emulation as a debugging substrate. |

### 4.11 Forensics

Memory and file-system forensics, inspired by Volatility3.

| Crate | Role |
|---|---|
| `rustre-forensics` | Facade. ~7,418 lines, 7 files. |
| `rustre-forensics-mem` | Memory image analysis: process list, VAD tree, handle table, kernel pool scanning, DKOM detection. ~10,950 lines, 10 files. **TOP tier.** |
| `rustre-forensics-fs` | Filesystem forensics via FUSE (`fuser`): mounts forensic images (NTFS, ext4, FAT) as a virtual filesystem for artifact extraction. ~7,608 lines, 9 files. |
| `rustre-forensics-plugins` | 10+ analysis plugins: registry hive analysis, prefetch parsing, event log extraction, shimcache, MFT analysis, network connection reconstruction. ~10,538 lines, 13 files. **TOP tier.** |

### 4.12 Sandbox

Behavioral analysis in an isolated environment.

| Crate | Role |
|---|---|
| `rustre-sandbox` | Facade: orchestrates sandbox lifecycle. |
| `rustre-sandbox-vm` | VM management: creates and destroys analysis VMs (Hyper-V / QEMU-KVM abstraction). |
| `rustre-sandbox-monitor` | Behavioral monitor: intercepts syscalls, API calls, file/registry/network events inside the VM. |
| `rustre-sandbox-extract` | Artifact extraction from sandbox run: dropped files, network captures, injected processes, memory dumps. |
| `rustre-sandbox-report` | Report generation: structured JSON + HTML reports with IOCs, behavioral tags, MITRE ATT&CK mapping. |

### 4.13 Symbols and Debug Info

Parses debug-symbol formats and populates the symbol table.

| Crate | Role |
|---|---|
| `rustre-symbols` | Facade: unified `Symbol` model and `SymbolProvider` trait. |
| `rustre-symbols-pdb` | PDB (Program Database) parsing. Uses `pdb` crate. Type info (TPI/IPI streams), public/global symbols, section map, FPO records. |
| `rustre-symbols-dwarf` | DWARF debug info. Uses `gimli` + `addr2line`. Function names, inlined functions, variable locations, type units. |
| `rustre-symbols-codeview` | CodeView symbols embedded in PE files (.debug section or old COFF format). |
| `rustre-symbols-stabs` | STABS debug format (older Unix/ELF). |

### 4.14 Crypto Identification

Identifies cryptographic algorithms and key material in binaries.

| Crate | Role |
|---|---|
| `rustre-crypto-id` | Findcrypt-style constant detection: searches for known AES S-boxes, SHA round constants, DES tables, RC4 init patterns, Salsa20 constants, curve parameters. Uses `aho-corasick` for fast multi-pattern search. |
| `rustre-crypto-oracle` | Dynamic crypto oracle: runs suspect crypto code under Unicorn emulation, feeds known plaintext, and tries to identify algorithm from output behavior. |
| `rustre-crypto-whitebox` | Whitebox cryptography analysis: detects lookup-table obfuscated AES (AES-WB), extracts the effective key material. |

### 4.15 Mobile (Android / iOS)

| Crate | Role |
|---|---|
| `rustre-mobile` | Facade. |
| `rustre-mobile-android` | APK parsing, manifest analysis, permission extraction, DEX class enumeration. |
| `rustre-mobile-ios` | IPA parsing, Info.plist analysis, Mach-O fat binary handling, entitlement extraction. ~9,770 lines, 12 files. |
| `rustre-mobile-ipa` | IPA archive handling and code-signature verification. |
| `rustre-mobile-apktool` | Integration with ApkTool (subprocess) for resource decoding. |
| `rustre-mobile-jadx` | JADX integration: drives JADX as a subprocess to decompile DEX to Java. ~10,130 lines, 8 files. **TOP tier.** |
| `rustre-mobile-smali` | Smali/Baksmali assembler/disassembler for DEX bytecode. |
| `rustre-mobile-dyld` | dyld_shared_cache analysis for iOS system library extraction. |
| `rustre-adb` | Android Debug Bridge client: device enumeration, file push/pull, logcat streaming, shell commands. ~7,506 lines, 8 files. |

### 4.16 .NET / CIL

| Crate | Role |
|---|---|
| `rustre-dotnet` | Facade. ~6,923 lines, 5 files. |
| `rustre-dotnet-metadata` | CLI metadata parsing: assembly manifest, TypeDef/TypeRef/MethodDef/Field/Param tables, custom attributes, generic parameters. ~7,047 lines, 3 files. |
| `rustre-dotnet-decompile` | CIL → C# decompiler. Reconstructs high-level C# from CIL bytecode with type annotations. ~10,619 lines, 4 files. **TOP tier.** |
| `rustre-dotnet-edit` | .NET assembly editing: add/remove methods, patch IL bodies, resign assemblies. |

### 4.17 Plugins

Runtime plugin system for extending RustRE without recompilation.

| Crate | Role |
|---|---|
| `rustre-plugin-api` | Plugin trait definitions: `AnalysisPlugin`, `LoaderPlugin`, `ArchPlugin`, `UiPlugin`. ABI-stable interface using `abi_stable` conventions. |
| `rustre-plugin-host` | Plugin manager: loads, unloads, versions, and sandboxes plugins. Handles ABI compatibility. |
| `rustre-plugin-loader` | dlopen-based shared library loader using `libloading`. |
| `rustre-plugin-native` | Helpers for writing native Rust plugins that compile to shared libraries. |
| `rustre-plugin-lua` | Lua plugin support: Lua scripts can implement plugin traits via `mlua`. |
| `rustre-plugin-python` | Python plugin support: Python scripts can implement plugin traits via `pyo3`. |

### 4.18 Scripting

Interactive and batch scripting for analysis automation.

| Crate | Role |
|---|---|
| `rustre-script` | Facade: script engine registry, unified `run_script(path/source)` API. ~8,276 lines, 8 files. |
| `rustre-script-lua` | Lua 5.4 scripting via `mlua`. Binds all major RustRE APIs. |
| `rustre-script-python` | Python 3 scripting via `pyo3`. IDA-compatible API surface where possible. |
| `rustre-script-rhai` | Rhai (pure-Rust embedded scripting language) support. Sandboxed, no unsafe, good for trusted user scripts. |

### 4.19 Time-Travel Debugging (TTD)

Full execution recording and deterministic replay.

| Crate | Role |
|---|---|
| `rustre-ttd` | Facade: `TtdSession` abstraction. |
| `rustre-ttd-recorder` | Execution recorder: uses hardware tracing (Intel PT) or software instrumentation to record a full execution trace. |
| `rustre-ttd-replayer` | Replay engine: re-executes the recorded trace deterministically, supporting reverse-step. |
| `rustre-ttd-replay` | High-level replay API: set breakpoints in the past, time-travel to specific events. |
| `rustre-ttd-query` | Trace query language: find all calls to `malloc`, find first write to address X, find last jump before crash. |

### 4.20 Binary Diffing

Finds structural and semantic similarities between binary versions.

| Crate | Role |
|---|---|
| `rustre-diff` | Facade: `diff(binary_a, binary_b) -> DiffReport`. |
| `rustre-diff-bindiff` | BinDiff-compatible algorithm: graph isomorphism on CFGs using prime-product hashing, matched/unmatched function list. ~6,636 lines, 4 files. |
| `rustre-diff-semantic` | Semantic diffing: executes both versions under emulation with equivalent inputs and compares I/O behavior. ~6,650 lines, 8 files. |

### 4.21 Fuzzing

Instrumented fuzzing integration.

| Crate | Role |
|---|---|
| `rustre-fuzz` | Facade: `Fuzzer` trait. |
| `rustre-fuzz-libfuzzer` | libFuzzer integration: generates fuzz harnesses, collects coverage feedback. |
| `rustre-fuzz-afl` | AFL++ integration: manages corpus, distillation, crash triage. ~7,640 lines, 5 files. |
| `rustre-fuzz-cov` | Coverage collection and visualization: bitmap, edge coverage, DRCOV-format output. |
| `rustre-fuzz-net` | Network protocol fuzzer: generates mutated protocol messages based on a captured PCAP or a grammar spec. |
| `rustre-fuzz-sanitizers` | AddressSanitizer / MemorySanitizer / UBSanitizer result parsing and grouping. |

### 4.22 Triage

Fast first-pass classification of unknown files.

| Crate | Role |
|---|---|
| `rustre-triage` | Facade: runs all triage passes and produces a `TriageReport`. ~7,819 lines, 7 files. |
| `rustre-triage-entropy` | Per-section and global entropy computation. Flags packers / encryptors. |
| `rustre-triage-die` | Detect-It-Easy (DIE) style packer/compiler detection using signature rules. |
| `rustre-triage-peid` | PEiD signature database matching. |
| `rustre-triage-yara` | Runs YARA rules (`rustre-yara`) as part of triage and embeds hits in the report. |

### 4.23 Threat Intelligence

Integration with external threat-intelligence platforms.

| Crate | Role |
|---|---|
| `rustre-threatintel` | Facade: unified `ThreatIntel` lookup by hash/IOC. ~7,831 lines, 17 files. |
| `rustre-ti-vt` | VirusTotal API v3: file report, URL scan, behavior summary, sandbox reports. |
| `rustre-ti-otx` | AlienVault OTX: pulse lookup, IOC enrichment. |
| `rustre-ti-misp` | MISP platform integration: event lookup, attribute search, IOC submission. |
| `rustre-ti-opencti` | OpenCTI GraphQL API: threat actor lookup, malware family attribution. |
| `rustre-ti-malpedia` | Malpedia malware family database lookup. |
| `rustre-ti-shodan` | Shodan search: C2 infrastructure pivot from IP/domain. |
| `rustre-ti-correlate` | Cross-platform correlation: finds an IOC across all connected TI sources and merges results. |

### 4.24 GUI

The GUI is explicitly excluded from the RustRE workspace for independent development. Three GUI crates (`rustre-gui-docking`, `rustre-gui-themes`, `rustre-gui-views`) are commented out of `Cargo.toml`. Only the placeholder crate `rustre-gui` remains as a member (skeleton, no source).

GUI development is tracked in a separate project. The `docs/GUI_STATUS.md` file tracks status.

### 4.25 Hex / Binary View

| Crate | Role |
|---|---|
| `rustre-hex` | Core hex-view data model: virtual address display, byte grouping, highlights, annotations. ~7,272 lines, 3 files. |
| `rustre-hex-view` | Rendering: renders hex dumps to terminal (crossterm) or to a framebuffer for GUI embedding. |
| `rustre-hex-pattern` | Pattern highlight engine: marks byte ranges by YARA hit, entropy region, string location. ~7,184 lines, 3 files. |
| `rustre-hex-template` | Binary template parser (similar to 010 Editor templates): declarative field definitions applied to hex view. ~7,273 lines, 4 files. |

### 4.26 Network

Network traffic analysis.

| Crate | Role |
|---|---|
| `rustre-net` | Facade. |
| `rustre-net-pcap` | PCAP / PCAPNG reader and writer: packet iteration, filtering, stream reassembly. |
| `rustre-net-dissect` | Protocol dissector framework: TCP, UDP, HTTP, TLS (fingerprinting), DNS, SMB, RDP dissectors. ~9,284 lines, monolithic — needs decomposition into modules. |
| `rustre-net-proxy` | MITM proxy: intercepts and re-signs TLS connections using `rcgen`/`rustls`; logs HTTP/2 streams. ~9,472 lines, monolithic — needs decomposition. |
| `rustre-net-rules` | Suricata/Snort rule parser and applier over captured traffic. |

### 4.27 Patching

Binary patching and modification.

| Crate | Role |
|---|---|
| `rustre-patch` | Patch definition model: byte patches, NOP patches, hook patches (redirect call to new stub). |

### 4.28 PE Tools

Windows PE-specific manipulation utilities.

| Crate | Role |
|---|---|
| `rustre-pe-tools` | High-level PE utility operations: import table walking, export table modification, version resource parsing, manifest extraction. |
| `rustre-pe-editor` | In-place PE editing: modify headers, add/remove sections, change entry point. |
| `rustre-pe-rebuild` | PE rebuilding: reconstructs a clean PE from an in-memory dump (fixes headers, restores IAT). |

### 4.29 FLIRT Signatures

Fast Library Identification and Recognition Technology — matches known library code.

| Crate | Role |
|---|---|
| `rustre-flirt` | Facade: `FlirtDatabase` and matching API. |
| `rustre-flirt-gen` | Signature generation: computes FLIRT patterns from known library `.lib` / `.a` files. |
| `rustre-flirt-apply` | Signature application: scans binary functions against the FLIRT database, names matches. |

### 4.30 Emulation

Full-system and user-mode emulation.

| Crate | Role |
|---|---|
| `rustre-emu` | Facade: `Emulator` trait. |
| `rustre-emu-unicorn` | Unicorn Engine integration for CPU-level emulation (x86, ARM, MIPS, etc.). |
| `rustre-emu-shellcode` | Shellcode emulation harness: maps PE imports as stubs, hooks common WinAPI calls for logging. |
| `rustre-emu-qiling` | Qiling framework bridge (subprocess / FFI): full OS-level emulation with syscall emulation. |

### 4.31 Symbolic Execution

Path-sensitive analysis using SMT.

| Crate | Role |
|---|---|
| `rustre-symb` | Facade: `SymbolicExecutor` — executes functions symbolically, accumulates path constraints. |
| `rustre-symb-engine` | Core symbolic execution engine: symbolic memory model, register map, expression builder, path condition stack. |
| `rustre-symb-z3` | Z3 backend: translates symbolic expressions to Z3 `Expr` and checks satisfiability using the static-linked `z3` crate. |
| `rustre-symb-taint` | Taint analysis built on top of symbolic execution: tracks data flow from sources to sinks for vulnerability finding. |

### 4.32 Syscalls

Syscall enumeration and monitoring.

| Crate | Role |
|---|---|
| `rustre-syscalls` | Facade: `Syscall` model with name, number, argument types. |
| `rustre-syscalls-linux` | Linux syscall tables for x86, x86-64, ARM, AArch64, MIPS, RISC-V. |
| `rustre-syscalls-windows` | Windows NT syscall tables (NtXxx functions), sourced from ntdll exports and known-good tables. |
| `rustre-sysinternals` | Sysinternals-style process / handle / driver enumeration using `windows-sys`. |

### 4.33 Execution Trace

Hardware and software execution tracing.

| Crate | Role |
|---|---|
| `rustre-trace` | Facade: `Trace` model — ordered sequence of executed instructions with register snapshots. |
| `rustre-trace-pt` | Intel Processor Trace (IPT) decoding: decodes raw PT packets to instruction-level traces using `libipt` or a Rust reimplementation. |
| `rustre-trace-coresight` | ARM CoreSight ETM trace decoding for embedded targets. |
| `rustre-trace-coverage` | Derives code-coverage bitmaps from traces; exports to DRCOV, LCOV, HTML. |
| `rustre-trace-navigate` | Interactive trace navigation: jump to caller, find loop iterations, filter by address range. |

### 4.34 Project Management

| Crate | Role |
|---|---|
| `rustre-project` | Analysis session persistence: saves/loads function names, comments, type assignments, bookmarks, scripts, settings to a project file (SQLite). |

### 4.35 Events

| Crate | Role |
|---|---|
| `rustre-events` | Typed event bus: `AnalysisEvent` enum variants published by analysis passes and consumed by MCP server, GUI, agents. Uses `crossbeam-channel`. |

### 4.36 Knowledge Graph

| Crate | Role |
|---|---|
| `rustre-knowledge` | Semantic knowledge base linking binary hashes, function signatures, FLIRT matches, YARA hits, TI records, and vulnerability database entries into a queryable graph. |
| `rustre-graph` | Low-level graph infrastructure: typed edges and nodes, community detection, BFS/DFS, shortest-path, DOT export. Uses `petgraph` + `sqlx`. ~10,208 lines, 5 files. |

### 4.37 Database / Persistence

| Crate | Role |
|---|---|
| `rustre-db` | Unified persistence layer. SQLite via `rusqlite` (bundled, always available). MySQL via `mysql` (optional). Async interface via `sqlx`. Stores all analysis results. |

### 4.38 ADB

| Crate | Role |
|---|---|
| `rustre-adb` | Android Debug Bridge client implemented in Rust: ADB wire protocol, device enumeration, file transfer (SYNC protocol), logcat, shell, forward/reverse port mapping. ~7,506 lines, 8 files. |

### 4.39 YARA

| Crate | Role |
|---|---|
| `rustre-yara` | Facade. |
| `rustre-yara-engine` | YARA-X based scan engine. Compiles rules, scans byte slices, returns match reports with rule name, string matches, offsets. |
| `rustre-yara-rules` | Bundled rule sets: malware families, packer signatures, crypto constants, exploit patterns. |

### 4.40 Graph

| Crate | Role |
|---|---|
| `rustre-graph` | (Already described under 4.36) Call graph, CFG-level graph operations, knowledge graph. |

### 4.41 Demangle

| Crate | Role |
|---|---|
| `rustre-demangle` | Routes symbols through `cpp_demangle` (GCC / Clang / MSVC C++ mangling), `rustc-demangle` (Rust symbols), and a Rust-aware heuristic for `_ZN`-prefixed names. |

### 4.42 Memory

| Crate | Role |
|---|---|
| `rustre-mem` | (Already described under 4.01) Virtual memory abstraction, segment map, sparse byte map. ~13,142 lines, 27 files. |

### 4.43 Daemon / CLI / Binary Entry

| Crate | Role |
|---|---|
| `rustre-daemon` | Background service: hosts the MCP server, the project database, and the analysis engine in a long-running process. Communicates with `rustre-cli` and GUI over local sockets. |
| `rustre-cli` | CLI front-end: `clap`-based sub-commands. `rustre analyze <file>`, `rustre disasm <va>`, `rustre decompile <func>`, `rustre script <file>`, `rustre diff <a> <b>`, `rustre mcp`. |
| `rustre-bin` | The single compiled executable `rustre`. Dispatches to daemon or CLI sub-commands. |

---

## 5. Data-Flow and Dependency Relationships

```
Binary File on Disk
       │
       ▼
rustre-loader-* (format detection + parsing)
       │  populates
       ▼
rustre-core::Binary (segment map, sections, imports, exports)
       │
       ├──► rustre-mem (virtual address space)
       │
       ├──► rustre-symbols-* (debug info → symbol table)
       │
       ├──► rustre-analysis-fn (function discovery)
       │         │
       │         ▼
       │    rustre-il-lift (native insns → LLIL)
       │         │
       │         ▼
       │    rustre-il-passes (SSA, DCE, const-fold)
       │         │
       │    ┌────┴────────┐
       │    ▼             ▼
       │  rustre-analysis-cfg   rustre-analysis-dataflow
       │         │
       │         ▼
       │    rustre-analysis-callconv (MLIL annotations)
       │         │
       │         ▼
       │    rustre-analysis-type + rustre-analysis-typerecov
       │         │
       │         ▼
       │    rustre-il-hlil (structured expressions)
       │         │
       │         ▼
       │    rustre-decompiler-cfs (control-flow structuring)
       │         │
       │         ▼
       │    rustre-decompiler-c (C pseudocode output)
       │
       ├──► rustre-analysis-string (string extraction)
       ├──► rustre-analysis-xref (cross-references)
       ├──► rustre-analysis-vtable (C++ vtables)
       ├──► rustre-analysis-vsa (value-set analysis)
       ├──► rustre-crypto-id (crypto constant detection)
       ├──► rustre-flirt-apply (library function naming)
       ├──► rustre-triage (fast classification)
       │
       ▼
rustre-db (all results persisted)
       │
       ▼
rustre-project (session save/load)
       │
       ▼
rustre-mcp-tools → rustre-mcp-server (MCP transport)
       │
       ├──► AI Agents (Claude via MCP)
       ├──► rustre-agent (programmatic workflows)
       └──► rustre-cli (human-driven)
```

**Deobfuscation path:**
```
rustre-triage (detect obfuscation) → rustre-deobf-* → re-run analysis pipeline on clean code
```

**Dynamic path:**
```
rustre-debug-* (attach) → rustre-trace-* (record) → rustre-ttd (replay)
                                                   → rustre-emu (emulate)
                                                   → rustre-symb (symbolically execute)
                                                   → rustre-fuzz (fuzz)
```

---

## 6. Size and Quality Tier Summary

Based on `docs/AUDIT.md` (generated 2026-06-05, total: ~1,397,501 lines across 190 crates, target: 4,000,000 lines):

### TOP Tier (10K+ lines) — 14 crates

| Crate | Lines | Files |
|---|---|---|
| rustre-il-lift | 58,013 | 45 |
| rustre-analysis-type | 10,917 | 12 |
| rustre-forensics-mem | 10,950 | 10 |
| rustre-loader-pe | 11,022 | 16 |
| rustre-loader-elf | 10,678 | 15 |
| rustre-forensics-plugins | 10,538 | 13 |
| rustre-dotnet-decompile | 10,619 | 4 |
| rustre-il-passes | 10,230 | 5 |
| rustre-graph | 10,208 | 5 |
| rustre-deobf-vm | 10,020 | 9 |
| rustre-mobile-jadx | 10,130 | 8 |
| rustre-core | 15,068 | 18 |
| rustre-mem | 13,142 | 27 |
| rustre-analysis-dataflow | 9,091 | 11 |

### GOOD Tier (7K–9.9K lines) — ~36 crates

Includes: rustre-analysis-vsa, rustre-mobile-ios, rustre-il-llil, rustre-il-mlil, rustre-arch-arm, rustre-decompiler-cfs, rustre-arch-x86, rustre-il-hlil, rustre-analysis-cfg, rustre-arch-6502, rustre-forensics, rustre-forensics-fs, rustre-fuzz-afl, rustre-triage, rustre-threatintel, rustre-arch-jvm, rustre-loader-macho, rustre-adb, rustre-loader-firmware, rustre-agent, rustre-arch-msp430, rustre-deobf-vmlift, rustre-arch-mips, rustre-arch-bpf, rustre-hex-template, rustre-arch-luajit, rustre-arch-riscv, rustre-hex, rustre-hex-pattern, rustre-analysis-string, rustre-dotnet-metadata, rustre-dotnet, rustre-mcp, rustre-mcp-server, rustre-analysis, rustre-debug, rustre-net-proxy (monolithic), rustre-net-dissect (monolithic).

### MEDIUM Tier (5K–7K lines) — majority of remaining crates

These crates have the minimum viable implementation and need expansion toward 8K–15K to reach full feature parity.

### Known Monolithic Crates (few files, large lines)

- `rustre-net-proxy` — 9,472 lines in **1 file**; must be decomposed into modules.
- `rustre-net-dissect` — 9,284 lines in **1 file**; must be decomposed.
- `rustre-arch-riscv` — 7,266 lines in **2 files**; borderline.
- `rustre-arch-mips` — 7,352 lines in **3 files**.

---

## 7. Feature Flags and Conditional Compilation

While the workspace `Cargo.toml` does not declare workspace-level features (individual crate `Cargo.toml` files handle this), the following patterns are observable from the dependency table:

| Dependency | Conditional usage |
|---|---|
| `unicorn-engine` | Commented out at workspace level; individual crates (`rustre-emu-unicorn`, `rustre-debug-unicorn`) add it per-crate with a local feature gate. |
| `frida-gum` | Required by `rustre-debug-frida` only; `auto-download` feature pulls prebuilt Frida binaries. |
| `z3` | `static-link-z3` feature enabled workspace-wide; patched via `vendor/z3-sys` for CMake 4.x. |
| `mlua` | `lua54 + vendored` — Lua 5.4 source compiled in; no system Lua dependency. |
| `pyo3` | `auto-initialize` — Python interpreter found at runtime via `PyO3`'s dynamic loading. |
| `nix` | `ptrace + signal + process + user` features; Linux-only; guarded by `#[cfg(target_os = "linux")]` in debug-linux. |
| `windows-sys` | Large feature set for debug/forensics Win32 APIs; guarded by `#[cfg(target_os = "windows")]`. |
| `mach2` | macOS only; guarded by `#[cfg(target_os = "macos")]`. |
| `fuser` | FUSE filesystem; Linux-only. |
| `rmcp` | `server + client + transport-io + transport-sse-server` — all transport modes enabled for MCP. |
| `reqwest` | `json + rustls-tls + multipart`; `default-features = false` to avoid OpenSSL. |
| `rusqlite` | `bundled` — SQLite compiled in; no system libsqlite3 required. |
| `sqlx` | `sqlite + runtime-tokio-rustls` — async SQLite over Tokio. |
| `tokio` | `full` features; version pinned at `=1.40.0` to ensure deterministic async behavior across the workspace. |

---

## 8. Removed / Deferred Crates

Three GUI crates are commented out in `Cargo.toml` (lines 102–104):

```toml
# "crates/rustre-gui-docking",  # crate removed from project
# "crates/rustre-gui-themes",   # crate removed from project
# "crates/rustre-gui-views",    # crate removed from project
```

The stub `rustre-gui` crate remains as a placeholder to anchor GUI-related traits but contains no source. GUI work is tracked separately.

---

## 9. Integration Test Infrastructure

`tests/integration_pipeline` is a workspace member (not under `crates/`). It serves as the end-to-end integration test harness:

- Exercises the full pipeline: load binary → analyze → disassemble → decompile → FLIRT match → YARA scan → triage report.
- Compares output against known-good golden files.
- In the project session notes, `exercise_v3.py` (likely a Python script in the test directory) is used to verify MCP tool coverage (NONE → PARTIAL → FULL → verified).

---

## 10. IDA Pro Comparison Context

The primary benchmark for RustRE is `cargo-zyphora.exe`, a 1.18 MB Rust/MSVC PE64 binary analyzed by both IDA Pro and the RustRE MCP server.

| Metric | IDA Pro | RustRE | Delta |
|---|---|---|---|
| Functions found | 1,456 | 1,726 | **+270 (+18.5%)** |
| Named functions | 395 | 630 | **+235 (+59.5%)** |
| Crypto constants found | 43 | 43 | Tied |
| Disassembly | Works | Works | Tied |
| Decompiler | Works | Works | Tied |
| Xrefs | 13,735 | 13,735 | Tied |
| String extraction | 4,650 | 4,650 | Tied |
| PDB parsing | Working in IDA | Priority fix item | Gap |
| MCP interface | None | 486+ tools | **RustRE wins** |
| Agent integration | None | Full LLM workflows | **RustRE wins** |
| Scripting | IDAPython (Python 2/3) | Lua + Python + Rhai | **RustRE richer** |
| Plugin system | IDA SDK (C++) | Native + Lua + Python | **RustRE richer** |
| Threat-intel | None | 7 TI sources | **RustRE wins** |
| Sandbox analysis | None | Full sandbox | **RustRE wins** |
| TTD | WinDbg TTD (external) | Native implementation | **RustRE wins** |
| FLIRT | Yes | Yes | Tied |
| YARA | External only | Built-in YARA-X | **RustRE wins** |
| Deobfuscation | Limited (manual) | 10 deobf modules | **RustRE wins** |
| Forensics | None | Volatility-style | **RustRE wins** |
| Mobile | Limited | Android + iOS full | **RustRE wins** |
| .NET | IDA + Hex-Rays .NET | CIL decompiler native | Comparable |

The project notes (memory files) indicate that as of 2026-06-23 the priority fix items were: PDB parsing, findcrypt refinement, path-accepting tools, and string virtual addresses.

---

*This document reflects the state of the workspace as of 2026-07-01.*
*Total crates: 210 (208 under `crates/`, 1 integration test, 3 GUI removed).*
*Total workspace lines: ~1,397,501 (target: 4,000,000).*
