# RustRE Analysis Documentation — Index

> Generated: 2026-07-01
> 16 documents covering the full ~210-crate workspace.

---

## How to Read This Documentation

### New contributor
Start with **00-OVERVIEW** for the project's identity, goals, and full crate map. Then read **01-core-and-workspace** to understand the foundational crates every other subsystem depends on. Follow with **17-CROSS-REFERENCES** to see how the subsystems interconnect before diving into any specific domain document.

### MCP tool developer
Read **09-mcp-and-agents** first — it covers the full MCP transport, tool-handler pattern, federation layer, and agent/LLM framework. Then read **17-CROSS-REFERENCES §2** (MCP tool surface) to see which subsystems are already wired. Use the individual subsystem documents as reference when adding tools for a specific domain (e.g. **06-decompiler** when writing decompiler tools).

### Decompiler contributor
Read **02-il-and-lifting** to understand the IL pipeline that feeds the decompiler, then **06-decompiler** for the decompiler subsystem itself (CFG structuring, expression trees, type inference, C emission, Ghidra P-Code back-end). Cross-check **05-analysis** for the analysis passes (CFG, dataflow, type recovery) that the decompiler consumes, and **08-symbols-demangle-flirt** for symbol resolution that improves output quality.

### Architecture / loader contributor
Read **03-architectures** for the ISA back-end hub and all 19 concrete disassemblers. Then read **04-loaders** for the binary-ingestion layer (PE, ELF, Mach-O, and 12 other formats). Follow with **02-il-and-lifting** to see how loader output feeds into the lifting pipeline, and **17-CROSS-REFERENCES §1** for the full data-flow pipeline from binary on disk to output.

---

## File Descriptions

### [00-OVERVIEW.md](00-OVERVIEW.md)
Top-level architecture survey of the entire RustRE workspace. Covers project identity and goals, the Cargo build system layout, key third-party dependencies, and a domain-by-domain subsystem map listing every crate grouped by function. Read this first for a broad mental model of the project.

### [01-core-and-workspace.md](01-core-and-workspace.md)
Deep analysis of the seven foundational crates: `rustre-core`, `rustre-events`, `rustre-db`, `rustre-knowledge`, `rustre-mem`, `rustre-project`, and `rustre-daemon`. Documents the dependency graph, each crate's public API, cross-crate integration map, implementation status, and known gaps. Essential reading before touching any crate that depends on core infrastructure.

### [02-il-and-lifting.md](02-il-and-lifting.md)
Covers the four-tier Intermediate Language pipeline (`rustre-il`, `rustre-il-llil`, `rustre-il-mlil`, `rustre-il-hlil`) and the architecture-agnostic lifting layer (`rustre-il-lift`, `rustre-il-passes`). Includes pipeline diagrams, per-tier data structures, SSA/phi placement, and the HLIL control-flow recovery algorithm. The authoritative reference for anyone working on IR or lifting.

### [03-architectures.md](03-architectures.md)
Analyses the 21 crates forming the ISA back-end tier: the `rustre-arch` hub, `rustre-arch-registry` aggregator, and 19 concrete disassemblers (x86, ARM, ARM64, MIPS, RISC-V, PowerPC, SPARC, AVR, MSP430, Z80, BPF, and more). Documents the `Architecture` trait contract, binary-detection logic, and per-ISA implementation status. The primary reference for adding a new CPU architecture or fixing an existing disassembler.

### [04-loaders.md](04-loaders.md)
Deep analysis of all 15 loader crates that form the binary-ingestion layer. Covers the layered diamond dependency pattern (trait hub → format crates → registry), the `Loader` and `BinaryView` traits from `rustre-core`, and per-format notes for PE, ELF, Mach-O, COFF, raw binary, PDF, and others. Documents integration points with the arch and IL layers and lists known parser gaps.

### [05-analysis.md](05-analysis.md)
Covers the eleven-crate analysis subsystem: the `AnalysisPass` trait and pipeline scheduler in `rustre-analysis`, then each specialized pass crate — function detection, CFG/dominator trees, call-convention inference, dataflow, string recovery, type propagation, value-set analysis, vtable detection, and cross-reference database. Explains how passes are scheduled, how results are stored in `AnalysisDb`, and what is still unimplemented.

### [06-decompiler.md](06-decompiler.md)
In-depth analysis of the six decompiler crates. Describes the coordinator facade (`rustre-decompiler`), CFG structuring via the DREAM algorithm (`rustre-decompiler-cfs`), expression tree simplification (`rustre-decompiler-expr`), the type system and inference engine (`rustre-decompiler-type`), C pseudo-code emission (`rustre-decompiler-c`), and the optional Ghidra P-Code back-end (`rustre-decompiler-ghidra`). Includes the full pipeline from raw instructions to C-like output.

### [07-deobfuscation.md](07-deobfuscation.md)
Unified analysis of the full deobfuscation subsystem across eleven crates. Part A covers the core `rustre-deobf` framework (trait, pipeline, utility decryptors), CFF removal (`rustre-deobf-cff`, including OLLVM sub-module), opaque predicate elimination (`rustre-deobf-opaque`, 24-pattern database, pure-Rust SMT prover), and anti-analysis neutralization (`rustre-deobf-antianti`, 14 byte-level signatures, Frida script generation). Part B covers MBA simplification (`rustre-deobf-mba`, 7 006-line rule engine, truth-table verifier), the iterative adversarial deobfuscation loop (`rustre-deobf-iadl`, rayon-parallel hypothesis scoring), and mixed honig dead-code elimination (`rustre-deobf-mhcde`, x86 byte-level NOP planner). Part C covers string decryption (`rustre-deobf-string`, XOR/RC4/stack-string/LLIL), self-modifying code unpacking (`rustre-deobf-smc`, 4-pattern detection, multi-layer iteration), VM obfuscation detection (`rustre-deobf-vm`, VMProtect/Themida handler analysis), and VM bytecode lifting (`rustre-deobf-vmlift`, ISA synthesis, LLIL emission). Merges sub-files `07a`, `07b`, `07c`.

### [08-symbols-demangle-flirt.md](08-symbols-demangle-flirt.md)
Covers 13 crates across three conceptual layers: debug-format readers (PDB, DWARF, CodeView, STABS), the demangling and FLIRT signature layer (multi-ABI demangler, `.sig` parser, signature application and generation), and the symbolic execution engine (`rustre-symb`, `rustre-symb-taint`, `rustre-symb-z3`). Documents the `SymbolProvider` trait, FLIRT trie matching, and Z3-backed constraint solving.

### [09-mcp-and-agents.md](09-mcp-and-agents.md)
Full analysis of the MCP transport and agent framework across eight crates. Covers the JSON-RPC 2.0 wire layer (`rustre-mcp-server`), the `McpTool` trait and coordinator (`rustre-mcp`), all concrete tool implementations (`rustre-mcp-tools`), multi-server federation and routing (`rustre-mcp-federation`), and the agent/LLM stack (`rustre-agent`, `rustre-agent-llm`, `rustre-agent-prompts`, `rustre-agent-workflow`). The definitive reference for MCP integration work.

### [10-debug-and-emu.md](10-debug-and-emu.md)
Analyses the 15-crate debug and emulation subsystem. Covers the `Debugger` trait hub and `rustre-debug-registry` composition crate, then each platform-specific backend (Windows, Linux, macOS, GDB, WinDbg, KGDB, Frida), and the emulation layer (`rustre-emu`, `rustre-emu-unicorn`, `rustre-emu-qiling`, `rustre-emu-shellcode`) plus `rustre-adb` for Android device interaction. Documents session management, register sets, breakpoint types, and emulator integration.

### [11-crypto-and-triage.md](11-crypto-and-triage.md)
Unified analysis of the cryptographic identification/attack pipeline and the static triage and YARA stacks. Part A covers passive crypto identification (`rustre-crypto-id`, 10 built-in constants, active probe generation), active oracle attacks (`rustre-crypto-oracle`, CBC padding oracle, ECB suffix recovery, RSA toy-scale attacks, protocol synthesis), and whitebox cryptanalysis (`rustre-crypto-whitebox`, DFA/BGE/DCA, AES T-table scanning, key-schedule reversal, SQLite/MySQL storage). Part B covers the triage coordinator (`rustre-triage`, 9-stage pipeline, threat scoring), DIE-style packer/compiler detection (`rustre-triage-die`, 25 YAML rules + 200-entry extended DB), entropy analysis (`rustre-triage-entropy`, per-section + sliding-window, visualization), PEiD signature matching (`rustre-triage-peid`, 300+ signatures, rayon-parallel), and an embedded YARA-like engine (`rustre-triage-yara`, Aho-Corasick VM). Part C covers the full standalone YARA stack: pure-Rust foundation (`rustre-yara`, recursive-descent parser, full modifier set), dual-path execution engine (`rustre-yara-engine`, pure-Rust + yara-x, distributed coordinator, PE module), and repository manager (`rustre-yara-rules`, ~40 built-in rules, local/Git/HTTP sources). Merges sub-files `11a`, `11b`, `11c`.

### [12-mobile-dotnet.md](12-mobile-dotnet.md)
Covers twelve crates split across two independent pillars. The mobile pillar handles Android APK/DEX analysis (`rustre-mobile-android`), apktool and JADX wrappers, a full Smali IR (`rustre-mobile-smali`), iOS bundle/ObjC/Swift metadata (`rustre-mobile-ios`), dyld shared-cache parsing (`rustre-mobile-dyld`), and IPA extraction. The .NET pillar covers ECMA-335 metadata parsing, CIL IR, C# decompilation with LINQ/async recovery, and assembly mutation.

### [13-forensics-sandbox-ti.md](13-forensics-sandbox-ti.md)
Analyses 18 crates across four areas: memory forensics (`rustre-forensics`, `rustre-forensics-mem`, `rustre-forensics-fs`, `rustre-forensics-plugins`), dynamic sandbox analysis (`rustre-sandbox` and four sub-crates), threat-intelligence connectors (VirusTotal, MISP, OpenCTI, Malpedia, OTX, Shodan, and a correlator), and `rustre-sysinternals` for platform-introspection data types. Documents the `MemoryImage` trait, behavioral analysis pipeline, and TI aggregation model.

### [14-fuzz-trace-ttd-diff.md](14-fuzz-trace-ttd-diff.md)
Covers 19 crates across four subsystems. The fuzz subsystem wraps AFL++ and libFuzzer with coverage and sanitizer support. The trace subsystem decodes Intel PT and ARM CoreSight hardware traces and provides a navigation API. The TTD (time-travel debugging) subsystem handles recording, replay, and query over execution snapshots. The diff subsystem provides binary diffing, BinDiff-compatible output, and semantic function comparison.

### [15-gui-hex-net-patch-pe.md](15-gui-hex-net-patch-pe.md)
Analyses 15 crates covering the graphical interface, hex-view toolkit, network analysis, binary patching, and PE manipulation. `rustre-gui` provides the egui-based UI shell and `rustre-graph` the interactive CFG/call-graph renderer. The hex crates supply a low-level viewer, pattern search, and template-based struct overlay. Network crates handle protocol dissection, PCAP capture, proxy, and Snort-style rules. Patch and PE crates handle in-place patching, PE header editing, section rebuild, and export-table manipulation.

### [16-plugins-scripting-syscalls.md](16-plugins-scripting-syscalls.md)
Covers 13 crates for extensibility: the native plugin ABI and host (`rustre-plugin-api`, `rustre-plugin-host`, `rustre-plugin-loader`, `rustre-plugin-native`) plus scripting bindings for Python, Lua, and Rhai (`rustre-script-*`, `rustre-plugin-python`, `rustre-plugin-lua`). The syscall subsystem (`rustre-syscalls`, `-linux`, `-windows`) provides a cross-platform syscall database, argument type resolution, and Windows NTAPI metadata. Documents the `Plugin` trait ABI, safe FFI boundary, and scripting host lifecycle.

### [17-CROSS-REFERENCES.md](17-CROSS-REFERENCES.md)
Synthesises all 15 preceding documents into nine cross-cutting views: the full data-flow pipeline from binary on disk to output, the MCP tool surface (which subsystems are exposed and which are not), the agent/LLM integration surface, plugin and scripting extension points, the debug/emulation/TTD flow, obfuscation-resistant paths via deobfuscation and symbolic execution, mobile and .NET dedicated pipelines, forensics/sandbox/threat-intel side-flows, and an integration-gap completeness matrix benchmarked against IDA Pro on `cargo-zyphora.exe`. Read this for the holistic picture of how the workspace fits together.
