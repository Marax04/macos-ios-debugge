# rustre-analysis-callconv

## Scopo
Rilevamento e analisi della **calling convention** di funzioni a partire dal flusso di istruzioni / disassemblato. Identifica come una funzione passa gli argomenti e restituisce i valori esaminando euristicamente prologo/epilogo, registri letti-prima-di-scritti (candidati argomento) e registri salvati/ripristinati (callee-saved). Copre x86, x86_64, Arm32, Arm64, MIPS32/64, PPC32/64, RISC-V32/64 con cdecl, stdcall, fastcall, thiscall, vectorcall, System V AMD64, Microsoft x64, AAPCS32/64, MIPS O32, RISC-V LP64D, varianti Rust/Swift.

## Dipendenze chiave
- `rustre-analysis`, `rustre-core`, `petgraph`, `parking_lot`, `rustc-hash`, `serde`, `thiserror`, `async-trait`

## Moduli pubblici
`abi_analyzer`, `cc_database`, `cc_detector`, `cc_detector_advanced`, `calling_convention_detector`, `argument_tracker`, `heuristics`, `propagation`, `register_colouring`, `return_type_analyzer`, `return_type_recovery`, `stack_cleanup_analyzer`, `vararg_detector`, `variadic_analyzer`, `variadic_detection`.

## Tipi pubblici principali
- `Arch` (X86, X86_64, Arm32/64, Mips32/64, Ppc32/64, RiscV32/64, Other) con `pointer_width()`
- `Os` (Linux, Windows, MacOs, FreeBsd, Bare, Other)
- `Compiler` (Gcc, Msvc, Clang, Icc, Any)
- `CcKey { arch, os, compiler }` chiave registry
- `CallingConventionPattern` (arg_registers, fp_arg_registers, retval_registers, callee_saved, caller_saved, stack_alignment, caller_cleanup, hidden_this_ptr, max_reg_args, supports_variadic, shadow_space_bytes)
- `ObservedPattern` (read_before_write, saved_registers, written_before_return, callee_pops_stack, this_ptr_hint, callee_stack_pop, fp_read_before_write, max_stack_frame, shadow_space_observed, stack_arg_count)
- `DetectInstr` enum (RegRead/RegWrite/Push/Pop/Ret/ThisPtrUse/FpRegRead/StackAlloc/StackArgAccess/Other)
- `CallingConventionDetector` (unit struct con metodi associati)
- `CallingConventionDatabase` (registry HashMap<CcKey, Vec<Pattern>>)
- `CallConvError` (NoMatch, Ambiguous, UnknownKey, Json, TooShort, UnknownRegister)

## Funzioni pubbliche principali (firme)

### Built-in CC factories (`-> CallingConventionPattern`)
- `sysv_x64()` — System V AMD64 (rdi,rsi,rdx,rcx,r8,r9 args; rax/rdx ret)
- `msvc_x64()` — Microsoft x64 (rcx,rdx,r8,r9; shadow 32B)
- `cdecl_x86()` — caller cleanup, stack-only args
- `stdcall_x86()` — callee cleanup, stack-only
- `fastcall_x86()` — ecx,edx
- `thiscall_x86()` — this in ecx
- `vectorcall_x64()`
- `aapcs64()` — x0..x7 args
- `aapcs32()` — r0..r3 args
- `mips_o32()` — a0..a3 args
- `riscv64_lp64d()` — a0..a7 args

### `CallingConventionPattern`
- `score(&self, observed: &ObservedPattern) -> u32` — punteggio match 0..100
- `is_arg_register(&self, reg: &str) -> bool`
- `is_callee_saved(&self, reg: &str) -> bool`
- `is_retval_register(&self, reg: &str) -> bool`
- `arg_register_at(&self, n: usize) -> Option<&str>`
- `arg_register_count(&self) -> usize`

### `ObservedPattern`
- `new() -> Self`
- `has_arg_evidence(&self) -> bool`
- `looks_like_leaf(&self) -> bool`

### `CallingConventionDetector` (metodi associati)
- `extract_pattern(instrs: &[DetectInstr], pointer_width: u32) -> ObservedPattern`
- `detect(observed, candidates) -> Result<Pattern, CallConvError>` — best score, errore se vuoto/tie
- `detect_with_hints(observed, candidates) -> Result<Pattern, CallConvError>` — tiebreaking con shadow_space, this_ptr, callee_pops, stack-only
- `rank_candidates(observed, candidates) -> Vec<(Pattern, u32)>`

### `CallingConventionDatabase`
- `new()`, `with_builtins()` — registry pre-popolato per tutte le combinazioni note
- `register(&mut self, key: CcKey, pattern)`
- `lookup(&self, key) -> &[Pattern]`
- `lookup_any_compiler(&self, arch, os) -> Vec<&Pattern>`
- `lookup_any_os(&self, arch) -> Vec<&Pattern>`
- `all_names(&self) -> Vec<String>`

### Re-export da sotto-moduli
- da `heuristics`: `ArgRegisterProfile`, `CallConvVerdict`, `PreservationReport`, `StackCleanup`, `analyze_preservation`, `classify_stack_cleanup`, `default_callee_saved`, `profile_arg_registers`
- da `cc_database`: costanti `CC_AAPCS32`, `CC_AAPCS32_VFP`, `CC_AAPCS64`, `CC_CDECL_X86`, `CC_FASTCALL_X86`, `CC_MIPS_N64`, `CC_MIPS_O32`, `CC_MS_X64_DB`, `CC_REGCALL_X64/X86`, `CC_RISCV32_ILP32D`, `CC_RISCV64_LP64D`, `CC_RUST_ARM64`, `CC_RUST_X64`, `CC_STDCALL_X86`, `CC_SWIFT_ARM64`, `CC_SWIFT_X64`, `CC_SYSV_AMD64_DB`, `CC_SYSV_X86`, `CC_THISCALL_X86`, `CC_VECTORCALL_X64`; tipo `CcRegistry`; funzioni `abis_are_compatible`, `shared_arg_registers`
- da `propagation`: `BulkPropagator`, `CallSite`, `CallSiteArgument`, `CallSiteInstr`, `CalleePropagator`, `PropagationResult`, `PropagationStats`, `RawCallSite`, `function_info_from_observed`, `infer_params_from_observed`

## Input / Output
- **Input**: sequenza `&[DetectInstr]` (modello istruzione semplificato), `pointer_width: u32`, set di `CallingConventionPattern` candidati (o lookup tramite `CcKey`).
- **Output**: `ObservedPattern` (evidenza grezza), `CallingConventionPattern` selezionato + score, ranking ordinato, oppure `CallConvError`.

## Ground truth verificabile esternamente
- **ABI ufficiali**: il pattern restituito da ogni factory deve corrispondere a:
  - System V AMD64 ABI (psABI) — args RDI,RSI,RDX,RCX,R8,R9; ret RAX/RDX; callee-saved RBX,RBP,R12-R15; align 16
  - Microsoft x64 — args RCX,RDX,R8,R9; shadow space 32B; callee-saved RBX,RBP,RDI,RSI,R12-R15
  - cdecl/stdcall/fastcall/thiscall x86 — documentazione MSDN
  - AAPCS64 (ARM IHI 0055) — X0-X7 args, X19-X28 callee-saved
  - AAPCS32 (ARM IHI 0042) — R0-R3 args, R4-R11 callee-saved
  - MIPS O32 — a0-a3, shadow 16B; SystemV gABI RISC-V LP64D — a0-a7
- **Cross-check con altri tool**:
  - IDA Pro `__usercall`/`__fastcall` annotations su funzioni note
  - Ghidra `CallingConvention` resolver
  - Compilazione con `gcc/clang -O0` di una funzione `int f(int,int,int,int,int,int,int)` e ispezione del prologo (objdump) → confronto con `extract_pattern`
  - Binari noti (es. `/bin/ls` glibc) compilati Linux x64 dovrebbero dare `sysv_x64` come miglior match

## Tool MCP esistenti (rustre-mcp / ida-pro-mcp)
- `mcp__rustre-mcp__decompiler_stack_frame_report` — frame stack (overlap parziale)
- `mcp__rustre-mcp__analysis_xref_callees` / `analysis_xref_call_graph` — call sites (input per propagation)
- `mcp__rustre-mcp__decompile_function_path` / `decompile_function` — può esporre CC nei prototipi
- `mcp__rustre-mcp__type_infer` / `type_propagate_path` — types correlati ai parametri
- `mcp__ida-pro-mcp__set_function_prototype` — applica CC su IDA
- `mcp__ida-pro-mcp__stack_frame` / `declare_stack`
- `mcp__ida-pro-mcp__analyze_function` — fornisce CC IDA come riferimento

**NESSUN tool MCP dedicato direttamente al CC detection esiste oggi**; la crate è esposta indirettamente via decompiler / type infer. Gap: tool MCP `analysis_callconv_detect_path(binary, fn_va)` mancante.

## Testabilità
- Sì: pure functions, deterministiche, input strutturato (`Vec<DetectInstr>`), output serializzabile via serde. Esiste `tests/` dir. Verificabile sia via unit test sintetici sia via end-to-end comparando con IDA/Ghidra su binari di riferimento.
