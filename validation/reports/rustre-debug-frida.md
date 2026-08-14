# rustre-debug-frida

## Scopo
Debugger basato su Frida per RustRE Suite. Simula una sessione di dynamic instrumentation Frida (iniezione agente, esecuzione script JS, memory scanning, hook Interceptor, Stalker, memory patching) e implementa il trait `Debugger` di `rustre-debug`. Supporta architetture x86/x86_64/arm/arm64/aarch64/mips. Feature opzionale `frida-gum` per binding reali a `frida-gum-sys` v0.14; di default la sessione e' simulata in-memory. Su Unix usa `nix` per ptrace/signal/mman.

## Moduli pub
- `frida_agent` — gestione agente
- `frida_scripts` — FridaScriptBuilder, HookScript, MemoryScanScript, StalkerScript, AntiAntiDebugScript, 30+ ScriptTemplates, ScriptOptimizer
- `frida_stalker` / `stalker_engine` — code tracing (block/call/return/exec callbacks), SMC detection, JIT regions, exclude ranges, call-graph, BB heat maps
- `interceptor_engine` — prolog/epilog hooking, args/retval inspection, function replacement, NativeFunction/NativeCallback, transactions
- `memory_patcher` — byte-level writes, NOP fill, jump/call redirection (x86/ARM64 near+absolute), `ret` insertion, undo/redo stack, scan-and-patch
- `frida_script_builder`, `frida_rpc_client`, `frida_trace_analyzer`, `frida_message_handler`, `frida_stalker_controller`
- `v2` — API spec-compliant: `FridaDevice`, `FridaTarget`, `FridaSession`, `FridaScript`, `InterceptorRule`, `StalkerEvent`, `FridaManager`

## Tipi pubblici principali (lib.rs)
- `FridaError` — ScriptError, AgentNotInjected, ProcessNotFound, RpcFailed, Debug(#[from] DebugError)
- `FridaHook { address: u64, script: String, hook_id: u64 }`
- `InterceptorRecord { hook_id, address, thread_id: u32, args: Vec<u64>, return_value: Option<u64>, timestamp }`
- `FridaSessionState` — Detached/Attaching/Attached/Suspended/Resuming
- `FridaDebugSession` — sessione principale

## Funzioni pubbliche FridaDebugSession (inerenti)
- `new() -> Self` / `Default`
- `install_hook(&mut self, address: u64, script: String) -> Result<u64, FridaError>` — richiede Attached
- `remove_hook(&mut self, hook_id: u64) -> Result<(), FridaError>`
- `intercept_records(&self) -> Vec<InterceptorRecord>`
- `hooks(&self) -> Vec<FridaHook>`
- `state(&self) -> FridaSessionState`
- `execute_script(&self, script: &str) -> Result<serde_json::Value, FridaError>`
- `scan_memory_pattern(&self, pattern: &[u8]) -> Result<Vec<u64>, FridaError>` — scan pagine simulate
- `debug_session(&self) -> &DebugSession`
- `simulate_hook_hit(&self, hook_id, args: Vec<u64>, return_value: Option<u64>)` — no-op se non Attached

## Funzioni pubbliche tramite `impl Debugger` (async)
- `name() -> "frida"`, `supported_architectures()`
- `launch(opts) -> Err(Unsupported)` (Frida richiede attach a processo gia' in esecuzione)
- `attach(pid)`, `detach()`, `kill()`, `is_attached()`, `target_pid()`
- `continue_execution()`, `single_step(tid)` (incrementa rip di 1), `step_over`, `step_out`, `pause`
- `threads()`, `current_thread()`
- `get_registers/set_registers/get_register/set_register` (x86_64 default reg set)
- `read_memory(addr, size)`, `write_memory(addr, &[u8])`, `memory_maps()` — pagine simulate (NOP sled @0x1000, 4KB @0x401000)
- `set_breakpoint/remove_breakpoint/enable_breakpoint/disable_breakpoint/breakpoints()`
- `modules()`, `backtrace(tid)` — frame singolo da rip/rsp/rbp

## API v2
- `FridaTarget::local_pid(u32)`, `FridaTarget::local_name(name)`
- `FridaSession::new(id, target)`, `is_attached()`, `script_count()`
- `FridaManager::new()/default()`, `attach(target) -> Result<FridaSession, FridaError>`, `detach(id)`, `add_interceptor(rule)`, `interceptor_count()`, `session_count()`, `mock_stalker_events(count) -> Vec<StalkerEvent>`

## Ground truth verificabile esternamente
- **Frida-gum API reale**: `frida-gum-sys` v0.14 (crates.io / frida.re docs) — verifica nomi Interceptor/Stalker/NativeFunction/NativeCallback corrispondano alla semantica Frida ufficiale.
- **Frida JS scripts**: `Interceptor.attach(addr, {onEnter, onLeave})`, `Memory.scan`, `Stalker.follow` — confrontabili contro frida.re/docs/javascript-api.
- **Debugger trait**: definito in `rustre-debug` (stesso workspace) — comportamento atteso (NotAttached errors, BreakpointExists, ecc.) testabile via mock.
- **Comportamento ptrace**: su Unix usa `nix 0.29` con feature ptrace; verificabile contro `man ptrace(2)`.
- **Architetture supportate**: x86/x86_64/arm/arm64/mips coincidono con quelle ufficiali Frida.
- I 60+ unit test inclusi (`#[cfg(test)]`) sono verifiche dirette del contratto: attach/detach idempotency, breakpoint dup-error, hook lifecycle, memory page mapping, pattern scan.

## Tool MCP esistenti (rustre-mcp) correlati
- `debug_attach`, `debug_launch`, `debug_continue`, `debug_step_into`, `debug_step_over`, `debug_backtrace`
- `debug_set_breakpoint`, `debug_remove_breakpoint`
- `debug_read_memory`, `debug_write_memory`, `debug_read_registers`, `debug_evaluate`
- Nessun tool MCP dedicato a Frida hooks/Stalker/Interceptor/script execution → gap: `frida_install_hook`, `frida_execute_script`, `frida_scan_memory_pattern`, `frida_stalker_follow`, `frida_intercept_records` non esposti.

## Testabile
Si — la sessione e' completamente in-process e simulata: attach a un PID arbitrario funziona senza processo reale, memoria/registri/hook sono strutture interne, e l'intera superficie e' coperta da unit test sincroni e tokio-async. La feature `frida-gum` (opzionale) richiederebbe invece un target reale.
