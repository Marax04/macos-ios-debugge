# rustre-arch-registry

## Scopo
Composition crate che cabla ogni sub-crate `rustre-arch-*` concreto (19 backend) nel `rustre_arch::global_registry` di processo. Sta fuori dal hub `rustre-arch` per evitare cicli di path-deps (i sub-crate dipendono dal hub).

## Dipendenze rilevanti
- `rustre-core` (trait `Architecture`)
- `rustre-arch` (hub + `global_registry`)
- 19 backend: 6502, 68k, arm, arm64, avr, bpf, cil, dex, jvm, lua, luajit, mips, msp430, ppc, riscv, sparc, wasm, x86, z80

## Public functions

### `pub fn all() -> Vec<Arc<dyn Architecture>>`
- Input: nessuno
- Output: vettore fresco con un `Arc<dyn Architecture>` per ciascuno dei 19 backend cablati, costruiti via `::default()` (o unit struct per `Arm64Arch`, `JvmArch`, `LuaJitArch`, `WasmArch`).
- `#[must_use]`

### `pub fn register_all()`
- Input: nessuno
- Output: `()`. Side-effect: per ogni arch in `all()`, esegue `global_registry().insert(arch.name().to_owned(), arch)`, sovrascrivendo eventuali `PlaceholderArch` da `rustre_arch::register_all_builtins`.

## Ground truth verificabile esternamente
- `all().len() == 19` (conteggio sub-crate in `Cargo.toml` = 19, `vec![...]` in `lib.rs` = 19 elementi).
- Set dei nomi attesi (via `arch.name()` di ciascun backend) deve coprire: 6502, 68k, arm, arm64, avr, bpf, cil, dex, jvm, lua, luajit, mips, msp430, ppc, riscv, sparc, wasm, x86, z80.
- Dopo `register_all()`, `global_registry().get(name)` per ognuno deve restituire l'istanza concreta (non `PlaceholderArch`).
- Idempotenza: due chiamate consecutive a `register_all()` lasciano il registry con un'entry per nome (insert overwrite).
- Cargo.toml lista esattamente le 19 deps `rustre-arch-*` + `rustre-arch` + `rustre-core`.

## Tool MCP esistenti rilevanti
- `mcp__rustre-mcp__analysis_disasm_at_path_arm64` / `_cil` / `_jvm` / `_mips` / `_riscv` / `_wasm`: dispatch per arch specifica — implicitamente dipendono dal registry popolato.
- Nessun tool MCP espone direttamente `arch-registry`; la verifica si fa via test unitario nel crate o ispezione del `global_registry` dal binario MCP server all'avvio.

## Testabile
true — `all().len()`, set dei nomi e idempotenza di `register_all()` sono verificabili senza I/O esterno.
