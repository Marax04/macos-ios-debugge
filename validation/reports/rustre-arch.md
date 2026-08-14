# rustre-arch

## Scopo
Hub di orchestrazione architetturale per la RustRE Suite. Ri-esporta il trait `Architecture` e i tipi correlati da `rustre-core` e aggiunge: registry thread-safe di backend ISA, disassemblatori linear/recursive, iteratore lazy di istruzioni, snapshot register file, statistiche aggregate, contesto di lift IL, metadati arch, errori tipizzati, e detection di formato/architettura da bytes (ELF/PE/Mach-O). Non implementa singoli ISA (quelli vivono nei sub-crates `rustre-arch-*`); espone invece la collante comune e il registry globale.

## Dipendenze chiave
- `rustre-core` (trait `Architecture`, tipi `Instruction`, `BranchInfo`, `RegisterInfo`, `CallingConvention`, `Address`, `Endian`, `CoreError`)
- `dashmap`, `parking_lot` (concurrency), `thiserror`, `bitflags`, `serde`, `anyhow`

## Moduli pubblici
- `arch_features`, `arch_feature_flags` — feature flags ISA
- `arch_meta` — metadati estesi
- `arch_registry`, `arch_registry_full` — registry alternativi
- `calling_conv`, `calling_conventions` — convenzioni di chiamata
- `instr_analysis`, `instruction_semantics` — analisi istruzione singola
- `register_set`, `register_alias_map` — descrittori registri
- `cross_arch_normalizer` — normalizzazione cross-ISA

## Public types & functions (lib.rs)

### Errori
- `enum DecodeError { Invalid, Truncated, Other(String) }`
- `enum EncodeError { InvalidOperand, Unsupported, Other(String) }`
- `enum LiftError { Unsupported, StackOverflow, Other(String) }`

### `LiftContext`
- `new() -> Self`
- `push(&mut self) -> Result<(), LiftError>` — overflow se depth ≥ 4096
- `pop(&mut self)` — saturating
- `set_temp(name, value: u64)`, `get_temp(name) -> Option<u64>`
- `warn(msg)` — cap 4096 warnings
- `has_warnings() -> bool`

### `ArchMetadata`
- `fixed_width(instr_size, nop, description) -> Self`
- `variable_width(min, max, nop, description) -> Self`
- Campi: `description`, `min_instr_size`, `max_instr_size`, `variable_length`, `nop_bytes`

### `ArchRegistry`
- `new()`, `register(Arc<dyn Architecture>)`, `register_with_meta(arch, meta)`
- `find(name) -> Option<Arc<dyn Architecture>>`
- `metadata(name) -> Option<ArchMetadata>`
- `names() -> Vec<String>`
- `remove(name) -> bool`, `len()`, `is_empty()`

### `InstrStats`
- `feed(&mut self, &Instruction)` — accumula contatori (total/branches/calls/returns/conditionals/memory_ops)
- `from_slice(&[Instruction]) -> Self`
- `branch_density() -> f64`
- `Display` impl

### `RegisterFile`
- `new(arch_name)`, `zeroed(&dyn Architecture)`
- `write(id: u32, value: u64)`, `read(id) -> u64` (default 0)
- `has(id) -> bool`, `zero_all()`, `arch_name() -> &str`, `len()`, `is_empty()`

### `InstrStream`
- `new()`, `stats() -> InstrStats`, `is_empty()`, `len()`
- Campi: `instructions: Vec<Instruction>`, `errors: Vec<(Address, String)>`

### `LinearDisassembler`
- `new(Arc<dyn Architecture>)` (strict=false)
- `disassemble(base: Address, bytes: &[u8]) -> InstrStream` — linear sweep, su errore avanza di 1 byte (o break se strict)
- `disassemble_count(base, bytes, count) -> InstrStream`
- `arch_name() -> &str`

### `RecursiveDisassembler`
- `new(arch)` — `max_instrs = 100_000` default
- `disassemble(base, bytes, entry: Address) -> InstrStream` — recursive descent, segue rami, dedup via HashSet visited, output ordinato per address
- `arch_name() -> &str`

### `DisasmFilter`
- `accept_all()`, `branches_only()`, `calls_only()`
- `matches(&Instruction) -> bool`
- `apply(&InstrStream) -> InstrStream`
- Campi: `mnemonic_contains`, `required_flags`, `excluded_flags`

### `DisasmCache`
- `new()`, `insert(Instruction)`, `get(addr: u64)`, `contains(addr)`, `clear()`, `len()`, `is_empty()` — thread-safe via Mutex

### Global registry
- `global_registry() -> &'static DashMap<String, Arc<dyn Architecture>>`
- `register_all_builtins()` — pre-registra placeholder per: x86, x86_64, arm, arm64, mips, mips64, ppc, ppc64, riscv32, riscv64, sparc, sparc64, msp430, avr, 6502, z80, 68k, bpf, wasm, jvm, cil, luajit, dex

### Detection arch da bytes
- `detect_arch_from_bytes(data: &[u8]) -> Option<String>` — dispatch ELF/PE/Mach-O
- `detect_from_elf(data) -> Option<String>` — legge `e_machine` @ offset 18, `EI_DATA` @ 5, `EI_CLASS` @ 4. Mapping: 3→x86, 62→x86_64, 40→arm, 183→arm64, 8→mips, 20→ppc, 21→ppc64, 243→riscv32/64 (per ELF class), 2→sparc, 18→sparc64, 220→msp430, 83→avr
- `detect_from_pe(data) -> Option<String>` — legge PE offset @ 0x3C (LE u32), verifica `PE\0\0`, machine @ +4. Mapping: 0x014c→x86, 0x8664→x86_64, 0x01c0→arm, 0xaa64→arm64, 0x01f0→ppc, 0x0162→mips
- `detect_from_macho(data) -> Option<String>` — magic FEEDFACE/FACF (BE) o CEFAEDFE/CFFAEDFE (LE), cputype @ +4. Mapping: 7→x86, 0x1000007→x86_64, 12→arm, 0x100000c→arm64, 18→ppc, 0x1000012→ppc64

### `DisassemblyResult`
- `new()` (+ altri non visti nel chunk; complementa InstrStream con `total_bytes`)
- Campi: `instructions`, `total_bytes`, `errors`

## Re-exports da `rustre-core`
`Address`, `ArchMode`, `Architecture`, `BranchInfo`, `CallingConvention`, `InstrFlags`, `Instruction`, `RegisterInfo`, `Endian`, `CoreError`.

## Ground truth verificabile esternamente

1. **Magic bytes ELF/PE/Mach-O** — costanti standard, verificabili contro:
   - Specifica ELF (`/usr/include/elf.h`, `EM_*` values: EM_386=3, EM_X86_64=62, EM_ARM=40, EM_AARCH64=183, EM_MIPS=8, EM_PPC=20, EM_PPC64=21, EM_RISCV=243, EM_SPARC=2, EM_SPARCV9=18, EM_MSP430=105 — **ATTENZIONE: il codice usa 220, ma EM_MSP430 standard è 105**, EM_AVR=83).
   - PE/COFF spec Microsoft: IMAGE_FILE_MACHINE_I386=0x014c, AMD64=0x8664, ARM=0x01c0, ARM64=0xAA64, POWERPC=0x01F0, R4000=0x0166 (**il codice usa 0x0162 per mips — verificare**).
   - Mach-O `<mach/machine.h>`: CPU_TYPE_X86=7, X86_64=0x01000007, ARM=12, ARM64=0x0100000C, POWERPC=18, POWERPC64=0x01000012 — match.
2. **Confronto con `goblin`/`object` crate** per detection di formato.
3. **`file(1)` / `readelf -h`** su binari noti per validare il mapping arch.
4. **`LiftContext::push` overflow** a 4096 — verificabile via unit test diretto.
5. **`register_all_builtins` lista** confrontabile con i sub-crates effettivamente presenti in `crates/rustre-arch-*`.
6. **Linear vs Recursive disassembly**: confronto contro `objdump -d` (linear) e `radare2 aaa` / IDA recursive descent su un binario ELF x86_64 di test.

## Possibili bug rilevati
- **EM_MSP430**: codice usa `220`, valore ELF ufficiale è `105` (0x69). Da verificare.
- **PE MIPS**: codice usa `0x0162` (IMAGE_FILE_MACHINE_R3000), comune oggi è `0x0166` (R4000) o `0x0366`/`0x0466`. Da verificare contro spec MS.

## Tool MCP RustRE esistenti correlati
- `mcp__rustre-mcp__binary_info` — info formato/arch (overlap con `detect_arch_from_bytes`)
- `mcp__rustre-mcp__survey_binary` — overview binario
- `mcp__rustre-mcp__disasm_at` / `analysis_disasm_at_path*` — disassembly (consumer di `LinearDisassembler`/sub-arch)
- `mcp__rustre-mcp__analysis_fn_cfg_path` — usa recursive disasm sotto
- `mcp__rustre-mcp__analysis_basic_blocks_path` — consumer di `InstrStream`/branch info

## Test
- Directory `tests/` presente nel crate — testable in isolamento (unit + integration).
- Tutte le funzioni di detection sono pure (input `&[u8]` → `Option<String>`) e banalmente fuzzabili.
- `ArchRegistry`, `LiftContext`, `InstrStats`, `DisasmFilter`, `RegisterFile`, `DisasmCache`: state-machine puro, facilmente testabili.

**Testable: true**
