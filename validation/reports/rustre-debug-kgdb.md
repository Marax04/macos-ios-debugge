# rustre-debug-kgdb

## Scopo
Crate per il debugging del kernel via protocollo GDB Remote Serial (RSP) — sia lato Linux (KGDB / `kgdboc` / `kgdboe`) sia lato Windows (KD / WinDbg). Modella sessioni simulate del kernel-debugger, parsing/encoding di pacchetti RSP e KD, gestione di breakpoint software e hardware (DR0–DR3 x86-64), watchpoint, accesso a memoria e registri, enumerazione di thread/processi/moduli del kernel, risoluzione simboli kallsyms con supporto KASLR, parsing di strutture kernel Linux (`task_struct`, `mm_struct`, `vm_area_struct`, `file`, `inode`) e Windows (EPROCESS, ETHREAD, KPCR, PEB/TEB, KPRCB, DRIVER_OBJECT, DEVICE_OBJECT, TOKEN). Dipende da `rustre-debug` e `rustre-core`.

## Moduli e funzioni / tipi pubblici

### `lib.rs` (root)
- `enum KgdbError`, `struct GdbPacket`, `struct KernelModule`, `enum KgdbTransport`, `struct KgdbSession` — sessione KGDB simulata
- `enum RspCommand`, `enum RspResponse` — modello comandi/risposte RSP
- `fn bytes_to_hex(data: &[u8]) -> String`
- `fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String>`
- `fn u32_to_hex_le(v: u32) -> String`
- `fn u64_to_hex_le(v: u64) -> String`
- `fn hex_le_to_u64(hex: &str) -> Result<u64, String>`

### `kd_protocol.rs` — Windows KD packet protocol (KD2/KDCom)
- `enum KdPacketType`, `enum KdManipulateRequest`, `struct KdPacket`, `struct KdStateChange`, `struct KdManipulateState`, `enum KdTransport`, `struct KdSession`
- Layout pacchetto: `[leader u32][type u16][byte_count u16][id u32][checksum u32][data N]` little-endian

### `windbg_kd.rs` — WinDbg-style client su `kd_protocol`
- `struct KdSymbol`, `struct KdBreakpoint`, `struct KdCallFrame`, `struct KdCallStack`, `struct KdProcess`, `struct KdThread`, `struct WinDbgKdClient`, `struct AddressInfo`
- Espone equivalenti di `dt`, `!address`, `!process`, lookup simboli, breakpoint, callstack, enumerazione thread/process

### `kgdb_protocol.rs` — estensioni KGDB su RSP
- `enum KgdbTransport` (kgdboc/kgdboe/serial), `enum KgdbStopReason` (panic/Oops/NULL/stack overflow), `struct SysrqTrigger`, `struct KgdbAgentThread`, `struct KgdboeConfig`, `struct KernelPanicInfo`, `struct NmiDebugger`

### `kgdb_packet_handler.rs` — handler RSP server-side
- `enum PacketKind`, `struct KgdbPacket`, `struct KgdbTarget`, `struct KgdbPacketHandler`
- Supporta comandi: `g G m M p P ? c s Z z D k H q`

### `kgdb_memory_access.rs`
- `enum MemAccessError`, `enum MemoryRequest`, `enum MemoryResponse`, `struct KgdbMemoryAccess` con page-cache

### `kgdb_register_access.rs`
- `enum RegAccessError`, `enum RegWidth`, `struct RegDescriptor`, `enum RegLayout`, `enum RegRequest`, `struct RegResponse`, `struct KgdbRegisterAccess`
- `fn layout_descriptors(layout: RegLayout) -> &'static [RegDescriptor]`

### `kgdb_breakpoint_manager.rs`
- `enum BreakpointKind`, `enum WatchpointSize`, `enum BreakpointState`, `enum BreakpointAction`, `struct SavedBytes`, `struct Breakpoint`, `trait TargetMemory`, `struct FlatTargetMemory`, `enum BpError`, `trait RspSession`, `struct SimulatedRspSession`, `struct KgdbBreakpointManager`
- Gestisce breakpoint software (Z0/z0) e hardware (Z1–Z4)

### `kgdb_watchpoint.rs` — hardware watchpoint x86-64 DR0–DR3
- `enum WatchpointType`, `enum WatchpointSize`, `struct HwBreakpoint`, `struct KgdbWatchpoint`
- `fn gdb_z_command(insert: bool, kind: WatchpointType, address: u64, size: u8) -> String`
- `fn describe_dr7(dr7: u32) -> Vec<String>`

### `kgdb_thread_enumerator.rs`
- `enum ThreadEnumError`, `enum ThreadState`, `struct KernelThread`, `struct ThreadList`, `struct KgdbThreadEnumerator`
- `fn list_threads(responses: &[&str]) -> Result<ThreadList>` — parsa `qfThreadInfo`/`qsThreadInfo`/`qThreadExtraInfo`

### `kernel_memory.rs` — accesso memoria kernel Linux
- `enum KernelMemError`, `struct IomemRegion`, `struct IomemParser` (parser `/proc/iomem`), `struct KcoreSegment`, `struct KcoreReader` (ELF `/proc/kcore`), `struct DevMemReader` (`/dev/mem`), `struct CrashDumpInfo` (kdump notes)

### `kernel_memory_reader.rs` — task/module walker con offsets noti
- `enum KernelArchitecture`, `struct KernelSymbol`, `struct KalliSymsParser` (copia minima intenzionale), `struct TaskInfo`, `struct TaskStructOffsets`, `struct KernelModuleInfo`, `trait KernelMemoryAccess`, `struct FlatMemory`, `struct KernelMemoryReader`

### `kernel_symbols.rs` — parser kallsyms con KASLR detector
- `KallsymsParser`, `KernelSymbol`, `SymbolType` (T/t distinction), `SymbolCache` (O(log n) floor via `partition_point`), `KaslrDetector` (confronto runtime vs `System.map`), `ModuleSymbols`

### `kernel_symbol_resolver.rs` — resolver high-level KASLR-adjusted
- `enum SymbolType`, `struct KallsymEntry`, `struct SymbolMap` (fuzzy_search, range, insert), `struct KernelSymbolResolver`, `struct ResolvedSymbol`

### `kernel_struct_parser.rs` — parser strutture kernel Linux
- `struct KernelVersion`, `struct OffsetTable`, `enum ParseError`
- `fn read_u8(mem: &[u8], off: usize) -> Result<u8, ParseError>`
- `fn read_bool(mem: &[u8], off: usize) -> Result<bool, ParseError>`
- `struct TaskStruct`, `struct MmStruct`, `struct VmaStruct` (+ VMA perm flags), `struct FileStruct`, `struct InodeStruct`, `struct OffsetTableRegistry`, `struct KernelStructParser`

### `kernel_structures.rs` — strutture kernel Windows
- `enum WindowsVersion`, `struct FieldOffset`, `struct EprocessLayout`, `struct ParsedEprocess`, `struct EthreadLayout`, `struct KpcrLayout`, `struct PebLayout`, `struct ParsedPeb`, `struct TebLayout`, `struct DriverObjectLayout`, `struct DeviceObjectLayout`, `struct TokenLayout`, `struct KprcbLayout`
- `fn dt_format(struct_name: &str, fields: &[FieldOffset], buf: &[u8]) -> String` — equivalente WinDbg `dt`

### `kernel_modules.rs` — analisi moduli + heap/slab + heuristic exploit
- `enum KernelModuleError`, `struct KernelModule`, `enum ModuleState`, `struct ModuleSymbol`, `struct ModuleSymbols`, `struct KernelModules`, `struct SlabObject`, `struct SlabCache`, `struct SlabAllocator` (SLUB/SLAB), `struct KernelHeap`, `struct ExploitIndicator`, `enum ExploitCategory`, `enum ExploitSeverity`, `struct KernelExploit`

### `kernel_debugging.rs` — aggregato debug Linux
- `enum SymbolType`, `struct KernelSymbol`, `enum ModuleState`, `struct KernelModule`, `struct KernelStackFrame`, `struct KernelCallStack`, `enum ProcessState`, `struct ProcessEntry`, `struct ProcessList`, `struct IrqLine`, `struct IRQState`, `struct RunQueue`, `struct SchedulerState`, `struct KernelPanic`, `struct KernelDebugging`

## Input / Output

| Tipo | Input | Output |
|---|---|---|
| `bytes_to_hex` / `hex_to_bytes` | bytes / hex string | hex / Vec<u8> |
| `u{32,64}_to_hex_le` / `hex_le_to_u64` | numero / hex | hex LE / numero |
| `KallsymsParser` / `SymbolMap` | testo `/proc/kallsyms` o `System.map` | tabella simboli con KASLR slide |
| `KcoreReader` | path `/proc/kcore` (ELF) | segmenti PT_LOAD + read VA |
| `IomemParser` | testo `/proc/iomem` | regioni fisiche tipizzate |
| `KdPacket` / `KgdbPacket` | bytes wire | struct decodificata (+ checksum) |
| `KgdbPacketHandler` | RSP packet | response packet su `KgdbTarget` |
| `KgdbThreadEnumerator::list_threads` | risposte `qfThreadInfo`/`qsThreadInfo` | `ThreadList` |
| `KernelStructParser` | blob memoria + `KernelVersion` | `TaskStruct` / `MmStruct` / `VmaStruct` / `FileStruct` / `InodeStruct` |
| `dt_format` | nome struct + `FieldOffset[]` + buffer | stringa formattata stile WinDbg `dt` |
| `gdb_z_command` | insert flag, tipo, addr, size | stringa RSP `Z`/`z` |
| `describe_dr7` | DR7 (u32) | descrizioni slot attivi |
| `KernelSymbolResolver` | kallsyms + slide KASLR | addr ↔ symbol + offset |

## Ground truth verificabile esternamente

- **GDB RSP wire format** — RFC-style spec in GDB sources (`gdb/doc/gdb.texinfo` "Remote Serial Protocol"); pacchetti `$data#XX` con checksum mod-256 dei byte tra `$` e `#`. Comandi `g G m M p P ? c s Z z D k H q` documentati.
- **KGDB protocol** — `Documentation/dev-tools/kgdb.rst` del kernel Linux; trasporti `kgdboc`/`kgdboe`, SysRq-g via `/proc/sysrq-trigger`.
- **kallsyms format** — `<hex-addr> <type> <name> [module]`, con `T`=global text, `t`=local text, etc. (vedi `kernel/kallsyms.c` e output `nm`).
- **`/proc/kcore`** — ELF core file, segmenti `PT_LOAD` mappano VA kernel → file offset (`fs/proc/kcore.c`).
- **`/proc/iomem`** — formato `start-end : description` documentato in `Documentation/filesystems/proc.rst`.
- **x86-64 DR0-DR7** — Intel SDM Vol. 3B §17.2 (Debug Registers). DR7 layout: 2 bit local/global enable per slot + 4 bit LEN/RW per slot a partire dal bit 16.
- **Windows KD protocol (KD2 / KDCom)** — leader `0x30303030` (control) / `0x69696969` (data, "iiii"); reverse-engineered in tool come WinDbg, KdSrv, e progetti FOSS (rekall, livecloudkd). `EPROCESS`/`ETHREAD`/`KPCR` offsets per versione documentati su Vergilius Project.
- **Linux `task_struct`/`mm_struct`** — versione-dipendente; offset tipici noti per 5.x x86-64 (cross-check con `pahole` su un vmlinux con debuginfo).
- **KASLR slide** — calcolabile come `runtime_addr(sym) - System.map_addr(sym)` per qualsiasi simbolo testo non randomizzato internamente.
- **kdump/makedumpfile** — formato note ELF documentato in `Documentation/admin-guide/kdump/kdump.rst`.

## Tool MCP esistenti correlati

- `mcp__rustre-mcp__debug_attach`, `debug_launch`, `debug_continue`, `debug_step_into`, `debug_step_over` — debugger generico RustRE (non specificamente KGDB).
- `mcp__rustre-mcp__debug_read_memory`, `debug_write_memory`, `debug_read_registers`, `debug_backtrace`, `debug_evaluate` — accesso memoria/registri/backtrace in sessione di debug.
- `mcp__rustre-mcp__debug_set_breakpoint`, `debug_remove_breakpoint` — gestione breakpoint.
- `mcp__hyperdbg__*` — debugger Windows hypervisor-based, copre scenari kernel-mode Windows.
- `mcp__x64Dbg__x64dbg_debug`, `x64dbg_breakpoints`, `x64dbg_memory`, `x64dbg_registers`, `x64dbg_threads`, `x64dbg_modules` — debugger user-mode (non kernel).
- `mcp__frida__*` — dynamic instrumentation (user-mode).
- **Gap**: nessun tool MCP esistente espone direttamente parsing pacchetti RSP/KD, walker `task_struct`, parser `/proc/kcore`/`/proc/iomem`, o KASLR detector. Questo crate è quindi candidato a un nuovo gruppo MCP `debug_kgdb_*` / `debug_kd_*`.

## Testabilità

Sì — il crate è testabile in modo significativo senza hardware reale:
- Parser puri (kallsyms, kcore, iomem, KD/RSP packet, DR7) verificabili con vettori noti.
- `SimulatedRspSession` + `FlatTargetMemory` + `KgdbTarget` simulati permettono test end-to-end del packet handler e breakpoint manager.
- `KernelStructParser` testabile con blob `pahole`-derived offset tables.
- Cartella `tests/` già presente nel crate.
- Ground truth esterna: GDB sources, kernel Documentation, Intel SDM, Vergilius Project.
