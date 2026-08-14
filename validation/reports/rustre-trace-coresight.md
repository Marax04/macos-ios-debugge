# rustre-trace-coresight

ARM CoreSight ETM trace decode engine: full ETMv4/ETE trace decode, PTM/ETM3 support, CoreSight topology discovery via ROM tables, data trace, and trace filtering.

## Cargo.toml

```toml
[package]
name = "rustre-trace-coresight"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow      = { workspace = true }
thiserror   = { workspace = true }
serde       = { workspace = true }
parking_lot = { workspace = true }
libc        = "0.2"
```

No optional features. Workspace lints applied.

## Public modules (`src/lib.rs`)

| Module | Purpose |
|---|---|
| `coresight_packets` | Low-level packet structures |
| `coresight_topology` | CoreSight topology / ROM table discovery |
| `ptm_decoder` | PTM (Program Trace Macrocell) decoder |
| `cs_analysis` | High-level trace analysis helpers |
| `etm_decoder` | ETM decoder front-end |
| `etm_packets` | ETM packet types |
| `stm_decoder` | STM (System Trace Macrocell) decoder |
| `timestamp_decoder` | Timestamp packet decoding |
| `tpiu_sink` | TPIU (Trace Port Interface Unit) sink |
| `trace_reconstructor` | Reconstruct instruction stream from packets |
| `ptt_trace_parser` | PTT (Perf Trace) parser |
| `coresight_etm_decoder` | CoreSight ETM specialization |
| `coresight_stm_decoder` | CoreSight STM specialization |

## Public API surface (`lib.rs`)

### Error

- `enum CsError` (thiserror) — `InvalidPacket(u8)`, `TruncatedBuffer`, `UnknownFormat(String)`, `SyncLost(usize)`, `UnsupportedIsa(String)`, `RomTable(String)`, `DataTrace(String)`.

### Enums (with Serde + Display)

- `ExceptionType` (u8 repr) — Reset, Undefined, Svc, PrefetchAbort, DataAbort, Irq, Fiq, Hvc, Smc, SError, Debug, Unknown.
  - `const fn from_etm_field(v: u8) -> Self`
- `ExceptionLevel` (u8 repr) — El0..El3.
  - `fn from_bits(b: u8) -> Self`
  - `const fn level(self) -> u8`
- `IsaMode` — Aarch64, Arm, Thumb, Thumb16, Jazelle.
- `SecurityState` — NonSecure, Secure.
- `EtmVersion` — Etm3, Etm4, EtmV4p1, Ptm, Ete.
- `TracePortMode` — Tpiu, Etf, Etb, SysMemory.

### Packet types

- `enum CsPacketKind` — TraceInfo, TraceOn, TraceOff, `Address{addr}`, `Atom{taken,count}`, `Exception{exc_type}`, Timestamp(u64), ContextId(u32), VmId(u32), Overflow, CycleCount(u64), Sync, Ignore, `DataAddress{addr,is_write}`, `DataValue{value,size}`, ExceptionReturn, `Context{el,ns}`, `QElement{count}`, `BranchFuture{target}`, `IndirectBranch{target}`.
- `struct CsPacket { kind, byte_offset }`.
- `struct AtomPacket { en_bits, count, byte_offset }`
  - `const fn new(en_bits, count, byte_offset)`
  - `const fn is_taken(&self, idx: u8) -> bool`
  - `fn to_vec(&self) -> Vec<bool>`
- `struct ExceptionPacket { exc_type, level, previous_el, target_addr, byte_offset }`
  - `const fn new(exc_type, level, byte_offset)`
- `struct DataTracePacket { address, value, size, is_write, byte_offset }`
  - `const fn new(...)`, `const fn with_value(self, value) -> Self`
- `struct EtmAddressUpdate { address, is_full, bytes_valid, el_hint }`
  - `const fn full(address)`, `const fn partial(address, bytes)`
- `struct EtmTimestamp { value }`
  - `const fn new`, `const fn delta_from`

### Configuration / context

- `struct EtmConfig { version, arch, addr_comparators, context_id_comparators, data_trace_enabled, cycle_counting, timestamps, trace_id }`
  - `fn new(version, arch)`
  - `const fn with_data_trace(self) -> Self`, `const fn with_cycle_count(self) -> Self`
- `struct EtmContext { isa, security, el, current_addr, context_id, vmid, speculative, addr_valid, timestamp, cycle_count }` (Default)
  - `fn new_aarch64()`
  - `const fn apply_address(&mut self, addr)`
  - `const fn apply_context(&mut self, el, ns)`
  - `const fn advance(&mut self, n: u64)`

### Decoders

- `struct CoreSightDecoder { config, context, atoms, exceptions, data_trace, ... }` — full ETM4/ETE engine.
  - `fn new(config: EtmConfig)`
  - `fn feed(&mut self, data: &[u8])`
  - `fn find_sync(&mut self) -> bool`
  - `fn next_packet(&mut self) -> Option<CsPacket>` (dispatches on header byte: 0x00/0x04 atom, 0x01 TraceInfo, 0x05/0x06 TraceOn/Off, 0x07 ExceptionReturn, 0x08 exception, 0x0D cycle count, 0x0E context, 0x43 timestamp, 0x50 ContextId, 0x51 VmId, 0x80 Sync, 0x9A/0x9B addr32/64, 0xAA indirect branch).
  - `fn decode_all(&mut self) -> Vec<CsPacket>`
  - `const fn position(&self) -> usize`
  - `fn reset(&mut self)`
  - `const fn is_synchronized(&self) -> bool`
- `struct CsDecoder { buf, pos, config }` — legacy compatibility wrapper. Same `new/feed/next_packet/decode_all` surface, narrower opcode coverage.
- `struct PtmDecoder { config, last_addr, atom_queue, .. }` (Default).
  - `new/feed/next_packet/next_atom`.
- `struct Etm3Decoder { config, context_id, last_addr, .. }` (Default).
  - `new/feed/next_packet`.
- `struct EteDecoder { config, in_branch_table, .. }` (Default) — ARMv9 ETE wrapper around `CoreSightDecoder`.
  - `new/feed/next_packet/decode_all`.

### Trace structures

- `struct EtmTrace { packets, config }`
  - `fn instruction_addresses(&self) -> Vec<u64>`
  - `fn atom_count(&self) -> usize`
  - `fn taken_atoms(&self) -> usize`
  - `fn not_taken_atoms(&self) -> usize`
  - `fn exception_count(&self) -> usize`
  - `fn last_timestamp(&self) -> Option<u64>`

### Synchronization & ports

- `struct CoreSightSynchronization` (zero-sized).
  - `fn find_sync_offsets(data: &[u8]) -> Vec<usize>` — locate ASYNC frames (11 × 0x00 + 0x80).
  - `fn is_valid_stream(data: &[u8]) -> bool` — short-circuit validity check.
- `struct CoreSightTracePort { width, frequency_hz, mode, ddr }`.
  - `const fn new_tpiu(width, frequency_hz)`, `const fn new_etb()`.

### Buffers / memory interfaces

- `struct EmbeddedTraceBuffer { capacity, wrapped, .. }` — on-chip trace buffer (ETB) with wrap-around simulation.
  - `new/write/read_all/stored_bytes/is_full/reset/advance_read/read_bytes`.
- `struct TraceMemoryInterface { base_addr, size, write_ptr, read_ptr, data }` — TMI for system-memory trace capture.
  - `const fn new(base_addr, size)`, `fn receive(&mut self, bytes)`, `const fn has_data(&self)`, `fn drain(&mut self) -> Vec<u8>`.

### ROM table

- `struct RomTableEntry { base_addr, component_class, part_number, description, present }`.
  - `fn new(base_addr, component_class, part_number)`
  - `const fn is_etm(&self) -> bool` (matches Cortex-A ETM part numbers)
  - `const fn is_cti(&self) -> bool`

## Notes

- All packet/config/enum types derive `Serialize`/`Deserialize`, suitable for trace-session persistence.
- `lib.rs` is large (~4346 lines); this report covers the top portion exhaustively and lists every submodule. Submodules (`coresight_topology`, `cs_analysis`, `trace_reconstructor`, `ptt_trace_parser`, etc.) provide additional pub API not enumerated here.
- The crate is pure host-side decode logic plus `libc` for OS interaction in submodules; no unsafe FFI in the core types.

## Testability

The crate exposes pure decoders that accept `&[u8]` and emit `Vec<CsPacket>`/`EtmTrace`, making it directly unit-testable with synthetic byte streams. Sync detection (`CoreSightSynchronization::find_sync_offsets`), packet dispatch (`CoreSightDecoder::next_packet`), and atom/exception helpers all have deterministic outputs given a known input buffer. Integration tests would feed canonical ETMv4 captures and assert packet sequences.
