# rustre-trace-pt

Intel Processor Trace (PT) decode and reconstruction library.

## Cargo.toml

- **name**: `rustre-trace-pt`
- **version**: 0.1.0
- **edition**: 2024
- **license / description / repository / readme / keywords / categories / authors**: ereditati dal workspace
- **dipendenze runtime**:
  - `anyhow` (workspace)
  - `thiserror` (workspace)
  - `serde` (workspace)
  - `libc = "0.2"`
- **dev-dependencies**: `serde_json` (workspace)
- **lints**: `unsafe_code = "allow"` a livello di package (necessario per `__cpuid_count` nelle CPUID intrinsics; mirror di `rustre-debug-windows` e `rustre-script-python`).
- **Vincolo**: NON deve dipendere da `rustre-trace` (ciclo workspace — `rustre-trace` lista questo crate come dep opzionale).

## Moduli pubblici (`src/lib.rs`)

- `pt_decoder`
- `pt_filter`
- `pt_flow_reconstruction`
- `pt_sideband`
- `pt_snapshot`
- `pt_timing`
- `pt_trace_builder`
- `pt_packet_decoder`
- `pt_instruction_decoder`
- `pt_perf_integration`
- `pt_block_decoder`
- `pt_timing_analyzer`
- `pt_coverage_reporter`

Modulo interno: `cast_helpers` (re-export `#[doc(hidden)]` di `__ch_*`).

## Tipi pubblici (lib.rs)

### `enum PtError` (thiserror)
Errori di decodifica PT:
- `InvalidPacket(u8)`
- `TruncatedPacket`
- `UnknownOpcode(u8)`
- `IpCompression(String)`
- `FlowReconstruction(String)`
- `Sideband(String)`
- `Timing(String)`
- `Overflow(usize)`

### `enum IpCompression`
Modalita compressione IP nei pacchetti PT: `Zero`, `Update16`, `Update32`, `Full48`, `Full48SignExt`, `Full64`.

Funzioni pubbliche:
- `pub const fn byte_count(self) -> usize` — byte addizionali da leggere.
- `pub const fn from_ipr(ipr: u8) -> Self` — parse dal campo IPR a 3 bit.

### `enum PtPacketKind`
Tipo di pacchetto decodificato. Varianti: `Pad`, `Psb`, `PsbEnd`, `Tip{ip,compression}`, `TipPge{...}`, `TipPgd{...}`, `Tnt{bits,count}`, `TntLong{bits,count}`, `Tsc(u64)`, `Mtc{ctc}`, `Cyc{value}`, `Cbr(u8)`, `Overflow`, `Mode{leaf,bits}`, `Pip{cr3,nr}`, `Vmcs{base}`, `ExStop{ip}`, `Mwait{ext,hints}`, `Pwre{...}`, `Pwrx{...}`, `Bbp{type_flag}`, `Bip{id,value}`, `Bep{ip}`.

Implementa `Display`. Metodi:
- `pub const fn is_timing(&self) -> bool`
- `pub const fn is_flow(&self) -> bool`
- `pub const fn ip_addr(&self) -> Option<u64>`

### `struct PtPacket { kind, offset, size }`
Pacchetto decodificato con offset/size raw. Implementa `Display`.

Funzioni:
- `pub const fn new(kind, offset, size) -> Self`
- `pub const fn is_timing(&self) -> bool`
- `pub const fn is_flow(&self) -> bool`

### `struct PtDecoder`
Decoder stateful per stream di byte PT.

Campi pubblici: `buf: Vec<u8>`, `pos: usize`, `overflow_count: usize`, `error_count: usize`.

Funzioni:
- `pub const fn new() -> Self`
- `pub fn feed(&mut self, data: &[u8])`
- `pub const fn reset(&mut self)` — resetta stato ma non il buffer.
- `pub const fn remaining_bytes(&self) -> usize`
- `pub fn peek_byte(&self) -> Option<u8>`
- `pub fn next_packet(&mut self) -> Option<Result<PtPacket, PtError>>`
- `pub fn decode_all(&mut self) -> Vec<PtPacket>` — silenzia gli errori.
- `pub fn decode_all_with_errors(&mut self) -> Vec<Result<PtPacket, PtError>>`
- `pub fn count_by_kind(packets: &[PtPacket]) -> HashMap<&'static str, usize>`

Implementa `Default`.

### `enum PtEvent`
Eventi high-level di esecuzione prodotti durante la flow reconstruction: `BranchTaken{ip,target}`, `BranchNotTaken{ip,fallthrough}`, `IndirectBranch{from,to}`, `Call{from,to}`, `Return{from,to}`, `TraceEnabled{ip}`, `TraceDisabled{ip}`, `Overflow{offset}`, `Timestamp{tsc}`, `ModeChange{leaf,bits}`. Implementa `Display`.

### `struct TimingInfo`
Campi pubblici: `first_tsc`, `last_tsc`, `cbr`, `mtc_values`, `cyc_values`.

Funzioni:
- `pub fn new() -> Self`
- `pub const fn record_tsc(&mut self, tsc: u64)`
- `pub const fn record_cbr(&mut self, cbr: u8)`
- `pub fn record_mtc(&mut self, ctc: u8)`
- `pub fn record_cyc(&mut self, value: u64)`
- `pub const fn elapsed_tsc(&self) -> Option<u64>`
- `pub fn total_cycles(&self) -> u64`
- `pub fn elapsed_ns(&self, cpu_mhz: f64) -> Option<f64>`

### `struct SidebandInfo`
Campi pubblici: `cr3_to_image: BTreeMap<u64,u64>`, `modules: Vec<(u64,u64,String)>`, `pid_names: HashMap<u32,String>`.

Funzioni:
- `pub fn new() -> Self`
- `pub fn register_module(&mut self, base, size, name: impl Into<String>)`
- `pub fn register_cr3(&mut self, cr3: u64, image_base: u64)`
- `pub fn module_for_addr(&self, addr: u64) -> Option<&str>`
- `pub fn image_base_for_cr3(&self, cr3: u64) -> Option<u64>`

### `struct PtFlow`
Flow di controllo ricostruito. Campi: `events`, `timing`, `addresses_visited`, `tnt_bits_consumed`, `tip_packets_consumed`.

Funzioni:
- `pub fn new() -> Self`
- `pub fn push_event(&mut self, event: PtEvent)`
- `pub const fn event_count(&self) -> usize`
- `pub fn unique_addresses(&self) -> usize`
- `pub fn calls(&self) -> Vec<&PtEvent>`
- `pub fn returns(&self) -> Vec<&PtEvent>`
- `pub fn overflows(&self) -> Vec<&PtEvent>`

### `struct PtTrace`
Traccia PT completa: `packets`, `flow`, `sideband`.

Funzioni:
- `pub fn new(packets: Vec<PtPacket>) -> Self`
- `pub const fn packet_count(&self) -> usize`
- `pub fn tsc_values(&self) -> Vec<u64>`
- `pub fn tip_addresses(&self) -> Vec<u64>`
- `pub fn tnt_bits(&self) -> Vec<(u64, u8)>`
- `pub fn extract_timing(&self) -> TimingInfo`
- `pub fn summary(&self) -> String`

### `struct PtFlowReconstructor`
Reconstruction engine che consuma `PtPacket`. Campi pubblici: `current_ip`, `tracing_enabled`, `flow`.

Funzioni:
- `pub fn new() -> Self`
- `pub fn feed_packet(&mut self, pkt: &PtPacket) -> bool`
- `pub fn pop_tnt(&mut self) -> Option<bool>`
- `pub fn pending_tnt_count(&self) -> usize`
- `pub fn record_conditional_branch(&mut self, ip, target, fallthrough)`
- `pub fn record_call(&mut self, from, to)`
- `pub fn record_return(&mut self, from, to)`

Implementa `Default`.

## Note

- `lib.rs` e di ~6300 righe; oltre alle API qui catalogate dichiara i 13 sotto-moduli pubblici elencati sopra, ciascuno con superficie API addizionale.
- Test inline (`#[cfg(test)] mod tests`) presenti in `lib.rs` (verificati: Display, decode, ecc.).
- Libreria testabile (build + `cargo test -p rustre-trace-pt`).
