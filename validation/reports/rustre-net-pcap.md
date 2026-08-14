# rustre-net-pcap

PCAP and PCAPNG file reading/writing, TCP reassembly, packet dissection, flow tracking, conversation extraction and a BPF filter VM.

## Cargo.toml

- **name**: `rustre-net-pcap`
- **edition/version/license**: workspace
- **dependencies**:
  - `rustre-net` (path = ../rustre-net)
  - `rustre-net-dissect` (path = ../rustre-net-dissect)
  - `thiserror`, `serde`, `tokio` (workspace)
- `#![forbid(unsafe_code)]`

## Public modules

- `pcap_analyzer`
- `pcap_filter_engine`
- `pcap_writer`
- `flow_tracker`
- `packet_dissector`
- `pcap_reader`
- `tcp_reassembly`
- `pcapng_reader`
- `packet_filter`
- `conversation_extractor`
- `bpf_ops` (BPF classic opcodes constants)

## Errors

`pub enum PcapError` (thiserror): `InvalidMagic(u32)`, `InvalidBlockType(u32)`, `UnsupportedVersion{major,minor}`, `BufferTooShort{needed,got}`, `BlockLengthMismatch`, `NoSectionHeader`, `Io(io::Error)`, `Utf8Error`, `UnsupportedLinkType(u16)`, `RecordTruncated`, `InterfaceNotFound(u32)`.

## Link-layer

`pub enum LinkType { Null, Ethernet, Ax25, Ieee8024, ArcnetBsd, Slip, Ppp, Fddi, PppHdlc, PppEther, AtmRfc1483, Raw, CSlip, Ieee80211, Frelay, Loop, LinuxSll, Ltalk, PfLog, Ieee80211Radio, ArcnetLinux, Ipv4, Ipv6, Unknown(u16) }`
- `const fn from_u16(v: u16) -> Self`
- `const fn as_u16(self) -> u16`
- Implements `Display` via `Debug`.

## PCAP core types

### `PcapGlobalHeader`
Fields: `magic: u32`, `version_major: u16`, `version_minor: u16`, `thiszone: i32`, `sigfigs: u32`, `snaplen: u32`, `linktype: LinkType`, `nanosecond_ts: bool`, `little_endian: bool`.

### `PcapRecord`
Fields: `ts_sec: u32`, `ts_usec: u32`, `orig_len: u32`, `data: Vec<u8>`.
- `const fn captured_len(&self) -> u32`
- Display impl

### `MemoryPcapReader`
Fields: `header: PcapGlobalHeader`, `records: Vec<PcapRecord>`.
- `pub fn from_bytes(data: &[u8]) -> Result<Self, PcapError>` — **I/O**: input bytes
- `pub fn iter(&self) -> impl Iterator<Item=&PcapRecord>`
- `const fn len(&self) -> usize`
- `const fn is_empty(&self) -> bool`

### `FilePcapReader` (async)
- `pub async fn open(path: impl AsRef<Path>) -> Result<Self, PcapError>` — **I/O**: reads file via tokio
- `const fn header(&self) -> &PcapGlobalHeader`
- `pub fn records(&self) -> &[PcapRecord]`

### `StreamPcapWriter<W: Write>`
- `pub fn new(writer: W, snaplen: u32, linktype: LinkType) -> io::Result<Self>` — emits LE global header
- `pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> io::Result<()>` — **I/O**: writes record
- `const fn record_count(&self) -> u64`
- `const fn linktype(&self) -> LinkType`
- `pub fn flush(&mut self) -> io::Result<()>`

### `PcapWriter` (spec-required in-memory)
- `const fn new(network: u32) -> Self`
- `pub fn add_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8])`
- `const fn network(&self) -> u32`
- `const fn is_empty(&self) -> bool`
- `pub fn finish(self) -> Vec<u8>`
- `pub fn to_bytes(&self) -> Vec<u8>`

### `PcapFile`
Fields: `header: PcapFileHeader`, `records: Vec<PcapFileRecord>`.
- `pub fn parse(bytes: &[u8]) -> Result<Self, PcapError>`
- `pub fn iter_records(&self) -> impl Iterator<Item=&PcapFileRecord>`
- `const fn record_count(&self) -> usize`
- `pub fn total_bytes(&self) -> usize`

### `PcapFileHeader`
Fields: `magic, version_major, version_minor, thiszone, sigfigs, snaplen, network: u32`.

### `PcapFileRecord`
Fields: `ts_sec, ts_usec, incl_len, orig_len: u32`, `data: Vec<u8>`.

### `PcapReader`
Fields: `records: Vec<PcapFileRecord>`, `global: PcapFileHeader`.
- `pub fn parse(bytes: &[u8]) -> Result<Self, PcapError>` — supports LE/BE + nanosecond magic
- `pub fn iter(&self) -> impl Iterator<Item=&PcapFileRecord>`

### `PcapFileWriter`
- `pub fn new(network: u32) -> Self`
- `pub fn add_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8])`
- `pub fn finish(self) -> Vec<u8>`
- `const fn network(&self) -> u32`

## PCAPNG types

### Blocks
- `SectionHeaderBlock { byte_order_magic, major_version, minor_version, section_length, options }`
- `InterfaceDescriptionBlock { link_type, snap_len, options }`
- `EnhancedPacketBlock { interface_id, timestamp_high, timestamp_low, captured_len, original_len, data, options }`
  - `pub fn timestamp(&self) -> u64`
- `SimplePacketBlock { original_len, data }`
- `NrbRecord { record_type, value }`
- `NameResolutionBlock { records, options }`
- `enum PcapNgBlock { SectionHeader, InterfaceDescription, EnhancedPacket, SimplePacket, NameResolution, Unknown { block_type, data } }`

### `PcapNgReader`
Field: `blocks: Vec<PcapNgBlock>`.
- `pub fn from_bytes(data: &[u8]) -> Result<Self, PcapError>`
- `pub fn enhanced_packets(&self) -> Vec<&EnhancedPacketBlock>`
- `pub fn interfaces(&self) -> Vec<&InterfaceDescriptionBlock>`
- `const fn len(&self) -> usize`, `const fn is_empty(&self) -> bool`

### `PcapNgWriter`
- `const fn new(link_type: LinkType) -> Self`
- `pub fn add_packet(&mut self, timestamp_us: u64, data: &[u8])`
- `const fn packet_count(&self) -> usize`
- `pub fn finish(self) -> Vec<u8>` — emits SHB + IDB + EPBs (LE)

## BPF VM (partial, in lib.rs)

- `pub struct BpfInsn { code: u16, jt: u8, jf: u8, k: u32 }`
  - `const fn new(code, jt, jf, k) -> Self`
- `pub mod bpf_ops` — constants: `LD_W_ABS, LD_H_ABS, LD_B_ABS, LD_IMM, ALU_AND_K, ALU_RSH_K, JMP_JEQ_K, JMP_JGT_K, JMP_JGE_K, JMP_JSET_K, RET_K, RET_A, LD_LEN, ...`

## Submodules (selected exports)

- **tcp_reassembly**: `TcpFlags`, `TcpState`, `StreamKey { new(src_ip,src_port,dst_ip,dst_port) }`, `TcpSegment`, plus reassembler.
- **pcap_reader / pcapng_reader / pcap_writer**: alternate entry points.
- **flow_tracker, packet_dissector, packet_filter, conversation_extractor, pcap_analyzer, pcap_filter_engine**: higher-level helpers (see source for full API).

## I/O summary

- **Pure in-memory**: `MemoryPcapReader::from_bytes`, `PcapReader::parse`, `PcapFile::parse`, `PcapNgReader::from_bytes`, `PcapWriter`, `PcapFileWriter`, `PcapNgWriter` — fully testable with synthetic buffers.
- **Disk I/O (async)**: `FilePcapReader::open` (tokio fs).
- **Streaming write**: `StreamPcapWriter<W: Write>` — testable with `Vec<u8>` as sink.

## Testability

Yes — all parsers and writers operate on byte slices or generic `Write` sinks; round-trip tests are straightforward (build PCAP/PCAPNG bytes with the writers, re-parse via the readers, assert equality).
