# Crate Analysis: GUI, Hex, Net, Patch, PE Group

**Scope:** 15 crates — rustre-gui, rustre-graph, rustre-hex, rustre-hex-view,
rustre-hex-pattern, rustre-hex-template, rustre-net, rustre-net-dissect,
rustre-net-pcap, rustre-net-proxy, rustre-net-rules, rustre-patch,
rustre-pe-editor, rustre-pe-rebuild, rustre-pe-tools.

**Date:** 2026-07-01  
**Workspace root:** `C:/Users/Fra/Desktop/RustRE`

---

## Table of Contents

1. [rustre-gui](#1-rustre-gui)
2. [rustre-graph](#2-rustre-graph)
3. [rustre-hex](#3-rustre-hex)
4. [rustre-hex-view](#4-rustre-hex-view)
5. [rustre-hex-pattern](#5-rustre-hex-pattern)
6. [rustre-hex-template](#6-rustre-hex-template)
7. [rustre-net](#7-rustre-net)
8. [rustre-net-dissect](#8-rustre-net-dissect)
9. [rustre-net-pcap](#9-rustre-net-pcap)
10. [rustre-net-proxy](#10-rustre-net-proxy)
11. [rustre-net-rules](#11-rustre-net-rules)
12. [rustre-patch](#12-rustre-patch)
13. [rustre-pe-editor](#13-rustre-pe-editor)
14. [rustre-pe-rebuild](#14-rustre-pe-rebuild)
15. [rustre-pe-tools](#15-rustre-pe-tools)
16. [Cross-cutting dependency map](#16-cross-cutting-dependency-map)
17. [Pipeline integration summary](#17-pipeline-integration-summary)
18. [Gap / TODO summary](#18-gap--todo-summary)

---

## 1. rustre-gui

### Purpose
The top-level application binary (package name: `zyphora`). Owns the GPUI
window, application state, and all UI panels. Every other workspace crate is
consumed here through intra-workspace path dependencies. Corresponds to the
"Zyphora Reversing" workstation product.

### Architecture

```
main.rs
├── core/app_state.rs         — AppState (global singleton)
├── db/                       — SQLite session persistence
├── analysis/                 — analysis pass wrappers (binary load pipeline)
├── formats/                  — format-specific loaders surfaced in the UI
├── debugger/                 — debugger bridge (wraps rustre-debug)
├── ui/
│   ├── app.rs — IDAApp (root GPUI component)
│   └── panels/
│       ├── mcp_panel.rs      — MCP chat panel (rustre-mcp-tools)
│       ├── ai_panel.rs       — AI annotations panel (rustre-agent-llm)
│       ├── flirt_panel.rs    — FLIRT sig DB panel (rustre-flirt-*)
│       ├── network_panel.rs  — captures panel (rustre-net, rustre-net-dissect, rustre-net-pcap)
│       ├── memory_search     — memory search panel (rustre-debug)
│       └── ...many more
└── ensure_used.rs            — dead-code anchor (keeps all backend symbols live)
```

### Key entry points

| Symbol | Description |
|--------|-------------|
| `fn main()` | GPUI app init, panic hook, DirectComposition workaround, `--open` CLI flag |
| `IDAApp::new(app_state, cx)` | Root GPUI component, opens 1280×780 window |
| `IDAApp::new_with_autoload(…, path)` | Same but schedules `UICommand::AnalyzeFile` on first frame |
| `fn parse_open_flag(args)` | Parses `--open=<path>` / `--open <path>` from argv |

### Dependencies

| Dependency | Role |
|-----------|------|
| `gpui`, `gpui_platform` | Zed's GPU-accelerated UI framework (git dep) |
| `rustre-core` | `Address`, `FileOffset`, `ViewId` primitives |
| `rustre-graph` | Knowledge graph (SQLite/MySQL) |
| `rustre-il-mlil` | IL/MLIL switching in decompiler tab |
| `rustre-decompiler[-c/-cfs/-type]` | Decompiler lift pipeline |
| `rustre-analysis-fn` | Function detection backend |
| `rustre-yara[-engine/-rules]` | YARA panel backend |
| `rustre-flirt[-apply/-gen]` | FLIRT panel backend |
| `rustre-symbols-{pdb,dwarf,codeview}` | Symbol resolution |
| `rustre-triage[-entropy/-peid/-die]` | Triage/entropy overview |
| `rustre-net`, `rustre-net-dissect`, `rustre-net-pcap` | Network panel |
| `rustre-debug` | Memory search / debugger |
| `rustre-loader-pe`, `rustre-demangle` | PE loader + demangling |
| `rustre-mcp-tools`, `rustre-agent-llm` | MCP chat + AI panel |
| `reqwest`, `tokio` | HTTP downloads (symbol server) |
| `sha1`, `sha2`, `md-5` | Hash computation for overview panel |
| `capstone`, `object` | Disassembly + binary format parsing |

### Implementation status: **Partial / Integration**

The entry point and window setup are complete. Individual panels are wired to
backend crates but their rendering depth varies — some panels are complete
feature-for-feature while others (`network_panel`, `mcp_panel`) were wired
last. The `ensure_used::touch_all()` function keeps all intra-workspace symbols
live to prevent dead-code elimination during cross-crate LTO.

### Known gaps
- No tests in the binary crate (GPUI apps cannot easily unit-test panels).
- `--open` flag parses the path but does not validate it before enqueuing.
- `GPUI_DISABLE_DIRECT_COMPOSITION` workaround is a runtime env-var hack; needs
  a proper GPUI flags API when that stabilises.

---

## 2. rustre-graph

### Purpose
Persistent knowledge graph for a binary analysis session. Stores functions,
symbols, basic blocks, CFG edges, xrefs, comments, patches, strings, bookmarks,
events, sections, imports, and exports in a relational database. Supports both
SQLite (file or in-memory) and MySQL backends through a `DatabaseEngine` trait.

### Architecture

```
lib.rs          — KnowledgeGraph, row types, schema init, CRUD
db.rs           — DatabaseEngine trait, SqliteEngine, MysqlEngine, GraphParam/Value
analysis_graph.rs      — In-memory petgraph representation, FunctionNode/CallEdge
graph_algorithms_extended.rs — DFS, BFS, dominator tree, SCCs, shortest paths
graph_export.rs        — DOT, JSON, GraphML, GEXF, Cytoscape, Neo4j Cypher, CSV
graph_persistence.rs   — Serialise/deserialise petgraph to/from DB
query_engine.rs        — Structured query DSL over the knowledge graph
collaboration.rs       — Multi-session event broadcast (tokio broadcast channel)
```

### Key public API

```rust
pub struct KnowledgeGraph { conn: Arc<dyn DatabaseEngine> }

impl KnowledgeGraph {
    pub fn new_in_memory() -> Result<Self, GraphError>
    pub fn new_file(path: &Path) -> Result<Self, GraphError>
    pub fn new_mysql(url: &str) -> Result<Self, GraphError>

    // Views
    pub fn add_view(id, uri, arch, endian, bits) -> Result<(), GraphError>
    pub fn get_view_info(id) -> Result<Option<ViewRow>, GraphError>

    // Functions
    pub fn add_function(view_id, address, end_address, meta: FunctionMeta) -> Result<i64, GraphError>
    pub fn get_function_at(view_id, address) -> Result<Option<FunctionRow>, GraphError>
    pub fn get_functions_in_range(view_id, start, end) -> Result<Vec<FunctionRow>, GraphError>
    pub fn rename_function(view_id, address, name) -> Result<(), GraphError>
    pub fn set_function_prototype(view_id, address, prototype) -> Result<(), GraphError>
    pub fn count_functions(view_id) -> Result<i64, GraphError>

    // Symbols, Xrefs, Comments, Patches, Strings, Bookmarks,
    // BasicBlocks, CFGEdges, Annotations, Sections, Imports, Exports …
    // (each follows the same add/get/delete/count pattern)

    pub fn query_sql(sql: &str) -> Result<Vec<HashMap<String, GraphValue>>, GraphError>
    // Only SELECT/WITH allowed; comments rejected for safety

    pub fn begin_transaction / commit_transaction / rollback_transaction
}
```

### DB schema (15 tables)

`views`, `functions`, `basic_blocks`, `cfg_edges`, `symbols`, `xrefs`,
`types`, `comments`, `patches`, `events`, `strings`, `bookmarks`,
`annotations`, `sections`, `imports`, `exports`

All address columns store `u64` as signed `i64` (two's-complement round-trip).

### Dependencies

| Dep | Role |
|-----|------|
| `rustre-core` | `Address`, `ViewId` |
| `rusqlite` | SQLite backend |
| `mysql` | MySQL backend |
| `petgraph` | In-memory graph algorithms (`analysis_graph`) |
| `tokio` | Async broadcast in `collaboration` |

### Implementation status: **Complete**

All CRUD operations are implemented and tested. The schema is stable. The
`query_engine` and `collaboration` modules have full implementations; the
petgraph-based `analysis_graph` is also complete. Export formats (DOT, GraphML,
GEXF, Cytoscape, Neo4j, CSV) are implemented in `graph_export.rs`.

### Known gaps
- No migration system: schema changes require manual DROP/recreate.
- MySQL index creation silently swallows duplicate-key errors — could hide
  schema drift.
- `query_sql` rejects comments with `--` or `/*` but does not handle PostgreSQL
  `$…$` quoting or MSSQL syntax if backends are ever extended.

---

## 3. rustre-hex

### Purpose
Core hex editor data model. Provides `HexBuffer` — a mutable byte buffer with
full undo/redo, multi-cursor editing, typed reads (all primitive LE/BE types,
CStr, UTF-16), block operations (fill, reverse, shift, rotate), bitwise
transforms (XOR/AND/OR/NOT/add/negate), KMP and regex search, hex-pattern
search with `?`/`??` wildcards, find-replace, byte statistics, Shannon entropy,
256-bucket histograms, bookmarks, and structured data annotations.

### Key public types

```rust
pub struct HexBuffer {
    pub data: Vec<u8>,
    pub cursor: usize,
    pub selection: Option<Range<usize>>,
    pub undo_stack: Vec<Edit>,
    pub redo_stack: Vec<Edit>,
    pub multi_cursor: MultiCursorState,
    pub bookmarks: Vec<Bookmark>,
    pub annotations: Vec<DataAnnotation>,
    pub base_address: u64,
}

pub enum Edit { Insert{..}, Delete{..}, Replace{..} }
pub enum DataType { U8, U16Le, U16Be, …, F64Be, Bytes(usize), CStr, Utf16(usize) }
pub enum TypedValue { U8(u8), U16(u16), …, F64(f64), Bytes(Vec<u8>), Str(String) }
pub struct ByteStatistics { total, min, max, mean, median, std_dev, entropy, unique_count, mode, mode_count }
pub struct Histogram { counts: [u64; 256], total: u64 }
pub struct MultiCursorState { cursors: Vec<Cursor> }

pub enum SearchMode { Exact, Regex, HexPattern }
pub struct FindReplaceOptions { mode, wrap, limit: Option<Range<usize>> }
pub struct FindResult { offset: usize, len: usize }

pub struct HexDiff;
impl HexDiff {
    pub fn compare(left, right) -> Vec<DiffRegion>
    pub fn compare_slices(left: &[u8], right: &[u8]) -> Vec<DiffRegion>
    pub fn apply_patch(left: &mut HexBuffer, region: &DiffRegion) -> Result<…>
}
```

### Sub-modules

| Module | Content |
|--------|---------|
| `hex_editor_core` | Extended editing operations beyond the struct methods |
| `hex_search_engine` | KMP implementation, regex NFA |
| `hex_analysis` | Entropy analysis, byte statistics helpers |
| `hex_diff` | Diff algorithms (LCS, Myers) |
| `hex_bookmark_manager` | Bookmark CRUD, serialization |
| `hex_patch_manager` | Patch record tracking |
| `hex_undo_manager` | Compound undo groups |
| `hex_undo` | Low-level undo stack |
| `hex_disassembler` | Inline disassembly overlay |
| `hex_selection` | Selection state machine |
| `hex_goto_dialog` | Address/offset parsing for goto |

### Implementation status: **Complete**

All methods in `HexBuffer` are fully implemented with inline tests. The module
has 100+ unit tests covering every operation. `kmp_search` and `regex_search`
are public (re-exported by `hex_search_engine`) and used by sibling crates.

### Dependencies
`rustre-core` (for `FileOffset`), `thiserror`, `serde`, `serde_json`.

---

## 4. rustre-hex-view

### Purpose
Rendering layer for the hex editor. Provides a trait-based renderer
architecture (`HexViewRenderer`) with `PlainHexRenderer` (plain text) and
`AnsiHexRenderer` (ANSI 24-bit colour). Manages `HexViewState` — full
interactive state combining `HexBuffer`, viewport navigation, annotation layers,
diff highlighting, entropy visualisation, and structure overlays.

### Key public types

```rust
pub trait HexViewRenderer {
    fn render_line(&self, offset, bytes, annotations) -> RenderedLine;
    fn render_all(&self, data, base_offset, config, annotations) -> Vec<RenderedLine>;
}

pub struct HexViewConfig {
    pub bytes_per_row: usize, pub group_size: usize,
    pub show_offset: bool, pub offset_base: OffsetBase,
    pub show_ascii: bool, pub show_diff: bool,
    pub show_entropy_bar: bool, pub show_structure_overlay: bool,
    pub color_scheme: ColorScheme, pub visible_rows: usize,
    pub uppercase_hex: bool, …
}

pub struct HexViewState {
    pub buffer: HexBuffer,
    pub config: HexViewConfig,
    pub annotations: AnnotationLayer,
    pub bookmarks: Vec<Bookmark>,
    pub viewport: ViewportState,
    pub diff_buffer: Option<HexBuffer>,
    pub diff_highlights: DiffHighlightMap,
    pub structure_overlay: StructureOverlayView,
}

pub struct AnnotationLayer { annotations: Vec<Annotation>, floating: Vec<FloatingAnnotation> }
pub struct StructureOverlayView { fields: Vec<StructFieldOverlay> }
pub struct DiffHighlightMap { map: HashMap<usize, DiffStatus> }
pub enum ColorScheme { Dark, Light, Monokai, Nord, Solarized, HighContrast, Custom(ColorMap) }
```

### Navigation API (HexViewState)

`go_to_offset`, `scroll_to`, `cursor_move_{left,right,up,down}`, `page_up`,
`page_down`, `go_to_start`, `go_to_end`, `begin_selection`, `extend_selection`,
`clear_selection`, `set_diff_buffer`, `clear_diff`, `row_entropy`,
`render_visible_ansi`, `render_visible_plain`, `selected_bytes`.

### Sub-modules

| Module | Content |
|--------|---------|
| `hex_formatter` | Column width calculation, address formatting |
| `hex_renderer` | Core renderer helpers |
| `highlight_engine` | Selection / search highlight engine |
| `column_renderer` | Per-column rendering (hex, ASCII, offset) |
| `virtual_scroll` | Large-buffer virtualised scrolling |
| `diff_mode` / `diff_view` | Two-pane diff layout |
| `comparison_view` | Side-by-side comparison |
| `data_inspector` | Type panel showing typed value under cursor |
| `hex_search` / `search_engine` / `search_bar` | Interactive search UI state |
| `transform_ops` | UI-level transform menu |
| `hex_exporter` | Export to text/hex/C array |
| `annotation_layer` | Annotation CRUD UI layer |

### Implementation status: **Complete**

Both renderers are fully implemented with a 200+ test suite covering colour
blending, diff highlighting, offset formatting, viewport navigation, and
annotation queries. The `format_hex_dump` and `format_hex_dump_ansi` free
functions are stable public API used by the GUI's hex panel.

### Dependencies
`rustre-hex` (data model), `thiserror`, `serde`, `serde_json`.

---

## 5. rustre-hex-pattern

### Purpose
IDA/HxD-style binary pattern matching engine. Supports full wildcards (`??`,
`?`), nibble wildcards (`A?`, `?B`), bitmask patterns (`MaskedPattern`),
alternation (`pat1 | pat2`), named capture groups, FLIRT-style function
signatures (CRC-16/IBM validated), pattern compilation (`CompiledPattern`) with
first-exact-byte anchor acceleration, pattern groups, and a persistent
`PatternDatabase` (SQLite + MySQL).

### Key public types

```rust
pub enum PatternByte { Exact(u8), Wildcard, Nibble { high: Option<u8>, low: Option<u8> } }

pub struct Pattern {
    pub bytes: Vec<PatternByte>,
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub captures: Vec<NamedCapture>,
    pub comment: String,
}
impl Pattern {
    pub fn parse(s: &str) -> Result<Self, PatternError>
    pub fn matches(&self, data: &[u8], offset: usize) -> bool
    pub fn search(&self, data: &[u8]) -> Vec<usize>
    pub fn search_with_captures(&self, data: &[u8]) -> Vec<(usize, Vec<CaptureResult>)>
    pub fn to_bytes(&self) -> Option<Vec<u8>>
    pub fn to_simd_form(&self) -> (Vec<u8>, Vec<u8>)   // (values, masks)
    pub fn to_hex_string(&self) -> String
    pub fn specificity(&self) -> f64
}

pub struct CompiledPattern { bytes, values, masks, first_exact, len, name }
impl CompiledPattern {
    pub fn compile(pat: &Pattern) -> Self
    pub fn matches(&self, data: &[u8], offset: usize) -> bool
    pub fn search(&self, data: &[u8]) -> Vec<usize>
}

pub struct AlternationPattern { alternatives: Vec<Pattern>, name: Option<String> }
pub struct MaskedPattern { bytes: Vec<u8>, mask: Vec<u8>, name: Option<String> }
pub struct SignaturePattern { name, prologue: Pattern, crc16, crc_len, func_len, module_name }
pub struct PatternGroup { name, patterns: Vec<Pattern> }
pub struct CompiledPatternGroup { name, patterns: Vec<CompiledPattern> }

pub struct PatternDatabase { conn: Mutex<rusqlite::Connection> }  // SQLite
pub struct MySqlPatternStore { pool: mysql::Pool, cache: RwLock<HashMap<…>> }

pub fn crc16_ibm(data: &[u8]) -> u16
```

### Implementation status: **Complete**

Pattern parsing, matching, search with anchor acceleration, FLIRT CRC
validation, named captures, alternation, group search, compilation, and both
database backends are fully implemented. Sub-modules (`pattern_optimizer`,
`multi_pattern_scanner`, `pattern_debugger`, `wildcard_pattern_compiler`,
`pattern_diff`, `pattern_search_engine`, `pattern_evaluator`, `pattern_stdlib`,
`pattern_import`, `pattern_exporter`) extend the core with optimisation passes,
parallel scanning with `rayon`, and I/O in multiple formats (JSON, IDA `.pat`).

### Dependencies
`rustre-core`, `rustre-hex` (re-uses `kmp_search`), `rusqlite`, `mysql`,
`rayon`, `serde`, `serde-big-array`, `parking_lot`.

---

## 6. rustre-hex-template

### Purpose
010 Editor–style binary templates applied to a `HexBuffer`. Produces a typed
`ParsedStruct` tree. Comes with built-in templates for PE/COFF, ELF32/64, ZIP,
PNG, BMP, JPEG, GIF, PDF, and MZ/DOS. Supports conditional fields, repeated
fields, nested templates, and expression evaluation.

### Key public types

```rust
pub enum Expr { Eq(String, u64), Ne(…), Gt(…), Lt(…), And(Box<Expr>, Box<Expr>), Or(…) }

pub enum FieldSpec {
    Typed { name, data_type: DataType, condition: Option<Expr> }
    Repeated { name, item_type: DataType, count_field: String }
    Nested { name, template_name: String, condition: Option<Expr> }
}

pub struct Template { pub name: String, pub fields: Vec<FieldSpec> }

pub enum ParsedValue { Typed(TypedValue), Array(Vec<TypedValue>), Nested(ParsedStruct) }
pub struct ParsedField { pub name, pub offset, pub size, pub value: ParsedValue }
pub struct ParsedStruct { pub template_name, pub fields: Vec<ParsedField> }

pub struct TemplateEngine { templates: HashMap<String, Template> }
impl TemplateEngine {
    pub fn register(&mut self, template: Template)
    pub fn apply(&self, name: &str, buf: &HexBuffer, offset: usize) -> Result<ParsedStruct, TemplateError>
    pub fn apply_auto(&self, buf: &HexBuffer) -> Result<ParsedStruct, TemplateError>
}
```

### Sub-modules

| Module | Content |
|--------|---------|
| `builtin_templates` | PE, ELF, ZIP, PNG, BMP, JPEG, GIF, PDF, MZ/DOS templates |
| `template_library` | User-facing template registry |
| `template_auto_detect` | Magic-byte heuristics → template selection |
| `template_compiler` | Source-text → `Template` compiler |
| `template_interpreter` | Step-by-step interpreter (debug mode) |
| `template_expression_eval` | Expression evaluator for conditions/counts |
| `template_type_system` | Extended type system (arrays, bitfields, enums) |
| `template_composition` | Template inheritance / include |
| `struct_extractor` | Extract fields from `ParsedStruct` by path |
| `template_stdlib` | Standard library of reusable field types |

### Implementation status: **Complete**

The template engine, expression evaluator, all built-in templates, auto-detect,
and sub-modules are implemented. The `ParsedStruct` tree is used by
`rustre-hex-view`'s structure overlay.

### Dependencies
`rustre-hex` (data model, `DataType`, `TypedValue`), `serde`, `serde-big-array`,
`thiserror`.

---

## 7. rustre-net

### Purpose
Network capture and traffic analysis core. Provides zero-copy protocol parsers
for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP/1.1, ARP. Implements TCP
reassembly, flow tracking, protocol fingerprinting, packet building/decoding,
and C2 traffic detection heuristics.

### Key public types

```rust
pub enum NetError { BufferTooShort, InvalidEthernetFrame, InvalidIpv4Packet, … }

bitflags! { pub struct TcpFlags: u8 { const FIN; SYN; RST; PSH; ACK; URG; ECE; CWR; } }

// Parsed packet types (each produced by a parse_* function):
pub struct EthernetFrame { src_mac, dst_mac, ethertype, payload: &[u8] }
pub struct Ipv4Packet { src, dst: Ipv4Addr, protocol, ttl, payload: &[u8], … }
pub struct Ipv6Packet { src, dst: Ipv6Addr, next_header, payload: &[u8], … }
pub struct TcpSegment { src_port, dst_port, seq, ack, flags: TcpFlags, payload: &[u8], … }
pub struct UdpDatagram { src_port, dst_port, payload: &[u8] }
pub struct IcmpPacket { icmp_type, code, payload: &[u8] }
pub struct DnsPacket { id, flags, questions, answers, … }
pub struct HttpRequest { method, path, version, headers, body: &[u8] }
pub struct HttpResponse { status, reason, headers, body: &[u8] }

// Async capture trait:
#[async_trait]
pub trait PacketSource { async fn next_packet(&mut self) -> Result<Option<RawPacket>, NetError>; }

// Flow tracking:
pub struct FlowKey { src_ip, dst_ip, src_port, dst_port, protocol }
pub struct Flow { key: FlowKey, packets: Vec<RawPacket>, state: FlowState, … }
pub struct FlowTracker { flows: RwLock<HashMap<FlowKey, Flow>>, … }

// TCP reassembly:
pub struct TcpReassembler { streams: HashMap<FlowKey, TcpStream>, … }
```

### Sub-modules

| Module | Content |
|--------|---------|
| `protocol_dissector` | Protocol dispatch tree |
| `protocol_fingerprint` | OS/service fingerprinting |
| `packet_builder` | Craft raw packets for replay |
| `packet_decoder` | Decode raw bytes → typed packets |
| `traffic_reassembler` | Multi-protocol reassembly |
| `tcp_reassembler` | RFC-793 TCP stream reassembly |
| `flow_tracker` | Bidirectional flow table |
| `c2_detector` | Heuristic C2 traffic detection |
| `network_analyzer` | High-level analysis façade |
| `registry` | Protocol handler registry |

### Implementation status: **Complete**

All protocol parsers, the flow tracker, TCP reassembler, and C2 detector are
implemented. The `#[forbid(unsafe_code)]` attribute is set. The crate has no
external OS-level PCAP dependency; it consumes raw bytes and is platform-neutral.

### Dependencies
`thiserror`, `serde`, `serde_json`, `async-trait`, `parking_lot`, `bitflags`.

---

## 8. rustre-net-dissect

### Purpose
Deep packet dissection and protocol recognition layer above `rustre-net`.
Implements a trait-based dissector registry, a layer tree (`DissectedPacket`),
and built-in dissectors for: HTTP/1.1, HTTP/2, DNS, SMTP, FTP, SSH, MQTT,
AMQP, TLS, industrial protocols (Modbus, DNP3, IEC 104, BACnet, EtherNet/IP),
and known C2 protocol signatures.

### Key public types

```rust
pub enum FieldValue { Bytes(Vec<u8>), Str(String), U8(u8), U16(u16), U32(u32), U64(u64), Bool(bool), Ipv4(…), Ipv6(…) }

pub struct ProtocolField { pub name: String, pub value: FieldValue }

pub struct DissectedLayer {
    pub protocol: String,
    pub fields: Vec<ProtocolField>,
    pub payload_offset: usize,
}

pub struct DissectedPacket { pub layers: Vec<DissectedLayer> }

pub trait Dissector: Send + Sync {
    fn protocol(&self) -> &str;
    fn dissect(&self, data: &[u8], context: &DissectContext) -> Result<DissectedLayer, DissectError>;
    fn can_dissect(&self, data: &[u8], context: &DissectContext) -> bool;
}

pub struct DissectorRegistry { dissectors: RwLock<HashMap<String, Arc<dyn Dissector>>> }
impl DissectorRegistry {
    pub fn register(&self, dissector: Arc<dyn Dissector>)
    pub fn dissect_packet(&self, data: &[u8]) -> Result<DissectedPacket, DissectError>
}
```

### Sub-modules

| Module | Content |
|--------|---------|
| `application_protocols` | HTTP/1.1, HTTP/2, DNS, SMTP, FTP, SSH, MQTT, AMQP |
| `tls_dissector` | TLS record parsing, handshake inspection |
| `dns_dissector` | RFC-1035 DNS |
| `http2_dissector` | HTTP/2 frame parser |
| `stream_reassembler` | TCP stream PDU extraction |
| `protocol_stats` | Per-protocol counters, conversation matrix, bandwidth |
| `dissectors_c2` | Known C2 protocol signatures (Cobalt Strike, Metasploit…) |
| `dissectors_industrial` | Modbus, DNP3, IEC 104, BACnet, EtherNet/IP |
| `dissectors_application` | Generic application layer dispatch |

### Implementation status: **Complete**

The registry, all built-in dissectors, stream reassembler, and protocol stats
are implemented. `#[forbid(unsafe_code)]`. The layer-tree model cleanly
separates parsing from display.

### Dependencies
`rustre-net` (parsers), `anyhow`, `thiserror`, `serde`, `parking_lot`,
`md-5`, `bitflags`.

---

## 9. rustre-net-pcap

### Purpose
PCAP and PCAPNG file reading and writing. Supports both endiannesses of legacy
PCAP (magic `0xa1b2c3d4` / `0xd4c3b2a1`) and PCAPNG block types (SHB, IDB,
EPB, SPB, NRB). Provides async file-based reading (Tokio), BPF-style packet
filtering, TCP conversation extraction, and a structured PCAP analyzer.

### Key public types

```rust
pub struct PcapHeader { magic, major, minor, snaplen, link_type }
pub struct PcapRecord { ts_sec, ts_usec, orig_len, data: Vec<u8> }
pub struct PcapNgBlock { block_type, body: Vec<u8> }

pub struct PcapReader { /* sync */ }
pub struct AsyncPcapReader { /* tokio */ }
pub struct PcapngReader { /* sync PCAPNG */ }
pub struct PcapWriter { /* write PCAP */ }

pub struct PacketFilter { bpf_like expression }
pub struct PcapFilterEngine { filters: Vec<PacketFilter> }
pub struct FlowTracker { … }
pub struct TcpReassembly { … }
pub struct ConversationExtractor { … }
pub struct PcapAnalyzer { … }
pub struct PacketDissector { … }
```

### Implementation status: **Complete**

Both PCAP and PCAPNG readers, the writer, filter engine, flow tracker, TCP
reassembly, and conversation extractor are implemented. `#[forbid(unsafe_code)]`.

### Dependencies
`rustre-net`, `rustre-net-dissect`, `thiserror`, `serde`, `tokio`.

---

## 10. rustre-net-proxy

### Purpose
Transparent network proxy and MITM engine for traffic interception during
dynamic analysis. Supports HTTP CONNECT, SOCKS4, SOCKS5, raw TCP forwarding,
intercept hooks for request/response modification, TLS interception with on-the-
fly certificate generation (`rcgen`), WebSocket dissection, HAR/PCAP traffic
logging, upstream chaining, and connection pooling.

### Key public types

```rust
pub enum ProxyMode { Transparent, HttpConnect, Socks4, Socks5, Raw }
pub enum InterceptAction { Forward, Drop, Modify(Vec<u8>), Redirect(SocketAddr) }

#[async_trait]
pub trait InterceptHook: Send + Sync {
    async fn on_request(&self, req: &[u8], ctx: &ProxyContext) -> InterceptAction;
    async fn on_response(&self, resp: &[u8], ctx: &ProxyContext) -> InterceptAction;
}

pub struct ProxyServer {
    addr: SocketAddr,
    mode: ProxyMode,
    hook: Option<Arc<dyn InterceptHook>>,
    …
}
impl ProxyServer {
    pub async fn run(&self) -> Result<(), ProxyError>
}

pub struct TlsProxy { /* rcgen + rustls + tokio-rustls */ }
pub struct HttpInterceptor { rules: Vec<InterceptRule> }

// Upstream selection:
pub struct UpstreamProxy { … }
pub struct UpstreamChain { proxies: Vec<UpstreamProxy> }
pub struct ConnectionPool { … }

// WebSocket:
pub struct WebSocketFrame { opcode: WsOpcode, payload: Vec<u8>, … }
pub enum WsOpcode { Continuation, Text, Binary, Close, Ping, Pong }
pub fn detect_websocket_upgrade(headers: &[u8]) -> bool
pub fn parse_websocket_stream(data: &[u8]) -> Vec<WebSocketFrame>
pub fn reassemble_ws_messages(frames: &[WebSocketFrame]) -> Vec<Vec<u8>>
```

### Sub-modules

| Module | Content |
|--------|---------|
| `mitm_engine` | Core proxy accept loop |
| `tls_proxy` | TLS interception, SNI extraction, cert generation |
| `http_interceptor` | Rule-based HTTP transform |
| `traffic_logger` | Structured log with PCAP/HAR export |
| `upstream` | Upstream chain, connection pool |
| `websocket` | WS frame parsing / reassembly |

### Implementation status: **Complete**

The proxy server, TLS interception, HTTP interceptor, upstream chaining, and
WebSocket support are implemented. `#[forbid(unsafe_code)]`. Uses `rcgen` for
on-the-fly certificate generation, `rustls` + `tokio-rustls` for TLS.

### Dependencies
`rustre-net`, `tokio`, `async-trait`, `rcgen`, `rustls`, `rustls-pemfile`,
`tokio-rustls`, `parking_lot`, `serde`.

---

## 11. rustre-net-rules

### Purpose
Network traffic rule engine modelled on Snort/Suricata rule syntax. Parses
Snort-style rules into a structured `Rule` type, evaluates rules against
packets in the engine, correlates alerts, and persists the rule store to both
SQLite and MySQL.

### Key public types

```rust
pub enum RuleAction { Alert, Log, Pass, Drop, Reject }
pub enum RuleProto { Tcp, Udp, Icmp, Ip }

pub struct RuleOption { keyword: String, value: Option<String> }
pub struct Rule {
    pub id: u32,
    pub action: RuleAction,
    pub proto: RuleProto,
    pub src_net: String, pub src_port: String,
    pub dst_net: String, pub dst_port: String,
    pub options: Vec<RuleOption>,
    pub enabled: bool,
    pub msg: Option<String>,
    pub sid: Option<u32>,
    pub rev: Option<u32>,
}

pub fn parse_snort_rule(s: &str) -> Result<Rule, RuleError>

pub struct RuleEngine { rules: RwLock<Vec<Rule>> }
impl RuleEngine {
    pub fn add_rule(&self, rule: Rule)
    pub fn evaluate(&self, packet: &[u8]) -> Vec<RuleAlert>
}

pub struct RuleAlert { rule_id, sid, msg, timestamp }
pub struct AlertCorrelator { window_secs, min_count }

// Persistent rule stores:
pub struct SqliteRuleStore { conn: SqliteConnection }
pub struct MySqlRuleStore { pool: mysql::Pool }

// Suricata:
pub fn parse_suricata_rule(s: &str) -> Result<Rule, RuleError>
pub fn load_suricata_rules(text: &str) -> Vec<Rule>

// Protocol fingerprinting:
pub struct ProtocolFingerprinter { … }
pub struct TrafficClassifier { … }
pub struct SignatureMatcher { … }
pub struct PacketMatcher { … }
pub struct SnortExtended { … }
```

### Implementation status: **Complete**

Snort and Suricata rule parsers, the rule engine, alert correlator, traffic
classifier, protocol fingerprinter, signature matcher, and both database
backends are implemented. `#[forbid(unsafe_code)]`.

### Dependencies
`rustre-net`, `regex`, `rusqlite`, `mysql`, `parking_lot`, `serde`.

---

## 12. rustre-patch

### Purpose
Binary patching layer: validate, apply, and roll back patches to binary files
and in-memory byte buffers. Supports PE security flag editing, NOP patching,
assembly-based patches (via a simple built-in assembler), VA-relative patches,
XOR region patching, code cave scanning, hot-patching of live processes, and
binary delta / diff format.

### Key public types

```rust
pub struct Patch {
    pub id: String,
    pub description: String,
    pub offset: u64,
    pub original_bytes: Vec<u8>,
    pub patch_bytes: Vec<u8>,
    pub applied: bool,
}

pub struct PatchSet { id, name, patches: Vec<Patch>, target_version: Option<String> }

// Sub-module exports (all re-exported at crate root):
pub use binary_patcher::{
    BinaryPatcher, PatchOp, PatchOptions, PatchResult, apply_patches,
    ValidateBefore, FailFast, MarkApplied, SortByOffset, ForceApply,
    VaPatchError, VaPatchOutcome, PeSectionMap,
    parse_hex_bytes, pe_va_to_file_offset, assemble_simple,
    patch_bytes_at_va, patch_nop_range_at_va, patch_xor_region_at_va, patch_asm_at_va,
};
pub use patch_validator::{PatchValidator, ValidationError, validate_patch};
pub use patch_rollback::{PatchRollback, RollbackEntry, RollbackResult, create_rollback};
pub use code_cave::{CaveError, CodeCave, CodeCaveScanner, find_code_caves, find_code_caves_from_path};
pub use pe_security::{
    PeFlags, PeSecuritySummary, SecurityError, pe_security_summary,
    pe_security_summary_from_path, pe_security_set_from_path, compute_pe_checksum,
};
pub use hot_patch::{HotPatchError, HotPatcher, InMemoryWriter, LivePatch, RuntimeMemoryWriter};
pub use binary_diff::{BinaryDelta, DiffError, DiffOp, DiffOptions, build_delta, diff, patch};
```

### BinaryPatcher API (from re-exports)

```rust
pub struct BinaryPatcher { patches: Vec<Patch>, options: PatchOptions }
impl BinaryPatcher {
    pub fn add(&mut self, patch: Patch)
    pub fn apply(&mut self, data: &mut Vec<u8>) -> PatchResult
    pub fn rollback(&mut self, data: &mut Vec<u8>) -> PatchResult
}

// VA-based helpers:
pub fn pe_va_to_file_offset(pe_map: &PeSectionMap, va: u64) -> Option<u64>
pub fn patch_bytes_at_va(data: &mut Vec<u8>, pe_map: &PeSectionMap, va: u64, bytes: &[u8]) -> Result<VaPatchOutcome, VaPatchError>
pub fn patch_nop_range_at_va(…) -> Result<VaPatchOutcome, VaPatchError>
pub fn patch_xor_region_at_va(…, key: &[u8]) -> Result<VaPatchOutcome, VaPatchError>
pub fn patch_asm_at_va(…, asm: &str) -> Result<VaPatchOutcome, VaPatchError>
```

### Implementation status: **Complete**

All sub-modules are implemented. The `pe_security` module can read and toggle
PE DLL characteristics (ASLR, DEP/NX, CFG, SafeSEH, etc.) and recompute the PE
checksum. The `code_cave` scanner finds runs of NOP/CC bytes between sections.
The `hot_patch` module provides both in-memory and (on Windows) live process
patching via `RuntimeMemoryWriter`. The `binary_diff` module provides a delta
format compatible with simple patch distribution.

### Dependencies
`thiserror`, `serde`, `parking_lot`, `sha2` (patch integrity check).

---

## 13. rustre-pe-editor

### Purpose
PE binary editing layer built on top of `rustre-pe-tools`. Enables in-place
modification of sections (add/remove/resize/rename/encrypt), imports
(add/remove DLL imports), exports, resources, the PE header, certificates
(Authenticode table), and the debug directory. Also provides a "PE surgeon"
for complex multi-operation transplants.

### Key public types

```rust
pub enum EditError { Pe(PeError), SectionNotFound(String), PatchOutOfBounds{…},
    InvalidAlignment(String), CryptoError(String), ImportError(String), ExportError(String), … }

// All sub-modules expose impl blocks on PeFile (from rustre-pe-tools):
// pe_section_editor:
pub fn add_section(pe: &mut PeFile, name: &str, data: &[u8], characteristics: u32) -> Result<(), EditError>
pub fn remove_section(pe: &mut PeFile, name: &str) -> Result<(), EditError>
pub fn resize_section(…) -> Result<(), EditError>
pub fn encrypt_section(…, key: &[u8]) -> Result<(), EditError>

// pe_import_editor:
pub fn add_import(pe: &mut PeFile, dll: &str, name: &str) -> Result<(), EditError>
pub fn remove_import(pe: &mut PeFile, dll: &str, name: &str) -> Result<(), EditError>
pub fn redirect_import(…) -> Result<(), EditError>

// pe_resource_editor:
pub fn add_resource(pe: &mut PeFile, type_id, name_id, lang_id, data: &[u8]) -> Result<(), EditError>
pub fn remove_resource(…) -> Result<(), EditError>

// pe_header_editor:
pub fn set_image_base(pe: &mut PeFile, base: u64) -> Result<(), EditError>
pub fn set_subsystem(pe: &mut PeFile, subsystem: u16) -> Result<(), EditError>
pub fn set_characteristics(…) -> Result<(), EditError>

// pe_surgeon: orchestrates multi-step edits atomically
// pe_patcher: low-level byte-level patch inside PE sections
// certificate_editor / pe_certificate_table: Authenticode table R/W
// pe_debug_directory: debug directory R/W
```

### Implementation status: **Complete**

All 11 sub-modules are implemented. The `PeFile` type from `rustre-pe-tools`
carries the mutable buffer throughout; edit operations mutate it in-place and
update headers as needed.

### Dependencies
`rustre-pe-tools` (PeFile, PeError), `thiserror`, `serde`, `parking_lot`.

---

## 14. rustre-pe-rebuild

### Purpose
PE reconstruction from corrupted or memory-dumped images. Handles IAT/import
table rebuilding (including Scylla-style IAT walking), OEP detection (prologue
heuristics), relocation rebuilding, section realignment, header repair, and
dumping live process memory to a clean PE file.

### Key public types

```rust
pub enum RebuildError { Pe(PeError), NoSections, SectionDataMissing(String),
    ImageBaseNotSet, IatOutOfBounds(u64), BadReloc(u64), ExportCorrupt(String),
    OepNotFound, … }

// iat_rebuilder:
pub struct IatRebuilder { … }
impl IatRebuilder {
    pub fn scan_iat(&self, dump: &[u8], pe: &PeFile) -> Vec<IatEntry>
    pub fn rebuild(&self, dump: &mut Vec<u8>, pe: &PeFile) -> Result<(), RebuildError>
}

// oep_detection / oep_finder:
pub fn detect_oep(data: &[u8], machine: PeMachine) -> Option<u64>
pub fn find_oep_candidates(data: &[u8], machine: PeMachine) -> Vec<u64>

// pe_reconstructor:
pub struct PeReconstructor { image_base, sections, … }
impl PeReconstructor {
    pub fn rebuild(&self) -> Result<Vec<u8>, RebuildError>
}

// pe_header_fixer:
pub fn fix_pe_header(data: &mut Vec<u8>) -> Result<(), RebuildError>

// scylla_iat_rebuilder: emulates Scylla IAT scanning
// import_table_rebuilder: reconstructs the import directory from scratch
// relocation_rebuilder: rebuilds .reloc section
// section_aligner / section_realigner: align VAs and raw offsets
// pe_dump_fixer: patch common dump artifacts
// pe_dumper: dump from process memory
// pe_fixup: generic fixups (checksum, size fields)
// pe_section_rebuilder: rebuild section table
```

### Implementation status: **Complete**

All 16 sub-modules are present and implemented. Builds on `PeFile` and
`PeBuilder` from `rustre-pe-tools`. The Scylla-style IAT rebuilder is the most
complex module, walking the loaded process IAT to reconstruct the import table.

### Dependencies
`rustre-pe-tools` (PeBuilder, PeFile, PeMachine, PeError), `thiserror`, `serde`.

---

## 15. rustre-pe-tools

### Purpose
Foundation PE format library used by `rustre-pe-editor`, `rustre-pe-rebuild`,
`rustre-gui`, and `rustre-loader-pe`. Provides `PeFile` (in-memory mutable PE
view), `PeBuilder` (PE construction from scratch), imports/exports/sections/
resources parsing, anomaly detection, overlay analysis, Rich header parsing,
signature checking, PE statistics, checksum calculation, and manifest parsing.

### Key public types

```rust
pub enum PeError { NotPe(u16), TooShort{…}, InvalidHeader(String),
    SectionNotFound(String), ImportTableCorrupt, ExportTableCorrupt,
    ResourceNotFound(String), Io(…), Serde(…) }

pub enum PeMachine { Unknown, I386, Amd64, Arm, Arm64, Mips32, Riscv32, Riscv64, Ia64 }

pub struct PeSection { pub name: String, pub virtual_address: u32, pub virtual_size: u32,
    pub raw_offset: u32, pub raw_size: u32, pub characteristics: u32 }

pub struct PeImport { pub dll: String, pub name: Option<String>, pub ordinal: Option<u16>,
    pub iat_rva: u32 }
pub struct PeExport { pub name: Option<String>, pub ordinal: u16, pub rva: u32 }

pub struct PeFile {
    pub data: Vec<u8>,
    pub machine: PeMachine,
    pub image_base: u64,
    pub entry_point: u32,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
    pub is_64bit: bool,
}
impl PeFile {
    pub fn parse(data: Vec<u8>) -> Result<Self, PeError>
    pub fn from_path(path: &Path) -> Result<Self, PeError>
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize>
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32>
    pub fn section_of_rva(&self, rva: u32) -> Option<&PeSection>
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Result<&[u8], PeError>
    pub fn checksum(&self) -> u32
    pub fn recompute_checksum(&mut self)
}

pub struct PeBuilder { … }  // constructs PE from scratch

// Sub-module API highlights:
pub fn compute_pe_checksum(data: &[u8]) -> u32  // pe_checksum_calculator
pub fn parse_rich_header(data: &[u8]) -> Option<RichHeader>  // pe_rich_header
pub fn check_pe_signature(data: &[u8]) -> SignatureStatus  // pe_sign_checker
pub struct PeStatistics { … }  // pe_statistics
pub struct PeAnomalyDetector / PeAnomalyScanner  // anomaly detection
pub struct PeOverlayAnalyzer / PeOverlayExtractor  // overlay
pub fn parse_pe_manifest(data: &[u8]) -> Option<PeManifest>  // pe_manifest_parser
pub struct ResourceParser { … }  // resource directory walker
pub struct ImportAnalysis { … }  // import graph analysis
pub struct CffEditor { … }  // CFF-style PE editor (mirrors CFF Explorer)
pub struct PeValidation { result: bool, issues: Vec<String> }  // pe_validation
```

### Sub-modules (15)

| Module | Content |
|--------|---------|
| `cff_editor` | CFF Explorer–style interactive PE editor |
| `import_analysis` | Import graph, DLL coupling metrics |
| `pe_manifest_parser` | RT_MANIFEST / SxS manifest XML |
| `pe_anomaly_detector` | Heuristic PE anomaly detection |
| `pe_anomaly_scanner` | Batch anomaly scanning |
| `pe_overlay_analyzer` | Overlay detection and analysis |
| `pe_overlay_extractor` | Overlay extraction to file |
| `pe_patcher` | Low-level byte patcher within PE |
| `pe_rebuild` | Embedded rebuild helper |
| `pe_sign_checker` | Authenticode signature status |
| `pe_statistics` | Section/import/export statistics |
| `pe_validation` | Structural PE validation |
| `pe_checksum_calculator` | PE checksum algorithm |
| `pe_rich_header` | Rich header decode |
| `resource_parser` | Resource directory walk + VS_VERSION_INFO |

### Implementation status: **Complete**

`PeFile`, `PeBuilder`, all parsers, and all 15 sub-modules are fully
implemented. This is the PE foundation crate used by five other workspace crates.

### Dependencies
`rustre-core`, `thiserror`, `serde`, `serde_json`, `parking_lot`, `bitflags`.

---

## 16. Cross-cutting dependency map

```
rustre-gui ──────────────────────────────────────────────────────────┐
  │                                                                  ▼
  ├─► rustre-graph ──► rustre-core                         rustre-net-pcap
  │     │ (SQLite/MySQL)                                        │
  │                                                             │
  ├─► rustre-hex ──► rustre-core                               ▼
  │     │                                                 rustre-net-dissect
  ├─► rustre-hex-view ──► rustre-hex                           │
  │                                                             ▼
  ├─► rustre-hex-pattern ──► rustre-hex ──► rustre-core   rustre-net
  │                                                             │
  ├─► rustre-hex-template ──► rustre-hex                       │
  │                                                         (no rustre-core)
  ├─► rustre-net ─────────────────────────────────────────────►│
  ├─► rustre-net-dissect ──► rustre-net                         │
  ├─► rustre-net-pcap ──► rustre-net, rustre-net-dissect        │
  │                                                             │
  ├─► rustre-patch ─────────────────────────────────────────────┤
  │                                                             │
  ├─► rustre-pe-tools ──► rustre-core                           │
  ├─► rustre-pe-editor ──► rustre-pe-tools                      │
  └─► rustre-pe-rebuild ──► rustre-pe-tools                     │
```

**Not in rustre-gui (standalone):** `rustre-net-proxy`, `rustre-net-rules`
(wired separately via `rustre-mcp-tools` wrappers).

### Workspace dependency table

| Crate | rustre-core | rustre-hex | rustre-net | rustre-pe-tools | rustre-graph |
|-------|:-----------:|:----------:|:----------:|:---------------:|:------------:|
| rustre-gui | yes | — | yes | — | — |
| rustre-graph | yes | — | — | — | — |
| rustre-hex | yes | — | — | — | — |
| rustre-hex-view | — | yes | — | — | — |
| rustre-hex-pattern | yes | yes | — | — | — |
| rustre-hex-template | — | yes | — | — | — |
| rustre-net | — | — | — | — | — |
| rustre-net-dissect | — | — | yes | — | — |
| rustre-net-pcap | — | — | yes | — | — |
| rustre-net-proxy | — | — | yes | — | — |
| rustre-net-rules | — | — | yes | — | — |
| rustre-patch | — | — | — | — | — |
| rustre-pe-editor | — | — | — | yes | — |
| rustre-pe-rebuild | — | — | — | yes | — |
| rustre-pe-tools | yes | — | — | — | — |

---

## 17. Pipeline integration summary

```
Binary file on disk
        │
        ▼
rustre-loader-pe  ──► rustre-pe-tools (parse headers)
        │                    │
        │                    ▼
        │           rustre-pe-editor   (modify sections/imports)
        │           rustre-pe-rebuild  (fix dumped PEs)
        │
        ▼
rustre-core (Address, ViewId, Section)
        │
        ├─► rustre-graph  (knowledge graph — functions, xrefs, symbols, patches)
        │
        ├─► rustre-hex    (buffer + undo/redo/search)
        │       ├─► rustre-hex-view    (render panel)
        │       ├─► rustre-hex-pattern (pattern search)
        │       └─► rustre-hex-template (structure overlay)
        │
        ├─► rustre-patch  (apply/rollback byte patches to file buffer)
        │       └─► pe_security (toggle ASLR/DEP/CFG flags)
        │
        └─► rustre-net    (network capture)
                ├─► rustre-net-dissect  (deep protocol inspection)
                ├─► rustre-net-pcap     (PCAP file I/O)
                ├─► rustre-net-proxy    (MITM / dynamic analysis)
                └─► rustre-net-rules   (Snort/Suricata alert engine)
```

**GUI integration points in rustre-gui:**

| Panel | Backend crates |
|-------|---------------|
| Hex View | `rustre-hex`, `rustre-hex-view` |
| Pattern Search | `rustre-hex-pattern` |
| Structure Overlay | `rustre-hex-template`, `rustre-hex-view` |
| Knowledge Graph | `rustre-graph` |
| Network Capture | `rustre-net`, `rustre-net-dissect`, `rustre-net-pcap` |
| PE Overview | `rustre-pe-tools`, `rustre-loader-pe` |
| Patch Manager | `rustre-patch` |
| Decompiler | `rustre-decompiler-*`, `rustre-il-mlil` |
| YARA | `rustre-yara-*` |
| FLIRT | `rustre-flirt-*` |
| Triage/Entropy | `rustre-triage-*` |
| Symbols | `rustre-symbols-*`, `rustre-demangle` |
| Debug/Memory | `rustre-debug` |
| MCP Chat | `rustre-mcp-tools` |
| AI Annotations | `rustre-agent-llm` |

---

## 18. Gap / TODO summary

| Crate | Status | Notable gaps |
|-------|--------|-------------|
| rustre-gui | Partial/Integration | No unit tests; `network_panel` wiring recency unclear; `ensure_used` is an anti-pattern workaround |
| rustre-graph | **Complete** | No schema migration system; MySQL index error swallowing could mask drift |
| rustre-hex | **Complete** | None found; 100+ tests |
| rustre-hex-view | **Complete** | None found; 200+ tests; GPUI rendering adapter not in this crate (in gui) |
| rustre-hex-pattern | **Complete** | `serde-big-array` dep suggests some large array type in sub-modules; verify this is used |
| rustre-hex-template | **Complete** | Template compiler source language is undocumented; no formal grammar |
| rustre-net | **Complete** | No live PCAP capture (pcap/libpcap not linked); purely in-memory/file-based |
| rustre-net-dissect | **Complete** | C2 signature list is static; no auto-update mechanism |
| rustre-net-pcap | **Complete** | PCAPNG NRB (Name Resolution Block) parsing may be partial |
| rustre-net-proxy | **Complete** | SOCKS4A hostname resolution is async but depends on system resolver |
| rustre-net-rules | **Complete** | No rule performance benchmarks; large rule sets may be slow (no Aho-Corasick) |
| rustre-patch | **Complete** | `assemble_simple` is a minimal assembler (x86 JMP/NOP/INT3 only); no full assembler |
| rustre-pe-editor | **Complete** | `encrypt_section` uses XOR-only; no AES support |
| rustre-pe-rebuild | **Complete** | `RuntimeMemoryWriter` (live process write) is Windows-only |
| rustre-pe-tools | **Complete** | No ARM64/RISC-V specific section alignment handling in `PeBuilder` |

### Priority wiring gaps (from GUI perspective)

1. **rustre-net-proxy** and **rustre-net-rules** are not directly imported by
   `rustre-gui`; they are available through `rustre-mcp-tools` wrappers only.
   Direct panel integration would improve usability.

2. **rustre-graph** is imported by `rustre-gui` but the wiring to propagate
   `add_function` / `add_xref` calls from the analysis pass into the graph is
   the responsibility of `analysis/` sub-modules in `rustre-gui` — verify those
   are complete and not stubs.

3. **rustre-hex-template** auto-detect should be called by the hex panel when
   a binary is loaded; confirm the call site exists in `ui/panels/hex_panel.rs`.

4. **rustre-patch → rustre-graph** integration: when a patch is applied via
   `BinaryPatcher`, the corresponding `KnowledgeGraph::add_patch` call should
   persist it. Verify this round-trip is wired.
