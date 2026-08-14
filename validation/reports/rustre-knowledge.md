# rustre-knowledge

## Purpose
Knowledge-graph layer for RustRE: data model (entities, snapshot), event-sourced store with pluggable persistence (JSON / NullBackend), query helpers, and JSON import/export/merge of `KnowledgeGraph`s (nodes + directed edges). Pure in-process Rust, no external deps beyond serde/uuid/parking_lot.

## Core types
- `KnowledgeNode { id, label, kind, metadata }`
- `KnowledgeEdge { from, to, relation, weight }`
- `KnowledgeGraph { nodes: HashMap<id,Node>, edges: Vec<Edge> }`
- `EntitySnapshot` — current state aggregated from event log
- Entities: `Symbol`, `Function`, `TypeDef`, `Comment`, `Xref`, `Patch`, `Bookmark`, `Trace`, `Tag`

## Public functions (semantic)

### `KnowledgeGraph` methods
| fn | input | output | behavior | ground truth |
|---|---|---|---|---|
| `new` | – | empty graph | constructor | node_count==0 && edge_count==0 |
| `add_node(node)` | KnowledgeNode | – | inserts/overwrites by id | after add, node retrievable by id; duplicate id replaces |
| `add_edge(edge)` | KnowledgeEdge | – | appends edge | edge_count increments by 1 |
| `node_count` | – | usize | size of node map | matches number of distinct ids inserted |
| `edge_count` | – | usize | length of edge vec | matches number of add_edge calls |
| `outgoing(id)` | node id | `Vec<&Edge>` | filter edges where from==id | reproducible with Python list-comp |
| `incoming(id)` | node id | `Vec<&Edge>` | filter edges where to==id | reproducible with Python list-comp |

### Importer (`knowledge_importer`)
| fn | input | output | behavior | ground truth |
|---|---|---|---|---|
| `import_from_json(json: &str)` | JSON string of graph | `ImportResult` | parses graph JSON, returns nodes+edges count & graph | round-trip: export_to_json(g)→import_from_json yields same counts |
| `minimal_graph_json(nodes,edges)` | slices of (id,label,kind) and (from,to,relation) | JSON string | helper to build canonical JSON | re-import yields exact counts |
| `KnowledgeImporter::new` | – | builder | default importer | – |
| `.filter_node_kinds(kinds)` | Vec<String> | Self | builder filter | imported nodes' kind ⊂ filter set |
| `.filter_relations(rels)` | Vec<String> | Self | builder filter | imported edges' relation ⊂ filter set |
| `.import_json_str(s)` / `.import_json_file(p)` / `.import_json(src)` | source | ImportResult | parse + apply filters | counts ≤ unfiltered counts |
| `ImportSource::read_bytes/read_string` | self | bytes/string | reads from file/inline | bytes == fs::read(path) |

### Exporter (`knowledge_exporter`)
| fn | input | output | behavior | ground truth |
|---|---|---|---|---|
| `export_to_json(&graph)` | KnowledgeGraph | ExportResult (string) | serialize to JSON | json.loads in Python yields nodes/edges counts equal to graph |
| `KnowledgeExporter::new` | – | builder | – | – |
| `.filter_node_kinds/.filter_relations` | Vec<String> | Self | builder filters | exported counts ≤ original |
| `.export(graph, format)` | graph, ExportFormat | ExportResult | format selection | round-trip via import_from_json preserves filtered set |
| `.export_to_file(...)` | path | () | writes file | fs.stat size>0; re-import equals |
| `ExportResult::as_str` / `write_to_file` | self | str/() | accessor | – |

### Merger (`knowledge_merger`)
| fn | input | output | behavior | ground truth |
|---|---|---|---|---|
| `merge_graphs(left,right)` | two graphs | `MergeResult` | union by node id, edges concatenated, conflict policy default | merged.node_count == |ids(left)∪ids(right)|; edges == left.edges+right.edges (modulo dedup policy) |
| `KnowledgeMerger::merge(l,r)` | graphs | MergeResult | configurable strategy | same as above with strategy semantics |
| `.merge_many(&[graphs])` | slice | MergeResult | fold merge | equivalent to repeated pairwise merges |
| `MergeResult::left_wins_count/right_wins_count` | – | usize | conflict accounting | sum ≤ conflicts |

### Query helpers (`query`) — read-only on `EntitySnapshot`
All take `&EntitySnapshot`; return `Option<&T>` or `Vec<&T>`. Pure lookup with deterministic predicate.

- `find_symbol_by_addr(snap, addr)` → first symbol with address == addr
- `find_symbol_by_name(snap, name)` → first symbol with name == name
- `symbols_in_range(snap, lo, hi)` → symbols with lo ≤ addr < hi
- `find_function_by_entry(snap, entry)` → function whose entry == entry
- `function_containing(snap, addr)` → function with entry ≤ addr < end
- `functions_in_range(snap, lo, hi)` → functions overlapping range
- `find_type_by_name(snap, name)` → first type with given name
- `comments_at(snap, addr)` → comments where addr matches
- `comments_at_scope(snap, addr, scope)` → comments_at filtered by scope
- `xrefs_to(snap, addr)` / `xrefs_from(snap, addr)` → xrefs by target/source
- `xrefs_of_kind(snap, kind)` → xrefs filtered by XrefKind
- `patches_at(snap, addr)` / `applied_patches(snap)` → patches by addr / where applied==true
- `bookmarks_at(snap, addr)` → bookmarks at addr
- `traces_in_window(snap, lo, hi)` / `traces_at(snap, addr)` → traces by timestamp window / addr
- `tags_for(snap, entity_id)` / `tags_with_key(snap, key)` → tags filtered
- `count(snap, kind: EntityKind)` → usize: number of entities of that kind

All trivially verifiable by populating a snapshot and counting with a Python reference filter.

### Store (`store`) — event-sourced
- `KnowledgeStore::in_memory() / with_backend(b) / open_json(dir)` → store
- `.begin(author)` → `Transaction` (stage upsert/remove for every entity kind; commit→events appended, snapshot updated; rollback discards)
- `.snapshot()` → cloned EntitySnapshot
- `.event_count()` / `.event_log()` → metadata
- `.flush()` → persists via backend
- `.query(|snap| …)` → run closure with read lock
- `Transaction::{upsert_*, remove_*, stage, commit, rollback}` for Symbol/Function/TypeDef/Comment/Xref/Patch/Bookmark/Trace/Tag

### Events (`events`)
- `KnowledgeEvent::new(seq, author, payload)` → event
- `.apply(&mut snap)` → mutates snapshot per payload
- `EventLog::events/record/replay/replay_up_to` → log + deterministic replay producing snapshot

## Existing MCP tools (rustre-mcp-tools)
Wired in `register_kg_group` (lib.rs ~6765+). Currently STUB implementations returning hard-coded JSON:
- `kg.query` — structured query (stub: returns 2 fake hits)
- `kg.search` — full-text search (stub)
- `kg.annotate` — attach key/value annotation (stub echoes input)
- (additional kg_* tools likely exist; group registered as a whole — `kg_set_function_name`, `kg_set_comment` referenced in comments)

These do NOT currently invoke `rustre-knowledge` — gap: real wiring missing.

## Testable functions (best ground-truth candidates)
1. `KnowledgeGraph::{add_node, add_edge, node_count, edge_count, outgoing, incoming}` — pure set/list semantics, trivially mirrored in Python.
2. `export_to_json` / `import_from_json` round-trip — output JSON parseable, counts preserved.
3. `merge_graphs` — node union by id, edge concatenation.
4. `minimal_graph_json` — produces JSON parseable into expected schema.
5. Query helpers (`symbols_in_range`, `function_containing`, `xrefs_to/from`, `count`) — deterministic filters over an explicit snapshot built via Transaction.
6. `EventLog::replay` — applying N events then replay yields equivalent snapshot to step-by-step apply.

## Validator strategy
Build a Rust harness binary (or `cargo test --package rustre-knowledge` invoked from Python) that:
1. **Graph primitives**: construct graphs with known nodes/edges, dump counts+outgoing/incoming via `serde_json`, compare with Python reference (dict + list filter).
2. **Round-trip**: build graph → `export_to_json` → write stdout → Python `json.loads`, verify node/edge counts and ids match. Then feed JSON back via `import_from_json` and confirm counts equal.
3. **Merge**: two graphs with overlapping ids → `merge_graphs` → assert `merged.node_count == len(set(ids_l)|set(ids_r))` and edges == concat (or dedup per strategy).
4. **Query**: populate `KnowledgeStore::in_memory()` via Transaction with known Symbols/Functions/Xrefs, then for each query helper compare results vs Python list-comprehension over the same JSON-serialized snapshot.
5. **Event replay**: stage N upserts → commit → call `EventLog::replay` from seq 0 and assert snapshot equals current `store.snapshot()`.
6. **MCP gap test**: call `kg.query` MCP tool with a known store state and assert response is not the hard-coded stub — currently expected to FAIL, documenting the integration gap.
