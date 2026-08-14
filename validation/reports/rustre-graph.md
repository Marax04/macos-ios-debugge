# rustre-graph

Knowledge-graph / analysis-graph crate for RustRE. Persists reverse-engineering
artifacts (functions, symbols, xrefs, types, strings, comments, patches, basic
blocks, traces, agents, sessions, etc.) into a relational store (SQLite or
MySQL) and exposes typed query, traversal, export, collaboration, and graph
algorithm APIs on top.

## Cargo.toml

- name: `rustre-graph` v0.1.0, edition 2024
- deps: `rustre-core` (sibling), `rusqlite`, `mysql`, `petgraph`, `serde`,
  `serde_json`, `thiserror`, `parking_lot`, `tokio`, `uuid` (v4).
- workspace-licensed; library only (no bin).

## Module layout (`src/`)

- `lib.rs` — re-exports + `KnowledgeGraph` (DB-backed RE store), row types,
  `run_migrations`, `QueryParser`/`CypherQuery`, undo log, event subscriptions,
  `GraphStats`, `XrefGraph`.
- `db.rs` — `DatabaseEngine` trait + `SqliteEngine`, `MysqlEngine`,
  `DbDialect`, `GraphParam`, `GraphValue`, `GraphError`.
- `query_engine.rs` — typed `QueryEngine` over an in-memory `KnowledgeGraph`
  (functions/xrefs/symbols/types/strings), `GraphQuery` enum, fluent
  `QueryBuilder` family, `parse_sql`, `QueryCache`, `FullTextResults`.
- `analysis_graph.rs` — petgraph-backed `AnalysisGraph` with `FunctionNode`,
  `DataNode`, `CallEdge`, `DataFlowEdge`, `TypeEdge`; `GraphQuery`,
  `GraphExport` (DOT/JSON), `GraphMetrics`, `SCCFinder`.
- `graph_algorithms_extended.rs` — `Graph`, `PageRank`,
  `BetweennessCentrality`, `ClosenessCentrality`, `GraphPartitioning`
  (bisection), `MaxFlow`, `MinCut`, `SpanningTree`, `GraphColoring`,
  `degree_map`.
- `graph_persistence.rs` — `GraphPersistence` (SQLite), `PersistedNode`,
  `PersistedEdge`, `NodeKind`, `EdgeKind`, `NodeSerializer`,
  `EdgeSerializer`, `GraphMigration`, `GraphTransaction`, `GraphBackup`,
  `PersistError`.
- `graph_export.rs` — `ExportNode`/`ExportEdge`/`ExportGraph`, `ExportFilter`,
  exporters `GraphMLExporter`, `GEXFExporter`, `DotExporter`,
  `CytoscapeExporter`, `Neo4jCypherExporter`, `CsvExporter`, dispatcher
  `write_export(W, &ExportGraph, ExportFormat)`, `ExportFormat` enum.
- `collaboration.rs` — multi-user delta sync: `CollabEvent`, `EventPayload`,
  `Actor`, `EventStore`, `DeltaExport(er)`/`DeltaImporter`, `ImportResult`,
  `ConflictResolver` + `ConflictStrategy`, `SyncSession`, `HttpSyncer`,
  `WsSyncChannel`/`WsState`/`WsMessage`, `UndoHistory`,
  `AuditTrail`/`AuditEntry`, `CollaborationManager`, `compensate(...)`,
  `now_ms()`.

## Public API surface

Counted public functions (`pub fn` / `pub async fn`) across `src/`: **395**.
Hundreds of public structs/enums/traits in addition (see grep above for the
full list).

### Key entry points

- `lib::KnowledgeGraph` — opens/owns a `DatabaseEngine`; CRUD over
  functions, symbols, xrefs, comments, patches, strings, events, bookmarks,
  basic blocks, CFG edges, views, stack vars, vtables, FLIRT matches, debug
  info, notes, analysis cache, scripts, diff sessions, traces, breakpoints,
  watches, agent/MCP sessions, call graphs. Emits `KgEvent` broadcasts via
  `KgSubscription`. Wraps writes in `UndoTransaction`/`UndoLog`.
- `lib::run_migrations(&dyn DatabaseEngine) -> Result<(), GraphError>` —
  schema bootstrap (SQLite + MySQL dialect aware).
- `db::DatabaseEngine` trait — `execute`, `query`, transaction begin/commit,
  dialect; implemented by `SqliteEngine::open(path)` and
  `MysqlEngine::connect(url)`.
- `query_engine::QueryEngine` — operates on an in-memory
  `query_engine::KnowledgeGraph` snapshot; dispatches `GraphQuery` variants
  (Function/Xref/Symbol/Type/String/Path/Subgraph/Traverse/Sql/DataFlow)
  and returns `QueryResult`. Builders (`QueryBuilder::functions()` etc.)
  produce filters with glob support (`glob_match`). `parse_sql(&str)` lifts
  a SQL subset into `ParsedSql`. `QueryCache` memoises.
- `analysis_graph::AnalysisGraph` — petgraph store for live analysis with
  `NodeId`/`EdgeId`, predicates (`NodePredicate`, `EdgeFilter`), `GraphQuery`
  traversal, metrics, SCC finder. `GraphExport` writes DOT/JSON via
  `ExportFormat`.
- `graph_persistence::GraphPersistence` — durable graph snapshots
  (nodes/edges serialized via `NodeSerializer`/`EdgeSerializer`), schema
  migrations, transactional updates, backup/restore.
- `graph_export::write_export` — single dispatch for all exporters keyed by
  `ExportFormat` (GraphML, GEXF, DOT, Cytoscape, Neo4j Cypher, CSV).
- `collaboration::CollaborationManager` — orchestrates `EventStore`,
  delta export/import, conflict resolution, HTTP/WebSocket sync,
  undo history, audit trail. `compensate(&CollabEvent, Actor)` produces
  inverse events for undo.
- `graph_algorithms_extended` — standalone graph analytics over a generic
  `Graph` (adjacency-based): `PageRank::compute`,
  `BetweennessCentrality::compute`, `ClosenessCentrality::compute`,
  `GraphPartitioning::bisect`, `MaxFlow` (Edmonds–Karp), `MinCut`,
  `SpanningTree` (Kruskal/Prim), `GraphColoring` (greedy).

## I/O

- **Storage:** SQLite file (`SqliteEngine`) or remote MySQL
  (`MysqlEngine`); schema created by `run_migrations`.
- **Inputs:** typed row structs (`FunctionRow`, `SymbolRow`, `XrefRow`,
  `StringRow`, ...), `GraphParam` values, `GraphQuery`/`SqlQuery` strings,
  `CollabEvent` payloads, `PersistedNode`/`PersistedEdge`.
- **Outputs:** typed `QueryResult` variants, `SubgraphResult`,
  `CallPath`, `DataFlowPath`, `FullTextResults`, `GraphStats`,
  `GraphMetrics`, `ImportResult`/`SyncResult`, broadcast `KgEvent` over
  `tokio::sync::broadcast`, exported text streams (`GraphML`/`GEXF`/`DOT`/
  `Cytoscape JSON`/`Cypher`/`CSV`) via `Write`.
- **Concurrency:** `parking_lot` mutexes inside the store; async APIs
  through `tokio` for sync sessions and event broadcast. UUIDs (v4) tag
  events and sessions.

## Behavior notes

- All mutations go through transactions (DB or graph) and append to
  `UndoLog` / `EventStore`, enabling local undo and multi-user delta sync.
- Conflict resolution uses pluggable `ConflictStrategy` (LWW, server-wins,
  client-wins, manual) returning a `ConflictOutcome` with `Winner`.
- Export filters (`ExportFilter`) prune by node/edge kind before
  serialization. Cytoscape and Neo4j formats emit JSON / Cypher text.
- Query engine supports glob patterns, SQL subset, BFS/DFS traversal with
  direction (`In`/`Out`/`Both`) and mode (`Nodes`/`Edges`/`Paths`), and a
  result cache.

## Testability

Two integration tests already exist (`tests/blitz.rs`, `tests/blitz2.rs`).
The crate is testable: `SqliteEngine` accepts `:memory:` for unit tests,
`AnalysisGraph` and `graph_algorithms_extended::Graph` are pure in-memory,
and `parse_sql`/`glob_match` are pure functions.
