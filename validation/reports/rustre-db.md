# rustre-db

## Scopo
Database layer per RustRE: storage SQLite-backed (via `rusqlite`) per il knowledge graph persistente (P4). Fornisce connection pool, RAII connection/transaction, migrazioni di schema versionate, schema base del knowledge graph, event store append-only, gestione indici, e query builder componibile.

## Dipendenze chiave
- `rusqlite` (SQLite binding)
- `parking_lot` (mutex per pool)
- `thiserror`, `serde`

## Moduli pubblici
- `db_connection` — pool, Database, Connection, Transaction, DbConfig, DbLocation, DbError
- `db_events` — EventStore append-only (NewEvent, StoredEvent, EventError)
- `db_index_manager` — DbIndexManager, IndexDef, IndexKind, IndexInfo, IndexError, helper `create_index`
- `db_migration_manager` — DbMigrationManager, Migration, MigrationVersion, MigrationStatus, MigrationReport, helper `run_migrations`
- `db_query_builder` — DbQueryBuilder, QueryParams, QueryPart, SqlValue, CompiledQuery, OrderDirection, helper `build_select`
- `db_schema` — `apply_base_schema`, `base_migrations`, SchemaError

## Public API principali

### Database / Connection
- `DbConfig::file(path) -> Self`, `DbConfig::memory() -> Self`
- `Database::open(DbConfig) -> Result<Database, DbError>`
- `Database::open_in_memory() / open_file(path)`
- `Database::acquire() -> Result<Connection, DbError>` (pool)
- `Database::max_size() -> usize`, `checked_out() -> usize`, `close()`
- `Connection::transaction() -> Result<Transaction, DbError>`
- `Transaction::commit() / rollback() -> Result<(), DbError>`

### EventStore (append-only event sourcing)
- `NewEvent::new(...)`, `with_metadata(bytes)`
- `EventStore::append(conn, &NewEvent) -> Result<i64 offset, EventError>`
- `append_in_tx(tx, &NewEvent)`, `append_batch(...)`
- `read_stream(conn, stream_id, ...) -> Vec<StoredEvent>`
- `read_all(conn, ...)`
- `latest_offset(conn) -> Option<i64>`
- `count(conn) -> u64`

### IndexManager
- `IndexDef::new(name, table, cols)`, `::unique(...)`, `::partial(...)`, `with_filter(expr)`
- `IndexDef::to_sql() -> Result<String>`, `drop_sql() -> String`
- `DbIndexManager::new(Arc<Mutex<Connection>>)`
- `register / create / create_if_missing / drop / rebuild / index_exists / list_all / inspect / create_all_registered / drop_all_registered / analyse_table`
- free fn `create_index(conn, &IndexDef) -> Result<(), IndexError>`

### MigrationManager
- `Migration::new(version, name, up_sql)`, `with_rollback(down_sql)`, `checksum_valid()`
- `MigrationVersion(u32)`, `MigrationStatus`, `MigrationReport`
- `DbMigrationManager::new(...)`, `with_table_name(...)`
- `ensure_tracking_table()`, `applied_versions() -> HashMap<u32, MigrationRecord>`
- `migrate_up() -> MigrationReport`, `migrate_down_one()`, `migrate_down_all() -> usize`
- `status() -> Vec<(Migration, MigrationStatus)>`
- free fn `run_migrations(conn, migrations) -> Result<MigrationReport, MigrationError>`

### QueryBuilder
- `DbQueryBuilder::select() / insert() / update() / delete()`
- `from / columns / where_clause / where_and / where_or / order_by / group_by / having / limit / offset / join / param / params / set`
- `build() -> Result<CompiledQuery, QueryBuilderError>`
- `CompiledQuery::placeholder_count()`, `validate()`
- `QueryParams::new / push / with / values / get`
- helper `build_select(...)`, `DbQueryBuilder::count(table)`, `::exists(table)`

### Schema
- `base_migrations() -> Vec<Migration>` — set di migrazioni base del knowledge graph
- `apply_base_schema(&mut Connection) -> Result<MigrationReport, SchemaError>`

## Input / Output (forma generale)
- Input: percorsi file SQLite o `:memory:`, SQL fragment per builder/indici/migrazioni, blob/bytes per metadata event, structs `NewEvent`, `IndexDef`, `Migration`.
- Output: handle (Database/Connection/Transaction), record (StoredEvent, MigrationRecord, IndexInfo), report (MigrationReport), stringhe SQL (`to_sql`, `drop_sql`, `CompiledQuery.sql`), id/offset numerici, errori tipizzati (`thiserror`).

## Ground truth verificabile esternamente
- **SQLite CLI / qualsiasi binding sqlite**: aprire il file DB prodotto e verificare:
  - tabella di tracking migrazioni (default `_rustre_migrations` o custom via `with_table_name`) con righe versione/checksum/applied_at.
  - schema base creato da `apply_base_schema` (tabelle del KG: nodes/edges/properties, e tabella events per EventStore) ispezionabile via `sqlite_master`.
  - indici creati visibili in `sqlite_master WHERE type='index'` e via `PRAGMA index_list(table)` / `PRAGMA index_info(idx)`; confrontabili col CREATE INDEX prodotto da `IndexDef::to_sql()`.
- **rusqlite upstream**: semantica connessione/transazione (BEGIN/COMMIT/ROLLBACK) e PRAGMA conformi alla doc SQLite ufficiale.
- **EventStore append-only**: `latest_offset` monotono crescente; `count` == numero righe nella tabella eventi; `read_stream` ordinato per offset — verificabile con query SQL diretta.
- **Migration checksum**: `checksum_valid()` deve riprodurre hash deterministico dell'`up_sql`; ricomputabile esternamente con stessa funzione hash documentata nel sorgente.
- **QueryBuilder**: `CompiledQuery.sql` parsabile da SQLite (`EXPLAIN`) e `placeholder_count()` == numero di `?` nella stringa.
- **Pool**: `max_size()` e `checked_out()` ispezionabili; comportamento confrontabile con r2d2/deadpool come riferimento concettuale.
- Test integrati: directory `tests/` del crate.

## Tool MCP esistenti correlati
Nessun tool MCP RustRE espone direttamente questo layer (è infrastruttura interna del KG). Tool del server `rustre-mcp` che ne dipendono indirettamente:
- `mcp__rustre-mcp__kg_*` (kg_query, kg_search, kg_get_function, kg_list_functions, kg_annotate, kg_set_comment, kg_set_function_name) — il knowledge graph persistente poggia su questo storage.
- `mcp__rustre-mcp__project_open / project_info / project_close` — gestione progetto (potenziale persistenza KG).
Nessun tool MCP diretto per migrations / event store / index manager / query builder.

## Testabilità
- Test unitari/integrazione con DB `:memory:` (DbConfig::memory) — niente IO disco.
- Round-trip verificabile via SQL diretto su file SQLite reale.
- `dev-dependencies`: `uuid` (id stabili nei test).

testable: true
