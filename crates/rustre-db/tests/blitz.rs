//! Comprehensive blitz integration tests for `rustre-db`.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::Connection as SqliteConnection;

use rustre_db::db_query_builder::{
    CompiledQuery, OrderDirection, QueryBuilderError, QueryPart, SqlValue,
};
use rustre_db::{
    Database, DbConfig, DbError, DbIndexManager, DbLocation, DbMigrationManager, DbQueryBuilder,
    EventError, EventStore, IndexDef, IndexError, IndexKind, Migration, MigrationError,
    MigrationStatus, MigrationVersion, NewEvent, QueryParams, SchemaError, StoredEvent,
    apply_base_schema, base_migrations, build_select, create_index, run_migrations,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mem_db() -> Database {
    Database::open_in_memory().unwrap()
}

fn mem_db_with_schema() -> Database {
    let db = mem_db();
    {
        let mut c = db.acquire().unwrap();
        apply_base_schema(&mut c).unwrap();
    }
    db
}

fn tmp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rustre-db-blitz-{tag}-{}.sqlite",
        uuid::Uuid::new_v4()
    ))
}

fn raw_conn() -> Arc<Mutex<SqliteConnection>> {
    Arc::new(Mutex::new(SqliteConnection::open_in_memory().unwrap()))
}

// ---------------------------------------------------------------------------
// DbConfig / DbLocation
// ---------------------------------------------------------------------------

#[test]
fn dbconfig_memory_forces_max_size_one() {
    let cfg = DbConfig::memory();
    assert_eq!(cfg.max_size, 1);
    assert!(matches!(cfg.location, DbLocation::Memory));
    assert!(cfg.enable_wal);
    assert!(cfg.enable_foreign_keys);
}

#[test]
fn dbconfig_file_defaults_have_pool() {
    let cfg = DbConfig::file("foo.sqlite");
    assert_eq!(cfg.max_size, 8);
    assert!(matches!(cfg.location, DbLocation::File(_)));
}

#[test]
fn dbconfig_clone_roundtrip() {
    let cfg = DbConfig::memory();
    let cloned = cfg.clone();
    assert_eq!(cfg.max_size, cloned.max_size);
}

// ---------------------------------------------------------------------------
// Database open / acquire / close
// ---------------------------------------------------------------------------

#[test]
fn database_open_in_memory_succeeds() {
    let db = Database::open_in_memory().unwrap();
    assert_eq!(db.max_size(), 1);
    assert_eq!(db.checked_out(), 0);
}

#[test]
fn database_open_zero_max_size_errors() {
    let err = Database::open(DbConfig {
        location: DbLocation::Memory,
        max_size: 0,
        ..DbConfig::file("x")
    })
    .unwrap_err();
    assert!(matches!(err, DbError::InvalidConfig(_)));
}

#[test]
fn database_open_file_creates_db() {
    let path = tmp_path("openfile");
    let db = Database::open_file(&path).unwrap();
    let c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE x (id INTEGER);").unwrap();
    drop(c);
    drop(db);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn database_acquire_release_cycle() {
    let db = mem_db();
    {
        let c = db.acquire().unwrap();
        assert_eq!(db.checked_out(), 1);
        drop(c);
    }
    assert_eq!(db.checked_out(), 0);
}

#[test]
fn database_acquire_timeout() {
    let path = tmp_path("timeout");
    let db = Database::open(DbConfig {
        location: DbLocation::File(path),
        max_size: 1,
        acquire_timeout: Duration::from_millis(20),
        busy_timeout: Duration::from_millis(50),
        enable_wal: false,
        enable_foreign_keys: true,
    })
    .unwrap();
    let _held = db.acquire().unwrap();
    let err = db.acquire().unwrap_err();
    assert!(matches!(err, DbError::AcquireTimeout(_)));
}

#[test]
fn database_close_then_acquire_errors() {
    let db = mem_db();
    db.close();
    let err = db.acquire().unwrap_err();
    assert!(matches!(err, DbError::Closed));
}

#[test]
fn database_debug_format_includes_max_size() {
    let db = mem_db();
    let s = format!("{db:?}");
    assert!(s.contains("Database"));
    assert!(s.contains("max_size"));
}

#[test]
fn database_clone_shares_pool() {
    let db = mem_db();
    let db2 = db.clone();
    let _c = db.acquire().unwrap();
    assert_eq!(db2.checked_out(), 1);
}

// ---------------------------------------------------------------------------
// Connection / Transaction
// ---------------------------------------------------------------------------

#[test]
fn connection_raw_deref_works() {
    let db = mem_db();
    let c = db.acquire().unwrap();
    let n: i64 = c.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn transaction_commit_persists() {
    let db = mem_db();
    let mut c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("INSERT INTO t VALUES (1)", []).unwrap();
    tx.commit().unwrap();
    let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn transaction_explicit_rollback() {
    let db = mem_db();
    let mut c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("INSERT INTO t VALUES (1)", []).unwrap();
    tx.rollback().unwrap();
    let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn transaction_drop_rolls_back() {
    let db = mem_db();
    let mut c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    {
        let tx = c.transaction().unwrap();
        tx.execute("INSERT INTO t VALUES (1)", []).unwrap();
    }
    let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0);
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

#[test]
fn base_migrations_has_three_entries() {
    let m = base_migrations();
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].version.as_u32(), 1);
    assert_eq!(m[2].version.as_u32(), 3);
    assert!(m.iter().all(Migration::can_rollback));
}

#[test]
fn apply_base_schema_creates_tables() {
    let db = mem_db();
    let mut c = db.acquire().unwrap();
    let r = apply_base_schema(&mut c).unwrap();
    assert!(r.is_success());
    assert_eq!(r.newly_applied, 3);
}

#[test]
fn apply_base_schema_idempotent() {
    let db = mem_db();
    let mut c = db.acquire().unwrap();
    apply_base_schema(&mut c).unwrap();
    let r2 = apply_base_schema(&mut c).unwrap();
    assert_eq!(r2.newly_applied, 0);
    assert_eq!(r2.already_applied, 3);
}

#[test]
fn schema_error_from_db_error() {
    let e: SchemaError = SchemaError::Db(DbError::Closed);
    let s = format!("{e}");
    assert!(!s.is_empty());
}

// ---------------------------------------------------------------------------
// EventStore
// ---------------------------------------------------------------------------

#[test]
fn newevent_constructor_no_metadata() {
    let e = NewEvent::new("s", "k", b"p".to_vec());
    assert_eq!(e.stream, "s");
    assert_eq!(e.kind, "k");
    assert_eq!(e.payload, b"p");
    assert!(e.metadata.is_none());
}

#[test]
fn newevent_with_metadata_attaches() {
    let e = NewEvent::new("s", "k", vec![]).with_metadata(b"m".to_vec());
    assert_eq!(e.metadata.as_deref(), Some(&b"m"[..]));
}

#[test]
fn eventstore_new_is_default() {
    let s1 = EventStore::new();
    let s2 = EventStore;
    let _ = (s1, s2);
}

#[test]
fn eventstore_append_then_read() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    let o1 = s.append(&c, &NewEvent::new("a", "K1", b"x".to_vec())).unwrap();
    let o2 = s.append(&c, &NewEvent::new("a", "K2", b"y".to_vec())).unwrap();
    assert!(o2 > o1);
    let evs = s.read_stream(&c, "a", None, 100).unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn eventstore_read_stream_filters() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(&c, &NewEvent::new("a", "K", b"1".to_vec())).unwrap();
    s.append(&c, &NewEvent::new("b", "K", b"2".to_vec())).unwrap();
    let a = s.read_stream(&c, "a", None, 100).unwrap();
    let b = s.read_stream(&c, "b", None, 100).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
}

#[test]
fn eventstore_read_after_offset() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    let o1 = s.append(&c, &NewEvent::new("a", "A", b"1".to_vec())).unwrap();
    s.append(&c, &NewEvent::new("a", "B", b"2".to_vec())).unwrap();
    let rest = s.read_stream(&c, "a", Some(o1), 100).unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].kind, "B");
}

#[test]
fn eventstore_read_all() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(&c, &NewEvent::new("s1", "A", b"1".to_vec())).unwrap();
    s.append(&c, &NewEvent::new("s2", "B", b"2".to_vec())).unwrap();
    let all = s.read_all(&c, None, 100).unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn eventstore_read_limit_zero_returns_empty() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(&c, &NewEvent::new("a", "K", b"x".to_vec())).unwrap();
    let evs = s.read_stream(&c, "a", None, 0).unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn eventstore_append_batch_atomic() {
    let db = mem_db_with_schema();
    let mut c = db.acquire().unwrap();
    let s = EventStore::new();
    let offsets = s
        .append_batch(
            &mut c,
            &[
                NewEvent::new("s", "A", b"1".to_vec()),
                NewEvent::new("s", "B", b"2".to_vec()),
                NewEvent::new("s", "C", b"3".to_vec()),
            ],
        )
        .unwrap();
    assert_eq!(offsets.len(), 3);
    assert!(offsets[0] < offsets[1]);
}

#[test]
fn eventstore_append_batch_empty() {
    let db = mem_db_with_schema();
    let mut c = db.acquire().unwrap();
    let s = EventStore::new();
    let offsets = s.append_batch(&mut c, &[]).unwrap();
    assert!(offsets.is_empty());
}

#[test]
fn eventstore_count_and_latest() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    assert_eq!(s.count(&c).unwrap(), 0);
    let off = s.append(&c, &NewEvent::new("s", "K", b"".to_vec())).unwrap();
    assert_eq!(s.count(&c).unwrap(), 1);
    assert_eq!(s.latest_offset(&c).unwrap(), Some(off));
}

#[test]
fn eventstore_append_without_schema_errors() {
    let db = mem_db();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    let err = s.append(&c, &NewEvent::new("s", "K", b"".to_vec())).unwrap_err();
    assert!(matches!(err, EventError::Sql(_)));
}

#[test]
fn eventstore_metadata_roundtrip() {
    let db = mem_db_with_schema();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(
        &c,
        &NewEvent::new("s", "K", b"p".to_vec()).with_metadata(b"meta".to_vec()),
    )
    .unwrap();
    let evs = s.read_stream(&c, "s", None, 10).unwrap();
    assert_eq!(evs[0].metadata.as_deref(), Some(&b"meta"[..]));
    assert_eq!(evs[0].payload, b"p");
    assert!(evs[0].created_at > 0);
}

#[test]
fn stored_event_clone_works() {
    let e = StoredEvent {
        offset: 1,
        stream: "s".into(),
        kind: "K".into(),
        payload: b"x".to_vec(),
        metadata: None,
        created_at: 42,
    };
    let c = e.clone();
    assert_eq!(c.offset, 1);
    assert_eq!(e.offset, 1);
}

// ---------------------------------------------------------------------------
// IndexKind / IndexDef / DbIndexManager
// ---------------------------------------------------------------------------

#[test]
fn index_kind_all_names() {
    assert_eq!(IndexKind::Standard.name(), "standard");
    assert_eq!(IndexKind::Unique.name(), "unique");
    assert_eq!(IndexKind::Partial.name(), "partial");
    assert_eq!(IndexKind::Covering.name(), "covering");
}

#[test]
fn index_kind_is_unique() {
    assert!(IndexKind::Unique.is_unique());
    assert!(!IndexKind::Standard.is_unique());
    assert!(!IndexKind::Partial.is_unique());
    assert!(!IndexKind::Covering.is_unique());
}

#[test]
fn index_kind_supports_filter() {
    assert!(IndexKind::Partial.supports_filter());
    assert!(!IndexKind::Standard.supports_filter());
}

#[test]
fn index_kind_display_matches_name() {
    assert_eq!(IndexKind::Unique.to_string(), "unique");
}

#[test]
fn index_kind_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(IndexKind::Standard);
    s.insert(IndexKind::Standard);
    assert_eq!(s.len(), 1);
}

#[test]
fn indexdef_new_basic() {
    let d = IndexDef::new("idx", "t", ["a"]);
    assert_eq!(d.name, "idx");
    assert_eq!(d.columns, vec!["a".to_string()]);
    assert!(matches!(d.kind, IndexKind::Standard));
    assert_eq!(d.column_count(), 1);
    assert!(!d.is_composite());
}

#[test]
fn indexdef_unique_constructor() {
    let d = IndexDef::unique("idx", "t", ["a"]);
    assert!(d.kind.is_unique());
}

#[test]
fn indexdef_partial_constructor() {
    let d = IndexDef::partial("idx", "t", ["a"], "a > 0");
    assert_eq!(d.filter.as_deref(), Some("a > 0"));
}

#[test]
fn indexdef_to_sql_empty_columns_errors() {
    let mut d = IndexDef::new("idx", "t", ["a"]);
    d.columns.clear();
    let err = d.to_sql().unwrap_err();
    assert!(matches!(err, IndexError::NoColumns(_)));
}

#[test]
fn indexdef_to_sql_empty_name_errors() {
    let mut d = IndexDef::new("idx", "t", ["a"]);
    d.name.clear();
    let err = d.to_sql().unwrap_err();
    assert!(matches!(err, IndexError::InvalidName(_)));
}

#[test]
fn indexdef_to_sql_unique_has_keyword() {
    let d = IndexDef::unique("idx", "t", ["a"]);
    let sql = d.to_sql().unwrap();
    assert!(sql.contains("UNIQUE"));
}

#[test]
fn indexdef_to_sql_partial_has_where() {
    let d = IndexDef::partial("idx", "t", ["a"], "a IS NOT NULL");
    let sql = d.to_sql().unwrap();
    assert!(sql.contains("WHERE a IS NOT NULL"));
}

#[test]
fn indexdef_drop_sql() {
    let d = IndexDef::new("idx", "t", ["a"]);
    assert!(d.drop_sql().contains("DROP INDEX IF EXISTS idx"));
}

#[test]
fn indexdef_with_kind_and_filter() {
    let d = IndexDef::new("idx", "t", ["a"])
        .with_kind(IndexKind::Partial)
        .with_filter("a = 1");
    assert!(matches!(d.kind, IndexKind::Partial));
    assert_eq!(d.filter.as_deref(), Some("a = 1"));
}

#[test]
fn indexdef_composite() {
    let d = IndexDef::new("idx", "t", ["a", "b", "c"]);
    assert!(d.is_composite());
    assert_eq!(d.column_count(), 3);
}

#[test]
fn indexdef_display_includes_kind() {
    let d = IndexDef::unique("uq", "t", ["a"]);
    assert!(d.to_string().contains("uq"));
    assert!(d.to_string().contains("unique"));
}

fn idx_db() -> Arc<Mutex<SqliteConnection>> {
    let conn = SqliteConnection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b INTEGER);")
        .unwrap();
    Arc::new(Mutex::new(conn))
}

#[test]
fn index_manager_create_drop_exists() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    let d = IndexDef::new("idx_a", "t", ["a"]);
    m.create(&d).unwrap();
    assert!(m.index_exists("idx_a").unwrap());
    m.drop("idx_a").unwrap();
    assert!(!m.index_exists("idx_a").unwrap());
}

#[test]
fn index_manager_create_if_missing() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    let d = IndexDef::new("idx", "t", ["a"]);
    assert!(m.create_if_missing(&d).unwrap());
    assert!(!m.create_if_missing(&d).unwrap());
}

#[test]
fn index_manager_rebuild() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    let d = IndexDef::new("idx", "t", ["a"]);
    m.create(&d).unwrap();
    m.rebuild(&d).unwrap();
    assert!(m.index_exists("idx").unwrap());
}

#[test]
fn index_manager_list_all_and_inspect() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    m.create(&IndexDef::new("ix_a", "t", ["a"])).unwrap();
    m.create(&IndexDef::unique("ix_b", "t", ["b"])).unwrap();
    let list = m.list_all().unwrap();
    assert_eq!(list.len(), 2);
    let info = m.inspect("ix_b").unwrap().unwrap();
    assert!(info.unique);
    assert_eq!(info.columns, vec!["b".to_string()]);
}

#[test]
fn index_manager_inspect_missing_returns_none() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    assert!(m.inspect("nope").unwrap().is_none());
}

#[test]
fn index_manager_register_create_all() {
    let db = idx_db();
    let mut m = DbIndexManager::new(db);
    assert_eq!(m.registered_count(), 0);
    m.register(IndexDef::new("ix1", "t", ["a"]));
    m.register(IndexDef::new("ix2", "t", ["b"]));
    assert_eq!(m.registered_count(), 2);
    let n = m.create_all_registered().unwrap();
    assert_eq!(n, 2);
    let dropped = m.drop_all_registered().unwrap();
    assert_eq!(dropped, 2);
}

#[test]
fn index_manager_analyse_table() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    m.analyse_table("t").unwrap();
}

#[test]
fn create_index_free_function() {
    let db = idx_db();
    create_index(db.clone(), &IndexDef::new("ix_free", "t", ["a"])).unwrap();
    let m = DbIndexManager::new(db);
    assert!(m.index_exists("ix_free").unwrap());
}

#[test]
fn index_manager_debug_format() {
    let db = idx_db();
    let m = DbIndexManager::new(db);
    let s = format!("{m:?}");
    assert!(s.contains("DbIndexManager"));
}

// ---------------------------------------------------------------------------
// MigrationVersion / Migration / DbMigrationManager
// ---------------------------------------------------------------------------

#[test]
fn migration_version_ctor_and_display() {
    let v = MigrationVersion::new(7);
    assert_eq!(v.as_u32(), 7);
    assert_eq!(v.to_string(), "v7");
    let v2: MigrationVersion = 8u32.into();
    assert!(v < v2);
}

#[test]
fn migration_new_has_checksum() {
    let m = Migration::new(1u32, "x", "CREATE TABLE t (id INT);");
    assert!(m.checksum.is_some());
    assert!(m.checksum_valid());
    assert!(!m.can_rollback());
}

#[test]
fn migration_with_rollback() {
    let m = Migration::with_rollback(1u32, "x", "UP", "DOWN");
    assert!(m.can_rollback());
    assert_eq!(m.down_sql.as_deref(), Some("DOWN"));
}

#[test]
fn migration_checksum_mismatch_after_mutation() {
    let mut m = Migration::new(1u32, "x", "ORIGINAL");
    m.up_sql = "DIFFERENT".to_string();
    assert!(!m.checksum_valid());
}

#[test]
fn migration_display() {
    let m = Migration::new(9u32, "create", "SELECT 1;");
    let s = m.to_string();
    assert!(s.contains("v9"));
    assert!(s.contains("create"));
}

#[test]
fn migration_status_display_variants() {
    assert_eq!(MigrationStatus::Applied.to_string(), "applied");
    assert_eq!(MigrationStatus::Pending.to_string(), "pending");
    assert_eq!(MigrationStatus::Orphan.to_string(), "orphan");
    assert!(MigrationStatus::AppliedWithChecksumMismatch
        .to_string()
        .contains("checksum"));
}

#[test]
fn migration_manager_duplicate_version_error() {
    let db = raw_conn();
    let err = DbMigrationManager::new(
        db,
        vec![
            Migration::new(1u32, "a", "SELECT 1;"),
            Migration::new(1u32, "b", "SELECT 2;"),
        ],
    )
    .unwrap_err();
    assert!(matches!(err, MigrationError::DuplicateVersion(1)));
}

#[test]
fn migration_manager_out_of_order() {
    let db = raw_conn();
    let err = DbMigrationManager::new(
        db,
        vec![
            Migration::new(5u32, "a", "SELECT 1;"),
            Migration::new(3u32, "b", "SELECT 2;"),
        ],
    )
    .unwrap_err();
    assert!(matches!(err, MigrationError::OutOfOrder(3, 5)));
}

#[test]
fn run_migrations_applies_all() {
    let db = raw_conn();
    let report = run_migrations(
        db,
        vec![
            Migration::with_rollback(1u32, "a", "CREATE TABLE a(id INT);", "DROP TABLE a;"),
            Migration::with_rollback(2u32, "b", "CREATE TABLE b(id INT);", "DROP TABLE b;"),
        ],
    )
    .unwrap();
    assert_eq!(report.total, 2);
    assert_eq!(report.newly_applied, 2);
    assert!(report.is_success());
}

#[test]
fn run_migrations_idempotent_second_pass() {
    let db = raw_conn();
    run_migrations(
        db.clone(),
        vec![Migration::with_rollback(
            1u32, "a", "CREATE TABLE a(id INT);", "DROP TABLE a;",
        )],
    )
    .unwrap();
    let r = run_migrations(
        db,
        vec![Migration::with_rollback(
            1u32, "a", "CREATE TABLE a(id INT);", "DROP TABLE a;",
        )],
    )
    .unwrap();
    assert_eq!(r.newly_applied, 0);
    assert_eq!(r.already_applied, 1);
}

#[test]
fn migration_manager_status_pending() {
    let db = raw_conn();
    let m = DbMigrationManager::new(
        db,
        vec![Migration::new(1u32, "a", "SELECT 1;")],
    )
    .unwrap();
    let s = m.status().unwrap();
    assert_eq!(s.len(), 1);
    assert!(matches!(s[0].1, MigrationStatus::Pending));
}

#[test]
fn migration_manager_migrate_down_all() {
    let db = raw_conn();
    let m = DbMigrationManager::new(
        db,
        vec![
            Migration::with_rollback(1u32, "a", "CREATE TABLE a(id INT);", "DROP TABLE a;"),
            Migration::with_rollback(2u32, "b", "CREATE TABLE b(id INT);", "DROP TABLE b;"),
        ],
    )
    .unwrap();
    m.migrate_up().unwrap();
    let n = m.migrate_down_all().unwrap();
    assert_eq!(n, 2);
}

#[test]
fn migration_manager_no_rollback_error() {
    let db = raw_conn();
    let m = DbMigrationManager::new(
        db,
        vec![Migration::new(1u32, "a", "CREATE TABLE a(id INT);")],
    )
    .unwrap();
    m.migrate_up().unwrap();
    let err = m.migrate_down_one().unwrap_err();
    assert!(matches!(err, MigrationError::NoRollback(1)));
}

#[test]
fn migration_manager_with_table_name() {
    let db = raw_conn();
    let m = DbMigrationManager::new(db, vec![])
        .unwrap()
        .with_table_name("my_migrations");
    m.ensure_tracking_table().unwrap();
    let s = format!("{m:?}");
    assert!(s.contains("my_migrations"));
}

#[test]
fn migration_manager_down_one_empty_ok() {
    let db = raw_conn();
    let m = DbMigrationManager::new(db, vec![]).unwrap();
    // No applied migrations, should be a no-op.
    m.migrate_down_one().unwrap();
}

// ---------------------------------------------------------------------------
// QueryBuilder / SqlValue / QueryParams / build_select
// ---------------------------------------------------------------------------

#[test]
fn sql_value_type_names() {
    assert_eq!(SqlValue::Null.type_name(), "NULL");
    assert_eq!(SqlValue::Integer(1).type_name(), "INTEGER");
    assert_eq!(SqlValue::Float(1.0).type_name(), "REAL");
    assert_eq!(SqlValue::Text("x".into()).type_name(), "TEXT");
    assert_eq!(SqlValue::Blob(vec![1]).type_name(), "BLOB");
    assert!(SqlValue::Null.is_null());
    assert!(!SqlValue::Integer(0).is_null());
}

#[test]
fn sql_value_from_impls() {
    assert_eq!(SqlValue::from(1i64), SqlValue::Integer(1));
    assert_eq!(SqlValue::from(1i32), SqlValue::Integer(1));
    assert_eq!(SqlValue::from(1u32), SqlValue::Integer(1));
    assert_eq!(SqlValue::from(1u64), SqlValue::Integer(1));
    assert_eq!(SqlValue::from(1.5f64), SqlValue::Float(1.5));
    assert_eq!(SqlValue::from("a"), SqlValue::Text("a".into()));
    assert_eq!(SqlValue::from(String::from("b")), SqlValue::Text("b".into()));
    assert_eq!(SqlValue::from(vec![1u8, 2]), SqlValue::Blob(vec![1, 2]));
    assert_eq!(SqlValue::from(true), SqlValue::Integer(1));
    assert_eq!(SqlValue::from(false), SqlValue::Integer(0));
}

#[test]
fn sql_value_display() {
    assert_eq!(SqlValue::Null.to_string(), "NULL");
    assert_eq!(SqlValue::Integer(7).to_string(), "7");
    assert_eq!(SqlValue::Text("x".into()).to_string(), "'x'");
    assert!(SqlValue::Blob(vec![1, 2, 3]).to_string().contains("3 bytes"));
}

#[test]
fn query_params_basic() {
    let mut p = QueryParams::new();
    assert!(p.is_empty());
    p.push(1i64);
    p.push("a");
    assert_eq!(p.len(), 2);
    assert!(!p.is_empty());
    assert_eq!(p.values().len(), 2);
    assert!(matches!(p.get(0), Some(SqlValue::Integer(1))));
    assert!(p.get(99).is_none());
}

#[test]
fn query_params_with_builder() {
    let p = QueryParams::new().with(1i64).with("a");
    assert_eq!(p.len(), 2);
}

#[test]
fn query_params_display() {
    let p = QueryParams::new().with(1i64).with("a");
    let s = p.to_string();
    assert!(s.starts_with('[') && s.ends_with(']'));
    assert!(s.contains('1'));
}

#[test]
fn order_direction_display() {
    assert_eq!(OrderDirection::Asc.to_string(), "ASC");
    assert_eq!(OrderDirection::Desc.to_string(), "DESC");
}

#[test]
fn querypart_display_variants() {
    let p = QueryPart::Columns(vec!["a".into(), "b".into()]);
    assert_eq!(p.to_string(), "SELECT a, b");
    let t = QueryPart::Table {
        name: "t".into(),
        alias: Some("u".into()),
    };
    assert_eq!(t.to_string(), "FROM t AS u");
    let t2 = QueryPart::Table {
        name: "t".into(),
        alias: None,
    };
    assert_eq!(t2.to_string(), "FROM t");
    assert_eq!(QueryPart::Limit(10).to_string(), "LIMIT 10");
    assert_eq!(QueryPart::Offset(5).to_string(), "OFFSET 5");
    assert_eq!(QueryPart::GroupBy("g".into()).to_string(), "GROUP BY g");
    assert_eq!(QueryPart::Having("h".into()).to_string(), "HAVING h");
    assert_eq!(QueryPart::Where("a = 1".into()).to_string(), "WHERE a = 1");
    let j = QueryPart::Join {
        kind: "LEFT".into(),
        table: "x".into(),
        condition: "a = b".into(),
    };
    assert_eq!(j.to_string(), "LEFT JOIN x ON a = b");
    let ob = QueryPart::OrderBy {
        column: "c".into(),
        direction: OrderDirection::Desc,
    };
    assert_eq!(ob.to_string(), "ORDER BY c DESC");
}

#[test]
fn build_select_default_star() {
    let q = build_select("t", &[], &[], vec![], None).unwrap();
    assert!(q.sql.contains("SELECT *"));
    assert!(q.sql.contains("FROM t"));
}

#[test]
fn build_select_columns_limit() {
    let q = build_select("t", &["a", "b"], &["a > ?"], vec![SqlValue::Integer(1)], Some(5))
        .unwrap();
    assert!(q.sql.contains("SELECT a, b"));
    assert!(q.sql.contains("LIMIT 5"));
    assert!(q.sql.contains("WHERE a > ?"));
    assert_eq!(q.params.len(), 1);
    assert!(q.validate().is_ok());
}

#[test]
fn build_select_empty_table_errors() {
    let err = build_select("", &[], &[], vec![], None).unwrap_err();
    assert!(matches!(err, QueryBuilderError::NoTable));
}

#[test]
fn builder_select_no_table_errors() {
    let err = DbQueryBuilder::select().build().unwrap_err();
    assert!(matches!(err, QueryBuilderError::NoTable));
}

#[test]
fn builder_insert_default_values() {
    let q = DbQueryBuilder::insert().from("t").build().unwrap();
    assert!(q.sql.contains("DEFAULT VALUES"));
}

#[test]
fn builder_insert_with_columns() {
    let q = DbQueryBuilder::insert()
        .from("t")
        .columns(["a", "b"])
        .param(1i64)
        .param("x")
        .build()
        .unwrap();
    assert!(q.sql.contains("INSERT INTO t (a, b)"));
    assert!(q.sql.contains("VALUES (?, ?)"));
    assert_eq!(q.params.len(), 2);
}

#[test]
fn builder_update_sets_before_where_params() {
    let q = DbQueryBuilder::update()
        .from("t")
        .set("a", "newval")
        .where_clause("id = ?")
        .param(42i64)
        .build()
        .unwrap();
    assert!(q.sql.contains("UPDATE t SET a = ?"));
    assert!(q.sql.contains("WHERE id = ?"));
    // SET value must come before WHERE binding
    assert_eq!(q.params.len(), 2);
    assert_eq!(q.params.get(0), Some(&SqlValue::Text("newval".into())));
    assert_eq!(q.params.get(1), Some(&SqlValue::Integer(42)));
}

#[test]
fn builder_delete_with_where() {
    let q = DbQueryBuilder::delete()
        .from("t")
        .where_clause("id = ?")
        .param(1i64)
        .build()
        .unwrap();
    assert!(q.sql.starts_with("DELETE FROM t"));
    assert!(q.sql.contains("WHERE id = ?"));
}

#[test]
fn builder_where_and_or_empty_ignored() {
    let q1 = DbQueryBuilder::select()
        .from("t")
        .where_and(Vec::<String>::new())
        .build()
        .unwrap();
    assert!(!q1.sql.contains("WHERE"));
    let q2 = DbQueryBuilder::select()
        .from("t")
        .where_or(Vec::<String>::new())
        .build()
        .unwrap();
    assert!(!q2.sql.contains("WHERE"));
}

#[test]
fn builder_join_group_having_order_offset() {
    let q = DbQueryBuilder::select()
        .from("t")
        .columns(["x", "COUNT(*) AS c"])
        .join("LEFT", "u", "t.id = u.tid")
        .group_by("x")
        .having("c > ?")
        .order_by("x", OrderDirection::Desc)
        .limit(10)
        .offset(20)
        .param(0i64)
        .build()
        .unwrap();
    assert!(q.sql.contains("LEFT JOIN u ON t.id = u.tid"));
    assert!(q.sql.contains("GROUP BY x"));
    assert!(q.sql.contains("HAVING c > ?"));
    assert!(q.sql.contains("ORDER BY x DESC"));
    assert!(q.sql.contains("LIMIT 10"));
    assert!(q.sql.contains("OFFSET 20"));
}

#[test]
fn builder_count_query() {
    let q = DbQueryBuilder::count("t").build().unwrap();
    assert!(q.sql.contains("SELECT COUNT(*)"));
    assert!(q.sql.contains("FROM t"));
}

#[test]
fn builder_exists_query_limit_one() {
    let q = DbQueryBuilder::exists("t").build().unwrap();
    assert!(q.sql.contains("SELECT 1"));
    assert!(q.sql.contains("LIMIT 1"));
}

#[test]
fn compiled_query_validate_mismatch() {
    let q = CompiledQuery {
        sql: "SELECT ? ?".into(),
        params: QueryParams::new().with(1i64),
    };
    assert_eq!(q.placeholder_count(), 2);
    let err = q.validate().unwrap_err();
    assert!(matches!(
        err,
        QueryBuilderError::ParameterMismatch {
            placeholders: 2,
            values: 1,
        }
    ));
}

#[test]
fn compiled_query_display_has_params() {
    let q = build_select("t", &[], &["id = ?"], vec![SqlValue::Integer(1)], None).unwrap();
    let s = q.to_string();
    assert!(s.contains("params"));
}

// ---------------------------------------------------------------------------
// Send/Sync bounds
// ---------------------------------------------------------------------------

#[test]
fn database_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Database>();
}

#[test]
fn event_store_is_send_sync_copy() {
    fn assert_traits<T: Send + Sync + Copy>() {}
    assert_traits::<EventStore>();
}
