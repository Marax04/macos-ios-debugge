//! blitz2: deep adversarial tests for `rustre-db`.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::Connection as SqliteConnection;

use rustre_db::{
    Database, DbConfig, DbError, DbLocation, EventStore, NewEvent,
    DbIndexManager, IndexDef, IndexKind, create_index,
    DbMigrationManager, Migration, MigrationError, MigrationStatus, MigrationVersion,
    run_migrations,
    DbQueryBuilder, QueryParams, QueryPart, build_select,
    apply_base_schema, base_migrations,
};
use rustre_db::db_query_builder::{CompiledQuery, OrderDirection, SqlValue};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    {
        let mut c = db.acquire().unwrap();
        apply_base_schema(&mut c).unwrap();
    }
    db
}

fn raw_db() -> Arc<Mutex<SqliteConnection>> {
    let c = SqliteConnection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, address INTEGER, kind TEXT);
         CREATE TABLE u (id INTEGER PRIMARY KEY, sym TEXT);",
    )
    .unwrap();
    Arc::new(Mutex::new(c))
}

// ---------- DbConfig / Database ----------

#[test]
fn cfg_zero_max_size_rejected() {
    let mut cfg = DbConfig::memory();
    cfg.max_size = 0;
    let err = Database::open(cfg).unwrap_err();
    assert!(matches!(err, DbError::InvalidConfig(_)));
}

#[test]
fn cfg_memory_forces_single() {
    let cfg = DbConfig::memory();
    assert_eq!(cfg.max_size, 1);
}

#[test]
fn cfg_file_uses_defaults() {
    let cfg = DbConfig::file("x.sqlite");
    assert_eq!(cfg.max_size, 8);
    assert!(matches!(cfg.location, DbLocation::File(_)));
}

#[test]
fn db_close_then_acquire_errors() {
    let db = Database::open_in_memory().unwrap();
    db.close();
    let err = db.acquire().unwrap_err();
    assert!(matches!(err, DbError::Closed));
}

#[test]
fn db_close_idempotent() {
    let db = Database::open_in_memory().unwrap();
    db.close();
    db.close();
}

#[test]
fn db_debug_format_contains_max_size() {
    let db = Database::open_in_memory().unwrap();
    let s = format!("{db:?}");
    assert!(s.contains("max_size"));
}

#[test]
fn db_checked_out_tracking() {
    let path = std::env::temp_dir().join(format!(
        "rustre-db-blitz2-co-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let db = Database::open(DbConfig {
        location: DbLocation::File(path),
        max_size: 3,
        ..DbConfig {
            location: DbLocation::Memory,
            max_size: 8,
            acquire_timeout: Duration::from_secs(5),
            busy_timeout: Duration::from_secs(1),
            enable_wal: true,
            enable_foreign_keys: true,
        }
    })
    .unwrap();
    assert_eq!(db.checked_out(), 0);
    let c1 = db.acquire().unwrap();
    assert_eq!(db.checked_out(), 1);
    let c2 = db.acquire().unwrap();
    assert_eq!(db.checked_out(), 2);
    drop(c1);
    assert_eq!(db.checked_out(), 1);
    drop(c2);
    assert_eq!(db.checked_out(), 0);
}

#[test]
fn connection_debug_open_true() {
    let db = Database::open_in_memory().unwrap();
    let c = db.acquire().unwrap();
    let s = format!("{c:?}");
    assert!(s.contains("open: true"));
}

// ---------- Transactions ----------

#[test]
fn tx_explicit_rollback() {
    let db = Database::open_in_memory().unwrap();
    let mut c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("INSERT INTO t (id) VALUES (1);", []).unwrap();
    tx.rollback().unwrap();
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM t;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn tx_50_round_trips() {
    let db = Database::open_in_memory().unwrap();
    let mut c = db.acquire().unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    for i in 0..50i64 {
        let tx = c.transaction().unwrap();
        tx.execute("INSERT INTO t (id) VALUES (?);", [i]).unwrap();
        tx.commit().unwrap();
    }
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM t;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 50);
}

// ---------- EventStore ----------

#[test]
fn events_count_starts_zero() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    assert_eq!(EventStore::new().count(&c).unwrap(), 0);
}

#[test]
fn events_latest_offset_empty_is_none_or_zero() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    let r = EventStore::new().latest_offset(&c).unwrap();
    assert!(r.is_none() || r == Some(0));
}

#[test]
fn events_read_after_none_returns_all() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    for i in 0..5 {
        s.append(&c, &NewEvent::new("st", format!("k{i}"), vec![u8::try_from(i).unwrap()]))
            .unwrap();
    }
    let evs = s.read_stream(&c, "st", None, 100).unwrap();
    assert_eq!(evs.len(), 5);
    let all = s.read_all(&c, None, 100).unwrap();
    assert_eq!(all.len(), 5);
}

#[test]
fn events_read_limit_caps_results() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    for i in 0..10 {
        s.append(&c, &NewEvent::new("st", "k", vec![i])).unwrap();
    }
    let evs = s.read_stream(&c, "st", None, 3).unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn events_batch_then_read_round_trip() {
    let db = fresh_db();
    let mut c = db.acquire().unwrap();
    let s = EventStore::new();
    let evs: Vec<NewEvent> = (0..50)
        .map(|i| NewEvent::new("bs", format!("k{i}"), vec![u8::try_from(i).unwrap()]))
        .collect();
    let offsets = s.append_batch(&mut c, &evs).unwrap();
    assert_eq!(offsets.len(), 50);
    for w in offsets.windows(2) {
        assert!(w[0] < w[1]);
    }
    let read = s.read_stream(&c, "bs", None, 1000).unwrap();
    assert_eq!(read.len(), 50);
    for (i, ev) in read.iter().enumerate() {
        assert_eq!(ev.payload, vec![u8::try_from(i).unwrap()]);
    }
}

#[test]
fn events_streams_isolated() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(&c, &NewEvent::new("a", "k", b"1".to_vec())).unwrap();
    s.append(&c, &NewEvent::new("b", "k", b"2".to_vec())).unwrap();
    s.append(&c, &NewEvent::new("a", "k", b"3".to_vec())).unwrap();
    assert_eq!(s.read_stream(&c, "a", None, 100).unwrap().len(), 2);
    assert_eq!(s.read_stream(&c, "b", None, 100).unwrap().len(), 1);
    assert_eq!(s.read_stream(&c, "missing", None, 100).unwrap().len(), 0);
}

#[test]
fn events_metadata_optional() {
    let db = fresh_db();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    s.append(&c, &NewEvent::new("s", "k", b"p".to_vec())).unwrap();
    let evs = s.read_stream(&c, "s", None, 10).unwrap();
    assert!(evs[0].metadata.is_none());
}

#[test]
fn events_fuzz_payload() {
    let db = fresh_db();
    let mut c = db.acquire().unwrap();
    let s = EventStore::new();
    let mut g = lcg();
    let mut batch = Vec::new();
    for _ in 0..50 {
        let len = (g() % 32) as usize;
        let payload: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        batch.push(NewEvent::new("fz", "k", payload));
    }
    let offs = s.append_batch(&mut c, &batch).unwrap();
    assert_eq!(offs.len(), 50);
    assert_eq!(s.count(&c).unwrap(), 50);
}

#[test]
fn events_no_schema_errors() {
    // Append into a DB without apply_base_schema should yield Sql error
    let db = Database::open_in_memory().unwrap();
    let c = db.acquire().unwrap();
    let s = EventStore::new();
    let err = s.append(&c, &NewEvent::new("s", "k", vec![1u8])).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("sql") || msg.contains("events"));
}

#[test]
fn newevent_with_metadata_builder() {
    let e = NewEvent::new("s", "k", vec![1u8]).with_metadata(vec![9, 8]);
    assert_eq!(e.metadata.as_deref(), Some(&[9u8, 8][..]));
}

// ---------- Schema / base_migrations ----------

#[test]
fn base_migrations_3_with_rollback() {
    let v = base_migrations();
    assert_eq!(v.len(), 3);
    for (i, m) in v.iter().enumerate() {
        assert_eq!(m.version.as_u32(), u32::try_from(i + 1).unwrap());
        assert!(m.can_rollback());
        assert!(m.checksum_valid());
    }
}

#[test]
fn apply_base_schema_creates_kv_meta() {
    let db = Database::open_in_memory().unwrap();
    let mut c = db.acquire().unwrap();
    apply_base_schema(&mut c).unwrap();
    c.execute("INSERT INTO kv_meta (key, value) VALUES (?1, ?2)", ["x", "y"])
        .unwrap();
    let v: String = c
        .query_row("SELECT value FROM kv_meta WHERE key='x'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "y");
}

// ---------- Migrations ----------

#[test]
fn migration_new_no_rollback() {
    let m = Migration::new(7u32, "x", "SELECT 1;");
    assert!(!m.can_rollback());
}

#[test]
fn migration_version_round_trip() {
    let v = MigrationVersion::from(42u32);
    assert_eq!(v.as_u32(), 42);
    assert_eq!(format!("{v}"), "v42");
}

#[test]
fn migration_version_ord_50_pairs() {
    let mut g = lcg();
    for _ in 0..50 {
        let a = (g() & 0xFFFF) as u32;
        let b = (g() & 0xFFFF) as u32;
        let va = MigrationVersion(a);
        let vb = MigrationVersion(b);
        assert_eq!(va.cmp(&vb), a.cmp(&b));
        if a == b {
            assert_eq!(va, vb);
        }
    }
}

#[test]
fn migration_status_display() {
    assert_eq!(MigrationStatus::Applied.to_string(), "applied");
    assert_eq!(MigrationStatus::Pending.to_string(), "pending");
    assert_eq!(MigrationStatus::Orphan.to_string(), "orphan");
    assert_eq!(
        MigrationStatus::AppliedWithChecksumMismatch.to_string(),
        "applied(checksum-mismatch)"
    );
}

#[test]
fn migration_checksum_detects_mutation() {
    let mut m = Migration::new(1u32, "n", "CREATE TABLE t (id INT);");
    assert!(m.checksum_valid());
    m.up_sql = "CREATE TABLE t (id INT, x INT);".to_string();
    assert!(!m.checksum_valid());
}

#[test]
fn migrations_duplicate_rejected() {
    let v = vec![
        Migration::new(2u32, "a", "SELECT 1;"),
        Migration::new(2u32, "b", "SELECT 2;"),
    ];
    let err = DbMigrationManager::new(raw_db(), v).unwrap_err();
    assert!(matches!(err, MigrationError::DuplicateVersion(2)));
}

#[test]
fn migrations_out_of_order_rejected() {
    let v = vec![
        Migration::new(10u32, "a", "SELECT 1;"),
        Migration::new(5u32, "b", "SELECT 2;"),
    ];
    let err = DbMigrationManager::new(raw_db(), v).unwrap_err();
    assert!(matches!(err, MigrationError::OutOfOrder(5, 10)));
}

#[test]
fn migrations_apply_idempotent_status() {
    let db = raw_db();
    let m = DbMigrationManager::new(
        db,
        vec![Migration::with_rollback(
            1u32,
            "x",
            "CREATE TABLE xx (id INT);",
            "DROP TABLE xx;",
        )],
    )
    .unwrap();
    m.migrate_up().unwrap();
    let st = m.status().unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].1, MigrationStatus::Applied);
}

#[test]
fn migrations_orphan_detected() {
    let db = raw_db();
    {
        let m1 = DbMigrationManager::new(
            db.clone(),
            vec![
                Migration::with_rollback(1u32, "a", "CREATE TABLE a1 (id INT);", "DROP TABLE a1;"),
                Migration::with_rollback(2u32, "b", "CREATE TABLE a2 (id INT);", "DROP TABLE a2;"),
            ],
        )
        .unwrap();
        m1.migrate_up().unwrap();
    }
    // Reopen with only migration 1; migration 2 should be an orphan
    let m2 = DbMigrationManager::new(
        db,
        vec![Migration::with_rollback(
            1u32,
            "a",
            "CREATE TABLE a1 (id INT);",
            "DROP TABLE a1;",
        )],
    )
    .unwrap();
    let st = m2.status().unwrap();
    assert!(st.iter().any(|(_, s)| *s == MigrationStatus::Orphan));
}

#[test]
fn migrations_down_one_works() {
    let db = raw_db();
    let m = DbMigrationManager::new(
        db,
        vec![
            Migration::with_rollback(1u32, "a", "CREATE TABLE m1 (id INT);", "DROP TABLE m1;"),
            Migration::with_rollback(2u32, "b", "CREATE TABLE m2 (id INT);", "DROP TABLE m2;"),
        ],
    )
    .unwrap();
    m.migrate_up().unwrap();
    m.migrate_down_one().unwrap();
    let applied = m.applied_versions().unwrap();
    assert!(applied.contains_key(&1));
    assert!(!applied.contains_key(&2));
}

#[test]
fn migrations_down_one_no_rollback_errs() {
    let db = raw_db();
    let m = DbMigrationManager::new(
        db,
        vec![Migration::new(1u32, "a", "CREATE TABLE no_rb (id INT);")],
    )
    .unwrap();
    m.migrate_up().unwrap();
    let err = m.migrate_down_one().unwrap_err();
    assert!(matches!(err, MigrationError::NoRollback(1)));
}

#[test]
fn migrations_down_one_on_empty_ok() {
    let db = raw_db();
    let m =
        DbMigrationManager::new(db, vec![Migration::new(1u32, "a", "SELECT 1;")]).unwrap();
    m.ensure_tracking_table().unwrap();
    m.migrate_down_one().unwrap(); // no-op
}

#[test]
fn migrations_custom_table_name() {
    let db = raw_db();
    let m =
        DbMigrationManager::new(db.clone(), vec![Migration::new(1u32, "a", "SELECT 1;")])
            .unwrap()
            .with_table_name("my_migrations");
    m.ensure_tracking_table().unwrap();
    let n: i64 = db.lock()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='my_migrations'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
#[should_panic(expected = "table_name must contain only ASCII alphanumerics")]
fn migrations_table_name_panics_on_bad_chars() {
    let db = raw_db();
    let _ = DbMigrationManager::new(db, vec![]).unwrap().with_table_name("bad;name");
}

#[test]
fn migrations_table_name_empty_panics() {
    let db = raw_db();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = DbMigrationManager::new(db, vec![]).unwrap().with_table_name("");
    }));
    assert!(r.is_err());
}

#[test]
fn run_migrations_helper() {
    let db = raw_db();
    let r = run_migrations(db, base_migrations()).unwrap();
    assert!(r.is_success());
    assert_eq!(r.total, 3);
    assert_eq!(r.newly_applied, 3);
}

// ---------- IndexDef / DbIndexManager ----------

#[test]
fn indexkind_supports_filter() {
    assert!(IndexKind::Partial.supports_filter());
    assert!(!IndexKind::Standard.supports_filter());
    assert!(!IndexKind::Unique.supports_filter());
    assert!(!IndexKind::Covering.supports_filter());
}

#[test]
fn indexkind_display() {
    assert_eq!(IndexKind::Covering.to_string(), "covering");
    assert_eq!(IndexKind::Partial.to_string(), "partial");
}

#[test]
fn indexdef_with_kind_and_filter_builder() {
    let d = IndexDef::new("i", "t", ["c"])
        .with_kind(IndexKind::Partial)
        .with_filter("c IS NOT NULL");
    assert_eq!(d.kind, IndexKind::Partial);
    assert!(d.to_sql().unwrap().contains("WHERE c IS NOT NULL"));
}

#[test]
fn indexdef_empty_name_errors() {
    let d = IndexDef {
        name: String::new(),
        table: "t".into(),
        columns: vec!["c".into()],
        kind: IndexKind::Standard,
        filter: None,
        include_columns: vec![],
    };
    let err = d.to_sql().unwrap_err();
    assert!(format!("{err}").contains("invalid index name"));
}

#[test]
fn indexdef_unique_to_sql() {
    let d = IndexDef::unique("u", "t", ["a", "b"]);
    let s = d.to_sql().unwrap();
    assert!(s.contains("CREATE UNIQUE INDEX"));
    assert!(s.contains("(a, b)"));
}

#[test]
fn index_manager_inspect_rejects_unsafe_name() {
    let db = raw_db();
    let mgr = DbIndexManager::new(db);
    let err = mgr.inspect("evil; DROP TABLE t").unwrap_err();
    assert!(format!("{err}").contains("invalid index name"));
}

#[test]
fn index_manager_inspect_missing_returns_none() {
    let db = raw_db();
    let mgr = DbIndexManager::new(db);
    assert!(mgr.inspect("nope").unwrap().is_none());
}

#[test]
fn index_manager_analyse_rejects_unsafe_table() {
    let db = raw_db();
    let mgr = DbIndexManager::new(db);
    let err = mgr.analyse_table("a; DROP").unwrap_err();
    assert!(format!("{err}").contains("invalid index name"));
    let err2 = mgr.analyse_table("").unwrap_err();
    assert!(format!("{err2}").contains("invalid index name"));
}

#[test]
fn index_manager_analyse_ok() {
    let db = raw_db();
    let mgr = DbIndexManager::new(db);
    mgr.analyse_table("t").unwrap();
}

#[test]
fn create_index_fn_full_cycle() {
    let db = raw_db();
    let d = IndexDef::new("idx_x", "t", ["name"]);
    create_index(db.clone(), &d).unwrap();
    let mgr = DbIndexManager::new(db);
    assert!(mgr.index_exists("idx_x").unwrap());
    let info = mgr.inspect("idx_x").unwrap().unwrap();
    assert_eq!(info.columns, vec!["name".to_string()]);
}

#[test]
fn index_manager_drop_all_registered_count() {
    let db = raw_db();
    let mut mgr = DbIndexManager::new(db);
    mgr.register(IndexDef::new("a1", "t", ["name"]));
    mgr.register(IndexDef::new("a2", "t", ["address"]));
    mgr.register(IndexDef::new("a3", "u", ["sym"]));
    assert_eq!(mgr.registered_count(), 3);
    mgr.create_all_registered().unwrap();
    assert_eq!(mgr.drop_all_registered().unwrap(), 3);
}

// ---------- QueryBuilder ----------

#[test]
fn sqlvalue_from_50_seeded() {
    let mut g = lcg();
    for _ in 0..50 {
        let v = g().cast_signed();
        let s: SqlValue = v.into();
        match s {
            SqlValue::Integer(x) => assert_eq!(x, v),
            _ => panic!("expected Integer"),
        }
    }
}

#[test]
fn sqlvalue_u64_clamps_to_i64_max() {
    let v: SqlValue = u64::MAX.into();
    assert!(matches!(v, SqlValue::Integer(x) if x == i64::MAX));
}

#[test]
fn sqlvalue_bool_conversion() {
    assert!(matches!(SqlValue::from(true), SqlValue::Integer(1)));
    assert!(matches!(SqlValue::from(false), SqlValue::Integer(0)));
}

#[test]
fn sqlvalue_is_null_and_typename() {
    assert!(SqlValue::Null.is_null());
    assert!(!SqlValue::Integer(0).is_null());
    assert_eq!(SqlValue::Float(1.0).type_name(), "REAL");
}

#[test]
fn sqlvalue_display() {
    assert_eq!(SqlValue::Null.to_string(), "NULL");
    assert_eq!(SqlValue::Integer(7).to_string(), "7");
    assert_eq!(SqlValue::Text("hi".into()).to_string(), "'hi'");
    let s = SqlValue::Blob(vec![1, 2, 3]).to_string();
    assert!(s.contains("blob 3"));
}

#[test]
fn query_params_push_get_len() {
    let mut p = QueryParams::new();
    assert!(p.is_empty());
    p.push(1i64);
    p.push("x");
    assert_eq!(p.len(), 2);
    assert!(!p.is_empty());
    assert!(matches!(p.get(0), Some(SqlValue::Integer(1))));
    assert!(matches!(p.get(1), Some(SqlValue::Text(_))));
    assert!(p.get(2).is_none());
}

#[test]
fn query_params_with_builder_display() {
    let p = QueryParams::new().with(1i64).with("hi");
    let s = p.to_string();
    assert!(s.starts_with('['));
    assert!(s.contains("'hi'"));
    assert!(s.ends_with(']'));
}

#[test]
fn build_select_empty_table_errors() {
    let err = build_select("", &[], &[], vec![], None);
    assert!(err.is_err());
}

#[test]
fn build_select_placeholder_validate_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 6) as usize;
        let conds: Vec<String> = (0..n).map(|i| format!("c{i} = ?")).collect();
        let cond_refs: Vec<&str> = conds.iter().map(String::as_str).collect();
        let params: Vec<SqlValue> = (0..n).map(|i| SqlValue::Integer(i64::try_from(i).unwrap())).collect();
        let q = build_select("t", &[], &cond_refs, params, Some(10)).unwrap();
        assert_eq!(q.placeholder_count(), n);
        q.validate().unwrap();
    }
}

#[test]
fn compiled_query_mismatch_errs() {
    let q = CompiledQuery {
        sql: "SELECT * FROM t WHERE a=? AND b=? AND c=?".to_string(),
        params: QueryParams::new().with(1i64),
    };
    assert!(q.validate().is_err());
}

#[test]
fn querypart_display_variants() {
    let p = QueryPart::Columns(vec!["a".into(), "b".into()]);
    assert_eq!(p.to_string(), "SELECT a, b");
    let p = QueryPart::Table {
        name: "t".into(),
        alias: Some("x".into()),
    };
    assert_eq!(p.to_string(), "FROM t AS x");
    let p = QueryPart::Table {
        name: "t".into(),
        alias: None,
    };
    assert_eq!(p.to_string(), "FROM t");
    let p = QueryPart::Limit(5);
    assert_eq!(p.to_string(), "LIMIT 5");
    let p = QueryPart::Offset(7);
    assert_eq!(p.to_string(), "OFFSET 7");
    let p = QueryPart::Join {
        kind: "LEFT".into(),
        table: "u".into(),
        condition: "t.id=u.id".into(),
    };
    assert_eq!(p.to_string(), "LEFT JOIN u ON t.id=u.id");
    let p = QueryPart::GroupBy("c".into());
    assert_eq!(p.to_string(), "GROUP BY c");
    let p = QueryPart::Having("c > 0".into());
    assert_eq!(p.to_string(), "HAVING c > 0");
}

#[test]
fn orderdirection_display_round_trip() {
    assert_eq!(OrderDirection::Asc.to_string(), "ASC");
    assert_eq!(OrderDirection::Desc.to_string(), "DESC");
}

#[test]
fn builder_no_table_errs() {
    let err = DbQueryBuilder::select().columns(["a"]).build().unwrap_err();
    assert!(format!("{err}").contains("no table"));
}

#[test]
fn builder_update_set_params_before_where() {
    let q = DbQueryBuilder::update()
        .from("t")
        .set("name", "new")
        .where_clause("id = ?")
        .param(99i64)
        .build()
        .unwrap();
    // SET value first, then WHERE param
    assert_eq!(q.params.len(), 2);
    assert!(matches!(q.params.get(0), Some(SqlValue::Text(s)) if s == "new"));
    assert!(matches!(q.params.get(1), Some(SqlValue::Integer(99))));
    assert!(q.sql.contains("UPDATE t SET name = ?"));
    assert!(q.sql.contains("WHERE id = ?"));
}

#[test]
fn builder_insert_default_values_when_no_cols() {
    let q = DbQueryBuilder::insert().from("t").build().unwrap();
    assert!(q.sql.contains("DEFAULT VALUES"));
}

#[test]
fn builder_where_and_empty_ignored() {
    let q = DbQueryBuilder::select()
        .from("t")
        .where_and(Vec::<String>::new())
        .build()
        .unwrap();
    assert!(!q.sql.contains("WHERE"));
}

#[test]
fn builder_where_or_empty_ignored() {
    let q = DbQueryBuilder::select()
        .from("t")
        .where_or(Vec::<String>::new())
        .build()
        .unwrap();
    assert!(!q.sql.contains("WHERE"));
}

#[test]
fn builder_count_and_exists() {
    let q = DbQueryBuilder::count("t").build().unwrap();
    assert!(q.sql.contains("SELECT COUNT(*)"));
    let q = DbQueryBuilder::exists("t").build().unwrap();
    assert!(q.sql.contains("LIMIT 1"));
}

#[test]
fn builder_full_kitchen_sink() {
    let q = DbQueryBuilder::select()
        .from("t")
        .columns(["a", "b"])
        .join("LEFT", "u", "t.id=u.id")
        .where_and(["x = ?", "y > ?"])
        .params([SqlValue::Integer(1), SqlValue::Integer(2)])
        .group_by("a")
        .having("COUNT(*) > 0")
        .order_by("a", OrderDirection::Desc)
        .limit(10)
        .offset(5)
        .build()
        .unwrap();
    assert!(q.sql.contains("LEFT JOIN u"));
    assert!(q.sql.contains("WHERE (x = ?) AND (y > ?)"));
    assert!(q.sql.contains("GROUP BY a"));
    assert!(q.sql.contains("HAVING COUNT(*) > 0"));
    assert!(q.sql.contains("ORDER BY a DESC"));
    assert!(q.sql.contains("LIMIT 10"));
    assert!(q.sql.contains("OFFSET 5"));
    q.validate().unwrap();
}

#[test]
fn builder_boundary_limits() {
    let q = DbQueryBuilder::select().from("t").limit(0).build().unwrap();
    assert!(q.sql.contains("LIMIT 0"));
    let q = DbQueryBuilder::select()
        .from("t")
        .limit(u64::MAX)
        .build()
        .unwrap();
    assert!(q.sql.contains(&format!("LIMIT {}", u64::MAX)));
}

// ---------- Send/Sync threaded stress ----------

#[test]
fn database_is_send_sync_threaded_stress() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Database>();

    let path = std::env::temp_dir().join(format!(
        "rustre-db-blitz2-thr-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let db = Database::open(DbConfig {
        location: DbLocation::File(path),
        max_size: 4,
        acquire_timeout: Duration::from_secs(10),
        busy_timeout: Duration::from_secs(2),
        enable_wal: true,
        enable_foreign_keys: true,
    })
    .unwrap();
    {
        let c = db.acquire().unwrap();
        c.execute_batch("CREATE TABLE counter (id INTEGER PRIMARY KEY, n INTEGER NOT NULL);")
            .unwrap();
    }

    let mut handles = Vec::new();
    for t in 0..4 {
        let db2 = db.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let c = db2.acquire().unwrap();
                c.execute(
                    "INSERT INTO counter (n) VALUES (?1)",
                    [i64::from(t * 1000 + i)],
                )
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let c = db.acquire().unwrap();
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM counter", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 400);
}

#[test]
fn event_store_clone_copy_send_sync() {
    fn check<T: Send + Sync + Copy + Clone>() {}
    check::<EventStore>();
    let s1 = EventStore::new();
    let s2 = s1; // Copy
    let s3 = s1;
    let _ = (s2, s3);
}
