//! Annotation storage — address-anchored notes/warnings attached to a binary.
//!
//! Provides:
//! * [`AnnotationKind`] — Note / Warning / BugReport / Highlight / Reference / Todo.
//! * [`Annotation`] — id/binary_id/addr/kind/body/author/created_at/color/is_pinned.
//! * [`AnnotationStore`] — full CRUD backed by SQLite.
//! * [`AnnotationQuery`] — flexible filter builder.
//! * [`export_annotations_json`] / [`import_annotations_json`] — JSON round-trip.

use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── AnnotationKind ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    Note,
    Warning,
    BugReport,
    Highlight,
    Reference,
    Todo,
}

impl AnnotationKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Warning => "warning",
            Self::BugReport => "bug_report",
            Self::Highlight => "highlight",
            Self::Reference => "reference",
            Self::Todo => "todo",
        }
    }
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "warning" => Self::Warning,
            "bug_report" => Self::BugReport,
            "highlight" => Self::Highlight,
            "reference" => Self::Reference,
            "todo" => Self::Todo,
            _ => Self::Note,
        }
    }
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Note,
            Self::Warning,
            Self::BugReport,
            Self::Highlight,
            Self::Reference,
            Self::Todo,
        ]
    }
}

impl std::fmt::Display for AnnotationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Annotation ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: u64,
    pub binary_id: u64,
    pub addr: u64,
    pub kind: AnnotationKind,
    pub body: String,
    pub author: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Hex color string, e.g. `"#ffff00"`.
    pub color: String,
    pub is_pinned: bool,
}

impl Annotation {
    /// Create a new annotation (id=0, timestamps=now).
    #[must_use]
    pub fn new(
        binary_id: u64,
        addr: u64,
        kind: AnnotationKind,
        body: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        let now = unix_now();
        Self {
            id: 0,
            binary_id,
            addr,
            kind,
            body: body.into(),
            author: author.into(),
            created_at: now,
            updated_at: now,
            color: "#ffff00".into(),
            is_pinned: false,
        }
    }
}

// ── AnnotationQuery ───────────────────────────────────────────────────────────

/// Builder for filtered annotation queries.
#[derive(Debug, Default, Clone)]
pub struct AnnotationQuery {
    pub binary_id: Option<u64>,
    pub addr: Option<u64>,
    pub addr_min: Option<u64>,
    pub addr_max: Option<u64>,
    pub kinds: Vec<AnnotationKind>,
    pub author: Option<String>,
    pub pinned_only: bool,
    pub body_contains: Option<String>,
    pub limit: Option<usize>,
    pub offset_rows: Option<usize>,
}

impl AnnotationQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn binary(mut self, id: u64) -> Self {
        self.binary_id = Some(id);
        self
    }
    #[must_use]
    pub fn at_addr(mut self, addr: u64) -> Self {
        self.addr = Some(addr);
        self
    }
    #[must_use]
    pub fn addr_range(mut self, lo: u64, hi: u64) -> Self {
        self.addr_min = Some(lo);
        self.addr_max = Some(hi);
        self
    }
    #[must_use]
    pub fn of_kinds(mut self, kinds: Vec<AnnotationKind>) -> Self {
        self.kinds = kinds;
        self
    }
    #[must_use]
    pub fn by_author(mut self, a: impl Into<String>) -> Self {
        self.author = Some(a.into());
        self
    }
    #[must_use]
    pub fn pinned(mut self) -> Self {
        self.pinned_only = true;
        self
    }
    #[must_use]
    pub fn body_contains(mut self, needle: impl Into<String>) -> Self {
        self.body_contains = Some(needle.into());
        self
    }
    #[must_use]
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
    #[must_use]
    pub fn offset(mut self, n: usize) -> Self {
        self.offset_rows = Some(n);
        self
    }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

fn ensure_tables(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS ann_store_annotations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    addr        INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'note',
    body        TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT 'user',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    color       TEXT NOT NULL DEFAULT '#ffff00',
    is_pinned   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ann_binary_addr ON ann_store_annotations(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_ann_kind ON ann_store_annotations(binary_id, kind);
CREATE INDEX IF NOT EXISTS idx_ann_author ON ann_store_annotations(author);
CREATE INDEX IF NOT EXISTS idx_ann_pinned ON ann_store_annotations(binary_id, is_pinned);
    "#,
    )?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn row_to_annotation(r: &rusqlite::Row<'_>) -> SqlResult<Annotation> {
    Ok(Annotation {
        id: r.get::<_, i64>(0)? as u64,
        binary_id: r.get::<_, i64>(1)? as u64,
        addr: r.get::<_, i64>(2)? as u64,
        kind: AnnotationKind::from_str(&r.get::<_, String>(3)?),
        body: r.get(4)?,
        author: r.get(5)?,
        created_at: r.get::<_, i64>(6)? as u64,
        updated_at: r.get::<_, i64>(7)? as u64,
        color: r.get(8)?,
        is_pinned: r.get::<_, i64>(9)? != 0,
    })
}

// ── AnnotationStore ───────────────────────────────────────────────────────────

/// SQLite-backed annotation store.
pub struct AnnotationStore {
    db_path: PathBuf,
}

impl std::fmt::Debug for AnnotationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnnotationStore({:?})", self.db_path)
    }
}

impl AnnotationStore {
    pub fn new(db_path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        ensure_tables(&conn)?;
        Ok(Self { db_path })
    }

    fn open(&self) -> rusqlite::Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(conn)
    }

    // ── Create ────────────────────────────────────────────────────────────

    /// Insert a new annotation. The `id` field of `ann` is ignored and replaced
    /// with the auto-assigned rowid.
    pub fn insert(&self, ann: &Annotation) -> rusqlite::Result<u64> {
        let conn = self.open()?;
        let now = unix_now();
        conn.execute(
            "INSERT INTO ann_store_annotations \
             (binary_id, addr, kind, body, author, created_at, updated_at, color, is_pinned) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                ann.binary_id as i64,
                ann.addr as i64,
                ann.kind.as_str(),
                &ann.body,
                &ann.author,
                now,
                now,
                &ann.color,
                i64::from(ann.is_pinned) ],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    // ── Read ──────────────────────────────────────────────────────────────

    pub fn get_by_id(&self, id: u64) -> rusqlite::Result<Option<Annotation>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            "SELECT id,binary_id,addr,kind,body,author,created_at,updated_at,color,is_pinned \
             FROM ann_store_annotations WHERE id=?1",
        )?;
        let mut rows = stmt.query(params![id as i64])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(row_to_annotation(r)?));
        }
        Ok(None)
    }

    /// Return all annotations matching `query`.
    pub fn query(&self, q: &AnnotationQuery) -> rusqlite::Result<Vec<Annotation>> {
        let conn = self.open()?;
        // Build a dynamic SQL query.
        let mut sql = String::from(
            "SELECT id,binary_id,addr,kind,body,author,created_at,updated_at,color,is_pinned \
             FROM ann_store_annotations WHERE 1=1",
        );

        if let Some(bid) = q.binary_id {
            sql.push_str(&format!(" AND binary_id={}", bid as i64));
        }
        if let Some(addr) = q.addr {
            sql.push_str(&format!(" AND addr={}", addr as i64));
        } else {
            if let Some(lo) = q.addr_min {
                sql.push_str(&format!(" AND addr>={}", lo as i64));
            }
            if let Some(hi) = q.addr_max {
                sql.push_str(&format!(" AND addr<={}", hi as i64));
            }
        }
        if q.pinned_only {
            sql.push_str(" AND is_pinned=1");
        }
        if let Some(ref author) = q.author {
            sql.push_str(&format!(" AND author='{}'", author.replace('\'', "''")));
        }
        if let Some(ref needle) = q.body_contains {
            sql.push_str(&format!(
                " AND body LIKE '%{}%'",
                needle.replace('\'', "''").replace('%', "\\%")
            ));
        }
        if !q.kinds.is_empty() {
            let kinds_list: Vec<String> = q
                .kinds
                .iter()
                .map(|k| format!("'{}'", k.as_str()))
                .collect();
            sql.push_str(&format!(" AND kind IN ({})", kinds_list.join(",")));
        }
        sql.push_str(" ORDER BY addr ASC, id ASC");
        if let Some(lim) = q.limit {
            sql.push_str(&format!(" LIMIT {lim}"));
        }
        if let Some(off) = q.offset_rows {
            sql.push_str(&format!(" OFFSET {off}"));
        }
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_annotation)?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// All annotations for a binary.
    pub fn list(&self, binary_id: u64) -> rusqlite::Result<Vec<Annotation>> {
        self.query(&AnnotationQuery::new().binary(binary_id))
    }

    /// Annotations at a specific address.
    pub fn at_addr(&self, binary_id: u64, addr: u64) -> rusqlite::Result<Vec<Annotation>> {
        self.query(&AnnotationQuery::new().binary(binary_id).at_addr(addr))
    }

    // ── Update ────────────────────────────────────────────────────────────

    pub fn update_body(&self, id: u64, body: &str) -> rusqlite::Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE ann_store_annotations SET body=?1, updated_at=?2 WHERE id=?3",
            params![body, unix_now(), id as i64],
        )?;
        Ok(n > 0)
    }

    pub fn update_kind(&self, id: u64, kind: AnnotationKind) -> rusqlite::Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE ann_store_annotations SET kind=?1, updated_at=?2 WHERE id=?3",
            params![kind.as_str(), unix_now(), id as i64],
        )?;
        Ok(n > 0)
    }

    pub fn update_color(&self, id: u64, color: &str) -> rusqlite::Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE ann_store_annotations SET color=?1, updated_at=?2 WHERE id=?3",
            params![color, unix_now(), id as i64],
        )?;
        Ok(n > 0)
    }

    pub fn set_pinned(&self, id: u64, pinned: bool) -> rusqlite::Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE ann_store_annotations SET is_pinned=?1, updated_at=?2 WHERE id=?3",
            params![i64::from(pinned), unix_now(), id as i64],
        )?;
        Ok(n > 0)
    }

    // ── Delete ────────────────────────────────────────────────────────────

    pub fn delete(&self, id: u64) -> rusqlite::Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "DELETE FROM ann_store_annotations WHERE id=?1",
            params![id as i64],
        )?;
        Ok(n > 0)
    }

    pub fn delete_all(&self, binary_id: u64) -> rusqlite::Result<usize> {
        let conn = self.open()?;
        let n = conn.execute(
            "DELETE FROM ann_store_annotations WHERE binary_id=?1",
            params![binary_id as i64],
        )?;
        Ok(n)
    }

    // ── Count ─────────────────────────────────────────────────────────────

    #[must_use]
    pub fn count(&self, binary_id: u64) -> u64 {
        let Ok(conn) = self.open() else { return 0 };
        conn.query_row(
            "SELECT COUNT(*) FROM ann_store_annotations WHERE binary_id=?1",
            params![binary_id as i64],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u64)
        .unwrap_or(0)
    }

    #[must_use]
    pub fn count_by_kind(&self, binary_id: u64, kind: AnnotationKind) -> u64 {
        let Ok(conn) = self.open() else { return 0 };
        conn.query_row(
            "SELECT COUNT(*) FROM ann_store_annotations WHERE binary_id=?1 AND kind=?2",
            params![binary_id as i64, kind.as_str()],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u64)
        .unwrap_or(0)
    }

    // ── Export / Import ───────────────────────────────────────────────────

    /// Serialise all annotations for `binary_id` to a JSON string.
    pub fn export_json(&self, binary_id: u64) -> rusqlite::Result<String> {
        let annotations = self.list(binary_id)?;
        Ok(serde_json::to_string_pretty(&annotations).unwrap_or_else(|_| "[]".into()))
    }

    /// Import annotations from a JSON string (as produced by [`export_json`]).
    /// Returns the number of imported records.
    pub fn import_json(&self, json: &str) -> rusqlite::Result<usize> {
        let annotations: Vec<Annotation> = serde_json::from_str(json).unwrap_or_default();
        let mut count = 0;
        for ann in &annotations {
            self.insert(ann)?;
            count += 1;
        }
        Ok(count)
    }
}

// ── Free-function wrappers ────────────────────────────────────────────────────

/// Export `binary_id`'s annotations to JSON.
#[must_use]
pub fn export_annotations_json(store: &AnnotationStore, binary_id: u64) -> String {
    store.export_json(binary_id).unwrap_or_else(|_| "[]".into())
}

/// Import JSON annotations into the store. Returns imported count.
#[must_use]
pub fn import_annotations_json(store: &AnnotationStore, json: &str) -> usize {
    store.import_json(json).unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_store() -> (TempDir, AnnotationStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ann.db");
        let store = AnnotationStore::new(&db).unwrap();
        (dir, store)
    }

    fn make_note(binary_id: u64, addr: u64, body: &str) -> Annotation {
        Annotation::new(binary_id, addr, AnnotationKind::Note, body, "tester")
    }

    // ── AnnotationKind ────────────────────────────────────────────────────

    #[test]
    fn kind_round_trip_str() {
        for k in AnnotationKind::all() {
            assert_eq!(AnnotationKind::from_str(k.as_str()), *k);
        }
    }

    #[test]
    fn kind_display() {
        assert_eq!(AnnotationKind::BugReport.to_string(), "bug_report");
    }

    #[test]
    fn kind_unknown_defaults_note() {
        assert_eq!(AnnotationKind::from_str("xyzzy"), AnnotationKind::Note);
    }

    #[test]
    fn kind_all_count() {
        assert_eq!(AnnotationKind::all().len(), 6);
    }

    // ── Annotation::new ───────────────────────────────────────────────────

    #[test]
    fn annotation_new_defaults() {
        let a = make_note(1, 0x1000, "hello");
        assert_eq!(a.binary_id, 1);
        assert_eq!(a.addr, 0x1000);
        assert_eq!(a.body, "hello");
        assert_eq!(a.author, "tester");
        assert_eq!(a.color, "#ffff00");
        assert!(!a.is_pinned);
        assert!(a.created_at > 0);
    }

    // ── CRUD ──────────────────────────────────────────────────────────────

    #[test]
    fn insert_and_get() {
        let (_d, store) = tmp_store();
        let ann = make_note(1, 0x1000, "first note");
        let id = store.insert(&ann).unwrap();
        let got = store.get_by_id(id).unwrap().unwrap();
        assert_eq!(got.body, "first note");
        assert_eq!(got.kind, AnnotationKind::Note);
        assert_eq!(got.binary_id, 1);
    }

    #[test]
    fn get_by_id_not_found() {
        let (_d, store) = tmp_store();
        assert!(store.get_by_id(9999).unwrap().is_none());
    }

    #[test]
    fn list_empty() {
        let (_d, store) = tmp_store();
        assert!(store.list(1).unwrap().is_empty());
    }

    #[test]
    fn list_returns_all() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x1000, "a")).unwrap();
        store.insert(&make_note(1, 0x2000, "b")).unwrap();
        store.insert(&make_note(2, 0x1000, "c")).unwrap(); // different binary
        assert_eq!(store.list(1).unwrap().len(), 2);
    }

    #[test]
    fn at_addr_filter() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x1000, "at 1000")).unwrap();
        store.insert(&make_note(1, 0x2000, "at 2000")).unwrap();
        let r = store.at_addr(1, 0x1000).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].body, "at 1000");
    }

    #[test]
    fn update_body() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "old")).unwrap();
        assert!(store.update_body(id, "new").unwrap());
        let got = store.get_by_id(id).unwrap().unwrap();
        assert_eq!(got.body, "new");
    }

    #[test]
    fn update_kind() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "note")).unwrap();
        assert!(store.update_kind(id, AnnotationKind::Warning).unwrap());
        let got = store.get_by_id(id).unwrap().unwrap();
        assert_eq!(got.kind, AnnotationKind::Warning);
    }

    #[test]
    fn update_color() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "n")).unwrap();
        assert!(store.update_color(id, "#ff0000").unwrap());
        let got = store.get_by_id(id).unwrap().unwrap();
        assert_eq!(got.color, "#ff0000");
    }

    #[test]
    fn set_pinned() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "n")).unwrap();
        assert!(store.set_pinned(id, true).unwrap());
        assert!(store.get_by_id(id).unwrap().unwrap().is_pinned);
    }

    #[test]
    fn delete_removes() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "n")).unwrap();
        assert!(store.delete(id).unwrap());
        assert!(store.get_by_id(id).unwrap().is_none());
    }

    #[test]
    fn delete_all() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x0, "a")).unwrap();
        store.insert(&make_note(1, 0x100, "b")).unwrap();
        assert_eq!(store.delete_all(1).unwrap(), 2);
        assert_eq!(store.count(1), 0);
    }

    // ── Count ─────────────────────────────────────────────────────────────

    #[test]
    fn count_empty() {
        let (_d, store) = tmp_store();
        assert_eq!(store.count(1), 0);
    }

    #[test]
    fn count_total() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x0, "a")).unwrap();
        store.insert(&make_note(1, 0x100, "b")).unwrap();
        assert_eq!(store.count(1), 2);
    }

    #[test]
    fn count_by_kind() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x0, "note")).unwrap();
        let mut w = make_note(1, 0x100, "warn");
        w.kind = AnnotationKind::Warning;
        store.insert(&w).unwrap();
        assert_eq!(store.count_by_kind(1, AnnotationKind::Note), 1);
        assert_eq!(store.count_by_kind(1, AnnotationKind::Warning), 1);
        assert_eq!(store.count_by_kind(1, AnnotationKind::Todo), 0);
    }

    // ── AnnotationQuery ───────────────────────────────────────────────────

    #[test]
    fn query_addr_range() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x1000, "a")).unwrap();
        store.insert(&make_note(1, 0x2000, "b")).unwrap();
        store.insert(&make_note(1, 0x3000, "c")).unwrap();
        let r = store
            .query(&AnnotationQuery::new().binary(1).addr_range(0x1500, 0x2500))
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].addr, 0x2000);
    }

    #[test]
    fn query_pinned_only() {
        let (_d, store) = tmp_store();
        let id = store.insert(&make_note(1, 0x0, "pinned")).unwrap();
        store.insert(&make_note(1, 0x100, "not pinned")).unwrap();
        store.set_pinned(id, true).unwrap();
        let r = store
            .query(&AnnotationQuery::new().binary(1).pinned())
            .unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].is_pinned);
    }

    #[test]
    fn query_kind_filter() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x0, "note")).unwrap();
        let mut todo = make_note(1, 0x100, "todo");
        todo.kind = AnnotationKind::Todo;
        store.insert(&todo).unwrap();
        let r = store
            .query(
                &AnnotationQuery::new()
                    .binary(1)
                    .of_kinds(vec![AnnotationKind::Todo]),
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, AnnotationKind::Todo);
    }

    #[test]
    fn query_limit() {
        let (_d, store) = tmp_store();
        for i in 0..5 {
            store.insert(&make_note(1, i * 0x100, "n")).unwrap();
        }
        let r = store
            .query(&AnnotationQuery::new().binary(1).limit(2))
            .unwrap();
        assert_eq!(r.len(), 2);
    }

    // ── Export / Import ───────────────────────────────────────────────────

    #[test]
    fn export_import_round_trip() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x1000, "alpha")).unwrap();
        store.insert(&make_note(1, 0x2000, "beta")).unwrap();
        let json = store.export_json(1).unwrap();
        assert!(json.contains("alpha"));

        // Import into fresh store
        let (_d2, store2) = tmp_store();
        let imported = store2.import_json(&json).unwrap();
        assert_eq!(imported, 2);
        assert_eq!(store2.count(1), 2);
    }

    #[test]
    fn export_empty_returns_empty_array() {
        let (_d, store) = tmp_store();
        let json = store.export_json(99).unwrap();
        assert_eq!(json.trim(), "[]");
    }

    #[test]
    fn import_invalid_json_returns_zero() {
        let (_d, store) = tmp_store();
        let n = store.import_json("not valid json").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn free_fn_export_import() {
        let (_d, store) = tmp_store();
        store.insert(&make_note(1, 0x0, "test")).unwrap();
        let json = export_annotations_json(&store, 1);
        let (_d2, store2) = tmp_store();
        let n = import_annotations_json(&store2, &json);
        assert_eq!(n, 1);
    }

    // ── Serialization ─────────────────────────────────────────────────────

    #[test]
    fn annotation_serde_round_trip() {
        let ann = make_note(5, 0xDEAD, "test body");
        let json = serde_json::to_string(&ann).unwrap();
        let ann2: Annotation = serde_json::from_str(&json).unwrap();
        assert_eq!(ann2.body, "test body");
        assert_eq!(ann2.kind, AnnotationKind::Note);
    }

    #[test]
    fn kind_serde_snake_case() {
        let k = AnnotationKind::BugReport;
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, r#""bug_report""#);
    }
}
