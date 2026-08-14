//! `db_query_builder` — Composable SQL query builder for `SQLite`.
//!
//! Provides [`DbQueryBuilder`], [`QueryPart`], [`QueryParams`], and
//! the primary entry point [`build_select`].

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by query building operations.
#[derive(Debug, Error)]
pub enum QueryBuilderError {
    /// No table was specified.
    #[error("no table specified")]
    NoTable,
    /// A column name is invalid (empty or contains unsafe characters).
    #[error("invalid column name: '{0}'")]
    InvalidColumn(String),
    /// A condition is malformed.
    #[error("malformed condition: '{0}'")]
    MalformedCondition(String),
    /// Parameter count mismatch between placeholders and values.
    #[error("parameter mismatch: {placeholders} placeholders but {values} values")]
    ParameterMismatch { placeholders: usize, values: usize },
    /// An ordering direction is invalid.
    #[error("invalid order direction: '{0}'")]
    InvalidOrderDirection(String),
}

// ---------------------------------------------------------------------------
// SqlValue
// ---------------------------------------------------------------------------

/// A bound SQL parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlValue {
    /// NULL value.
    Null,
    /// Integer value.
    Integer(i64),
    /// Floating-point value.
    Float(f64),
    /// Text value.
    Text(String),
    /// Blob (binary) value.
    Blob(Vec<u8>),
}

impl SqlValue {
    /// Returns `true` if this value is NULL.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Type name as a string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Integer(_) => "INTEGER",
            Self::Float(_) => "REAL",
            Self::Text(_) => "TEXT",
            Self::Blob(_) => "BLOB",
        }
    }
}

impl fmt::Display for SqlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "NULL"),
            Self::Integer(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            // Escape control characters (including \n, \r) so that a
            // user-controlled Text value cannot inject fake log lines when
            // a CompiledQuery is passed to a tracing macro.
            Self::Text(s) => {
                write!(f, "'")?;
                for c in s.chars() {
                    if c.is_control() {
                        write!(f, "\\x{:02x}", c as u32)?;
                    } else if c == '\'' {
                        write!(f, "''")?;
                    } else {
                        write!(f, "{c}")?;
                    }
                }
                write!(f, "'")
            }
            Self::Blob(b) => write!(f, "<blob {} bytes>", b.len()),
        }
    }
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self { Self::Integer(v) }
}

impl From<i32> for SqlValue {
    fn from(v: i32) -> Self { Self::Integer(i64::from(v)) }
}

impl From<u32> for SqlValue {
    fn from(v: u32) -> Self { Self::Integer(i64::from(v)) }
}

impl From<u64> for SqlValue {
    fn from(v: u64) -> Self {
        // u64 values that exceed i64::MAX cannot be represented losslessly in
        // SQLite's INTEGER type (which is signed 64-bit). Clamp to i64::MAX so
        // callers get a meaningful value rather than a silently wrapped negative.
        Self::Integer(i64::try_from(v).unwrap_or(i64::MAX))
    }
}

impl From<f64> for SqlValue {
    fn from(v: f64) -> Self { Self::Float(v) }
}

impl From<String> for SqlValue {
    fn from(s: String) -> Self { Self::Text(s) }
}

impl From<&str> for SqlValue {
    fn from(s: &str) -> Self { Self::Text(s.to_string()) }
}

impl From<Vec<u8>> for SqlValue {
    fn from(b: Vec<u8>) -> Self { Self::Blob(b) }
}

impl From<bool> for SqlValue {
    fn from(b: bool) -> Self { Self::Integer(i64::from(b)) }
}

// ---------------------------------------------------------------------------
// QueryParams
// ---------------------------------------------------------------------------

/// A list of bound parameter values for a parameterised query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryParams {
    values: Vec<SqlValue>,
}

impl QueryParams {
    /// Create an empty parameter list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a value.
    pub fn push(&mut self, v: impl Into<SqlValue>) {
        self.values.push(v.into());
    }

    /// Builder-style push, consuming self.
    #[must_use]
    pub fn with(mut self, v: impl Into<SqlValue>) -> Self {
        self.push(v);
        self
    }

    /// All values in order.
    #[must_use]
    pub fn values(&self) -> &[SqlValue] {
        &self.values
    }

    /// Number of parameters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if there are no parameters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get the value at index `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&SqlValue> {
        self.values.get(i)
    }
}

impl fmt::Display for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, v) in self.values.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{v}")?;
        }
        write!(f, "]")
    }
}

// ---------------------------------------------------------------------------
// QueryPart
// ---------------------------------------------------------------------------

/// A composable fragment of a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryPart {
    /// SELECT column list.
    Columns(Vec<String>),
    /// FROM table (with optional alias).
    Table { name: String, alias: Option<String> },
    /// JOIN clause.
    Join { kind: String, table: String, condition: String },
    /// WHERE condition (raw SQL fragment with `?` placeholders).
    Where(String),
    /// AND-joined compound WHERE condition.
    WhereAnd(Vec<String>),
    /// OR-joined compound WHERE condition.
    WhereOr(Vec<String>),
    /// ORDER BY expression.
    OrderBy { column: String, direction: OrderDirection },
    /// GROUP BY column.
    GroupBy(String),
    /// HAVING clause.
    Having(String),
    /// LIMIT.
    Limit(u64),
    /// OFFSET.
    Offset(u64),
}

impl fmt::Display for QueryPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Columns(cols) => write!(f, "SELECT {}", cols.join(", ")),
            Self::Table { name, alias } => {
                if let Some(a) = alias {
                    write!(f, "FROM {name} AS {a}")
                } else {
                    write!(f, "FROM {name}")
                }
            }
            Self::Join { kind, table, condition } => {
                write!(f, "{kind} JOIN {table} ON {condition}")
            }
            Self::Where(cond) => write!(f, "WHERE {cond}"),
            Self::WhereAnd(conds) => write!(f, "WHERE ({})", conds.join(") AND (")),
            Self::WhereOr(conds) => write!(f, "WHERE ({})", conds.join(") OR (")),
            Self::OrderBy { column, direction } => {
                write!(f, "ORDER BY {column} {direction}")
            }
            Self::GroupBy(col) => write!(f, "GROUP BY {col}"),
            Self::Having(cond) => write!(f, "HAVING {cond}"),
            Self::Limit(n) => write!(f, "LIMIT {n}"),
            Self::Offset(n) => write!(f, "OFFSET {n}"),
        }
    }
}

// ---------------------------------------------------------------------------
// OrderDirection
// ---------------------------------------------------------------------------

/// SQL ORDER BY direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderDirection {
    Asc,
    Desc,
}

impl fmt::Display for OrderDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asc => write!(f, "ASC"),
            Self::Desc => write!(f, "DESC"),
        }
    }
}

// ---------------------------------------------------------------------------
// CompiledQuery
// ---------------------------------------------------------------------------

/// A fully built SQL query string together with its bound parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledQuery {
    /// The SQL string with `?` placeholders.
    pub sql: String,
    /// The bound parameters, in placeholder order.
    pub params: QueryParams,
}

impl CompiledQuery {
    /// Count of `?` placeholders in the SQL string.
    #[must_use]
    pub fn placeholder_count(&self) -> usize {
        self.sql.chars().filter(|&c| c == '?').count()
    }

    /// Validate that placeholder count matches parameter count.
    ///
    /// # Errors
    ///
    /// Returns [`QueryBuilderError::ParameterMismatch`] if they differ.
    pub fn validate(&self) -> Result<(), QueryBuilderError> {
        let p = self.placeholder_count();
        let v = self.params.len();
        if p != v {
            return Err(QueryBuilderError::ParameterMismatch { placeholders: p, values: v });
        }
        Ok(())
    }
}

impl fmt::Display for CompiledQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -- params: {}", self.sql, self.params)
    }
}

// ---------------------------------------------------------------------------
// DbQueryBuilder
// ---------------------------------------------------------------------------

/// A builder for composing SELECT, INSERT, UPDATE, and DELETE queries.
///
/// Accumulates [`QueryPart`]s and compiles them into a [`CompiledQuery`].
#[derive(Debug, Clone, Default)]
pub struct DbQueryBuilder {
    parts: Vec<QueryPart>,
    params: QueryParams,
    query_kind: QueryKind,
    table: Option<String>,
    columns: Vec<String>,
    set_clauses: Vec<(String, SqlValue)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum QueryKind {
    #[default]
    Select,
    Insert,
    Update,
    Delete,
}

impl DbQueryBuilder {
    /// Start building a SELECT query.
    #[must_use]
    pub fn select() -> Self {
        Self { query_kind: QueryKind::Select, ..Self::default() }
    }

    /// Start building an INSERT query.
    #[must_use]
    pub fn insert() -> Self {
        Self { query_kind: QueryKind::Insert, ..Self::default() }
    }

    /// Start building an UPDATE query.
    #[must_use]
    pub fn update() -> Self {
        Self { query_kind: QueryKind::Update, ..Self::default() }
    }

    /// Start building a DELETE query.
    #[must_use]
    pub fn delete() -> Self {
        Self { query_kind: QueryKind::Delete, ..Self::default() }
    }

    /// Set the target table.
    #[must_use]
    pub fn from(mut self, table: impl Into<String>) -> Self {
        self.table = Some(table.into());
        self
    }

    /// Add columns to SELECT or INSERT.
    #[must_use]
    pub fn columns(mut self, cols: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.columns.extend(cols.into_iter().map(Into::into));
        self
    }

    /// Add a WHERE condition.
    #[must_use]
    pub fn where_clause(mut self, cond: impl Into<String>) -> Self {
        self.parts.push(QueryPart::Where(cond.into()));
        self
    }

    /// Add multiple AND-joined WHERE conditions.
    #[must_use]
    pub fn where_and(mut self, conds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let v: Vec<String> = conds.into_iter().map(Into::into).collect();
        if !v.is_empty() {
            self.parts.push(QueryPart::WhereAnd(v));
        }
        self
    }

    /// Add multiple OR-joined WHERE conditions.
    #[must_use]
    pub fn where_or(mut self, conds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let v: Vec<String> = conds.into_iter().map(Into::into).collect();
        if !v.is_empty() {
            self.parts.push(QueryPart::WhereOr(v));
        }
        self
    }

    /// Add an ORDER BY clause.
    #[must_use]
    pub fn order_by(mut self, column: impl Into<String>, direction: OrderDirection) -> Self {
        self.parts.push(QueryPart::OrderBy {
            column: column.into(),
            direction,
        });
        self
    }

    /// Add a GROUP BY clause.
    #[must_use]
    pub fn group_by(mut self, column: impl Into<String>) -> Self {
        self.parts.push(QueryPart::GroupBy(column.into()));
        self
    }

    /// Add a HAVING clause.
    #[must_use]
    pub fn having(mut self, cond: impl Into<String>) -> Self {
        self.parts.push(QueryPart::Having(cond.into()));
        self
    }

    /// Add a LIMIT.
    #[must_use]
    pub fn limit(mut self, n: u64) -> Self {
        self.parts.push(QueryPart::Limit(n));
        self
    }

    /// Add an OFFSET.
    #[must_use]
    pub fn offset(mut self, n: u64) -> Self {
        self.parts.push(QueryPart::Offset(n));
        self
    }

    /// Add a JOIN clause.
    #[must_use]
    pub fn join(
        mut self,
        kind: impl Into<String>,
        table: impl Into<String>,
        condition: impl Into<String>,
    ) -> Self {
        self.parts.push(QueryPart::Join {
            kind: kind.into(),
            table: table.into(),
            condition: condition.into(),
        });
        self
    }

    /// Add a bound parameter value.
    #[must_use]
    pub fn param(mut self, v: impl Into<SqlValue>) -> Self {
        self.params.push(v);
        self
    }

    /// Add multiple bound parameter values.
    #[must_use]
    pub fn params(mut self, values: impl IntoIterator<Item = impl Into<SqlValue>>) -> Self {
        for v in values {
            self.params.push(v);
        }
        self
    }

    /// For UPDATE: add a SET column=value pair.
    #[must_use]
    pub fn set(mut self, column: impl Into<String>, value: impl Into<SqlValue>) -> Self {
        self.set_clauses.push((column.into(), value.into()));
        self
    }

    /// Compile the query into a [`CompiledQuery`].
    ///
    /// # Errors
    ///
    /// Returns [`QueryBuilderError::NoTable`] if no table was set.
    pub fn build(self) -> Result<CompiledQuery, QueryBuilderError> {
        let table = self.table.as_deref().ok_or(QueryBuilderError::NoTable)?;
        let mut params = self.params.clone();

        let sql = match self.query_kind {
            QueryKind::Select => self.build_select_sql(table),
            QueryKind::Insert => self.build_insert_sql(table, &mut params),
            QueryKind::Update => self.build_update_sql(table, &mut params),
            QueryKind::Delete => self.build_delete_sql(table),
        };

        Ok(CompiledQuery { sql, params })
    }

    fn build_select_sql(&self, table: &str) -> String {
        let cols = if self.columns.is_empty() {
            "*".to_string()
        } else {
            self.columns.join(", ")
        };
        let mut parts_sql: Vec<String> = vec![
            format!("SELECT {cols}"),
            format!("FROM {table}"),
        ];
        for part in &self.parts {
            match part {
                QueryPart::Join { .. }
                | QueryPart::Where(_)
                | QueryPart::WhereAnd(_)
                | QueryPart::WhereOr(_)
                | QueryPart::GroupBy(_)
                | QueryPart::Having(_)
                | QueryPart::OrderBy { .. }
                | QueryPart::Limit(_)
                | QueryPart::Offset(_) => {
                    parts_sql.push(part.to_string());
                }
                _ => {}
            }
        }
        parts_sql.join(" ")
    }

    fn build_insert_sql(&self, table: &str, _params: &mut QueryParams) -> String {
        if self.columns.is_empty() {
            return format!("INSERT INTO {table} DEFAULT VALUES");
        }
        let col_list = self.columns.join(", ");
        let placeholders: Vec<&str> = self.columns.iter().map(|_| "?").collect();
        // For INSERT we expect params to already be set via .param()
        format!(
            "INSERT INTO {table} ({col_list}) VALUES ({})",
            placeholders.join(", ")
        )
    }

    fn build_update_sql(&self, table: &str, params: &mut QueryParams) -> String {
        // SET values must bind *before* the WHERE parameters that were added
        // via `.param()` / `.params()`. Build a fresh param list: set-clause
        // values first, then the caller-supplied params (WHERE bindings).
        let mut ordered = QueryParams::new();
        let set_parts: Vec<String> = self.set_clauses.iter().map(|(col, val)| {
            ordered.push(val.clone());
            format!("{col} = ?")
        }).collect();
        // Append original params (WHERE bindings) after the SET values.
        for v in params.values() {
            ordered.push(v.clone());
        }
        *params = ordered;

        let mut sql = format!("UPDATE {table} SET {}", set_parts.join(", "));
        for part in &self.parts {
            if matches!(part, QueryPart::Where(_) | QueryPart::WhereAnd(_) | QueryPart::WhereOr(_)) {
                sql.push(' ');
                sql.push_str(&part.to_string());
            }
        }
        sql
    }

    fn build_delete_sql(&self, table: &str) -> String {
        let mut sql = format!("DELETE FROM {table}");
        for part in &self.parts {
            if matches!(part, QueryPart::Where(_) | QueryPart::WhereAnd(_) | QueryPart::WhereOr(_)) {
                sql.push(' ');
                sql.push_str(&part.to_string());
            }
        }
        sql
    }
}

// ---------------------------------------------------------------------------
// build_select — primary entry point
// ---------------------------------------------------------------------------

/// Build a simple SELECT query for the given table and optional conditions.
///
/// # Errors
///
/// Returns [`QueryBuilderError::NoTable`] if `table` is empty.
pub fn build_select(
    table: &str,
    columns: &[&str],
    conditions: &[&str],
    params: Vec<SqlValue>,
    limit: Option<u64>,
) -> Result<CompiledQuery, QueryBuilderError> {
    if table.is_empty() {
        return Err(QueryBuilderError::NoTable);
    }
    let mut builder = DbQueryBuilder::select()
        .from(table)
        .columns(columns.iter().copied());

    for cond in conditions {
        builder = builder.where_clause(*cond);
    }
    for p in params {
        builder = builder.param(p);
    }
    if let Some(n) = limit {
        builder = builder.limit(n);
    }
    builder.build()
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

impl DbQueryBuilder {
    /// Create a simple count query: `SELECT COUNT(*) FROM table WHERE ...`
    #[must_use]
    pub fn count(table: impl Into<String>) -> Self {
        Self::select().from(table).columns(["COUNT(*)"])
    }

    /// Create an exists-check query: `SELECT 1 FROM table WHERE ... LIMIT 1`
    #[must_use]
    pub fn exists(table: impl Into<String>) -> Self {
        Self::select().from(table).columns(["1"]).limit(1)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_select_all_columns() {
        let q = build_select("functions", &[], &[], vec![], None).unwrap();
        assert!(q.sql.contains("SELECT *"));
        assert!(q.sql.contains("FROM functions"));
    }

    #[test]
    fn test_build_select_specific_columns() {
        let q = build_select("functions", &["id", "name"], &[], vec![], None).unwrap();
        assert!(q.sql.contains("SELECT id, name"));
    }

    #[test]
    fn test_build_select_with_condition() {
        let q = build_select(
            "functions",
            &["*"],
            &["address > ?"],
            vec![SqlValue::Integer(0x1000)],
            Some(100),
        ).unwrap();
        assert!(q.sql.contains("WHERE address > ?"));
        assert!(q.sql.contains("LIMIT 100"));
        assert_eq!(q.params.len(), 1);
    }

    #[test]
    fn test_build_select_no_table_error() {
        let err = build_select("", &[], &[], vec![], None);
        assert!(err.is_err());
    }

    #[test]
    fn test_builder_select_basic() {
        let q = DbQueryBuilder::select()
            .from("symbols")
            .columns(["name", "address"])
            .where_clause("kind = ?")
            .param("function")
            .order_by("address", OrderDirection::Asc)
            .limit(50)
            .build()
            .unwrap();
        assert!(q.sql.contains("SELECT name, address"));
        assert!(q.sql.contains("FROM symbols"));
        assert!(q.sql.contains("WHERE kind = ?"));
        assert!(q.sql.contains("ORDER BY address ASC"));
        assert!(q.sql.contains("LIMIT 50"));
    }

    #[test]
    fn test_builder_where_and() {
        let q = DbQueryBuilder::select()
            .from("t")
            .where_and(["a = ?", "b = ?"])
            .params([SqlValue::Integer(1), SqlValue::Integer(2)])
            .build()
            .unwrap();
        assert!(q.sql.contains("WHERE (a = ?) AND (b = ?)"));
        assert_eq!(q.params.len(), 2);
    }

    #[test]
    fn test_builder_where_or() {
        let q = DbQueryBuilder::select()
            .from("t")
            .where_or(["a = ?", "b = ?"])
            .build()
            .unwrap();
        assert!(q.sql.contains("WHERE (a = ?) OR (b = ?)"));
    }

    #[test]
    fn test_builder_delete() {
        let q = DbQueryBuilder::delete()
            .from("functions")
            .where_clause("id = ?")
            .param(42i64)
            .build()
            .unwrap();
        assert!(q.sql.starts_with("DELETE FROM functions"));
        assert!(q.sql.contains("WHERE id = ?"));
    }

    #[test]
    fn test_builder_update() {
        let q = DbQueryBuilder::update()
            .from("functions")
            .set("name", "renamed")
            .where_clause("id = ?")
            .param(1i64)
            .build()
            .unwrap();
        assert!(q.sql.contains("UPDATE functions"));
        assert!(q.sql.contains("SET name = ?"));
        assert!(q.sql.contains("WHERE id = ?"));
    }

    #[test]
    fn test_builder_insert() {
        let q = DbQueryBuilder::insert()
            .from("symbols")
            .columns(["name", "address", "kind"])
            .param("main")
            .param(0x1000u64)
            .param("function")
            .build()
            .unwrap();
        assert!(q.sql.starts_with("INSERT INTO symbols"));
        assert!(q.sql.contains("(name, address, kind)"));
        assert!(q.sql.contains("VALUES (?, ?, ?)"));
    }

    #[test]
    fn test_count_query() {
        let q = DbQueryBuilder::count("functions")
            .where_clause("size > ?")
            .param(0i64)
            .build()
            .unwrap();
        assert!(q.sql.contains("SELECT COUNT(*)"));
    }

    #[test]
    fn test_exists_query() {
        let q = DbQueryBuilder::exists("functions")
            .where_clause("id = ?")
            .param(99i64)
            .build()
            .unwrap();
        assert!(q.sql.contains("LIMIT 1"));
    }

    #[test]
    fn test_join_query() {
        let q = DbQueryBuilder::select()
            .from("functions")
            .columns(["functions.name", "symbols.address"])
            .join("INNER", "symbols", "functions.id = symbols.func_id")
            .build()
            .unwrap();
        assert!(q.sql.contains("INNER JOIN symbols ON functions.id = symbols.func_id"));
    }

    #[test]
    fn test_group_by_having() {
        let q = DbQueryBuilder::select()
            .from("calls")
            .columns(["callee", "COUNT(*) as cnt"])
            .group_by("callee")
            .having("cnt > ?")
            .param(5i64)
            .build()
            .unwrap();
        assert!(q.sql.contains("GROUP BY callee"));
        assert!(q.sql.contains("HAVING cnt > ?"));
    }

    #[test]
    fn test_sql_value_types() {
        assert_eq!(SqlValue::Null.type_name(), "NULL");
        assert_eq!(SqlValue::Integer(1).type_name(), "INTEGER");
        assert_eq!(SqlValue::Float(1.0).type_name(), "REAL");
        assert_eq!(SqlValue::Text("x".into()).type_name(), "TEXT");
        assert_eq!(SqlValue::Blob(vec![]).type_name(), "BLOB");
    }

    #[test]
    fn test_compiled_query_validate_ok() {
        let q = build_select("t", &[], &["id = ?"], vec![SqlValue::Integer(1)], None).unwrap();
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_compiled_query_validate_mismatch() {
        let q = CompiledQuery {
            sql: "SELECT * FROM t WHERE id = ? AND name = ?".to_string(),
            params: QueryParams::new().with(1i64),
        };
        let err = q.validate();
        assert!(err.is_err());
    }

    #[test]
    fn test_order_direction_display() {
        assert_eq!(OrderDirection::Asc.to_string(), "ASC");
        assert_eq!(OrderDirection::Desc.to_string(), "DESC");
    }
}
