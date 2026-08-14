use mysql::prelude::Queryable;

/// Dialect tag so schema generation can pick the right SQL syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbDialect {
    Sqlite,
    Mysql,
}

// ---------------------------------------------------------------------------
// GraphParam – query parameter type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum GraphParam {
    Int(i64),
    Real(f64),
    Bool(bool),
    Text(String),
    Blob(Vec<u8>),
    Null,
}

impl rusqlite::types::ToSql for GraphParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            Self::Int(i) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(*i),
            )),
            Self::Real(f) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Real(*f),
            )),
            Self::Bool(b) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(i64::from(*b)),
            )),
            Self::Text(s) => Ok(rusqlite::types::ToSqlOutput::Borrowed(
                rusqlite::types::ValueRef::Text(s.as_bytes()),
            )),
            Self::Blob(b) => Ok(rusqlite::types::ToSqlOutput::Borrowed(
                rusqlite::types::ValueRef::Blob(b),
            )),
            Self::Null => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Null,
            )),
        }
    }
}

impl From<GraphParam> for mysql::Value {
    fn from(param: GraphParam) -> Self {
        match param {
            GraphParam::Int(i) => Self::Int(i),
            GraphParam::Real(f) => Self::Double(f),
            GraphParam::Bool(b) => Self::Int(i64::from(b)),
            GraphParam::Text(s) => Self::Bytes(s.into_bytes()),
            GraphParam::Blob(b) => Self::Bytes(b),
            GraphParam::Null => Self::NULL,
        }
    }
}

// ---------------------------------------------------------------------------
// GraphValue – a typed value returned from queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum GraphValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl GraphValue {
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }
 #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Self::Blob(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Real(f) => Some(*f),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

// ---------------------------------------------------------------------------
// GraphError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("MySQL error: {0}")]
    Mysql(#[from] mysql::Error),
    #[error("Database error: {0}")]
    Generic(String),
}

// ---------------------------------------------------------------------------
// DatabaseEngine trait
// ---------------------------------------------------------------------------

pub trait DatabaseEngine: Send + Sync {
    /// Return the SQL dialect in use.
    fn dialect(&self) -> DbDialect;

    /// Execute a DML/DDL statement and return the number of affected rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn execute(&self, query: &str, params: &[GraphParam]) -> Result<usize, GraphError>;

    /// Return the first column of the first row as a `String`, or `None`.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn query_row_string(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Option<String>, GraphError>;

    /// Return the first column of the first row as an `i64`, or `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn query_row_i64(&self, query: &str, params: &[GraphParam]) -> Result<Option<i64>, GraphError>;

    /// Return all rows as `Vec<Vec<Option<String>>>` (each cell coerced to string).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn query_rows_strings(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<Option<String>>>, GraphError>;

    /// Return all rows as `Vec<Vec<GraphValue>>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn query_rows_mixed(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<GraphValue>>, GraphError>;

    /// Return column names and all rows as `(Vec<String>, Vec<Vec<GraphValue>>)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn query_rows_with_columns(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<(Vec<String>, Vec<Vec<GraphValue>>), GraphError>;

    /// Return the ROWID / `AUTO_INCREMENT` id of the last successful INSERT.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn last_insert_id(&self) -> Result<i64, GraphError>;

    /// Begin a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn begin_transaction(&self) -> Result<(), GraphError>;

    /// Commit the current transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn commit_transaction(&self) -> Result<(), GraphError>;

    /// Roll back the current transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn rollback_transaction(&self) -> Result<(), GraphError>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert positional SQLite-style `?1 .. ?20` placeholders to bare `?` for
/// `MySQL`. The replacement is done in reverse-index order so that `?10` is
/// replaced before `?1`.
pub(crate) fn clean_query_for_mysql(query: &str) -> String {
    let upserted = rewrite_insert_or_replace_for_mysql(query)
        .unwrap_or_else(|| query.replace("INSERT OR REPLACE", "REPLACE"));
    let indexed_placeholders = strip_indexed_placeholders(&upserted);
    rewrite_mysql_index_prefixes(&indexed_placeholders)
}

fn strip_indexed_placeholders(query: &str) -> String {
    let mut cleaned = String::with_capacity(query.len());
    let mut chars = query.chars().peekable();
    let mut quote = None;

    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            cleaned.push(ch);
            if ch == '\\' && q != '`' {
                if let Some(next) = chars.next() {
                    cleaned.push(next);
                }
            } else if ch == q {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' | '`' => {
                quote = Some(ch);
                cleaned.push(ch);
            }
            '?' => {
                while matches!(chars.peek(), Some(next) if next.is_ascii_digit()) {
                    chars.next();
                }
                cleaned.push('?');
            }
            _ => cleaned.push(ch),
        }
    }

    cleaned
}

fn rewrite_insert_or_replace_for_mysql(query: &str) -> Option<String> {
    const PREFIX: &str = "INSERT OR REPLACE INTO ";
    let trimmed_start = query.trim_start();
    let prefix_len = query.len() - trimmed_start.len();
    let upper = trimmed_start.to_ascii_uppercase();
    if !upper.starts_with(PREFIX) {
        return None;
    }

    let after_into = &trimmed_start[PREFIX.len()..];
    let columns_start = after_into.find('(')?;
    let table_name = after_into[..columns_start].trim();
    if table_name.is_empty() {
        return None;
    }

    let columns_end = find_matching_paren(after_into, columns_start)?;
    let columns_raw = &after_into[columns_start + 1..columns_end];
    let columns: Vec<&str> = columns_raw
        .split(',')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .collect();
    if columns.is_empty() {
        return None;
    }

    let rest = after_into[columns_end + 1..].trim_end();
    let rest = rest.strip_suffix(';').unwrap_or(rest).trim_end();
    if !rest.trim_start().to_ascii_uppercase().starts_with("VALUES") {
        return None;
    }

    let update_columns: Vec<&str> = columns.iter().copied().skip(1).collect();
    if update_columns.is_empty() {
        return None;
    }

    let leading_ws = &query[..prefix_len];
    let assignments = update_columns
        .iter()
        .map(|column| format!("{column} = VALUES({column})"))
        .collect::<Vec<_>>()
        .join(", ");

    Some(format!(
        "{leading_ws}INSERT INTO {table_name} ({columns_raw}){rest} ON DUPLICATE KEY UPDATE {assignments}"
    ))
}

fn find_matching_paren(s: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0_usize;
    let mut quote = None;

    for (idx, ch) in s.char_indices().skip_while(|(idx, _)| *idx < open_idx) {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }

    None
}

fn rewrite_mysql_index_prefixes(query: &str) -> String {
    query.replace(
        "CREATE INDEX idx_symbols_name ON symbols(name)",
        "CREATE INDEX idx_symbols_name ON symbols(name(255))",
    )
}

fn mysql_params(params: &[GraphParam]) -> mysql::Params {
    mysql::Params::Positional(params.iter().cloned().map(mysql::Value::from).collect())
}

// ---------------------------------------------------------------------------
// SqliteEngine
// ---------------------------------------------------------------------------

pub struct SqliteEngine {
    conn: parking_lot::Mutex<rusqlite::Connection>,
    /// Tracks whether we are inside an explicit transaction.
    in_txn: parking_lot::Mutex<bool>,
}

impl SqliteEngine {
    pub const fn new(conn: rusqlite::Connection) -> Self {
        Self {
            conn: parking_lot::Mutex::new(conn),
            in_txn: parking_lot::Mutex::new(false),
        }
    }
}

impl DatabaseEngine for SqliteEngine {
    fn dialect(&self) -> DbDialect {
        DbDialect::Sqlite
    }

    fn execute(&self, query: &str, params: &[GraphParam]) -> Result<usize, GraphError> {
        let rparams: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = self.conn.lock().execute(query, rusqlite::params_from_iter(rparams))?;
        Ok(rows)
    }

    fn query_row_string(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Option<String>, GraphError> {
        let rparams: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();
        {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(query)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(rparams))?;
            if let Some(row) = rows.next()? {
                let val: Option<String> = row.get(0)?;
                Ok(val)
            } else {
                Ok(None)
            }
        }
    }

    fn query_row_i64(&self, query: &str, params: &[GraphParam]) -> Result<Option<i64>, GraphError> {
        let rparams: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();
        {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(query)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(rparams))?;
            if let Some(row) = rows.next()? {
                let val: Option<i64> = row.get(0)?;
                Ok(val)
            } else {
                Ok(None)
            }
        }
    }

    fn query_rows_strings(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<Option<String>>>, GraphError> {
        let mut rparams: Vec<&dyn rusqlite::types::ToSql> = Vec::with_capacity(params.len());
        rparams.extend(params.iter().map(|p| p as &dyn rusqlite::types::ToSql));
        {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(query)?;
            let col_count = stmt.column_count();
            let mut rows = stmt.query(rusqlite::params_from_iter(rparams))?;
            let mut result: Vec<Vec<Option<String>>> = Vec::new();
            while let Some(row) = rows.next()? {
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let v = match row.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => None,
                        rusqlite::types::ValueRef::Integer(n) => Some(n.to_string()),
                        rusqlite::types::ValueRef::Real(f) => Some(f.to_string()),
                        rusqlite::types::ValueRef::Text(b) => {
                            Some(String::from_utf8_lossy(b).into_owned())
                        }
                        rusqlite::types::ValueRef::Blob(b) => Some(format!("<blob {} bytes>", b.len())),
                    };
                    record.push(v);
                }
                result.push(record);
            }
            Ok(result)
        }
    }

    fn query_rows_mixed(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<GraphValue>>, GraphError> {
        let mut rparams: Vec<&dyn rusqlite::types::ToSql> = Vec::with_capacity(params.len());
        rparams.extend(params.iter().map(|p| p as &dyn rusqlite::types::ToSql));
        {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(query)?;
            let col_count = stmt.column_count();
            let mut rows = stmt.query(rusqlite::params_from_iter(rparams))?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let gv = match row.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => GraphValue::Null,
                        rusqlite::types::ValueRef::Integer(n) => GraphValue::Integer(n),
                        rusqlite::types::ValueRef::Real(f) => GraphValue::Real(f),
                        rusqlite::types::ValueRef::Text(b) => {
                            GraphValue::Text(String::from_utf8_lossy(b).into_owned())
                        }
                        rusqlite::types::ValueRef::Blob(b) => GraphValue::Blob(b.to_vec()),
                    };
                    record.push(gv);
                }
                result.push(record);
            }
            Ok(result)
        }
    }

    fn query_rows_with_columns(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<(Vec<String>, Vec<Vec<GraphValue>>), GraphError> {
        let mut rparams: Vec<&dyn rusqlite::types::ToSql> = Vec::with_capacity(params.len());
        rparams.extend(params.iter().map(|p| p as &dyn rusqlite::types::ToSql));
        {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(query)?;
            let names = stmt.column_names();
            let mut col_names: Vec<String> = Vec::with_capacity(names.len());
            col_names.extend(names.into_iter().map(std::string::ToString::to_string));
            let col_count = col_names.len();
            let mut rows = stmt.query(rusqlite::params_from_iter(rparams))?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let gv = match row.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => GraphValue::Null,
                        rusqlite::types::ValueRef::Integer(n) => GraphValue::Integer(n),
                        rusqlite::types::ValueRef::Real(f) => GraphValue::Real(f),
                        rusqlite::types::ValueRef::Text(b) => {
                            GraphValue::Text(String::from_utf8_lossy(b).into_owned())
                        }
                        rusqlite::types::ValueRef::Blob(b) => GraphValue::Blob(b.to_vec()),
                    };
                    record.push(gv);
                }
                result.push(record);
            }
            Ok((col_names, result))
        }
    }

    fn last_insert_id(&self) -> Result<i64, GraphError> {
        Ok(self.conn.lock().last_insert_rowid())
    }

    fn begin_transaction(&self) -> Result<(), GraphError> {
        let mut in_txn = self.in_txn.lock();
        if !*in_txn {
            self.conn.lock().execute_batch("BEGIN")?;
            *in_txn = true;
        }
        Ok(())
    }

    fn commit_transaction(&self) -> Result<(), GraphError> {
        let mut in_txn = self.in_txn.lock();
        if *in_txn {
            self.conn.lock().execute_batch("COMMIT")?;
            *in_txn = false;
        }
        Ok(())
    }

    fn rollback_transaction(&self) -> Result<(), GraphError> {
        let mut in_txn = self.in_txn.lock();
        if *in_txn {
            self.conn.lock().execute_batch("ROLLBACK")?;
            *in_txn = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MysqlEngine
// ---------------------------------------------------------------------------

pub struct MysqlEngine {
    pool: mysql::Pool,
    txn_conn: parking_lot::Mutex<Option<mysql::PooledConn>>,
    last_id: parking_lot::Mutex<i64>,
}

impl MysqlEngine {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new(url: &str) -> Result<Self, GraphError> {
        let pool = mysql::Pool::new(url)?;
        Ok(Self {
            pool,
            txn_conn: parking_lot::Mutex::new(None),
            last_id: parking_lot::Mutex::new(0),
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut mysql::PooledConn) -> Result<T, GraphError>,
    ) -> Result<T, GraphError> {
        let mut txn_conn = self.txn_conn.lock();
        if let Some(conn) = txn_conn.as_mut() {
            return f(conn);
        }
        drop(txn_conn);

        let mut conn = self.pool.get_conn()?;
        f(&mut conn)
    }
}

impl DatabaseEngine for MysqlEngine {
    fn dialect(&self) -> DbDialect {
        DbDialect::Mysql
    }

    fn execute(&self, query: &str, params: &[GraphParam]) -> Result<usize, GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            let affected = usize::try_from(result.affected_rows()).unwrap_or(usize::MAX);
            let id = i64::try_from(result.last_insert_id().unwrap_or(0)).unwrap_or(i64::MAX);
            *self.last_id.lock() = id;
            Ok(affected)
        })
    }

    fn query_row_string(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Option<String>, GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            for row_result in result {
                let row = row_result?;
                if let Some(val) = row.get::<Option<String>, _>(0) {
                    return Ok(val);
                }
            }
            Ok(None)
        })
    }

    fn query_row_i64(&self, query: &str, params: &[GraphParam]) -> Result<Option<i64>, GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            for row_result in result {
                let row = row_result?;
                if let Some(val) = row.get::<Option<i64>, _>(0) {
                    return Ok(val);
                }
            }
            Ok(None)
        })
    }

    fn query_rows_strings(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<Option<String>>>, GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            let col_count = result.columns().as_ref().len();
            let mut out = Vec::new();
            for row_result in result {
                let row = row_result?;
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let v: Option<String> = match row.get::<mysql::Value, _>(i) {
                        Some(mysql::Value::NULL) | None => None,
                        Some(mysql::Value::Bytes(b)) => {
                            Some(String::from_utf8_lossy(&b).into_owned())
                        }
                        Some(mysql::Value::Int(n)) => Some(n.to_string()),
                        Some(mysql::Value::UInt(n)) => Some(n.to_string()),
                        Some(mysql::Value::Float(f)) => Some(f.to_string()),
                        Some(mysql::Value::Double(f)) => Some(f.to_string()),
                        Some(other) => Some(format!("{other:?}")),
                    };
                    record.push(v);
                }
                out.push(record);
            }
            Ok(out)
        })
    }

    fn query_rows_mixed(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<Vec<Vec<GraphValue>>, GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            let col_count = result.columns().as_ref().len();
            let mut out = Vec::new();
            for row_result in result {
                let row = row_result?;
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let gv = match row.get::<mysql::Value, _>(i) {
                        Some(mysql::Value::NULL) | None => GraphValue::Null,
                        Some(mysql::Value::Int(n)) => GraphValue::Integer(n),
                        Some(mysql::Value::UInt(n)) => GraphValue::Integer(n.cast_signed()),
                        Some(mysql::Value::Float(f)) => GraphValue::Real(f64::from(f)),
                        Some(mysql::Value::Double(f)) => GraphValue::Real(f),
                        Some(mysql::Value::Bytes(b)) => match String::from_utf8(b.clone()) {
                            Ok(s) => GraphValue::Text(s),
                            Err(_) => GraphValue::Blob(b),
                        },
                        Some(other) => GraphValue::Text(format!("{other:?}")),
                    };
                    record.push(gv);
                }
                out.push(record);
            }
            Ok(out)
        })
    }

    fn query_rows_with_columns(
        &self,
        query: &str,
        params: &[GraphParam],
    ) -> Result<(Vec<String>, Vec<Vec<GraphValue>>), GraphError> {
        self.with_conn(|conn| {
            let cleaned = clean_query_for_mysql(query);
            let result = conn.exec_iter(cleaned, mysql_params(params))?;
            let col_names: Vec<String> = result
                .columns()
                .as_ref()
                .iter()
                .map(|c| c.name_str().to_string())
                .collect();
            let col_count = col_names.len();
            let mut out = Vec::new();
            for row_result in result {
                let row = row_result?;
                let mut record = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let gv = match row.get::<mysql::Value, _>(i) {
                        Some(mysql::Value::NULL) | None => GraphValue::Null,
                        Some(mysql::Value::Int(n)) => GraphValue::Integer(n),
                        Some(mysql::Value::UInt(n)) => GraphValue::Integer(n.cast_signed()),
                        Some(mysql::Value::Float(f)) => GraphValue::Real(f64::from(f)),
                        Some(mysql::Value::Double(f)) => GraphValue::Real(f),
                        Some(mysql::Value::Bytes(b)) => match String::from_utf8(b.clone()) {
                            Ok(s) => GraphValue::Text(s),
                            Err(_) => GraphValue::Blob(b),
                        },
                        Some(other) => GraphValue::Text(format!("{other:?}")),
                    };
                    record.push(gv);
                }
                out.push(record);
            }
            Ok((col_names, out))
        })
    }

    fn last_insert_id(&self) -> Result<i64, GraphError> {
        Ok(*self.last_id.lock())
    }

    fn begin_transaction(&self) -> Result<(), GraphError> {
        let mut txn_conn = self.txn_conn.lock();
        if txn_conn.is_none() {
            let mut conn = self.pool.get_conn()?;
            conn.exec_drop("START TRANSACTION", mysql::Params::Empty)?;
            *txn_conn = Some(conn);
        }
        Ok(())
    }

    fn commit_transaction(&self) -> Result<(), GraphError> {
        let maybe_conn = self.txn_conn.lock().take();
        if let Some(mut conn) = maybe_conn {
            conn.exec_drop("COMMIT", mysql::Params::Empty)?;
        }
        Ok(())
    }

    fn rollback_transaction(&self) -> Result<(), GraphError> {
        let maybe_conn = self.txn_conn.lock().take();
        if let Some(mut conn) = maybe_conn {
            conn.exec_drop("ROLLBACK", mysql::Params::Empty)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_engine() -> SqliteEngine {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        SqliteEngine::new(conn)
    }

    #[test]
    fn test_dialect() {
        let engine = sqlite_engine();
        assert_eq!(engine.dialect(), DbDialect::Sqlite);
    }

    #[test]
    fn test_execute_and_query_row_string() {
        let engine = sqlite_engine();
        engine
            .execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", &[])
            .unwrap();
        engine
            .execute(
                "INSERT INTO t (name) VALUES (?1)",
                &[GraphParam::Text("hello".into())],
            )
            .unwrap();
        let v = engine
            .query_row_string("SELECT name FROM t WHERE id = ?1", &[GraphParam::Int(1)])
            .unwrap();
        assert_eq!(v, Some("hello".into()));
    }

    #[test]
    fn test_query_row_i64() {
        let engine = sqlite_engine();
        engine
            .execute("CREATE TABLE nums (v INTEGER)", &[])
            .unwrap();
        engine
            .execute("INSERT INTO nums VALUES (?1)", &[GraphParam::Int(42)])
            .unwrap();
        let v = engine.query_row_i64("SELECT v FROM nums", &[]).unwrap();
        assert_eq!(v, Some(42));
    }

    #[test]
    fn test_query_rows_mixed() {
        let engine = sqlite_engine();
        engine
            .execute("CREATE TABLE mixed (a INTEGER, b TEXT, c REAL)", &[])
            .unwrap();
        engine
            .execute(
                "INSERT INTO mixed VALUES (?1, ?2, ?3)",
                &[
                    GraphParam::Int(7),
                    GraphParam::Text("foo".into()),
                    GraphParam::Real(std::f64::consts::PI),
                ],
            )
            .unwrap();
        let rows = engine
            .query_rows_mixed("SELECT a, b, c FROM mixed", &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], GraphValue::Integer(7));
        assert_eq!(rows[0][1], GraphValue::Text("foo".into()));
        match &rows[0][2] {
            GraphValue::Real(f) => assert!((*f - std::f64::consts::PI).abs() < 1e-9),
            other => panic!("expected Real, got {other:?}"),
        }
    }

    #[test]
    fn test_last_insert_id() {
        let engine = sqlite_engine();
        engine
            .execute("CREATE TABLE seq (id INTEGER PRIMARY KEY, v TEXT)", &[])
            .unwrap();
        engine
            .execute(
                "INSERT INTO seq (v) VALUES (?1)",
                &[GraphParam::Text("a".into())],
            )
            .unwrap();
        let id = engine.last_insert_id().unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn test_transaction_commit() {
        let engine = sqlite_engine();
        engine.execute("CREATE TABLE tx (v INTEGER)", &[]).unwrap();
        engine.begin_transaction().unwrap();
        engine
            .execute("INSERT INTO tx VALUES (?1)", &[GraphParam::Int(100)])
            .unwrap();
        engine.commit_transaction().unwrap();
        let v = engine.query_row_i64("SELECT v FROM tx", &[]).unwrap();
        assert_eq!(v, Some(100));
    }

    #[test]
    fn test_transaction_rollback() {
        let engine = sqlite_engine();
        engine.execute("CREATE TABLE txr (v INTEGER)", &[]).unwrap();
        engine.begin_transaction().unwrap();
        engine
            .execute("INSERT INTO txr VALUES (?1)", &[GraphParam::Int(99)])
            .unwrap();
        engine.rollback_transaction().unwrap();
        let v = engine.query_row_i64("SELECT v FROM txr", &[]).unwrap();
        assert_eq!(v, None);
    }

    #[test]
    fn test_graph_param_real_and_bool() {
        let engine = sqlite_engine();
        engine
            .execute("CREATE TABLE params_test (r REAL, b INTEGER)", &[])
            .unwrap();
        engine
            .execute(
                "INSERT INTO params_test VALUES (?1, ?2)",
                &[GraphParam::Real(2.71), GraphParam::Bool(true)],
            )
            .unwrap();
        let rows = engine
            .query_rows_mixed("SELECT r, b FROM params_test", &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        match &rows[0][0] {
            GraphValue::Real(f) => assert!((*f - 2.71).abs() < 1e-9),
            other => panic!("expected Real, got {other:?}"),
        }
        assert_eq!(rows[0][1], GraphValue::Integer(1));
    }

    #[test]
    fn test_clean_query_for_mysql() {
        let q = clean_query_for_mysql("SELECT * FROM t WHERE a = ?1 AND b = ?2 AND c = ?10");
        // ?10 must be replaced before ?1, so no "?0" artifacts
        assert!(!q.contains("?1"));
        assert!(!q.contains("?2"));
        assert!(!q.contains("?10"));
        assert_eq!(q.matches('?').count(), 3);
    }

    #[test]
    fn test_clean_query_for_mysql_handles_large_placeholders_and_literals() {
        let q =
            clean_query_for_mysql("SELECT '?123' AS literal, col FROM t WHERE a = ?1 AND z = ?123");
        assert!(q.contains("'?123'"));
        assert!(q.contains("a = ? AND z = ?"));
        assert_eq!(q.matches('?').count(), 3);
    }

    #[test]
    fn test_clean_query_for_mysql_rewrites_insert_or_replace_as_upsert() {
        let q = clean_query_for_mysql(
            "INSERT OR REPLACE INTO views (id, uri, arch, endian, bits, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
        );
        assert!(q.starts_with("INSERT INTO views"));
        assert!(q.contains("ON DUPLICATE KEY UPDATE"));
        assert!(q.contains("uri = VALUES(uri)"));
        assert!(!q.contains("INSERT OR REPLACE"));
        assert!(!q.contains("; ON DUPLICATE KEY UPDATE"));
        assert_eq!(q.matches('?').count(), 6);
    }

    #[test]
    fn test_clean_query_for_mysql_rewrites_text_index_prefix() {
        let q = clean_query_for_mysql("CREATE INDEX idx_symbols_name ON symbols(name)");
        assert_eq!(q, "CREATE INDEX idx_symbols_name ON symbols(name(255))");
    }

    #[test]
    fn test_null_param() {
        let engine = sqlite_engine();
        engine.execute("CREATE TABLE nulls (v TEXT)", &[]).unwrap();
        engine
            .execute("INSERT INTO nulls VALUES (?1)", &[GraphParam::Null])
            .unwrap();
        let rows = engine.query_rows_mixed("SELECT v FROM nulls", &[]).unwrap();
        assert_eq!(rows[0][0], GraphValue::Null);
    }
}
