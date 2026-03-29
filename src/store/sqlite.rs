use std::ops::DerefMut;
use std::path::Path;
use std::time::Duration;

use rusqlite::OptionalExtension;

use db_vfs_core::{Error, Result};

use super::{DeleteOutcome, FileMeta, Store, db_err, make_prefix_bounds, monotonic_updated_at_ms};

pub struct SqliteStoreWithConn<C> {
    conn: C,
}

pub type SqliteStore<C = Box<rusqlite::Connection>> = SqliteStoreWithConn<C>;

impl SqliteStoreWithConn<Box<rusqlite::Connection>> {
    pub fn new(conn: rusqlite::Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(map_sqlite_err)?;
        crate::migrations::migrate_sqlite(&conn).map_err(map_sqlite_err)?;
        Ok(Self {
            conn: Box::new(conn),
        })
    }

    pub fn new_no_migrate(conn: rusqlite::Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(map_sqlite_err)?;
        Ok(Self {
            conn: Box::new(conn),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path).map_err(db_err)?;
        Self::new(conn)
    }

    pub fn open_no_migrate(path: impl AsRef<Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path).map_err(db_err)?;
        Self::new_no_migrate(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory().map_err(db_err)?;
        Self::new(conn)
    }
}

impl<C> SqliteStoreWithConn<C> {
    pub fn from_connection(conn: C) -> Self {
        Self { conn }
    }
}

impl<C> Store for SqliteStoreWithConn<C>
where
    C: DerefMut<Target = rusqlite::Connection>,
{
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT size_bytes, version, updated_at_ms
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2",
            )
            .map_err(map_sqlite_err)?;

        let row = stmt
            .query_row(rusqlite::params![workspace_id, path], |row| {
                Ok((
                    i64_to_u64_sql(row.get::<_, i64>(0)?, "size_bytes", 0)?,
                    i64_to_u64_sql(row.get::<_, i64>(1)?, "version", 1)?,
                    i64_to_u64_sql(row.get::<_, i64>(2)?, "updated_at_ms", 2)?,
                ))
            })
            .optional()
            .map_err(map_sqlite_err)?;

        row.map(|(size_bytes, version, updated_at_ms)| {
            FileMeta {
                path: path.to_string(),
                size_bytes,
                version,
                updated_at_ms,
            }
            .validated()
        })
        .transpose()
    }

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> Result<Option<String>> {
        let version = u64_to_i64(version, "version")?;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT content
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2 AND version = ?3",
            )
            .map_err(map_sqlite_err)?;

        stmt.query_row(rusqlite::params![workspace_id, path, version], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(map_sqlite_err)
    }

    fn get_content_chunk(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_char: u64,
        max_chars: usize,
    ) -> Result<Option<String>> {
        if max_chars == 0 {
            return Ok(Some(String::new()));
        }

        let version = u64_to_i64(version, "version")?;
        let start_char = u64_to_i64(start_char, "start_char")?;
        let max_chars = usize_to_i64(max_chars, "max_chars")?;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT substr(content, ?4, ?5)
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2 AND version = ?3",
            )
            .map_err(map_sqlite_err)?;

        stmt.query_row(
            rusqlite::params![workspace_id, path, version, start_char, max_chars],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_err)
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> Result<u64> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_sqlite_err)?;
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;

        let (current_version, last_version) =
            load_current_versions_sqlite(&tx, workspace_id, path).map_err(map_sqlite_err)?;
        if current_version.is_some() {
            return Err(Error::Conflict("file exists".to_string()));
        }

        let version = super::next_version(i64_to_u64(last_version.unwrap_or(0), "last_version")?)?;
        let version_i64 = u64_to_i64(version, "version")?;
        persist_generation_sqlite(&tx, workspace_id, path, version_i64).map_err(map_sqlite_err)?;

        tx.execute(
            "INSERT INTO files(
                workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            rusqlite::params![
                workspace_id,
                path,
                content,
                size_bytes_i64,
                version_i64,
                now_ms_i64,
                now_ms_i64,
            ],
        )
        .map_err(map_sqlite_err)?;

        tx.commit().map_err(map_sqlite_err)?;
        Ok(version)
    }

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> Result<u64> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_sqlite_err)?;
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let current = tx
            .query_row(
                "SELECT version, created_at_ms, updated_at_ms
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2",
                rusqlite::params![workspace_id, path],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        i64_to_u64_sql(row.get::<_, i64>(1)?, "created_at_ms", 1)?,
                        i64_to_u64_sql(row.get::<_, i64>(2)?, "updated_at_ms", 2)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_err)?;
        let Some((current_version, created_at_ms, previous_updated_at_ms)) = current else {
            return Err(Error::NotFound("file not found".to_string()));
        };
        let new_version = super::next_version(expected_version)?;
        if current_version != u64_to_i64(expected_version, "expected_version")? {
            return Err(Error::Conflict("version mismatch".to_string()));
        }
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let new_version_i64 = u64_to_i64(new_version, "new_version")?;
        let next_updated_at_ms =
            monotonic_updated_at_ms(now_ms, created_at_ms, previous_updated_at_ms);
        let next_updated_at_ms_i64 = u64_to_i64(next_updated_at_ms, "updated_at_ms")?;
        let expected_version_i64 = u64_to_i64(expected_version, "expected_version")?;

        let updated = tx
            .execute(
                "UPDATE files
                 SET content = ?1, size_bytes = ?2, version = ?3, updated_at_ms = ?4
                 WHERE workspace_id = ?5 AND path = ?6 AND version = ?7",
                rusqlite::params![
                    content,
                    size_bytes_i64,
                    new_version_i64,
                    next_updated_at_ms_i64,
                    workspace_id,
                    path,
                    expected_version_i64,
                ],
            )
            .map_err(map_sqlite_err)?;

        if updated == 1 {
            persist_generation_sqlite(&tx, workspace_id, path, new_version_i64)
                .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            return Ok(new_version);
        }

        Err(Error::Db(format!(
            "update_file_cas: expected to update exactly one row, updated={updated}"
        )))
    }

    fn delete_file(
        &mut self,
        workspace_id: &str,
        path: &str,
        expected_version: Option<u64>,
    ) -> Result<DeleteOutcome> {
        match expected_version {
            Some(version) => {
                let version = u64_to_i64(version, "version")?;
                let tx = self
                    .conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(map_sqlite_err)?;
                let current_version = tx
                    .query_row(
                        "SELECT version
                         FROM files
                         WHERE workspace_id = ?1 AND path = ?2",
                        rusqlite::params![workspace_id, path],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(map_sqlite_err)?;

                let Some(current_version) = current_version else {
                    return Ok(DeleteOutcome::NotFound);
                };
                if current_version != version {
                    return Err(Error::Conflict("version mismatch".to_string()));
                }

                let deleted = tx
                    .execute(
                        "DELETE FROM files
                         WHERE workspace_id = ?1 AND path = ?2 AND version = ?3",
                        rusqlite::params![workspace_id, path, version],
                    )
                    .map_err(map_sqlite_err)?;
                if deleted != 1 {
                    return Err(Error::Db(format!(
                        "delete_file: expected to delete exactly one row, deleted={deleted}"
                    )));
                }
                persist_generation_sqlite(&tx, workspace_id, path, version)
                    .map_err(map_sqlite_err)?;
                tx.commit().map_err(map_sqlite_err)?;
                Ok(DeleteOutcome::Deleted)
            }
            None => {
                let tx = self
                    .conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(map_sqlite_err)?;
                let current_version = tx
                    .query_row(
                        "SELECT version
                         FROM files
                         WHERE workspace_id = ?1 AND path = ?2",
                        rusqlite::params![workspace_id, path],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(map_sqlite_err)?;
                let Some(current_version) = current_version else {
                    return Ok(DeleteOutcome::NotFound);
                };

                let deleted = tx
                    .execute(
                        "DELETE FROM files WHERE workspace_id = ?1 AND path = ?2",
                        rusqlite::params![workspace_id, path],
                    )
                    .map_err(map_sqlite_err)?;
                if deleted != 1 {
                    return Err(Error::Db(format!(
                        "delete_file: expected to delete exactly one row, deleted={deleted}"
                    )));
                }
                persist_generation_sqlite(&tx, workspace_id, path, current_version)
                    .map_err(map_sqlite_err)?;
                tx.commit().map_err(map_sqlite_err)?;
                Ok(DeleteOutcome::Deleted)
            }
        }
    }

    fn list_metas_by_prefix(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<FileMeta>> {
        self.list_metas_by_prefix_page(workspace_id, prefix, None, limit)
    }

    fn list_metas_by_prefix_page(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<FileMeta>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let (lower, upper) = make_prefix_bounds(prefix);
        let limit_u64 = u64::try_from(limit)
            .map_err(|_| Error::Db("integer overflow converting limit".to_string()))?;
        let limit_i64 = u64_to_i64(limit_u64, "limit")?;
        let mut out = Vec::with_capacity(limit.min(1024));
        match (after, upper.as_deref()) {
            (Some(after), Some(upper)) => {
                let mut stmt = self
                    .conn
                    .prepare_cached(
                        "SELECT path, size_bytes, version, updated_at_ms
                         FROM files
                         WHERE workspace_id = ?1 AND path >= ?2 AND path < ?3 AND path > ?4
                         ORDER BY path
                         LIMIT ?5",
                    )
                    .map_err(map_sqlite_err)?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![workspace_id, &lower, upper, after, limit_i64],
                        decode_meta_row,
                    )
                    .map_err(map_sqlite_err)?;
                for row in rows {
                    let (path, size_bytes, version, updated_at_ms) = row.map_err(map_sqlite_err)?;
                    out.push(
                        FileMeta {
                            path,
                            size_bytes,
                            version,
                            updated_at_ms,
                        }
                        .validated()?,
                    );
                }
            }
            (Some(after), None) => {
                let mut stmt = self
                    .conn
                    .prepare_cached(
                        "SELECT path, size_bytes, version, updated_at_ms
                         FROM files
                         WHERE workspace_id = ?1 AND path >= ?2 AND path > ?3
                         ORDER BY path
                         LIMIT ?4",
                    )
                    .map_err(map_sqlite_err)?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![workspace_id, &lower, after, limit_i64],
                        decode_meta_row,
                    )
                    .map_err(map_sqlite_err)?;
                for row in rows {
                    let (path, size_bytes, version, updated_at_ms) = row.map_err(map_sqlite_err)?;
                    out.push(
                        FileMeta {
                            path,
                            size_bytes,
                            version,
                            updated_at_ms,
                        }
                        .validated()?,
                    );
                }
            }
            (None, Some(upper)) => {
                let mut stmt = self
                    .conn
                    .prepare_cached(
                        "SELECT path, size_bytes, version, updated_at_ms
                         FROM files
                         WHERE workspace_id = ?1 AND path >= ?2 AND path < ?3
                         ORDER BY path
                         LIMIT ?4",
                    )
                    .map_err(map_sqlite_err)?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![workspace_id, &lower, upper, limit_i64],
                        decode_meta_row,
                    )
                    .map_err(map_sqlite_err)?;
                for row in rows {
                    let (path, size_bytes, version, updated_at_ms) = row.map_err(map_sqlite_err)?;
                    out.push(
                        FileMeta {
                            path,
                            size_bytes,
                            version,
                            updated_at_ms,
                        }
                        .validated()?,
                    );
                }
            }
            (None, None) => {
                let mut stmt = self
                    .conn
                    .prepare_cached(
                        "SELECT path, size_bytes, version, updated_at_ms
                         FROM files
                         WHERE workspace_id = ?1 AND path >= ?2
                         ORDER BY path
                         LIMIT ?3",
                    )
                    .map_err(map_sqlite_err)?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![workspace_id, &lower, limit_i64],
                        decode_meta_row,
                    )
                    .map_err(map_sqlite_err)?;
                for row in rows {
                    let (path, size_bytes, version, updated_at_ms) = row.map_err(map_sqlite_err)?;
                    out.push(
                        FileMeta {
                            path,
                            size_bytes,
                            version,
                            updated_at_ms,
                        }
                        .validated()?,
                    );
                }
            }
        }
        Ok(out)
    }
}

fn decode_meta_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, u64, u64, u64)> {
    Ok((
        row.get::<_, String>(0)?,
        i64_to_u64_sql(row.get::<_, i64>(1)?, "size_bytes", 1)?,
        i64_to_u64_sql(row.get::<_, i64>(2)?, "version", 2)?,
        i64_to_u64_sql(row.get::<_, i64>(3)?, "updated_at_ms", 3)?,
    ))
}

fn load_current_versions_sqlite(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    path: &str,
) -> rusqlite::Result<(Option<i64>, Option<i64>)> {
    tx.query_row(
        "SELECT
             (SELECT version FROM files WHERE workspace_id = ?1 AND path = ?2),
             (SELECT last_version FROM file_generations WHERE workspace_id = ?1 AND path = ?2)",
        rusqlite::params![workspace_id, path],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    )
}

fn persist_generation_sqlite(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    path: &str,
    version: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO file_generations(workspace_id, path, last_version)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(workspace_id, path) DO UPDATE SET
             last_version = excluded.last_version
         WHERE excluded.last_version > file_generations.last_version",
        rusqlite::params![workspace_id, path, version],
    )?;
    Ok(())
}

fn map_sqlite_err(err: rusqlite::Error) -> Error {
    match err.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            Error::Timeout(format!("sqlite contention timed out: {err}"))
        }
        _ => db_err(err),
    }
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Db(format!("integer overflow converting {field}")))
}

fn usize_to_i64(value: usize, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Db(format!("integer overflow converting {field}")))
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Db(format!("invalid negative {field} value: {value}")))
}

fn i64_to_u64_sql(value: i64, field: &'static str, column_idx: usize) -> rusqlite::Result<u64> {
    i64_to_u64(value, field).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column_idx,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )),
        )
    })
}

#[cfg(test)]
fn is_unique_constraint_violation(err: &rusqlite::Error) -> bool {
    use rusqlite::Error::SqliteFailure;
    match err {
        SqliteFailure(err, _) => matches!(
            err.extended_code,
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rusqlite::ffi::{Error as SqliteError, ErrorCode};

    #[test]
    fn unique_constraint_detection_is_precise() {
        let unique = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::ConstraintViolation,
                extended_code: rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
            },
            None,
        );
        assert!(is_unique_constraint_violation(&unique));

        let primary_key = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::ConstraintViolation,
                extended_code: rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY,
            },
            None,
        );
        assert!(is_unique_constraint_violation(&primary_key));

        let not_null = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::ConstraintViolation,
                extended_code: rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL,
            },
            None,
        );
        assert!(!is_unique_constraint_violation(&not_null));

        let other = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::Unknown,
                extended_code: rusqlite::ffi::SQLITE_ERROR,
            },
            None,
        );
        assert!(!is_unique_constraint_violation(&other));
    }

    #[test]
    fn list_metas_by_prefix_page_respects_after_cursor() {
        let mut store = SqliteStore::open_in_memory().expect("open sqlite memory");
        store
            .insert_file_new("ws", "docs/a.txt", "a", 1)
            .expect("insert a");
        store
            .insert_file_new("ws", "docs/b.txt", "b", 2)
            .expect("insert b");
        store
            .insert_file_new("ws", "docs/c.txt", "c", 3)
            .expect("insert c");

        let page1 = store
            .list_metas_by_prefix_page("ws", "docs/", None, 2)
            .expect("page1");
        let page1_paths = page1.into_iter().map(|meta| meta.path).collect::<Vec<_>>();
        assert_eq!(page1_paths, vec!["docs/a.txt", "docs/b.txt"]);

        let page2 = store
            .list_metas_by_prefix_page("ws", "docs/", Some("docs/b.txt"), 2)
            .expect("page2");
        let page2_paths = page2.into_iter().map(|meta| meta.path).collect::<Vec<_>>();
        assert_eq!(page2_paths, vec!["docs/c.txt"]);
    }

    #[test]
    fn sqlite_busy_and_locked_errors_map_to_timeout() {
        let busy = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::DatabaseBusy,
                extended_code: rusqlite::ffi::SQLITE_BUSY,
            },
            None,
        );
        let locked = rusqlite::Error::SqliteFailure(
            SqliteError {
                code: ErrorCode::DatabaseLocked,
                extended_code: rusqlite::ffi::SQLITE_LOCKED,
            },
            None,
        );

        assert_eq!(map_sqlite_err(busy).code(), "timeout");
        assert_eq!(map_sqlite_err(locked).code(), "timeout");
    }
}
