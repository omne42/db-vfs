use std::ops::Deref;
use std::path::Path;
use std::time::Duration;

use rusqlite::OptionalExtension;

use db_vfs_core::{Error, Result};

use super::{DeleteOutcome, FileMeta, FileRecord, Store, db_err, make_prefix_bounds};

pub struct SqliteStoreWithConn<C> {
    conn: C,
}

pub type SqliteStore<C = Box<rusqlite::Connection>> = SqliteStoreWithConn<C>;

impl SqliteStoreWithConn<Box<rusqlite::Connection>> {
    pub fn new(conn: rusqlite::Connection) -> Result<Self> {
        let _ = conn.busy_timeout(Duration::from_secs(5));
        crate::migrations::migrate_sqlite(&conn).map_err(db_err)?;
        Ok(Self {
            conn: Box::new(conn),
        })
    }

    pub fn new_no_migrate(conn: rusqlite::Connection) -> Result<Self> {
        let _ = conn.busy_timeout(Duration::from_secs(5));
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
    C: Deref<Target = rusqlite::Connection>,
{
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT size_bytes, version, updated_at_ms
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2",
            )
            .map_err(db_err)?;

        stmt.query_row(rusqlite::params![workspace_id, path], |row| {
            Ok(FileMeta {
                path: path.to_string(),
                size_bytes: i64_to_u64_sql(row.get::<_, i64>(0)?, "size_bytes")?,
                version: i64_to_u64_sql(row.get::<_, i64>(1)?, "version")?,
                updated_at_ms: i64_to_u64_sql(row.get::<_, i64>(2)?, "updated_at_ms")?,
            })
        })
        .optional()
        .map_err(db_err)
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
            .prepare(
                "SELECT content
                 FROM files
                 WHERE workspace_id = ?1 AND path = ?2 AND version = ?3",
            )
            .map_err(db_err)?;

        stmt.query_row(rusqlite::params![workspace_id, path, version], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(db_err)
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> Result<FileRecord> {
        let size_bytes = content.len() as u64;
        let version: u64 = 1;
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let version_i64 = u64_to_i64(version, "version")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;

        let res = self.conn.execute(
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
        );

        match res {
            Ok(_) => Ok(FileRecord {
                workspace_id: workspace_id.to_string(),
                path: path.to_string(),
                content: content.to_string(),
                size_bytes,
                version,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                metadata_json: None,
            }),
            Err(err) => {
                if is_unique_constraint_violation(&err) {
                    return Err(Error::Conflict("file exists".to_string()));
                }
                Err(db_err(err))
            }
        }
    }

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> Result<FileRecord> {
        let size_bytes = content.len() as u64;
        let new_version = expected_version.saturating_add(1);
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let new_version_i64 = u64_to_i64(new_version, "new_version")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;
        let expected_version_i64 = u64_to_i64(expected_version, "expected_version")?;

        let updated = self
            .conn
            .execute(
                "UPDATE files
                 SET content = ?1, size_bytes = ?2, version = ?3, updated_at_ms = ?4
                 WHERE workspace_id = ?5 AND path = ?6 AND version = ?7",
                rusqlite::params![
                    content,
                    size_bytes_i64,
                    new_version_i64,
                    now_ms_i64,
                    workspace_id,
                    path,
                    expected_version_i64,
                ],
            )
            .map_err(db_err)?;

        if updated == 1 {
            let created_at_ms = self
                .conn
                .query_row(
                    "SELECT created_at_ms FROM files WHERE workspace_id = ?1 AND path = ?2",
                    rusqlite::params![workspace_id, path],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(db_err)?
                .map(|v| i64_to_u64(v, "created_at_ms"))
                .transpose()?
                .unwrap_or(now_ms);

            return Ok(FileRecord {
                workspace_id: workspace_id.to_string(),
                path: path.to_string(),
                content: content.to_string(),
                size_bytes,
                version: new_version,
                created_at_ms,
                updated_at_ms: now_ms,
                metadata_json: None,
            });
        }

        let exists = self
            .conn
            .query_row(
                "SELECT version FROM files WHERE workspace_id = ?1 AND path = ?2",
                rusqlite::params![workspace_id, path],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(db_err)?;
        if exists.is_none() {
            return Err(Error::NotFound("file not found".to_string()));
        }
        Err(Error::Conflict("version mismatch".to_string()))
    }

    fn delete_file(
        &mut self,
        workspace_id: &str,
        path: &str,
        expected_version: Option<u64>,
    ) -> Result<DeleteOutcome> {
        let deleted = match expected_version {
            Some(version) => {
                let version = u64_to_i64(version, "version")?;
                self.conn
                    .execute(
                        "DELETE FROM files WHERE workspace_id = ?1 AND path = ?2 AND version = ?3",
                        rusqlite::params![workspace_id, path, version],
                    )
                    .map_err(db_err)?
            }
            None => self
                .conn
                .execute(
                    "DELETE FROM files WHERE workspace_id = ?1 AND path = ?2",
                    rusqlite::params![workspace_id, path],
                )
                .map_err(db_err)?,
        };

        if deleted == 1 {
            return Ok(DeleteOutcome::Deleted);
        }

        let exists = self
            .conn
            .query_row(
                "SELECT 1 FROM files WHERE workspace_id = ?1 AND path = ?2",
                rusqlite::params![workspace_id, path],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(db_err)?;

        if exists.is_none() {
            return Ok(DeleteOutcome::NotFound);
        }

        if expected_version.is_some() {
            return Err(Error::Conflict("version mismatch".to_string()));
        }
        Ok(DeleteOutcome::NotFound)
    }

    fn list_metas_by_prefix(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<FileMeta>> {
        let (lower, upper) = make_prefix_bounds(prefix);
        let limit = u64_to_i64(limit as u64, "limit")?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT path, size_bytes, version, updated_at_ms
                 FROM files
                 WHERE workspace_id = ?1 AND path >= ?2 AND path < ?3
                 ORDER BY path
                 LIMIT ?4",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(
                rusqlite::params![workspace_id, lower, upper, limit],
                |row| {
                    Ok(FileMeta {
                        path: row.get::<_, String>(0)?,
                        size_bytes: i64_to_u64_sql(row.get::<_, i64>(1)?, "size_bytes")?,
                        version: i64_to_u64_sql(row.get::<_, i64>(2)?, "version")?,
                        updated_at_ms: i64_to_u64_sql(row.get::<_, i64>(3)?, "updated_at_ms")?,
                    })
                },
            )
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Db(format!("integer overflow converting {field}")))
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Db(format!("invalid negative {field} value: {value}")))
}

fn i64_to_u64_sql(value: i64, field: &'static str) -> rusqlite::Result<u64> {
    i64_to_u64(value, field).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )),
        )
    })
}

fn is_unique_constraint_violation(err: &rusqlite::Error) -> bool {
    use rusqlite::Error::SqliteFailure;
    match err {
        SqliteFailure(code, _) => {
            matches!(code.code, rusqlite::ErrorCode::ConstraintViolation)
        }
        _ => false,
    }
}
