use db_vfs_core::{Error, Result};

use std::ops::DerefMut;

use super::{DeleteOutcome, FileMeta, Store, db_err, make_prefix_bounds};

pub struct PostgresStoreWithClient<C> {
    client: C,
}

pub type PostgresStore<C = Box<postgres::Client>> = PostgresStoreWithClient<C>;

impl PostgresStoreWithClient<Box<postgres::Client>> {
    pub fn new(mut client: postgres::Client) -> Result<Self> {
        crate::migrations::migrate_postgres(&mut client).map_err(db_err)?;
        Ok(Self {
            client: Box::new(client),
        })
    }

    pub fn new_no_migrate(client: postgres::Client) -> Result<Self> {
        Ok(Self {
            client: Box::new(client),
        })
    }

    pub fn connect(url: &str) -> Result<Self> {
        let client = postgres::Client::connect(url, postgres::NoTls).map_err(db_err)?;
        Self::new(client)
    }

    pub fn connect_no_migrate(url: &str) -> Result<Self> {
        let client = postgres::Client::connect(url, postgres::NoTls).map_err(db_err)?;
        Self::new_no_migrate(client)
    }
}

impl<C> PostgresStoreWithClient<C> {
    pub fn from_client(client: C) -> Self {
        Self { client }
    }
}

impl<C> Store for PostgresStoreWithClient<C>
where
    C: DerefMut<Target = postgres::Client>,
{
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
        let row = self
            .client
            .query_opt(
                "SELECT size_bytes, version, updated_at_ms
                 FROM files
                 WHERE workspace_id = $1 AND path = $2",
                &[&workspace_id, &path],
            )
            .map_err(db_err)?;

        Ok(match row {
            Some(row) => Some(
                FileMeta {
                    path: path.to_string(),
                    size_bytes: i64_to_u64(row.get::<_, i64>(0), "size_bytes")?,
                    version: i64_to_u64(row.get::<_, i64>(1), "version")?,
                    updated_at_ms: i64_to_u64(row.get::<_, i64>(2), "updated_at_ms")?,
                }
                .validated()?,
            ),
            None => None,
        })
    }

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> Result<Option<String>> {
        let version = u64_to_i64(version, "version")?;
        let row = self
            .client
            .query_opt(
                "SELECT content
                 FROM files
                 WHERE workspace_id = $1 AND path = $2 AND version = $3",
                &[&workspace_id, &path, &version],
            )
            .map_err(db_err)?;

        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> Result<u64> {
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let version: u64 = 1;
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let version_i64 = u64_to_i64(version, "version")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;

        let res = self.client.execute(
            "INSERT INTO files(
                workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
            &[
                &workspace_id,
                &path,
                &content,
                &size_bytes_i64,
                &version_i64,
                &now_ms_i64,
                &now_ms_i64,
            ],
        );

        match res {
            Ok(_) => Ok(version),
            Err(err) => {
                if is_unique_violation(&err) {
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
    ) -> Result<u64> {
        let mut tx = self.client.transaction().map_err(db_err)?;
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let new_version = super::next_version(expected_version)?;
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let new_version_i64 = u64_to_i64(new_version, "new_version")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;
        let expected_version_i64 = u64_to_i64(expected_version, "expected_version")?;

        let updated = tx
            .execute(
                "UPDATE files
                 SET content = $1, size_bytes = $2, version = $3, updated_at_ms = $4
                 WHERE workspace_id = $5 AND path = $6 AND version = $7",
                &[
                    &content,
                    &size_bytes_i64,
                    &new_version_i64,
                    &now_ms_i64,
                    &workspace_id,
                    &path,
                    &expected_version_i64,
                ],
            )
            .map_err(db_err)?;

        if updated == 1 {
            tx.commit().map_err(db_err)?;
            return Ok(new_version);
        }

        let exists = tx
            .query_opt(
                "SELECT version FROM files WHERE workspace_id = $1 AND path = $2",
                &[&workspace_id, &path],
            )
            .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
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
                let version_i64 = u64_to_i64(version, "version")?;
                self.client
                    .execute(
                        "DELETE FROM files WHERE workspace_id = $1 AND path = $2 AND version = $3",
                        &[&workspace_id, &path, &version_i64],
                    )
                    .map_err(db_err)?
            }
            None => self
                .client
                .execute(
                    "DELETE FROM files WHERE workspace_id = $1 AND path = $2",
                    &[&workspace_id, &path],
                )
                .map_err(db_err)?,
        };

        if deleted > 0 {
            return Ok(DeleteOutcome::Deleted);
        }

        if expected_version.is_none() {
            return Ok(DeleteOutcome::NotFound);
        }

        let exists = self
            .client
            .query_opt(
                "SELECT 1 FROM files WHERE workspace_id = $1 AND path = $2",
                &[&workspace_id, &path],
            )
            .map_err(db_err)?;
        if exists.is_none() {
            return Ok(DeleteOutcome::NotFound);
        }

        Err(Error::Conflict("version mismatch".to_string()))
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
        let rows = match (after, upper.as_deref()) {
            (Some(after), Some(upper)) => self
                .client
                .query(
                    "SELECT path, size_bytes, version, updated_at_ms
                     FROM files
                     WHERE workspace_id = $1 AND path >= $2 AND path < $3 AND path > $4
                     ORDER BY path
                     LIMIT $5",
                    &[&workspace_id, &lower, &upper, &after, &limit_i64],
                )
                .map_err(db_err)?,
            (Some(after), None) => self
                .client
                .query(
                    "SELECT path, size_bytes, version, updated_at_ms
                     FROM files
                     WHERE workspace_id = $1 AND path >= $2 AND path > $3
                     ORDER BY path
                     LIMIT $4",
                    &[&workspace_id, &lower, &after, &limit_i64],
                )
                .map_err(db_err)?,
            (None, Some(upper)) => self
                .client
                .query(
                    "SELECT path, size_bytes, version, updated_at_ms
                     FROM files
                     WHERE workspace_id = $1 AND path >= $2 AND path < $3
                     ORDER BY path
                     LIMIT $4",
                    &[&workspace_id, &lower, &upper, &limit_i64],
                )
                .map_err(db_err)?,
            (None, None) => self
                .client
                .query(
                    "SELECT path, size_bytes, version, updated_at_ms
                     FROM files
                     WHERE workspace_id = $1 AND path >= $2
                     ORDER BY path
                     LIMIT $3",
                    &[&workspace_id, &lower, &limit_i64],
                )
                .map_err(db_err)?,
        };

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let (path, size_bytes, version, updated_at_ms) = decode_meta_row(&row)?;
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
        Ok(out)
    }
}

fn decode_meta_row(row: &postgres::Row) -> Result<(String, u64, u64, u64)> {
    Ok((
        row.get::<_, String>(0),
        i64_to_u64(row.get::<_, i64>(1), "size_bytes")?,
        i64_to_u64(row.get::<_, i64>(2), "version")?,
        i64_to_u64(row.get::<_, i64>(3), "updated_at_ms")?,
    ))
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Db(format!("integer overflow converting {field}")))
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Db(format!("invalid negative {field} value: {value}")))
}

fn is_unique_violation(err: &postgres::Error) -> bool {
    if let Some(db) = err.as_db_error() {
        return db.code() == &postgres::error::SqlState::UNIQUE_VIOLATION;
    }
    false
}
