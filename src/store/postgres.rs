use db_vfs_core::{Error, Result};

use std::ops::DerefMut;

use super::{
    DeleteOutcome, FileMeta, LineRangeData, Store, db_err, get_line_range_via_chunks,
    make_prefix_bounds, monotonic_updated_at_ms,
};

pub struct PostgresStoreWithClient<C> {
    client: C,
}

pub type PostgresStore<C = Box<postgres::Client>> = PostgresStoreWithClient<C>;

impl PostgresStoreWithClient<Box<postgres::Client>> {
    pub fn new(mut client: postgres::Client) -> Result<Self> {
        crate::migrations::migrate_postgres(&mut client).map_err(map_postgres_err)?;
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
        let client = postgres::Client::connect(url, postgres::NoTls).map_err(map_postgres_err)?;
        Self::new(client)
    }

    pub fn connect_no_migrate(url: &str) -> Result<Self> {
        let client = postgres::Client::connect(url, postgres::NoTls).map_err(map_postgres_err)?;
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
            .map_err(map_postgres_err)?;

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
            .map_err(map_postgres_err)?;

        Ok(row.map(|row| row.get::<_, String>(0)))
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
        let row = self
            .client
            .query_opt(
                "SELECT substring(content FROM $4 FOR $5)
                 FROM files
                 WHERE workspace_id = $1 AND path = $2 AND version = $3",
                &[&workspace_id, &path, &version, &start_char, &max_chars],
            )
            .map_err(map_postgres_err)?;

        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    fn get_line_range(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_line: u64,
        end_line: u64,
        max_bytes: u64,
    ) -> Result<Option<LineRangeData>> {
        get_line_range_via_chunks(
            self,
            workspace_id,
            path,
            version,
            start_line,
            end_line,
            max_bytes,
        )
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> Result<u64> {
        let mut tx = self.client.transaction().map_err(map_postgres_err)?;
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let now_ms_i64 = u64_to_i64(now_ms, "now_ms")?;

        let last_version = lock_generation_row_postgres(&mut tx, workspace_id, path)?;
        let current_version = tx
            .query_opt(
                "SELECT version
                 FROM files
                 WHERE workspace_id = $1 AND path = $2
                 FOR UPDATE",
                &[&workspace_id, &path],
            )
            .map_err(map_postgres_err)?
            .map(|row| row.get::<_, i64>(0));
        if current_version.is_some() {
            return Err(Error::Conflict("file exists".to_string()));
        }

        let version = super::next_version(i64_to_u64(last_version, "last_version")?)?;
        let version_i64 = u64_to_i64(version, "version")?;
        persist_generation_postgres(&mut tx, workspace_id, path, version_i64)?;

        tx.execute(
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
        )
        .map_err(map_postgres_err)?;

        tx.commit().map_err(map_postgres_err)?;
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
        let mut tx = self.client.transaction().map_err(map_postgres_err)?;
        lock_generation_row_postgres(&mut tx, workspace_id, path)?;
        let current = tx
            .query_opt(
                "SELECT version, created_at_ms, updated_at_ms
                 FROM files
                 WHERE workspace_id = $1 AND path = $2
                 FOR UPDATE",
                &[&workspace_id, &path],
            )
            .map_err(map_postgres_err)?;
        let Some(current) = current else {
            return Err(Error::NotFound("file not found".to_string()));
        };
        let size_bytes = u64::try_from(content.len())
            .map_err(|_| Error::Db("integer overflow converting size_bytes".to_string()))?;
        let new_version = super::next_version(expected_version)?;
        let current_version = current.get::<_, i64>(0);
        let expected_version_i64 = u64_to_i64(expected_version, "expected_version")?;
        if current_version != expected_version_i64 {
            return Err(Error::Conflict("version mismatch".to_string()));
        }
        let size_bytes_i64 = u64_to_i64(size_bytes, "size_bytes")?;
        let new_version_i64 = u64_to_i64(new_version, "new_version")?;
        let created_at_ms = i64_to_u64(current.get::<_, i64>(1), "created_at_ms")?;
        let previous_updated_at_ms = i64_to_u64(current.get::<_, i64>(2), "updated_at_ms")?;
        let next_updated_at_ms =
            monotonic_updated_at_ms(now_ms, created_at_ms, previous_updated_at_ms);
        let next_updated_at_ms_i64 = u64_to_i64(next_updated_at_ms, "updated_at_ms")?;

        let updated = tx
            .execute(
                "UPDATE files
                 SET content = $1, size_bytes = $2, version = $3, updated_at_ms = $4
                 WHERE workspace_id = $5 AND path = $6 AND version = $7",
                &[
                    &content,
                    &size_bytes_i64,
                    &new_version_i64,
                    &next_updated_at_ms_i64,
                    &workspace_id,
                    &path,
                    &expected_version_i64,
                ],
            )
            .map_err(map_postgres_err)?;

        if updated == 1 {
            persist_generation_postgres(&mut tx, workspace_id, path, new_version_i64)?;
            tx.commit().map_err(map_postgres_err)?;
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
                let version_i64 = u64_to_i64(version, "version")?;
                let mut tx = self.client.transaction().map_err(map_postgres_err)?;
                lock_generation_row_postgres(&mut tx, workspace_id, path)?;
                let current_version = tx
                    .query_opt(
                        "SELECT version
                         FROM files
                         WHERE workspace_id = $1 AND path = $2
                         FOR UPDATE",
                        &[&workspace_id, &path],
                    )
                    .map_err(map_postgres_err)?
                    .map(|row| row.get::<_, i64>(0));
                let Some(current_version) = current_version else {
                    return Ok(DeleteOutcome::NotFound);
                };
                if current_version != version_i64 {
                    return Err(Error::Conflict("version mismatch".to_string()));
                }
                let deleted = tx
                    .execute(
                        "DELETE FROM files
                         WHERE workspace_id = $1 AND path = $2 AND version = $3",
                        &[&workspace_id, &path, &version_i64],
                    )
                    .map_err(map_postgres_err)?;
                if deleted != 1 {
                    return Err(Error::Db(format!(
                        "delete_file: expected to delete exactly one row, deleted={deleted}"
                    )));
                }
                persist_generation_postgres(&mut tx, workspace_id, path, version_i64)?;
                tx.commit().map_err(map_postgres_err)?;
                Ok(DeleteOutcome::Deleted)
            }
            None => {
                let mut tx = self.client.transaction().map_err(map_postgres_err)?;
                lock_generation_row_postgres(&mut tx, workspace_id, path)?;
                let current_version = tx
                    .query_opt(
                        "SELECT version
                         FROM files
                         WHERE workspace_id = $1 AND path = $2
                         FOR UPDATE",
                        &[&workspace_id, &path],
                    )
                    .map_err(map_postgres_err)?
                    .map(|row| row.get::<_, i64>(0));
                let Some(current_version) = current_version else {
                    return Ok(DeleteOutcome::NotFound);
                };
                let deleted = tx
                    .execute(
                        "DELETE FROM files WHERE workspace_id = $1 AND path = $2",
                        &[&workspace_id, &path],
                    )
                    .map_err(map_postgres_err)?;
                if deleted != 1 {
                    return Err(Error::Db(format!(
                        "delete_file: expected to delete exactly one row, deleted={deleted}"
                    )));
                }
                persist_generation_postgres(&mut tx, workspace_id, path, current_version)?;
                tx.commit().map_err(map_postgres_err)?;
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
                .map_err(map_postgres_err)?,
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
                .map_err(map_postgres_err)?,
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
                .map_err(map_postgres_err)?,
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
                .map_err(map_postgres_err)?,
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

fn lock_generation_row_postgres(
    tx: &mut postgres::Transaction<'_>,
    workspace_id: &str,
    path: &str,
) -> Result<i64> {
    tx.execute(
        "INSERT INTO file_generations(workspace_id, path, last_version)
         VALUES ($1, $2, 0)
         ON CONFLICT (workspace_id, path) DO NOTHING",
        &[&workspace_id, &path],
    )
    .map_err(map_postgres_err)?;
    let row = tx
        .query_one(
            "SELECT last_version
             FROM file_generations
             WHERE workspace_id = $1 AND path = $2
             FOR UPDATE",
            &[&workspace_id, &path],
        )
        .map_err(map_postgres_err)?;
    Ok(row.get::<_, i64>(0))
}

fn persist_generation_postgres(
    tx: &mut postgres::Transaction<'_>,
    workspace_id: &str,
    path: &str,
    version: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO file_generations(workspace_id, path, last_version)
         VALUES ($1, $2, $3)
         ON CONFLICT (workspace_id, path) DO UPDATE SET
             last_version = EXCLUDED.last_version
         WHERE EXCLUDED.last_version > file_generations.last_version",
        &[&workspace_id, &path, &version],
    )
    .map_err(map_postgres_err)?;
    Ok(())
}

fn map_postgres_err(err: postgres::Error) -> Error {
    match err.code() {
        Some(&postgres::error::SqlState::QUERY_CANCELED)
        | Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        | Some(&postgres::error::SqlState::TOO_MANY_CONNECTIONS) => {
            Error::Timeout(format!("postgres contention timed out: {err}"))
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
