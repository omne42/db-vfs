#[cfg(feature = "sqlite")]
use db_vfs_core::path::normalize_path;

#[cfg(feature = "sqlite")]
pub fn migrate_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(include_str!("../migrations/sqlite/0001_init.sql"))?;
    conn.execute_batch(include_str!(
        "../migrations/sqlite/0002_file_generations.sql"
    ))?;
    if sqlite_has_column(conn, "files", "metadata_json")? {
        conn.execute_batch("ALTER TABLE files DROP COLUMN metadata_json;")?;
    }
    conn.execute_batch(include_str!(
        "../migrations/sqlite/0003_path_invariants.sql"
    ))?;
    validate_existing_sqlite_paths(conn)?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub fn migrate_postgres(client: &mut postgres::Client) -> Result<(), postgres::Error> {
    client.batch_execute(include_str!("../migrations/postgres/0001_init.sql"))?;
    client.batch_execute(include_str!(
        "../migrations/postgres/0002_file_generations.sql"
    ))?;
    client.batch_execute(include_str!(
        "../migrations/postgres/0003_path_invariants.sql"
    ))?;
    Ok(())
}

#[cfg(feature = "sqlite")]
fn sqlite_has_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "sqlite")]
fn sqlite_path_invariant_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::ConstraintViolation,
            extended_code: rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER,
        },
        Some(message.into()),
    )
}

#[cfg(feature = "sqlite")]
fn validate_existing_sqlite_paths(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("SELECT path FROM files ORDER BY path")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let path = row.get::<_, String>(0)?;
        let normalized = normalize_path(&path).map_err(|err| {
            sqlite_path_invariant_error(format!(
                "existing files.path violates canonical-path invariant for {path:?}: {err}"
            ))
        })?;
        if normalized != path {
            return Err(sqlite_path_invariant_error(format!(
                "existing files.path violates canonical-path invariant for {path:?}: expected {normalized:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_migration_contains_integrity_checks() {
        let sql = include_str!("../migrations/postgres/0001_init.sql");
        let generations_sql = include_str!("../migrations/postgres/0002_file_generations.sql");
        let invariants_sql = include_str!("../migrations/postgres/0003_path_invariants.sql");

        assert!(sql.contains("CHECK (length(workspace_id) > 0)"));
        assert!(sql.contains("CHECK (length(path) > 0)"));
        assert!(sql.contains("CHECK (size_bytes = octet_length(content))"));
        assert!(sql.contains("CHECK (version >= 1)"));
        assert!(!sql.contains("metadata_json"));
        assert!(generations_sql.contains("CREATE TABLE IF NOT EXISTS file_generations"));
        assert!(generations_sql.contains("CHECK (last_version >= 0)"));
        assert!(generations_sql.contains("SELECT workspace_id, path, version"));
        assert!(invariants_sql.contains("ALTER TABLE files DROP COLUMN metadata_json"));
        assert!(invariants_sql.contains("db_vfs_is_canonical_path"));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_migration_enforces_table_constraints() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite memory");
        migrate_sqlite(&conn).expect("run sqlite migrations");

        conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "docs/a.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
        )
        .expect("valid insert should pass");

        let invalid_size = conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "docs/b.txt", "hello", 3_i64, 1_i64, 1_i64, 1_i64],
        );
        assert!(invalid_size.is_err(), "size/content mismatch must fail");

        let invalid_timestamps = conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "docs/c.txt", "hello", 5_i64, 1_i64, 10_i64, 9_i64],
        );
        assert!(
            invalid_timestamps.is_err(),
            "updated_at_ms < created_at_ms must fail"
        );

        let invalid_path = conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
        );
        assert!(invalid_path.is_err(), "empty path must fail");

        let invalid_noncanonical_path = conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "../docs/d.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
        );
        assert!(
            invalid_noncanonical_path.is_err(),
            "noncanonical path must fail"
        );

        assert!(
            !sqlite_has_column(&conn, "files", "metadata_json").expect("table_info"),
            "metadata_json should be removed from the active schema"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_migration_rejects_legacy_noncanonical_rows() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite memory");
        conn.execute_batch(
            "CREATE TABLE files (
                workspace_id TEXT NOT NULL,
                path TEXT NOT NULL,
                content TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                version INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                metadata_json TEXT,
                PRIMARY KEY (workspace_id, path)
            );",
        )
        .expect("create legacy table");
        conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            rusqlite::params!["ws", "../.env", "SECRET=1\n", 9_i64, 1_i64, 1_i64, 1_i64],
        )
        .expect("seed legacy invalid row");

        let err = migrate_sqlite(&conn).expect_err("legacy invalid rows must fail migration");
        assert!(
            err.to_string().contains("canonical-path invariant"),
            "unexpected error: {err}"
        );
    }
}
