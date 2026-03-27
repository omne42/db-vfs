#[cfg(feature = "sqlite")]
pub fn migrate_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(include_str!("../migrations/sqlite/0001_init.sql"))?;
    conn.execute_batch(include_str!(
        "../migrations/sqlite/0002_file_generations.sql"
    ))?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub fn migrate_postgres(client: &mut postgres::Client) -> Result<(), postgres::Error> {
    client.batch_execute(include_str!("../migrations/postgres/0001_init.sql"))?;
    client.batch_execute(include_str!(
        "../migrations/postgres/0002_file_generations.sql"
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_migration_contains_integrity_checks() {
        let sql = include_str!("../migrations/postgres/0001_init.sql");
        let generations_sql = include_str!("../migrations/postgres/0002_file_generations.sql");

        assert!(sql.contains("CHECK (length(workspace_id) > 0)"));
        assert!(sql.contains("CHECK (length(path) > 0)"));
        assert!(sql.contains("CHECK (size_bytes = octet_length(content))"));
        assert!(sql.contains("CHECK (version >= 1)"));
        assert!(sql.contains("metadata_json JSONB"));
        assert!(generations_sql.contains("CREATE TABLE IF NOT EXISTS file_generations"));
        assert!(generations_sql.contains("CHECK (last_version >= 0)"));
        assert!(generations_sql.contains("SELECT workspace_id, path, version"));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_migration_enforces_table_constraints() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite memory");
        conn.execute_batch(include_str!("../migrations/sqlite/0001_init.sql"))
            .expect("run sqlite 0001");

        conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params!["ws", "docs/a.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64, "{\"k\":1}"],
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

        let invalid_json = conn.execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params!["ws", "docs/d.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64, "{"],
        );
        assert!(invalid_json.is_err(), "invalid metadata_json must fail");

        conn.execute_batch(include_str!(
            "../migrations/sqlite/0002_file_generations.sql"
        ))
        .expect("run sqlite 0002");

        let generation = conn
            .query_row(
                "SELECT last_version FROM file_generations WHERE workspace_id = ?1 AND path = ?2",
                rusqlite::params!["ws", "docs/a.txt"],
                |row| row.get::<_, i64>(0),
            )
            .expect("generation row should be backfilled");
        assert_eq!(generation, 1);
    }
}
