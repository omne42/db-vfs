#[cfg(feature = "sqlite")]
pub fn migrate_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(include_str!("../migrations/sqlite/0001_init.sql"))?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub fn migrate_postgres(client: &mut postgres::Client) -> std::result::Result<(), postgres::Error> {
    client.batch_execute(include_str!("../migrations/postgres/0001_init.sql"))?;
    Ok(())
}
