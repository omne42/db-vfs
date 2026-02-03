#![cfg(feature = "postgres")]

use std::time::{SystemTime, UNIX_EPOCH};

use db_vfs::store::DeleteOutcome;
use db_vfs::store::Store;
use db_vfs::store::postgres::PostgresStore;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn maybe_postgres_url() -> Option<String> {
    let url = std::env::var("DB_VFS_TEST_POSTGRES_URL").ok()?;
    let url = url.trim().to_string();
    if url.is_empty() { None } else { Some(url) }
}

#[test]
fn postgres_store_roundtrip_if_configured() {
    let Some(url) = maybe_postgres_url() else {
        eprintln!("skipping: set DB_VFS_TEST_POSTGRES_URL to run Postgres store integration test");
        return;
    };

    let mut store = PostgresStore::connect(&url).expect("connect postgres");

    let ws = format!("test_{}", now_ms());
    let path = "docs/a.txt";
    let now = now_ms();

    let inserted = store
        .insert_file_new(&ws, path, "hello", now)
        .expect("insert");
    assert_eq!(inserted.version, 1);

    let meta = store.get_meta(&ws, path).expect("meta").expect("meta");
    assert_eq!(meta.version, 1);

    let updated = store
        .update_file_cas(&ws, path, "hi", 1, now_ms())
        .expect("update");
    assert_eq!(updated.version, 2);

    let outcome = store.delete_file(&ws, path, Some(2)).expect("delete");
    assert_eq!(outcome, DeleteOutcome::Deleted);
}
