#![cfg(feature = "postgres")]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use db_vfs::store::DeleteOutcome;
use db_vfs::store::Store;
use db_vfs::store::postgres::PostgresStore;

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);
static POSTGRES_SCHEMA_INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(1)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1)
}

fn postgres_url() -> String {
    let raw = std::env::var("DB_VFS_TEST_POSTGRES_URL").expect(
        "DB_VFS_TEST_POSTGRES_URL is required when running ignored postgres integration tests",
    );
    let url = raw.trim().to_string();
    assert!(
        !url.is_empty(),
        "DB_VFS_TEST_POSTGRES_URL must be non-empty when running ignored postgres integration tests"
    );
    url
}

fn ensure_postgres_schema(url: &str) {
    let init = POSTGRES_SCHEMA_INIT.get_or_init(|| {
        let mut client = postgres::Client::connect(url, postgres::NoTls)
            .map_err(|err| format!("connect postgres client: {err}"))?;
        db_vfs::migrations::migrate_postgres(&mut client)
            .map_err(|err| format!("migrate postgres schema: {err}"))?;
        Ok(())
    });
    if let Err(err) = init {
        panic!("failed to initialize shared postgres test schema: {err}");
    }
}

struct CleanupGuard {
    url: String,
    workspace_id: String,
    path: String,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Ok(mut store) = PostgresStore::connect_no_migrate(&self.url) {
            let _ = store.delete_file(&self.workspace_id, &self.path, None);
        }
    }
}

#[test]
#[ignore = "requires DB_VFS_TEST_POSTGRES_URL"]
fn postgres_store_roundtrip() {
    let url = postgres_url();
    ensure_postgres_schema(&url);
    let mut store = PostgresStore::connect_no_migrate(&url).expect("connect postgres store");

    let unique = format!(
        "{}_{}_{}",
        std::process::id(),
        now_nanos(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let ws = format!("test_{unique}");
    let path = format!("docs/{unique}.txt");
    let _cleanup = CleanupGuard {
        url,
        workspace_id: ws.clone(),
        path: path.clone(),
    };

    let now = now_ms();

    let inserted = store
        .insert_file_new(&ws, &path, "hello", now)
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(inserted, 1);

    let meta = store
        .get_meta(&ws, &path)
        .unwrap_or_else(|err| panic!("get_meta failed for ws={ws}, path={path}: {err}"))
        .unwrap_or_else(|| panic!("meta missing after insert for ws={ws}, path={path}"));
    assert_eq!(meta.version, 1);

    let updated = store
        .update_file_cas(&ws, &path, "hi", 1, now_ms())
        .unwrap_or_else(|err| panic!("update_file_cas failed for ws={ws}, path={path}: {err}"));
    assert_eq!(updated, 2);

    let outcome = store
        .delete_file(&ws, &path, Some(2))
        .unwrap_or_else(|err| panic!("delete_file failed for ws={ws}, path={path}: {err}"));
    assert_eq!(outcome, DeleteOutcome::Deleted);

    let meta_after = store.get_meta(&ws, &path).unwrap_or_else(|err| {
        panic!("get_meta(after delete) failed for ws={ws}, path={path}: {err}")
    });
    assert!(
        meta_after.is_none(),
        "meta still exists after delete for ws={ws}, path={path}"
    );
}

#[test]
#[ignore = "requires DB_VFS_TEST_POSTGRES_URL"]
fn postgres_delete_with_expected_version_distinguishes_conflict_and_not_found() {
    let url = postgres_url();
    ensure_postgres_schema(&url);
    let mut store = PostgresStore::connect_no_migrate(&url).expect("connect postgres store");

    let unique = format!(
        "{}_{}_{}",
        std::process::id(),
        now_nanos(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let ws = format!("test_{unique}");
    let path = format!("docs/{unique}.txt");
    let _cleanup = CleanupGuard {
        url,
        workspace_id: ws.clone(),
        path: path.clone(),
    };

    let version = store
        .insert_file_new(&ws, &path, "hello", now_ms())
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(version, 1);

    let err = store
        .delete_file(&ws, &path, Some(version + 1))
        .expect_err("mismatched version should conflict");
    assert_eq!(err.code(), "conflict");
    assert!(
        store
            .get_meta(&ws, &path)
            .unwrap_or_else(|err| panic!("get_meta failed for ws={ws}, path={path}: {err}"))
            .is_some(),
        "row should remain after conflict for ws={ws}, path={path}"
    );

    let deleted = store
        .delete_file(&ws, &path, Some(version))
        .unwrap_or_else(|err| panic!("delete_file failed for ws={ws}, path={path}: {err}"));
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let missing = store
        .delete_file(&ws, &path, Some(version))
        .unwrap_or_else(|err| panic!("repeat delete failed for ws={ws}, path={path}: {err}"));
    assert_eq!(missing, DeleteOutcome::NotFound);
}
