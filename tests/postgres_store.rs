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

fn postgres_url() -> Option<String> {
    let raw = match std::env::var("DB_VFS_TEST_POSTGRES_URL") {
        Ok(raw) => raw,
        Err(_) => return None,
    };
    let url = raw.trim().to_string();
    if url.is_empty() {
        return None;
    }
    Some(url)
}

fn require_postgres_url(test_name: &str) -> Option<String> {
    let Some(url) = postgres_url() else {
        eprintln!("skipping {test_name}: DB_VFS_TEST_POSTGRES_URL unset");
        return None;
    };
    Some(url)
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

fn generation_row_count(url: &str, workspace_id: &str, path: &str) -> i64 {
    let mut client =
        postgres::Client::connect(url, postgres::NoTls).expect("connect postgres client");
    client
        .query_one(
            "SELECT COUNT(*)::BIGINT
             FROM file_generations
             WHERE workspace_id = $1 AND path = $2",
            &[&workspace_id, &path],
        )
        .expect("count generation rows")
        .get::<_, i64>(0)
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
fn postgres_store_roundtrip() {
    let Some(url) = require_postgres_url("postgres_store_roundtrip") else {
        return;
    };
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
fn postgres_line_range_reads_use_chunk_query_path() {
    let Some(url) = require_postgres_url("postgres_line_range_reads_use_chunk_query_path") else {
        return;
    };
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
        .insert_file_new(
            &ws,
            &path,
            "line-0001\nline-0002\nline-0003\nline-0004\n",
            now_ms(),
        )
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(version, 1);

    let range = store
        .get_line_range(&ws, &path, version, 2, 2, 1_024)
        .unwrap_or_else(|err| panic!("get_line_range failed for ws={ws}, path={path}: {err}"))
        .unwrap_or_else(|| panic!("line range missing for ws={ws}, path={path}"));
    assert_eq!(range.content.as_deref(), Some("line-0002\n"));
    assert_eq!(range.bytes_read, 10);
    assert_eq!(range.total_lines, 2);
}

#[test]
fn postgres_delete_with_expected_version_distinguishes_conflict_and_not_found() {
    let Some(url) = require_postgres_url(
        "postgres_delete_with_expected_version_distinguishes_conflict_and_not_found",
    ) else {
        return;
    };
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

#[test]
fn postgres_versions_remain_monotonic_across_delete_and_recreate() {
    let Some(url) =
        require_postgres_url("postgres_versions_remain_monotonic_across_delete_and_recreate")
    else {
        return;
    };
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

    let first = store
        .insert_file_new(&ws, &path, "v1", now_ms())
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(first, 1);

    let deleted = store
        .delete_file(&ws, &path, Some(first))
        .unwrap_or_else(|err| panic!("delete_file failed for ws={ws}, path={path}: {err}"));
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let recreated = store
        .insert_file_new(&ws, &path, "v2", now_ms())
        .unwrap_or_else(|err| panic!("recreate failed for ws={ws}, path={path}: {err}"));
    assert_eq!(recreated, 2);

    let err = store
        .update_file_cas(&ws, &path, "stale", first, now_ms())
        .expect_err("stale CAS should conflict");
    assert_eq!(err.code(), "conflict");

    let err = store
        .delete_file(&ws, &path, Some(first))
        .expect_err("stale delete should conflict");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn postgres_store_normalizes_public_keys_and_rejects_invalid_workspace_ids() {
    let Some(url) = require_postgres_url(
        "postgres_store_normalizes_public_keys_and_rejects_invalid_workspace_ids",
    ) else {
        return;
    };
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
    let dirty_path = format!("./docs//{unique}.txt");
    let _cleanup = CleanupGuard {
        url,
        workspace_id: ws.clone(),
        path: path.clone(),
    };

    let now = now_ms();
    let version = store
        .insert_file_new(&ws, &dirty_path, "hello", now)
        .expect("insert dirty path");
    assert_eq!(version, 1);

    let meta = store
        .get_meta(&ws, &path)
        .expect("get meta")
        .expect("meta exists");
    assert_eq!(meta.path, path);
    assert_eq!(meta.version, 1);

    let same_meta = store
        .get_meta(&ws, &dirty_path)
        .expect("get meta dirty path")
        .expect("meta exists");
    assert_eq!(same_meta.path, path);

    let updated = store
        .update_file_cas(&ws, &dirty_path, "hi", 1, now.saturating_add(1))
        .expect("update dirty path");
    assert_eq!(updated, 2);

    let listed = store
        .list_metas_by_prefix(&ws, "./docs", 16)
        .expect("list dirty prefix");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, path);

    let deleted = store
        .delete_file(&ws, &dirty_path, Some(2))
        .expect("delete dirty path");
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let err = store
        .insert_file_new("bad ws", &path, "hello", now_ms())
        .expect_err("invalid workspace id");
    assert_eq!(err.code(), "invalid_path");
}

#[test]
fn postgres_update_distinguishes_conflict_and_not_found() {
    let Some(url) = require_postgres_url("postgres_update_distinguishes_conflict_and_not_found")
    else {
        return;
    };
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
        .insert_file_new(&ws, &path, "v1", now_ms())
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(version, 1);

    let err = store
        .update_file_cas(&ws, &path, "stale", version + 1, now_ms())
        .expect_err("mismatched version should conflict");
    assert_eq!(err.code(), "conflict");

    let deleted = store
        .delete_file(&ws, &path, Some(version))
        .unwrap_or_else(|err| panic!("delete_file failed for ws={ws}, path={path}: {err}"));
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let err = store
        .update_file_cas(&ws, &path, "missing", version, now_ms())
        .expect_err("missing row should report not_found");
    assert_eq!(err.code(), "not_found");
}

#[test]
fn postgres_missing_update_does_not_create_generation_state() {
    let Some(url) =
        require_postgres_url("postgres_missing_update_does_not_create_generation_state")
    else {
        return;
    };
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
        url: url.clone(),
        workspace_id: ws.clone(),
        path: path.clone(),
    };

    let err = store
        .update_file_cas(&ws, &path, "missing", 1, now_ms())
        .expect_err("missing row should report not_found");
    assert_eq!(err.code(), "not_found");
    assert_eq!(generation_row_count(&url, &ws, &path), 0);

    let inserted = store
        .insert_file_new(&ws, &path, "hello", now_ms())
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(inserted, 1);
}

#[test]
fn postgres_missing_delete_does_not_create_generation_state() {
    let Some(url) =
        require_postgres_url("postgres_missing_delete_does_not_create_generation_state")
    else {
        return;
    };
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
        url: url.clone(),
        workspace_id: ws.clone(),
        path: path.clone(),
    };

    let outcome = store
        .delete_file(&ws, &path, Some(1))
        .unwrap_or_else(|err| panic!("delete_file failed for ws={ws}, path={path}: {err}"));
    assert_eq!(outcome, DeleteOutcome::NotFound);
    assert_eq!(generation_row_count(&url, &ws, &path), 0);

    let inserted = store
        .insert_file_new(&ws, &path, "hello", now_ms())
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(inserted, 1);
}

#[test]
fn postgres_update_keeps_updated_at_monotonic_when_clock_moves_backwards() {
    let Some(url) = require_postgres_url(
        "postgres_update_keeps_updated_at_monotonic_when_clock_moves_backwards",
    ) else {
        return;
    };
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

    let first = store
        .insert_file_new(&ws, &path, "v1", 100)
        .unwrap_or_else(|err| panic!("insert failed for ws={ws}, path={path}: {err}"));
    assert_eq!(first, 1);

    let second = store
        .update_file_cas(&ws, &path, "v2", first, 50)
        .unwrap_or_else(|err| panic!("update_file_cas failed for ws={ws}, path={path}: {err}"));
    assert_eq!(second, 2);

    let meta = store
        .get_meta(&ws, &path)
        .unwrap_or_else(|err| panic!("get_meta failed for ws={ws}, path={path}: {err}"))
        .unwrap_or_else(|| panic!("meta missing for ws={ws}, path={path}"));
    assert_eq!(meta.version, 2);
    assert_eq!(meta.updated_at_ms, 100);
}

#[test]
fn postgres_schema_rejects_invalid_workspace_ids() {
    let Some(url) = require_postgres_url("postgres_schema_rejects_invalid_workspace_ids") else {
        return;
    };
    ensure_postgres_schema(&url);

    let mut client =
        postgres::Client::connect(&url, postgres::NoTls).expect("connect postgres client");
    let err = client
        .execute(
            "INSERT INTO files (workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &"team-*",
                &"docs/invalid-workspace.txt",
                &"hello",
                &5_i64,
                &1_i64,
                &1_i64,
                &1_i64,
            ],
        )
        .expect_err("invalid workspace_id insert must fail");
    let db_error = err
        .as_db_error()
        .expect("check violation should be a db error");
    assert_eq!(db_error.code(), &postgres::error::SqlState::CHECK_VIOLATION);
    assert_eq!(
        db_error.constraint(),
        Some("files_workspace_id_literal_check"),
        "unexpected error: {db_error}"
    );
}
