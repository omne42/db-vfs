use db_vfs::store::{
    DeleteOutcome, FileMeta, LineRangeData, PrefixPage, PrefixPaginationMode, Store,
};

#[cfg(feature = "postgres")]
use db_vfs::store::postgres::PostgresStore;
#[cfg(feature = "sqlite")]
use db_vfs::store::sqlite::SqliteStore;
#[cfg(feature = "postgres")]
use std::sync::OnceLock;
#[cfg(feature = "postgres")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(feature = "sqlite")]
type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
#[cfg(feature = "sqlite")]
type SqliteConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

#[cfg(feature = "postgres")]
type PostgresPool =
    r2d2::Pool<r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>>;
#[cfg(feature = "postgres")]
type PostgresConn = r2d2::PooledConnection<
    r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>,
>;
const R2D2_TIMEOUT_MESSAGE: &str = "timed out waiting for connection";
#[cfg(feature = "sqlite")]
const SQLITE_UNBOUNDED_BUSY_TIMEOUT_MS: u64 = i32::MAX as u64;
#[cfg(feature = "postgres")]
const POSTGRES_CANCEL_QUEUE_CAPACITY: usize = 1024;
#[cfg(feature = "postgres")]
struct PostgresCancelDispatch {
    tx: Option<std::sync::mpsc::SyncSender<r2d2_postgres::postgres::CancelToken>>,
}
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_DISPATCH: OnceLock<PostgresCancelDispatch> = OnceLock::new();
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_QUEUE_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_OVERFLOW_PENDING: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "postgres")]
const POSTGRES_CANCEL_OVERFLOW_WARN_PENDING: usize = 256;
#[cfg(feature = "postgres")]
struct PostgresCancelOverflowDispatch {
    tx: Option<std::sync::mpsc::Sender<r2d2_postgres::postgres::CancelToken>>,
}
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_OVERFLOW_DISPATCH: OnceLock<PostgresCancelOverflowDispatch> =
    OnceLock::new();

#[cfg(feature = "postgres")]
fn postgres_cancel_tx()
-> Option<&'static std::sync::mpsc::SyncSender<r2d2_postgres::postgres::CancelToken>> {
    POSTGRES_CANCEL_DISPATCH
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<r2d2_postgres::postgres::CancelToken>(
                POSTGRES_CANCEL_QUEUE_CAPACITY,
            );
            let spawn = std::thread::Builder::new()
                .name("db-vfs-pg-cancel-worker".to_string())
                .spawn(move || {
                    while let Ok(token) = rx.recv() {
                        if let Err(err) = token.cancel_query(r2d2_postgres::postgres::NoTls) {
                            tracing::warn!(err = %err, "failed to cancel postgres query");
                        }
                    }
                });
            match spawn {
                Ok(_) => PostgresCancelDispatch { tx: Some(tx) },
                Err(err) => {
                    tracing::warn!(
                        err = %err,
                        "failed to spawn postgres cancel worker; using direct cancel fallback mode"
                    );
                    PostgresCancelDispatch { tx: None }
                }
            }
        })
        .tx
        .as_ref()
}

#[cfg(feature = "postgres")]
fn postgres_cancel_overflow_tx()
-> Option<&'static std::sync::mpsc::Sender<r2d2_postgres::postgres::CancelToken>> {
    POSTGRES_CANCEL_OVERFLOW_DISPATCH
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel::<r2d2_postgres::postgres::CancelToken>();
            let spawn = std::thread::Builder::new()
                .name("db-vfs-pg-cancel-overflow-worker".to_string())
                .spawn(move || {
                    while let Ok(token) = rx.recv() {
                        if let Err(err) = token.cancel_query(r2d2_postgres::postgres::NoTls) {
                            tracing::warn!(
                                err = %err,
                                "failed to cancel postgres query from overflow worker"
                            );
                        }
                        POSTGRES_CANCEL_OVERFLOW_PENDING.fetch_sub(1, Ordering::AcqRel);
                    }
                });
            match spawn {
                Ok(_) => PostgresCancelOverflowDispatch { tx: Some(tx) },
                Err(err) => {
                    tracing::warn!(
                        err = %err,
                        "failed to spawn postgres cancel overflow worker; direct cancel fallback will be used"
                    );
                    PostgresCancelOverflowDispatch { tx: None }
                }
            }
        })
        .tx
        .as_ref()
}

#[cfg(feature = "postgres")]
enum CancelDispatchOutcome<T> {
    Dispatched,
    DirectFallback(T),
}

#[cfg(feature = "postgres")]
fn dispatch_cancel_item<T>(
    item: T,
    primary_send: impl FnOnce(T) -> Result<(), std::sync::mpsc::TrySendError<T>>,
    overflow_send: impl FnOnce(T) -> Result<(), std::sync::mpsc::SendError<T>>,
) -> CancelDispatchOutcome<T> {
    let item = match primary_send(item) {
        Ok(()) => return CancelDispatchOutcome::Dispatched,
        Err(std::sync::mpsc::TrySendError::Full(item))
        | Err(std::sync::mpsc::TrySendError::Disconnected(item)) => item,
    };

    match overflow_send(item) {
        Ok(()) => CancelDispatchOutcome::Dispatched,
        Err(std::sync::mpsc::SendError(item)) => CancelDispatchOutcome::DirectFallback(item),
    }
}

#[derive(Clone)]
pub(super) enum Backend {
    #[cfg(feature = "sqlite")]
    Sqlite { pool: SqlitePool },
    #[cfg(feature = "postgres")]
    Postgres { pool: PostgresPool },
}

pub(super) enum BackendStore {
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteStore<SqliteConn>),
    #[cfg(feature = "postgres")]
    Postgres(Box<PostgresStore<PostgresConn>>),
}

pub(super) enum CancelHandle {
    #[cfg(feature = "sqlite")]
    Sqlite(rusqlite::InterruptHandle),
    #[cfg(feature = "postgres")]
    Postgres(r2d2_postgres::postgres::CancelToken),
}

impl CancelHandle {
    pub(super) fn cancel(&self) {
        match self {
            #[cfg(feature = "sqlite")]
            CancelHandle::Sqlite(handle) => handle.interrupt(),
            #[cfg(feature = "postgres")]
            CancelHandle::Postgres(token) => {
                let token = match dispatch_cancel_item(
                    token.clone(),
                    |token| {
                        if let Some(cancel_tx) = postgres_cancel_tx() {
                            cancel_tx.try_send(token)
                        } else {
                            Err(std::sync::mpsc::TrySendError::Disconnected(token))
                        }
                    },
                    |token| {
                        let pending =
                            POSTGRES_CANCEL_OVERFLOW_PENDING.fetch_add(1, Ordering::AcqRel) + 1;
                        let overflow_count = POSTGRES_CANCEL_QUEUE_OVERFLOW_COUNT
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;
                        if overflow_count == 1 || overflow_count.is_multiple_of(100) {
                            tracing::warn!(
                                overflow_count,
                                pending,
                                "postgres cancel queue saturated/disconnected; routing cancel through overflow worker"
                            );
                        }
                        if pending >= POSTGRES_CANCEL_OVERFLOW_WARN_PENDING
                            && (pending == POSTGRES_CANCEL_OVERFLOW_WARN_PENDING
                                || pending.is_multiple_of(100))
                        {
                            tracing::warn!(
                                pending,
                                warn_pending = POSTGRES_CANCEL_OVERFLOW_WARN_PENDING,
                                "postgres cancel overflow worker is backlogged"
                            );
                        }
                        if let Some(overflow_tx) = postgres_cancel_overflow_tx() {
                            overflow_tx.send(token)
                        } else {
                            POSTGRES_CANCEL_OVERFLOW_PENDING.fetch_sub(1, Ordering::AcqRel);
                            Err(std::sync::mpsc::SendError(token))
                        }
                    },
                ) {
                    CancelDispatchOutcome::Dispatched => return,
                    CancelDispatchOutcome::DirectFallback(token) => token,
                };
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn_blocking(move || {
                        if let Err(err) = token.cancel_query(r2d2_postgres::postgres::NoTls) {
                            tracing::warn!(err = %err, "failed to cancel postgres query");
                        }
                    });
                    return;
                }
                if let Err(err) = token.cancel_query(r2d2_postgres::postgres::NoTls) {
                    tracing::warn!(
                        err = %err,
                        "failed to cancel postgres query (sync fallback without tokio runtime)"
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolGetFailureKind {
    Timeout,
    BackendError,
}

fn classify_pool_get_error(detail: &str) -> PoolGetFailureKind {
    if detail
        .strip_prefix(R2D2_TIMEOUT_MESSAGE)
        .and_then(|rest| rest.strip_prefix(": "))
        .is_some()
    {
        PoolGetFailureKind::BackendError
    } else {
        PoolGetFailureKind::Timeout
    }
}

fn map_pool_get_error(backend: &'static str, err: r2d2::Error) -> db_vfs::Error {
    let detail = err.to_string();
    let message = format!("backend={backend} stage=pool_get detail={detail}");
    match classify_pool_get_error(&detail) {
        PoolGetFailureKind::Timeout => db_vfs::Error::Timeout(message),
        PoolGetFailureKind::BackendError => db_vfs::Error::Db(message),
    }
}

#[cfg(debug_assertions)]
fn maybe_reject_test_whole_content_read(content_len: usize) -> db_vfs::Result<()> {
    let Some(raw_limit) = std::env::var_os("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES") else {
        return Ok(());
    };
    let raw_limit = raw_limit.to_string_lossy();
    let limit = raw_limit.parse::<usize>().map_err(|err| {
        db_vfs::Error::Db(format!(
            "invalid DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES={raw_limit:?}: {err}"
        ))
    })?;
    if content_len > limit {
        return Err(db_vfs::Error::Db(format!(
            "test whole-content read guard rejected content_len={content_len} > limit={limit}"
        )));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn maybe_reject_test_whole_content_read(_content_len: usize) -> db_vfs::Result<()> {
    Ok(())
}

#[cfg(feature = "sqlite")]
pub(super) fn sqlite_busy_timeout(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or_else(|| Duration::from_millis(SQLITE_UNBOUNDED_BUSY_TIMEOUT_MS))
}

#[cfg(feature = "postgres")]
fn postgres_timeout_ms(timeout: Option<Duration>) -> u64 {
    match timeout {
        None => 0,
        Some(timeout) => {
            let timeout_ms = timeout.as_millis();
            if timeout_ms == 0 {
                1
            } else {
                timeout_ms.min(u128::from(u64::MAX)) as u64
            }
        }
    }
}

#[cfg(feature = "postgres")]
pub(super) fn configure_postgres_session_timeouts(
    client: &mut r2d2_postgres::postgres::Client,
    timeout: Option<Duration>,
) -> db_vfs::Result<()> {
    let timeout_ms = postgres_timeout_ms(timeout);
    client
        .batch_execute(&format!(
            "SET statement_timeout = {timeout_ms}; SET lock_timeout = {timeout_ms};"
        ))
        .map_err(|err| {
            db_vfs::Error::Db(format!(
                "backend=postgres stage=set_session_timeouts timeout_ms={timeout_ms} error={err}"
            ))
        })?;
    Ok(())
}

impl BackendStore {
    pub(super) fn open(
        backend: Backend,
        pool_timeout: Option<std::time::Duration>,
        operation_timeout: Option<std::time::Duration>,
    ) -> db_vfs::Result<(Self, CancelHandle)> {
        match backend {
            #[cfg(feature = "sqlite")]
            Backend::Sqlite { pool } => {
                let conn = match pool_timeout {
                    Some(timeout) => pool
                        .get_timeout(timeout)
                        .map_err(|err| map_pool_get_error("sqlite", err))?,
                    None => pool
                        .get()
                        .map_err(|err| map_pool_get_error("sqlite", err))?,
                };
                conn.busy_timeout(sqlite_busy_timeout(operation_timeout))
                    .map_err(|err| {
                        db_vfs::Error::Db(format!(
                            "backend=sqlite stage=set_busy_timeout error={err}"
                        ))
                    })?;
                let cancel = CancelHandle::Sqlite(conn.get_interrupt_handle());
                Ok((Self::Sqlite(SqliteStore::from_connection(conn)), cancel))
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let mut client = match pool_timeout {
                    Some(timeout) => pool
                        .get_timeout(timeout)
                        .map_err(|err| map_pool_get_error("postgres", err))?,
                    None => pool
                        .get()
                        .map_err(|err| map_pool_get_error("postgres", err))?,
                };
                configure_postgres_session_timeouts(&mut client, operation_timeout)?;
                let cancel = CancelHandle::Postgres(client.cancel_token());
                Ok((
                    Self::Postgres(Box::new(PostgresStore::from_client(client))),
                    cancel,
                ))
            }
        }
    }
}

macro_rules! dispatch_store {
    ($this:expr, $method:ident($($arg:expr),* $(,)?)) => {
        match $this {
            #[cfg(feature = "sqlite")]
            BackendStore::Sqlite(store) => store.$method($($arg),*),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => store.$method($($arg),*),
        }
    };
}

impl Store for BackendStore {
    fn range_read_mode(&self) -> db_vfs::store::RangeReadMode {
        dispatch_store!(self, range_read_mode())
    }

    fn get_meta(&mut self, workspace_id: &str, path: &str) -> db_vfs::Result<Option<FileMeta>> {
        dispatch_store!(self, get_meta(workspace_id, path))
    }

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> db_vfs::Result<Option<String>> {
        let content = dispatch_store!(self, get_content(workspace_id, path, version))?;
        if let Some(content) = content.as_ref() {
            maybe_reject_test_whole_content_read(content.len())?;
        }
        Ok(content)
    }

    fn get_content_chunk(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_char: u64,
        max_chars: usize,
    ) -> db_vfs::Result<Option<String>> {
        dispatch_store!(
            self,
            get_content_chunk(workspace_id, path, version, start_char, max_chars)
        )
    }

    fn get_line_range(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_line: u64,
        end_line: u64,
        max_bytes: u64,
    ) -> db_vfs::Result<Option<LineRangeData>> {
        dispatch_store!(
            self,
            get_line_range(workspace_id, path, version, start_line, end_line, max_bytes)
        )
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> db_vfs::Result<u64> {
        dispatch_store!(self, insert_file_new(workspace_id, path, content, now_ms))
    }

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> db_vfs::Result<u64> {
        dispatch_store!(
            self,
            update_file_cas(workspace_id, path, content, expected_version, now_ms)
        )
    }

    fn delete_file(
        &mut self,
        workspace_id: &str,
        path: &str,
        expected_version: Option<u64>,
    ) -> db_vfs::Result<DeleteOutcome> {
        dispatch_store!(self, delete_file(workspace_id, path, expected_version))
    }

    fn list_metas_by_prefix(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        limit: usize,
    ) -> db_vfs::Result<Vec<FileMeta>> {
        dispatch_store!(self, list_metas_by_prefix(workspace_id, prefix, limit))
    }

    fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
        dispatch_store!(self, prefix_pagination_mode())
    }

    fn list_metas_by_prefix_page(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> db_vfs::Result<PrefixPage> {
        dispatch_store!(
            self,
            list_metas_by_prefix_page(workspace_id, prefix, after, limit)
        )
    }
}

#[cfg(test)]
mod postgres_tests {
    #[cfg(feature = "postgres")]
    use super::CancelDispatchOutcome;
    #[cfg(feature = "postgres")]
    use super::configure_postgres_session_timeouts;
    #[cfg(feature = "postgres")]
    use super::dispatch_cancel_item;
    #[cfg(feature = "postgres")]
    use super::postgres_timeout_ms;
    #[cfg(feature = "postgres")]
    use r2d2_postgres::postgres::NoTls;
    #[cfg(feature = "postgres")]
    use std::sync::mpsc;
    #[cfg(feature = "postgres")]
    use std::time::Duration;

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_session_timeouts_are_unbounded_without_budget() {
        assert_eq!(postgres_timeout_ms(None), 0);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_session_timeouts_round_positive_sub_millisecond_budget_up() {
        assert_eq!(postgres_timeout_ms(Some(Duration::from_nanos(1))), 1);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_session_timeouts_use_budget_milliseconds() {
        assert_eq!(postgres_timeout_ms(Some(Duration::from_millis(1450))), 1450);
    }

    #[cfg(feature = "postgres")]
    fn postgres_test_url() -> Option<String> {
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

    #[cfg(feature = "postgres")]
    fn current_statement_timeout_ms(client: &mut r2d2_postgres::postgres::Client) -> i64 {
        current_timeout_ms(client, "statement_timeout")
    }

    #[cfg(feature = "postgres")]
    fn current_lock_timeout_ms(client: &mut r2d2_postgres::postgres::Client) -> i64 {
        current_timeout_ms(client, "lock_timeout")
    }

    #[cfg(feature = "postgres")]
    fn current_timeout_ms(client: &mut r2d2_postgres::postgres::Client, name: &str) -> i64 {
        client
            .query_one(
                "SELECT setting::bigint FROM pg_settings WHERE name = $1",
                &[&name],
            )
            .unwrap_or_else(|_| panic!("query {name}"))
            .get(0)
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn configure_postgres_session_timeouts_track_request_budget() {
        let Some(url) = postgres_test_url() else {
            eprintln!("skipping postgres timeout integration test: DB_VFS_TEST_POSTGRES_URL unset");
            return;
        };
        let mut client =
            r2d2_postgres::postgres::Client::connect(&url, NoTls).expect("connect postgres");

        configure_postgres_session_timeouts(&mut client, Some(Duration::from_millis(1450)))
            .expect("set bounded postgres session timeouts");
        assert_eq!(current_statement_timeout_ms(&mut client), 1450);
        assert_eq!(current_lock_timeout_ms(&mut client), 1450);

        configure_postgres_session_timeouts(&mut client, None)
            .expect("clear postgres session timeouts for unbounded scans");
        assert_eq!(current_statement_timeout_ms(&mut client), 0);
        assert_eq!(current_lock_timeout_ms(&mut client), 0);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn dispatch_cancel_item_routes_full_primary_queue_to_overflow_queue() {
        let (primary_tx, primary_rx) = mpsc::sync_channel::<u32>(1);
        primary_tx.send(1).expect("fill primary queue");
        let (overflow_tx, overflow_rx) = mpsc::channel::<u32>();

        let outcome = dispatch_cancel_item(
            2,
            |token| primary_tx.try_send(token),
            |token| overflow_tx.send(token),
        );

        assert!(matches!(outcome, CancelDispatchOutcome::Dispatched));
        assert_eq!(primary_rx.recv().expect("primary token"), 1);
        assert_eq!(overflow_rx.recv().expect("overflow token"), 2);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn dispatch_cancel_item_only_uses_direct_fallback_when_both_paths_are_unavailable() {
        let (primary_tx, primary_rx) = mpsc::sync_channel::<u32>(1);
        primary_tx.send(1).expect("fill primary queue");
        drop(primary_rx);
        let (overflow_tx, overflow_rx) = mpsc::channel::<u32>();
        drop(overflow_rx);

        let outcome = dispatch_cancel_item(
            2,
            |token| primary_tx.try_send(token),
            |token| overflow_tx.send(token),
        );

        match outcome {
            CancelDispatchOutcome::DirectFallback(token) => assert_eq!(token, 2),
            CancelDispatchOutcome::Dispatched => {
                panic!(
                    "direct fallback should be reserved for unavailable primary and overflow paths"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sqlite")]
    use std::sync::{Mutex, OnceLock};

    #[cfg(feature = "sqlite")]
    fn backend_whole_content_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(feature = "sqlite")]
    struct BackendWholeContentGuard {
        previous: Option<std::ffi::OsString>,
    }

    #[cfg(feature = "sqlite")]
    impl BackendWholeContentGuard {
        fn install(limit: usize) -> Self {
            let previous = std::env::var_os("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES");
            // SAFETY: tests serialize access to this process-wide env var.
            unsafe {
                std::env::set_var(
                    "DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES",
                    limit.to_string(),
                );
            }
            Self { previous }
        }
    }

    #[cfg(feature = "sqlite")]
    impl Drop for BackendWholeContentGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(previous) => {
                    // SAFETY: tests serialize access to this process-wide env var.
                    unsafe {
                        std::env::set_var("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES", previous);
                    }
                }
                None => {
                    // SAFETY: tests serialize access to this process-wide env var.
                    unsafe {
                        std::env::remove_var("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES");
                    }
                }
            }
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_backend_open_returns_sqlite_cancel_handle() {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let (store, cancel) =
            BackendStore::open(Backend::Sqlite { pool }, None, None).expect("open backend");

        assert!(matches!(store, BackendStore::Sqlite(_)));
        assert!(matches!(cancel, CancelHandle::Sqlite(_)));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_backend_open_honors_pool_timeout() {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_secs(1))
            .build(manager)
            .expect("sqlite pool");
        let _held = pool.get().expect("hold pooled connection");
        let start = std::time::Instant::now();
        let err = match BackendStore::open(
            Backend::Sqlite { pool: pool.clone() },
            Some(std::time::Duration::from_millis(10)),
            None,
        ) {
            Ok(_) => panic!("open should time out"),
            Err(err) => err,
        };
        assert!(
            start.elapsed() < std::time::Duration::from_millis(300),
            "pool timeout was not honored quickly"
        );
        assert_eq!(err.code(), "timeout");
    }

    #[test]
    fn classify_pool_get_error_treats_timeout_without_backend_detail_as_timeout() {
        assert_eq!(
            classify_pool_get_error(R2D2_TIMEOUT_MESSAGE),
            PoolGetFailureKind::Timeout
        );
    }

    #[test]
    fn classify_pool_get_error_treats_timeout_with_backend_detail_as_db_error() {
        assert_eq!(
            classify_pool_get_error("timed out waiting for connection: connection refused"),
            PoolGetFailureKind::BackendError
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_backend_open_maps_connect_failures_to_db_error() {
        let dir = tempfile::tempdir().expect("temp sqlite dir");
        let manager = r2d2_sqlite::SqliteConnectionManager::file(dir.path());
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .min_idle(Some(0))
            .connection_timeout(std::time::Duration::from_millis(50))
            .build_unchecked(manager);

        let raw = pool
            .get_timeout(std::time::Duration::from_millis(20))
            .expect_err("pool checkout should fail when sqlite manager points at a directory");
        let expected_kind = classify_pool_get_error(&raw.to_string());
        let mapped = map_pool_get_error("sqlite", raw);

        assert_eq!(
            mapped.code(),
            match expected_kind {
                PoolGetFailureKind::Timeout => "timeout",
                PoolGetFailureKind::BackendError => "db",
            }
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_busy_timeout_tracks_request_budget() {
        assert_eq!(
            sqlite_busy_timeout(Some(std::time::Duration::from_millis(1450))),
            std::time::Duration::from_millis(1450)
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_busy_timeout_is_effectively_unbounded_without_budget() {
        assert_eq!(
            sqlite_busy_timeout(None),
            std::time::Duration::from_millis(SQLITE_UNBOUNDED_BUSY_TIMEOUT_MS)
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_backend_maps_locked_read_under_request_budget_to_timeout() {
        let db = tempfile::NamedTempFile::new().expect("temp sqlite file");
        let seed = rusqlite::Connection::open(db.path()).expect("sqlite connection");
        db_vfs::migrations::migrate_sqlite(&seed).expect("migrate sqlite");
        seed.execute(
            "INSERT INTO files(
                workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["ws", "docs/a.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
        )
        .expect("seed file");
        drop(seed);

        let locker = rusqlite::Connection::open(db.path()).expect("lock sqlite connection");
        locker
            .execute_batch("BEGIN EXCLUSIVE;")
            .expect("acquire exclusive sqlite lock");

        let manager = r2d2_sqlite::SqliteConnectionManager::file(db.path());
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let (mut store, _cancel) = BackendStore::open(
            Backend::Sqlite { pool },
            Some(std::time::Duration::from_millis(100)),
            Some(std::time::Duration::from_millis(25)),
        )
        .expect("open backend under sqlite lock");

        let started = std::time::Instant::now();
        let err = store
            .get_meta("ws", "docs/a.txt")
            .expect_err("exclusive sqlite lock should time out the read");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "sqlite busy timeout was not honored quickly"
        );
        assert_eq!(err.code(), "timeout");

        locker
            .execute_batch("ROLLBACK;")
            .expect("release exclusive sqlite lock");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn backend_store_forwards_chunked_content_reads() {
        let _lock = backend_whole_content_test_lock()
            .lock()
            .expect("lock backend whole-content guard");
        let _guard = BackendWholeContentGuard::install(12);
        let db = tempfile::NamedTempFile::new().expect("temp sqlite file");
        let seed = rusqlite::Connection::open(db.path()).expect("sqlite connection");
        db_vfs::migrations::migrate_sqlite(&seed).expect("migrate sqlite");
        seed.execute(
            "INSERT INTO files(
                workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "ws",
                "docs/a.txt",
                "line-0001\nline-0002\nline-0003\nline-0004\n",
                40_i64,
                1_i64,
                1_i64,
                1_i64
            ],
        )
        .expect("seed file");

        let manager = r2d2_sqlite::SqliteConnectionManager::file(db.path());
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let (mut store, _cancel) =
            BackendStore::open(Backend::Sqlite { pool }, None, None).expect("open backend");
        let chunk = store
            .get_content_chunk("ws", "docs/a.txt", 1, 11, 10)
            .expect("chunk read")
            .expect("existing content");
        assert_eq!(chunk, "line-0002\n");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn backend_store_forwards_line_range_reads() {
        let _lock = backend_whole_content_test_lock()
            .lock()
            .expect("lock backend whole-content guard");
        let _guard = BackendWholeContentGuard::install(12);
        let db = tempfile::NamedTempFile::new().expect("temp sqlite file");
        let seed = rusqlite::Connection::open(db.path()).expect("sqlite connection");
        db_vfs::migrations::migrate_sqlite(&seed).expect("migrate sqlite");
        seed.execute(
            "INSERT INTO files(
                workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "ws",
                "docs/a.txt",
                "line-0001\nline-0002\nline-0003\nline-0004\n",
                40_i64,
                1_i64,
                1_i64,
                1_i64
            ],
        )
        .expect("seed file");

        let manager = r2d2_sqlite::SqliteConnectionManager::file(db.path());
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let (mut store, _cancel) =
            BackendStore::open(Backend::Sqlite { pool }, None, None).expect("open backend");
        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 32)
            .expect("line range read")
            .expect("existing content");
        assert_eq!(range.content.as_deref(), Some("line-0002\n"));
        assert_eq!(range.bytes_read, 10);
        assert_eq!(range.total_lines, 2);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_cancel_handle_variant_exists() {
        let _ = std::mem::size_of::<CancelHandle>();
    }
}
