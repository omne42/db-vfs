use db_vfs::store::sqlite::SqliteStore;
use db_vfs::store::{DeleteOutcome, FileMeta, Store};

#[cfg(feature = "postgres")]
use db_vfs::store::postgres::PostgresStore;
#[cfg(feature = "postgres")]
use std::sync::OnceLock;
#[cfg(feature = "postgres")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
type SqliteConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

#[cfg(feature = "postgres")]
type PostgresPool =
    r2d2::Pool<r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>>;
#[cfg(feature = "postgres")]
type PostgresConn = r2d2::PooledConnection<
    r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>,
>;
#[cfg(feature = "postgres")]
const POSTGRES_CANCEL_QUEUE_CAPACITY: usize = 1024;
#[cfg(feature = "postgres")]
struct PostgresCancelDispatch {
    tx: Option<std::sync::mpsc::SyncSender<r2d2_postgres::postgres::CancelToken>>,
}
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_DISPATCH: OnceLock<PostgresCancelDispatch> = OnceLock::new();
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_QUEUE_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "postgres")]
const POSTGRES_CANCEL_FALLBACK_MAX_INFLIGHT: usize = 64;
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_FALLBACK_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "postgres")]
static POSTGRES_CANCEL_FALLBACK_SKIPPED: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "postgres")]
struct PostgresCancelFallbackInflightGuard;

#[cfg(feature = "postgres")]
impl Drop for PostgresCancelFallbackInflightGuard {
    fn drop(&mut self) {
        POSTGRES_CANCEL_FALLBACK_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

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

#[derive(Clone)]
pub(super) enum Backend {
    Sqlite {
        pool: SqlitePool,
    },
    #[cfg(feature = "postgres")]
    Postgres {
        pool: PostgresPool,
    },
}

pub(super) enum BackendStore {
    Sqlite(SqliteStore<SqliteConn>),
    #[cfg(feature = "postgres")]
    Postgres(PostgresStore<PostgresConn>),
}

pub(super) enum CancelHandle {
    Sqlite(rusqlite::InterruptHandle),
    #[cfg(feature = "postgres")]
    Postgres(r2d2_postgres::postgres::CancelToken),
}

impl CancelHandle {
    pub(super) fn cancel(&self) {
        match self {
            CancelHandle::Sqlite(handle) => handle.interrupt(),
            #[cfg(feature = "postgres")]
            CancelHandle::Postgres(token) => {
                if let Some(cancel_tx) = postgres_cancel_tx()
                    && cancel_tx.try_send(token.clone()).is_ok()
                {
                    return;
                }
                let token = token.clone();
                let fallback_count =
                    POSTGRES_CANCEL_QUEUE_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if fallback_count == 1 || fallback_count.is_multiple_of(100) {
                    tracing::warn!(
                        fallback_count,
                        "postgres cancel queue saturated/disconnected; falling back to ad-hoc cancel task"
                    );
                }
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let in_flight =
                        POSTGRES_CANCEL_FALLBACK_INFLIGHT.fetch_add(1, Ordering::AcqRel) + 1;
                    if in_flight > POSTGRES_CANCEL_FALLBACK_MAX_INFLIGHT {
                        POSTGRES_CANCEL_FALLBACK_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
                        let skipped =
                            POSTGRES_CANCEL_FALLBACK_SKIPPED.fetch_add(1, Ordering::Relaxed) + 1;
                        if skipped == 1 || skipped.is_multiple_of(100) {
                            tracing::warn!(
                                skipped,
                                in_flight,
                                max_in_flight = POSTGRES_CANCEL_FALLBACK_MAX_INFLIGHT,
                                "postgres cancel fallback saturated; skipping ad-hoc cancel task"
                            );
                        }
                        return;
                    }
                    runtime.spawn_blocking(move || {
                        let _inflight_guard = PostgresCancelFallbackInflightGuard;
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

fn map_pool_get_error(backend: &'static str, err: impl std::fmt::Display) -> db_vfs::Error {
    db_vfs::Error::Db(format!("backend={backend} stage=pool_get error={err}"))
}

impl BackendStore {
    pub(super) fn open(
        backend: Backend,
        pool_timeout: Option<std::time::Duration>,
    ) -> db_vfs::Result<(Self, CancelHandle)> {
        match backend {
            Backend::Sqlite { pool } => {
                let conn = match pool_timeout {
                    Some(timeout) => pool
                        .get_timeout(timeout)
                        .map_err(|err| map_pool_get_error("sqlite", err))?,
                    None => pool
                        .get()
                        .map_err(|err| map_pool_get_error("sqlite", err))?,
                };
                let cancel = CancelHandle::Sqlite(conn.get_interrupt_handle());
                Ok((Self::Sqlite(SqliteStore::from_connection(conn)), cancel))
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = match pool_timeout {
                    Some(timeout) => pool
                        .get_timeout(timeout)
                        .map_err(|err| map_pool_get_error("postgres", err))?,
                    None => pool
                        .get()
                        .map_err(|err| map_pool_get_error("postgres", err))?,
                };
                let cancel = CancelHandle::Postgres(client.cancel_token());
                Ok((Self::Postgres(PostgresStore::from_client(client)), cancel))
            }
        }
    }
}

macro_rules! dispatch_store {
    ($this:expr, $method:ident($($arg:expr),* $(,)?)) => {
        match $this {
            BackendStore::Sqlite(store) => store.$method($($arg),*),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => store.$method($($arg),*),
        }
    };
}

impl Store for BackendStore {
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> db_vfs::Result<Option<FileMeta>> {
        dispatch_store!(self, get_meta(workspace_id, path))
    }

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> db_vfs::Result<Option<String>> {
        dispatch_store!(self, get_content(workspace_id, path, version))
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

    fn list_metas_by_prefix_page(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> db_vfs::Result<Vec<FileMeta>> {
        dispatch_store!(
            self,
            list_metas_by_prefix_page(workspace_id, prefix, after, limit)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_backend_open_returns_sqlite_cancel_handle() {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let (store, cancel) =
            BackendStore::open(Backend::Sqlite { pool }, None).expect("open backend");

        assert!(matches!(store, BackendStore::Sqlite(_)));
        assert!(matches!(cancel, CancelHandle::Sqlite(_)));
    }

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
        ) {
            Ok(_) => panic!("open should time out"),
            Err(err) => err,
        };
        assert!(
            start.elapsed() < std::time::Duration::from_millis(300),
            "pool timeout was not honored quickly"
        );
        assert_eq!(err.code(), "db");
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_cancel_handle_variant_exists() {
        let _ = std::mem::size_of::<CancelHandle>();
    }
}
