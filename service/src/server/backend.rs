use db_vfs::store::sqlite::SqliteStore;
use db_vfs::store::{DeleteOutcome, FileMeta, FileRecord, Store};

#[cfg(feature = "postgres")]
use db_vfs::store::postgres::PostgresStore;

type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
type SqliteConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

#[cfg(feature = "postgres")]
type PostgresPool =
    r2d2::Pool<r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>>;
#[cfg(feature = "postgres")]
type PostgresConn = r2d2::PooledConnection<
    r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>,
>;

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
    Unsupported,
}

impl CancelHandle {
    pub(super) fn cancel(&self) {
        match self {
            CancelHandle::Sqlite(handle) => handle.interrupt(),
            #[cfg(feature = "postgres")]
            CancelHandle::Unsupported => {}
        }
    }
}

fn map_pool_get_error(backend: &'static str, err: impl std::fmt::Display) -> db_vfs::Error {
    db_vfs::Error::Db(format!("backend={backend} stage=pool_get error={err}"))
}

impl BackendStore {
    pub(super) fn open(backend: Backend) -> db_vfs::Result<(Self, CancelHandle)> {
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| map_pool_get_error("sqlite", err))?;
                let cancel = CancelHandle::Sqlite(conn.get_interrupt_handle());
                Ok((Self::Sqlite(SqliteStore::from_connection(conn)), cancel))
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| map_pool_get_error("postgres", err))?;
                Ok((
                    Self::Postgres(PostgresStore::from_client(client)),
                    CancelHandle::Unsupported,
                ))
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
    ) -> db_vfs::Result<FileRecord> {
        dispatch_store!(self, insert_file_new(workspace_id, path, content, now_ms))
    }

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> db_vfs::Result<FileRecord> {
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
        let (store, cancel) = BackendStore::open(Backend::Sqlite { pool }).expect("open backend");

        assert!(matches!(store, BackendStore::Sqlite(_)));
        assert!(matches!(cancel, CancelHandle::Sqlite(_)));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn cancel_unsupported_is_noop() {
        CancelHandle::Unsupported.cancel();
    }
}
