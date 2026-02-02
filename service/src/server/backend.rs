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
    Sqlite(Box<SqliteStore<SqliteConn>>),
    #[cfg(feature = "postgres")]
    Postgres(Box<PostgresStore<PostgresConn>>),
}

pub(super) enum CancelHandle {
    Sqlite(rusqlite::InterruptHandle),
}

impl CancelHandle {
    pub(super) fn cancel(&self) {
        match self {
            CancelHandle::Sqlite(handle) => handle.interrupt(),
        }
    }
}

impl BackendStore {
    pub(super) fn open(backend: Backend) -> db_vfs::Result<(Self, Option<CancelHandle>)> {
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let cancel = Some(CancelHandle::Sqlite(conn.get_interrupt_handle()));
                Ok((
                    Self::Sqlite(Box::new(SqliteStore::from_connection(conn))),
                    cancel,
                ))
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                Ok((
                    Self::Postgres(Box::new(PostgresStore::from_client(client))),
                    None,
                ))
            }
        }
    }
}

impl Store for BackendStore {
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> db_vfs::Result<Option<FileMeta>> {
        match self {
            BackendStore::Sqlite(store) => store.get_meta(workspace_id, path),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => store.get_meta(workspace_id, path),
        }
    }

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> db_vfs::Result<Option<String>> {
        match self {
            BackendStore::Sqlite(store) => store.get_content(workspace_id, path, version),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => store.get_content(workspace_id, path, version),
        }
    }

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> db_vfs::Result<FileRecord> {
        match self {
            BackendStore::Sqlite(store) => {
                store.insert_file_new(workspace_id, path, content, now_ms)
            }
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => {
                store.insert_file_new(workspace_id, path, content, now_ms)
            }
        }
    }

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> db_vfs::Result<FileRecord> {
        match self {
            BackendStore::Sqlite(store) => {
                store.update_file_cas(workspace_id, path, content, expected_version, now_ms)
            }
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => {
                store.update_file_cas(workspace_id, path, content, expected_version, now_ms)
            }
        }
    }

    fn delete_file(
        &mut self,
        workspace_id: &str,
        path: &str,
        expected_version: Option<u64>,
    ) -> db_vfs::Result<DeleteOutcome> {
        match self {
            BackendStore::Sqlite(store) => store.delete_file(workspace_id, path, expected_version),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => {
                store.delete_file(workspace_id, path, expected_version)
            }
        }
    }

    fn list_metas_by_prefix(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        limit: usize,
    ) -> db_vfs::Result<Vec<FileMeta>> {
        match self {
            BackendStore::Sqlite(store) => store.list_metas_by_prefix(workspace_id, prefix, limit),
            #[cfg(feature = "postgres")]
            BackendStore::Postgres(store) => {
                store.list_metas_by_prefix(workspace_id, prefix, limit)
            }
        }
    }
}
