use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;

use db_vfs::vfs::DbVfs;
use db_vfs_core::policy::VfsPolicy;

pub(super) fn io_timeout(policy: &VfsPolicy) -> Duration {
    Duration::from_millis(policy.limits.max_io_ms.saturating_add(250))
}

pub(super) fn scan_timeout(policy: &VfsPolicy) -> Option<Duration> {
    policy
        .limits
        .max_walk_ms
        .map(|ms| Duration::from_millis(ms.saturating_add(250)))
}

struct CancelState {
    requested: AtomicBool,
    handle: Mutex<Option<super::backend::CancelHandle>>,
}

impl CancelState {
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            handle: Mutex::new(None),
        }
    }

    fn request_cancel(&self) {
        self.requested.store(true, Ordering::Release);
        if let Ok(guard) = self.handle.try_lock()
            && let Some(handle) = guard.as_ref()
        {
            handle.cancel();
        }
    }

    fn set_handle(&self, handle: super::backend::CancelHandle) {
        if let Ok(mut guard) = self.handle.lock() {
            let should_cancel = self.requested.load(Ordering::Acquire);
            *guard = Some(handle);
            if should_cancel && let Some(handle) = guard.as_ref() {
                handle.cancel();
            }
        }
    }
}

async fn run_blocking<T>(
    timeout: Option<Duration>,
    cancel: Option<Arc<CancelState>>,
    f: impl FnOnce() -> db_vfs::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, Json<super::ErrorBody>)>
where
    T: Send + 'static,
{
    let mut handle = tokio::task::spawn_blocking(f);
    let join = if let Some(timeout) = timeout {
        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);
        tokio::select! {
            res = &mut handle => res,
            _ = &mut sleep => {
                if let Some(cancel) = cancel {
                    cancel.request_cancel();
                }
                handle.abort();
                tracing::warn!(timeout_ms = timeout.as_millis() as u64, "db-vfs request timed out");
                return Err(super::err(StatusCode::REQUEST_TIMEOUT, "timeout", "request timed out"));
            }
        }
    } else {
        handle.await
    };

    let result = join.map_err(|err| super::map_err(db_vfs_core::Error::Db(err.to_string())))?;
    result.map_err(super::map_err)
}

pub(super) async fn run_vfs<T>(
    state: super::AppState,
    permit: tokio::sync::OwnedSemaphorePermit,
    timeout: Option<Duration>,
    op: impl FnOnce(&mut DbVfs<super::backend::BackendStore>) -> db_vfs::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, Json<super::ErrorBody>)>
where
    T: Send + 'static,
{
    let _permit = permit;
    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();
    let traversal = state.inner.traversal.clone();

    let cancel = Arc::new(CancelState::new());
    let cancel_for_timeout = cancel.clone();
    let cancel_for_worker = cancel.clone();

    run_blocking(
        timeout,
        Some(cancel_for_timeout),
        move || -> db_vfs::Result<T> {
            let (store, cancel_handle) = super::backend::BackendStore::open(backend)?;
            if let Some(cancel_handle) = cancel_handle {
                cancel_for_worker.set_handle(cancel_handle);
            }
            let mut vfs = DbVfs::new_with_matchers(store, policy, redactor, traversal)?;
            op(&mut vfs)
        },
    )
    .await
}
