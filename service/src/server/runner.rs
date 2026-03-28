use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;

use db_vfs::vfs::DbVfs;
use db_vfs_core::policy::VfsPolicy;

static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COMPLETED_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COMPLETED_TOTAL_MS: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COMPLETED_LONG_COUNT: AtomicU64 = AtomicU64::new(0);
const TIMEOUT_COMPLETED_LONG_MS: u64 = 30_000;

pub(super) fn io_timeout(policy: &VfsPolicy) -> Duration {
    Duration::from_millis(policy.limits.max_io_ms)
}

pub(super) fn scan_timeout(policy: &VfsPolicy) -> Option<Duration> {
    policy.limits.max_walk_ms.map(Duration::from_millis)
}

pub(super) fn db_pool_timeout(policy: &VfsPolicy) -> Duration {
    io_timeout(policy)
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
        if self.requested.swap(true, Ordering::AcqRel) {
            return;
        }
        match self.handle.lock() {
            Ok(guard) => {
                if let Some(handle) = guard.as_ref() {
                    handle.cancel();
                }
            }
            Err(_) => {
                tracing::error!("cancel state lock poisoned while requesting cancellation");
            }
        }
    }

    fn set_handle(&self, handle: super::backend::CancelHandle) {
        if let Ok(mut guard) = self.handle.lock() {
            *guard = Some(handle);
            if self.requested.load(Ordering::Acquire)
                && let Some(handle) = guard.as_ref()
            {
                handle.cancel();
            }
        } else {
            tracing::error!("cancel state lock poisoned while installing cancel handle");
        }
    }
}

async fn run_blocking<T>(
    timeout: Option<Duration>,
    permit: tokio::sync::OwnedSemaphorePermit,
    cancel: Option<Arc<CancelState>>,
    f: impl FnOnce() -> db_vfs::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, Json<super::ErrorBody>)>
where
    T: Send + 'static,
{
    let timed_out = timeout.map(|_| Arc::new(AtomicBool::new(false)));
    let timed_out_for_worker = timed_out.clone();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let started = Instant::now();
        let result = f();
        if let Some(timed_out) = timed_out_for_worker
            && timed_out.load(Ordering::Acquire)
        {
            let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            if elapsed_ms >= TIMEOUT_COMPLETED_LONG_MS {
                let long_count = TIMEOUT_COMPLETED_LONG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if long_count == 1 || long_count.is_multiple_of(50) {
                    tracing::warn!(
                        elapsed_ms,
                        long_count,
                        threshold_ms = TIMEOUT_COMPLETED_LONG_MS,
                        "db-vfs timed-out request worker ran for too long in background"
                    );
                }
            }
            let completed = TIMEOUT_COMPLETED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let total_ms =
                TIMEOUT_COMPLETED_TOTAL_MS.fetch_add(elapsed_ms, Ordering::Relaxed) + elapsed_ms;
            if completed == 1 || completed.is_multiple_of(100) {
                tracing::warn!(
                    elapsed_ms,
                    timed_out_worker_count = completed,
                    timed_out_worker_avg_elapsed_ms = total_ms / completed,
                    "db-vfs timed-out request finished in background"
                );
            }
        }
        result
    });
    let join = if let Some(timeout) = timeout {
        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);
        tokio::select! {
            biased;
            res = &mut handle => res,
            _ = &mut sleep => {
                if let Some(timed_out) = timed_out.as_ref() {
                    timed_out.store(true, Ordering::Release);
                }
                if let Some(cancel) = cancel {
                    cancel.request_cancel();
                }
                handle.abort();
                let timeout_count = TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if timeout_count == 1 || timeout_count.is_multiple_of(100) {
                    tracing::warn!(
                        timeout_ms = timeout.as_millis() as u64,
                        timeout_count,
                        "db-vfs request timed out"
                    );
                }
                return Err(super::err(
                    StatusCode::REQUEST_TIMEOUT,
                    "timeout",
                    "request timed out; operation status is unknown and may still complete",
                ));
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
    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();
    let traversal = state.inner.traversal.clone();
    let pool_timeout = Some(db_pool_timeout(policy.as_ref()));

    let cancel = timeout.map(|_| Arc::new(CancelState::new()));
    let cancel_for_timeout = cancel.clone();
    let cancel_for_worker = cancel;

    run_blocking(
        timeout,
        permit,
        cancel_for_timeout,
        move || -> db_vfs::Result<T> {
            let (store, cancel_handle) =
                super::backend::BackendStore::open(backend, pool_timeout, timeout)?;
            if let Some(cancel) = cancel_for_worker.as_ref() {
                cancel.set_handle(cancel_handle);
            }
            let mut vfs =
                DbVfs::try_new_with_matchers_validated(store, policy, redactor, traversal)?;
            op(&mut vfs)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_vfs_core::policy::VfsPolicy;

    #[test]
    fn scan_timeout_is_unbounded_when_walk_limit_missing() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_io_ms = 700;
        policy.limits.max_walk_ms = None;
        assert_eq!(scan_timeout(&policy), None);
    }

    #[test]
    fn scan_timeout_prefers_walk_limit_when_present() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_io_ms = 700;
        policy.limits.max_walk_ms = Some(1200);
        assert_eq!(scan_timeout(&policy), Some(Duration::from_millis(1200)));
    }

    #[test]
    fn db_pool_timeout_stays_bounded_by_io_limit() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_io_ms = 700;
        policy.limits.max_walk_ms = None;
        assert_eq!(db_pool_timeout(&policy), Duration::from_millis(700));
    }

    #[tokio::test]
    async fn timeout_keeps_permit_until_worker_finishes() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();

        let run = tokio::spawn(async move {
            run_blocking(
                Some(Duration::from_millis(100)),
                permit,
                None,
                move || -> db_vfs::Result<()> {
                    let _ = started_tx.send(());
                    std::thread::sleep(Duration::from_millis(250));
                    Ok(())
                },
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("worker started")
            .expect("start signal");
        let result = run.await.expect("run task join");
        let err = result.expect_err("request should time out");
        assert_eq!(err.0, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(err.1.0.code, "timeout");
        assert!(
            err.1.0.message.contains("status is unknown"),
            "timeout message should describe unknown completion semantics"
        );

        let immediate =
            tokio::time::timeout(Duration::from_millis(10), semaphore.clone().acquire_owned())
                .await;
        assert!(
            immediate.is_err(),
            "permit should still be held by timed-out worker"
        );

        let eventual = tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                    return permit;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            eventual.is_ok(),
            "permit should be released after worker exits"
        );
    }
}
