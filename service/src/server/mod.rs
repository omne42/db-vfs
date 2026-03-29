//! HTTP server implementation.

mod audit;
mod auth;
mod backend;
mod handlers;
mod layers;
mod rate_limiter;
mod runner;

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use db_vfs_core::policy::ValidatedVfsPolicy;
use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;

#[derive(Clone)]
struct AppState {
    inner: Arc<AppInner>,
}

struct AppInner {
    backend: backend::Backend,
    policy: Arc<ValidatedVfsPolicy>,
    redactor: Arc<SecretRedactor>,
    traversal: Arc<TraversalSkipper>,
    audit: Option<audit::AuditLogger>,
    auth: auth::AuthMode,
    rate_limiter: rate_limiter::RateLimiter,
    io_concurrency: Arc<tokio::sync::Semaphore>,
    scan_concurrency: Arc<tokio::sync::Semaphore>,
}

struct PreparedState {
    policy: Arc<ValidatedVfsPolicy>,
    redactor: Arc<SecretRedactor>,
    traversal: Arc<TraversalSkipper>,
    audit: Option<audit::AuditLogger>,
    auth: auth::AuthMode,
    rate_limiter: rate_limiter::RateLimiter,
    io_concurrency: usize,
    scan_concurrency: usize,
    body_limit: usize,
}

#[derive(Debug, serde::Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

fn err(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            code,
            message: message.into(),
        }),
    )
}

fn err_response(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    err(status, code, message).into_response()
}

fn audit_failure_response(audit_err: audit::AuditFailure) -> (StatusCode, Json<ErrorBody>) {
    tracing::error!(err = %audit_err, "required audit logging failed");
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        CODE_AUDIT_UNAVAILABLE,
        "required audit logging failed; operation status is unknown and may still have completed",
    )
}

async fn log_audit_event(
    audit: &audit::AuditLogger,
    event: audit::AuditEvent,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let audit = audit.clone();
    tokio::task::spawn_blocking(move || audit.try_log(event))
        .await
        .map_err(|err| {
            audit_failure_response(audit::AuditFailure::new(format!(
                "audit wait task failed: {err}"
            )))
        })?
        .map_err(audit_failure_response)
}

async fn log_audit_event_with_permit(
    audit: &audit::AuditLogger,
    event: audit::AuditEvent,
    permit: tokio::sync::OwnedSemaphorePermit,
    budget: Option<Duration>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let audit = audit.clone();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        audit.try_log(event)
    });

    let result = if let Some(timeout) = budget {
        if timeout.is_zero() {
            handle.abort();
            return Err(audit_failure_response(audit::AuditFailure::new(
                "audit wait budget exhausted before append+flush completed",
            )));
        }

        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(join) => join,
            Err(_) => {
                handle.abort();
                return Err(audit_failure_response(audit::AuditFailure::new(format!(
                    "audit append+flush exceeded the remaining request budget ({timeout:?})"
                ))));
            }
        }
    } else {
        handle.await
    };

    result
        .map_err(|err| {
            audit_failure_response(audit::AuditFailure::new(format!(
                "audit wait task failed: {err}"
            )))
        })?
        .map_err(audit_failure_response)
}

const CODE_NOT_PERMITTED: &str = "not_permitted";
const CODE_SECRET_PATH_DENIED: &str = "secret_path_denied";
const CODE_INVALID_PATH: &str = "invalid_path";
const CODE_INVALID_POLICY: &str = "invalid_policy";
const CODE_INVALID_REGEX: &str = "invalid_regex";
const CODE_PATCH: &str = "patch";
const CODE_NOT_FOUND: &str = "not_found";
const CODE_CONFLICT: &str = "conflict";
const CODE_INPUT_TOO_LARGE: &str = "input_too_large";
const CODE_FILE_TOO_LARGE: &str = "file_too_large";
const CODE_QUOTA_EXCEEDED: &str = "quota_exceeded";
const CODE_TIMEOUT: &str = "timeout";
const CODE_AUDIT_UNAVAILABLE: &str = "audit_unavailable";
const RECOMMENDED_MAX_SCAN_INFLIGHT_BYTES: u64 = 512 * 1024 * 1024;

fn status_for_error_code(code: &str) -> StatusCode {
    match code {
        CODE_NOT_PERMITTED | CODE_SECRET_PATH_DENIED => StatusCode::FORBIDDEN,
        CODE_INVALID_PATH | CODE_INVALID_POLICY | CODE_INVALID_REGEX | CODE_PATCH => {
            StatusCode::BAD_REQUEST
        }
        CODE_NOT_FOUND => StatusCode::NOT_FOUND,
        CODE_CONFLICT => StatusCode::CONFLICT,
        CODE_INPUT_TOO_LARGE | CODE_FILE_TOO_LARGE | CODE_QUOTA_EXCEEDED => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        CODE_TIMEOUT => StatusCode::REQUEST_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_err(err: db_vfs_core::Error) -> (StatusCode, Json<ErrorBody>) {
    let code = err.code();
    let status = status_for_error_code(code);

    let message = if status.is_server_error() {
        tracing::error!(code, err = %err, "db-vfs request failed");
        "internal error".to_string()
    } else if code == CODE_SECRET_PATH_DENIED {
        "path is denied by secret rules".to_string()
    } else {
        err.to_string()
    };

    (status, Json(ErrorBody { code, message }))
}

fn max_body_bytes(policy: &VfsPolicy) -> usize {
    const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024 + 64 * 1024;
    let patch = policy
        .limits
        .max_patch_bytes
        .unwrap_or(policy.limits.max_read_bytes);
    let max = policy
        .limits
        .max_read_bytes
        .max(policy.limits.max_write_bytes)
        .max(patch);
    let max = max.saturating_add(64 * 1024);
    let max = max.min(MAX_BODY_BYTES);
    usize::try_from(max).unwrap_or(usize::MAX)
}

fn prepare_state(
    mut policy: ValidatedVfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<PreparedState> {
    let estimated_scan_inflight_bytes = policy
        .limits
        .max_read_bytes
        .saturating_mul(policy.limits.max_concurrency_scan as u64);
    if estimated_scan_inflight_bytes > RECOMMENDED_MAX_SCAN_INFLIGHT_BYTES {
        tracing::warn!(
            max_read_bytes = policy.limits.max_read_bytes,
            max_concurrency_scan = policy.limits.max_concurrency_scan,
            estimated_scan_inflight_bytes,
            recommended_max_scan_inflight_bytes = RECOMMENDED_MAX_SCAN_INFLIGHT_BYTES,
            "scan memory budget is high; consider lowering limits.max_read_bytes or limits.max_concurrency_scan"
        );
    }

    let redactor = SecretRedactor::from_rules(&policy.secrets).map_err(anyhow::Error::msg)?;
    let traversal = TraversalSkipper::from_rules(&policy.traversal).map_err(anyhow::Error::msg)?;
    let io_concurrency = policy.limits.max_concurrency_io;
    let scan_concurrency = policy.limits.max_concurrency_scan;
    let rate_limiter = rate_limiter::RateLimiter::new(&policy);
    let auth = auth::build_auth_mode(&policy, unsafe_no_auth)?;
    let audit = if let Some(path) = policy.audit.jsonl_path.as_deref() {
        let flush_every_events = policy
            .audit
            .flush_every_events
            .unwrap_or(audit::DEFAULT_AUDIT_FLUSH_EVERY_EVENTS);
        let flush_max_interval = policy.audit.flush_max_interval_ms.map_or(
            audit::DEFAULT_AUDIT_FLUSH_MAX_INTERVAL,
            Duration::from_millis,
        );

        match audit::AuditLogger::new(
            path,
            policy.audit.required,
            flush_every_events,
            flush_max_interval,
        ) {
            Ok(logger) => Some(logger),
            Err(err) if policy.audit.required => return Err(err),
            Err(err) => {
                tracing::warn!(
                    err = %err,
                    audit_path = %path,
                    "failed to initialize audit log; continuing with audit disabled"
                );
                None
            }
        }
    } else {
        None
    };

    let auth_token_count = policy.auth.tokens.len();
    let auth_allowed_workspace_patterns: usize = policy
        .auth
        .tokens
        .iter()
        .map(|rule| rule.allowed_workspaces.len())
        .sum();
    tracing::info!(
        auth_enabled = !unsafe_no_auth,
        auth_token_count,
        auth_allowed_workspace_patterns,
        "auth configuration loaded"
    );

    policy.clear_auth_tokens();

    let body_limit = max_body_bytes(&policy);
    Ok(PreparedState {
        policy: Arc::new(policy),
        redactor: Arc::new(redactor),
        traversal: Arc::new(traversal),
        audit,
        auth,
        rate_limiter,
        io_concurrency,
        scan_concurrency,
        body_limit,
    })
}

fn build_state(backend: backend::Backend, prepared: PreparedState) -> (AppState, usize) {
    let state = AppState {
        inner: Arc::new(AppInner {
            backend,
            policy: prepared.policy,
            redactor: prepared.redactor,
            traversal: prepared.traversal,
            audit: prepared.audit,
            auth: prepared.auth,
            rate_limiter: prepared.rate_limiter,
            io_concurrency: Arc::new(tokio::sync::Semaphore::new(prepared.io_concurrency)),
            scan_concurrency: Arc::new(tokio::sync::Semaphore::new(prepared.scan_concurrency)),
        }),
    };

    (state, prepared.body_limit)
}

fn build_router(state: AppState, body_limit: usize) -> Router {
    Router::new()
        .route("/v1/read", post(handlers::read))
        .route("/v1/write", post(handlers::write))
        .route("/v1/patch", post(handlers::patch))
        .route("/v1/delete", post(handlers::delete))
        .route("/v1/glob", post(handlers::glob))
        .route("/v1/grep", post(handlers::grep))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            layers::rate_limit_middleware,
        ))
        .layer(middleware::from_fn(layers::request_id_middleware))
        .with_state(state)
}

fn sqlite_uses_in_memory_pool(db_path: &std::path::Path) -> bool {
    db_path == std::path::Path::new(":memory:")
}

fn startup_migration_timeout(policy: &VfsPolicy) -> Duration {
    Duration::from_millis(policy.limits.max_io_ms)
}

fn sqlite_connection_manager(
    db_path: &std::path::Path,
    startup_busy_timeout: Duration,
) -> r2d2_sqlite::SqliteConnectionManager {
    let manager = if sqlite_uses_in_memory_pool(db_path) {
        r2d2_sqlite::SqliteConnectionManager::memory()
    } else {
        r2d2_sqlite::SqliteConnectionManager::file(db_path)
    };
    manager.with_init(move |conn| {
        conn.busy_timeout(startup_busy_timeout)?;
        Ok(())
    })
}

fn sqlite_pool_max_size(db_path: &std::path::Path, configured: u32) -> u32 {
    if sqlite_uses_in_memory_pool(db_path) {
        1
    } else {
        configured
    }
}

pub fn build_app_sqlite(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    let policy = ValidatedVfsPolicy::new(policy).map_err(anyhow::Error::msg)?;
    let prepared = prepare_state(policy, unsafe_no_auth)?;
    let migration_timeout = startup_migration_timeout(prepared.policy.as_ref());
    let manager = sqlite_connection_manager(&db_path, migration_timeout);
    let max_pool_size = sqlite_pool_max_size(&db_path, prepared.policy.limits.max_db_connections);
    if max_pool_size != prepared.policy.limits.max_db_connections {
        tracing::warn!(
            configured_max_db_connections = prepared.policy.limits.max_db_connections,
            effective_max_db_connections = max_pool_size,
            "sqlite :memory: forces a single pooled connection so schema and data stay consistent"
        );
    }
    let pool = r2d2::Pool::builder()
        .max_size(max_pool_size)
        .connection_timeout(migration_timeout)
        .build(manager)
        .map_err(anyhow::Error::msg)?;
    {
        let conn = pool.get().map_err(anyhow::Error::msg)?;
        db_vfs::migrations::migrate_sqlite(&conn).map_err(anyhow::Error::msg)?;
    }

    let (state, body_limit) = build_state(backend::Backend::Sqlite { pool }, prepared);

    Ok(build_router(state, body_limit))
}

#[cfg(feature = "postgres")]
pub fn build_app_postgres(
    url: String,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    let policy = ValidatedVfsPolicy::new(policy).map_err(anyhow::Error::msg)?;
    let prepared = prepare_state(policy, unsafe_no_auth)?;
    let migration_timeout = startup_migration_timeout(prepared.policy.as_ref());

    let mut config: r2d2_postgres::postgres::Config = url.parse()?;
    config.connect_timeout(migration_timeout);

    {
        let mut client = config.connect(r2d2_postgres::postgres::NoTls)?;
        backend::configure_postgres_session_timeouts(&mut client, Some(migration_timeout))
            .map_err(anyhow::Error::msg)?;
        db_vfs::migrations::migrate_postgres(&mut client).map_err(anyhow::Error::msg)?;
    }

    let manager =
        r2d2_postgres::PostgresConnectionManager::new(config, r2d2_postgres::postgres::NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(prepared.policy.limits.max_db_connections)
        .connection_timeout(migration_timeout)
        .build(manager)?;

    let (state, body_limit) = build_state(backend::Backend::Postgres { pool }, prepared);
    Ok(build_router(state, body_limit))
}

/// Convenience entrypoint using the SQLite backend.
///
/// For PostgreSQL, call `build_app_postgres` when the `postgres` feature is enabled.
///
/// The returned router can be served with or without `ConnectInfo<SocketAddr>`. When no peer
/// address is installed by the outer server, request handling still succeeds; audit `peer_ip`
/// stays unset and rate limiting falls back to the shared unspecified-IP bucket.
pub fn build_app(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    build_app_sqlite(db_path, policy, unsafe_no_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use tempfile::tempdir;

    #[test]
    fn audit_required_false_allows_startup_when_audit_path_invalid() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::create_dir_all(&audit_path).expect("create_dir_all");

        let mut policy = VfsPolicy::default();
        policy.audit.jsonl_path = Some(audit_path.to_string_lossy().into_owned());
        policy.audit.required = false;

        assert!(build_app_sqlite(db_path, policy, true).is_ok());
    }

    #[test]
    fn audit_required_true_fails_startup_when_audit_path_invalid() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::create_dir_all(&audit_path).expect("create_dir_all");

        let mut policy = VfsPolicy::default();
        policy.audit.jsonl_path = Some(audit_path.to_string_lossy().into_owned());

        let err = build_app_sqlite(db_path.clone(), policy, true).expect_err("should fail");
        assert!(
            err.to_string()
                .contains("audit.jsonl_path must be a regular file")
        );
        assert!(
            !db_path.exists(),
            "invalid required audit config should fail before touching sqlite"
        );
    }

    #[test]
    fn auth_validation_fails_before_touching_sqlite() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");

        let err = build_app_sqlite(db_path.clone(), VfsPolicy::default(), false)
            .expect_err("missing auth tokens should fail");
        assert!(err.to_string().contains("no auth tokens configured"));
        assert!(
            !db_path.exists(),
            "invalid auth config should fail before touching sqlite"
        );
    }

    #[test]
    fn map_err_db_is_internal_and_redacted() {
        let (status, Json(body)) = map_err(db_vfs_core::Error::Db("boom".to_string()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.code, "db");
        assert_eq!(body.message, "internal error");
    }

    #[test]
    fn map_err_timeout_is_request_timeout_and_not_redacted() {
        let (status, Json(body)) = map_err(db_vfs_core::Error::Timeout(
            "backend wait expired".to_string(),
        ));
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(body.code, "timeout");
        assert_eq!(body.message, "timeout: backend wait expired");
    }

    #[test]
    fn max_body_bytes_is_capped_to_hard_limit() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_read_bytes = u64::MAX;
        policy.limits.max_write_bytes = u64::MAX;
        policy.limits.max_patch_bytes = Some(u64::MAX);

        assert_eq!(
            max_body_bytes(&policy),
            (256 * 1024 * 1024 + 64 * 1024) as usize
        );
    }

    #[test]
    fn sqlite_memory_path_uses_single_connection_pool() {
        assert!(sqlite_uses_in_memory_pool(std::path::Path::new(":memory:")));
        assert!(!sqlite_uses_in_memory_pool(std::path::Path::new(
            "db.sqlite"
        )));
        assert_eq!(
            sqlite_pool_max_size(std::path::Path::new(":memory:"), 16),
            1
        );
        assert_eq!(
            sqlite_pool_max_size(std::path::Path::new("db.sqlite"), 16),
            16
        );
    }

    #[test]
    fn sqlite_memory_pool_reuses_the_single_migrated_connection() {
        let manager = sqlite_connection_manager(
            std::path::Path::new(":memory:"),
            startup_migration_timeout(&VfsPolicy::default()),
        );
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");

        {
            let conn = pool.get().expect("first connection");
            db_vfs::migrations::migrate_sqlite(&conn).expect("migrate sqlite");
            conn.execute(
                "INSERT INTO files (
                    workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
                rusqlite::params!["ws", "docs/a.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
            )
            .expect("seed row");
        }

        let conn = pool.get().expect("second connection");
        let content: String = conn
            .query_row(
                "SELECT content FROM files WHERE workspace_id = ?1 AND path = ?2",
                rusqlite::params!["ws", "docs/a.txt"],
                |row| row.get(0),
            )
            .expect("read seeded row");
        assert_eq!(content, "hello");
    }

    #[test]
    fn startup_migration_timeout_tracks_io_budget() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_io_ms = 1450;
        assert_eq!(
            startup_migration_timeout(&policy),
            Duration::from_millis(1450)
        );
    }

    #[test]
    fn sqlite_connection_manager_applies_startup_busy_timeout_budget() {
        let manager = sqlite_connection_manager(
            std::path::Path::new(":memory:"),
            Duration::from_millis(1450),
        );
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");
        let conn = pool.get().expect("pooled sqlite connection");
        let busy_timeout_ms: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("query busy_timeout");
        assert_eq!(busy_timeout_ms, 1450);
    }

    #[tokio::test]
    async fn required_audit_keeps_concurrency_permit_until_append_finishes() {
        let (audit, control) = audit::AuditLogger::blocking_required_logger_for_test();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire permit");

        let audit_task = tokio::spawn({
            let audit = audit.clone();
            async move {
                log_audit_event_with_permit(
                    &audit,
                    audit::minimal_event("req-1".to_string(), None, "write", 200, None),
                    permit,
                    Some(Duration::from_secs(1)),
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("audit wait should block");
        let immediate =
            tokio::time::timeout(Duration::from_millis(20), semaphore.clone().acquire_owned())
                .await;
        assert!(
            immediate.is_err(),
            "required audit should keep the originating permit until append+flush finishes"
        );

        control.release_success();
        audit_task
            .await
            .expect("audit task join")
            .expect("audit should succeed");

        let permit = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned())
            .await
            .expect("permit should be released after audit finishes")
            .expect("acquire permit after audit");
        drop(permit);
    }

    #[tokio::test]
    async fn required_audit_timeout_keeps_permit_until_worker_exits() {
        let (audit, control) = audit::AuditLogger::blocking_required_logger_for_test();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire permit");

        let audit_task = tokio::spawn({
            let audit = audit.clone();
            async move {
                log_audit_event_with_permit(
                    &audit,
                    audit::minimal_event("req-2".to_string(), None, "write", 200, None),
                    permit,
                    Some(Duration::from_millis(25)),
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("audit wait should block");
        let err = audit_task
            .await
            .expect("audit task join")
            .expect_err("audit wait should time out");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");

        let immediate =
            tokio::time::timeout(Duration::from_millis(20), semaphore.clone().acquire_owned())
                .await;
        assert!(
            immediate.is_err(),
            "timed-out audit wait should still hold the permit until the worker exits"
        );

        control.release_success();

        let eventual = tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                    return permit;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("permit should be released once timed-out audit worker finishes");
        drop(eventual);
    }

    #[tokio::test]
    async fn required_audit_worker_loss_returns_service_unavailable() {
        let audit = audit::AuditLogger::broken_required_logger_for_test();

        let err = log_audit_event(
            &audit,
            audit::minimal_event("req-broken".to_string(), None, "write", 500, Some("broken")),
        )
        .await
        .expect_err("broken required audit logger should surface as HTTP error");

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");
    }
}
