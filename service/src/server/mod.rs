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
    policy: ValidatedVfsPolicy,
    redactor: SecretRedactor,
    traversal: TraversalSkipper,
    audit: Option<audit::AuditLogger>,
    auth: auth::AuthMode,
    rate_limiter: rate_limiter::RateLimiter,
    io_concurrency: Arc<tokio::sync::Semaphore>,
    scan_concurrency: Arc<tokio::sync::Semaphore>,
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

fn build_state(
    backend: backend::Backend,
    mut policy: ValidatedVfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<(AppState, usize)> {
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
        let flush_max_interval = policy
            .audit
            .flush_max_interval_ms
            .map(Duration::from_millis)
            .unwrap_or(audit::DEFAULT_AUDIT_FLUSH_MAX_INTERVAL);

        match audit::AuditLogger::new(path, flush_every_events, flush_max_interval) {
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

    let state = AppState {
        inner: Arc::new(AppInner {
            backend,
            policy,
            redactor,
            traversal,
            audit,
            auth,
            rate_limiter,
            io_concurrency: Arc::new(tokio::sync::Semaphore::new(io_concurrency)),
            scan_concurrency: Arc::new(tokio::sync::Semaphore::new(scan_concurrency)),
        }),
    };

    let body_limit = max_body_bytes(&state.inner.policy);
    Ok((state, body_limit))
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

pub fn build_app_sqlite(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    let policy = ValidatedVfsPolicy::new(policy).map_err(anyhow::Error::msg)?;

    const SQLITE_BUSY_TIMEOUT_CAP_MS: u64 = 5_000;
    let busy_timeout =
        Duration::from_millis(policy.limits.max_io_ms.min(SQLITE_BUSY_TIMEOUT_CAP_MS));

    {
        let conn = rusqlite::Connection::open(&db_path)?;
        conn.busy_timeout(busy_timeout)?;
        db_vfs::migrations::migrate_sqlite(&conn).map_err(anyhow::Error::msg)?;
    }

    let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path).with_init(move |conn| {
        conn.busy_timeout(busy_timeout)?;
        Ok(())
    });
    let pool = r2d2::Pool::builder()
        .max_size(policy.limits.max_db_connections)
        .connection_timeout(Duration::from_millis(policy.limits.max_io_ms))
        .build(manager)
        .map_err(anyhow::Error::msg)?;

    let (state, body_limit) =
        build_state(backend::Backend::Sqlite { pool }, policy, unsafe_no_auth)?;

    Ok(build_router(state, body_limit))
}

#[cfg(feature = "postgres")]
pub fn build_app_postgres(
    url: String,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    let policy = ValidatedVfsPolicy::new(policy).map_err(anyhow::Error::msg)?;

    let statement_timeout_ms = policy.limits.max_io_ms;
    let mut config: r2d2_postgres::postgres::Config = url.parse()?;
    let options_extra = format!("-c statement_timeout={statement_timeout_ms}");
    let options = match config.get_options() {
        Some(existing) => format!("{existing} {options_extra}"),
        None => options_extra,
    };
    config.options(&options);
    config.connect_timeout(Duration::from_millis(policy.limits.max_io_ms));

    {
        let mut client = config.connect(r2d2_postgres::postgres::NoTls)?;
        db_vfs::migrations::migrate_postgres(&mut client).map_err(anyhow::Error::msg)?;
    }

    let manager =
        r2d2_postgres::PostgresConnectionManager::new(config, r2d2_postgres::postgres::NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(policy.limits.max_db_connections)
        .connection_timeout(Duration::from_millis(policy.limits.max_io_ms))
        .build(manager)?;

    let (state, body_limit) =
        build_state(backend::Backend::Postgres { pool }, policy, unsafe_no_auth)?;
    Ok(build_router(state, body_limit))
}

/// Convenience entrypoint using the SQLite backend.
///
/// For PostgreSQL, call `build_app_postgres` when the `postgres` feature is enabled.
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

        let err = build_app_sqlite(db_path, policy, true).expect_err("should fail");
        assert!(
            err.to_string()
                .contains("audit.jsonl_path must be a regular file")
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
}
