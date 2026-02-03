//! HTTP server implementation.

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

use db_vfs::store::sqlite::SqliteStore;
use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;

#[derive(Clone)]
struct AppState {
    inner: Arc<AppInner>,
}

struct AppInner {
    backend: backend::Backend,
    policy: VfsPolicy,
    redactor: SecretRedactor,
    traversal: TraversalSkipper,
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

fn map_err(err: db_vfs_core::Error) -> (StatusCode, Json<ErrorBody>) {
    let code = err.code();
    let status = match code {
        "not_permitted" => StatusCode::FORBIDDEN,
        "secret_path_denied" => StatusCode::FORBIDDEN,
        "invalid_path" | "invalid_policy" | "invalid_regex" => StatusCode::BAD_REQUEST,
        "patch" => StatusCode::BAD_REQUEST,
        "not_found" => StatusCode::NOT_FOUND,
        "conflict" => StatusCode::CONFLICT,
        "input_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        "file_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        "quota_exceeded" => StatusCode::PAYLOAD_TOO_LARGE,
        "timeout" => StatusCode::REQUEST_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let message = if status.is_server_error() {
        tracing::error!(code, err = %err, "db-vfs request failed");
        "internal error".to_string()
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
    mut policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<(AppState, usize)> {
    policy.validate().map_err(anyhow::Error::msg)?;
    let redactor = SecretRedactor::from_rules(&policy.secrets).map_err(anyhow::Error::msg)?;
    let traversal = TraversalSkipper::from_rules(&policy.traversal).map_err(anyhow::Error::msg)?;
    let io_concurrency = policy.limits.max_concurrency_io;
    let scan_concurrency = policy.limits.max_concurrency_scan;
    let rate_limiter = rate_limiter::RateLimiter::new(&policy);
    let auth = auth::build_auth_mode(&policy, unsafe_no_auth)?;

    policy.auth.tokens.clear();

    let state = AppState {
        inner: Arc::new(AppInner {
            backend,
            policy,
            redactor,
            traversal,
            auth,
            rate_limiter,
            io_concurrency: Arc::new(tokio::sync::Semaphore::new(io_concurrency)),
            scan_concurrency: Arc::new(tokio::sync::Semaphore::new(scan_concurrency)),
        }),
    };

    let body_limit = max_body_bytes(&state.inner.policy);
    Ok((state, body_limit))
}

pub fn build_app_sqlite(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    policy.validate().map_err(anyhow::Error::msg)?;
    let _ = SqliteStore::open(&db_path)?;

    const SQLITE_BUSY_TIMEOUT_CAP_MS: u64 = 5_000;
    let busy_timeout =
        Duration::from_millis(policy.limits.max_io_ms.min(SQLITE_BUSY_TIMEOUT_CAP_MS));
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

    Ok(Router::new()
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
        .with_state(state))
}

#[cfg(feature = "postgres")]
pub fn build_app_postgres(
    url: String,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    policy.validate().map_err(anyhow::Error::msg)?;

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
    Ok(Router::new()
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
        .with_state(state))
}

pub fn build_app(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    build_app_sqlite(db_path, policy, unsafe_no_auth)
}
