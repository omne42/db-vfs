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

use crate::TrustMode;
use crate::policy::ServicePolicy;
use db_vfs_core::policy::ValidatedVfsPolicy;
use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;

#[derive(Clone)]
pub(in crate::server) struct AppState {
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
    max_db_connections: u32,
    redactor: Arc<SecretRedactor>,
    traversal: Arc<TraversalSkipper>,
    audit: Option<audit::AuditLogger>,
    auth: auth::AuthMode,
    rate_limiter: rate_limiter::RateLimiter,
    io_concurrency: usize,
    scan_concurrency: usize,
    body_limits: BodyLimits,
}

struct RequiredAuditGate {
    permit: tokio::sync::OwnedSemaphorePermit,
    budget: Option<Duration>,
}

#[derive(Clone, Copy)]
enum RequestClass {
    Io,
    Scan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyLimits {
    small_json: usize,
    write_json: usize,
    patch_json: usize,
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
    if !audit.is_required() {
        audit.try_log(event).map_err(audit_failure_response)?;
        return Ok(());
    }

    audit
        .log_required(event, None)
        .await
        .map_err(audit_failure_response)
}

async fn log_audit_event_with_permit(
    audit: &audit::AuditLogger,
    event: audit::AuditEvent,
    permit: tokio::sync::OwnedSemaphorePermit,
    budget: Option<Duration>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let _permit = permit;
    audit
        .log_required(event, budget)
        .await
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
const SMALL_JSON_BODY_BYTES: u64 = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: u64 = 256 * 1024 * 1024 + 64 * 1024;
const MAX_JSON_STRING_EXPANSION: u64 = 6;

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

fn request_body_limit_for_json_string(decoded_bytes: u64) -> usize {
    let max = decoded_bytes
        .saturating_mul(MAX_JSON_STRING_EXPANSION)
        .saturating_add(SMALL_JSON_BODY_BYTES)
        .min(MAX_REQUEST_BODY_BYTES);
    usize::try_from(max).unwrap_or(usize::MAX)
}

fn body_limits(policy: &VfsPolicy) -> BodyLimits {
    BodyLimits {
        small_json: usize::try_from(SMALL_JSON_BODY_BYTES).unwrap_or(usize::MAX),
        write_json: request_body_limit_for_json_string(policy.limits.max_write_bytes),
        patch_json: request_body_limit_for_json_string(
            policy
                .limits
                .max_patch_bytes
                .unwrap_or(policy.limits.max_read_bytes),
        ),
    }
}

fn estimated_scan_inflight_bytes(policy: &VfsPolicy) -> u64 {
    let per_request_bytes = if policy.secrets.redact_regexes.is_empty() {
        policy.limits.max_read_bytes
    } else {
        // `grep` and redaction-enabled ranged `read` may need both the original text
        // buffer and a bounded redacted copy in memory at the same time.
        policy.limits.max_read_bytes.saturating_mul(2)
    };
    per_request_bytes.saturating_mul(policy.limits.max_concurrency_scan as u64)
}

fn request_class_for_path(path: &str) -> Option<RequestClass> {
    match path {
        "/v1/read" | "/v1/write" | "/v1/patch" | "/v1/delete" => Some(RequestClass::Io),
        "/v1/glob" | "/v1/grep" => Some(RequestClass::Scan),
        _ => None,
    }
}

fn frontdoor_budget(policy: &ValidatedVfsPolicy) -> Option<Duration> {
    Some(runner::io_timeout(policy))
}

async fn try_acquire_required_audit_gate_for_path(
    state: &AppState,
    path: &str,
) -> Result<Option<RequiredAuditGate>, (StatusCode, Json<ErrorBody>)> {
    let Some(audit) = state.inner.audit.as_ref() else {
        return Ok(None);
    };
    if !audit.is_required() {
        return Ok(None);
    }

    let Some(class) = request_class_for_path(path) else {
        return Ok(None);
    };
    let semaphore = match class {
        RequestClass::Io => state.inner.io_concurrency.clone(),
        RequestClass::Scan => state.inner.scan_concurrency.clone(),
    };
    let permit = semaphore
        .try_acquire_owned()
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;
    Ok(Some(RequiredAuditGate {
        permit,
        budget: frontdoor_budget(&state.inner.policy),
    }))
}

fn prepare_state(policy: ServicePolicy, unsafe_no_auth: bool) -> anyhow::Result<PreparedState> {
    let validated_policy = policy.validated_vfs_policy().map_err(anyhow::Error::msg)?;
    let estimated_scan_inflight_bytes = estimated_scan_inflight_bytes(&validated_policy);
    if estimated_scan_inflight_bytes > RECOMMENDED_MAX_SCAN_INFLIGHT_BYTES {
        tracing::warn!(
            max_read_bytes = validated_policy.limits.max_read_bytes,
            max_concurrency_scan = validated_policy.limits.max_concurrency_scan,
            redaction_copies_input = !validated_policy.secrets.redact_regexes.is_empty(),
            estimated_scan_inflight_bytes,
            recommended_max_scan_inflight_bytes = RECOMMENDED_MAX_SCAN_INFLIGHT_BYTES,
            "scan memory budget is high; consider lowering limits.max_read_bytes or limits.max_concurrency_scan"
        );
    }

    let redactor =
        SecretRedactor::from_rules(&validated_policy.secrets).map_err(anyhow::Error::msg)?;
    let traversal =
        TraversalSkipper::from_rules(&validated_policy.traversal).map_err(anyhow::Error::msg)?;
    let io_concurrency = validated_policy.limits.max_concurrency_io;
    let scan_concurrency = validated_policy.limits.max_concurrency_scan;
    let rate_limiter = rate_limiter::RateLimiter::new(&policy.limits);
    let auth = auth::build_auth_mode(&policy.auth, unsafe_no_auth)?;
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

    let body_limits = body_limits(&validated_policy);
    Ok(PreparedState {
        policy: Arc::new(validated_policy),
        max_db_connections: policy.limits.max_db_connections,
        redactor: Arc::new(redactor),
        traversal: Arc::new(traversal),
        audit,
        auth,
        rate_limiter,
        io_concurrency,
        scan_concurrency,
        body_limits,
    })
}

fn build_state(backend: backend::Backend, prepared: PreparedState) -> (AppState, BodyLimits) {
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

    (state, prepared.body_limits)
}

fn build_router(state: AppState, body_limits: BodyLimits) -> Router {
    Router::new()
        .route(
            "/v1/read",
            post(handlers::read).layer(DefaultBodyLimit::max(body_limits.small_json)),
        )
        .route(
            "/v1/write",
            post(handlers::write).layer(DefaultBodyLimit::max(body_limits.write_json)),
        )
        .route(
            "/v1/patch",
            post(handlers::patch).layer(DefaultBodyLimit::max(body_limits.patch_json)),
        )
        .route(
            "/v1/delete",
            post(handlers::delete).layer(DefaultBodyLimit::max(body_limits.small_json)),
        )
        .route(
            "/v1/glob",
            post(handlers::glob).layer(DefaultBodyLimit::max(body_limits.small_json)),
        )
        .route(
            "/v1/grep",
            post(handlers::grep).layer(DefaultBodyLimit::max(body_limits.small_json)),
        )
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

#[cfg(feature = "sqlite")]
fn sqlite_uses_in_memory_pool(db_path: &std::path::Path) -> bool {
    db_path == std::path::Path::new(":memory:")
}

fn startup_migration_timeout(policy: &VfsPolicy) -> Duration {
    Duration::from_millis(policy.limits.max_io_ms)
}

#[cfg(feature = "sqlite")]
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

#[cfg(feature = "sqlite")]
fn sqlite_pool_max_size(db_path: &std::path::Path, configured: u32) -> u32 {
    if sqlite_uses_in_memory_pool(db_path) {
        1
    } else {
        configured
    }
}

#[cfg(all(test, feature = "sqlite"))]
pub(in crate::server) fn test_state_with_policy_audit_and_auth(
    policy: ServicePolicy,
    audit: Option<audit::AuditLogger>,
    unsafe_no_auth: bool,
) -> AppState {
    let auth_mode = auth::build_auth_mode(&policy.auth, unsafe_no_auth).expect("auth mode");
    let rate_limiter = rate_limiter::RateLimiter::new(&policy.limits);
    let policy = Arc::new(policy.validated_vfs_policy().expect("validated policy"));
    let manager = sqlite_connection_manager(
        std::path::Path::new(":memory:"),
        startup_migration_timeout(policy.as_ref()),
    );
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .build(manager)
        .expect("sqlite pool");

    AppState {
        inner: Arc::new(AppInner {
            backend: backend::Backend::Sqlite { pool },
            policy: policy.clone(),
            redactor: Arc::new(SecretRedactor::from_rules(&policy.secrets).expect("redactor")),
            traversal: Arc::new(
                TraversalSkipper::from_rules(&policy.traversal).expect("traversal skipper"),
            ),
            audit,
            auth: auth_mode,
            rate_limiter,
            io_concurrency: Arc::new(tokio::sync::Semaphore::new(1)),
            scan_concurrency: Arc::new(tokio::sync::Semaphore::new(1)),
        }),
    }
}

#[cfg(all(test, feature = "sqlite"))]
pub(in crate::server) fn test_state_with_audit(audit: Option<audit::AuditLogger>) -> AppState {
    test_state_with_policy_audit_and_auth(ServicePolicy::default(), audit, true)
}

#[cfg(all(test, feature = "sqlite"))]
pub(in crate::server) fn test_state_with_policy_and_audit(
    policy: ServicePolicy,
    audit: Option<audit::AuditLogger>,
) -> AppState {
    test_state_with_policy_audit_and_auth(policy, audit, true)
}

#[cfg(feature = "sqlite")]
/// Builds the SQLite-backed service router.
///
/// Public builders re-apply `trust_mode` startup validation even when the caller provides an
/// already-materialized [`ServicePolicy`], so `TrustMode::Untrusted` constraints cannot be
/// bypassed by skipping [`crate::policy_io::load_policy`].
pub fn build_app_sqlite(
    db_path: std::path::PathBuf,
    policy: ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    crate::policy_io::validate_policy_for_startup(&policy, trust_mode, unsafe_no_auth)?;
    let prepared = prepare_state(policy, unsafe_no_auth)?;
    let migration_timeout = startup_migration_timeout(prepared.policy.as_ref());
    let manager = sqlite_connection_manager(&db_path, migration_timeout);
    let max_pool_size = sqlite_pool_max_size(&db_path, prepared.max_db_connections);
    if max_pool_size != prepared.max_db_connections {
        tracing::warn!(
            configured_max_db_connections = prepared.max_db_connections,
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

    let (state, body_limits) = build_state(backend::Backend::Sqlite { pool }, prepared);

    Ok(build_router(state, body_limits))
}

#[cfg(feature = "postgres")]
/// Builds the Postgres-backed service router.
///
/// Public builders re-apply `trust_mode` startup validation even when the caller provides an
/// already-materialized [`ServicePolicy`], so `TrustMode::Untrusted` constraints cannot be
/// bypassed by skipping [`crate::policy_io::load_policy`].
pub fn build_app_postgres(
    url: String,
    policy: ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    crate::policy_io::validate_policy_for_startup(&policy, trust_mode, unsafe_no_auth)?;
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
        .max_size(prepared.max_db_connections)
        .connection_timeout(migration_timeout)
        .build(manager)?;

    let (state, body_limits) = build_state(backend::Backend::Postgres { pool }, prepared);
    Ok(build_router(state, body_limits))
}

#[cfg(feature = "sqlite")]
/// Convenience entrypoint using the SQLite backend.
///
/// For PostgreSQL, call `build_app_postgres` when the `postgres` feature is enabled.
/// This wrapper also re-applies `trust_mode` startup validation before any backend side effects.
///
/// The returned router can be served with or without `ConnectInfo<SocketAddr>`. When no peer
/// address is installed by the outer server, request handling still succeeds; audit `peer_ip`
/// stays unset and service-local per-IP rate limiting is skipped for those requests.
pub fn build_app(
    db_path: std::path::PathBuf,
    policy: ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    build_app_sqlite(db_path, policy, trust_mode, unsafe_no_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    #[cfg(feature = "sqlite")]
    use tempfile::tempdir;
    #[cfg(feature = "sqlite")]
    use tower::ServiceExt;

    #[cfg(feature = "sqlite")]
    #[test]
    fn audit_required_false_allows_startup_when_audit_path_invalid() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::create_dir_all(&audit_path).expect("create_dir_all");

        let mut policy = ServicePolicy::default();
        policy.audit.jsonl_path = Some(audit_path.to_string_lossy().into_owned());
        policy.audit.required = false;

        assert!(build_app_sqlite(db_path, policy, TrustMode::Trusted, true).is_ok());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn audit_required_true_fails_startup_when_audit_path_invalid() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::create_dir_all(&audit_path).expect("create_dir_all");

        let mut policy = ServicePolicy::default();
        policy.audit.jsonl_path = Some(audit_path.to_string_lossy().into_owned());

        let err = build_app_sqlite(db_path.clone(), policy, TrustMode::Trusted, true)
            .expect_err("should fail");
        assert!(
            err.to_string()
                .contains("audit.jsonl_path must be a regular file")
        );
        assert!(
            !db_path.exists(),
            "invalid required audit config should fail before touching sqlite"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn auth_validation_fails_before_touching_sqlite() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");

        let err = build_app_sqlite(
            db_path.clone(),
            ServicePolicy::default(),
            TrustMode::Trusted,
            false,
        )
        .expect_err("missing auth tokens should fail");
        assert!(err.to_string().contains("no auth tokens configured"));
        assert!(
            !db_path.exists(),
            "invalid auth config should fail before touching sqlite"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn build_app_sqlite_reapplies_untrusted_constraints() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");
        let mut policy = ServicePolicy::default();
        policy.permissions.read = true;
        policy.permissions.write = true;
        policy.limits.max_walk_ms = Some(1_000);
        policy.limits.max_requests_per_ip_per_sec = 1;
        policy.limits.max_requests_burst_per_ip = 1;
        policy.limits.max_rate_limit_ips = 16;
        policy.auth.tokens = vec![crate::policy::AuthToken {
            token: Some(format!("sha256:{}", "11".repeat(32))),
            token_env_var: None,
            allowed_workspaces: vec!["ws".to_string()],
        }];

        let err = build_app_sqlite(db_path.clone(), policy, TrustMode::Untrusted, false)
            .expect_err("untrusted startup should reject write permissions");
        assert!(err.to_string().contains("forbids write/patch/delete"));
        assert!(
            !db_path.exists(),
            "trust_mode rejection should fail before touching sqlite"
        );
    }

    #[test]
    fn prepare_state_keeps_core_policy_and_service_limits_separate() {
        let mut raw = ServicePolicy::default();
        raw.auth.tokens = vec![crate::policy::AuthToken {
            token: Some(format!("sha256:{}", "11".repeat(32))),
            token_env_var: None,
            allowed_workspaces: vec!["team-*".to_string()],
        }];
        raw.permissions.read = true;
        raw.limits.max_db_connections = 7;

        let prepared = prepare_state(raw, false).expect("prepared state");

        assert!(prepared.policy.permissions.read);
        assert_eq!(prepared.max_db_connections, 7);
        assert!(matches!(prepared.auth, auth::AuthMode::Enforced { .. }));
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
    fn request_body_limit_for_json_string_is_capped_to_hard_limit() {
        assert_eq!(
            request_body_limit_for_json_string(u64::MAX),
            MAX_REQUEST_BODY_BYTES as usize
        );
    }

    #[test]
    fn body_limits_separate_small_json_from_write_and_patch_caps() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_write_bytes = 4096;
        policy.limits.max_patch_bytes = Some(8192);

        assert_eq!(
            body_limits(&policy),
            BodyLimits {
                small_json: SMALL_JSON_BODY_BYTES as usize,
                write_json: (4096 * 6 + SMALL_JSON_BODY_BYTES) as usize,
                patch_json: (8192 * 6 + SMALL_JSON_BODY_BYTES) as usize,
            }
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn router_keeps_small_json_routes_on_their_own_body_cap() {
        let mut service_policy = ServicePolicy::default();
        service_policy.permissions.read = true;
        service_policy.permissions.write = true;
        service_policy.limits.max_write_bytes = 96 * 1024;
        let state = test_state_with_policy_audit_and_auth(service_policy.clone(), None, true);
        let router = build_router(state, body_limits(&service_policy.vfs_policy()));

        let oversized_path = "a".repeat(SMALL_JSON_BODY_BYTES as usize);
        let read_req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/read")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(format!(
                "{{\"workspace_id\":\"ws\",\"path\":\"{oversized_path}\"}}"
            )))
            .expect("read request");
        let read_resp = router
            .clone()
            .oneshot(read_req)
            .await
            .expect("read response");
        assert_eq!(read_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let write_content = "b".repeat(SMALL_JSON_BODY_BYTES as usize);
        let write_req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(format!(
                "{{\"workspace_id\":\"ws\",\"path\":\"docs/a.txt\",\"content\":\"{write_content}\",\"expected_version\":null}}"
            )))
            .expect("write request");
        let write_resp = router.oneshot(write_req).await.expect("write response");
        assert_ne!(write_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn router_times_out_scan_lock_contention_even_when_walk_budget_is_unbounded() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.sqlite");

        let mut policy = ServicePolicy::default();
        policy.permissions.glob = true;
        policy.limits.max_io_ms = 25;
        policy.limits.max_walk_ms = None;

        let router = build_app_sqlite(db_path.clone(), policy, TrustMode::Trusted, true)
            .expect("build sqlite router");

        let locker = rusqlite::Connection::open(&db_path).expect("sqlite connection");
        locker
            .execute(
                "INSERT INTO files(
                    workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params!["ws", "docs/a.txt", "hello", 5_i64, 1_i64, 1_i64, 1_i64],
            )
            .expect("seed file");
        locker
            .execute_batch("BEGIN EXCLUSIVE;")
            .expect("acquire exclusive sqlite lock");

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/glob")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"workspace_id":"ws","pattern":"docs/*.txt","path_prefix":"docs"}"#,
            ))
            .expect("glob request");

        let started = std::time::Instant::now();
        let response = router.oneshot(request).await.expect("glob response");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "scan request did not respect the IO lock timeout budget"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read timeout response body");
        let err: serde_json::Value =
            serde_json::from_slice(&body).expect("decode timeout response");
        assert_eq!(
            err.get("code").and_then(serde_json::Value::as_str),
            Some(CODE_TIMEOUT)
        );

        locker
            .execute_batch("ROLLBACK;")
            .expect("release exclusive sqlite lock");
    }

    #[cfg(feature = "sqlite")]
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
    fn estimated_scan_inflight_bytes_matches_single_buffer_without_redaction() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_read_bytes = 128;
        policy.limits.max_concurrency_scan = 3;

        assert_eq!(estimated_scan_inflight_bytes(&policy), 384);
    }

    #[test]
    fn estimated_scan_inflight_bytes_accounts_for_redaction_copy() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_read_bytes = 128;
        policy.limits.max_concurrency_scan = 3;
        policy.secrets.redact_regexes = vec!["secret".to_string()];

        assert_eq!(estimated_scan_inflight_bytes(&policy), 768);
    }

    #[cfg(feature = "sqlite")]
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
                    workspace_id, path, content, size_bytes, version, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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

    #[cfg(feature = "sqlite")]
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
    async fn required_audit_timeout_releases_permit_when_wait_budget_expires() {
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
        let permit = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned())
            .await
            .expect("timed-out audit wait should release the originating permit")
            .expect("acquire permit after timed-out audit");
        drop(permit);

        control.release_success();
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
