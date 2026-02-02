use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use sha2::{Digest, Sha256};
use tracing::Instrument;

#[cfg(feature = "postgres")]
use db_vfs::store::postgres::PostgresStore;
use db_vfs::store::sqlite::SqliteStore;
use db_vfs::vfs::{
    DbVfs, DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};
use db_vfs_core::policy::{AuthToken, VfsPolicy};
use db_vfs_core::redaction::SecretRedactor;

type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;

#[cfg(feature = "postgres")]
type PostgresPool =
    r2d2::Pool<r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>>;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
enum Backend {
    Sqlite {
        pool: SqlitePool,
    },
    #[cfg(feature = "postgres")]
    Postgres {
        pool: PostgresPool,
    },
}

#[derive(Clone)]
struct AppState {
    inner: Arc<AppInner>,
}

struct AppInner {
    backend: Backend,
    policy: VfsPolicy,
    redactor: SecretRedactor,
    auth: AuthMode,
    io_concurrency: Arc<tokio::sync::Semaphore>,
    scan_concurrency: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
enum AuthMode {
    Disabled,
    Enforced { rules: Arc<[AuthRule]> },
}

#[derive(Clone)]
struct AuthRule {
    token_sha256: [u8; 32],
    allowed_workspaces: Arc<[String]>,
}

#[derive(Clone)]
struct AuthContext {
    allowed_workspaces: Arc<[String]>,
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
        "invalid_path" | "invalid_policy" | "invalid_regex" | "input_too_large" => {
            StatusCode::BAD_REQUEST
        }
        "patch" => StatusCode::BAD_REQUEST,
        "not_found" => StatusCode::NOT_FOUND,
        "conflict" => StatusCode::CONFLICT,
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

fn parse_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    Some(token)
}

fn workspace_allowed(patterns: &[String], workspace_id: &str) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        let Some(prefix) = pattern.strip_suffix('*') else {
            return pattern == workspace_id;
        };
        workspace_id.starts_with(prefix)
    })
}

fn hash_token_sha256(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for idx in 0..32 {
        diff |= a[idx] ^ b[idx];
    }
    diff == 0
}

fn match_token<'a>(rules: &'a [AuthRule], token: &str) -> Option<&'a AuthRule> {
    let actual = hash_token_sha256(token);
    rules
        .iter()
        .find(|rule| constant_time_eq_32(&rule.token_sha256, &actual))
}

async fn auth_middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let ctx = match &state.inner.auth {
        AuthMode::Disabled => AuthContext {
            allowed_workspaces: Arc::from(vec!["*".to_string()]),
        },
        AuthMode::Enforced { rules } => {
            let Some(token) = parse_bearer_token(req.headers()) else {
                return err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid Authorization header",
                );
            };

            let Some(rule) = match_token(rules, token) else {
                return err_response(StatusCode::UNAUTHORIZED, "unauthorized", "invalid token");
            };

            AuthContext {
                allowed_workspaces: rule.allowed_workspaces.clone(),
            }
        }
    };

    req.extensions_mut().insert(ctx);
    next.run(req).await
}

async fn request_id_middleware(req: Request, next: Next) -> Response {
    let header_name = HeaderName::from_static("x-request-id");
    let request_id = req
        .headers()
        .get(&header_name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(ToString::to_string)
        .unwrap_or_else(generate_request_id);

    let req = req;

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %req.method(),
        path = %req.uri().path(),
    );

    let mut resp = next.run(req).instrument(span).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert(header_name, value);
    }
    resp
}

fn generate_request_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{millis:016x}{seq:016x}")
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
    backend: Backend,
    mut policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<(AppState, usize)> {
    policy.validate().map_err(anyhow::Error::msg)?;
    let redactor = SecretRedactor::from_rules(&policy.secrets).map_err(anyhow::Error::msg)?;
    let io_concurrency = policy.limits.max_concurrency_io;
    let scan_concurrency = policy.limits.max_concurrency_scan;

    let auth = if unsafe_no_auth {
        AuthMode::Disabled
    } else if policy.auth.tokens.is_empty() {
        anyhow::bail!(
            "no auth tokens configured; set [auth.tokens] in the policy file or pass --unsafe-no-auth"
        );
    } else {
        let mut rules = Vec::with_capacity(policy.auth.tokens.len());
        for AuthToken {
            token,
            allowed_workspaces,
        } in &policy.auth.tokens
        {
            let token_sha256 = if let Some(hex) = token.strip_prefix("sha256:") {
                let bytes = hex::decode(hex).map_err(anyhow::Error::msg)?;
                let hash: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid sha256 token hash length"))?;
                hash
            } else {
                hash_token_sha256(token)
            };
            rules.push(AuthRule {
                token_sha256,
                allowed_workspaces: Arc::from(allowed_workspaces.clone()),
            });
        }
        AuthMode::Enforced {
            rules: Arc::from(rules),
        }
    };

    policy.auth.tokens.clear();

    let state = AppState {
        inner: Arc::new(AppInner {
            backend,
            policy,
            redactor,
            auth,
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

    let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path).with_init(|conn| {
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(())
    });
    let pool = r2d2::Pool::builder()
        .max_size(policy.limits.max_db_connections)
        .connection_timeout(Duration::from_millis(policy.limits.max_io_ms))
        .build(manager)
        .map_err(anyhow::Error::msg)?;

    let (state, body_limit) = build_state(Backend::Sqlite { pool }, policy, unsafe_no_auth)?;

    Ok(Router::new()
        .route("/v1/read", post(read))
        .route("/v1/write", post(write))
        .route("/v1/patch", post(patch))
        .route("/v1/delete", post(delete))
        .route("/v1/glob", post(glob))
        .route("/v1/grep", post(grep))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(request_id_middleware))
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

    let (state, body_limit) = build_state(Backend::Postgres { pool }, policy, unsafe_no_auth)?;
    Ok(Router::new()
        .route("/v1/read", post(read))
        .route("/v1/write", post(write))
        .route("/v1/patch", post(patch))
        .route("/v1/delete", post(delete))
        .route("/v1/glob", post(glob))
        .route("/v1/grep", post(grep))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(request_id_middleware))
        .with_state(state))
}

pub fn build_app(
    db_path: std::path::PathBuf,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    build_app_sqlite(db_path, policy, unsafe_no_auth)
}

fn io_timeout(policy: &VfsPolicy) -> Duration {
    Duration::from_millis(policy.limits.max_io_ms)
}

fn scan_timeout(policy: &VfsPolicy) -> Option<Duration> {
    policy
        .limits
        .max_walk_ms
        .map(|ms| Duration::from_millis(ms.saturating_add(250)))
}

async fn run_blocking<T>(
    timeout: Option<Duration>,
    f: impl FnOnce() -> db_vfs::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, Json<ErrorBody>)>
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
                handle.abort();
                tracing::warn!(timeout_ms = timeout.as_millis() as u64, "db-vfs request timed out");
                return Err(err(StatusCode::REQUEST_TIMEOUT, "timeout", "request timed out"));
            }
        }
    } else {
        handle.await
    };

    let result = join.map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;
    result.map_err(map_err)
}

async fn read(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .io_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = Some(io_timeout(&state.inner.policy));
    let result = run_blocking(timeout, move || -> db_vfs::Result<ReadResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.read(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.read(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}

async fn write(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .io_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = Some(io_timeout(&state.inner.policy));
    let result = run_blocking(timeout, move || -> db_vfs::Result<WriteResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.write(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.write(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}

async fn patch(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<PatchRequest>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .io_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = Some(io_timeout(&state.inner.policy));
    let result = run_blocking(timeout, move || -> db_vfs::Result<PatchResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.apply_unified_patch(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.apply_unified_patch(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}

async fn delete(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .io_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = Some(io_timeout(&state.inner.policy));
    let result = run_blocking(timeout, move || -> db_vfs::Result<DeleteResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.delete(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.delete(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}

async fn glob(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .scan_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = scan_timeout(&state.inner.policy);
    let result = run_blocking(timeout, move || -> db_vfs::Result<GlobResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.glob(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.glob(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}

async fn grep(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(map_err)?;
    if !workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let permit = state
        .inner
        .scan_concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let backend = state.inner.backend.clone();
    let policy = state.inner.policy.clone();
    let redactor = state.inner.redactor.clone();

    let timeout = scan_timeout(&state.inner.policy);
    let result = run_blocking(timeout, move || -> db_vfs::Result<GrepResponse> {
        let _permit = permit;
        match backend {
            Backend::Sqlite { pool } => {
                let conn = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = SqliteStore::from_connection(conn);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.grep(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { pool } => {
                let client = pool
                    .get()
                    .map_err(|err| db_vfs::Error::Db(err.to_string()))?;
                let store = PostgresStore::from_client(client);
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.grep(req)
            }
        }
    })
    .await?;

    Ok(Json(result))
}
