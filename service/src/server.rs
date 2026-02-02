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
    matcher: TokenMatcher,
    allowed_workspaces: Arc<[String]>,
}

#[derive(Clone)]
enum TokenMatcher {
    Plain(String),
    Sha256([u8; 32]),
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
        "invalid_path" | "invalid_policy" | "invalid_regex" | "input_too_large" => {
            StatusCode::BAD_REQUEST
        }
        "not_found" => StatusCode::NOT_FOUND,
        "conflict" => StatusCode::CONFLICT,
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

fn match_token<'a>(rules: &'a [AuthRule], token: &str) -> Option<&'a AuthRule> {
    let mut token_sha256: Option<[u8; 32]> = None;
    for rule in rules {
        match &rule.matcher {
            TokenMatcher::Plain(expected) => {
                if expected == token {
                    return Some(rule);
                }
            }
            TokenMatcher::Sha256(expected) => {
                let actual = token_sha256.get_or_insert_with(|| hash_token_sha256(token));
                if actual == expected {
                    return Some(rule);
                }
            }
        }
    }
    None
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
    usize::try_from(max).unwrap_or(usize::MAX)
}

fn build_state(
    backend: Backend,
    policy: VfsPolicy,
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
            let matcher = if let Some(hex) = token.strip_prefix("sha256:") {
                let bytes = hex::decode(hex).map_err(anyhow::Error::msg)?;
                let hash: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid sha256 token hash length"))?;
                TokenMatcher::Sha256(hash)
            } else {
                TokenMatcher::Plain(token.clone())
            };
            rules.push(AuthRule {
                matcher,
                allowed_workspaces: Arc::from(allowed_workspaces.clone()),
            });
        }
        AuthMode::Enforced {
            rules: Arc::from(rules),
        }
    };

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
    let _ = PostgresStore::connect(&url)?;

    let config: r2d2_postgres::postgres::Config = url.parse()?;
    let manager =
        r2d2_postgres::PostgresConnectionManager::new(config, r2d2_postgres::postgres::NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(policy.limits.max_db_connections)
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

async fn read(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<ReadResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}

async fn write(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<WriteResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}

async fn patch(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<PatchRequest>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<PatchResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}

async fn delete(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<DeleteResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}

async fn glob(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<GlobResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}

async fn grep(
    State(state): State<AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<ErrorBody>)> {
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

    let result = tokio::task::spawn_blocking(move || -> db_vfs::Result<GrepResponse> {
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
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}
