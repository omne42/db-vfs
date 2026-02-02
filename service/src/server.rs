use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::post;

#[cfg(feature = "postgres")]
use db_vfs::store::postgres::PostgresStore;
use db_vfs::store::sqlite::SqliteStore;
use db_vfs::vfs::{
    DbVfs, DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};
use db_vfs_core::policy::{AuthToken, VfsPolicy};
use db_vfs_core::redaction::SecretRedactor;

#[derive(Clone)]
enum Backend {
    Sqlite {
        db_path: std::path::PathBuf,
    },
    #[cfg(feature = "postgres")]
    Postgres {
        url: String,
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
    concurrency: Arc<tokio::sync::Semaphore>,
}

enum AuthMode {
    Disabled,
    Enforced { tokens: Vec<AuthToken> },
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

fn authorize(
    auth: &AuthMode,
    headers: &HeaderMap,
    workspace_id: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let AuthMode::Enforced { tokens } = auth else {
        return Ok(());
    };

    let Some(token) = parse_bearer_token(headers) else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid Authorization header",
        ));
    };

    let Some(rule) = tokens.iter().find(|rule| rule.token == token) else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid token",
        ));
    };

    if !workspace_allowed(&rule.allowed_workspaces, workspace_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }
    Ok(())
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

    let auth = if unsafe_no_auth {
        AuthMode::Disabled
    } else if policy.auth.tokens.is_empty() {
        anyhow::bail!(
            "no auth tokens configured; set [auth.tokens] in the policy file or pass --unsafe-no-auth"
        );
    } else {
        AuthMode::Enforced {
            tokens: policy.auth.tokens.clone(),
        }
    };

    let state = AppState {
        inner: Arc::new(AppInner {
            backend,
            policy,
            redactor,
            auth,
            concurrency: Arc::new(tokio::sync::Semaphore::new(64)),
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
    let _ = SqliteStore::open(&db_path)?;
    let (state, body_limit) = build_state(Backend::Sqlite { db_path }, policy, unsafe_no_auth)?;
    Ok(Router::new()
        .route("/v1/read", post(read))
        .route("/v1/write", post(write))
        .route("/v1/patch", post(patch))
        .route("/v1/delete", post(delete))
        .route("/v1/glob", post(glob))
        .route("/v1/grep", post(grep))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state))
}

#[cfg(feature = "postgres")]
pub fn build_app_postgres(
    url: String,
    policy: VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<Router> {
    let _ = PostgresStore::connect(&url)?;
    let (state, body_limit) = build_state(Backend::Postgres { url }, policy, unsafe_no_auth)?;
    Ok(Router::new()
        .route("/v1/read", post(read))
        .route("/v1/write", post(write))
        .route("/v1/patch", post(patch))
        .route("/v1/delete", post(delete))
        .route("/v1/glob", post(glob))
        .route("/v1/grep", post(grep))
        .layer(DefaultBodyLimit::max(body_limit))
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
    headers: HeaderMap,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.read(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
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
    headers: HeaderMap,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.write(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
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
    headers: HeaderMap,
    Json(req): Json<PatchRequest>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.apply_unified_patch(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
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
    headers: HeaderMap,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.delete(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
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
    headers: HeaderMap,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.glob(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
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
    headers: HeaderMap,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<ErrorBody>)> {
    authorize(&state.inner.auth, &headers, &req.workspace_id)?;
    let permit = state
        .inner
        .concurrency
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
            Backend::Sqlite { db_path } => {
                let store = SqliteStore::open_no_migrate(db_path)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.grep(req)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres { url } => {
                let store = PostgresStore::connect_no_migrate(&url)?;
                let mut vfs = DbVfs::new_with_redactor(store, policy, redactor)?;
                vfs.grep(req)
            }
        }
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?;

    result.map(Json).map_err(map_err)
}
