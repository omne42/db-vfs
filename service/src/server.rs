use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;

use db_vfs::store::sqlite::SqliteStore;
use db_vfs::vfs::{
    DbVfs, DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};
use db_vfs_core::policy::VfsPolicy;

#[derive(Clone)]
struct AppState {
    vfs: Arc<Mutex<DbVfs<SqliteStore>>>,
}

#[derive(Debug, serde::Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
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
    (
        status,
        Json(ErrorBody {
            code,
            message: err.to_string(),
        }),
    )
}

pub fn build_app(db_path: std::path::PathBuf, policy: VfsPolicy) -> anyhow::Result<Router> {
    let store = SqliteStore::open(db_path)?;
    let vfs = DbVfs::new(store, policy)?;
    let state = AppState {
        vfs: Arc::new(Mutex::new(vfs)),
    };

    Ok(Router::new()
        .route("/v1/read", post(read))
        .route("/v1/write", post(write))
        .route("/v1/patch", post(patch))
        .route("/v1/delete", post(delete))
        .route("/v1/glob", post(glob))
        .route("/v1/grep", post(grep))
        .with_state(state))
}

async fn read(
    State(state): State<AppState>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.read(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}

async fn write(
    State(state): State<AppState>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.write(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}

async fn patch(
    State(state): State<AppState>,
    Json(req): Json<PatchRequest>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.apply_unified_patch(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}

async fn delete(
    State(state): State<AppState>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.delete(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}

async fn glob(
    State(state): State<AppState>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.glob(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}

async fn grep(
    State(state): State<AppState>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<ErrorBody>)> {
    tokio::task::spawn_blocking(move || {
        let mut vfs = state
            .vfs
            .lock()
            .map_err(|_| map_err(db_vfs_core::Error::Db("vfs lock is poisoned".to_string())))?;
        vfs.grep(req).map(Json).map_err(map_err)
    })
    .await
    .map_err(|err| map_err(db_vfs_core::Error::Db(err.to_string())))?
}
