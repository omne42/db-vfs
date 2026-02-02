use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use db_vfs::vfs::{
    DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};

pub(super) async fn read(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = Some(super::runner::io_timeout(&state.inner.policy));
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| vfs.read(req)).await?;

    Ok(Json(result))
}

pub(super) async fn write(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = Some(super::runner::io_timeout(&state.inner.policy));
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| vfs.write(req)).await?;

    Ok(Json(result))
}

pub(super) async fn patch(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<PatchRequest>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = Some(super::runner::io_timeout(&state.inner.policy));
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| {
        vfs.apply_unified_patch(req)
    })
    .await?;

    Ok(Json(result))
}

pub(super) async fn delete(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = Some(super::runner::io_timeout(&state.inner.policy));
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| vfs.delete(req)).await?;

    Ok(Json(result))
}

pub(super) async fn glob(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = super::runner::scan_timeout(&state.inner.policy);
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| vfs.glob(req)).await?;

    Ok(Json(result))
}

pub(super) async fn grep(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<super::ErrorBody>)> {
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
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
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;

    let timeout = super::runner::scan_timeout(&state.inner.policy);
    let result = super::runner::run_vfs(state, permit, timeout, move |vfs| vfs.grep(req)).await?;

    Ok(Json(result))
}
