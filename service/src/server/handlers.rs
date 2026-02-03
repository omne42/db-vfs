use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;

use db_vfs::vfs::{
    DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};

fn map_json_rejection(err: JsonRejection) -> (StatusCode, Json<super::ErrorBody>) {
    if matches!(err, JsonRejection::MissingJsonContentType(_)) {
        return super::err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "missing or invalid content-type; expected application/json",
        );
    }

    let status = err.status();
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return super::err(status, "payload_too_large", "request body is too large");
    }

    super::err(StatusCode::BAD_REQUEST, "invalid_json", "invalid JSON body")
}

async fn acquire_permit_with_budget(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: Option<Duration>,
) -> Result<
    (tokio::sync::OwnedSemaphorePermit, Option<Duration>),
    (StatusCode, Json<super::ErrorBody>),
> {
    match budget {
        Some(budget) => {
            let deadline = tokio::time::Instant::now() + budget;
            let permit = tokio::time::timeout_at(deadline, semaphore.acquire_owned())
                .await
                .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?
                .map_err(|_| {
                    super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy")
                })?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            Ok((permit, Some(remaining)))
        }
        None => {
            let permit = semaphore.acquire_owned().await.map_err(|_| {
                super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy")
            })?;
            Ok((permit, None))
        }
    }
}

pub(super) async fn read(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<ReadRequest>, JsonRejection>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await?;
    let result = super::runner::run_vfs(state, permit, remaining, move |vfs| vfs.read(req)).await?;

    Ok(Json(result))
}

pub(super) async fn write(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<WriteRequest>, JsonRejection>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await?;
    let result =
        super::runner::run_vfs(state, permit, remaining, move |vfs| vfs.write(req)).await?;

    Ok(Json(result))
}

pub(super) async fn patch(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<PatchRequest>, JsonRejection>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await?;
    let result = super::runner::run_vfs(state, permit, remaining, move |vfs| {
        vfs.apply_unified_patch(req)
    })
    .await?;

    Ok(Json(result))
}

pub(super) async fn delete(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<DeleteRequest>, JsonRejection>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await?;
    let result =
        super::runner::run_vfs(state, permit, remaining, move |vfs| vfs.delete(req)).await?;

    Ok(Json(result))
}

pub(super) async fn glob(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<GlobRequest>, JsonRejection>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.scan_concurrency.clone(),
        super::runner::scan_timeout(&state.inner.policy),
    )
    .await?;
    let result = super::runner::run_vfs(state, permit, remaining, move |vfs| vfs.glob(req)).await?;

    Ok(Json(result))
}

pub(super) async fn grep(
    State(state): State<super::AppState>,
    axum::extract::Extension(auth): axum::extract::Extension<super::auth::AuthContext>,
    payload: Result<Json<GrepRequest>, JsonRejection>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    db_vfs_core::path::validate_workspace_id(&req.workspace_id).map_err(super::map_err)?;
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        return Err(super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        ));
    }

    let (permit, remaining) = acquire_permit_with_budget(
        state.inner.scan_concurrency.clone(),
        super::runner::scan_timeout(&state.inner.policy),
    )
    .await?;
    let result = super::runner::run_vfs(state, permit, remaining, move |vfs| vfs.grep(req)).await?;

    Ok(Json(result))
}
