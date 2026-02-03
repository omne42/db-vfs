use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::StatusCode;

use db_vfs::vfs::{
    DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
    PatchRequest, PatchResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};

use super::audit::AuditEvent;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn audit_preview(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &input[..end])
}

fn redact_path(redactor: &db_vfs_core::redaction::SecretRedactor, path: &str) -> String {
    if redactor.is_path_denied(path) {
        "<secret>".to_string()
    } else {
        path.to_string()
    }
}

fn audit_event_base(
    request_id: String,
    peer: SocketAddr,
    op: &'static str,
    workspace_id: String,
    status: u16,
    error_code: Option<String>,
) -> AuditEvent {
    AuditEvent {
        ts_ms: now_ms(),
        request_id,
        peer_ip: Some(peer.ip().to_string()),
        op,
        workspace_id,
        requested_path: None,
        path: None,
        path_prefix: None,
        glob_pattern: None,
        grep_regex: None,
        grep_query_len: None,
        status,
        error_code,
        bytes_read: None,
        bytes_written: None,
        created: None,
        deleted: None,
        version: None,
        matches: None,
        truncated: None,
        scan_limit_reason: None,
        scanned_files: None,
        scanned_entries: None,
        skipped_too_large_files: None,
        skipped_traversal_skipped: None,
        skipped_secret_denied: None,
        skipped_glob_mismatch: None,
        skipped_missing_content: None,
    }
}

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
            if remaining.is_zero() {
                drop(permit);
                return Err(super::err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    "server is busy",
                ));
            }
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<ReadRequest>, JsonRejection>,
) -> Result<Json<ReadResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let req_path = audit_preview(&req.path, 4096);
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "read",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "read",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "read",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.requested_path = Some(req_path);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| vfs.read(req)).await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "read",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.requested_path =
                    Some(redact_path(&state.inner.redactor, &resp.requested_path));
                event.path = Some(redact_path(&state.inner.redactor, &resp.path));
                event.bytes_read = Some(resp.bytes_read);
                event.version = Some(resp.version);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "read",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                if body.code == "secret_path_denied" {
                    event.requested_path = Some("<secret>".to_string());
                    event.path = Some("<secret>".to_string());
                } else {
                    event.requested_path = Some(req_path);
                }
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn write(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<WriteRequest>, JsonRejection>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let req_path = audit_preview(&req.path, 4096);
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "write",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "write",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "write",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.requested_path = Some(req_path);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| vfs.write(req)).await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "write",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.requested_path =
                    Some(redact_path(&state.inner.redactor, &resp.requested_path));
                event.path = Some(redact_path(&state.inner.redactor, &resp.path));
                event.bytes_written = Some(resp.bytes_written);
                event.created = Some(resp.created);
                event.version = Some(resp.version);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "write",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                if body.code == "secret_path_denied" {
                    event.requested_path = Some("<secret>".to_string());
                    event.path = Some("<secret>".to_string());
                } else {
                    event.requested_path = Some(req_path);
                }
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn patch(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<PatchRequest>, JsonRejection>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let req_path = audit_preview(&req.path, 4096);
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "patch",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "patch",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "patch",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.requested_path = Some(req_path);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result = super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| {
        vfs.apply_unified_patch(req)
    })
    .await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "patch",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.requested_path =
                    Some(redact_path(&state.inner.redactor, &resp.requested_path));
                event.path = Some(redact_path(&state.inner.redactor, &resp.path));
                event.bytes_written = Some(resp.bytes_written);
                event.version = Some(resp.version);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "patch",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                if body.code == "secret_path_denied" {
                    event.requested_path = Some("<secret>".to_string());
                    event.path = Some("<secret>".to_string());
                } else {
                    event.requested_path = Some(req_path);
                }
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn delete(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<DeleteRequest>, JsonRejection>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let req_path = audit_preview(&req.path, 4096);
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "delete",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "delete",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.requested_path = Some(req_path);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.io_concurrency.clone(),
        Some(super::runner::io_timeout(&state.inner.policy)),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "delete",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.requested_path = Some(req_path);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| vfs.delete(req)).await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "delete",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.requested_path =
                    Some(redact_path(&state.inner.redactor, &resp.requested_path));
                event.path = Some(redact_path(&state.inner.redactor, &resp.path));
                event.deleted = Some(resp.deleted);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "delete",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                if body.code == "secret_path_denied" {
                    event.requested_path = Some("<secret>".to_string());
                    event.path = Some("<secret>".to_string());
                } else {
                    event.requested_path = Some(req_path);
                }
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn glob(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<GlobRequest>, JsonRejection>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let path_prefix = req
        .path_prefix
        .as_deref()
        .map(|prefix| audit_preview(prefix, 4096));
    let glob_pattern = audit_preview(&req.pattern, 4096);
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "glob",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.path_prefix = path_prefix;
            event.glob_pattern = Some(glob_pattern);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "glob",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.path_prefix = path_prefix;
            event.glob_pattern = Some(glob_pattern);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.scan_concurrency.clone(),
        super::runner::scan_timeout(&state.inner.policy),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "glob",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = Some(glob_pattern);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| vfs.glob(req)).await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "glob",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = Some(glob_pattern);
                event.matches = Some(resp.matches.len());
                event.truncated = Some(resp.truncated);
                event.scan_limit_reason = resp.scan_limit_reason;
                event.scanned_files = Some(resp.scanned_files);
                event.scanned_entries = Some(resp.scanned_entries);
                event.skipped_traversal_skipped = Some(resp.skipped_traversal_skipped);
                event.skipped_secret_denied = Some(resp.skipped_secret_denied);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "glob",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = Some(glob_pattern);
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn grep(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<GrepRequest>, JsonRejection>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let Json(req) = payload.map_err(map_json_rejection)?;
    let workspace_id = audit_preview(&req.workspace_id, 256);
    let path_prefix = req
        .path_prefix
        .as_deref()
        .map(|prefix| audit_preview(prefix, 4096));
    let glob_pattern = req
        .glob
        .as_deref()
        .map(|pattern| audit_preview(pattern, 4096));
    let grep_regex = req.regex;
    let grep_query_len = req.query.len();
    if let Err(err) = db_vfs_core::path::validate_workspace_id(&req.workspace_id) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "grep",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.path_prefix = path_prefix;
            event.glob_pattern = glob_pattern;
            event.grep_regex = Some(grep_regex);
            event.grep_query_len = Some(grep_query_len);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, &req.workspace_id) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event = audit_event_base(
                request_id,
                peer,
                "grep",
                workspace_id,
                status.as_u16(),
                Some(body.code.to_string()),
            );
            event.path_prefix = path_prefix;
            event.glob_pattern = glob_pattern;
            event.grep_regex = Some(grep_regex);
            event.grep_query_len = Some(grep_query_len);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(
        state.inner.scan_concurrency.clone(),
        super::runner::scan_timeout(&state.inner.policy),
    )
    .await
    {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "grep",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = glob_pattern;
                event.grep_regex = Some(grep_regex);
                event.grep_query_len = Some(grep_query_len);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };
    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| vfs.grep(req)).await;

    match result {
        Ok(resp) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "grep",
                    workspace_id,
                    StatusCode::OK.as_u16(),
                    None,
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = glob_pattern;
                event.grep_regex = Some(grep_regex);
                event.grep_query_len = Some(grep_query_len);
                event.matches = Some(resp.matches.len());
                event.truncated = Some(resp.truncated);
                event.scan_limit_reason = resp.scan_limit_reason;
                event.scanned_files = Some(resp.scanned_files);
                event.scanned_entries = Some(resp.scanned_entries);
                event.skipped_too_large_files = Some(resp.skipped_too_large_files);
                event.skipped_traversal_skipped = Some(resp.skipped_traversal_skipped);
                event.skipped_secret_denied = Some(resp.skipped_secret_denied);
                event.skipped_glob_mismatch = Some(resp.skipped_glob_mismatch);
                event.skipped_missing_content = Some(resp.skipped_missing_content);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_base(
                    request_id,
                    peer,
                    "grep",
                    workspace_id,
                    status.as_u16(),
                    Some(body.code.to_string()),
                );
                event.path_prefix = path_prefix;
                event.glob_pattern = glob_pattern;
                event.grep_regex = Some(grep_regex);
                event.grep_query_len = Some(grep_query_len);
                audit.log(event);
            }
            Err((status, Json(body)))
        }
    }
}
