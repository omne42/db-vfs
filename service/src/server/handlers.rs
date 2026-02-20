use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::StatusCode;

use db_vfs::vfs::{
    DbVfs, DeleteRequest, DeleteResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse,
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
    if max_bytes == 0 {
        return String::new();
    }

    const ELLIPSIS: &str = "…";
    if max_bytes <= ELLIPSIS.len() {
        let mut end = max_bytes;
        while end > 0 && !input.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        return input[..end].to_string();
    }

    let mut end = max_bytes.saturating_sub(ELLIPSIS.len());
    while end > 0 && !input.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut out = String::with_capacity(end.saturating_add(ELLIPSIS.len()));
    out.push_str(&input[..end]);
    out.push_str(ELLIPSIS);
    out
}

fn is_path_or_descendant_denied(
    redactor: &db_vfs_core::redaction::SecretRedactor,
    path: &str,
) -> bool {
    if redactor.is_path_denied(path) {
        return true;
    }

    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return false;
    }

    let mut descendant_probe = String::with_capacity(trimmed.len().saturating_add(24));
    descendant_probe.push_str(trimmed);
    descendant_probe.push('/');
    descendant_probe.push_str("__db_vfs_audit_probe__");
    redactor.is_path_denied(&descendant_probe)
}

fn redact_path_owned(redactor: &db_vfs_core::redaction::SecretRedactor, path: String) -> String {
    if is_path_or_descendant_denied(redactor, &path) {
        "<secret>".to_string()
    } else {
        path
    }
}

fn redact_path_pair(
    redactor: &db_vfs_core::redaction::SecretRedactor,
    requested_path: String,
    path: String,
) -> (String, String) {
    if requested_path == path {
        let redacted = redact_path_owned(redactor, requested_path);
        return (redacted.clone(), redacted);
    }
    (
        redact_path_owned(redactor, requested_path),
        redact_path_owned(redactor, path),
    )
}

fn redact_glob_pattern(
    redactor: &db_vfs_core::redaction::SecretRedactor,
    pattern: String,
) -> String {
    redact_path_owned(redactor, pattern)
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
    match err {
        JsonRejection::MissingJsonContentType(_) => super::err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "missing or invalid content-type; expected application/json",
        ),
        JsonRejection::JsonSyntaxError(_) => super::err(
            StatusCode::BAD_REQUEST,
            "invalid_json_syntax",
            "invalid JSON syntax",
        ),
        JsonRejection::JsonDataError(_) => super::err(
            StatusCode::BAD_REQUEST,
            "invalid_json_schema",
            "JSON payload does not match request schema",
        ),
        other => {
            let status = other.status();
            if status == StatusCode::PAYLOAD_TOO_LARGE {
                return super::err(status, "payload_too_large", "request body is too large");
            }
            if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                return super::err(
                    status,
                    "unsupported_media_type",
                    "missing or invalid content-type; expected application/json",
                );
            }
            super::err(status, "invalid_json", "invalid JSON body")
        }
    }
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
                    StatusCode::REQUEST_TIMEOUT,
                    "timeout",
                    "request timed out before execution",
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

trait HasWorkspaceId {
    fn workspace_id(&self) -> &str;
}

impl HasWorkspaceId for ReadRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

impl HasWorkspaceId for WriteRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

impl HasWorkspaceId for PatchRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

impl HasWorkspaceId for DeleteRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

impl HasWorkspaceId for GlobRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

impl HasWorkspaceId for GrepRequest {
    fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

#[derive(Debug, Clone)]
struct AuditRequest {
    workspace_id: String,
    requested_path: Option<String>,
    path_prefix: Option<String>,
    glob_pattern: Option<String>,
    grep_regex: Option<bool>,
    grep_query_len: Option<usize>,
}

impl AuditRequest {
    fn into_event(
        self,
        request_id: String,
        peer: SocketAddr,
        op: &'static str,
        status: StatusCode,
        error_code: Option<String>,
    ) -> AuditEvent {
        let mut event = audit_event_base(
            request_id,
            peer,
            op,
            self.workspace_id,
            status.as_u16(),
            error_code,
        );
        event.requested_path = self.requested_path;
        event.path_prefix = self.path_prefix;
        event.glob_pattern = self.glob_pattern;
        event.grep_regex = self.grep_regex;
        event.grep_query_len = self.grep_query_len;
        event
    }
}

fn build_path_audit_req(workspace_id: &str, path: &str) -> AuditRequest {
    AuditRequest {
        workspace_id: audit_preview(workspace_id, 256),
        requested_path: Some(audit_preview(path, 4096)),
        path_prefix: None,
        glob_pattern: None,
        grep_regex: None,
        grep_query_len: None,
    }
}

fn audit_err_hide_secret_path(
    state: &super::AppState,
    event: &mut AuditEvent,
    body: &super::ErrorBody,
) {
    match (event.requested_path.take(), event.path.take()) {
        (Some(requested_path), Some(path)) => {
            let (requested_path, path) =
                redact_path_pair(&state.inner.redactor, requested_path, path);
            event.requested_path = Some(requested_path);
            event.path = Some(path);
        }
        (Some(requested_path), None) => {
            event.requested_path = Some(redact_path_owned(&state.inner.redactor, requested_path));
        }
        (None, Some(path)) => {
            event.path = Some(redact_path_owned(&state.inner.redactor, path));
        }
        (None, None) => {}
    }
    if body.code == "secret_path_denied" {
        event.requested_path = Some("<secret>".to_string());
        event.path = Some("<secret>".to_string());
    }
}

fn audit_ok_read(state: &super::AppState, event: &mut AuditEvent, resp: &ReadResponse) {
    let (requested_path, path) = redact_path_pair(
        &state.inner.redactor,
        resp.requested_path.clone(),
        resp.path.clone(),
    );
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_read = Some(resp.bytes_read);
    event.version = Some(resp.version);
}

fn audit_ok_write(state: &super::AppState, event: &mut AuditEvent, resp: &WriteResponse) {
    let (requested_path, path) = redact_path_pair(
        &state.inner.redactor,
        resp.requested_path.clone(),
        resp.path.clone(),
    );
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.created = Some(resp.created);
    event.version = Some(resp.version);
}

fn audit_ok_patch(state: &super::AppState, event: &mut AuditEvent, resp: &PatchResponse) {
    let (requested_path, path) = redact_path_pair(
        &state.inner.redactor,
        resp.requested_path.clone(),
        resp.path.clone(),
    );
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.version = Some(resp.version);
}

fn audit_ok_delete(state: &super::AppState, event: &mut AuditEvent, resp: &DeleteResponse) {
    let (requested_path, path) = redact_path_pair(
        &state.inner.redactor,
        resp.requested_path.clone(),
        resp.path.clone(),
    );
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.deleted = Some(resp.deleted);
}

fn audit_redact_scan_fields(state: &super::AppState, event: &mut AuditEvent) {
    if let Some(prefix) = event.path_prefix.take() {
        event.path_prefix = Some(redact_path_owned(&state.inner.redactor, prefix));
    }
    if let Some(pattern) = event.glob_pattern.take() {
        event.glob_pattern = Some(redact_glob_pattern(&state.inner.redactor, pattern));
    }
}

fn audit_err_redact_scan_fields(
    state: &super::AppState,
    event: &mut AuditEvent,
    _body: &super::ErrorBody,
) {
    audit_redact_scan_fields(state, event);
}

fn audit_ok_glob(state: &super::AppState, event: &mut AuditEvent, resp: &GlobResponse) {
    audit_redact_scan_fields(state, event);
    event.matches = Some(resp.matches.len());
    event.truncated = Some(resp.truncated);
    event.scan_limit_reason = resp.scan_limit_reason;
    event.scanned_files = Some(resp.scanned_files);
    event.scanned_entries = Some(resp.scanned_entries);
    event.skipped_traversal_skipped = Some(resp.skipped_traversal_skipped);
    event.skipped_secret_denied = Some(resp.skipped_secret_denied);
}

fn audit_ok_grep(state: &super::AppState, event: &mut AuditEvent, resp: &GrepResponse) {
    audit_redact_scan_fields(state, event);
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
}

struct RequestContext {
    peer: SocketAddr,
    state: super::AppState,
    request_id: String,
    auth: super::auth::AuthContext,
    op: &'static str,
}

struct VfsLimits {
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: Option<Duration>,
}

struct AuditHooks<Resp> {
    ok: fn(&super::AppState, &mut AuditEvent, &Resp),
    err: fn(&super::AppState, &mut AuditEvent, &super::ErrorBody),
}

fn request_ctx(
    peer: SocketAddr,
    state: super::AppState,
    request_id: String,
    auth: super::auth::AuthContext,
    op: &'static str,
) -> RequestContext {
    RequestContext {
        peer,
        state,
        request_id,
        auth,
        op,
    }
}

fn io_limits(state: &super::AppState) -> VfsLimits {
    VfsLimits {
        semaphore: state.inner.io_concurrency.clone(),
        budget: Some(super::runner::io_timeout(&state.inner.policy)),
    }
}

fn scan_limits(state: &super::AppState) -> VfsLimits {
    VfsLimits {
        semaphore: state.inner.scan_concurrency.clone(),
        budget: super::runner::scan_timeout(&state.inner.policy),
    }
}

async fn handle_vfs_request<Req, Resp, BuildAuditReq, Run>(
    ctx: RequestContext,
    payload: Result<Json<Req>, JsonRejection>,
    limits: VfsLimits,
    build_audit_req: BuildAuditReq,
    run: Run,
    hooks: AuditHooks<Resp>,
) -> Result<Json<Resp>, (StatusCode, Json<super::ErrorBody>)>
where
    Req: HasWorkspaceId + Send + 'static,
    Resp: Send + 'static,
    BuildAuditReq: FnOnce(&Req) -> AuditRequest,
    Run: FnOnce(&mut DbVfs<super::backend::BackendStore>, Req) -> db_vfs::Result<Resp>
        + Send
        + 'static,
{
    let RequestContext {
        peer,
        state,
        request_id,
        auth,
        op,
    } = ctx;
    let VfsLimits { semaphore, budget } = limits;
    let AuditHooks {
        ok: audit_ok,
        err: audit_err,
    } = hooks;

    let (req, audit_req) = match payload {
        Ok(Json(req)) => {
            let audit_req = build_audit_req(&req);
            (req, audit_req)
        }
        Err(err) => {
            let (status, Json(body)) = map_json_rejection(err);
            if let Some(audit) = state.inner.audit.as_ref() {
                let audit_req = AuditRequest {
                    workspace_id: super::audit::UNKNOWN_WORKSPACE_ID.to_string(),
                    requested_path: None,
                    path_prefix: None,
                    glob_pattern: None,
                    grep_regex: None,
                    grep_query_len: None,
                };
                let event =
                    audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };

    if let Err(err) = db_vfs_core::path::validate_workspace_id(req.workspace_id()) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event =
                audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
            audit_err(&state, &mut event, &body);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, req.workspace_id()) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event =
                audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
            audit_err(&state, &mut event, &body);
            audit.log(event);
        }
        return Err((status, Json(body)));
    }

    let (permit, remaining) = match acquire_permit_with_budget(semaphore, budget).await {
        Ok(v) => v,
        Err((status, Json(body))) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event =
                    audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
                audit_err(&state, &mut event, &body);
                audit.log(event);
            }
            return Err((status, Json(body)));
        }
    };

    let state_for_run = state.clone();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| run(vfs, req)).await;

    match (result, request_id, audit_req) {
        (Ok(resp), request_id, audit_req) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_req.into_event(request_id, peer, op, StatusCode::OK, None);
                audit_ok(&state, &mut event, &resp);
                audit.log(event);
            }
            Ok(Json(resp))
        }
        (Err((status, Json(body))), request_id, audit_req) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event =
                    audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
                audit_err(&state, &mut event, &body);
                audit.log(event);
            }
            Err((status, Json(body)))
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
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "read");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| build_path_audit_req(req.workspace_id(), &req.path),
        DbVfs::read,
        AuditHooks {
            ok: audit_ok_read,
            err: audit_err_hide_secret_path,
        },
    )
    .await
}

pub(super) async fn write(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<WriteRequest>, JsonRejection>,
) -> Result<Json<WriteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "write");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| build_path_audit_req(req.workspace_id(), &req.path),
        DbVfs::write,
        AuditHooks {
            ok: audit_ok_write,
            err: audit_err_hide_secret_path,
        },
    )
    .await
}

pub(super) async fn patch(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<PatchRequest>, JsonRejection>,
) -> Result<Json<PatchResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "patch");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| build_path_audit_req(req.workspace_id(), &req.path),
        DbVfs::apply_unified_patch,
        AuditHooks {
            ok: audit_ok_patch,
            err: audit_err_hide_secret_path,
        },
    )
    .await
}

pub(super) async fn delete(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<DeleteRequest>, JsonRejection>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "delete");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| build_path_audit_req(req.workspace_id(), &req.path),
        DbVfs::delete,
        AuditHooks {
            ok: audit_ok_delete,
            err: audit_err_hide_secret_path,
        },
    )
    .await
}

pub(super) async fn glob(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<GlobRequest>, JsonRejection>,
) -> Result<Json<GlobResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = scan_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "glob");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| AuditRequest {
            workspace_id: audit_preview(req.workspace_id(), 256),
            requested_path: None,
            path_prefix: req
                .path_prefix
                .as_deref()
                .map(|prefix| audit_preview(prefix, 4096)),
            glob_pattern: Some(audit_preview(&req.pattern, 4096)),
            grep_regex: None,
            grep_query_len: None,
        },
        DbVfs::glob,
        AuditHooks {
            ok: audit_ok_glob,
            err: audit_err_redact_scan_fields,
        },
    )
    .await
}

pub(super) async fn grep(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    payload: Result<Json<GrepRequest>, JsonRejection>,
) -> Result<Json<GrepResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = scan_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "grep");
    handle_vfs_request(
        ctx,
        payload,
        limits,
        |req| AuditRequest {
            workspace_id: audit_preview(req.workspace_id(), 256),
            requested_path: None,
            path_prefix: req
                .path_prefix
                .as_deref()
                .map(|prefix| audit_preview(prefix, 4096)),
            glob_pattern: req
                .glob
                .as_deref()
                .map(|pattern| audit_preview(pattern, 4096)),
            grep_regex: Some(req.regex),
            grep_query_len: Some(req.query.len()),
        },
        DbVfs::grep,
        AuditHooks {
            ok: audit_ok_grep,
            err: audit_err_redact_scan_fields,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_permit_with_budget, audit_preview, redact_glob_pattern, redact_path_owned,
    };
    use axum::http::StatusCode;
    use db_vfs_core::policy::SecretRules;
    use db_vfs_core::redaction::SecretRedactor;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn redact_path_hides_denied_prefix_root_paths() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");

        assert_eq!(redact_path_owned(&redactor, ".git".to_string()), "<secret>");
        assert_eq!(
            redact_path_owned(&redactor, ".git/".to_string()),
            "<secret>"
        );
        assert_eq!(redact_path_owned(&redactor, ".git".to_string()), "<secret>");
        assert_eq!(
            redact_glob_pattern(&redactor, ".git".to_string()),
            "<secret>"
        );
        assert_eq!(redact_path_owned(&redactor, "docs".to_string()), "docs");
    }

    #[tokio::test]
    async fn acquire_permit_times_out_before_execution_when_budget_is_exhausted() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (status, body) = acquire_permit_with_budget(semaphore, Some(Duration::ZERO))
            .await
            .expect_err("zero budget should time out");
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(body.0.code, "timeout");
    }

    #[test]
    fn audit_preview_honors_byte_budget() {
        let ascii = audit_preview("abcdef", 4);
        assert_eq!(ascii, "a…");
        assert!(ascii.len() <= 4);

        let unicode = audit_preview("你好世界", 7);
        assert_eq!(unicode, "你…");
        assert!(unicode.len() <= 7);

        let tiny = audit_preview("abcdef", 2);
        assert_eq!(tiny, "ab");
        assert!(tiny.len() <= 2);
    }
}
