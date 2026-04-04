use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::async_trait;
use axum::extract::Request;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Extension, FromRequest, FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

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

fn audit_event_base(
    request_id: String,
    peer: Option<SocketAddr>,
    op: &'static str,
    workspace_id: String,
    auth_subject: Option<&str>,
    status: u16,
    error_code: Option<String>,
) -> AuditEvent {
    AuditEvent {
        ts_ms: now_ms(),
        request_id,
        peer_ip: peer.map(|addr| addr.ip().to_string()),
        op,
        workspace_id,
        auth_subject: auth_subject.map(ToOwned::to_owned),
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

#[derive(Clone, Copy, Debug)]
pub(super) struct MaybeConnectInfo(Option<SocketAddr>);

#[async_trait]
impl<S> FromRequestParts<S> for MaybeConnectInfo
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| *addr),
        ))
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

async fn try_acquire_permit(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: Option<Duration>,
) -> Result<
    (tokio::sync::OwnedSemaphorePermit, Option<Duration>),
    (StatusCode, Json<super::ErrorBody>),
> {
    if budget.is_some_and(|limit| limit.is_zero()) {
        return Err(super::err(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "request timed out before execution",
        ));
    }

    let permit = semaphore
        .try_acquire_owned()
        .map_err(|_| super::err(StatusCode::SERVICE_UNAVAILABLE, "busy", "server is busy"))?;
    Ok((permit, budget))
}

async fn parse_json_payload<Req, S>(request: Request, state: &S) -> Result<Req, JsonRejection>
where
    Req: DeserializeOwned,
    S: Send + Sync,
{
    Ok(Json::<Req>::from_request(request, state).await?.0)
}

#[derive(Debug)]
enum PermitThenParseJson<Req> {
    Parsed {
        permit: tokio::sync::OwnedSemaphorePermit,
        remaining: Option<Duration>,
        req: Req,
    },
    Rejected {
        permit: tokio::sync::OwnedSemaphorePermit,
        remaining: Option<Duration>,
        status: StatusCode,
        body: super::ErrorBody,
    },
}

async fn try_acquire_permit_then_parse_json<Req, S>(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: Option<Duration>,
    request: Request,
    state: &S,
) -> Result<PermitThenParseJson<Req>, (StatusCode, Json<super::ErrorBody>)>
where
    Req: DeserializeOwned,
    S: Send + Sync,
{
    let (permit, remaining) = try_acquire_permit(semaphore, budget).await?;
    let started = Instant::now();
    let parsed = if let Some(timeout) = remaining {
        if timeout.is_zero() {
            return Ok(PermitThenParseJson::Rejected {
                permit,
                remaining: Some(Duration::ZERO),
                status: StatusCode::REQUEST_TIMEOUT,
                body: super::ErrorBody {
                    code: super::CODE_TIMEOUT,
                    message: "request timed out while buffering or decoding JSON body".to_string(),
                },
            });
        }

        match tokio::time::timeout(timeout, parse_json_payload::<Req, S>(request, state)).await {
            Ok(parsed) => parsed,
            Err(_) => {
                return Ok(PermitThenParseJson::Rejected {
                    permit,
                    remaining: Some(Duration::ZERO),
                    status: StatusCode::REQUEST_TIMEOUT,
                    body: super::ErrorBody {
                        code: super::CODE_TIMEOUT,
                        message: "request timed out while buffering or decoding JSON body"
                            .to_string(),
                    },
                });
            }
        }
    } else {
        parse_json_payload::<Req, S>(request, state).await
    };
    let remaining = remaining.map(|budget| budget.saturating_sub(started.elapsed()));

    match parsed {
        Ok(req) => Ok(PermitThenParseJson::Parsed {
            permit,
            remaining,
            req,
        }),
        Err(err) => {
            let (status, Json(body)) = map_json_rejection(err);
            Ok(PermitThenParseJson::Rejected {
                permit,
                remaining,
                status,
                body,
            })
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
        peer: Option<SocketAddr>,
        op: &'static str,
        auth_subject: Option<&str>,
        status: StatusCode,
        error_code: Option<String>,
    ) -> AuditEvent {
        let mut event = audit_event_base(
            request_id,
            peer,
            op,
            self.workspace_id,
            auth_subject,
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
            let (requested_path, path) = state
                .inner
                .redactor
                .redact_audit_path_pair(&requested_path, &path);
            event.requested_path = Some(requested_path);
            event.path = Some(path);
        }
        (Some(requested_path), None) => {
            event.requested_path = Some(state.inner.redactor.redact_audit_path(&requested_path));
        }
        (None, Some(path)) => {
            event.path = Some(state.inner.redactor.redact_audit_path(&path));
        }
        (None, None) => {}
    }
    if body.code == "secret_path_denied" {
        event.requested_path = Some("<secret>".to_string());
        event.path = Some("<secret>".to_string());
    }
}

fn audit_ok_read(state: &super::AppState, event: &mut AuditEvent, resp: &ReadResponse) {
    let (requested_path, path) = state
        .inner
        .redactor
        .redact_audit_path_pair(&resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_read = Some(resp.bytes_read);
    event.version = Some(resp.version);
}

fn audit_ok_write(state: &super::AppState, event: &mut AuditEvent, resp: &WriteResponse) {
    let (requested_path, path) = state
        .inner
        .redactor
        .redact_audit_path_pair(&resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.created = Some(resp.created);
    event.version = Some(resp.version);
}

fn audit_ok_patch(state: &super::AppState, event: &mut AuditEvent, resp: &PatchResponse) {
    let (requested_path, path) = state
        .inner
        .redactor
        .redact_audit_path_pair(&resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.version = Some(resp.version);
}

fn audit_ok_delete(state: &super::AppState, event: &mut AuditEvent, resp: &DeleteResponse) {
    let (requested_path, path) = state
        .inner
        .redactor
        .redact_audit_path_pair(&resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.deleted = Some(resp.deleted);
}

fn audit_redact_scan_fields(state: &super::AppState, event: &mut AuditEvent) {
    if let Some(prefix) = event.path_prefix.take() {
        event.path_prefix = Some(state.inner.redactor.redact_audit_path(&prefix));
    }
    if let Some(pattern) = event.glob_pattern.take() {
        event.glob_pattern = Some(state.inner.redactor.redact_audit_glob_pattern(&pattern));
    }
}

fn audit_err_redact_scan_fields(
    state: &super::AppState,
    event: &mut AuditEvent,
    _body: &super::ErrorBody,
) {
    audit_redact_scan_fields(state, event);
}

fn audit_err_noop(_state: &super::AppState, _event: &mut AuditEvent, _body: &super::ErrorBody) {}

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
    peer: Option<SocketAddr>,
    state: super::AppState,
    request_id: String,
    auth: super::auth::AuthContext,
    op: &'static str,
}

struct VfsLimits {
    semaphore: Arc<tokio::sync::Semaphore>,
    parse_budget: Option<Duration>,
    runtime_budget: Option<Duration>,
}

struct AuditHooks<Resp> {
    ok: fn(&super::AppState, &mut AuditEvent, &Resp),
    err: fn(&super::AppState, &mut AuditEvent, &super::ErrorBody),
}

#[derive(Clone, Copy)]
struct AuditEventContext<'a> {
    request_id: &'a str,
    peer: Option<SocketAddr>,
    op: &'static str,
    auth_subject: Option<&'a str>,
}

impl AuditEventContext<'_> {
    fn build_event(
        self,
        audit_req: AuditRequest,
        status: StatusCode,
        error_code: Option<String>,
    ) -> AuditEvent {
        audit_req.into_event(
            self.request_id.to_string(),
            self.peer,
            self.op,
            self.auth_subject,
            status,
            error_code,
        )
    }
}

struct RejectionAuditContext<'a> {
    state: &'a super::AppState,
    event_ctx: AuditEventContext<'a>,
    audit_err: fn(&super::AppState, &mut AuditEvent, &super::ErrorBody),
}

async fn log_request_rejection_audit(
    ctx: RejectionAuditContext<'_>,
    audit_req: AuditRequest,
    status: StatusCode,
    body: &super::ErrorBody,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    remaining: Option<Duration>,
) -> Result<(), (StatusCode, Json<super::ErrorBody>)> {
    let RejectionAuditContext {
        state,
        event_ctx,
        audit_err,
    } = ctx;

    if let Some(audit) = state.inner.audit.as_ref() {
        let mut event = event_ctx.build_event(audit_req, status, Some(body.code.to_string()));
        audit_err(state, &mut event, body);
        if let Some(permit) = permit {
            super::log_audit_event_with_permit(audit, event, permit, remaining).await?;
        } else {
            super::log_audit_event(audit, event).await?;
        }
    } else if let Some(permit) = permit {
        drop(permit);
    }

    Ok(())
}

fn request_ctx(
    peer: Option<SocketAddr>,
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
        parse_budget: Some(super::runner::io_timeout(&state.inner.policy)),
        runtime_budget: Some(super::runner::io_timeout(&state.inner.policy)),
    }
}

fn scan_limits(state: &super::AppState) -> VfsLimits {
    VfsLimits {
        semaphore: state.inner.scan_concurrency.clone(),
        parse_budget: Some(super::runner::io_timeout(&state.inner.policy)),
        runtime_budget: super::runner::scan_timeout(&state.inner.policy),
    }
}

fn audit_budget_after_execution(
    state: &super::AppState,
    runtime_budget: Option<Duration>,
    started: Instant,
) -> Option<Duration> {
    runtime_budget
        .map(|budget| budget.saturating_sub(started.elapsed()))
        .or_else(|| Some(super::runner::io_timeout(&state.inner.policy)))
}

async fn handle_vfs_request<Req, Resp, BuildAuditReq, Run>(
    ctx: RequestContext,
    request: Request,
    limits: VfsLimits,
    build_audit_req: BuildAuditReq,
    run: Run,
    hooks: AuditHooks<Resp>,
) -> Result<Json<Resp>, (StatusCode, Json<super::ErrorBody>)>
where
    Req: DeserializeOwned + HasWorkspaceId + Send + 'static,
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
    let VfsLimits {
        semaphore,
        parse_budget,
        runtime_budget,
    } = limits;
    let AuditHooks {
        ok: audit_ok,
        err: audit_err,
    } = hooks;
    let audit_event_ctx = AuditEventContext {
        request_id: &request_id,
        peer,
        op,
        auth_subject: auth.audit_subject.as_deref(),
    };

    let (permit, remaining, req) = match try_acquire_permit_then_parse_json::<Req, _>(
        semaphore,
        parse_budget,
        request,
        &state,
    )
    .await
    {
        Ok(PermitThenParseJson::Parsed {
            permit,
            remaining,
            req,
        }) => (permit, remaining, req),
        Ok(PermitThenParseJson::Rejected {
            permit,
            remaining,
            status,
            body,
        }) => {
            log_request_rejection_audit(
                RejectionAuditContext {
                    state: &state,
                    event_ctx: audit_event_ctx,
                    audit_err: audit_err_noop,
                },
                AuditRequest {
                    workspace_id: super::audit::UNKNOWN_WORKSPACE_ID.to_string(),
                    requested_path: None,
                    path_prefix: None,
                    glob_pattern: None,
                    grep_regex: None,
                    grep_query_len: None,
                },
                status,
                &body,
                Some(permit),
                remaining,
            )
            .await?;
            return Err((status, Json(body)));
        }
        Err((status, Json(body))) => return Err((status, Json(body))),
    };
    let audit_req = build_audit_req(&req);

    if let Err(err) = db_vfs_core::path::validate_workspace_id(req.workspace_id()) {
        let (status, Json(body)) = super::map_err(err);
        log_request_rejection_audit(
            RejectionAuditContext {
                state: &state,
                event_ctx: audit_event_ctx,
                audit_err,
            },
            audit_req,
            status,
            &body,
            Some(permit),
            remaining,
        )
        .await?;
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, req.workspace_id()) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            super::CODE_NOT_PERMITTED,
            "workspace is not allowed for this token",
        );
        log_request_rejection_audit(
            RejectionAuditContext {
                state: &state,
                event_ctx: audit_event_ctx,
                audit_err,
            },
            audit_req,
            status,
            &body,
            Some(permit),
            remaining,
        )
        .await?;
        return Err((status, Json(body)));
    }

    let state_for_run = state.clone();
    let started = Instant::now();
    let result = super::runner::run_vfs(state_for_run, permit, runtime_budget, move |vfs| {
        run(vfs, req)
    })
    .await;

    match (result, audit_req) {
        (Ok((Ok(resp), permit)), audit_req) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_event_ctx.build_event(audit_req, StatusCode::OK, None);
                audit_ok(&state, &mut event, &resp);
                let audit_budget = audit_budget_after_execution(&state, runtime_budget, started);
                super::log_audit_event_with_permit(audit, event, permit, audit_budget).await?;
            } else {
                drop(permit);
            }
            Ok(Json(resp))
        }
        (Ok((Err(err), permit)), audit_req) => {
            let (status, Json(body)) = super::map_err(err);
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event =
                    audit_event_ctx.build_event(audit_req, status, Some(body.code.to_string()));
                audit_err(&state, &mut event, &body);
                let audit_budget = audit_budget_after_execution(&state, runtime_budget, started);
                super::log_audit_event_with_permit(audit, event, permit, audit_budget).await?;
            } else {
                drop(permit);
            }
            Err((status, Json(body)))
        }
        (Err((permit, status, Json(body))), audit_req) => {
            log_request_rejection_audit(
                RejectionAuditContext {
                    state: &state,
                    event_ctx: audit_event_ctx,
                    audit_err,
                },
                audit_req,
                status,
                &body,
                Some(permit),
                audit_budget_after_execution(&state, runtime_budget, started),
            )
            .await?;
            Err((status, Json(body)))
        }
    }
}

pub(super) async fn read(
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<ReadResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "read");
    handle_vfs_request(
        ctx,
        request,
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
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<WriteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "write");
    handle_vfs_request(
        ctx,
        request,
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
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<PatchResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "patch");
    handle_vfs_request(
        ctx,
        request,
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
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = io_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "delete");
    handle_vfs_request(
        ctx,
        request,
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
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<GlobResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = scan_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "glob");
    handle_vfs_request(
        ctx,
        request,
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
    MaybeConnectInfo(peer): MaybeConnectInfo,
    State(state): State<super::AppState>,
    Extension(super::layers::RequestId(request_id)): Extension<super::layers::RequestId>,
    Extension(auth): Extension<super::auth::AuthContext>,
    request: Request,
) -> Result<Json<GrepResponse>, (StatusCode, Json<super::ErrorBody>)> {
    let limits = scan_limits(&state);
    let ctx = request_ctx(peer, state, request_id, auth, "grep");
    handle_vfs_request(
        ctx,
        request,
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
        AuditEventContext, AuditHooks, AuditRequest, PermitThenParseJson, VfsLimits, audit_preview,
        handle_vfs_request, io_limits, request_ctx, try_acquire_permit,
        try_acquire_permit_then_parse_json,
    };
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use db_vfs::vfs::{DbVfs, WriteRequest};
    use db_vfs_core::policy::{AuditPolicy, Limits, ValidatedVfsPolicy, VfsPolicy};
    use db_vfs_core::redaction::SecretRedactor;
    use db_vfs_core::traversal::TraversalSkipper;
    use std::sync::Arc;
    use std::time::Duration;

    #[cfg(feature = "sqlite")]
    fn test_state_with_audit(
        audit: Option<super::super::audit::AuditLogger>,
    ) -> super::super::AppState {
        let policy = Arc::new(ValidatedVfsPolicy::new(VfsPolicy::default()).expect("policy"));
        let redactor = Arc::new(SecretRedactor::from_rules(&policy.secrets).expect("redactor"));
        let traversal =
            Arc::new(TraversalSkipper::from_rules(&policy.traversal).expect("traversal"));
        let manager = super::super::sqlite_connection_manager(
            std::path::Path::new(":memory:"),
            Duration::from_millis(50),
        );
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("sqlite pool");

        super::super::AppState {
            inner: Arc::new(super::super::AppInner {
                backend: super::super::backend::Backend::Sqlite { pool },
                policy: policy.clone(),
                redactor,
                traversal,
                audit,
                auth: super::super::auth::AuthMode::Disabled,
                rate_limiter: super::super::rate_limiter::RateLimiter::new(policy.as_ref()),
                io_concurrency: Arc::new(tokio::sync::Semaphore::new(1)),
                scan_concurrency: Arc::new(tokio::sync::Semaphore::new(1)),
            }),
        }
    }

    fn allow_all_auth_ctx() -> super::super::auth::AuthContext {
        auth_ctx_with_subject(None)
    }

    fn auth_ctx_with_subject(audit_subject: Option<&str>) -> super::super::auth::AuthContext {
        super::super::auth::AuthContext {
            allowed_workspaces: Arc::from(vec![super::super::auth::WorkspacePattern::Any]),
            audit_subject: audit_subject.map(Arc::<str>::from),
        }
    }

    #[tokio::test]
    async fn try_acquire_permit_times_out_before_execution_when_budget_is_exhausted() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (status, body) = try_acquire_permit(semaphore, Some(Duration::ZERO))
            .await
            .expect_err("zero budget should time out");
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(body.0.code, "timeout");
    }

    #[tokio::test]
    async fn try_acquire_permit_preserves_large_budget_when_slot_is_available() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (_permit, remaining) = try_acquire_permit(semaphore, Some(Duration::MAX))
            .await
            .expect("large budget should not block immediate acquisition");
        assert_eq!(remaining, Some(Duration::MAX));
    }

    #[tokio::test]
    async fn try_acquire_permit_returns_busy_when_all_slots_are_in_use() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let held_permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");

        let (status, body) = try_acquire_permit(semaphore, Some(Duration::from_millis(10)))
            .await
            .expect_err("saturated semaphore should return busy");
        drop(held_permit);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.code, "busy");
    }

    #[tokio::test]
    async fn try_acquire_permit_then_parse_json_returns_busy_before_invalid_json() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let held_permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .expect("request");

        let (status, body) =
            try_acquire_permit_then_parse_json::<WriteRequest, _>(semaphore, None, request, &())
                .await
                .expect_err("saturated semaphore should short-circuit before JSON parsing");
        drop(held_permit);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.code, "busy");
    }

    #[tokio::test]
    async fn try_acquire_permit_then_parse_json_returns_rejected_json_errors_with_permit() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .expect("request");

        let outcome = try_acquire_permit_then_parse_json::<WriteRequest, _>(
            Arc::new(tokio::sync::Semaphore::new(1)),
            None,
            request,
            &(),
        )
        .await
        .expect("invalid JSON should still be reported once a permit is held");

        match outcome {
            PermitThenParseJson::Rejected {
                permit,
                status,
                body,
                ..
            } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body.code, "invalid_json_syntax");
                drop(permit);
            }
            PermitThenParseJson::Parsed { .. } => panic!("invalid JSON should not parse"),
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn handle_vfs_request_keeps_io_permit_during_required_audit_for_json_rejects() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let state = test_state_with_audit(Some(audit));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .expect("request");

        let task = tokio::spawn({
            let state = state.clone();
            async move {
                handle_vfs_request(
                    request_ctx(
                        None,
                        state.clone(),
                        "req-invalid-json".to_string(),
                        allow_all_auth_ctx(),
                        "write",
                    ),
                    request,
                    io_limits(&state),
                    |req: &WriteRequest| {
                        super::build_path_audit_req(req.workspace_id.as_str(), &req.path)
                    },
                    DbVfs::write,
                    AuditHooks {
                        ok: super::audit_ok_write,
                        err: super::audit_err_hide_secret_path,
                    },
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("required audit should block");
        assert!(
            state
                .inner
                .io_concurrency
                .clone()
                .try_acquire_owned()
                .is_err(),
            "required audit should keep the original IO permit on JSON rejects"
        );

        control.release_success();
        let err = task
            .await
            .expect("join invalid JSON task")
            .expect_err("invalid JSON should be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.0.code, "invalid_json_syntax");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn handle_vfs_request_times_out_required_audit_for_json_rejects() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let policy = VfsPolicy {
            limits: Limits {
                max_io_ms: 10,
                ..Limits::default()
            },
            audit: AuditPolicy {
                required: true,
                ..AuditPolicy::default()
            },
            ..VfsPolicy::default()
        };
        let state = super::super::test_state_with_policy_and_audit(policy, Some(audit));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .expect("request");

        let err = handle_vfs_request(
            request_ctx(
                None,
                state.clone(),
                "req-invalid-json-timeout".to_string(),
                allow_all_auth_ctx(),
                "write",
            ),
            request,
            io_limits(&state),
            |req: &WriteRequest| super::build_path_audit_req(req.workspace_id.as_str(), &req.path),
            DbVfs::write,
            AuditHooks {
                ok: super::audit_ok_write,
                err: super::audit_err_hide_secret_path,
            },
        )
        .await
        .expect_err("required audit timeout should fail closed");

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");
        let permit = tokio::time::timeout(
            Duration::from_secs(1),
            state.inner.io_concurrency.clone().acquire_owned(),
        )
        .await
        .expect("timed-out audit should release the semaphore slot")
        .expect("acquire IO permit after timed-out audit");
        drop(permit);

        control.release_success();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn handle_vfs_request_keeps_io_permit_during_required_audit_for_workspace_rejects() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let state = test_state_with_audit(Some(audit));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"workspace_id":"bad*ws","path":"docs/a.txt","content":"x","expected_version":null}"#,
            ))
            .expect("request");

        let task = tokio::spawn({
            let state = state.clone();
            async move {
                handle_vfs_request(
                    request_ctx(
                        None,
                        state.clone(),
                        "req-invalid-workspace".to_string(),
                        allow_all_auth_ctx(),
                        "write",
                    ),
                    request,
                    io_limits(&state),
                    |req: &WriteRequest| {
                        super::build_path_audit_req(req.workspace_id.as_str(), &req.path)
                    },
                    DbVfs::write,
                    AuditHooks {
                        ok: super::audit_ok_write,
                        err: super::audit_err_hide_secret_path,
                    },
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("required audit should block");
        assert!(
            state
                .inner
                .io_concurrency
                .clone()
                .try_acquire_owned()
                .is_err(),
            "required audit should keep the original IO permit on workspace rejects"
        );

        control.release_success();
        let err = task
            .await
            .expect("join invalid workspace task")
            .expect_err("invalid workspace should be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1.0.code, "invalid_path");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn handle_vfs_request_audit_includes_auth_subject_on_rejection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let audit = super::super::audit::AuditLogger::new(&path, true, 1, Duration::from_millis(1))
            .expect("audit logger");
        let state = test_state_with_audit(Some(audit));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"workspace_id":"bad*ws","path":"docs/a.txt","content":"x","expected_version":null}"#,
            ))
            .expect("request");

        let err = handle_vfs_request(
            request_ctx(
                None,
                state,
                "req-invalid-workspace".to_string(),
                auth_ctx_with_subject(Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )),
                "write",
            ),
            request,
            VfsLimits {
                semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                parse_budget: None,
                runtime_budget: None,
            },
            |req: &WriteRequest| super::build_path_audit_req(req.workspace_id.as_str(), &req.path),
            DbVfs::write,
            AuditHooks {
                ok: super::audit_ok_write,
                err: super::audit_err_hide_secret_path,
            },
        )
        .await
        .expect_err("invalid workspace should be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let raw = std::fs::read_to_string(&path).expect("read audit log");
        let parsed: serde_json::Value =
            serde_json::from_str(raw.lines().next().expect("audit line")).expect("parse json");
        assert_eq!(
            parsed["auth_subject"].as_str(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(parsed["error_code"].as_str(), Some("invalid_path"));
    }

    #[test]
    fn audit_event_context_applies_auth_subject_to_all_event_builds() {
        let event_ctx = AuditEventContext {
            request_id: "req-1",
            peer: None,
            op: "write",
            auth_subject: Some(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            ),
        };

        let ok_event = event_ctx.build_event(
            AuditRequest {
                workspace_id: "ws".to_string(),
                requested_path: Some("docs/a.txt".to_string()),
                path_prefix: None,
                glob_pattern: None,
                grep_regex: None,
                grep_query_len: None,
            },
            StatusCode::OK,
            None,
        );
        assert_eq!(
            ok_event.auth_subject.as_deref(),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
        );

        let err_event = event_ctx.build_event(
            AuditRequest {
                workspace_id: "ws".to_string(),
                requested_path: None,
                path_prefix: None,
                glob_pattern: None,
                grep_regex: None,
                grep_query_len: None,
            },
            StatusCode::FORBIDDEN,
            Some("not_permitted".to_string()),
        );
        assert_eq!(
            err_event.auth_subject.as_deref(),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(err_event.error_code.as_deref(), Some("not_permitted"));
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

    #[test]
    fn audit_failure_response_is_service_unavailable() {
        let (status, body) = super::super::audit_failure_response(
            super::super::audit::AuditFailure::new("the audit worker stopped"),
        );
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.code, "audit_unavailable");
        assert_eq!(
            body.0.message,
            "required audit logging failed; operation status is unknown and may still have completed"
        );
    }

    #[tokio::test]
    async fn log_audit_event_surfaces_required_audit_failures() {
        let audit = super::super::audit::AuditLogger::broken_required_logger_for_test();

        let err = super::super::log_audit_event(
            &audit,
            super::super::audit::minimal_event("req-1".to_string(), None, "read", 200, None),
        )
        .await
        .expect_err("required audit failure should become a service error");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");
    }

    #[tokio::test]
    async fn log_audit_event_with_permit_keeps_semaphore_slot_until_ack_finishes() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");

        let task = tokio::spawn({
            let audit = audit.clone();
            async move {
                super::super::log_audit_event_with_permit(
                    &audit,
                    super::super::audit::minimal_event(
                        "req-1".to_string(),
                        None,
                        "read",
                        200,
                        None,
                    ),
                    permit,
                    Some(Duration::from_secs(1)),
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("audit logger should block");
        assert!(
            semaphore.clone().try_acquire_owned().is_err(),
            "required audit should keep the originating semaphore slot until ack completes"
        );

        control.release_success();
        task.await.expect("audit task join").expect("audit log");

        let reacquired = semaphore
            .clone()
            .try_acquire_owned()
            .expect("permit should be released once audit finishes");
        drop(reacquired);
    }

    #[tokio::test]
    async fn log_audit_event_with_permit_times_out_and_releases_slot() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");

        let task = tokio::spawn({
            let audit = audit.clone();
            async move {
                super::super::log_audit_event_with_permit(
                    &audit,
                    super::super::audit::minimal_event(
                        "req-timeout".to_string(),
                        None,
                        "write",
                        200,
                        None,
                    ),
                    permit,
                    Some(Duration::from_millis(10)),
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("audit logger should block");
        let err = task
            .await
            .expect("audit timeout task join")
            .expect_err("audit timeout should fail closed");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");
        let permit = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned())
            .await
            .expect("timed-out audit should release the semaphore slot")
            .expect("acquire permit after timed-out audit");
        drop(permit);

        control.release_success();
    }

    #[tokio::test]
    async fn log_audit_event_with_permit_fails_fast_when_required_audit_queue_is_full() {
        let (audit, _control) = super::super::audit::AuditLogger::full_required_logger_for_test();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");

        let err = super::super::log_audit_event_with_permit(
            &audit,
            super::super::audit::minimal_event("req-full".to_string(), None, "write", 200, None),
            permit,
            Some(Duration::from_secs(1)),
        )
        .await
        .expect_err("full required audit queue should fail closed");

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.0.code, "audit_unavailable");
        let permit = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned())
            .await
            .expect("queue-full audit should release the semaphore slot")
            .expect("acquire permit after queue-full audit");
        drop(permit);
    }
}
