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
    if redactor.is_path_denied(&descendant_probe) {
        return true;
    }

    for probe in path_redaction_probes(path) {
        if redactor.is_path_denied(&probe) {
            return true;
        }

        let mut descendant_probe = String::with_capacity(probe.len().saturating_add(24));
        descendant_probe.push_str(&probe);
        descendant_probe.push('/');
        descendant_probe.push_str("__db_vfs_audit_probe__");
        if redactor.is_path_denied(&descendant_probe) {
            return true;
        }
    }

    false
}

fn redact_path(redactor: &db_vfs_core::redaction::SecretRedactor, path: &str) -> String {
    if is_path_or_descendant_denied(redactor, path) {
        "<secret>".to_string()
    } else {
        path.to_string()
    }
}

fn redact_path_pair(
    redactor: &db_vfs_core::redaction::SecretRedactor,
    requested_path: &str,
    path: &str,
) -> (String, String) {
    if requested_path == path {
        let redacted = redact_path(redactor, requested_path);
        return (redacted.clone(), redacted);
    }
    (
        redact_path(redactor, requested_path),
        redact_path(redactor, path),
    )
}

fn redact_glob_pattern(redactor: &db_vfs_core::redaction::SecretRedactor, pattern: &str) -> String {
    if is_path_or_descendant_denied(redactor, pattern) {
        return "<secret>".to_string();
    }

    for probe in glob_redaction_probes(pattern) {
        if is_path_or_descendant_denied(redactor, &probe) {
            return "<secret>".to_string();
        }
    }

    pattern.to_string()
}

fn glob_redaction_probes(pattern: &str) -> Vec<String> {
    const MAX_GLOB_PROBES: usize = 64;
    let normalized = db_vfs_core::glob_utils::normalize_glob_pattern_for_matching(pattern);
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut probes = Vec::new();
    let mut active = vec![String::new()];
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        let variants = glob_segment_probe_variants(segment);
        if variants.is_empty() {
            active.clear();
            active.push(String::new());
            continue;
        }

        let mut next = Vec::new();
        for base in &active {
            for variant in &variants {
                let candidate = if base.is_empty() {
                    variant.clone()
                } else {
                    format!("{base}/{variant}")
                };
                push_unique(&mut probes, candidate.clone(), MAX_GLOB_PROBES);
                push_unique(&mut next, candidate, MAX_GLOB_PROBES);
                if probes.len() >= MAX_GLOB_PROBES && next.len() >= MAX_GLOB_PROBES {
                    break;
                }
            }
            if probes.len() >= MAX_GLOB_PROBES && next.len() >= MAX_GLOB_PROBES {
                break;
            }
        }
        active = if next.is_empty() {
            vec![String::new()]
        } else {
            next
        };
        if probes.len() >= MAX_GLOB_PROBES {
            break;
        }
    }

    probes
}

fn path_redaction_probes(path: &str) -> Vec<String> {
    const MAX_PATH_PROBES: usize = 64;

    let normalized = path.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut probes = Vec::new();
    let mut current = String::new();
    for segment in normalized
        .split('/')
        .map(sanitize_path_probe_segment)
        .filter(|segment| !segment.is_empty())
    {
        if segment == "." {
            continue;
        }
        if segment == ".." {
            current.clear();
            continue;
        }

        push_unique(&mut probes, segment.clone(), MAX_PATH_PROBES);
        let joined = if current.is_empty() {
            segment
        } else {
            format!("{current}/{segment}")
        };
        push_unique(&mut probes, joined.clone(), MAX_PATH_PROBES);
        current = joined;
        if probes.len() >= MAX_PATH_PROBES {
            break;
        }
    }

    probes
}

fn sanitize_path_probe_segment(segment: &str) -> String {
    segment
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .collect()
}

fn glob_segment_probe_variants(segment: &str) -> Vec<String> {
    const MAX_SEGMENT_VARIANTS: usize = 16;
    let expanded = expand_brace_variants(segment, MAX_SEGMENT_VARIANTS)
        .unwrap_or_else(|| vec![segment.to_string()]);
    let mut probes = Vec::new();
    for variant in expanded {
        for probe in sanitize_glob_probe_variant(&variant) {
            push_unique(&mut probes, probe, MAX_SEGMENT_VARIANTS);
        }
    }
    probes
}

fn expand_brace_variants(segment: &str, limit: usize) -> Option<Vec<String>> {
    let Some(open) = segment.find('{') else {
        return Some(vec![segment.to_string()]);
    };

    let mut depth = 0usize;
    let mut close = None;
    let mut split_points = Vec::new();
    for (idx, ch) in segment[open..].char_indices() {
        let absolute = open + idx;
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(absolute);
                    break;
                }
            }
            ',' if depth == 1 => split_points.push(absolute),
            _ => {}
        }
    }
    let close = close?;

    let prefix = &segment[..open];
    let suffix = &segment[close + 1..];
    let mut start = open + 1;
    let mut arms = Vec::new();
    for split in split_points {
        arms.push(&segment[start..split]);
        start = split + 1;
    }
    arms.push(&segment[start..close]);

    let mut expanded = Vec::new();
    for arm in arms {
        let nested = format!("{prefix}{arm}{suffix}");
        for variant in expand_brace_variants(&nested, limit)? {
            push_unique(&mut expanded, variant, limit);
        }
        if expanded.len() >= limit {
            break;
        }
    }
    Some(expanded)
}

fn sanitize_glob_probe_variant(segment: &str) -> Vec<String> {
    let mut collapsed = String::with_capacity(segment.len());
    for ch in segment.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '!') {
            continue;
        }
        collapsed.push(ch);
    }

    let collapsed = collapsed.trim_matches('/').to_string();
    if collapsed.is_empty() {
        return Vec::new();
    }

    let mut probes = vec![collapsed.clone()];
    let trimmed = collapsed.trim_end_matches(['.', '-', '_']);
    if !trimmed.is_empty() && trimmed != collapsed {
        probes.push(trimmed.to_string());
    }
    probes
}

fn push_unique(values: &mut Vec<String>, candidate: String, limit: usize) {
    if values.len() >= limit || values.iter().any(|value| value == &candidate) {
        return;
    }
    values.push(candidate);
}

fn audit_event_base(
    request_id: String,
    peer: Option<SocketAddr>,
    op: &'static str,
    workspace_id: String,
    status: u16,
    error_code: Option<String>,
) -> AuditEvent {
    AuditEvent {
        ts_ms: now_ms(),
        request_id,
        peer_ip: peer.map(|addr| addr.ip().to_string()),
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

async fn acquire_permit_with_budget(
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

async fn acquire_permit_then_parse_json<Req, S>(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: Option<Duration>,
    request: Request,
    state: &S,
) -> Result<
    (tokio::sync::OwnedSemaphorePermit, Option<Duration>, Req),
    (StatusCode, Json<super::ErrorBody>),
>
where
    Req: DeserializeOwned,
    S: Send + Sync,
{
    let (permit, remaining) = acquire_permit_with_budget(semaphore, budget).await?;
    let req = parse_json_payload::<Req, S>(request, state)
        .await
        .map_err(map_json_rejection)?;
    Ok((permit, remaining, req))
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
                redact_path_pair(&state.inner.redactor, &requested_path, &path);
            event.requested_path = Some(requested_path);
            event.path = Some(path);
        }
        (Some(requested_path), None) => {
            event.requested_path = Some(redact_path(&state.inner.redactor, &requested_path));
        }
        (None, Some(path)) => {
            event.path = Some(redact_path(&state.inner.redactor, &path));
        }
        (None, None) => {}
    }
    if body.code == "secret_path_denied" {
        event.requested_path = Some("<secret>".to_string());
        event.path = Some("<secret>".to_string());
    }
}

fn audit_ok_read(state: &super::AppState, event: &mut AuditEvent, resp: &ReadResponse) {
    let (requested_path, path) =
        redact_path_pair(&state.inner.redactor, &resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_read = Some(resp.bytes_read);
    event.version = Some(resp.version);
}

fn audit_ok_write(state: &super::AppState, event: &mut AuditEvent, resp: &WriteResponse) {
    let (requested_path, path) =
        redact_path_pair(&state.inner.redactor, &resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.created = Some(resp.created);
    event.version = Some(resp.version);
}

fn audit_ok_patch(state: &super::AppState, event: &mut AuditEvent, resp: &PatchResponse) {
    let (requested_path, path) =
        redact_path_pair(&state.inner.redactor, &resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.bytes_written = Some(resp.bytes_written);
    event.version = Some(resp.version);
}

fn audit_ok_delete(state: &super::AppState, event: &mut AuditEvent, resp: &DeleteResponse) {
    let (requested_path, path) =
        redact_path_pair(&state.inner.redactor, &resp.requested_path, &resp.path);
    event.requested_path = Some(requested_path);
    event.path = Some(path);
    event.deleted = Some(resp.deleted);
}

fn audit_redact_scan_fields(state: &super::AppState, event: &mut AuditEvent) {
    if let Some(prefix) = event.path_prefix.take() {
        event.path_prefix = Some(redact_path(&state.inner.redactor, &prefix));
    }
    if let Some(pattern) = event.glob_pattern.take() {
        event.glob_pattern = Some(redact_glob_pattern(&state.inner.redactor, &pattern));
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
    peer: Option<SocketAddr>,
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
    let VfsLimits { semaphore, budget } = limits;
    let AuditHooks {
        ok: audit_ok,
        err: audit_err,
    } = hooks;

    let (permit, remaining, req) =
        match acquire_permit_then_parse_json::<Req, _>(semaphore, budget, request, &state).await {
            Ok(value) => value,
            Err((status, Json(body))) => {
                if let Some(audit) = state.inner.audit.as_ref() {
                    let audit_req = AuditRequest {
                        workspace_id: super::audit::UNKNOWN_WORKSPACE_ID.to_string(),
                        requested_path: None,
                        path_prefix: None,
                        glob_pattern: None,
                        grep_regex: None,
                        grep_query_len: None,
                    };
                    let event = audit_req.into_event(
                        request_id,
                        peer,
                        op,
                        status,
                        Some(body.code.to_string()),
                    );
                    super::log_audit_event(audit, event).await?;
                }
                return Err((status, Json(body)));
            }
        };
    let audit_req = build_audit_req(&req);

    if let Err(err) = db_vfs_core::path::validate_workspace_id(req.workspace_id()) {
        let (status, Json(body)) = super::map_err(err);
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event =
                audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
            audit_err(&state, &mut event, &body);
            super::log_audit_event(audit, event).await?;
        }
        return Err((status, Json(body)));
    }
    if !super::auth::workspace_allowed(&auth.allowed_workspaces, req.workspace_id()) {
        let (status, Json(body)) = super::err(
            StatusCode::FORBIDDEN,
            super::CODE_NOT_PERMITTED,
            "workspace is not allowed for this token",
        );
        if let Some(audit) = state.inner.audit.as_ref() {
            let mut event =
                audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
            audit_err(&state, &mut event, &body);
            super::log_audit_event(audit, event).await?;
        }
        return Err((status, Json(body)));
    }

    let state_for_run = state.clone();
    let started = Instant::now();
    let result =
        super::runner::run_vfs(state_for_run, permit, remaining, move |vfs| run(vfs, req)).await;

    match (result, request_id, audit_req) {
        (Ok((Ok(resp), permit)), request_id, audit_req) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event = audit_req.into_event(request_id, peer, op, StatusCode::OK, None);
                audit_ok(&state, &mut event, &resp);
                let audit_budget = remaining.map(|budget| budget.saturating_sub(started.elapsed()));
                super::log_audit_event_with_permit(audit, event, permit, audit_budget).await?;
            } else {
                drop(permit);
            }
            Ok(Json(resp))
        }
        (Ok((Err(err), permit)), request_id, audit_req) => {
            let (status, Json(body)) = super::map_err(err);
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event =
                    audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
                audit_err(&state, &mut event, &body);
                let audit_budget = remaining.map(|budget| budget.saturating_sub(started.elapsed()));
                super::log_audit_event_with_permit(audit, event, permit, audit_budget).await?;
            } else {
                drop(permit);
            }
            Err((status, Json(body)))
        }
        (Err((status, Json(body))), request_id, audit_req) => {
            if let Some(audit) = state.inner.audit.as_ref() {
                let mut event =
                    audit_req.into_event(request_id, peer, op, status, Some(body.code.to_string()));
                audit_err(&state, &mut event, &body);
                super::log_audit_event(audit, event).await?;
            }
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
        acquire_permit_then_parse_json, acquire_permit_with_budget, audit_preview,
        glob_redaction_probes, path_redaction_probes, redact_glob_pattern, redact_path,
        redact_path_pair,
    };
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use db_vfs::vfs::WriteRequest;
    use db_vfs_core::policy::SecretRules;
    use db_vfs_core::redaction::SecretRedactor;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn redact_path_hides_denied_prefix_root_paths() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");

        assert_eq!(redact_path(&redactor, ".git"), "<secret>");
        assert_eq!(redact_path(&redactor, ".git/"), "<secret>");
        assert_eq!(redact_path(&redactor, ".git"), "<secret>");
        assert_eq!(redact_glob_pattern(&redactor, ".git"), "<secret>");
        assert_eq!(redact_glob_pattern(&redactor, ".env*"), "<secret>");
        assert_eq!(redact_glob_pattern(&redactor, "docs/**/.env*"), "<secret>");
        assert_eq!(redact_glob_pattern(&redactor, ".{envrc,netrc}"), "<secret>");
        assert_eq!(
            redact_glob_pattern(&redactor, "**/{.envrc,.netrc}"),
            "<secret>"
        );
        assert_eq!(redact_glob_pattern(&redactor, "docs/*.txt"), "docs/*.txt");
        assert_eq!(
            redact_glob_pattern(&redactor, "docs/{readme,license}.md"),
            "docs/{readme,license}.md"
        );
        assert_eq!(redact_path(&redactor, "docs"), "docs");
    }

    #[test]
    fn glob_redaction_probes_expand_brace_literals_without_collapsing_them_together() {
        let probes = glob_redaction_probes(".{envrc,netrc}");
        assert!(probes.iter().any(|probe| probe == ".envrc"));
        assert!(probes.iter().any(|probe| probe == ".netrc"));
        assert!(!probes.iter().any(|probe| probe.contains(".envrcnetrc")));

        let probes = glob_redaction_probes("**/{.envrc,.netrc}");
        assert!(probes.iter().any(|probe| probe == ".envrc"));
        assert!(probes.iter().any(|probe| probe == ".netrc"));
    }

    #[test]
    fn redact_path_pair_matches_single_field_redaction_behavior() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");
        let (requested_path, path) = redact_path_pair(&redactor, ".git", ".git");
        assert_eq!(requested_path, "<secret>");
        assert_eq!(path, "<secret>");

        let (requested_path, path) = redact_path_pair(&redactor, "docs/a.txt", "docs/a.txt");
        assert_eq!(requested_path, "docs/a.txt");
        assert_eq!(path, "docs/a.txt");
    }

    #[test]
    fn redact_path_hides_secretish_malformed_paths() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");

        assert_eq!(redact_path(&redactor, ".env/../visible.txt"), "<secret>");
        assert_eq!(
            redact_path(&redactor, "docs/.git/\u{0000}config"),
            "<secret>"
        );
        assert_eq!(
            redact_path(&redactor, "docs/../visible.txt"),
            "docs/../visible.txt"
        );
    }

    #[test]
    fn path_redaction_probes_keep_secret_segments_from_malformed_paths() {
        let probes = path_redaction_probes(".env/../visible.txt");
        assert!(probes.iter().any(|probe| probe == ".env"));
        assert!(probes.iter().any(|probe| probe == "visible.txt"));

        let probes = path_redaction_probes("docs/.git/\u{0000}config");
        assert!(probes.iter().any(|probe| probe == ".git"));
        assert!(probes.iter().any(|probe| probe == "docs/.git"));
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

    #[tokio::test]
    async fn acquire_permit_preserves_large_budget_when_slot_is_available() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (_permit, remaining) = acquire_permit_with_budget(semaphore, Some(Duration::MAX))
            .await
            .expect("large budget should not block immediate acquisition");
        assert_eq!(remaining, Some(Duration::MAX));
    }

    #[tokio::test]
    async fn acquire_permit_returns_busy_when_all_slots_are_in_use() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let held_permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("acquire initial permit");

        let (status, body) = acquire_permit_with_budget(semaphore, Some(Duration::from_millis(10)))
            .await
            .expect_err("saturated semaphore should return busy");
        drop(held_permit);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.code, "busy");
    }

    #[tokio::test]
    async fn acquire_permit_then_parse_json_returns_busy_before_invalid_json() {
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
            acquire_permit_then_parse_json::<WriteRequest, _>(semaphore, None, request, &())
                .await
                .expect_err("saturated semaphore should short-circuit before JSON parsing");
        drop(held_permit);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0.code, "busy");
    }

    #[tokio::test]
    async fn acquire_permit_then_parse_json_surfaces_json_errors_after_permit() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/write")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .expect("request");

        let (status, body) = acquire_permit_then_parse_json::<WriteRequest, _>(
            Arc::new(tokio::sync::Semaphore::new(1)),
            None,
            request,
            &(),
        )
        .await
        .expect_err("invalid JSON should still be reported once a permit is held");

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0.code, "invalid_json_syntax");
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
    async fn log_audit_event_with_permit_times_out_without_releasing_slot_early() {
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
                    Some(Duration::from_millis(250)),
                )
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
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
        assert!(
            semaphore.clone().try_acquire_owned().is_err(),
            "timed-out audit should keep the semaphore slot until the worker actually unwinds"
        );

        control.release_success();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                    drop(permit);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("permit should be released after delayed audit completion");
    }
}
