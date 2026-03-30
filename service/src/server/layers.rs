use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static MISSING_IP_COUNT: AtomicU64 = AtomicU64::new(0);
const FALLBACK_RATE_LIMIT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

#[derive(Clone, Debug)]
pub(super) struct RequestId(pub String);

fn peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(super) async fn rate_limit_middleware(
    State(state): State<super::AppState>,
    req: Request,
    next: Next,
) -> Response {
    let peer_ip = peer_ip(&req);
    let limiter_ip = match peer_ip {
        Some(ip) => Some(ip),
        None => Some(FALLBACK_RATE_LIMIT_IP),
    };
    if peer_ip.is_none() {
        let missing = MISSING_IP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if missing == 1 || missing.is_multiple_of(1000) {
            tracing::warn!(
                missing_ip_total = missing,
                fallback_ip = %FALLBACK_RATE_LIMIT_IP,
                "request missing peer ip; applying shared fallback rate-limit bucket"
            );
        }
    }

    if !state.inner.rate_limiter.allow(limiter_ip).await {
        if let Some(audit) = state.inner.audit.as_ref()
            && let Some(op) = super::audit::op_from_path(req.uri().path())
        {
            let request_id = req
                .extensions()
                .get::<RequestId>()
                .map_or_else(generate_request_id, |value| value.0.clone());
            let event = super::audit::minimal_event(
                request_id,
                peer_ip,
                op,
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                Some("rate_limited"),
            );
            match super::try_acquire_required_audit_gate_for_path(&state, req.uri().path()).await {
                Ok(Some(super::RequiredAuditGate { permit, budget })) => {
                    if let Err((status, body)) =
                        super::log_audit_event_with_permit(audit, event, permit, budget).await
                    {
                        return (status, body).into_response();
                    }
                }
                Ok(None) => {
                    if let Err((status, body)) = super::log_audit_event(audit, event).await {
                        return (status, body).into_response();
                    }
                }
                Err((status, body)) => {
                    return (status, body).into_response();
                }
            }
        }
        return super::err_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        );
    }

    next.run(req).await
}

pub(super) async fn request_id_middleware(req: Request, next: Next) -> Response {
    let header_name = HeaderName::from_static("x-request-id");
    let request_id = req
        .headers()
        .get(&header_name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| is_valid_request_id(value))
        .map_or_else(generate_request_id, ToString::to_string);

    let mut req = req;
    req.extensions_mut().insert(RequestId(request_id.clone()));

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
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    format!("{pid:08x}{millis:016x}{seq:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::post;
    use db_vfs_core::policy::{AuditPolicy, Limits, VfsPolicy};
    use std::time::Duration;
    use tower::ServiceExt;

    #[test]
    fn request_id_validation_accepts_whitelisted_characters() {
        assert!(is_valid_request_id("abcDEF0123-_"));
        assert!(is_valid_request_id(&"a".repeat(128)));
    }

    #[test]
    fn request_id_validation_rejects_empty_too_long_and_invalid_chars() {
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id(&"a".repeat(129)));
        assert!(!is_valid_request_id("contains space"));
        assert!(!is_valid_request_id("contains/slash"));
        assert!(!is_valid_request_id("contains.dot"));
    }

    #[test]
    fn generated_request_id_has_expected_shape_and_uniqueness() {
        let first = generate_request_id();
        let second = generate_request_id();

        assert_eq!(first.len(), 40);
        assert_eq!(second.len(), 40);
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(second.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn rate_limit_middleware_keeps_io_permit_while_required_audit_blocks() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();
        let policy = VfsPolicy {
            limits: Limits {
                max_requests_per_ip_per_sec: 1,
                max_requests_burst_per_ip: 1,
                max_rate_limit_ips: 16,
                ..Limits::default()
            },
            audit: AuditPolicy {
                required: true,
                ..AuditPolicy::default()
            },
            ..VfsPolicy::default()
        };
        let state = super::super::test_state_with_policy_and_audit(policy, Some(audit));

        let app = Router::new()
            .route("/v1/read", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::rate_limit_middleware,
            ))
            .with_state(state.clone());

        let first = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/read")
            .body(Body::empty())
            .expect("first request");
        let first_resp = app.clone().oneshot(first).await.expect("first response");
        assert_eq!(first_resp.status(), StatusCode::OK);

        let second = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/read")
            .body(Body::empty())
            .expect("second request");
        let task = tokio::spawn(async move { app.oneshot(second).await.expect("second response") });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("required audit should block rate-limited response");

        assert!(
            state
                .inner
                .io_concurrency
                .clone()
                .try_acquire_owned()
                .is_err(),
            "rate-limited required-audit path should hold the IO permit until audit wait ends"
        );

        control.release_success();
        let resp = task.await.expect("join rate-limited task");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
