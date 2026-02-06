use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static MISSING_IP_COUNT: AtomicU64 = AtomicU64::new(0);

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
    let client_ip = peer_ip(&req);
    if client_ip.is_none() {
        let missing = MISSING_IP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if missing == 1 || missing.is_multiple_of(1000) {
            tracing::warn!(
                missing_ip_total = missing,
                "request missing peer ip; rate limit bypassed"
            );
        }
    }

    if !state.inner.rate_limiter.allow(client_ip).await {
        if let Some(audit) = state.inner.audit.as_ref()
            && let Some(op) = super::audit::op_from_path(req.uri().path())
        {
            let request_id = req
                .extensions()
                .get::<RequestId>()
                .map(|value| value.0.clone())
                .unwrap_or_else(generate_request_id);
            audit.log(super::audit::minimal_event(
                request_id,
                client_ip,
                op,
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                Some("rate_limited"),
            ));
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
        .map(ToString::to_string)
        .unwrap_or_else(generate_request_id);

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
        .as_millis() as u64;
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    format!("{pid:08x}{millis:016x}{seq:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
