use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

pub(super) async fn rate_limit_middleware(
    State(state): State<super::AppState>,
    req: Request,
    next: Next,
) -> Response {
    if !state.inner.rate_limiter.allow(peer_ip(&req)).await {
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
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(ToString::to_string)
        .unwrap_or_else(generate_request_id);

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
    format!("{millis:016x}{seq:016x}")
}
