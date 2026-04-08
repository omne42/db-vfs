#![cfg(any(feature = "sqlite", feature = "postgres"))]

use std::net::{Ipv4Addr, SocketAddr};
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use std::sync::OnceLock;
#[cfg(feature = "sqlite")]
use std::time::Duration;
#[cfg(feature = "postgres")]
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
#[cfg(feature = "sqlite")]
use axum::body::Bytes;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{Permissions, SecretRules, TraversalRules};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
#[cfg(feature = "sqlite")]
use tokio::sync::mpsc;
#[cfg(feature = "sqlite")]
use tokio_stream::wrappers::ReceiverStream;
use tower::ServiceExt;

use db_vfs_service::policy::{AuditPolicy, AuthPolicy, AuthToken, ServiceLimits, ServicePolicy};

const DEV_TOKEN: &str = "dev-token";

#[cfg(feature = "postgres")]
fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}_{}", std::process::id(), nanos)
}

#[derive(serde::Deserialize)]
struct WriteBody {
    path: String,
    version: u64,
}

#[derive(serde::Deserialize)]
struct ReadBody {
    content: String,
    version: u64,
}

#[cfg(feature = "sqlite")]
#[derive(serde::Deserialize)]
struct GrepMatchBody {
    path: String,
    line: u64,
    text: String,
    line_truncated: bool,
}

#[cfg(feature = "sqlite")]
#[derive(serde::Deserialize)]
struct GrepBody {
    matches: Vec<GrepMatchBody>,
}

#[cfg(feature = "sqlite")]
#[derive(serde::Deserialize)]
struct GlobBody {
    matches: Vec<String>,
    truncated: bool,
    scanned_files: u64,
    scanned_entries: u64,
}

#[cfg(feature = "sqlite")]
#[derive(serde::Deserialize)]
struct ErrorBody {
    code: String,
}

#[cfg(feature = "sqlite")]
#[derive(serde::Deserialize)]
struct DeleteBody {
    deleted: bool,
}

struct TestServer {
    app: Option<Router>,
    peer_addr: SocketAddr,
    #[cfg(feature = "sqlite")]
    _db: Option<tempfile::NamedTempFile>,
}

impl TestServer {
    #[cfg(feature = "sqlite")]
    fn sqlite(app: Router, db: tempfile::NamedTempFile) -> Self {
        Self {
            app: Some(app),
            peer_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 31337)),
            _db: Some(db),
        }
    }

    #[cfg(feature = "postgres")]
    fn postgres(app: Router) -> Self {
        Self {
            app: Some(app),
            peer_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 31337)),
            #[cfg(feature = "sqlite")]
            _db: None,
        }
    }

    async fn send(&self, mut req: Request<Body>) -> Response {
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(self.peer_addr));
        self.app
            .as_ref()
            .expect("router")
            .clone()
            .oneshot(req)
            .await
            .expect("response")
    }

    #[cfg(feature = "sqlite")]
    async fn send_without_connect_info(&self, req: Request<Body>) -> Response {
        self.app
            .as_ref()
            .expect("router")
            .clone()
            .oneshot(req)
            .await
            .expect("response")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let Some(app) = self.app.take() else {
            return;
        };
        std::thread::spawn(move || drop(app))
            .join()
            .expect("drop test router on helper thread");
    }
}

fn dev_token_sha256() -> String {
    let digest = Sha256::digest(DEV_TOKEN.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn policy_allow_all() -> ServicePolicy {
    ServicePolicy {
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            write: true,
            patch: true,
            delete: true,
            allow_full_scan: false,
        },
        limits: ServiceLimits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        audit: AuditPolicy::default(),
        auth: AuthPolicy {
            tokens: vec![AuthToken {
                token: Some(dev_token_sha256()),
                token_env_var: None,
                allowed_workspaces: vec!["ws".to_string()],
            }],
        },
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn test_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
struct BackendWholeContentGuard {
    previous: Option<std::ffi::OsString>,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl BackendWholeContentGuard {
    fn install(limit: u64) -> Self {
        let previous = std::env::var_os("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES");
        // SAFETY: callers hold the process-wide test env mutex while this guard lives.
        unsafe {
            std::env::set_var(
                "DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES",
                limit.to_string(),
            );
        }
        Self { previous }
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl Drop for BackendWholeContentGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => {
                // SAFETY: callers hold the process-wide test env mutex while this guard lives.
                unsafe {
                    std::env::set_var("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES", previous);
                }
            }
            None => {
                // SAFETY: callers hold the process-wide test env mutex while this guard lives.
                unsafe {
                    std::env::remove_var("DB_VFS_TEST_BACKEND_WHOLE_CONTENT_MAX_BYTES");
                }
            }
        }
    }
}

fn json_request<T: Serialize>(uri: &str, body: &T) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize request json"),
        ))
        .expect("request")
}

#[cfg(feature = "sqlite")]
fn raw_request(uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.into())
        .expect("request")
}

fn bearer_request<T: Serialize>(uri: &str, body: &T) -> Request<Body> {
    let mut req = json_request(uri, body);
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {DEV_TOKEN}")
            .parse()
            .expect("authorization header"),
    );
    req
}

#[cfg(feature = "sqlite")]
fn bearer_raw_request(uri: &str, body: impl Into<Body>) -> Request<Body> {
    let mut req = raw_request(uri, body);
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {DEV_TOKEN}")
            .parse()
            .expect("authorization header"),
    );
    req
}

async fn json_body<T: DeserializeOwned>(resp: Response) -> T {
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice::<T>(&body).expect("response json")
}

async fn expect_json<T: DeserializeOwned>(resp: Response, status: StatusCode) -> T {
    assert_eq!(resp.status(), status);
    json_body(resp).await
}

#[cfg(feature = "sqlite")]
fn delayed_body(delay: Duration, payload: &'static str) -> Body {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = tx.send(Ok(Bytes::from_static(payload.as_bytes()))).await;
    });
    Body::from_stream(ReceiverStream::new(rx))
}

#[cfg(feature = "sqlite")]
async fn setup() -> TestServer {
    setup_with_policy(policy_allow_all()).await
}

#[cfg(feature = "sqlite")]
async fn setup_with_policy(policy: ServicePolicy) -> TestServer {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(
        db.path().to_path_buf(),
        policy,
        db_vfs_service::TrustMode::Trusted,
        false,
    )
    .expect("build app");
    TestServer::sqlite(app, db)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn embedded_router_write_works_without_connect_info() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(
        db.path().to_path_buf(),
        policy_allow_all(),
        db_vfs_service::TrustMode::Trusted,
        true,
    )
    .expect("build app");
    let server = TestServer::sqlite(app, db);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/write")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"workspace_id":"ws","path":"docs/a.txt","content":"hello\n","expected_version":null}"#,
        ))
        .expect("request");

    let resp = server.send_without_connect_info(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-request-id"));

    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let write = serde_json::from_slice::<WriteBody>(&body).expect("write json");
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.version, 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn workspace_id_with_wildcard_is_rejected() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(
        db.path().to_path_buf(),
        policy_allow_all(),
        db_vfs_service::TrustMode::Trusted,
        true,
    )
    .expect("build app");

    let req = Request::builder()
        .method("POST")
        .uri("/v1/write")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"workspace_id":"team-*","path":"docs/a.txt","content":"hello\n","expected_version":null}"#,
        ))
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let err = serde_json::from_slice::<ErrorBody>(&body).expect("error json");
    assert_eq!(err.code, "invalid_path");
}

#[cfg(feature = "postgres")]
fn postgres_test_url() -> Option<String> {
    let raw = match std::env::var("DB_VFS_TEST_POSTGRES_URL") {
        Ok(raw) => raw,
        Err(_) => return None,
    };
    let url = raw.trim().to_string();
    if url.is_empty() {
        return None;
    }
    Some(url)
}

#[cfg(feature = "postgres")]
async fn setup_postgres() -> Option<TestServer> {
    let Some(url) = postgres_test_url() else {
        eprintln!("skipping postgres http_smoke test: DB_VFS_TEST_POSTGRES_URL unset");
        return None;
    };
    let app = tokio::task::spawn_blocking(move || {
        db_vfs_service::server::build_app_postgres(
            url,
            policy_allow_all(),
            db_vfs_service::TrustMode::Trusted,
            false,
        )
    })
    .await
    .expect("join postgres app builder")
    .expect("build postgres app");
    Some(TestServer::postgres(app))
}

#[cfg(feature = "sqlite")]
fn is_generated_request_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn write_then_read() {
    let server = setup().await;

    let write = expect_json::<WriteBody>(
        server
            .send(bearer_request(
                "/v1/write",
                &WriteRequest {
                    workspace_id: "ws".to_string(),
                    path: "docs/a.txt".to_string(),
                    content: "hello\n".to_string(),
                    expected_version: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.version, 1);

    let read = expect_json::<ReadBody>(
        server
            .send(bearer_request(
                "/v1/read",
                &ReadRequest {
                    workspace_id: "ws".to_string(),
                    path: "docs/a.txt".to_string(),
                    start_line: None,
                    end_line: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read.content, "hello\n");
    assert_eq!(read.version, 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn write_then_read_line_range() {
    let _env_guard = test_env_lock().lock().await;
    let max_read_bytes = 12u64;
    let _whole_content_guard = BackendWholeContentGuard::install(max_read_bytes);

    let mut policy = policy_allow_all();
    policy.limits.max_read_bytes = max_read_bytes;
    let server = setup_with_policy(policy).await;

    let write_resp = server
        .send(bearer_request(
            "/v1/write",
            &WriteRequest {
                workspace_id: "ws".to_string(),
                path: "docs/range.txt".to_string(),
                content: "line-0001\nline-0002\nline-0003\nline-0004\n".to_string(),
                expected_version: None,
            },
        ))
        .await;
    assert_eq!(write_resp.status(), StatusCode::OK);

    let read = expect_json::<ReadBody>(
        server
            .send(bearer_request(
                "/v1/read",
                &ReadRequest {
                    workspace_id: "ws".to_string(),
                    path: "docs/range.txt".to_string(),
                    start_line: Some(2),
                    end_line: Some(2),
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read.content, "line-0002\n");
    assert_eq!(read.version, 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn auth_is_checked_before_json_body_is_parsed() {
    let server = setup().await;

    let resp = server.send(raw_request("/v1/write", "{")).await;

    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = json_body::<ErrorBody>(resp).await;
    assert_eq!(body.code, "unauthorized");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn request_id_header_roundtrip_and_sanitization() {
    let server = setup().await;

    let valid_request_id = "client_req-123_ABC";
    let mut valid_req = raw_request("/v1/write", "{");
    valid_req.headers_mut().insert(
        "x-request-id",
        valid_request_id.parse().expect("valid request-id"),
    );
    let valid_resp = server.send(valid_req).await;
    assert_eq!(valid_resp.status(), 401);
    let echoed = valid_resp
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("echoed x-request-id");
    assert_eq!(echoed, valid_request_id);

    let mut invalid_req = raw_request("/v1/write", "{");
    invalid_req.headers_mut().insert(
        "x-request-id",
        "bad id !".parse().expect("invalid request-id header"),
    );
    let invalid_resp = server.send(invalid_req).await;
    assert_eq!(invalid_resp.status(), 401);
    let generated = invalid_resp
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("generated x-request-id");
    assert!(is_generated_request_id(generated));
    assert_ne!(generated, "bad id !");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn invalid_json_returns_json_error_body() {
    let server = setup().await;

    let resp = server.send(bearer_raw_request("/v1/write", "{")).await;

    assert_eq!(resp.status(), 400);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = json_body::<ErrorBody>(resp).await;
    assert_eq!(body.code, "invalid_json_syntax");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn escaped_write_body_is_accepted_when_decoded_content_fits_policy_limit() {
    let mut policy = policy_allow_all();
    policy.limits.max_read_bytes = 1024;
    policy.limits.max_write_bytes = 20_000;
    policy.limits.max_patch_bytes = Some(1024);
    let server = setup_with_policy(policy).await;

    let content = "\0".repeat(20_000);
    let raw = serde_json::json!({
        "workspace_id": "ws",
        "path": "docs/escaped.txt",
        "content": content,
        "expected_version": null
    })
    .to_string();
    let legacy_limit = 20_000usize + 64 * 1024;
    assert!(
        raw.len() > legacy_limit,
        "escaped payload should exceed the pre-fix body limit to prove the regression"
    );

    let resp = server.send(bearer_raw_request("/v1/write", raw)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body::<WriteBody>(resp).await;
    assert_eq!(body.path, "docs/escaped.txt");
    assert_eq!(body.version, 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn missing_content_type_returns_json_error_body() {
    let server = setup().await;

    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/write")
        .body(Body::from("{}"))
        .expect("request");
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {DEV_TOKEN}")
            .parse()
            .expect("authorization header"),
    );
    let resp = server.send(req).await;

    assert_eq!(resp.status(), 415);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = json_body::<ErrorBody>(resp).await;
    assert_eq!(body.code, "unsupported_media_type");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn slow_request_body_times_out_before_json_decode() {
    let mut policy = policy_allow_all();
    policy.limits.max_io_ms = 1_000;
    let server = setup_with_policy(policy).await;

    let resp = server
        .send(bearer_raw_request(
            "/v1/write",
            delayed_body(
                Duration::from_millis(1_250),
                r#"{"workspace_id":"ws","path":"docs/a.txt","content":"hello\n","expected_version":null}"#,
            ),
        ))
        .await;
    let body = expect_json::<ErrorBody>(resp, StatusCode::REQUEST_TIMEOUT).await;
    assert_eq!(body.code, "timeout");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn slow_body_holds_io_permit_and_second_io_request_fails_fast_with_busy() {
    let mut policy = policy_allow_all();
    policy.limits.max_concurrency_io = 1;
    policy.limits.max_io_ms = 2_000;
    let server = setup_with_policy(policy).await;

    let slow_write = tokio::spawn({
        let server = TestServer {
            app: server.app.clone(),
            peer_addr: server.peer_addr,
            _db: None,
        };
        async move {
            server
                .send(bearer_raw_request(
                    "/v1/write",
                    delayed_body(
                        Duration::from_millis(300),
                        r#"{"workspace_id":"ws","path":"docs/slow.txt","content":"hello\n","expected_version":null}"#,
                    ),
                ))
                .await
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let busy = expect_json::<ErrorBody>(
        server
            .send(bearer_request(
                "/v1/write",
                &WriteRequest {
                    workspace_id: "ws".to_string(),
                    path: "docs/fast.txt".to_string(),
                    content: "fast\n".to_string(),
                    expected_version: None,
                },
            ))
            .await,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(busy.code, "busy");

    let slow =
        expect_json::<WriteBody>(slow_write.await.expect("join slow write"), StatusCode::OK).await;
    assert_eq!(slow.path, "docs/slow.txt");
    assert_eq!(slow.version, 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn read_and_grep_treat_cr_and_crlf_as_line_boundaries() {
    let _env_guard = test_env_lock().lock().await;
    let server = setup().await;

    let write_resp = server
        .send(bearer_request(
            "/v1/write",
            &WriteRequest {
                workspace_id: "ws".to_string(),
                path: "docs/crlf.txt".to_string(),
                content: "alpha\rbeta\r\ngamma\n".to_string(),
                expected_version: None,
            },
        ))
        .await;
    assert_eq!(write_resp.status(), StatusCode::OK);

    let read = expect_json::<ReadBody>(
        server
            .send(bearer_request(
                "/v1/read",
                &ReadRequest {
                    workspace_id: "ws".to_string(),
                    path: "docs/crlf.txt".to_string(),
                    start_line: Some(2),
                    end_line: Some(3),
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read.content, "beta\r\ngamma\n");
    assert_eq!(read.version, 1);

    let grep = expect_json::<GrepBody>(
        server
            .send(bearer_request(
                "/v1/grep",
                &db_vfs::vfs::GrepRequest {
                    workspace_id: "ws".to_string(),
                    query: "beta".to_string(),
                    regex: false,
                    glob: None,
                    path_prefix: Some("docs/".to_string()),
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(grep.matches.len(), 1);
    assert_eq!(grep.matches[0].path, "docs/crlf.txt");
    assert_eq!(grep.matches[0].line, 2);
    assert_eq!(grep.matches[0].text, "beta");
    assert!(!grep.matches[0].line_truncated);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn glob_and_grep_routes_scan_the_expected_scope() {
    let _env_guard = test_env_lock().lock().await;
    let server = setup().await;

    for (path, content) in [
        ("docs/a.txt", "alpha\nneedle\n"),
        ("docs/b.txt", "beta\n"),
        ("logs/c.txt", "needle\n"),
    ] {
        let write = server
            .send(bearer_request(
                "/v1/write",
                &WriteRequest {
                    workspace_id: "ws".to_string(),
                    path: path.to_string(),
                    content: content.to_string(),
                    expected_version: None,
                },
            ))
            .await;
        assert_eq!(write.status(), StatusCode::OK, "write failed for {path}");
    }

    let glob = expect_json::<GlobBody>(
        server
            .send(bearer_request(
                "/v1/glob",
                &db_vfs::vfs::GlobRequest {
                    workspace_id: "ws".to_string(),
                    pattern: "docs/*.txt".to_string(),
                    path_prefix: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(glob.matches, vec!["docs/a.txt", "docs/b.txt"]);
    assert!(!glob.truncated);
    assert_eq!(glob.scanned_files, 2);
    assert_eq!(glob.scanned_entries, 2);

    let grep = expect_json::<GrepBody>(
        server
            .send(bearer_request(
                "/v1/grep",
                &db_vfs::vfs::GrepRequest {
                    workspace_id: "ws".to_string(),
                    query: "needle".to_string(),
                    regex: false,
                    glob: Some("docs/*.txt".to_string()),
                    path_prefix: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(grep.matches.len(), 1);
    assert_eq!(grep.matches[0].path, "docs/a.txt");
    assert_eq!(grep.matches[0].line, 2);
    assert_eq!(grep.matches[0].text, "needle");
    assert!(!grep.matches[0].line_truncated);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn unknown_request_fields_are_rejected_as_invalid_json_schema() {
    let server = setup().await;

    let resp = server
        .send(bearer_raw_request(
            "/v1/write",
            r#"{"workspace_id":"ws","path":"docs/a.txt","content":"hello","unexpected":true}"#,
        ))
        .await;

    let body = expect_json::<ErrorBody>(resp, StatusCode::BAD_REQUEST).await;
    assert_eq!(body.code, "invalid_json_schema");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn workspace_allowlist_rejections_return_not_permitted_code() {
    let server = setup().await;

    let resp = server
        .send(bearer_request(
            "/v1/write",
            &WriteRequest {
                workspace_id: "other".to_string(),
                path: "docs/a.txt".to_string(),
                content: "hello\n".to_string(),
                expected_version: None,
            },
        ))
        .await;

    let body = expect_json::<ErrorBody>(resp, StatusCode::FORBIDDEN).await;
    assert_eq!(body.code, "not_permitted");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn rate_limited_requests_return_rate_limited_code() {
    let mut policy = policy_allow_all();
    policy.limits.max_requests_per_ip_per_sec = 1;
    policy.limits.max_requests_burst_per_ip = 1;
    policy.limits.max_rate_limit_ips = 16;
    let server = setup_with_policy(policy).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let first = server.send(bearer_raw_request("/v1/read", "{}")).await;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = server.send(bearer_raw_request("/v1/read", "{}")).await;
    let body = expect_json::<ErrorBody>(second, StatusCode::TOO_MANY_REQUESTS).await;
    assert_eq!(body.code, "rate_limited");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn delete_ignore_missing_returns_deleted_false() {
    let server = setup().await;

    let resp = expect_json::<DeleteBody>(
        server
            .send(bearer_raw_request(
                "/v1/delete",
                r#"{"workspace_id":"ws","path":"docs/missing.txt","ignore_missing":true}"#,
            ))
            .await,
        StatusCode::OK,
    )
    .await;

    assert!(!resp.deleted);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn write_then_read_postgres() {
    let Some(server) = setup_postgres().await else {
        return;
    };

    let suffix = unique_suffix();
    let path = format!("docs/{suffix}.txt");
    let workspace_id = "ws".to_string();

    let write = expect_json::<WriteBody>(
        server
            .send(bearer_request(
                "/v1/write",
                &WriteRequest {
                    workspace_id: workspace_id.clone(),
                    path: path.clone(),
                    content: "hello\n".to_string(),
                    expected_version: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(write.path, path);
    assert_eq!(write.version, 1);

    let read = expect_json::<ReadBody>(
        server
            .send(bearer_request(
                "/v1/read",
                &ReadRequest {
                    workspace_id,
                    path,
                    start_line: None,
                    end_line: None,
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read.content, "hello\n");
    assert_eq!(read.version, 1);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn write_then_read_line_range_postgres() {
    let _env_guard = test_env_lock().lock().await;
    let _whole_content_guard = BackendWholeContentGuard::install(12);
    let Some(server) = setup_postgres().await else {
        return;
    };

    let suffix = unique_suffix();
    let path = format!("docs/{suffix}.txt");
    let workspace_id = "ws".to_string();

    let write_resp = server
        .send(bearer_request(
            "/v1/write",
            &WriteRequest {
                workspace_id: workspace_id.clone(),
                path: path.clone(),
                content: "line-0001\nline-0002\nline-0003\nline-0004\n".to_string(),
                expected_version: None,
            },
        ))
        .await;
    assert_eq!(write_resp.status(), StatusCode::OK);

    let read = expect_json::<ReadBody>(
        server
            .send(bearer_request(
                "/v1/read",
                &ReadRequest {
                    workspace_id,
                    path,
                    start_line: Some(2),
                    end_line: Some(2),
                },
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read.content, "line-0002\n");
    assert_eq!(read.version, 1);
}
