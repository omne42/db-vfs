use std::net::SocketAddr;
use std::time::Duration;
#[cfg(feature = "postgres")]
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

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

#[derive(serde::Deserialize)]
struct ErrorBody {
    code: String,
}

#[derive(serde::Deserialize)]
struct DeleteBody {
    deleted: bool,
}

struct TestServer {
    _db: tempfile::NamedTempFile,
    addr: SocketAddr,
    base: String,
    client: reqwest::Client,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn dev_token_sha256() -> String {
    let digest = Sha256::digest(DEV_TOKEN.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn policy_allow_all() -> VfsPolicy {
    VfsPolicy {
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            write: true,
            patch: true,
            delete: true,
            allow_full_scan: false,
        },
        limits: Limits::default(),
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

async fn serve(app: Router) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    Ok((addr, handle))
}

async fn wait_until_ready(client: &reqwest::Client, base: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let result = client
            .post(format!("{base}/v1/write"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await;
        if let Ok(resp) = result
            && resp.status().as_u16() >= 400
        {
            return;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!("server readiness probe timed out for base={base}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn setup() -> Option<TestServer> {
    setup_with_policy(policy_allow_all()).await
}

async fn setup_with_policy(policy: VfsPolicy) -> Option<TestServer> {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy, false)
        .expect("build app");
    let (addr, handle) = match serve(app).await {
        Ok(server) => server,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping http_smoke test: local bind denied ({err})");
            return None;
        }
        Err(err) => panic!("bind: {err}"),
    };
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    wait_until_ready(&client, &base).await;

    Some(TestServer {
        _db: db,
        addr,
        base,
        client,
        handle,
    })
}

#[tokio::test]
async fn embedded_router_write_works_without_connect_info() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), true)
        .expect("build app");

    let req = Request::builder()
        .method("POST")
        .uri("/v1/write")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"workspace_id":"ws","path":"docs/a.txt","content":"hello\n","expected_version":null}"#,
        ))
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-request-id"));

    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let write = serde_json::from_slice::<WriteBody>(&body).expect("write json");
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.version, 1);
}

#[tokio::test]
async fn workspace_id_with_wildcard_is_rejected() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), true)
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
async fn setup_postgres() -> Option<(String, reqwest::Client, tokio::task::JoinHandle<()>)> {
    let Some(url) = postgres_test_url() else {
        eprintln!("skipping postgres http_smoke test: DB_VFS_TEST_POSTGRES_URL unset");
        return None;
    };
    let app = tokio::task::spawn_blocking(move || {
        db_vfs_service::server::build_app_postgres(url, policy_allow_all(), false)
    })
    .await
    .expect("join postgres app builder")
    .expect("build postgres app");
    let (addr, handle) = match serve(app).await {
        Ok(server) => server,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping postgres http_smoke test: local bind denied ({err})");
            return None;
        }
        Err(err) => panic!("bind postgres app: {err}"),
    };
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    wait_until_ready(&client, &base).await;
    Some((base, client, handle))
}

fn is_generated_request_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[tokio::test]
async fn write_then_read() {
    let Some(server) = setup().await else {
        return;
    };

    let write = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "hello\n".to_string(),
            expected_version: None,
        })
        .send()
        .await
        .expect("send write")
        .error_for_status()
        .expect("write status")
        .json::<WriteBody>()
        .await
        .expect("write json");
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.version, 1);

    let read = server
        .client
        .post(format!("{}/v1/read", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&ReadRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .send()
        .await
        .expect("send read")
        .error_for_status()
        .expect("read status")
        .json::<ReadBody>()
        .await
        .expect("read json");
    assert_eq!(read.content, "hello\n");
    assert_eq!(read.version, 1);
}

#[tokio::test]
async fn auth_is_checked_before_json_body_is_parsed() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send unauthorized invalid json");

    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "unauthorized");
}

#[tokio::test]
async fn request_id_header_roundtrip_and_sanitization() {
    let Some(server) = setup().await else {
        return;
    };

    let valid_request_id = "client_req-123_ABC";
    let valid_resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("x-request-id", valid_request_id)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send request with valid request-id");
    assert_eq!(valid_resp.status(), 401);
    let echoed = valid_resp
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("echoed x-request-id");
    assert_eq!(echoed, valid_request_id);

    let invalid_resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("x-request-id", "bad id !")
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send request with invalid request-id");
    assert_eq!(invalid_resp.status(), 401);
    let generated = invalid_resp
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("generated x-request-id");
    assert!(is_generated_request_id(generated));
    assert_ne!(generated, "bad id !");
}

#[tokio::test]
async fn invalid_json_returns_json_error_body() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send invalid json");

    assert_eq!(resp.status(), 400);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "invalid_json_syntax");
}

#[tokio::test]
async fn missing_content_type_returns_json_error_body() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .body("{}")
        .send()
        .await
        .expect("send without content-type");

    assert_eq!(resp.status(), 415);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "unsupported_media_type");
}

#[tokio::test]
async fn slow_request_body_times_out_before_json_decode() {
    let mut policy = policy_allow_all();
    policy.limits.max_io_ms = 1_000;
    let Some(server) = setup_with_policy(policy).await else {
        return;
    };

    let mut stream = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect raw tcp stream");
    let headers = concat!(
        "POST /v1/write HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Authorization: Bearer dev-token\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: 79\r\n",
        "\r\n"
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write request headers");

    tokio::time::sleep(Duration::from_millis(1_250)).await;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("read timed-out body response")
        .expect("read response");
    let response = String::from_utf8(response).expect("response utf8");
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "expected a timeout response, got: {response}"
    );
    assert!(
        response.contains("\"code\":\"timeout\""),
        "expected timeout error code, got: {response}"
    );
}

#[tokio::test]
async fn unknown_request_fields_are_rejected_as_invalid_json_schema() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body(r#"{"workspace_id":"ws","path":"docs/a.txt","content":"hello","unexpected":true}"#)
        .send()
        .await
        .expect("send request with unknown field");

    assert_eq!(resp.status(), 400);
    let body = resp.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "invalid_json_schema");
}

#[tokio::test]
async fn workspace_allowlist_rejections_return_not_permitted_code() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&WriteRequest {
            workspace_id: "other".to_string(),
            path: "docs/a.txt".to_string(),
            content: "hello\n".to_string(),
            expected_version: None,
        })
        .send()
        .await
        .expect("send forbidden workspace request");

    assert_eq!(resp.status(), 403);
    let body = resp.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "not_permitted");
}

#[tokio::test]
async fn rate_limited_requests_return_rate_limited_code() {
    let mut policy = policy_allow_all();
    policy.limits.max_requests_per_ip_per_sec = 1;
    policy.limits.max_requests_burst_per_ip = 1;
    policy.limits.max_rate_limit_ips = 16;
    let Some(server) = setup_with_policy(policy).await else {
        return;
    };
    tokio::time::sleep(Duration::from_secs(2)).await;

    let first = server
        .client
        .post(format!("{}/v1/read", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("send first request");
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = server
        .client
        .post(format!("{}/v1/read", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("send second request");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = second.json::<ErrorBody>().await.expect("error json");
    assert_eq!(body.code, "rate_limited");
}

#[tokio::test]
async fn delete_ignore_missing_returns_deleted_false() {
    let Some(server) = setup().await else {
        return;
    };

    let resp = server
        .client
        .post(format!("{}/v1/delete", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body(r#"{"workspace_id":"ws","path":"docs/missing.txt","ignore_missing":true}"#)
        .send()
        .await
        .expect("send delete ignore_missing request")
        .error_for_status()
        .expect("delete status")
        .json::<DeleteBody>()
        .await
        .expect("delete json");

    assert!(!resp.deleted);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn write_then_read_postgres() {
    let Some((base, client, handle)) = setup_postgres().await else {
        return;
    };

    let suffix = unique_suffix();
    let path = format!("docs/{suffix}.txt");
    let workspace_id = "ws".to_string();

    let write = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&WriteRequest {
            workspace_id: workspace_id.clone(),
            path: path.clone(),
            content: "hello\n".to_string(),
            expected_version: None,
        })
        .send()
        .await
        .expect("send postgres write")
        .error_for_status()
        .expect("postgres write status")
        .json::<WriteBody>()
        .await
        .expect("postgres write json");
    assert_eq!(write.path, path);
    assert_eq!(write.version, 1);

    let read = client
        .post(format!("{base}/v1/read"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&ReadRequest {
            workspace_id,
            path,
            start_line: None,
            end_line: None,
        })
        .send()
        .await
        .expect("send postgres read")
        .error_for_status()
        .expect("postgres read status")
        .json::<ReadBody>()
        .await
        .expect("postgres read json");
    assert_eq!(read.content, "hello\n");
    assert_eq!(read.version, 1);

    handle.abort();
}
