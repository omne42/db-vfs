use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};
use sha2::{Digest, Sha256};

const DEV_TOKEN: &str = "dev-token";

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

struct TestServer {
    _db: tempfile::NamedTempFile,
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

async fn serve(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    (addr, handle)
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

async fn setup() -> TestServer {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
        .expect("build app");
    let (addr, handle) = serve(app).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    wait_until_ready(&client, &base).await;

    TestServer {
        _db: db,
        base,
        client,
        handle,
    }
}

fn is_generated_request_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[tokio::test]
async fn write_then_read() {
    let server = setup().await;

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
    let server = setup().await;

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
    let server = setup().await;

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
    let server = setup().await;

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
    let server = setup().await;

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
