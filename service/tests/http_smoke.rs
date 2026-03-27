use std::net::SocketAddr;
use std::time::Duration;
#[cfg(feature = "postgres")]
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};
use sha2::{Digest, Sha256};

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
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
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
        base,
        client,
        handle,
    })
}

#[cfg(feature = "postgres")]
fn postgres_test_url() -> String {
    let raw = std::env::var("DB_VFS_TEST_POSTGRES_URL").expect(
        "DB_VFS_TEST_POSTGRES_URL is required when running ignored postgres integration tests",
    );
    let url = raw.trim().to_string();
    assert!(
        !url.is_empty(),
        "DB_VFS_TEST_POSTGRES_URL must be non-empty when running ignored postgres integration tests"
    );
    url
}

#[cfg(feature = "postgres")]
async fn setup_postgres() -> Option<(String, reqwest::Client, tokio::task::JoinHandle<()>)> {
    let app = tokio::task::spawn_blocking(|| {
        db_vfs_service::server::build_app_postgres(postgres_test_url(), policy_allow_all(), false)
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
#[ignore = "requires DB_VFS_TEST_POSTGRES_URL"]
async fn write_then_read_postgres() {
    let Some((base, client, handle)) = setup_postgres().await else {
        return;
    };

    let suffix = unique_suffix();
    let path = format!("docs/{suffix}.txt");
    let workspace_id = format!("ws-{suffix}");

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
