use std::net::SocketAddr;

use axum::Router;
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};

const DEV_TOKEN: &str = "dev-token";
const DEV_TOKEN_SHA256: &str =
    "sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712";

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
                token: Some(DEV_TOKEN_SHA256.to_string()),
                token_env_var: None,
                allowed_workspaces: vec!["ws".to_string()],
            }],
        },
    }
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    addr
}

#[tokio::test]
async fn write_then_read() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
        .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let write = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "hello\n".to_string(),
            expected_version: None,
        })
        .send()
        .await
        .expect("send")
        .error_for_status()
        .expect("status")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(write["path"], "docs/a.txt");
    assert_eq!(write["version"], 1);

    let read = client
        .post(format!("{base}/v1/read"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&ReadRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .send()
        .await
        .expect("send")
        .error_for_status()
        .expect("status")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(read["content"], "hello\n");
    assert_eq!(read["version"], 1);
}

#[tokio::test]
async fn auth_is_checked_before_json_body_is_parsed() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
        .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/write"))
        .header("content-type", "application/json")
        .body("{") // invalid JSON
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn invalid_json_returns_json_error_body() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
        .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body("{") // invalid JSON
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 400);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["code"], "invalid_json");
}

#[tokio::test]
async fn missing_content_type_returns_json_error_body() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all(), false)
        .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .body("{}") // no content-type header
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 415);
    assert!(resp.headers().contains_key("x-request-id"));
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["code"], "unsupported_media_type");
}
