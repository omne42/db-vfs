use std::net::SocketAddr;

use axum::Router;
use db_vfs::vfs::{ReadRequest, WriteRequest};
use db_vfs_core::policy::{Limits, Permissions, SecretRules, VfsPolicy};

fn policy_allow_all() -> VfsPolicy {
    VfsPolicy {
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            write: true,
            patch: true,
            delete: true,
        },
        limits: Limits::default(),
        secrets: SecretRules::default(),
    }
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

#[tokio::test]
async fn write_then_read() {
    let db = tempfile::NamedTempFile::new().expect("temp db");
    let app = db_vfs_service::server::build_app(db.path().to_path_buf(), policy_allow_all())
        .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let write = client
        .post(format!("{base}/v1/write"))
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
