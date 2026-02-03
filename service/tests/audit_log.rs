use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::Router;
use db_vfs::vfs::WriteRequest;
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};

const DEV_TOKEN: &str = "dev-token";
const DEV_TOKEN_SHA256: &str =
    "sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712";

fn policy_allow_all_with_audit(audit_path: &Path) -> VfsPolicy {
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
        audit: AuditPolicy {
            jsonl_path: Some(audit_path.to_string_lossy().into_owned()),
            required: true,
            flush_every_events: Some(1),
            flush_max_interval_ms: Some(1),
        },
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

async fn wait_for_audit_lines(path: &Path, min_lines: usize) -> Vec<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let lines: Vec<_> = raw
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .collect();
            if lines.len() >= min_lines {
                return lines;
            }
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for audit log lines (path={}, min_lines={})",
                path.display(),
                min_lines
            );
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn audit_logs_unauthorized_requests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let audit_path = dir.path().join("audit.jsonl");

    let app =
        db_vfs_service::server::build_app(db, policy_allow_all_with_audit(&audit_path), false)
            .expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/write"))
        .header("content-type", "application/json")
        .body("{") // invalid JSON, but should be rejected by auth first
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);

    let lines = wait_for_audit_lines(&audit_path, 1).await;
    let event = &lines[0];
    assert_eq!(event["op"], "write");
    assert_eq!(event["status"], 401);
    assert_eq!(event["error_code"], "unauthorized");
    assert_eq!(event["workspace_id"], "<unknown>");
    assert!(event["request_id"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn audit_logs_invalid_json_requests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let audit_path = dir.path().join("audit.jsonl");

    let app =
        db_vfs_service::server::build_app(db, policy_allow_all_with_audit(&audit_path), false)
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

    let lines = wait_for_audit_lines(&audit_path, 1).await;
    let event = &lines[0];
    assert_eq!(event["op"], "write");
    assert_eq!(event["status"], 400);
    assert_eq!(event["error_code"], "invalid_json");
    assert_eq!(event["workspace_id"], "<unknown>");
    assert!(event["request_id"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn audit_logs_rate_limited_requests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let audit_path = dir.path().join("audit.jsonl");

    let mut policy = policy_allow_all_with_audit(&audit_path);
    policy.limits = Limits {
        max_requests_per_ip_per_sec: 1,
        max_requests_burst_per_ip: 1,
        max_rate_limit_ips: 1024,
        ..Limits::default()
    };

    let app = db_vfs_service::server::build_app(db, policy, false).expect("build app");
    let addr = serve(app).await;

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let req = WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "hello\n".to_string(),
        expected_version: None,
    };

    let ok = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&req)
        .send()
        .await
        .expect("send");
    assert_eq!(ok.status(), 200);

    let limited = client
        .post(format!("{base}/v1/write"))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&req)
        .send()
        .await
        .expect("send");
    assert_eq!(limited.status(), 429);

    let lines = wait_for_audit_lines(&audit_path, 2).await;
    assert!(lines.iter().any(|event| {
        event["op"] == "write"
            && event["status"] == 429
            && event["error_code"] == "rate_limited"
            && event["workspace_id"] == "<unknown>"
    }));
}
