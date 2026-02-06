use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::Router;
use db_vfs::vfs::WriteRequest;
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, AuthToken, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};

const DEV_TOKEN: &str = "dev-token";
const DEV_TOKEN_SHA256: &str =
    "sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712";

fn base_policy() -> VfsPolicy {
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

struct TestServer {
    _dir: tempfile::TempDir,
    audit_path: PathBuf,
    base: String,
    client: reqwest::Client,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
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

async fn setup(mut policy: VfsPolicy) -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let audit_path = dir.path().join("audit.jsonl");

    policy.audit = AuditPolicy {
        jsonl_path: Some(audit_path.to_string_lossy().into_owned()),
        required: true,
        flush_every_events: Some(1),
        flush_max_interval_ms: Some(1),
    };

    let app = db_vfs_service::server::build_app(db, policy, false).expect("build app");
    let (addr, handle) = serve(app).await;

    TestServer {
        _dir: dir,
        audit_path,
        base: format!("http://{addr}"),
        client: reqwest::Client::new(),
        handle,
    }
}

async fn wait_for_audit_lines(path: &Path, min_lines: usize) -> Vec<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let mut lines = Vec::new();
            for (idx, line) in raw.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let parsed =
                    serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|err| {
                        panic!(
                            "invalid audit json at line {} in {}: {} (content={})",
                            idx + 1,
                            path.display(),
                            err,
                            line
                        )
                    });
                lines.push(parsed);
            }
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

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn find_event<'a>(
    events: &'a [serde_json::Value],
    op: &str,
    status: u16,
    error_code: &str,
) -> &'a serde_json::Value {
    events
        .iter()
        .find(|event| {
            event["op"] == op
                && event["status"] == u64::from(status)
                && event["error_code"] == error_code
        })
        .unwrap_or_else(|| {
            panic!(
                "missing audit event op={op}, status={status}, error_code={error_code}; events={events:?}"
            )
        })
}

#[tokio::test]
async fn audit_logs_unauthorized_requests() {
    let server = setup(base_policy()).await;

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send unauthorized request");
    assert_eq!(resp.status(), 401);

    let lines = wait_for_audit_lines(&server.audit_path, 1).await;
    let event = find_event(&lines, "write", 401, "unauthorized");
    assert_eq!(event["workspace_id"], "<unknown>");
    assert!(
        event["request_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[tokio::test]
async fn audit_logs_invalid_json_requests() {
    let server = setup(base_policy()).await;

    let resp = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .expect("send invalid json request");
    assert_eq!(resp.status(), 400);

    let lines = wait_for_audit_lines(&server.audit_path, 1).await;
    let event = find_event(&lines, "write", 400, "invalid_json_syntax");
    assert_eq!(event["workspace_id"], "<unknown>");
    assert!(
        event["request_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[tokio::test]
async fn audit_logs_rate_limited_requests() {
    let mut policy = base_policy();
    policy.limits = Limits {
        max_requests_per_ip_per_sec: 1,
        max_requests_burst_per_ip: 1,
        max_rate_limit_ips: 1024,
        ..Limits::default()
    };
    let server = setup(policy).await;

    let req = WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "hello\n".to_string(),
        expected_version: None,
    };

    let ok = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&req)
        .send()
        .await
        .expect("send first write");
    assert_eq!(ok.status(), 200);

    let limited = server
        .client
        .post(format!("{}/v1/write", server.base))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .json(&req)
        .send()
        .await
        .expect("send second write");
    assert_eq!(limited.status(), 429);

    let lines = wait_for_audit_lines(&server.audit_path, 2).await;
    let event = find_event(&lines, "write", 429, "rate_limited");
    assert_eq!(event["workspace_id"], "<unknown>");
}
