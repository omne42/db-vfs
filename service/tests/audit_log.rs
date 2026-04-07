#![cfg(feature = "sqlite")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use db_vfs::vfs::{GlobRequest, WriteRequest};
use db_vfs_core::policy::{Permissions, SecretRules, TraversalRules};
use serde::Serialize;
use tower::ServiceExt;

use db_vfs_service::policy::{AuditPolicy, AuthPolicy, AuthToken, ServiceLimits, ServicePolicy};

const DEV_TOKEN: &str = "dev-token";
const DEV_TOKEN_SHA256: &str =
    "sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712";

fn base_policy() -> ServicePolicy {
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
                token: Some(DEV_TOKEN_SHA256.to_string()),
                token_env_var: None,
                allowed_workspaces: vec!["ws".to_string()],
            }],
        },
    }
}

struct TestServer {
    _dir: tempfile::TempDir,
    app: Router,
    audit_path: PathBuf,
    peer_addr: SocketAddr,
}

impl TestServer {
    async fn send(&self, mut req: Request<Body>) -> axum::response::Response {
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(self.peer_addr));
        self.app.clone().oneshot(req).await.expect("response")
    }
}

fn raw_request_for_uri(uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.into())
        .expect("request")
}

fn raw_request(body: impl Into<Body>) -> Request<Body> {
    raw_request_for_uri("/v1/write", body)
}

fn authorized_raw_request_for_uri(uri: &str, body: impl Into<Body>) -> Request<Body> {
    let mut req = raw_request_for_uri(uri, body);
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {DEV_TOKEN}")
            .parse()
            .expect("authorization header"),
    );
    req
}

fn authorized_raw_request(body: impl Into<Body>) -> Request<Body> {
    authorized_raw_request_for_uri("/v1/write", body)
}

fn bearer_request<T: Serialize>(body: &T) -> Request<Body> {
    authorized_raw_request(Body::from(
        serde_json::to_vec(body).expect("serialize request json"),
    ))
}

fn bearer_request_for_uri<T: Serialize>(uri: &str, body: &T) -> Request<Body> {
    authorized_raw_request_for_uri(
        uri,
        Body::from(serde_json::to_vec(body).expect("serialize request json")),
    )
}

async fn setup(mut policy: ServicePolicy) -> TestServer {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let audit_path = dir.path().join("audit.jsonl");

    policy.audit = AuditPolicy {
        jsonl_path: Some(audit_path.to_string_lossy().into_owned()),
        required: true,
        flush_every_events: Some(1),
        flush_max_interval_ms: Some(1),
    };

    let app =
        db_vfs_service::server::build_app(db, policy, db_vfs_service::TrustMode::Trusted, false)
            .expect("build app");
    TestServer {
        _dir: dir,
        app,
        audit_path,
        peer_addr: SocketAddr::from(([127, 0, 0, 1], 31337)),
    }
}

async fn wait_for_audit_lines(path: &Path, min_lines: usize) -> Vec<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(lines) = try_read_audit_lines(path)
            && lines.len() >= min_lines
        {
            return lines;
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

fn try_read_audit_lines(path: &Path) -> Option<Vec<serde_json::Value>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut lines = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|err| {
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
    Some(lines)
}

fn read_audit_lines_immediately(path: &Path) -> Vec<serde_json::Value> {
    let lines = try_read_audit_lines(path).unwrap_or_else(|| {
        panic!(
            "required audit should have flushed before the response returned (path={})",
            path.display()
        )
    });
    assert!(
        !lines.is_empty(),
        "required audit should have flushed at least one event before the response returned (path={})",
        path.display()
    );
    lines
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

    let resp = server.send(raw_request("{")).await;
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

    let resp = server.send(authorized_raw_request("{")).await;
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
    policy.limits = ServiceLimits {
        max_requests_per_ip_per_sec: 1,
        max_requests_burst_per_ip: 1,
        max_rate_limit_ips: 1024,
        ..ServiceLimits::default()
    };
    let server = setup(policy).await;

    let req = WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "hello\n".to_string(),
        expected_version: None,
    };

    let ok = server.send(bearer_request(&req)).await;
    assert_eq!(ok.status(), 200);

    let mut saw_rate_limit = false;
    for attempt in 0..8 {
        let mut req = req.clone();
        req.path = format!("docs/rate-limit-{attempt}.txt");
        let resp = server.send(bearer_request(&req)).await;
        if resp.status() == 429 {
            saw_rate_limit = true;
            break;
        }
        assert_eq!(
            resp.status(),
            200,
            "expected follow-up write to be accepted or rate limited"
        );
    }
    assert!(saw_rate_limit, "expected at least one rate-limited write");

    let lines = wait_for_audit_lines(&server.audit_path, 2).await;
    let event = find_event(&lines, "write", 429, "rate_limited");
    assert_eq!(event["workspace_id"], "<unknown>");
}

#[tokio::test]
async fn audit_logs_disallowed_workspace_rejects_before_response_returns() {
    let server = setup(base_policy()).await;

    let resp = server
        .send(authorized_raw_request(
            r#"{"workspace_id":"denied","path":"docs/a.txt","content":[],"expected_version":null}"#,
        ))
        .await;
    assert_eq!(resp.status(), 403);

    let lines = read_audit_lines_immediately(&server.audit_path);
    let event = find_event(&lines, "write", 403, "not_permitted");
    assert_eq!(event["workspace_id"], "denied");
    assert_eq!(event["auth_subject"], DEV_TOKEN_SHA256);
}

#[tokio::test]
async fn audit_logs_invalid_workspace_id_rejects_before_response_returns() {
    let server = setup(base_policy()).await;

    let resp = server
        .send(authorized_raw_request(
            r#"{"workspace_id":"bad*ws","path":"docs/a.txt","content":"hello\n","expected_version":null}"#,
        ))
        .await;
    assert_eq!(resp.status(), 400);

    let lines = read_audit_lines_immediately(&server.audit_path);
    let event = find_event(&lines, "write", 400, "invalid_path");
    assert_eq!(event["workspace_id"], "bad*ws");
    assert_eq!(event["auth_subject"], DEV_TOKEN_SHA256);
}

#[tokio::test]
async fn audit_redacts_secretish_malformed_write_paths_in_jsonl() {
    let server = setup(base_policy()).await;

    let resp = server
        .send(bearer_request(&WriteRequest {
            workspace_id: "ws".to_string(),
            path: ".env/../visible.txt".to_string(),
            content: "hello\n".to_string(),
            expected_version: None,
        }))
        .await;
    assert_eq!(resp.status(), 400);

    let lines = read_audit_lines_immediately(&server.audit_path);
    let event = find_event(&lines, "write", 400, "invalid_path");
    assert_eq!(event["workspace_id"], "ws");
    assert_eq!(
        event["requested_path"].as_str(),
        Some("<secret>"),
        "unexpected malformed-write audit event: {event:?}"
    );
    assert_eq!(
        event["path"].as_str(),
        Some("<secret>"),
        "unexpected malformed-write audit event: {event:?}"
    );
    assert_eq!(event["auth_subject"], DEV_TOKEN_SHA256);
}

#[tokio::test]
async fn audit_redacts_secretish_glob_patterns_in_jsonl() {
    let server = setup(base_policy()).await;

    let resp = server
        .send(bearer_request_for_uri(
            "/v1/glob",
            &GlobRequest {
                workspace_id: "ws".to_string(),
                path_prefix: Some("docs".to_string()),
                pattern: "docs/**/.env*".to_string(),
            },
        ))
        .await;
    assert_eq!(resp.status(), 200);

    let lines = read_audit_lines_immediately(&server.audit_path);
    let event = lines
        .iter()
        .find(|event| event["op"] == "glob" && event["status"] == 200)
        .unwrap_or_else(|| panic!("missing successful glob audit event: {lines:?}"));
    assert_eq!(event["workspace_id"], "ws");
    assert_eq!(event["path_prefix"], "docs");
    assert_eq!(event["glob_pattern"], "<secret>");
    assert_eq!(event["auth_subject"], DEV_TOKEN_SHA256);
}
