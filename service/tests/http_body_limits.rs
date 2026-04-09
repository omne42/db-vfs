#![cfg(feature = "sqlite")]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use db_vfs::vfs::{PatchRequest, WriteRequest};
use serde_json::json;
use tower::ServiceExt;

use db_vfs_core::policy::{Permissions, SecretRules, TraversalRules};
use db_vfs_service::policy::{AuditPolicy, AuthPolicy, ServiceLimits, ServicePolicy};

fn policy_with_limits(max_write_bytes: u64, max_patch_bytes: u64) -> ServicePolicy {
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
        limits: ServiceLimits {
            max_write_bytes,
            max_patch_bytes: Some(max_patch_bytes),
            ..ServiceLimits::default()
        },
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        audit: AuditPolicy::default(),
        auth: AuthPolicy::default(),
    }
}

fn json_request(uri: &str, value: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("serialize request json"),
        ))
        .expect("request")
}

async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
    router.clone().oneshot(request).await.expect("response")
}

#[tokio::test]
async fn write_accepts_escape_dense_json_that_would_exceed_old_transport_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db.sqlite");
    let content = "\"".repeat(70 * 1024);
    let router = db_vfs_service::server::build_app(
        db_path,
        policy_with_limits(content.len() as u64, 256 * 1024),
        db_vfs_service::TrustMode::Trusted,
        true,
    )
    .expect("build sqlite router");

    let request_body = json!({
        "workspace_id": "ws",
        "path": "docs/escaped-write.txt",
        "content": content,
        "expected_version": null,
    });
    let encoded = serde_json::to_vec(&request_body).expect("encode write request");
    assert!(
        encoded.len() > (70 * 1024) + (64 * 1024),
        "request should exceed the legacy decoded-size+64KiB transport cap"
    );

    let response = send(&router, json_request("/v1/write", request_body)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "escape-dense but decoded-legal write should reach VFS validation instead of returning 413"
    );
}

#[tokio::test]
async fn patch_accepts_escape_dense_json_that_would_exceed_old_transport_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db.sqlite");
    let replacement = "\"".repeat(70 * 1024);
    let patch = format!("@@ -1 +1 @@\n-base\n+{replacement}\n");
    let router = db_vfs_service::server::build_app(
        db_path,
        policy_with_limits((replacement.len() + 1) as u64, patch.len() as u64),
        db_vfs_service::TrustMode::Trusted,
        true,
    )
    .expect("build sqlite router");

    let write = WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/escaped-patch.txt".to_string(),
        content: "base\n".to_string(),
        expected_version: None,
    };
    let seeded = send(
        &router,
        json_request(
            "/v1/write",
            serde_json::to_value(&write).expect("encode seed write"),
        ),
    )
    .await;
    assert_eq!(seeded.status(), StatusCode::OK);

    let patch_request = PatchRequest {
        workspace_id: "ws".to_string(),
        path: "docs/escaped-patch.txt".to_string(),
        patch: patch.clone(),
        expected_version: 1,
    };
    let request_body = serde_json::to_value(&patch_request).expect("encode patch request");
    let encoded = serde_json::to_vec(&request_body).expect("encode patch request json");
    assert!(
        encoded.len() > patch.len() + (64 * 1024),
        "request should exceed the legacy decoded-size+64KiB transport cap"
    );

    let response = send(&router, json_request("/v1/patch", request_body)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "escape-dense but decoded-legal patch should reach VFS validation instead of returning 413"
    );
}
