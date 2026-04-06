use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::policy::AuthPolicy;
pub(super) use db_vfs_core::workspace_pattern::AllowedWorkspacePattern as WorkspacePattern;

static ALLOW_ALL_WORKSPACES: OnceLock<Arc<[WorkspacePattern]>> = OnceLock::new();

const MAX_BEARER_TOKEN_BYTES: usize = 4096;

fn allow_all_workspaces() -> Arc<[WorkspacePattern]> {
    ALLOW_ALL_WORKSPACES
        .get_or_init(|| Arc::from(vec![WorkspacePattern::Any]))
        .clone()
}

#[derive(Clone)]
pub(super) enum AuthMode {
    Disabled,
    Enforced { rules: Arc<[AuthRule]> },
}

#[derive(Clone)]
pub(super) struct AuthRule {
    token_sha256: [u8; 32],
    allowed_workspaces: Arc<[WorkspacePattern]>,
    audit_subject: Arc<str>,
}

#[derive(Clone)]
pub(super) struct AuthContext {
    pub(super) allowed_workspaces: Arc<[WorkspacePattern]>,
    pub(super) audit_subject: Option<Arc<str>>,
}

fn compile_workspace_patterns(patterns: &[String]) -> anyhow::Result<Arc<[WorkspacePattern]>> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        compiled.push(
            WorkspacePattern::parse(pattern).map_err(|err| {
                anyhow::anyhow!("invalid auth workspace pattern {pattern:?}: {err}")
            })?,
        );
    }
    Ok(Arc::from(compiled))
}

pub(super) fn build_auth_mode(
    policy: &AuthPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<AuthMode> {
    build_auth_mode_with_env_lookup(policy, unsafe_no_auth, |env| {
        std::env::var(env).map_err(|_| {
            anyhow::anyhow!("auth token env var {env:?} is not set or not valid UTF-8")
        })
    })
}

fn build_auth_mode_with_env_lookup(
    policy: &AuthPolicy,
    unsafe_no_auth: bool,
    mut env_lookup: impl FnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<AuthMode> {
    if unsafe_no_auth {
        return Ok(AuthMode::Disabled);
    }
    if policy.tokens.is_empty() {
        anyhow::bail!(
            "no auth tokens configured; set [auth.tokens] in the policy file or pass --unsafe-no-auth"
        );
    }

    let mut rules = Vec::with_capacity(policy.tokens.len());
    let mut seen = HashSet::<[u8; 32]>::with_capacity(policy.tokens.len());
    for (idx, rule) in policy.tokens.iter().enumerate() {
        let token_sha256 = if let Some(token) = rule.token.as_deref() {
            parse_token_sha256(token)?
        } else if let Some(env) = rule.token_env_var.as_deref() {
            let value = env_lookup(env)?;
            if value.is_empty() {
                anyhow::bail!("auth token env var {env:?} must be non-empty");
            }
            hash_plaintext_token_sha256(&value, &format!("auth token env var {env:?}"))?
        } else {
            anyhow::bail!("auth token entry {idx} is missing token / token_env_var");
        };

        if !seen.insert(token_sha256) {
            anyhow::bail!("auth token entry {idx} duplicates a previous token hash");
        }

        rules.push(AuthRule {
            token_sha256,
            allowed_workspaces: compile_workspace_patterns(&rule.allowed_workspaces)?,
            audit_subject: format_token_audit_subject(&token_sha256),
        });
    }

    Ok(AuthMode::Enforced {
        rules: Arc::from(rules),
    })
}

fn parse_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if token.is_empty() {
        return None;
    }
    if !is_valid_bearer_token(token) {
        return None;
    }
    Some(token)
}

pub(super) fn workspace_allowed(patterns: &[WorkspacePattern], workspace_id: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(workspace_id))
}

fn hash_token_sha256(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
}

fn format_token_audit_subject(token_sha256: &[u8; 32]) -> Arc<str> {
    Arc::<str>::from(format!("sha256:{}", hex::encode(token_sha256)))
}

fn audit_subject_for_presented_token(token: &str) -> Arc<str> {
    format_token_audit_subject(&hash_token_sha256(token))
}

fn is_valid_bearer_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_BYTES {
        return false;
    }

    let mut seen_body = false;
    let mut seen_padding = false;
    for byte in token.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'+' | b'/'
                if !seen_padding =>
            {
                seen_body = true
            }
            b'=' if seen_body => seen_padding = true,
            _ => return false,
        }
    }
    true
}

fn validate_plaintext_bearer_token(token: &str, source: &str) -> anyhow::Result<()> {
    if !is_valid_bearer_token(token) {
        anyhow::bail!(
            "{source} must be a valid HTTP Bearer token (token68 syntax, no whitespace or disallowed punctuation)"
        );
    }
    Ok(())
}

fn hash_plaintext_token_sha256(token: &str, source: &str) -> anyhow::Result<[u8; 32]> {
    validate_plaintext_bearer_token(token, source)?;
    Ok(hash_token_sha256(token))
}

fn parse_token_sha256(token: &str) -> anyhow::Result<[u8; 32]> {
    let Some(hex) = token.strip_prefix("sha256:") else {
        anyhow::bail!("auth token must be sha256:<64 hex chars>");
    };
    if hex.len() != 64 {
        anyhow::bail!("invalid sha256 token hash length");
    }
    let mut hash = [0u8; 32];
    hex::decode_to_slice(hex, &mut hash).map_err(anyhow::Error::msg)?;
    Ok(hash)
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for idx in 0..32 {
        diff |= a[idx] ^ b[idx];
    }
    diff == 0
}

fn match_token<'a>(rules: &'a [AuthRule], token: &str) -> Option<&'a AuthRule> {
    let actual = hash_token_sha256(token);
    let mut matched: Option<&AuthRule> = None;
    for rule in rules {
        if constant_time_eq_32(&rule.token_sha256, &actual) {
            matched = Some(rule);
        }
    }
    matched
}

async fn log_unauthorized(
    state: &super::AppState,
    request_id: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
    path: &str,
    auth_subject: Option<Arc<str>>,
) -> Result<(), Response> {
    if let (Some(audit), Some(request_id), Some(op)) = (
        state.inner.audit.as_ref(),
        request_id,
        super::audit::op_from_path(path),
    ) {
        let mut event = super::audit::minimal_event(
            request_id,
            peer_ip,
            op,
            StatusCode::UNAUTHORIZED.as_u16(),
            Some("unauthorized"),
        );
        event.auth_subject = auth_subject.map(|subject| subject.to_string());
        if let Some(super::RequiredAuditGate { permit, budget }) =
            super::try_acquire_required_audit_gate_for_path(state, path)
                .await
                .map_err(IntoResponse::into_response)?
        {
            super::log_audit_event_with_permit(audit, event, permit, budget)
                .await
                .map_err(IntoResponse::into_response)?;
        } else {
            super::log_audit_event(audit, event)
                .await
                .map_err(IntoResponse::into_response)?;
        }
    }
    Ok(())
}

pub(super) async fn auth_middleware(
    State(state): State<super::AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let request_id = req
        .extensions()
        .get::<super::layers::RequestId>()
        .map(|v| v.0.clone());

    let ctx = match &state.inner.auth {
        AuthMode::Disabled => AuthContext {
            allowed_workspaces: allow_all_workspaces(),
            audit_subject: None,
        },
        AuthMode::Enforced { rules } => {
            let Some(token) = parse_bearer_token(req.headers()) else {
                if let Err(resp) =
                    log_unauthorized(&state, request_id.clone(), peer_ip, &path, None).await
                {
                    return resp;
                }
                return super::err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid Authorization header",
                );
            };

            let Some(rule) = match_token(rules, token) else {
                if let Err(resp) = log_unauthorized(
                    &state,
                    request_id,
                    peer_ip,
                    &path,
                    Some(audit_subject_for_presented_token(token)),
                )
                .await
                {
                    return resp;
                }
                return super::err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "invalid token",
                );
            };

            AuthContext {
                allowed_workspaces: rule.allowed_workspaces.clone(),
                audit_subject: Some(rule.audit_subject.clone()),
            }
        }
    };

    req.extensions_mut().insert(ctx);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::http::HeaderValue;
    use axum::routing::post;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tower::ServiceExt;

    use crate::policy::{AuditPolicy, AuthPolicy, AuthToken, ServiceLimits, ServicePolicy};

    #[test]
    fn bearer_token_parsing_is_case_insensitive_and_strict() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(parse_bearer_token(&headers), Some("abc"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer abc"),
        );
        assert_eq!(parse_bearer_token(&headers), Some("abc"));

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer"));
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer ="));
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer a b"),
        );
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer\tabc"),
        );
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc\tdef"),
        );
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer  abc"),
        );
        assert_eq!(parse_bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bad:token"),
        );
        assert_eq!(parse_bearer_token(&headers), None);

        let long = format!("Bearer {}", "a".repeat(MAX_BEARER_TOKEN_BYTES + 1));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&long).expect("header value"),
        );
        assert_eq!(parse_bearer_token(&headers), None);
    }

    #[test]
    fn workspace_allowlist_supports_star_and_prefix() {
        assert!(workspace_allowed(
            &compile_workspace_patterns(&[String::from("*")]).expect("compile workspace patterns"),
            "ws"
        ));
        assert!(workspace_allowed(
            &compile_workspace_patterns(&[String::from("ws")]).expect("compile workspace patterns"),
            "ws"
        ));
        assert!(!workspace_allowed(
            &compile_workspace_patterns(&[String::from("ws")]).expect("compile workspace patterns"),
            "ws2"
        ));
        assert!(workspace_allowed(
            &compile_workspace_patterns(&[String::from("team-*")])
                .expect("compile workspace patterns"),
            "team-123"
        ));
        assert!(!workspace_allowed(
            &compile_workspace_patterns(&[String::from("team-*")])
                .expect("compile workspace patterns"),
            "team-"
        ));
        assert!(!workspace_allowed(
            &compile_workspace_patterns(&[String::from("team-*")])
                .expect("compile workspace patterns"),
            "other"
        ));
    }

    #[test]
    fn compile_workspace_patterns_rejects_invalid_wildcards() {
        let err = compile_workspace_patterns(&[String::from("team*")])
            .expect_err("invalid wildcard pattern should fail");
        assert!(
            err.to_string()
                .contains("trailing wildcard patterns must end with '-*'")
        );
    }

    #[test]
    fn compile_workspace_patterns_rejects_whitespace_patterns() {
        let err = compile_workspace_patterns(&[String::from("team a")])
            .expect_err("whitespace-bearing pattern should fail");
        assert!(err.to_string().contains("must not contain whitespace"));
    }

    #[test]
    fn parse_sha256_token_requires_exact_length() {
        assert!(parse_token_sha256("sha256:abcd").is_err());
        assert!(parse_token_sha256("abcd").is_err());

        let ok = parse_token_sha256(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(ok.len(), 32);
    }

    #[test]
    fn hash_plaintext_token_rejects_oversized_token() {
        let err = hash_plaintext_token_sha256(
            &"a".repeat(MAX_BEARER_TOKEN_BYTES + 1),
            "auth token env var \"DB_VFS_TOKEN\"",
        )
        .expect_err("oversized plaintext token must be rejected");
        assert!(err.to_string().contains("valid HTTP Bearer token"));
    }

    #[test]
    fn hash_plaintext_token_rejects_invalid_bearer_syntax() {
        let err = hash_plaintext_token_sha256("dev token", "auth token env var \"DB_VFS_TOKEN\"")
            .expect_err("whitespace-bearing plaintext token must be rejected");
        assert!(err.to_string().contains("valid HTTP Bearer token"));

        let err = hash_plaintext_token_sha256("bad:token", "auth token env var \"DB_VFS_TOKEN\"")
            .expect_err("colon-bearing plaintext token must be rejected");
        assert!(err.to_string().contains("valid HTTP Bearer token"));
    }

    #[test]
    fn build_auth_mode_allows_unsafe_no_auth_with_no_tokens() {
        let policy = AuthPolicy::default();
        let mode = build_auth_mode(&policy, true).unwrap();
        assert!(matches!(mode, AuthMode::Disabled));

        let err = build_auth_mode(&policy, false).err().expect("should fail");
        assert!(err.to_string().contains("no auth tokens configured"));
    }

    #[test]
    fn build_auth_mode_rejects_duplicate_token_hashes() {
        let mut policy = AuthPolicy::default();
        let token = format!("sha256:{}", "a".repeat(64));
        policy.tokens = vec![
            AuthToken {
                token: Some(token.clone()),
                token_env_var: None,
                allowed_workspaces: vec!["team-a".to_string()],
            },
            AuthToken {
                token: Some(token),
                token_env_var: None,
                allowed_workspaces: vec!["team-b".to_string()],
            },
        ];

        let err = build_auth_mode(&policy, false)
            .err()
            .expect("duplicate token hashes should be rejected");
        assert!(err.to_string().contains("duplicates a previous token hash"));
    }

    #[test]
    fn build_auth_mode_rejects_env_backed_token_whitespace() {
        let var = format!("DB_VFS_TEST_TOKEN_{}", std::process::id());
        let token = " dev-token-with-spaces \n";

        let policy = AuthPolicy {
            tokens: vec![AuthToken {
                token: None,
                token_env_var: Some(var.clone()),
                allowed_workspaces: vec!["ws".to_string()],
            }],
        };

        let err = build_auth_mode_for_test(&policy, [(&var, token)], false)
            .err()
            .expect("whitespace-bearing env token should be rejected");
        assert!(err.to_string().contains("valid HTTP Bearer token"));
    }

    #[test]
    fn build_auth_mode_hashes_env_backed_plaintext_token() {
        let var = format!("DB_VFS_TEST_TOKEN_OK_{}", std::process::id());
        let token = "dev-token";
        let digest = format!("sha256:{}", hex::encode(hash_token_sha256(token)));

        let policy = AuthPolicy {
            tokens: vec![AuthToken {
                token: None,
                token_env_var: Some(var.clone()),
                allowed_workspaces: vec!["ws".to_string()],
            }],
        };

        let mode =
            build_auth_mode_for_test(&policy, [(&var, token)], false).expect("build auth mode");

        let AuthMode::Enforced { rules } = mode else {
            panic!("expected enforced auth mode");
        };
        assert_eq!(rules.len(), 1);
        assert!(constant_time_eq_32(
            &rules[0].token_sha256,
            &parse_token_sha256(&digest).unwrap()
        ));
        assert_eq!(rules[0].audit_subject.as_ref(), digest);
    }

    #[test]
    fn build_auth_mode_rejects_sha256_prefixed_env_value_as_invalid_plaintext_token() {
        let var = format!("DB_VFS_TEST_TOKEN_SHA256_{}", std::process::id());
        let token = format!("sha256:{}", "a".repeat(64));

        let policy = AuthPolicy {
            tokens: vec![AuthToken {
                token: None,
                token_env_var: Some(var.clone()),
                allowed_workspaces: vec!["ws".to_string()],
            }],
        };

        let err = build_auth_mode_for_test(&policy, [(&var, token.as_str())], false)
            .err()
            .expect("sha256-prefixed env value should be treated as invalid plaintext");

        assert!(err.to_string().contains("valid HTTP Bearer token"));
    }

    fn build_auth_mode_for_test<'a>(
        policy: &AuthPolicy,
        env: impl IntoIterator<Item = (&'a String, &'a str)>,
        unsafe_no_auth: bool,
    ) -> anyhow::Result<AuthMode> {
        let env_map: HashMap<&str, &str> = env
            .into_iter()
            .map(|(key, value)| (key.as_str(), value))
            .collect();
        build_auth_mode_with_env_lookup(policy, unsafe_no_auth, |name| {
            env_map
                .get(name)
                .map(|value| (*value).to_string())
                .ok_or_else(|| {
                    anyhow::anyhow!("auth token env var {name:?} is not set or not valid UTF-8")
                })
        })
    }

    #[test]
    fn audit_subject_uses_token_sha256_fingerprint() {
        assert_eq!(
            audit_subject_for_presented_token("dev-token").as_ref(),
            "sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn unauthorized_audit_records_presented_token_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let audit = super::super::audit::AuditLogger::new(&path, true, 1, Duration::from_millis(1))
            .expect("audit logger");
        let state = super::super::test_state_with_audit(Some(audit.clone()));

        log_unauthorized(
            &state,
            Some("req-unauthorized".to_string()),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "/v1/read",
            Some(audit_subject_for_presented_token("dev-token")),
        )
        .await
        .expect("log unauthorized");

        let raw = std::fs::read_to_string(&path).expect("read audit log");
        let parsed: serde_json::Value =
            serde_json::from_str(raw.lines().next().expect("audit line")).expect("parse json");
        assert_eq!(
            parsed["auth_subject"].as_str(),
            Some("sha256:c91cbbedf8c712e8e2b7517ddeca8fe4fde839ebd8339e0b2001363002b37712")
        );
        assert_eq!(parsed["error_code"].as_str(), Some("unauthorized"));
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn auth_middleware_keeps_io_permit_while_required_audit_blocks() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();

        let mut policy = ServicePolicy::default();
        policy.auth.tokens = vec![AuthToken {
            token: Some(dev_token_sha256_for_test()),
            token_env_var: None,
            allowed_workspaces: vec!["ws".to_string()],
        }];
        policy.audit.required = true;
        let state = super::super::test_state_with_policy_audit_and_auth(policy, Some(audit), false);

        let app = Router::new()
            .route("/v1/read", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::auth_middleware,
            ))
            .with_state(state.clone());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/read")
            .body(axum::body::Body::empty())
            .expect("request");
        let mut request = request;
        request
            .extensions_mut()
            .insert(super::super::layers::RequestId(
                "req-auth-unauthorized".to_string(),
            ));

        let task = tokio::spawn(async move { app.oneshot(request).await.expect("response") });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_blocked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("required audit should block unauthorized response");

        assert!(
            state
                .inner
                .io_concurrency
                .clone()
                .try_acquire_owned()
                .is_err(),
            "unauthorized required-audit path should hold the IO permit until audit wait ends"
        );

        control.release_success();
        let resp = task.await.expect("join auth middleware task");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn auth_middleware_times_out_required_audit_for_unauthorized_requests() {
        let (audit, control) =
            super::super::audit::AuditLogger::blocking_required_logger_for_test();

        let mut policy = ServicePolicy {
            limits: ServiceLimits {
                max_io_ms: 10,
                ..ServiceLimits::default()
            },
            audit: AuditPolicy {
                required: true,
                ..AuditPolicy::default()
            },
            ..ServicePolicy::default()
        };
        policy.auth.tokens = vec![AuthToken {
            token: Some(dev_token_sha256_for_test()),
            token_env_var: None,
            allowed_workspaces: vec!["ws".to_string()],
        }];
        let state = super::super::test_state_with_policy_audit_and_auth(policy, Some(audit), false);

        let app = Router::new()
            .route("/v1/read", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::auth_middleware,
            ))
            .with_state(state.clone());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/read")
            .body(axum::body::Body::empty())
            .expect("request");
        let mut request = request;
        request
            .extensions_mut()
            .insert(super::super::layers::RequestId(
                "req-auth-timeout".to_string(),
            ));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let permit = tokio::time::timeout(
            Duration::from_secs(1),
            state.inner.io_concurrency.clone().acquire_owned(),
        )
        .await
        .expect("timed-out audit should release the IO permit")
        .expect("acquire IO permit after auth audit timeout");
        drop(permit);

        control.release_success();
    }

    fn dev_token_sha256_for_test() -> String {
        format!("sha256:{}", hex::encode(hash_token_sha256("dev-token")))
    }
}
