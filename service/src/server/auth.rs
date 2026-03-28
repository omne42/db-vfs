use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};

use db_vfs_core::policy::VfsPolicy;

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
}

#[derive(Clone)]
pub(super) struct AuthContext {
    pub(super) allowed_workspaces: Arc<[WorkspacePattern]>,
}

#[derive(Clone)]
pub(super) enum WorkspacePattern {
    Any,
    Prefix(String),
    Exact(String),
}

fn compile_workspace_patterns(patterns: &[String]) -> anyhow::Result<Arc<[WorkspacePattern]>> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        if pattern == "*" {
            compiled.push(WorkspacePattern::Any);
            continue;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.ends_with('-') && !prefix.is_empty() {
                compiled.push(WorkspacePattern::Prefix(prefix.to_string()));
                continue;
            }
            anyhow::bail!(
                "invalid auth workspace pattern {pattern:?}: trailing wildcard must be \"-*\" or exactly \"*\""
            );
        }
        compiled.push(WorkspacePattern::Exact(pattern.clone()));
    }
    Ok(Arc::from(compiled))
}

pub(super) fn build_auth_mode(
    policy: &VfsPolicy,
    unsafe_no_auth: bool,
) -> anyhow::Result<AuthMode> {
    if unsafe_no_auth {
        return Ok(AuthMode::Disabled);
    }
    if policy.auth.tokens.is_empty() {
        anyhow::bail!(
            "no auth tokens configured; set [auth.tokens] in the policy file or pass --unsafe-no-auth"
        );
    }

    let mut rules = Vec::with_capacity(policy.auth.tokens.len());
    let mut seen = HashSet::<[u8; 32]>::with_capacity(policy.auth.tokens.len());
    for (idx, rule) in policy.auth.tokens.iter().enumerate() {
        let token_sha256 = if let Some(token) = rule.token.as_deref() {
            parse_token_sha256(token)?
        } else if let Some(env) = rule.token_env_var.as_deref() {
            let value = std::env::var(env).map_err(|_| {
                anyhow::anyhow!("auth token env var {env:?} is not set or not valid UTF-8")
            })?;
            if value.is_empty() {
                anyhow::bail!("auth token env var {env:?} must be non-empty");
            }
            if value.starts_with("sha256:") {
                parse_token_sha256(&value)?
            } else {
                hash_plaintext_token_sha256(&value, &format!("auth token env var {env:?}"))?
            }
        } else {
            anyhow::bail!("auth token entry {idx} is missing token / token_env_var");
        };

        if !seen.insert(token_sha256) {
            anyhow::bail!("auth token entry {idx} duplicates a previous token hash");
        }

        rules.push(AuthRule {
            token_sha256,
            allowed_workspaces: compile_workspace_patterns(&rule.allowed_workspaces)?,
        });
    }

    Ok(AuthMode::Enforced {
        rules: Arc::from(rules),
    })
}

fn parse_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if !is_valid_bearer_token(token) {
        return None;
    }
    Some(token)
}

fn prefix_pattern_matches(prefix: &str, workspace_id: &str) -> bool {
    workspace_id.starts_with(prefix)
}

pub(super) fn workspace_allowed(patterns: &[WorkspacePattern], workspace_id: &str) -> bool {
    patterns.iter().any(|pattern| match pattern {
        WorkspacePattern::Any => true,
        WorkspacePattern::Prefix(prefix) => prefix_pattern_matches(prefix, workspace_id),
        WorkspacePattern::Exact(exact) => exact == workspace_id,
    })
}

fn hash_token_sha256(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
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

fn log_unauthorized(state: &super::AppState, req: &Request, peer_ip: Option<std::net::IpAddr>) {
    if let Some(audit) = state.inner.audit.as_ref()
        && let Some(op) = super::audit::op_from_path(req.uri().path())
        && let Some(request_id) = req
            .extensions()
            .get::<super::layers::RequestId>()
            .map(|v| v.0.clone())
    {
        audit.log(super::audit::minimal_event(
            request_id,
            peer_ip,
            op,
            StatusCode::UNAUTHORIZED.as_u16(),
            Some("unauthorized"),
        ));
    }
}

pub(super) async fn auth_middleware(
    State(state): State<super::AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let ctx = match &state.inner.auth {
        AuthMode::Disabled => AuthContext {
            allowed_workspaces: allow_all_workspaces(),
        },
        AuthMode::Enforced { rules } => {
            let Some(token) = parse_bearer_token(req.headers()) else {
                log_unauthorized(&state, &req, peer_ip);
                return super::err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid Authorization header",
                );
            };

            let Some(rule) = match_token(rules, token) else {
                log_unauthorized(&state, &req, peer_ip);
                return super::err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "invalid token",
                );
            };

            AuthContext {
                allowed_workspaces: rule.allowed_workspaces.clone(),
            }
        }
    };

    req.extensions_mut().insert(ctx);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::HeaderValue;
    use db_vfs_core::policy::AuthToken;

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
            "other"
        ));
    }

    #[test]
    fn compile_workspace_patterns_rejects_invalid_wildcards() {
        let err = compile_workspace_patterns(&[String::from("team*")])
            .err()
            .expect("invalid wildcard pattern should fail");
        assert!(err.to_string().contains("trailing wildcard must be"));
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
        let policy = VfsPolicy::default();
        let mode = build_auth_mode(&policy, true).unwrap();
        assert!(matches!(mode, AuthMode::Disabled));

        let err = build_auth_mode(&policy, false).err().expect("should fail");
        assert!(err.to_string().contains("no auth tokens configured"));
    }

    #[test]
    fn build_auth_mode_rejects_duplicate_token_hashes() {
        let mut policy = VfsPolicy::default();
        let token = format!("sha256:{}", "a".repeat(64));
        policy.auth.tokens = vec![
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

        let mut policy = VfsPolicy::default();
        policy.auth.tokens = vec![AuthToken {
            token: None,
            token_env_var: Some(var.clone()),
            allowed_workspaces: vec!["ws".to_string()],
        }];

        // SAFETY: test-only scoped environment mutation.
        unsafe { std::env::set_var(&var, token) };
        let err = build_auth_mode(&policy, false)
            .err()
            .expect("whitespace-bearing env token should be rejected");
        // SAFETY: test-only scoped environment mutation.
        unsafe { std::env::remove_var(&var) };
        assert!(err.to_string().contains("valid HTTP Bearer token"));
    }

    #[test]
    fn build_auth_mode_hashes_env_backed_plaintext_token() {
        let var = format!("DB_VFS_TEST_TOKEN_OK_{}", std::process::id());
        let token = "dev-token";
        let digest = format!("sha256:{}", hex::encode(hash_token_sha256(token)));

        let mut policy = VfsPolicy::default();
        policy.auth.tokens = vec![AuthToken {
            token: None,
            token_env_var: Some(var.clone()),
            allowed_workspaces: vec!["ws".to_string()],
        }];

        // SAFETY: test-only scoped environment mutation.
        unsafe { std::env::set_var(&var, token) };
        let mode = build_auth_mode(&policy, false).expect("build auth mode");
        // SAFETY: test-only scoped environment mutation.
        unsafe { std::env::remove_var(&var) };

        let AuthMode::Enforced { rules } = mode else {
            panic!("expected enforced auth mode");
        };
        assert_eq!(rules.len(), 1);
        assert!(constant_time_eq_32(
            &rules[0].token_sha256,
            &parse_token_sha256(&digest).unwrap()
        ));
    }
}
