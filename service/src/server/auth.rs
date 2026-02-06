use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};

use db_vfs_core::policy::VfsPolicy;

static ALLOW_ALL_WORKSPACES: OnceLock<Arc<[String]>> = OnceLock::new();

const MAX_BEARER_TOKEN_BYTES: usize = 4096;

fn allow_all_workspaces() -> Arc<[String]> {
    ALLOW_ALL_WORKSPACES
        .get_or_init(|| Arc::from(vec!["*".to_string()]))
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
    allowed_workspaces: Arc<[String]>,
}

#[derive(Clone)]
pub(super) struct AuthContext {
    pub(super) allowed_workspaces: Arc<[String]>,
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
    for (idx, rule) in policy.auth.tokens.iter().enumerate() {
        let token_sha256 = if let Some(token) = rule.token.as_deref() {
            parse_token_sha256(token)?
        } else if let Some(env) = rule.token_env_var.as_deref() {
            let value = std::env::var(env).map_err(|_| {
                anyhow::anyhow!("auth token env var {env:?} is not set or not valid UTF-8")
            })?;
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("auth token env var {env:?} must be non-empty");
            }
            if value.starts_with("sha256:") {
                parse_token_sha256(value)?
            } else {
                hash_token_sha256(value)
            }
        } else {
            anyhow::bail!("auth token entry {idx} is missing token / token_env_var");
        };

        rules.push(AuthRule {
            token_sha256,
            allowed_workspaces: Arc::from(rule.allowed_workspaces.clone()),
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
    if token.len() > MAX_BEARER_TOKEN_BYTES {
        return None;
    }
    Some(token)
}

fn prefix_pattern_matches(prefix: &str, workspace_id: &str) -> bool {
    if !workspace_id.starts_with(prefix) {
        return false;
    }
    if prefix.ends_with('-') {
        return true;
    }
    workspace_id
        .as_bytes()
        .get(prefix.len())
        .is_some_and(|next| *next == b'-')
}

pub(super) fn workspace_allowed(patterns: &[String], workspace_id: &str) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return prefix_pattern_matches(prefix, workspace_id);
        }
        pattern == workspace_id
    })
}

fn hash_token_sha256(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
}

fn parse_token_sha256(token: &str) -> anyhow::Result<[u8; 32]> {
    let Some(hex) = token.strip_prefix("sha256:") else {
        anyhow::bail!("auth token must be sha256:<64 hex chars>");
    };
    let bytes = hex::decode(hex).map_err(anyhow::Error::msg)?;
    let hash: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid sha256 token hash length"))?;
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

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer a b"),
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
        assert!(workspace_allowed(&[String::from("*")], "ws"));
        assert!(workspace_allowed(&[String::from("ws")], "ws"));
        assert!(!workspace_allowed(&[String::from("ws")], "ws2"));
        assert!(workspace_allowed(&[String::from("team-*")], "team-123"));
        assert!(workspace_allowed(&[String::from("team*")], "team-123"));
        assert!(!workspace_allowed(&[String::from("team*")], "teammate"));
        assert!(!workspace_allowed(&[String::from("team-*")], "other"));
    }

    #[test]
    fn parse_sha256_token_requires_exact_length() {
        assert!(parse_token_sha256("sha256:abcd").is_err());
        assert!(parse_token_sha256("abcd").is_err());

        let ok = parse_token_sha256(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(ok.len(), 32);
    }

    #[test]
    fn build_auth_mode_allows_unsafe_no_auth_with_no_tokens() {
        let policy = VfsPolicy::default();
        let mode = build_auth_mode(&policy, true).unwrap();
        assert!(matches!(mode, AuthMode::Disabled));

        let err = build_auth_mode(&policy, false).err().expect("should fail");
        assert!(err.to_string().contains("no auth tokens configured"));
    }
}
