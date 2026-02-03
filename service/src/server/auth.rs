use std::sync::{Arc, OnceLock};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};

use db_vfs_core::policy::VfsPolicy;

static ALLOW_ALL_WORKSPACES: OnceLock<Arc<[String]>> = OnceLock::new();

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
    Some(token)
}

pub(super) fn workspace_allowed(patterns: &[String], workspace_id: &str) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        let Some(prefix) = pattern.strip_suffix('*') else {
            return pattern == workspace_id;
        };
        workspace_id.starts_with(prefix)
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
    rules
        .iter()
        .find(|rule| constant_time_eq_32(&rule.token_sha256, &actual))
}

pub(super) async fn auth_middleware(
    State(state): State<super::AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let ctx = match &state.inner.auth {
        AuthMode::Disabled => AuthContext {
            allowed_workspaces: allow_all_workspaces(),
        },
        AuthMode::Enforced { rules } => {
            let Some(token) = parse_bearer_token(req.headers()) else {
                return super::err_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid Authorization header",
                );
            };

            let Some(rule) = match_token(rules, token) else {
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
