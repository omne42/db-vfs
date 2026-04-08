use std::fmt;

use db_vfs_core::policy::{
    Limits as VfsLimits, Permissions, SecretRules, TraversalRules, ValidatedVfsPolicy, VfsPolicy,
};
use db_vfs_core::workspace_pattern::AllowedWorkspacePattern;
use db_vfs_core::{Error, Result};
use omne_integrity_primitives::parse_sha256_digest;
use serde::{Deserialize, Serialize};

const MAX_AUDIT_JSONL_PATH_BYTES: usize = 4096;
const MAX_AUDIT_FLUSH_EVERY_EVENTS: usize = 65_536;
const MAX_AUDIT_FLUSH_MAX_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_read_bytes: u64,
    pub max_patch_bytes: Option<u64>,
    pub max_write_bytes: u64,
    pub max_results: usize,
    pub max_walk_entries: usize,
    pub max_walk_files: usize,
    pub max_walk_ms: Option<u64>,
    pub max_line_bytes: usize,
    pub max_io_ms: u64,
    pub max_concurrency_io: usize,
    pub max_concurrency_scan: usize,
    #[serde(default = "default_max_db_connections")]
    pub max_db_connections: u32,
    #[serde(default = "default_max_requests_per_ip_per_sec")]
    pub max_requests_per_ip_per_sec: u32,
    #[serde(default = "default_max_requests_burst_per_ip")]
    pub max_requests_burst_per_ip: u32,
    #[serde(default = "default_max_rate_limit_ips")]
    pub max_rate_limit_ips: u32,
}

const fn default_max_db_connections() -> u32 {
    16
}

const fn default_max_requests_per_ip_per_sec() -> u32 {
    100
}

const fn default_max_requests_burst_per_ip() -> u32 {
    200
}

const fn default_max_rate_limit_ips() -> u32 {
    65_536
}

impl Default for Limits {
    fn default() -> Self {
        let vfs = VfsLimits::default();
        Self {
            max_read_bytes: vfs.max_read_bytes,
            max_patch_bytes: vfs.max_patch_bytes,
            max_write_bytes: vfs.max_write_bytes,
            max_results: vfs.max_results,
            max_walk_entries: vfs.max_walk_entries,
            max_walk_files: vfs.max_walk_files,
            max_walk_ms: vfs.max_walk_ms,
            max_line_bytes: vfs.max_line_bytes,
            max_io_ms: vfs.max_io_ms,
            max_concurrency_io: vfs.max_concurrency_io,
            max_concurrency_scan: vfs.max_concurrency_scan,
            max_db_connections: default_max_db_connections(),
            max_requests_per_ip_per_sec: default_max_requests_per_ip_per_sec(),
            max_requests_burst_per_ip: default_max_requests_burst_per_ip(),
            max_rate_limit_ips: default_max_rate_limit_ips(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthPolicy {
    #[serde(default)]
    pub tokens: Vec<AuthToken>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env_var: Option<String>,
    #[serde(default)]
    pub allowed_workspaces: Vec<String>,
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthToken")
            .field(
                "token",
                &self.token.as_ref().map_or("<none>", |_| "<redacted>"),
            )
            .field("token_env_var", &self.token_env_var)
            .field("allowed_workspaces", &self.allowed_workspaces)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonl_path: Option<String>,
    #[serde(default = "default_audit_required")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_every_events: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_max_interval_ms: Option<u64>,
}

const fn default_audit_required() -> bool {
    true
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            jsonl_path: None,
            required: default_audit_required(),
            flush_every_events: None,
            flush_max_interval_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicy {
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub secrets: SecretRules,
    #[serde(default)]
    pub traversal: TraversalRules,
    #[serde(default)]
    pub audit: AuditPolicy,
    #[serde(default)]
    pub auth: AuthPolicy,
}

impl ServicePolicy {
    pub fn vfs_policy(&self) -> VfsPolicy {
        VfsPolicy {
            permissions: self.permissions.clone(),
            limits: self.limits.vfs_limits(),
            secrets: self.secrets.clone(),
            traversal: self.traversal.clone(),
        }
    }

    pub fn validated_vfs_policy(&self) -> Result<ValidatedVfsPolicy> {
        let validated = ValidatedVfsPolicy::new(self.vfs_policy())?;
        validate_limits(&self.limits)?;
        validate_auth(&self.auth)?;
        validate_audit(&self.audit)?;
        Ok(validated)
    }

    pub fn validate(&self) -> Result<()> {
        self.validated_vfs_policy().map(|_| ())
    }
}

impl Limits {
    pub fn vfs_limits(&self) -> VfsLimits {
        VfsLimits {
            max_read_bytes: self.max_read_bytes,
            max_patch_bytes: self.max_patch_bytes,
            max_write_bytes: self.max_write_bytes,
            max_results: self.max_results,
            max_walk_entries: self.max_walk_entries,
            max_walk_files: self.max_walk_files,
            max_walk_ms: self.max_walk_ms,
            max_line_bytes: self.max_line_bytes,
            max_io_ms: self.max_io_ms,
            max_concurrency_io: self.max_concurrency_io,
            max_concurrency_scan: self.max_concurrency_scan,
        }
    }
}

pub type ServiceLimits = Limits;

fn validate_limits(limits: &Limits) -> Result<()> {
    if limits.max_db_connections == 0 {
        return Err(Error::InvalidPolicy(
            "limits.max_db_connections must be > 0".to_string(),
        ));
    }
    if limits.max_db_connections > 1024 {
        return Err(Error::InvalidPolicy(
            "limits.max_db_connections is too large (max 1024)".to_string(),
        ));
    }

    if limits.max_requests_per_ip_per_sec == 0 {
        if limits.max_requests_burst_per_ip != 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_requests_burst_per_ip must be 0 when max_requests_per_ip_per_sec is 0"
                    .to_string(),
            ));
        }
    } else {
        if limits.max_requests_burst_per_ip == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_requests_burst_per_ip must be > 0 when max_requests_per_ip_per_sec is enabled"
                    .to_string(),
            ));
        }
        if limits.max_requests_burst_per_ip < limits.max_requests_per_ip_per_sec {
            return Err(Error::InvalidPolicy(
                "limits.max_requests_burst_per_ip must be >= max_requests_per_ip_per_sec"
                    .to_string(),
            ));
        }
        if limits.max_rate_limit_ips == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_rate_limit_ips must be > 0 when max_requests_per_ip_per_sec is enabled"
                    .to_string(),
            ));
        }
        if limits.max_rate_limit_ips > 1_000_000 {
            return Err(Error::InvalidPolicy(
                "limits.max_rate_limit_ips is too large (max 1000000)".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_auth(auth: &AuthPolicy) -> Result<()> {
    if auth.tokens.len() > 256 {
        return Err(Error::InvalidPolicy(
            "auth.tokens has too many entries (max 256)".to_string(),
        ));
    }
    for (idx, rule) in auth.tokens.iter().enumerate() {
        match (&rule.token, &rule.token_env_var) {
            (Some(_), Some(_)) => {
                return Err(Error::InvalidPolicy(format!(
                    "auth.tokens[{idx}] must set exactly one of token or token_env_var"
                )));
            }
            (None, None) => {
                return Err(Error::InvalidPolicy(format!(
                    "auth.tokens[{idx}] must set token or token_env_var"
                )));
            }
            (Some(token), None) => {
                if token.trim().is_empty() {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token must be non-empty"
                    )));
                }
                if token.len() > 4096 {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token is too large (max 4096 bytes)"
                    )));
                }
                let Some(hex) = token.strip_prefix("sha256:") else {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token must be sha256:<64 hex chars> (use token_env_var for plaintext tokens)"
                    )));
                };
                if token != token.trim()
                    || hex.len() != 64
                    || parse_sha256_digest(Some(token)).is_none()
                {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token must be sha256:<64 hex chars>"
                    )));
                }
            }
            (None, Some(env)) => {
                if env.trim().is_empty() {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token_env_var must be non-empty"
                    )));
                }
                if env.len() > 128 {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token_env_var is too large (max 128 bytes)"
                    )));
                }
                let mut chars = env.chars();
                let Some(first) = chars.next() else {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token_env_var must be non-empty"
                    )));
                };
                if !(first.is_ascii_alphabetic() || first == '_') {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token_env_var must start with [A-Za-z_]"
                    )));
                }
                if chars.any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].token_env_var must contain only [A-Za-z0-9_]"
                    )));
                }
            }
        }

        if rule.allowed_workspaces.is_empty() {
            return Err(Error::InvalidPolicy(format!(
                "auth.tokens[{idx}].allowed_workspaces must be non-empty (use \"*\" to allow all)"
            )));
        }
        if rule.allowed_workspaces.len() > 1024 {
            return Err(Error::InvalidPolicy(format!(
                "auth.tokens[{idx}].allowed_workspaces has too many entries (max 1024)"
            )));
        }
        for (j, pattern) in rule.allowed_workspaces.iter().enumerate() {
            AllowedWorkspacePattern::parse(pattern).map_err(|err| {
                Error::InvalidPolicy(format!("auth.tokens[{idx}].allowed_workspaces[{j}] {err}"))
            })?;
        }
    }

    Ok(())
}

fn validate_audit(audit: &AuditPolicy) -> Result<()> {
    if let Some(path) = audit.jsonl_path.as_deref() {
        if path.trim().is_empty() {
            return Err(Error::InvalidPolicy(
                "audit.jsonl_path must be non-empty when set".to_string(),
            ));
        }
        if path != path.trim() {
            return Err(Error::InvalidPolicy(
                "audit.jsonl_path must not have leading or trailing whitespace".to_string(),
            ));
        }
        if path.len() > MAX_AUDIT_JSONL_PATH_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "audit.jsonl_path is too large ({} bytes; max {} bytes)",
                path.len(),
                MAX_AUDIT_JSONL_PATH_BYTES
            )));
        }
        if path.contains('\0') {
            return Err(Error::InvalidPolicy(
                "audit.jsonl_path must not contain NUL bytes".to_string(),
            ));
        }
        if path.chars().any(char::is_control) {
            return Err(Error::InvalidPolicy(
                "audit.jsonl_path must not contain control characters".to_string(),
            ));
        }
    }

    if audit.jsonl_path.is_none() {
        let mut fields = Vec::new();
        if audit.flush_every_events.is_some() {
            fields.push("audit.flush_every_events");
        }
        if audit.flush_max_interval_ms.is_some() {
            fields.push("audit.flush_max_interval_ms");
        }
        if !fields.is_empty() {
            return Err(Error::InvalidPolicy(format!(
                "{} requires audit.jsonl_path to be set",
                fields.join(" and ")
            )));
        }
    }

    if let Some(flush_every_events) = audit.flush_every_events {
        if flush_every_events == 0 {
            return Err(Error::InvalidPolicy(
                "audit.flush_every_events must be > 0 when set".to_string(),
            ));
        }
        if flush_every_events > MAX_AUDIT_FLUSH_EVERY_EVENTS {
            return Err(Error::InvalidPolicy(format!(
                "audit.flush_every_events is too large (max {})",
                MAX_AUDIT_FLUSH_EVERY_EVENTS
            )));
        }
    }

    if let Some(flush_max_interval_ms) = audit.flush_max_interval_ms {
        if flush_max_interval_ms == 0 {
            return Err(Error::InvalidPolicy(
                "audit.flush_max_interval_ms must be > 0 when set".to_string(),
            ));
        }
        if flush_max_interval_ms > MAX_AUDIT_FLUSH_MAX_INTERVAL_MS {
            return Err(Error::InvalidPolicy(format!(
                "audit.flush_max_interval_ms is too large (max {} ms)",
                MAX_AUDIT_FLUSH_MAX_INTERVAL_MS
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_policy_preserves_vfs_policy_projection() {
        let mut policy = ServicePolicy::default();
        policy.permissions.read = true;
        policy.limits.max_walk_ms = Some(123);
        policy.secrets.deny_globs = vec![".env".to_string()];
        policy.traversal.skip_globs = vec!["target/**".to_string()];

        let vfs = policy.vfs_policy();
        assert!(vfs.permissions.read);
        assert_eq!(vfs.limits.max_walk_ms, Some(123));
        assert_eq!(vfs.secrets.deny_globs, vec![".env"]);
        assert_eq!(vfs.traversal.skip_globs, vec!["target/**"]);
    }

    #[test]
    fn validate_rejects_invalid_rate_limit_shape() {
        let mut policy = ServicePolicy::default();
        policy.limits.max_requests_per_ip_per_sec = 5;
        policy.limits.max_requests_burst_per_ip = 0;

        let err = policy.validate().expect_err("policy should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_invalid_auth_pattern() {
        let mut policy = ServicePolicy::default();
        policy.auth.tokens = vec![AuthToken {
            token: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            ),
            token_env_var: None,
            allowed_workspaces: vec!["team*prod".to_string()],
        }];

        let err = policy.validate().expect_err("policy should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_auth_pattern_whitespace_via_core_parser() {
        let mut policy = ServicePolicy::default();
        policy.auth.tokens = vec![AuthToken {
            token: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            ),
            token_env_var: None,
            allowed_workspaces: vec!["team a".to_string()],
        }];

        let err = policy.validate().expect_err("policy should fail");
        assert_eq!(err.code(), "invalid_policy");
        assert!(err.to_string().contains("must not contain whitespace"));
    }

    #[test]
    fn validate_rejects_audit_flush_without_path() {
        let mut policy = ServicePolicy::default();
        policy.audit.flush_every_events = Some(1);

        let err = policy.validate().expect_err("policy should fail");
        assert_eq!(err.code(), "invalid_policy");
    }
}
