use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Error;
use crate::Result;

const MAX_GLOB_PATTERN_BYTES: usize = 4096;
const MAX_SECRET_DENY_GLOBS: usize = 4096;
const MAX_TRAVERSAL_SKIP_GLOBS: usize = 4096;
const MAX_SECRET_REPLACEMENT_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub glob: bool,
    #[serde(default)]
    pub grep: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub patch: bool,
    #[serde(default)]
    pub delete: bool,
    /// Allow `path_prefix = ""` (scan the full workspace) for `glob` and `grep`.
    #[serde(default)]
    pub allow_full_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    #[serde(default = "default_max_write_bytes")]
    pub max_write_bytes: u64,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    #[serde(default = "default_max_walk_entries")]
    pub max_walk_entries: usize,
    #[serde(default = "default_max_walk_files")]
    pub max_walk_files: usize,
    #[serde(default)]
    pub max_walk_ms: Option<u64>,
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
    /// Wall-clock budget for non-scan requests (read/write/patch/delete), in milliseconds.
    #[serde(default = "default_max_io_ms")]
    pub max_io_ms: u64,
    /// Max in-flight non-scan requests (read/write/patch/delete).
    #[serde(default = "default_max_concurrency_io")]
    pub max_concurrency_io: usize,
    /// Max in-flight scan requests (glob/grep).
    #[serde(default = "default_max_concurrency_scan")]
    pub max_concurrency_scan: usize,
    /// Max DB connections in the service pool.
    #[serde(default = "default_max_db_connections")]
    pub max_db_connections: u32,
    /// Optional per-IP request rate limit (requests/second).
    ///
    /// - `0` disables rate limiting.
    #[serde(default = "default_max_requests_per_ip_per_sec")]
    pub max_requests_per_ip_per_sec: u32,
    /// Optional per-IP request burst capacity (requests).
    ///
    /// - Must be > 0 when `max_requests_per_ip_per_sec > 0`.
    /// - `0` disables rate limiting (must match `max_requests_per_ip_per_sec = 0`).
    #[serde(default = "default_max_requests_burst_per_ip")]
    pub max_requests_burst_per_ip: u32,
    /// Max number of distinct IPs tracked by the per-IP rate limiter.
    ///
    /// When `max_requests_per_ip_per_sec > 0`, this must be > 0.
    #[serde(default = "default_max_rate_limit_ips")]
    pub max_rate_limit_ips: u32,
}

const fn default_max_read_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_write_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_results() -> usize {
    2000
}

const fn default_max_walk_entries() -> usize {
    500_000
}

const fn default_max_walk_files() -> usize {
    200_000
}

const fn default_max_line_bytes() -> usize {
    4096
}

const fn default_max_io_ms() -> u64 {
    30_000
}

const fn default_max_concurrency_io() -> usize {
    16
}

const fn default_max_concurrency_scan() -> usize {
    8
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
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_patch_bytes: None,
            max_write_bytes: default_max_write_bytes(),
            max_results: default_max_results(),
            max_walk_entries: default_max_walk_entries(),
            max_walk_files: default_max_walk_files(),
            max_walk_ms: None,
            max_line_bytes: default_max_line_bytes(),
            max_io_ms: default_max_io_ms(),
            max_concurrency_io: default_max_concurrency_io(),
            max_concurrency_scan: default_max_concurrency_scan(),
            max_db_connections: default_max_db_connections(),
            max_requests_per_ip_per_sec: default_max_requests_per_ip_per_sec(),
            max_requests_burst_per_ip: default_max_requests_burst_per_ip(),
            max_rate_limit_ips: default_max_rate_limit_ips(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TraversalRules {
    /// Glob patterns that should be skipped during scan traversal (`glob`/`grep`) for performance.
    ///
    /// Unlike `secrets.deny_globs`, this does **not** deny direct access to the path.
    #[serde(default)]
    pub skip_globs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRules {
    #[serde(default = "default_secret_deny_globs")]
    pub deny_globs: Vec<String>,
    #[serde(default)]
    pub redact_regexes: Vec<String>,
    #[serde(default = "default_redaction_replacement")]
    pub replacement: String,
}

fn default_secret_deny_globs() -> Vec<String> {
    vec![
        ".git/**".to_string(),
        "**/.git/**".to_string(),
        ".env".to_string(),
        ".env.*".to_string(),
        "**/.env".to_string(),
        "**/.env.*".to_string(),
        ".envrc".to_string(),
        "**/.envrc".to_string(),
        ".direnv/**".to_string(),
        "**/.direnv/**".to_string(),
        ".ssh/**".to_string(),
        "**/.ssh/**".to_string(),
        ".aws/**".to_string(),
        "**/.aws/**".to_string(),
        ".kube/**".to_string(),
        "**/.kube/**".to_string(),
        ".npmrc".to_string(),
        "**/.npmrc".to_string(),
        ".netrc".to_string(),
        "**/.netrc".to_string(),
        ".pypirc".to_string(),
        "**/.pypirc".to_string(),
        ".cargo/credentials".to_string(),
        "**/.cargo/credentials".to_string(),
        ".docker/config.json".to_string(),
        "**/.docker/config.json".to_string(),
        ".omne_agent_data/**".to_string(),
        "**/.omne_agent_data/**".to_string(),
    ]
}

fn default_redaction_replacement() -> String {
    "***REDACTED***".to_string()
}

impl Default for SecretRules {
    fn default() -> Self {
        Self {
            deny_globs: default_secret_deny_globs(),
            redact_regexes: Vec::new(),
            replacement: default_redaction_replacement(),
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
                &self
                    .token
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("<none>"),
            )
            .field("token_env_var", &self.token_env_var)
            .field("allowed_workspaces", &self.allowed_workspaces)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VfsPolicy {
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub secrets: SecretRules,
    #[serde(default)]
    pub traversal: TraversalRules,
    #[serde(default)]
    pub auth: AuthPolicy,
}

impl VfsPolicy {
    pub fn validate(&self) -> Result<()> {
        const MAX_REQUEST_BYTES: u64 = 256 * 1024 * 1024;

        if self.limits.max_read_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_read_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_read_bytes > MAX_REQUEST_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_read_bytes is too large (max {} bytes)",
                MAX_REQUEST_BYTES
            )));
        }
        if let Some(max_patch_bytes) = self.limits.max_patch_bytes
            && max_patch_bytes == 0
        {
            return Err(Error::InvalidPolicy(
                "limits.max_patch_bytes must be > 0".to_string(),
            ));
        }
        if let Some(max_patch_bytes) = self.limits.max_patch_bytes
            && max_patch_bytes > MAX_REQUEST_BYTES
        {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_patch_bytes is too large (max {} bytes)",
                MAX_REQUEST_BYTES
            )));
        }
        if self.limits.max_write_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_write_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_write_bytes > MAX_REQUEST_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_write_bytes is too large (max {} bytes)",
                MAX_REQUEST_BYTES
            )));
        }
        if self.limits.max_results == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_results must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_files == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_files must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_entries == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_entries must be > 0".to_string(),
            ));
        }
        if self.limits.max_line_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_line_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_io_ms == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_io_ms must be > 0".to_string(),
            ));
        }
        if self.limits.max_concurrency_io == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_concurrency_io must be > 0".to_string(),
            ));
        }
        if self.limits.max_concurrency_scan == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_concurrency_scan must be > 0".to_string(),
            ));
        }
        if self.limits.max_db_connections == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_db_connections must be > 0".to_string(),
            ));
        }
        if self.limits.max_db_connections > 1024 {
            return Err(Error::InvalidPolicy(
                "limits.max_db_connections is too large (max 1024)".to_string(),
            ));
        }

        if self.auth.tokens.len() > 256 {
            return Err(Error::InvalidPolicy(
                "auth.tokens has too many entries (max 256)".to_string(),
            ));
        }
        for (idx, rule) in self.auth.tokens.iter().enumerate() {
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
                    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
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
                if pattern.trim().is_empty() {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].allowed_workspaces[{j}] must be non-empty"
                    )));
                }
                if pattern.chars().any(|ch| ch.is_whitespace()) {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].allowed_workspaces[{j}] must not contain whitespace"
                    )));
                }
                if pattern != "*" && pattern.contains('*') && !pattern.ends_with('*') {
                    return Err(Error::InvalidPolicy(format!(
                        "auth.tokens[{idx}].allowed_workspaces[{j}] only supports '*' as a full wildcard or a trailing '*' prefix"
                    )));
                }
            }
        }

        if self.limits.max_requests_per_ip_per_sec == 0 {
            if self.limits.max_requests_burst_per_ip != 0 {
                return Err(Error::InvalidPolicy(
                    "limits.max_requests_burst_per_ip must be 0 when max_requests_per_ip_per_sec is 0"
                        .to_string(),
                ));
            }
        } else {
            if self.limits.max_requests_burst_per_ip == 0 {
                return Err(Error::InvalidPolicy(
                    "limits.max_requests_burst_per_ip must be > 0 when max_requests_per_ip_per_sec is enabled"
                        .to_string(),
                ));
            }
            if self.limits.max_requests_burst_per_ip < self.limits.max_requests_per_ip_per_sec {
                return Err(Error::InvalidPolicy(
                    "limits.max_requests_burst_per_ip must be >= max_requests_per_ip_per_sec"
                        .to_string(),
                ));
            }
            if self.limits.max_rate_limit_ips == 0 {
                return Err(Error::InvalidPolicy(
                    "limits.max_rate_limit_ips must be > 0 when max_requests_per_ip_per_sec is enabled"
                        .to_string(),
                ));
            }
            if self.limits.max_rate_limit_ips > 1_000_000 {
                return Err(Error::InvalidPolicy(
                    "limits.max_rate_limit_ips is too large (max 1000000)".to_string(),
                ));
            }
        }

        if self.secrets.replacement.len() > MAX_SECRET_REPLACEMENT_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "secrets.replacement is too large ({} bytes; max {} bytes)",
                self.secrets.replacement.len(),
                MAX_SECRET_REPLACEMENT_BYTES
            )));
        }

        if self.secrets.deny_globs.len() > MAX_SECRET_DENY_GLOBS {
            return Err(Error::InvalidPolicy(format!(
                "secrets.deny_globs has too many entries ({} > {})",
                self.secrets.deny_globs.len(),
                MAX_SECRET_DENY_GLOBS
            )));
        }
        for (idx, pattern) in self.secrets.deny_globs.iter().enumerate() {
            if pattern.len() > MAX_GLOB_PATTERN_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "secrets.deny_globs[{idx}] is too large ({} bytes; max {} bytes)",
                    pattern.len(),
                    MAX_GLOB_PATTERN_BYTES
                )));
            }
        }

        if self.traversal.skip_globs.len() > MAX_TRAVERSAL_SKIP_GLOBS {
            return Err(Error::InvalidPolicy(format!(
                "traversal.skip_globs has too many entries ({} > {})",
                self.traversal.skip_globs.len(),
                MAX_TRAVERSAL_SKIP_GLOBS
            )));
        }
        for (idx, pattern) in self.traversal.skip_globs.iter().enumerate() {
            if pattern.len() > MAX_GLOB_PATTERN_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "traversal.skip_globs[{idx}] is too large ({} bytes; max {} bytes)",
                    pattern.len(),
                    MAX_GLOB_PATTERN_BYTES
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_large_secrets_replacement() {
        let mut policy = VfsPolicy::default();
        policy.secrets.replacement = "x".repeat(MAX_SECRET_REPLACEMENT_BYTES + 1);
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_many_deny_globs() {
        let mut policy = VfsPolicy::default();
        policy.secrets.deny_globs = vec!["a".to_string(); MAX_SECRET_DENY_GLOBS + 1];
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_long_deny_glob_pattern() {
        let mut policy = VfsPolicy::default();
        policy.secrets.deny_globs = vec!["a".repeat(MAX_GLOB_PATTERN_BYTES + 1)];
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_many_traversal_skip_globs() {
        let mut policy = VfsPolicy::default();
        policy.traversal.skip_globs = vec!["a".to_string(); MAX_TRAVERSAL_SKIP_GLOBS + 1];
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }
}
