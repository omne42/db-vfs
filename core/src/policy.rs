use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Error;
use crate::Result;

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
        }
    }
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
    pub token: String,
    #[serde(default)]
    pub allowed_workspaces: Vec<String>,
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthToken")
            .field("token", &"<redacted>")
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
            if rule.token.trim().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "auth.tokens[{idx}].token must be non-empty"
                )));
            }
            if rule.token.len() > 4096 {
                return Err(Error::InvalidPolicy(format!(
                    "auth.tokens[{idx}].token is too large (max 4096 bytes)"
                )));
            }
            if let Some(hex) = rule.token.strip_prefix("sha256:")
                && (hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()))
            {
                return Err(Error::InvalidPolicy(format!(
                    "auth.tokens[{idx}].token must be sha256:<64 hex chars>"
                )));
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
        Ok(())
    }
}
