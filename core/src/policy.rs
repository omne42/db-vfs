use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthToken {
    pub token: String,
    #[serde(default)]
    pub allowed_workspaces: Vec<String>,
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
        if self.limits.max_read_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_read_bytes must be > 0".to_string(),
            ));
        }
        if let Some(max_patch_bytes) = self.limits.max_patch_bytes
            && max_patch_bytes == 0
        {
            return Err(Error::InvalidPolicy(
                "limits.max_patch_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_write_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_write_bytes must be > 0".to_string(),
            ));
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
