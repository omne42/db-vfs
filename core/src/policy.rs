use serde::{Deserialize, Serialize};

use crate::Error;
use crate::Result;
use crate::redaction::SecretRedactor;
use crate::traversal::TraversalSkipper;

const MAX_GLOB_PATTERN_BYTES: usize = 4096;
const MAX_SECRET_DENY_GLOBS: usize = 4096;
const MAX_TRAVERSAL_SKIP_GLOBS: usize = 4096;
const MAX_SECRET_REPLACEMENT_BYTES: usize = 4096;
const MAX_LIMIT_MAX_RESULTS: usize = 100_000;
const MAX_LIMIT_MAX_WALK_FILES: usize = 500_000;
const MAX_LIMIT_MAX_WALK_ENTRIES: usize = 1_000_000;
const MAX_LIMIT_MAX_WALK_MS: u64 = 600_000;
// Keep in sync with backend session-timeout contracts (SQLite busy_timeout / Postgres statement_timeout).
const MAX_LIMIT_MAX_IO_MS: u64 = i32::MAX as u64;
const MAX_LIMIT_MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_SCAN_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
// Keep in sync with `core::path::normalize_path_inner` max path bytes.
const MAX_NORMALIZED_PATH_BYTES: usize = 4096;
const MAX_REDACT_REGEXES: usize = 128;
const MAX_REDACT_REGEX_PATTERN_BYTES: usize = 4096;

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
    #[serde(default = "default_max_walk_ms")]
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

const fn default_max_walk_ms() -> Option<u64> {
    Some(2_000)
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

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_patch_bytes: None,
            max_write_bytes: default_max_write_bytes(),
            max_results: default_max_results(),
            max_walk_entries: default_max_walk_entries(),
            max_walk_files: default_max_walk_files(),
            max_walk_ms: default_max_walk_ms(),
            max_line_bytes: default_max_line_bytes(),
            max_io_ms: default_max_io_ms(),
            max_concurrency_io: default_max_concurrency_io(),
            max_concurrency_scan: default_max_concurrency_scan(),
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
pub struct VfsPolicy {
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub secrets: SecretRules,
    #[serde(default)]
    pub traversal: TraversalRules,
}

/// A [`VfsPolicy`] that has passed [`VfsPolicy::validate`].
///
/// This guarantees the structural validation enforced by `VfsPolicy::validate()` (permissions,
/// core VFS limits, and secret/traversal rules) *and* that policy-derived secret/traversal
/// matchers can be built. That keeps constructor families such as `DbVfs::new_validated()` and
/// `DbVfs::new_with_supplied_matchers_validated()` aligned on the same invariant.
#[derive(Debug, Clone)]
pub struct ValidatedVfsPolicy(VfsPolicy);

impl ValidatedVfsPolicy {
    pub fn new(policy: VfsPolicy) -> Result<Self> {
        policy.validate()?;
        SecretRedactor::from_rules(&policy.secrets)?;
        TraversalSkipper::from_rules(&policy.traversal)?;
        Ok(Self(policy))
    }

    pub fn into_inner(self) -> VfsPolicy {
        self.0
    }
}

impl std::ops::Deref for ValidatedVfsPolicy {
    type Target = VfsPolicy;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<VfsPolicy> for ValidatedVfsPolicy {
    fn as_ref(&self) -> &VfsPolicy {
        &self.0
    }
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
        if self.limits.max_results > MAX_LIMIT_MAX_RESULTS {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_results is too large (max {})",
                MAX_LIMIT_MAX_RESULTS
            )));
        }
        if self.limits.max_walk_files == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_files must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_files > MAX_LIMIT_MAX_WALK_FILES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_walk_files is too large (max {})",
                MAX_LIMIT_MAX_WALK_FILES
            )));
        }
        if self.limits.max_walk_entries == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_entries must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_entries > MAX_LIMIT_MAX_WALK_ENTRIES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_walk_entries is too large (max {})",
                MAX_LIMIT_MAX_WALK_ENTRIES
            )));
        }
        if self.limits.max_line_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_line_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_line_bytes > MAX_LIMIT_MAX_LINE_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_line_bytes is too large (max {})",
                MAX_LIMIT_MAX_LINE_BYTES
            )));
        }
        let glob_response_budget = self
            .limits
            .max_results
            .checked_mul(MAX_NORMALIZED_PATH_BYTES)
            .ok_or_else(|| {
                Error::InvalidPolicy(
                    "limits.max_results * path_max_bytes overflows usize".to_string(),
                )
            })?;
        if glob_response_budget > MAX_SCAN_RESPONSE_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_results * path_max_bytes is too large ({} bytes; max {} bytes)",
                glob_response_budget, MAX_SCAN_RESPONSE_BYTES
            )));
        }

        let grep_entry_max_bytes = self
            .limits
            .max_line_bytes
            .checked_add(MAX_NORMALIZED_PATH_BYTES)
            .ok_or_else(|| {
                Error::InvalidPolicy(
                    "limits.max_line_bytes + path_max_bytes overflows usize".to_string(),
                )
            })?;
        let grep_response_budget = self
            .limits
            .max_results
            .checked_mul(grep_entry_max_bytes)
            .ok_or_else(|| {
                Error::InvalidPolicy(
                    "limits.max_results * (limits.max_line_bytes + path_max_bytes) overflows usize"
                        .to_string(),
                )
            })?;
        if grep_response_budget > MAX_SCAN_RESPONSE_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_results * (limits.max_line_bytes + path_max_bytes) is too large ({} bytes; max {} bytes)",
                grep_response_budget, MAX_SCAN_RESPONSE_BYTES
            )));
        }
        if let Some(max_walk_ms) = self.limits.max_walk_ms {
            if max_walk_ms == 0 {
                return Err(Error::InvalidPolicy(
                    "limits.max_walk_ms must be > 0 when set".to_string(),
                ));
            }
            if max_walk_ms > MAX_LIMIT_MAX_WALK_MS {
                return Err(Error::InvalidPolicy(format!(
                    "limits.max_walk_ms is too large (max {} ms)",
                    MAX_LIMIT_MAX_WALK_MS
                )));
            }
        }
        if self.limits.max_io_ms == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_io_ms must be > 0".to_string(),
            ));
        }
        if self.limits.max_io_ms > MAX_LIMIT_MAX_IO_MS {
            return Err(Error::InvalidPolicy(format!(
                "limits.max_io_ms is too large (max {} ms)",
                MAX_LIMIT_MAX_IO_MS
            )));
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
        if self.secrets.replacement.len() > MAX_SECRET_REPLACEMENT_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "secrets.replacement is too large ({} bytes; max {} bytes)",
                self.secrets.replacement.len(),
                MAX_SECRET_REPLACEMENT_BYTES
            )));
        }
        if self.secrets.replacement.chars().any(char::is_control) {
            return Err(Error::InvalidPolicy(
                "secrets.replacement must not contain control characters".to_string(),
            ));
        }

        if self.secrets.redact_regexes.len() > MAX_REDACT_REGEXES {
            return Err(Error::InvalidPolicy(format!(
                "secrets.redact_regexes has too many entries ({} > {})",
                self.secrets.redact_regexes.len(),
                MAX_REDACT_REGEXES
            )));
        }
        for (idx, pattern) in self.secrets.redact_regexes.iter().enumerate() {
            if pattern.len() > MAX_REDACT_REGEX_PATTERN_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "secrets.redact_regexes[{idx}] is too large ({} bytes; max {} bytes)",
                    pattern.len(),
                    MAX_REDACT_REGEX_PATTERN_BYTES
                )));
            }
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
    use serde_json::json;

    #[test]
    fn deserialize_limits_defaults_max_walk_ms_when_omitted_in_json() {
        let limits: Limits = serde_json::from_str("{}").expect("deserialize limits");
        assert_eq!(limits.max_walk_ms, Some(2_000));
    }

    #[test]
    fn deserialize_limits_defaults_max_walk_ms_when_omitted_in_toml() {
        let limits: Limits = toml::from_str("").expect("deserialize limits");
        assert_eq!(limits.max_walk_ms, Some(2_000));
    }

    #[test]
    fn validate_rejects_large_max_results() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_results = MAX_LIMIT_MAX_RESULTS + 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_large_max_walk_files() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_walk_files = MAX_LIMIT_MAX_WALK_FILES + 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_large_max_walk_entries() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_walk_entries = MAX_LIMIT_MAX_WALK_ENTRIES + 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_large_max_line_bytes() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_line_bytes = MAX_LIMIT_MAX_LINE_BYTES + 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_excessive_grep_response_budget() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_results = MAX_LIMIT_MAX_RESULTS;
        policy.limits.max_line_bytes = 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_excessive_glob_response_budget() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_results =
            (MAX_SCAN_RESPONSE_BYTES / MAX_NORMALIZED_PATH_BYTES).saturating_add(1);
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_zero_max_walk_ms_when_set() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_walk_ms = Some(0);
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_large_max_walk_ms() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_walk_ms = Some(MAX_LIMIT_MAX_WALK_MS + 1);
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_large_max_io_ms() {
        let mut policy = VfsPolicy::default();
        policy.limits.max_io_ms = MAX_LIMIT_MAX_IO_MS + 1;
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_large_secrets_replacement() {
        let mut policy = VfsPolicy::default();
        policy.secrets.replacement = "x".repeat(MAX_SECRET_REPLACEMENT_BYTES + 1);
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_control_characters_in_secrets_replacement() {
        let mut policy = VfsPolicy::default();
        policy.secrets.replacement = "line1\nline2".to_string();
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn default_limits_enable_bounded_scan_runtime() {
        let policy = VfsPolicy::default();
        assert_eq!(policy.limits.max_walk_ms, Some(2_000));
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
    fn validate_rejects_too_many_redact_regexes() {
        let mut policy = VfsPolicy::default();
        policy.secrets.redact_regexes = vec!["a".to_string(); MAX_REDACT_REGEXES + 1];
        let err = policy.validate().expect_err("should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validate_rejects_too_long_redact_regex_pattern() {
        let mut policy = VfsPolicy::default();
        policy.secrets.redact_regexes = vec!["a".repeat(MAX_REDACT_REGEX_PATTERN_BYTES + 1)];
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

    #[test]
    fn deserialize_missing_max_walk_ms_uses_policy_default() {
        let policy: VfsPolicy = serde_json::from_value(json!({
            "permissions": {},
            "limits": {},
            "secrets": {},
            "traversal": {}
        }))
        .expect("deserialize policy");

        assert_eq!(policy.limits.max_walk_ms, Some(2_000));
    }
}
