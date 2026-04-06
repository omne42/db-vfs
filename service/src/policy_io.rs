use std::borrow::Cow;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::TrustMode;
use crate::policy::ServicePolicy;

const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
enum PolicyFormat {
    Json,
    Toml,
}

pub fn load_policy(
    path: impl AsRef<Path>,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<ServicePolicy> {
    let path = path.as_ref();
    let raw = read_policy_file(path)?;
    let format = policy_format(path)?;
    let policy = parse_policy_str(&raw, format, trust_mode, Some(path))?;
    validate_policy_for_startup(&policy, trust_mode, unsafe_no_auth)?;
    Ok(policy)
}

pub fn validate_policy_for_startup(
    policy: &ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<()> {
    policy.validate().map_err(anyhow::Error::msg)?;
    validate_trust_mode(policy, trust_mode, unsafe_no_auth)?;
    Ok(())
}

fn read_policy_file(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|err| anyhow::anyhow!("failed to stat policy file {}: {err}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("policy path must not be a symlink: {}", path.display());
    }
    if !meta.is_file() {
        anyhow::bail!("policy path is not a regular file: {}", path.display());
    }

    let file = std::fs::File::open(path)
        .map_err(|err| anyhow::anyhow!("failed to open policy file {}: {err}", path.display()))?;
    let limit = u64::try_from(MAX_POLICY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let capacity = usize::try_from(meta.len().min(limit))
        .unwrap_or(MAX_POLICY_BYTES.saturating_add(1))
        .min(MAX_POLICY_BYTES.saturating_add(1));
    let mut bytes = Vec::<u8>::with_capacity(capacity);
    let reader = BufReader::new(file);
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| anyhow::anyhow!("failed to read policy file {}: {err}", path.display()))?;
    if bytes.len() > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy file is too large ({} bytes; max {} bytes)",
            bytes.len(),
            MAX_POLICY_BYTES
        );
    }

    String::from_utf8(bytes)
        .map_err(|err| anyhow::anyhow!("policy file {} is not valid UTF-8: {err}", path.display()))
}

fn policy_format(path: &Path) -> anyhow::Result<PolicyFormat> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("json") => Ok(PolicyFormat::Json),
        Some("toml") | None => Ok(PolicyFormat::Toml),
        Some(other) => anyhow::bail!("unsupported policy extension: {other}"),
    }
}

fn parse_policy_str(
    raw: &str,
    format: PolicyFormat,
    trust_mode: TrustMode,
    path: Option<&Path>,
) -> anyhow::Result<ServicePolicy> {
    parse_policy_str_with(raw, format, trust_mode, path, |name| std::env::var(name))
}

fn parse_policy_str_with(
    raw: &str,
    format: PolicyFormat,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    match format {
        PolicyFormat::Json => parse_json_policy(raw, trust_mode, path, lookup),
        PolicyFormat::Toml => parse_toml_policy(raw, trust_mode, path, lookup),
    }
}

fn parse_json_policy(
    raw: &str,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    let mut value: serde_json::Value = serde_json::from_str(raw).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse JSON policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse JSON policy: {err}"),
    })?;
    transform_json_value(&mut value, trust_mode, lookup)?;
    enforce_interpolated_size_json(&value)?;
    serde_json::from_value(value).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse JSON policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse JSON policy: {err}"),
    })
}

fn parse_toml_policy(
    raw: &str,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    let mut value: toml::Value = toml::from_str(raw).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse TOML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse TOML policy: {err}"),
    })?;
    transform_toml_value(&mut value, trust_mode, lookup)?;
    enforce_interpolated_size_toml(&value)?;
    value.try_into().map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse TOML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse TOML policy: {err}"),
    })
}

fn enforce_interpolated_size_json(value: &serde_json::Value) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| anyhow::anyhow!("failed to serialize interpolated JSON policy: {err}"))?;
    ensure_interpolated_size(bytes.len())
}

fn enforce_interpolated_size_toml(value: &toml::Value) -> anyhow::Result<()> {
    let rendered = toml::to_string(value)
        .map_err(|err| anyhow::anyhow!("failed to serialize interpolated TOML policy: {err}"))?;
    ensure_interpolated_size(rendered.len())
}

fn ensure_interpolated_size(len: usize) -> anyhow::Result<()> {
    if len > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy after env interpolation is too large ({} bytes; max {} bytes)",
            len,
            MAX_POLICY_BYTES
        );
    }
    Ok(())
}

fn transform_json_value(
    value: &mut serde_json::Value,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<()> {
    match value {
        serde_json::Value::String(string) => {
            let next = process_string_value(string, trust_mode, lookup)?;
            if let Cow::Owned(next) = next {
                *string = next;
            }
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for value in values {
                transform_json_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                transform_json_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(())
        }
    }
}

fn transform_toml_value(
    value: &mut toml::Value,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<()> {
    match value {
        toml::Value::String(string) => {
            let next = process_string_value(string, trust_mode, lookup)?;
            if let Cow::Owned(next) = next {
                *string = next;
            }
            Ok(())
        }
        toml::Value::Array(values) => {
            for value in values {
                transform_toml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        toml::Value::Table(values) => {
            for (_, value) in values.iter_mut() {
                transform_toml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => Ok(()),
    }
}

fn process_string_value(
    input: &str,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<Cow<'_, str>> {
    match trust_mode {
        TrustMode::Trusted => interpolate_env_with(input, lookup),
        TrustMode::Untrusted => reject_env_interpolation(input),
    }
}

fn reject_env_interpolation(input: &str) -> anyhow::Result<Cow<'_, str>> {
    if input.contains("${") {
        anyhow::bail!(
            "policy env interpolation is not allowed in trust_mode=untrusted (found '${{')"
        );
    }
    Ok(Cow::Borrowed(input))
}

fn interpolate_env_with(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<Cow<'_, str>> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());

    let mut idx: usize = 0;
    let mut last: usize = 0;
    let mut changed = false;

    while idx + 1 < bytes.len() {
        if bytes[idx] == b'$' && bytes[idx + 1] == b'{' {
            out.push_str(&raw[last..idx]);
            let start = idx + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end >= bytes.len() {
                anyhow::bail!("policy env interpolation: unterminated ${{...}}");
            }
            let name = &raw[start..end];
            if !is_valid_env_var_name(name) {
                anyhow::bail!("policy env interpolation: invalid env var name {name:?}");
            }
            let value = lookup(name).map_err(|_| {
                anyhow::anyhow!("policy env interpolation: env var {name:?} is not set")
            })?;
            out.push_str(&value);
            changed = true;
            idx = end + 1;
            last = idx;
            continue;
        }

        idx += 1;
    }

    if !changed {
        return Ok(Cow::Borrowed(raw));
    }

    out.push_str(&raw[last..]);
    Ok(Cow::Owned(out))
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn validate_trust_mode(
    policy: &ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<()> {
    if trust_mode != TrustMode::Untrusted {
        return Ok(());
    }

    if unsafe_no_auth {
        anyhow::bail!("trust_mode=untrusted forbids --unsafe-no-auth");
    }

    if policy.permissions.write || policy.permissions.patch || policy.permissions.delete {
        anyhow::bail!("trust_mode=untrusted forbids write/patch/delete permissions");
    }

    if policy.permissions.allow_full_scan {
        anyhow::bail!("trust_mode=untrusted forbids permissions.allow_full_scan");
    }

    if policy.limits.max_walk_ms.is_none() {
        anyhow::bail!("trust_mode=untrusted requires limits.max_walk_ms");
    }

    if policy.limits.max_requests_per_ip_per_sec == 0 {
        anyhow::bail!(
            "trust_mode=untrusted requires per-IP rate limiting (limits.max_requests_per_ip_per_sec > 0)"
        );
    }

    if policy.audit.jsonl_path.is_some() {
        anyhow::bail!("trust_mode=untrusted forbids audit.jsonl_path");
    }

    for (idx, token) in policy.auth.tokens.iter().enumerate() {
        if token.token_env_var.is_some() {
            anyhow::bail!("trust_mode=untrusted forbids auth.tokens[{idx}].token_env_var");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::process::Command;

    use db_vfs_core::policy::Permissions;

    use crate::policy::{AuthPolicy, AuthToken, ServiceLimits, ServicePolicy};
    use tempfile::tempdir;

    #[test]
    fn interpolate_env_replaces_vars() {
        let key = format!("DB_VFS_TEST_ENV_{}", std::process::id());
        let raw = format!("hello ${{{key}}}!");
        let out = interpolate_env_with(&raw, |name| {
            if name == key.as_str() {
                return Ok("world".to_string());
            }
            Err(std::env::VarError::NotPresent)
        })
        .unwrap();
        assert_eq!(out, "hello world!");
    }

    #[test]
    fn interpolate_env_rejects_invalid_name() {
        let err = interpolate_env_with("x=${1BAD}", |_| Ok(String::new())).unwrap_err();
        assert!(err.to_string().contains("invalid env var name"));
    }

    #[test]
    fn trusted_interpolation_only_touches_string_values() {
        let policy = parse_policy_str_with(
            r#"
# ${COMMENT_ONLY}
[auth]
tokens = [{ token = "sha256:${TOKEN_HASH}", allowed_workspaces = ["${WORKSPACE}"] }]
"#,
            PolicyFormat::Toml,
            TrustMode::Trusted,
            None,
            lookup,
        )
        .unwrap_or_else(|err| panic!("unexpected parse error: {err}"));
        assert_eq!(
            policy.auth.tokens[0].token.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(policy.auth.tokens[0].allowed_workspaces, vec!["team-a"]);
    }

    #[test]
    fn untrusted_mode_ignores_comment_placeholders_but_rejects_string_values() {
        let trusted_comment_only = parse_policy_str(
            r#"
# ${COMMENT_ONLY}
[permissions]
read = true
[limits]
max_walk_ms = 1000
max_requests_per_ip_per_sec = 1
"#,
            PolicyFormat::Toml,
            TrustMode::Untrusted,
            None,
        )
        .unwrap();
        assert!(trusted_comment_only.permissions.read);

        let err = parse_policy_str(
            r#"
[permissions]
read = true
[limits]
max_walk_ms = 1000
max_requests_per_ip_per_sec = 1
[auth]
tokens = [{ token = "${TOKEN}", allowed_workspaces = ["ws"] }]
"#,
            PolicyFormat::Toml,
            TrustMode::Untrusted,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("policy env interpolation is not allowed in trust_mode=untrusted")
        );
    }

    #[test]
    fn trusted_json_interpolation_walks_nested_strings() {
        let policy = parse_policy_str_with(
            r#"{"auth":{"tokens":[{"token":"sha256:${TOKEN_HASH}","allowed_workspaces":["${WORKSPACE}"]}]}}"#,
            PolicyFormat::Json,
            TrustMode::Trusted,
            None,
            lookup,
        )
        .unwrap();
        assert_eq!(
            policy.auth.tokens[0].token.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(policy.auth.tokens[0].allowed_workspaces, vec!["team-a"]);
    }

    #[test]
    fn read_policy_file_rejects_non_regular_paths() {
        let dir = tempdir().expect("tempdir");
        let err = read_policy_file(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("policy path is not a regular file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_policy_file_rejects_symlinks_without_following_them() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("policy.toml");
        std::fs::write(&target, "[permissions]\nread = true\n").expect("write target policy");

        let link = dir.path().join("policy-link.toml");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = read_policy_file(&link).unwrap_err();
        assert!(err.to_string().contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn read_policy_file_rejects_fifo_without_opening_it() {
        let dir = tempdir().expect("tempdir");
        let fifo = dir.path().join("policy.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo command");
        assert!(status.success(), "mkfifo failed: {status}");

        let err = read_policy_file(&fifo).unwrap_err();
        assert!(
            err.to_string()
                .contains("policy path is not a regular file")
        );
    }

    #[test]
    fn untrusted_rejects_env_tokens_and_writes() {
        let policy = ServicePolicy {
            permissions: Permissions {
                read: true,
                glob: true,
                grep: true,
                write: true,
                patch: false,
                delete: false,
                allow_full_scan: false,
            },
            limits: ServiceLimits {
                max_walk_ms: Some(1000),
                max_requests_per_ip_per_sec: 10,
                max_requests_burst_per_ip: 10,
                max_rate_limit_ips: 4,
                ..ServiceLimits::default()
            },
            auth: AuthPolicy {
                tokens: vec![AuthToken {
                    token: None,
                    token_env_var: Some("SECRET".to_string()),
                    allowed_workspaces: vec!["ws".to_string()],
                }],
            },
            ..ServicePolicy::default()
        };

        let err = validate_trust_mode(&policy, TrustMode::Untrusted, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbids write/patch/delete")
                || msg.contains("forbids auth.tokens[0].token_env_var"),
            "unexpected error: {msg}"
        );
    }

    fn parse_policy_str(
        raw: &str,
        format: PolicyFormat,
        trust_mode: TrustMode,
        path: Option<&Path>,
    ) -> anyhow::Result<ServicePolicy> {
        super::parse_policy_str(raw, format, trust_mode, path)
    }

    fn parse_policy_str_with(
        raw: &str,
        format: PolicyFormat,
        trust_mode: TrustMode,
        path: Option<&Path>,
        lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
    ) -> anyhow::Result<ServicePolicy> {
        super::parse_policy_str_with(raw, format, trust_mode, path, lookup)
    }

    fn interpolate_env_with(
        raw: &str,
        lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
    ) -> anyhow::Result<String> {
        super::interpolate_env_with(raw, lookup).map(Cow::into_owned)
    }

    fn lookup(name: &str) -> Result<String, std::env::VarError> {
        match name {
            "TOKEN_HASH" => Ok("abc123".to_string()),
            "WORKSPACE" => Ok("team-a".to_string()),
            _ => Err(std::env::VarError::NotPresent),
        }
    }
}
