use std::io::Read;
use std::path::Path;

use db_vfs_core::policy::VfsPolicy;

use crate::TrustMode;

const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

pub fn load_policy(
    path: impl AsRef<Path>,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<VfsPolicy> {
    let path = path.as_ref();
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        anyhow::bail!("policy path is not a regular file: {}", path.display());
    }

    let limit = u64::try_from(MAX_POLICY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy file is too large ({} bytes; max {} bytes)",
            bytes.len(),
            MAX_POLICY_BYTES
        );
    }
    let raw = String::from_utf8(bytes)?;
    let raw = match trust_mode {
        TrustMode::Trusted => interpolate_env(&raw)?,
        TrustMode::Untrusted => {
            if raw.contains("${") {
                anyhow::bail!(
                    "policy env interpolation is not allowed in trust_mode=untrusted (found '${{')"
                );
            }
            raw
        }
    };
    let ext = path.extension().and_then(|s| s.to_str());
    let policy: VfsPolicy = match ext {
        Some("json") => serde_json::from_str(&raw)?,
        Some("toml") | None => toml::from_str(&raw)?,
        Some(other) => anyhow::bail!("unsupported policy extension: {other}"),
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    validate_trust_mode(&policy, trust_mode, unsafe_no_auth)?;
    Ok(policy)
}

fn interpolate_env(raw: &str) -> anyhow::Result<String> {
    interpolate_env_with(raw, |name| std::env::var(name))
}

fn interpolate_env_with(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<String> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());

    let mut idx: usize = 0;
    let mut last: usize = 0;

    while idx + 1 < bytes.len() {
        if bytes[idx] == b'$' && bytes[idx + 1] == b'{' {
            out.push_str(&raw[last..idx]);
            if out.len() > MAX_POLICY_BYTES {
                anyhow::bail!(
                    "policy after env interpolation is too large ({} bytes; max {} bytes)",
                    out.len(),
                    MAX_POLICY_BYTES
                );
            }
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
            if out.len() > MAX_POLICY_BYTES {
                anyhow::bail!(
                    "policy after env interpolation is too large ({} bytes; max {} bytes)",
                    out.len(),
                    MAX_POLICY_BYTES
                );
            }

            idx = end + 1;
            last = idx;
            continue;
        }

        idx += 1;
    }

    out.push_str(&raw[last..]);
    if out.len() > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy after env interpolation is too large ({} bytes; max {} bytes)",
            out.len(),
            MAX_POLICY_BYTES
        );
    }
    Ok(out)
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
    policy: &VfsPolicy,
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

    use db_vfs_core::policy::{AuthPolicy, AuthToken, Limits, Permissions};

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
        let err = interpolate_env("x=${1BAD}").unwrap_err();
        assert!(err.to_string().contains("invalid env var name"));
    }

    #[test]
    fn untrusted_rejects_env_tokens_and_writes() {
        let policy = VfsPolicy {
            permissions: Permissions {
                read: true,
                glob: true,
                grep: true,
                write: true,
                patch: false,
                delete: false,
                allow_full_scan: false,
            },
            limits: Limits {
                max_walk_ms: Some(1000),
                max_requests_per_ip_per_sec: 10,
                max_requests_burst_per_ip: 10,
                max_rate_limit_ips: 4,
                ..Limits::default()
            },
            auth: AuthPolicy {
                tokens: vec![AuthToken {
                    token: None,
                    token_env_var: Some("SECRET".to_string()),
                    allowed_workspaces: vec!["ws".to_string()],
                }],
            },
            ..VfsPolicy::default()
        };

        let err = validate_trust_mode(&policy, TrustMode::Untrusted, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbids write/patch/delete")
                || msg.contains("forbids auth.tokens[0].token_env_var"),
            "unexpected error: {msg}"
        );
    }
}
