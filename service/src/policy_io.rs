use std::path::Path;

use db_vfs_core::policy::VfsPolicy;

const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

pub fn load_policy(path: impl AsRef<Path>) -> anyhow::Result<VfsPolicy> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    if bytes.len() > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy file is too large ({} bytes; max {} bytes)",
            bytes.len(),
            MAX_POLICY_BYTES
        );
    }
    let raw = String::from_utf8(bytes)?;
    let ext = path.extension().and_then(|s| s.to_str());
    let policy: VfsPolicy = match ext {
        Some("json") => serde_json::from_str(&raw)?,
        Some("toml") | None => toml::from_str(&raw)?,
        Some(other) => anyhow::bail!("unsupported policy extension: {other}"),
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(policy)
}
