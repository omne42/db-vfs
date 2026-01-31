use std::path::Path;

use db_vfs_core::policy::VfsPolicy;

pub fn load_policy(path: impl AsRef<Path>) -> anyhow::Result<VfsPolicy> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)?;
    let ext = path.extension().and_then(|s| s.to_str());
    let policy: VfsPolicy = match ext {
        Some("json") => serde_json::from_str(&raw)?,
        Some("toml") | None => toml::from_str(&raw)?,
        Some(other) => anyhow::bail!("unsupported policy extension: {other}"),
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(policy)
}
