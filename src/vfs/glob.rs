use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::util::{compile_glob, derive_safe_prefix_from_glob, elapsed_ms, glob_is_match};
use super::{DbVfs, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRequest {
    pub workspace_id: String,
    pub pattern: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobResponse {
    pub matches: Vec<String>,
    pub truncated: bool,
    #[serde(default)]
    pub scanned_files: u64,
    #[serde(default)]
    pub scan_limit_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_limit_reason: Option<ScanLimitReason>,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub scanned_entries: u64,
}

pub(super) fn glob<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: GlobRequest,
) -> Result<GlobResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.glob, "glob")?;
    validate_workspace_id(&request.workspace_id)?;

    let started = std::time::Instant::now();
    let max_walk = vfs
        .policy
        .limits
        .max_walk_ms
        .map(std::time::Duration::from_millis);

    let matcher = compile_glob(&request.pattern)?;

    let prefix = match request.path_prefix {
        Some(prefix) => normalize_path_prefix(&prefix)?,
        None => derive_safe_prefix_from_glob(&request.pattern).ok_or_else(|| {
            Error::NotPermitted(
                "glob requires path_prefix for patterns without a safe literal prefix".to_string(),
            )
        })?,
    };
    if prefix.is_empty() && !vfs.policy.permissions.allow_full_scan {
        return Err(Error::NotPermitted(
            "glob requires a non-empty path_prefix unless allow_full_scan is enabled".to_string(),
        ));
    }

    let max_scan = vfs
        .policy
        .limits
        .max_walk_entries
        .min(vfs.policy.limits.max_walk_files)
        .max(1);
    let mut metas = vfs.store.list_metas_by_prefix(
        &request.workspace_id,
        &prefix,
        max_scan.saturating_add(1),
    )?;
    let truncated_by_store_limit = metas.len() > max_scan;
    if truncated_by_store_limit {
        metas.truncate(max_scan);
    }
    let truncated_reason = if vfs.policy.limits.max_walk_entries <= vfs.policy.limits.max_walk_files
    {
        ScanLimitReason::Entries
    } else {
        ScanLimitReason::Files
    };

    let mut matches = Vec::<String>::new();
    let mut scanned_entries: u64 = 0;
    let mut scan_limit_reached = truncated_by_store_limit;
    let mut scan_limit_reason: Option<ScanLimitReason> =
        truncated_by_store_limit.then_some(truncated_reason);

    for meta in metas {
        scanned_entries = scanned_entries.saturating_add(1);
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Time);
            break;
        }
        if vfs.redactor.is_path_denied(&meta.path) {
            continue;
        }
        if glob_is_match(&matcher, &meta.path) {
            matches.push(meta.path);
            if matches.len() >= vfs.policy.limits.max_results {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Results);
                break;
            }
        }
    }

    matches.sort();
    Ok(GlobResponse {
        matches,
        truncated: scan_limit_reached,
        scanned_files: scanned_entries,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries,
    })
}
