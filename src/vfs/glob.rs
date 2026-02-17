use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::policy::MAX_SCAN_RESPONSE_BYTES;
use db_vfs_core::{Error, Result};

use super::util::{
    compile_glob, derive_safe_prefix_from_glob, elapsed_ms, glob_is_match, json_escaped_str_len,
};
use super::{DbVfs, ScanLimitReason};

const META_PAGE_SIZE: usize = 2048;
const GLOB_RESPONSE_JSON_FIXED_OVERHEAD: usize = 2048;

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
    pub skipped_traversal_skipped: u64,
    #[serde(default)]
    pub skipped_secret_denied: u64,
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
    if vfs.policy.limits.max_results == 0 {
        return Ok(GlobResponse {
            matches: Vec::new(),
            truncated: true,
            scanned_files: 0,
            skipped_traversal_skipped: 0,
            skipped_secret_denied: 0,
            scan_limit_reached: true,
            scan_limit_reason: Some(ScanLimitReason::Results),
            elapsed_ms: 0,
            scanned_entries: 0,
        });
    }

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

    let max_scan_entries = vfs.policy.limits.max_walk_entries.max(1);
    let max_scan_files = vfs.policy.limits.max_walk_files.max(1);
    let mut matches = Vec::<String>::with_capacity(vfs.policy.limits.max_results.min(1024));
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: usize = 0;
    let mut skipped_traversal_skipped: u64 = 0;
    let mut skipped_secret_denied: u64 = 0;
    let mut scan_limit_reached = false;
    let mut scan_limit_reason: Option<ScanLimitReason> = None;
    let mut response_bytes: usize = GLOB_RESPONSE_JSON_FIXED_OVERHEAD;
    let mut needs_sort = false;
    let mut after: Option<String> = None;

    'scan: loop {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Time);
            break;
        }

        let remaining_entries = max_scan_entries.saturating_sub(scanned_entries);
        if remaining_entries == 0 {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Entries);
            break;
        }

        let page_budget = remaining_entries.min(META_PAGE_SIZE);
        let fetch_limit = page_budget.saturating_add(1);
        let mut metas = vfs.store.list_metas_by_prefix_page(
            &request.workspace_id,
            &prefix,
            after.as_deref(),
            fetch_limit,
        )?;
        let has_more = metas.len() > page_budget;
        if has_more {
            metas.truncate(page_budget);
        }

        if metas.is_empty() {
            break;
        }
        after = metas.last().map(|meta| meta.path.clone());

        for meta in metas {
            let path = meta.path;

            scanned_entries = scanned_entries.saturating_add(1);
            if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Time);
                break 'scan;
            }

            if vfs.traversal.is_path_skipped(&path) {
                skipped_traversal_skipped = skipped_traversal_skipped.saturating_add(1);
                continue;
            }
            if vfs.redactor.is_path_denied(&path) {
                skipped_secret_denied = skipped_secret_denied.saturating_add(1);
                continue;
            }
            if scanned_files >= max_scan_files as u64 {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Files);
                break 'scan;
            }
            scanned_files = scanned_files.saturating_add(1);
            if glob_is_match(&matcher, &path) {
                // Budget against JSON-encoded output size (escaped bytes + quotes + separator).
                let entry_bytes = json_escaped_str_len(&path)
                    .saturating_add(2)
                    .saturating_add(usize::from(!matches.is_empty()));
                let next_response_bytes = response_bytes.saturating_add(entry_bytes);
                if next_response_bytes > MAX_SCAN_RESPONSE_BYTES {
                    scan_limit_reached = true;
                    scan_limit_reason = Some(ScanLimitReason::Results);
                    break 'scan;
                }
                if matches.last().is_some_and(|prev| prev > &path) {
                    needs_sort = true;
                }
                response_bytes = next_response_bytes;
                matches.push(path);
                if matches.len() >= vfs.policy.limits.max_results {
                    scan_limit_reached = true;
                    scan_limit_reason = Some(ScanLimitReason::Results);
                    break 'scan;
                }
            }
        }

        if has_more && scanned_entries >= max_scan_entries {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Entries);
            break;
        }

        if !has_more {
            break;
        }
    }

    if needs_sort {
        matches.sort();
    }
    Ok(GlobResponse {
        matches,
        truncated: scan_limit_reached,
        scanned_files,
        skipped_traversal_skipped,
        skipped_secret_denied,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries: scanned_entries as u64,
    })
}
