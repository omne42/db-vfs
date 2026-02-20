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

fn advance_after_cursor(
    after: &mut Option<String>,
    metas: &[crate::store::FileMeta],
    op: &'static str,
) -> Result<()> {
    let Some(next_after) = metas.last().map(|meta| meta.path.clone()) else {
        return Ok(());
    };
    if let Some(prev_after) = after.as_ref()
        && next_after <= *prev_after
    {
        return Err(Error::Db(format!(
            "{op}: store returned non-monotonic pagination cursor (prev={prev_after:?}, next={next_after:?})"
        )));
    }
    *after = Some(next_after);
    Ok(())
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
    let max_scan_files_u64 = u64::try_from(max_scan_files).unwrap_or(u64::MAX);
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
        advance_after_cursor(&mut after, &metas, "glob")?;

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
            if scanned_files >= max_scan_files_u64 {
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
        matches.sort_unstable();
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
        scanned_entries: u64::try_from(scanned_entries).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::{DeleteOutcome, FileMeta, Store};
    use db_vfs_core::policy::VfsPolicy;

    struct NonMonotonicPageStore {
        row: FileMeta,
    }

    impl Store for NonMonotonicPageStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            unimplemented!()
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn delete_file(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _expected_version: Option<u64>,
        ) -> Result<DeleteOutcome> {
            unimplemented!()
        }

        fn list_metas_by_prefix(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            unimplemented!()
        }

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(vec![self.row.clone(); META_PAGE_SIZE + 1])
        }
    }

    #[test]
    fn glob_rejects_non_monotonic_pagination_cursor() {
        let store = NonMonotonicPageStore {
            row: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "other/*.txt".to_string(),
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on non-monotonic cursor");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string().contains("non-monotonic pagination cursor"),
            "unexpected error: {err}"
        );
    }
}
