use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::policy::MAX_SCAN_RESPONSE_BYTES;
use db_vfs_core::{Error, Result};

use super::util::{
    compile_glob, derive_exact_path_from_glob, derive_safe_prefix_from_glob, glob_is_match,
    json_escaped_str_len,
};
use super::{DbVfs, ScanControl, ScanLimitReason, ScanTarget, scan_metas};
const GLOB_RESPONSE_JSON_FIXED_OVERHEAD: usize = 2048;
#[cfg(test)]
const META_PAGE_SIZE: usize = crate::vfs::SCAN_META_PAGE_SIZE;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default, skip_serializing)]
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

    let max_walk = vfs
        .policy
        .limits
        .max_walk_ms
        .map(std::time::Duration::from_millis);

    let matcher = compile_glob(&request.pattern)?;
    let exact_path = request
        .path_prefix
        .is_none()
        .then(|| derive_exact_path_from_glob(&request.pattern))
        .flatten();

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
    let mut response_bytes: usize = GLOB_RESPONSE_JSON_FIXED_OVERHEAD;
    let target = exact_path
        .as_deref()
        .map(ScanTarget::ExactPath)
        .unwrap_or(ScanTarget::Prefix(&prefix));
    let outcome = scan_metas(
        &mut vfs.store,
        &request.workspace_id,
        target,
        max_scan_entries,
        max_walk,
        "glob",
        |_store, meta| {
            let path = meta.path;

            if vfs.traversal.is_path_skipped(&path) {
                skipped_traversal_skipped = skipped_traversal_skipped.saturating_add(1);
                return Ok(ScanControl::Continue);
            }
            if vfs.redactor.is_path_denied(&path) {
                skipped_secret_denied = skipped_secret_denied.saturating_add(1);
                return Ok(ScanControl::ContinueWithoutBudget);
            }
            scanned_entries = scanned_entries.saturating_add(1);
            if scanned_files >= max_scan_files_u64 {
                return Ok(ScanControl::Stop(ScanLimitReason::Files));
            }
            scanned_files = scanned_files.saturating_add(1);
            if glob_is_match(&matcher, &path) {
                let entry_bytes = json_escaped_str_len(&path)
                    .saturating_add(2)
                    .saturating_add(usize::from(!matches.is_empty()));
                let next_response_bytes = response_bytes.saturating_add(entry_bytes);
                if next_response_bytes > MAX_SCAN_RESPONSE_BYTES {
                    return Ok(ScanControl::Stop(ScanLimitReason::Results));
                }
                response_bytes = next_response_bytes;
                matches.push(path);
                if matches.len() >= vfs.policy.limits.max_results {
                    return Ok(ScanControl::Stop(ScanLimitReason::Results));
                }
            }
            Ok(ScanControl::Continue)
        },
    )?;

    Ok(GlobResponse {
        matches,
        truncated: outcome.truncated(),
        scanned_files,
        skipped_traversal_skipped,
        skipped_secret_denied,
        scan_limit_reached: outcome.truncated(),
        scan_limit_reason: outcome.limit_reason,
        elapsed_ms: outcome.elapsed_ms(),
        scanned_entries: u64::try_from(scanned_entries).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::store::{DeleteOutcome, FileMeta, PrefixPaginationMode, RangeReadMode, Store};
    use db_vfs_core::policy::VfsPolicy;

    struct PrefixFilteringStore {
        rows: Vec<FileMeta>,
    }

    impl Store for PrefixFilteringStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

        fn get_meta(&mut self, _workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
            Ok(self.rows.iter().find(|meta| meta.path == path).cloned())
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
            prefix: &str,
            limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(self
                .rows
                .iter()
                .filter(|meta| meta.path.starts_with(prefix))
                .take(limit)
                .cloned()
                .collect())
        }

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn glob_allows_root_exact_file_patterns_without_full_scan() {
        let store = PrefixFilteringStore {
            rows: vec![
                FileMeta {
                    path: "README.md".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "README.md.bak".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/README.md".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
            ],
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "README.md".to_string(),
                path_prefix: None,
            })
            .expect("glob");

        assert_eq!(resp.matches, vec!["README.md".to_string()]);
        assert_eq!(resp.scanned_entries, 1);
        assert_eq!(resp.scanned_files, 1);
    }

    struct NonMonotonicPageStore {
        row: FileMeta,
    }

    impl Store for NonMonotonicPageStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
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
            err.to_string().contains("non-monotonic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn glob_response_hides_secret_denied_count_from_serialized_output() {
        let value = serde_json::to_value(GlobResponse {
            matches: vec!["docs/a.txt".to_string()],
            truncated: false,
            scanned_files: 1,
            skipped_traversal_skipped: 0,
            skipped_secret_denied: 3,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 1,
            scanned_entries: 1,
        })
        .expect("serialize glob response");

        assert!(value.get("skipped_secret_denied").is_none());
    }

    struct SecretDeniedBudgetStore;

    impl Store for SecretDeniedBudgetStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
        }

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            let rows = match after {
                None => vec![
                    FileMeta {
                        path: "docs/secret/hidden.txt".to_string(),
                        size_bytes: 1,
                        version: 1,
                        updated_at_ms: 0,
                    },
                    FileMeta {
                        path: "docs/visible.txt".to_string(),
                        size_bytes: 1,
                        version: 1,
                        updated_at_ms: 0,
                    },
                ],
                Some("docs/secret/hidden.txt") => vec![FileMeta {
                    path: "docs/visible.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                }],
                _ => Vec::new(),
            };
            Ok(rows)
        }
    }

    #[test]
    fn glob_entry_budget_ignores_secret_denied_rows() {
        let store = SecretDeniedBudgetStore;
        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;
        policy.limits.max_walk_entries = 1;
        policy.secrets.deny_globs = vec!["docs/secret/**".to_string()];

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let response = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "docs/*.txt".to_string(),
                path_prefix: Some("docs/".to_string()),
            })
            .expect("glob");

        assert_eq!(response.matches, vec!["docs/visible.txt"]);
        assert!(!response.truncated);
        assert_eq!(response.scan_limit_reason, None);
        assert_eq!(response.scanned_entries, 1);
        assert_eq!(response.skipped_secret_denied, 1);
    }

    struct NonMonotonicWithinPageStore {
        rows: Vec<FileMeta>,
    }

    impl Store for NonMonotonicWithinPageStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
        }

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(self.rows.clone())
        }
    }

    #[test]
    fn glob_rejects_non_monotonic_within_page_ordering() {
        let store = NonMonotonicWithinPageStore {
            rows: vec![
                FileMeta {
                    path: "docs/a.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/c.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/b.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
            ],
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;
        policy.limits.max_walk_entries = 2;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "docs/*.txt".to_string(),
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on non-monotonic page ordering");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string().contains("non-monotonic page ordering"),
            "unexpected error: {err}"
        );
    }

    struct NonMonotonicAcrossPagesStore;

    impl Store for NonMonotonicAcrossPagesStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
        }

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            if after.is_none() {
                return Ok((0..=META_PAGE_SIZE)
                    .map(|idx| FileMeta {
                        path: format!("docs/{idx:04}.txt"),
                        size_bytes: 1,
                        version: 1,
                        updated_at_ms: 0,
                    })
                    .collect());
            }

            Ok(vec![
                FileMeta {
                    path: "docs/0001.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/9999.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
            ])
        }
    }

    #[test]
    fn glob_rejects_rows_not_strictly_after_cursor_across_pages() {
        let store = NonMonotonicAcrossPagesStore;

        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;
        policy.limits.max_walk_entries = META_PAGE_SIZE + 8;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "other/*.txt".to_string(),
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on rows at/before previous cursor");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string()
                .contains("not strictly after pagination cursor"),
            "unexpected error: {err}"
        );
    }

    struct SlowEmptyPageStore;

    impl Store for SlowEmptyPageStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
        }

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            std::thread::sleep(Duration::from_millis(3));
            Ok(Vec::new())
        }
    }

    #[test]
    fn glob_marks_time_limit_when_store_page_fetch_exceeds_budget() {
        let store = SlowEmptyPageStore;

        let mut policy = VfsPolicy::default();
        policy.permissions.glob = true;
        policy.limits.max_walk_ms = Some(1);

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let response = vfs
            .glob(GlobRequest {
                workspace_id: "ws".to_string(),
                pattern: "docs/*.txt".to_string(),
                path_prefix: Some("docs/".to_string()),
            })
            .expect("glob");
        assert!(response.truncated);
        assert!(response.scan_limit_reached);
        assert_eq!(response.scan_limit_reason, Some(ScanLimitReason::Time));
    }
}
