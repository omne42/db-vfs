use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;
use super::util::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRequest {
    pub workspace_id: String,
    pub path: String,
    pub patch: String,
    pub expected_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResponse {
    pub requested_path: String,
    pub path: String,
    pub bytes_written: u64,
    pub version: u64,
}

const MAX_PATCH_HUNKS: usize = 512;

fn projected_patch_output_size(
    existing_size_bytes: u64,
    patch: &diffy::Patch<'_, str>,
) -> Option<u64> {
    let mut inserted_bytes = 0u64;
    let mut deleted_bytes = 0u64;

    for hunk in patch.hunks() {
        for line in hunk.lines() {
            match line {
                diffy::Line::Insert(text) => {
                    inserted_bytes = inserted_bytes.checked_add(u64::try_from(text.len()).ok()?)?;
                }
                diffy::Line::Delete(text) => {
                    deleted_bytes = deleted_bytes.checked_add(u64::try_from(text.len()).ok()?)?;
                }
                diffy::Line::Context(_) => {}
            }
        }
    }

    let projected = i128::from(existing_size_bytes)
        .checked_add(i128::from(inserted_bytes))?
        .checked_sub(i128::from(deleted_bytes))?;
    if projected < 0 {
        return None;
    }
    u64::try_from(projected).ok()
}

pub(super) fn apply_unified_patch<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: PatchRequest,
) -> Result<PatchResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.patch, "patch")?;
    if vfs.redactor.has_redact_rules() {
        return Err(Error::NotPermitted(
            "patch is not supported when secret redaction rules are active".to_string(),
        ));
    }
    validate_workspace_id(&request.workspace_id)?;

    let requested_path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&requested_path) {
        return Err(Error::SecretPathDenied(requested_path));
    }
    super::validate_expected_version(request.expected_version)?;

    let max_patch_bytes = vfs
        .policy
        .limits
        .max_patch_bytes
        .unwrap_or(vfs.policy.limits.max_read_bytes);
    let patch_bytes = u64::try_from(request.patch.len()).map_err(|_| Error::InputTooLarge {
        size_bytes: u64::MAX,
        max_bytes: max_patch_bytes,
    })?;
    if patch_bytes > max_patch_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: patch_bytes,
            max_bytes: max_patch_bytes,
        });
    }

    let parsed =
        diffy::Patch::from_str(&request.patch).map_err(|err| Error::Patch(err.to_string()))?;
    if parsed.hunks().len() > MAX_PATCH_HUNKS {
        let hunk_count = u64::try_from(parsed.hunks().len()).unwrap_or(u64::MAX);
        let max_hunks = u64::try_from(MAX_PATCH_HUNKS).unwrap_or(u64::MAX);
        return Err(Error::InputTooLarge {
            size_bytes: hunk_count,
            max_bytes: max_hunks,
        });
    }

    let Some(mut meta) = vfs.store.get_meta(&request.workspace_id, &requested_path)? else {
        return Err(Error::NotFound(format!(
            "file not found (workspace_id={}, path={})",
            request.workspace_id, requested_path
        )));
    };

    if meta.version != request.expected_version {
        return Err(Error::Conflict(format!(
            "version mismatch (workspace_id={}, path={}, expected_version={}, actual_version={})",
            request.workspace_id, requested_path, request.expected_version, meta.version
        )));
    }

    let max_fetch_bytes = vfs.policy.limits.max_read_bytes;
    if meta.size_bytes > max_fetch_bytes {
        // Re-check metadata once before failing hard. This avoids false
        // `file_too_large` errors when metadata is stale and a newer/smaller
        // version won the race between metadata and content reads.
        let Some(now_meta) = vfs.store.get_meta(&request.workspace_id, &requested_path)? else {
            return Err(Error::NotFound(format!(
                "file not found (workspace_id={}, path={})",
                request.workspace_id, requested_path
            )));
        };
        if now_meta.version != meta.version || now_meta.size_bytes <= max_fetch_bytes {
            meta = now_meta;
        }
        if meta.version != request.expected_version {
            return Err(Error::Conflict(format!(
                "version mismatch (workspace_id={}, path={}, expected_version={}, actual_version={})",
                request.workspace_id, requested_path, request.expected_version, meta.version
            )));
        }
    }

    if meta.size_bytes > max_fetch_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path,
            size_bytes: meta.size_bytes,
            max_bytes: max_fetch_bytes,
        });
    }

    let Some(existing_content) = vfs.store.get_content(
        &request.workspace_id,
        &requested_path,
        request.expected_version,
    )?
    else {
        let Some(now_meta) = vfs.store.get_meta(&request.workspace_id, &requested_path)? else {
            return Err(Error::NotFound(format!(
                "file not found (workspace_id={}, path={})",
                request.workspace_id, requested_path
            )));
        };
        if now_meta.version != request.expected_version {
            return Err(Error::Conflict(format!(
                "version mismatch (workspace_id={}, path={}, expected_version={}, actual_version={})",
                request.workspace_id, requested_path, request.expected_version, now_meta.version
            )));
        }
        return Err(Error::Db("file content could not be loaded".to_string()));
    };
    let existing_size_bytes = u64::try_from(existing_content.len()).unwrap_or(u64::MAX);
    if existing_size_bytes > max_fetch_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path.clone(),
            size_bytes: existing_size_bytes,
            max_bytes: max_fetch_bytes,
        });
    }

    if let Some(projected_size_bytes) = projected_patch_output_size(existing_size_bytes, &parsed)
        && projected_size_bytes > vfs.policy.limits.max_write_bytes
    {
        return Err(Error::FileTooLarge {
            path: requested_path,
            size_bytes: projected_size_bytes,
            max_bytes: vfs.policy.limits.max_write_bytes,
        });
    }

    let updated =
        diffy::apply(&existing_content, &parsed).map_err(|err| Error::Patch(err.to_string()))?;

    let bytes_written = u64::try_from(updated.len()).unwrap_or(u64::MAX);
    if bytes_written > vfs.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path,
            size_bytes: bytes_written,
            max_bytes: vfs.policy.limits.max_write_bytes,
        });
    }

    let now_ms = now_ms();
    let version = vfs.store.update_file_cas(
        &request.workspace_id,
        &requested_path,
        &updated,
        request.expected_version,
        now_ms,
    )?;

    Ok(PatchResponse {
        path: requested_path.clone(),
        requested_path,
        bytes_written,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::{DeleteOutcome, FileMeta, PrefixPaginationMode, RangeReadMode, Store};
    use db_vfs_core::policy::{SecretRules, VfsPolicy};

    struct InconsistentSizeStore {
        meta: FileMeta,
        content: String,
    }

    impl Store for InconsistentSizeStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

        fn get_meta(&mut self, _workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
            if path == self.meta.path {
                Ok(Some(self.meta.clone()))
            } else {
                Ok(None)
            }
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            path: &str,
            version: u64,
        ) -> Result<Option<String>> {
            if path == self.meta.path && version == self.meta.version {
                Ok(Some(self.content.clone()))
            } else {
                Ok(None)
            }
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
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    struct PanicStore;

    impl Store for PanicStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            panic!("patch should reject before loading metadata when redaction is active")
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            panic!("patch should reject before loading content when redaction is active")
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<u64> {
            panic!("patch test should not insert through store")
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<u64> {
            panic!("patch test should not update through store")
        }

        fn delete_file(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _expected_version: Option<u64>,
        ) -> Result<DeleteOutcome> {
            panic!("patch test should not delete through store")
        }

        fn list_metas_by_prefix(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            panic!("patch test should not scan through store")
        }

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn patch_fails_when_actual_content_exceeds_read_limit_even_if_meta_is_stale() {
        let store = InconsistentSizeStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content: "abcdef".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.patch = true;
        policy.limits.max_read_bytes = 4;
        policy.limits.max_patch_bytes = Some(1024);

        let patch = diffy::create_patch("abcdef", "abcxef").to_string();
        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .apply_unified_patch(PatchRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                patch,
                expected_version: 1,
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "file_too_large");
    }

    struct StaleLargeMetaStore {
        meta_calls: usize,
    }

    impl Store for StaleLargeMetaStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

        fn get_meta(&mut self, _workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
            self.meta_calls = self.meta_calls.saturating_add(1);
            if self.meta_calls == 1 {
                Ok(Some(FileMeta {
                    path: path.to_string(),
                    size_bytes: 9,
                    version: 1,
                    updated_at_ms: 0,
                }))
            } else {
                Ok(Some(FileMeta {
                    path: path.to_string(),
                    size_bytes: 2,
                    version: 1,
                    updated_at_ms: 0,
                }))
            }
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            version: u64,
        ) -> Result<Option<String>> {
            if version == 1 {
                Ok(Some("ok".to_string()))
            } else {
                Ok(None)
            }
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
            expected_version: u64,
            _now_ms: u64,
        ) -> Result<u64> {
            if expected_version == 1 {
                Ok(2)
            } else {
                Err(Error::Conflict("version mismatch".to_string()))
            }
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
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn patch_rechecks_oversized_meta_before_failing() {
        let store = StaleLargeMetaStore { meta_calls: 0 };
        let mut policy = VfsPolicy::default();
        policy.permissions.patch = true;
        policy.limits.max_read_bytes = 4;
        policy.limits.max_patch_bytes = Some(1024);

        let patch = diffy::create_patch("ok", "go").to_string();
        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .apply_unified_patch(PatchRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                patch,
                expected_version: 1,
            })
            .expect("patch should succeed after stale meta re-check");
        assert_eq!(resp.version, 2);
    }

    #[test]
    fn patch_rejects_malformed_input_before_parsing_or_loading_when_redaction_is_active() {
        let mut policy = VfsPolicy::default();
        policy.permissions.patch = true;
        policy.secrets = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "REDACTED".to_string(),
            ..SecretRules::default()
        };

        let mut vfs = DbVfs::new(PanicStore, policy).expect("vfs");
        let err = vfs
            .apply_unified_patch(PatchRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                patch: "not a unified diff".to_string(),
                expected_version: 1,
            })
            .expect_err("redaction-backed patch should be rejected before parsing or loading");

        assert_eq!(err.code(), "not_permitted");
        assert_eq!(
            err.to_string(),
            "operation is not permitted: patch is not supported when secret redaction rules are active"
        );
    }

    #[test]
    fn patch_is_rejected_when_secret_redaction_rules_are_active() {
        let mut policy = VfsPolicy::default();
        policy.permissions.patch = true;
        policy.secrets = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "REDACTED".to_string(),
            ..SecretRules::default()
        };

        let mut vfs = DbVfs::new(PanicStore, policy).expect("vfs");
        let matching_err = vfs
            .apply_unified_patch(PatchRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                patch: diffy::create_patch("secret\npublic\n", "changed\npublic\n").to_string(),
                expected_version: 1,
            })
            .expect_err("redaction-backed patch should be rejected");
        let mismatched_err = vfs
            .apply_unified_patch(PatchRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                patch: diffy::create_patch("wrong\npublic\n", "changed\npublic\n").to_string(),
                expected_version: 1,
            })
            .expect_err("redaction-backed patch should be rejected before diff evaluation");

        assert_eq!(matching_err.code(), "not_permitted");
        assert_eq!(mismatched_err.code(), "not_permitted");
        assert_eq!(matching_err.to_string(), mismatched_err.to_string());
        assert_eq!(
            matching_err.to_string(),
            "operation is not permitted: patch is not supported when secret redaction rules are active"
        );
    }
}
