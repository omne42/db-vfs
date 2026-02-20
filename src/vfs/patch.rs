use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;
use super::util::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub(super) fn apply_unified_patch<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: PatchRequest,
) -> Result<PatchResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.patch, "patch")?;
    validate_workspace_id(&request.workspace_id)?;

    let requested_path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&requested_path) {
        return Err(Error::SecretPathDenied(requested_path));
    }
    if request.expected_version > i64::MAX as u64 {
        return Err(Error::Conflict(format!(
            "expected_version is too large (max {})",
            i64::MAX
        )));
    }

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
        return Err(Error::InputTooLarge {
            size_bytes: parsed.hunks().len() as u64,
            max_bytes: MAX_PATCH_HUNKS as u64,
        });
    }

    let Some(meta) = vfs.store.get_meta(&request.workspace_id, &requested_path)? else {
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

    use crate::store::{DeleteOutcome, FileMeta, Store};
    use db_vfs_core::policy::VfsPolicy;

    struct InconsistentSizeStore {
        meta: FileMeta,
        content: String,
    }

    impl Store for InconsistentSizeStore {
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
}
