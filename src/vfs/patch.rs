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

    let requested_path = request.path.clone();
    let path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
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

    let Some(meta) = vfs.store.get_meta(&request.workspace_id, &path)? else {
        return Err(Error::NotFound(format!(
            "file not found (workspace_id={}, path={})",
            request.workspace_id, path
        )));
    };

    if meta.version != request.expected_version {
        return Err(Error::Conflict(format!(
            "version mismatch (workspace_id={}, path={}, expected_version={}, actual_version={})",
            request.workspace_id, path, request.expected_version, meta.version
        )));
    }

    let max_fetch_bytes = vfs.policy.limits.max_read_bytes;
    if meta.size_bytes > max_fetch_bytes {
        return Err(Error::FileTooLarge {
            path,
            size_bytes: meta.size_bytes,
            max_bytes: max_fetch_bytes,
        });
    }

    let Some(existing_content) =
        vfs.store
            .get_content(&request.workspace_id, &path, request.expected_version)?
    else {
        let Some(now_meta) = vfs.store.get_meta(&request.workspace_id, &path)? else {
            return Err(Error::NotFound(format!(
                "file not found (workspace_id={}, path={})",
                request.workspace_id, path
            )));
        };
        if now_meta.version != request.expected_version {
            return Err(Error::Conflict(format!(
                "version mismatch (workspace_id={}, path={}, expected_version={}, actual_version={})",
                request.workspace_id, path, request.expected_version, now_meta.version
            )));
        }
        return Err(Error::Db("file content could not be loaded".to_string()));
    };

    let updated =
        diffy::apply(&existing_content, &parsed).map_err(|err| Error::Patch(err.to_string()))?;

    let bytes_written = updated.len() as u64;
    if bytes_written > vfs.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path,
            size_bytes: bytes_written,
            max_bytes: vfs.policy.limits.max_write_bytes,
        });
    }

    let now_ms = now_ms();
    let record = vfs.store.update_file_cas(
        &request.workspace_id,
        &path,
        &updated,
        request.expected_version,
        now_ms,
    )?;

    Ok(PatchResponse {
        requested_path,
        path,
        bytes_written,
        version: record.version,
    })
}
