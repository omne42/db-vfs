use serde::{Deserialize, Serialize};

use db_vfs_core::path::normalize_path;
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
    pub path: String,
    pub bytes_written: u64,
    pub version: u64,
}

pub(super) fn apply_unified_patch<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: PatchRequest,
) -> Result<PatchResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.patch, "patch")?;

    let path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
    }

    let max_patch_bytes = vfs
        .policy
        .limits
        .max_patch_bytes
        .unwrap_or(vfs.policy.limits.max_read_bytes);
    let patch_bytes = request.patch.len() as u64;
    if patch_bytes > max_patch_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: patch_bytes,
            max_bytes: max_patch_bytes,
        });
    }

    let Some(existing) = vfs.store.get_file(&request.workspace_id, &path)? else {
        return Err(Error::NotFound("file not found".to_string()));
    };

    if existing.version != request.expected_version {
        return Err(Error::Conflict("version mismatch".to_string()));
    }

    let parsed =
        diffy::Patch::from_str(&request.patch).map_err(|err| Error::Patch(err.to_string()))?;
    let updated =
        diffy::apply(&existing.content, &parsed).map_err(|err| Error::Patch(err.to_string()))?;

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
        path,
        bytes_written,
        version: record.version,
    })
}
