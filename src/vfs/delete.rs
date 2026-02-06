use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use crate::store::DeleteOutcome;

use super::DbVfs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub workspace_id: String,
    pub path: String,
    #[serde(default)]
    pub expected_version: Option<u64>,
    #[serde(default)]
    pub ignore_missing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub requested_path: String,
    pub path: String,
    pub deleted: bool,
}

pub(super) fn delete<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: DeleteRequest,
) -> Result<DeleteResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.delete, "delete")?;
    validate_workspace_id(&request.workspace_id)?;

    let requested_path = normalize_path(&request.path)?;
    let path = requested_path.clone();
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
    }

    if let Some(expected_version) = request.expected_version
        && expected_version > i64::MAX as u64
    {
        return Err(Error::Conflict(format!(
            "expected_version is too large (max {})",
            i64::MAX
        )));
    }

    let outcome = vfs
        .store
        .delete_file(&request.workspace_id, &path, request.expected_version)?;

    match outcome {
        DeleteOutcome::Deleted => Ok(DeleteResponse {
            requested_path,
            path,
            deleted: true,
        }),
        DeleteOutcome::NotFound if request.ignore_missing => Ok(DeleteResponse {
            requested_path,
            path,
            deleted: false,
        }),
        DeleteOutcome::NotFound => Err(Error::NotFound("file not found".to_string())),
    }
}
