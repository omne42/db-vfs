use serde::{Deserialize, Serialize};

use db_vfs_core::path::normalize_path;
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
    pub path: String,
    pub deleted: bool,
}

pub(super) fn delete<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: DeleteRequest,
) -> Result<DeleteResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.delete, "delete")?;

    let path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
    }

    let outcome = vfs
        .store
        .delete_file(&request.workspace_id, &path, request.expected_version)?;

    match outcome {
        DeleteOutcome::Deleted => Ok(DeleteResponse {
            path,
            deleted: true,
        }),
        DeleteOutcome::NotFound if request.ignore_missing => Ok(DeleteResponse {
            path,
            deleted: false,
        }),
        DeleteOutcome::NotFound => Err(Error::NotFound("file not found".to_string())),
    }
}
