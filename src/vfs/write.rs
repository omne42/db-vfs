use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;
use super::util::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub workspace_id: String,
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub expected_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    pub path: String,
    pub bytes_written: u64,
    pub created: bool,
    pub version: u64,
}

pub(super) fn write<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: WriteRequest,
) -> Result<WriteResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.write, "write")?;
    validate_workspace_id(&request.workspace_id)?;

    let path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
    }

    let bytes_written = request.content.len() as u64;
    if bytes_written > vfs.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path,
            size_bytes: bytes_written,
            max_bytes: vfs.policy.limits.max_write_bytes,
        });
    }

    let now_ms = now_ms();
    let record = match request.expected_version {
        None => {
            vfs.store
                .insert_file_new(&request.workspace_id, &path, &request.content, now_ms)?
        }
        Some(expected) => vfs.store.update_file_cas(
            &request.workspace_id,
            &path,
            &request.content,
            expected,
            now_ms,
        )?,
    };

    Ok(WriteResponse {
        path,
        bytes_written,
        created: request.expected_version.is_none(),
        version: record.version,
    })
}
