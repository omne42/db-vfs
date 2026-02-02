use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub workspace_id: String,
    pub path: String,
    #[serde(default)]
    pub start_line: Option<u64>,
    #[serde(default)]
    pub end_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub path: String,
    pub bytes_read: u64,
    pub content: String,
    /// Always `false`: `read` fails instead of truncating.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    pub version: u64,
}

pub(super) fn read<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: ReadRequest,
) -> Result<ReadResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.read, "read")?;
    validate_workspace_id(&request.workspace_id)?;

    let path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&path) {
        return Err(Error::SecretPathDenied(path));
    }

    let Some(mut meta) = vfs.store.get_meta(&request.workspace_id, &path)? else {
        return Err(Error::NotFound("file not found".to_string()));
    };

    let (bytes_read, content, version) = match (request.start_line, request.end_line) {
        (None, None) => {
            if meta.size_bytes > vfs.policy.limits.max_read_bytes {
                return Err(Error::FileTooLarge {
                    path,
                    size_bytes: meta.size_bytes,
                    max_bytes: vfs.policy.limits.max_read_bytes,
                });
            }

            let content = loop {
                if meta.size_bytes > vfs.policy.limits.max_read_bytes {
                    return Err(Error::FileTooLarge {
                        path,
                        size_bytes: meta.size_bytes,
                        max_bytes: vfs.policy.limits.max_read_bytes,
                    });
                }
                match vfs
                    .store
                    .get_content(&request.workspace_id, &path, meta.version)?
                {
                    Some(content) => break content,
                    None => {
                        meta = vfs
                            .store
                            .get_meta(&request.workspace_id, &path)?
                            .ok_or_else(|| Error::NotFound("file not found".to_string()))?;
                        continue;
                    }
                }
            };

            (meta.size_bytes, content, meta.version)
        }
        (Some(start_line), Some(end_line)) => {
            if meta.size_bytes > vfs.policy.limits.max_read_bytes {
                return Err(Error::FileTooLarge {
                    path,
                    size_bytes: meta.size_bytes,
                    max_bytes: vfs.policy.limits.max_read_bytes,
                });
            }

            let content = loop {
                if meta.size_bytes > vfs.policy.limits.max_read_bytes {
                    return Err(Error::FileTooLarge {
                        path,
                        size_bytes: meta.size_bytes,
                        max_bytes: vfs.policy.limits.max_read_bytes,
                    });
                }

                match vfs
                    .store
                    .get_content(&request.workspace_id, &path, meta.version)?
                {
                    Some(content) => break content,
                    None => {
                        meta = vfs
                            .store
                            .get_meta(&request.workspace_id, &path)?
                            .ok_or_else(|| Error::NotFound("file not found".to_string()))?;
                        continue;
                    }
                }
            };

            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            let extracted = extract_line_range(
                &content,
                start_line,
                end_line,
                vfs.policy.limits.max_read_bytes,
                meta.size_bytes,
                &path,
            )?;
            let bytes_read = extracted.len() as u64;
            (bytes_read, extracted, meta.version)
        }
        _ => {
            return Err(Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            ));
        }
    };

    let content = vfs.redactor.redact_text(&content);
    Ok(ReadResponse {
        path,
        bytes_read,
        content,
        truncated: false,
        start_line: request.start_line,
        end_line: request.end_line,
        version,
    })
}

fn extract_line_range(
    content: &str,
    start_line: u64,
    end_line: u64,
    max_scan_bytes: u64,
    file_size_bytes: u64,
    path: &str,
) -> Result<String> {
    let bytes = content.as_bytes();
    let mut pos: usize = 0;
    let mut current_line: u64 = 0;
    let mut scanned_bytes: u64 = 0;

    let mut start_pos: Option<usize> = None;
    let mut end_pos: Option<usize> = None;

    while pos < bytes.len() {
        let mut next = pos;
        while next < bytes.len() && bytes[next] != b'\n' {
            next += 1;
        }
        if next < bytes.len() && bytes[next] == b'\n' {
            next += 1; // include newline
        }

        scanned_bytes = scanned_bytes.saturating_add((next - pos) as u64);
        if scanned_bytes > max_scan_bytes {
            let size_bytes = file_size_bytes.max(scanned_bytes);
            return Err(Error::FileTooLarge {
                path: path.to_string(),
                size_bytes,
                max_bytes: max_scan_bytes,
            });
        }

        current_line += 1;
        if current_line == start_line {
            start_pos = Some(pos);
        }
        if current_line == end_line {
            end_pos = Some(next);
            break;
        }

        pos = next;
    }

    let Some(start_pos) = start_pos else {
        return Err(Error::InvalidPath(format!(
            "line range {}..{} out of bounds (file has {} lines)",
            start_line, end_line, current_line
        )));
    };
    let Some(end_pos) = end_pos else {
        return Err(Error::InvalidPath(format!(
            "line range {}..{} out of bounds (file has {} lines)",
            start_line, end_line, current_line
        )));
    };

    let slice = &content[start_pos..end_pos];
    Ok(slice.to_string())
}
