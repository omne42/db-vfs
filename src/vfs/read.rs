use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;

const MAX_CONTENT_LOAD_ATTEMPTS: usize = 8;

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

    let Some(meta) = vfs.store.get_meta(&request.workspace_id, &path)? else {
        return Err(Error::NotFound("file not found".to_string()));
    };

    let (mut content, version) = match (request.start_line, request.end_line) {
        (None, None) => {
            let (meta, content) = load_content_with_retry(vfs, &request.workspace_id, &path, meta)?;
            (content, meta.version)
        }
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            let (meta, content) = load_content_with_retry(vfs, &request.workspace_id, &path, meta)?;
            let extracted = extract_line_range(
                &content,
                start_line,
                end_line,
                vfs.policy.limits.max_read_bytes,
                meta.size_bytes,
                &path,
            )?;
            (extracted, meta.version)
        }
        _ => {
            return Err(Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            ));
        }
    };

    content = vfs.redactor.redact_text(&content);
    let bytes_read = content.len() as u64;
    if bytes_read > vfs.policy.limits.max_read_bytes {
        return Err(Error::FileTooLarge {
            path,
            size_bytes: bytes_read,
            max_bytes: vfs.policy.limits.max_read_bytes,
        });
    }
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

fn load_content_with_retry<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    workspace_id: &str,
    path: &str,
    mut meta: crate::store::FileMeta,
) -> Result<(crate::store::FileMeta, String)> {
    let max_bytes = vfs.policy.limits.max_read_bytes;
    let mut attempts: usize = 0;
    loop {
        if meta.size_bytes > max_bytes {
            return Err(Error::FileTooLarge {
                path: path.to_string(),
                size_bytes: meta.size_bytes,
                max_bytes,
            });
        }

        if attempts >= MAX_CONTENT_LOAD_ATTEMPTS {
            let now = vfs.store.get_meta(workspace_id, path)?;
            return Err(match now {
                None => Error::NotFound("file not found".to_string()),
                Some(now) => {
                    if now.version != meta.version {
                        Error::Conflict("file changed during read; please retry".to_string())
                    } else {
                        Error::Db("file content could not be loaded".to_string())
                    }
                }
            });
        }
        attempts += 1;

        match vfs.store.get_content(workspace_id, path, meta.version)? {
            Some(content) => return Ok((meta, content)),
            None => {
                meta = vfs
                    .store
                    .get_meta(workspace_id, path)?
                    .ok_or_else(|| Error::NotFound("file not found".to_string()))?;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::{DeleteOutcome, FileMeta, FileRecord, Store};
    use db_vfs_core::policy::VfsPolicy;

    struct MissingContentStore {
        meta: FileMeta,
    }

    impl Store for MissingContentStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            Ok(Some(self.meta.clone()))
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<FileRecord> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<FileRecord> {
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
    fn read_fails_after_retry_cap_when_content_missing() {
        let store = MissingContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 4,
                version: 1,
                updated_at_ms: 0,
            },
        };
        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: None,
                end_line: None,
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "db");
    }

    struct FlappingMetaStore {
        version: u64,
    }

    impl Store for FlappingMetaStore {
        fn get_meta(&mut self, _workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
            let v = self.version;
            self.version = self.version.saturating_add(1);
            Ok(Some(FileMeta {
                path: path.to_string(),
                size_bytes: 1,
                version: v,
                updated_at_ms: 0,
            }))
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<FileRecord> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<FileRecord> {
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
    fn read_returns_conflict_when_file_changes_during_retries() {
        let store = FlappingMetaStore { version: 1 };
        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: None,
                end_line: None,
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "conflict");
    }

    struct StaticContentStore {
        meta: FileMeta,
        content: String,
    }

    impl Store for StaticContentStore {
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
        ) -> Result<FileRecord> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<FileRecord> {
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
    fn read_fails_when_redaction_expands_beyond_max_read_bytes() {
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content: "a".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 5;
        policy.secrets.redact_regexes = vec!["a".to_string()];
        policy.secrets.replacement = "xxxxxx".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: None,
                end_line: None,
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "file_too_large");
    }

    #[test]
    fn read_bytes_read_counts_returned_bytes_after_redaction() {
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 6,
                version: 1,
                updated_at_ms: 0,
            },
            content: "secret".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.secrets.redact_regexes = vec!["secret".to_string()];
        policy.secrets.replacement = "x".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: None,
                end_line: None,
            })
            .expect("read");
        assert_eq!(resp.content, "x");
        assert_eq!(resp.bytes_read, 1);
    }
}
