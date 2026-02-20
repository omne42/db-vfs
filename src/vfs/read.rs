use serde::{Deserialize, Serialize};
use std::time::Duration;

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::DbVfs;

const MAX_CONTENT_LOAD_ATTEMPTS: usize = 8;
const CONTENT_RETRY_BACKOFF_MS: u64 = 2;
const CONTENT_RETRY_YIELD_ATTEMPTS: usize = 4;

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
    pub requested_path: String,
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

    let requested_path = normalize_path(&request.path)?;
    if vfs.redactor.is_path_denied(&requested_path) {
        return Err(Error::SecretPathDenied(requested_path));
    }

    let Some(meta) = vfs.store.get_meta(&request.workspace_id, &requested_path)? else {
        return Err(Error::NotFound("file not found".to_string()));
    };

    let (mut content, version) = match (request.start_line, request.end_line) {
        (None, None) => {
            let (meta, content) =
                load_content_with_retry(vfs, &request.workspace_id, &requested_path, meta)?;
            (content, meta.version)
        }
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            let (meta, content) =
                load_content_with_retry(vfs, &request.workspace_id, &requested_path, meta)?;
            let extracted = extract_line_range(
                &content,
                start_line,
                end_line,
                vfs.policy.limits.max_read_bytes,
                meta.size_bytes,
                &requested_path,
            )?;
            (extracted, meta.version)
        }
        _ => {
            return Err(Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            ));
        }
    };

    let max_read_bytes = vfs.policy.limits.max_read_bytes;
    let max_read_bytes_usize = usize::try_from(max_read_bytes).unwrap_or(usize::MAX);
    content = vfs
        .redactor
        .redact_text_owned_bounded(content, max_read_bytes_usize)
        .map_err(|size| Error::FileTooLarge {
            path: requested_path.clone(),
            size_bytes: size as u64,
            max_bytes: max_read_bytes,
        })?;

    let bytes_read = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if bytes_read > max_read_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path,
            size_bytes: bytes_read,
            max_bytes: max_read_bytes,
        });
    }
    Ok(ReadResponse {
        path: requested_path.clone(),
        requested_path,
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
                None => {
                    Error::NotFound(format!("file not found (path={path}, attempts={attempts})"))
                }
                Some(now) => {
                    if now.version != meta.version {
                        Error::Conflict(format!(
                            "file changed during read (path={path}, expected_version={}, actual_version={}, attempts={attempts})",
                            meta.version, now.version
                        ))
                    } else {
                        Error::Db(format!(
                            "file content could not be loaded (path={path}, version={}, attempts={attempts})",
                            meta.version
                        ))
                    }
                }
            });
        }
        attempts += 1;

        match vfs.store.get_content(workspace_id, path, meta.version)? {
            Some(content) => {
                let content_size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
                if content_size_bytes > max_bytes {
                    return Err(Error::FileTooLarge {
                        path: path.to_string(),
                        size_bytes: content_size_bytes,
                        max_bytes,
                    });
                }
                return Ok((meta, content));
            }
            None => {
                meta = vfs.store.get_meta(workspace_id, path)?.ok_or_else(|| {
                    Error::NotFound(format!("file not found (path={path}, attempts={attempts})"))
                })?;
                // Favor immediate rescheduling on early misses to reduce blocked-worker time.
                if attempts <= CONTENT_RETRY_YIELD_ATTEMPTS {
                    std::thread::yield_now();
                } else {
                    // `read` is synchronous; service runs it in a blocking worker.
                    // Keep a tiny backoff here to avoid tight spinning on rapidly mutating rows.
                    std::thread::sleep(Duration::from_millis(CONTENT_RETRY_BACKOFF_MS));
                }
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
    let content_size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if content_size_bytes > max_scan_bytes {
        return Err(Error::FileTooLarge {
            path: path.to_string(),
            size_bytes: file_size_bytes.max(content_size_bytes),
            max_bytes: max_scan_bytes,
        });
    }

    let bytes = content.as_bytes();
    let mut pos: usize = 0;
    let mut current_line: u64 = 0;

    let mut start_pos: Option<usize> = None;
    let mut end_pos: Option<usize> = None;

    while pos < bytes.len() {
        let next = match memchr::memchr(b'\n', &bytes[pos..]) {
            Some(offset) => pos.saturating_add(offset).saturating_add(1), // include newline
            None => bytes.len(),
        };

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

    use crate::store::{DeleteOutcome, FileMeta, Store};
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
    fn read_fails_when_actual_content_exceeds_read_limit_even_if_meta_is_stale() {
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content: "abcdef".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 4;

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

    #[test]
    fn extract_line_range_handles_no_trailing_newline() {
        let content = "a\nb";
        let out = extract_line_range(content, 2, 2, 1024, content.len() as u64, "a.txt")
            .expect("line range");
        assert_eq!(out, "b");
    }

    #[test]
    fn extract_line_range_rejects_out_of_bounds() {
        let err = extract_line_range("a\n", 2, 2, 1024, 2, "a.txt").expect_err("out of bounds");
        assert_eq!(err.code(), "invalid_path");
    }
}
