use serde::{Deserialize, Serialize};
use std::time::Duration;

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

use crate::store::line_segments;

use super::DbVfs;

const MAX_CONTENT_LOAD_ATTEMPTS: usize = 8;
const CONTENT_RETRY_BACKOFF_MS: u64 = 2;
const CONTENT_RETRY_YIELD_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    let has_redaction_rules = vfs.redactor.has_redact_rules();
    let max_read_bytes = vfs.policy.limits.max_read_bytes;
    let max_read_bytes_usize = usize::try_from(max_read_bytes).unwrap_or(usize::MAX);
    let (mut content, version, already_redacted) = match (request.start_line, request.end_line) {
        (None, None) => {
            let (meta, content) =
                load_content_with_retry(vfs, &request.workspace_id, &requested_path, meta, true)?;
            (content, meta.version, false)
        }
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            if has_redaction_rules {
                let (meta, content) = load_content_with_retry(
                    vfs,
                    &request.workspace_id,
                    &requested_path,
                    meta,
                    true,
                )?;
                let content = vfs
                    .redactor
                    .redact_text_owned_bounded(content, max_read_bytes_usize)
                    .map_err(|size| {
                        file_too_large_due_to_redaction(&requested_path, size, max_read_bytes)
                    })?;
                let extracted = extract_line_range(
                    &content,
                    start_line,
                    end_line,
                    max_read_bytes,
                    meta.size_bytes,
                    &requested_path,
                )?;
                (extracted, meta.version, true)
            } else {
                let (meta, extracted) = load_line_range_with_retry(
                    vfs,
                    &request.workspace_id,
                    &requested_path,
                    meta,
                    start_line,
                    end_line,
                )?;
                (extracted, meta.version, false)
            }
        }
        _ => {
            return Err(Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            ));
        }
    };

    if !already_redacted {
        content = vfs
            .redactor
            .redact_text_owned_bounded(content, max_read_bytes_usize)
            .map_err(|size| {
                file_too_large_due_to_redaction(&requested_path, size, max_read_bytes)
            })?;
    }

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

fn file_too_large_due_to_redaction(path: &str, size: usize, max_bytes: u64) -> Error {
    Error::FileTooLarge {
        path: path.to_string(),
        size_bytes: u64::try_from(size).unwrap_or(u64::MAX),
        max_bytes,
    }
}

fn load_content_with_retry<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    workspace_id: &str,
    path: &str,
    mut meta: crate::store::FileMeta,
    enforce_max_bytes: bool,
) -> Result<(crate::store::FileMeta, String)> {
    let max_bytes = vfs.policy.limits.max_read_bytes;
    let mut attempts: usize = 0;
    loop {
        if attempts >= MAX_CONTENT_LOAD_ATTEMPTS {
            let now = vfs.store.get_meta(workspace_id, path)?;
            return Err(match now {
                None => read_not_found_err(path, attempts),
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

        if enforce_max_bytes && meta.size_bytes > max_bytes {
            // Re-check metadata once before failing hard. This avoids false
            // `file_too_large` errors when a newer/smaller version won the race
            // between the caller's initial meta read and content fetch.
            let Some(now) = vfs.store.get_meta(workspace_id, path)? else {
                return Err(read_not_found_err(path, attempts));
            };
            if now.version != meta.version || now.size_bytes <= max_bytes {
                meta = now;
                continue;
            }
            return Err(Error::FileTooLarge {
                path: path.to_string(),
                size_bytes: now.size_bytes.max(meta.size_bytes),
                max_bytes,
            });
        }

        match vfs.store.get_content(workspace_id, path, meta.version)? {
            Some(content) => {
                let content_size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
                if enforce_max_bytes && content_size_bytes > max_bytes {
                    return Err(Error::FileTooLarge {
                        path: path.to_string(),
                        size_bytes: content_size_bytes,
                        max_bytes,
                    });
                }
                return Ok((meta, content));
            }
            None => {
                meta = vfs
                    .store
                    .get_meta(workspace_id, path)?
                    .ok_or_else(|| read_not_found_err(path, attempts))?;
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

fn load_line_range_with_retry<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    workspace_id: &str,
    path: &str,
    mut meta: crate::store::FileMeta,
    start_line: u64,
    end_line: u64,
) -> Result<(crate::store::FileMeta, String)> {
    let max_bytes = vfs.policy.limits.max_read_bytes;
    let mut attempts: usize = 0;
    loop {
        if attempts >= MAX_CONTENT_LOAD_ATTEMPTS {
            let now = vfs.store.get_meta(workspace_id, path)?;
            return Err(match now {
                None => read_not_found_err(path, attempts),
                Some(now) => {
                    if now.version != meta.version {
                        Error::Conflict(format!(
                            "file changed during read (path={path}, expected_version={}, actual_version={}, attempts={attempts})",
                            meta.version, now.version
                        ))
                    } else {
                        Error::Db(format!(
                            "file line range could not be loaded (path={path}, version={}, attempts={attempts})",
                            meta.version
                        ))
                    }
                }
            });
        }
        attempts += 1;

        match vfs.store.get_line_range(
            workspace_id,
            path,
            meta.version,
            start_line,
            end_line,
            max_bytes,
        )? {
            Some(range) => {
                if range.total_lines < end_line || start_line > range.total_lines {
                    return Err(line_range_out_of_bounds_error(
                        path,
                        start_line,
                        end_line,
                        range.total_lines,
                    ));
                }
                if range.bytes_read > max_bytes {
                    return Err(Error::FileTooLarge {
                        path: path.to_string(),
                        size_bytes: range.bytes_read,
                        max_bytes,
                    });
                }
                let content = range.content.ok_or_else(|| {
                    Error::Db(format!(
                        "store returned no content for in-bounds line range (path={path}, version={})",
                        meta.version
                    ))
                })?;
                return Ok((meta, content));
            }
            None => {
                meta = vfs
                    .store
                    .get_meta(workspace_id, path)?
                    .ok_or_else(|| read_not_found_err(path, attempts))?;
                if attempts <= CONTENT_RETRY_YIELD_ATTEMPTS {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(Duration::from_millis(CONTENT_RETRY_BACKOFF_MS));
                }
            }
        }
    }
}

fn read_not_found_err(path: &str, attempts: usize) -> Error {
    Error::NotFound(format!("file not found (path={path}, attempts={attempts})"))
}

fn line_range_out_of_bounds_error(
    _path: &str,
    start_line: u64,
    end_line: u64,
    line_count: u64,
) -> Error {
    Error::InvalidPath(format!(
        "line range {}..{} out of bounds (file has {} lines)",
        start_line, end_line, line_count
    ))
}

fn extract_line_range(
    content: &str,
    start_line: u64,
    end_line: u64,
    max_read_bytes: u64,
    _file_size_bytes: u64,
    path: &str,
) -> Result<String> {
    let mut current_line = 0u64;
    let mut slice = None;

    for segment in line_segments(content) {
        current_line = current_line.saturating_add(1);
        if current_line == start_line {
            slice = Some(String::new());
        }
        if let Some(buffer) = slice.as_mut()
            && current_line >= start_line
            && current_line <= end_line
        {
            buffer.push_str(segment.full);
        }
        if current_line == end_line {
            break;
        }
    }

    if current_line < start_line || current_line < end_line {
        return Err(line_range_out_of_bounds_error(
            path,
            start_line,
            end_line,
            current_line,
        ));
    }

    let Some(slice) = slice else {
        return Err(line_range_out_of_bounds_error(
            path,
            start_line,
            end_line,
            current_line,
        ));
    };
    let slice_size_bytes = u64::try_from(slice.len()).unwrap_or(u64::MAX);
    if slice_size_bytes > max_read_bytes {
        return Err(Error::FileTooLarge {
            path: path.to_string(),
            size_bytes: slice_size_bytes,
            max_bytes: max_read_bytes,
        });
    }
    Ok(slice)
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

    struct StaleLargeMetaStore {
        meta_calls: usize,
    }

    impl Store for StaleLargeMetaStore {
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
                    version: 2,
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
            if version == 2 {
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
    fn read_rechecks_oversized_meta_before_failing() {
        let store = StaleLargeMetaStore { meta_calls: 0 };
        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 4;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: None,
                end_line: None,
            })
            .expect("read");
        assert_eq!(resp.version, 2);
        assert_eq!(resp.content, "ok");
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

    struct ChunkOnlyStore {
        meta: FileMeta,
        content: String,
        chunk_chars: usize,
        chunk_reads: usize,
    }

    impl Store for ChunkOnlyStore {
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
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            panic!("chunked ranged read should not fall back to get_content");
        }

        fn get_content_chunk(
            &mut self,
            _workspace_id: &str,
            path: &str,
            version: u64,
            start_char: u64,
            max_chars: usize,
        ) -> Result<Option<String>> {
            if path != self.meta.path || version != self.meta.version {
                return Ok(None);
            }

            self.chunk_reads = self.chunk_reads.saturating_add(1);
            let take = max_chars.min(self.chunk_chars);
            let start_idx = usize::try_from(start_char.saturating_sub(1))
                .map_err(|_| Error::Db("integer overflow converting start_char".to_string()))?;
            Ok(Some(
                self.content.chars().skip(start_idx).take(take).collect(),
            ))
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
    fn extract_line_range_treats_cr_only_as_line_break() {
        let content = "a\rb\rc";
        let out = extract_line_range(content, 2, 2, 1024, content.len() as u64, "a.txt")
            .expect("line range");
        assert_eq!(out, "b\r");
    }

    #[test]
    fn extract_line_range_preserves_crlf_boundaries() {
        let content = "a\r\nb\r\nc";
        let out = extract_line_range(content, 2, 2, 1024, content.len() as u64, "a.txt")
            .expect("line range");
        assert_eq!(out, "b\r\n");
    }

    #[test]
    fn extract_line_range_rejects_out_of_bounds() {
        let err = extract_line_range("a\n", 2, 2, 1024, 2, "a.txt").expect_err("out of bounds");
        assert_eq!(err.code(), "invalid_path");
    }

    #[test]
    fn ranged_read_allows_large_file_when_selected_slice_is_small() {
        let content = "line-1\nline-2\nline-3\n".repeat(64);
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 8;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(2),
                end_line: Some(2),
            })
            .expect("ranged read");
        assert_eq!(resp.content, "line-2\n");
        assert_eq!(resp.bytes_read, 7);
    }

    #[test]
    fn ranged_read_without_redaction_uses_chunked_store_reads() {
        let content = "line-1\nline-2\nline-3\n".repeat(32);
        let store = ChunkOnlyStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content,
            chunk_chars: 5,
            chunk_reads: 0,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 8;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(2),
                end_line: Some(2),
            })
            .expect("ranged read");
        assert_eq!(resp.content, "line-2\n");
        assert!(vfs.store_mut().chunk_reads > 1);
    }

    #[test]
    fn ranged_read_with_chunked_store_handles_crlf_split_across_chunks() {
        let content = "line-1\r\nline-2\r\nline-3\r\n".to_string();
        let store = ChunkOnlyStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content,
            chunk_chars: 4,
            chunk_reads: 0,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 16;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(2),
                end_line: Some(2),
            })
            .expect("ranged read");
        assert_eq!(resp.content, "line-2\r\n");
        assert!(vfs.store_mut().chunk_reads > 1);
    }

    #[test]
    fn ranged_read_still_rejects_selected_slice_that_exceeds_limit() {
        let content = "12345\nabcdef\n";
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 4;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(1),
                end_line: Some(1),
            })
            .expect_err("slice should be too large");
        assert_eq!(err.code(), "file_too_large");
    }

    #[test]
    fn ranged_read_redacts_multiline_matches_before_extracting_lines() {
        let content = "BEGIN\nsecret\nEND\npublic\n";
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.secrets.redact_regexes = vec!["BEGIN\\nsecret\\nEND".to_string()];
        policy.secrets.replacement = "REDACTED".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(2),
                end_line: Some(3),
            })
            .expect("ranged read");
        assert_eq!(resp.content, "\n\n");
    }

    #[test]
    fn ranged_read_with_redaction_rules_rejects_large_file_before_slice_extraction() {
        let content = "line-1\nline-2\nline-3\n".repeat(64);
        let store = StaticContentStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 8;
        policy.secrets.redact_regexes = vec!["secret".to_string()];
        policy.secrets.replacement = "x".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(2),
                end_line: Some(2),
            })
            .expect_err("redacted whole-file intermediate should stay budgeted");
        assert_eq!(err.code(), "file_too_large");
    }

    struct OversizedRedactionInputStore {
        meta: FileMeta,
    }

    impl Store for OversizedRedactionInputStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            Ok(Some(self.meta.clone()))
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            panic!("oversized redaction path should fail before loading full content")
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
    fn ranged_read_with_redaction_rules_rejects_oversized_raw_input_before_loading_content() {
        let store = OversizedRedactionInputStore {
            meta: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: 1024,
                version: 1,
                updated_at_ms: 0,
            },
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.read = true;
        policy.limits.max_read_bytes = 8;
        policy.secrets.redact_regexes = vec!["secret".to_string()];
        policy.secrets.replacement = "x".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .read(ReadRequest {
                workspace_id: "ws".to_string(),
                path: "docs/a.txt".to_string(),
                start_line: Some(1),
                end_line: Some(1),
            })
            .expect_err("oversized raw content should fail before full-content load");
        assert_eq!(err.code(), "file_too_large");
    }
}
