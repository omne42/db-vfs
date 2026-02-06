use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::{Error, Result};

use super::util::{compile_glob, derive_safe_prefix_from_glob, elapsed_ms, glob_is_match};
use super::{DbVfs, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepRequest {
    pub workspace_id: String,
    pub query: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub line: u64,
    pub text: String,
    #[serde(default)]
    pub line_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResponse {
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
    #[serde(default)]
    pub skipped_too_large_files: u64,
    #[serde(default)]
    pub skipped_traversal_skipped: u64,
    #[serde(default)]
    pub skipped_secret_denied: u64,
    #[serde(default)]
    pub skipped_glob_mismatch: u64,
    #[serde(default)]
    pub skipped_missing_content: u64,
    #[serde(default)]
    pub scanned_files: u64,
    #[serde(default)]
    pub scan_limit_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_limit_reason: Option<ScanLimitReason>,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub scanned_entries: u64,
}

const MAX_GREP_REGEX_COMPILED_SIZE_BYTES: usize = 1_000_000;
const MAX_GREP_REGEX_NEST_LIMIT: u32 = 128;
const MAX_GREP_QUERY_BYTES: usize = 4096;

fn summarize_pattern_for_error(pattern: &str) -> String {
    const MAX_BYTES: usize = 200;
    if pattern.len() <= MAX_BYTES {
        return pattern.to_string();
    }
    let mut end = MAX_BYTES;
    while end > 0 && !pattern.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &pattern[..end])
}

fn validate_grep_query(query: &str, regex: bool) -> Result<()> {
    if query.is_empty() {
        return Err(if regex {
            Error::InvalidRegex("grep regex must be non-empty".to_string())
        } else {
            Error::InvalidPath("grep query must be non-empty".to_string())
        });
    }

    if query.len() > MAX_GREP_QUERY_BYTES {
        return Err(if regex {
            Error::InvalidRegex(format!(
                "grep regex is too large ({} bytes; max {} bytes)",
                query.len(),
                MAX_GREP_QUERY_BYTES
            ))
        } else {
            Error::InputTooLarge {
                size_bytes: query.len() as u64,
                max_bytes: MAX_GREP_QUERY_BYTES as u64,
            }
        });
    }

    Ok(())
}

pub(super) fn grep<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: GrepRequest,
) -> Result<GrepResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.grep, "grep")?;
    validate_workspace_id(&request.workspace_id)?;
    validate_grep_query(&request.query, request.regex)?;

    if vfs.policy.limits.max_results == 0 {
        return Ok(GrepResponse {
            matches: Vec::new(),
            truncated: true,
            skipped_too_large_files: 0,
            skipped_traversal_skipped: 0,
            skipped_secret_denied: 0,
            skipped_glob_mismatch: 0,
            skipped_missing_content: 0,
            scanned_files: 0,
            scan_limit_reached: true,
            scan_limit_reason: Some(ScanLimitReason::Results),
            elapsed_ms: 0,
            scanned_entries: 0,
        });
    }

    let started = std::time::Instant::now();
    let max_walk = vfs
        .policy
        .limits
        .max_walk_ms
        .map(std::time::Duration::from_millis);

    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;

    let prefix = match request.path_prefix {
        Some(prefix) => normalize_path_prefix(&prefix)?,
        None => request
            .glob
            .as_deref()
            .and_then(derive_safe_prefix_from_glob)
            .ok_or_else(|| {
                Error::NotPermitted("grep requires an explicit path_prefix".to_string())
            })?,
    };
    if prefix.is_empty() && !vfs.policy.permissions.allow_full_scan {
        return Err(Error::NotPermitted(
            "grep requires a non-empty path_prefix unless allow_full_scan is enabled".to_string(),
        ));
    }

    let regex = if request.regex {
        let preview = summarize_pattern_for_error(&request.query);
        Some(
            regex::RegexBuilder::new(&request.query)
                .size_limit(MAX_GREP_REGEX_COMPILED_SIZE_BYTES)
                .nest_limit(MAX_GREP_REGEX_NEST_LIMIT)
                .build()
                .map_err(|err| {
                    Error::InvalidRegex(format!("invalid grep regex {preview:?}: {err}"))
                })?,
        )
    } else {
        None
    };

    let max_scan = vfs
        .policy
        .limits
        .max_walk_entries
        .min(vfs.policy.limits.max_walk_files)
        .max(1);
    let mut metas = vfs.store.list_metas_by_prefix(
        &request.workspace_id,
        &prefix,
        max_scan.saturating_add(1),
    )?;
    let truncated_by_store_limit = metas.len() > max_scan;
    if truncated_by_store_limit {
        metas.truncate(max_scan);
    }
    let truncated_reason = if vfs.policy.limits.max_walk_entries <= vfs.policy.limits.max_walk_files
    {
        ScanLimitReason::Entries
    } else {
        ScanLimitReason::Files
    };

    let mut matches = Vec::<GrepMatch>::new();
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_traversal_skipped: u64 = 0;
    let mut skipped_secret_denied: u64 = 0;
    let mut skipped_glob_mismatch: u64 = 0;
    let mut skipped_missing_content: u64 = 0;
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: u64 = 0;
    let mut scan_limit_reached = truncated_by_store_limit;
    let mut scan_limit_reason: Option<ScanLimitReason> =
        truncated_by_store_limit.then_some(truncated_reason);

    for meta in metas {
        scanned_entries = scanned_entries.saturating_add(1);

        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Time);
            break;
        }

        if vfs.traversal.is_path_skipped(&meta.path) {
            skipped_traversal_skipped = skipped_traversal_skipped.saturating_add(1);
            continue;
        }

        if vfs.redactor.is_path_denied(&meta.path) {
            skipped_secret_denied = skipped_secret_denied.saturating_add(1);
            continue;
        }

        if let Some(glob) = &file_glob
            && !glob_is_match(glob, &meta.path)
        {
            skipped_glob_mismatch = skipped_glob_mismatch.saturating_add(1);
            continue;
        }

        scanned_files = scanned_files.saturating_add(1);
        if scanned_files as usize > vfs.policy.limits.max_walk_files {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Files);
            break;
        }

        if meta.size_bytes > vfs.policy.limits.max_read_bytes {
            skipped_too_large_files = skipped_too_large_files.saturating_add(1);
            continue;
        }

        let Some(content) =
            vfs.store
                .get_content(&request.workspace_id, &meta.path, meta.version)?
        else {
            skipped_missing_content = skipped_missing_content.saturating_add(1);
            continue;
        };

        for (idx, line) in content.lines().enumerate() {
            if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Time);
                break;
            }

            let ok = match &regex {
                Some(regex) => regex.is_match(line),
                None => line.contains(&request.query),
            };
            if !ok {
                continue;
            }

            let max_line_bytes = vfs.policy.limits.max_line_bytes;
            let mut line_truncated = line.len() > max_line_bytes;
            let mut end = line.len().min(max_line_bytes);
            while end > 0 && !line.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            let mut text = vfs.redactor.redact_text(&line[..end]);
            if text.len() > max_line_bytes {
                line_truncated = true;
                let mut out_end = max_line_bytes;
                while out_end > 0 && !text.is_char_boundary(out_end) {
                    out_end = out_end.saturating_sub(1);
                }
                text.truncate(out_end);
            }
            matches.push(GrepMatch {
                path: meta.path.clone(),
                line: idx.saturating_add(1) as u64,
                text,
                line_truncated,
            });

            if matches.len() >= vfs.policy.limits.max_results {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Results);
                break;
            }
        }

        if scan_limit_reached && matches.len() >= vfs.policy.limits.max_results {
            break;
        }
    }

    matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    Ok(GrepResponse {
        matches,
        truncated: scan_limit_reached,
        skipped_too_large_files,
        skipped_traversal_skipped,
        skipped_secret_denied,
        skipped_glob_mismatch,
        skipped_missing_content,
        scanned_files,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::{DeleteOutcome, FileMeta, FileRecord, Store};
    use db_vfs_core::policy::VfsPolicy;

    struct DummyStore;

    impl Store for DummyStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            unimplemented!()
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
    fn grep_rejects_empty_query() {
        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;

        let mut vfs = DbVfs::new(DummyStore, policy).expect("vfs");
        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "invalid_path");

        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "".to_string(),
                regex: true,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail");
        assert_eq!(err.code(), "invalid_regex");
    }

    struct SingleFileStore {
        meta: FileMeta,
        content: String,
    }

    impl Store for SingleFileStore {
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
            prefix: &str,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            if self.meta.path.starts_with(prefix) {
                Ok(vec![self.meta.clone()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[test]
    fn grep_truncates_after_redaction_expansion() {
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 2,
                version: 1,
                updated_at_ms: 0,
            },
            content: "a\n".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;
        policy.limits.max_line_bytes = 1;
        policy.secrets.redact_regexes = vec!["a".to_string()];
        policy.secrets.replacement = "XX".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "a".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].text, "X");
        assert!(resp.matches[0].line_truncated);
    }
}
