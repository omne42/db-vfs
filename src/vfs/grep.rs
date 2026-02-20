use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::policy::MAX_SCAN_RESPONSE_BYTES;
use db_vfs_core::{Error, Result};

use super::util::{
    compile_glob, derive_safe_prefix_from_glob, elapsed_ms, glob_is_match, json_escaped_str_len,
    u64_decimal_len,
};
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
const META_PAGE_SIZE: usize = 2048;
const GREP_RESPONSE_JSON_FIXED_OVERHEAD: usize = 4096;

fn advance_after_cursor(
    after: &mut Option<String>,
    metas: &[crate::store::FileMeta],
    op: &'static str,
) -> Result<()> {
    let Some(next_after) = metas.last().map(|meta| meta.path.as_str()) else {
        return Ok(());
    };
    if let Some(prev_after) = after.as_ref()
        && next_after <= prev_after.as_str()
    {
        return Err(Error::Db(format!(
            "{op}: store returned non-monotonic pagination cursor (prev={prev_after:?}, next={next_after:?})"
        )));
    }
    if let Some(cursor) = after.as_mut() {
        cursor.clear();
        cursor.push_str(next_after);
    } else {
        *after = Some(next_after.to_string());
    }
    Ok(())
}

fn ensure_page_strictly_increasing(
    metas: &[crate::store::FileMeta],
    op: &'static str,
) -> Result<()> {
    for pair in metas.windows(2) {
        if pair[0].path >= pair[1].path {
            return Err(Error::Db(format!(
                "{op}: store returned non-monotonic page ordering (prev={:?}, next={:?})",
                pair[0].path, pair[1].path
            )));
        }
    }
    Ok(())
}

fn ensure_page_starts_after_cursor(
    metas: &[crate::store::FileMeta],
    after: Option<&str>,
    op: &'static str,
) -> Result<()> {
    let (Some(prev_after), Some(first)) = (after, metas.first()) else {
        return Ok(());
    };
    if first.path.as_str() <= prev_after {
        return Err(Error::Db(format!(
            "{op}: store returned rows not strictly after pagination cursor (after={prev_after:?}, first={:?})",
            first.path
        )));
    }
    Ok(())
}

fn grep_match_json_bytes(
    path_json_escaped_len: usize,
    line_no: u64,
    text: &str,
    line_truncated: bool,
) -> usize {
    // {"path":"...","line":123,"text":"...","line_truncated":false}
    let bool_len = if line_truncated { 4 } else { 5 };
    "{\"path\":\""
        .len()
        .saturating_add(path_json_escaped_len)
        .saturating_add("\",\"line\":".len())
        .saturating_add(u64_decimal_len(line_no))
        .saturating_add(",\"text\":\"".len())
        .saturating_add(json_escaped_str_len(text))
        .saturating_add("\",\"line_truncated\":".len())
        .saturating_add(bool_len)
        .saturating_add("}".len())
}

fn clamp_char_boundary(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &input[..end]
}

fn summarize_pattern_for_error(pattern: &str) -> String {
    const MAX_BYTES: usize = 200;
    if pattern.len() <= MAX_BYTES {
        return pattern.to_string();
    }
    format!("{}…", clamp_char_boundary(pattern, MAX_BYTES))
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
        Some(
            regex::RegexBuilder::new(&request.query)
                .size_limit(MAX_GREP_REGEX_COMPILED_SIZE_BYTES)
                .nest_limit(MAX_GREP_REGEX_NEST_LIMIT)
                .build()
                .map_err(|err| {
                    let preview = summarize_pattern_for_error(&request.query);
                    Error::InvalidRegex(format!("invalid grep regex {preview:?}: {err}"))
                })?,
        )
    } else {
        None
    };
    let literal_finder = if request.regex {
        None
    } else {
        Some(memchr::memmem::Finder::new(request.query.as_bytes()))
    };
    let literal_query_spans_lines = !request.regex && request.query.as_bytes().contains(&b'\n');

    let max_scan_entries = vfs.policy.limits.max_walk_entries.max(1);
    let max_scan_files = vfs.policy.limits.max_walk_files.max(1);
    let max_scan_files_u64 = u64::try_from(max_scan_files).unwrap_or(u64::MAX);
    let max_read_bytes = vfs.policy.limits.max_read_bytes;

    let mut matches = Vec::<GrepMatch>::with_capacity(vfs.policy.limits.max_results.min(1024));
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_traversal_skipped: u64 = 0;
    let mut skipped_secret_denied: u64 = 0;
    let mut skipped_glob_mismatch: u64 = 0;
    let mut skipped_missing_content: u64 = 0;
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: usize = 0;
    let mut scan_limit_reached = false;
    let mut scan_limit_reason: Option<ScanLimitReason> = None;
    let mut response_bytes: usize = GREP_RESPONSE_JSON_FIXED_OVERHEAD;
    let has_redaction_rules = vfs.redactor.has_redact_rules();
    let max_line_bytes = vfs.policy.limits.max_line_bytes;
    let redaction_overflow_replacement = has_redaction_rules
        .then(|| clamp_char_boundary(vfs.redactor.replacement(), max_line_bytes));
    let mut after: Option<String> = None;

    'scan: loop {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Time);
            break;
        }

        let remaining_entries = max_scan_entries.saturating_sub(scanned_entries);
        if remaining_entries == 0 {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Entries);
            break;
        }

        let page_budget = remaining_entries.min(META_PAGE_SIZE);
        let fetch_limit = page_budget.saturating_add(1);
        let mut metas = vfs.store.list_metas_by_prefix_page(
            &request.workspace_id,
            &prefix,
            after.as_deref(),
            fetch_limit,
        )?;
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Time);
            break;
        }
        ensure_page_strictly_increasing(&metas, "grep")?;
        let has_more = metas.len() > page_budget;
        if has_more {
            metas.truncate(page_budget);
        }
        ensure_page_starts_after_cursor(&metas, after.as_deref(), "grep")?;

        if metas.is_empty() {
            break;
        }
        if has_more {
            advance_after_cursor(&mut after, &metas, "grep")?;
        }

        for meta in metas {
            let path = meta.path;
            let meta_version = meta.version;
            let meta_size_bytes = meta.size_bytes;
            let mut path_json_escaped_len: Option<usize> = None;

            scanned_entries = scanned_entries.saturating_add(1);

            if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Time);
                break 'scan;
            }

            if vfs.traversal.is_path_skipped(&path) {
                skipped_traversal_skipped = skipped_traversal_skipped.saturating_add(1);
                continue;
            }

            if vfs.redactor.is_path_denied(&path) {
                skipped_secret_denied = skipped_secret_denied.saturating_add(1);
                continue;
            }

            if let Some(glob) = &file_glob
                && !glob_is_match(glob, &path)
            {
                skipped_glob_mismatch = skipped_glob_mismatch.saturating_add(1);
                continue;
            }

            if scanned_files >= max_scan_files_u64 {
                scan_limit_reached = true;
                scan_limit_reason = Some(ScanLimitReason::Files);
                break 'scan;
            }
            scanned_files = scanned_files.saturating_add(1);

            if meta_size_bytes > max_read_bytes {
                skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                continue;
            }

            let Some(content) =
                vfs.store
                    .get_content(&request.workspace_id, &path, meta_version)?
            else {
                skipped_missing_content = skipped_missing_content.saturating_add(1);
                continue;
            };
            let content_size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
            if content_size_bytes > max_read_bytes {
                skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                continue;
            }
            if literal_query_spans_lines {
                continue;
            }
            if let Some(finder) = literal_finder.as_ref()
                && finder.find(content.as_bytes()).is_none()
            {
                continue;
            }

            let mut line_no: u64 = 1;
            for line in content.lines() {
                if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                    scan_limit_reached = true;
                    scan_limit_reason = Some(ScanLimitReason::Time);
                    break 'scan;
                }

                let ok = match &regex {
                    Some(regex) => regex.is_match(line),
                    None => literal_finder
                        .as_ref()
                        .is_some_and(|finder| finder.find(line.as_bytes()).is_some()),
                };
                if !ok {
                    line_no = line_no.saturating_add(1);
                    continue;
                }

                let line_slice = clamp_char_boundary(line, max_line_bytes);
                let mut line_truncated = line_slice.len() < line.len();
                let mut text: Option<String> = None;
                if has_redaction_rules {
                    let redacted = match vfs
                        .redactor
                        .redact_text_owned_bounded(line_slice.to_string(), max_line_bytes)
                    {
                        Ok(text) => text,
                        Err(_) => {
                            line_truncated = true;
                            redaction_overflow_replacement
                                .unwrap_or_default()
                                .to_string()
                        }
                    };
                    text = Some(redacted);
                }
                let path_json_escaped_len =
                    *path_json_escaped_len.get_or_insert_with(|| json_escaped_str_len(&path));
                // Budget against JSON-encoded output size (escaped strings + object structure).
                let entry_text = text.as_deref().unwrap_or(line_slice);
                let entry_bytes = grep_match_json_bytes(
                    path_json_escaped_len,
                    line_no,
                    entry_text,
                    line_truncated,
                )
                .saturating_add(usize::from(!matches.is_empty()));
                let next_response_bytes = response_bytes.saturating_add(entry_bytes);
                if next_response_bytes > MAX_SCAN_RESPONSE_BYTES {
                    scan_limit_reached = true;
                    scan_limit_reason = Some(ScanLimitReason::Results);
                    break 'scan;
                }
                response_bytes = next_response_bytes;
                let text = text.unwrap_or_else(|| line_slice.to_string());
                matches.push(GrepMatch {
                    path: path.clone(),
                    line: line_no,
                    text,
                    line_truncated,
                });
                line_no = line_no.saturating_add(1);

                if matches.len() >= vfs.policy.limits.max_results {
                    scan_limit_reached = true;
                    scan_limit_reason = Some(ScanLimitReason::Results);
                    break 'scan;
                }
            }
        }

        if has_more && scanned_entries >= max_scan_entries {
            scan_limit_reached = true;
            scan_limit_reason = Some(ScanLimitReason::Entries);
            break;
        }

        if !has_more {
            break;
        }
    }

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
        scanned_entries: u64::try_from(scanned_entries).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::store::{DeleteOutcome, FileMeta, Store};
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

    #[test]
    fn grep_skips_file_when_actual_content_exceeds_read_limit_even_if_meta_is_stale() {
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content: "abcdef".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;
        policy.limits.max_read_bytes = 4;

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

        assert!(resp.matches.is_empty());
        assert_eq!(resp.skipped_too_large_files, 1);
    }

    #[test]
    fn grep_literal_query_spanning_newline_does_not_match_across_lines() {
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 5,
                version: 1,
                updated_at_ms: 0,
            },
            content: "ab\ncd".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "b\nc".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert!(resp.matches.is_empty());
        assert_eq!(resp.scanned_files, 1);
    }

    struct NonMonotonicPageStore {
        row: FileMeta,
    }

    impl Store for NonMonotonicPageStore {
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

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(vec![self.row.clone(); META_PAGE_SIZE + 1])
        }
    }

    #[test]
    fn grep_rejects_non_monotonic_pagination_cursor() {
        let store = NonMonotonicPageStore {
            row: FileMeta {
                path: "docs/a.txt".to_string(),
                size_bytes: u64::MAX,
                version: 1,
                updated_at_ms: 0,
            },
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on non-monotonic cursor");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string().contains("non-monotonic"),
            "unexpected error: {err}"
        );
    }

    struct NonMonotonicWithinPageStore {
        rows: Vec<FileMeta>,
    }

    impl Store for NonMonotonicWithinPageStore {
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

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(self.rows.clone())
        }
    }

    #[test]
    fn grep_rejects_non_monotonic_within_page_ordering() {
        let store = NonMonotonicWithinPageStore {
            rows: vec![
                FileMeta {
                    path: "docs/a.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/c.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/b.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
            ],
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.limits.max_walk_entries = 2;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on non-monotonic page ordering");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string().contains("non-monotonic page ordering"),
            "unexpected error: {err}"
        );
    }

    struct NonMonotonicAcrossPagesStore;

    impl Store for NonMonotonicAcrossPagesStore {
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

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            if after.is_none() {
                return Ok((0..=META_PAGE_SIZE)
                    .map(|idx| FileMeta {
                        path: format!("docs/{idx:04}.txt"),
                        size_bytes: u64::MAX,
                        version: 1,
                        updated_at_ms: 0,
                    })
                    .collect());
            }

            Ok(vec![
                FileMeta {
                    path: "docs/0001.txt".to_string(),
                    size_bytes: u64::MAX,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/9999.txt".to_string(),
                    size_bytes: u64::MAX,
                    version: 1,
                    updated_at_ms: 0,
                },
            ])
        }
    }

    #[test]
    fn grep_rejects_rows_not_strictly_after_cursor_across_pages() {
        let store = NonMonotonicAcrossPagesStore;

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.limits.max_walk_entries = META_PAGE_SIZE + 8;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("should fail on rows at/before previous cursor");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string()
                .contains("not strictly after pagination cursor"),
            "unexpected error: {err}"
        );
    }

    struct SlowEmptyPageStore;

    impl Store for SlowEmptyPageStore {
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

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            std::thread::sleep(Duration::from_millis(3));
            Ok(Vec::new())
        }
    }

    #[test]
    fn grep_marks_time_limit_when_store_page_fetch_exceeds_budget() {
        let store = SlowEmptyPageStore;

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.limits.max_walk_ms = Some(1);

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let response = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect("grep");
        assert!(response.truncated);
        assert!(response.scan_limit_reached);
        assert_eq!(response.scan_limit_reason, Some(ScanLimitReason::Time));
    }
}
