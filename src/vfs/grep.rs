use serde::{Deserialize, Serialize};

use db_vfs_core::path::{normalize_path_prefix, validate_workspace_id};
use db_vfs_core::policy::MAX_SCAN_RESPONSE_BYTES;
use db_vfs_core::{Error, Result};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::store::line_segments;

use super::util::{
    compile_glob, derive_exact_path_from_glob, derive_safe_prefix_from_glob, glob_is_match,
    json_escaped_str_len, u64_decimal_len,
};
use super::{DbVfs, ScanControl, ScanLimitReason, ScanTarget, scan_metas};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default, skip_serializing)]
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
pub(super) const META_PAGE_SIZE: usize = 2048;
const GREP_RESPONSE_JSON_FIXED_OVERHEAD: usize = 4096;

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
    let query_len = query.len();
    if query.is_empty() {
        return Err(if regex {
            Error::InvalidRegex("grep regex must be non-empty".to_string())
        } else {
            Error::InvalidPath("grep query must be non-empty".to_string())
        });
    }

    if query_len > MAX_GREP_QUERY_BYTES {
        let size_bytes = u64::try_from(query_len).unwrap_or(u64::MAX);
        let max_bytes = u64::try_from(MAX_GREP_QUERY_BYTES).unwrap_or(u64::MAX);
        return Err(if regex {
            Error::InvalidRegex(format!(
                "grep regex is too large ({} bytes; max {} bytes)",
                query_len, MAX_GREP_QUERY_BYTES
            ))
        } else {
            Error::InputTooLarge {
                size_bytes,
                max_bytes,
            }
        });
    }

    Ok(())
}

fn class_can_match_line_terminator(class: &Class) -> bool {
    match class {
        Class::Unicode(class) => {
            class
                .ranges()
                .iter()
                .any(|range| range.start() <= '\n' && '\n' <= range.end())
                || class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= '\r' && '\r' <= range.end())
        }
        Class::Bytes(class) => {
            class
                .ranges()
                .iter()
                .any(|range| range.start() <= b'\n' && b'\n' <= range.end())
                || class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= b'\r' && b'\r' <= range.end())
        }
    }
}

fn hir_can_match_line_terminator(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(literal) => literal.0.iter().any(|byte| matches!(byte, b'\n' | b'\r')),
        HirKind::Class(class) => class_can_match_line_terminator(class),
        HirKind::Repetition(repetition) => hir_can_match_line_terminator(&repetition.sub),
        HirKind::Capture(capture) => hir_can_match_line_terminator(&capture.sub),
        HirKind::Concat(subs) | HirKind::Alternation(subs) => {
            subs.iter().any(hir_can_match_line_terminator)
        }
    }
}

fn ensure_line_oriented_regex(query: &str) -> Result<()> {
    let hir = regex_syntax::parse(query)
        .map_err(|err| Error::InvalidRegex(format!("invalid grep regex {query:?}: {err}")))?;
    if hir_can_match_line_terminator(&hir) {
        return Err(Error::InvalidRegex(
            "grep regex is evaluated per line and must not match line terminators".to_string(),
        ));
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

    let max_walk = vfs
        .policy
        .limits
        .max_walk_ms
        .map(std::time::Duration::from_millis);

    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;
    let exact_path = request
        .path_prefix
        .is_none()
        .then(|| {
            request
                .glob
                .as_deref()
                .and_then(derive_exact_path_from_glob)
        })
        .flatten();

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
        ensure_line_oriented_regex(&request.query)?;
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
    let literal_query_spans_lines = !request.regex
        && request
            .query
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r'));

    let max_scan_entries = vfs.policy.limits.max_walk_entries.max(1);
    let max_scan_files = vfs.policy.limits.max_walk_files.max(1);
    let max_scan_files_u64 = u64::try_from(max_scan_files).unwrap_or(u64::MAX);
    let max_read_bytes = vfs.policy.limits.max_read_bytes;
    let max_read_bytes_usize = usize::try_from(max_read_bytes).unwrap_or(usize::MAX);

    let mut matches = Vec::<GrepMatch>::with_capacity(vfs.policy.limits.max_results.min(1024));
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_traversal_skipped: u64 = 0;
    let mut skipped_secret_denied: u64 = 0;
    let mut skipped_glob_mismatch: u64 = 0;
    let mut skipped_missing_content: u64 = 0;
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: usize = 0;
    let mut response_bytes: usize = GREP_RESPONSE_JSON_FIXED_OVERHEAD;
    let has_redaction_rules = vfs.redactor.has_redact_rules();
    let max_line_bytes = vfs.policy.limits.max_line_bytes;
    let target = exact_path
        .as_deref()
        .map(ScanTarget::ExactPath)
        .unwrap_or(ScanTarget::Prefix(&prefix));
    let outcome = scan_metas(
        &mut vfs.store,
        &request.workspace_id,
        target,
        max_scan_entries,
        max_walk,
        "grep",
        |store, meta| {
            let path = meta.path;
            let meta_version = meta.version;
            let meta_size_bytes = meta.size_bytes;
            let mut path_json_escaped_len: Option<usize> = None;

            if vfs.traversal.is_path_skipped(&path) {
                skipped_traversal_skipped = skipped_traversal_skipped.saturating_add(1);
                return Ok(ScanControl::Continue);
            }
            if vfs.redactor.is_path_denied(&path) {
                skipped_secret_denied = skipped_secret_denied.saturating_add(1);
                return Ok(ScanControl::Continue);
            }
            scanned_entries = scanned_entries.saturating_add(1);

            if let Some(glob) = &file_glob
                && !glob_is_match(glob, &path)
            {
                skipped_glob_mismatch = skipped_glob_mismatch.saturating_add(1);
                return Ok(ScanControl::Continue);
            }

            if scanned_files >= max_scan_files_u64 {
                return Ok(ScanControl::Stop(ScanLimitReason::Files));
            }
            scanned_files = scanned_files.saturating_add(1);

            if literal_query_spans_lines {
                return Ok(ScanControl::Continue);
            }

            if meta_size_bytes > max_read_bytes {
                skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                return Ok(ScanControl::Continue);
            }

            let Some(content) = store.get_content(&request.workspace_id, &path, meta_version)?
            else {
                skipped_missing_content = skipped_missing_content.saturating_add(1);
                return Ok(ScanControl::Continue);
            };
            let content_size_bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
            if content_size_bytes > max_read_bytes {
                skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                return Ok(ScanControl::Continue);
            }
            let redacted_content = if has_redaction_rules {
                match vfs
                    .redactor
                    .redact_text_bounded(content.as_str(), max_read_bytes_usize)
                {
                    Ok(redacted) => Some(redacted),
                    Err(_) => {
                        skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                        return Ok(ScanControl::Continue);
                    }
                }
            } else {
                None
            };
            let searchable_content = redacted_content.as_deref().unwrap_or(content.as_str());
            if let Some(finder) = literal_finder.as_ref()
                && finder.find(searchable_content.as_bytes()).is_none()
            {
                return Ok(ScanControl::Continue);
            }

            let mut line_no: u64 = 1;
            for segment in line_segments(searchable_content) {
                let line = segment.text;
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
                let line_truncated = line_slice.len() < line.len();
                let path_json_escaped_len =
                    *path_json_escaped_len.get_or_insert_with(|| json_escaped_str_len(&path));
                let entry_bytes = grep_match_json_bytes(
                    path_json_escaped_len,
                    line_no,
                    line_slice,
                    line_truncated,
                )
                .saturating_add(usize::from(!matches.is_empty()));
                let next_response_bytes = response_bytes.saturating_add(entry_bytes);
                if next_response_bytes > MAX_SCAN_RESPONSE_BYTES {
                    return Ok(ScanControl::Stop(ScanLimitReason::Results));
                }
                response_bytes = next_response_bytes;
                matches.push(GrepMatch {
                    path: path.clone(),
                    line: line_no,
                    text: line_slice.to_string(),
                    line_truncated,
                });
                line_no = line_no.saturating_add(1);

                if matches.len() >= vfs.policy.limits.max_results {
                    return Ok(ScanControl::Stop(ScanLimitReason::Results));
                }
            }

            Ok(ScanControl::Continue)
        },
    )?;

    Ok(GrepResponse {
        matches,
        truncated: outcome.truncated(),
        skipped_too_large_files,
        skipped_traversal_skipped,
        skipped_secret_denied,
        skipped_glob_mismatch,
        skipped_missing_content,
        scanned_files,
        scan_limit_reached: outcome.truncated(),
        scan_limit_reason: outcome.limit_reason,
        elapsed_ms: outcome.elapsed_ms(),
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

    #[test]
    fn grep_rejects_regexes_that_can_match_line_terminators() {
        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;

        let mut vfs = DbVfs::new(DummyStore, policy).expect("vfs");
        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "foo\\nbar".to_string(),
                regex: true,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("newline literal regex should fail");
        assert_eq!(err.code(), "invalid_regex");
        assert!(err.to_string().contains("per line"));

        let err = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "(?s)foo.*bar".to_string(),
                regex: true,
                glob: None,
                path_prefix: Some("docs/".to_string()),
            })
            .expect_err("dotall regex should fail");
        assert_eq!(err.code(), "invalid_regex");
    }

    #[test]
    fn grep_response_hides_secret_denied_count_from_serialized_output() {
        let value = serde_json::to_value(GrepResponse {
            matches: vec![GrepMatch {
                path: "docs/a.txt".to_string(),
                line: 1,
                text: "hello".to_string(),
                line_truncated: false,
            }],
            truncated: false,
            skipped_too_large_files: 0,
            skipped_traversal_skipped: 0,
            skipped_secret_denied: 2,
            skipped_glob_mismatch: 0,
            skipped_missing_content: 0,
            scanned_files: 1,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 1,
            scanned_entries: 1,
        })
        .expect("serialize grep response");

        assert!(value.get("skipped_secret_denied").is_none());
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

    struct ExactGlobStore {
        meta: FileMeta,
        content: String,
    }

    impl Store for ExactGlobStore {
        fn get_meta(&mut self, _workspace_id: &str, path: &str) -> Result<Option<FileMeta>> {
            Ok((path == self.meta.path).then(|| self.meta.clone()))
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            path: &str,
            version: u64,
        ) -> Result<Option<String>> {
            Ok((path == self.meta.path && version == self.meta.version)
                .then(|| self.content.clone()))
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
            panic!("exact-path grep should not fall back to prefix scanning")
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
                query: "X".to_string(),
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
    fn grep_allows_root_exact_glob_without_full_scan() {
        let store = SingleFileStore {
            meta: FileMeta {
                path: "README.md".to_string(),
                size_bytes: 12,
                version: 1,
                updated_at_ms: 0,
            },
            content: "hello world\n".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "hello".to_string(),
                regex: false,
                glob: Some("README.md".to_string()),
                path_prefix: None,
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].path, "README.md");
        assert_eq!(resp.scanned_entries, 1);
        assert_eq!(resp.scanned_files, 1);
    }

    #[test]
    fn grep_uses_exact_glob_path_without_prefix_rescan() {
        let store = ExactGlobStore {
            meta: FileMeta {
                path: "README.md".to_string(),
                size_bytes: 12,
                version: 1,
                updated_at_ms: 0,
            },
            content: "hello world\n".to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "hello".to_string(),
                regex: false,
                glob: Some("README.md".to_string()),
                path_prefix: None,
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].path, "README.md");
        assert_eq!(resp.scanned_entries, 1);
        assert_eq!(resp.scanned_files, 1);
    }

    #[test]
    fn grep_uses_line_preserving_redaction_for_multiline_secret_matches() {
        let content = "BEGIN\nsecret\nEND\npublic\n";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;
        policy.secrets.redact_regexes = vec!["BEGIN\\nsecret\\nEND".to_string()];
        policy.secrets.replacement = "REDACTED".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "REDACTED".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].line, 1);
        assert_eq!(resp.matches[0].text, "REDACTED");
    }

    #[test]
    fn grep_does_not_match_literals_hidden_by_redaction() {
        let content = "secret\npublic\n";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;
        policy.secrets.redact_regexes = vec!["secret".to_string()];
        policy.secrets.replacement = "REDACTED".to_string();

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let hidden = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "secret".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");
        assert!(hidden.matches.is_empty());

        let visible = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "REDACTED".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");
        assert_eq!(visible.matches.len(), 1);
        assert_eq!(visible.matches[0].text, "REDACTED");
    }

    #[test]
    fn grep_regex_matches_are_evaluated_per_line() {
        let content = "foo\nbar\nbaz\n";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "^bar$".to_string(),
                regex: true,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].line, 2);
        assert_eq!(resp.matches[0].text, "bar");
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

    struct NewlineLiteralNoContentStore {
        meta: FileMeta,
        content_calls: usize,
    }

    impl Store for NewlineLiteralNoContentStore {
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
            self.content_calls = self.content_calls.saturating_add(1);
            Ok(Some("unused".to_string()))
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
    fn grep_literal_query_spanning_newline_skips_content_load() {
        let store = NewlineLiteralNoContentStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content_calls: 0,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x\ny".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert!(resp.matches.is_empty());
        assert_eq!(resp.scanned_files, 1);
        assert_eq!(vfs.store_mut().content_calls, 0);
    }

    #[test]
    fn grep_literal_query_spanning_newline_does_not_count_oversized_files() {
        let store = NewlineLiteralNoContentStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 10_000,
                version: 1,
                updated_at_ms: 0,
            },
            content_calls: 0,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;
        policy.limits.max_read_bytes = 1;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x\ny".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert!(resp.matches.is_empty());
        assert_eq!(resp.scanned_files, 1);
        assert_eq!(resp.skipped_too_large_files, 0);
        assert_eq!(vfs.store_mut().content_calls, 0);
    }

    #[test]
    fn grep_literal_query_spanning_carriage_return_does_not_match_crlf_lines() {
        let content = "ab\r\ncd\r\n";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "b\rc".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert!(resp.matches.is_empty());
        assert_eq!(resp.scanned_files, 1);
    }

    #[test]
    fn grep_literal_query_spanning_carriage_return_skips_content_load() {
        let store = NewlineLiteralNoContentStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            },
            content_calls: 0,
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "x\ry".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert!(resp.matches.is_empty());
        assert_eq!(resp.scanned_files, 1);
        assert_eq!(vfs.store_mut().content_calls, 0);
    }

    #[test]
    fn grep_matches_cr_only_lines_as_distinct_lines() {
        let content = "alpha\rbeta\rneedle\romega";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "needle".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].line, 3);
        assert_eq!(resp.matches[0].text, "needle");
    }

    #[test]
    fn grep_matches_crlf_lines_without_including_terminators() {
        let content = "alpha\r\nneedle\r\nomega\r\n";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "needle".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].line, 2);
        assert_eq!(resp.matches[0].text, "needle");
    }

    #[test]
    fn grep_matches_mixed_line_endings_with_stable_line_numbers() {
        let content = "alpha\rneedle-lf\nneedle-crlf\r\nomega";
        let store = SingleFileStore {
            meta: FileMeta {
                path: "a".to_string(),
                size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
                version: 1,
                updated_at_ms: 0,
            },
            content: content.to_string(),
        };

        let mut policy = VfsPolicy::default();
        policy.permissions.grep = true;
        policy.permissions.allow_full_scan = true;

        let mut vfs = DbVfs::new(store, policy).expect("vfs");
        let resp = vfs
            .grep(GrepRequest {
                workspace_id: "ws".to_string(),
                query: "needle".to_string(),
                regex: false,
                glob: None,
                path_prefix: Some("".to_string()),
            })
            .expect("grep");

        assert_eq!(resp.matches.len(), 2);
        assert_eq!(resp.matches[0].line, 2);
        assert_eq!(resp.matches[0].text, "needle-lf");
        assert_eq!(resp.matches[1].line, 3);
        assert_eq!(resp.matches[1].text, "needle-crlf");
    }

    #[test]
    fn grep_counts_redaction_expansion_over_budget_as_too_large() {
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
        policy.limits.max_read_bytes = 2;
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

        assert!(resp.matches.is_empty());
        assert_eq!(resp.skipped_too_large_files, 1);
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
