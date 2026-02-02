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

const MAX_GREP_REGEX_PATTERN_BYTES: usize = 4096;
const MAX_GREP_REGEX_COMPILED_SIZE_BYTES: usize = 1_000_000;
const MAX_GREP_REGEX_NEST_LIMIT: u32 = 128;

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

pub(super) fn grep<S: crate::store::Store>(
    vfs: &mut DbVfs<S>,
    request: GrepRequest,
) -> Result<GrepResponse> {
    vfs.ensure_allowed(vfs.policy.permissions.grep, "grep")?;
    validate_workspace_id(&request.workspace_id)?;

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

    if !request.regex && request.query.len() > MAX_GREP_REGEX_PATTERN_BYTES {
        return Err(Error::InputTooLarge {
            size_bytes: request.query.len() as u64,
            max_bytes: MAX_GREP_REGEX_PATTERN_BYTES as u64,
        });
    }

    let regex = if request.regex {
        if request.query.len() > MAX_GREP_REGEX_PATTERN_BYTES {
            return Err(Error::InvalidRegex(format!(
                "grep regex is too large ({} bytes; max {} bytes)",
                request.query.len(),
                MAX_GREP_REGEX_PATTERN_BYTES
            )));
        }
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
            continue;
        }

        if vfs.redactor.is_path_denied(&meta.path) {
            continue;
        }

        if let Some(glob) = &file_glob
            && !glob_is_match(glob, &meta.path)
        {
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
            continue;
        };

        for (idx, line) in content.lines().enumerate() {
            let ok = match &regex {
                Some(regex) => regex.is_match(line),
                None => line.contains(&request.query),
            };
            if !ok {
                continue;
            }

            let line_truncated = line.len() > vfs.policy.limits.max_line_bytes;
            let mut end = line.len().min(vfs.policy.limits.max_line_bytes);
            while end > 0 && !line.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            let text = vfs.redactor.redact_text(&line[..end]);
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
        scanned_files,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries,
    })
}
