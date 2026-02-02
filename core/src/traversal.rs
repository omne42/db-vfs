use globset::{GlobSet, GlobSetBuilder};

use crate::policy::TraversalRules;
use crate::{Error, Result};

const PROBE_FILE_NAME: &str = ".db-vfs-probe";

#[derive(Debug, Clone)]
pub struct TraversalSkipper {
    skip: Option<GlobSet>,
}

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

fn validate_root_relative_glob_pattern(pattern: &str) -> std::result::Result<(), &'static str> {
    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }
    if pattern.split('/').any(|seg| seg == "..") {
        return Err("glob patterns must not contain '..' segments");
    }
    Ok(())
}

fn build_glob_from_normalized(pattern: &str) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = globset::GlobBuilder::new(pattern);
    builder.literal_separator(true);
    builder.build()
}

fn normalize_glob_pattern_for_matching(pattern: &str) -> String {
    let mut normalized = pattern.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    if normalized.is_empty() {
        normalized.push('.');
    }
    normalized
}

impl TraversalSkipper {
    pub fn from_rules(rules: &TraversalRules) -> Result<Self> {
        if rules.skip_globs.is_empty() {
            return Ok(Self { skip: None });
        }

        let mut builder = GlobSetBuilder::new();
        for pattern in &rules.skip_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            validate_root_relative_glob_pattern(&normalized).map_err(|msg| {
                Error::InvalidPolicy(format!(
                    "invalid traversal.skip_globs glob {:?}: {msg}",
                    summarize_pattern_for_error(pattern)
                ))
            })?;
            let glob = build_glob_from_normalized(&normalized).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "invalid traversal.skip_globs glob {:?}: {err}",
                    summarize_pattern_for_error(pattern)
                ))
            })?;
            builder.add(glob);
        }
        let skip = builder
            .build()
            .map_err(|err| Error::InvalidPolicy(format!("invalid traversal.skip_globs: {err}")))?;
        Ok(Self { skip: Some(skip) })
    }

    pub fn is_path_skipped(&self, path: &str) -> bool {
        let Some(skip) = &self.skip else {
            return false;
        };

        if skip.is_match(std::path::Path::new(path)) {
            return true;
        }

        // Directory probe trick: `dir/*` should skip everything under `dir/**`.
        let is_dir = path.ends_with('/');
        let path = path.trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|seg| !seg.is_empty()).collect();
        let probe_depth = if is_dir {
            segments.len()
        } else {
            segments.len().saturating_sub(1)
        };

        let mut current = String::new();
        for segment in segments.into_iter().take(probe_depth) {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(segment);
            let probe = format!("{current}/{PROBE_FILE_NAME}");
            if skip.is_match(std::path::Path::new(&probe)) {
                return true;
            }
        }

        false
    }
}
