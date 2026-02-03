use std::time::{Instant, SystemTime, UNIX_EPOCH};

use globset::{GlobSet, GlobSetBuilder};

use db_vfs_core::glob_utils::{
    build_glob_from_normalized, normalize_glob_pattern_for_matching,
    validate_root_relative_glob_pattern,
};
use db_vfs_core::{Error, Result};

const MAX_GLOB_PATTERN_BYTES: usize = 4096;

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(super) fn elapsed_ms(started: &Instant) -> u64 {
    let ms = started.elapsed().as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    if pattern.len() > MAX_GLOB_PATTERN_BYTES {
        return Err(Error::InvalidPath(format!(
            "glob pattern is too large ({} bytes; max {} bytes)",
            pattern.len(),
            MAX_GLOB_PATTERN_BYTES
        )));
    }
    let normalized = normalize_glob_pattern_for_matching(pattern);
    validate_root_relative_glob_pattern(&normalized)
        .map_err(|msg| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {msg}")))?;
    let glob = build_glob_from_normalized(&normalized)
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

pub(super) fn glob_is_match(glob: &GlobSet, path: &str) -> bool {
    glob.is_match(std::path::Path::new(path))
}

pub(super) fn derive_safe_prefix_from_glob(pattern: &str) -> Option<String> {
    let normalized = normalize_glob_pattern_for_matching(pattern);
    if normalized.starts_with('/') {
        return None;
    }

    let mut out = Vec::<&str>::new();
    let mut stopped_on_wildcard = normalized.ends_with('/');

    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        if segment
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
        {
            stopped_on_wildcard = true;
            break;
        }
        out.push(segment);
    }

    if out.is_empty() {
        return None;
    }

    let mut prefix = out.join("/");
    if stopped_on_wildcard {
        prefix.push('/');
    }
    Some(prefix)
}
