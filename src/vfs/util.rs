use std::time::{Instant, SystemTime, UNIX_EPOCH};

use globset::{GlobSet, GlobSetBuilder};

use db_vfs_core::{Error, Result};

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
    let mut normalized = pattern.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    if normalized.starts_with('/') {
        return None;
    }

    let mut out = Vec::<&str>::new();
    let mut stopped_on_wildcard = false;

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

fn validate_root_relative_glob_pattern(pattern: &str) -> std::result::Result<(), &'static str> {
    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }
    if pattern.split('/').any(|segment| segment == "..") {
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
