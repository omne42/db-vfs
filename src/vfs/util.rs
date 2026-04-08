use std::time::{Instant, SystemTime, UNIX_EPOCH};

use globset::GlobMatcher;

use db_vfs_core::glob_utils::{
    analyze_literal_glob_for_matching, build_glob_from_normalized,
    normalize_glob_pattern_for_matching, validate_normalized_root_relative_glob_pattern,
};
use db_vfs_core::path::normalize_runtime_relative_path_for_matching;
use db_vfs_core::{Error, Result};

const MAX_GLOB_PATTERN_BYTES: usize = 4096;

pub(super) fn now_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(err) => {
            eprintln!("db-vfs: system time before UNIX_EPOCH ({err}); using 0 timestamp");
            0
        }
    }
}

pub(super) fn elapsed_ms(started: &Instant) -> u64 {
    let ms = started.elapsed().as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

pub(super) fn json_escaped_str_len(input: &str) -> usize {
    if input.is_ascii() {
        return input
            .as_bytes()
            .iter()
            .map(|byte| match byte {
                b'"' | b'\\' | b'\x08' | b'\x0C' | b'\n' | b'\r' | b'\t' => 2,
                0x00..=0x1F => 6,
                _ => 1,
            })
            .sum();
    }

    input
        .chars()
        .map(|ch| match ch {
            '"' | '\\' => 2,
            '\u{08}' | '\u{0C}' | '\n' | '\r' | '\t' => 2,
            '\u{2028}' | '\u{2029}' => 6,
            c if c <= '\u{1F}' => 6,
            _ => ch.len_utf8(),
        })
        .sum()
}

pub(super) fn u64_decimal_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    value.ilog10() as usize + 1
}

pub(super) fn compile_glob(pattern: &str) -> Result<GlobMatcher> {
    if pattern.len() > MAX_GLOB_PATTERN_BYTES {
        return Err(Error::InvalidPath(format!(
            "glob pattern is too large ({} bytes; max {} bytes)",
            pattern.len(),
            MAX_GLOB_PATTERN_BYTES
        )));
    }
    let normalized = normalize_glob_pattern_for_matching(pattern);
    if normalized.len() > MAX_GLOB_PATTERN_BYTES {
        return Err(Error::InvalidPath(format!(
            "normalized glob pattern is too large ({} bytes; max {} bytes)",
            normalized.len(),
            MAX_GLOB_PATTERN_BYTES
        )));
    }
    validate_normalized_root_relative_glob_pattern(&normalized).map_err(|err| {
        Error::InvalidPath(format!(
            "invalid glob pattern {pattern:?}: {}",
            err.as_message()
        ))
    })?;
    let glob = build_glob_from_normalized(&normalized)
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))?;
    Ok(glob.compile_matcher())
}

pub(super) fn glob_is_match(glob: &GlobMatcher, path: &str) -> bool {
    let Some(normalized) = normalize_runtime_relative_path_for_matching(path) else {
        return false;
    };
    glob.is_match(std::path::Path::new(normalized.as_ref()))
}

pub(super) fn derive_safe_prefix_from_glob(pattern: &str) -> Option<String> {
    let analysis = analyze_literal_glob_for_matching(pattern)?;
    if analysis.prefix.is_empty() {
        return None;
    }
    let mut prefix = analysis.prefix;
    if analysis.truncated {
        prefix.push('/');
    }
    Some(prefix)
}

pub(super) fn derive_exact_path_from_glob(pattern: &str) -> Option<String> {
    let analysis = analyze_literal_glob_for_matching(pattern)?;
    analysis.exact_path.then_some(analysis.prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaped_str_len_counts_escapes() {
        assert_eq!(json_escaped_str_len("abc"), 3);
        assert_eq!(json_escaped_str_len("\"\\\n"), 6);
        assert_eq!(json_escaped_str_len("abc\u{0001}"), 9);
        assert_eq!(json_escaped_str_len("\u{2028}"), 6);
    }

    #[test]
    fn u64_decimal_len_handles_zero_and_max() {
        assert_eq!(u64_decimal_len(0), 1);
        assert_eq!(u64_decimal_len(9), 1);
        assert_eq!(u64_decimal_len(10), 2);
        assert_eq!(u64_decimal_len(u64::MAX), 20);
    }

    #[test]
    fn canonical_runtime_path_detection_is_strict() {
        assert!(db_vfs_core::path::is_canonical_runtime_relative_path(
            "docs/a.txt"
        ));
        assert!(!db_vfs_core::path::is_canonical_runtime_relative_path(
            "./docs/a.txt"
        ));
        assert!(!db_vfs_core::path::is_canonical_runtime_relative_path(
            "/docs/a.txt"
        ));
        assert!(!db_vfs_core::path::is_canonical_runtime_relative_path(
            "docs//a.txt"
        ));
        assert!(!db_vfs_core::path::is_canonical_runtime_relative_path(
            "docs/a.txt/"
        ));
    }

    #[test]
    fn glob_match_runtime_normalization_rejects_invalid_paths() {
        let glob = compile_glob("docs/*.txt").expect("glob");
        assert!(glob_is_match(&glob, "./docs//a.txt"));
        assert!(glob_is_match(&glob, "///./docs//a.txt"));
        assert!(!glob_is_match(&glob, "docs/../a.txt"));
        assert!(!glob_is_match(&glob, "docs/\na.txt"));
    }

    #[test]
    fn derive_safe_prefix_accepts_exact_file_patterns() {
        assert_eq!(
            derive_safe_prefix_from_glob("docs/a.txt"),
            Some("docs/a.txt".to_string())
        );
        assert_eq!(
            derive_safe_prefix_from_glob("docs/nested/a.txt"),
            Some("docs/nested/a.txt".to_string())
        );
        assert_eq!(
            derive_safe_prefix_from_glob("top-level.txt"),
            Some("top-level.txt".to_string())
        );
    }

    #[test]
    fn derive_safe_prefix_keeps_wildcard_scopes() {
        assert_eq!(
            derive_safe_prefix_from_glob("docs/*.txt"),
            Some("docs/".to_string())
        );
        assert_eq!(
            derive_safe_prefix_from_glob("docs/**/a.txt"),
            Some("docs/".to_string())
        );
        assert_eq!(derive_safe_prefix_from_glob("**/*.txt"), None);
    }

    #[test]
    fn derive_exact_path_rejects_wildcards_and_dirs() {
        assert_eq!(
            derive_exact_path_from_glob("docs/a.txt"),
            Some("docs/a.txt".to_string())
        );
        assert_eq!(
            derive_exact_path_from_glob("./docs//a.txt"),
            Some("docs/a.txt".to_string())
        );
        assert_eq!(derive_exact_path_from_glob("docs/*.txt"), None);
        assert_eq!(derive_exact_path_from_glob("docs/{a,b}.txt"), None);
        assert_eq!(derive_exact_path_from_glob("docs/"), None);
    }
}
