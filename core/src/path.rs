use std::borrow::Cow;

use crate::{Error, Result};

#[inline]
pub fn is_canonical_runtime_relative_path(path: &str) -> bool {
    let mut chars = path.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if first.is_whitespace() || first == '/' {
        return false;
    }
    if path.chars().next_back().is_some_and(char::is_whitespace) {
        return false;
    }

    let mut at_segment_start = true;
    let mut segment_len = 0usize;
    let mut segment_is_dot = false;
    let mut segment_is_dotdot = false;

    for ch in path.chars() {
        if ch == '\\' || ch == '\0' || ch.is_control() {
            return false;
        }

        if ch == '/' {
            if at_segment_start || segment_is_dot || segment_is_dotdot {
                return false;
            }
            at_segment_start = true;
            segment_len = 0;
            segment_is_dot = false;
            segment_is_dotdot = false;
            continue;
        }

        if at_segment_start {
            at_segment_start = false;
            segment_len = 1;
            segment_is_dot = ch == '.';
            segment_is_dotdot = ch == '.';
            continue;
        }

        segment_len = segment_len.saturating_add(1);
        if segment_len == 2 {
            segment_is_dot = false;
            segment_is_dotdot = segment_is_dotdot && ch == '.';
        } else {
            segment_is_dot = false;
            segment_is_dotdot = false;
        }
    }

    !at_segment_start && !segment_is_dot && !segment_is_dotdot
}

pub fn validate_workspace_id(workspace_id: &str) -> Result<()> {
    const MAX_BYTES: usize = 256;
    if workspace_id.is_empty() {
        return Err(Error::InvalidPath("workspace_id: is empty".to_string()));
    }
    if workspace_id.len() > MAX_BYTES {
        return Err(Error::InvalidPath(format!(
            "workspace_id: is too large ({} bytes; max {} bytes)",
            workspace_id.len(),
            MAX_BYTES
        )));
    }

    let (has_nul, has_whitespace, has_control, has_separator, has_colon, has_dotdot, has_wildcard) =
        if workspace_id.is_ascii() {
            let mut has_nul = false;
            let mut has_whitespace = false;
            let mut has_control = false;
            let mut has_separator = false;
            let mut has_colon = false;
            let mut has_dotdot = false;
            let mut has_wildcard = false;
            let mut prev_dot = false;

            for &byte in workspace_id.as_bytes() {
                if byte == b'\0' {
                    has_nul = true;
                }
                if byte.is_ascii_whitespace() {
                    has_whitespace = true;
                }
                if byte.is_ascii_control() {
                    has_control = true;
                }
                if byte == b'/' || byte == b'\\' {
                    has_separator = true;
                }
                if byte == b':' {
                    has_colon = true;
                }
                if byte == b'*' {
                    has_wildcard = true;
                }
                if byte == b'.' && prev_dot {
                    has_dotdot = true;
                }
                prev_dot = byte == b'.';
            }

            (
                has_nul,
                has_whitespace,
                has_control,
                has_separator,
                has_colon,
                has_dotdot,
                has_wildcard,
            )
        } else {
            let mut has_nul = false;
            let mut has_whitespace = false;
            let mut has_control = false;
            let mut has_separator = false;
            let mut has_colon = false;
            let mut has_dotdot = false;
            let mut has_wildcard = false;
            let mut prev_dot = false;

            for ch in workspace_id.chars() {
                if ch == '\0' {
                    has_nul = true;
                }
                if ch.is_whitespace() {
                    has_whitespace = true;
                }
                if ch.is_control() {
                    has_control = true;
                }
                if ch == '/' || ch == '\\' {
                    has_separator = true;
                }
                if ch == ':' {
                    has_colon = true;
                }
                if ch == '*' {
                    has_wildcard = true;
                }
                if ch == '.' && prev_dot {
                    has_dotdot = true;
                }
                prev_dot = ch == '.';
            }

            (
                has_nul,
                has_whitespace,
                has_control,
                has_separator,
                has_colon,
                has_dotdot,
                has_wildcard,
            )
        };

    if has_nul {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain NUL bytes".to_string(),
        ));
    }
    if has_whitespace {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain whitespace".to_string(),
        ));
    }
    if has_control {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain control characters".to_string(),
        ));
    }
    if has_separator {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain path separators".to_string(),
        ));
    }
    if has_colon {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain ':'".to_string(),
        ));
    }
    if has_dotdot {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain '..'".to_string(),
        ));
    }
    if has_wildcard {
        return Err(Error::InvalidPath(
            "workspace_id: must not contain '*' because auth allowlists reserve wildcard syntax"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn normalize_path(path: &str) -> Result<String> {
    normalize_path_inner(path, PathKind::File)
}

pub fn normalize_path_prefix(prefix: &str) -> Result<String> {
    normalize_path_inner(prefix, PathKind::Prefix)
}

fn strip_leading_runtime_match_prefixes(mut s: &str) -> &str {
    loop {
        if let Some(rest) = s.strip_prefix("./") {
            s = rest;
            continue;
        }
        if let Some(rest) = s.strip_prefix('/') {
            s = rest;
            continue;
        }
        return s;
    }
}

pub fn normalize_runtime_path_for_matching(path: &str) -> Option<Cow<'_, str>> {
    if is_canonical_runtime_relative_path(path) {
        return Some(Cow::Borrowed(path));
    }

    let trimmed = path.trim();
    let normalized: Cow<'_, str> = if trimmed.contains('\\') {
        Cow::Owned(trimmed.replace('\\', "/"))
    } else {
        Cow::Borrowed(trimmed)
    };
    let normalized = strip_leading_runtime_match_prefixes(normalized.as_ref());
    if normalized.is_empty() || normalized.contains('\0') {
        return None;
    }
    if normalized.chars().any(char::is_control) {
        return None;
    }

    let mut out = String::with_capacity(normalized.len());
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(segment);
    }

    if out.is_empty() {
        return None;
    }
    Some(Cow::Owned(out))
}

#[derive(Clone, Copy)]
enum PathKind {
    File,
    Prefix,
}

fn is_windows_drive_absolute_path(s: &str) -> bool {
    s.as_bytes().get(1) == Some(&b':') && s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
}

fn strip_leading_dot_slashes(mut s: &str) -> &str {
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s
}

fn is_canonical_relative_path(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.starts_with("./")
        && !s.starts_with("../")
        && s != "."
        && s != ".."
        && !s.contains('\\')
        && !s.contains("//")
        && !s.contains("/./")
        && !s.contains("/../")
        && !s.ends_with("/.")
        && !s.ends_with("/..")
        && !is_windows_drive_absolute_path(s)
        && !s.contains('\0')
        && !s.chars().any(char::is_control)
}

fn normalize_path_inner(input: &str, kind: PathKind) -> Result<String> {
    const MAX_PATH_BYTES: usize = 4096;

    let label = match kind {
        PathKind::File => "path",
        PathKind::Prefix => "path_prefix",
    };
    if input != input.trim() {
        return Err(Error::InvalidPath(format!(
            "{label} must not have leading or trailing whitespace"
        )));
    }
    if input.len() > MAX_PATH_BYTES {
        return Err(Error::InvalidPath(format!(
            "{label} is too large ({} bytes; max {} bytes)",
            input.len(),
            MAX_PATH_BYTES
        )));
    }

    if is_canonical_relative_path(input) {
        return match kind {
            PathKind::File => {
                if input.ends_with('/') {
                    Err(Error::InvalidPath(format!(
                        "{label}: file path must not end with '/'"
                    )))
                } else {
                    Ok(input.to_string())
                }
            }
            PathKind::Prefix => {
                if input.ends_with('/') {
                    Ok(input.to_string())
                } else {
                    Ok(format!("{input}/"))
                }
            }
        };
    }

    let normalized: Cow<'_, str> = if input.contains('\\') {
        Cow::Owned(input.replace('\\', "/"))
    } else {
        Cow::Borrowed(input)
    };
    let s = strip_leading_dot_slashes(normalized.as_ref());
    if is_windows_drive_absolute_path(s) {
        return Err(Error::InvalidPath(format!(
            "{label}: absolute paths are not supported"
        )));
    }
    if s.starts_with('/') {
        return Err(Error::InvalidPath(format!(
            "{label}: absolute paths are not supported"
        )));
    }
    if s.contains('\0') {
        return Err(Error::InvalidPath(format!(
            "{label}: NUL bytes are not allowed"
        )));
    }
    if s.chars().any(char::is_control) {
        return Err(Error::InvalidPath(format!(
            "{label} must not contain control characters"
        )));
    }

    let ends_with_slash = s.ends_with('/');
    let mut normalized = String::with_capacity(s.len());
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(Error::InvalidPath(format!(
                "{label}: '..' segments are not allowed"
            )));
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(seg);
    }

    match kind {
        PathKind::File => {
            if ends_with_slash {
                return Err(Error::InvalidPath(format!(
                    "{label}: file path must not end with '/'"
                )));
            }
        }
        PathKind::Prefix => {}
    }

    if matches!(kind, PathKind::Prefix) && !normalized.is_empty() {
        normalized.push('/');
    }

    if normalized.is_empty() {
        return match kind {
            PathKind::File => Err(Error::InvalidPath("path: is empty".to_string())),
            PathKind::Prefix => Ok(String::new()),
        };
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_prefix_allows_empty() {
        assert_eq!(normalize_path_prefix("").unwrap(), "");
        assert_eq!(normalize_path_prefix(".").unwrap(), "");
        assert_eq!(normalize_path_prefix("./").unwrap(), "");
    }

    #[test]
    fn normalize_path_collapses_double_slashes() {
        assert_eq!(normalize_path("a//b").unwrap(), "a/b");
    }

    #[test]
    fn normalize_path_ignores_leading_dot_slash() {
        assert_eq!(normalize_path("./a/b").unwrap(), "a/b");
    }

    #[test]
    fn normalize_path_ignores_repeated_leading_dot_slash() {
        assert_eq!(normalize_path("./././docs/a.txt").unwrap(), "docs/a.txt");
        assert_eq!(normalize_path_prefix("././docs").unwrap(), "docs/");
    }

    #[test]
    fn normalize_path_rejects_parent_dir_segments() {
        assert!(matches!(normalize_path("../x"), Err(Error::InvalidPath(_))));
    }

    #[test]
    fn normalize_path_prefix_appends_trailing_slash() {
        assert_eq!(normalize_path_prefix("a").unwrap(), "a/");
    }

    #[test]
    fn normalize_path_rejects_leading_or_trailing_whitespace() {
        assert!(matches!(normalize_path(" a"), Err(Error::InvalidPath(_))));
        assert!(matches!(normalize_path("a "), Err(Error::InvalidPath(_))));
        assert!(matches!(
            normalize_path_prefix(" a"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            normalize_path_prefix("a "),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn normalize_path_allows_internal_whitespace() {
        assert_eq!(normalize_path("a b.txt").unwrap(), "a b.txt");
        assert_eq!(normalize_path_prefix("a b").unwrap(), "a b/");
    }

    #[test]
    fn normalize_path_rejects_control_characters() {
        assert!(matches!(normalize_path("a\nb"), Err(Error::InvalidPath(_))));
        assert!(matches!(
            normalize_path_prefix("a\tb"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_workspace_id_rejects_ambiguous_characters() {
        assert!(validate_workspace_id("a/b").is_err());
        assert!(validate_workspace_id("a\\b").is_err());
        assert!(validate_workspace_id("a:b").is_err());
        assert!(validate_workspace_id("a..b").is_err());
        assert!(validate_workspace_id("*").is_err());
        assert!(validate_workspace_id("team-*").is_err());
    }

    #[test]
    fn normalize_path_rejects_windows_drive_prefix() {
        assert!(matches!(
            normalize_path("C:\\tmp\\a.txt"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn normalize_path_fast_path_preserves_canonical_inputs() {
        assert_eq!(normalize_path("docs/a.txt").unwrap(), "docs/a.txt");
        assert_eq!(normalize_path_prefix("docs").unwrap(), "docs/");
        assert_eq!(normalize_path_prefix("docs/").unwrap(), "docs/");
    }

    #[test]
    fn canonical_runtime_relative_path_detection_is_strict() {
        assert!(is_canonical_runtime_relative_path("docs/a.txt"));
        assert!(is_canonical_runtime_relative_path("team/a b.txt"));
        assert!(!is_canonical_runtime_relative_path(""));
        assert!(!is_canonical_runtime_relative_path("./docs/a.txt"));
        assert!(!is_canonical_runtime_relative_path("../docs/a.txt"));
        assert!(!is_canonical_runtime_relative_path("."));
        assert!(!is_canonical_runtime_relative_path(".."));
        assert!(!is_canonical_runtime_relative_path("/docs/a.txt"));
        assert!(!is_canonical_runtime_relative_path("docs//a.txt"));
        assert!(!is_canonical_runtime_relative_path("docs/./a.txt"));
        assert!(!is_canonical_runtime_relative_path("docs/../a.txt"));
        assert!(!is_canonical_runtime_relative_path("docs/a.txt/"));
        assert!(!is_canonical_runtime_relative_path(" docs/a.txt"));
        assert!(!is_canonical_runtime_relative_path("docs/a.txt "));
        assert!(!is_canonical_runtime_relative_path("docs\\a.txt"));
    }

    #[test]
    fn normalize_runtime_path_for_matching_canonicalizes_matcher_inputs() {
        assert_eq!(
            normalize_runtime_path_for_matching("././docs//a.txt")
                .unwrap()
                .as_ref(),
            "docs/a.txt"
        );
        assert_eq!(
            normalize_runtime_path_for_matching("///./docs/a.txt")
                .unwrap()
                .as_ref(),
            "docs/a.txt"
        );
        assert_eq!(normalize_runtime_path_for_matching("docs/../a.txt"), None);
        assert_eq!(normalize_runtime_path_for_matching("docs/\na.txt"), None);
    }
}
