use std::borrow::Cow;

use crate::{Error, Result};

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

    let mut has_nul = false;
    let mut has_whitespace = false;
    let mut has_control = false;
    let mut has_separator = false;
    let mut has_colon = false;
    let mut has_dotdot = false;
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
        if ch == '.' && prev_dot {
            has_dotdot = true;
        }
        prev_dot = ch == '.';
    }

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
    Ok(())
}

pub fn normalize_path(path: &str) -> Result<String> {
    normalize_path_inner(path, PathKind::File)
}

pub fn normalize_path_prefix(prefix: &str) -> Result<String> {
    normalize_path_inner(prefix, PathKind::Prefix)
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
}
