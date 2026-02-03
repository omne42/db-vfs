use crate::{Error, Result};

pub fn validate_workspace_id(workspace_id: &str) -> Result<()> {
    const MAX_BYTES: usize = 256;
    if workspace_id.is_empty() {
        return Err(Error::InvalidPath("workspace_id is empty".to_string()));
    }
    if workspace_id.len() > MAX_BYTES {
        return Err(Error::InvalidPath(format!(
            "workspace_id is too large ({} bytes; max {} bytes)",
            workspace_id.len(),
            MAX_BYTES
        )));
    }
    if workspace_id.contains('\0') {
        return Err(Error::InvalidPath(
            "workspace_id must not contain NUL bytes".to_string(),
        ));
    }
    if workspace_id.chars().any(|ch| ch.is_whitespace()) {
        return Err(Error::InvalidPath(
            "workspace_id must not contain whitespace".to_string(),
        ));
    }
    if workspace_id.chars().any(|ch| ch.is_control()) {
        return Err(Error::InvalidPath(
            "workspace_id must not contain control characters".to_string(),
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

    let mut s = input.replace('\\', "/");
    while s.starts_with("./") {
        s.drain(..2);
    }
    if s.starts_with('/') {
        return Err(Error::InvalidPath(
            "absolute paths are not supported".to_string(),
        ));
    }
    if s.contains('\0') {
        return Err(Error::InvalidPath("NUL bytes are not allowed".to_string()));
    }
    if s.chars().any(|ch| ch.is_control()) {
        return Err(Error::InvalidPath(format!(
            "{label} must not contain control characters"
        )));
    }

    let ends_with_slash = s.ends_with('/');
    let mut out = Vec::<&str>::new();
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(Error::InvalidPath(
                ".. segments are not allowed".to_string(),
            ));
        }
        out.push(seg);
    }

    match kind {
        PathKind::File => {
            if ends_with_slash {
                return Err(Error::InvalidPath(
                    "file path must not end with '/'".to_string(),
                ));
            }
        }
        PathKind::Prefix => {}
    }

    let mut normalized = out.join("/");
    if matches!(kind, PathKind::Prefix) && !normalized.is_empty() && !normalized.ends_with('/') {
        normalized.push('/');
    }

    if normalized.is_empty() {
        return match kind {
            PathKind::File => Err(Error::InvalidPath("path is empty".to_string())),
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
}
