use crate::{Error, Result};

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
    let mut s = input.trim().replace('\\', "/");
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
}
