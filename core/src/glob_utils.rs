use globset::GlobBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobPatternValidationError {
    Empty,
    Absolute,
    ParentTraversal,
}

impl GlobPatternValidationError {
    pub fn as_message(self) -> &'static str {
        match self {
            GlobPatternValidationError::Empty => "glob patterns must be non-empty",
            GlobPatternValidationError::Absolute => {
                "glob patterns must be root-relative (must not start with '/')"
            }
            GlobPatternValidationError::ParentTraversal => {
                "glob patterns must not contain '..' segments"
            }
        }
    }
}

/// Normalize a glob pattern for matching against `db-vfs` root-relative paths.
///
/// - Trims surrounding whitespace.
/// - Converts `\` to `/` so patterns work consistently across platforms.
/// - Strips leading `./` segments.
pub fn normalize_glob_pattern_for_matching(pattern: &str) -> String {
    let mut normalized = pattern.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    normalized
}

/// Validate that a glob pattern is root-relative for `db-vfs`.
pub fn validate_root_relative_glob_pattern(
    pattern: &str,
) -> std::result::Result<(), GlobPatternValidationError> {
    let normalized = normalize_glob_pattern_for_matching(pattern);
    if normalized.is_empty() {
        return Err(GlobPatternValidationError::Empty);
    }
    if normalized.starts_with('/') {
        return Err(GlobPatternValidationError::Absolute);
    }
    if normalized.split('/').any(|segment| segment == "..") {
        return Err(GlobPatternValidationError::ParentTraversal);
    }
    Ok(())
}

/// Expand a `dir/*`-style glob into a second pattern that matches descendants (`dir/**`).
///
/// This is used to preserve historical semantics where deny/skip globs ending with `/*` also apply
/// to nested paths under that directory.
pub(crate) fn expand_dir_star_to_descendants(normalized: &str) -> Option<String> {
    if !normalized.ends_with("/*") {
        return None;
    }
    let prefix = normalized.strip_suffix('*')?;
    Some(format!("{prefix}**"))
}

/// Build a `globset` glob for matching against `db-vfs` root-relative paths.
pub fn build_glob_from_normalized(
    pattern: &str,
) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true);
    builder.build()
}
