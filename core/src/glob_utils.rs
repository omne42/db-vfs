use globset::GlobBuilder;

/// Normalize a glob pattern for matching against `db-vfs` root-relative paths.
///
/// - Trims surrounding whitespace.
/// - Converts `\` to `/` so patterns work consistently across platforms.
/// - Strips leading `./` segments.
/// - Converts an empty pattern to `"."` (so `globset` can compile it).
pub fn normalize_glob_pattern_for_matching(pattern: &str) -> String {
    let mut normalized = pattern.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    if normalized.is_empty() {
        normalized.push('.');
    }
    normalized
}

/// Validate that a glob pattern is root-relative for `db-vfs`.
pub fn validate_root_relative_glob_pattern(pattern: &str) -> std::result::Result<(), &'static str> {
    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }
    if pattern.split('/').any(|segment| segment == "..") {
        return Err("glob patterns must not contain '..' segments");
    }
    Ok(())
}

/// Build a `globset` glob for matching against `db-vfs` root-relative paths.
pub fn build_glob_from_normalized(
    pattern: &str,
) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true);
    builder.build()
}
