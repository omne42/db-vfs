use globset::{GlobSet, GlobSetBuilder};

use crate::glob_utils::{
    build_glob_from_normalized, normalize_glob_pattern_for_matching,
    validate_root_relative_glob_pattern,
};
use crate::policy::TraversalRules;
use crate::{Error, Result};

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

            if normalized.ends_with("/*") {
                let expanded = format!(
                    "{}**",
                    normalized
                        .strip_suffix('*')
                        .expect("ends_with(\"/*\") implies a trailing '*'")
                );
                let glob = build_glob_from_normalized(&expanded).map_err(|err| {
                    Error::InvalidPolicy(format!(
                        "invalid traversal.skip_globs glob {:?}: {err}",
                        summarize_pattern_for_error(pattern)
                    ))
                })?;
                builder.add(glob);
            }
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
        let path = path.trim_start_matches('/');
        skip.is_match(std::path::Path::new(path))
    }
}
