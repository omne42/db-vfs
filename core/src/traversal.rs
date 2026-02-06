use globset::{GlobSet, GlobSetBuilder};

use crate::glob_utils::{
    build_glob_from_normalized, expand_dir_star_to_descendants,
    normalize_glob_pattern_for_matching, validate_root_relative_glob_pattern,
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

fn normalize_runtime_path_for_matching(path: &str) -> Option<String> {
    let mut normalized = path.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    normalized = normalized.trim_start_matches('/').to_string();
    if normalized.is_empty() {
        return None;
    }

    let mut out = Vec::<&str>::new();
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        out.push(segment);
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join("/"))
}

impl TraversalSkipper {
    pub fn from_rules(rules: &TraversalRules) -> Result<Self> {
        if rules.skip_globs.is_empty() {
            return Ok(Self { skip: None });
        }

        let mut builder = GlobSetBuilder::new();
        let map_err = |pattern: &str, err: String| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {:?}: {err}",
                summarize_pattern_for_error(pattern)
            ))
        };
        for pattern in &rules.skip_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            validate_root_relative_glob_pattern(&normalized)
                .map_err(|err| map_err(pattern, err.as_message().to_string()))?;
            let glob = build_glob_from_normalized(&normalized)
                .map_err(|err| map_err(pattern, err.to_string()))?;
            builder.add(glob);

            if let Some(expanded) = expand_dir_star_to_descendants(&normalized) {
                validate_root_relative_glob_pattern(&expanded)
                    .map_err(|err| map_err(pattern, err.as_message().to_string()))?;
                let glob = build_glob_from_normalized(&expanded)
                    .map_err(|err| map_err(pattern, err.to_string()))?;
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
        let Some(path) = normalize_runtime_path_for_matching(path) else {
            return false;
        };
        skip.is_match(std::path::Path::new(&path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipper_normalizes_runtime_path_separators() {
        let rules = TraversalRules {
            skip_globs: vec!["dir/*".to_string()],
        };
        let skipper = TraversalSkipper::from_rules(&rules).expect("skipper");
        assert!(skipper.is_path_skipped(".\\dir\\a.txt"));
    }

    #[test]
    fn skipper_rejects_parent_segments_at_runtime() {
        let rules = TraversalRules {
            skip_globs: vec!["dir/*".to_string()],
        };
        let skipper = TraversalSkipper::from_rules(&rules).expect("skipper");
        assert!(!skipper.is_path_skipped("dir/../a.txt"));
    }
}
