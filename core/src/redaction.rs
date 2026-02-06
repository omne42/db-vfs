use std::borrow::Cow;

use globset::{GlobSet, GlobSetBuilder};
use regex::{NoExpand, Regex};

use crate::glob_utils::{
    build_glob_from_normalized, expand_dir_star_to_descendants,
    normalize_glob_pattern_for_matching, validate_root_relative_glob_pattern,
};
use crate::policy::SecretRules;
use crate::{Error, Result};

const MAX_REDACT_REGEXES: usize = 128;
const MAX_REDACT_REGEX_PATTERN_BYTES: usize = 4096;
const MAX_REDACT_REGEX_COMPILED_SIZE_BYTES: usize = 1_000_000;
const MAX_REDACT_REGEX_NEST_LIMIT: u32 = 128;

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

#[derive(Debug, Clone)]
pub struct SecretRedactor {
    deny: GlobSet,
    redact: Vec<Regex>,
    replacement: String,
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

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        let mut deny_builder = GlobSetBuilder::new();
        for pattern in &rules.deny_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            validate_root_relative_glob_pattern(&normalized).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "invalid deny glob {pattern:?}: {}",
                    err.as_message()
                ))
            })?;
            let glob = build_glob_from_normalized(&normalized).map_err(|err| {
                Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {err}"))
            })?;
            deny_builder.add(glob);

            if let Some(expanded) = expand_dir_star_to_descendants(&normalized) {
                validate_root_relative_glob_pattern(&expanded).map_err(|err| {
                    Error::InvalidPolicy(format!(
                        "invalid deny glob {pattern:?}: {}",
                        err.as_message()
                    ))
                })?;
                let glob = build_glob_from_normalized(&expanded).map_err(|err| {
                    Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {err}"))
                })?;
                deny_builder.add(glob);
            }
        }
        let deny = deny_builder
            .build()
            .map_err(|err| Error::InvalidPolicy(format!("invalid deny globs: {err}")))?;

        if rules.redact_regexes.len() > MAX_REDACT_REGEXES {
            return Err(Error::InvalidPolicy(format!(
                "secrets.redact_regexes has too many patterns ({} > {})",
                rules.redact_regexes.len(),
                MAX_REDACT_REGEXES
            )));
        }

        let mut redact = Vec::<Regex>::new();
        for pattern in &rules.redact_regexes {
            if pattern.len() > MAX_REDACT_REGEX_PATTERN_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "invalid secrets.redact_regexes regex ({} bytes; max {} bytes)",
                    pattern.len(),
                    MAX_REDACT_REGEX_PATTERN_BYTES
                )));
            }
            if pattern.is_empty() {
                return Err(Error::InvalidPolicy(
                    "invalid secrets.redact_regexes regex: empty pattern is not allowed"
                        .to_string(),
                ));
            }
            let preview = summarize_pattern_for_error(pattern);
            let regex = regex::RegexBuilder::new(pattern)
                .size_limit(MAX_REDACT_REGEX_COMPILED_SIZE_BYTES)
                .nest_limit(MAX_REDACT_REGEX_NEST_LIMIT)
                .build()
                .map_err(|err| {
                    Error::InvalidPolicy(format!(
                        "invalid secrets.redact_regexes regex {preview:?}: {err}"
                    ))
                })?;
            redact.push(regex);
        }

        Ok(Self {
            deny,
            redact,
            replacement: rules.replacement.clone(),
        })
    }

    pub fn is_path_denied(&self, path: &str) -> bool {
        let Some(path) = normalize_runtime_path_for_matching(path) else {
            return false;
        };
        self.deny.is_match(std::path::Path::new(&path))
    }

    pub fn redact_text(&self, input: &str) -> String {
        let mut current: Cow<'_, str> = Cow::Borrowed(input);
        for regex in &self.redact {
            let replaced = regex.replace_all(current.as_ref(), NoExpand(&self.replacement));
            if matches!(replaced, Cow::Borrowed(_)) {
                continue;
            }
            current = Cow::Owned(replaced.into_owned());
        }
        current.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_dir_star_denies_nested_descendants() {
        let rules = SecretRules {
            deny_globs: vec!["dir/*".to_string()],
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).unwrap();

        assert!(redactor.is_path_denied("dir/a"));
        assert!(redactor.is_path_denied("dir/a/b.txt"));
        assert!(!redactor.is_path_denied("other/a/b.txt"));
    }

    #[test]
    fn redact_regex_rejects_empty_pattern() {
        let rules = SecretRules {
            redact_regexes: vec![String::new()],
            ..SecretRules::default()
        };
        assert!(SecretRedactor::from_rules(&rules).is_err());
    }

    #[test]
    fn deny_path_normalizes_backslashes_and_dot_segments() {
        let rules = SecretRules {
            deny_globs: vec!["dir/*".to_string()],
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert!(redactor.is_path_denied(".\\dir\\a.txt"));
    }

    #[test]
    fn redact_text_uses_literal_replacement() {
        let rules = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "$1".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert_eq!(redactor.redact_text("secret"), "$1");
    }

    #[test]
    fn redact_text_applies_regexes_in_order() {
        let rules = SecretRules {
            redact_regexes: vec!["foo".to_string(), "bar".to_string()],
            replacement: "x".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert_eq!(redactor.redact_text("foobar"), "xx");
    }
}
