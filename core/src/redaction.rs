use std::borrow::Cow;

use globset::{GlobSet, GlobSetBuilder};
use regex::{NoExpand, Regex};

use crate::policy::SecretRules;
use crate::{Error, Result};

const MAX_REDACT_REGEXES: usize = 128;
const MAX_REDACT_REGEX_PATTERN_BYTES: usize = 4096;
const MAX_REDACT_REGEX_COMPILED_SIZE_BYTES: usize = 1_000_000;
const MAX_REDACT_REGEX_NEST_LIMIT: u32 = 128;

const PROBE_FILE_NAME: &str = ".db-vfs-probe";

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

fn validate_root_relative_glob_pattern(pattern: &str) -> std::result::Result<(), &'static str> {
    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }
    if pattern.split('/').any(|seg| seg == "..") {
        return Err("glob patterns must not contain '..' segments");
    }
    Ok(())
}

fn build_glob_from_normalized(pattern: &str) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = globset::GlobBuilder::new(pattern);
    builder.literal_separator(true);
    builder.build()
}

fn normalize_glob_pattern_for_matching(pattern: &str) -> String {
    let mut normalized = pattern.trim().replace('\\', "/");
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    if normalized.is_empty() {
        normalized.push('.');
    }
    normalized
}

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        let mut deny_builder = GlobSetBuilder::new();
        for pattern in &rules.deny_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            validate_root_relative_glob_pattern(&normalized).map_err(|msg| {
                Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {msg}"))
            })?;
            let glob = build_glob_from_normalized(&normalized).map_err(|err| {
                Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {err}"))
            })?;
            deny_builder.add(glob);
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
        if self.deny.is_match(std::path::Path::new(path)) {
            return true;
        }

        // Directory probe trick: deny `dir/*` should hide everything under `dir/**`.
        let is_dir = path.ends_with('/');
        let path = path.trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|seg| !seg.is_empty()).collect();
        let probe_depth = if is_dir {
            segments.len()
        } else {
            segments.len().saturating_sub(1)
        };

        let mut current = String::new();
        for segment in segments.into_iter().take(probe_depth) {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(segment);
            let probe = format!("{current}/{PROBE_FILE_NAME}");
            if self.deny.is_match(std::path::Path::new(&probe)) {
                return true;
            }
        }
        false
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
}
