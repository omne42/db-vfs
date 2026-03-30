use std::borrow::Cow;
use std::path::Path;

use globset::{GlobSet, GlobSetBuilder};
use regex::Regex;

use crate::glob_utils::{
    build_glob_from_normalized, expand_dir_star_to_descendants,
    normalize_glob_pattern_for_matching, validate_normalized_root_relative_glob_pattern,
};
use crate::path::is_canonical_runtime_relative_path;
use crate::policy::SecretRules;
use crate::{Error, Result};

const MAX_REDACT_REGEXES: usize = 128;
const MAX_REDACT_REGEX_PATTERN_BYTES: usize = 4096;
const MAX_REDACT_REGEX_COMPILED_SIZE_BYTES: usize = 1_000_000;
const MAX_REDACT_REGEX_NEST_LIMIT: u32 = 128;
// Keep in sync with the corresponding `VfsPolicy::validate` bound.
const MAX_SECRET_REPLACEMENT_BYTES: usize = 4096;
const AUDIT_DESCENDANT_PROBE_SEGMENT: &str = "__db_vfs_audit_probe__";
const MAX_AUDIT_DENY_PROBES: usize = 128;

fn is_canonical_runtime_path(path: &str) -> bool {
    is_canonical_runtime_relative_path(path)
}

fn strip_leading_dot_slashes(mut s: &str) -> &str {
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s
}

fn strip_leading_slashes(s: &str) -> &str {
    s.trim_start_matches('/')
}

fn normalize_runtime_path_for_matching(path: &str) -> Option<Cow<'_, str>> {
    if is_canonical_runtime_path(path) {
        return Some(Cow::Borrowed(path));
    }

    let trimmed = path.trim();
    let normalized: Cow<'_, str> = if trimmed.contains('\\') {
        Cow::Owned(trimmed.replace('\\', "/"))
    } else {
        Cow::Borrowed(trimmed)
    };
    let normalized = strip_leading_dot_slashes(normalized.as_ref());
    let normalized = strip_leading_slashes(normalized);
    if normalized.is_empty()
        || normalized.contains('\0')
        || normalized.chars().any(char::is_control)
    {
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

#[derive(Debug, Clone)]
pub struct SecretRedactor {
    deny: GlobSet,
    redact: Vec<Regex>,
    replacement: String,
    source: SecretRulesSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretRulesSource {
    deny_globs: Vec<String>,
    redact_regexes: Vec<String>,
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

fn validate_replacement(replacement: &str) -> Result<()> {
    if replacement.len() > MAX_SECRET_REPLACEMENT_BYTES {
        return Err(Error::InvalidPolicy(format!(
            "secrets.replacement is too large ({} bytes; max {} bytes)",
            replacement.len(),
            MAX_SECRET_REPLACEMENT_BYTES
        )));
    }
    if replacement.chars().any(char::is_control) {
        return Err(Error::InvalidPolicy(
            "secrets.replacement must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        validate_replacement(&rules.replacement)?;

        let mut deny_builder = GlobSetBuilder::new();
        let source = SecretRulesSource {
            deny_globs: rules.deny_globs.clone(),
            redact_regexes: rules.redact_regexes.clone(),
            replacement: rules.replacement.clone(),
        };
        for pattern in &rules.deny_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            validate_normalized_root_relative_glob_pattern(&normalized).map_err(|err| {
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
                validate_normalized_root_relative_glob_pattern(&expanded).map_err(|err| {
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
            let regex = regex::RegexBuilder::new(pattern)
                .size_limit(MAX_REDACT_REGEX_COMPILED_SIZE_BYTES)
                .nest_limit(MAX_REDACT_REGEX_NEST_LIMIT)
                .build()
                .map_err(|err| {
                    let preview = summarize_pattern_for_error(pattern);
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
            source,
        })
    }

    pub fn is_compatible_with_rules(&self, rules: &SecretRules) -> bool {
        self.source.deny_globs == rules.deny_globs
            && self.source.redact_regexes == rules.redact_regexes
            && self.source.replacement == rules.replacement
    }

    pub fn is_path_denied(&self, path: &str) -> bool {
        let Some(path) = normalize_runtime_path_for_matching(path) else {
            return false;
        };
        self.deny.is_match(Path::new(path.as_ref()))
    }

    pub fn path_or_any_descendant_is_denied(&self, path: &str) -> bool {
        if self.is_path_denied(path) {
            return true;
        }

        let trimmed = path.trim().trim_matches('/');
        if trimmed.is_empty() {
            return false;
        }

        if self.descendant_probe_is_denied(trimmed) {
            return true;
        }

        for probe in audit_path_probes(path) {
            if self.is_path_denied(&probe) || self.descendant_probe_is_denied(&probe) {
                return true;
            }
        }

        false
    }

    pub fn glob_may_match_denied_path(&self, pattern: &str) -> bool {
        if self.path_or_any_descendant_is_denied(pattern) {
            return true;
        }

        let Some(glob) = compile_audit_glob_matcher(pattern) else {
            return false;
        };
        let literal_prefix = literal_glob_prefix(pattern);

        self.audit_deny_probes().into_iter().any(|probe| {
            glob.is_match(Path::new(&probe))
                || literal_prefix.as_ref().is_some_and(|prefix| {
                    let prefixed = if prefix.is_empty() {
                        probe.clone()
                    } else {
                        format!("{prefix}/{probe}")
                    };
                    glob.is_match(Path::new(&prefixed))
                })
        })
    }

    pub fn redact_text(&self, input: &str) -> String {
        if self.redact.is_empty() {
            return input.to_string();
        }
        let mut current: Cow<'_, str> = Cow::Borrowed(input);
        for regex in &self.redact {
            current = redact_with_literal_replacement(current, regex, &self.replacement);
        }
        current.into_owned()
    }

    pub fn redact_text_owned(&self, mut input: String) -> String {
        if self.redact.is_empty() {
            return input;
        }

        for regex in &self.redact {
            let replaced = redact_with_literal_replacement(
                Cow::Borrowed(input.as_str()),
                regex,
                &self.replacement,
            );
            if let Cow::Owned(next) = replaced {
                input = next;
            }
        }
        input
    }

    pub fn redact_text_owned_bounded(
        &self,
        input: String,
        max_output_bytes: usize,
    ) -> std::result::Result<String, usize> {
        if input.len() > max_output_bytes {
            return Err(input.len());
        }

        let mut current: Cow<'_, str> = Cow::Borrowed(input.as_str());
        for regex in &self.redact {
            current = redact_with_literal_replacement_bounded(
                current,
                regex,
                &self.replacement,
                max_output_bytes,
            )?;
        }
        Ok(match current {
            Cow::Borrowed(_) => input,
            Cow::Owned(text) => text,
        })
    }

    pub fn redact_text_bounded<'a>(
        &self,
        input: &'a str,
        max_output_bytes: usize,
    ) -> std::result::Result<Cow<'a, str>, usize> {
        if input.len() > max_output_bytes {
            return Err(input.len());
        }
        if self.redact.is_empty() {
            return Ok(Cow::Borrowed(input));
        }

        let mut current: Cow<'a, str> = Cow::Borrowed(input);
        for regex in &self.redact {
            current = redact_with_literal_replacement_bounded(
                current,
                regex,
                &self.replacement,
                max_output_bytes,
            )?;
        }
        Ok(current)
    }

    pub fn has_redact_rules(&self) -> bool {
        !self.redact.is_empty()
    }

    pub fn replacement(&self) -> &str {
        &self.replacement
    }

    fn descendant_probe_is_denied(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let mut descendant_probe = String::with_capacity(
            path.len()
                .saturating_add(AUDIT_DESCENDANT_PROBE_SEGMENT.len() + 1),
        );
        descendant_probe.push_str(path);
        descendant_probe.push('/');
        descendant_probe.push_str(AUDIT_DESCENDANT_PROBE_SEGMENT);
        self.is_path_denied(&descendant_probe)
    }

    fn audit_deny_probes(&self) -> Vec<String> {
        let mut probes = Vec::new();
        for pattern in &self.source.deny_globs {
            let normalized = normalize_glob_pattern_for_matching(pattern);
            for probe in sample_paths_from_glob_pattern(&normalized, MAX_AUDIT_DENY_PROBES) {
                push_unique(&mut probes, probe, MAX_AUDIT_DENY_PROBES);
                if probes.len() >= MAX_AUDIT_DENY_PROBES {
                    return probes;
                }
            }
        }
        probes
    }
}

fn compile_audit_glob_matcher(pattern: &str) -> Option<globset::GlobMatcher> {
    let normalized = normalize_glob_pattern_for_matching(pattern);
    validate_normalized_root_relative_glob_pattern(&normalized).ok()?;
    let glob = build_glob_from_normalized(&normalized).ok()?;
    Some(glob.compile_matcher())
}

fn literal_glob_prefix(pattern: &str) -> Option<String> {
    let normalized = normalize_glob_pattern_for_matching(pattern);
    if normalized.starts_with('/') {
        return None;
    }

    let mut prefix = String::with_capacity(normalized.len());
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        if segment
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
        {
            break;
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(segment);
    }

    Some(prefix)
}

fn audit_path_probes(path: &str) -> Vec<String> {
    const MAX_PATH_PROBES: usize = 64;

    let normalized = path.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut probes = Vec::new();
    let mut current = String::new();
    for segment in normalized
        .split('/')
        .map(sanitize_audit_path_probe_segment)
        .filter(|segment| !segment.is_empty())
    {
        if segment == "." {
            continue;
        }
        if segment == ".." {
            current.clear();
            continue;
        }

        push_unique(&mut probes, segment.clone(), MAX_PATH_PROBES);
        let joined = if current.is_empty() {
            segment
        } else {
            format!("{current}/{segment}")
        };
        push_unique(&mut probes, joined.clone(), MAX_PATH_PROBES);
        current = joined;
        if probes.len() >= MAX_PATH_PROBES {
            break;
        }
    }

    probes
}

fn sanitize_audit_path_probe_segment(segment: &str) -> String {
    segment
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .collect()
}

fn sample_paths_from_glob_pattern(pattern: &str, limit: usize) -> Vec<String> {
    if pattern.is_empty() {
        return Vec::new();
    }

    let mut active = vec![String::new()];
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        let variants = sample_glob_segment_variants(segment, limit);
        if variants.is_empty() {
            continue;
        }

        let mut next = Vec::new();
        for base in &active {
            for variant in &variants {
                let candidate = if variant.is_empty() {
                    base.clone()
                } else if base.is_empty() {
                    variant.clone()
                } else {
                    format!("{base}/{variant}")
                };
                push_unique(&mut next, candidate, limit);
                if next.len() >= limit {
                    break;
                }
            }
            if next.len() >= limit {
                break;
            }
        }

        if next.is_empty() {
            continue;
        }
        active = next;
        if active.len() >= limit {
            break;
        }
    }

    active
        .into_iter()
        .filter(|candidate| !candidate.is_empty())
        .take(limit)
        .collect()
}

fn sample_glob_segment_variants(segment: &str, limit: usize) -> Vec<String> {
    if segment == "**" {
        return vec![String::new(), "nested".to_string()];
    }

    let mut out = Vec::new();
    let expanded =
        expand_brace_variants(segment, limit).unwrap_or_else(|| vec![segment.to_string()]);
    for variant in expanded {
        if let Some(sample) = sample_glob_segment(&variant) {
            push_unique(&mut out, sample, limit);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn sample_glob_segment(segment: &str) -> Option<String> {
    let mut out = String::with_capacity(segment.len().saturating_add(4));
    let mut chars = segment.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '*' | '?' => out.push('x'),
            '[' => out.push(sample_char_class(&mut chars)?),
            _ => out.push(ch),
        }
    }

    if out.is_empty() { None } else { Some(out) }
}

fn sample_char_class(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    let mut negate = false;
    if matches!(chars.peek(), Some('!' | '^')) {
        negate = true;
        chars.next();
    }

    let mut first_literal = None;
    let mut previous = None;
    while let Some(ch) = chars.next() {
        if ch == ']' {
            break;
        }
        if ch == '-'
            && let (Some(start), Some(end)) = (previous, chars.peek().copied())
            && end != ']'
        {
            chars.next();
            first_literal.get_or_insert(start);
            previous = Some(end);
            continue;
        }
        first_literal.get_or_insert(ch);
        previous = Some(ch);
    }

    let candidate = first_literal?;
    if !negate {
        return Some(candidate);
    }

    for fallback in ['x', 'y', 'z', '0', '_'] {
        if fallback != candidate {
            return Some(fallback);
        }
    }
    Some(candidate)
}

fn expand_brace_variants(segment: &str, limit: usize) -> Option<Vec<String>> {
    let open = segment.find('{')?;

    let mut depth = 0usize;
    let mut close = None;
    let mut split_points = Vec::new();
    for (idx, ch) in segment[open..].char_indices() {
        let absolute = open + idx;
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(absolute);
                    break;
                }
            }
            ',' if depth == 1 => split_points.push(absolute),
            _ => {}
        }
    }
    let close = close?;

    let prefix = &segment[..open];
    let suffix = &segment[close + 1..];
    let mut start = open + 1;
    let mut arms = Vec::new();
    for split in split_points {
        arms.push(&segment[start..split]);
        start = split + 1;
    }
    arms.push(&segment[start..close]);

    let mut expanded = Vec::new();
    for arm in arms {
        let nested = format!("{prefix}{arm}{suffix}");
        for variant in expand_brace_variants(&nested, limit).unwrap_or_else(|| vec![nested.clone()])
        {
            push_unique(&mut expanded, variant, limit);
        }
        if expanded.len() >= limit {
            break;
        }
    }
    Some(expanded)
}

fn push_unique(values: &mut Vec<String>, candidate: String, limit: usize) {
    if values.len() >= limit || values.iter().any(|value| value == &candidate) {
        return;
    }
    values.push(candidate);
}

fn preserved_line_break_bytes(matched: &str) -> usize {
    matched
        .bytes()
        .filter(|byte| matches!(byte, b'\n' | b'\r'))
        .count()
}

fn push_preserved_line_breaks(matched: &str, out: &mut String) {
    for ch in matched.chars() {
        if matches!(ch, '\n' | '\r') {
            out.push(ch);
        }
    }
}

fn redact_with_literal_replacement<'a>(
    input: Cow<'a, str>,
    regex: &Regex,
    replacement: &str,
) -> Cow<'a, str> {
    let mut matches = regex.find_iter(input.as_ref());
    let Some(first) = matches.next() else {
        return input;
    };

    let input_ref = input.as_ref();
    let mut out = String::with_capacity(input_ref.len());
    let mut last = 0usize;

    for m in std::iter::once(first).chain(matches) {
        out.push_str(&input_ref[last..m.start()]);
        out.push_str(replacement);
        push_preserved_line_breaks(m.as_str(), &mut out);
        last = m.end();
    }

    out.push_str(&input_ref[last..]);
    Cow::Owned(out)
}

fn redact_with_literal_replacement_bounded<'a>(
    input: Cow<'a, str>,
    regex: &Regex,
    replacement: &str,
    max_output_bytes: usize,
) -> std::result::Result<Cow<'a, str>, usize> {
    let mut matches = regex.find_iter(input.as_ref());
    let Some(first) = matches.next() else {
        return Ok(input);
    };

    let input_ref = input.as_ref();
    let mut out = String::with_capacity(input_ref.len().min(max_output_bytes));
    let mut out_len = 0usize;
    let mut last = 0usize;

    for m in std::iter::once(first).chain(matches) {
        let prefix = &input_ref[last..m.start()];
        if out_len > max_output_bytes.saturating_sub(prefix.len()) {
            return Err(max_output_bytes.saturating_add(1));
        }
        out.push_str(prefix);
        out_len += prefix.len();

        if out_len > max_output_bytes.saturating_sub(replacement.len()) {
            return Err(max_output_bytes.saturating_add(1));
        }
        out.push_str(replacement);
        out_len += replacement.len();

        let preserved_line_break_bytes = preserved_line_break_bytes(m.as_str());
        if out_len > max_output_bytes.saturating_sub(preserved_line_break_bytes) {
            return Err(max_output_bytes.saturating_add(1));
        }
        push_preserved_line_breaks(m.as_str(), &mut out);
        out_len += preserved_line_break_bytes;
        last = m.end();
    }

    let tail = &input_ref[last..];
    if out_len > max_output_bytes.saturating_sub(tail.len()) {
        return Err(max_output_bytes.saturating_add(1));
    }
    out.push_str(tail);
    Ok(Cow::Owned(out))
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
    fn replacement_rejects_control_characters() {
        let rules = SecretRules {
            replacement: "line1\nline2".to_string(),
            ..SecretRules::default()
        };
        let err = SecretRedactor::from_rules(&rules).expect_err("control chars should fail");
        assert!(
            err.to_string()
                .contains("must not contain control characters")
        );
    }

    #[test]
    fn replacement_rejects_oversized_value() {
        let rules = SecretRules {
            replacement: "x".repeat(MAX_SECRET_REPLACEMENT_BYTES + 1),
            ..SecretRules::default()
        };
        let err =
            SecretRedactor::from_rules(&rules).expect_err("oversized replacement should fail");
        assert!(err.to_string().contains("secrets.replacement is too large"));
    }

    #[test]
    fn deny_path_normalizes_backslashes_and_dot_segments() {
        let rules = SecretRules {
            deny_globs: vec!["dir/*".to_string()],
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert!(redactor.is_path_denied(".\\dir\\a.txt"));
        assert!(redactor.is_path_denied("./././dir//a.txt"));
        assert!(redactor.is_path_denied("///./dir/a.txt"));
    }

    #[test]
    fn deny_path_rejects_control_characters_at_runtime() {
        let rules = SecretRules {
            deny_globs: vec!["dir/*".to_string()],
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert!(!redactor.is_path_denied("dir/\nsecret.txt"));
    }

    #[test]
    fn path_or_any_descendant_is_denied_keeps_secret_roots_from_malformed_paths() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");

        assert!(redactor.path_or_any_descendant_is_denied(".env/../visible.txt"));
        assert!(redactor.path_or_any_descendant_is_denied("docs/.git/\u{0000}config"));
        assert!(!redactor.path_or_any_descendant_is_denied("docs/../visible.txt"));
    }

    #[test]
    fn glob_may_match_denied_path_uses_real_glob_matching() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");

        assert!(redactor.glob_may_match_denied_path(".[en]nv"));
        assert!(redactor.glob_may_match_denied_path(".{envrc,netrc}"));
        assert!(redactor.glob_may_match_denied_path("docs/**/.env*"));
        assert!(!redactor.glob_may_match_denied_path("docs/*.txt"));
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

    #[test]
    fn redact_text_owned_bounded_rejects_expansion() {
        let rules = SecretRules {
            redact_regexes: vec!["a".to_string()],
            replacement: "xxxx".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        let err = redactor
            .redact_text_owned_bounded("aaaa".to_string(), 8)
            .expect_err("expansion should exceed limit");
        assert!(err > 8);
    }

    #[test]
    fn redact_text_owned_bounded_keeps_input_when_no_matches() {
        let rules = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "x".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        let out = redactor
            .redact_text_owned_bounded("public".to_string(), 8)
            .expect("bounded redact");
        assert_eq!(out, "public");
    }

    #[test]
    fn redact_text_owned_bounded_rejects_oversized_input_without_match() {
        let rules = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "x".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        let err = redactor
            .redact_text_owned_bounded("public-data".to_string(), 6)
            .expect_err("oversized input should fail even without regex matches");
        assert_eq!(err, "public-data".len());
    }

    #[test]
    fn redact_text_owned_bounded_rejects_oversized_input_without_rules() {
        let redactor = SecretRedactor::from_rules(&SecretRules::default()).expect("redactor");
        let err = redactor
            .redact_text_owned_bounded("public-data".to_string(), 6)
            .expect_err("oversized input should fail even without redact rules");
        assert_eq!(err, "public-data".len());
    }

    #[test]
    fn redact_text_bounded_borrows_input_when_no_matches() {
        let rules = SecretRules {
            redact_regexes: vec!["secret".to_string()],
            replacement: "x".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        let input = "public";
        let out = redactor
            .redact_text_bounded(input, 8)
            .expect("bounded redact");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), input);
    }

    #[test]
    fn redact_text_preserves_line_breaks_inside_multiline_matches() {
        let rules = SecretRules {
            redact_regexes: vec!["BEGIN\\nsecret\\nEND".to_string()],
            replacement: "REDACTED".to_string(),
            ..SecretRules::default()
        };
        let redactor = SecretRedactor::from_rules(&rules).expect("redactor");
        assert_eq!(
            redactor.redact_text("BEGIN\nsecret\nEND\npublic\n"),
            "REDACTED\n\n\npublic\n"
        );
    }
}
