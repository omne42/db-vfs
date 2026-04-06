use std::fmt;

pub const MAX_ALLOWED_WORKSPACE_PATTERN_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedWorkspacePattern {
    Any,
    Prefix(String),
    Exact(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedWorkspacePatternError {
    Empty,
    ContainsWhitespace,
    TooLong { len: usize, max: usize },
    UnsupportedWildcard,
    InvalidTrailingWildcardSyntax,
    TrailingWildcardMustEndWithDash,
}

impl fmt::Display for AllowedWorkspacePatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must be non-empty"),
            Self::ContainsWhitespace => f.write_str("must not contain whitespace"),
            Self::TooLong { len, max } => write!(f, "is too large ({} bytes; max {})", len, max),
            Self::UnsupportedWildcard => {
                f.write_str("only supports '*' as a full wildcard or a trailing '*' prefix")
            }
            Self::InvalidTrailingWildcardSyntax => {
                f.write_str("has invalid trailing wildcard syntax")
            }
            Self::TrailingWildcardMustEndWithDash => {
                f.write_str("trailing wildcard patterns must end with '-*'")
            }
        }
    }
}

impl AllowedWorkspacePattern {
    pub fn parse(pattern: &str) -> std::result::Result<Self, AllowedWorkspacePatternError> {
        if pattern.trim().is_empty() {
            return Err(AllowedWorkspacePatternError::Empty);
        }
        if pattern.chars().any(char::is_whitespace) {
            return Err(AllowedWorkspacePatternError::ContainsWhitespace);
        }
        if pattern.len() > MAX_ALLOWED_WORKSPACE_PATTERN_BYTES {
            return Err(AllowedWorkspacePatternError::TooLong {
                len: pattern.len(),
                max: MAX_ALLOWED_WORKSPACE_PATTERN_BYTES,
            });
        }
        if pattern == "*" {
            return Ok(Self::Any);
        }

        let star_count = pattern.chars().filter(|ch| *ch == '*').count();
        if star_count > 1 || (star_count == 1 && !pattern.ends_with('*')) {
            return Err(AllowedWorkspacePatternError::UnsupportedWildcard);
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.is_empty() {
                return Err(AllowedWorkspacePatternError::InvalidTrailingWildcardSyntax);
            }
            if !prefix.ends_with('-') {
                return Err(AllowedWorkspacePatternError::TrailingWildcardMustEndWithDash);
            }
            return Ok(Self::Prefix(prefix.to_string()));
        }

        Ok(Self::Exact(pattern.to_string()))
    }

    pub fn matches(&self, workspace_id: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Prefix(prefix) => workspace_id
                .strip_prefix(prefix)
                .is_some_and(|suffix| !suffix.is_empty()),
            Self::Exact(exact) => exact == workspace_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllowedWorkspacePattern, AllowedWorkspacePatternError, MAX_ALLOWED_WORKSPACE_PATTERN_BYTES,
    };

    #[test]
    fn parse_supports_any_exact_and_prefix_patterns() {
        assert_eq!(
            AllowedWorkspacePattern::parse("*"),
            Ok(AllowedWorkspacePattern::Any)
        );
        assert_eq!(
            AllowedWorkspacePattern::parse("ws-prod"),
            Ok(AllowedWorkspacePattern::Exact("ws-prod".to_string()))
        );
        assert_eq!(
            AllowedWorkspacePattern::parse("team-*"),
            Ok(AllowedWorkspacePattern::Prefix("team-".to_string()))
        );
    }

    #[test]
    fn parse_rejects_non_trailing_or_multi_wildcards() {
        assert_eq!(
            AllowedWorkspacePattern::parse("team*prod"),
            Err(AllowedWorkspacePatternError::UnsupportedWildcard)
        );
        assert_eq!(
            AllowedWorkspacePattern::parse("team-*prod"),
            Err(AllowedWorkspacePatternError::UnsupportedWildcard)
        );
    }

    #[test]
    fn parse_rejects_dashless_prefix_wildcards() {
        assert_eq!(
            AllowedWorkspacePattern::parse("team*"),
            Err(AllowedWorkspacePatternError::TrailingWildcardMustEndWithDash)
        );
    }

    #[test]
    fn parse_rejects_empty_whitespace_and_oversized_patterns() {
        assert_eq!(
            AllowedWorkspacePattern::parse(""),
            Err(AllowedWorkspacePatternError::Empty)
        );
        assert_eq!(
            AllowedWorkspacePattern::parse("  "),
            Err(AllowedWorkspacePatternError::Empty)
        );
        assert_eq!(
            AllowedWorkspacePattern::parse("team a"),
            Err(AllowedWorkspacePatternError::ContainsWhitespace)
        );
        assert_eq!(
            AllowedWorkspacePattern::parse(
                &"a".repeat(MAX_ALLOWED_WORKSPACE_PATTERN_BYTES.saturating_add(1))
            ),
            Err(AllowedWorkspacePatternError::TooLong {
                len: MAX_ALLOWED_WORKSPACE_PATTERN_BYTES + 1,
                max: MAX_ALLOWED_WORKSPACE_PATTERN_BYTES,
            })
        );
    }

    #[test]
    fn prefix_matching_requires_non_empty_suffix() {
        let pattern = AllowedWorkspacePattern::parse("team-*").expect("compile");
        assert!(pattern.matches("team-123"));
        assert!(!pattern.matches("team-"));
        assert!(!pattern.matches("other"));
    }
}
