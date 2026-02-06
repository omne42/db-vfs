use thiserror::Error;

macro_rules! define_error_codes {
    ($( $pattern:pat => $code:literal, )+ ) => {
        pub fn code(&self) -> &'static str {
            match self {
                $( $pattern => $code, )+
            }
        }
    };
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("db error: {0}")]
    Db(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("operation is not permitted: {0}")]
    NotPermitted(String),

    #[error("path is denied by secret rules: {0}")]
    SecretPathDenied(String),

    #[error("file is too large ({size_bytes} bytes; max {max_bytes} bytes): {path}")]
    FileTooLarge {
        path: String,
        size_bytes: u64,
        max_bytes: u64,
    },

    #[error("failed to apply patch: {0}")]
    Patch(String),

    #[error("invalid regex: {0}")]
    InvalidRegex(String),

    #[error("input is too large ({size_bytes} bytes; max {max_bytes} bytes)")]
    InputTooLarge { size_bytes: u64, max_bytes: u64 },

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    define_error_codes! {
        Error::Db(_) => "db",
        Error::InvalidPolicy(_) => "invalid_policy",
        Error::InvalidPath(_) => "invalid_path",
        Error::NotFound(_) => "not_found",
        Error::NotPermitted(_) => "not_permitted",
        Error::SecretPathDenied(_) => "secret_path_denied",
        Error::FileTooLarge { .. } => "file_too_large",
        Error::Patch(_) => "patch",
        Error::InvalidRegex(_) => "invalid_regex",
        Error::InputTooLarge { .. } => "input_too_large",
        Error::Conflict(_) => "conflict",
        Error::QuotaExceeded(_) => "quota_exceeded",
        Error::Timeout(_) => "timeout",
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::collections::HashSet;

    #[test]
    fn error_codes_are_non_empty_and_unique() {
        let errors = [
            Error::Db("x".to_string()),
            Error::InvalidPolicy("x".to_string()),
            Error::InvalidPath("x".to_string()),
            Error::NotFound("x".to_string()),
            Error::NotPermitted("x".to_string()),
            Error::SecretPathDenied("x".to_string()),
            Error::FileTooLarge {
                path: "x".to_string(),
                size_bytes: 1,
                max_bytes: 1,
            },
            Error::Patch("x".to_string()),
            Error::InvalidRegex("x".to_string()),
            Error::InputTooLarge {
                size_bytes: 1,
                max_bytes: 1,
            },
            Error::Conflict("x".to_string()),
            Error::QuotaExceeded("x".to_string()),
            Error::Timeout("x".to_string()),
        ];

        let mut unique = HashSet::new();
        for error in errors {
            let code = error.code();
            assert!(!code.is_empty());
            assert!(unique.insert(code));
        }
    }
}
