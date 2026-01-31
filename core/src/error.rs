use thiserror::Error;

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
    pub fn code(&self) -> &'static str {
        match self {
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
}
