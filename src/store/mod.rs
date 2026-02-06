use db_vfs_core::{Error, Result};

pub const MAX_STORE_VERSION: u64 = i64::MAX as u64;

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub workspace_id: String,
    pub path: String,
    pub content: String,
    pub size_bytes: u64,
    pub version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub metadata_json: Option<String>,
}

impl FileRecord {
    pub fn validated(self) -> Result<Self> {
        if self.version == 0 {
            return Err(Error::Db("invalid file version: 0".to_string()));
        }
        if self.size_bytes != self.content.len() as u64 {
            return Err(Error::Db(format!(
                "size/content mismatch: size_bytes={} content_len={}",
                self.size_bytes,
                self.content.len()
            )));
        }
        if self.updated_at_ms < self.created_at_ms {
            return Err(Error::Db(format!(
                "invalid timestamps: updated_at_ms={} < created_at_ms={}",
                self.updated_at_ms, self.created_at_ms
            )));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub path: String,
    pub size_bytes: u64,
    pub version: u64,
    pub updated_at_ms: u64,
}

impl FileMeta {
    pub fn validated(self) -> Result<Self> {
        if self.version == 0 {
            return Err(Error::Db("invalid file version: 0".to_string()));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

pub trait Store {
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> Result<Option<FileMeta>>;

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> Result<Option<String>>;

    fn insert_file_new(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        now_ms: u64,
    ) -> Result<FileRecord>;

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> Result<FileRecord>;

    /// Deletes a file for the given workspace/path.
    ///
    /// - `expected_version = Some(v)`: delete only when current version equals `v`; mismatch returns `conflict`.
    /// - `expected_version = None`: unconditional delete by `(workspace_id, path)`.
    /// - Returns `NotFound` when target row does not exist.
    fn delete_file(
        &mut self,
        workspace_id: &str,
        path: &str,
        expected_version: Option<u64>,
    ) -> Result<DeleteOutcome>;

    fn list_metas_by_prefix(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<FileMeta>>;
}

fn db_err(err: impl std::fmt::Display) -> Error {
    Error::Db(err.to_string())
}

fn make_prefix_bounds(prefix: &str) -> (String, String) {
    let lower = prefix.to_string();
    let upper = format!("{prefix}\u{10FFFF}");
    (lower, upper)
}

fn next_version(expected_version: u64) -> Result<u64> {
    if expected_version >= MAX_STORE_VERSION {
        return Err(Error::Conflict("version overflow".to_string()));
    }
    Ok(expected_version + 1)
}

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_version_increments() {
        assert_eq!(next_version(1).unwrap(), 2);
    }

    #[test]
    fn next_version_rejects_overflow() {
        let err = next_version(MAX_STORE_VERSION).expect_err("should overflow");
        assert_eq!(err.code(), "conflict");
    }

    #[test]
    fn file_record_rejects_inconsistent_invariants() {
        let err = FileRecord {
            workspace_id: "ws".to_string(),
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            size_bytes: 4,
            version: 1,
            created_at_ms: 10,
            updated_at_ms: 10,
            metadata_json: None,
        }
        .validated()
        .expect_err("invalid size");
        assert_eq!(err.code(), "db");

        let err = FileRecord {
            workspace_id: "ws".to_string(),
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            size_bytes: 5,
            version: 0,
            created_at_ms: 10,
            updated_at_ms: 10,
            metadata_json: None,
        }
        .validated()
        .expect_err("invalid version");
        assert_eq!(err.code(), "db");

        let err = FileRecord {
            workspace_id: "ws".to_string(),
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            size_bytes: 5,
            version: 1,
            created_at_ms: 10,
            updated_at_ms: 9,
            metadata_json: None,
        }
        .validated()
        .expect_err("invalid timestamps");
        assert_eq!(err.code(), "db");
    }

    #[test]
    fn file_meta_rejects_zero_version() {
        let err = FileMeta {
            path: "a.txt".to_string(),
            size_bytes: 1,
            version: 0,
            updated_at_ms: 1,
        }
        .validated()
        .expect_err("invalid version");
        assert_eq!(err.code(), "db");
    }

    #[test]
    fn make_prefix_bounds_handles_empty_and_unicode() {
        assert_eq!(
            make_prefix_bounds(""),
            ("".to_string(), "\u{10FFFF}".to_string())
        );

        let (lower, upper) = make_prefix_bounds("文档/");
        assert_eq!(lower, "文档/");
        assert_eq!(upper, "文档/\u{10FFFF}");
    }
}
