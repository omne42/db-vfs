use db_vfs_core::{Error, Result};

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

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub path: String,
    pub size_bytes: u64,
    pub version: u64,
    pub updated_at_ms: u64,
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

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;
