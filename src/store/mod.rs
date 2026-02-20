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
        let content_len = u64::try_from(self.content.len())
            .map_err(|_| Error::Db("integer overflow converting content length".to_string()))?;
        if self.size_bytes != content_len {
            return Err(Error::Db(format!(
                "size/content mismatch: size_bytes={} content_len={}",
                self.size_bytes, content_len
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
    ) -> Result<u64>;

    fn update_file_cas(
        &mut self,
        workspace_id: &str,
        path: &str,
        content: &str,
        expected_version: u64,
        now_ms: u64,
    ) -> Result<u64>;

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

    fn list_metas_by_prefix_page(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<FileMeta>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let Some(after) = after else {
            return self.list_metas_by_prefix(workspace_id, prefix, limit);
        };

        // Compatibility slow-path for legacy stores that only implement
        // `list_metas_by_prefix`. This may require repeated prefix scans.
        // Implement `list_metas_by_prefix_page` in concrete stores to avoid
        // this fallback and provide predictable large-prefix performance.
        let mut fetch_limit = limit.max(64);
        loop {
            let mut rows = self.list_metas_by_prefix(workspace_id, prefix, fetch_limit)?;
            let rows_len = rows.len();
            if rows_len > 1 && rows.windows(2).any(|pair| pair[0].path > pair[1].path) {
                // Legacy stores may not return rows in lexical path order. Keep the
                // fallback deterministic/correct for cursor pagination.
                rows.sort_unstable_by(|a, b| a.path.cmp(&b.path));
            }
            let split = rows.partition_point(|meta| meta.path.as_str() <= after);
            let mut out = rows.split_off(split);
            if out.len() >= limit {
                out.truncate(limit);
                return Ok(out);
            }
            if rows_len < fetch_limit {
                return Ok(out);
            }

            let next = if split == rows_len {
                fetch_limit.saturating_mul(2)
            } else {
                let missing = limit.saturating_sub(out.len());
                fetch_limit.saturating_add(missing.max(fetch_limit / 2))
            };
            if next == fetch_limit {
                return Ok(out);
            }
            fetch_limit = next;
        }
    }
}

fn db_err(err: impl std::fmt::Display) -> Error {
    Error::Db(err.to_string())
}

fn make_prefix_bounds(prefix: &str) -> (String, Option<String>) {
    (prefix.to_string(), prefix_successor(prefix))
}

fn prefix_successor(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }

    for (idx, ch) in prefix.char_indices().rev() {
        if let Some(next) = next_scalar_char(ch) {
            let mut out = String::with_capacity(idx.saturating_add(next.len_utf8()));
            out.push_str(&prefix[..idx]);
            out.push(next);
            return Some(out);
        }
    }

    None
}

fn next_scalar_char(ch: char) -> Option<char> {
    let mut code = (ch as u32).saturating_add(1);
    while code <= char::MAX as u32 {
        if let Some(next) = char::from_u32(code) {
            return Some(next);
        }
        code = code.saturating_add(1);
    }
    None
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
        assert_eq!(make_prefix_bounds(""), ("".to_string(), None));

        let (lower, upper) = make_prefix_bounds("文档/");
        assert_eq!(lower, "文档/");
        assert_eq!(upper, Some("文档0".to_string()));
    }

    #[test]
    fn make_prefix_bounds_covers_max_scalar_tail() {
        let (lower, upper) = make_prefix_bounds("a");
        assert_eq!(lower, "a");
        assert_eq!(upper, Some("b".to_string()));

        let candidate = "a\u{10FFFF}x".to_string();
        assert!(candidate.starts_with(&lower));
        assert!(candidate < upper.expect("upper bound should exist"));
    }

    #[derive(Default)]
    struct PrefixOnlyStore {
        paths: Vec<String>,
    }

    impl Store for PrefixOnlyStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            unimplemented!()
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn delete_file(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _expected_version: Option<u64>,
        ) -> Result<DeleteOutcome> {
            unimplemented!()
        }

        fn list_metas_by_prefix(
            &mut self,
            _workspace_id: &str,
            prefix: &str,
            limit: usize,
        ) -> Result<Vec<FileMeta>> {
            Ok(self
                .paths
                .iter()
                .filter(|path| path.starts_with(prefix))
                .take(limit)
                .map(|path| FileMeta {
                    path: path.clone(),
                    size_bytes: 0,
                    version: 1,
                    updated_at_ms: 0,
                })
                .collect())
        }
    }

    #[derive(Default)]
    struct UnsortedPrefixStore {
        paths: Vec<String>,
    }

    impl Store for UnsortedPrefixStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            unimplemented!()
        }

        fn insert_file_new(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn update_file_cas(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _content: &str,
            _expected_version: u64,
            _now_ms: u64,
        ) -> Result<u64> {
            unimplemented!()
        }

        fn delete_file(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _expected_version: Option<u64>,
        ) -> Result<DeleteOutcome> {
            unimplemented!()
        }

        fn list_metas_by_prefix(
            &mut self,
            _workspace_id: &str,
            prefix: &str,
            limit: usize,
        ) -> Result<Vec<FileMeta>> {
            let mut rows = self
                .paths
                .iter()
                .filter(|path| path.starts_with(prefix))
                .take(limit)
                .map(|path| FileMeta {
                    path: path.clone(),
                    size_bytes: 0,
                    version: 1,
                    updated_at_ms: 0,
                })
                .collect::<Vec<_>>();
            rows.reverse();
            Ok(rows)
        }
    }

    #[test]
    fn default_page_impl_supports_cursor_pagination_with_legacy_stores() {
        let mut store = PrefixOnlyStore {
            paths: vec![
                "docs/a.txt".to_string(),
                "docs/b.txt".to_string(),
                "docs/c.txt".to_string(),
            ],
        };
        let page = store
            .list_metas_by_prefix_page("ws", "docs/", Some("docs/a.txt"), 2)
            .expect("cursor pagination fallback should work");
        let paths = page.into_iter().map(|meta| meta.path).collect::<Vec<_>>();
        assert_eq!(paths, vec!["docs/b.txt", "docs/c.txt"]);
    }

    #[test]
    fn default_page_impl_handles_unsorted_legacy_rows() {
        let mut store = UnsortedPrefixStore {
            paths: vec![
                "docs/a.txt".to_string(),
                "docs/b.txt".to_string(),
                "docs/c.txt".to_string(),
            ],
        };

        let page = store
            .list_metas_by_prefix_page("ws", "docs/", Some("docs/a.txt"), 2)
            .expect("fallback should sort unsorted legacy rows");
        let paths = page.into_iter().map(|meta| meta.path).collect::<Vec<_>>();
        assert_eq!(paths, vec!["docs/b.txt", "docs/c.txt"]);
    }
}
