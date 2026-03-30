#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use db_vfs_core::{Error, Result};

#[cfg(test)]
use crate::text_lines::line_spans;

pub const MAX_STORE_VERSION: u64 = i64::MAX as u64;
const DEFAULT_RANGE_READ_CHUNK_CHARS: usize = 4096;
const MAX_RANGE_READ_CHUNK_CHARS: usize = 64 * 1024;

static LEGACY_PREFIX_PAGE_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK: Mutex<()> = Mutex::new(());

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRangeData {
    pub content: Option<String>,
    pub bytes_read: u64,
    pub total_lines: u64,
}

pub trait Store {
    fn get_meta(&mut self, workspace_id: &str, path: &str) -> Result<Option<FileMeta>>;

    fn get_content(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
    ) -> Result<Option<String>>;

    /// Reads a character-bounded chunk of file content for ranged-read traversal.
    ///
    /// - `start_char` is 1-based and inclusive.
    /// - `max_chars` bounds the number of Unicode scalar values returned.
    /// - `None` indicates the `(workspace_id, path, version)` row no longer exists.
    /// - `Some("")` indicates end-of-file once the row exists but `start_char` is past the end.
    ///
    /// Production stores should override this to avoid materializing whole-file content for
    /// line-range reads. The default implementation preserves compatibility for legacy stores by
    /// falling back to [`Store::get_content`].
    fn get_content_chunk(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_char: u64,
        max_chars: usize,
    ) -> Result<Option<String>> {
        if max_chars == 0 {
            return Ok(Some(String::new()));
        }

        let Some(content) = self.get_content(workspace_id, path, version)? else {
            return Ok(None);
        };
        if start_char <= 1 {
            return Ok(Some(content.chars().take(max_chars).collect()));
        }

        let start_idx = usize::try_from(start_char.saturating_sub(1))
            .map_err(|_| Error::Db("integer overflow converting start_char".to_string()))?;
        Ok(Some(
            content.chars().skip(start_idx).take(max_chars).collect(),
        ))
    }

    /// Reads an inclusive line range without forcing the caller to load the entire file.
    ///
    /// The returned `content` is present only when the selected slice fits within `max_bytes`.
    /// When the slice exceeds that budget, `bytes_read` still reports the exact size while
    /// `content` stays `None` so the caller can fail without materializing the oversized range.
    fn get_line_range(
        &mut self,
        workspace_id: &str,
        path: &str,
        version: u64,
        start_line: u64,
        end_line: u64,
        max_bytes: u64,
    ) -> Result<Option<LineRangeData>> {
        let chunk_chars = range_read_chunk_chars(max_bytes);
        let mut start_char = 1u64;
        let mut current_line = 1u64;
        let mut bytes_read = 0u64;
        let mut content = String::new();
        let mut saw_content = false;
        let mut line_buffer = String::new();
        let mut pending_cr = false;

        loop {
            let Some(chunk) =
                self.get_content_chunk(workspace_id, path, version, start_char, chunk_chars)?
            else {
                return Ok(None);
            };
            if chunk.is_empty() {
                if !line_buffer.is_empty() {
                    if current_line >= start_line && current_line <= end_line {
                        append_range_segment(
                            &mut content,
                            &mut bytes_read,
                            max_bytes,
                            &line_buffer,
                        );
                    }
                    let total_lines = current_line;
                    return Ok(Some(LineRangeData {
                        content: (bytes_read <= max_bytes).then_some(content),
                        bytes_read,
                        total_lines,
                    }));
                }
                let total_lines = if saw_content {
                    current_line.saturating_sub(1)
                } else {
                    0
                };
                return Ok(Some(LineRangeData {
                    content: (bytes_read <= max_bytes).then_some(content),
                    bytes_read,
                    total_lines,
                }));
            }

            saw_content = true;
            let chunk_char_count = u64::try_from(chunk.chars().count())
                .map_err(|_| Error::Db("integer overflow converting chunk size".to_string()))?;

            let bytes = chunk.as_bytes();
            let mut pos = 0usize;
            if pending_cr && bytes.first() == Some(&b'\n') {
                line_buffer.push('\n');
                if current_line >= start_line && current_line <= end_line {
                    append_range_segment(&mut content, &mut bytes_read, max_bytes, &line_buffer);
                }
                if current_line == end_line {
                    return Ok(Some(LineRangeData {
                        content: (bytes_read <= max_bytes).then_some(content),
                        bytes_read,
                        total_lines: end_line,
                    }));
                }
                line_buffer.clear();
                current_line = current_line.saturating_add(1);
                pos = 1;
            }
            pending_cr = false;

            while pos < chunk.len() {
                let Some(rel_break) = bytes[pos..]
                    .iter()
                    .position(|byte| matches!(byte, b'\n' | b'\r'))
                else {
                    line_buffer.push_str(&chunk[pos..]);
                    break;
                };
                let break_idx = pos + rel_break;

                if bytes[break_idx] == b'\r' && break_idx + 1 == chunk.len() {
                    line_buffer.push_str(&chunk[pos..]);
                    pending_cr = true;
                    break;
                }

                let mut end = break_idx + 1;
                if bytes[break_idx] == b'\r' && bytes.get(break_idx + 1) == Some(&b'\n') {
                    end += 1;
                }
                line_buffer.push_str(&chunk[pos..end]);
                if current_line >= start_line && current_line <= end_line {
                    append_range_segment(&mut content, &mut bytes_read, max_bytes, &line_buffer);
                }
                if current_line == end_line {
                    return Ok(Some(LineRangeData {
                        content: (bytes_read <= max_bytes).then_some(content),
                        bytes_read,
                        total_lines: end_line,
                    }));
                }
                line_buffer.clear();
                current_line = current_line.saturating_add(1);
                pos = end;
            }

            start_char = start_char.saturating_add(chunk_char_count);
        }
    }

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

    /// Cursor-based variant of [`Store::list_metas_by_prefix`].
    ///
    /// Production stores should override this instead of relying on the
    /// compatibility fallback below. The default implementation preserves
    /// correctness for legacy stores, but it may re-scan the prefix from the
    /// beginning multiple times and therefore does not preserve large-prefix
    /// performance or scan-budget predictability. When this slow path is used,
    /// `db-vfs` emits a one-time warning naming the store type so degraded scan
    /// behavior is visible instead of silent.
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
        warn_legacy_prefix_page_fallback::<Self>();
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

fn warn_legacy_prefix_page_fallback<S: ?Sized>() {
    if !LEGACY_PREFIX_PAGE_FALLBACK_WARNED.swap(true, Ordering::AcqRel) {
        #[cfg(test)]
        LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "Store::list_metas_by_prefix_page is using the legacy compatibility fallback for {}; implement cursor pagination to preserve scan-budget predictability",
            std::any::type_name::<S>()
        );
    }
}

#[cfg(test)]
fn reset_legacy_prefix_page_fallback_warning_for_test() {
    LEGACY_PREFIX_PAGE_FALLBACK_WARNED.store(false, Ordering::Release);
    LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.store(0, Ordering::Release);
}

#[cfg(test)]
fn legacy_prefix_page_fallback_warn_count_for_test() -> usize {
    LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.load(Ordering::Acquire)
}

fn range_read_chunk_chars(max_bytes: u64) -> usize {
    let budget_chars = usize::try_from(max_bytes.saturating_add(1)).unwrap_or(usize::MAX);
    budget_chars.clamp(DEFAULT_RANGE_READ_CHUNK_CHARS, MAX_RANGE_READ_CHUNK_CHARS)
}

fn append_range_segment(content: &mut String, bytes_read: &mut u64, max_bytes: u64, segment: &str) {
    let segment_bytes = u64::try_from(segment.len()).unwrap_or(u64::MAX);
    *bytes_read = bytes_read.saturating_add(segment_bytes);
    if *bytes_read <= max_bytes {
        content.push_str(segment);
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

fn monotonic_updated_at_ms(now_ms: u64, created_at_ms: u64, previous_updated_at_ms: u64) -> u64 {
    now_ms.max(created_at_ms).max(previous_updated_at_ms)
}

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::text_lines::LineSpan;

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
    fn monotonic_updated_at_clamps_clock_rollback() {
        assert_eq!(monotonic_updated_at_ms(50, 100, 120), 120);
        assert_eq!(monotonic_updated_at_ms(50, 100, 100), 100);
        assert_eq!(monotonic_updated_at_ms(150, 100, 120), 150);
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
        let _guard = LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy fallback test state");
        reset_legacy_prefix_page_fallback_warning_for_test();
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
        assert_eq!(legacy_prefix_page_fallback_warn_count_for_test(), 1);
    }

    #[test]
    fn default_page_impl_handles_unsorted_legacy_rows() {
        let _guard = LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy fallback test state");
        reset_legacy_prefix_page_fallback_warning_for_test();
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
        assert_eq!(legacy_prefix_page_fallback_warn_count_for_test(), 1);
    }

    #[test]
    fn default_page_impl_warns_only_once_for_repeated_legacy_fallbacks() {
        let _guard = LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy fallback test state");
        reset_legacy_prefix_page_fallback_warning_for_test();
        let mut store = PrefixOnlyStore {
            paths: vec![
                "docs/a.txt".to_string(),
                "docs/b.txt".to_string(),
                "docs/c.txt".to_string(),
            ],
        };

        store
            .list_metas_by_prefix_page("ws", "docs/", Some("docs/a.txt"), 2)
            .expect("first fallback page");
        store
            .list_metas_by_prefix_page("ws", "docs/", Some("docs/b.txt"), 1)
            .expect("second fallback page");

        assert_eq!(legacy_prefix_page_fallback_warn_count_for_test(), 1);
    }

    #[test]
    fn line_spans_count_cr_only_and_crlf_boundaries() {
        assert_eq!(
            line_spans("a\rb\r\nc")
                .map(|span| LineSpan {
                    content: span.content,
                    full: span.full,
                })
                .collect::<Vec<_>>(),
            vec![
                LineSpan {
                    content: "a",
                    full: "a\r",
                },
                LineSpan {
                    content: "b",
                    full: "b\r\n",
                },
                LineSpan {
                    content: "c",
                    full: "c",
                },
            ]
        );
    }

    struct ContentStore {
        content: String,
    }

    impl Store for ContentStore {
        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            Ok(Some(self.content.clone()))
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
            _prefix: &str,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            unimplemented!()
        }
    }

    #[test]
    fn default_line_range_supports_cr_only_and_crlf() {
        let mut store = ContentStore {
            content: "a\rb\r\nc".to_string(),
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 3, 32)
            .expect("line range")
            .expect("line range data");
        assert_eq!(
            range,
            LineRangeData {
                content: Some("b\r\nc".to_string()),
                bytes_read: 4,
                total_lines: 3,
            }
        );
    }
}
