use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::sync::atomic::Ordering;

use db_vfs_core::path::{normalize_path, validate_workspace_id};
use db_vfs_core::{Error, Result};

pub const MAX_STORE_VERSION: u64 = i64::MAX as u64;
const MAX_UTF8_CHAR_BYTES: usize = 4;
const MAX_RANGE_READ_CHUNK_CHARS: usize = 64 * 1024;

static LEGACY_PREFIX_PAGE_FALLBACK_WARNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
static LEGACY_RANGE_READ_FALLBACK_WARNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
#[cfg(test)]
static LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static LEGACY_RANGE_READ_FALLBACK_WARN_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static LEGACY_RANGE_READ_FALLBACK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub workspace_id: String,
    pub path: String,
    pub content: String,
    pub size_bytes: u64,
    pub version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl FileRecord {
    pub fn validated(self) -> Result<Self> {
        validate_stored_workspace_id(&self.workspace_id)?;
        validate_stored_path(&self.path)?;
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
        validate_stored_path(&self.path)?;
        if self.version == 0 {
            return Err(Error::Db("invalid file version: 0".to_string()));
        }
        Ok(self)
    }
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
pub(crate) fn normalize_store_workspace_id(workspace_id: &str) -> Result<String> {
    validate_workspace_id(workspace_id)?;
    Ok(workspace_id.to_string())
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
pub(crate) fn normalize_store_path(path: &str) -> Result<String> {
    normalize_path(path)
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
pub(crate) fn normalize_store_path_prefix(prefix: &str) -> Result<String> {
    db_vfs_core::path::normalize_path_prefix(prefix)
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
pub(crate) fn normalize_store_after_cursor(after: &str) -> Result<String> {
    normalize_path(after)
}

fn validate_stored_path(path: &str) -> Result<()> {
    let normalized = normalize_path(path)
        .map_err(|err| Error::Db(format!("invalid stored path invariant for {path:?}: {err}")))?;
    if normalized != path {
        return Err(Error::Db(format!(
            "invalid stored path invariant for {path:?}: expected canonical path {normalized:?}"
        )));
    }
    Ok(())
}

fn validate_stored_workspace_id(workspace_id: &str) -> Result<()> {
    validate_workspace_id(workspace_id).map_err(|err| {
        Error::Db(format!(
            "invalid stored workspace_id invariant for {workspace_id:?}: {err}"
        ))
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixPaginationMode {
    NativeCursorPagination,
    LegacyCompatibilityFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeReadMode {
    NativeChunkedReads,
    LegacyCompatibilityFallback,
}

#[derive(Debug, Clone)]
pub struct PrefixPage {
    pub metas: Vec<FileMeta>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LineSegment<'a> {
    pub text: &'a str,
    pub full: &'a str,
    pub terminated: bool,
}

fn next_line_segment_from(
    input: &str,
    start: usize,
    trailing_cr_is_terminator: bool,
) -> Option<(usize, LineSegment<'_>)> {
    if start >= input.len() {
        return None;
    }

    let bytes = input.as_bytes();
    let mut idx = start;
    while idx < bytes.len() {
        match bytes[idx] {
            b'\n' => {
                return Some((
                    idx + 1,
                    LineSegment {
                        text: &input[start..idx],
                        full: &input[start..idx + 1],
                        terminated: true,
                    },
                ));
            }
            b'\r' => {
                if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' {
                    return Some((
                        idx + 2,
                        LineSegment {
                            text: &input[start..idx],
                            full: &input[start..idx + 2],
                            terminated: true,
                        },
                    ));
                }
                if idx + 1 < bytes.len() || trailing_cr_is_terminator {
                    return Some((
                        idx + 1,
                        LineSegment {
                            text: &input[start..idx],
                            full: &input[start..idx + 1],
                            terminated: true,
                        },
                    ));
                }
                break;
            }
            _ => idx += 1,
        }
    }

    Some((
        input.len(),
        LineSegment {
            text: &input[start..],
            full: &input[start..],
            terminated: false,
        },
    ))
}

pub(crate) struct LineSegments<'a> {
    input: &'a str,
    pos: usize,
    trailing_cr_is_terminator: bool,
}

impl<'a> Iterator for LineSegments<'a> {
    type Item = LineSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (next_pos, segment) =
            next_line_segment_from(self.input, self.pos, self.trailing_cr_is_terminator)?;
        self.pos = next_pos;
        Some(segment)
    }
}

pub(crate) fn line_segments(input: &str) -> LineSegments<'_> {
    LineSegments {
        input,
        pos: 0,
        trailing_cr_is_terminator: true,
    }
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
    /// Every `Store` impl must explicitly declare whether ranged reads are backed by native
    /// chunked reads or by the legacy compatibility fallback. New backends should not silently
    /// compile through this default path without choosing a contract.
    fn range_read_mode(&self) -> RangeReadMode;

    /// Reads a character-bounded chunk of file content for ranged-read traversal.
    ///
    /// Production stores should override this to avoid materializing whole-file content for
    /// line-range reads. The default implementation preserves compatibility for legacy stores by
    /// falling back to [`Store::get_content`], and emits a one-time warning so this degraded
    /// compatibility path is visible instead of silent.
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
        if !matches!(
            self.range_read_mode(),
            RangeReadMode::LegacyCompatibilityFallback
        ) {
            return Err(Error::Db(format!(
                "Store::get_content_chunk is using the legacy compatibility fallback for {}; declare RangeReadMode::LegacyCompatibilityFallback or implement native chunked reads",
                std::any::type_name::<Self>()
            )));
        }

        warn_legacy_range_read_fallback::<Self>();
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
        if matches!(
            self.range_read_mode(),
            RangeReadMode::LegacyCompatibilityFallback
        ) {
            warn_legacy_range_read_fallback::<Self>();
            let Some(content) = self.get_content(workspace_id, path, version)? else {
                return Ok(None);
            };
            return Ok(Some(line_range_from_full_content(
                &content, start_line, end_line, max_bytes,
            )));
        }

        let chunk_chars = range_read_chunk_chars(max_bytes);
        let chunk_byte_budget = range_read_chunk_byte_budget(max_bytes);
        let mut start_char = 1u64;
        let mut current_line = 1u64;
        let mut bytes_read = 0u64;
        let mut content = String::new();
        let mut saw_content = false;
        let mut carry = String::new();
        let mut last_chunk_ended_with_newline = false;

        loop {
            let Some(chunk) =
                self.get_content_chunk(workspace_id, path, version, start_char, chunk_chars)?
            else {
                return Ok(None);
            };
            let (chunk, chunk_char_count) = trim_range_read_chunk(chunk, chunk_byte_budget)?;
            if chunk.is_empty() {
                let mut pos = 0usize;
                while let Some((next_pos, segment)) = next_line_segment_from(&carry, pos, true) {
                    if current_line >= start_line && current_line <= end_line {
                        append_range_segment(
                            &mut content,
                            &mut bytes_read,
                            max_bytes,
                            segment.full,
                        );
                    }
                    last_chunk_ended_with_newline = segment.terminated;
                    if current_line == end_line {
                        return Ok(Some(LineRangeData {
                            content: (bytes_read <= max_bytes).then_some(content),
                            bytes_read,
                            total_lines: end_line,
                        }));
                    }
                    if !segment.terminated {
                        break;
                    }
                    current_line = current_line.saturating_add(1);
                    pos = next_pos;
                }
                let total_lines = if !saw_content {
                    0
                } else if last_chunk_ended_with_newline {
                    current_line.saturating_sub(1)
                } else {
                    current_line
                };
                return Ok(Some(LineRangeData {
                    content: (bytes_read <= max_bytes).then_some(content),
                    bytes_read,
                    total_lines,
                }));
            }

            saw_content = true;
            carry.push_str(&chunk);

            let mut consumed = 0usize;
            let mut pos = 0usize;
            while let Some((next_pos, segment)) = next_line_segment_from(&carry, pos, false) {
                if !segment.terminated {
                    last_chunk_ended_with_newline = false;
                    break;
                }

                if current_line >= start_line && current_line <= end_line {
                    append_range_segment(&mut content, &mut bytes_read, max_bytes, segment.full);
                }
                last_chunk_ended_with_newline = true;
                if current_line == end_line {
                    return Ok(Some(LineRangeData {
                        content: (bytes_read <= max_bytes).then_some(content),
                        bytes_read,
                        total_lines: end_line,
                    }));
                }
                current_line = current_line.saturating_add(1);
                consumed = next_pos;
                pos = next_pos;
            }
            if consumed > 0 {
                carry.drain(..consumed);
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

    /// Declares whether [`Store::list_metas_by_prefix_page`] is a native cursor-paginated
    /// implementation or the legacy compatibility fallback.
    ///
    /// Native cursor pagination preserves the scan-budget and performance semantics expected by
    /// `glob` / `grep`. The legacy mode still preserves correctness, but it may re-scan a large
    /// prefix repeatedly and therefore should not be treated as operationally equivalent.
    fn prefix_pagination_mode(&self) -> PrefixPaginationMode;

    /// Cursor-based variant of [`Store::list_metas_by_prefix`].
    ///
    /// Production stores should override this instead of relying on the
    /// compatibility fallback below. The default implementation preserves
    /// correctness for legacy stores, but it may re-scan the prefix from the
    /// beginning multiple times and therefore does not preserve large-prefix
    /// performance or scan-budget predictability. When this slow path is used,
    /// `db-vfs` emits a one-time warning naming the store type so degraded scan
    /// behavior is visible instead of silent.
    ///
    /// Native implementations must preserve the cursor contract that `glob` /
    /// `grep` rely on:
    ///
    /// - rows within a page must be in strictly increasing lexical `path` order
    /// - when `after` is present, every returned row must satisfy `path > after`
    /// - callers may persist the last returned `path` as the next cursor, and
    ///   the following page must continue strictly after that path instead of
    ///   repeating or rewinding rows
    fn list_metas_by_prefix_page(
        &mut self,
        workspace_id: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<PrefixPage> {
        if limit == 0 {
            return Ok(PrefixPage {
                metas: Vec::new(),
                has_more: false,
            });
        }
        if !matches!(
            self.prefix_pagination_mode(),
            PrefixPaginationMode::LegacyCompatibilityFallback
        ) {
            return Err(Error::Db(format!(
                "Store::list_metas_by_prefix_page is using the legacy compatibility fallback for {}; declare PrefixPaginationMode::LegacyCompatibilityFallback or implement native cursor pagination",
                std::any::type_name::<Self>()
            )));
        }

        // Compatibility slow-path for legacy stores that only implement
        // `list_metas_by_prefix`. This may require repeated prefix scans.
        // Implement `list_metas_by_prefix_page` in concrete stores to avoid
        // this fallback and provide predictable large-prefix performance.
        warn_legacy_prefix_page_fallback::<Self>();
        let Some(after) = after else {
            let fetch_limit = limit.saturating_add(1);
            let mut rows = self.list_metas_by_prefix(workspace_id, prefix, fetch_limit)?;
            if rows.len() > 1 && rows.windows(2).any(|pair| pair[0].path > pair[1].path) {
                rows.sort_unstable_by(|a, b| a.path.cmp(&b.path));
            }
            let has_more = rows.len() > limit;
            if has_more {
                rows.truncate(limit);
            }
            return Ok(PrefixPage {
                metas: rows,
                has_more,
            });
        };
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
            let out_len = out.len();
            if out_len > limit {
                out.truncate(limit);
                return Ok(PrefixPage {
                    metas: out,
                    has_more: true,
                });
            }
            if out_len == limit {
                let has_more = rows_len >= fetch_limit;
                return Ok(PrefixPage {
                    metas: out,
                    has_more,
                });
            }
            if rows_len < fetch_limit {
                return Ok(PrefixPage {
                    metas: out,
                    has_more: false,
                });
            }

            let next = if split == rows_len {
                fetch_limit.saturating_mul(2)
            } else {
                let missing = limit.saturating_sub(out.len());
                fetch_limit.saturating_add(missing.max(fetch_limit / 2))
            };
            if next == fetch_limit {
                return Ok(PrefixPage {
                    metas: out,
                    has_more: rows_len >= fetch_limit,
                });
            }
            fetch_limit = next;
        }
    }
}

fn line_range_from_full_content(
    content_source: &str,
    start_line: u64,
    end_line: u64,
    max_bytes: u64,
) -> LineRangeData {
    let mut bytes_read = 0u64;
    let mut content = String::new();
    let mut total_lines = 0u64;

    for (idx, segment) in line_segments(content_source).enumerate() {
        let line_no = u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX);
        total_lines = line_no;
        if line_no >= start_line && line_no <= end_line {
            append_range_segment(&mut content, &mut bytes_read, max_bytes, segment.full);
        }
        if line_no == end_line {
            break;
        }
    }

    LineRangeData {
        content: (bytes_read <= max_bytes).then_some(content),
        bytes_read,
        total_lines,
    }
}

fn warn_legacy_prefix_page_fallback<S: ?Sized>() {
    if mark_warning_emitted_for_store_type::<S>(&LEGACY_PREFIX_PAGE_FALLBACK_WARNED) {
        #[cfg(test)]
        LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "Store::list_metas_by_prefix_page is using the legacy compatibility fallback for {}; implement cursor pagination to preserve scan-budget predictability",
            std::any::type_name::<S>()
        );
    }
}

fn warn_legacy_range_read_fallback<S: ?Sized>() {
    if mark_warning_emitted_for_store_type::<S>(&LEGACY_RANGE_READ_FALLBACK_WARNED) {
        #[cfg(test)]
        LEGACY_RANGE_READ_FALLBACK_WARN_COUNT.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "Store::get_content_chunk is using the legacy compatibility fallback for {}; ranged reads will materialize whole-file content via get_content; implement get_content_chunk or get_line_range to preserve line-range boundary and performance semantics",
            std::any::type_name::<S>()
        );
    }
}

fn mark_warning_emitted_for_store_type<S: ?Sized>(
    warned: &'static OnceLock<Mutex<HashSet<&'static str>>>,
) -> bool {
    let warned = warned.get_or_init(|| Mutex::new(HashSet::new()));
    match warned.lock() {
        Ok(mut warned) => warned.insert(std::any::type_name::<S>()),
        Err(err) => {
            log::warn!(
                "legacy store fallback warning registry lock poisoned; continuing without dedupe: {err}"
            );
            true
        }
    }
}

#[cfg(test)]
fn reset_legacy_prefix_page_fallback_warning_for_test() {
    if let Some(warned) = LEGACY_PREFIX_PAGE_FALLBACK_WARNED.get() {
        warned
            .lock()
            .expect("lock legacy prefix fallback warned set")
            .clear();
    }
    LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.store(0, Ordering::Release);
}

#[cfg(test)]
fn legacy_prefix_page_fallback_warn_count_for_test() -> usize {
    LEGACY_PREFIX_PAGE_FALLBACK_WARN_COUNT.load(Ordering::Acquire)
}

#[cfg(test)]
fn reset_legacy_range_read_fallback_warning_for_test() {
    if let Some(warned) = LEGACY_RANGE_READ_FALLBACK_WARNED.get() {
        warned
            .lock()
            .expect("lock legacy range fallback warned set")
            .clear();
    }
    LEGACY_RANGE_READ_FALLBACK_WARN_COUNT.store(0, Ordering::Release);
}

#[cfg(test)]
fn legacy_range_read_fallback_warn_count_for_test() -> usize {
    LEGACY_RANGE_READ_FALLBACK_WARN_COUNT.load(Ordering::Acquire)
}

fn range_read_chunk_chars(max_bytes: u64) -> usize {
    let budget_bytes = range_read_chunk_byte_budget(max_bytes);
    budget_bytes
        .saturating_add(MAX_UTF8_CHAR_BYTES - 1)
        .saturating_div(MAX_UTF8_CHAR_BYTES)
        .clamp(1, MAX_RANGE_READ_CHUNK_CHARS)
}

fn range_read_chunk_byte_budget(max_bytes: u64) -> usize {
    usize::try_from(max_bytes).unwrap_or(usize::MAX)
}

fn trim_range_read_chunk(chunk: String, byte_budget: usize) -> Result<(String, u64)> {
    if chunk.is_empty() {
        return Ok((chunk, 0));
    }

    let effective_budget = byte_budget.max(1);
    let mut end = 0usize;
    let mut chars = 0u64;
    for (idx, ch) in chunk.char_indices() {
        let next_end = idx.saturating_add(ch.len_utf8());
        if chars > 0 && next_end > effective_budget {
            break;
        }
        end = next_end;
        chars = chars.saturating_add(1);
        if next_end >= effective_budget {
            break;
        }
    }

    if end == chunk.len() {
        return Ok((chunk, chars));
    }

    Ok((chunk[..end].to_string(), chars))
}

fn append_range_segment(content: &mut String, bytes_read: &mut u64, max_bytes: u64, segment: &str) {
    let segment_bytes = u64::try_from(segment.len()).unwrap_or(u64::MAX);
    *bytes_read = bytes_read.saturating_add(segment_bytes);
    if *bytes_read <= max_bytes {
        content.push_str(segment);
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn db_err(err: impl std::fmt::Display) -> Error {
    Error::Db(err.to_string())
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
fn make_prefix_bounds(prefix: &str) -> (String, Option<String>) {
    (prefix.to_string(), prefix_successor(prefix))
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
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

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
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

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
fn next_version(expected_version: u64) -> Result<u64> {
    if expected_version >= MAX_STORE_VERSION {
        return Err(Error::Conflict("version overflow".to_string()));
    }
    Ok(expected_version + 1)
}

#[cfg(any(test, feature = "sqlite", feature = "postgres"))]
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
        }
        .validated()
        .expect_err("invalid timestamps");
        assert_eq!(err.code(), "db");
    }

    #[test]
    fn file_meta_rejects_noncanonical_path_and_zero_version() {
        let err = FileMeta {
            path: "../secret".to_string(),
            size_bytes: 1,
            version: 1,
            updated_at_ms: 1,
        }
        .validated()
        .expect_err("noncanonical path");
        assert_eq!(err.code(), "db");

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
    fn file_record_rejects_invalid_workspace_id() {
        let err = FileRecord {
            workspace_id: "bad ws".to_string(),
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            size_bytes: 5,
            version: 1,
            created_at_ms: 10,
            updated_at_ms: 10,
        }
        .validated()
        .expect_err("invalid workspace id");
        assert_eq!(err.code(), "db");
    }

    #[test]
    fn normalize_store_inputs_match_vfs_path_contract() {
        assert_eq!(normalize_store_workspace_id("ws").expect("workspace"), "ws");
        assert_eq!(
            normalize_store_path("./docs//a.txt").expect("path"),
            "docs/a.txt"
        );
        assert_eq!(
            normalize_store_path_prefix("./docs").expect("prefix"),
            "docs/"
        );
        assert_eq!(
            normalize_store_after_cursor("./docs//a.txt").expect("cursor"),
            "docs/a.txt"
        );

        let err = normalize_store_workspace_id("bad ws").expect_err("invalid workspace");
        assert_eq!(err.code(), "invalid_path");
        let err = normalize_store_path("../secret").expect_err("invalid path");
        assert_eq!(err.code(), "invalid_path");
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
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[derive(Default)]
    struct UnsortedPrefixStore {
        paths: Vec<String>,
    }

    impl Store for UnsortedPrefixStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
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
        let paths = page
            .metas
            .into_iter()
            .map(|meta| meta.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["docs/b.txt", "docs/c.txt"]);
        assert!(!page.has_more);
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
        let paths = page
            .metas
            .into_iter()
            .map(|meta| meta.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["docs/b.txt", "docs/c.txt"]);
        assert!(!page.has_more);
        assert_eq!(legacy_prefix_page_fallback_warn_count_for_test(), 1);
    }

    #[test]
    fn default_page_impl_sorts_unsorted_legacy_first_page() {
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
            .list_metas_by_prefix_page("ws", "docs/", None, 2)
            .expect("fallback should sort unsorted legacy first page");
        let paths = page
            .metas
            .into_iter()
            .map(|meta| meta.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["docs/a.txt", "docs/b.txt"]);
        assert!(page.has_more);
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
    fn default_page_impl_warns_once_per_store_type() {
        let _guard = LEGACY_PREFIX_PAGE_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy fallback test state");
        reset_legacy_prefix_page_fallback_warning_for_test();
        let mut prefix_only = PrefixOnlyStore {
            paths: vec!["docs/a.txt".to_string(), "docs/b.txt".to_string()],
        };
        let mut unsorted = UnsortedPrefixStore {
            paths: vec!["docs/b.txt".to_string(), "docs/a.txt".to_string()],
        };

        prefix_only
            .list_metas_by_prefix_page("ws", "docs/", None, 1)
            .expect("prefix-only fallback page");
        unsorted
            .list_metas_by_prefix_page("ws", "docs/", None, 1)
            .expect("unsorted fallback page");

        assert_eq!(legacy_prefix_page_fallback_warn_count_for_test(), 2);
    }

    #[test]
    fn default_prefix_pagination_mode_is_legacy_fallback() {
        let store = PrefixOnlyStore::default();
        assert_eq!(
            store.prefix_pagination_mode(),
            PrefixPaginationMode::LegacyCompatibilityFallback
        );
    }

    #[derive(Default)]
    struct MisdeclaredNativePrefixStore;

    impl Store for MisdeclaredNativePrefixStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

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
            _prefix: &str,
            _limit: usize,
        ) -> Result<Vec<FileMeta>> {
            unimplemented!()
        }

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::NativeCursorPagination
        }
    }

    #[test]
    fn default_page_impl_rejects_native_mode_without_override() {
        let mut store = MisdeclaredNativePrefixStore;
        let err = store
            .list_metas_by_prefix_page("ws", "docs/", None, 1)
            .expect_err("misdeclared native pagination should fail closed");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string()
                .contains("declare PrefixPaginationMode::LegacyCompatibilityFallback"),
            "unexpected error: {err}"
        );
    }

    #[derive(Default)]
    struct ContentOnlyStore {
        content: String,
        content_reads: usize,
    }

    impl Store for ContentOnlyStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::LegacyCompatibilityFallback
        }

        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            self.content_reads = self.content_reads.saturating_add(1);
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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn default_range_read_impl_warns_for_legacy_chunk_fallback() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ContentOnlyStore {
            content: "line1\nline2\n".to_string(),
            ..Default::default()
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 128)
            .expect("load line range")
            .expect("range data");
        assert_eq!(
            range,
            LineRangeData {
                content: Some("line2\n".to_string()),
                bytes_read: 6,
                total_lines: 2,
            }
        );
        assert_eq!(store.content_reads, 1);
        assert_eq!(legacy_range_read_fallback_warn_count_for_test(), 1);
    }

    #[test]
    fn default_range_read_impl_warns_only_once_for_repeated_legacy_fallbacks() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ContentOnlyStore {
            content: "line1\nline2\nline3\n".to_string(),
            ..Default::default()
        };

        store
            .get_line_range("ws", "docs/a.txt", 1, 1, 1, 128)
            .expect("first line range");
        store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 128)
            .expect("second line range");

        assert_eq!(legacy_range_read_fallback_warn_count_for_test(), 1);
    }

    #[derive(Default)]
    struct MisdeclaredNativeRangeStore {
        content: String,
    }

    impl Store for MisdeclaredNativeRangeStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::NativeChunkedReads
        }

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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn default_range_read_impl_rejects_native_mode_without_override() {
        let mut store = MisdeclaredNativeRangeStore {
            content: "line1\nline2\n".to_string(),
        };
        let err = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 128)
            .expect_err("misdeclared native range reads should fail closed");
        assert_eq!(err.code(), "db");
        assert!(
            err.to_string()
                .contains("declare RangeReadMode::LegacyCompatibilityFallback"),
            "unexpected error: {err}"
        );
    }

    struct ChunkOnlyStore {
        content: String,
        chunk_chars: usize,
        requested_max_chars: Vec<usize>,
    }

    impl Store for ChunkOnlyStore {
        fn range_read_mode(&self) -> RangeReadMode {
            RangeReadMode::NativeChunkedReads
        }

        fn get_meta(&mut self, _workspace_id: &str, _path: &str) -> Result<Option<FileMeta>> {
            unimplemented!()
        }

        fn get_content(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
        ) -> Result<Option<String>> {
            panic!("chunked range read should not fall back to get_content");
        }

        fn get_content_chunk(
            &mut self,
            _workspace_id: &str,
            _path: &str,
            _version: u64,
            start_char: u64,
            max_chars: usize,
        ) -> Result<Option<String>> {
            self.requested_max_chars.push(max_chars);
            let take = max_chars.min(self.chunk_chars);
            let start_idx = usize::try_from(start_char.saturating_sub(1))
                .map_err(|_| Error::Db("integer overflow converting start_char".to_string()))?;
            Ok(Some(
                self.content.chars().skip(start_idx).take(take).collect(),
            ))
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

        fn prefix_pagination_mode(&self) -> PrefixPaginationMode {
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    #[test]
    fn default_range_read_impl_treats_cr_only_as_line_break() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ContentOnlyStore {
            content: "line1\rline2\rline3".to_string(),
            ..Default::default()
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 128)
            .expect("load line range")
            .expect("range data");
        assert_eq!(
            range,
            LineRangeData {
                content: Some("line2\r".to_string()),
                bytes_read: 6,
                total_lines: 2,
            }
        );
    }

    #[test]
    fn default_range_read_impl_handles_mixed_line_endings() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ContentOnlyStore {
            content: "line1\rline2\nline3\r\nline4".to_string(),
            ..Default::default()
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 3, 128)
            .expect("load line range")
            .expect("range data");
        assert_eq!(
            range,
            LineRangeData {
                content: Some("line2\nline3\r\n".to_string()),
                bytes_read: 13,
                total_lines: 3,
            }
        );
    }

    #[test]
    fn default_range_read_impl_does_not_duplicate_unterminated_lines_across_chunks() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ChunkOnlyStore {
            content: "line1\r\nline2\r\n".to_string(),
            chunk_chars: 4,
            requested_max_chars: Vec::new(),
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 128)
            .expect("load line range")
            .expect("range data");
        assert_eq!(
            range,
            LineRangeData {
                content: Some("line2\r\n".to_string()),
                bytes_read: 7,
                total_lines: 2,
            }
        );
    }

    #[test]
    fn range_read_chunk_chars_scales_multibyte_budget_conservatively() {
        assert_eq!(range_read_chunk_chars(1), 1);
        assert_eq!(range_read_chunk_chars(4), 1);
        assert_eq!(range_read_chunk_chars(5), 2);
        assert_eq!(range_read_chunk_chars(8), 2);
    }

    #[test]
    fn trim_range_read_chunk_keeps_first_multibyte_scalar_for_tiny_budget() {
        let (chunk, chars) = trim_range_read_chunk("你好".to_string(), 1).expect("trim chunk");
        assert_eq!(chunk, "你");
        assert_eq!(chars, 1);
    }

    #[test]
    fn default_range_read_impl_bounds_multibyte_chunk_requests_by_byte_budget() {
        let _guard = LEGACY_RANGE_READ_FALLBACK_TEST_LOCK
            .lock()
            .expect("lock legacy range read fallback test state");
        reset_legacy_range_read_fallback_warning_for_test();
        let mut store = ChunkOnlyStore {
            content: "你你\n好好\n".to_string(),
            chunk_chars: usize::MAX,
            requested_max_chars: Vec::new(),
        };

        let range = store
            .get_line_range("ws", "docs/a.txt", 1, 2, 2, 12)
            .expect("load line range")
            .expect("range data");

        assert_eq!(
            range,
            LineRangeData {
                content: Some("好好\n".to_string()),
                bytes_read: 7,
                total_lines: 2,
            }
        );
        assert!(
            store
                .requested_max_chars
                .iter()
                .all(|&max_chars| max_chars <= 3),
            "expected conservative char requests, got {:?}",
            store.requested_max_chars
        );
    }

    #[test]
    fn line_segments_treat_cr_only_and_crlf_as_single_line_breaks() {
        let segments = line_segments("a\rb\r\nc\n")
            .map(|segment| (segment.text.to_string(), segment.full.to_string()))
            .collect::<Vec<_>>();

        assert_eq!(
            segments,
            vec![
                ("a".to_string(), "a\r".to_string()),
                ("b".to_string(), "b\r\n".to_string()),
                ("c".to_string(), "c\n".to_string()),
            ]
        );
    }
}
