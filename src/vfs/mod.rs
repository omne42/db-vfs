mod delete;
mod glob;
mod grep;
mod patch;
mod read;
mod util;
mod write;

use std::sync::Arc;
use std::time::{Duration, Instant};

use db_vfs_core::policy::ValidatedVfsPolicy;
use db_vfs_core::policy::VfsPolicy;
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;
use db_vfs_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::store::{FileMeta, Store};

pub use delete::{DeleteRequest, DeleteResponse};
pub use glob::{GlobRequest, GlobResponse};
pub use grep::{GrepMatch, GrepRequest, GrepResponse};
pub use patch::{PatchRequest, PatchResponse};
pub use read::{ReadRequest, ReadResponse};
pub use write::{WriteRequest, WriteResponse};

#[derive(Debug)]
pub struct DbVfs<S> {
    policy: Arc<ValidatedVfsPolicy>,
    redactor: Arc<SecretRedactor>,
    traversal: Arc<TraversalSkipper>,
    store: S,
}

impl<S: Store> DbVfs<S> {
    fn build_matchers(policy: &ValidatedVfsPolicy) -> Result<(SecretRedactor, TraversalSkipper)> {
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;
        let traversal = TraversalSkipper::from_rules(&policy.traversal)?;
        Ok((redactor, traversal))
    }

    fn matcher_mismatch_error(kind: &str) -> Error {
        Error::InvalidPolicy(format!(
            "provided {kind} does not match the supplied policy; build matchers from the same policy"
        ))
    }

    fn ensure_redactor_matches_policy(
        policy: &ValidatedVfsPolicy,
        redactor: &SecretRedactor,
    ) -> Result<()> {
        if redactor.is_compatible_with_rules(&policy.secrets) {
            Ok(())
        } else {
            Err(Self::matcher_mismatch_error("SecretRedactor"))
        }
    }

    fn ensure_traversal_matches_policy(
        policy: &ValidatedVfsPolicy,
        traversal: &TraversalSkipper,
    ) -> Result<()> {
        if traversal.is_compatible_with_rules(&policy.traversal) {
            Ok(())
        } else {
            Err(Self::matcher_mismatch_error("TraversalSkipper"))
        }
    }

    pub fn new(store: S, policy: VfsPolicy) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        let (redactor, traversal) = Self::build_matchers(&policy)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_validated(store: S, policy: ValidatedVfsPolicy) -> Result<Self> {
        let (redactor, traversal) = Self::build_matchers(&policy)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_with_redactor(
        store: S,
        policy: VfsPolicy,
        redactor: SecretRedactor,
    ) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        Self::ensure_redactor_matches_policy(&policy, &redactor)?;
        let traversal = TraversalSkipper::from_rules(&policy.traversal)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    pub fn new_with_matchers(
        store: S,
        policy: VfsPolicy,
        redactor: SecretRedactor,
        traversal: TraversalSkipper,
    ) -> Result<Self> {
        let policy = ValidatedVfsPolicy::new(policy)?;
        Self::ensure_redactor_matches_policy(&policy, &redactor)?;
        Self::ensure_traversal_matches_policy(&policy, &traversal)?;
        Ok(Self {
            policy: Arc::new(policy),
            redactor: Arc::new(redactor),
            traversal: Arc::new(traversal),
            store,
        })
    }

    /// Builds a VFS from a validated policy plus caller-supplied matchers.
    ///
    /// This is the strict constructor: mismatched matchers are rejected
    /// instead of being silently rebuilt from policy state.
    pub fn try_new_with_supplied_matchers_validated(
        store: S,
        policy: Arc<ValidatedVfsPolicy>,
        redactor: impl Into<Arc<SecretRedactor>>,
        traversal: impl Into<Arc<TraversalSkipper>>,
    ) -> Result<Self> {
        let redactor = redactor.into();
        let traversal = traversal.into();
        Self::ensure_redactor_matches_policy(policy.as_ref(), redactor.as_ref())?;
        Self::ensure_traversal_matches_policy(policy.as_ref(), traversal.as_ref())?;
        Ok(Self {
            policy,
            redactor,
            traversal,
            store,
        })
    }

    /// Deprecated compatibility alias.
    ///
    /// This remains a strict alias and will not silently rebuild mismatched
    /// matchers from policy state.
    #[deprecated(
        since = "1.0.0",
        note = "use DbVfs::try_new_with_supplied_matchers_validated() for strict caller-supplied matchers, or DbVfs::new_validated() for policy-derived matchers"
    )]
    pub fn try_new_with_matchers_validated(
        store: S,
        policy: Arc<ValidatedVfsPolicy>,
        redactor: impl Into<Arc<SecretRedactor>>,
        traversal: impl Into<Arc<TraversalSkipper>>,
    ) -> Result<Self> {
        Self::try_new_with_supplied_matchers_validated(store, policy, redactor, traversal)
    }

    /// Builds a VFS from a validated policy plus caller-supplied matchers.
    ///
    /// This constructor now rejects mismatched matchers instead of silently
    /// rebuilding them from policy state. Call [`DbVfs::new_validated`] when
    /// the caller wants policy-derived matchers and does not need to supply
    /// pre-built matcher instances.
    pub fn new_with_supplied_matchers_validated(
        store: S,
        policy: Arc<ValidatedVfsPolicy>,
        redactor: impl Into<Arc<SecretRedactor>>,
        traversal: impl Into<Arc<TraversalSkipper>>,
    ) -> Result<Self> {
        Self::try_new_with_supplied_matchers_validated(store, policy, redactor, traversal)
    }

    /// Deprecated compatibility alias.
    ///
    /// This remains a strict alias and will not silently rebuild mismatched
    /// matchers from policy state.
    #[deprecated(
        since = "1.0.0",
        note = "use DbVfs::new_with_supplied_matchers_validated() for strict caller-supplied matchers, or DbVfs::new_validated() for policy-derived matchers"
    )]
    pub fn new_with_matchers_validated(
        store: S,
        policy: Arc<ValidatedVfsPolicy>,
        redactor: impl Into<Arc<SecretRedactor>>,
        traversal: impl Into<Arc<TraversalSkipper>>,
    ) -> Result<Self> {
        Self::new_with_supplied_matchers_validated(store, policy, redactor, traversal)
    }

    pub fn policy(&self) -> &VfsPolicy {
        self.policy.as_ref()
    }

    /// Bypasses all VFS policy and path invariants to mutate the raw store directly.
    ///
    /// This exists only for tests and narrow integration glue that must seed or inspect
    /// backend state underneath the VFS contract.
    #[doc(hidden)]
    pub fn store_mut_unchecked(&mut self) -> &mut S {
        &mut self.store
    }

    #[doc(hidden)]
    /// Compatibility shim for existing tests/integration glue.
    ///
    /// This still bypasses all VFS invariants; prefer `store_mut_unchecked` for any new callsites
    /// so the escape hatch is explicit at the type boundary.
    pub fn store_mut(&mut self) -> &mut S {
        self.store_mut_unchecked()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    Entries,
    Files,
    Time,
    Results,
}

impl<S: Store> DbVfs<S> {
    pub fn read(&mut self, request: ReadRequest) -> Result<ReadResponse> {
        read::read(self, request)
    }

    pub fn write(&mut self, request: WriteRequest) -> Result<WriteResponse> {
        write::write(self, request)
    }

    pub fn apply_unified_patch(&mut self, request: PatchRequest) -> Result<PatchResponse> {
        patch::apply_unified_patch(self, request)
    }

    pub fn delete(&mut self, request: DeleteRequest) -> Result<DeleteResponse> {
        delete::delete(self, request)
    }

    pub fn glob(&mut self, request: GlobRequest) -> Result<GlobResponse> {
        glob::glob(self, request)
    }

    pub fn grep(&mut self, request: GrepRequest) -> Result<GrepResponse> {
        grep::grep(self, request)
    }
}

impl<S> DbVfs<S> {
    fn ensure_allowed(&self, ok: bool, op: &str) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err(Error::NotPermitted(format!("{op} is disabled by policy")))
        }
    }
}

pub(super) fn validate_expected_version(expected_version: u64) -> Result<()> {
    if expected_version == 0 {
        return Err(Error::Conflict("expected_version must be >= 1".to_string()));
    }
    if expected_version > i64::MAX as u64 {
        return Err(Error::Conflict(format!(
            "expected_version is too large (max {})",
            i64::MAX
        )));
    }
    Ok(())
}

pub(super) fn validate_optional_expected_version(expected_version: Option<u64>) -> Result<()> {
    if let Some(expected_version) = expected_version {
        validate_expected_version(expected_version)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum ScanTarget<'a> {
    Prefix(&'a str),
    ExactPath(&'a str),
}

pub(super) enum ScanControl {
    Continue,
    ContinueWithoutBudget,
    Stop(ScanLimitReason),
}

pub(super) const SCAN_META_PAGE_SIZE: usize = 2048;

pub(super) fn scan_page_budget(remaining_entries: usize) -> usize {
    remaining_entries.min(SCAN_META_PAGE_SIZE)
}

pub(super) struct ScanOutcome {
    pub limit_reason: Option<ScanLimitReason>,
    started: Instant,
}

impl ScanOutcome {
    pub fn elapsed_ms(&self) -> u64 {
        util::elapsed_ms(&self.started)
    }

    pub fn truncated(&self) -> bool {
        self.limit_reason.is_some()
    }
}

pub(super) fn scan_metas<S, F>(
    store: &mut S,
    workspace_id: &str,
    target: ScanTarget<'_>,
    max_scan_entries: usize,
    max_walk: Option<Duration>,
    op: &'static str,
    mut visit: F,
) -> Result<ScanOutcome>
where
    S: Store,
    F: FnMut(&mut S, FileMeta) -> Result<ScanControl>,
{
    let started = Instant::now();
    let mut budgeted_entries = 0usize;
    let mut after: Option<String> = None;
    let mut exact_path_fetched = false;

    loop {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            return Ok(ScanOutcome {
                limit_reason: Some(ScanLimitReason::Time),
                started,
            });
        }

        let remaining_entries = max_scan_entries.saturating_sub(budgeted_entries);
        if remaining_entries == 0 {
            return Ok(ScanOutcome {
                limit_reason: Some(ScanLimitReason::Entries),
                started,
            });
        }

        let page_budget = scan_page_budget(remaining_entries);
        let (mut metas, has_more) = match target {
            ScanTarget::Prefix(prefix) => {
                let page = store.list_metas_by_prefix_page(
                    workspace_id,
                    prefix,
                    after.as_deref(),
                    page_budget,
                )?;
                if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                    return Ok(ScanOutcome {
                        limit_reason: Some(ScanLimitReason::Time),
                        started,
                    });
                }
                validate_scan_page_order(&page.metas, after.as_deref(), op)?;
                (page.metas, page.has_more)
            }
            ScanTarget::ExactPath(path) => {
                if exact_path_fetched {
                    (Vec::new(), false)
                } else {
                    exact_path_fetched = true;
                    let meta = store.get_meta(workspace_id, path)?.into_iter().collect();
                    (meta, false)
                }
            }
        };
        validate_scan_target_page(&metas, target, op)?;

        if metas.is_empty() {
            return Ok(ScanOutcome {
                limit_reason: None,
                started,
            });
        }
        if has_more {
            advance_scan_after_cursor(&mut after, &metas, op)?;
        }

        for meta in metas.drain(..) {
            if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
                return Ok(ScanOutcome {
                    limit_reason: Some(ScanLimitReason::Time),
                    started,
                });
            }
            match visit(store, meta)? {
                ScanControl::Continue => {
                    budgeted_entries = budgeted_entries.saturating_add(1);
                }
                ScanControl::ContinueWithoutBudget => {}
                ScanControl::Stop(reason) => {
                    return Ok(ScanOutcome {
                        limit_reason: Some(reason),
                        started,
                    });
                }
            }
        }

        if !has_more {
            return Ok(ScanOutcome {
                limit_reason: None,
                started,
            });
        }
    }
}

pub(super) fn advance_scan_after_cursor(
    after: &mut Option<String>,
    metas: &[FileMeta],
    op: &'static str,
) -> Result<()> {
    let Some(next_after) = metas.last().map(|meta| meta.path.as_str()) else {
        return Ok(());
    };
    if let Some(prev_after) = after.as_ref()
        && next_after <= prev_after.as_str()
    {
        return Err(Error::Db(format!(
            "{op}: store returned non-monotonic pagination cursor (prev={prev_after:?}, next={next_after:?})"
        )));
    }
    if let Some(cursor) = after.as_mut() {
        cursor.clear();
        cursor.push_str(next_after);
    } else {
        *after = Some(next_after.to_string());
    }
    Ok(())
}

pub(super) fn validate_scan_page_order(
    metas: &[FileMeta],
    after: Option<&str>,
    op: &'static str,
) -> Result<()> {
    for pair in metas.windows(2) {
        if pair[0].path >= pair[1].path {
            return Err(Error::Db(format!(
                "{op}: store returned non-monotonic page ordering (prev={:?}, next={:?})",
                pair[0].path, pair[1].path
            )));
        }
    }

    let (Some(prev_after), Some(first)) = (after, metas.first()) else {
        return Ok(());
    };
    if first.path.as_str() <= prev_after {
        return Err(Error::Db(format!(
            "{op}: store returned rows not strictly after pagination cursor (after={prev_after:?}, first={:?})",
            first.path
        )));
    }

    Ok(())
}

fn validate_scan_target_page(
    metas: &[FileMeta],
    target: ScanTarget<'_>,
    op: &'static str,
) -> Result<()> {
    for meta in metas {
        match target {
            ScanTarget::Prefix(prefix) => {
                if !prefix.is_empty() && !meta.path.starts_with(prefix) {
                    return Err(Error::Db(format!(
                        "{op}: store returned path {:?} outside requested prefix {:?}",
                        meta.path, prefix
                    )));
                }
            }
            ScanTarget::ExactPath(path) => {
                if meta.path != path {
                    return Err(Error::Db(format!(
                        "{op}: store returned path {:?} for exact target {:?}",
                        meta.path, path
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::{
        DeleteOutcome, FileMeta, PrefixPage, PrefixPaginationMode, RangeReadMode, Store,
    };

    #[derive(Debug)]
    struct DummyStore;

    impl Store for DummyStore {
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
            PrefixPaginationMode::LegacyCompatibilityFallback
        }
    }

    fn validated_policy() -> Arc<ValidatedVfsPolicy> {
        Arc::new(ValidatedVfsPolicy::new(VfsPolicy::default()).expect("validated policy"))
    }

    #[test]
    fn validate_scan_target_page_rejects_prefix_escape() {
        let err = validate_scan_target_page(
            &[FileMeta {
                path: "secret/.env".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            }],
            ScanTarget::Prefix("docs/"),
            "glob",
        )
        .expect_err("path outside requested prefix should fail closed");
        assert_eq!(err.code(), "db");
        assert!(err.to_string().contains("outside requested prefix"));
    }

    #[test]
    fn validate_scan_target_page_rejects_exact_path_mismatch() {
        let err = validate_scan_target_page(
            &[FileMeta {
                path: "docs/other.txt".to_string(),
                size_bytes: 1,
                version: 1,
                updated_at_ms: 0,
            }],
            ScanTarget::ExactPath("docs/a.txt"),
            "grep",
        )
        .expect_err("wrong exact path should fail closed");
        assert_eq!(err.code(), "db");
        assert!(err.to_string().contains("exact target"));
    }

    #[test]
    fn validate_scan_target_page_allows_matching_prefix_rows() {
        validate_scan_target_page(
            &[
                FileMeta {
                    path: "docs/a.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
                FileMeta {
                    path: "docs/nested/b.txt".to_string(),
                    size_bytes: 1,
                    version: 1,
                    updated_at_ms: 0,
                },
            ],
            ScanTarget::Prefix("docs/"),
            "glob",
        )
        .expect("matching prefix rows should pass");
    }

    #[test]
    fn strict_validated_constructor_rejects_mismatched_matchers() {
        let policy = validated_policy();
        let mismatched = SecretRedactor::from_rules(&db_vfs_core::policy::SecretRules {
            replacement: "DIFFERENT".to_string(),
            ..policy.secrets.clone()
        })
        .expect("mismatched redactor");
        let traversal = TraversalSkipper::from_rules(&policy.traversal).expect("policy traversal");

        let err = DbVfs::try_new_with_supplied_matchers_validated(
            DummyStore, policy, mismatched, traversal,
        )
        .expect_err("mismatch should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validated_constructor_rejects_mismatched_matchers() {
        let policy = validated_policy();
        let mismatched = SecretRedactor::from_rules(&db_vfs_core::policy::SecretRules {
            replacement: "DIFFERENT".to_string(),
            ..policy.secrets.clone()
        })
        .expect("mismatched redactor");
        let traversal = TraversalSkipper::from_rules(&policy.traversal).expect("policy traversal");

        let err =
            DbVfs::new_with_supplied_matchers_validated(DummyStore, policy, mismatched, traversal)
                .expect_err("mismatch should fail");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    fn validated_constructor_accepts_aligned_matchers() {
        let policy = validated_policy();
        let redactor = SecretRedactor::from_rules(&policy.secrets).expect("matching redactor");
        let traversal =
            TraversalSkipper::from_rules(&policy.traversal).expect("matching traversal");

        let vfs = DbVfs::new_with_supplied_matchers_validated(
            DummyStore,
            policy.clone(),
            redactor,
            traversal,
        )
        .expect("matching matchers should succeed");
        assert!(vfs.redactor.is_compatible_with_rules(&policy.secrets));
        assert!(vfs.traversal.is_compatible_with_rules(&policy.traversal));
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_validated_constructor_alias_rejects_mismatched_matchers() {
        let policy = validated_policy();
        let mismatched = SecretRedactor::from_rules(&db_vfs_core::policy::SecretRules {
            replacement: "DIFFERENT".to_string(),
            ..policy.secrets.clone()
        })
        .expect("mismatched redactor");
        let traversal = TraversalSkipper::from_rules(&policy.traversal).expect("policy traversal");

        let err = DbVfs::new_with_matchers_validated(DummyStore, policy, mismatched, traversal)
            .expect_err("deprecated alias should keep rejecting mismatched matchers");
        assert_eq!(err.code(), "invalid_policy");
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_validated_constructor_alias_still_accepts_aligned_matchers() {
        let policy = validated_policy();
        let redactor = SecretRedactor::from_rules(&policy.secrets).expect("matching redactor");
        let traversal =
            TraversalSkipper::from_rules(&policy.traversal).expect("matching traversal");

        let vfs =
            DbVfs::new_with_matchers_validated(DummyStore, policy.clone(), redactor, traversal)
                .expect("deprecated alias should stay compatible");
        assert!(vfs.redactor.is_compatible_with_rules(&policy.secrets));
        assert!(vfs.traversal.is_compatible_with_rules(&policy.traversal));
    }

    #[test]
    fn validated_policy_rejects_unbuildable_matchers() {
        let mut raw_policy = VfsPolicy::default();
        raw_policy.secrets.redact_regexes = vec!["(".to_string()];
        let err = ValidatedVfsPolicy::new(raw_policy).expect_err("policy should be rejected");
        assert_eq!(err.code(), "invalid_policy");
    }

    fn meta(path: &str) -> FileMeta {
        FileMeta {
            path: path.to_string(),
            size_bytes: 1,
            version: 1,
            updated_at_ms: 0,
        }
    }

    #[test]
    fn validate_scan_page_order_accepts_strictly_increasing_page() {
        validate_scan_page_order(
            &[meta("docs/a.txt"), meta("docs/b.txt")],
            Some("docs/0"),
            "op",
        )
        .expect("strictly increasing page should pass");
    }

    #[test]
    fn validate_scan_page_order_rejects_non_monotonic_rows() {
        let err = validate_scan_page_order(
            &[meta("docs/a.txt"), meta("docs/c.txt"), meta("docs/b.txt")],
            None,
            "glob",
        )
        .expect_err("non-monotonic page ordering should fail");
        assert!(
            err.to_string().contains("non-monotonic page ordering"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_scan_page_order_rejects_rows_at_or_before_cursor() {
        let err = validate_scan_page_order(&[meta("docs/a.txt")], Some("docs/a.txt"), "grep")
            .expect_err("rows at or before previous cursor should fail");
        assert!(
            err.to_string()
                .contains("not strictly after pagination cursor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn advance_scan_after_cursor_updates_and_rejects_non_monotonic_cursor() {
        let mut after = Some("docs/b.txt".to_string());
        let err = advance_scan_after_cursor(&mut after, &[meta("docs/a.txt")], "glob")
            .expect_err("cursor rewind should fail");
        assert!(
            err.to_string().contains("non-monotonic pagination cursor"),
            "unexpected error: {err}"
        );

        advance_scan_after_cursor(&mut after, &[meta("docs/c.txt")], "glob")
            .expect("cursor should advance");
        assert_eq!(after.as_deref(), Some("docs/c.txt"));
    }

    #[test]
    fn scan_page_budget_caps_large_remaining_budgets() {
        assert_eq!(
            scan_page_budget(SCAN_META_PAGE_SIZE.saturating_add(17)),
            SCAN_META_PAGE_SIZE
        );
    }

    #[test]
    fn scan_page_budget_preserves_smaller_remaining_budgets() {
        assert_eq!(scan_page_budget(7), 7);
    }

    struct ScanPageStore {
        rows: Vec<FileMeta>,
    }

    impl Store for ScanPageStore {
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

        fn list_metas_by_prefix_page(
            &mut self,
            _workspace_id: &str,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> Result<PrefixPage> {
            let mut rows = self
                .rows
                .iter()
                .filter(|meta| meta.path.starts_with(prefix))
                .filter(|meta| after.is_none_or(|cursor| meta.path.as_str() > cursor))
                .take(limit.saturating_add(1))
                .cloned()
                .collect::<Vec<_>>();
            let has_more = rows.len() > limit;
            if has_more {
                rows.truncate(limit);
            }
            Ok(PrefixPage {
                metas: rows,
                has_more,
            })
        }
    }

    #[test]
    fn scan_metas_keeps_hidden_rows_out_of_entry_budget() {
        let mut store = ScanPageStore {
            rows: vec![
                meta("docs/hidden-1"),
                meta("docs/visible"),
                meta("docs/visible-2"),
            ],
        };
        let mut visible = Vec::new();

        let outcome = scan_metas(
            &mut store,
            "ws",
            ScanTarget::Prefix("docs/"),
            1,
            None,
            "glob",
            |_store, meta| {
                if meta.path.contains("hidden") {
                    return Ok(ScanControl::ContinueWithoutBudget);
                }
                visible.push(meta.path);
                Ok(ScanControl::Continue)
            },
        )
        .expect("scan should succeed");

        assert_eq!(visible, vec!["docs/visible"]);
        assert_eq!(outcome.limit_reason, Some(ScanLimitReason::Entries));
    }
}
