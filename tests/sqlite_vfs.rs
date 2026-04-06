#![cfg(feature = "sqlite")]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use db_vfs::store::sqlite::SqliteStore;
use db_vfs::store::{DeleteOutcome, Store};
use db_vfs::vfs::{
    DbVfs, DeleteRequest, GlobRequest, GrepRequest, PatchRequest, ReadRequest, WriteRequest,
};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, Limits, Permissions, SecretRules, TraversalRules, ValidatedVfsPolicy,
    VfsPolicy,
};
use db_vfs_core::redaction::SecretRedactor;
use db_vfs_core::traversal::TraversalSkipper;
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn open_vfs(policy: VfsPolicy) -> DbVfs<SqliteStore> {
    let store = SqliteStore::open_in_memory().expect("open sqlite");
    DbVfs::new(store, policy).expect("create vfs")
}

fn policy_all_perms() -> VfsPolicy {
    VfsPolicy {
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            write: true,
            patch: true,
            delete: true,
            allow_full_scan: false,
        },
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        audit: AuditPolicy::default(),
        auth: AuthPolicy::default(),
    }
}

#[test]
fn responses_echo_requested_path() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let write = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "./docs//a.txt".to_string(),
            content: "hello\n".to_string(),
            expected_version: None,
        })
        .expect("write");
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.requested_path, "docs/a.txt");

    let read = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "./docs//a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .expect("read");
    assert_eq!(read.path, "docs/a.txt");
    assert_eq!(read.requested_path, "docs/a.txt");

    let patched = vfs
        .apply_unified_patch(PatchRequest {
            workspace_id: "ws".to_string(),
            path: "./docs//a.txt".to_string(),
            expected_version: 1,
            patch: concat!(
                "--- a/docs/a.txt\n",
                "+++ b/docs/a.txt\n",
                "@@ -1 +1 @@\n",
                "-hello\n",
                "+HELLO\n",
            )
            .to_string(),
        })
        .expect("patch");
    assert_eq!(patched.path, "docs/a.txt");
    assert_eq!(patched.requested_path, "docs/a.txt");
}

#[test]
fn write_read_patch_delete_roundtrip() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let write = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "hello\nworld\n".to_string(),
            expected_version: None,
        })
        .expect("write");
    assert_eq!(write.requested_path, "docs/a.txt");
    assert_eq!(write.path, "docs/a.txt");
    assert_eq!(write.version, 1);
    assert!(write.created);

    let read = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .expect("read");
    assert_eq!(read.requested_path, "docs/a.txt");
    assert_eq!(read.version, 1);
    assert_eq!(read.content, "hello\nworld\n");

    let patched = vfs
        .apply_unified_patch(PatchRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            expected_version: 1,
            patch: concat!(
                "--- a/docs/a.txt\n",
                "+++ b/docs/a.txt\n",
                "@@ -1,2 +1,2 @@\n",
                "-hello\n",
                "+hi\n",
                " world\n",
            )
            .to_string(),
        })
        .expect("patch");
    assert_eq!(patched.requested_path, "docs/a.txt");
    assert_eq!(patched.version, 2);

    let read2 = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .expect("read");
    assert_eq!(read2.requested_path, "docs/a.txt");
    assert_eq!(read2.version, 2);
    assert!(read2.content.starts_with("hi\n"));

    let err = vfs
        .apply_unified_patch(PatchRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            expected_version: 1,
            patch: "".to_string(),
        })
        .expect_err("should conflict");
    assert_eq!(err.code(), "conflict");

    let deleted = vfs
        .delete(DeleteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            expected_version: Some(2),
            ignore_missing: false,
        })
        .expect("delete");
    assert_eq!(deleted.requested_path, "docs/a.txt");
    assert!(deleted.deleted);

    let err = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .expect_err("missing");
    assert_eq!(err.code(), "not_found");
}

#[test]
fn write_rejects_expected_version_overflow() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let too_large = i64::MAX as u64 + 1;
    let err = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "hello".to_string(),
            expected_version: Some(too_large),
        })
        .expect_err("should reject expected_version overflow");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn delete_ignore_missing_returns_deleted_false() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let deleted = vfs
        .delete(DeleteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/missing.txt".to_string(),
            expected_version: None,
            ignore_missing: true,
        })
        .expect("ignore_missing should succeed");
    assert_eq!(deleted.requested_path, "docs/missing.txt");
    assert_eq!(deleted.path, "docs/missing.txt");
    assert!(!deleted.deleted);
}

#[test]
fn glob_scan_diagnostics_exclude_secret_denied_entries() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);
    let now = now_ms();

    vfs.store_mut()
        .insert_file_new("ws", "docs/a.txt", "hello\n", now)
        .expect("seed visible path");
    vfs.store_mut()
        .insert_file_new("ws", "docs/.env", "SECRET=1\n", now)
        .expect("seed denied path");

    let resp = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "docs/**".to_string(),
            path_prefix: Some("docs/".to_string()),
        })
        .expect("glob");

    assert_eq!(resp.matches, vec!["docs/a.txt".to_string()]);
    assert_eq!(resp.scanned_entries, 1);

    let json = serde_json::to_value(&resp).expect("serialize glob response");
    assert!(json.get("skipped_secret_denied").is_none());
}

#[test]
fn grep_scan_diagnostics_exclude_secret_denied_entries() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);
    let now = now_ms();

    vfs.store_mut()
        .insert_file_new("ws", "docs/a.txt", "needle\n", now)
        .expect("seed visible path");
    vfs.store_mut()
        .insert_file_new("ws", "docs/.env", "needle\n", now)
        .expect("seed denied path");

    let resp = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
            path_prefix: Some("docs/".to_string()),
        })
        .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, "docs/a.txt");
    assert_eq!(resp.scanned_entries, 1);

    let json = serde_json::to_value(&resp).expect("serialize grep response");
    assert!(json.get("skipped_secret_denied").is_none());
}

#[test]
fn delete_rejects_expected_version_overflow() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let too_large = i64::MAX as u64 + 1;
    let err = vfs
        .delete(DeleteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            expected_version: Some(too_large),
            ignore_missing: true,
        })
        .expect_err("should reject expected_version overflow");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn store_delete_with_expected_version_distinguishes_conflict_and_not_found() {
    let mut store = SqliteStore::open_in_memory().expect("open sqlite");
    let now = now_ms();

    let version = store
        .insert_file_new("ws", "docs/a.txt", "hello\n", now)
        .expect("seed write");
    assert_eq!(version, 1);

    let err = store
        .delete_file("ws", "docs/a.txt", Some(version + 1))
        .expect_err("mismatched version should conflict");
    assert_eq!(err.code(), "conflict");
    assert!(
        store
            .get_meta("ws", "docs/a.txt")
            .expect("read meta")
            .is_some(),
        "row should remain after conflict"
    );

    let deleted = store
        .delete_file("ws", "docs/a.txt", Some(version))
        .expect("delete matching version");
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let missing = store
        .delete_file("ws", "docs/a.txt", Some(version))
        .expect("repeat delete should report missing");
    assert_eq!(missing, DeleteOutcome::NotFound);
}

#[test]
fn store_versions_remain_monotonic_across_delete_and_recreate() {
    let mut store = SqliteStore::open_in_memory().expect("open sqlite");
    let now = now_ms();

    let first = store
        .insert_file_new("ws", "docs/a.txt", "v1\n", now)
        .expect("insert initial version");
    assert_eq!(first, 1);

    let deleted = store
        .delete_file("ws", "docs/a.txt", Some(first))
        .expect("delete initial version");
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let recreated = store
        .insert_file_new("ws", "docs/a.txt", "v2\n", now.saturating_add(1))
        .expect("recreate file");
    assert_eq!(recreated, 2);

    let err = store
        .update_file_cas("ws", "docs/a.txt", "stale\n", first, now.saturating_add(2))
        .expect_err("stale CAS should not update recreated file");
    assert_eq!(err.code(), "conflict");

    let err = store
        .delete_file("ws", "docs/a.txt", Some(first))
        .expect_err("stale delete should not delete recreated file");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn store_update_distinguishes_conflict_and_not_found() {
    let mut store = SqliteStore::open_in_memory().expect("open sqlite");
    let now = now_ms();

    let version = store
        .insert_file_new("ws", "docs/a.txt", "v1\n", now)
        .expect("insert initial version");
    assert_eq!(version, 1);

    let err = store
        .update_file_cas(
            "ws",
            "docs/a.txt",
            "stale\n",
            version + 1,
            now.saturating_add(1),
        )
        .expect_err("mismatched version should conflict");
    assert_eq!(err.code(), "conflict");

    let deleted = store
        .delete_file("ws", "docs/a.txt", Some(version))
        .expect("delete matching version");
    assert_eq!(deleted, DeleteOutcome::Deleted);

    let err = store
        .update_file_cas(
            "ws",
            "docs/a.txt",
            "missing\n",
            version,
            now.saturating_add(2),
        )
        .expect_err("missing row should report not_found");
    assert_eq!(err.code(), "not_found");
}

#[test]
fn store_update_keeps_updated_at_monotonic_when_clock_moves_backwards() {
    let mut store = SqliteStore::open_in_memory().expect("open sqlite");

    let first = store
        .insert_file_new("ws", "docs/a.txt", "v1\n", 100)
        .expect("insert initial version");
    assert_eq!(first, 1);

    let second = store
        .update_file_cas("ws", "docs/a.txt", "v2\n", first, 50)
        .expect("update should clamp timestamp");
    assert_eq!(second, 2);

    let meta = store
        .get_meta("ws", "docs/a.txt")
        .expect("read meta")
        .expect("meta exists");
    assert_eq!(meta.version, 2);
    assert_eq!(meta.updated_at_ms, 100);
}

#[test]
fn vfs_write_rejects_stale_expected_version_after_delete_and_recreate() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    let first = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "v1\n".to_string(),
            expected_version: None,
        })
        .expect("write initial version");
    assert_eq!(first.version, 1);

    vfs.delete(DeleteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        expected_version: Some(first.version),
        ignore_missing: false,
    })
    .expect("delete initial version");

    let recreated = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "v2\n".to_string(),
            expected_version: None,
        })
        .expect("recreate version");
    assert_eq!(recreated.version, 2);

    let err = vfs
        .write(WriteRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            content: "stale\n".to_string(),
            expected_version: Some(first.version),
        })
        .expect_err("stale expected_version should conflict");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn patch_rejects_expected_version_overflow() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "hello\n".to_string(),
        expected_version: None,
    })
    .expect("seed write");

    let too_large = i64::MAX as u64 + 1;
    let err = vfs
        .apply_unified_patch(PatchRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            patch: "".to_string(),
            expected_version: too_large,
        })
        .expect_err("should reject expected_version overflow");
    assert_eq!(err.code(), "conflict");
}

#[test]
fn patch_is_disabled_when_secret_redaction_rules_are_active() {
    let mut policy = policy_all_perms();
    policy.secrets.redact_regexes = vec!["secret".to_string()];
    policy.secrets.replacement = "REDACTED".to_string();
    let mut vfs = open_vfs(policy);

    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "secret\npublic\n".to_string(),
        expected_version: None,
    })
    .expect("seed write");

    let patch = diffy::create_patch("secret\npublic\n", "secret\nvisible\n").to_string();
    let err = vfs
        .apply_unified_patch(PatchRequest {
            workspace_id: "ws".to_string(),
            path: "docs/a.txt".to_string(),
            patch,
            expected_version: 1,
        })
        .expect_err("redaction-enabled patch should be rejected");
    assert_eq!(err.code(), "not_permitted");
    assert!(
        err.to_string()
            .contains("patch is not supported when secret redaction rules are active"),
        "unexpected error: {err}"
    );
}

#[test]
fn glob_requires_scope_for_broad_patterns() {
    let policy = policy_all_perms();
    let mut vfs = open_vfs(policy);

    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.md".to_string(),
        content: "x".to_string(),
        expected_version: None,
    })
    .unwrap();

    let ok = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "docs/*.md".to_string(),
            path_prefix: None,
        })
        .unwrap();
    assert_eq!(ok.matches, vec!["docs/a.md".to_string()]);

    let err = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "**/*.md".to_string(),
            path_prefix: None,
        })
        .expect_err("should require explicit scope");
    assert_eq!(err.code(), "not_permitted");

    let ok2 = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "**/*.md".to_string(),
            path_prefix: Some("docs/".to_string()),
        })
        .unwrap();
    assert_eq!(ok2.matches, vec!["docs/a.md".to_string()]);
}

#[test]
fn grep_requires_explicit_path_prefix() {
    let mut policy = policy_all_perms();
    policy.limits.max_results = 1;
    let mut vfs = open_vfs(policy);

    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "docs/a.txt".to_string(),
        content: "one\ntwo\n".to_string(),
        expected_version: None,
    })
    .unwrap();

    let err = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "one".to_string(),
            regex: false,
            glob: None,
            path_prefix: None,
        })
        .expect_err("should require path_prefix");
    assert_eq!(err.code(), "not_permitted");

    let ok = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "o".to_string(),
            regex: false,
            glob: None,
            path_prefix: Some("docs/".to_string()),
        })
        .unwrap();
    assert!(ok.truncated);
    assert_eq!(
        ok.scan_limit_reason,
        Some(db_vfs::vfs::ScanLimitReason::Results)
    );
    assert_eq!(ok.matches.len(), 1);
    assert_eq!(ok.matches[0].path, "docs/a.txt");
}

#[test]
fn glob_keeps_scanning_when_denied_entries_precede_visible_files() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store
        .insert_file_new("ws", "a/secret.txt", "hidden", now_ms())
        .unwrap();
    store
        .insert_file_new("ws", "b/visible.txt", "visible", now_ms())
        .unwrap();

    let mut policy = policy_all_perms();
    policy.permissions.allow_full_scan = true;
    policy.limits.max_walk_entries = 8;
    policy.limits.max_walk_files = 1;
    policy.secrets.deny_globs = vec!["a/*".to_string()];
    let mut vfs = DbVfs::new(store, policy).unwrap();

    let resp = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "**/*.txt".to_string(),
            path_prefix: Some("".to_string()),
        })
        .unwrap();
    assert_eq!(resp.matches, vec!["b/visible.txt".to_string()]);
}

#[test]
fn grep_keeps_scanning_when_denied_entries_precede_visible_files() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store
        .insert_file_new("ws", "a/secret.txt", "needle", now_ms())
        .unwrap();
    store
        .insert_file_new("ws", "b/visible.txt", "needle", now_ms())
        .unwrap();

    let mut policy = policy_all_perms();
    policy.permissions.allow_full_scan = true;
    policy.limits.max_walk_entries = 8;
    policy.limits.max_walk_files = 1;
    policy.secrets.deny_globs = vec!["a/*".to_string()];
    let mut vfs = DbVfs::new(store, policy).unwrap();

    let resp = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("**/*.txt".to_string()),
            path_prefix: Some("".to_string()),
        })
        .unwrap();
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, "b/visible.txt");
}

#[test]
fn grep_matches_against_redacted_view_instead_of_hidden_secret_text() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store
        .insert_file_new("ws", "docs/a.txt", "secret\npublic\n", now_ms())
        .unwrap();

    let mut policy = policy_all_perms();
    policy.permissions.allow_full_scan = true;
    policy.secrets.redact_regexes = vec!["secret".to_string()];
    policy.secrets.replacement = "REDACTED".to_string();
    let mut vfs = DbVfs::new(store, policy).unwrap();

    let hidden = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "secret".to_string(),
            regex: false,
            glob: None,
            path_prefix: Some("docs/".to_string()),
        })
        .unwrap();
    assert!(hidden.matches.is_empty());

    let visible = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "REDACTED".to_string(),
            regex: false,
            glob: None,
            path_prefix: Some("docs/".to_string()),
        })
        .unwrap();
    assert_eq!(visible.matches.len(), 1);
    assert_eq!(visible.matches[0].path, "docs/a.txt");
    assert_eq!(visible.matches[0].text, "REDACTED");
}

#[test]
fn deny_globs_hide_descendants_under_dir_star() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store
        .insert_file_new("ws", "dir/a/b.txt", "secret", now_ms())
        .unwrap();

    let policy = VfsPolicy {
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            write: true,
            patch: true,
            delete: true,
            allow_full_scan: true,
        },
        limits: Limits::default(),
        secrets: SecretRules {
            deny_globs: vec!["dir/*".to_string()],
            ..SecretRules::default()
        },
        traversal: TraversalRules::default(),
        audit: AuditPolicy::default(),
        auth: AuthPolicy::default(),
    };

    let mut vfs = DbVfs::new(store, policy).unwrap();
    let err = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "dir/a/b.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .expect_err("denied");
    assert_eq!(err.code(), "secret_path_denied");

    let listed = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "**/*.txt".to_string(),
            path_prefix: Some("".to_string()),
        })
        .unwrap();
    assert!(listed.matches.is_empty());
    assert_eq!(listed.scanned_files, 0);
    assert_eq!(listed.scanned_entries, 0);
}

#[test]
fn traversal_skip_globs_do_not_affect_direct_read() {
    let mut policy = policy_all_perms();
    policy.permissions.allow_full_scan = true;
    policy.traversal.skip_globs = vec!["node_modules/*".to_string()];
    let mut vfs = open_vfs(policy);

    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "keep.txt".to_string(),
        content: "keep\n".to_string(),
        expected_version: None,
    })
    .unwrap();
    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "node_modules/skip.txt".to_string(),
        content: "skip\n".to_string(),
        expected_version: None,
    })
    .unwrap();
    vfs.write(WriteRequest {
        workspace_id: "ws".to_string(),
        path: "node_modules/sub/keep2.txt".to_string(),
        content: "keep\n".to_string(),
        expected_version: None,
    })
    .unwrap();

    let globbed = vfs
        .glob(GlobRequest {
            workspace_id: "ws".to_string(),
            pattern: "**/*.txt".to_string(),
            path_prefix: Some("".to_string()),
        })
        .unwrap();
    assert_eq!(globbed.matches, vec!["keep.txt".to_string()]);

    let grepped = vfs
        .grep(GrepRequest {
            workspace_id: "ws".to_string(),
            query: "keep".to_string(),
            regex: false,
            glob: None,
            path_prefix: Some("".to_string()),
        })
        .unwrap();
    assert_eq!(grepped.matches.len(), 1);
    assert_eq!(grepped.matches[0].path, "keep.txt");

    let read = vfs
        .read(ReadRequest {
            workspace_id: "ws".to_string(),
            path: "node_modules/skip.txt".to_string(),
            start_line: None,
            end_line: None,
        })
        .unwrap();
    assert_eq!(read.content, "skip\n");
}

#[test]
fn new_with_redactor_rejects_mismatched_secret_rules() {
    let store = SqliteStore::open_in_memory().expect("open sqlite");
    let mut policy = policy_all_perms();
    policy.secrets.deny_globs = vec![".env".to_string()];

    let redactor = SecretRedactor::from_rules(&SecretRules {
        deny_globs: Vec::new(),
        ..SecretRules::default()
    })
    .expect("mismatched redactor");

    let err = match DbVfs::new_with_redactor(store, policy, redactor) {
        Ok(_) => panic!("mismatched redactor should be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "invalid_policy");
}

#[test]
fn new_with_matchers_rejects_mismatched_traversal_rules() {
    let store = SqliteStore::open_in_memory().expect("open sqlite");
    let mut policy = policy_all_perms();
    policy.traversal.skip_globs = vec!["node_modules/**".to_string()];

    let redactor = SecretRedactor::from_rules(&policy.secrets).expect("matching redactor");
    let traversal =
        TraversalSkipper::from_rules(&TraversalRules::default()).expect("mismatched traversal");

    let err = match DbVfs::new_with_matchers(store, policy, redactor, traversal) {
        Ok(_) => panic!("mismatched traversal should be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "invalid_policy");
}

#[test]
fn new_with_supplied_matchers_validated_rejects_mismatched_matchers() {
    let store = SqliteStore::open_in_memory().expect("open sqlite");
    let mut policy = policy_all_perms();
    policy.permissions.allow_full_scan = true;
    policy.secrets.deny_globs = vec![".env".to_string()];
    policy.traversal.skip_globs = vec!["node_modules/**".to_string()];
    let policy = Arc::new(ValidatedVfsPolicy::new(policy).expect("validated policy"));

    let redactor = Arc::new(
        SecretRedactor::from_rules(&SecretRules {
            deny_globs: Vec::new(),
            ..SecretRules::default()
        })
        .expect("mismatched redactor"),
    );
    let traversal = Arc::new(
        TraversalSkipper::from_rules(&TraversalRules::default()).expect("mismatched traversal"),
    );

    let err = match DbVfs::new_with_supplied_matchers_validated(store, policy, redactor, traversal)
    {
        Ok(_) => panic!("mismatched validated matchers should be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "invalid_policy");
}
