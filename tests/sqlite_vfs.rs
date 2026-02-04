#![cfg(feature = "sqlite")]

use std::time::{SystemTime, UNIX_EPOCH};

use db_vfs::store::Store;
use db_vfs::store::sqlite::SqliteStore;
use db_vfs::vfs::{
    DbVfs, DeleteRequest, GlobRequest, GrepRequest, PatchRequest, ReadRequest, WriteRequest,
};
use db_vfs_core::policy::{
    AuditPolicy, AuthPolicy, Limits, Permissions, SecretRules, TraversalRules, VfsPolicy,
};
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
    assert_eq!(err.code(), "invalid_path");
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
    assert_eq!(err.code(), "invalid_path");
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
fn deny_globs_hide_descendants_via_probe() {
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
    assert!(listed.scanned_entries > 0);
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
