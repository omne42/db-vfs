use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::Serialize;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;

static DROPPED_AUDIT_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(super) struct AuditLogger {
    sender: mpsc::SyncSender<AuditEvent>,
}

#[derive(Debug, Serialize)]
pub(super) struct AuditEvent {
    pub ts_ms: u64,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    pub op: &'static str,
    pub workspace_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glob_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grep_regex: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grep_query_len: Option<usize>,

    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_read: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_limit_reason: Option<db_vfs::vfs::ScanLimitReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_entries: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_too_large_files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_traversal_skipped: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_secret_denied: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_glob_mismatch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_missing_content: Option<u64>,
}

impl AuditLogger {
    pub(super) fn new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (lock_file, file) = open_audit_file(&path)?;
        let (sender, receiver) = mpsc::sync_channel::<AuditEvent>(AUDIT_CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("db-vfs-audit".to_string())
            .spawn(move || audit_worker(file, receiver, path, lock_file))
            .map_err(anyhow::Error::msg)?;

        Ok(Self { sender })
    }

    pub(super) fn log(&self, event: AuditEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                let dropped = DROPPED_AUDIT_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped == 1 || dropped % 1000 == 0 {
                    tracing::warn!(dropped, "audit log channel is full; dropping audit events");
                }
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {}
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn open_audit_file(path: &Path) -> anyhow::Result<(std::fs::File, std::fs::File)> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let exists = path.exists();
    if exists {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            anyhow::bail!("audit.jsonl_path must be a regular file: {path:?}");
        }
    }

    let lock_path = lock_path_for(path);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;

    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("audit.jsonl_path must be a regular file: {path:?}");
    }
    Ok((lock_file, file))
}

fn lock_path_for(log_path: &Path) -> PathBuf {
    let mut lock_path = log_path.to_path_buf();
    lock_path.set_extension(format!(
        "{}.lock",
        log_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("lock")
    ));
    lock_path
}

fn audit_worker(
    file: std::fs::File,
    receiver: mpsc::Receiver<AuditEvent>,
    path: PathBuf,
    _lock_file: std::fs::File,
) {
    let mut out = BufWriter::new(file);
    let mut write_failures: u64 = 0;
    for event in receiver {
        let mut event = event;
        event.ts_ms = event.ts_ms.max(now_ms());

        if let Err(err) = serde_json::to_writer(&mut out, &event) {
            write_failures = write_failures.saturating_add(1);
            if write_failures == 1 || write_failures % 1000 == 0 {
                tracing::warn!(
                    err = %err,
                    audit_path = ?path,
                    write_failures,
                    "failed to serialize audit event"
                );
            }
            continue;
        }

        if let Err(err) = out.write_all(b"\n").and_then(|_| out.flush()) {
            write_failures = write_failures.saturating_add(1);
            if write_failures == 1 || write_failures % 1000 == 0 {
                tracing::warn!(
                    err = %err,
                    audit_path = ?path,
                    write_failures,
                    "failed to write audit event"
                );
            }
        }
    }
}
