use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::Serialize;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;
pub(super) const DEFAULT_AUDIT_FLUSH_EVERY_EVENTS: usize = 32;
pub(super) const DEFAULT_AUDIT_FLUSH_MAX_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const UNKNOWN_WORKSPACE_ID: &str = "<unknown>";

static DROPPED_AUDIT_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(super) struct AuditLogger {
    sender: mpsc::SyncSender<QueuedAuditEvent>,
    disconnected_warned: Arc<AtomicBool>,
    required: bool,
}

struct QueuedAuditEvent {
    event: AuditEvent,
    ack: Option<mpsc::SyncSender<Result<(), String>>>,
}

pub(super) fn op_from_path(path: &str) -> Option<&'static str> {
    match path {
        "/v1/read" => Some("read"),
        "/v1/write" => Some("write"),
        "/v1/patch" => Some("patch"),
        "/v1/delete" => Some("delete"),
        "/v1/glob" => Some("glob"),
        "/v1/grep" => Some("grep"),
        _ => None,
    }
}

pub(super) fn minimal_event(
    request_id: String,
    peer_ip: Option<IpAddr>,
    op: &'static str,
    status: u16,
    error_code: Option<&'static str>,
) -> AuditEvent {
    AuditEvent {
        ts_ms: now_ms(),
        request_id,
        peer_ip: peer_ip.map(|ip| ip.to_string()),
        op,
        workspace_id: UNKNOWN_WORKSPACE_ID.to_string(),
        requested_path: None,
        path: None,
        path_prefix: None,
        glob_pattern: None,
        grep_regex: None,
        grep_query_len: None,
        status,
        error_code: error_code.map(ToString::to_string),
        bytes_read: None,
        bytes_written: None,
        created: None,
        deleted: None,
        version: None,
        matches: None,
        truncated: None,
        scan_limit_reason: None,
        scanned_files: None,
        scanned_entries: None,
        skipped_too_large_files: None,
        skipped_traversal_skipped: None,
        skipped_secret_denied: None,
        skipped_glob_mismatch: None,
        skipped_missing_content: None,
    }
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
    pub(super) fn new(
        path: impl AsRef<Path>,
        required: bool,
        flush_every_events: usize,
        flush_max_interval: Duration,
    ) -> anyhow::Result<Self> {
        if flush_every_events == 0 {
            anyhow::bail!("flush_every_events must be > 0 (got {flush_every_events})");
        }
        if flush_max_interval.is_zero() {
            anyhow::bail!("flush_max_interval must be > 0 (got {flush_max_interval:?})");
        }

        let path = path.as_ref().to_path_buf();
        let (lock_file, file) = open_audit_file(&path)?;
        let (sender, receiver) = mpsc::sync_channel::<QueuedAuditEvent>(AUDIT_CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("db-vfs-audit".to_string())
            .spawn(move || {
                audit_worker(
                    file,
                    receiver,
                    path,
                    lock_file,
                    required,
                    flush_every_events,
                    flush_max_interval,
                )
            })
            .map_err(anyhow::Error::msg)?;

        Ok(Self {
            sender,
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required,
        })
    }

    pub(super) fn log(&self, event: AuditEvent) {
        if self.required {
            let (ack_tx, ack_rx) = mpsc::sync_channel(1);
            if self
                .sender
                .send(QueuedAuditEvent {
                    event,
                    ack: Some(ack_tx),
                })
                .is_err()
            {
                panic!("audit.required=true but the audit worker stopped");
            }
            match ack_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => panic!("audit.required=true but {err}"),
                Err(_) => panic!("audit.required=true but the audit worker stopped"),
            }
            return;
        }

        match self.sender.try_send(QueuedAuditEvent { event, ack: None }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                let dropped = DROPPED_AUDIT_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped == 1 || dropped.is_multiple_of(1000) {
                    tracing::warn!(
                        dropped,
                        capacity = AUDIT_CHANNEL_CAPACITY,
                        "audit log channel is full; dropping audit events"
                    );
                }
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                if !self.disconnected_warned.swap(true, Ordering::Relaxed) {
                    let dropped = DROPPED_AUDIT_EVENTS.load(Ordering::Relaxed);
                    tracing::warn!(
                        dropped,
                        "audit log worker thread has stopped; audit events will be dropped"
                    );
                }
            }
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
    lock_file.try_lock_exclusive().map_err(|err| {
        if is_lock_already_held(&err) {
            anyhow::anyhow!("audit lock is already held: {}", lock_path.display())
        } else {
            anyhow::Error::from(err)
        }
    })?;

    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("audit.jsonl_path must be a regular file: {path:?}");
    }
    Ok((lock_file, file))
}

fn is_lock_already_held(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }

    #[cfg(windows)]
    {
        matches!(err.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn lock_path_for(log_path: &Path) -> PathBuf {
    let suffix = if log_path.extension() == Some(std::ffi::OsStr::new("lock")) {
        ".audit-lock"
    } else {
        ".lock"
    };
    let mut lock_path = log_path.as_os_str().to_owned();
    lock_path.push(suffix);
    PathBuf::from(lock_path)
}

fn audit_worker(
    file: std::fs::File,
    receiver: mpsc::Receiver<QueuedAuditEvent>,
    path: PathBuf,
    _lock_file: std::fs::File,
    required: bool,
    flush_every_events: usize,
    flush_max_interval: Duration,
) {
    let mut out = BufWriter::new(file);
    audit_worker_with_writer(
        &mut out,
        receiver,
        &path,
        required,
        flush_every_events,
        flush_max_interval,
    );
}

fn audit_worker_with_writer<W: Write>(
    out: &mut BufWriter<W>,
    receiver: mpsc::Receiver<QueuedAuditEvent>,
    path: &Path,
    required: bool,
    flush_every_events: usize,
    flush_max_interval: Duration,
) {
    let mut write_failures: u64 = 0;
    let mut pending: usize = 0;
    let mut last_flush: Instant = Instant::now();
    let mut writer_failed = false;

    loop {
        match receiver.recv_timeout(flush_max_interval) {
            Ok(QueuedAuditEvent { mut event, ack }) => {
                if event.ts_ms == 0 {
                    event.ts_ms = now_ms();
                }

                if let Err(err) = serde_json::to_writer(&mut *out, &event) {
                    write_failures = write_failures.saturating_add(1);
                    writer_failed = true;
                    if let Some(ack) = ack {
                        drop(ack.send(Err(format_unrecoverable_write_failure(
                            path,
                            "serialize audit event",
                            &err,
                        ))));
                    }
                    log_unrecoverable_write_failure(
                        required,
                        path,
                        write_failures,
                        &err,
                        "serialize audit event",
                    );
                    break;
                }
                if let Err(err) = out.write_all(b"\n") {
                    write_failures = write_failures.saturating_add(1);
                    writer_failed = true;
                    if let Some(ack) = ack {
                        drop(ack.send(Err(format_unrecoverable_write_failure(
                            path,
                            "append audit newline",
                            &err,
                        ))));
                    }
                    log_unrecoverable_write_failure(
                        required,
                        path,
                        write_failures,
                        &err,
                        "append audit newline",
                    );
                    break;
                }

                if required {
                    if let Err(err) = out.flush() {
                        write_failures = write_failures.saturating_add(1);
                        writer_failed = true;
                        if let Some(ack) = ack {
                            drop(ack.send(Err(format_unrecoverable_write_failure(
                                path,
                                "flush audit log",
                                &err,
                            ))));
                        }
                        log_unrecoverable_write_failure(
                            required,
                            path,
                            write_failures,
                            &err,
                            "flush audit log",
                        );
                        break;
                    }
                    if let Some(ack) = ack {
                        drop(ack.send(Ok(())));
                    }
                    last_flush = Instant::now();
                    continue;
                }

                pending = pending.saturating_add(1);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if pending == 0 {
            continue;
        }

        if pending >= flush_every_events || last_flush.elapsed() >= flush_max_interval {
            if let Err(err) = out.flush() {
                write_failures = write_failures.saturating_add(1);
                writer_failed = true;
                log_unrecoverable_write_failure(
                    required,
                    path,
                    write_failures,
                    &err,
                    "flush audit log",
                );
                break;
            }
            pending = 0;
            last_flush = Instant::now();
        }
    }

    if !writer_failed
        && pending > 0
        && let Err(err) = out.flush()
    {
        tracing::warn!(
            err = %err,
            audit_path = ?path,
            "failed to flush audit log during worker shutdown"
        );
    }
}

fn log_unrecoverable_write_failure(
    required: bool,
    path: &Path,
    write_failures: u64,
    err: &dyn std::fmt::Display,
    stage: &'static str,
) {
    if required {
        tracing::error!(
            err = %err,
            audit_path = ?path,
            write_failures,
            stage,
            "required audit worker cannot continue after write failure; stopping worker"
        );
        return;
    }

    tracing::warn!(
        err = %err,
        audit_path = ?path,
        write_failures,
        stage,
        "audit worker cannot continue after write failure; stopping worker to avoid corrupting later JSONL"
    );
}

fn format_unrecoverable_write_failure(
    path: &Path,
    stage: &'static str,
    err: &dyn std::fmt::Display,
) -> String {
    format!("{stage} for {} failed: {err}", path.display())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;
    use std::{panic, sync::Arc};

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FailAfterPartialWrite {
        bytes: Arc<Mutex<Vec<u8>>>,
        partial_bytes: usize,
        pending_error: bool,
        writes: Arc<AtomicUsize>,
    }

    impl FailAfterPartialWrite {
        fn new(partial_bytes: usize) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let writes = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    bytes: bytes.clone(),
                    partial_bytes,
                    pending_error: false,
                    writes: writes.clone(),
                },
                bytes,
                writes,
            )
        }
    }

    impl std::io::Write for FailAfterPartialWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            if self.pending_error {
                return Err(std::io::Error::other("synthetic audit writer failure"));
            }

            let written = buf.len().min(self.partial_bytes.max(1));
            self.partial_bytes = self.partial_bytes.saturating_sub(written);
            self.pending_error = self.partial_bytes == 0;
            self.bytes
                .lock()
                .expect("lock audit bytes")
                .extend_from_slice(&buf[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lock_path_for_appends_lock_suffix() {
        assert_eq!(
            super::lock_path_for(Path::new("audit.jsonl")),
            PathBuf::from("audit.jsonl.lock")
        );
        assert_eq!(
            super::lock_path_for(Path::new("audit")),
            PathBuf::from("audit.lock")
        );
    }

    #[test]
    fn lock_path_for_avoids_lock_lock_suffixes() {
        assert_eq!(
            super::lock_path_for(Path::new("audit.lock")),
            PathBuf::from("audit.lock.audit-lock")
        );
    }

    #[test]
    fn audit_worker_preserves_provided_event_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let (lock_file, file) = super::open_audit_file(&path).expect("open audit file");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        let mut event = super::minimal_event("req-1".to_string(), None, "read", 200, None);
        event.ts_ms = 42;
        sender
            .send(super::QueuedAuditEvent { event, ack: None })
            .expect("send event");
        drop(sender);

        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            super::audit_worker(
                file,
                receiver,
                worker_path,
                lock_file,
                false,
                1,
                Duration::from_millis(1),
            )
        });
        worker.join().expect("worker join");

        let raw = std::fs::read_to_string(&path).expect("read audit log");
        let line = raw.lines().next().expect("audit line");
        let parsed: serde_json::Value = serde_json::from_str(line).expect("parse json");
        assert_eq!(parsed["ts_ms"].as_u64(), Some(42));
    }

    #[test]
    fn open_audit_file_fails_fast_when_lock_is_already_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let (_first_lock, _first_file) = super::open_audit_file(&path).expect("first open");
        let started = std::time::Instant::now();
        let err = super::open_audit_file(&path).expect_err("second open should fail");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "second open should fail without blocking on the audit lock"
        );
        #[cfg(not(windows))]
        assert!(err.to_string().contains("audit lock is already held"));
        #[cfg(windows)]
        let _ = err;
    }

    #[test]
    fn required_audit_logger_panics_when_worker_is_gone() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let logger = super::AuditLogger {
            sender,
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required: true,
        };

        let result = panic::catch_unwind(|| {
            logger.log(super::minimal_event(
                "req-1".to_string(),
                None,
                "read",
                200,
                None,
            ))
        });
        assert!(result.is_err());
    }

    #[test]
    fn optional_audit_worker_stops_after_partial_write_failure() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        sender
            .send(super::QueuedAuditEvent {
                event: super::minimal_event("req-1".to_string(), None, "read", 200, None),
                ack: None,
            })
            .expect("send first event");
        sender
            .send(super::QueuedAuditEvent {
                event: super::minimal_event("req-2".to_string(), None, "read", 200, None),
                ack: None,
            })
            .expect("send second event");
        drop(sender);

        let (writer, bytes, writes) = FailAfterPartialWrite::new(64);
        let mut out = std::io::BufWriter::with_capacity(1, writer);

        super::audit_worker_with_writer(
            &mut out,
            receiver,
            Path::new("audit.jsonl"),
            false,
            1,
            Duration::from_millis(1),
        );

        let raw = String::from_utf8(bytes.lock().expect("lock bytes").clone()).expect("utf8");
        assert!(
            raw.contains("req-1"),
            "first event should have started writing before the synthetic failure"
        );
        assert!(
            !raw.contains("req-2"),
            "worker should stop before attempting later events after the stream becomes unreliable"
        );
        assert!(
            writes.load(Ordering::Relaxed) >= 2,
            "test writer should observe the retry that surfaces the failure"
        );
    }

    #[test]
    fn required_audit_worker_reports_write_failure_to_caller() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(super::QueuedAuditEvent {
                event: super::minimal_event("req-1".to_string(), None, "read", 200, None),
                ack: Some(ack_tx),
            })
            .expect("send event");
        drop(sender);

        let (writer, _, _) = FailAfterPartialWrite::new(8);
        let mut out = std::io::BufWriter::with_capacity(1, writer);
        super::audit_worker_with_writer(
            &mut out,
            receiver,
            Path::new("audit.jsonl"),
            true,
            1,
            Duration::from_millis(1),
        );

        let err = ack_rx
            .recv()
            .expect("required audit ack")
            .expect_err("required audit should surface write failure");
        assert!(err.contains("serialize audit event") || err.contains("append audit newline"));
    }
}
