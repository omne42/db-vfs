use std::fmt;
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
static OPTIONAL_AUDIT_RECOVERY_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(super) struct AuditLogger {
    sender: Arc<std::sync::Mutex<mpsc::SyncSender<QueuedAuditEvent>>>,
    disconnected_warned: Arc<AtomicBool>,
    required: bool,
    optional_recovery: Option<Arc<OptionalAuditRecovery>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditFailure {
    detail: String,
}

impl AuditFailure {
    pub(super) fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    fn worker_stopped() -> Self {
        Self::new("the audit worker stopped")
    }

    fn queue_full() -> Self {
        Self::new(format!(
            "the required audit queue is full (capacity {AUDIT_CHANNEL_CAPACITY})"
        ))
    }

    fn budget_exhausted(timeout: Duration) -> Self {
        Self::new(format!(
            "audit append+flush exceeded the remaining request budget ({timeout:?})"
        ))
    }
}

impl fmt::Display for AuditFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for AuditFailure {}

struct QueuedAuditEvent {
    event: AuditEvent,
    ack: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

struct OptionalAuditRecovery {
    path: PathBuf,
    flush_every_events: usize,
    flush_max_interval: Duration,
    respawn_lock: std::sync::Mutex<()>,
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
        auth_subject: None,
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
    pub auth_subject: Option<String>,

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
        let sender = spawn_audit_worker(
            path.clone(),
            required,
            flush_every_events,
            flush_max_interval,
        )?;

        Ok(Self {
            sender: Arc::new(std::sync::Mutex::new(sender)),
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required,
            optional_recovery: (!required).then(|| {
                Arc::new(OptionalAuditRecovery {
                    path,
                    flush_every_events,
                    flush_max_interval,
                    respawn_lock: std::sync::Mutex::new(()),
                })
            }),
        })
    }

    pub(super) async fn log_required(
        &self,
        event: AuditEvent,
        budget: Option<Duration>,
    ) -> Result<(), AuditFailure> {
        debug_assert!(
            self.required,
            "required audit path should only be used for required loggers"
        );
        let ack_rx = self.enqueue_required(event)?;
        let ack_result = match budget {
            Some(timeout) if timeout.is_zero() => {
                return Err(AuditFailure::budget_exhausted(timeout));
            }
            Some(timeout) => tokio::time::timeout(timeout, ack_rx)
                .await
                .map_err(|_| AuditFailure::budget_exhausted(timeout))?
                .map_err(|_| AuditFailure::worker_stopped())?,
            None => ack_rx.await.map_err(|_| AuditFailure::worker_stopped())?,
        };
        match ack_result {
            Ok(()) => Ok(()),
            Err(err) => Err(AuditFailure::new(err)),
        }
    }

    pub(super) fn try_log(&self, event: AuditEvent) -> Result<(), AuditFailure> {
        let mut queued = QueuedAuditEvent { event, ack: None };
        loop {
            let sender = self
                .sender
                .lock()
                .map_err(|_| AuditFailure::new("audit sender lock poisoned"))?
                .clone();
            match sender.try_send(queued) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(_returned)) => {
                    let dropped = DROPPED_AUDIT_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped == 1 || dropped.is_multiple_of(1000) {
                        tracing::warn!(
                            dropped,
                            capacity = AUDIT_CHANNEL_CAPACITY,
                            "audit log channel is full; dropping audit events"
                        );
                    }
                    return Ok(());
                }
                Err(mpsc::TrySendError::Disconnected(returned)) => {
                    queued = returned;
                    let Some(recovery) = self.optional_recovery.as_ref() else {
                        if !self.disconnected_warned.swap(true, Ordering::Relaxed) {
                            let dropped = DROPPED_AUDIT_EVENTS.load(Ordering::Relaxed);
                            tracing::warn!(
                                dropped,
                                "audit log worker thread has stopped; audit events will be dropped"
                            );
                        }
                        return Ok(());
                    };
                    if let Err(err) =
                        recovery.recover_sender(&self.sender, self.disconnected_warned.as_ref())
                    {
                        if !self.disconnected_warned.swap(true, Ordering::Relaxed) {
                            tracing::warn!(
                                err = %err,
                                "audit log worker stopped and automatic recovery failed; dropping audit events"
                            );
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    fn enqueue_required(
        &self,
        event: AuditEvent,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<(), String>>, AuditFailure> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let sender = self
            .sender
            .lock()
            .map_err(|_| AuditFailure::new("audit sender lock poisoned"))?
            .clone();
        match sender.try_send(QueuedAuditEvent {
            event,
            ack: Some(ack_tx),
        }) {
            Ok(()) => Ok(ack_rx),
            Err(mpsc::TrySendError::Full(_)) => Err(AuditFailure::queue_full()),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(AuditFailure::worker_stopped()),
        }
    }

    pub(super) fn is_required(&self) -> bool {
        self.required
    }

    #[cfg(test)]
    pub(super) fn broken_required_logger_for_test() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        Self {
            sender: Arc::new(std::sync::Mutex::new(sender)),
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required: true,
            optional_recovery: None,
        }
    }

    #[cfg(test)]
    pub(super) fn broken_optional_logger_for_test() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        Self {
            sender: Arc::new(std::sync::Mutex::new(sender)),
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required: false,
            optional_recovery: None,
        }
    }

    #[cfg(test)]
    pub(super) fn blocking_required_logger_for_test() -> (Self, BlockingRequiredAuditControl) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let blocked = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let blocked_for_worker = blocked.clone();
        std::thread::Builder::new()
            .name("db-vfs-audit-test-blocking".to_string())
            .spawn(move || {
                let queued: QueuedAuditEvent = receiver.recv().expect("receive queued audit event");
                blocked_for_worker.store(true, Ordering::Release);
                if release_rx.recv().is_err() {
                    return;
                }
                if let Some(ack) = queued.ack {
                    // Timeout-path tests may drop the ack receiver before the
                    // helper thread is released; treat that as a normal teardown.
                    let _ = ack.send(Ok(()));
                }
            })
            .expect("spawn blocking audit test worker");
        (
            Self {
                sender: Arc::new(std::sync::Mutex::new(sender)),
                disconnected_warned: Arc::new(AtomicBool::new(false)),
                required: true,
                optional_recovery: None,
            },
            BlockingRequiredAuditControl {
                blocked,
                release_tx,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn full_required_logger_for_test() -> (Self, FullRequiredAuditControl) {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(QueuedAuditEvent {
                event: minimal_event("queued".to_string(), None, "read", 200, None),
                ack: None,
            })
            .expect("fill required audit queue");
        (
            Self {
                sender: Arc::new(std::sync::Mutex::new(sender)),
                disconnected_warned: Arc::new(AtomicBool::new(false)),
                required: true,
                optional_recovery: None,
            },
            FullRequiredAuditControl {
                _receiver: receiver,
            },
        )
    }
}

#[cfg(test)]
pub(super) struct BlockingRequiredAuditControl {
    blocked: Arc<AtomicBool>,
    release_tx: mpsc::SyncSender<()>,
}

#[cfg(test)]
pub(super) struct FullRequiredAuditControl {
    _receiver: mpsc::Receiver<QueuedAuditEvent>,
}

#[cfg(test)]
impl BlockingRequiredAuditControl {
    pub(super) fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::Acquire)
    }

    pub(super) fn release_success(&self) {
        self.release_tx.send(()).expect("release audit success");
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

    let file = open_audit_append_file(path)?;
    Ok((lock_file, file))
}

fn open_audit_append_file(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("audit.jsonl_path must be a regular file: {path:?}");
    }
    Ok(file)
}

fn spawn_audit_worker(
    path: PathBuf,
    required: bool,
    flush_every_events: usize,
    flush_max_interval: Duration,
) -> anyhow::Result<mpsc::SyncSender<QueuedAuditEvent>> {
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

    Ok(sender)
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

impl OptionalAuditRecovery {
    fn recover_sender(
        &self,
        sender: &std::sync::Mutex<mpsc::SyncSender<QueuedAuditEvent>>,
        disconnected_warned: &AtomicBool,
    ) -> anyhow::Result<()> {
        let _respawn_guard = self
            .respawn_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("audit respawn lock poisoned"))?;
        let rotated = rotate_corrupt_audit_log(&self.path)?;
        let next_sender = spawn_audit_worker(
            self.path.clone(),
            false,
            self.flush_every_events,
            self.flush_max_interval,
        )?;
        *sender
            .lock()
            .map_err(|_| anyhow::anyhow!("audit sender lock poisoned"))? = next_sender;
        disconnected_warned.store(false, Ordering::Release);
        tracing::warn!(
            audit_path = %self.path.display(),
            rotated_path = rotated.as_ref().map(|path| path.display().to_string()),
            "optional audit worker stopped; rotated previous log and started a new worker"
        );
        Ok(())
    }
}

fn rotate_corrupt_audit_log(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }

    let rotated = corrupt_audit_log_path(path);
    std::fs::rename(path, &rotated).map_err(|err| {
        anyhow::anyhow!(
            "failed to rotate possibly corrupted audit log {} to {}: {err}",
            path.display(),
            rotated.display()
        )
    })?;
    Ok(Some(rotated))
}

fn corrupt_audit_log_path(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(format!(".corrupt-{}", now_ms()));
    PathBuf::from(rotated)
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
    audit_worker_with_recovery(
        BufWriter::new(file),
        receiver,
        &path,
        required,
        flush_every_events,
        flush_max_interval,
        || {
            recover_optional_audit_writer(&path)
                .ok()
                .map(BufWriter::new)
        },
    );
}

#[cfg(test)]
fn audit_worker_with_writer<W: Write>(
    out: BufWriter<W>,
    receiver: mpsc::Receiver<QueuedAuditEvent>,
    path: &Path,
    required: bool,
    flush_every_events: usize,
    flush_max_interval: Duration,
) {
    audit_worker_with_recovery(
        out,
        receiver,
        path,
        required,
        flush_every_events,
        flush_max_interval,
        || None::<BufWriter<W>>,
    );
}

fn audit_worker_with_recovery<W, Recover>(
    out: BufWriter<W>,
    receiver: mpsc::Receiver<QueuedAuditEvent>,
    path: &Path,
    required: bool,
    flush_every_events: usize,
    flush_max_interval: Duration,
    mut recover: Recover,
) where
    W: Write,
    Recover: FnMut() -> Option<BufWriter<W>>,
{
    let mut write_failures: u64 = 0;
    let mut pending: usize = 0;
    let mut last_flush: Instant = Instant::now();
    let mut writer_failed = false;
    let mut out = Some(out);

    loop {
        match receiver.recv_timeout(flush_max_interval) {
            Ok(QueuedAuditEvent { mut event, ack }) => {
                if event.ts_ms == 0 {
                    event.ts_ms = now_ms();
                }

                let Some(writer) = out.as_mut() else {
                    break;
                };

                if let Err(err) = serde_json::to_writer(writer, &event) {
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
                    if !try_recover_optional_writer(
                        required,
                        OptionalWriterRecoveryState {
                            out: &mut out,
                            pending: &mut pending,
                            last_flush: &mut last_flush,
                            recover: &mut recover,
                        },
                        OptionalWriterRecoveryMeta {
                            path,
                            write_failures,
                            stage: "serialize audit event",
                        },
                    ) {
                        break;
                    }
                    writer_failed = false;
                    continue;
                }
                let Some(writer) = out.as_mut() else {
                    break;
                };
                if let Err(err) = writer.write_all(b"\n") {
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
                    if !try_recover_optional_writer(
                        required,
                        OptionalWriterRecoveryState {
                            out: &mut out,
                            pending: &mut pending,
                            last_flush: &mut last_flush,
                            recover: &mut recover,
                        },
                        OptionalWriterRecoveryMeta {
                            path,
                            write_failures,
                            stage: "append audit newline",
                        },
                    ) {
                        break;
                    }
                    writer_failed = false;
                    continue;
                }

                if required {
                    let Some(writer) = out.as_mut() else {
                        break;
                    };
                    if let Err(err) = writer.flush() {
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
                        if !try_recover_optional_writer(
                            required,
                            OptionalWriterRecoveryState {
                                out: &mut out,
                                pending: &mut pending,
                                last_flush: &mut last_flush,
                                recover: &mut recover,
                            },
                            OptionalWriterRecoveryMeta {
                                path,
                                write_failures,
                                stage: "flush audit log",
                            },
                        ) {
                            break;
                        }
                        writer_failed = false;
                        continue;
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
            let Some(writer) = out.as_mut() else {
                break;
            };
            if let Err(err) = writer.flush() {
                write_failures = write_failures.saturating_add(1);
                writer_failed = true;
                log_unrecoverable_write_failure(
                    required,
                    path,
                    write_failures,
                    &err,
                    "flush audit log",
                );
                if !try_recover_optional_writer(
                    required,
                    OptionalWriterRecoveryState {
                        out: &mut out,
                        pending: &mut pending,
                        last_flush: &mut last_flush,
                        recover: &mut recover,
                    },
                    OptionalWriterRecoveryMeta {
                        path,
                        write_failures,
                        stage: "flush audit log",
                    },
                ) {
                    break;
                }
                writer_failed = false;
                continue;
            }
            pending = 0;
            last_flush = Instant::now();
        }
    }

    if !writer_failed
        && pending > 0
        && let Some(writer) = out.as_mut()
        && let Err(err) = writer.flush()
    {
        tracing::warn!(
            err = %err,
            audit_path = ?path,
            "failed to flush audit log during worker shutdown"
        );
    }
}

struct OptionalWriterRecoveryState<'a, W, Recover>
where
    W: Write,
    Recover: FnMut() -> Option<BufWriter<W>>,
{
    out: &'a mut Option<BufWriter<W>>,
    pending: &'a mut usize,
    last_flush: &'a mut Instant,
    recover: &'a mut Recover,
}

struct OptionalWriterRecoveryMeta<'a> {
    path: &'a Path,
    write_failures: u64,
    stage: &'static str,
}

fn try_recover_optional_writer<W, Recover>(
    required: bool,
    state: OptionalWriterRecoveryState<'_, W, Recover>,
    meta: OptionalWriterRecoveryMeta<'_>,
) -> bool
where
    W: Write,
    Recover: FnMut() -> Option<BufWriter<W>>,
{
    if required {
        return false;
    }

    let OptionalWriterRecoveryState {
        out,
        pending,
        last_flush,
        recover,
    } = state;
    let OptionalWriterRecoveryMeta {
        path,
        write_failures,
        stage,
    } = meta;

    drop(out.take());
    match recover() {
        Some(writer) => {
            *out = Some(writer);
            *pending = 0;
            *last_flush = Instant::now();
            tracing::warn!(
                audit_path = ?path,
                write_failures,
                stage,
                "optional audit writer recovered after write failure; the failed event was dropped"
            );
            true
        }
        None => false,
    }
}

fn recover_optional_audit_writer(path: &Path) -> anyhow::Result<std::fs::File> {
    let rotated_path = broken_audit_path(path);
    if path.exists() {
        std::fs::rename(path, &rotated_path).map_err(|err| {
            anyhow::anyhow!(
                "failed to rotate broken audit log {} to {}: {err}",
                path.display(),
                rotated_path.display()
            )
        })?;
    }

    tracing::warn!(
        audit_path = ?path,
        rotated_path = ?rotated_path,
        "rotated broken optional audit log before reopening writer"
    );
    open_audit_append_file(path)
}

fn broken_audit_path(path: &Path) -> PathBuf {
    let seq = OPTIONAL_AUDIT_RECOVERY_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(format!(".broken-{}-{seq}", now_ms()));
    PathBuf::from(rotated)
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
    use std::io::BufWriter;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

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

    struct SharedBufferWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBufferWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    bytes: bytes.clone(),
                },
                bytes,
            )
        }
    }

    impl std::io::Write for SharedBufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .expect("lock shared bytes")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    enum TestAuditWriter {
        Failing(FailAfterPartialWrite),
        Recovery(SharedBufferWriter),
    }

    impl std::io::Write for TestAuditWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self {
                TestAuditWriter::Failing(writer) => writer.write(buf),
                TestAuditWriter::Recovery(writer) => writer.write(buf),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            match self {
                TestAuditWriter::Failing(writer) => writer.flush(),
                TestAuditWriter::Recovery(writer) => writer.flush(),
            }
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
    fn audit_event_serialization_omits_auth_subject_when_absent() {
        let json = serde_json::to_value(super::minimal_event(
            "req-1".to_string(),
            None,
            "read",
            200,
            None,
        ))
        .expect("serialize event");

        assert!(json.get("auth_subject").is_none());
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

    #[tokio::test]
    async fn required_audit_logger_returns_error_when_worker_is_gone() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let logger = super::AuditLogger {
            sender: Arc::new(std::sync::Mutex::new(sender)),
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required: true,
            optional_recovery: None,
        };

        let err = logger
            .log_required(
                super::minimal_event("req-1".to_string(), None, "read", 200, None),
                Some(Duration::from_millis(10)),
            )
            .await
            .expect_err("required audit should surface worker failure");
        assert_eq!(err.to_string(), "the audit worker stopped");
    }

    #[tokio::test]
    async fn required_audit_logger_fails_when_queue_is_full() {
        let (logger, _control) = super::AuditLogger::full_required_logger_for_test();
        let err = logger
            .log_required(
                super::minimal_event("req-1".to_string(), None, "read", 200, None),
                Some(Duration::from_secs(1)),
            )
            .await
            .expect_err("required audit should fail immediately when queue is full");
        assert!(
            err.to_string().contains("required audit queue is full"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn required_audit_logger_times_out_waiting_for_ack() {
        let (logger, _control) = super::AuditLogger::blocking_required_logger_for_test();
        let err = logger
            .log_required(
                super::minimal_event("req-1".to_string(), None, "read", 200, None),
                Some(Duration::from_millis(10)),
            )
            .await
            .expect_err("required audit should fail when ack wait exhausts budget");
        assert!(
            err.to_string()
                .contains("audit append+flush exceeded the remaining request budget"),
            "unexpected error: {err}"
        );
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
        super::audit_worker_with_writer(
            std::io::BufWriter::with_capacity(1, writer),
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
    fn optional_audit_worker_recovers_later_events_when_recovery_writer_is_available() {
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

        let (writer, broken_bytes, _) = FailAfterPartialWrite::new(64);
        let (recovery_writer, recovery_bytes) = SharedBufferWriter::new();
        let mut recovery_writer = Some(BufWriter::with_capacity(
            1,
            TestAuditWriter::Recovery(recovery_writer),
        ));

        super::audit_worker_with_recovery(
            BufWriter::with_capacity(1, TestAuditWriter::Failing(writer)),
            receiver,
            Path::new("audit.jsonl"),
            false,
            1,
            Duration::from_millis(1),
            || recovery_writer.take(),
        );

        let broken_raw = String::from_utf8(broken_bytes.lock().expect("lock broken bytes").clone())
            .expect("utf8");
        assert!(broken_raw.contains("req-1"));
        assert!(!broken_raw.contains("req-2"));

        let recovered_raw =
            String::from_utf8(recovery_bytes.lock().expect("lock recovery bytes").clone())
                .expect("utf8");
        assert!(!recovered_raw.contains("req-1"));
        assert!(recovered_raw.contains("req-2"));
    }

    #[test]
    fn recover_optional_audit_writer_rotates_broken_log_and_reopens_primary_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"broken-json").expect("seed broken log");

        let reopened = super::recover_optional_audit_writer(&path).expect("recover optional audit");
        drop(reopened);

        let reopened_raw = std::fs::read_to_string(&path).expect("read reopened log");
        assert!(
            reopened_raw.is_empty(),
            "reopened primary log should start empty"
        );

        let rotated = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| {
                entry != &path
                    && entry
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("audit.jsonl.broken-"))
            })
            .expect("rotated broken log path");
        let rotated_raw = std::fs::read_to_string(rotated).expect("read rotated log");
        assert_eq!(rotated_raw, "broken-json");
    }

    #[test]
    fn required_audit_worker_reports_write_failure_to_caller() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        sender
            .send(super::QueuedAuditEvent {
                event: super::minimal_event("req-1".to_string(), None, "read", 200, None),
                ack: Some(ack_tx),
            })
            .expect("send event");
        drop(sender);

        let (writer, _, _) = FailAfterPartialWrite::new(8);
        super::audit_worker_with_writer(
            std::io::BufWriter::with_capacity(1, writer),
            receiver,
            Path::new("audit.jsonl"),
            true,
            1,
            Duration::from_millis(1),
        );

        let err = ack_rx
            .blocking_recv()
            .expect("required audit ack")
            .expect_err("required audit should surface write failure");
        assert!(err.contains("serialize audit event") || err.contains("append audit newline"));
    }

    #[test]
    fn optional_audit_logger_rotates_corrupt_log_and_recovers_after_disconnect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"broken\":").expect("seed corrupt audit log");

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let logger = super::AuditLogger {
            sender: Arc::new(std::sync::Mutex::new(sender)),
            disconnected_warned: Arc::new(AtomicBool::new(false)),
            required: false,
            optional_recovery: Some(Arc::new(super::OptionalAuditRecovery {
                path: path.clone(),
                flush_every_events: 1,
                flush_max_interval: Duration::from_millis(1),
                respawn_lock: std::sync::Mutex::new(()),
            })),
        };

        logger
            .try_log(super::minimal_event(
                "req-recovered".to_string(),
                None,
                "read",
                200,
                None,
            ))
            .expect("optional audit logger should recover");

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let active = loop {
            let active = std::fs::read_to_string(&path).unwrap_or_default();
            if active.contains("req-recovered") {
                break active;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for recovered audit event"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(active.contains("req-recovered"));

        let rotated = std::fs::read_dir(dir.path())
            .expect("read tempdir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate != &path
                    && candidate
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("audit.jsonl.corrupt-"))
            })
            .expect("rotated corrupt audit log");
        let rotated_raw = std::fs::read_to_string(rotated).expect("read rotated log");
        assert_eq!(rotated_raw, "{\"broken\":");
    }
}
