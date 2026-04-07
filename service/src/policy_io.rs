use std::borrow::Cow;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::TrustMode;
use crate::policy::{ServiceLimits, ServicePolicy};

const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_UNTRUSTED_SCAN_INFLIGHT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
enum PolicyFormat {
    Json,
    Toml,
    Yaml,
}

pub fn load_policy(
    path: impl AsRef<Path>,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<ServicePolicy> {
    let path = path.as_ref();
    let raw = read_policy_file(path)?;
    let format = policy_format(path)?;
    let policy = parse_policy_str(&raw, format, trust_mode, Some(path))?;
    validate_policy_for_startup(&policy, trust_mode, unsafe_no_auth)?;
    Ok(policy)
}

pub fn validate_policy_for_startup(
    policy: &ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<()> {
    policy.validate().map_err(anyhow::Error::msg)?;
    validate_trust_mode(policy, trust_mode, unsafe_no_auth)?;
    Ok(())
}

fn read_policy_file(path: &Path) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let before_open = std::fs::symlink_metadata(path).map_err(|err| {
            anyhow::anyhow!("failed to stat policy file {}: {err}", path.display())
        })?;
        if before_open.file_type().is_symlink() {
            anyhow::bail!("policy path must not be a symlink: {}", path.display());
        }
        if !before_open.is_file() {
            anyhow::bail!("policy path is not a regular file: {}", path.display());
        }

        let probe = open_policy_file_nofollow(path)?;
        let probe_info = query_open_policy_file_info(path, &probe)?;
        ensure_windows_regular_policy_file(path, probe_info.file_attributes)?;

        let file = open_policy_file_nofollow(path)?;
        let file_info = query_open_policy_file_info(path, &file)?;
        ensure_windows_regular_policy_file(path, file_info.file_attributes)?;
        if probe_info.identity() != file_info.identity() {
            anyhow::bail!("policy path changed while opening: {}", path.display());
        }

        let limit = u64::try_from(MAX_POLICY_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let capacity = usize::try_from(file_info.file_size.min(limit))
            .unwrap_or(MAX_POLICY_BYTES.saturating_add(1))
            .min(MAX_POLICY_BYTES.saturating_add(1));
        let mut bytes = Vec::<u8>::with_capacity(capacity);
        let reader = BufReader::new(file);
        reader.take(limit).read_to_end(&mut bytes).map_err(|err| {
            anyhow::anyhow!("failed to read policy file {}: {err}", path.display())
        })?;
        if bytes.len() > MAX_POLICY_BYTES {
            anyhow::bail!(
                "policy file is too large ({} bytes; max {} bytes)",
                bytes.len(),
                MAX_POLICY_BYTES
            );
        }

        String::from_utf8(bytes).map_err(|err| {
            anyhow::anyhow!("policy file {} is not valid UTF-8: {err}", path.display())
        })
    }

    #[cfg(not(windows))]
    {
        let before_open = std::fs::symlink_metadata(path).map_err(|err| {
            anyhow::anyhow!("failed to stat policy file {}: {err}", path.display())
        })?;
        if before_open.file_type().is_symlink() {
            anyhow::bail!("policy path must not be a symlink: {}", path.display());
        }
        if !before_open.is_file() {
            anyhow::bail!("policy path is not a regular file: {}", path.display());
        }

        let file = open_policy_file_nofollow(path)?;
        let after_open = file.metadata().map_err(|err| {
            anyhow::anyhow!(
                "failed to stat opened policy file {}: {err}",
                path.display()
            )
        })?;
        if !after_open.is_file() {
            anyhow::bail!("policy path is not a regular file: {}", path.display());
        }
        ensure_same_file(path, &before_open, &after_open)?;

        let limit = u64::try_from(MAX_POLICY_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let capacity = usize::try_from(after_open.len().min(limit))
            .unwrap_or(MAX_POLICY_BYTES.saturating_add(1))
            .min(MAX_POLICY_BYTES.saturating_add(1));
        let mut bytes = Vec::<u8>::with_capacity(capacity);
        let reader = BufReader::new(file);
        reader.take(limit).read_to_end(&mut bytes).map_err(|err| {
            anyhow::anyhow!("failed to read policy file {}: {err}", path.display())
        })?;
        if bytes.len() > MAX_POLICY_BYTES {
            anyhow::bail!(
                "policy file is too large ({} bytes; max {} bytes)",
                bytes.len(),
                MAX_POLICY_BYTES
            );
        }

        String::from_utf8(bytes).map_err(|err| {
            anyhow::anyhow!("policy file {} is not valid UTF-8: {err}", path.display())
        })
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsOpenedFileInfo {
    file_attributes: u32,
    volume_serial_number: u32,
    file_index: u64,
    file_size: u64,
}

#[cfg(windows)]
impl WindowsOpenedFileInfo {
    fn identity(self) -> (u32, u64) {
        (self.volume_serial_number, self.file_index)
    }
}

fn open_policy_file_nofollow(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    configure_open_options_nofollow(&mut options);
    options
        .open(path)
        .map_err(|err| anyhow::anyhow!("failed to open policy file {}: {err}", path.display()))
}

#[cfg(unix)]
fn configure_open_options_nofollow(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_open_options_nofollow(options: &mut std::fs::OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_open_options_nofollow(_options: &mut std::fs::OpenOptions) {}

#[cfg(windows)]
fn query_open_policy_file_info(
    path: &Path,
    file: &std::fs::File,
) -> anyhow::Result<WindowsOpenedFileInfo> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;

    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a live Windows handle and `info` points to writable memory.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!(
            "failed to query opened policy file {}: {err}",
            path.display()
        );
    }

    // SAFETY: `GetFileInformationByHandle` succeeded and initialized `info`.
    let info = unsafe { info.assume_init() };
    Ok(WindowsOpenedFileInfo {
        file_attributes: info.dwFileAttributes,
        volume_serial_number: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        file_size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    })
}

#[cfg(windows)]
fn ensure_windows_regular_policy_file(path: &Path, file_attributes: u32) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if (file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        anyhow::bail!(
            "policy path must not be a symlink or reparse point: {}",
            path.display()
        );
    }
    if (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
        anyhow::bail!("policy path is not a regular file: {}", path.display());
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_same_file(
    path: &Path,
    before_open: &std::fs::Metadata,
    after_open: &std::fs::Metadata,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if before_open.dev() != after_open.dev() || before_open.ino() != after_open.ino() {
            anyhow::bail!("policy path changed while opening: {}", path.display());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        if before_open.volume_serial_number() != after_open.volume_serial_number()
            || before_open.file_index() != after_open.file_index()
        {
            anyhow::bail!("policy path changed while opening: {}", path.display());
        }
    }
    Ok(())
}

fn policy_format(path: &Path) -> anyhow::Result<PolicyFormat> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("json") => Ok(PolicyFormat::Json),
        Some("toml") => Ok(PolicyFormat::Toml),
        Some("yaml" | "yml") => Ok(PolicyFormat::Yaml),
        Some(other) => anyhow::bail!(
            "unsupported policy extension: {other} (expected .json, .toml, .yaml, or .yml)"
        ),
        None => anyhow::bail!(
            "policy file must use an explicit extension (.json, .toml, .yaml, or .yml)"
        ),
    }
}

fn parse_policy_str(
    raw: &str,
    format: PolicyFormat,
    trust_mode: TrustMode,
    path: Option<&Path>,
) -> anyhow::Result<ServicePolicy> {
    parse_policy_str_with(raw, format, trust_mode, path, |name| std::env::var(name))
}

fn parse_policy_str_with(
    raw: &str,
    format: PolicyFormat,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    match format {
        PolicyFormat::Json => parse_json_policy(raw, trust_mode, path, lookup),
        PolicyFormat::Toml => parse_toml_policy(raw, trust_mode, path, lookup),
        PolicyFormat::Yaml => parse_yaml_policy(raw, trust_mode, path, lookup),
    }
}

fn parse_json_policy(
    raw: &str,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    let mut value: serde_json::Value = serde_json::from_str(raw).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse JSON policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse JSON policy: {err}"),
    })?;
    transform_json_value(&mut value, trust_mode, lookup)?;
    enforce_interpolated_size_json(&value)?;
    serde_json::from_value(value).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse JSON policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse JSON policy: {err}"),
    })
}

fn parse_toml_policy(
    raw: &str,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    let mut value: toml::Value = toml::from_str(raw).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse TOML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse TOML policy: {err}"),
    })?;
    transform_toml_value(&mut value, trust_mode, lookup)?;
    enforce_interpolated_size_toml(&value)?;
    value.try_into().map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse TOML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse TOML policy: {err}"),
    })
}

fn parse_yaml_policy(
    raw: &str,
    trust_mode: TrustMode,
    path: Option<&Path>,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<ServicePolicy> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(raw).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse YAML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse YAML policy: {err}"),
    })?;
    transform_yaml_value(&mut value, trust_mode, lookup)?;
    enforce_interpolated_size_yaml(&value)?;
    serde_yaml::from_value(value).map_err(|err| match path {
        Some(path) => anyhow::anyhow!("failed to parse YAML policy {}: {err}", path.display()),
        None => anyhow::anyhow!("failed to parse YAML policy: {err}"),
    })
}

fn enforce_interpolated_size_json(value: &serde_json::Value) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| anyhow::anyhow!("failed to serialize interpolated JSON policy: {err}"))?;
    ensure_interpolated_size(bytes.len())
}

fn enforce_interpolated_size_toml(value: &toml::Value) -> anyhow::Result<()> {
    let rendered = toml::to_string(value)
        .map_err(|err| anyhow::anyhow!("failed to serialize interpolated TOML policy: {err}"))?;
    ensure_interpolated_size(rendered.len())
}

fn enforce_interpolated_size_yaml(value: &serde_yaml::Value) -> anyhow::Result<()> {
    let rendered = serde_yaml::to_string(value)
        .map_err(|err| anyhow::anyhow!("failed to serialize interpolated YAML policy: {err}"))?;
    ensure_interpolated_size(rendered.len())
}

fn ensure_interpolated_size(len: usize) -> anyhow::Result<()> {
    if len > MAX_POLICY_BYTES {
        anyhow::bail!(
            "policy after env interpolation is too large ({} bytes; max {} bytes)",
            len,
            MAX_POLICY_BYTES
        );
    }
    Ok(())
}

fn transform_json_value(
    value: &mut serde_json::Value,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<()> {
    match value {
        serde_json::Value::String(string) => {
            let next = process_string_value(string, trust_mode, lookup)?;
            if let Cow::Owned(next) = next {
                *string = next;
            }
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for value in values {
                transform_json_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                transform_json_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(())
        }
    }
}

fn transform_toml_value(
    value: &mut toml::Value,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<()> {
    match value {
        toml::Value::String(string) => {
            let next = process_string_value(string, trust_mode, lookup)?;
            if let Cow::Owned(next) = next {
                *string = next;
            }
            Ok(())
        }
        toml::Value::Array(values) => {
            for value in values {
                transform_toml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        toml::Value::Table(values) => {
            for (_, value) in values.iter_mut() {
                transform_toml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => Ok(()),
    }
}

fn transform_yaml_value(
    value: &mut serde_yaml::Value,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
) -> anyhow::Result<()> {
    match value {
        serde_yaml::Value::String(string) => {
            let next = process_string_value(string, trust_mode, lookup)?;
            if let Cow::Owned(next) = next {
                *string = next;
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                transform_yaml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_yaml::Value::Mapping(values) => {
            for value in values.values_mut() {
                transform_yaml_value(value, trust_mode, lookup)?;
            }
            Ok(())
        }
        serde_yaml::Value::Null
        | serde_yaml::Value::Bool(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::Tagged(_) => Ok(()),
    }
}

fn process_string_value(
    input: &str,
    trust_mode: TrustMode,
    lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<Cow<'_, str>> {
    match trust_mode {
        TrustMode::Trusted => interpolate_env_with(input, lookup),
        TrustMode::Untrusted => reject_env_interpolation(input),
    }
}

fn reject_env_interpolation(input: &str) -> anyhow::Result<Cow<'_, str>> {
    if input.contains("${") {
        anyhow::bail!(
            "policy env interpolation is not allowed in trust_mode=untrusted (found '${{')"
        );
    }
    Ok(Cow::Borrowed(input))
}

fn interpolate_env_with(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<Cow<'_, str>> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());

    let mut idx: usize = 0;
    let mut last: usize = 0;
    let mut changed = false;

    while idx + 1 < bytes.len() {
        if bytes[idx] == b'$' && bytes[idx + 1] == b'{' {
            out.push_str(&raw[last..idx]);
            let start = idx + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end >= bytes.len() {
                anyhow::bail!("policy env interpolation: unterminated ${{...}}");
            }
            let name = &raw[start..end];
            if !is_valid_env_var_name(name) {
                anyhow::bail!("policy env interpolation: invalid env var name {name:?}");
            }
            let value = lookup(name).map_err(|_| {
                anyhow::anyhow!("policy env interpolation: env var {name:?} is not set")
            })?;
            out.push_str(&value);
            changed = true;
            idx = end + 1;
            last = idx;
            continue;
        }

        idx += 1;
    }

    if !changed {
        return Ok(Cow::Borrowed(raw));
    }

    out.push_str(&raw[last..]);
    Ok(Cow::Owned(out))
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn validate_trust_mode(
    policy: &ServicePolicy,
    trust_mode: TrustMode,
    unsafe_no_auth: bool,
) -> anyhow::Result<()> {
    if trust_mode != TrustMode::Untrusted {
        return Ok(());
    }

    if unsafe_no_auth {
        anyhow::bail!("trust_mode=untrusted forbids --unsafe-no-auth");
    }

    if policy.permissions.write || policy.permissions.patch || policy.permissions.delete {
        anyhow::bail!("trust_mode=untrusted forbids write/patch/delete permissions");
    }

    if policy.permissions.allow_full_scan {
        anyhow::bail!("trust_mode=untrusted forbids permissions.allow_full_scan");
    }

    if policy.limits.max_walk_ms.is_none() {
        anyhow::bail!("trust_mode=untrusted requires limits.max_walk_ms");
    }

    let defaults = ServiceLimits::default();
    enforce_untrusted_usize_limit(
        "limits.max_concurrency_io",
        policy.limits.max_concurrency_io,
        defaults.max_concurrency_io,
    )?;
    enforce_untrusted_usize_limit(
        "limits.max_concurrency_scan",
        policy.limits.max_concurrency_scan,
        defaults.max_concurrency_scan,
    )?;
    enforce_untrusted_u32_limit(
        "limits.max_db_connections",
        policy.limits.max_db_connections,
        defaults.max_db_connections,
    )?;
    let estimated_scan_inflight_bytes = estimate_scan_inflight_bytes(policy);
    if estimated_scan_inflight_bytes > MAX_UNTRUSTED_SCAN_INFLIGHT_BYTES {
        anyhow::bail!(
            "trust_mode=untrusted requires estimated scan in-flight bytes <= {} (got {})",
            MAX_UNTRUSTED_SCAN_INFLIGHT_BYTES,
            estimated_scan_inflight_bytes
        );
    }

    if policy.limits.max_requests_per_ip_per_sec == 0 {
        anyhow::bail!(
            "trust_mode=untrusted requires per-IP rate limiting (limits.max_requests_per_ip_per_sec > 0)"
        );
    }

    if policy.audit.jsonl_path.is_some() {
        anyhow::bail!("trust_mode=untrusted forbids audit.jsonl_path");
    }

    for (idx, token) in policy.auth.tokens.iter().enumerate() {
        if token.token_env_var.is_some() {
            anyhow::bail!("trust_mode=untrusted forbids auth.tokens[{idx}].token_env_var");
        }
    }

    Ok(())
}

fn enforce_untrusted_usize_limit(
    field: &str,
    actual: usize,
    max_allowed: usize,
) -> anyhow::Result<()> {
    if actual > max_allowed {
        anyhow::bail!("trust_mode=untrusted requires {field} <= {max_allowed} (got {actual})");
    }
    Ok(())
}

fn enforce_untrusted_u32_limit(field: &str, actual: u32, max_allowed: u32) -> anyhow::Result<()> {
    if actual > max_allowed {
        anyhow::bail!("trust_mode=untrusted requires {field} <= {max_allowed} (got {actual})");
    }
    Ok(())
}

fn estimate_scan_inflight_bytes(policy: &ServicePolicy) -> u64 {
    let per_request_bytes = if policy.secrets.redact_regexes.is_empty() {
        policy.limits.max_read_bytes
    } else {
        policy.limits.max_read_bytes.saturating_mul(2)
    };
    per_request_bytes.saturating_mul(policy.limits.max_concurrency_scan as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::process::Command;

    use db_vfs_core::policy::Permissions;

    use crate::policy::{AuthPolicy, AuthToken, ServiceLimits, ServicePolicy};
    use tempfile::tempdir;

    fn baseline_untrusted_policy() -> ServicePolicy {
        ServicePolicy {
            permissions: Permissions {
                read: true,
                glob: true,
                grep: true,
                ..Permissions::default()
            },
            limits: ServiceLimits {
                max_walk_ms: Some(1000),
                max_requests_per_ip_per_sec: 10,
                max_requests_burst_per_ip: 10,
                max_rate_limit_ips: 4,
                ..ServiceLimits::default()
            },
            ..ServicePolicy::default()
        }
    }

    #[test]
    fn interpolate_env_replaces_vars() {
        let key = format!("DB_VFS_TEST_ENV_{}", std::process::id());
        let raw = format!("hello ${{{key}}}!");
        let out = interpolate_env_with(&raw, |name| {
            if name == key.as_str() {
                return Ok("world".to_string());
            }
            Err(std::env::VarError::NotPresent)
        })
        .unwrap();
        assert_eq!(out, "hello world!");
    }

    #[test]
    fn interpolate_env_rejects_invalid_name() {
        let err = interpolate_env_with("x=${1BAD}", |_| Ok(String::new())).unwrap_err();
        assert!(err.to_string().contains("invalid env var name"));
    }

    #[test]
    fn trusted_interpolation_only_touches_string_values() {
        let policy = parse_policy_str_with(
            r#"
# ${COMMENT_ONLY}
[auth]
tokens = [{ token = "sha256:${TOKEN_HASH}", allowed_workspaces = ["${WORKSPACE}"] }]
"#,
            PolicyFormat::Toml,
            TrustMode::Trusted,
            None,
            lookup,
        )
        .unwrap_or_else(|err| panic!("unexpected parse error: {err}"));
        assert_eq!(
            policy.auth.tokens[0].token.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(policy.auth.tokens[0].allowed_workspaces, vec!["team-a"]);
    }

    #[test]
    fn untrusted_mode_ignores_comment_placeholders_but_rejects_string_values() {
        let trusted_comment_only = parse_policy_str(
            r#"
# ${COMMENT_ONLY}
[permissions]
read = true
[limits]
max_walk_ms = 1000
max_requests_per_ip_per_sec = 1
"#,
            PolicyFormat::Toml,
            TrustMode::Untrusted,
            None,
        )
        .unwrap();
        assert!(trusted_comment_only.permissions.read);

        let err = parse_policy_str(
            r#"
[permissions]
read = true
[limits]
max_walk_ms = 1000
max_requests_per_ip_per_sec = 1
[auth]
tokens = [{ token = "${TOKEN}", allowed_workspaces = ["ws"] }]
"#,
            PolicyFormat::Toml,
            TrustMode::Untrusted,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("policy env interpolation is not allowed in trust_mode=untrusted")
        );
    }

    #[test]
    fn trusted_json_interpolation_walks_nested_strings() {
        let policy = parse_policy_str_with(
            r#"{"auth":{"tokens":[{"token":"sha256:${TOKEN_HASH}","allowed_workspaces":["${WORKSPACE}"]}]}}"#,
            PolicyFormat::Json,
            TrustMode::Trusted,
            None,
            lookup,
        )
        .unwrap();
        assert_eq!(
            policy.auth.tokens[0].token.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(policy.auth.tokens[0].allowed_workspaces, vec!["team-a"]);
    }

    #[test]
    fn trusted_yaml_interpolation_walks_nested_strings() {
        let policy = parse_policy_str_with(
            r#"
auth:
  tokens:
    - token: "sha256:${TOKEN_HASH}"
      allowed_workspaces:
        - "${WORKSPACE}"
"#,
            PolicyFormat::Yaml,
            TrustMode::Trusted,
            None,
            lookup,
        )
        .unwrap();
        assert_eq!(
            policy.auth.tokens[0].token.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(policy.auth.tokens[0].allowed_workspaces, vec!["team-a"]);
    }

    #[test]
    fn policy_format_requires_explicit_known_extension() {
        let dir = tempdir().expect("tempdir");
        let missing_ext = dir.path().join("policy");
        std::fs::write(&missing_ext, "[permissions]\nread = true\n").expect("write policy");
        let err = policy_format(&missing_ext).expect_err("missing extension should fail");
        assert!(
            err.to_string().contains("explicit extension"),
            "unexpected error: {err}"
        );

        let yaml_path = dir.path().join("policy.yaml");
        std::fs::write(&yaml_path, "permissions:\n  read: true\n").expect("write yaml policy");
        assert!(matches!(
            policy_format(&yaml_path).expect("yaml policy format"),
            PolicyFormat::Yaml
        ));

        let yml_path = dir.path().join("policy.YML");
        std::fs::write(&yml_path, "permissions:\n  read: true\n").expect("write yml policy");
        assert!(matches!(
            policy_format(&yml_path).expect("yml policy format"),
            PolicyFormat::Yaml
        ));
    }

    #[test]
    fn read_policy_file_rejects_non_regular_paths() {
        let dir = tempdir().expect("tempdir");
        let err = read_policy_file(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("policy path is not a regular file")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn ensure_same_file_rejects_replaced_regular_file() {
        let dir = tempdir().expect("tempdir");
        let first = dir.path().join("first.toml");
        let second = dir.path().join("second.toml");
        std::fs::write(&first, "[permissions]\nread = true\n").expect("write first policy");
        std::fs::write(&second, "[permissions]\nread = true\n").expect("write second policy");

        let first_meta = std::fs::metadata(&first).expect("first metadata");
        let second_meta = std::fs::metadata(&second).expect("second metadata");
        let err = ensure_same_file(Path::new("policy.toml"), &first_meta, &second_meta)
            .expect_err("different files should be rejected");
        assert!(err.to_string().contains("changed while opening"));
    }

    #[cfg(unix)]
    #[test]
    fn read_policy_file_rejects_symlinks_without_following_them() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("policy.toml");
        std::fs::write(&target, "[permissions]\nread = true\n").expect("write target policy");

        let link = dir.path().join("policy-link.toml");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = read_policy_file(&link).unwrap_err();
        assert!(err.to_string().contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn read_policy_file_rejects_fifo_without_opening_it() {
        let dir = tempdir().expect("tempdir");
        let fifo = dir.path().join("policy.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo command");
        assert!(status.success(), "mkfifo failed: {status}");

        let err = read_policy_file(&fifo).unwrap_err();
        assert!(
            err.to_string()
                .contains("policy path is not a regular file")
        );
    }

    #[test]
    fn untrusted_rejects_env_tokens_and_writes() {
        let policy = ServicePolicy {
            permissions: Permissions {
                write: true,
                ..baseline_untrusted_policy().permissions
            },
            auth: AuthPolicy {
                tokens: vec![AuthToken {
                    token: None,
                    token_env_var: Some("SECRET".to_string()),
                    allowed_workspaces: vec!["ws".to_string()],
                }],
            },
            ..baseline_untrusted_policy()
        };

        let err = validate_trust_mode(&policy, TrustMode::Untrusted, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbids write/patch/delete")
                || msg.contains("forbids auth.tokens[0].token_env_var"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn untrusted_rejects_elevated_resource_limits() {
        let defaults = ServiceLimits::default();
        let mut io_policy = baseline_untrusted_policy();
        io_policy.limits.max_concurrency_io = defaults.max_concurrency_io.saturating_add(1);
        let io_err = validate_trust_mode(&io_policy, TrustMode::Untrusted, false)
            .expect_err("untrusted policy should reject elevated IO concurrency");
        assert!(
            io_err.to_string().contains("limits.max_concurrency_io"),
            "unexpected error: {io_err}"
        );

        let mut scan_policy = baseline_untrusted_policy();
        scan_policy.limits.max_concurrency_scan = defaults.max_concurrency_scan.saturating_add(1);
        let scan_err = validate_trust_mode(&scan_policy, TrustMode::Untrusted, false)
            .expect_err("untrusted policy should reject elevated scan concurrency");
        assert!(
            scan_err.to_string().contains("limits.max_concurrency_scan"),
            "unexpected error: {scan_err}"
        );

        let mut db_policy = baseline_untrusted_policy();
        db_policy.limits.max_db_connections = defaults.max_db_connections.saturating_add(1);
        let db_err = validate_trust_mode(&db_policy, TrustMode::Untrusted, false)
            .expect_err("untrusted policy should reject elevated DB connections");
        assert!(
            db_err.to_string().contains("limits.max_db_connections"),
            "unexpected error: {db_err}"
        );
    }

    #[test]
    fn untrusted_rejects_scan_memory_budget_amplification() {
        let mut policy = baseline_untrusted_policy();
        policy.limits.max_concurrency_scan = 8;
        policy.limits.max_read_bytes = (MAX_UNTRUSTED_SCAN_INFLIGHT_BYTES / 8).saturating_add(1);
        policy.secrets.redact_regexes = vec!["secret".to_string()];

        let err = validate_trust_mode(&policy, TrustMode::Untrusted, false)
            .expect_err("untrusted policy should reject oversized scan memory budget");
        assert!(
            err.to_string().contains("estimated scan in-flight bytes"),
            "unexpected error: {err}"
        );
    }

    fn parse_policy_str(
        raw: &str,
        format: PolicyFormat,
        trust_mode: TrustMode,
        path: Option<&Path>,
    ) -> anyhow::Result<ServicePolicy> {
        super::parse_policy_str(raw, format, trust_mode, path)
    }

    fn parse_policy_str_with(
        raw: &str,
        format: PolicyFormat,
        trust_mode: TrustMode,
        path: Option<&Path>,
        lookup: impl FnMut(&str) -> Result<String, std::env::VarError> + Copy,
    ) -> anyhow::Result<ServicePolicy> {
        super::parse_policy_str_with(raw, format, trust_mode, path, lookup)
    }

    fn interpolate_env_with(
        raw: &str,
        lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
    ) -> anyhow::Result<String> {
        super::interpolate_env_with(raw, lookup).map(Cow::into_owned)
    }

    fn lookup(name: &str) -> Result<String, std::env::VarError> {
        match name {
            "TOKEN_HASH" => Ok("abc123".to_string()),
            "WORKSPACE" => Ok("team-a".to_string()),
            _ => Err(std::env::VarError::NotPresent),
        }
    }
}
