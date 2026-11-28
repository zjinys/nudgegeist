use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use std::time::Instant;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::config::{MatchSource, TransportMode, WatchdogConfig, resolve_luvus_socket_path};

static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfo {
    pub pane: String,
    pub agent: String,
    pub status: String,
    pub name: Option<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuvusEvent {
    AgentStatus {
        pane: String,
        status: String,
        agent: String,
        sequence: Option<u64>,
    },
    PaneClosed {
        pane: String,
        sequence: Option<u64>,
    },
    ResyncRequired {
        sequence: Option<u64>,
    },
    Other {
        sequence: Option<u64>,
    },
}

/// Returns `true` when a `luvus` pane entry represents a plain shell, closed/exited
/// process, or non-agent placeholder that should not be tracked or shown as a live agent.
pub fn is_non_agent_pane(agent: &str, status: &str) -> bool {
    let status_norm = status.trim().to_ascii_lowercase();
    if matches!(
        status_norm.as_str(),
        "exited" | "closed" | "stopped" | "terminated" | "dead"
    ) {
        return true;
    }

    let trimmed = agent.trim();
    let basename = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .trim_start_matches('-');
    let lowered = basename.to_ascii_lowercase();
    let norm = lowered.strip_suffix(".exe").unwrap_or(&lowered);

    matches!(
        norm,
        "" | "unknown"
            | "none"
            | "shell"
            | "terminal"
            | "view"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "ash"
            | "ksh"
            | "mksh"
            | "csh"
            | "tcsh"
            | "nu"
            | "nushell"
            | "xonsh"
            | "elvish"
            | "ion"
            | "oil"
            | "osh"
            | "pwsh"
            | "powershell"
            | "cmd"
            | "conhost"
            | "wsl"
            | "wslhost"
            | "wt"
            | "windowsterminal"
            | "tmux"
            | "screen"
    )
}

pub trait LuvusClient: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentInfo>>;
    fn read_pane(&self, pane: &str, lines: usize, source: MatchSource) -> Result<String>;
    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()>;
    fn send_text(&self, pane: &str, text: &str) -> Result<()>;
}

/// Cross-platform UHP stream (`UnixStream` on Unix, Named Pipe on Windows).
pub enum UhpEndpointStream {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    Windows(win_pipe::WinNamedPipeStream),
}

impl UhpEndpointStream {
    pub fn connect(endpoint: &Path, timeout: Duration) -> Result<Self> {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(endpoint).with_context(|| {
                format!("连接 luvus UHP socket 失败: {}", endpoint.display())
            })?;
            stream.set_read_timeout(Some(timeout)).ok();
            stream.set_write_timeout(Some(timeout)).ok();
            Ok(Self::Unix(stream))
        }
        #[cfg(windows)]
        {
            let pipe_addr = windows_pipe_name_from_socket_path(endpoint);
            let pipe = win_pipe::WinNamedPipeStream::connect(&pipe_addr, timeout)
                .with_context(|| format!("连接 luvus Windows Named Pipe 失败: {pipe_addr}"))?;
            Ok(Self::Windows(pipe))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (endpoint, timeout);
            anyhow::bail!("当前平台不支持直连 UHP 本地端点");
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) {
        #[cfg(unix)]
        match self {
            Self::Unix(s) => {
                let _ = s.set_read_timeout(timeout);
            }
        }
        #[cfg(windows)]
        match self {
            Self::Windows(s) => s.set_read_timeout(timeout),
        }
    }
}

impl Read for UhpEndpointStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        match self {
            Self::Unix(s) => s.read(buf),
        }
        #[cfg(windows)]
        match self {
            Self::Windows(s) => s.read(buf),
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = buf;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }
    }
}

impl Write for UhpEndpointStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        match self {
            Self::Unix(s) => s.write(buf),
        }
        #[cfg(windows)]
        match self {
            Self::Windows(s) => s.write(buf),
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = buf;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        match self {
            Self::Unix(s) => s.flush(),
        }
        #[cfg(windows)]
        match self {
            Self::Windows(s) => s.flush(),
        }
        #[cfg(not(any(unix, windows)))]
        Ok(())
    }
}

#[cfg(windows)]
mod win_pipe {
    use std::ffi::{OsStr, c_void};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    const NMPWAIT_NOWAIT: u32 = 1;
    const ERROR_BROKEN_PIPE: i32 = 109;
    const ERROR_SEM_TIMEOUT: i32 = 121;
    const ERROR_PIPE_BUSY: i32 = 231;
    const ERROR_PIPE_NOT_CONNECTED: i32 = 233;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> *mut c_void;
        fn WaitNamedPipeW(lp_named_pipe_name: *const u16, n_time_out: u32) -> i32;
        fn PeekNamedPipe(
            h_named_pipe: *mut c_void,
            lp_buffer: *mut c_void,
            n_buffer_size: u32,
            lp_bytes_read: *mut u32,
            lp_total_bytes_avail: *mut u32,
            lp_bytes_left_this_message: *mut u32,
        ) -> i32;
    }

    fn to_wide_z(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub fn pipe_exists(pipe_name: &str) -> bool {
        let wide = to_wide_z(pipe_name);
        let ok = unsafe { WaitNamedPipeW(wide.as_ptr(), NMPWAIT_NOWAIT) };
        if ok != 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() == Some(ERROR_SEM_TIMEOUT)
    }

    pub struct WinNamedPipeStream {
        file: File,
        read_timeout_ms: AtomicU64,
    }

    impl WinNamedPipeStream {
        pub fn connect(pipe_name: &str, timeout: Duration) -> io::Result<Self> {
            let wide = to_wide_z(pipe_name);
            let deadline = Instant::now() + timeout;
            loop {
                let handle = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
                    return Ok(Self {
                        file: File::from(owned),
                        read_timeout_ms: AtomicU64::new(timeout.as_millis() as u64),
                    });
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_PIPE_BUSY) {
                    return Err(err);
                }
                let rem = deadline.saturating_duration_since(Instant::now());
                if rem.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "named pipe connect timed out",
                    ));
                }
                let ms = u32::try_from(rem.as_millis().max(1)).unwrap_or(u32::MAX);
                let waited = unsafe { WaitNamedPipeW(wide.as_ptr(), ms) };
                if waited == 0 {
                    let werr = io::Error::last_os_error();
                    if werr.raw_os_error() == Some(ERROR_SEM_TIMEOUT) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "named pipe wait timed out",
                        ));
                    }
                    return Err(werr);
                }
            }
        }

        pub fn set_read_timeout(&self, timeout: Option<Duration>) {
            let ms = timeout
                .map(|d| u64::try_from(d.as_millis().max(1)).unwrap_or(u64::MAX))
                .unwrap_or(0);
            self.read_timeout_ms.store(ms, Ordering::Relaxed);
        }

        fn peek_available(&self) -> io::Result<u32> {
            let mut avail = 0u32;
            let ok = unsafe {
                PeekNamedPipe(
                    self.file.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0 {
                Ok(avail)
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    impl Read for WinNamedPipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let timeout_ms = self.read_timeout_ms.load(Ordering::Relaxed);
            if timeout_ms > 0 {
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                loop {
                    match self.peek_available() {
                        Ok(avail) if avail > 0 => break,
                        Ok(_) => {
                            let rem = deadline.saturating_duration_since(Instant::now());
                            if rem.is_zero() {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "named pipe read timed out",
                                ));
                            }
                            std::thread::sleep(rem.min(Duration::from_millis(20)));
                        }
                        Err(e)
                            if matches!(
                                e.raw_os_error(),
                                Some(ERROR_BROKEN_PIPE) | Some(ERROR_PIPE_NOT_CONNECTED)
                            ) =>
                        {
                            return Ok(0);
                        }
                        Err(e) => return Err(e),
                    }
                }
            }

            match self.file.read(buf) {
                Ok(n) => Ok(n),
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(ERROR_BROKEN_PIPE) | Some(ERROR_PIPE_NOT_CONNECTED)
                    ) =>
                {
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }
    }

    impl Write for WinNamedPipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (&self.file).write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&self.file).flush()
        }
    }
}

/// Convert a logical Luvus socket path (e.g. `~/.luvus/luvus.sock`) into Luvus's Windows Named Pipe address.
pub fn windows_pipe_name_from_socket_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if raw.len() >= 9 && raw[..9].eq_ignore_ascii_case(r"\\.\pipe\") {
        return raw.into_owned();
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!(r"\\.\pipe\luvus-{:016x}", hasher.finish())
}

/// Extract a running Windows Named Pipe UHP endpoint address from `luvus session list --json`.
pub fn parse_session_list_pipe_address(raw: &str) -> Option<String> {
    let val: Value = serde_json::from_str(raw.trim()).ok()?;
    let sessions = val.get("sessions")?.as_array()?;
    let pick = |only_default: bool| -> Option<String> {
        for s in sessions {
            if !s.get("running").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            if only_default && !s.get("default").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            let transport = s
                .pointer("/endpoint/transport")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if transport == "windows_named_pipe"
                && let Some(addr) = s.pointer("/endpoint/address").and_then(|v| v.as_str())
                && !addr.trim().is_empty()
            {
                return Some(addr.to_string());
            }
        }
        None
    };
    pick(true).or_else(|| pick(false))
}

#[cfg(windows)]
fn discover_windows_pipe_cached(cfg: &WatchdogConfig) -> Option<PathBuf> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<(String, Option<(Instant, Option<PathBuf>)>)>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((String::new(), None)));
    let mut guard = cache.lock().ok()?;
    if guard.0 == cfg.luvus_bin
        && let Some((ts, ref cached)) = guard.1
        && ts.elapsed() < Duration::from_secs(15)
    {
        return cached.clone();
    }
    let output = new_luvus_command(&cfg.luvus_bin)
        .args(["session", "list", "--json"])
        .output()
        .ok();
    let resolved = output.and_then(|out| {
        if !out.status.success() {
            return None;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        parse_session_list_pipe_address(&txt).map(PathBuf::from)
    });
    *guard = (cfg.luvus_bin.clone(), Some((Instant::now(), resolved.clone())));
    resolved
}

/// Resolve the UHP endpoint path and whether it is currently reachable (`unix_socket` or `windows_named_pipe`).
pub fn resolve_uhp_endpoint(cfg: &WatchdogConfig) -> (PathBuf, bool) {
    let sock_path = resolve_luvus_socket_path(cfg);
    #[cfg(unix)]
    {
        let avail = sock_path.exists();
        (sock_path, avail)
    }
    #[cfg(windows)]
    {
        let pipe_name = windows_pipe_name_from_socket_path(&sock_path);
        if win_pipe::pipe_exists(&pipe_name) {
            return (PathBuf::from(pipe_name), true);
        }
        if cfg.luvus_socket_path.trim().is_empty()
            && std::env::var_os("LUVUS_SOCKET_PATH").is_none_or(|v| v.is_empty())
            && let Some(discovered) = discover_windows_pipe_cached(cfg)
            && win_pipe::pipe_exists(&discovered.to_string_lossy())
        {
            return (discovered, true);
        }
        (PathBuf::from(pipe_name), false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        (sock_path, false)
    }
}

/// Direct UHP 1.0 (NDJSON) client over Unix Domain Socket (Unix) or Named Pipe (Windows).
#[derive(Debug, Clone)]
pub struct UnixSocketUhpClient {
    pub socket_path: PathBuf,
    pub timeout: Duration,
}

impl UnixSocketUhpClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut stream = UhpEndpointStream::connect(&self.socket_path, self.timeout)?;

        let req_id = format!("ng-{}", NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed));
        let payload = json!({
            "id": req_id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&payload)?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .with_context(|| format!("写入 UHP 请求 {method} 失败"))?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        loop {
            let mut resp_line = String::new();
            let n = reader
                .read_line(&mut resp_line)
                .with_context(|| format!("读取 UHP 响应 {method} 失败"))?;
            if n == 0 {
                anyhow::bail!("luvus UHP 连接在响应 {method} 前已关闭");
            }
            let trimmed = resp_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = serde_json::from_str(trimmed)
                .with_context(|| format!("解析 UHP 响应 JSON 失败: {trimmed}"))?;
            if val.get("id").and_then(|v| v.as_str()) != Some(req_id.as_str()) {
                // Skip interleaved event frames if any appear before our response.
                continue;
            }
            if let Some(err) = val.get("error") {
                let code = err
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown_error");
                let msg = err
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未知 UHP 错误");
                anyhow::bail!("UHP {method} 返回错误 [{code}]: {msg}");
            }
            return Ok(val.get("result").cloned().unwrap_or_else(|| json!({})));
        }
    }

    /// Connect to UHP endpoint and subscribe to live events (`events.subscribe`).
    pub fn subscribe_events(
        &self,
        after_sequence: Option<u64>,
    ) -> Result<BufReader<UhpEndpointStream>> {
        let mut stream = UhpEndpointStream::connect(&self.socket_path, Duration::from_secs(5))?;

        let req_id = format!("ng-sub-{}", NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed));
        let params = match after_sequence {
            Some(seq) => json!({ "after_sequence": seq }),
            None => json!({}),
        };
        let payload = json!({
            "id": req_id,
            "method": "events.subscribe",
            "params": params,
        });
        let mut line = serde_json::to_string(&payload)?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        loop {
            let mut ack_line = String::new();
            let n = reader
                .read_line(&mut ack_line)
                .context("读取 UHP events.subscribe 确认失败")?;
            if n == 0 {
                anyhow::bail!("events.subscribe 未收到确认即断开");
            }
            let trimmed = ack_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = serde_json::from_str(trimmed)
                .with_context(|| format!("解析 events.subscribe 响应失败: {trimmed}"))?;
            if val.get("id").and_then(|v| v.as_str()) == Some(req_id.as_str()) {
                if let Some(err) = val.get("error") {
                    let msg = err
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("订阅失败");
                    anyhow::bail!("UHP events.subscribe 错误: {msg}");
                }
                break;
            }
        }

        // Short read timeout allows the background loop to process pending cooldown rechecks & stop signal promptly.
        reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(250)));
        Ok(reader)
    }
}

impl LuvusClient for UnixSocketUhpClient {
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let result = self.call("agent.list", json!({}))?;
        parse_agent_list_value(&result)
    }

    fn read_pane(&self, pane: &str, lines: usize, source: MatchSource) -> Result<String> {
        let source_arg = match source {
            MatchSource::Visible => "visible",
            MatchSource::Recent => "recent",
        };
        let result = self.call(
            "agent.read",
            json!({
                "target": pane,
                "lines": lines.max(1),
                "source": source_arg,
            }),
        )?;
        Ok(extract_text_from_value(&result))
    }

    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()> {
        let _ = self.call(
            "agent.keys",
            json!({
                "target": pane,
                "keys": keys,
            }),
        )?;
        Ok(())
    }

    fn send_text(&self, pane: &str, text: &str) -> Result<()> {
        let _ = self.call(
            "agent.send",
            json!({
                "target": pane,
                "text": text,
            }),
        )?;
        Ok(())
    }
}

/// Installation status of the `luvus` CLI binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuvusInstallStatus {
    pub installed: bool,
    pub resolved_path: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Resolve the `luvus` executable path from explicit path, `PATH`, or standard user install dirs.
pub fn resolve_luvus_executable(configured_bin: &str) -> Option<PathBuf> {
    let raw = configured_bin.trim();
    let bin = if raw.is_empty() { "luvus" } else { raw };
    let has_sep = bin.contains('/') || bin.contains('\\');

    let candidates: Vec<String> = {
        #[cfg(windows)]
        {
            if bin.to_ascii_lowercase().ends_with(".exe") {
                vec![bin.to_string()]
            } else {
                vec![format!("{bin}.exe"), bin.to_string()]
            }
        }
        #[cfg(not(windows))]
        {
            vec![bin.to_string()]
        }
    };

    if has_sep {
        for cand in candidates {
            let p = PathBuf::from(&cand);
            if is_executable_file(&p) {
                return Some(p);
            }
        }
        return None;
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for cand in &candidates {
                let full = dir.join(cand);
                if is_executable_file(&full) {
                    return Some(full);
                }
            }
        }
    }

    // Also probe standard install directories in case GUI launch environment omitted them from PATH.
    if bin.eq_ignore_ascii_case("luvus") || bin.eq_ignore_ascii_case("luvus.exe") {
        let mut extra_dirs = Vec::new();
        if let Some(home) = dirs::home_dir() {
            extra_dirs.push(home.join(".local").join("bin"));
            extra_dirs.push(home.join(".cargo").join("bin"));
        }
        #[cfg(unix)]
        {
            extra_dirs.push(PathBuf::from("/opt/homebrew/bin"));
            extra_dirs.push(PathBuf::from("/usr/local/bin"));
            extra_dirs.push(PathBuf::from("/usr/bin"));
        }
        #[cfg(windows)]
        {
            if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
                let base = PathBuf::from(local_app_data);
                extra_dirs.push(base.join("Programs").join("luvus"));
                extra_dirs.push(base.join("luvus"));
            }
        }

        for dir in extra_dirs {
            for cand in &candidates {
                let full = dir.join(cand);
                if is_executable_file(&full) {
                    return Some(full);
                }
            }
        }
    }

    None
}

/// Build a `luvus` CLI command without flashing a console window on Windows.
fn new_luvus_command(bin_path: &str) -> Command {
    let program = resolve_luvus_executable(bin_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            let trimmed = bin_path.trim();
            if trimmed.is_empty() {
                "luvus".to_string()
            } else {
                trimmed.to_string()
            }
        });
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = &mut cmd;
    cmd
}

/// Detect whether `luvus` is installed and runnable, returning its resolved path and version.
pub fn detect_luvus_installation(configured_bin: &str) -> LuvusInstallStatus {
    let resolved = resolve_luvus_executable(configured_bin);
    let invoke_target = resolved
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            let trimmed = configured_bin.trim();
            if trimmed.is_empty() {
                "luvus".to_string()
            } else {
                trimmed.to_string()
            }
        });

    let mut cmd = Command::new(&invoke_target);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    match cmd.arg("--version").output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let version = stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map(|s| s.to_string());
            LuvusInstallStatus {
                installed: true,
                resolved_path: resolved
                    .map(|p| p.display().to_string())
                    .or(Some(invoke_target)),
                version,
                error: None,
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                format!("exit code {:?}", out.status.code())
            } else {
                stderr
            };
            LuvusInstallStatus {
                installed: false,
                resolved_path: resolved.map(|p| p.display().to_string()),
                version: None,
                error: Some(detail),
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => LuvusInstallStatus {
            installed: false,
            resolved_path: None,
            version: None,
            error: None,
        },
        Err(err) => LuvusInstallStatus {
            installed: false,
            resolved_path: resolved.map(|p| p.display().to_string()),
            version: None,
            error: Some(err.to_string()),
        },
    }
}

/// Human-readable one-line install command for the current platform.
pub fn luvus_install_command_preview() -> &'static str {
    #[cfg(windows)]
    {
        "irm https://luvus.dev/install.ps1 | iex"
    }
    #[cfg(not(windows))]
    {
        "curl -fsSL https://luvus.dev/install.sh | sh"
    }
}

/// Install `luvus` CLI using the official platform installer script and verify detection.
pub fn install_luvus_cli() -> Result<LuvusInstallStatus> {
    #[cfg(windows)]
    let output = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = Command::new("powershell");
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "irm https://luvus.dev/install.ps1 | iex",
        ])
        .output()
        .context("调用 PowerShell 安装 luvus 失败")?
    };

    #[cfg(not(windows))]
    let output = {
        let mut path_entries: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        if let Some(home) = dirs::home_dir() {
            for extra in [home.join(".local/bin"), home.join(".cargo/bin")] {
                if !path_entries.contains(&extra) {
                    path_entries.push(extra);
                }
            }
        }
        let joined_path = std::env::join_paths(path_entries).unwrap_or_default();
        Command::new("sh")
            .env("PATH", joined_path)
            .args(["-c", "set -eu; curl -fsSL https://luvus.dev/install.sh | sh"])
            .output()
            .context("执行 `curl -fsSL https://luvus.dev/install.sh | sh` 失败")?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!(
            "安装 luvus 失败 ({}): {}",
            output
                .status
                .code()
                .map(|c| format!("exit {c}"))
                .unwrap_or_else(|| "terminated".to_string()),
            detail
        );
    }

    let status = detect_luvus_installation("luvus");
    if !status.installed {
        anyhow::bail!(
            "安装脚本执行完成，但未在 PATH 或常用目录检测到 luvus 可执行文件{}",
            status
                .error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        );
    }
    Ok(status)
}

/// CLI subprocess client invoking the `luvus` binary directly.
#[derive(Debug, Clone)]
pub struct RealLuvusClient {
    pub bin_path: String,
}

impl RealLuvusClient {
    pub fn new(bin_path: impl Into<String>) -> Self {
        Self {
            bin_path: bin_path.into(),
        }
    }

    pub fn spawn_events_process(&self) -> Result<Child> {
        new_luvus_command(&self.bin_path)
            .arg("events")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("启动 `{} events` 失败", self.bin_path))
    }
}

impl LuvusClient for RealLuvusClient {
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let output = new_luvus_command(&self.bin_path)
            .args(["agent", "list"])
            .output()
            .with_context(|| format!("执行 `{} agent list` 失败", self.bin_path))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("luvus agent list 退出异常: {}", stderr.trim());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_agent_list_json(&stdout)
    }

    fn read_pane(&self, pane: &str, lines: usize, source: MatchSource) -> Result<String> {
        let source_arg = match source {
            MatchSource::Visible => "visible",
            MatchSource::Recent => "recent",
        };
        let lines_str = lines.max(1).to_string();
        let output = new_luvus_command(&self.bin_path)
            .args([
                "agent",
                "read",
                pane,
                "--source",
                source_arg,
                "--lines",
                &lines_str,
            ])
            .output()
            .with_context(|| format!("执行 `{} agent read {pane}` 失败", self.bin_path))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("luvus agent read 失败: {}", stderr.trim());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_read_pane_json(&stdout)
    }

    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()> {
        let mut cmd = new_luvus_command(&self.bin_path);
        cmd.args(["agent", "keys", pane]);
        for k in keys {
            cmd.arg(k);
        }
        let output = cmd
            .output()
            .with_context(|| format!("执行 `{} agent keys {pane}` 失败", self.bin_path))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("luvus agent keys 失败: {}", stderr.trim());
        }
        Ok(())
    }

    fn send_text(&self, pane: &str, text: &str) -> Result<()> {
        let output = new_luvus_command(&self.bin_path)
            .args(["agent", "send", pane, text])
            .output()
            .with_context(|| format!("执行 `{} agent send {pane}` 失败", self.bin_path))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("luvus agent send 失败: {}", stderr.trim());
        }
        Ok(())
    }
}

/// Transport-aware client supporting Auto (UHP Socket preferred, CLI fallback), Socket-only, or CLI-only.
#[derive(Debug, Clone)]
pub enum DynamicLuvusClient {
    Socket(UnixSocketUhpClient),
    Cli(RealLuvusClient),
}

impl DynamicLuvusClient {
    pub fn from_config(cfg: &WatchdogConfig) -> Self {
        match cfg.transport_mode {
            TransportMode::Socket => {
                let (endpoint, _) = resolve_uhp_endpoint(cfg);
                Self::Socket(UnixSocketUhpClient::new(endpoint))
            }
            TransportMode::Cli => Self::Cli(RealLuvusClient::new(&cfg.luvus_bin)),
            TransportMode::Auto => {
                let (endpoint, available) = resolve_uhp_endpoint(cfg);
                if available {
                    Self::Socket(UnixSocketUhpClient::new(endpoint))
                } else {
                    Self::Cli(RealLuvusClient::new(&cfg.luvus_bin))
                }
            }
        }
    }

    pub fn transport_label(&self) -> String {
        match self {
            Self::Socket(s) => {
                let raw = s.socket_path.to_string_lossy();
                if cfg!(windows) || raw.to_ascii_lowercase().starts_with(r"\\.\pipe\") {
                    format!("UHP Named Pipe ({})", s.socket_path.display())
                } else {
                    format!("UHP Socket ({})", s.socket_path.display())
                }
            }
            Self::Cli(c) => format!("CLI 子进程 ({})", c.bin_path),
        }
    }
}

impl LuvusClient for DynamicLuvusClient {
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        match self {
            Self::Socket(s) => s.list_agents(),
            Self::Cli(c) => c.list_agents(),
        }
    }

    fn read_pane(&self, pane: &str, lines: usize, source: MatchSource) -> Result<String> {
        match self {
            Self::Socket(s) => s.read_pane(pane, lines, source),
            Self::Cli(c) => c.read_pane(pane, lines, source),
        }
    }

    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()> {
        match self {
            Self::Socket(s) => s.send_keys(pane, keys),
            Self::Cli(c) => c.send_keys(pane, keys),
        }
    }

    fn send_text(&self, pane: &str, text: &str) -> Result<()> {
        match self {
            Self::Socket(s) => s.send_text(pane, text),
            Self::Cli(c) => c.send_text(pane, text),
        }
    }
}

pub fn parse_agent_list_json(raw: &str) -> Result<Vec<AgentInfo>> {
    let val: Value = serde_json::from_str(raw).context("解析 luvus agent list JSON 失败")?;
    parse_agent_list_value(&val)
}

pub fn parse_agent_list_value(val: &Value) -> Result<Vec<AgentInfo>> {
    let arr = val
        .pointer("/result/agents")
        .and_then(|v| v.as_array())
        .or_else(|| val.get("agents").and_then(|v| v.as_array()))
        .or_else(|| val.as_array());

    let Some(items) = arr else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for item in items {
        let Some(pane) = item.get("pane").and_then(|v| v.as_str()) else {
            continue;
        };
        if pane.trim().is_empty() {
            continue;
        }
        let agent = item
            .get("agent")
            .or_else(|| item.get("kind"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let status = item
            .get("status")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let cwd = item
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        out.push(AgentInfo {
            pane: pane.to_string(),
            agent,
            status,
            name,
            cwd,
        });
    }
    Ok(out)
}

pub fn parse_read_pane_json(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        return Ok(extract_text_from_value(&val));
    }
    Ok(String::new())
}

fn extract_text_from_value(val: &Value) -> String {
    if let Some(s) = val.as_str() {
        return s.to_string();
    }
    val.pointer("/result/text")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("text").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string()
}

pub fn parse_luvus_event_line(line: &str) -> Option<LuvusEvent> {
    let val: Value = serde_json::from_str(line.trim()).ok()?;
    let event = val.get("event").and_then(|v| v.as_str())?;
    let sequence = val.get("sequence").and_then(|v| v.as_u64());

    if event == "events.resync_required" {
        return Some(LuvusEvent::ResyncRequired { sequence });
    }

    if event == "pane.closed" || event == "terminal.closed" || event == "terminal.exited" {
        if let Some(pane) = val
            .pointer("/data/pane")
            .or_else(|| val.pointer("/data/pane_id"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return Some(LuvusEvent::PaneClosed {
                pane: pane.to_string(),
                sequence,
            });
        }
        return Some(LuvusEvent::Other { sequence });
    }

    if event != "agent_status" && event != "pane.agent_status_changed" {
        return Some(LuvusEvent::Other { sequence });
    }

    let pane = val.pointer("/data/pane").and_then(|v| v.as_str())?;
    if pane.is_empty() {
        return Some(LuvusEvent::Other { sequence });
    }
    let status = val
        .pointer("/data/status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let agent = val
        .pointer("/data/agent")
        .or_else(|| val.pointer("/data/kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    Some(LuvusEvent::AgentStatus {
        pane: pane.to_string(),
        status,
        agent,
        sequence,
    })
}
