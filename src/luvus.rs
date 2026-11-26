use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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
    ResyncRequired {
        sequence: Option<u64>,
    },
    Other {
        sequence: Option<u64>,
    },
}

pub trait LuvusClient: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentInfo>>;
    fn read_pane(&self, pane: &str, lines: usize, source: MatchSource) -> Result<String>;
    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()>;
    fn send_text(&self, pane: &str, text: &str) -> Result<()>;
}

/// Direct Unix Domain Socket client speaking Luvus UHP 1.0 (NDJSON).
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
        #[cfg(not(unix))]
        {
            let _ = (method, params);
            anyhow::bail!(
                "UHP Unix Domain Socket 仅支持 Unix 平台，请在 Windows 上使用 CLI 模式: {}",
                self.socket_path.display()
            );
        }

        #[cfg(unix)]
        {
            let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
                format!("连接 luvus UHP socket 失败: {}", self.socket_path.display())
            })?;
            stream.set_read_timeout(Some(self.timeout)).ok();
            stream.set_write_timeout(Some(self.timeout)).ok();

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
                    anyhow::bail!("luvus UHP socket 在响应 {method} 前已关闭");
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
    }

    /// Connect to UHP socket and subscribe to live events (`events.subscribe`).
    #[cfg(unix)]
    pub fn subscribe_events(&self, after_sequence: Option<u64>) -> Result<BufReader<UnixStream>> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!("订阅 UHP 事件流失败: {}", self.socket_path.display())
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

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
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
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
        Command::new(&self.bin_path)
            .arg("events")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("启动 `{} events` 失败", self.bin_path))
    }
}

impl LuvusClient for RealLuvusClient {
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let output = Command::new(&self.bin_path)
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
        let output = Command::new(&self.bin_path)
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
        let mut cmd = Command::new(&self.bin_path);
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
        let output = Command::new(&self.bin_path)
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
        let sock_path = resolve_luvus_socket_path(cfg);
        match cfg.transport_mode {
            TransportMode::Socket => Self::Socket(UnixSocketUhpClient::new(sock_path)),
            TransportMode::Cli => Self::Cli(RealLuvusClient::new(&cfg.luvus_bin)),
            TransportMode::Auto => {
                if cfg!(unix) && sock_path.exists() {
                    Self::Socket(UnixSocketUhpClient::new(sock_path))
                } else {
                    Self::Cli(RealLuvusClient::new(&cfg.luvus_bin))
                }
            }
        }
    }

    pub fn transport_label(&self) -> String {
        match self {
            Self::Socket(s) => format!("UHP Socket ({})", s.socket_path.display()),
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
