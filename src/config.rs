use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const RULES_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl AppPaths {
    pub fn resolve_default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let config_base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| home.join(".config"));
        let cache_base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| home.join(".cache"));

        Self {
            config_dir: config_base.join("nudgegeist"),
            cache_dir: cache_base.join("nudgegeist"),
        }
    }

    pub fn from_root(root: &Path) -> Self {
        Self {
            config_dir: root.join("config"),
            cache_dir: root.join("cache"),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }

    pub fn rules_file(&self) -> PathBuf {
        self.config_dir.join("rules.json")
    }

    pub fn audit_file(&self) -> PathBuf {
        self.cache_dir.join("audit.jsonl")
    }

    pub fn state_file(&self) -> PathBuf {
        self.cache_dir.join("state.json")
    }

    pub fn log_file(&self) -> PathBuf {
        self.cache_dir.join("watchdog.log")
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)
            .with_context(|| format!("创建配置目录失败: {}", self.config_dir.display()))?;
        fs::create_dir_all(&self.cache_dir)
            .with_context(|| format!("创建缓存目录失败: {}", self.cache_dir.display()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UiLanguage {
    #[default]
    Zh,
    En,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Auto,
    Socket,
    Cli,
}

impl TransportMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "auto (Socket优先)",
            Self::Socket => "socket (UHP直连)",
            Self::Cli => "cli (子进程)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchdogConfig {
    #[serde(default = "default_config_version")]
    pub version: u32,
    #[serde(default)]
    pub language: UiLanguage,
    #[serde(default)]
    pub transport_mode: TransportMode,
    #[serde(default)]
    pub luvus_socket_path: String,
    #[serde(default = "default_luvus_bin")]
    pub luvus_bin: String,
    #[serde(default = "default_scan_interval_sec")]
    pub scan_interval_sec: u64,
    #[serde(default = "default_reconnect_delay_sec")]
    pub reconnect_delay_sec: u64,
    #[serde(default = "default_read_lines_blocked")]
    pub read_lines_blocked: usize,
    #[serde(default = "default_read_lines_error")]
    pub read_lines_error: usize,
    #[serde(default)]
    pub global_dry_run: bool,
    #[serde(default)]
    pub paused_all: bool,
    #[serde(default = "default_wildcard_vec")]
    pub allowed_panes: Vec<String>,
    #[serde(default = "default_wildcard_vec")]
    pub allowed_agents: Vec<String>,
    #[serde(default = "default_whitelisted_keys")]
    pub whitelisted_keys: Vec<String>,
    #[serde(default = "default_whitelisted_send_texts")]
    pub whitelisted_send_texts: Vec<String>,
    #[serde(default = "default_non_retryable_regexes")]
    pub non_retryable_regexes: Vec<String>,
    #[serde(default)]
    pub max_continuous_default: u32,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
    #[serde(default)]
    pub redact_audit_summary: bool,
}

fn default_config_version() -> u32 {
    CONFIG_SCHEMA_VERSION
}
fn default_luvus_bin() -> String {
    "luvus".to_string()
}
fn default_scan_interval_sec() -> u64 {
    15
}
fn default_reconnect_delay_sec() -> u64 {
    2
}
fn default_read_lines_blocked() -> usize {
    12
}
fn default_read_lines_error() -> usize {
    40
}
fn default_wildcard_vec() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_whitelisted_keys() -> Vec<String> {
    vec![
        "enter".to_string(),
        "esc".to_string(),
        "up".to_string(),
        "down".to_string(),
    ]
}
fn default_whitelisted_send_texts() -> Vec<String> {
    vec!["继续".to_string()]
}
fn default_audit_retention_days() -> u32 {
    30
}

pub fn default_non_retryable_regexes() -> Vec<String> {
    vec![
        r"credit balance|insufficient credits|not enough credits|billing|payment required|usage limit|quota exceeded".to_string(),
        r"invalid api key|incorrect api key|authentication failed|unauthorized|forbidden|\b401\b|\b403\b".to_string(),
        r"account.*disabled|suspended|plan does not include|please log in|login required|sign in required".to_string(),
    ]
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_SCHEMA_VERSION,
            language: UiLanguage::Zh,
            transport_mode: TransportMode::Auto,
            luvus_socket_path: String::new(),
            luvus_bin: default_luvus_bin(),
            scan_interval_sec: default_scan_interval_sec(),
            reconnect_delay_sec: default_reconnect_delay_sec(),
            read_lines_blocked: default_read_lines_blocked(),
            read_lines_error: default_read_lines_error(),
            global_dry_run: false,
            paused_all: false,
            allowed_panes: default_wildcard_vec(),
            allowed_agents: default_wildcard_vec(),
            whitelisted_keys: default_whitelisted_keys(),
            whitelisted_send_texts: default_whitelisted_send_texts(),
            non_retryable_regexes: default_non_retryable_regexes(),
            max_continuous_default: 0,
            audit_retention_days: default_audit_retention_days(),
            redact_audit_summary: false,
        }
    }
}

pub fn resolve_luvus_socket_path(cfg: &WatchdogConfig) -> PathBuf {
    if !cfg.luvus_socket_path.trim().is_empty() {
        return PathBuf::from(cfg.luvus_socket_path.trim());
    }
    if let Ok(env_sock) = std::env::var("LUVUS_SOCKET_PATH")
        && !env_sock.trim().is_empty()
    {
        return PathBuf::from(env_sock.trim());
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".luvus").join("luvus.sock")
}

impl WatchdogConfig {
    /// Apply legacy bash watchdog environment overrides when present.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("LUVUS_SOCKET_PATH")
            && !v.trim().is_empty()
            && self.luvus_socket_path.trim().is_empty()
        {
            self.luvus_socket_path = v;
        }
        if let Ok(v) = std::env::var("LUVUS_BIN_PATH")
            && !v.trim().is_empty()
        {
            self.luvus_bin = v;
        }
        if let Ok(v) = std::env::var("WATCHDOG_PANES")
            && !v.trim().is_empty()
        {
            self.allowed_panes = split_csv(&v);
        }
        if let Ok(v) = std::env::var("WATCHDOG_AGENTS")
            && !v.trim().is_empty()
        {
            self.allowed_agents = split_csv(&v);
        }
        if let Ok(v) = std::env::var("WATCHDOG_MAX_CONTINUOUS")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            self.max_continuous_default = n;
        }
        if let Ok(v) = std::env::var("WATCHDOG_SCAN_INTERVAL")
            && let Ok(n) = v.trim().parse::<u64>()
        {
            self.scan_interval_sec = n;
        }
        if let Ok(v) = std::env::var("WATCHDOG_RECONNECT_DELAY")
            && let Ok(n) = v.trim().parse::<u64>()
        {
            self.reconnect_delay_sec = n;
        }
        if let Ok(v) = std::env::var("WATCHDOG_READ_LINES")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            self.read_lines_blocked = n;
        }
        if let Ok(v) = std::env::var("WATCHDOG_ERROR_LINES")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            self.read_lines_error = n;
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    #[default]
    Visible,
    Recent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchRegion {
    #[default]
    Full,
    ClaudeLastTurn,
    AutoAgent,
}

impl MatchRegion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::ClaudeLastTurn => "claude_last_turn",
            Self::AutoAgent => "auto_agent",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    #[default]
    Keys,
    Send,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Keys => "keys",
            Self::Send => "send",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DedupeStrategy {
    None,
    #[default]
    Signature,
    PaneRule,
}

impl DedupeStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Signature => "signature",
            Self::PaneRule => "pane_rule",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    #[default]
    Approved,
    DryRunOnly,
    PendingReview,
}

impl ReviewStatus {
    pub fn label(&self) -> &'static str {
        self.label_i18n(UiLanguage::Zh)
    }

    pub fn label_i18n(&self, lang: UiLanguage) -> &'static str {
        match (self, lang) {
            (Self::Approved, UiLanguage::Zh) => "已审核",
            (Self::Approved, UiLanguage::En) => "Approved",
            (Self::DryRunOnly, UiLanguage::Zh) => "仅Dry-Run",
            (Self::DryRunOnly, UiLanguage::En) => "Dry-Run Only",
            (Self::PendingReview, UiLanguage::Zh) => "待审核",
            (Self::PendingReview, UiLanguage::En) => "Pending Review",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    #[serde(default)]
    pub source: MatchSource,
    #[serde(default)]
    pub lines: usize,
    #[serde(default)]
    pub region: MatchRegion,
    #[serde(default)]
    pub any_regex: Vec<String>,
    #[serde(default)]
    pub all_regex: Vec<String>,
    #[serde(default)]
    pub none_regex: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

impl Default for RuleMatch {
    fn default() -> Self {
        Self {
            source: MatchSource::Visible,
            lines: 12,
            region: MatchRegion::Full,
            any_regex: vec![],
            all_regex: vec![],
            none_regex: vec![],
            case_insensitive: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuleGuards {
    #[serde(default)]
    pub none_regex: Vec<String>,
    #[serde(default)]
    pub skip_if_claude_retrying: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleAction {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub text: Option<String>,
}

impl Default for RuleAction {
    fn default() -> Self {
        Self {
            action_type: ActionType::Keys,
            keys: vec!["enter".to_string()],
            text: None,
        }
    }
}

impl RuleAction {
    pub fn summary(&self) -> String {
        match self.action_type {
            ActionType::Keys => format!("keys: [{}]", self.keys.join(", ")),
            ActionType::Send => format!("send: \"{}\"", self.text.as_deref().unwrap_or("")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleDedupe {
    #[serde(default)]
    pub strategy: DedupeStrategy,
    #[serde(default = "default_dedupe_window")]
    pub window_sec: u64,
}

fn default_dedupe_window() -> u64 {
    300
}

impl Default for RuleDedupe {
    fn default() -> Self {
        Self {
            strategy: DedupeStrategy::Signature,
            window_sec: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub dry_run_only: bool,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_wildcard_vec")]
    pub agents: Vec<String>,
    #[serde(default = "default_wildcard_vec")]
    pub panes: Vec<String>,
    #[serde(default = "default_wildcard_vec")]
    pub statuses: Vec<String>,
    #[serde(rename = "match")]
    pub match_cfg: RuleMatch,
    #[serde(default)]
    pub guards: RuleGuards,
    pub action: RuleAction,
    #[serde(default)]
    pub dedupe: RuleDedupe,
    #[serde(default = "default_cooldown")]
    pub cooldown_sec: u64,
    #[serde(default)]
    pub max_continuous: u32,
    #[serde(default)]
    pub source_origin: Option<String>,
    #[serde(default)]
    pub review_status: ReviewStatus,
}

fn default_true() -> bool {
    true
}
fn default_priority() -> i32 {
    50
}
fn default_cooldown() -> u64 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RulesFile {
    #[serde(default = "default_rules_version")]
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_rules_version() -> u32 {
    RULES_SCHEMA_VERSION
}

impl Default for RulesFile {
    fn default() -> Self {
        Self {
            version: RULES_SCHEMA_VERSION,
            rules: default_builtin_rules(),
        }
    }
}

/// Built-in conservative defaults migrated from `~/.local/bin/agent-auto-confirm-watchdog`.
pub fn default_builtin_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "approve-yes".to_string(),
            name: "确认提示自动同意".to_string(),
            enabled: true,
            dry_run_only: false,
            priority: 100,
            agents: vec!["*".to_string()],
            panes: vec!["*".to_string()],
            statuses: vec!["blocked".to_string()],
            match_cfg: RuleMatch {
                source: MatchSource::Visible,
                lines: 12,
                region: MatchRegion::Full,
                any_regex: vec![
                    r"(?m)^[\s│›>*-]*\d+\.\s+(Yes|Allow|Proceed|Run|Continue|Retry|Trust|Approve)\b".to_string(),
                    r"(?m)^[\s│›>*-]*(Yes|Allow once|Allow always|Trust and continue|Proceed)\b".to_string(),
                ],
                all_regex: vec![],
                none_regex: vec![],
                case_insensitive: false,
            },
            guards: RuleGuards {
                none_regex: vec![
                    r"(?i)Delete|Overwrite|cannot be undone|destructive".to_string(),
                ],
                skip_if_claude_retrying: false,
            },
            action: RuleAction {
                action_type: ActionType::Keys,
                keys: vec!["enter".to_string()],
                text: None,
            },
            dedupe: RuleDedupe {
                strategy: DedupeStrategy::None,
                window_sec: 0,
            },
            cooldown_sec: 2,
            max_continuous: 0,
            source_origin: Some("builtin".to_string()),
            review_status: ReviewStatus::Approved,
        },
        Rule {
            id: "recover-transient-error".to_string(),
            name: "可恢复传输/限流错误自动续跑".to_string(),
            enabled: true,
            dry_run_only: false,
            priority: 50,
            agents: vec!["*".to_string()],
            panes: vec!["*".to_string()],
            statuses: vec!["!working".to_string()],
            match_cfg: RuleMatch {
                source: MatchSource::Visible,
                lines: 40,
                region: MatchRegion::AutoAgent,
                any_regex: vec![
                    r"stream disconnected before completion|Transport error|Connection dropped|ECONNRESET|ETIMEDOUT|EAI_AGAIN|socket hang up".to_string(),
                    r"network.*(error|unreachable|changed)|temporarily unavailable|service unavailable|overloaded|rate limit|too many requests".to_string(),
                    r"Internal Server Error|Bad Gateway|Gateway Timeout|API Error.*(5\d\d|timeout|overload|reset|disconnect)|timed? out|timeout exceeded|request timed out|connection reset|connection closed|server_error|upstream connect error".to_string(),
                ],
                all_regex: vec![],
                none_regex: vec![],
                case_insensitive: true,
            },
            guards: RuleGuards {
                none_regex: vec![
                    r"(?i)Do you want|Would you like|Are you sure|Delete|Remove|Overwrite|destructive|cannot be undone|No, cancel|Cancel".to_string(),
                ],
                skip_if_claude_retrying: true,
            },
            action: RuleAction {
                action_type: ActionType::Send,
                keys: vec![],
                text: Some("继续".to_string()),
            },
            dedupe: RuleDedupe {
                strategy: DedupeStrategy::Signature,
                window_sec: 300,
            },
            cooldown_sec: 120,
            max_continuous: 0,
            source_origin: Some("builtin".to_string()),
            review_status: ReviewStatus::Approved,
        },
    ]
}

pub fn new_rule_template(existing: &[Rule]) -> Rule {
    let mut idx = existing.len() + 1;
    let ids: HashSet<&str> = existing.iter().map(|r| r.id.as_str()).collect();
    while ids.contains(format!("custom-rule-{idx}").as_str()) {
        idx += 1;
    }
    Rule {
        id: format!("custom-rule-{idx}"),
        name: format!("自定义规则 {idx}"),
        enabled: false,
        dry_run_only: true,
        priority: 40,
        agents: vec!["*".to_string()],
        panes: vec!["*".to_string()],
        statuses: vec!["blocked".to_string()],
        match_cfg: RuleMatch {
            source: MatchSource::Visible,
            lines: 12,
            region: MatchRegion::Full,
            any_regex: vec![r"(?i)continue\?".to_string()],
            all_regex: vec![],
            none_regex: vec![],
            case_insensitive: false,
        },
        guards: RuleGuards {
            none_regex: vec![r"(?i)Delete|Overwrite|cannot be undone".to_string()],
            skip_if_claude_retrying: false,
        },
        action: RuleAction {
            action_type: ActionType::Keys,
            keys: vec!["enter".to_string()],
            text: None,
        },
        dedupe: RuleDedupe {
            strategy: DedupeStrategy::Signature,
            window_sec: 300,
        },
        cooldown_sec: 5,
        max_continuous: 0,
        source_origin: Some("user".to_string()),
        review_status: ReviewStatus::DryRunOnly,
    }
}

pub fn compile_regex(pattern: &str, case_insensitive: bool) -> std::result::Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(true)
        .build()
}

/// Compile or retrieve a cached multi-line regex so rule evaluations reuse DFAs across scans.
pub fn compile_regex_cached(
    pattern: &str,
    case_insensitive: bool,
) -> std::result::Result<Arc<Regex>, regex::Error> {
    static CACHE: OnceLock<Mutex<HashMap<(String, bool), Arc<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(re) = guard.get(&(pattern.to_string(), case_insensitive))
    {
        return Ok(Arc::clone(re));
    }

    let compiled = Arc::new(compile_regex(pattern, case_insensitive)?);
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= 512 {
            guard.clear();
        }
        guard.insert((pattern.to_string(), case_insensitive), Arc::clone(&compiled));
    }
    Ok(compiled)
}

pub fn validate_config(cfg: &WatchdogConfig) -> std::result::Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if cfg.version == 0 {
        errors.push("config.version 必须大于 0".to_string());
    }
    if cfg.luvus_bin.trim().is_empty() {
        errors.push("luvusBin 不能为空".to_string());
    }
    if cfg.read_lines_blocked == 0 || cfg.read_lines_blocked > 500 {
        errors.push("readLinesBlocked 应在 1..=500 之间".to_string());
    }
    if cfg.read_lines_error == 0 || cfg.read_lines_error > 1000 {
        errors.push("readLinesError 应在 1..=1000 之间".to_string());
    }
    if cfg.whitelisted_keys.is_empty() {
        errors.push("whitelistedKeys 不能为空".to_string());
    }
    for (idx, pat) in cfg.non_retryable_regexes.iter().enumerate() {
        if pat.trim().is_empty() {
            errors.push(format!("nonRetryableRegexes[{idx}] 不能为空"));
        } else if let Err(e) = compile_regex(pat, true) {
            errors.push(format!("nonRetryableRegexes[{idx}] 正则非法: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_rule(rule: &Rule, cfg: &WatchdogConfig) -> std::result::Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if rule.id.trim().is_empty() {
        errors.push("规则 id 不能为空".to_string());
    }
    if rule.name.trim().is_empty() {
        errors.push(format!("规则 {} 的 name 不能为空", rule.id));
    }
    if rule.agents.is_empty() {
        errors.push(format!("规则 {} 至少需要一个 agent 作用域（如 *）", rule.id));
    }
    if rule.panes.is_empty() {
        errors.push(format!("规则 {} 至少需要一个 pane 作用域（如 *）", rule.id));
    }
    if rule.statuses.is_empty() {
        errors.push(format!("规则 {} 至少需要一个 status 作用域（如 blocked 或 *）", rule.id));
    }
    if rule.match_cfg.any_regex.is_empty() && rule.match_cfg.all_regex.is_empty() {
        errors.push(format!(
            "规则 {} 必须至少配置一条 anyRegex 或 allRegex",
            rule.id
        ));
    }

    let ci = rule.match_cfg.case_insensitive;
    for (field, list) in [
        ("match.anyRegex", &rule.match_cfg.any_regex),
        ("match.allRegex", &rule.match_cfg.all_regex),
        ("match.noneRegex", &rule.match_cfg.none_regex),
    ] {
        for (i, pat) in list.iter().enumerate() {
            if pat.trim().is_empty() {
                errors.push(format!("规则 {} 的 {field}[{i}] 不能为空", rule.id));
            } else if let Err(e) = compile_regex(pat, ci) {
                errors.push(format!("规则 {} 的 {field}[{i}] 正则非法: {e}", rule.id));
            }
        }
    }

    for (i, pat) in rule.guards.none_regex.iter().enumerate() {
        if pat.trim().is_empty() {
            errors.push(format!("规则 {} 的 guards.noneRegex[{i}] 不能为空", rule.id));
        } else if let Err(e) = compile_regex(pat, false) {
            errors.push(format!(
                "规则 {} 的 guards.noneRegex[{i}] 正则非法: {e}",
                rule.id
            ));
        }
    }

    match rule.action.action_type {
        ActionType::Keys => {
            if rule.action.keys.is_empty() {
                errors.push(format!("规则 {} 的 action.keys 不能为空", rule.id));
            }
            for key in &rule.action.keys {
                if !cfg.whitelisted_keys.iter().any(|w| w.eq_ignore_ascii_case(key)) {
                    errors.push(format!(
                        "规则 {} 的按键 \"{}\" 不在白名单 {:?} 中",
                        rule.id, key, cfg.whitelisted_keys
                    ));
                }
            }
        }
        ActionType::Send => {
            let text = rule.action.text.as_deref().unwrap_or("");
            if text.trim().is_empty() {
                errors.push(format!("规则 {} 的 action.text 不能为空", rule.id));
            } else if !cfg.whitelisted_send_texts.iter().any(|w| w == text) {
                errors.push(format!(
                    "规则 {} 的发送文本 \"{}\" 不在白名单 {:?} 中",
                    rule.id, text, cfg.whitelisted_send_texts
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_rules_file(
    rules_file: &RulesFile,
    cfg: &WatchdogConfig,
) -> std::result::Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if rules_file.version == 0 {
        errors.push("rules.version 必须大于 0".to_string());
    }
    let mut seen_ids = HashSet::new();
    for rule in &rules_file.rules {
        if !seen_ids.insert(rule.id.clone()) {
            errors.push(format!("存在重复规则 id: {}", rule.id));
        }
        if let Err(mut rule_errs) = validate_rule(rule, cfg) {
            errors.append(&mut rule_errs);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Write JSON atomically (temp file -> parse-back validation -> atomic rename).
pub fn save_json_atomic<T: Serialize + for<'de> Deserialize<'de>>(
    path: &Path,
    value: &T,
) -> Result<()> {
    let parent = path
        .parent()
        .context("配置文件缺少父目录")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("创建目录失败: {}", parent.display()))?;

    let json = serde_json::to_string_pretty(value).context("序列化 JSON 失败")?;
    // Verify round-trip parse before writing to disk.
    let _: T = serde_json::from_str(&json).context("JSON 校验回读失败")?;

    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("在 {} 创建临时文件失败", parent.display()))?;
    tmp.write_all(json.as_bytes())
        .context("写入临时配置文件失败")?;
    tmp.write_all(b"\n").ok();
    tmp.as_file().sync_all().context("刷盘失败")?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("原子替换文件 {} 失败: {}", path.display(), e.error))?;
    Ok(())
}

/// Ensure default config.json and rules.json exist if missing; otherwise load and validate.
pub fn load_or_init_config(paths: &AppPaths) -> Result<(WatchdogConfig, RulesFile)> {
    paths.ensure_dirs()?;

    let config = if paths.config_file().exists() {
        let raw = fs::read_to_string(paths.config_file())
            .with_context(|| format!("读取配置失败: {}", paths.config_file().display()))?;
        let parsed: WatchdogConfig = serde_json::from_str(&raw)
            .with_context(|| format!("解析配置 JSON 失败: {}", paths.config_file().display()))?;
        validate_config(&parsed).map_err(|errs| anyhow::anyhow!(errs.join("; ")))?;
        parsed
    } else {
        let cfg = WatchdogConfig::default();
        save_json_atomic(&paths.config_file(), &cfg)?;
        cfg
    };

    let rules = if paths.rules_file().exists() {
        let raw = fs::read_to_string(paths.rules_file())
            .with_context(|| format!("读取规则失败: {}", paths.rules_file().display()))?;
        let parsed: RulesFile = serde_json::from_str(&raw)
            .with_context(|| format!("解析规则 JSON 失败: {}", paths.rules_file().display()))?;
        validate_rules_file(&parsed, &config).map_err(|errs| anyhow::anyhow!(errs.join("; ")))?;
        parsed
    } else {
        let rf = RulesFile::default();
        save_json_atomic(&paths.rules_file(), &rf)?;
        rf
    };

    Ok((config, rules))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ImportedRulesPayload {
    File(RulesFile),
    List(Vec<Rule>),
}

/// Import external JSON rules safely: validates every rule and forces disabled/dry-run until reviewed.
pub fn import_rules_json(
    raw: &str,
    cfg: &WatchdogConfig,
    origin: &str,
    dry_run_only: bool,
) -> std::result::Result<Vec<Rule>, Vec<String>> {
    let payload: ImportedRulesPayload = serde_json::from_str(raw)
        .map_err(|e| vec![format!("导入 JSON 解析失败: {e}")])?;
    let mut rules = match payload {
        ImportedRulesPayload::File(f) => f.rules,
        ImportedRulesPayload::List(v) => v,
    };
    if rules.is_empty() {
        return Err(vec!["导入的规则列表为空".to_string()]);
    }

    let mut errors = Vec::new();
    for rule in &mut rules {
        rule.source_origin = Some(origin.to_string());
        if dry_run_only {
            rule.dry_run_only = true;
            rule.review_status = ReviewStatus::DryRunOnly;
        } else {
            rule.enabled = false;
            rule.dry_run_only = true;
            rule.review_status = ReviewStatus::PendingReview;
        }
        if let Err(mut e) = validate_rule(rule, cfg) {
            errors.append(&mut e);
        }
    }
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

pub fn split_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
