use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::audit::{AuditRecord, AuditResult, AuditStore, SkipReason};
use crate::config::{
    ActionType, AppPaths, DedupeStrategy, MatchRegion, MatchSource, ReviewStatus, Rule, RulesFile,
    TransportMode, UiLanguage, WatchdogConfig, compile_regex, load_or_init_config,
    resolve_luvus_socket_path, save_json_atomic, validate_config, validate_rules_file,
};
use crate::luvus::{
    AgentInfo, DynamicLuvusClient, LuvusClient, LuvusEvent, RealLuvusClient, UnixSocketUhpClient,
    parse_luvus_event_line,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalDecision {
    Execute(String),
    DryRun(String),
    Skipped(SkipReason, String),
    NoMatch,
}

#[derive(Debug, Clone)]
pub struct RuleEvalTrace {
    pub rule_id: String,
    pub rule_name: String,
    pub priority: i32,
    pub enabled: bool,
    pub scope_matched: bool,
    pub matched: bool,
    pub guard_blocked: Option<String>,
    pub skip_reason: Option<SkipReason>,
    pub matched_snippet: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct EvaluationReport {
    pub normalized_text: String,
    pub evaluated_region_preview: String,
    pub non_retryable_hit: Option<String>,
    pub winning_rule_id: Option<String>,
    pub winning_rule_name: Option<String>,
    pub signature: Option<String>,
    pub final_decision: FinalDecision,
    pub traces: Vec<RuleEvalTrace>,
}

#[derive(Debug, Clone)]
pub struct PaneRuntimeState {
    pub pane: String,
    pub agent: String,
    pub status: String,
    pub name: Option<String>,
    pub continuous_count: u32,
    pub continuous_paused: bool,
    pub manual_paused: bool,
    pub non_retryable_notified: bool,
    pub last_checked: Option<DateTime<Utc>>,
    pub last_status_change: Option<DateTime<Utc>>,
    pub last_action: Option<String>,
    pub last_action_at: Option<DateTime<Utc>>,
    pub action_seq: u64,
}

impl PaneRuntimeState {
    fn new(pane: &str, agent: &str, status: &str) -> Self {
        Self {
            pane: pane.to_string(),
            agent: agent.to_string(),
            status: status.to_string(),
            name: None,
            continuous_count: 0,
            continuous_paused: false,
            manual_paused: false,
            non_retryable_notified: false,
            last_checked: None,
            last_status_change: Some(Utc::now()),
            last_action: None,
            last_action_at: None,
            action_seq: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineSnapshot {
    pub config: WatchdogConfig,
    pub rules_file: RulesFile,
    pub panes: Vec<PaneRuntimeState>,
    pub paused_rules: HashSet<String>,
    pub rule_hit_counts: HashMap<String, u64>,
    pub rule_last_hit: HashMap<String, DateTime<Utc>>,
    pub audit_records: Vec<AuditRecord>,
    pub events_connected: bool,
    pub active_transport: String,
    pub last_config_error: Option<String>,
    pub last_luvus_error: Option<String>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub total_actions: u64,
    pub total_dry_runs: u64,
    pub total_errors: u64,
    pub action_seq: u64,
}

pub fn normalize_text(text: &str) -> String {
    text.replace('\u{00a0}', " ")
}

/// Extract Claude's latest turn after the last non-empty `❯` prompt line, matching bash watchdog.
pub fn claude_turn_region(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut last_prompt_idx: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix('❯')
            && !rest.trim().is_empty()
        {
            last_prompt_idx = Some(idx);
        }
    }
    match last_prompt_idx {
        Some(idx) if idx + 1 < lines.len() => lines[idx + 1..].join("\n"),
        _ => String::new(),
    }
}

pub fn extract_region(text: &str, agent: &str, region: MatchRegion) -> String {
    match region {
        MatchRegion::Full => text.to_string(),
        MatchRegion::ClaudeLastTurn => {
            let sub = claude_turn_region(text);
            if sub.is_empty() {
                text.to_string()
            } else {
                sub
            }
        }
        MatchRegion::AutoAgent => {
            if agent.eq_ignore_ascii_case("claude") {
                let sub = claude_turn_region(text);
                if sub.is_empty() {
                    text.to_string()
                } else {
                    sub
                }
            } else {
                text.to_string()
            }
        }
    }
}

pub fn scope_matches(patterns: &[String], value: &str) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let mut has_positive = false;
    let mut positive_matched = false;
    for pat in patterns {
        let p = pat.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(neg) = p.strip_prefix('!') {
            if neg.eq_ignore_ascii_case(value) {
                return false;
            }
        } else {
            has_positive = true;
            if p == "*" || p.eq_ignore_ascii_case(value) {
                positive_matched = true;
            }
        }
    }
    if has_positive {
        positive_matched
    } else {
        true
    }
}

pub fn action_is_whitelisted(rule: &Rule, cfg: &WatchdogConfig) -> std::result::Result<(), String> {
    match rule.action.action_type {
        ActionType::Keys => {
            if rule.action.keys.is_empty() {
                return Err("keys 动作未配置按键".to_string());
            }
            for k in &rule.action.keys {
                if !cfg.whitelisted_keys.iter().any(|w| w.eq_ignore_ascii_case(k)) {
                    return Err(format!("按键 '{k}' 不在白名单中"));
                }
            }
            Ok(())
        }
        ActionType::Send => {
            let text = rule.action.text.as_deref().unwrap_or("");
            if text.is_empty() {
                return Err("send 动作文本为空".to_string());
            }
            if !cfg.whitelisted_send_texts.iter().any(|w| w == text) {
                return Err(format!("文本 '{text}' 不在白名单中"));
            }
            Ok(())
        }
    }
}

pub fn evaluate_rules_stateless(
    raw_text: &str,
    agent: &str,
    pane: &str,
    status: &str,
    rules: &[Rule],
    cfg: &WatchdogConfig,
) -> EvaluationReport {
    let normalized = normalize_text(raw_text);
    let error_region = extract_region(&normalized, agent, MatchRegion::AutoAgent);

    let mut non_retryable_hit = None;
    for pat in &cfg.non_retryable_regexes {
        if let Ok(re) = compile_regex(pat, true)
            && let Some(m) = re.find(&error_region)
        {
            non_retryable_hit = Some(m.as_str().trim().to_string());
            break;
        }
    }

    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

    let mut traces = Vec::with_capacity(sorted.len());
    let mut winning: Option<(&Rule, String, String)> = None;

    for rule in sorted {
        let scope_ok = scope_matches(&rule.agents, agent)
            && scope_matches(&rule.panes, pane)
            && scope_matches(&rule.statuses, status);

        if !rule.enabled {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: false,
                scope_matched: scope_ok,
                matched: false,
                guard_blocked: None,
                skip_reason: None,
                matched_snippet: None,
                detail: "规则已禁用".to_string(),
            });
            continue;
        }

        if !scope_ok {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: false,
                matched: false,
                guard_blocked: None,
                skip_reason: None,
                matched_snippet: None,
                detail: format!(
                    "作用域不匹配 (agent={agent}, pane={pane}, status={status})"
                ),
            });
            continue;
        }

        if non_retryable_hit.is_some() && rule.action.action_type == ActionType::Send {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: false,
                guard_blocked: None,
                skip_reason: Some(SkipReason::NonRetryable),
                matched_snippet: non_retryable_hit.clone(),
                detail: format!(
                    "命中非自动重试错误（{}），禁止自动续跑",
                    non_retryable_hit.as_deref().unwrap_or("")
                ),
            });
            continue;
        }

        let region_text = extract_region(&normalized, agent, rule.match_cfg.region);

        if rule.guards.skip_if_claude_retrying
            && agent.eq_ignore_ascii_case("claude")
            && region_text.contains("Retrying in")
        {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: false,
                guard_blocked: Some("Claude Retrying in".to_string()),
                skip_reason: Some(SkipReason::Retrying),
                matched_snippet: Some("Retrying in".to_string()),
                detail: "Claude 正在自动重试中，跳过".to_string(),
            });
            continue;
        }

        let ci = rule.match_cfg.case_insensitive;

        // Evaluate noneRegex first.
        let mut none_hit = None;
        for pat in &rule.match_cfg.none_regex {
            if let Ok(re) = compile_regex(pat, ci)
                && let Some(m) = re.find(&region_text)
            {
                none_hit = Some(m.as_str().trim().to_string());
                break;
            }
        }
        if let Some(hit) = none_hit {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: false,
                guard_blocked: None,
                skip_reason: None,
                matched_snippet: Some(hit.clone()),
                detail: format!("被 match.noneRegex 排除: {hit}"),
            });
            continue;
        }

        // Evaluate allRegex.
        let mut all_ok = true;
        let mut all_failed_pat = None;
        let mut first_all_snippet = None;
        for pat in &rule.match_cfg.all_regex {
            match compile_regex(pat, ci) {
                Ok(re) => {
                    if let Some(m) = re.find(&region_text) {
                        if first_all_snippet.is_none() {
                            first_all_snippet = Some(m.as_str().trim().to_string());
                        }
                    } else {
                        all_ok = false;
                        all_failed_pat = Some(pat.clone());
                        break;
                    }
                }
                Err(e) => {
                    all_ok = false;
                    all_failed_pat = Some(format!("{pat} (正则错误: {e})"));
                    break;
                }
            }
        }
        if !all_ok {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: false,
                guard_blocked: None,
                skip_reason: None,
                matched_snippet: None,
                detail: format!(
                    "未满足 allRegex: {}",
                    all_failed_pat.as_deref().unwrap_or("")
                ),
            });
            continue;
        }

        // Evaluate anyRegex.
        let mut any_hit = None;
        if rule.match_cfg.any_regex.is_empty() {
            any_hit = first_all_snippet.clone();
        } else {
            for pat in &rule.match_cfg.any_regex {
                if let Ok(re) = compile_regex(pat, ci)
                    && let Some(m) = re.find(&region_text)
                {
                    any_hit = Some(m.as_str().trim().to_string());
                    break;
                }
            }
        }

        let Some(snippet) = any_hit else {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: false,
                guard_blocked: None,
                skip_reason: None,
                matched_snippet: None,
                detail: "未命中 anyRegex".to_string(),
            });
            continue;
        };

        // Evaluate guards.noneRegex.
        let mut guard_hit = None;
        for pat in &rule.guards.none_regex {
            if let Ok(re) = compile_regex(pat, false)
                && let Some(m) = re.find(&region_text)
            {
                guard_hit = Some(m.as_str().trim().to_string());
                break;
            }
        }
        if let Some(g) = guard_hit {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: true,
                guard_blocked: Some(g.clone()),
                skip_reason: Some(SkipReason::Guard),
                matched_snippet: Some(snippet),
                detail: format!("命中规则但被 guard 拦截: {g}"),
            });
            continue;
        }

        if let Err(err) = action_is_whitelisted(rule, cfg) {
            traces.push(RuleEvalTrace {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                enabled: true,
                scope_matched: true,
                matched: true,
                guard_blocked: Some(err.clone()),
                skip_reason: Some(SkipReason::NotWhitelisted),
                matched_snippet: Some(snippet),
                detail: format!("动作未通过白名单校验: {err}"),
            });
            continue;
        }

        let sig_token = snippet
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("_");
        let sig = format!("{}:{}", rule.id, sig_token);

        traces.push(RuleEvalTrace {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            priority: rule.priority,
            enabled: true,
            scope_matched: true,
            matched: true,
            guard_blocked: None,
            skip_reason: None,
            matched_snippet: Some(snippet.clone()),
            detail: format!("命中规则 → {}", rule.action.summary()),
        });

        if winning.is_none() {
            winning = Some((rule, snippet, sig));
        }
    }

    let (winning_rule_id, winning_rule_name, signature, final_decision) =
        if let Some((rule, _snippet, sig)) = winning {
            let summary = rule.action.summary();
            let decision = if cfg.global_dry_run
                || rule.dry_run_only
                || rule.review_status == ReviewStatus::PendingReview
            {
                FinalDecision::DryRun(summary)
            } else {
                FinalDecision::Execute(summary)
            };
            (
                Some(rule.id.clone()),
                Some(rule.name.clone()),
                Some(sig),
                decision,
            )
        } else if let Some(nr) = &non_retryable_hit {
            (
                None,
                None,
                None,
                FinalDecision::Skipped(
                    SkipReason::NonRetryable,
                    format!("非重试错误: {nr}"),
                ),
            )
        } else if let Some(guard_trace) = traces.iter().find(|t| t.skip_reason == Some(SkipReason::Guard)) {
            (
                Some(guard_trace.rule_id.clone()),
                Some(guard_trace.rule_name.clone()),
                None,
                FinalDecision::Skipped(
                    SkipReason::Guard,
                    guard_trace.detail.clone(),
                ),
            )
        } else if let Some(retry_trace) = traces.iter().find(|t| t.skip_reason == Some(SkipReason::Retrying)) {
            (
                Some(retry_trace.rule_id.clone()),
                Some(retry_trace.rule_name.clone()),
                None,
                FinalDecision::Skipped(SkipReason::Retrying, retry_trace.detail.clone()),
            )
        } else {
            (None, None, None, FinalDecision::NoMatch)
        };

    EvaluationReport {
        normalized_text: normalized,
        evaluated_region_preview: error_region,
        non_retryable_hit,
        winning_rule_id,
        winning_rule_name,
        signature,
        final_decision,
        traces,
    }
}

pub struct WatchdogEngine {
    pub paths: AppPaths,
    pub config: WatchdogConfig,
    pub rules_file: RulesFile,
    pub audit_store: AuditStore,
    pub panes: HashMap<String, PaneRuntimeState>,
    pub paused_rules: HashSet<String>,
    pub rule_hit_counts: HashMap<String, u64>,
    pub rule_last_hit: HashMap<String, DateTime<Utc>>,
    cooldowns: HashMap<String, Instant>,
    dedupe_cache: HashMap<(String, String, String), Instant>,
    config_mtime: Option<SystemTime>,
    rules_mtime: Option<SystemTime>,
    pub events_connected: bool,
    pub active_transport: String,
    pub last_config_error: Option<String>,
    pub last_luvus_error: Option<String>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub total_actions: u64,
    pub total_dry_runs: u64,
    pub total_errors: u64,
    pub action_seq: u64,
}

fn pane_sort_key(pane: &str) -> (u8, u64, &str) {
    if let Ok(num) = pane.trim_start_matches('%').parse::<u64>() {
        (0, num, pane)
    } else {
        (1, 0, pane)
    }
}

impl WatchdogEngine {
    pub fn initialize(paths: AppPaths, apply_env: bool) -> Result<Self> {
        let (mut config, rules_file) = load_or_init_config(&paths)?;
        if apply_env {
            config.apply_env_overrides();
        }
        let audit_store = AuditStore::load(paths.audit_file(), config.audit_retention_days);
        let config_mtime = fs::metadata(paths.config_file())
            .and_then(|m| m.modified())
            .ok();
        let rules_mtime = fs::metadata(paths.rules_file())
            .and_then(|m| m.modified())
            .ok();
        let active_transport = DynamicLuvusClient::from_config(&config).transport_label();

        Ok(Self {
            paths,
            config,
            rules_file,
            audit_store,
            panes: HashMap::new(),
            paused_rules: HashSet::new(),
            rule_hit_counts: HashMap::new(),
            rule_last_hit: HashMap::new(),
            cooldowns: HashMap::new(),
            dedupe_cache: HashMap::new(),
            config_mtime,
            rules_mtime,
            events_connected: false,
            active_transport,
            last_config_error: None,
            last_luvus_error: None,
            last_scan_at: None,
            total_actions: 0,
            total_dry_runs: 0,
            total_errors: 0,
            action_seq: 0,
        })
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        let mut panes: Vec<PaneRuntimeState> = self.panes.values().cloned().collect();
        panes.sort_by(|a, b| {
            b.last_status_change
                .cmp(&a.last_status_change)
                .then_with(|| pane_sort_key(&a.pane).cmp(&pane_sort_key(&b.pane)))
        });
        EngineSnapshot {
            config: self.config.clone(),
            rules_file: self.rules_file.clone(),
            panes,
            paused_rules: self.paused_rules.clone(),
            rule_hit_counts: self.rule_hit_counts.clone(),
            rule_last_hit: self.rule_last_hit.clone(),
            audit_records: self.audit_store.records().to_vec(),
            events_connected: self.events_connected,
            active_transport: self.active_transport.clone(),
            last_config_error: self.last_config_error.clone(),
            last_luvus_error: self.last_luvus_error.clone(),
            last_scan_at: self.last_scan_at,
            total_actions: self.total_actions,
            total_dry_runs: self.total_dry_runs,
            total_errors: self.total_errors,
            action_seq: self.action_seq,
        }
    }

    pub fn hot_reload_if_changed(&mut self) -> bool {
        let cfg_mt = fs::metadata(self.paths.config_file())
            .and_then(|m| m.modified())
            .ok();
        let rules_mt = fs::metadata(self.paths.rules_file())
            .and_then(|m| m.modified())
            .ok();

        if cfg_mt == self.config_mtime && rules_mt == self.rules_mtime {
            return false;
        }
        self.reload_from_disk()
    }

    /// Reload config & rules safely; keep previous valid configuration if loading/validation fails.
    pub fn reload_from_disk(&mut self) -> bool {
        let mut changed = false;
        let mut errors = Vec::new();

        let next_cfg = match fs::read_to_string(self.paths.config_file()) {
            Ok(raw) => match serde_json::from_str::<WatchdogConfig>(&raw) {
                Ok(parsed) => match validate_config(&parsed) {
                    Ok(()) => Some(parsed),
                    Err(e) => {
                        errors.push(format!("配置校验失败（已保留旧配置）: {}", e.join("; ")));
                        None
                    }
                },
                Err(e) => {
                    errors.push(format!("配置 JSON 解析失败（已保留旧配置）: {e}"));
                    None
                }
            },
            Err(e) => {
                errors.push(format!("读取配置失败: {e}"));
                None
            }
        };

        let effective_cfg = next_cfg.as_ref().unwrap_or(&self.config);
        let next_rules = match fs::read_to_string(self.paths.rules_file()) {
            Ok(raw) => match serde_json::from_str::<RulesFile>(&raw) {
                Ok(parsed) => match validate_rules_file(&parsed, effective_cfg) {
                    Ok(()) => Some(parsed),
                    Err(e) => {
                        errors.push(format!("规则校验失败（已保留旧规则）: {}", e.join("; ")));
                        None
                    }
                },
                Err(e) => {
                    errors.push(format!("规则 JSON 解析失败（已保留旧规则）: {e}"));
                    None
                }
            },
            Err(e) => {
                errors.push(format!("读取规则失败: {e}"));
                None
            }
        };

        if let Some(cfg) = next_cfg {
            self.config = cfg;
            self.config_mtime = fs::metadata(self.paths.config_file())
                .and_then(|m| m.modified())
                .ok();
            changed = true;
        }
        if let Some(rules) = next_rules {
            self.rules_file = rules;
            self.rules_mtime = fs::metadata(self.paths.rules_file())
                .and_then(|m| m.modified())
                .ok();
            changed = true;
        }

        if errors.is_empty() {
            self.last_config_error = None;
        } else {
            self.last_config_error = Some(errors.join(" | "));
            self.total_errors += 1;
        }
        changed
    }

    pub fn save_config(&mut self, cfg: WatchdogConfig) -> std::result::Result<(), Vec<String>> {
        validate_config(&cfg)?;
        validate_rules_file(&self.rules_file, &cfg)?;
        save_json_atomic(&self.paths.config_file(), &cfg)
            .map_err(|e| vec![format!("保存 config.json 失败: {e}")])?;
        self.config = cfg;
        self.active_transport = DynamicLuvusClient::from_config(&self.config).transport_label();
        self.config_mtime = fs::metadata(self.paths.config_file())
            .and_then(|m| m.modified())
            .ok();
        self.last_config_error = None;
        Ok(())
    }

    pub fn save_rules(&mut self, rules_file: RulesFile) -> std::result::Result<(), Vec<String>> {
        validate_rules_file(&rules_file, &self.config)?;
        save_json_atomic(&self.paths.rules_file(), &rules_file)
            .map_err(|e| vec![format!("保存 rules.json 失败: {e}")])?;
        self.rules_file = rules_file;
        self.rules_mtime = fs::metadata(self.paths.rules_file())
            .and_then(|m| m.modified())
            .ok();
        self.last_config_error = None;
        Ok(())
    }

    pub fn toggle_global_dry_run(&mut self) -> Result<bool> {
        let mut cfg = self.config.clone();
        cfg.global_dry_run = !cfg.global_dry_run;
        self.save_config(cfg)
            .map_err(|e| anyhow::anyhow!(e.join("; ")))?;
        Ok(self.config.global_dry_run)
    }

    pub fn toggle_pause_all(&mut self) -> Result<bool> {
        let mut cfg = self.config.clone();
        cfg.paused_all = !cfg.paused_all;
        self.save_config(cfg)
            .map_err(|e| anyhow::anyhow!(e.join("; ")))?;
        Ok(self.config.paused_all)
    }

    pub fn set_language(&mut self, lang: UiLanguage) -> Result<UiLanguage> {
        let mut cfg = self.config.clone();
        cfg.language = lang;
        self.save_config(cfg)
            .map_err(|e| anyhow::anyhow!(e.join("; ")))?;
        Ok(self.config.language)
    }

    pub fn toggle_pane_pause(&mut self, pane: &str) {
        if let Some(st) = self.panes.get_mut(pane) {
            st.manual_paused = !st.manual_paused;
        }
    }

    pub fn reset_pane_continuous(&mut self, pane: &str) {
        if let Some(st) = self.panes.get_mut(pane) {
            st.continuous_count = 0;
            st.continuous_paused = false;
            st.non_retryable_notified = false;
        }
        self.dedupe_cache.retain(|(p, _, _), _| p != pane);
    }

    pub fn toggle_rule_pause(&mut self, rule_id: &str) {
        if !self.paused_rules.remove(rule_id) {
            self.paused_rules.insert(rule_id.to_string());
        }
    }

    pub fn scan_once(&mut self, client: &dyn LuvusClient, cli_dry_run: bool) -> Result<()> {
        self.hot_reload_if_changed();
        match client.list_agents() {
            Ok(agents) => {
                self.last_luvus_error = None;
                self.last_scan_at = Some(Utc::now());
                for info in agents {
                    self.process_agent_info(client, &info, cli_dry_run);
                }
                Ok(())
            }
            Err(err) => {
                self.last_luvus_error = Some(err.to_string());
                self.total_errors += 1;
                Err(err)
            }
        }
    }

    pub fn process_agent_info(
        &mut self,
        client: &dyn LuvusClient,
        info: &AgentInfo,
        cli_dry_run: bool,
    ) {
        if !scope_matches(&self.config.allowed_panes, &info.pane)
            || !scope_matches(&self.config.allowed_agents, &info.agent)
        {
            return;
        }

        let audit_store = &self.audit_store;
        let state = self.panes.entry(info.pane.clone()).or_insert_with(|| {
            let mut st = PaneRuntimeState::new(&info.pane, &info.agent, &info.status);
            if let Some(last_rec) = audit_store.records().iter().rev().find(|r| {
                r.pane == info.pane
                    && matches!(r.result, AuditResult::Success | AuditResult::DryRun)
            }) {
                st.last_action = Some(if last_rec.dry_run {
                    format!("[dry-run] {}", last_rec.action_summary)
                } else {
                    last_rec.action_summary.clone()
                });
                st.last_action_at = Some(last_rec.timestamp);
            }
            st
        });

        if info.name.is_some() {
            state.name = info.name.clone();
        }
        state.agent = info.agent.clone();
        state.last_checked = Some(Utc::now());

        if state.status != info.status {
            state.status = info.status.clone();
            state.last_status_change = Some(Utc::now());
        }

        if info.status.eq_ignore_ascii_case("working") {
            if state.continuous_count > 0 || state.continuous_paused || state.non_retryable_notified
            {
                state.continuous_count = 0;
                state.continuous_paused = false;
                state.non_retryable_notified = false;
                let pane_id = info.pane.clone();
                self.dedupe_cache.retain(|(p, _, _), _| p != &pane_id);
            }
            return;
        }

        if self.config.paused_all || state.manual_paused {
            return;
        }

        // Determine max visible lines required by applicable rules/status defaults.
        let base_lines = if info.status.eq_ignore_ascii_case("blocked") {
            self.config.read_lines_blocked
        } else {
            self.config.read_lines_error
        };
        let mut lines_to_read = base_lines;
        for rule in &self.rules_file.rules {
            if rule.enabled
                && scope_matches(&rule.agents, &info.agent)
                && scope_matches(&rule.panes, &info.pane)
                && scope_matches(&rule.statuses, &info.status)
                && rule.match_cfg.lines > lines_to_read
            {
                lines_to_read = rule.match_cfg.lines;
            }
        }

        let raw_text = match client.read_pane(&info.pane, lines_to_read, MatchSource::Visible) {
            Ok(t) => t,
            Err(err) => {
                self.total_errors += 1;
                self.last_luvus_error = Some(err.to_string());
                return;
            }
        };
        if raw_text.trim().is_empty() {
            return;
        }

        let report = evaluate_rules_stateless(
            &raw_text,
            &info.agent,
            &info.pane,
            &info.status,
            &self.rules_file.rules,
            &self.config,
        );

        let now = Instant::now();
        let redact = self.config.redact_audit_summary;

        // Handle non-retryable / guard / retrying skips with auditability (without spamming identical non-retryable).
        if report.winning_rule_id.is_none() {
            match &report.final_decision {
                FinalDecision::Skipped(SkipReason::NonRetryable, detail) => {
                    let already_notified = self
                        .panes
                        .get(&info.pane)
                        .map(|s| s.non_retryable_notified)
                        .unwrap_or(false);
                    if !already_notified {
                        if let Some(st) = self.panes.get_mut(&info.pane) {
                            st.non_retryable_notified = true;
                        }
                        let rec = AuditRecord::new(
                            &info.pane,
                            &info.agent,
                            &info.status,
                            None,
                            None,
                            report.non_retryable_hit.clone().unwrap_or_default(),
                            None,
                            "-",
                            AuditResult::Skipped,
                            Some(SkipReason::NonRetryable),
                            self.config.global_dry_run || cli_dry_run,
                            detail.clone(),
                        );
                        let _ = self.audit_store.append(rec, redact);
                    }
                }
                FinalDecision::Skipped(reason, detail) => {
                    let dedupe_key = (
                        info.pane.clone(),
                        format!("skip:{}", reason.label()),
                        detail.clone(),
                    );
                    if !self.is_deduped(&dedupe_key, 60, now) {
                        self.mark_dedupe(dedupe_key, now);
                        let rec = AuditRecord::new(
                            &info.pane,
                            &info.agent,
                            &info.status,
                            None,
                            None,
                            detail.clone(),
                            None,
                            "-",
                            AuditResult::Skipped,
                            Some(*reason),
                            self.config.global_dry_run || cli_dry_run,
                            detail.clone(),
                        );
                        let _ = self.audit_store.append(rec, redact);
                    }
                }
                FinalDecision::NoMatch => {}
                FinalDecision::Execute(_) | FinalDecision::DryRun(_) => {}
            }
            return;
        }

        let Some(rule_id) = report.winning_rule_id.as_ref() else {
            return;
        };
        let Some(rule) = self.rules_file.rules.iter().find(|r| &r.id == rule_id).cloned() else {
            return;
        };
        let signature = report.signature.clone().unwrap_or_else(|| rule.id.clone());
        let match_summary = report
            .traces
            .iter()
            .find(|t| &t.rule_id == rule_id)
            .and_then(|t| t.matched_snippet.clone())
            .unwrap_or_default();

        // Rule-level pause check.
        if self.paused_rules.contains(&rule.id) {
            let rec = AuditRecord::new(
                &info.pane,
                &info.agent,
                &info.status,
                Some(rule.id.clone()),
                Some(rule.name.clone()),
                match_summary,
                Some(signature),
                rule.action.summary(),
                AuditResult::Skipped,
                Some(SkipReason::Paused),
                false,
                "规则已被人工暂停",
            );
            let _ = self.audit_store.append(rec, redact);
            return;
        }

        // Dedupe check.
        let dedupe_key = match rule.dedupe.strategy {
            DedupeStrategy::None => None,
            DedupeStrategy::Signature => Some((info.pane.clone(), rule.id.clone(), signature.clone())),
            DedupeStrategy::PaneRule => Some((info.pane.clone(), rule.id.clone(), "*".to_string())),
        };
        if let Some(ref key) = dedupe_key
            && rule.dedupe.window_sec > 0
            && self.is_deduped(key, rule.dedupe.window_sec, now)
        {
            let rec = AuditRecord::new(
                &info.pane,
                &info.agent,
                &info.status,
                Some(rule.id.clone()),
                Some(rule.name.clone()),
                match_summary,
                Some(signature),
                rule.action.summary(),
                AuditResult::Skipped,
                Some(SkipReason::Dedupe),
                self.config.global_dry_run || cli_dry_run,
                format!("窗口 {}s 内重复命中去重跳过", rule.dedupe.window_sec),
            );
            let _ = self.audit_store.append(rec, redact);
            return;
        }

        // Cooldown check.
        let cd_key = format!("{}:{}", info.pane, rule.id);
        if rule.cooldown_sec > 0
            && let Some(prev) = self.cooldowns.get(&cd_key)
            && now.duration_since(*prev).as_secs() < rule.cooldown_sec
        {
            let rec = AuditRecord::new(
                &info.pane,
                &info.agent,
                &info.status,
                Some(rule.id.clone()),
                Some(rule.name.clone()),
                match_summary,
                Some(signature),
                rule.action.summary(),
                AuditResult::Skipped,
                Some(SkipReason::Cooldown),
                self.config.global_dry_run || cli_dry_run,
                format!("规则冷却中 ({}s)", rule.cooldown_sec),
            );
            let _ = self.audit_store.append(rec, redact);
            return;
        }

        // Max continuous cap check.
        let effective_max = if rule.max_continuous > 0 {
            rule.max_continuous
        } else {
            self.config.max_continuous_default
        };
        if effective_max > 0 {
            let pane_state = self.panes.get_mut(&info.pane).unwrap();
            if pane_state.continuous_count >= effective_max {
                if !pane_state.continuous_paused {
                    pane_state.continuous_paused = true;
                    let rec = AuditRecord::new(
                        &info.pane,
                        &info.agent,
                        &info.status,
                        Some(rule.id.clone()),
                        Some(rule.name.clone()),
                        match_summary,
                        Some(signature),
                        rule.action.summary(),
                        AuditResult::Skipped,
                        Some(SkipReason::MaxContinuous),
                        self.config.global_dry_run || cli_dry_run,
                        format!("连续自动处理已达上限 {effective_max} 次，已暂停该 pane"),
                    );
                    let _ = self.audit_store.append(rec, redact);
                }
                return;
            }
        }

        let effective_dry_run = cli_dry_run
            || self.config.global_dry_run
            || rule.dry_run_only
            || rule.review_status == ReviewStatus::PendingReview;

        if effective_dry_run {
            self.cooldowns.insert(cd_key, now);
            if let Some(key) = dedupe_key {
                self.mark_dedupe(key, now);
            }
            self.total_dry_runs += 1;
            self.action_seq += 1;
            *self.rule_hit_counts.entry(rule.id.clone()).or_insert(0) += 1;
            self.rule_last_hit.insert(rule.id.clone(), Utc::now());
            if let Some(st) = self.panes.get_mut(&info.pane) {
                st.continuous_count += 1;
                st.last_action = Some(format!("[dry-run] {}", rule.action.summary()));
                st.last_action_at = Some(Utc::now());
                st.action_seq += 1;
            }
            let rec = AuditRecord::new(
                &info.pane,
                &info.agent,
                &info.status,
                Some(rule.id.clone()),
                Some(rule.name.clone()),
                match_summary,
                Some(signature),
                rule.action.summary(),
                AuditResult::DryRun,
                None,
                true,
                "Dry-Run 模式：仅记录计划动作，未调用 luvus",
            );
            let _ = self.audit_store.append(rec, redact);
            return;
        }

        // Execute whitelisted action via luvus.
        let exec_res = match rule.action.action_type {
            ActionType::Keys => client.send_keys(&info.pane, &rule.action.keys),
            ActionType::Send => {
                let text = rule.action.text.as_deref().unwrap_or("");
                client.send_text(&info.pane, text)
            }
        };

        match exec_res {
            Ok(()) => {
                self.cooldowns.insert(cd_key, now);
                if let Some(key) = dedupe_key {
                    self.mark_dedupe(key, now);
                }
                self.total_actions += 1;
                self.action_seq += 1;
                *self.rule_hit_counts.entry(rule.id.clone()).or_insert(0) += 1;
                self.rule_last_hit.insert(rule.id.clone(), Utc::now());
                if let Some(st) = self.panes.get_mut(&info.pane) {
                    st.continuous_count += 1;
                    st.last_action = Some(rule.action.summary());
                    st.last_action_at = Some(Utc::now());
                    st.action_seq += 1;
                }
                let rec = AuditRecord::new(
                    &info.pane,
                    &info.agent,
                    &info.status,
                    Some(rule.id.clone()),
                    Some(rule.name.clone()),
                    match_summary,
                    Some(signature),
                    rule.action.summary(),
                    AuditResult::Success,
                    None,
                    false,
                    "动作执行成功",
                );
                let _ = self.audit_store.append(rec, redact);
            }
            Err(err) => {
                self.total_errors += 1;
                self.last_luvus_error = Some(err.to_string());
                let rec = AuditRecord::new(
                    &info.pane,
                    &info.agent,
                    &info.status,
                    Some(rule.id.clone()),
                    Some(rule.name.clone()),
                    match_summary,
                    Some(signature),
                    rule.action.summary(),
                    AuditResult::Failure,
                    None,
                    false,
                    format!("执行失败: {err}"),
                );
                let _ = self.audit_store.append(rec, redact);
            }
        }
    }

    fn is_deduped(&self, key: &(String, String, String), window_sec: u64, now: Instant) -> bool {
        if let Some(prev) = self.dedupe_cache.get(key) {
            now.duration_since(*prev).as_secs() < window_sec
        } else {
            false
        }
    }

    fn mark_dedupe(&mut self, key: (String, String, String), now: Instant) {
        self.dedupe_cache.insert(key, now);
    }
}

/// Spawn background thread subscribing to luvus events (UHP Unix socket preferred, CLI fallback)
/// with automatic reconnect + polling fallback.
pub fn spawn_engine_loop(
    shared: Arc<Mutex<WatchdogEngine>>,
    stop: Arc<AtomicBool>,
    cli_dry_run: bool,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_sequence: Option<u64> = None;

        while !stop.load(Ordering::Relaxed) {
            let (cfg_snapshot, reconnect_delay, use_socket, sock_path) = {
                let mut eng = shared.lock().unwrap();
                let client = DynamicLuvusClient::from_config(&eng.config);
                eng.active_transport = client.transport_label();
                let _ = eng.scan_once(&client, cli_dry_run);
                let sock_path = resolve_luvus_socket_path(&eng.config);
                let use_socket = cfg!(unix)
                    && match eng.config.transport_mode {
                        TransportMode::Socket => true,
                        TransportMode::Cli => false,
                        TransportMode::Auto => sock_path.exists(),
                    };
                (
                    eng.config.clone(),
                    eng.config.reconnect_delay_sec.max(1),
                    use_socket,
                    sock_path,
                )
            };

            #[cfg(not(unix))]
            let _ = (use_socket, &sock_path);

            #[cfg(unix)]
            if use_socket {
                let sock_client = UnixSocketUhpClient::new(&sock_path);
                match sock_client.subscribe_events(last_sequence) {
                    Ok(mut reader) => {
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = true;
                            eng.active_transport = format!("UHP Socket ({})", sock_path.display());
                            eng.last_luvus_error = None;
                        }
                        let mut last_poll = Instant::now();
                        let mut line = String::new();
                        while !stop.load(Ordering::Relaxed) {
                            line.clear();
                            match reader.read_line(&mut line) {
                                Ok(0) => break, // EOF -> reconnect
                                Ok(_) => {
                                    handle_event_stream_line(
                                        &shared,
                                        &line,
                                        &mut last_sequence,
                                        cli_dry_run,
                                    );
                                }
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                                Err(e) => {
                                    let mut eng = shared.lock().unwrap();
                                    eng.last_luvus_error = Some(format!("UHP 事件流读取错误: {e}"));
                                    break;
                                }
                            }

                            let (scan_interval, transport_changed) = {
                                let mut eng = shared.lock().unwrap();
                                eng.hot_reload_if_changed();
                                let cur_sock = resolve_luvus_socket_path(&eng.config);
                                let changed = eng.config.transport_mode == TransportMode::Cli
                                    || cur_sock != sock_path;
                                (eng.config.scan_interval_sec, changed)
                            };
                            if transport_changed {
                                break;
                            }
                            if scan_interval > 0 && last_poll.elapsed().as_secs() >= scan_interval {
                                let mut eng = shared.lock().unwrap();
                                let c = DynamicLuvusClient::from_config(&eng.config);
                                eng.active_transport = c.transport_label();
                                let _ = eng.scan_once(&c, cli_dry_run);
                                last_poll = Instant::now();
                            }
                        }
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = false;
                        }
                        continue;
                    }
                    Err(err) => {
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = false;
                            eng.last_luvus_error = Some(err.to_string());
                        }
                        sleep_with_stop(&stop, reconnect_delay.min(cfg_snapshot.scan_interval_sec.max(1)));
                        continue;
                    }
                }
            }

            {
                let cli_client = RealLuvusClient::new(&cfg_snapshot.luvus_bin);
                match cli_client.spawn_events_process() {
                    Ok(mut child) => {
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = true;
                            eng.active_transport = format!("CLI 子进程 ({})", cfg_snapshot.luvus_bin);
                            eng.last_luvus_error = None;
                        }

                        let stdout = child.stdout.take();
                        let (tx, rx) = std::sync::mpsc::channel::<String>();
                        if let Some(out) = stdout {
                            std::thread::spawn(move || {
                                let reader = BufReader::new(out);
                                for line in reader.lines().map_while(Result::ok) {
                                    if tx.send(line).is_err() {
                                        break;
                                    }
                                }
                            });
                        }

                        let mut last_poll = Instant::now();
                        while !stop.load(Ordering::Relaxed) {
                            match rx.recv_timeout(Duration::from_millis(500)) {
                                Ok(line) => {
                                    handle_event_stream_line(
                                        &shared,
                                        &line,
                                        &mut last_sequence,
                                        cli_dry_run,
                                    );
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }

                            let (scan_interval, transport_changed) = {
                                let mut eng = shared.lock().unwrap();
                                eng.hot_reload_if_changed();
                                let cur_sock = resolve_luvus_socket_path(&eng.config);
                                let switch_to_sock = cfg!(unix)
                                    && match eng.config.transport_mode {
                                        TransportMode::Socket => true,
                                        TransportMode::Auto => cur_sock.exists(),
                                        TransportMode::Cli => false,
                                    };
                                let changed = switch_to_sock
                                    || eng.config.luvus_bin != cfg_snapshot.luvus_bin;
                                (eng.config.scan_interval_sec, changed)
                            };
                            if transport_changed {
                                break;
                            }
                            if scan_interval > 0 && last_poll.elapsed().as_secs() >= scan_interval {
                                let mut eng = shared.lock().unwrap();
                                let c = DynamicLuvusClient::from_config(&eng.config);
                                eng.active_transport = c.transport_label();
                                let _ = eng.scan_once(&c, cli_dry_run);
                                last_poll = Instant::now();
                            }
                        }

                        let _ = child.kill();
                        let _ = child.wait();
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = false;
                        }
                    }
                    Err(err) => {
                        {
                            let mut eng = shared.lock().unwrap();
                            eng.events_connected = false;
                            eng.last_luvus_error = Some(err.to_string());
                        }
                        let wait_sec = if cfg_snapshot.scan_interval_sec > 0 {
                            reconnect_delay.min(cfg_snapshot.scan_interval_sec)
                        } else {
                            reconnect_delay
                        };
                        sleep_with_stop(&stop, wait_sec);
                        continue;
                    }
                }
            }

            sleep_with_stop(&stop, reconnect_delay);
        }
    })
}

fn handle_event_stream_line(
    shared: &Arc<Mutex<WatchdogEngine>>,
    line: &str,
    last_sequence: &mut Option<u64>,
    cli_dry_run: bool,
) {
    let Some(ev) = parse_luvus_event_line(line) else {
        return;
    };
    match ev {
        LuvusEvent::AgentStatus {
            pane,
            status,
            agent,
            sequence,
        } => {
            if let Some(seq) = sequence {
                *last_sequence = Some(seq);
            }
            let mut eng = shared.lock().unwrap();
            eng.hot_reload_if_changed();
            let c = DynamicLuvusClient::from_config(&eng.config);
            eng.active_transport = c.transport_label();
            let info = AgentInfo {
                pane,
                agent,
                status,
                name: None,
                cwd: None,
            };
            eng.process_agent_info(&c, &info, cli_dry_run);
        }
        LuvusEvent::ResyncRequired { sequence } => {
            if let Some(seq) = sequence {
                *last_sequence = Some(seq);
            }
            let mut eng = shared.lock().unwrap();
            let c = DynamicLuvusClient::from_config(&eng.config);
            let _ = eng.scan_once(&c, cli_dry_run);
        }
        LuvusEvent::Other { sequence } => {
            if let Some(seq) = sequence {
                *last_sequence = Some(seq);
            }
        }
    }
}

fn sleep_with_stop(stop: &Arc<AtomicBool>, secs: u64) {
    for _ in 0..(secs.max(1) * 2) {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
