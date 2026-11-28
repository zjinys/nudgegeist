use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::{Value, json};
use tempfile::TempDir;

use nudgegeist::audit::{AuditResult, SkipReason};
use nudgegeist::config::{
    ActionType, AppPaths, DedupeStrategy, MatchSource, ReviewStatus, Rule, RuleAction,
    RuleDedupe, RuleGuards, RuleMatch, RulesFile, ThemeMode, TransportMode, UiLanguage,
    WatchdogConfig, import_rules_json, load_or_init_config, save_json_atomic, validate_rule,
};
use nudgegeist::engine::{
    FinalDecision, WatchdogEngine, evaluate_rules_stateless, parse_quota_reset_delay,
};
#[cfg(unix)]
use nudgegeist::luvus::UnixSocketUhpClient;
use nudgegeist::luvus::{
    AgentInfo, DynamicLuvusClient, LuvusClient, LuvusEvent, detect_luvus_installation,
    luvus_install_command_preview, parse_agent_list_json, parse_luvus_event_line,
    parse_read_pane_json, parse_session_list_pipe_address, resolve_luvus_executable,
    windows_pipe_name_from_socket_path,
};
use nudgegeist::ui::app::{APP_ICON_PNG, pane_status_colors, write_linux_desktop_files};
use nudgegeist::ui::i18n::{pretty_time, tr};

#[derive(Default, Clone)]
struct MockLuvusState {
    agents: Vec<AgentInfo>,
    pane_texts: HashMap<String, String>,
    sent_keys: Vec<(String, Vec<String>)>,
    sent_texts: Vec<(String, String)>,
}

struct MockLuvusClient {
    state: Arc<Mutex<MockLuvusState>>,
}

impl MockLuvusClient {
    fn new(agents: Vec<AgentInfo>, texts: Vec<(&str, &str)>) -> (Self, Arc<Mutex<MockLuvusState>>) {
        let mut map = HashMap::new();
        for (p, t) in texts {
            map.insert(p.to_string(), t.to_string());
        }
        let state = Arc::new(Mutex::new(MockLuvusState {
            agents,
            pane_texts: map,
            sent_keys: Vec::new(),
            sent_texts: Vec::new(),
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            state,
        )
    }
}

impl LuvusClient for MockLuvusClient {
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        Ok(self.state.lock().unwrap().agents.clone())
    }

    fn read_pane(&self, pane: &str, _lines: usize, _source: MatchSource) -> Result<String> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .pane_texts
            .get(pane)
            .cloned()
            .unwrap_or_default())
    }

    fn send_keys(&self, pane: &str, keys: &[String]) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .sent_keys
            .push((pane.to_string(), keys.to_vec()));
        Ok(())
    }

    fn send_text(&self, pane: &str, text: &str) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .sent_texts
            .push((pane.to_string(), text.to_string()));
        Ok(())
    }
}

#[test]
fn test_rule_matching_any_all_none_and_priority() {
    let cfg = WatchdogConfig::default();
    let rules = vec![
        Rule {
            id: "low".into(),
            name: "Low".into(),
            enabled: true,
            dry_run_only: false,
            priority: 10,
            agents: vec!["*".into()],
            panes: vec!["*".into()],
            statuses: vec!["blocked".into()],
            match_cfg: RuleMatch {
                any_regex: vec![r"Yes".into()],
                ..Default::default()
            },
            guards: RuleGuards::default(),
            action: RuleAction {
                action_type: ActionType::Keys,
                keys: vec!["up".into()],
                text: None,
            },
            dedupe: RuleDedupe::default(),
            cooldown_sec: 0,
            max_continuous: 0,
            source_origin: None,
            review_status: ReviewStatus::Approved,
        },
        Rule {
            id: "high".into(),
            name: "High".into(),
            enabled: true,
            dry_run_only: false,
            priority: 100,
            agents: vec!["codex".into()],
            panes: vec!["*".into()],
            statuses: vec!["blocked".into()],
            match_cfg: RuleMatch {
                any_regex: vec![],
                all_regex: vec![r"Yes".into(), r"proceed".into()],
                none_regex: vec![r"forbidden_word".into()],
                ..Default::default()
            },
            guards: RuleGuards::default(),
            action: RuleAction {
                action_type: ActionType::Keys,
                keys: vec!["enter".into()],
                text: None,
            },
            dedupe: RuleDedupe::default(),
            cooldown_sec: 0,
            max_continuous: 0,
            source_origin: None,
            review_status: ReviewStatus::Approved,
        },
    ];

    let report = evaluate_rules_stateless(
        "1. Yes, proceed now",
        "codex",
        "%1",
        "blocked",
        &rules,
        &cfg,
    );
    assert_eq!(report.winning_rule_id.as_deref(), Some("high"));
    assert_eq!(
        report.final_decision,
        FinalDecision::Execute("keys: [enter]".into())
    );

    // Trigger noneRegex on high rule -> falls back to low rule.
    let report2 = evaluate_rules_stateless(
        "1. Yes, proceed forbidden_word",
        "codex",
        "%1",
        "blocked",
        &rules,
        &cfg,
    );
    assert_eq!(report2.winning_rule_id.as_deref(), Some("low"));
}

#[test]
fn test_guards_and_non_retryable_block_dangerous_actions() {
    let cfg = WatchdogConfig::default();
    let rules = RulesFile::default().rules;

    // Dangerous confirmation blocked by guard.
    let danger = evaluate_rules_stateless(
        "Warning: Delete files (cannot be undone)\n1. Yes, proceed",
        "codex",
        "%1",
        "blocked",
        &rules,
        &cfg,
    );
    assert_eq!(danger.winning_rule_id.as_deref(), Some("approve-yes"));
    assert!(matches!(
        danger.final_decision,
        FinalDecision::Skipped(SkipReason::Guard, _)
    ));

    // Auth / 401 error must not auto-continue.
    let auth = evaluate_rules_stateless(
        "API Error: 401 unauthorized - invalid api key\nConnection dropped",
        "codex",
        "%2",
        "error",
        &rules,
        &cfg,
    );
    assert!(auth.non_retryable_hit.is_some());
    assert!(matches!(
        auth.final_decision,
        FinalDecision::Skipped(SkipReason::NonRetryable, _)
    ));

    // Claude "Retrying in" guard.
    let retrying = evaluate_rules_stateless(
        "❯ fix build\nTransport error: timeout\nRetrying in 3 seconds...",
        "claude",
        "%3",
        "error",
        &rules,
        &cfg,
    );
    assert!(matches!(
        retrying.final_decision,
        FinalDecision::Skipped(SkipReason::Retrying, _)
    ));
}

#[test]
fn test_claude_api_error_resend_placeholder_triggers_continue() {
    let cfg = WatchdogConfig::default();
    let rules = RulesFile::default().rules;

    // Captured from a real pane: Claude exits with a 429, then shows a "Resend" input
    // placeholder. That placeholder must not hide the error from the evaluated region,
    // and the "API Usage Billing" status label must not be treated as a billing error.
    let text = r#" ▐▛███▛█   Claude Code v2.1.327
▝▜██████▀  Fable 5.2 · API Usage Billing
❯ 你去看看 个人认知主循环路线图 这个proposal的完成情况

● API Error: Request rejected (429) · Service Unavailable

❯ Resend your message to try again
  ⏵⏵ auto mode on (shift+tab to cycle) · ← 1 agent"#;

    let report = evaluate_rules_stateless(text, "claude", "%6", "done", &rules, &cfg);
    assert_eq!(
        report.winning_rule_id.as_deref(),
        Some("recover-transient-error")
    );
    assert!(report.non_retryable_hit.is_none());
    assert!(matches!(report.final_decision, FinalDecision::Execute(_)));
}

#[test]
fn test_api_usage_billing_label_does_not_suppress_transient_errors() {
    let cfg = WatchdogConfig::default();
    let rules = RulesFile::default().rules;

    // No `❯` prompt in this read window, so the evaluated region falls back to the full text,
    // including Claude's static status label. A bare `billing` pattern used to block the 429.
    let label = evaluate_rules_stateless(
        "▝▜██████▀  Fable 5.2 · API Usage Billing\n● API Error: Request rejected (429) · Service Unavailable",
        "claude",
        "%6",
        "idle",
        &rules,
        &cfg,
    );
    assert!(label.non_retryable_hit.is_none());
    assert_eq!(
        label.winning_rule_id.as_deref(),
        Some("recover-transient-error")
    );
    assert!(matches!(label.final_decision, FinalDecision::Execute(_)));

    // A genuine billing failure must still block auto-continue.
    let real_billing = evaluate_rules_stateless(
        "● Billing hard limit reached. Please add credits to continue.",
        "claude",
        "%6",
        "idle",
        &rules,
        &cfg,
    );
    assert!(real_billing.non_retryable_hit.is_some());
    assert!(matches!(
        real_billing.final_decision,
        FinalDecision::Skipped(SkipReason::NonRetryable, _)
    ));
}

#[test]
fn test_individual_quota_reached_is_non_retryable() {
    let cfg = WatchdogConfig::default();
    let rules = RulesFile::default().rules;

    // Antigravity shows an exhausted individual quota but its earlier log mentions rate
    // limiting, which the recover rule matches. Quota exhaustion must win over that match.
    let text = r#"○ Thought for 9.6s (API error response indicates rate limiting during proposal status check.)
⚠ Individual quota reached. Please upgrade your subscription to increase your limits. Resets in 1h8m25s.
Error ID: 65d0fb86-a5e4-427d-b085-0642a461f736-249

> 继续"#;

    let report = evaluate_rules_stateless(text, "antigravity", "%7", "idle", &rules, &cfg);
    assert!(report.non_retryable_hit.is_some());
    assert!(report.winning_rule_id.is_none());
    assert!(matches!(
        report.final_decision,
        FinalDecision::Skipped(SkipReason::NonRetryable, _)
    ));
}

#[test]
fn test_validation_rejects_bad_regex_and_non_whitelisted_actions() {
    let cfg = WatchdogConfig::default();
    let mut bad_rule = RulesFile::default().rules.remove(0);
    bad_rule.match_cfg.any_regex = vec!["[unclosed(".into()];
    bad_rule.action = RuleAction {
        action_type: ActionType::Send,
        keys: vec![],
        text: Some("rm -rf /".into()),
    };

    let errs = validate_rule(&bad_rule, &cfg).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("正则非法")));
    assert!(errs.iter().any(|e| e.contains("不在白名单")));
}

#[test]
fn test_import_rules_marks_pending_review_or_dry_run() {
    let cfg = WatchdogConfig::default();
    let raw = r#"[{
        "id": "ext-1",
        "name": "External Rule",
        "enabled": true,
        "priority": 90,
        "agents": ["*"],
        "panes": ["*"],
        "statuses": ["blocked"],
        "match": { "anyRegex": ["Continue\\?"] },
        "action": { "type": "keys", "keys": ["enter"] }
    }]"#;

    let imported = import_rules_json(raw, &cfg, "community", false).unwrap();
    assert_eq!(imported.len(), 1);
    assert!(!imported[0].enabled);
    assert!(imported[0].dry_run_only);
    assert_eq!(imported[0].review_status, ReviewStatus::PendingReview);
    assert_eq!(imported[0].source_origin.as_deref(), Some("community"));
}

#[test]
fn test_corrupt_reload_retains_last_valid_config() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths.clone(), false).unwrap();
    let original_count = engine.rules_file.rules.len();

    fs::write(paths.rules_file(), "{ broken json !!!").unwrap();
    engine.reload_from_disk();

    assert!(engine.last_config_error.is_some());
    assert_eq!(engine.rules_file.rules.len(), original_count);

    // Valid atomic write recovers cleanly.
    save_json_atomic(&paths.rules_file(), &engine.rules_file).unwrap();
    engine.reload_from_disk();
    assert!(engine.last_config_error.is_none());
}

#[test]
fn test_dry_run_and_live_integration_with_dedupe_and_max_continuous() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let (_, _) = load_or_init_config(&paths).unwrap();
    let mut engine = WatchdogEngine::initialize(paths, false).unwrap();
    engine.config.max_continuous_default = 2;

    let agents = vec![
        AgentInfo {
            pane: "%1".into(),
            agent: "codex".into(),
            status: "blocked".into(),
            name: None,
            cwd: None,
        },
        AgentInfo {
            pane: "%2".into(),
            agent: "codex".into(),
            status: "error".into(),
            name: None,
            cwd: None,
        },
        AgentInfo {
            pane: "%3".into(),
            agent: "claude".into(),
            status: "error".into(),
            name: None,
            cwd: None,
        },
    ];
    let (client, state) = MockLuvusClient::new(
        agents,
        vec![
            ("%1", "› 1. Yes, proceed with test"),
            ("%2", "Transport error: Connection dropped"),
            ("%3", "❯ run\nError: 401 unauthorized"),
        ],
    );

    // 1. Dry-run scan: zero actual luvus keys/send calls, audit records created.
    engine.scan_once(&client, true).unwrap();
    {
        let st = state.lock().unwrap();
        assert!(st.sent_keys.is_empty());
        assert!(st.sent_texts.is_empty());
    }
    assert!(engine
        .audit_store
        .records()
        .iter()
        .any(|r| r.pane == "%1" && r.result == AuditResult::DryRun));
    assert!(engine
        .audit_store
        .records()
        .iter()
        .any(|r| r.pane == "%2" && r.result == AuditResult::DryRun));
    assert!(engine
        .audit_store
        .records()
        .iter()
        .any(|r| r.pane == "%3" && r.skip_reason == Some(SkipReason::NonRetryable)));

    // 2. Second scan with same signal on %2 is deduped.
    engine.scan_once(&client, true).unwrap();
    assert!(engine
        .audit_store
        .records()
        .iter()
        .any(|r| r.pane == "%2" && r.skip_reason == Some(SkipReason::Dedupe)));

    // 3. Reset %1 and %2, disable cooldown/dedupe for live action test + maxContinuous check.
    engine.reset_pane_continuous("%1");
    engine.reset_pane_continuous("%2");
    for rule in &mut engine.rules_file.rules {
        rule.dedupe.strategy = DedupeStrategy::None;
        rule.cooldown_sec = 0;
    }

    engine.scan_once(&client, false).unwrap();
    assert!(engine.action_seq >= 4);
    assert_eq!(engine.panes.get("%1").unwrap().action_seq, 2);
    {
        let st = state.lock().unwrap();
        assert_eq!(st.sent_keys, vec![("%1".to_string(), vec!["enter".to_string()])]);
        assert_eq!(st.sent_texts, vec![("%2".to_string(), "继续".to_string())]);
    }

    // Second live action reaches maxContinuous=2, third attempt pauses pane %1 without bumping action_seq.
    engine.scan_once(&client, false).unwrap();
    let seq_at_limit = engine.panes.get("%1").unwrap().action_seq;
    assert_eq!(seq_at_limit, 3);
    engine.scan_once(&client, false).unwrap();
    assert_eq!(engine.panes.get("%1").unwrap().action_seq, seq_at_limit);
    assert!(engine.panes.get("%1").unwrap().continuous_paused);
    assert!(engine
        .audit_store
        .records()
        .iter()
        .any(|r| r.pane == "%1" && r.skip_reason == Some(SkipReason::MaxContinuous)));

    // 4. Returning %1 to working resets continuous counter.
    let working_client = MockLuvusClient::new(
        vec![AgentInfo {
            pane: "%1".into(),
            agent: "codex".into(),
            status: "working".into(),
            name: None,
            cwd: None,
        }],
        vec![],
    )
    .0;
    engine.scan_once(&working_client, false).unwrap();
    assert_eq!(engine.panes.get("%1").unwrap().continuous_count, 0);
}

#[test]
fn test_luvus_json_parsers() {
    let list_json = r#"{"result":{"agents":[{"pane":"%1","status":"blocked","agent":"codex","name":"worker"}]}}"#;
    let agents = parse_agent_list_json(list_json).unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].pane, "%1");
    assert_eq!(agents[0].agent, "codex");
    assert_eq!(agents[0].status, "blocked");

    let read_json = r#"{"result":{"text":"1. Yes, allow"}}"#;
    assert_eq!(parse_read_pane_json(read_json).unwrap(), "1. Yes, allow");

    let ev_line = r#"{"event":"agent_status","data":{"pane":"%4","status":"error","agent":"claude"}}"#;
    assert_eq!(
        parse_luvus_event_line(ev_line),
        Some(LuvusEvent::AgentStatus {
            pane: "%4".into(),
            status: "error".into(),
            agent: "claude".into(),
            sequence: None,
        })
    );

    let uhp_ev_line = r#"{"sequence":12,"event":"pane.agent_status_changed","data":{"pane":"%9","status":"blocked","agent":"codex","cwd":"/tmp","project":"p","branch":null,"authority":null}}"#;
    assert_eq!(
        parse_luvus_event_line(uhp_ev_line),
        Some(LuvusEvent::AgentStatus {
            pane: "%9".into(),
            status: "blocked".into(),
            agent: "codex".into(),
            sequence: Some(12),
        })
    );

    let resync_line = r#"{"sequence":13,"event":"events.resync_required","data":{"reason":"subscriber_overflow"}}"#;
    assert_eq!(
        parse_luvus_event_line(resync_line),
        Some(LuvusEvent::ResyncRequired { sequence: Some(13) })
    );
}

#[cfg(unix)]
#[test]
fn test_uhp_unix_socket_client_and_events_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let sock_path = tmp.path().join("luvus.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let recorded_calls: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = Arc::clone(&recorded_calls);

    let server_handle = std::thread::spawn(move || {
        // Expect 4 RPC calls from scan_once (agent.list, agent.read, agent.keys) + 1 subscribe_events
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let req: Value = serde_json::from_str(req_line.trim()).unwrap();
            let id = req["id"].as_str().unwrap().to_string();
            let method = req["method"].as_str().unwrap().to_string();
            let params = req["params"].clone();
            recorded_clone.lock().unwrap().push((method.clone(), params));

            let resp = match method.as_str() {
                "agent.list" => json!({
                    "id": id,
                    "result": {
                        "agents": [
                            { "pane": "%1", "agent": "codex", "status": "blocked" }
                        ]
                    }
                }),
                "agent.read" => json!({
                    "id": id,
                    "result": {
                        "text": "› 1. Yes, proceed"
                    }
                }),
                "agent.keys" => json!({
                    "id": id,
                    "result": { "ok": true }
                }),
                "events.subscribe" => {
                    let ack = format!("{}\n", json!({ "id": id, "result": { "subscribed": true } }));
                    stream.write_all(ack.as_bytes()).unwrap();
                    let ev = format!(
                        "{}\n",
                        json!({
                            "sequence": 7,
                            "event": "pane.agent_status_changed",
                            "data": { "pane": "%1", "status": "working", "agent": "codex" }
                        })
                    );
                    stream.write_all(ev.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    continue;
                }
                _ => json!({ "id": id, "error": { "code": "unknown", "message": "unknown" } }),
            };
            let line = format!("{resp}\n");
            stream.write_all(line.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });

    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths, false).unwrap();
    engine.config.transport_mode = TransportMode::Auto;
    engine.config.luvus_socket_path = sock_path.display().to_string();

    let client = DynamicLuvusClient::from_config(&engine.config);
    assert!(matches!(client, DynamicLuvusClient::Socket(_)));

    // 1. scan_once triggers agent.list -> agent.read -> agent.keys over Unix socket
    engine.scan_once(&client, false).unwrap();
    assert_eq!(engine.total_actions, 1);

    // 2. subscribe_events receives UHP ack + pane.agent_status_changed event
    let uhp = UnixSocketUhpClient::new(&sock_path);
    let mut ev_reader = uhp.subscribe_events(None).unwrap();
    let mut ev_line = String::new();
    ev_reader.read_line(&mut ev_line).unwrap();
    assert_eq!(
        parse_luvus_event_line(&ev_line),
        Some(LuvusEvent::AgentStatus {
            pane: "%1".into(),
            status: "working".into(),
            agent: "codex".into(),
            sequence: Some(7),
        })
    );

    server_handle.join().unwrap();
    let calls = recorded_calls.lock().unwrap();
    assert_eq!(calls[0].0, "agent.list");
    assert_eq!(calls[1].0, "agent.read");
    assert_eq!(calls[1].1["target"], "%1");
    assert_eq!(calls[2].0, "agent.keys");
    assert_eq!(calls[2].1["keys"], json!(["enter"]));
    assert_eq!(calls[3].0, "events.subscribe");
}

#[test]
fn test_idle_badge_color_and_i18n_language_persistence() {
    let default_paths = AppPaths::resolve_default();
    assert!(default_paths.config_dir.ends_with("nudgegeist"));
    assert!(default_paths.cache_dir.ends_with("nudgegeist"));

    assert_eq!(pane_status_colors("idle"), (0xfacc15, 0x0f172a));
    assert_eq!(pane_status_colors("working"), (0x065f46, 0x6ee7b7));
    assert_eq!(pane_status_colors("blocked"), (0x7c2d12, 0xfdba74));
    assert_eq!(pane_status_colors("error"), (0x7f1d1d, 0xfca5a5));

    assert_eq!(tr(UiLanguage::Zh, "仪表盘", "Dashboard"), "仪表盘");
    assert_eq!(tr(UiLanguage::En, "仪表盘", "Dashboard"), "Dashboard");
    assert_eq!(ReviewStatus::PendingReview.label_i18n(UiLanguage::En), "Pending Review");

    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths.clone(), false).unwrap();
    assert_eq!(engine.config.language, UiLanguage::Zh);

    engine.set_language(UiLanguage::En).unwrap();
    let reloaded = WatchdogEngine::initialize(paths, false).unwrap();
    assert_eq!(reloaded.config.language, UiLanguage::En);
}

#[test]
fn test_theme_mode_defaults_to_dark_and_is_persisted() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths.clone(), false).unwrap();
    assert_eq!(engine.config.theme, ThemeMode::Dark);
    assert_eq!(ThemeMode::System.label_i18n(UiLanguage::Zh), "跟随系统");
    assert_eq!(ThemeMode::Light.label_i18n(UiLanguage::En), "Light");

    let mut cfg = engine.config.clone();
    cfg.theme = ThemeMode::System;
    engine.save_config(cfg).unwrap();
    let reloaded = WatchdogEngine::initialize(paths, false).unwrap();
    assert_eq!(reloaded.config.theme, ThemeMode::System);
}

#[test]
fn test_app_icon_and_desktop_registration() {
    assert!(APP_ICON_PNG.starts_with(b"\x89PNG\r\n\x1a\n"));

    let tmp = TempDir::new().unwrap();
    let fake_exe = tmp.path().join("nudgegeist");
    let (icon_path, desktop_path) = write_linux_desktop_files(tmp.path(), &fake_exe).unwrap();

    assert!(icon_path.exists());
    assert!(desktop_path.exists());
    let desktop_txt = fs::read_to_string(desktop_path).unwrap();
    assert!(desktop_txt.contains("StartupWMClass=nudgegeist"));
    assert!(desktop_txt.contains("Name=Nudgegeist"));
    assert!(desktop_txt.contains("Name[zh_CN]=辣椒"));
    assert!(desktop_txt.contains(&icon_path.display().to_string()));
}

#[test]
fn test_pretty_time_formatting() {
    let now = chrono::Utc::now();
    assert_eq!(pretty_time(now, now, UiLanguage::Zh), "刚刚");
    assert_eq!(pretty_time(now, now, UiLanguage::En), "just now");
    assert_eq!(
        pretty_time(now - chrono::Duration::seconds(25), now, UiLanguage::Zh),
        "25秒前"
    );
    assert_eq!(
        pretty_time(now - chrono::Duration::minutes(5), now, UiLanguage::Zh),
        "5分钟前"
    );
    assert_eq!(
        pretty_time(now - chrono::Duration::hours(3), now, UiLanguage::En),
        "3h ago"
    );
}

#[test]
fn test_snapshot_panes_sorted_by_last_status_change_time() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths, false).unwrap();

    let (client, _) = MockLuvusClient::new(
        vec![
            AgentInfo {
                pane: "1".into(),
                agent: "antigravity".into(),
                status: "idle".into(),
                name: None,
                cwd: None,
            },
            AgentInfo {
                pane: "2".into(),
                agent: "codex".into(),
                status: "working".into(),
                name: None,
                cwd: None,
            },
            AgentInfo {
                pane: "10".into(),
                agent: "opencode".into(),
                status: "idle".into(),
                name: None,
                cwd: None,
            },
        ],
        vec![],
    );

    engine.scan_once(&client, true).unwrap();

    // Pane 1 changes status from idle -> working: moves to the top
    std::thread::sleep(std::time::Duration::from_millis(5));
    engine.process_agent_info(
        &client,
        &AgentInfo {
            pane: "1".into(),
            agent: "antigravity".into(),
            status: "working".into(),
            name: None,
            cwd: None,
        },
        true,
    );
    let snap1 = engine.snapshot();
    assert_eq!(snap1.panes[0].pane, "1");

    // Pane 10 changes status from idle -> blocked: moves above pane 1
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (client3, _) = MockLuvusClient::new(vec![], vec![("10", "no matching text")]);
    engine.process_agent_info(
        &client3,
        &AgentInfo {
            pane: "10".into(),
            agent: "opencode".into(),
            status: "blocked".into(),
            name: None,
            cwd: None,
        },
        true,
    );
    let snap2 = engine.snapshot();
    let order2: Vec<&str> = snap2.panes.iter().map(|p| p.pane.as_str()).collect();
    assert_eq!(order2, vec!["10", "1", "2"]);
}

#[test]
fn test_cooldown_skip_schedules_recheck_and_executes_without_waiting_poll() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths, false).unwrap();

    // Use a 1s cooldown rule so test runs fast while proving due-recheck behavior.
    engine.rules_file.rules.iter_mut().for_each(|r| {
        if r.id == "approve-yes" {
            r.cooldown_sec = 1;
        }
    });

    let blocked_agent = AgentInfo {
        pane: "1".into(),
        agent: "codex".into(),
        status: "blocked".into(),
        name: None,
        cwd: None,
    };
    let working_agent = AgentInfo {
        pane: "1".into(),
        agent: "codex".into(),
        status: "working".into(),
        name: None,
        cwd: None,
    };

    let (client, state) = MockLuvusClient::new(
        vec![blocked_agent.clone()],
        vec![("1", "› 1. Yes, proceed")],
    );

    // First blocked transition executes enter immediately.
    engine.process_agent_info(&client, &blocked_agent, false);
    assert_eq!(state.lock().unwrap().sent_keys.len(), 1);

    // Quick cycle working -> blocked within cooldown skips and schedules recheck.
    engine.process_agent_info(&client, &working_agent, false);
    engine.process_agent_info(&client, &blocked_agent, false);
    assert_eq!(state.lock().unwrap().sent_keys.len(), 1);
    assert_eq!(engine.process_due_rechecks(&client, false), 0);

    // Wait just past cooldown (1.05s) without calling scan_once; recheck executes enter!
    std::thread::sleep(std::time::Duration::from_millis(1120));
    assert_eq!(engine.process_due_rechecks(&client, false), 1);
    assert_eq!(state.lock().unwrap().sent_keys.len(), 2);
}

#[test]
fn test_engine_session_kpi_counters_start_at_zero_and_count_current_run() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());

    {
        let mut eng = WatchdogEngine::initialize(paths.clone(), false).unwrap();
        let (ok_client, _) = MockLuvusClient::new(
            vec![AgentInfo {
                pane: "1".into(),
                agent: "codex".into(),
                status: "blocked".into(),
                name: None,
                cwd: None,
            }],
            vec![("1", "› 1. Yes, proceed")],
        );
        eng.scan_once(&ok_client, true).unwrap();
        eng.reset_pane_continuous("1");
        eng.rules_file.rules.iter_mut().for_each(|r| {
            r.cooldown_sec = 0;
            r.dedupe.strategy = DedupeStrategy::None;
        });
        eng.save_rules(eng.rules_file.clone()).unwrap();
        eng.scan_once(&ok_client, false).unwrap();
        assert_eq!(eng.total_dry_runs, 1);
        assert_eq!(eng.total_actions, 1);
        assert_eq!(eng.rule_hit_counts.get("approve-yes").copied(), Some(2));
    }

    // Re-initializing starts a new session with zeroed KPI counters while keeping audit history.
    let mut next_session = WatchdogEngine::initialize(paths, false).unwrap();
    assert_eq!(next_session.total_dry_runs, 0);
    assert_eq!(next_session.total_actions, 0);
    assert_eq!(next_session.total_errors, 0);
    assert!(next_session.rule_hit_counts.is_empty());
    assert_eq!(next_session.audit_store.records().len(), 2);

    next_session.clear_audit_logs().unwrap();
    assert!(next_session.audit_store.records().is_empty());
}

#[test]
fn test_parse_quota_reset_delay_formats() {
    assert_eq!(
        parse_quota_reset_delay("Resets in 1h8m25s."),
        Some(Duration::from_secs(4105))
    );
    assert_eq!(
        parse_quota_reset_delay("resets in 8m"),
        Some(Duration::from_secs(480))
    );
    assert_eq!(
        parse_quota_reset_delay("Resets in 45s"),
        Some(Duration::from_secs(45))
    );
    assert_eq!(
        parse_quota_reset_delay("Individual quota reached. Resets in 1h 8m 25s."),
        Some(Duration::from_secs(4105))
    );
    assert_eq!(parse_quota_reset_delay("no countdown here"), None);
    // Repeated errors in scrollback: wait for the latest reset.
    assert_eq!(
        parse_quota_reset_delay("Resets in 5m\nResets in 1h"),
        Some(Duration::from_secs(3600))
    );
}

#[test]
fn test_quota_reset_defers_continuation_and_reschedules_on_new_error() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths.clone(), false).unwrap();
    engine.config.quota_resume_padding_sec = 0;

    let agent = AgentInfo {
        pane: "5".into(),
        agent: "antigravity".into(),
        status: "idle".into(),
        name: None,
        cwd: None,
    };
    let old_text = "⚠ Individual quota reached. Resets in 0s.\nError ID: old";
    let (client, state) = MockLuvusClient::new(vec![agent.clone()], vec![("5", old_text)]);

    engine.process_agent_info(&client, &agent, false);
    assert!(state.lock().unwrap().sent_texts.is_empty());
    assert!(engine.deferred_resumes.contains_key("5"));

    // Schedule survives an engine restart.
    let restored = WatchdogEngine::initialize(paths, false).unwrap();
    assert!(restored.deferred_resumes.contains_key("5"));

    // A newer quota error while waiting postpones the continuation, with no send.
    state.lock().unwrap().pane_texts.insert(
        "5".to_string(),
        "⚠ Individual quota reached. Resets in 10m.\nError ID: new".to_string(),
    );
    engine.deferred_resumes.get_mut("5").unwrap().due_at = Instant::now();
    assert_eq!(engine.process_due_quota_resumes(&client, false), 0);
    assert_eq!(engine.deferred_resumes["5"].parsed_delay_sec, 600);
    assert!(state.lock().unwrap().sent_texts.is_empty());

    // Once the (new) reset time elapses, exactly one "继续" is sent.
    engine.deferred_resumes.get_mut("5").unwrap().due_at = Instant::now();
    assert_eq!(engine.process_due_quota_resumes(&client, false), 1);
    assert!(!engine.deferred_resumes.contains_key("5"));
    assert_eq!(
        state.lock().unwrap().sent_texts,
        vec![("5".to_string(), "继续".to_string())]
    );
}

#[test]
fn test_windows_named_pipe_resolution_and_session_discovery_parser() {
    use std::path::Path;

    let explicit = windows_pipe_name_from_socket_path(Path::new(r"\\.\pipe\luvus-custom"));
    assert_eq!(explicit, r"\\.\pipe\luvus-custom");

    let hashed = windows_pipe_name_from_socket_path(Path::new(r"C:\Users\alice\.luvus\luvus.sock"));
    assert!(hashed.starts_with(r"\\.\pipe\luvus-"));
    assert_eq!(hashed.len(), r"\\.\pipe\luvus-".len() + 16);

    let session_json = r#"{
        "sessions": [
            {
                "name": "other",
                "default": false,
                "running": true,
                "endpoint": { "transport": "windows_named_pipe", "address": "\\\\.\\pipe\\luvus-other" }
            },
            {
                "name": "default",
                "default": true,
                "running": true,
                "endpoint": { "transport": "windows_named_pipe", "address": "\\\\.\\pipe\\luvus-0123456789abcdef" }
            }
        ]
    }"#;
    assert_eq!(
        parse_session_list_pipe_address(session_json).as_deref(),
        Some(r"\\.\pipe\luvus-0123456789abcdef")
    );
}

#[test]
fn test_exited_agent_and_shell_panes_are_removed_and_hidden() {
    let tmp = TempDir::new().unwrap();
    let paths = AppPaths::from_root(tmp.path());
    let mut engine = WatchdogEngine::initialize(paths, false).unwrap();

    // Active agent pane alongside plain shell panes
    let (client1, _) = MockLuvusClient::new(
        vec![
            AgentInfo {
                pane: "1".into(),
                agent: "codex".into(),
                status: "working".into(),
                name: None,
                cwd: None,
            },
            AgentInfo {
                pane: "2".into(),
                agent: "/bin/zsh".into(),
                status: "idle".into(),
                name: None,
                cwd: None,
            },
            AgentInfo {
                pane: "3".into(),
                agent: "pwsh.exe".into(),
                status: "idle".into(),
                name: None,
                cwd: None,
            },
        ],
        vec![],
    );
    engine.scan_once(&client1, true).unwrap();
    let panes: Vec<&str> = engine.panes.keys().map(String::as_str).collect();
    assert_eq!(panes, vec!["1"]);

    // Agent in pane 1 exits back to bash shell via incremental update -> pane 1 disappears.
    engine.process_agent_info(
        &client1,
        &AgentInfo {
            pane: "1".into(),
            agent: "-bash".into(),
            status: "idle".into(),
            name: None,
            cwd: None,
        },
        true,
    );
    assert!(engine.panes.is_empty());

    // Bring pane 4 back, then verify missing pane on scan_once is pruned cleanly.
    let (client2, _) = MockLuvusClient::new(
        vec![AgentInfo {
            pane: "4".into(),
            agent: "claude".into(),
            status: "idle".into(),
            name: None,
            cwd: None,
        }],
        vec![],
    );
    engine.scan_once(&client2, true).unwrap();
    assert!(engine.panes.contains_key("4"));

    let (empty_client, _) = MockLuvusClient::new(vec![], vec![]);
    engine.scan_once(&empty_client, true).unwrap();
    assert!(engine.panes.is_empty());

    assert_eq!(
        parse_luvus_event_line(
            r#"{"event":"pane.closed","sequence":12,"data":{"pane":"4"}}"#
        ),
        Some(LuvusEvent::PaneClosed {
            pane: "4".into(),
            sequence: Some(12),
        })
    );
    assert_eq!(
        parse_luvus_event_line(
            r#"{"event":"terminal.closed","sequence":13,"data":{"pane_id":"5"}}"#
        ),
        Some(LuvusEvent::PaneClosed {
            pane: "5".into(),
            sequence: Some(13),
        })
    );
}

#[test]
fn test_luvus_installation_detection_and_command_preview() {
    let preview = luvus_install_command_preview();
    assert!(!preview.is_empty());

    let missing = detect_luvus_installation("/nonexistent/path/to/luvus-missing-bin");
    assert!(!missing.installed);
    assert!(missing.resolved_path.is_none());
    assert!(missing.version.is_none());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let fake_bin = tmp.path().join("luvus");
        std::fs::write(&fake_bin, "#!/bin/sh\necho 'luvus 0.9.9-test'\n").unwrap();
        let mut perms = std::fs::metadata(&fake_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_bin, perms).unwrap();

        let resolved = resolve_luvus_executable(fake_bin.to_str().unwrap());
        assert_eq!(resolved.as_deref(), Some(fake_bin.as_path()));

        let status = detect_luvus_installation(fake_bin.to_str().unwrap());
        assert!(status.installed);
        assert_eq!(status.version.as_deref(), Some("luvus 0.9.9-test"));
        assert_eq!(
            status.resolved_path.as_deref(),
            Some(fake_bin.to_string_lossy().as_ref())
        );
    }
}
