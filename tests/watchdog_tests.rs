use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::{Value, json};
use tempfile::TempDir;

use nudgegeist::audit::{AuditResult, SkipReason};
use nudgegeist::config::{
    ActionType, AppPaths, DedupeStrategy, MatchSource, ReviewStatus, Rule, RuleAction,
    RuleDedupe, RuleGuards, RuleMatch, RulesFile, TransportMode, UiLanguage, WatchdogConfig,
    import_rules_json, load_or_init_config, save_json_atomic, validate_rule,
};
use nudgegeist::engine::{FinalDecision, WatchdogEngine, evaluate_rules_stateless};
#[cfg(unix)]
use nudgegeist::luvus::UnixSocketUhpClient;
use nudgegeist::luvus::{
    AgentInfo, DynamicLuvusClient, LuvusClient, LuvusEvent, parse_agent_list_json,
    parse_luvus_event_line, parse_read_pane_json,
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
    let (client2, _) = MockLuvusClient::new(
        vec![AgentInfo {
            pane: "1".into(),
            agent: "antigravity".into(),
            status: "working".into(),
            name: None,
            cwd: None,
        }],
        vec![],
    );
    engine.scan_once(&client2, true).unwrap();
    let snap1 = engine.snapshot();
    assert_eq!(snap1.panes[0].pane, "1");

    // Pane 10 changes status from idle -> blocked: moves above pane 1
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (client3, _) = MockLuvusClient::new(
        vec![AgentInfo {
            pane: "10".into(),
            agent: "opencode".into(),
            status: "blocked".into(),
            name: None,
            cwd: None,
        }],
        vec![("10", "no matching text")],
    );
    engine.scan_once(&client3, true).unwrap();
    let snap2 = engine.snapshot();
    let order2: Vec<&str> = snap2.panes.iter().map(|p| p.pane.as_str()).collect();
    assert_eq!(order2, vec!["10", "1", "2"]);
}
