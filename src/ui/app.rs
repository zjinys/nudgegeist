use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpui::{
    Animation, AnimationExt as _, AnyElement, App, Application, Bounds, ClipboardItem, Context,
    CursorStyle, Decorations, Entity, MouseButton, ResizeEdge, SharedString, TitlebarOptions,
    Window, WindowBounds, WindowControlArea, WindowDecorations, WindowOptions, div,
    ease_out_quint, point, prelude::*, px, rgb, size,
};

pub const APP_ICON_PNG: &[u8] = include_bytes!("../../assets/nudgegeist.png");

use crate::audit::{AuditRecord, AuditResult};
use crate::config::{
    ActionType, AppPaths, DedupeStrategy, MatchRegion, MatchSource, ReviewStatus, Rule,
    RuleAction, RuleDedupe, RuleGuards, RuleMatch, TransportMode, UiLanguage, WatchdogConfig,
    import_rules_json, new_rule_template, split_csv, validate_config, validate_rule,
};
use crate::engine::{
    EngineSnapshot, EvaluationReport, FinalDecision, WatchdogEngine, evaluate_rules_stateless,
    spawn_engine_loop,
};
use crate::luvus::{DynamicLuvusClient, LuvusClient};
use crate::ui::i18n::{pretty_time_with_clock, tr};
use crate::ui::text_input::{TextInput, bind_input_keys};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Dashboard,
    Rules,
    Tester,
    Audit,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEditorMode {
    Form,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditFilter {
    All,
    Success,
    DryRun,
    Skipped,
    Failure,
}

pub fn pane_status_colors(status: &str) -> (u32, u32) {
    match status {
        "working" => (0x065f46, 0x6ee7b7),
        "idle" => (0xfacc15, 0x0f172a),
        "blocked" => (0x7c2d12, 0xfdba74),
        "done" => (0x1e3a8a, 0x93c5fd),
        _ => (0x7f1d1d, 0xfca5a5),
    }
}

struct RuleFormInputs {
    id: Entity<TextInput>,
    name: Entity<TextInput>,
    priority: Entity<TextInput>,
    agents: Entity<TextInput>,
    panes: Entity<TextInput>,
    statuses: Entity<TextInput>,
    lines: Entity<TextInput>,
    any_regex: Entity<TextInput>,
    all_regex: Entity<TextInput>,
    none_regex: Entity<TextInput>,
    guard_none_regex: Entity<TextInput>,
    action_keys: Entity<TextInput>,
    action_text: Entity<TextInput>,
    dedupe_window: Entity<TextInput>,
    cooldown_sec: Entity<TextInput>,
    max_continuous: Entity<TextInput>,
    json_editor: Entity<TextInput>,
}

struct RuleEditorState {
    selected_rule_id: Option<String>,
    mode: RuleEditorMode,
    enabled: bool,
    dry_run_only: bool,
    review_status: ReviewStatus,
    source: MatchSource,
    region: MatchRegion,
    case_insensitive: bool,
    skip_if_claude_retrying: bool,
    action_type: ActionType,
    dedupe_strategy: DedupeStrategy,
    source_origin: Option<String>,
    validation_errors: Vec<String>,
    inputs: RuleFormInputs,
}

struct TesterState {
    pane_input: Entity<TextInput>,
    text_input: Entity<TextInput>,
    agent: String,
    status: String,
    report: Option<EvaluationReport>,
    live_read_error: Option<String>,
}

struct SettingsInputs {
    luvus_socket_path: Entity<TextInput>,
    luvus_bin: Entity<TextInput>,
    scan_interval_sec: Entity<TextInput>,
    reconnect_delay_sec: Entity<TextInput>,
    read_lines_blocked: Entity<TextInput>,
    read_lines_error: Entity<TextInput>,
    allowed_panes: Entity<TextInput>,
    allowed_agents: Entity<TextInput>,
    whitelisted_keys: Entity<TextInput>,
    whitelisted_send_texts: Entity<TextInput>,
    non_retryable_regexes: Entity<TextInput>,
    max_continuous_default: Entity<TextInput>,
    audit_retention_days: Entity<TextInput>,
}

struct SettingsState {
    language: UiLanguage,
    transport_mode: TransportMode,
    global_dry_run: bool,
    paused_all: bool,
    redact_audit_summary: bool,
    validation_errors: Vec<String>,
    inputs: SettingsInputs,
}

pub struct WatchdogApp {
    engine: Arc<Mutex<WatchdogEngine>>,
    snapshot: EngineSnapshot,
    active_tab: ActiveTab,
    rule_editor: RuleEditorState,
    import_panel_open: bool,
    import_input: Entity<TextInput>,
    import_errors: Vec<String>,
    tester: TesterState,
    audit_filter: AuditFilter,
    audit_search_input: Entity<TextInput>,
    settings: SettingsState,
    status_banner: Option<(bool, String)>,
    last_seen_action_seq: u64,
    last_state_version: u64,
    last_clock_tick: Instant,
    window_nudge_seq: u64,
    window_nudge_until: Option<Instant>,
    prev_pane_action_seqs: HashMap<String, u64>,
    pane_nudge_seqs: HashMap<String, (u64, Instant)>,
    prev_pane_indices: HashMap<String, usize>,
    next_move_seq: u64,
    pane_move_anims: HashMap<String, (u64, i32, Instant)>,
}

impl WatchdogApp {
    pub fn new(engine: Arc<Mutex<WatchdogEngine>>, cx: &mut Context<Self>) -> Self {
        let snapshot = engine.lock().unwrap().snapshot();
        let lang = snapshot.config.language;
        let initial_rule = snapshot.rules_file.rules.first().cloned();
        let rule_editor = Self::build_rule_editor(initial_rule.as_ref(), lang, cx);
        let import_input = cx.new(|cx| {
            TextInput::new(
                cx,
                tr(
                    lang,
                    "粘贴要导入的规则 JSON（支持数组或 rules.json 对象）...",
                    "Paste rules JSON to import (array or rules.json object)...",
                ),
                "",
                true,
            )
            .with_monospace(true)
            .with_line_limits(6, 12)
        });

        let sample_prompt =
            "Codex blocked:\n  1. Yes, proceed with running cargo test\n  2. No, cancel";
        let tester = TesterState {
            pane_input: cx.new(|cx| {
                TextInput::new(cx, tr(lang, "可选 pane ID，如 %1", "Optional pane ID, e.g. %1"), "", false)
            }),
            text_input: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(
                        lang,
                        "在此粘贴终端输出文本进行规则测试...",
                        "Paste terminal output text here to test rules...",
                    ),
                    sample_prompt,
                    true,
                )
                .with_monospace(true)
                .with_line_limits(6, 14)
            }),
            agent: "codex".to_string(),
            status: "blocked".to_string(),
            report: None,
            live_read_error: None,
        };

        let audit_search_input = cx.new(|cx| {
            TextInput::new(
                cx,
                tr(
                    lang,
                    "按 pane / agent / 规则 / 摘要搜索...",
                    "Filter by pane / agent / rule / summary...",
                ),
                "",
                false,
            )
        });

        let settings = Self::build_settings(&snapshot.config, cx);

        cx.spawn(async move |this, cx| {
            loop {
                smol::Timer::after(Duration::from_millis(800)).await;
                let res = this.update(cx, |app, cx| {
                    let current_ver = app.engine.lock().unwrap().state_version;
                    if current_ver != app.last_state_version {
                        app.refresh_snapshot();
                        app.last_clock_tick = Instant::now();
                        cx.notify();
                        return;
                    }
                    let mut dirty = app.prune_expired_animations();
                    if let Some(interval) = app.relative_clock_tick_interval()
                        && app.last_clock_tick.elapsed() >= interval
                    {
                        app.last_clock_tick = Instant::now();
                        dirty = true;
                    }
                    if dirty {
                        cx.notify();
                    }
                });
                if res.is_err() {
                    break;
                }
            }
        })
        .detach();

        let initial_seq = snapshot.action_seq;
        let initial_ver = snapshot.state_version;
        let initial_pane_seqs: HashMap<String, u64> = snapshot
            .panes
            .iter()
            .map(|p| (p.pane.clone(), p.action_seq))
            .collect();
        let initial_pane_indices: HashMap<String, usize> = snapshot
            .panes
            .iter()
            .enumerate()
            .map(|(idx, p)| (p.pane.clone(), idx))
            .collect();

        let mut app = Self {
            engine,
            snapshot,
            active_tab: ActiveTab::Dashboard,
            rule_editor,
            import_panel_open: false,
            import_input,
            import_errors: Vec::new(),
            tester,
            audit_filter: AuditFilter::All,
            audit_search_input,
            settings,
            status_banner: None,
            last_seen_action_seq: initial_seq,
            last_state_version: initial_ver,
            last_clock_tick: Instant::now(),
            window_nudge_seq: 0,
            window_nudge_until: None,
            prev_pane_action_seqs: initial_pane_seqs,
            pane_nudge_seqs: HashMap::new(),
            prev_pane_indices: initial_pane_indices,
            next_move_seq: 0,
            pane_move_anims: HashMap::new(),
        };
        app.run_simulation_internal(cx);
        app
    }

    fn lang(&self) -> UiLanguage {
        self.snapshot.config.language
    }

    fn build_rule_editor(
        rule: Option<&Rule>,
        lang: UiLanguage,
        cx: &mut Context<Self>,
    ) -> RuleEditorState {
        let r = rule.cloned().unwrap_or_else(|| new_rule_template(&[]));
        let json_str = serde_json::to_string_pretty(&r).unwrap_or_default();
        let inputs = RuleFormInputs {
            id: cx.new(|cx| TextInput::new(cx, "rule-id", r.id.clone(), false)),
            name: cx.new(|cx| {
                TextInput::new(cx, tr(lang, "规则名称", "Rule name"), r.name.clone(), false)
            }),
            priority: cx.new(|cx| TextInput::new(cx, "100", r.priority.to_string(), false)),
            agents: cx.new(|cx| TextInput::new(cx, "*, codex, claude", r.agents.join(", "), false)),
            panes: cx.new(|cx| TextInput::new(cx, "*", r.panes.join(", "), false)),
            statuses: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "blocked 或 !working", "blocked or !working"),
                    r.statuses.join(", "),
                    false,
                )
            }),
            lines: cx.new(|cx| TextInput::new(cx, "12", r.match_cfg.lines.to_string(), false)),
            any_regex: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "每行一条正则", "One regex per line"),
                    r.match_cfg.any_regex.join("\n"),
                    true,
                )
                .with_monospace(true)
                .with_line_limits(3, 8)
            }),
            all_regex: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "每行一条必须全部命中的正则", "All regexes must match"),
                    r.match_cfg.all_regex.join("\n"),
                    true,
                )
                .with_monospace(true)
                .with_line_limits(2, 6)
            }),
            none_regex: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "每行一条排除正则", "Exclude if any matches"),
                    r.match_cfg.none_regex.join("\n"),
                    true,
                )
                .with_monospace(true)
                .with_line_limits(2, 6)
            }),
            guard_none_regex: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "危险词保护正则（每行一条）", "Guard block regexes (one per line)"),
                    r.guards.none_regex.join("\n"),
                    true,
                )
                .with_monospace(true)
                .with_line_limits(2, 6)
            }),
            action_keys: cx
                .new(|cx| TextInput::new(cx, "enter", r.action.keys.join(", "), false)),
            action_text: cx.new(|cx| {
                TextInput::new(
                    cx,
                    "继续",
                    r.action.text.clone().unwrap_or_else(|| "继续".to_string()),
                    false,
                )
            }),
            dedupe_window: cx
                .new(|cx| TextInput::new(cx, "300", r.dedupe.window_sec.to_string(), false)),
            cooldown_sec: cx
                .new(|cx| TextInput::new(cx, "2", r.cooldown_sec.to_string(), false)),
            max_continuous: cx.new(|cx| {
                TextInput::new(
                    cx,
                    tr(lang, "0（不限）", "0 (unlimited)"),
                    r.max_continuous.to_string(),
                    false,
                )
            }),
            json_editor: cx.new(|cx| {
                TextInput::new(cx, "{ ... }", json_str, true)
                    .with_monospace(true)
                    .with_line_limits(14, 24)
            }),
        };

        RuleEditorState {
            selected_rule_id: rule.map(|x| x.id.clone()),
            mode: RuleEditorMode::Form,
            enabled: r.enabled,
            dry_run_only: r.dry_run_only,
            review_status: r.review_status,
            source: r.match_cfg.source,
            region: r.match_cfg.region,
            case_insensitive: r.match_cfg.case_insensitive,
            skip_if_claude_retrying: r.guards.skip_if_claude_retrying,
            action_type: r.action.action_type,
            dedupe_strategy: r.dedupe.strategy,
            source_origin: r.source_origin,
            validation_errors: Vec::new(),
            inputs,
        }
    }

    fn build_settings(cfg: &WatchdogConfig, cx: &mut Context<Self>) -> SettingsState {
        let lang = cfg.language;
        SettingsState {
            language: cfg.language,
            transport_mode: cfg.transport_mode,
            global_dry_run: cfg.global_dry_run,
            paused_all: cfg.paused_all,
            redact_audit_summary: cfg.redact_audit_summary,
            validation_errors: Vec::new(),
            inputs: SettingsInputs {
                luvus_socket_path: cx.new(|cx| {
                    TextInput::new(
                        cx,
                        tr(
                            lang,
                            "留空则自动使用 $LUVUS_SOCKET_PATH 或 ~/.luvus/luvus.sock",
                            "Leave empty to auto-use $LUVUS_SOCKET_PATH or ~/.luvus/luvus.sock",
                        ),
                        cfg.luvus_socket_path.clone(),
                        false,
                    )
                }),
                luvus_bin: cx.new(|cx| TextInput::new(cx, "luvus", cfg.luvus_bin.clone(), false)),
                scan_interval_sec: cx.new(|cx| {
                    TextInput::new(cx, "15", cfg.scan_interval_sec.to_string(), false)
                }),
                reconnect_delay_sec: cx.new(|cx| {
                    TextInput::new(cx, "2", cfg.reconnect_delay_sec.to_string(), false)
                }),
                read_lines_blocked: cx.new(|cx| {
                    TextInput::new(cx, "12", cfg.read_lines_blocked.to_string(), false)
                }),
                read_lines_error: cx.new(|cx| {
                    TextInput::new(cx, "40", cfg.read_lines_error.to_string(), false)
                }),
                allowed_panes: cx
                    .new(|cx| TextInput::new(cx, "*", cfg.allowed_panes.join(", "), false)),
                allowed_agents: cx
                    .new(|cx| TextInput::new(cx, "*", cfg.allowed_agents.join(", "), false)),
                whitelisted_keys: cx.new(|cx| {
                    TextInput::new(
                        cx,
                        "enter, esc, up, down",
                        cfg.whitelisted_keys.join(", "),
                        false,
                    )
                }),
                whitelisted_send_texts: cx.new(|cx| {
                    TextInput::new(cx, "继续", cfg.whitelisted_send_texts.join(", "), false)
                }),
                non_retryable_regexes: cx.new(|cx| {
                    TextInput::new(
                        cx,
                        tr(
                            lang,
                            "不可重试错误正则（每行一条）",
                            "Non-retryable error regexes (one per line)",
                        ),
                        cfg.non_retryable_regexes.join("\n"),
                        true,
                    )
                    .with_monospace(true)
                    .with_line_limits(4, 8)
                }),
                max_continuous_default: cx.new(|cx| {
                    TextInput::new(cx, "0", cfg.max_continuous_default.to_string(), false)
                }),
                audit_retention_days: cx.new(|cx| {
                    TextInput::new(cx, "30", cfg.audit_retention_days.to_string(), false)
                }),
            },
        }
    }

    fn load_rule_into_editor(&mut self, rule: &Rule, cx: &mut Context<Self>) {
        self.rule_editor.selected_rule_id = Some(rule.id.clone());
        self.rule_editor.enabled = rule.enabled;
        self.rule_editor.dry_run_only = rule.dry_run_only;
        self.rule_editor.review_status = rule.review_status;
        self.rule_editor.source = rule.match_cfg.source;
        self.rule_editor.region = rule.match_cfg.region;
        self.rule_editor.case_insensitive = rule.match_cfg.case_insensitive;
        self.rule_editor.skip_if_claude_retrying = rule.guards.skip_if_claude_retrying;
        self.rule_editor.action_type = rule.action.action_type;
        self.rule_editor.dedupe_strategy = rule.dedupe.strategy;
        self.rule_editor.source_origin = rule.source_origin.clone();
        self.rule_editor.validation_errors.clear();

        let inp = &self.rule_editor.inputs;
        inp.id.update(cx, |i, cx| i.set_text(rule.id.clone(), cx));
        inp.name.update(cx, |i, cx| i.set_text(rule.name.clone(), cx));
        inp.priority
            .update(cx, |i, cx| i.set_text(rule.priority.to_string(), cx));
        inp.agents
            .update(cx, |i, cx| i.set_text(rule.agents.join(", "), cx));
        inp.panes
            .update(cx, |i, cx| i.set_text(rule.panes.join(", "), cx));
        inp.statuses
            .update(cx, |i, cx| i.set_text(rule.statuses.join(", "), cx));
        inp.lines
            .update(cx, |i, cx| i.set_text(rule.match_cfg.lines.to_string(), cx));
        inp.any_regex
            .update(cx, |i, cx| i.set_text(rule.match_cfg.any_regex.join("\n"), cx));
        inp.all_regex
            .update(cx, |i, cx| i.set_text(rule.match_cfg.all_regex.join("\n"), cx));
        inp.none_regex
            .update(cx, |i, cx| i.set_text(rule.match_cfg.none_regex.join("\n"), cx));
        inp.guard_none_regex
            .update(cx, |i, cx| i.set_text(rule.guards.none_regex.join("\n"), cx));
        inp.action_keys
            .update(cx, |i, cx| i.set_text(rule.action.keys.join(", "), cx));
        inp.action_text.update(cx, |i, cx| {
            i.set_text(rule.action.text.clone().unwrap_or_default(), cx)
        });
        inp.dedupe_window.update(cx, |i, cx| {
            i.set_text(rule.dedupe.window_sec.to_string(), cx)
        });
        inp.cooldown_sec
            .update(cx, |i, cx| i.set_text(rule.cooldown_sec.to_string(), cx));
        inp.max_continuous
            .update(cx, |i, cx| i.set_text(rule.max_continuous.to_string(), cx));

        let json_str = serde_json::to_string_pretty(rule).unwrap_or_default();
        inp.json_editor.update(cx, |i, cx| i.set_text(json_str, cx));
        cx.notify();
    }

    fn rule_from_editor_form(&self, cx: &App) -> Result<Rule, Vec<String>> {
        let lang = self.lang();
        let mut errs = Vec::new();
        let inp = &self.rule_editor.inputs;
        let id = inp.id.read(cx).text().trim().to_string();
        let name = inp.name.read(cx).text().trim().to_string();
        let priority = inp
            .priority
            .read(cx)
            .text()
            .trim()
            .parse::<i32>()
            .unwrap_or_else(|_| {
                errs.push(tr(lang, "priority 必须是整数", "priority must be an integer").into());
                50
            });
        let lines = inp
            .lines
            .read(cx)
            .text()
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|_| {
                errs.push(tr(lang, "读取行数 lines 必须是非负整数", "lines must be a non-negative integer").into());
                12
            });
        let dedupe_window = inp
            .dedupe_window
            .read(cx)
            .text()
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|_| {
                errs.push(tr(lang, "dedupe.windowSec 必须是非负整数", "dedupe.windowSec must be a non-negative integer").into());
                300
            });
        let cooldown_sec = inp
            .cooldown_sec
            .read(cx)
            .text()
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|_| {
                errs.push(tr(lang, "cooldownSec 必须是非负整数", "cooldownSec must be a non-negative integer").into());
                2
            });
        let max_continuous = inp
            .max_continuous
            .read(cx)
            .text()
            .trim()
            .parse::<u32>()
            .unwrap_or_else(|_| {
                errs.push(tr(lang, "maxContinuous 必须是非负整数", "maxContinuous must be a non-negative integer").into());
                0
            });

        let split_lines = |s: String| -> Vec<String> {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        };

        let action = match self.rule_editor.action_type {
            ActionType::Keys => RuleAction {
                action_type: ActionType::Keys,
                keys: split_csv(&inp.action_keys.read(cx).text()),
                text: None,
            },
            ActionType::Send => RuleAction {
                action_type: ActionType::Send,
                keys: vec![],
                text: Some(inp.action_text.read(cx).text().trim().to_string()),
            },
        };

        let rule = Rule {
            id,
            name,
            enabled: self.rule_editor.enabled,
            dry_run_only: self.rule_editor.dry_run_only,
            priority,
            agents: split_csv(&inp.agents.read(cx).text()),
            panes: split_csv(&inp.panes.read(cx).text()),
            statuses: split_csv(&inp.statuses.read(cx).text()),
            match_cfg: RuleMatch {
                source: self.rule_editor.source,
                lines,
                region: self.rule_editor.region,
                any_regex: split_lines(inp.any_regex.read(cx).text()),
                all_regex: split_lines(inp.all_regex.read(cx).text()),
                none_regex: split_lines(inp.none_regex.read(cx).text()),
                case_insensitive: self.rule_editor.case_insensitive,
            },
            guards: RuleGuards {
                none_regex: split_lines(inp.guard_none_regex.read(cx).text()),
                skip_if_claude_retrying: self.rule_editor.skip_if_claude_retrying,
            },
            action,
            dedupe: RuleDedupe {
                strategy: self.rule_editor.dedupe_strategy,
                window_sec: dedupe_window,
            },
            cooldown_sec,
            max_continuous,
            source_origin: self.rule_editor.source_origin.clone(),
            review_status: self.rule_editor.review_status,
        };

        if let Err(mut rule_errs) = validate_rule(&rule, &self.snapshot.config) {
            errs.append(&mut rule_errs);
        }
        if errs.is_empty() {
            Ok(rule)
        } else {
            Err(errs)
        }
    }

    fn sync_settings_from_config(&mut self, cfg: &WatchdogConfig, cx: &mut Context<Self>) {
        self.settings.language = cfg.language;
        self.settings.transport_mode = cfg.transport_mode;
        self.settings.global_dry_run = cfg.global_dry_run;
        self.settings.paused_all = cfg.paused_all;
        self.settings.redact_audit_summary = cfg.redact_audit_summary;
        let inp = &self.settings.inputs;
        inp.luvus_socket_path
            .update(cx, |i, cx| i.set_text(cfg.luvus_socket_path.clone(), cx));
        inp.luvus_bin
            .update(cx, |i, cx| i.set_text(cfg.luvus_bin.clone(), cx));
        inp.scan_interval_sec.update(cx, |i, cx| {
            i.set_text(cfg.scan_interval_sec.to_string(), cx)
        });
        inp.reconnect_delay_sec.update(cx, |i, cx| {
            i.set_text(cfg.reconnect_delay_sec.to_string(), cx)
        });
        inp.read_lines_blocked.update(cx, |i, cx| {
            i.set_text(cfg.read_lines_blocked.to_string(), cx)
        });
        inp.read_lines_error.update(cx, |i, cx| {
            i.set_text(cfg.read_lines_error.to_string(), cx)
        });
        inp.allowed_panes
            .update(cx, |i, cx| i.set_text(cfg.allowed_panes.join(", "), cx));
        inp.allowed_agents
            .update(cx, |i, cx| i.set_text(cfg.allowed_agents.join(", "), cx));
        inp.whitelisted_keys
            .update(cx, |i, cx| i.set_text(cfg.whitelisted_keys.join(", "), cx));
        inp.whitelisted_send_texts.update(cx, |i, cx| {
            i.set_text(cfg.whitelisted_send_texts.join(", "), cx)
        });
        inp.non_retryable_regexes.update(cx, |i, cx| {
            i.set_text(cfg.non_retryable_regexes.join("\n"), cx)
        });
        inp.max_continuous_default.update(cx, |i, cx| {
            i.set_text(cfg.max_continuous_default.to_string(), cx)
        });
        inp.audit_retention_days.update(cx, |i, cx| {
            i.set_text(cfg.audit_retention_days.to_string(), cx)
        });
    }

    fn prune_expired_animations(&mut self) -> bool {
        let now = Instant::now();
        let had_win = self.window_nudge_until.is_some();
        let had_nudge = !self.pane_nudge_seqs.is_empty();
        let had_move = !self.pane_move_anims.is_empty();
        self.pane_nudge_seqs.retain(|_, (_, until)| *until > now);
        self.pane_move_anims.retain(|_, (_, _, until)| *until > now);
        if self.window_nudge_until.is_some_and(|u| u <= now) {
            self.window_nudge_until = None;
        }
        (had_win && self.window_nudge_until.is_none())
            || (had_nudge && self.pane_nudge_seqs.is_empty())
            || (had_move && self.pane_move_anims.is_empty())
    }

    /// Adaptive interval for refreshing relative timestamps ("刚刚" / "3分钟前") without unnecessary redraws.
    fn relative_clock_tick_interval(&self) -> Option<Duration> {
        if !matches!(self.active_tab, ActiveTab::Dashboard | ActiveTab::Audit) {
            return None;
        }
        let now = chrono::Utc::now();
        let newest_age_sec = self
            .snapshot
            .panes
            .iter()
            .filter_map(|p| p.last_action_at)
            .chain(self.snapshot.audit_records.iter().rev().take(30).map(|r| r.timestamp))
            .map(|ts| now.signed_duration_since(ts).num_seconds().max(0))
            .min()?;
        if newest_age_sec < 60 {
            Some(Duration::from_secs(2))
        } else if newest_age_sec < 3600 {
            Some(Duration::from_secs(15))
        } else {
            None
        }
    }

    fn refresh_snapshot(&mut self) {
        self.snapshot = self.engine.lock().unwrap().snapshot();
        self.last_state_version = self.snapshot.state_version;
        let now = Instant::now();
        if self.snapshot.action_seq > self.last_seen_action_seq {
            self.last_seen_action_seq = self.snapshot.action_seq;
            self.window_nudge_seq += 1;
            self.window_nudge_until = Some(now + Duration::from_millis(500));
        }
        for (new_idx, p) in self.snapshot.panes.iter().enumerate() {
            let prev = self.prev_pane_action_seqs.get(&p.pane).copied().unwrap_or(0);
            if p.action_seq > prev {
                self.prev_pane_action_seqs.insert(p.pane.clone(), p.action_seq);
                self.pane_nudge_seqs
                    .insert(p.pane.clone(), (p.action_seq, now + Duration::from_millis(850)));
            }
            if let Some(&old_idx) = self.prev_pane_indices.get(&p.pane)
                && old_idx != new_idx
            {
                let idx_delta = old_idx as i32 - new_idx as i32;
                self.next_move_seq += 1;
                self.pane_move_anims.insert(
                    p.pane.clone(),
                    (
                        self.next_move_seq,
                        idx_delta,
                        now + Duration::from_millis(450),
                    ),
                );
            }
        }
        self.prev_pane_indices = self
            .snapshot
            .panes
            .iter()
            .enumerate()
            .map(|(idx, p)| (p.pane.clone(), idx))
            .collect();
        self.pane_nudge_seqs.retain(|_, (_, until)| *until > now);
        self.pane_move_anims.retain(|_, (_, _, until)| *until > now);
        if self.window_nudge_until.is_some_and(|u| u <= now) {
            self.window_nudge_until = None;
        }
    }

    fn set_banner(&mut self, is_error: bool, msg: impl Into<String>) {
        self.status_banner = Some((is_error, msg.into()));
    }

    fn on_toggle_language(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let next = match self.lang() {
            UiLanguage::Zh => UiLanguage::En,
            UiLanguage::En => UiLanguage::Zh,
        };
        let res = self.engine.lock().unwrap().set_language(next);
        match res {
            Ok(saved) => {
                self.refresh_snapshot();
                self.settings.language = saved;
                window.set_window_title(tr(saved, "辣椒", "Nudgegeist"));
                self.set_banner(
                    false,
                    tr(saved, "界面语言已切换为中文", "UI language switched to English"),
                );
            }
            Err(e) => self.set_banner(true, format!("Language switch failed: {e}")),
        }
        cx.notify();
    }

    fn on_toggle_dry_run(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        let res = self.engine.lock().unwrap().toggle_global_dry_run();
        match res {
            Ok(on) => {
                self.refresh_snapshot();
                self.settings.global_dry_run = on;
                self.set_banner(
                    false,
                    if on {
                        tr(
                            lang,
                            "已开启全局 Dry-Run（仅记录计划动作，不实际发送）",
                            "Global Dry-Run enabled (logging planned actions only)",
                        )
                    } else {
                        tr(
                            lang,
                            "已关闭全局 Dry-Run（恢复实际自动处理）",
                            "Global Dry-Run disabled (live execution active)",
                        )
                    },
                );
            }
            Err(e) => self.set_banner(
                true,
                format!("{}: {e}", tr(lang, "切换 Dry-Run 失败", "Failed to toggle Dry-Run")),
            ),
        }
        cx.notify();
    }

    fn on_toggle_pause_all(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        let res = self.engine.lock().unwrap().toggle_pause_all();
        match res {
            Ok(paused) => {
                self.refresh_snapshot();
                self.settings.paused_all = paused;
                self.set_banner(
                    false,
                    if paused {
                        tr(lang, "已暂停全部自动处理", "All automatic handling paused")
                    } else {
                        tr(lang, "已恢复自动处理", "Automatic handling resumed")
                    },
                );
            }
            Err(e) => self.set_banner(
                true,
                format!("{}: {e}", tr(lang, "切换全局暂停失败", "Failed to toggle pause")),
            ),
        }
        cx.notify();
    }

    fn on_scan_now(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        let res = {
            let mut eng = self.engine.lock().unwrap();
            let client = DynamicLuvusClient::from_config(&eng.config);
            eng.active_transport = client.transport_label();
            eng.scan_once(&client, false)
        };
        self.refresh_snapshot();
        match res {
            Ok(()) => self.set_banner(
                false,
                match lang {
                    UiLanguage::Zh => format!("扫描完成，当前检测到 {} 个 pane", self.snapshot.panes.len()),
                    UiLanguage::En => format!("Scan complete: {} pane(s) detected", self.snapshot.panes.len()),
                },
            ),
            Err(e) => self.set_banner(
                true,
                format!("{}: {e}", tr(lang, "扫描失败", "Scan failed")),
            ),
        }
        cx.notify();
    }

    fn on_reload_config(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        {
            let mut eng = self.engine.lock().unwrap();
            eng.reload_from_disk();
        }
        self.refresh_snapshot();
        let cfg = self.snapshot.config.clone();
        self.sync_settings_from_config(&cfg, cx);
        if let Some(err) = &self.snapshot.last_config_error {
            self.set_banner(true, err.clone());
        } else {
            self.set_banner(
                false,
                tr(
                    lang,
                    "已从磁盘重新加载配置与规则",
                    "Reloaded configuration and rules from disk",
                ),
            );
        }
        cx.notify();
    }

    fn on_save_rule(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        let parsed = match self.rule_editor.mode {
            RuleEditorMode::Form => self.rule_from_editor_form(cx),
            RuleEditorMode::Json => {
                let raw = self.rule_editor.inputs.json_editor.read(cx).text();
                match serde_json::from_str::<Rule>(&raw) {
                    Ok(r) => match validate_rule(&r, &self.snapshot.config) {
                        Ok(()) => Ok(r),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(vec![format!(
                        "{}: {e}",
                        tr(lang, "规则 JSON 解析失败", "Failed to parse rule JSON")
                    )]),
                }
            }
        };

        let rule = match parsed {
            Ok(r) => r,
            Err(errs) => {
                self.rule_editor.validation_errors = errs;
                cx.notify();
                return;
            }
        };

        let mut next_rules_file = self.snapshot.rules_file.clone();
        if let Some(old_id) = &self.rule_editor.selected_rule_id {
            if let Some(pos) = next_rules_file.rules.iter().position(|r| &r.id == old_id) {
                next_rules_file.rules[pos] = rule.clone();
            } else {
                next_rules_file.rules.push(rule.clone());
            }
        } else {
            next_rules_file.rules.push(rule.clone());
        }

        let res = self.engine.lock().unwrap().save_rules(next_rules_file);
        match res {
            Ok(()) => {
                self.refresh_snapshot();
                self.load_rule_into_editor(&rule, cx);
                self.set_banner(
                    false,
                    match lang {
                        UiLanguage::Zh => format!("规则 \"{}\" 已校验并原子保存", rule.name),
                        UiLanguage::En => format!("Rule \"{}\" validated and saved atomically", rule.name),
                    },
                );
            }
            Err(errs) => {
                self.rule_editor.validation_errors = errs;
            }
        }
        cx.notify();
    }

    fn on_new_rule(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        let template = new_rule_template(&self.snapshot.rules_file.rules);
        let mut next = self.snapshot.rules_file.clone();
        next.rules.push(template.clone());
        let res = self.engine.lock().unwrap().save_rules(next);
        match res {
            Ok(()) => {
                self.refresh_snapshot();
                self.load_rule_into_editor(&template, cx);
                self.set_banner(
                    false,
                    match lang {
                        UiLanguage::Zh => format!("已新建草稿规则 {}（默认仅 Dry-Run）", template.id),
                        UiLanguage::En => format!("Created draft rule {} (Dry-Run only)", template.id),
                    },
                );
            }
            Err(errs) => self.set_banner(true, errs.join("; ")),
        }
        cx.notify();
    }

    fn on_toggle_rule_enabled(&mut self, rule_id: &str, cx: &mut Context<Self>) {
        let mut next = self.snapshot.rules_file.clone();
        if let Some(r) = next.rules.iter_mut().find(|r| r.id == rule_id) {
            r.enabled = !r.enabled;
        }
        let res = self.engine.lock().unwrap().save_rules(next);
        if let Err(errs) = res {
            self.set_banner(true, errs.join("; "));
        } else {
            self.refresh_snapshot();
            if self.rule_editor.selected_rule_id.as_deref() == Some(rule_id)
                && let Some(r) = self
                    .snapshot
                    .rules_file
                    .rules
                    .iter()
                    .find(|r| r.id == rule_id)
                    .cloned()
            {
                self.load_rule_into_editor(&r, cx);
            }
        }
        cx.notify();
    }

    fn on_approve_rule(&mut self, rule_id: &str, cx: &mut Context<Self>) {
        let lang = self.lang();
        let mut next = self.snapshot.rules_file.clone();
        if let Some(r) = next.rules.iter_mut().find(|r| r.id == rule_id) {
            r.review_status = ReviewStatus::Approved;
            r.dry_run_only = false;
            r.enabled = true;
        }
        let res = self.engine.lock().unwrap().save_rules(next);
        if let Err(errs) = res {
            self.set_banner(true, errs.join("; "));
        } else {
            self.refresh_snapshot();
            if self.rule_editor.selected_rule_id.as_deref() == Some(rule_id)
                && let Some(r) = self
                    .snapshot
                    .rules_file
                    .rules
                    .iter()
                    .find(|r| r.id == rule_id)
                    .cloned()
            {
                self.load_rule_into_editor(&r, cx);
            }
            self.set_banner(
                false,
                match lang {
                    UiLanguage::Zh => format!("规则 {rule_id} 已审核通过并启用"),
                    UiLanguage::En => format!("Rule {rule_id} approved and enabled"),
                },
            );
        }
        cx.notify();
    }

    fn on_nudge_priority(&mut self, rule_id: &str, delta: i32, cx: &mut Context<Self>) {
        let mut next = self.snapshot.rules_file.clone();
        if let Some(r) = next.rules.iter_mut().find(|r| r.id == rule_id) {
            r.priority += delta;
        }
        let res = self.engine.lock().unwrap().save_rules(next);
        if let Err(errs) = res {
            self.set_banner(true, errs.join("; "));
        } else {
            self.refresh_snapshot();
            if self.rule_editor.selected_rule_id.as_deref() == Some(rule_id)
                && let Some(r) = self
                    .snapshot
                    .rules_file
                    .rules
                    .iter()
                    .find(|r| r.id == rule_id)
                    .cloned()
            {
                self.load_rule_into_editor(&r, cx);
            }
        }
        cx.notify();
    }

    fn on_delete_rule(&mut self, rule_id: &str, cx: &mut Context<Self>) {
        let lang = self.lang();
        let mut next = self.snapshot.rules_file.clone();
        next.rules.retain(|r| r.id != rule_id);
        let res = self.engine.lock().unwrap().save_rules(next);
        match res {
            Ok(()) => {
                self.refresh_snapshot();
                if self.rule_editor.selected_rule_id.as_deref() == Some(rule_id) {
                    if let Some(first) = self.snapshot.rules_file.rules.first().cloned() {
                        self.load_rule_into_editor(&first, cx);
                    } else {
                        self.rule_editor.selected_rule_id = None;
                    }
                }
                self.set_banner(
                    false,
                    match lang {
                        UiLanguage::Zh => format!("已删除规则 {rule_id}"),
                        UiLanguage::En => format!("Deleted rule {rule_id}"),
                    },
                );
            }
            Err(errs) => self.set_banner(true, errs.join("; ")),
        }
        cx.notify();
    }

    fn on_export_rules(&mut self, cx: &mut Context<Self>) {
        let lang = self.lang();
        match serde_json::to_string_pretty(&self.snapshot.rules_file) {
            Ok(json) => {
                cx.write_to_clipboard(ClipboardItem::new_string(json));
                self.set_banner(
                    false,
                    tr(
                        lang,
                        "已将全部规则 JSON 导出复制到剪贴板",
                        "Copied all rules JSON to clipboard",
                    ),
                );
            }
            Err(e) => self.set_banner(
                true,
                format!("{}: {e}", tr(lang, "导出失败", "Export failed")),
            ),
        }
        cx.notify();
    }

    fn on_import_rules(&mut self, dry_run_only: bool, cx: &mut Context<Self>) {
        let lang = self.lang();
        let raw = self.import_input.read(cx).text();
        match import_rules_json(&raw, &self.snapshot.config, "imported", dry_run_only) {
            Ok(imported) => {
                let mut next = self.snapshot.rules_file.clone();
                for r in imported {
                    if let Some(pos) = next.rules.iter().position(|e| e.id == r.id) {
                        next.rules[pos] = r;
                    } else {
                        next.rules.push(r);
                    }
                }
                let res = self.engine.lock().unwrap().save_rules(next);
                match res {
                    Ok(()) => {
                        self.refresh_snapshot();
                        self.import_errors.clear();
                        self.import_panel_open = false;
                        self.set_banner(
                            false,
                            if dry_run_only {
                                tr(
                                    lang,
                                    "外部规则已导入（已设为仅 Dry-Run 待审核）",
                                    "Imported external rules (Dry-Run only, pending review)",
                                )
                            } else {
                                tr(
                                    lang,
                                    "外部规则已导入（已设为禁用待审核）",
                                    "Imported external rules (disabled, pending review)",
                                )
                            },
                        );
                    }
                    Err(errs) => self.import_errors = errs,
                }
            }
            Err(errs) => self.import_errors = errs,
        }
        cx.notify();
    }

    fn run_simulation_internal(&mut self, cx: &App) {
        let text = self.tester.text_input.read(cx).text();
        let pane = {
            let p = self.tester.pane_input.read(cx).text();
            if p.trim().is_empty() {
                "sim-pane".to_string()
            } else {
                p.trim().to_string()
            }
        };
        let report = evaluate_rules_stateless(
            &text,
            &self.tester.agent,
            &pane,
            &self.tester.status,
            &self.snapshot.rules_file.rules,
            &self.snapshot.config,
        );
        self.tester.report = Some(report);
    }

    fn on_fetch_live_pane(
        &mut self,
        pane: String,
        agent: String,
        status: String,
        cx: &mut Context<Self>,
    ) {
        let lang = self.lang();
        self.tester
            .pane_input
            .update(cx, |i, cx| i.set_text(pane.clone(), cx));
        self.tester.agent = agent;
        self.tester.status = status;
        let client = DynamicLuvusClient::from_config(&self.snapshot.config);
        let lines = self
            .snapshot
            .config
            .read_lines_error
            .max(self.snapshot.config.read_lines_blocked);
        match client.read_pane(&pane, lines, MatchSource::Visible) {
            Ok(txt) => {
                self.tester.live_read_error = None;
                self.tester.text_input.update(cx, |i, cx| i.set_text(txt, cx));
                self.run_simulation_internal(cx);
                self.active_tab = ActiveTab::Tester;
                self.set_banner(
                    false,
                    match lang {
                        UiLanguage::Zh => format!("已读取实时 pane {pane} 输出并完成模拟"),
                        UiLanguage::En => format!("Fetched live pane {pane} output and simulated"),
                    },
                );
            }
            Err(e) => {
                self.tester.live_read_error = Some(match lang {
                    UiLanguage::Zh => format!("读取 pane {pane} 失败: {e}"),
                    UiLanguage::En => format!("Failed to read pane {pane}: {e}"),
                });
                self.active_tab = ActiveTab::Tester;
            }
        }
        cx.notify();
    }

    fn on_save_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let lang = self.lang();
        let inp = &self.settings.inputs;
        let mut errs = Vec::new();
        let parse_u64 = |val: String, label: &str, errs: &mut Vec<String>| -> u64 {
            val.trim().parse::<u64>().unwrap_or_else(|_| {
                errs.push(format!(
                    "{label} {}",
                    tr(lang, "必须是非负整数", "must be a non-negative integer")
                ));
                0
            })
        };
        let parse_usize = |val: String, label: &str, errs: &mut Vec<String>| -> usize {
            val.trim().parse::<usize>().unwrap_or_else(|_| {
                errs.push(format!(
                    "{label} {}",
                    tr(lang, "必须是正整数", "must be a positive integer")
                ));
                12
            })
        };
        let parse_u32 = |val: String, label: &str, errs: &mut Vec<String>| -> u32 {
            val.trim().parse::<u32>().unwrap_or_else(|_| {
                errs.push(format!(
                    "{label} {}",
                    tr(lang, "必须是非负整数", "must be a non-negative integer")
                ));
                0
            })
        };

        let cfg = WatchdogConfig {
            version: self.snapshot.config.version,
            language: self.settings.language,
            transport_mode: self.settings.transport_mode,
            luvus_socket_path: inp.luvus_socket_path.read(cx).text().trim().to_string(),
            luvus_bin: inp.luvus_bin.read(cx).text().trim().to_string(),
            scan_interval_sec: parse_u64(
                inp.scan_interval_sec.read(cx).text(),
                "scanIntervalSec",
                &mut errs,
            ),
            reconnect_delay_sec: parse_u64(
                inp.reconnect_delay_sec.read(cx).text(),
                "reconnectDelaySec",
                &mut errs,
            ),
            read_lines_blocked: parse_usize(
                inp.read_lines_blocked.read(cx).text(),
                "readLinesBlocked",
                &mut errs,
            ),
            read_lines_error: parse_usize(
                inp.read_lines_error.read(cx).text(),
                "readLinesError",
                &mut errs,
            ),
            global_dry_run: self.settings.global_dry_run,
            paused_all: self.settings.paused_all,
            allowed_panes: split_csv(&inp.allowed_panes.read(cx).text()),
            allowed_agents: split_csv(&inp.allowed_agents.read(cx).text()),
            whitelisted_keys: split_csv(&inp.whitelisted_keys.read(cx).text()),
            whitelisted_send_texts: split_csv(&inp.whitelisted_send_texts.read(cx).text()),
            non_retryable_regexes: inp
                .non_retryable_regexes
                .read(cx)
                .text()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            max_continuous_default: parse_u32(
                inp.max_continuous_default.read(cx).text(),
                "maxContinuousDefault",
                &mut errs,
            ),
            audit_retention_days: parse_u32(
                inp.audit_retention_days.read(cx).text(),
                "auditRetentionDays",
                &mut errs,
            ),
            redact_audit_summary: self.settings.redact_audit_summary,
        };

        if let Err(mut cfg_errs) = validate_config(&cfg) {
            errs.append(&mut cfg_errs);
        }
        if !errs.is_empty() {
            self.settings.validation_errors = errs;
            cx.notify();
            return;
        }

        let res = self.engine.lock().unwrap().save_config(cfg);
        match res {
            Ok(()) => {
                self.settings.validation_errors.clear();
                self.refresh_snapshot();
                let next_lang = self.lang();
                window.set_window_title(tr(next_lang, "辣椒", "Nudgegeist"));
                self.set_banner(
                    false,
                    tr(
                        next_lang,
                        "系统设置已校验并原子保存",
                        "Settings validated and saved atomically",
                    ),
                );
            }
            Err(save_errs) => self.settings.validation_errors = save_errs,
        }
        cx.notify();
    }
}

impl WatchdogApp {
    fn render_header(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let lang = self.lang();
        let dry_run = self.snapshot.config.global_dry_run;
        let paused_all = self.snapshot.config.paused_all;
        let events_ok = self.snapshot.events_connected;

        let mut brand = div()
            .flex()
            .flex_row()
            .items_center()
            .gap_4()
            .child(
                div()
                    .text_base()
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(rgb(0xf8fafc))
                    .child(tr(lang, "辣椒", "Nudgegeist Watchdog")),
            )
            .child(div().w(px(1.)).h_4().bg(rgb(0x334155)));

        if cfg!(target_os = "macos") {
            brand = brand.pl(px(72.));
        }

        let drag_area = div()
            .id("header-drag-region")
            .flex_1()
            .min_w_0()
            .flex()
            .flex_row()
            .items_center()
            .gap_5()
            .py_2()
            .window_control_area(WindowControlArea::Drag)
            .on_mouse_down(MouseButton::Left, |ev, window, _| {
                if ev.click_count == 2 {
                    window.zoom_window();
                } else {
                    window.start_window_move();
                }
            })
            .on_mouse_down(MouseButton::Right, |ev, window, _| {
                window.show_window_menu(ev.position);
            })
            .child(brand)
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(badge(
                        if events_ok {
                            tr(lang, "事件流已连接", "Events Connected")
                        } else {
                            tr(lang, "轮询/重连中", "Polling / Reconnecting")
                        },
                        if events_ok { 0x065f46 } else { 0x78350f },
                        if events_ok { 0x6ee7b7 } else { 0xfcd34d },
                    ))
                    .child(badge(
                        if paused_all {
                            tr(lang, "全局已暂停", "Paused All")
                        } else {
                            tr(lang, "引擎运行中", "Running")
                        },
                        if paused_all { 0x7f1d1d } else { 0x1e3a8a },
                        if paused_all { 0xfca5a5 } else { 0x93c5fd },
                    ))
                    .child(badge(
                        self.snapshot.active_transport.clone(),
                        0x1e293b,
                        0xcbd5e1,
                    )),
            );

        let show_window_controls = !cfg!(target_os = "macos")
            || matches!(window.window_decorations(), Decorations::Client { .. });

        div()
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .gap_3()
            .px_4()
            .bg(rgb(0x0b1220))
            .border_b_1()
            .border_color(rgb(0x1e293b))
            .child(drag_area)
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .flex_shrink_0()
                    .py_2()
                    .gap_2()
                    .child(action_btn(
                        "lang-toggle-btn",
                        match lang {
                            UiLanguage::Zh => "EN",
                            UiLanguage::En => "中文",
                        },
                        0x1e293b,
                        cx.listener(|app, _, window, cx| app.on_toggle_language(window, cx)),
                    ))
                    .child(action_btn(
                        "dry-run-toggle",
                        if dry_run {
                            "Dry-Run: ON"
                        } else {
                            "Dry-Run: OFF"
                        },
                        if dry_run { 0xb45309 } else { 0x1e293b },
                        cx.listener(|app, _, _, cx| app.on_toggle_dry_run(cx)),
                    ))
                    .child(action_btn(
                        "pause-all-toggle",
                        if paused_all {
                            tr(lang, "恢复全部", "Resume All")
                        } else {
                            tr(lang, "暂停全部", "Pause All")
                        },
                        if paused_all { 0x991b1b } else { 0x1e293b },
                        cx.listener(|app, _, _, cx| app.on_toggle_pause_all(cx)),
                    ))
                    .child(action_btn(
                        "scan-now-btn",
                        tr(lang, "立即扫描", "Scan Now"),
                        0x1d4ed8,
                        cx.listener(|app, _, _, cx| app.on_scan_now(cx)),
                    ))
                    .child(action_btn(
                        "reload-cfg-btn",
                        tr(lang, "重载配置", "Reload"),
                        0x1e293b,
                        cx.listener(|app, _, _, cx| app.on_reload_config(cx)),
                    ))
                    .when(show_window_controls, |d| {
                        d.child(div().w(px(1.)).h_4().mx_1().bg(rgb(0x334155)))
                            .child(win_control_btn("win-min-btn", "−", false, |_, window, _| {
                                window.minimize_window();
                            }))
                            .child(win_control_btn("win-max-btn", "□", false, |_, window, _| {
                                window.zoom_window();
                            }))
                            .child(win_control_btn("win-close-btn", "×", true, |_, window, _| {
                                window.remove_window();
                            }))
                    }),
            )
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let lang = self.lang();
        let tabs = [
            (ActiveTab::Dashboard, tr(lang, "仪表盘", "Dashboard")),
            (ActiveTab::Rules, tr(lang, "规则管理", "Rules")),
            (ActiveTab::Tester, tr(lang, "规则测试", "Rule Tester")),
            (ActiveTab::Audit, tr(lang, "审计日志", "Audit Logs")),
            (ActiveTab::Settings, tr(lang, "系统设置", "Settings")),
        ];

        let paths = AppPaths::resolve_default();
        div()
            .w(px(200.))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .justify_between()
            .bg(rgb(0x0d1526))
            .border_r_1()
            .border_color(rgb(0x1e293b))
            .p_3()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .children(tabs.into_iter().map(|(tab, label)| {
                        let active = self.active_tab == tab;
                        div()
                            .id(SharedString::from(format!("nav-{tab:?}")))
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .cursor_pointer()
                            .text_sm()
                            .bg(if active {
                                rgb(0x1d4ed8)
                            } else {
                                rgb(0x0d1526)
                            })
                            .text_color(if active {
                                rgb(0xffffff)
                            } else {
                                rgb(0x94a3b8)
                            })
                            .hover(|s| {
                                if active {
                                    s
                                } else {
                                    s.bg(rgb(0x1e293b)).text_color(rgb(0xe2e8f0))
                                }
                            })
                            .child(label)
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |app, _, _, cx| {
                                    app.active_tab = tab;
                                    cx.notify();
                                }),
                            )
                    })),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .pt_3()
                    .border_t_1()
                    .border_color(rgb(0x1e293b))
                    .text_xs()
                    .text_color(rgb(0x64748b))
                    .child(tr(lang, "配置目录:", "Config Dir:"))
                    .child(
                        div()
                            .text_color(rgb(0x94a3b8))
                            .truncate()
                            .child(paths.config_dir.display().to_string()),
                    )
                    .child(tr(lang, "缓存/审计目录:", "Cache / Audit Dir:"))
                    .child(
                        div()
                            .text_color(rgb(0x94a3b8))
                            .truncate()
                            .child(paths.cache_dir.display().to_string()),
                    ),
            )
    }

    fn render_dashboard(&self, cx: &mut Context<Self>) -> AnyElement {
        let lang = self.lang();
        let enabled_rules = self
            .snapshot
            .rules_file
            .rules
            .iter()
            .filter(|r| r.enabled)
            .count();
        let total_rules = self.snapshot.rules_file.rules.len();
        let last_scan = self
            .snapshot
            .last_scan_at
            .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
            .unwrap_or_else(|| tr(lang, "尚未扫描", "Not yet scanned").to_string());

        let recent_audits: Vec<&AuditRecord> =
            self.snapshot.audit_records.iter().rev().take(30).collect();

        div()
            .size_full()
            .overflow_hidden()
            .p_4()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex_shrink_0()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(kpi_card(
                        tr(lang, "监控 Pane 数", "Monitored Panes"),
                        format!("{}", self.snapshot.panes.len()),
                        match lang {
                            UiLanguage::Zh => format!("最近扫描: {last_scan}"),
                            UiLanguage::En => format!("Last scan: {last_scan}"),
                        },
                    ))
                    .child(kpi_card(
                        tr(lang, "启用规则 / 总规则", "Enabled / Total Rules"),
                        format!("{enabled_rules} / {total_rules}"),
                        tr(lang, "按优先级降序评估", "Evaluated by priority desc").to_string(),
                    ))
                    .child(kpi_card(
                        tr(lang, "已执行 / Dry-Run", "Executed / Dry-Run"),
                        format!(
                            "{} / {}",
                            self.snapshot.total_actions, self.snapshot.total_dry_runs
                        ),
                        tr(lang, "白名单 keys/send 动作", "Whitelisted keys/send actions")
                            .to_string(),
                    ))
                    .child(kpi_card(
                        tr(lang, "异常计数", "Errors"),
                        format!("{}", self.snapshot.total_errors),
                        self.snapshot
                            .last_luvus_error
                            .clone()
                            .unwrap_or_else(|| {
                                tr(lang, "luvus 通道正常", "luvus channel healthy").to_string()
                            }),
                    )),
            )
            .child(
                div().flex_shrink_0().child(section_card(
                    tr(lang, "实时 Pane 状态监控", "Live Pane Status"),
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .children(if self.snapshot.panes.is_empty() {
                            vec![
                                div()
                                    .p_3()
                                    .text_sm()
                                    .text_color(rgb(0x94a3b8))
                                    .child(tr(
                                        lang,
                                        "当前未检测到活动 agent pane（可点击顶部“立即扫描”，或先启动 luvus 会话；也可直接进入“规则测试”页进行离线模拟）。",
                                        "No active agent panes detected. Click \"Scan Now\" above, start a luvus session, or open Rule Tester to simulate offline.",
                                    ))
                                    .into_any_element(),
                            ]
                        } else {
                            self.snapshot
                                .panes
                                .iter()
                                .map(|p| {
                                    let pane_id = p.pane.clone();
                                    let pane_id2 = p.pane.clone();
                                    let pane_id3 = p.pane.clone();
                                    let agent = p.agent.clone();
                                    let status = p.status.clone();
                                    let is_paused = p.manual_paused || p.continuous_paused;
                                    let (s_bg, s_fg) = pane_status_colors(p.status.as_str());
                                    let row = div()
                                        .relative()
                                        .flex()
                                        .flex_row()
                                        .items_center()
                                        .justify_between()
                                        .p_2()
                                        .rounded_md()
                                        .bg(rgb(0x0f172a))
                                        .border_1()
                                        .border_color(rgb(0x1e293b))
                                        .child(
                                            div()
                                                .flex()
                                                .flex_row()
                                                .items_center()
                                                .gap_3()
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                                        .text_color(rgb(0xf8fafc))
                                                        .child(format!(
                                                            "{} ({})",
                                                            p.pane, p.agent
                                                        )),
                                                )
                                                .child(badge(p.status.clone(), s_bg, s_fg))
                                                .when(is_paused, |d| {
                                                    d.child(badge(
                                                        tr(lang, "已暂停", "Paused"),
                                                        0x7f1d1d,
                                                        0xfca5a5,
                                                    ))
                                                })
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .text_color(rgb(0x94a3b8))
                                                        .child({
                                                            let now = chrono::Utc::now();
                                                            let action_time = p
                                                                .last_action_at
                                                                .map(|ts| {
                                                                    pretty_time_with_clock(
                                                                        ts, now, lang,
                                                                    )
                                                                })
                                                                .unwrap_or_else(|| "-".to_string());
                                                            match lang {
                                                                UiLanguage::Zh => format!(
                                                                    "连续动作: {} | 最近动作: {} | 动作时间: {}",
                                                                    p.continuous_count,
                                                                    p.last_action
                                                                        .as_deref()
                                                                        .unwrap_or("-"),
                                                                    action_time
                                                                ),
                                                                UiLanguage::En => format!(
                                                                    "Continuous: {} | Last action: {} | Action time: {}",
                                                                    p.continuous_count,
                                                                    p.last_action
                                                                        .as_deref()
                                                                        .unwrap_or("-"),
                                                                    action_time
                                                                ),
                                                            }
                                                        }),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .flex_row()
                                                .gap_2()
                                                .child(small_btn(
                                                    format!("pause-pane-{}", p.pane),
                                                    if p.manual_paused {
                                                        tr(lang, "恢复", "Resume")
                                                    } else {
                                                        tr(lang, "暂停", "Pause")
                                                    },
                                                    cx.listener(move |app, _, _, cx| {
                                                        app.engine
                                                            .lock()
                                                            .unwrap()
                                                            .toggle_pane_pause(&pane_id);
                                                        app.refresh_snapshot();
                                                        cx.notify();
                                                    }),
                                                ))
                                                .child(small_btn(
                                                    format!("reset-pane-{}", p.pane),
                                                    tr(lang, "重置计数", "Reset Count"),
                                                    cx.listener(move |app, _, _, cx| {
                                                        app.engine
                                                            .lock()
                                                            .unwrap()
                                                            .reset_pane_continuous(&pane_id2);
                                                        app.refresh_snapshot();
                                                        cx.notify();
                                                    }),
                                                ))
                                                .child(small_btn(
                                                    format!("test-pane-{}", p.pane),
                                                    tr(lang, "实时测试", "Test Live"),
                                                    cx.listener(move |app, _, _, cx| {
                                                        app.on_fetch_live_pane(
                                                            pane_id3.clone(),
                                                            agent.clone(),
                                                            status.clone(),
                                                            cx,
                                                        );
                                                    }),
                                                )),
                                        );

                                    let now_inst = Instant::now();
                                    let active_nudge = self
                                        .pane_nudge_seqs
                                        .get(&p.pane)
                                        .copied()
                                        .filter(|(_, until)| now_inst < *until);
                                    let active_move = self
                                        .pane_move_anims
                                        .get(&p.pane)
                                        .copied()
                                        .filter(|(_, _, until)| now_inst < *until);

                                    match (active_nudge, active_move) {
                                        (Some((anim_seq, _)), Some((move_seq, idx_delta, _))) => {
                                            let start_y = (idx_delta as f32 * 48.0).clamp(-240.0, 240.0);
                                            row.with_animation(
                                                SharedString::from(format!(
                                                    "pane-act-move-{}-{anim_seq}-{move_seq}",
                                                    p.pane
                                                )),
                                                Animation::new(Duration::from_millis(750)),
                                                move |card, delta| {
                                                    let decay = 1.0 - delta;
                                                    let dx = (delta * std::f32::consts::TAU * 3.0)
                                                        .sin()
                                                        * 8.0
                                                        * decay;
                                                    let move_t = (delta / 0.55).min(1.0);
                                                    let eased_move = 1.0 - (1.0 - move_t).powi(4);
                                                    let dy = start_y * (1.0 - eased_move);
                                                    let card = card.left(px(dx)).top(px(dy));
                                                    if delta < 0.98 {
                                                        card.border_color(rgb(0xfacc15))
                                                            .bg(rgb(0x172554))
                                                    } else {
                                                        card
                                                    }
                                                },
                                            )
                                            .into_any_element()
                                        }
                                        (Some((anim_seq, _)), None) => row
                                            .with_animation(
                                                SharedString::from(format!(
                                                    "pane-nudge-{}-{anim_seq}",
                                                    p.pane
                                                )),
                                                Animation::new(Duration::from_millis(750)),
                                                |card, delta| {
                                                    let decay = 1.0 - delta;
                                                    let dx = (delta * std::f32::consts::TAU * 3.0)
                                                        .sin()
                                                        * 8.0
                                                        * decay;
                                                    let card = card.left(px(dx));
                                                    if delta < 0.98 {
                                                        card.border_color(rgb(0xfacc15))
                                                            .bg(rgb(0x172554))
                                                    } else {
                                                        card
                                                    }
                                                },
                                            )
                                            .into_any_element(),
                                        (None, Some((move_seq, idx_delta, _))) => {
                                            let start_y = (idx_delta as f32 * 48.0).clamp(-240.0, 240.0);
                                            row.with_animation(
                                                SharedString::from(format!(
                                                    "pane-move-{}-{move_seq}",
                                                    p.pane
                                                )),
                                                Animation::new(Duration::from_millis(380))
                                                    .with_easing(ease_out_quint()),
                                                move |card, delta| {
                                                    let dy = start_y * (1.0 - delta);
                                                    card.top(px(dy))
                                                },
                                            )
                                            .into_any_element()
                                        }
                                        (None, None) => row.into_any_element(),
                                    }
                                })
                                .collect()
                        }),
                )),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .p_3()
                    .rounded_md()
                    .bg(rgb(0x0b1220))
                    .border_1()
                    .border_color(rgb(0x1e293b))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .overflow_hidden()
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_sm()
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(rgb(0xf1f5f9))
                            .child(tr(lang, "最近审计动态", "Recent Audit Activity")),
                    )
                    .child(
                        div()
                            .id("recent-audit-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .children(if recent_audits.is_empty() {
                                vec![
                                    div()
                                        .p_2()
                                        .text_sm()
                                        .text_color(rgb(0x94a3b8))
                                        .child(tr(lang, "暂无审计记录", "No audit records yet"))
                                        .into_any_element(),
                                ]
                            } else {
                                recent_audits
                                    .into_iter()
                                    .map(|rec| audit_row(rec, lang).into_any_element())
                                    .collect()
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_rules(&self, cx: &mut Context<Self>) -> AnyElement {
        let lang = self.lang();
        let mut sorted_rules = self.snapshot.rules_file.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        div()
            .size_full()
            .flex()
            .flex_row()
            .overflow_hidden()
            .child(
                div()
                    .w(px(360.))
                    .flex_shrink_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .border_r_1()
                    .border_color(rgb(0x1e293b))
                    .bg(rgb(0x0b1220))
                    .child(
                        div()
                            .p_3()
                            .border_b_1()
                            .border_color(rgb(0x1e293b))
                            .flex()
                            .flex_row()
                            .flex_wrap()
                            .gap_2()
                            .child(action_btn(
                                "new-rule-btn",
                                tr(lang, "+ 新建", "+ New"),
                                0x1d4ed8,
                                cx.listener(|app, _, _, cx| app.on_new_rule(cx)),
                            ))
                            .child(action_btn(
                                "import-rules-btn",
                                if self.import_panel_open {
                                    tr(lang, "关闭导入", "Close Import")
                                } else {
                                    tr(lang, "导入 JSON", "Import JSON")
                                },
                                0x1e293b,
                                cx.listener(|app, _, _, cx| {
                                    app.import_panel_open = !app.import_panel_open;
                                    cx.notify();
                                }),
                            ))
                            .child(action_btn(
                                "export-rules-btn",
                                tr(lang, "导出 JSON", "Export JSON"),
                                0x1e293b,
                                cx.listener(|app, _, _, cx| app.on_export_rules(cx)),
                            )),
                    )
                    .when(self.import_panel_open, |d| {
                        d.child(
                            div()
                                .p_3()
                                .border_b_1()
                                .border_color(rgb(0x334155))
                                .bg(rgb(0x111c33))
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(rgb(0xfcd34d))
                                        .child(tr(
                                            lang,
                                            "安全导入：外部规则将校验白名单与正则，默认进入禁用/仅Dry-Run待审核状态",
                                            "Safe import: external rules are validated and marked disabled / Dry-Run only until reviewed.",
                                        )),
                                )
                                .child(self.import_input.clone())
                                .when(!self.import_errors.is_empty(), |err_box| {
                                    err_box.child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(0xfca5a5))
                                            .child(self.import_errors.join(" | ")),
                                    )
                                })
                                .child(
                                    div()
                                        .flex()
                                        .flex_row()
                                        .gap_2()
                                        .child(action_btn(
                                            "import-disabled",
                                            tr(lang, "导入(禁用待审)", "Import (Disabled)"),
                                            0x1d4ed8,
                                            cx.listener(|app, _, _, cx| {
                                                app.on_import_rules(false, cx)
                                            }),
                                        ))
                                        .child(action_btn(
                                            "import-dryrun",
                                            tr(lang, "导入(仅Dry-Run)", "Import (Dry-Run)"),
                                            0xb45309,
                                            cx.listener(|app, _, _, cx| {
                                                app.on_import_rules(true, cx)
                                            }),
                                        )),
                                ),
                        )
                    })
                    .child(
                        div()
                            .id("rules-list-scroll")
                            .flex_1()
                            .overflow_scroll()
                            .p_2()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .children(sorted_rules.into_iter().map(|rule| {
                                let selected = self.rule_editor.selected_rule_id.as_deref()
                                    == Some(rule.id.as_str());
                                let hits = self
                                    .snapshot
                                    .rule_hit_counts
                                    .get(&rule.id)
                                    .copied()
                                    .unwrap_or(0);
                                let paused_rule = self.snapshot.paused_rules.contains(&rule.id);
                                let r_select = rule.clone();
                                let rid_toggle = rule.id.clone();
                                let rid_up = rule.id.clone();
                                let rid_down = rule.id.clone();
                                let rid_del = rule.id.clone();
                                let rid_approve = rule.id.clone();
                                let rid_pause = rule.id.clone();

                                div()
                                    .id(SharedString::from(format!("rule-card-{}", rule.id)))
                                    .p_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(if selected {
                                        rgb(0x172554)
                                    } else {
                                        rgb(0x0f172a)
                                    })
                                    .border_1()
                                    .border_color(if selected {
                                        rgb(0x3b82f6)
                                    } else {
                                        rgb(0x1e293b)
                                    })
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |app, _, _, cx| {
                                            app.load_rule_into_editor(&r_select, cx);
                                        }),
                                    )
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                                    .text_color(rgb(0xf8fafc))
                                                    .truncate()
                                                    .child(rule.name.clone()),
                                            )
                                            .child(badge(
                                                format!("P{}", rule.priority),
                                                0x1e293b,
                                                0x93c5fd,
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .flex_wrap()
                                            .gap_1()
                                            .child(badge(
                                                if rule.enabled {
                                                    tr(lang, "启用", "Enabled")
                                                } else {
                                                    tr(lang, "禁用", "Disabled")
                                                },
                                                if rule.enabled { 0x065f46 } else { 0x334155 },
                                                if rule.enabled { 0x6ee7b7 } else { 0xcbd5e1 },
                                            ))
                                            .when(
                                                rule.dry_run_only
                                                    || rule.review_status != ReviewStatus::Approved,
                                                |d| {
                                                    d.child(badge(
                                                        rule.review_status.label_i18n(lang),
                                                        0x78350f,
                                                        0xfcd34d,
                                                    ))
                                                },
                                            )
                                            .when(paused_rule, |d| {
                                                d.child(badge(
                                                    tr(lang, "人工暂停", "Paused"),
                                                    0x7f1d1d,
                                                    0xfca5a5,
                                                ))
                                            })
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(rgb(0x94a3b8))
                                                    .child(match lang {
                                                        UiLanguage::Zh => format!(
                                                            "{} | 命中 {} 次",
                                                            rule.action.summary(),
                                                            hits
                                                        ),
                                                        UiLanguage::En => format!(
                                                            "{} | {} hit(s)",
                                                            rule.action.summary(),
                                                            hits
                                                        ),
                                                    }),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .flex_wrap()
                                            .gap_1()
                                            .pt_1()
                                            .child(small_btn(
                                                format!("tgl-{}", rule.id),
                                                if rule.enabled {
                                                    tr(lang, "禁用", "Disable")
                                                } else {
                                                    tr(lang, "启用", "Enable")
                                                },
                                                cx.listener(move |app, _, _, cx| {
                                                    app.on_toggle_rule_enabled(&rid_toggle, cx);
                                                }),
                                            ))
                                            .child(small_btn(
                                                format!("pause-r-{}", rule.id),
                                                if paused_rule {
                                                    tr(lang, "恢复", "Resume")
                                                } else {
                                                    tr(lang, "暂停", "Pause")
                                                },
                                                cx.listener(move |app, _, _, cx| {
                                                    app.engine
                                                        .lock()
                                                        .unwrap()
                                                        .toggle_rule_pause(&rid_pause);
                                                    app.refresh_snapshot();
                                                    cx.notify();
                                                }),
                                            ))
                                            .child(small_btn(
                                                format!("up-{}", rule.id),
                                                "+10",
                                                cx.listener(move |app, _, _, cx| {
                                                    app.on_nudge_priority(&rid_up, 10, cx);
                                                }),
                                            ))
                                            .child(small_btn(
                                                format!("dn-{}", rule.id),
                                                "-10",
                                                cx.listener(move |app, _, _, cx| {
                                                    app.on_nudge_priority(&rid_down, -10, cx);
                                                }),
                                            ))
                                            .when(
                                                rule.review_status != ReviewStatus::Approved,
                                                |d| {
                                                    d.child(small_btn(
                                                        format!("apr-{}", rule.id),
                                                        tr(lang, "审核通过", "Approve"),
                                                        cx.listener(move |app, _, _, cx| {
                                                            app.on_approve_rule(&rid_approve, cx);
                                                        }),
                                                    ))
                                                },
                                            )
                                            .child(small_btn(
                                                format!("del-{}", rule.id),
                                                tr(lang, "删除", "Delete"),
                                                cx.listener(move |app, _, _, cx| {
                                                    app.on_delete_rule(&rid_del, cx);
                                                }),
                                            )),
                                    )
                            })),
                    ),
            )
            .child(self.render_rule_editor(cx))
            .into_any_element()
    }

    fn render_rule_editor(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let lang = self.lang();
        let ed = &self.rule_editor;
        let is_form = ed.mode == RuleEditorMode::Form;

        div()
            .id("rule-editor-scroll")
            .flex_1()
            .h_full()
            .overflow_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_base()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(rgb(0xf8fafc))
                                    .child(tr(lang, "规则编辑器", "Rule Editor")),
                            )
                            .child(action_btn(
                                "mode-form",
                                tr(lang, "表单模式", "Form"),
                                if is_form { 0x1d4ed8 } else { 0x1e293b },
                                cx.listener(|app, _, _, cx| {
                                    app.rule_editor.mode = RuleEditorMode::Form;
                                    cx.notify();
                                }),
                            ))
                            .child(action_btn(
                                "mode-json",
                                tr(lang, "JSON 模式", "JSON"),
                                if !is_form { 0x1d4ed8 } else { 0x1e293b },
                                cx.listener(|app, _, _, cx| {
                                    if let Ok(r) = app.rule_from_editor_form(cx)
                                        && let Ok(j) = serde_json::to_string_pretty(&r)
                                    {
                                        app.rule_editor
                                            .inputs
                                            .json_editor
                                            .update(cx, |i, cx| i.set_text(j, cx));
                                    }
                                    app.rule_editor.mode = RuleEditorMode::Json;
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(action_btn(
                        "save-rule-btn",
                        tr(lang, "校验并保存规则", "Validate & Save Rule"),
                        0x059669,
                        cx.listener(|app, _, _, cx| app.on_save_rule(cx)),
                    )),
            )
            .when(!ed.validation_errors.is_empty(), |d| {
                d.child(
                    div()
                        .p_3()
                        .rounded_md()
                        .bg(rgb(0x450a0a))
                        .border_1()
                        .border_color(rgb(0xef4444))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .children(ed.validation_errors.iter().map(|e| {
                            div()
                                .text_xs()
                                .text_color(rgb(0xfca5a5))
                                .child(format!("• {e}"))
                        })),
                )
            })
            .child(if is_form {
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap_3()
                            .child(labeled_field(tr(lang, "规则 ID", "Rule ID"), ed.inputs.id.clone()))
                            .child(labeled_field(tr(lang, "规则名称", "Rule Name"), ed.inputs.name.clone()))
                            .child(labeled_field(
                                tr(lang, "优先级 (越大越优先)", "Priority (higher runs first)"),
                                ed.inputs.priority.clone(),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_wrap()
                            .gap_2()
                            .child(toggle_chip(
                                "rule-enabled-chip",
                                if ed.enabled {
                                    tr(lang, "状态: 启用", "Status: Enabled")
                                } else {
                                    tr(lang, "状态: 禁用", "Status: Disabled")
                                },
                                ed.enabled,
                                cx.listener(|app, _, _, cx| {
                                    app.rule_editor.enabled = !app.rule_editor.enabled;
                                    cx.notify();
                                }),
                            ))
                            .child(toggle_chip(
                                "rule-dryrun-chip",
                                if ed.dry_run_only {
                                    tr(lang, "仅 Dry-Run: 是", "Dry-Run Only: Yes")
                                } else {
                                    tr(lang, "仅 Dry-Run: 否", "Dry-Run Only: No")
                                },
                                ed.dry_run_only,
                                cx.listener(|app, _, _, cx| {
                                    app.rule_editor.dry_run_only = !app.rule_editor.dry_run_only;
                                    cx.notify();
                                }),
                            ))
                            .child(toggle_chip(
                                "rule-ci-chip",
                                if ed.case_insensitive {
                                    tr(lang, "忽略大小写: 是", "Case Insensitive: Yes")
                                } else {
                                    tr(lang, "忽略大小写: 否", "Case Insensitive: No")
                                },
                                ed.case_insensitive,
                                cx.listener(|app, _, _, cx| {
                                    app.rule_editor.case_insensitive =
                                        !app.rule_editor.case_insensitive;
                                    cx.notify();
                                }),
                            ))
                            .child(toggle_chip(
                                "rule-claude-retry-chip",
                                if ed.skip_if_claude_retrying {
                                    tr(lang, "Claude Retrying 跳过: 是", "Skip on Claude Retrying: Yes")
                                } else {
                                    tr(lang, "Claude Retrying 跳过: 否", "Skip on Claude Retrying: No")
                                },
                                ed.skip_if_claude_retrying,
                                cx.listener(|app, _, _, cx| {
                                    app.rule_editor.skip_if_claude_retrying =
                                        !app.rule_editor.skip_if_claude_retrying;
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap_3()
                            .child(labeled_field(
                                tr(lang, "Agents (逗号分隔, * 为全部)", "Agents (CSV, * for all)"),
                                ed.inputs.agents.clone(),
                            ))
                            .child(labeled_field(
                                tr(lang, "Panes (逗号分隔, * 为全部)", "Panes (CSV, * for all)"),
                                ed.inputs.panes.clone(),
                            ))
                            .child(labeled_field(
                                tr(lang, "Statuses (如 blocked, !working)", "Statuses (e.g. blocked, !working)"),
                                ed.inputs.statuses.clone(),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_end()
                            .gap_3()
                            .child(labeled_field(
                                tr(lang, "读取行数 (lines)", "Read Lines"),
                                ed.inputs.lines.clone(),
                            ))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label(tr(lang, "输出区域 (region)", "Output Region")))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .gap_1()
                                            .child(choice_chip(
                                                "reg-full",
                                                "full",
                                                ed.region == MatchRegion::Full,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.region = MatchRegion::Full;
                                                    cx.notify();
                                                }),
                                            ))
                                            .child(choice_chip(
                                                "reg-claude",
                                                "claude_last_turn",
                                                ed.region == MatchRegion::ClaudeLastTurn,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.region =
                                                        MatchRegion::ClaudeLastTurn;
                                                    cx.notify();
                                                }),
                                            ))
                                            .child(choice_chip(
                                                "reg-auto",
                                                "auto_agent",
                                                ed.region == MatchRegion::AutoAgent,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.region = MatchRegion::AutoAgent;
                                                    cx.notify();
                                                }),
                                            )),
                                    ),
                            ),
                    )
                    .child(labeled_field(
                        tr(
                            lang,
                            "match.anyRegex（每行一条正则，任一命中即可）",
                            "match.anyRegex (one regex per line, any match)",
                        ),
                        ed.inputs.any_regex.clone(),
                    ))
                    .child(labeled_field(
                        tr(
                            lang,
                            "match.allRegex（每行一条正则，须全部命中）",
                            "match.allRegex (one regex per line, all must match)",
                        ),
                        ed.inputs.all_regex.clone(),
                    ))
                    .child(labeled_field(
                        tr(
                            lang,
                            "match.noneRegex（每行一条正则，命中则排除）",
                            "match.noneRegex (one regex per line, exclude on match)",
                        ),
                        ed.inputs.none_regex.clone(),
                    ))
                    .child(labeled_field(
                        tr(
                            lang,
                            "guards.noneRegex（危险拦截词，命中则拒绝执行并审计）",
                            "guards.noneRegex (safety guards, block and audit on match)",
                        ),
                        ed.inputs.guard_none_regex.clone(),
                    ))
                    .child(
                        div()
                            .p_3()
                            .rounded_md()
                            .bg(rgb(0x0b1220))
                            .border_1()
                            .border_color(rgb(0x1e293b))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .child(field_label(tr(lang, "白名单动作类型:", "Whitelisted Action Type:")))
                                    .child(choice_chip(
                                        "act-keys",
                                        tr(lang, "keys (发送按键)", "keys (send keystrokes)"),
                                        ed.action_type == ActionType::Keys,
                                        cx.listener(|app, _, _, cx| {
                                            app.rule_editor.action_type = ActionType::Keys;
                                            cx.notify();
                                        }),
                                    ))
                                    .child(choice_chip(
                                        "act-send",
                                        tr(lang, "send (发送固定文本)", "send (send fixed text)"),
                                        ed.action_type == ActionType::Send,
                                        cx.listener(|app, _, _, cx| {
                                            app.rule_editor.action_type = ActionType::Send;
                                            cx.notify();
                                        }),
                                    )),
                            )
                            .child(if ed.action_type == ActionType::Keys {
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .flex_wrap()
                                            .gap_1()
                                            .children(self.snapshot.config.whitelisted_keys.iter().map(
                                                |k| {
                                                    let key_val = k.clone();
                                                    small_btn(
                                                        format!("wl-key-{k}"),
                                                        match lang {
                                                            UiLanguage::Zh => format!("填入 {k}"),
                                                            UiLanguage::En => format!("Use {k}"),
                                                        },
                                                        cx.listener(move |app, _, _, cx| {
                                                            app.rule_editor.inputs.action_keys.update(
                                                                cx,
                                                                |i, cx| {
                                                                    i.set_text(key_val.clone(), cx)
                                                                },
                                                            );
                                                        }),
                                                    )
                                                },
                                            )),
                                    )
                                    .child(labeled_field(
                                        tr(lang, "按键列表 (白名单内逗号分隔)", "Keys (whitelisted CSV)"),
                                        ed.inputs.action_keys.clone(),
                                    ))
                                    .into_any_element()
                            } else {
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .flex_wrap()
                                            .gap_1()
                                            .children(
                                                self.snapshot
                                                    .config
                                                    .whitelisted_send_texts
                                                    .iter()
                                                    .map(|t| {
                                                        let txt_val = t.clone();
                                                        small_btn(
                                                            format!("wl-txt-{t}"),
                                                            match lang {
                                                                UiLanguage::Zh => format!("填入 \"{t}\""),
                                                                UiLanguage::En => format!("Use \"{t}\""),
                                                            },
                                                            cx.listener(move |app, _, _, cx| {
                                                                app.rule_editor
                                                                    .inputs
                                                                    .action_text
                                                                    .update(cx, |i, cx| {
                                                                        i.set_text(txt_val.clone(), cx)
                                                                    });
                                                            }),
                                                        )
                                                    }),
                                            ),
                                    )
                                    .child(labeled_field(
                                        tr(lang, "发送文本 (须在白名单中)", "Send Text (must be whitelisted)"),
                                        ed.inputs.action_text.clone(),
                                    ))
                                    .into_any_element()
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_end()
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label(tr(lang, "去重策略", "Dedupe Strategy")))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .gap_1()
                                            .child(choice_chip(
                                                "dd-none",
                                                "none",
                                                ed.dedupe_strategy == DedupeStrategy::None,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.dedupe_strategy =
                                                        DedupeStrategy::None;
                                                    cx.notify();
                                                }),
                                            ))
                                            .child(choice_chip(
                                                "dd-sig",
                                                "signature",
                                                ed.dedupe_strategy == DedupeStrategy::Signature,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.dedupe_strategy =
                                                        DedupeStrategy::Signature;
                                                    cx.notify();
                                                }),
                                            ))
                                            .child(choice_chip(
                                                "dd-pane",
                                                "pane_rule",
                                                ed.dedupe_strategy == DedupeStrategy::PaneRule,
                                                cx.listener(|app, _, _, cx| {
                                                    app.rule_editor.dedupe_strategy =
                                                        DedupeStrategy::PaneRule;
                                                    cx.notify();
                                                }),
                                            )),
                                    ),
                            )
                            .child(labeled_field(
                                tr(lang, "去重窗口 (秒)", "Dedupe Window (s)"),
                                ed.inputs.dedupe_window.clone(),
                            ))
                            .child(labeled_field(
                                tr(lang, "冷却时间 (秒)", "Cooldown (s)"),
                                ed.inputs.cooldown_sec.clone(),
                            ))
                            .child(labeled_field(
                                tr(lang, "连续上限 (0=默认)", "Max Continuous (0=default)"),
                                ed.inputs.max_continuous.clone(),
                            )),
                    )
                    .into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x94a3b8))
                            .child(tr(
                                lang,
                                "高级 JSON 编辑模式（保存时同样执行 schema、正则和动作白名单校验）：",
                                "Advanced JSON editor (schema, regex, and action whitelist validated on save):",
                            )),
                    )
                    .child(ed.inputs.json_editor.clone())
                    .into_any_element()
            })
    }

    fn render_tester(&self, cx: &mut Context<Self>) -> AnyElement {
        let lang = self.lang();
        let agents = ["codex", "claude", "antigravity", "opencode", "unknown"];
        let statuses = ["blocked", "error", "idle", "working"];

        div()
            .id("tester-scroll")
            .size_full()
            .overflow_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                section_card(
                    tr(lang, "模拟条件与实时 Pane 拉取", "Simulation & Live Pane Fetch"),
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .flex_wrap()
                                .items_center()
                                .gap_2()
                                .child(field_label("Agent:"))
                                .children(agents.into_iter().map(|a| {
                                    choice_chip(
                                        format!("tst-ag-{a}"),
                                        a,
                                        self.tester.agent == a,
                                        cx.listener(move |app, _, _, cx| {
                                            app.tester.agent = a.to_string();
                                            cx.notify();
                                        }),
                                    )
                                }))
                                .child(field_label("Status:"))
                                .children(statuses.into_iter().map(|s| {
                                    choice_chip(
                                        format!("tst-st-{s}"),
                                        s,
                                        self.tester.status == s,
                                        cx.listener(move |app, _, _, cx| {
                                            app.tester.status = s.to_string();
                                            cx.notify();
                                        }),
                                    )
                                })),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .items_end()
                                .gap_2()
                                .child(div().w(px(220.)).child(labeled_field(
                                    tr(lang, "Pane ID (实时读取可选)", "Pane ID (optional live read)"),
                                    self.tester.pane_input.clone(),
                                )))
                                .child(action_btn(
                                    "fetch-pane-btn",
                                    tr(lang, "读取实时 Pane 输出", "Fetch Live Output"),
                                    0x1e293b,
                                    cx.listener(|app, _, _, cx| {
                                        let lang = app.lang();
                                        let pane =
                                            app.tester.pane_input.read(cx).text().trim().to_string();
                                        if pane.is_empty() {
                                            app.tester.live_read_error = Some(
                                                tr(
                                                    lang,
                                                    "请先输入 Pane ID（或在仪表盘点击对应 Pane 的“实时测试”）",
                                                    "Enter a Pane ID first (or click \"Test Live\" on Dashboard)",
                                                )
                                                .to_string(),
                                            );
                                            cx.notify();
                                            return;
                                        }
                                        let agent = app.tester.agent.clone();
                                        let status = app.tester.status.clone();
                                        app.on_fetch_live_pane(pane, agent, status, cx);
                                    }),
                                ))
                                .child(action_btn(
                                    "run-sim-btn",
                                    tr(lang, "运行规则模拟 (不发送动作)", "Run Simulation (No Send)"),
                                    0x1d4ed8,
                                    cx.listener(|app, _, _, cx| {
                                        app.run_simulation_internal(cx);
                                        cx.notify();
                                    }),
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .flex_wrap()
                                .gap_2()
                                .child(small_btn(
                                    "sample-confirm",
                                    tr(lang, "示例: 确认选项", "Sample: Confirm Prompt"),
                                    cx.listener(|app, _, _, cx| {
                                        app.tester.agent = "codex".into();
                                        app.tester.status = "blocked".into();
                                        app.tester.text_input.update(cx, |i, cx| {
                                            i.set_text("› 1. Yes, proceed with running tests\n  2. No, cancel", cx)
                                        });
                                        app.run_simulation_internal(cx);
                                        cx.notify();
                                    }),
                                ))
                                .child(small_btn(
                                    "sample-network",
                                    tr(lang, "示例: 网络超时", "Sample: Network Timeout"),
                                    cx.listener(|app, _, _, cx| {
                                        app.tester.agent = "codex".into();
                                        app.tester.status = "error".into();
                                        app.tester.text_input.update(cx, |i, cx| {
                                            i.set_text("Transport error: Connection dropped while streaming response", cx)
                                        });
                                        app.run_simulation_internal(cx);
                                        cx.notify();
                                    }),
                                ))
                                .child(small_btn(
                                    "sample-auth",
                                    tr(lang, "示例: 401 鉴权错误", "Sample: 401 Auth Error"),
                                    cx.listener(|app, _, _, cx| {
                                        app.tester.agent = "claude".into();
                                        app.tester.status = "error".into();
                                        app.tester.text_input.update(cx, |i, cx| {
                                            i.set_text("❯ fix tests\nAPI Error: 401 Unauthorized - invalid api key", cx)
                                        });
                                        app.run_simulation_internal(cx);
                                        cx.notify();
                                    }),
                                ))
                                .child(small_btn(
                                    "sample-danger",
                                    tr(lang, "示例: 危险删除 Guard", "Sample: Danger Guard"),
                                    cx.listener(|app, _, _, cx| {
                                        app.tester.agent = "codex".into();
                                        app.tester.status = "blocked".into();
                                        app.tester.text_input.update(cx, |i, cx| {
                                            i.set_text("Warning: This will Delete production database (cannot be undone)\n1. Yes, proceed", cx)
                                        });
                                        app.run_simulation_internal(cx);
                                        cx.notify();
                                    }),
                                )),
                        )
                        .when_some(self.tester.live_read_error.as_ref(), |d, err| {
                            d.child(div().text_xs().text_color(rgb(0xfca5a5)).child(err.clone()))
                        })
                        .child(self.tester.text_input.clone()),
                ),
            )
            .when_some(self.tester.report.as_ref(), |d, report| {
                let (dec_label, dec_bg, dec_fg) = match &report.final_decision {
                    FinalDecision::Execute(act) => (
                        match lang {
                            UiLanguage::Zh => format!("将执行: {act}"),
                            UiLanguage::En => format!("Will execute: {act}"),
                        },
                        0x065f46,
                        0x6ee7b7,
                    ),
                    FinalDecision::DryRun(act) => (
                        match lang {
                            UiLanguage::Zh => format!("Dry-Run 计划动作: {act}"),
                            UiLanguage::En => format!("Dry-Run planned action: {act}"),
                        },
                        0x78350f,
                        0xfcd34d,
                    ),
                    FinalDecision::Skipped(reason, detail) => (
                        match lang {
                            UiLanguage::Zh => format!("跳过 [{}]: {detail}", reason.label()),
                            UiLanguage::En => format!("Skipped [{}]: {detail}", reason.label()),
                        },
                        0x7f1d1d,
                        0xfca5a5,
                    ),
                    FinalDecision::NoMatch => (
                        tr(lang, "未命中任何规则（保守跳过）", "No rule matched (conservative skip)")
                            .to_string(),
                        0x334155,
                        0xcbd5e1,
                    ),
                };

                d.child(section_card(
                    tr(lang, "匹配解释与规则评估明细", "Match Explanation & Rule Traces"),
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .flex_wrap()
                                .items_center()
                                .gap_2()
                                .child(badge(dec_label, dec_bg, dec_fg))
                                .when_some(report.signature.as_ref(), |b, sig| {
                                    b.child(badge(
                                        match lang {
                                            UiLanguage::Zh => format!("签名: {sig}"),
                                            UiLanguage::En => format!("Signature: {sig}"),
                                        },
                                        0x1e293b,
                                        0x93c5fd,
                                    ))
                                })
                                .when_some(report.non_retryable_hit.as_ref(), |b, nr| {
                                    b.child(badge(
                                        match lang {
                                            UiLanguage::Zh => format!("非重试命中: {nr}"),
                                            UiLanguage::En => format!("Non-retryable hit: {nr}"),
                                        },
                                        0x7f1d1d,
                                        0xfca5a5,
                                    ))
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .children(report.traces.iter().map(|tr_item| {
                                    let is_winner = report.winning_rule_id.as_deref()
                                        == Some(&tr_item.rule_id);
                                    let (bg, fg, tag) = if is_winner {
                                        (0x065f46, 0x6ee7b7, tr(lang, "最终命中", "Winner"))
                                    } else if tr_item.guard_blocked.is_some() {
                                        (0x7f1d1d, 0xfca5a5, tr(lang, "Guard拦截", "Guard Blocked"))
                                    } else if tr_item.matched {
                                        (0x1e3a8a, 0x93c5fd, tr(lang, "备选命中", "Matched"))
                                    } else {
                                        (0x1e293b, 0x94a3b8, tr(lang, "未命中", "No Match"))
                                    };
                                    div()
                                        .p_2()
                                        .rounded_md()
                                        .bg(rgb(0x0f172a))
                                        .border_1()
                                        .border_color(if is_winner {
                                            rgb(0x10b981)
                                        } else {
                                            rgb(0x1e293b)
                                        })
                                        .flex()
                                        .flex_row()
                                        .items_center()
                                        .justify_between()
                                        .child(
                                            div()
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_row()
                                                        .items_center()
                                                        .gap_2()
                                                        .child(
                                                            div()
                                                                .text_sm()
                                                                .font_weight(
                                                                    gpui::FontWeight::SEMIBOLD,
                                                                )
                                                                .text_color(rgb(0xf8fafc))
                                                                .child(format!(
                                                                    "{} ({}) [P{}]",
                                                                    tr_item.rule_name,
                                                                    tr_item.rule_id,
                                                                    tr_item.priority
                                                                )),
                                                        )
                                                        .child(badge(tag, bg, fg)),
                                                )
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .text_color(rgb(0x94a3b8))
                                                        .child(tr_item.detail.clone()),
                                                ),
                                        )
                                })),
                        ),
                ))
            })
            .into_any_element()
    }

    fn render_audit(&self, cx: &mut Context<Self>) -> AnyElement {
        let lang = self.lang();
        let query = self.audit_search_input.read(cx).text().to_lowercase();
        let filtered: Vec<&AuditRecord> = self
            .snapshot
            .audit_records
            .iter()
            .rev()
            .filter(|r| match self.audit_filter {
                AuditFilter::All => true,
                AuditFilter::Success => r.result == AuditResult::Success,
                AuditFilter::DryRun => r.result == AuditResult::DryRun,
                AuditFilter::Skipped => r.result == AuditResult::Skipped,
                AuditFilter::Failure => r.result == AuditResult::Failure,
            })
            .filter(|r| query.is_empty() || audit_record_matches_lower_query(r, &query))
            .take(200)
            .collect();

        div()
            .size_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap_1()
                            .child(choice_chip(
                                "af-all",
                                tr(lang, "全部", "All"),
                                self.audit_filter == AuditFilter::All,
                                cx.listener(|app, _, _, cx| {
                                    app.audit_filter = AuditFilter::All;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "af-ok",
                                "success",
                                self.audit_filter == AuditFilter::Success,
                                cx.listener(|app, _, _, cx| {
                                    app.audit_filter = AuditFilter::Success;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "af-dry",
                                "dry-run",
                                self.audit_filter == AuditFilter::DryRun,
                                cx.listener(|app, _, _, cx| {
                                    app.audit_filter = AuditFilter::DryRun;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "af-skip",
                                "skipped",
                                self.audit_filter == AuditFilter::Skipped,
                                cx.listener(|app, _, _, cx| {
                                    app.audit_filter = AuditFilter::Skipped;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "af-fail",
                                "failure",
                                self.audit_filter == AuditFilter::Failure,
                                cx.listener(|app, _, _, cx| {
                                    app.audit_filter = AuditFilter::Failure;
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(div().flex_1().child(self.audit_search_input.clone()))
                    .child(action_btn(
                        "clear-audit-btn",
                        tr(lang, "清空日志", "Clear Logs"),
                        0x7f1d1d,
                        cx.listener(|app, _, _, cx| {
                            let lang = app.lang();
                            let _ = app.engine.lock().unwrap().clear_audit_logs();
                            app.refresh_snapshot();
                            app.set_banner(
                                false,
                                tr(lang, "已清空审计日志", "Audit logs cleared"),
                            );
                            cx.notify();
                        }),
                    )),
            )
            .child(
                div()
                    .id("audit-list-scroll")
                    .flex_1()
                    .overflow_scroll()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(if filtered.is_empty() {
                        vec![
                            div()
                                .p_4()
                                .text_sm()
                                .text_color(rgb(0x94a3b8))
                                .child(tr(lang, "没有匹配的审计记录", "No matching audit records"))
                                .into_any_element(),
                        ]
                    } else {
                        filtered
                            .into_iter()
                            .map(|rec| audit_row(rec, lang).into_any_element())
                            .collect()
                    }),
            )
            .into_any_element()
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let lang = self.lang();
        let s = &self.settings;
        div()
            .id("settings-scroll")
            .size_full()
            .overflow_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_base()
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(rgb(0xf8fafc))
                            .child(tr(lang, "全局设置与安全白名单", "Global Settings & Whitelist")),
                    )
                    .child(action_btn(
                        "save-settings-btn",
                        tr(lang, "校验并保存设置", "Validate & Save Settings"),
                        0x059669,
                        cx.listener(|app, _, window, cx| app.on_save_settings(window, cx)),
                    )),
            )
            .when(!s.validation_errors.is_empty(), |d| {
                d.child(
                    div()
                        .p_3()
                        .rounded_md()
                        .bg(rgb(0x450a0a))
                        .border_1()
                        .border_color(rgb(0xef4444))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .children(s.validation_errors.iter().map(|e| {
                            div()
                                .text_xs()
                                .text_color(rgb(0xfca5a5))
                                .child(format!("• {e}"))
                        })),
                )
            })
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(field_label(tr(lang, "界面语言:", "Language:")))
                    .child(choice_chip(
                        "lang-zh",
                        "中文",
                        s.language == UiLanguage::Zh,
                        cx.listener(|app, _, _, cx| {
                            app.settings.language = UiLanguage::Zh;
                            cx.notify();
                        }),
                    ))
                    .child(choice_chip(
                        "lang-en",
                        "English",
                        s.language == UiLanguage::En,
                        cx.listener(|app, _, _, cx| {
                            app.settings.language = UiLanguage::En;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_wrap()
                    .gap_2()
                    .child(toggle_chip(
                        "set-dry-run",
                        if s.global_dry_run {
                            tr(lang, "全局 Dry-Run: 开启", "Global Dry-Run: ON")
                        } else {
                            tr(lang, "全局 Dry-Run: 关闭", "Global Dry-Run: OFF")
                        },
                        s.global_dry_run,
                        cx.listener(|app, _, _, cx| {
                            app.settings.global_dry_run = !app.settings.global_dry_run;
                            cx.notify();
                        }),
                    ))
                    .child(toggle_chip(
                        "set-pause-all",
                        if s.paused_all {
                            tr(lang, "全局暂停: 开启", "Pause All: ON")
                        } else {
                            tr(lang, "全局暂停: 关闭", "Pause All: OFF")
                        },
                        s.paused_all,
                        cx.listener(|app, _, _, cx| {
                            app.settings.paused_all = !app.settings.paused_all;
                            cx.notify();
                        }),
                    ))
                    .child(toggle_chip(
                        "set-redact",
                        if s.redact_audit_summary {
                            tr(lang, "审计摘要脱敏: 开启", "Redact Audit Summary: ON")
                        } else {
                            tr(lang, "审计摘要脱敏: 关闭", "Redact Audit Summary: OFF")
                        },
                        s.redact_audit_summary,
                        cx.listener(|app, _, _, cx| {
                            app.settings.redact_audit_summary =
                                !app.settings.redact_audit_summary;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(field_label(tr(lang, "luvus 通信方式", "luvus Transport Mode")))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_wrap()
                            .gap_2()
                            .child(choice_chip(
                                "tm-auto",
                                tr(
                                    lang,
                                    "auto (UHP Socket 优先, CLI 回退)",
                                    "auto (UHP Socket first, CLI fallback)",
                                ),
                                s.transport_mode == TransportMode::Auto,
                                cx.listener(|app, _, _, cx| {
                                    app.settings.transport_mode = TransportMode::Auto;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "tm-socket",
                                tr(
                                    lang,
                                    "socket (UHP Unix Socket 直连)",
                                    "socket (Direct UHP Unix Socket)",
                                ),
                                s.transport_mode == TransportMode::Socket,
                                cx.listener(|app, _, _, cx| {
                                    app.settings.transport_mode = TransportMode::Socket;
                                    cx.notify();
                                }),
                            ))
                            .child(choice_chip(
                                "tm-cli",
                                tr(lang, "cli (luvus 子进程)", "cli (luvus subprocess)"),
                                s.transport_mode == TransportMode::Cli,
                                cx.listener(|app, _, _, cx| {
                                    app.settings.transport_mode = TransportMode::Cli;
                                    cx.notify();
                                }),
                            )),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(labeled_field(
                        tr(lang, "luvus UHP Socket 路径 (留空自动探测)", "luvus UHP Socket Path (auto if empty)"),
                        s.inputs.luvus_socket_path.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "luvus 可执行路径", "luvus Binary Path"),
                        s.inputs.luvus_bin.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "兜底轮询间隔 (秒, 0禁用)", "Poll Interval (s, 0=off)"),
                        s.inputs.scan_interval_sec.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "Events 重连延迟 (秒)", "Events Reconnect Delay (s)"),
                        s.inputs.reconnect_delay_sec.clone(),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(labeled_field(
                        tr(lang, "Blocked 读取行数", "Read Lines (blocked)"),
                        s.inputs.read_lines_blocked.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "错误检查读取行数", "Read Lines (errors)"),
                        s.inputs.read_lines_error.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "默认连续动作上限 (0不限)", "Default Max Continuous (0=off)"),
                        s.inputs.max_continuous_default.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "审计日志保留天数", "Audit Retention (days)"),
                        s.inputs.audit_retention_days.clone(),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(labeled_field(
                        tr(lang, "监控 Pane 过滤 (逗号分隔, * 为全部)", "Allowed Panes (CSV, * for all)"),
                        s.inputs.allowed_panes.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "监控 Agent 过滤 (逗号分隔, * 为全部)", "Allowed Agents (CSV, * for all)"),
                        s.inputs.allowed_agents.clone(),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(labeled_field(
                        tr(lang, "允许的按键白名单 (逗号分隔)", "Whitelisted Keys (CSV)"),
                        s.inputs.whitelisted_keys.clone(),
                    ))
                    .child(labeled_field(
                        tr(lang, "允许发送的文本白名单 (逗号分隔)", "Whitelisted Send Texts (CSV)"),
                        s.inputs.whitelisted_send_texts.clone(),
                    )),
            )
            .child(labeled_field(
                tr(
                    lang,
                    "全局不可自动重试错误正则（账单/鉴权/额度/401/403 等，每行一条）",
                    "Global Non-Retryable Error Regexes (billing/auth/quota/401/403, one per line)",
                ),
                s.inputs.non_retryable_regexes.clone(),
            ))
            .into_any_element()
    }
}

impl Render for WatchdogApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let lang = self.lang();
        let content = match self.active_tab {
            ActiveTab::Dashboard => self.render_dashboard(cx),
            ActiveTab::Rules => self.render_rules(cx),
            ActiveTab::Tester => self.render_tester(cx),
            ActiveTab::Audit => self.render_audit(cx),
            ActiveTab::Settings => self.render_settings(cx),
        };

        let is_client_deco = matches!(window.window_decorations(), Decorations::Client { .. });
        let root = div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0x0f172a))
            .text_color(rgb(0xe2e8f0))
            .border_1()
            .border_color(rgb(0x1e293b))
            .child(self.render_header(window, cx))
            .when_some(self.snapshot.last_config_error.as_ref(), |d, err| {
                d.child(
                    div()
                        .px_4()
                        .py_2()
                        .bg(rgb(0x450a0a))
                        .border_b_1()
                        .border_color(rgb(0xef4444))
                        .text_xs()
                        .text_color(rgb(0xfca5a5))
                        .child(format!("{}: {err}", tr(lang, "配置告警", "Config Warning"))),
                )
            })
            .when_some(self.status_banner.as_ref(), |d, (is_err, msg)| {
                d.child(
                    div()
                        .px_4()
                        .py_1()
                        .bg(if *is_err { rgb(0x450a0a) } else { rgb(0x064e3b) })
                        .border_b_1()
                        .border_color(if *is_err { rgb(0xef4444) } else { rgb(0x10b981) })
                        .flex()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .text_xs()
                        .text_color(if *is_err { rgb(0xfca5a5) } else { rgb(0xa7f3d0) })
                        .child(msg.clone())
                        .child(small_btn(
                            "dismiss-banner",
                            tr(lang, "关闭", "Dismiss"),
                            cx.listener(|app, _, _, cx| {
                                app.status_banner = None;
                                cx.notify();
                            }),
                        )),
                )
            })
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_row()
                    .overflow_hidden()
                    .child(self.render_sidebar(cx))
                    .child(div().flex_1().h_full().overflow_hidden().child(content)),
            )
            .when(is_client_deco, |d| {
                d.children(client_resize_handles())
            });

        if self
            .window_nudge_until
            .is_some_and(|until| Instant::now() < until)
        {
            root.with_animation(
                SharedString::from(format!("win-nudge-{}", self.window_nudge_seq)),
                Animation::new(Duration::from_millis(450)),
                |el, delta| {
                    let decay = 1.0 - delta;
                    let dx = (delta * std::f32::consts::TAU * 3.5).sin() * 7.0 * decay;
                    let dy = (delta * std::f32::consts::TAU * 2.5).cos() * 3.0 * decay;
                    let el = el.left(px(dx)).top(px(dy));
                    if delta < 0.98 {
                        el.border_1().border_color(rgb(0xfacc15))
                    } else {
                        el
                    }
                },
            )
            .into_any_element()
        } else {
            root.into_any_element()
        }
    }
}

fn badge(label: impl Into<SharedString>, bg: u32, fg: u32) -> impl IntoElement {
    div()
        .px_2()
        .py(px(2.))
        .rounded_sm()
        .bg(rgb(bg))
        .text_xs()
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_color(rgb(fg))
        .child(label.into())
}

fn action_btn(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    bg: u32,
    handler: impl Fn(&gpui::MouseUpEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id.into())
        .px_3()
        .py_1()
        .rounded_md()
        .bg(rgb(bg))
        .border_1()
        .border_color(rgb(0x334155))
        .text_xs()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(rgb(0xf8fafc))
        .cursor_pointer()
        .hover(|s| s.opacity(0.88))
        .on_mouse_up(MouseButton::Left, handler)
        .child(label.into())
}

fn small_btn(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    handler: impl Fn(&gpui::MouseUpEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id.into())
        .px_2()
        .py(px(2.))
        .rounded_sm()
        .bg(rgb(0x1e293b))
        .border_1()
        .border_color(rgb(0x334155))
        .text_xs()
        .text_color(rgb(0xe2e8f0))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(0x334155)))
        .on_mouse_up(MouseButton::Left, handler)
        .child(label.into())
}

fn toggle_chip(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    active: bool,
    handler: impl Fn(&gpui::MouseUpEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    choice_chip(id, label, active, handler)
}

fn choice_chip(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    active: bool,
    handler: impl Fn(&gpui::MouseUpEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id.into())
        .px_2()
        .py_1()
        .rounded_md()
        .cursor_pointer()
        .text_xs()
        .border_1()
        .border_color(if active { rgb(0x3b82f6) } else { rgb(0x334155) })
        .bg(if active { rgb(0x1e3a8a) } else { rgb(0x0f172a) })
        .text_color(if active { rgb(0xffffff) } else { rgb(0x94a3b8) })
        .on_mouse_up(MouseButton::Left, handler)
        .child(label.into())
}

fn field_label(text: impl Into<SharedString>) -> impl IntoElement {
    div()
        .text_xs()
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_color(rgb(0x94a3b8))
        .child(text.into())
}

fn labeled_field(label: impl Into<SharedString>, input: Entity<TextInput>) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap_1()
        .child(field_label(label))
        .child(input)
}

fn kpi_card(
    title: impl Into<SharedString>,
    value: impl Into<SharedString>,
    subtitle: impl Into<SharedString>,
) -> impl IntoElement {
    div()
        .flex_1()
        .p_3()
        .rounded_md()
        .bg(rgb(0x0b1220))
        .border_1()
        .border_color(rgb(0x1e293b))
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_xs().text_color(rgb(0x94a3b8)).child(title.into()))
        .child(
            div()
                .text_xl()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(rgb(0xf8fafc))
                .child(value.into()),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(0x64748b))
                .truncate()
                .child(subtitle.into()),
        )
}

fn str_contains_lower_query(hay: &str, lower_query: &str) -> bool {
    if hay.is_ascii() && lower_query.is_ascii() {
        let h = hay.as_bytes();
        let q = lower_query.as_bytes();
        if q.len() > h.len() {
            return false;
        }
        return h.windows(q.len()).any(|w| w.eq_ignore_ascii_case(q));
    }
    hay.to_lowercase().contains(lower_query)
}

fn audit_record_matches_lower_query(rec: &AuditRecord, lower_query: &str) -> bool {
    [
        rec.pane.as_str(),
        rec.agent.as_str(),
        rec.status.as_str(),
        rec.rule_id.as_deref().unwrap_or(""),
        rec.rule_name.as_deref().unwrap_or(""),
        rec.match_summary.as_str(),
        rec.action_summary.as_str(),
        rec.detail.as_str(),
    ]
    .into_iter()
    .any(|field| str_contains_lower_query(field, lower_query))
}

fn section_card(title: impl Into<SharedString>, body: impl IntoElement) -> impl IntoElement {
    div()
        .p_3()
        .rounded_md()
        .bg(rgb(0x0b1220))
        .border_1()
        .border_color(rgb(0x1e293b))
        .flex()
        .flex_col()
        .gap_3()
        .child(
            div()
                .text_sm()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(rgb(0xf1f5f9))
                .child(title.into()),
        )
        .child(body)
}

fn audit_row(rec: &AuditRecord, lang: UiLanguage) -> impl IntoElement {
    let (res_bg, res_fg) = match rec.result {
        AuditResult::Success => (0x065f46, 0x6ee7b7),
        AuditResult::DryRun => (0x78350f, 0xfcd34d),
        AuditResult::Skipped => (0x334155, 0xcbd5e1),
        AuditResult::Failure => (0x7f1d1d, 0xfca5a5),
    };

    div()
        .p_2()
        .rounded_md()
        .bg(rgb(0x0b1220))
        .border_1()
        .border_color(rgb(0x1e293b))
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .flex_row()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .flex_wrap()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(0x64748b))
                                .child(pretty_time_with_clock(
                                    rec.timestamp,
                                    chrono::Utc::now(),
                                    lang,
                                )),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(rgb(0xe2e8f0))
                                .child(format!("{} ({} / {})", rec.pane, rec.agent, rec.status)),
                        )
                        .child(badge(rec.result.label(), res_bg, res_fg))
                        .when_some(rec.skip_reason, |d, sr| {
                            d.child(badge(sr.label(), 0x1e293b, 0xfcd34d))
                        })
                        .when_some(rec.rule_name.as_ref(), |d, rn| {
                            d.child(badge(rn.clone(), 0x1e3a8a, 0x93c5fd))
                        }),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(0x93c5fd))
                        .child(rec.action_summary.clone()),
                ),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(0x94a3b8))
                .child(format!(
                    "{}{}",
                    rec.detail,
                    if rec.match_summary.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " | {}: {}",
                            tr(lang, "摘要", "Summary"),
                            rec.match_summary
                        )
                    }
                )),
        )
}

fn win_control_btn(
    id: &'static str,
    label: &'static str,
    danger: bool,
    on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .w(px(26.))
        .h(px(26.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_md()
        .cursor_pointer()
        .text_sm()
        .text_color(rgb(0xcbd5e1))
        .bg(rgb(0x131d31))
        .hover(move |s| {
            if danger {
                s.bg(rgb(0xb91c1c)).text_color(rgb(0xffffff))
            } else {
                s.bg(rgb(0x334155)).text_color(rgb(0xf8fafc))
            }
        })
        .on_click(on_click)
        .child(label)
}

fn client_resize_handles() -> Vec<AnyElement> {
    let edge = px(5.);
    let corner = px(8.);
    fn make<F>(
        id: &'static str,
        cursor: CursorStyle,
        resize_edge: ResizeEdge,
        style_fn: F,
    ) -> AnyElement
    where
        F: FnOnce(gpui::Stateful<gpui::Div>) -> gpui::Stateful<gpui::Div>,
    {
        style_fn(
            div()
                .id(id)
                .absolute()
                .cursor(cursor)
                .on_mouse_down(MouseButton::Left, move |_, window, cx| {
                    cx.stop_propagation();
                    window.start_window_resize(resize_edge);
                }),
        )
        .into_any_element()
    }

    vec![
        make("resize-n", CursorStyle::ResizeUpDown, ResizeEdge::Top, |d| {
            d.top_0().left(px(8.)).right(px(8.)).h(px(4.))
        }),
        make("resize-s", CursorStyle::ResizeUpDown, ResizeEdge::Bottom, |d| {
            d.bottom_0().left(px(8.)).right(px(8.)).h(edge)
        }),
        make("resize-w", CursorStyle::ResizeLeftRight, ResizeEdge::Left, |d| {
            d.left_0().top(px(8.)).bottom(px(8.)).w(edge)
        }),
        make("resize-e", CursorStyle::ResizeLeftRight, ResizeEdge::Right, |d| {
            d.right_0().top(px(8.)).bottom(px(8.)).w(edge)
        }),
        make("resize-nw", CursorStyle::ResizeUpRightDownLeft, ResizeEdge::TopLeft, |d| {
            d.top_0().left_0().w(corner).h(corner)
        }),
        make("resize-ne", CursorStyle::ResizeUpLeftDownRight, ResizeEdge::TopRight, |d| {
            d.top_0().right_0().w(corner).h(corner)
        }),
        make("resize-sw", CursorStyle::ResizeUpLeftDownRight, ResizeEdge::BottomLeft, |d| {
            d.bottom_0().left_0().w(corner).h(corner)
        }),
        make("resize-se", CursorStyle::ResizeUpRightDownLeft, ResizeEdge::BottomRight, |d| {
            d.bottom_0().right_0().w(corner).h(corner)
        }),
    ]
}

/// Write the XDG icon and `.desktop` entry so Wayland/X11 taskbars & titlebars display the app icon.
pub fn write_linux_desktop_files(
    data_home: &Path,
    exe_path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let icon_dir = data_home.join("icons/hicolor/512x512/apps");
    let apps_dir = data_home.join("applications");
    fs::create_dir_all(&icon_dir)?;
    fs::create_dir_all(&apps_dir)?;

    let icon_path = icon_dir.join("nudgegeist.png");
    fs::write(&icon_path, APP_ICON_PNG)?;

    let desktop_path = apps_dir.join("nudgegeist.desktop");
    let desktop_contents = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Nudgegeist\n\
         Name[zh_CN]=辣椒\n\
         Comment=AI Coding Agent Watchdog & Rule Engine GUI\n\
         Exec=\"{}\"\n\
         Icon={}\n\
         Terminal=false\n\
         Categories=Development;Utility;\n\
         StartupWMClass=nudgegeist\n",
        exe_path.display(),
        icon_path.display()
    );
    fs::write(&desktop_path, desktop_contents)?;
    Ok((icon_path, desktop_path))
}

pub fn ensure_linux_desktop_integration() -> anyhow::Result<(PathBuf, PathBuf)> {
    // Inside an AppImage, current_exe() points to an ephemeral FUSE mount (/tmp/.mount_*).
    if std::env::var_os("APPIMAGE").is_some_and(|v| !v.is_empty()) {
        return Ok((PathBuf::new(), PathBuf::new()));
    }

    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("nudgegeist"));
    let is_system_install = exe_path.starts_with("/usr/bin")
        || exe_path.starts_with("/usr/local/bin");
    if is_system_install
        && (Path::new("/usr/share/applications/nudgegeist.desktop").exists()
            || Path::new("/usr/local/share/applications/nudgegeist.desktop").exists())
    {
        return Ok((PathBuf::new(), PathBuf::new()));
    }

    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/share")
        });
    let res = write_linux_desktop_files(&data_home, &exe_path)?;
    if let Some(apps_dir) = res.1.parent() {
        let _ = std::process::Command::new("update-desktop-database")
            .arg(apps_dir)
            .output();
    }
    Ok(res)
}

pub fn launch_gui(cli_dry_run: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let _ = ensure_linux_desktop_integration();

    let paths = AppPaths::resolve_default();
    let engine = Arc::new(Mutex::new(WatchdogEngine::initialize(paths, true)?));
    if cli_dry_run {
        let mut eng = engine.lock().unwrap();
        eng.config.global_dry_run = true;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let bg_handle = spawn_engine_loop(Arc::clone(&engine), Arc::clone(&stop), cli_dry_run);

    let initial_title = {
        let eng = engine.lock().unwrap();
        tr(eng.config.language, "辣椒", "Nudgegeist")
    };

    let gui_engine = Arc::clone(&engine);
    Application::new().run(move |cx: &mut App| {
        bind_input_keys(cx);
        let bounds = Bounds::centered(None, size(px(1280.), px(820.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_decorations: Some(WindowDecorations::Client),
                titlebar: Some(TitlebarOptions {
                    title: Some(initial_title.into()),
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(12.), px(14.))),
                }),
                app_id: Some("nudgegeist".to_string()),
                ..Default::default()
            },
            |_, cx| cx.new(|cx| WatchdogApp::new(Arc::clone(&gui_engine), cx)),
        )
        .expect("Failed to open GPUI window");
        cx.activate(true);
    });

    stop.store(true, Ordering::Relaxed);
    let _ = bg_handle.join();
    Ok(())
}
