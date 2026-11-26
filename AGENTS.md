# AGENTS.md

Guidelines for coding agents working in `nudgegeist` (**Agent Auto Confirm Watchdog GUI**).

## Project Overview

This project evolves the `luvus`-based watchdog script (`~/.local/bin/agent-auto-confirm-watchdog`) into a configurable rule engine with a visual GUI for monitoring and unblocking stalled AI coding agents.

- **Primary spec**: `agent-auto-confirm-watchdog-gui-requirements.md`
- **Current status**: Implemented as a native **Rust + GPUI (`0.2.2`)** desktop application with an embedded rule engine, atomic JSON config/rules persistence, JSONL audit logging, and CLI compatibility (`--once`, `--dry-run`, `--headless`).

## Directory Layout & Modules

- `src/config.rs`: Versioned `WatchdogConfig` (`config.json`) & `RulesFile` (`rules.json`), built-in conservative rules, regex/schema/whitelist validation, atomic JSON save (`tempfile` + parse-back + `persist`), and safe external rule import.
- `src/audit.rs`: JSONL audit log store (`~/.cache/nudgegeist/audit.jsonl`), retention pruning, and optional summary redaction.
- `src/luvus.rs`: `LuvusClient` trait, `UnixSocketUhpClient` (direct UHP 1.0 NDJSON over `~/.luvus/luvus.sock`), `RealLuvusClient` CLI fallback (`agent list`, `agent read`, `agent keys`, `agent send`, `events`), `DynamicLuvusClient` (`auto` / `socket` / `cli`), and UHP/CLI event & output parsers.
- `src/engine.rs`: Stateless rule evaluator (`evaluate_rules_stateless` with `RuleEvalTrace` explanations), stateful `WatchdogEngine` (hot reload, cooldown, dedupe, `maxContinuous`, per-pane/rule pause), and `luvus events` reconnect + polling fallback loop.
- `src/ui/text_input.rs`: Reusable GPUI single-line and multi-line text editor (`TextInput`).
- `src/ui/app.rs`: `WatchdogApp` GPUI desktop UI (Dashboard, Rules CRUD + Form/JSON editor + Import/Export, Rule Tester with live pane fetch, Audit Log viewer, Settings).
- `src/main.rs`: Binary entry point supporting GUI mode and `--once` / `--dry-run` / `--headless`.
- `tests/watchdog_tests.rs`: Unit and `MockLuvusClient` dry-run/live integration tests.
- `build.rs` & `assets/`: App icons (`nudgegeist.png`, `nudgegeist-256.png`, `nudgegeist.ico`) and Windows PE icon resource embedding.
- `packaging/` & `scripts/`: Linux (`deb`, `rpm`, `pacman`, `AppImage`, XDG `.desktop`), macOS (`Info.plist.in`, `package-dmg.sh`), and Windows (`nudgegeist.wxs`, `package-msi.ps1`) packaging assets & scripts.
- `.github/workflows/`: Multi-OS CI (`ci.yml`) and tag-driven multi-platform GitHub Release (`release.yml`).
- `Makefile`: Convenience targets (`build`, `release`, `test`, `deb`, `rpm`, `pacman`, `appimage`, `dmg`, `msi`, `install-desktop`).

## Build, Test & Run Commands

- **Run all tests**: `cargo test --offline`
- **Build binary**: `cargo build --offline`
- **Release build**: `cargo build --release --offline --locked`
- **Launch GPUI app**: `cargo run --offline` (or `-- --dry-run`)
- **Single-scan CLI mode**: `cargo run --offline -- --once --dry-run`
- **Headless daemon mode**: `cargo run --offline -- --headless`
- **Package Linux bundles**: `./scripts/package-deb.sh dist`, `./scripts/package-rpm.sh dist`, `./scripts/package-pacman.sh dist`, `./scripts/package-appimage.sh dist`
- **Package macOS / Windows**: `./scripts/package-dmg.sh dist` (macOS), `powershell -File scripts/package-msi.ps1 dist` (Windows)

## Target Architecture

Keep strict separation across three layers:

1. **Rule & Config Layer** (`~/.config/nudgegeist/config.json`, `rules.json`; runtime state/logs under `~/.cache/nudgegeist/`):
   - Versioned JSON schemas for rules and global settings.
   - The GUI only edits configuration; it must not execute agent actions directly.
2. **Execution Engine Layer**:
   - Event-driven via `luvus events` (`agent_status`) with configurable `luvus agent list` polling fallback (default 15s, `0` disables).
   - Reads only trailing visible lines (default: 12 lines for `blocked`, 40 lines for errors).
   - Evaluates enabled rules by descending `priority` (at most one highest-priority match executes per pane per check).
   - Supports hot-reloading configuration without restarting.
3. **GUI Layer**:
   - MVP: Local daemon/engine + local Web GUI bound to `127.0.0.1` (future packaging via Tauri/Electron).
   - Views: Dashboard, rule list & editor (form + JSON + validation), text/live-pane rule tester with match/guard explanations, audit log viewer, and settings/global dry-run toggle.

## Non-Negotiable Safety & Reliability Rules

- **Strict action whitelist**: MVP actions are limited to `keys` (`luvus agent keys <pane> <key>`, whitelisted keys such as `enter`, `esc`, `up`, `down`) and `send` (`luvus agent send <pane> "<text>"`, whitelisted text such as `继续`). Never allow arbitrary shell commands as rule actions.
- **Conservative matching**: Never risk dangerous confirmations. Support `guards` (e.g. `Delete|Overwrite|cannot be undone`) and never auto-continue non-retryable billing, auth, quota, login, or permission failures (e.g., `401`/`403`).
- **Atomic & validated config**: Validate schema, regex syntax, and whitelisted actions before saving. Write atomically (temp file -> validate -> rename). If loading fails, keep the previous valid configuration and surface the error in logs and UI.
- **Dry-run & auditability**: `dry-run` must record planned actions without calling `luvus` `keys`/`send`. Every evaluation resulting in an action or skip must produce an audit record (timestamp, pane, agent kind, status, rule ID/name, match summary/signature, action, result, and skip reason such as `cooldown`, `dedupe`, `guard`, `paused`, `maxContinuous`, or `non-retryable`).
- **Resilience**: Engine failures must not affect `luvus`. Reconnect automatically when `luvus events` drops and run a compensating scan. Enforce cooldowns, signature/pane deduplication, and per-pane continuous action caps.
- **Imported rules**: Validate imported JSON rules and mark external rules disabled or dry-run-only until reviewed.

## Development & Testing Conventions

- **Incremental milestones** (see Section 10 of `agent-auto-confirm-watchdog-gui-requirements.md`):
  - **M1**: Extract rules into `rules.json`, build engine with validation, hot reload, dry-run, and CLI compatibility.
  - **M2**: Minimal local Web GUI (rules CRUD, text tester, audit logs, global dry-run toggle).
  - **M3**: Live pane testing, rule import/export, per-pane pause, continuous limits, service integration.
  - **M4**: Desktop packaging (Tauri/Electron) and built-in agent rule presets.
- **Testing requirements**:
  - Unit tests for rule matching (`anyRegex`, `allRegex`, `noneRegex`), guards, deduplication, cooldowns, and schema/regex validation.
  - Dry-run integration tests covering confirmation prompts, recoverable transport/rate-limit errors, non-retryable auth/billing errors, deduplication, and `luvus events` reconnect recovery.
- **Keep this file current**: Once the tech stack, directory layout, and build/test commands are chosen, document the exact commands and paths here.
