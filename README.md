# Nudgegeist（辣椒）

> 基于 Rust + GPUI 构建的 AI 编程 Agent 自动看门狗与可配置规则引擎桌面应用。

**Nudgegeist**（中文名：**辣椒**）用于通过 `luvus` 持续监控正在运行的 AI 编程助手会话（如 Codex、Antigravity、OpenCode 等），在遇到**安全的例行确认提示**或**可重试的临时网络/限流中断**时，按保守规则自动发送按键或恢复指令，减少人工盯屏与流程卡死；同时严格拦截高风险操作和不可恢复的鉴权/账单错误。

---

## 核心功能

### 1. 实时监控与事件驱动引擎
- **UHP Socket + CLI 双传输**：在 Unix 平台优先直连 `~/.luvus/luvus.sock`（UHP 1.0 NDJSON 实时事件流，支持断线自动重连与补偿扫描），也支持自动或手动回退至 `luvus` CLI 子进程轮询。
- **按状态变化时间动态排序**：Dashboard 实时面板优先展示最近状态变化的 Agent Pane，并在位置切换及触发动作时提供高亮、抖动反馈与相对时间（pretty print）显示。
- **精细化防刷与风控**：支持按规则或全局设置冷却时间（Cooldown）、基于签名/Pane 的去重（Dedupe）、单 Pane 连续动作上限（`maxContinuous`）、以及单 Pane / 全局暂停。

### 2. 保守可配的规则引擎
- **高危确认守卫（Guards）**：支持通过 `anyRegex` / `allRegex` / `noneRegex` 匹配结尾可见输出，内置高危关键词拦截（如 `Delete|Overwrite|cannot be undone` 等），绝不盲目放行破坏性确认。
- **非重试错误硬停止**：遇到余额不足、配额耗尽、登录失效或鉴权失败（如 `401` / `403` / billing / login required）时自动跳过并记录审计原因（`non-retryable`），不会死循环重试。
- **严格动作白名单**：规则动作仅允许安全白名单内的 `keys`（如 `enter`、`esc`、`up`、`down`）或 `send`（如 `继续`），**禁止执行任意 Shell 命令**。
- **热重载与安全导入**：配置与规则以原子方式校验并写入 `~/.config/nudgegeist/config.json` 与 `rules.json`；加载失败时保留上一次有效配置并在界面告警；导入外部规则时默认设为待审核或 Dry-Run。

### 3. GPUI 原生桌面界面（中/英双语）
- **无边框可拖拽窗口**：去除系统标题栏，顶部状态栏支持拖拽移动、双击最大化/还原、右键窗口菜单以及边缘缩放。
- **五大视图**：
  - **仪表盘（Dashboard）**：实时 Pane 状态列表、暂停/恢复、重置连续计数、一键跳转实时测试、最近审计动态。
  - **规则管理（Rules）**：按优先级管理内置与自定义规则，支持表单编辑、JSON 编辑、规则导入/导出。
  - **规则测试（Rule Tester）**：支持直接拉取运行中 Pane 的终端输出或粘贴测试文本，逐条展示匹配结果与 Guard/Skip 原因解释。
  - **审计日志（Audit Logs）**：持久化记录于 `~/.cache/nudgegeist/audit.jsonl`，支持按状态筛选、关键词检索、脱敏摘要与定期清理。
  - **系统设置（Settings）**：配置传输模式、扫频间隔、全局 Dry-Run 开关、动作白名单与非重试正则规则。

---

## 运行方式

```bash
# 启动 GPUI 桌面应用与后台看门狗引擎
cargo run --offline

# 以 Dry-Run（只记录计划动作、不实际发送按键/文本）模式启动 GUI
cargo run --offline -- --dry-run

# 仅执行一轮扫描后退出（兼容批处理/脚本模式）
cargo run --offline -- --once --dry-run

# 仅在终端运行后台守护引擎（不启动桌面窗口）
cargo run --offline -- --headless

# 安装 Linux 用户级桌面图标与 .desktop 启动器
cargo run --offline -- --install-desktop
```

### 常用环境变量

- `LUVUS_SOCKET_PATH`：覆盖默认 UHP Unix Socket 路径（默认 `~/.luvus/luvus.sock`）
- `LUVUS_BIN_PATH`：指定 `luvus` 可执行文件路径（默认从 `PATH` 查找 `luvus`）
- `WATCHDOG_PANES` / `WATCHDOG_AGENTS`：限定监控的 Pane / Agent 列表（逗号分隔，`*` 为全部）
- `WATCHDOG_MAX_CONTINUOUS` / `WATCHDOG_SCAN_INTERVAL` / `WATCHDOG_RECONNECT_DELAY`
- `WATCHDOG_READ_LINES` / `WATCHDOG_ERROR_LINES`

---

## 构建、测试与跨平台打包

项目支持通过 `Makefile` 与 `scripts/` 构建、测试及生成多平台安装包，并配备 GitHub Actions（[.github/workflows/ci.yml](.github/workflows/ci.yml) 与 [.github/workflows/release.yml](.github/workflows/release.yml)）：

```bash
# 运行全部单元测试与集成测试
cargo test --offline --locked

# 构建 Release 二进制
make release

# Linux 打包（输出到 dist/）
./scripts/package-deb.sh dist
./scripts/package-rpm.sh dist
./scripts/package-pacman.sh dist
./scripts/package-appimage.sh dist

# macOS 打包（生成 .app 与 .dmg，需在 macOS 上运行）
./scripts/package-dmg.sh dist
```

```powershell
# Windows 打包（生成 .msi 安装包与便携版 .zip，需安装 WiX Toolset v3.x）
powershell -File scripts/package-msi.ps1 dist
```
