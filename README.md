# Nudgegeist（辣椒）

> 一个**配合 Luvus 使用**的“自动看门狗”：Luvus 负责管理多个 AI Agent 会话，Nudgegeist 在旁边盯着这些会话——在安全的时候替你按一下确认、续一次跑，危险操作则坚决拦下来。

**Nudgegeist**（中文名：**辣椒**）是一个配合 **Luvus** 使用的辅助工具，基于 Rust + GPUI 构建。它持续监控 Luvus 里正在运行的 AI 编程助手会话（Codex、Antigravity、OpenCode 等），在遇到**安全的例行确认提示**或**可重试的临时网络/限流中断**时，按保守规则自动发送按键或恢复指令，减少人工盯屏与流程卡死；同时严格拦截高风险操作和不可恢复的鉴权/账单错误。它不替代 Luvus，只做 Luvus 之上的“无人值守”增强。

---

## 为什么需要它：那些让人抓狂的痛点

同时开几个 AI Agent 干活时，真正消耗人的往往不是写代码，而是“盯 Monitor”：

- **确认框把流程卡死**：Agent 跑到关键步骤弹出 `1. Yes, proceed... / Allow / Retry`，等你回来点一下 `Enter`。你没盯着，它就一直停在那儿，几分钟甚至几小时过去，什么都没发生。
- **瞬时错误白白中断**：`Connection dropped`、`Transport error: timeout`、`rate limit`、`overloaded` 这类可恢复错误，本该一句话“继续”就能接上，却因为没人及时响应而让整条任务线断掉。
- **人肉轮询很累**：为了让任务不停，你得反复切 pane、看输出、按回车、发“继续”。Agent 越多，这种机械劳动越多，人也越容易被打断点。
- **原有的脚本不好维护**：以前的 `agent-auto-confirm-watchdog` 把规则硬编码在脚本里——新增一种 Agent、多一条异常文案就得改代码；想调优先级、临时禁用某条规则、搞清楚“刚才为什么自动按了回车”，只能翻代码和日志，没有界面、没有规则测试、没有可解释性。
- **“自动”最怕误伤**：真要自动确认，最担心的就是对着 `Delete`、`Overwrite`、`cannot be undone` 这类危险提示也一按回车，或者在余额不足、登录失效时不断重试死循环。没有严格的白名单和守卫，没人敢放心开着。

**Nudgegeist 就是把这套“盯屏 + 手动续跑”的苦力活自动化，同时把安全边界做得足够保守、足够可解释。**

---

## 这个工具能做什么

### 1. 自动把卡住的 Agent 往前推
- **确认框自动处理**：识别结尾可见输出中的 `Yes / Allow / Proceed / Run / Continue / Retry / Trust` 等确认选项，自动发送 `Enter`。
- **瞬时错误自动续跑**：遇到 `Connection dropped`、`timeout`、`rate limit`、`overloaded` 等可恢复错误，自动发送“继续”。
- **危险与不可恢复场景硬停止**：删除、覆盖、不可撤销操作，以及余额不足、配额耗尽、登录失效、`401`/`403` 等鉴权/账单问题，一律不自动放行，只记录原因等人来处理。

### 2. 一套保守、可控、可解释的规则引擎
- **可视化规则管理**：在界面里增删改查规则、调优先级、启停规则，不用改一行代码；支持表单编辑、JSON 编辑和导入导出。
- **精确匹配 + 守卫**：用 `anyRegex` / `allRegex` / `noneRegex` 匹配结尾可见行，再用 `guards` 拦截高危关键词，做到“宁可漏过，不可误发”。
- **规则测试器**：上线前先验证——可以粘贴测试文本，也可以直接拉取运行中 pane 的真实输出，逐条看到命中了哪条正则、被哪个 guard 拦下、最终会执行什么动作。
- **多重防刷与风控**：每规则/全局冷却时间、基于签名与 pane 的去重、单 pane 连续动作上限（`maxContinuous`）、单 pane / 全局暂停，避免反复触发。
- **严格动作白名单**：动作只允许白名单内的 `keys`（`enter` / `esc` / `up` / `down`）和 `send`（如 `继续`），**绝不执行任意 Shell 命令**。
- **热重载与安全导入**：配置与规则原子校验写入 `~/.config/nudgegeist/`；加载失败保留上一次有效配置并告警；外部导入规则默认禁用或仅 Dry-Run，审核后才生效。

### 3. 事件驱动的实时监控
- **UHP Socket / Windows Named Pipe + CLI 双传输**：Unix 直连 `~/.luvus/luvus.sock`、Windows 直连命名管道（UHP 1.0 NDJSON 实时事件流），断线自动重连并补偿扫描；也可回退到 `luvus` CLI 轮询兜底。
- **按状态变化排序的仪表盘**：优先展示最近发生状态变化的 pane，位置切换与触发动作时高亮反馈，并显示相对时间。
- **全程可审计**：每次动作或跳过都写入 `~/.cache/nudgegeist/audit.jsonl`（时间、pane、Agent、状态、规则、命中摘要、动作、结果、跳过原因如 `cooldown` / `dedupe` / `guard` / `non-retryable`），支持筛选、检索、脱敏与清理。

### 4. GPUI 原生桌面界面（中/英双语）
- **五大视图**：仪表盘（实时状态与最近动作）、规则管理、规则测试、审计日志、系统设置（传输模式、扫频间隔、全局 Dry-Run、动作白名单等）。
- **无边框可拖拽窗口**：顶部状态栏支持拖拽移动、双击最大化/还原、右键菜单与边缘缩放。

---

## 它能给你带来什么

- **不盯屏也不卡住**：例行确认和瞬时错误自动处理，Agent 能连续跑下去，你不用一直守在屏幕前。
- **放心地“自动”**：白名单动作 + 高危守卫 + 非重试错误硬停止 + 连续上限，把误操作风险压到最低；一切都有审计记录可追溯。
- **规则随你长**：遇到新文案、新 Agent，在界面里加一条规则、先 Dry-Run 验证，再启用——不用来回改脚本、重启服务。
- **出事能说清**：每次自动动作都能解释“为什么做 / 为什么没做”，测试器还能复现问题，排查误匹配不再靠猜。
- **多平台可用**：Linux / macOS / Windows 均可构建打包（deb / rpm / pacman / AppImage / dmg / msi），也可在终端以 `--headless` 守护进程方式运行。

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

- `LUVUS_SOCKET_PATH`：覆盖默认 UHP 端点路径（Unix 默认 `~/.luvus/luvus.sock`；Windows 支持直接传 `\\.\pipe\...` 或按同名路径哈希推导命名管道）
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
