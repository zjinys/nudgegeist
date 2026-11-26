use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use nudgegeist::config::AppPaths;
use nudgegeist::engine::{WatchdogEngine, spawn_engine_loop};
use nudgegeist::luvus::DynamicLuvusClient;
use nudgegeist::ui::app::{ensure_linux_desktop_integration, launch_gui};

fn print_help() {
    println!(
        "nudgegeist - Agent Auto Confirm Watchdog (GPUI + 规则引擎)\n\n\
         用法:\n\
           nudgegeist                    启动 GPUI 桌面控制台与后台引擎\n\
           nudgegeist --dry-run          以 Dry-Run 模式启动 GUI\n\
           nudgegeist --once             仅执行一轮扫描后退出（CLI 兼容）\n\
           nudgegeist --headless         仅在终端运行后台引擎（不启动 GUI）\n\
           nudgegeist --install-desktop  安装桌面图标与 .desktop 启动器\n\
           nudgegeist -h, --help         显示帮助\n"
    );
}

fn main() -> anyhow::Result<()> {
    let mut once = false;
    let mut dry_run = false;
    let mut headless = false;
    let mut install_desktop = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--once" => once = true,
            "--dry-run" => dry_run = true,
            "--headless" => headless = true,
            "--install-desktop" => install_desktop = true,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => {
                eprintln!("未知参数: {other}");
                print_help();
                std::process::exit(1);
            }
        }
    }

    if install_desktop {
        let (icon_path, desktop_path) = ensure_linux_desktop_integration()?;
        println!("已安装图标: {}", icon_path.display());
        println!("已安装桌面入口: {}", desktop_path.display());
        return Ok(());
    }

    if once {
        let paths = AppPaths::resolve_default();
        let mut eng = WatchdogEngine::initialize(paths, true)?;
        let client = DynamicLuvusClient::from_config(&eng.config);
        eng.scan_once(&client, dry_run)?;
        return Ok(());
    }

    if headless {
        let paths = AppPaths::resolve_default();
        let engine = Arc::new(Mutex::new(WatchdogEngine::initialize(paths, true)?));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_engine_loop(engine, stop, dry_run);
        let _ = handle.join();
        return Ok(());
    }

    launch_gui(dry_run)
}
