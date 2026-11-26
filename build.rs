use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/nudgegeist.ico");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("assets").join("nudgegeist.ico");
    if !ico_path.exists() {
        println!("cargo:warning=Missing assets/nudgegeist.ico; skipping Windows exe icon embedding.");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("nudgegeist.rc");
    let ico_escaped = ico_path.display().to_string().replace('\\', "/");
    let rc_contents = format!("1 ICON \"{ico_escaped}\"\n");
    if let Err(err) = fs::write(&rc_path, rc_contents) {
        println!("cargo:warning=Failed to write Windows .rc file: {err}");
        return;
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());

    if target_env == "msvc" {
        if let Some(rc_bin) = find_windows_rc(&target_arch) {
            let res_path = out_dir.join("nudgegeist.res");
            let status = Command::new(&rc_bin)
                .arg("/nologo")
                .arg("/fo")
                .arg(&res_path)
                .arg(&rc_path)
                .status();
            match status {
                Ok(st) if st.success() && res_path.exists() => {
                    println!("cargo:rustc-link-arg-bin=nudgegeist={}", res_path.display());
                    return;
                }
                Ok(st) => println!("cargo:warning=rc.exe exited with {st}; skipping exe icon."),
                Err(err) => println!("cargo:warning=Failed to run rc.exe ({}): {err}", rc_bin.display()),
            }
        } else {
            println!("cargo:warning=rc.exe not found; skipping Windows exe icon embedding.");
        }
    } else if target_env == "gnu" {
        let windres_candidates = match target_arch.as_str() {
            "aarch64" => vec!["aarch64-w64-mingw32-windres", "windres"],
            "x86" => vec!["i686-w64-mingw32-windres", "windres"],
            _ => vec!["x86_64-w64-mingw32-windres", "windres"],
        };
        for tool in windres_candidates {
            if let Ok(st) = Command::new(tool)
                .arg(&rc_path)
                .arg("-O")
                .arg("coff")
                .arg("-o")
                .arg(out_dir.join("nudgegeist_res.o"))
                .status()
            {
                if st.success() {
                    println!(
                        "cargo:rustc-link-arg-bin=nudgegeist={}",
                        out_dir.join("nudgegeist_res.o").display()
                    );
                    return;
                }
            }
        }
    }
}

fn find_windows_rc(target_arch: &str) -> Option<PathBuf> {
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            for candidate in ["rc.exe", "rc", "llvm-rc.exe", "llvm-rc"] {
                let full = dir.join(candidate);
                if full.is_file() {
                    return Some(full);
                }
            }
        }
    }

    let arch_dir = match target_arch {
        "aarch64" => "arm64",
        "x86" => "x86",
        _ => "x64",
    };

    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(sdk_dir) = env::var_os("WindowsSdkDir") {
        roots.push(PathBuf::from(sdk_dir).join("bin"));
    }
    for var in ["ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"] {
        if let Some(pf) = env::var_os(var) {
            roots.push(PathBuf::from(pf).join("Windows Kits").join("10").join("bin"));
        }
    }

    for root in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|ent| ent.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for ver_dir in versions {
            let candidate = ver_dir.join(arch_dir).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let fallback = root.join(arch_dir).join("rc.exe");
        if fallback.is_file() {
            return Some(fallback);
        }
    }
    None
}
