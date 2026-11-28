//! Light/dark palette support for the GPUI UI.
//!
//! The views historically used hard-coded dark hex colours. `themed` keeps those
//! call sites intact and translates them when the light palette is active. The
//! active theme is process-wide (a single app window and a single config), so a
//! small global is sufficient and avoids threading a palette through every
//! element helper.

use std::sync::Mutex;

use gpui::{App, Rgba, WindowAppearance, rgb};

use crate::config::ThemeMode;

#[derive(Clone, Copy)]
struct ThemeState {
    mode: ThemeMode,
    system_is_dark: bool,
}

static THEME_STATE: Mutex<ThemeState> = Mutex::new(ThemeState {
    mode: ThemeMode::Dark,
    system_is_dark: false,
});

fn state() -> std::sync::MutexGuard<'static, ThemeState> {
    THEME_STATE.lock().unwrap_or_else(|err| err.into_inner())
}

fn system_is_dark(cx: &App) -> bool {
    matches!(
        cx.window_appearance(),
        WindowAppearance::Dark | WindowAppearance::VibrantDark
    )
}

/// Initialize the theme from persisted configuration at startup.
pub fn init(cx: &App, mode: ThemeMode) {
    *state() = ThemeState {
        mode,
        system_is_dark: system_is_dark(cx),
    };
}

/// Apply a user-selected theme and schedule a repaint.
pub fn set_mode(cx: &mut App, mode: ThemeMode) {
    state().mode = mode;
    cx.refresh_windows();
}

/// Track OS appearance changes while `ThemeMode::System` is selected.
pub fn sync_system_appearance(cx: &mut App) {
    let dark = system_is_dark(cx);
    let changed = {
        let mut s = state();
        let changed = s.system_is_dark != dark;
        s.system_is_dark = dark;
        changed
    };
    if changed && state().mode == ThemeMode::System {
        cx.refresh_windows();
    }
}

pub fn uses_light_theme() -> bool {
    let s = state();
    match s.mode {
        ThemeMode::Light => true,
        ThemeMode::Dark => false,
        ThemeMode::System => !s.system_is_dark,
    }
}

/// Translate one of the original dark palette colours into the active theme.
pub fn themed(dark: u32) -> Rgba {
    rgb(if uses_light_theme() {
        light_color(dark)
    } else {
        dark
    })
}

/// Like [`themed`], with an explicit light colour for the few places where the
/// same dark hex is used in two contexts needing different light counterparts.
pub fn themed_pair(dark: u32, light: u32) -> Rgba {
    rgb(if uses_light_theme() { light } else { dark })
}

fn light_color(dark: u32) -> u32 {
    match dark {
        // Surfaces and borders.
        0x0b1220 => 0xf8fafc, // page background
        0x0d1526 => 0xf1f5f9, // header
        0x0f172a => 0xf1f5f9, // cards / inactive chips
        0x111827 => 0xffffff, // luvus install card
        0x111c33 => 0xe2e8f0, // nested rows
        0x131d31 => 0xe2e8f0, // window controls
        0x172554 => 0xdbeafe, // highlighted row
        0x1e293b => 0xcbd5e1, // borders
        0x334155 => 0x94a3b8, // dividers / hover
        // Accents.
        0x1d4ed8 => 0x1d4ed8, // active tab fill
        0x1e3a8a => 0xbfdbfe, // active chip fill
        0x2563eb => 0x2563eb,
        0x3b82f6 => 0x2563eb,
        0x60a5fa => 0x2563eb, // text selection
        0x059669 => 0x059669, // save button
        0x10b981 => 0x059669,
        // Status / result badges (background, then foreground).
        0x064e3b => 0xd1fae5,
        0x065f46 => 0xd1fae5,
        0x6ee7b7 => 0x065f46,
        0xa7f3d0 => 0x065f46,
        0x78350f => 0xfef3c7,
        0xfcd34d => 0x92400e,
        0xfde68a => 0x92400e,
        0x7c2d12 => 0xffedd5,
        0xfdba74 => 0x9a3412,
        0x7f1d1d => 0xfee2e2,
        0x450a0a => 0xfee2e2,
        0xfca5a5 => 0x991b1b,
        0x991b1b => 0x991b1b,
        0xb91c1c => 0xdc2626,
        0xef4444 => 0xdc2626,
        0xb45309 => 0xb45309,
        0xfacc15 => 0x92400e,
        0x93c5fd => 0x1e3a8a,
        // Text.
        0xf8fafc => 0x0f172a,
        0xf1f5f9 => 0x1e293b,
        0xe2e8f0 => 0x334155,
        0xcbd5e1 => 0x475569,
        0x94a3b8 => 0x64748b,
        0x64748b => 0x475569,
        0x475569 => 0x475569,
        0xffffff => 0xffffff,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test because the active theme is process-wide global state.
    #[test]
    fn theme_modes_resolve_to_the_expected_palette() {
        let original = *state();
        {
            let mut s = state();
            s.mode = ThemeMode::Light;
        }
        assert!(uses_light_theme());
        assert_eq!(light_color(0x0b1220), 0xf8fafc);
        assert_eq!(light_color(0xf8fafc), 0x0f172a);

        {
            let mut s = state();
            s.mode = ThemeMode::System;
            s.system_is_dark = true;
        }
        assert!(!uses_light_theme());
        {
            let mut s = state();
            s.system_is_dark = false;
        }
        assert!(uses_light_theme());

        *state() = original;
    }
}
