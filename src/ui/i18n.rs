use chrono::{DateTime, Local, Utc};

use crate::config::UiLanguage;

pub fn tr(lang: UiLanguage, zh: &'static str, en: &'static str) -> &'static str {
    match lang {
        UiLanguage::Zh => zh,
        UiLanguage::En => en,
    }
}

pub fn pretty_time(ts: DateTime<Utc>, now: DateTime<Utc>, lang: UiLanguage) -> String {
    let secs = (now - ts).num_seconds().max(0);
    match lang {
        UiLanguage::Zh => {
            if secs < 5 {
                "刚刚".to_string()
            } else if secs < 60 {
                format!("{secs}秒前")
            } else if secs < 3600 {
                format!("{}分钟前", secs / 60)
            } else if secs < 86400 {
                format!("{}小时前", secs / 3600)
            } else if secs < 86400 * 7 {
                format!("{}天前", secs / 86400)
            } else {
                ts.with_timezone(&Local).format("%m-%d %H:%M").to_string()
            }
        }
        UiLanguage::En => {
            if secs < 5 {
                "just now".to_string()
            } else if secs < 60 {
                format!("{secs}s ago")
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else if secs < 86400 {
                format!("{}h ago", secs / 3600)
            } else if secs < 86400 * 7 {
                format!("{}d ago", secs / 86400)
            } else {
                ts.with_timezone(&Local).format("%m-%d %H:%M").to_string()
            }
        }
    }
}

pub fn pretty_time_with_clock(ts: DateTime<Utc>, now: DateTime<Utc>, lang: UiLanguage) -> String {
    let rel = pretty_time(ts, now, lang);
    let clock = ts.with_timezone(&Local).format("%H:%M:%S");
    format!("{rel} ({clock})")
}
