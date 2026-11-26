use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::{DateTime, Duration, Local, Utc};
use serde::{Deserialize, Serialize};

static NEXT_AUDIT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Skipped,
    DryRun,
}

impl AuditResult {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
            Self::DryRun => "dry-run",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Cooldown,
    Dedupe,
    Guard,
    Paused,
    MaxContinuous,
    NonRetryable,
    Retrying,
    NoMatch,
    NotWhitelisted,
    DryRunRule,
}

impl SkipReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cooldown => "cooldown",
            Self::Dedupe => "dedupe",
            Self::Guard => "guard",
            Self::Paused => "paused",
            Self::MaxContinuous => "maxContinuous",
            Self::NonRetryable => "non-retryable",
            Self::Retrying => "retrying",
            Self::NoMatch => "no-match",
            Self::NotWhitelisted => "not-whitelisted",
            Self::DryRunRule => "dry-run-rule",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub pane: String,
    pub agent: String,
    pub status: String,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub match_summary: String,
    pub signature: Option<String>,
    pub action_summary: String,
    pub result: AuditResult,
    pub skip_reason: Option<SkipReason>,
    pub dry_run: bool,
    pub detail: String,
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pane: impl Into<String>,
        agent: impl Into<String>,
        status: impl Into<String>,
        rule_id: Option<String>,
        rule_name: Option<String>,
        match_summary: impl Into<String>,
        signature: Option<String>,
        action_summary: impl Into<String>,
        result: AuditResult,
        skip_reason: Option<SkipReason>,
        dry_run: bool,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: NEXT_AUDIT_ID.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            pane: pane.into(),
            agent: agent.into(),
            status: status.into(),
            rule_id,
            rule_name,
            match_summary: match_summary.into(),
            signature,
            action_summary: action_summary.into(),
            result,
            skip_reason,
            dry_run,
            detail: detail.into(),
        }
    }

    pub fn local_time_str(&self) -> String {
        self.timestamp
            .with_timezone(&Local)
            .format("%m-%d %H:%M:%S")
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    path: PathBuf,
    records: Arc<Vec<AuditRecord>>,
    max_in_memory: usize,
}

impl AuditStore {
    pub fn load(path: PathBuf, retention_days: u32) -> Self {
        let mut records = Vec::new();
        if let Ok(file) = fs::File::open(&path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<AuditRecord>(trimmed) {
                    NEXT_AUDIT_ID.fetch_max(rec.id + 1, Ordering::Relaxed);
                    records.push(rec);
                }
            }
        }
        let mut store = Self {
            path,
            records: Arc::new(records),
            max_in_memory: 2000,
        };
        if retention_days > 0 {
            let _ = store.prune_older_than(retention_days);
        }
        if store.records.len() > store.max_in_memory {
            let drain = store.records.len() - store.max_in_memory;
            Arc::make_mut(&mut store.records).drain(0..drain);
        }
        store
    }

    pub fn append(&mut self, mut record: AuditRecord, redact_summary: bool) -> Result<()> {
        if redact_summary {
            record.match_summary = "[redacted]".to_string();
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(&record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        let vec = Arc::make_mut(&mut self.records);
        vec.push(record);
        if vec.len() > self.max_in_memory {
            let drain = vec.len() - self.max_in_memory;
            vec.drain(0..drain);
        }
        Ok(())
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Cheap O(1) handle for UI snapshots without deep-cloning up to 2000 audit records.
    pub fn records_arc(&self) -> Arc<Vec<AuditRecord>> {
        Arc::clone(&self.records)
    }

    pub fn prune_older_than(&mut self, days: u32) -> Result<usize> {
        let cutoff = Utc::now() - Duration::days(days as i64);
        let vec = Arc::make_mut(&mut self.records);
        let before = vec.len();
        vec.retain(|r| r.timestamp >= cutoff);
        let removed = before.saturating_sub(vec.len());
        if removed > 0 && self.path.exists() {
            let mut out = String::new();
            for r in vec.iter() {
                out.push_str(&serde_json::to_string(r)?);
                out.push('\n');
            }
            fs::write(&self.path, out)?;
        }
        Ok(removed)
    }

    pub fn clear(&mut self) -> Result<()> {
        Arc::make_mut(&mut self.records).clear();
        if self.path.exists() {
            fs::write(&self.path, "")?;
        }
        Ok(())
    }
}
