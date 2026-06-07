/// Structured JSON logger – writes to rotating file + stderr (coloured).
/// Output format is compatible with Wazuh / Filebeat.
use chrono::Utc;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use crate::engine::Hit;

#[derive(Serialize)]
pub struct LogRecord<'a> {
    pub timestamp:   String,
    pub product:     &'static str,
    pub action:      &'a str,
    pub client_ip:   &'a str,
    pub method:      &'a str,
    pub path:        &'a str,
    pub status_code: u16,
    pub duration_ms: f64,
    pub total_score: u32,
    pub hit_count:   usize,
    pub categories:  Vec<&'a str>,
    pub hits:        &'a [Hit],
}

const RED:    &str = "\x1b[91m";
const YELLOW: &str = "\x1b[93m";
const GREEN:  &str = "\x1b[92m";
const RESET:  &str = "\x1b[0m";

pub struct WafLogger {
    file: Mutex<File>,
}

impl WafLogger {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    pub fn log(
        &self,
        action: &str,
        client_ip: &str,
        method: &str,
        path: &str,
        status_code: u16,
        duration_ms: f64,
        total_score: u32,
        hits: &[Hit],
    ) {
        let categories: Vec<&str> = {
            let mut seen = std::collections::HashSet::new();
            hits.iter()
                .filter(|h| seen.insert(h.category))
                .map(|h| h.category)
                .collect()
        };

        let record = LogRecord {
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            product: "dome-waf",
            action,
            client_ip,
            method,
            path,
            status_code,
            duration_ms: (duration_ms * 100.0).round() / 100.0,
            total_score,
            hit_count: hits.len(),
            categories,
            hits,
        };

        let json = match serde_json::to_string(&record) {
            Ok(j) => j,
            Err(e) => { eprintln!("Logger serialise error: {e}"); return; }
        };

        // Write to file
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{json}");
        }

        // Write coloured line to stderr
        let colour = match action {
            "BLOCK"     => RED,
            "LOG" | "CHALLENGE" => YELLOW,
            _           => GREEN,
        };
        eprintln!(
            "{colour}[{ts}] {action:9} {method:6} {path} ({score}pt) {ip}{RESET}",
            ts     = &record.timestamp[11..19],
            action = action,
            method = method,
            path   = path,
            score  = total_score,
            ip     = client_ip,
        );
    }
}
