/// In-memory WAF statistics for the dashboard.
///
/// Uses atomics for lock-free counters and a Mutex-protected ring buffer
/// for the recent events feed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;

const RING_SIZE: usize = 500;

// ── Per-action counters ───────────────────────────────────────────────────────

pub struct Stats {
    pub total:     AtomicU64,
    pub allowed:   AtomicU64,
    pub blocked:   AtomicU64,
    pub logged:    AtomicU64,
    pub challenged: AtomicU64,
    pub errors:    AtomicU64,

    /// Ring buffer of recent WAF events
    ring: Mutex<RingBuffer>,

    /// Top blocked IPs (maintained as a simple sorted vec)
    top_ips: Mutex<TopIPs>,

    /// Top fired rule_ids
    top_rules: Mutex<TopRules>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total:      AtomicU64::new(0),
            allowed:    AtomicU64::new(0),
            blocked:    AtomicU64::new(0),
            logged:     AtomicU64::new(0),
            challenged: AtomicU64::new(0),
            errors:     AtomicU64::new(0),
            ring:       Mutex::new(RingBuffer::new()),
            top_ips:    Mutex::new(TopIPs::new()),
            top_rules:  Mutex::new(TopRules::new()),
        }
    }

    pub fn record(
        &self,
        action: &str,
        ip: &str,
        method: &str,
        path: &str,
        status: u16,
        score: u32,
        rule_ids: &[&str],
        elapsed_ms: f64,
    ) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match action {
            "ALLOW"     => { self.allowed.fetch_add(1, Ordering::Relaxed); }
            "BLOCK"     => { self.blocked.fetch_add(1, Ordering::Relaxed); }
            "LOG"       => { self.logged.fetch_add(1, Ordering::Relaxed); }
            "CHALLENGE" => { self.challenged.fetch_add(1, Ordering::Relaxed); }
            "ERROR"     => { self.errors.fetch_add(1, Ordering::Relaxed); }
            _           => {}
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let rules_str = rule_ids.join(",");
        let event = Event {
            ts,
            action: action.to_string(),
            ip: ip.to_string(),
            method: method.to_string(),
            path: if path.len() > 80 { format!("{}…", &path[..80]) } else { path.to_string() },
            status,
            score,
            rules: rules_str.clone(),
            elapsed_ms,
        };

        if let Ok(mut r) = self.ring.lock() {
            r.push(event);
        }

        // Track blocked/logged IPs and fired rules
        if matches!(action, "BLOCK" | "LOG" | "CHALLENGE") {
            if let Ok(mut t) = self.top_ips.lock() {
                t.record(ip);
            }
            if let Ok(mut t) = self.top_rules.lock() {
                for rid in rule_ids {
                    t.record(rid);
                }
            }
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total:      self.total.load(Ordering::Relaxed),
            allowed:    self.allowed.load(Ordering::Relaxed),
            blocked:    self.blocked.load(Ordering::Relaxed),
            logged:     self.logged.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            errors:     self.errors.load(Ordering::Relaxed),
        }
    }

    pub fn recent_events(&self, limit: usize) -> Vec<Event> {
        self.ring.lock().map(|r| r.tail(limit)).unwrap_or_default()
    }

    pub fn top_ips(&self, limit: usize) -> Vec<(String, u64)> {
        self.top_ips.lock().map(|t| t.top(limit)).unwrap_or_default()
    }

    pub fn top_rules(&self, limit: usize) -> Vec<(String, u64)> {
        self.top_rules.lock().map(|t| t.top(limit)).unwrap_or_default()
    }
}

// ── Serialisable types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total:      u64,
    pub allowed:    u64,
    pub blocked:    u64,
    pub logged:     u64,
    pub challenged: u64,
    pub errors:     u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts:         u64,
    pub action:     String,
    pub ip:         String,
    pub method:     String,
    pub path:       String,
    pub status:     u16,
    pub score:      u32,
    pub rules:      String,
    pub elapsed_ms: f64,
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

struct RingBuffer {
    buf:  Vec<Event>,
    head: usize,
    full: bool,
}

impl RingBuffer {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(RING_SIZE), head: 0, full: false }
    }

    fn push(&mut self, e: Event) {
        if self.full {
            self.buf[self.head] = e;
            self.head = (self.head + 1) % RING_SIZE;
        } else {
            self.buf.push(e);
            if self.buf.len() == RING_SIZE {
                self.full = true;
                self.head = 0;
            }
        }
    }

    /// Return up to `n` most-recent events in chronological order.
    fn tail(&self, n: usize) -> Vec<Event> {
        let len = self.buf.len();
        if len == 0 { return vec![]; }
        let n = n.min(len);
        if !self.full {
            // buf is linear, return last n
            return self.buf[len.saturating_sub(n)..].to_vec();
        }
        // Ring: head points to oldest
        let mut result = Vec::with_capacity(n);
        let start = (self.head + len - n) % len;
        for i in 0..n {
            result.push(self.buf[(start + i) % len].clone());
        }
        result
    }
}

// ── Top-N counter ─────────────────────────────────────────────────────────────

struct TopIPs {
    map: std::collections::HashMap<String, u64>,
}

impl TopIPs {
    fn new() -> Self { Self { map: std::collections::HashMap::new() } }
    fn record(&mut self, ip: &str) {
        *self.map.entry(ip.to_string()).or_insert(0) += 1;
    }
    fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<_> = self.map.iter().map(|(k,v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

struct TopRules {
    map: std::collections::HashMap<String, u64>,
}

impl TopRules {
    fn new() -> Self { Self { map: std::collections::HashMap::new() } }
    fn record(&mut self, rule: &str) {
        *self.map.entry(rule.to_string()).or_insert(0) += 1;
    }
    fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<_> = self.map.iter().map(|(k,v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}
