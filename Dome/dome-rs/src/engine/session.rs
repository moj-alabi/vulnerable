/// Per-IP session threat score accumulation.
///
/// ModSecurity + CRS tracks anomaly scores across a single transaction (request).
/// This module goes further: it accumulates scores **across multiple requests**
/// from the same IP within a sliding time window, enabling detection of
/// slow/distributed attacks that stay below per-request thresholds.
///
/// ## Architecture
///
/// Each IP gets a `SessionState` stored in a DashMap.  On every request:
///   1. Add the request's threat score to the session's running total.
///   2. Decay old scores based on the sliding window.
///   3. Evaluate the session against escalation thresholds.
///
/// ## Escalation tiers (configurable)
///
///   score < warn_threshold   → ALLOW (normal)
///   score < challenge_threshold → LOG (suspicious, accumulating)
///   score < block_threshold  → CHALLENGE (require JS PoW)
///   score >= block_threshold → BLOCK + reputation ban
///
/// This mirrors CRS paranoia levels but at the session level.

use dashmap::DashMap;
use std::time::{Duration, Instant};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    /// Rolling window in seconds (default: 300 = 5 min)
    #[serde(default = "default_window")]
    pub window_secs: u64,
    /// Score below this → allow silently
    #[serde(default = "default_warn")]
    pub warn_threshold: u32,
    /// Score above this → challenge
    #[serde(default = "default_challenge")]
    pub challenge_threshold: u32,
    /// Score above this → block + reputation-ban
    #[serde(default = "default_block")]
    pub block_threshold: u32,
    /// Max requests per session window before flagging as scan
    #[serde(default = "default_max_req")]
    pub max_requests: u32,
}

fn default_window()    -> u64 { 300 }
fn default_warn()      -> u32 { 20 }
fn default_challenge() -> u32 { 60 }
fn default_block()     -> u32 { 120 }
fn default_max_req()   -> u32 { 500 }

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            window_secs:         default_window(),
            warn_threshold:      default_warn(),
            challenge_threshold: default_challenge(),
            block_threshold:     default_block(),
            max_requests:        default_max_req(),
        }
    }
}

/// Per-IP accumulated session state.
#[derive(Debug)]
struct SessionState {
    /// Running cumulative threat score within the window
    cumulative_score: u32,
    /// Number of requests in the current window
    request_count: u32,
    /// Distinct rule_ids fired in this session (for pattern detection)
    rule_ids: Vec<&'static str>,
    /// Start of the current window
    window_start: Instant,
}

impl SessionState {
    fn new(score: u32) -> Self {
        Self {
            cumulative_score: score,
            request_count:    1,
            rule_ids:         Vec::new(),
            window_start:     Instant::now(),
        }
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.window_start.elapsed() > window
    }
}

/// Session escalation decision.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionAction {
    /// Below warn threshold – normal
    Normal,
    /// Suspicious – log but allow
    Suspicious { cumulative: u32 },
    /// Needs browser challenge
    Challenge { cumulative: u32 },
    /// Block + ban
    Block { cumulative: u32 },
}

pub struct SessionTracker {
    map:    DashMap<String, SessionState>,
    config: SessionConfig,
    window: Duration,
}

impl SessionTracker {
    pub fn new(config: SessionConfig) -> Self {
        let window = Duration::from_secs(config.window_secs);
        Self { map: DashMap::new(), config, window }
    }

    /// Record a request's threat score for `ip` and return the session action.
    pub fn record(&self, ip: &str, request_score: u32, fired_rules: &[&'static str]) -> SessionAction {
        let mut entry = self.map.entry(ip.to_string()).or_insert_with(|| SessionState::new(0));

        // Reset window if expired
        if entry.is_expired(self.window) {
            entry.cumulative_score = 0;
            entry.request_count    = 0;
            entry.rule_ids.clear();
            entry.window_start     = Instant::now();
        }

        entry.cumulative_score += request_score;
        entry.request_count    += 1;
        for &r in fired_rules {
            if !entry.rule_ids.contains(&r) {
                entry.rule_ids.push(r);
            }
        }

        let cum = entry.cumulative_score;
        let req = entry.request_count;

        // Request flood detection (independent of score)
        if req > self.config.max_requests {
            return SessionAction::Block { cumulative: cum };
        }

        if cum >= self.config.block_threshold {
            SessionAction::Block { cumulative: cum }
        } else if cum >= self.config.challenge_threshold {
            SessionAction::Challenge { cumulative: cum }
        } else if cum >= self.config.warn_threshold {
            SessionAction::Suspicious { cumulative: cum }
        } else {
            SessionAction::Normal
        }
    }

    /// Get current session score for an IP (0 if no session or expired).
    pub fn score(&self, ip: &str) -> u32 {
        self.map.get(ip).map(|s| {
            if s.is_expired(self.window) { 0 } else { s.cumulative_score }
        }).unwrap_or(0)
    }

    /// Get number of distinct rules fired in the current session window.
    pub fn distinct_rules(&self, ip: &str) -> usize {
        self.map.get(ip).map(|s| {
            if s.is_expired(self.window) { 0 } else { s.rule_ids.len() }
        }).unwrap_or(0)
    }

    /// Purge all expired sessions (call periodically to avoid unbounded growth).
    pub fn purge_expired(&self) {
        self.map.retain(|_, v| !v.is_expired(self.window));
    }
}
