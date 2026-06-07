/// IP reputation scorer.
///
/// Tracks cumulative threat score per IP across requests.
/// When the rolling score exceeds the threshold, the IP is added to
/// a temporary ban list (SafeLine-style persistent blocking).
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct ReputationEngine {
    /// ip → (cumulative_score, last_seen)
    scores: Arc<DashMap<String, (u32, Instant)>>,
    /// ip → ban expiry
    bans: Arc<DashMap<String, Instant>>,
    threshold: u32,
    ban_duration: Duration,
    /// Score decays to 0 after this idle period
    decay_after: Duration,
}

impl ReputationEngine {
    pub fn new(threshold: u32, ban_secs: u64) -> Self {
        Self {
            scores: Arc::new(DashMap::new()),
            bans: Arc::new(DashMap::new()),
            threshold,
            ban_duration: Duration::from_secs(ban_secs),
            decay_after: Duration::from_secs(3600), // 1 hour idle resets score
        }
    }

    /// Returns true if the IP is currently reputation-banned.
    pub fn is_banned(&self, ip: &str) -> bool {
        let now = Instant::now();
        if let Some(expiry) = self.bans.get(ip) {
            if now < *expiry {
                return true;
            }
            drop(expiry);
            self.bans.remove(ip);
        }
        false
    }

    /// Record a threat score hit for the IP.
    /// Returns true if the IP has just been banned (threshold crossed).
    pub fn record(&self, ip: &str, score: u32) -> bool {
        let now = Instant::now();
        let mut entry = self.scores.entry(ip.to_string()).or_insert((0, now));
        
        // Decay if idle too long
        if now.duration_since(entry.1) > self.decay_after {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(score);
        entry.1 = now;
        let total = entry.0;
        drop(entry);

        if total >= self.threshold && !self.is_banned(ip) {
            let ban_expiry = now + self.ban_duration;
            self.bans.insert(ip.to_string(), ban_expiry);
            tracing::warn!(
                ip = %ip,
                score = total,
                threshold = self.threshold,
                "IP reputation-banned"
            );
            return true;
        }
        false
    }

    /// Get current reputation score for an IP (0 if unknown / decayed).
    pub fn score(&self, ip: &str) -> u32 {
        self.scores.get(ip).map(|e| e.0).unwrap_or(0)
    }
}
