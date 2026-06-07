/// Sliding-window rate limiter per source IP.
/// Uses DashMap for lock-free concurrent access across Tokio tasks.
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use super::Hit;
use crate::config::RateLimitConfig;

const SCORE: u32 = 50;

static SENSITIVE_PATHS: &[&str] = &[
    "/login", "/admin", "/wp-login", "/signin",
    "/auth", "/password", "/register", "/api/auth",
];

pub struct RateLimiter {
    /// ip → Vec of request timestamps within the current window
    timestamps: Arc<DashMap<String, Vec<Instant>>>,
    /// ip → ban expiry
    bans: Arc<DashMap<String, Instant>>,
    cfg: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            timestamps: Arc::new(DashMap::new()),
            bans: Arc::new(DashMap::new()),
            cfg,
        }
    }

    fn is_sensitive(path: &str) -> bool {
        let lower = path.to_lowercase();
        SENSITIVE_PATHS.iter().any(|p| lower.starts_with(p))
    }

    /// Returns Some(Hit) if the request should be blocked, None otherwise.
    pub fn check(&self, ip: &str, path: &str) -> Option<Hit> {
        let now = Instant::now();

        // Check existing ban
        if let Some(expiry) = self.bans.get(ip) {
            if now < *expiry {
                return Some(Hit {
                    rule_id:     "RATE-002",
                    description: "IP is temporarily banned (rate limit)",
                    category:    "ratelimit",
                    score:       SCORE,
                });
            } else {
                drop(expiry);
                self.bans.remove(ip);
            }
        }

        let window = Duration::from_secs(self.cfg.window_seconds);
        let limit = if Self::is_sensitive(path) {
            self.cfg.sensitive_max
        } else {
            self.cfg.max_requests
        };

        // Prune old timestamps and count
        let mut entry = self.timestamps.entry(ip.to_string()).or_default();
        entry.retain(|&t| now.duration_since(t) < window);
        entry.push(now);
        let count = entry.len() as u32;
        drop(entry);

        if count > limit {
            let ban_expiry = now + Duration::from_secs(self.cfg.ban_duration_secs);
            self.bans.insert(ip.to_string(), ban_expiry);
            return Some(Hit {
                rule_id:     "RATE-001",
                description: "Rate limit exceeded – IP banned",
                category:    "ratelimit",
                score:       SCORE,
            });
        }
        None
    }
}
