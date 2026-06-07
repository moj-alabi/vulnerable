/// Detection engine – orchestrates all modules.
pub mod normaliser;
pub mod sqli;
pub mod xss;
pub mod lfi;
pub mod rce;
pub mod scanner;
pub mod ratelimit;
pub mod fingerprint;
pub mod reputation;

use std::sync::Arc;
use axum::http::HeaderMap;
use serde::Serialize;

use crate::config::WafConfig;
use ratelimit::RateLimiter;
use reputation::ReputationEngine;

// ── Shared hit type used by all rule modules ──────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub rule_id:     &'static str,
    pub description: &'static str,
    pub category:    &'static str,
    pub score:       u32,
}

// ── Inspection result ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Action {
    Allow,
    Block,
    Log,        // detect mode: would block but only log
    Challenge,  // send JS proof-of-work challenge page
}

#[derive(Debug)]
pub struct InspectionResult {
    pub action:      Action,
    pub hits:        Vec<Hit>,
    pub total_score: u32,
}

impl InspectionResult {
    pub fn allow() -> Self {
        Self { action: Action::Allow, hits: vec![], total_score: 0 }
    }
    pub fn is_allow(&self) -> bool {
        matches!(self.action, Action::Allow)
    }
}

// ── Request context ───────────────────────────────────────────────────────────

pub struct RequestContext<'a> {
    pub method:       &'a str,
    pub path:         &'a str,
    pub query:        &'a str,
    pub headers:      &'a HeaderMap,
    pub body:         &'a str,
    pub client_ip:    &'a str,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct Engine {
    cfg:           WafConfig,
    rate_limiter:  Arc<RateLimiter>,
    reputation:    Arc<ReputationEngine>,
    allowed_ips:   std::collections::HashSet<String>,
    blocked_ips:   std::collections::HashSet<String>,
}

impl Engine {
    pub fn new(cfg: WafConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(cfg.rate_limit.clone()));
        let reputation   = Arc::new(ReputationEngine::new(
            cfg.reputation_threshold,
            cfg.reputation_ban_secs,
        ));
        let allowed_ips = cfg.allowed_ips.iter().cloned().collect();
        let blocked_ips = cfg.blocked_ips.iter().cloned().collect();
        Self { cfg, rate_limiter, reputation, allowed_ips, blocked_ips }
    }

    pub fn inspect(&self, ctx: &RequestContext<'_>) -> InspectionResult {
        // 1. IP allowlist – fast pass
        if self.allowed_ips.contains(ctx.client_ip) {
            return InspectionResult::allow();
        }

        // 2. Reputation ban
        if self.reputation.is_banned(ctx.client_ip) {
            return InspectionResult {
                action: Action::Block,
                hits: vec![Hit {
                    rule_id:     "REP-001",
                    description: "IP is reputation-banned",
                    category:    "reputation",
                    score:       100,
                }],
                total_score: 100,
            };
        }

        // 3. Static IP blocklist
        if self.blocked_ips.contains(ctx.client_ip) {
            return InspectionResult {
                action: Action::Block,
                hits: vec![Hit {
                    rule_id:     "IP-001",
                    description: "IP is in static blocklist",
                    category:    "ip_block",
                    score:       100,
                }],
                total_score: 100,
            };
        }

        // 4. Blocked paths
        for bp in &self.cfg.blocked_paths {
            if ctx.path.starts_with(bp.as_str()) {
                return InspectionResult {
                    action: Action::Block,
                    hits: vec![Hit {
                        rule_id:     "PATH-001",
                        description: "Blocked path prefix",
                        category:    "path_block",
                        score:       100,
                    }],
                    total_score: 100,
                };
            }
        }

        // 5. Rate limiting
        if let Some(hit) = self.rate_limiter.check(ctx.client_ip, ctx.path) {
            return InspectionResult {
                action: self.decide_action(&[&hit]),
                total_score: hit.score,
                hits: vec![hit],
            };
        }

        // 6. JA3/JA4 fingerprint
        let mut hits = fingerprint::check(
            ctx.headers,
            &self.cfg.blocked_ja3,
            &self.cfg.blocked_ja4_prefixes,
        );

        // 7. Scanner detection (UA + path)
        hits.extend(scanner::check_ua(
            ctx.headers.get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        ));
        hits.extend(scanner::check_path(ctx.path));

        // 8. Payload inspection (all inputs, normalised)
        let inputs = self.collect_inputs(ctx);
        for raw in &inputs {
            let norm = normaliser::normalise(raw);
            hits.extend(sqli::check(&norm));
            hits.extend(xss::check(&norm));
            hits.extend(lfi::check(&norm));
            hits.extend(rce::check(&norm));
        }

        if hits.is_empty() {
            return InspectionResult::allow();
        }

        // 9. Compute total threat score
        let total_score: u32 = hits.iter().map(|h| h.score).sum();

        // 10. Update reputation
        self.reputation.record(ctx.client_ip, total_score);

        // 11. Decide action
        let action = if total_score < self.cfg.score_threshold {
            // Score below threshold: log but allow through
            Action::Log
        } else {
            // Check challenge categories
            let needs_challenge = self.cfg.challenge_enabled
                && hits.iter().any(|h| self.cfg.challenge_categories.contains(&h.category.to_string()));
            if needs_challenge {
                Action::Challenge
            } else {
                self.decide_action(hits.iter().collect::<Vec<_>>().as_slice())
            }
        };

        InspectionResult { action, hits, total_score }
    }

    fn decide_action(&self, hits: &[&Hit]) -> Action {
        let _ = hits; // used for future per-category routing
        if self.cfg.mode == "detect" {
            Action::Log
        } else {
            Action::Block
        }
    }

    /// Gather all user-controlled input strings for inspection.
    fn collect_inputs<'a>(&self, ctx: &RequestContext<'a>) -> Vec<String> {
        let mut inputs = Vec::with_capacity(8);

        inputs.push(ctx.path.to_string());

        // Query string values
        for (_, v) in form_urlencoded::parse(ctx.query.as_bytes()) {
            inputs.push(v.into_owned());
        }

        // Body (form or raw)
        if !ctx.body.is_empty() {
            inputs.push(ctx.body.to_string());
            for (_, v) in form_urlencoded::parse(ctx.body.as_bytes()) {
                inputs.push(v.into_owned());
            }
        }

        // Selected headers
        for hdr in &["referer", "x-forwarded-for", "x-original-url", "user-agent"] {
            if let Some(v) = ctx.headers.get(*hdr).and_then(|v| v.to_str().ok()) {
                inputs.push(v.to_string());
            }
        }

        inputs
    }
}
