/// Detection engine – orchestrates all modules.
pub mod normaliser;
pub mod sqli;
pub mod xss;
pub mod lfi;
pub mod rce;
pub mod ssrf;
pub mod xxe;
pub mod crlf;
pub mod scanner;
pub mod ratelimit;
pub mod fingerprint;
pub mod reputation;
pub mod anomaly;
pub mod vpatch;
pub mod response;
pub mod libinject;
pub mod crs;
pub mod session;

use std::sync::Arc;
use std::collections::HashSet;
use axum::http::HeaderMap;
use serde::Serialize;

use crate::config::WafConfig;
use ratelimit::RateLimiter;
use reputation::ReputationEngine;
use vpatch::VPatcher;
use session::{SessionTracker, SessionAction};

// ── Shared hit type ───────────────────────────────────────────────────────────

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
    Log,
    Challenge,
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
    pub method:    &'a str,
    pub path:      &'a str,
    pub query:     &'a str,
    pub headers:   &'a HeaderMap,
    pub body:      &'a str,
    pub client_ip: &'a str,
}

// ── HTTP method enforcement ───────────────────────────────────────────────────

/// Methods we flat-out refuse regardless of content
static BANNED_METHODS: &[&str] = &["TRACE", "TRACK", "CONNECT"];

/// Default allowlist (others blocked if `enforce_http_methods: true`)
static ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct Engine {
    cfg:           WafConfig,
    rate_limiter:  Arc<RateLimiter>,
    reputation:    Arc<ReputationEngine>,
    vpatcher:       Arc<VPatcher>,
    session_tracker: Arc<SessionTracker>,
    allowed_ips:   HashSet<String>,
    blocked_ips:   HashSet<String>,
}

impl Engine {
    pub fn new(cfg: WafConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(cfg.rate_limit.clone()));
        let reputation   = Arc::new(ReputationEngine::new(
            cfg.reputation_threshold,
            cfg.reputation_ban_secs,
        ));
        let vpatcher = Arc::new(VPatcher::new(&cfg.virtual_patches));
        let session_tracker = Arc::new(SessionTracker::new(cfg.session.clone()));
        let allowed_ips = cfg.allowed_ips.iter().cloned().collect();
        let blocked_ips = cfg.blocked_ips.iter().cloned().collect();
        Self { cfg, rate_limiter, reputation, vpatcher, session_tracker, allowed_ips, blocked_ips }
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
                hits: vec![Hit { rule_id: "REP-001", description: "IP is reputation-banned", category: "reputation", score: 100 }],
                total_score: 100,
            };
        }

        // 3. Static IP blocklist
        if self.blocked_ips.contains(ctx.client_ip) {
            return InspectionResult {
                action: Action::Block,
                hits: vec![Hit { rule_id: "IP-001", description: "IP is in static blocklist", category: "ip_block", score: 100 }],
                total_score: 100,
            };
        }

        // 4. HTTP method enforcement
        let method_upper = ctx.method.to_uppercase();
        if BANNED_METHODS.contains(&method_upper.as_str()) {
            return InspectionResult {
                action: Action::Block,
                hits: vec![Hit { rule_id: "HTTP-001", description: "Banned HTTP method (TRACE/TRACK/CONNECT)", category: "protocol", score: 100 }],
                total_score: 100,
            };
        }
        if self.cfg.enforce_http_methods && !ALLOWED_METHODS.contains(&method_upper.as_str()) {
            return InspectionResult {
                action: Action::Block,
                hits: vec![Hit { rule_id: "HTTP-002", description: "Non-standard HTTP method blocked", category: "protocol", score: 60 }],
                total_score: 60,
            };
        }

        // 5. Blocked paths
        for bp in &self.cfg.blocked_paths {
            if ctx.path.starts_with(bp.as_str()) {
                return InspectionResult {
                    action: Action::Block,
                    hits: vec![Hit { rule_id: "PATH-001", description: "Blocked path prefix", category: "path_block", score: 100 }],
                    total_score: 100,
                };
            }
        }

        // 6. Virtual patches (run before generic rules – highest priority)
        if let Some((vhit, action_override)) = self.vpatcher.check(
            ctx.method, ctx.path, ctx.query, ctx.headers, ctx.body,
        ) {
            let action = match action_override.as_str() {
                "allow" => Action::Allow,
                "log"   => Action::Log,
                _       => if self.cfg.mode == "detect" { Action::Log } else { Action::Block },
            };
            let score = vhit.score;
            return InspectionResult { action, hits: vec![vhit], total_score: score };
        }

        // 7. Rate limiting
        if let Some(hit) = self.rate_limiter.check(ctx.client_ip, ctx.path) {
            let score = hit.score;
            return InspectionResult {
                action: self.decide_action(&[&hit]),
                hits: vec![hit],
                total_score: score,
            };
        }

        // 8. JA3/JA4 fingerprint
        let mut hits = fingerprint::check(
            ctx.headers, &self.cfg.blocked_ja3, &self.cfg.blocked_ja4_prefixes,
        );

        // 9. Scanner detection
        hits.extend(scanner::check_ua(
            ctx.headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or(""),
        ));
        hits.extend(scanner::check_path(ctx.path));

        // 10. Anomaly scoring (before normalisation – works on raw input)
        hits.extend(anomaly::check(ctx.path, ctx.query, ctx.body, ctx.headers));

        // 11. XXE – raw body (XML check, no normalisation needed)
        hits.extend(xxe::check(ctx.body));

        // 12. Payload inspection (normalised inputs)
        let inputs = self.collect_inputs(ctx);
        for raw in &inputs {
            let norm = normaliser::normalise(raw);

            // libinjection tokeniser (primary SQLi + XSS)
            hits.extend(libinject::check(&norm));

            // CRS-equivalent ruleset (Aho-Corasick + structural regex)
            hits.extend(crs::check(&norm, self.cfg.paranoia_level));

            // Regex modules (supplementary/fallback for non-CRS categories)
            hits.extend(sqli::check(&norm));
            hits.extend(xss::check(&norm));
            hits.extend(lfi::check(&norm));
            hits.extend(rce::check(&norm));
            hits.extend(ssrf::check(&norm));
            hits.extend(crlf::check(&norm));
        }

        if hits.is_empty() {
            return InspectionResult::allow();
        }

        // 13. Compute total threat score
        let total_score: u32 = hits.iter().map(|h| h.score).sum();

        // 14. Update reputation
        self.reputation.record(ctx.client_ip, total_score);

        // 15. Session score accumulation
        let fired_rule_ids: Vec<&'static str> = hits.iter().map(|h| h.rule_id).collect();
        let session_action = self.session_tracker.record(ctx.client_ip, total_score, &fired_rule_ids);

        // If session escalates above per-request decision, use session action
        if let SessionAction::Block { cumulative } = &session_action {
            let action = if self.cfg.mode == "detect" { Action::Log } else { Action::Block };
            hits.push(Hit {
                rule_id: "SES-001",
                description: "Session cumulative score exceeded block threshold",
                category: "session",
                score: *cumulative,
            });
            return InspectionResult { action, hits, total_score: *cumulative };
        }
        if let SessionAction::Challenge { cumulative: _ } = &session_action {
            if self.cfg.challenge_enabled {
                return InspectionResult { action: Action::Challenge, hits, total_score };
            }
        }

        // 16. Decide action
        let action = if total_score < self.cfg.score_threshold {
            Action::Log
        } else {
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

    fn decide_action(&self, _hits: &[&Hit]) -> Action {
        if self.cfg.mode == "detect" { Action::Log } else { Action::Block }
    }

    fn collect_inputs<'a>(&self, ctx: &RequestContext<'a>) -> Vec<String> {
        let mut inputs = Vec::with_capacity(12);
        inputs.push(ctx.path.to_string());

        for (_, v) in form_urlencoded::parse(ctx.query.as_bytes()) {
            inputs.push(v.into_owned());
        }
        // Full query string as one unit (catches multi-param payloads)
        if !ctx.query.is_empty() {
            inputs.push(ctx.query.to_string());
        }

        if !ctx.body.is_empty() {
            inputs.push(ctx.body.to_string());
            for (_, v) in form_urlencoded::parse(ctx.body.as_bytes()) {
                inputs.push(v.into_owned());
            }
        }

        for hdr in &["referer", "x-forwarded-for", "x-original-url", "user-agent",
                     "x-http-method-override", "x-rewrite-url"] {
            if let Some(v) = ctx.headers.get(*hdr).and_then(|v| v.to_str().ok()) {
                inputs.push(v.to_string());
            }
        }

        inputs
    }
}
