use serde::Deserialize;
use std::collections::HashMap;
use crate::engine::vpatch::VPatchRule;
use crate::engine::session::SessionConfig;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub waf: WafConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

// ── Proxy ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    pub upstream: String,
    #[serde(default = "default_timeout")]
    pub upstream_timeout_secs: u64,
    /// Maximum request body size in bytes before truncation (default 1 MB)
    #[serde(default = "default_body_limit")]
    pub body_limit_bytes: usize,
}

fn default_listen_host() -> String { "0.0.0.0".into() }
fn default_listen_port() -> u16    { 8888 }
fn default_timeout()    -> u64     { 30 }
fn default_body_limit() -> usize   { 1_048_576 }

// ── WAF engine ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    /// block | detect
    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub blocked_paths: Vec<String>,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// JA3 hashes to block (supplements built-in list)
    #[serde(default)]
    pub blocked_ja3: Vec<String>,
    #[serde(default)]
    pub blocked_ja4_prefixes: Vec<String>,

    /// IP reputation: auto-ban after this many rule hits from same IP
    #[serde(default = "default_rep_threshold")]
    pub reputation_threshold: u32,
    /// How long (seconds) a reputation-banned IP stays banned
    #[serde(default = "default_rep_ban_secs")]
    pub reputation_ban_secs: u64,

    /// Enable JS challenge page (browser verification before allowing)
    #[serde(default)]
    pub challenge_enabled: bool,
    /// Rule categories that trigger a challenge instead of hard block
    /// e.g. ["scanner", "ratelimit"]
    #[serde(default)]
    pub challenge_categories: Vec<String>,

    /// Minimum threat score to block (0-100).  Each rule hit adds points.
    #[serde(default = "default_score_threshold")]
    pub score_threshold: u32,

    /// Block TRACE/TRACK/CONNECT always; also block non-standard methods when true
    #[serde(default)]
    pub enforce_http_methods: bool,

    /// Inspect response bodies for data leakage (DLP)
    #[serde(default)]
    pub dlp_enabled: bool,

    /// Virtual patch rules (custom per-path/method/param rules)
    #[serde(default)]
    pub virtual_patches: Vec<VPatchRule>,

    /// CRS-equivalent paranoia level 1-4 (1 = low FP, 4 = maximum detection)
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,

    /// Per-IP session score accumulation config
    #[serde(default)]
    pub session: SessionConfig,
}

fn default_paranoia() -> u8 { 1 }

// ── Admin dashboard ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// Enable the admin dashboard
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_host")]
    pub listen_host: String,
    #[serde(default = "default_admin_port")]
    pub listen_port: u16,
}

fn default_admin_host() -> String { "127.0.0.1".into() }
fn default_admin_port() -> u16    { 9000 }

impl Default for AdminConfig {
    fn default() -> Self {
        Self { enabled: false, listen_host: default_admin_host(), listen_port: default_admin_port() }
    }
}

fn default_mode()            -> String { "block".into() }
fn default_rep_threshold()   -> u32    { 10 }
fn default_rep_ban_secs()    -> u64    { 3600 }
fn default_score_threshold() -> u32    { 30 }

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    #[serde(default = "default_max_req")]
    pub max_requests: u32,
    #[serde(default = "default_sensitive_max")]
    pub sensitive_max: u32,
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
}

fn default_window()       -> u64 { 60 }
fn default_max_req()      -> u32 { 200 }
fn default_sensitive_max()-> u32 { 20 }
fn default_ban_duration() -> u64 { 300 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_seconds:  default_window(),
            max_requests:    default_max_req(),
            sensitive_max:   default_sensitive_max(),
            ban_duration_secs: default_ban_duration(),
        }
    }
}

// ── Notifications ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotificationsConfig {
    pub discord_webhook:   Option<String>,
    #[serde(default = "default_min_action")]
    pub discord_min_action: String,

    pub webhook_url:       Option<String>,
    #[serde(default)]
    pub webhook_headers:   HashMap<String, String>,
    #[serde(default = "default_min_action")]
    pub webhook_min_action: String,

    #[serde(default)]
    pub syslog: SyslogConfig,
}

fn default_min_action() -> String { "BLOCK".into() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SyslogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_syslog_host")]
    pub host: String,
    #[serde(default = "default_syslog_port")]
    pub port: u16,
    #[serde(default = "default_syslog_proto")]
    pub proto: String,
    #[serde(default = "default_min_action")]
    pub min_action: String,
}

fn default_syslog_host()  -> String { "127.0.0.1".into() }
fn default_syslog_port()  -> u16    { 514 }
fn default_syslog_proto() -> String { "udp".into() }

// ── Logging ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_path")]
    pub path: String,
    #[serde(default = "default_log_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_backup_count")]
    pub backup_count: u32,
}

fn default_log_path()      -> String { "/var/log/dome/waf.log".into() }
fn default_log_max_bytes() -> u64    { 10_485_760 }
fn default_backup_count()  -> u32    { 5 }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            path: default_log_path(),
            max_bytes: default_log_max_bytes(),
            backup_count: default_backup_count(),
        }
    }
}

// ── Load ─────────────────────────────────────────────────────────────────────

pub fn load(path: &str) -> anyhow::Result<Config> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read config {path}: {e}"))?;
    let cfg: Config = serde_yaml::from_str(&data)
        .map_err(|e| anyhow::anyhow!("Config parse error: {e}"))?;
    Ok(cfg)
}
