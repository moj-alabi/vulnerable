/// Alert notifiers – Discord, generic webhook, syslog (RFC 5424).
/// All are fire-and-forget: spawned as Tokio tasks, never block proxy path.
use reqwest::Client;
use serde_json::{json, Value};
use std::net::UdpSocket;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use chrono::Utc;
use crate::config::NotificationsConfig;
use crate::engine::Hit;

fn action_order(a: &str) -> u8 {
    match a { "ALLOW" => 0, "LOG" => 1, "CHALLENGE" => 1, _ => 2 }
}

fn should_send(event_action: &str, min_action: &str) -> bool {
    action_order(event_action) >= action_order(min_action)
}

// ── Discord ───────────────────────────────────────────────────────────────────
pub async fn send_discord(
    client: &Client,
    webhook_url: &str,
    action: &str,
    ip: &str,
    method: &str,
    path: &str,
    hits: &[Hit],
    score: u32,
    min_action: &str,
) {
    if !should_send(action, min_action) { return; }

    let colour: u32 = match action {
        "BLOCK" => 0xE74C3C,
        "LOG" | "CHALLENGE" => 0xF39C12,
        _ => 0x2ECC71,
    };

    let hit_text: String = hits.iter().take(10)
        .map(|h| format!("• `{}` – {}", h.rule_id, h.description))
        .collect::<Vec<_>>()
        .join("\n");
    let hit_text = if hit_text.is_empty() { "_no hits_".into() } else { hit_text };

    let cats: Vec<&str> = {
        let mut seen = std::collections::HashSet::new();
        hits.iter().filter(|h| seen.insert(h.category)).map(|h| h.category).collect()
    };
    let cats_str = if cats.is_empty() {
        "_none_".into()
    } else {
        cats.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")
    };

    let payload = json!({
        "username": "Dome WAF",
        "embeds": [{
            "title": format!("🛡️ Dome WAF — {action}"),
            "color": colour,
            "timestamp": Utc::now().to_rfc3339(),
            "fields": [
                { "name": "Action",     "value": format!("`{action}`"), "inline": true  },
                { "name": "Client IP",  "value": format!("`{ip}`"),     "inline": true  },
                { "name": "Request",    "value": format!("`{method} {path}`"), "inline": false },
                { "name": "Score",      "value": format!("{score} pts"), "inline": true },
                { "name": "Rules Hit",  "value": hit_text,              "inline": false },
                { "name": "Categories", "value": cats_str,              "inline": true  },
            ],
            "footer": { "text": "Dome WAF" }
        }]
    });

    if let Err(e) = client.post(webhook_url).json(&payload).send().await {
        tracing::warn!("Discord webhook error: {e}");
    }
}

// ── Generic HTTP webhook ──────────────────────────────────────────────────────
pub async fn send_webhook(
    client: &Client,
    url: &str,
    extra_headers: &std::collections::HashMap<String, String>,
    event: &Value,
    min_action: &str,
) {
    let action = event["action"].as_str().unwrap_or("");
    if !should_send(action, min_action) { return; }

    let mut req = client.post(url).json(event);
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Err(e) = req.send().await {
        tracing::warn!("Webhook error ({url}): {e}");
    }
}

// ── Syslog UDP ────────────────────────────────────────────────────────────────
pub fn send_syslog_udp(
    host: &str,
    port: u16,
    action: &str,
    ip: &str,
    method: &str,
    path: &str,
    hits: &[Hit],
    min_action: &str,
) {
    if !should_send(action, min_action) { return; }

    let severity: u8 = match action { "BLOCK" => 2, "LOG" => 4, _ => 6 };
    let facility: u8 = 16; // local0
    let priority = facility * 8 + severity;
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".into());
    let rules: String = hits.iter().map(|h| h.rule_id).collect::<Vec<_>>().join(",");
    let msg = format!(
        "<{priority}>1 {ts} {hostname} dome-waf - {action} - action={action} ip={ip} method={method} path={path} rules={rules}"
    );

    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let addr = format!("{host}:{port}");
            if let Err(e) = sock.send_to(msg.as_bytes(), &addr) {
                tracing::warn!("Syslog UDP send error: {e}");
            }
        }
        Err(e) => tracing::warn!("Syslog UDP bind error: {e}"),
    }
}

// ── Syslog TCP ────────────────────────────────────────────────────────────────
pub async fn send_syslog_tcp(
    host: &str,
    port: u16,
    action: &str,
    ip: &str,
    method: &str,
    path: &str,
    hits: &[Hit],
    min_action: &str,
) {
    if !should_send(action, min_action) { return; }

    let severity: u8 = match action { "BLOCK" => 2, "LOG" => 4, _ => 6 };
    let priority = 16u8 * 8 + severity;
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".into());
    let rules: String = hits.iter().map(|h| h.rule_id).collect::<Vec<_>>().join(",");
    let msg = format!(
        "<{priority}>1 {ts} {hostname} dome-waf - {action} - action={action} ip={ip} method={method} path={path} rules={rules}\n"
    );

    let addr = format!("{host}:{port}");
    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(mut stream)) => {
            let _ = stream.write_all(msg.as_bytes()).await;
        }
        Ok(Err(e)) => tracing::warn!("Syslog TCP connect error ({addr}): {e}"),
        Err(_)     => tracing::warn!("Syslog TCP timeout ({addr})"),
    }
}

// ── Manager ───────────────────────────────────────────────────────────────────
pub struct NotifierManager {
    cfg:    NotificationsConfig,
    client: Client,
}

impl NotifierManager {
    pub fn new(cfg: NotificationsConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self { cfg, client }
    }

    pub fn dispatch(
        &self,
        action: &str,
        ip: &str,
        method: &str,
        path: &str,
        status: u16,
        score: u32,
        hits: &[Hit],
    ) {
        let cfg    = self.cfg.clone();
        let client = self.client.clone();
        let action = action.to_string();
        let ip     = ip.to_string();
        let method = method.to_string();
        let path   = path.to_string();
        let hits_owned: Vec<Hit> = hits.to_vec();

        tokio::spawn(async move {
            // Discord
            if let Some(ref url) = cfg.discord_webhook {
                send_discord(
                    &client, url, &action, &ip, &method, &path,
                    &hits_owned, score, &cfg.discord_min_action,
                ).await;
            }

            // Generic webhook
            if let Some(ref url) = cfg.webhook_url {
                let cats: Vec<_> = {
                    let mut seen = std::collections::HashSet::new();
                    hits_owned.iter().filter(|h| seen.insert(h.category)).map(|h| h.category).collect()
                };
                let event = json!({
                    "product": "dome-waf",
                    "action": action,
                    "client_ip": ip,
                    "method": method,
                    "path": path,
                    "status_code": status,
                    "score": score,
                    "categories": cats,
                    "hits": hits_owned.iter().map(|h| json!({
                        "rule_id": h.rule_id,
                        "description": h.description,
                        "category": h.category,
                        "score": h.score,
                    })).collect::<Vec<_>>(),
                });
                send_webhook(&client, url, &cfg.webhook_headers, &event, &cfg.webhook_min_action).await;
            }

            // Syslog
            if cfg.syslog.enabled {
                if cfg.syslog.proto.to_lowercase() == "tcp" {
                    send_syslog_tcp(
                        &cfg.syslog.host, cfg.syslog.port,
                        &action, &ip, &method, &path,
                        &hits_owned, &cfg.syslog.min_action,
                    ).await;
                } else {
                    send_syslog_udp(
                        &cfg.syslog.host, cfg.syslog.port,
                        &action, &ip, &method, &path,
                        &hits_owned, &cfg.syslog.min_action,
                    );
                }
            }
        });
    }
}
