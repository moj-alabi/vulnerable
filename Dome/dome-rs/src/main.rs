mod config;
mod engine;
mod proxy;
mod logger;
mod notifiers;
mod challenge;

use std::sync::Arc;
use axum::{Router, routing::any};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use http_body_util::Full;
use bytes::Bytes;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use proxy::AppState;
use engine::Engine;
use logger::WafLogger;
use notifiers::NotifierManager;

#[derive(Parser)]
#[command(name = "dome", about = "Dome WAF – Standalone Rust Reverse Proxy WAF")]
struct Cli {
    /// Path to config.yml
    #[arg(short, long, default_value = "config.yml")]
    config: String,

    /// Override WAF mode (block | detect)
    #[arg(long)]
    mode: Option<String>,

    /// Override upstream URL
    #[arg(long)]
    upstream: Option<String>,

    /// Override listen port
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ───────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("dome=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // ── Config ────────────────────────────────────────────────────────────
    let mut cfg = config::load(&cli.config)?;
    if let Some(mode) = cli.mode       { cfg.waf.mode = mode; }
    if let Some(url)  = cli.upstream   { cfg.proxy.upstream = url; }
    if let Some(port) = cli.port       { cfg.proxy.listen_port = port; }

    // ── Components ────────────────────────────────────────────────────────
    let engine    = Arc::new(Engine::new(cfg.waf.clone()));
    let logger    = Arc::new(WafLogger::new(&cfg.logging.path)?);
    let notifiers = Arc::new(NotifierManager::new(cfg.notifications.clone()));

    let connector = HttpConnector::new();
    let hyper     = HyperClient::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);

    let challenge_enabled = cfg.waf.challenge_enabled;
    let upstream  = cfg.proxy.upstream.trim_end_matches('/').to_string();
    let body_limit = cfg.proxy.body_limit_bytes;

    let state = Arc::new(AppState {
        engine,
        logger,
        notifiers,
        upstream: upstream.clone(),
        body_limit,
        challenge_enabled,
        hyper,
    });

    // ── Router ────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/{*path}", any(proxy::handle))
        .route("/", any(proxy::handle))
        .with_state(state);

    let addr = format!("{}:{}", cfg.proxy.listen_host, cfg.proxy.listen_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // ── Banner ────────────────────────────────────────────────────────────
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║          Dome WAF  v1.0.0  (Rust)        ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();
    println!("  Listen:    http://{addr}");
    println!("  Upstream:  {upstream}");
    println!("  Mode:      {}", cfg.waf.mode.to_uppercase());
    println!("  Challenge: {}", if challenge_enabled { "enabled" } else { "disabled" });
    println!("  Log:       {}", cfg.logging.path);
    println!();

    tracing::info!("Dome WAF listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
