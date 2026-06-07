/// Async reverse proxy – axum handler + hyper upstream client.
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use std::sync::Arc;
use std::time::Instant;

use crate::challenge;
use crate::engine::{Action, Engine, RequestContext};
use crate::engine::response as dlp;
use crate::logger::WafLogger;
use crate::notifiers::NotifierManager;

const BLOCK_BODY: &str = r#"<!DOCTYPE html>
<html><head><title>403 – Blocked by Dome WAF</title></head>
<body style="font-family:sans-serif;text-align:center;padding:60px">
  <h1>🛡️ Request Blocked</h1>
  <p>This request was blocked by <strong>Dome WAF</strong>.</p>
</body></html>"#;

/// Hop-by-hop headers that must NOT be forwarded
static HOP_HEADERS: &[&str] = &[
    "connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "proxy-connection", "proxy-authenticate",
    "proxy-authorization",
];

fn is_hop(name: &str) -> bool {
    HOP_HEADERS.contains(&name)
}

pub struct AppState {
    pub engine:          Arc<Engine>,
    pub logger:          Arc<WafLogger>,
    pub notifiers:       Arc<NotifierManager>,
    pub upstream:        String,
    pub body_limit:      usize,
    pub challenge_enabled: bool,
    pub dlp_enabled:     bool,
    pub hyper:           HyperClient<HttpConnector, Full<Bytes>>,
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response<Body> {
    let start = Instant::now();

    // ── Client IP ─────────────────────────────────────────────────────────
    let client_ip = req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or("unknown")
        .to_string();

    let method = req.method().as_str().to_string();
    let path   = req.uri().path().to_string();
    let query  = req.uri().query().unwrap_or("").to_string();

    // Check PoW token if challenge is enabled
    if state.challenge_enabled {
        if let Some(tok) = req.uri().query()
            .and_then(|q| form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "_dome_tok")
                .map(|(_, v)| v.into_owned()))
        {
            let challenge_id = format!("dome-{}", &client_ip);
            if challenge::verify_token(&tok, &challenge_id) {
                // Token valid – strip it and forward
                return forward(&state, req, &client_ip, &method, &path, &query, start, 0, &[]).await;
            }
        }
    }

    // ── Read body (limited) ───────────────────────────────────────────────
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, state.body_limit).await {
        Ok(b)  => b,
        Err(_) => Bytes::new(),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

    let ctx = RequestContext {
        method:    &method,
        path:      &path,
        query:     &query,
        headers:   &parts.headers,
        body:      &body_str,
        client_ip: &client_ip,
    };

    let result = state.engine.inspect(&ctx);

    match result.action {
        Action::Allow => {
            let req2 = Request::from_parts(parts, Body::from(body_bytes));
            forward(&state, req2, &client_ip, &method, &path, &query, start, 0, &[]).await
        }

        Action::Log => {
            // Log the hits but forward anyway
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            state.logger.log("LOG", &client_ip, &method, &path, 0, elapsed, result.total_score, &result.hits);
            state.notifiers.dispatch("LOG", &client_ip, &method, &path, 0, result.total_score, &result.hits);
            let req2 = Request::from_parts(parts, Body::from(body_bytes));
            forward(&state, req2, &client_ip, &method, &path, &query, start, result.total_score, &result.hits).await
        }

        Action::Challenge => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            state.logger.log("CHALLENGE", &client_ip, &method, &path, 200, elapsed, result.total_score, &result.hits);
            state.notifiers.dispatch("CHALLENGE", &client_ip, &method, &path, 200, result.total_score, &result.hits);
            let challenge_id = format!("dome-{}", &client_ip);
            let return_url   = format!("{path}?{query}");
            let chal = challenge::challenge_response(&challenge_id, &return_url);
            // Convert Response<String> to Response<Body>
            let (p, b) = chal.into_parts();
            Response::from_parts(p, Body::from(b))
        }

        Action::Block => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            state.logger.log("BLOCK", &client_ip, &method, &path, 403, elapsed, result.total_score, &result.hits);
            state.notifiers.dispatch("BLOCK", &client_ip, &method, &path, 403, result.total_score, &result.hits);

            let rule_ids: String = result.hits.iter().map(|h| h.rule_id).collect::<Vec<_>>().join(",");
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "text/html; charset=utf-8")
                .header("x-dome-action", "BLOCK")
                .header("x-dome-rules", rule_ids)
                .body(Body::from(BLOCK_BODY))
                .unwrap()
        }
    }
}

async fn forward(
    state: &AppState,
    req: Request<Body>,
    client_ip: &str,
    method: &str,
    path: &str,
    _query: &str,
    start: Instant,
    score: u32,
    hits: &[crate::engine::Hit],
) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, state.body_limit).await.unwrap_or_default();

    let upstream_uri = format!(
        "{}{}{}",
        state.upstream.trim_end_matches('/'),
        parts.uri.path(),
        parts.uri.query().map(|q| format!("?{q}")).unwrap_or_default(),
    );

    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(&upstream_uri);

    // Forward headers, strip hop-by-hop
    for (k, v) in parts.headers.iter() {
        if !is_hop(k.as_str()) {
            builder = builder.header(k, v);
        }
    }
    builder = builder
        .header("x-forwarded-for", client_ip)
        .header("x-forwarded-proto", "http");

    let upstream_req = match builder.body(Full::new(body_bytes)) {
        Ok(r)  => r,
        Err(e) => {
            tracing::error!("Build upstream request: {e}");
            return Response::builder().status(500).body(Body::empty()).unwrap();
        }
    };

    match state.hyper.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            if !hits.is_empty() {
                state.logger.log("LOG", client_ip, method, path,
                    status.as_u16(), elapsed, score, hits);
            } else {
                state.logger.log("ALLOW", client_ip, method, path,
                    status.as_u16(), elapsed, 0, &[]);
            }

            let mut rb = Response::builder()
                .status(status)
                .header("x-dome-action", if hits.is_empty() { "ALLOW" } else { "LOG" });

            // Forward response headers
            for (k, v) in resp.headers().iter() {
                if !is_hop(k.as_str()) {
                    rb = rb.header(k, v);
                }
            }

            let body_bytes = resp.into_body().collect().await
                .map(|b| b.to_bytes())
                .unwrap_or_default();

            // DLP: inspect response body for leakage
            if state.dlp_enabled && !body_bytes.is_empty() {
                let body_str = String::from_utf8_lossy(&body_bytes);
                let leaks = dlp::check(&body_str, status.as_u16());
                if !leaks.is_empty() {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    let fake_hits: Vec<crate::engine::Hit> = leaks.iter().map(|l| crate::engine::Hit {
                        rule_id:     l.rule_id,
                        description: l.description,
                        category:    l.category,
                        score:       10,
                    }).collect();
                    state.logger.log("DLP", client_ip, method, path,
                        status.as_u16(), elapsed, 0, &fake_hits);
                    state.notifiers.dispatch("LOG", client_ip, method, path,
                        status.as_u16(), 0, &fake_hits);
                }
            }

            rb.body(Body::from(body_bytes)).unwrap()
        }
        Err(e) => {
            tracing::error!("Upstream error: {e}");
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            state.logger.log("ERROR", client_ip, method, path, 502, elapsed, 0, &[]);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Dome WAF: upstream unavailable – {e}")))
                .unwrap()
        }
    }
}
