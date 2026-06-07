/// JS Proof-of-Work challenge page (SafeLine-style browser verification).
///
/// When triggered, returns an HTML page with a JS challenge.
/// The browser must solve a simple hashcash-style PoW and redirect
/// back to the original URL with a token.  Dome verifies the token
/// before allowing through.
///
/// This is a lightweight alternative to a hard 403 – it filters
/// bots and automated scanners that can't execute JavaScript.

use axum::response::{Html, Response};
use axum::http::StatusCode;

const CHALLENGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Check – Dome WAF</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a; color: #e2e8f0;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #1e293b; border: 1px solid #334155;
      border-radius: 12px; padding: 40px; max-width: 440px;
      text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,.5);
    }
    .shield { font-size: 3rem; margin-bottom: 16px; }
    h1 { font-size: 1.4rem; margin-bottom: 8px; }
    p  { color: #94a3b8; font-size: .9rem; margin-bottom: 24px; line-height: 1.6; }
    .spinner {
      width: 40px; height: 40px; border: 3px solid #334155;
      border-top-color: #3b82f6; border-radius: 50%;
      animation: spin 0.8s linear infinite; margin: 0 auto 16px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .status { font-size: .85rem; color: #64748b; }
  </style>
</head>
<body>
  <div class="card">
    <div class="shield">🛡️</div>
    <h1>Security Verification</h1>
    <p>Dome WAF is verifying your browser.<br>This usually takes less than a second.</p>
    <div class="spinner" id="spinner"></div>
    <div class="status" id="status">Running security checks…</div>
  </div>

  <script>
  (function() {
    'use strict';
    // ── Hashcash-style PoW ────────────────────────────────────────────────
    // Find a nonce N such that SHA-256(challenge + N) starts with DIFFICULTY zero bits.
    const DIFFICULTY = 20; // bits (adjustable – 20 ≈ ~1M hashes, <100ms on modern HW)

    async function sha256hex(msg) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    function leadingZeroBits(hex) {
      let bits = 0;
      for (const c of hex) {
        const n = parseInt(c, 16);
        if (n === 0) { bits += 4; continue; }
        bits += Math.clz32(n) - 28;
        break;
      }
      return bits;
    }

    async function solve(challenge) {
      let nonce = 0;
      while (true) {
        const candidate = challenge + ':' + nonce;
        const hash = await sha256hex(candidate);
        if (leadingZeroBits(hash) >= DIFFICULTY) {
          return { nonce, hash };
        }
        nonce++;
        // Yield every 5000 iterations so the page stays responsive
        if (nonce % 5000 === 0) await new Promise(r => setTimeout(r, 0));
      }
    }

    async function run() {
      const challenge = '__DOME_CHALLENGE__';
      const returnUrl = '__DOME_RETURN_URL__';

      document.getElementById('status').textContent = 'Solving challenge…';
      const { nonce, hash } = await solve(challenge);
      document.getElementById('spinner').style.borderTopColor = '#22c55e';
      document.getElementById('status').textContent = 'Verified! Redirecting…';

      // Submit solution back to Dome via redirect with token in query
      const token = btoa(JSON.stringify({ c: challenge, n: nonce, h: hash }));
      const sep = returnUrl.includes('?') ? '&' : '?';
      window.location.replace(returnUrl + sep + '_dome_tok=' + encodeURIComponent(token));
    }

    run().catch(err => {
      document.getElementById('status').textContent = 'Error: ' + err.message;
    });
  })();
  </script>
</body>
</html>"#;

/// Build a 200 challenge response for a given request path.
pub fn challenge_response(challenge_id: &str, return_url: &str) -> Response<String> {
    let body = CHALLENGE_HTML
        .replace("__DOME_CHALLENGE__", challenge_id)
        .replace("__DOME_RETURN_URL__", return_url);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store, no-cache")
        .header("x-dome-action", "CHALLENGE")
        .body(body)
        .unwrap()
}

/// Verify a submitted PoW token.
/// Returns true if the solution is valid and meets DIFFICULTY.
pub fn verify_token(token: &str, expected_challenge: &str) -> bool {
    use base64::Engine as _;
    let decoded = match base64::engine::general_purpose::STANDARD.decode(token) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&decoded) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = parsed["c"].as_str().unwrap_or("");
    let n = parsed["n"].as_u64().unwrap_or(u64::MAX);
    let h = parsed["h"].as_str().unwrap_or("");

    if c != expected_challenge { return false; }

    // Re-verify hash
    use sha2::{Sha256, Digest};
    let input = format!("{c}:{n}");
    let hash = Sha256::digest(input.as_bytes());
    let hash_hex = hex::encode(hash);

    if hash_hex != h { return false; }

    // Check difficulty (20 bits = 5 leading hex zeros)
    let leading_zeros = hash_hex.chars().take_while(|&c| c == '0').count();
    leading_zeros >= 5
}
