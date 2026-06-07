/// Anomaly / entropy scoring.
///
/// Flags requests that look statistically abnormal regardless of specific attack patterns:
///   - Very long individual parameter values
///   - High Shannon entropy (dense encoding / shellcode)
///   - Excessive number of parameters
///   - Suspicious Content-Type mismatches
///   - Non-printable / null bytes in parameters

use super::Hit;
use axum::http::HeaderMap;

const SCORE_LONG_PARAM: u32 = 15;
const SCORE_HIGH_ENTROPY: u32 = 20;
const SCORE_EXCESS_PARAMS: u32 = 10;
const SCORE_NULL_BYTE: u32 = 25;
const SCORE_CT_MISMATCH: u32 = 10;

/// Shannon entropy in bits per byte (0.0 – 8.0)
fn entropy(s: &str) -> f64 {
    if s.len() < 8 { return 0.0; }
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn check(
    path: &str,
    query: &str,
    body: &str,
    headers: &HeaderMap,
) -> Vec<Hit> {
    let mut hits = Vec::new();

    // ── Null bytes ────────────────────────────────────────────────────────
    for input in &[path, query, body] {
        if input.contains('\x00') || input.contains("%00") {
            hits.push(Hit {
                rule_id:     "ANOM-001",
                description: "Null byte in request data",
                category:    "anomaly",
                score:       SCORE_NULL_BYTE,
            });
            break;
        }
    }

    // ── Excessive parameter count ─────────────────────────────────────────
    let param_count = form_urlencoded::parse(query.as_bytes()).count()
        + form_urlencoded::parse(body.as_bytes()).count();
    if param_count > 100 {
        hits.push(Hit {
            rule_id:     "ANOM-002",
            description: "Excessive number of parameters (>100)",
            category:    "anomaly",
            score:       SCORE_EXCESS_PARAMS,
        });
    }

    // ── Very long parameter values ────────────────────────────────────────
    let mut long_hit = false;
    for (_, v) in form_urlencoded::parse(query.as_bytes())
        .chain(form_urlencoded::parse(body.as_bytes()))
    {
        if v.len() > 8192 && !long_hit {
            hits.push(Hit {
                rule_id:     "ANOM-003",
                description: "Parameter value exceeds 8 KB",
                category:    "anomaly",
                score:       SCORE_LONG_PARAM,
            });
            long_hit = true;
        }
        // High-entropy check per value (>6.5 bits/byte = likely base64/binary)
        if v.len() > 64 && entropy(&v) > 6.5 {
            hits.push(Hit {
                rule_id:     "ANOM-004",
                description: "High-entropy parameter value (possible encoded payload)",
                category:    "anomaly",
                score:       SCORE_HIGH_ENTROPY,
            });
            break; // one hit per request is enough
        }
    }

    // ── Path length ───────────────────────────────────────────────────────
    if path.len() > 1024 {
        hits.push(Hit {
            rule_id:     "ANOM-005",
            description: "Abnormally long URL path (>1 KB)",
            category:    "anomaly",
            score:       SCORE_LONG_PARAM,
        });
    }

    // ── Content-Type vs body mismatch ─────────────────────────────────────
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        let ct_lower = ct.to_lowercase();
        let is_json_ct = ct_lower.contains("application/json");
        let is_xml_ct  = ct_lower.contains("xml");
        let body_trim  = body.trim_start();

        if is_json_ct && !body_trim.starts_with('{') && !body_trim.starts_with('[') && !body.is_empty() {
            hits.push(Hit {
                rule_id:     "ANOM-006",
                description: "Content-Type is JSON but body does not look like JSON",
                category:    "anomaly",
                score:       SCORE_CT_MISMATCH,
            });
        }
        if is_xml_ct && !body_trim.starts_with('<') && !body.is_empty() {
            hits.push(Hit {
                rule_id:     "ANOM-007",
                description: "Content-Type is XML but body does not start with <",
                category:    "anomaly",
                score:       SCORE_CT_MISMATCH,
            });
        }
    }

    hits
}
