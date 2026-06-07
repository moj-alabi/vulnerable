/// Virtual Patching – custom rules defined in config.yml.
///
/// Each rule specifies:
///   - path_prefix (optional)
///   - method      (optional, e.g. "POST")
///   - header      (optional, header name + regex value)
///   - param       (optional, param name + regex value)
///   - body_regex  (optional)
///   - action: "block" | "log" | "allow"  (overrides WAF mode for this rule)
///   - score: u32
///
/// Rules are evaluated in order; first matching rule wins.

use serde::Deserialize;
use regex::Regex;
use axum::http::HeaderMap;
use super::Hit;

#[derive(Debug, Clone, Deserialize)]
pub struct VPatchRule {
    /// Human-readable name for this rule
    pub name: String,
    /// Optional path prefix filter
    pub path_prefix: Option<String>,
    /// Optional HTTP method filter (uppercase, e.g. "POST")
    pub method: Option<String>,
    /// Optional header check: header name + regex
    pub header_name: Option<String>,
    pub header_regex: Option<String>,
    /// Optional parameter check (query or body): param name + regex
    pub param_name: Option<String>,
    pub param_regex: Option<String>,
    /// Optional raw body regex
    pub body_regex: Option<String>,
    /// Action override: "block" | "log" | "allow"
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_score")]
    pub score: u32,
}

fn default_action() -> String { "block".into() }
fn default_score()  -> u32    { 100 }

/// Compiled version of a VPatchRule (regexes pre-compiled)
pub struct CompiledVPatch {
    pub name:         String,
    pub path_prefix:  Option<String>,
    pub method:       Option<String>,
    pub header_name:  Option<String>,
    pub header_re:    Option<Regex>,
    pub param_name:   Option<String>,
    pub param_re:     Option<Regex>,
    pub body_re:      Option<Regex>,
    pub action:       String,
    pub score:        u32,
}

impl CompiledVPatch {
    pub fn compile(r: &VPatchRule) -> anyhow::Result<Self> {
        Ok(Self {
            name:        r.name.clone(),
            path_prefix: r.path_prefix.clone(),
            method:      r.method.as_ref().map(|m| m.to_uppercase()),
            header_name: r.header_name.clone(),
            header_re:   r.header_regex.as_deref().map(|p| Regex::new(p)).transpose()?,
            param_name:  r.param_name.clone(),
            param_re:    r.param_regex.as_deref().map(|p| Regex::new(p)).transpose()?,
            body_re:     r.body_regex.as_deref().map(|p| Regex::new(p)).transpose()?,
            action:      r.action.clone(),
            score:       r.score,
        })
    }

    pub fn matches(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        body: &str,
    ) -> bool {
        // Path prefix
        if let Some(ref pfx) = self.path_prefix {
            if !path.starts_with(pfx.as_str()) { return false; }
        }
        // Method
        if let Some(ref m) = self.method {
            if method.to_uppercase() != *m { return false; }
        }
        // Header check
        if let Some(ref hname) = self.header_name {
            let hval = headers.get(hname.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if let Some(ref re) = self.header_re {
                if !re.is_match(hval) { return false; }
            } else if hval.is_empty() {
                return false;
            }
        }
        // Parameter check
        if let Some(ref pname) = self.param_name {
            let val = form_urlencoded::parse(query.as_bytes())
                .chain(form_urlencoded::parse(body.as_bytes()))
                .find(|(k, _)| k == pname.as_str())
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            if let Some(ref re) = self.param_re {
                if !re.is_match(&val) { return false; }
            } else if val.is_empty() {
                return false;
            }
        }
        // Body regex
        if let Some(ref re) = self.body_re {
            if !re.is_match(body) { return false; }
        }
        true
    }
}

pub struct VPatcher {
    rules: Vec<CompiledVPatch>,
}

impl VPatcher {
    pub fn new(raw: &[VPatchRule]) -> Self {
        let rules = raw.iter().filter_map(|r| {
            CompiledVPatch::compile(r).map_err(|e| {
                tracing::warn!("VPatch rule '{}' compile error: {}", r.name, e);
            }).ok()
        }).collect();
        Self { rules }
    }

    /// Returns matched hit (if any) and the action override.
    pub fn check(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        body: &str,
    ) -> Option<(Hit, String)> {
        for rule in &self.rules {
            if rule.matches(method, path, query, headers, body) {
                // leak the name string for 'static lifetime via Box::leak
                let desc: &'static str = Box::leak(rule.name.clone().into_boxed_str());
                return Some((
                    Hit {
                        rule_id:     "VPATCH",
                        description: desc,
                        category:    "vpatch",
                        score:       rule.score,
                    },
                    rule.action.clone(),
                ));
            }
        }
        None
    }
}
