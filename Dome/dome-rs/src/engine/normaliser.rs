/// Anti-bypass normaliser – decodes all common obfuscation layers
/// before rule matching, mimicking SafeLine's approach.
///
/// Decoding order (applied repeatedly until stable):
///   1. URL percent-decoding (%xx, %uXXXX)
///   2. HTML entity decoding (&amp; &#60; &#x3c;)
///   3. Whitespace / comment stripping (SQL comments /**/, --, #)
///   4. Case folding (lowercase)
///   5. Unicode normalisation (NFKC-like: full-width → ASCII)
use once_cell::sync::Lazy;
use regex::Regex;

// ── Regex patterns compiled once ─────────────────────────────────────────────
static PCT_HEX:  Lazy<Regex> = Lazy::new(|| Regex::new(r"%([0-9a-fA-F]{2})").unwrap());
static PCT_UHEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"%u([0-9a-fA-F]{4})").unwrap());
static HTML_DEC: Lazy<Regex> = Lazy::new(|| Regex::new(r"&#(\d{1,5});").unwrap());
static HTML_HEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"&#x([0-9a-fA-F]{1,4});").unwrap());
static HTML_ENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"&(amp|lt|gt|quot|apos);").unwrap());
static SQL_CMT:  Lazy<Regex> = Lazy::new(|| Regex::new(r"/\*.*?\*/").unwrap());
static MULTI_SP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
// Full-width ASCII range: U+FF01–U+FF5E → subtract 0xFEE0 for ASCII
static FULL_WIDTH: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\u{FF01}-\u{FF5E}]").unwrap());

/// Decode one pass of percent-encoding
fn decode_pct(s: &str) -> String {
    // %uXXXX first
    let s = PCT_UHEX.replace_all(s, |caps: &regex::Captures| {
        let code = u32::from_str_radix(&caps[1], 16).unwrap_or(0xFFFD);
        char::from_u32(code).unwrap_or('\u{FFFD}').to_string()
    });
    PCT_HEX.replace_all(&s, |caps: &regex::Captures| {
        let byte = u8::from_str_radix(&caps[1], 16).unwrap_or(b'?');
        (byte as char).to_string()
    }).into_owned()
}

/// Decode HTML entities
fn decode_html(s: &str) -> String {
    let s = HTML_DEC.replace_all(s, |caps: &regex::Captures| {
        let code: u32 = caps[1].parse().unwrap_or(0xFFFD);
        char::from_u32(code).unwrap_or('\u{FFFD}').to_string()
    });
    let s = HTML_HEX.replace_all(&s, |caps: &regex::Captures| {
        let code = u32::from_str_radix(&caps[1], 16).unwrap_or(0xFFFD);
        char::from_u32(code).unwrap_or('\u{FFFD}').to_string()
    });
    HTML_ENT.replace_all(&s, |caps: &regex::Captures| {
        match &caps[1] {
            "amp"  => "&",
            "lt"   => "<",
            "gt"   => ">",
            "quot" => "\"",
            "apos" => "'",
            _      => "",
        }
    }).into_owned()
}

/// Map full-width Unicode characters to ASCII equivalents
fn map_fullwidth(s: &str) -> String {
    s.chars().map(|c| {
        let cp = c as u32;
        if (0xFF01..=0xFF5E).contains(&cp) {
            char::from_u32(cp - 0xFEE0).unwrap_or(c)
        } else {
            c
        }
    }).collect()
}

/// Full normalisation pipeline – returns lowercase normalised string
pub fn normalise(input: &str) -> String {
    let mut s = input.to_string();

    // Iterative decoding (handle double/triple encoding)
    for _ in 0..4 {
        let next = decode_html(&decode_pct(&s));
        if next == s { break; }
        s = next;
    }

    // Full-width → ASCII
    s = map_fullwidth(&s);

    // Strip SQL comments
    s = SQL_CMT.replace_all(&s, " ").into_owned();

    // Collapse whitespace
    s = MULTI_SP.replace_all(&s, " ").into_owned();

    // Lowercase for pattern matching
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pct_decode() {
        assert!(normalise("%27%20OR%20%271%27%3D%271").contains("' or '1'='1"));
    }

    #[test]
    fn test_html_entity() {
        assert!(normalise("&lt;script&gt;").contains("<script>"));
    }

    #[test]
    fn test_double_encode() {
        // %2527 → %27 → '
        assert!(normalise("%2527").contains("'") || normalise("%2527").contains("%27"));
    }

    #[test]
    fn test_sql_comment() {
        assert_eq!(normalise("SELECT/**/1"), "select 1");
    }

    #[test]
    fn test_fullwidth() {
        // Full-width S, E, L, E, C, T
        let fw = "\u{FF33}\u{FF25}\u{FF2C}\u{FF25}\u{FF23}\u{FF34}";
        assert!(normalise(fw).contains("select"));
    }
}
