//! Whether a loaded page is the site, or something standing in front of it.
//!
//! A bot challenge, a WAF block page, or an HTTP error page is a real page the
//! rules can run over, and a challenge page is small enough to come back
//! clean. A scan of it reports on the wrong page and exits 0, which reads as
//! "this site is fine". The URL engine classifies the page right after
//! navigation and refuses to report on a blocked one, so a clean result
//! always describes the site that was asked about.
//!
//! The decision is pure ([`classify`]) over two inputs: the main document's
//! HTTP response as CDP saw it, and a small in-page probe ([`probe_js`]).
//! Header and HTTP-status signals stand alone. Titles and DOM markers only
//! count on a small page, because a real page can carry a captcha widget on a
//! form or be titled "Access denied" in a CMS without being a block page.

use serde_json::{json, Value};

/// Challenge pages are short. A page with more visible text than this is
/// treated as content even when its title or a marker looks like a challenge.
pub const SMALL_PAGE_CHARS: u64 = 3000;

/// Titles challenge and block pages use, lowercased and trimmed. Matched by
/// prefix, so "Access Denied" also covers "Access Denied - Reference #18...".
const CHALLENGE_TITLE_PREFIXES: &[&str] = &[
    "just a moment",
    "attention required! | cloudflare",
    "checking your browser",
    "human verification",
    "access denied",
    "access to this page has been denied",
    "pardon our interruption",
    "are you a robot",
    "robot or human",
    "please verify you are a human",
    "verify you are human",
    "bot verification",
    "security check",
    "you have been blocked",
    "request rejected",
    "ddos-guard",
    "one more step",
    "403 forbidden",
    "radware bot manager",
    "captcha",
];

/// Hosts that only serve challenges. A page that ends up on one of them after
/// redirects is a challenge whatever its title says.
const CHALLENGE_HOSTS: &[&str] = &["perfdrive.com", "captcha-delivery.com"];

/// DOM markers of challenge widgets that fill a page (not inline form
/// captchas). Each entry is `(selector, label)`; the probe reports the labels
/// of the selectors that match.
pub const CHALLENGE_MARKERS: &[(&str, &str)] = &[
    ("#challenge-form, #challenge-running, #cf-challenge-running", "cloudflare-challenge"),
    ("#px-captcha", "perimeterx-captcha"),
    ("iframe[src*='captcha-delivery.com']", "datadome-captcha"),
    ("iframe[src*='_Incapsula_Resource']", "imperva-incapsula"),
    ("#sec-if-cpt-container, #sec-cpt-if", "akamai-challenge"),
    ("#captcha-container[class*='amzn'], awswaf-captcha", "aws-waf-captcha"),
    (".geetest_holder, #nc_1_wrapper, #aliyunCaptcha-sliding-wrapper", "slider-captcha"),
];

/// The in-page probe: title, visible text length, final URL, and which
/// challenge markers are present. Read-only; returns a plain object.
pub fn probe_js() -> String {
    let markers: Vec<Value> = CHALLENGE_MARKERS
        .iter()
        .map(|(selector, label)| json!([selector, label]))
        .collect();
    format!(
        r#"(() => {{
  const markers = {markers};
  const found = [];
  for (const [selector, label] of markers) {{
    try {{ if (document.querySelector(selector)) found.push(label); }} catch (e) {{}}
  }}
  const text = (document.body && document.body.innerText) || '';
  return {{
    title: String(document.title || ''),
    textChars: text.replace(/\s+/g, ' ').trim().length,
    href: String(location.href || ''),
    markers: found,
  }};
}})()"#,
        markers = Value::Array(markers)
    )
}

/// What the probe saw in the page.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PageProbe {
    pub title: String,
    pub text_chars: u64,
    pub href: String,
    pub markers: Vec<String>,
}

impl PageProbe {
    pub fn from_value(v: &Value) -> PageProbe {
        PageProbe {
            title: v.get("title").and_then(Value::as_str).unwrap_or("").to_string(),
            text_chars: v.get("textChars").and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u64,
            href: v.get("href").and_then(Value::as_str).unwrap_or("").to_string(),
            markers: v
                .get("markers")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default(),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({
            "title": self.title,
            "textChars": self.text_chars,
            "href": self.href,
            "markers": self.markers,
        })
    }
}

/// The main document's HTTP response (the last one for the main frame, so
/// after redirects). `headers` names are lowercased.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DocumentResponse {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl DocumentResponse {
    /// From a CDP `Network.Response` object.
    pub fn from_cdp(response: &Value) -> Option<DocumentResponse> {
        let status = response.get("status").and_then(Value::as_f64)?;
        let headers = response
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        (
                            k.to_ascii_lowercase(),
                            v.as_str().map(String::from).unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(DocumentResponse {
            url: response.get("url").and_then(Value::as_str).unwrap_or("").to_string(),
            status: status.max(0.0) as u16,
            headers,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn to_value(&self) -> Value {
        let headers: serde_json::Map<String, Value> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        json!({ "url": self.url, "status": self.status, "headers": headers })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// A bot challenge, captcha, or WAF block page.
    Challenge,
    /// The server answered with a 4xx/5xx status.
    HttpError,
}

impl BlockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockKind::Challenge => "challenge",
            BlockKind::HttpError => "http-error",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PageValidity {
    Ok,
    Blocked {
        kind: BlockKind,
        /// Human-readable signals, in the order they were checked.
        evidence: Vec<String>,
    },
}

impl PageValidity {
    pub fn is_blocked(&self) -> bool {
        matches!(self, PageValidity::Blocked { .. })
    }

    pub fn to_value(&self) -> Value {
        match self {
            PageValidity::Ok => json!({ "status": "ok" }),
            PageValidity::Blocked { kind, evidence } => {
                json!({ "status": kind.as_str(), "evidence": evidence })
            }
        }
    }

    /// The error the CLI prints for a blocked page, or `None` when it is fine.
    pub fn error_message(&self) -> Option<String> {
        let PageValidity::Blocked { kind, evidence } = self else {
            return None;
        };
        let signals = evidence.join(", ");
        Some(match kind {
            BlockKind::Challenge => format!(
                "the page is a bot challenge, not the site ({signals}). Findings would describe the challenge page, so none are reported."
            ),
            BlockKind::HttpError => format!(
                "the page returned an error ({signals}). Findings would describe the error page, so none are reported."
            ),
        })
    }
}

/// Page- and server-supplied text made safe to print: control characters
/// (an escape sequence in a `<title>`, a newline in a header) are written as
/// `\u{..}` escapes, so the evidence the CLI prints to a terminal cannot drive
/// that terminal.
fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Classify a loaded page. `response` is `None` when no main-document
/// response was seen (a `file://` URL, or a same-document navigation).
pub fn classify(response: Option<&DocumentResponse>, probe: &PageProbe) -> PageValidity {
    let mut challenge: Vec<String> = Vec::new();
    if let Some(r) = response {
        if let Some(action) = r.header("x-amzn-waf-action") {
            challenge.push(format!("x-amzn-waf-action: {}", printable(action)));
        }
        if let Some(v) = r.header("cf-mitigated") {
            if v.eq_ignore_ascii_case("challenge") {
                challenge.push("cf-mitigated: challenge".to_string());
            }
        }
    }
    if let Ok(final_url) = url::Url::parse(&probe.href) {
        if let Some(host) = final_url.host_str() {
            let host = host.to_ascii_lowercase();
            if CHALLENGE_HOSTS
                .iter()
                .any(|h| host == *h || host.ends_with(&format!(".{h}")))
            {
                challenge.push(format!("challenge host {host}"));
            }
        }
    }
    let small = probe.text_chars <= SMALL_PAGE_CHARS;
    if small {
        let title = probe.title.trim().to_lowercase();
        if !title.is_empty() && CHALLENGE_TITLE_PREFIXES.iter().any(|p| title.starts_with(p)) {
            challenge.push(format!("title \"{}\"", printable(probe.title.trim())));
        }
        for m in &probe.markers {
            challenge.push(format!("marker {m}"));
        }
    }
    let status = response.map(|r| r.status).unwrap_or(0);
    if !challenge.is_empty() {
        if status >= 400 {
            challenge.insert(0, format!("HTTP {status}"));
        }
        return PageValidity::Blocked {
            kind: BlockKind::Challenge,
            evidence: challenge,
        };
    }
    if status >= 400 {
        return PageValidity::Blocked {
            kind: BlockKind::HttpError,
            evidence: vec![format!("HTTP {status}")],
        };
    }
    PageValidity::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)]) -> DocumentResponse {
        DocumentResponse {
            url: "https://example.com/".into(),
            status,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn probe(title: &str, text_chars: u64, markers: &[&str]) -> PageProbe {
        PageProbe {
            title: title.into(),
            text_chars,
            href: "https://example.com/".into(),
            markers: markers.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[test]
    fn aws_waf_captcha_is_a_challenge() {
        // siemens.com, 2026-09-11: CloudFront answered 405 with a captcha page.
        let v = classify(
            Some(&resp(405, &[("x-amzn-waf-action", "captcha")])),
            &probe("Human Verification", 120, &[]),
        );
        assert_eq!(
            v,
            PageValidity::Blocked {
                kind: BlockKind::Challenge,
                evidence: vec![
                    "HTTP 405".into(),
                    "x-amzn-waf-action: captcha".into(),
                    "title \"Human Verification\"".into(),
                ],
            }
        );
        assert!(v.error_message().unwrap().starts_with("the page is a bot challenge"));
    }

    #[test]
    fn page_supplied_evidence_cannot_carry_control_characters() {
        let v = classify(
            Some(&resp(403, &[("x-amzn-waf-action", "captcha\r\n\u{1b}[2J")])),
            &probe("Human Verification\u{1b}]0;owned\u{7}", 120, &[]),
        );
        let message = v.error_message().unwrap();
        assert!(!message.chars().any(|c| c.is_control()), "{message:?}");
        assert!(message.contains("title \"Human Verification\\u{1b}]0;owned\\u{7}\""), "{message}");
        assert!(message.contains("x-amzn-waf-action: captcha\\u{d}\\u{a}\\u{1b}[2J"), "{message}");
    }

    #[test]
    fn cloudflare_interstitial_title_on_a_small_page() {
        let v = classify(Some(&resp(403, &[])), &probe("Just a moment...", 80, &[]));
        assert!(matches!(v, PageValidity::Blocked { kind: BlockKind::Challenge, .. }));
    }

    #[test]
    fn cf_mitigated_header_alone_is_enough() {
        let v = classify(
            Some(&resp(200, &[("cf-mitigated", "challenge")])),
            &probe("Example", 20000, &[]),
        );
        assert!(matches!(v, PageValidity::Blocked { kind: BlockKind::Challenge, .. }));
    }

    #[test]
    fn challenge_title_on_a_content_page_is_content() {
        let v = classify(Some(&resp(200, &[])), &probe("Access denied: a novel", 40000, &[]));
        assert_eq!(v, PageValidity::Ok);
    }

    #[test]
    fn captcha_marker_on_a_content_page_is_content() {
        let v = classify(Some(&resp(200, &[])), &probe("Sign up", 9000, &["slider-captcha"]));
        assert_eq!(v, PageValidity::Ok);
    }

    #[test]
    fn marker_on_a_small_page_is_a_challenge() {
        let v = classify(Some(&resp(200, &[])), &probe("", 40, &["datadome-captcha"]));
        assert_eq!(
            v,
            PageValidity::Blocked {
                kind: BlockKind::Challenge,
                evidence: vec!["marker datadome-captcha".into()],
            }
        );
    }

    #[test]
    fn radware_redirect_host_is_a_challenge() {
        // yad2.co.il, 2026-09-11: a 302 to validate.perfdrive.com, which answers 200.
        let mut p = probe("Radware Bot Manager Block", 300, &[]);
        p.href = "https://validate.perfdrive.com/ccb4768f/?ssa=1".into();
        let v = classify(Some(&resp(200, &[])), &p);
        assert_eq!(
            v,
            PageValidity::Blocked {
                kind: BlockKind::Challenge,
                evidence: vec![
                    "challenge host validate.perfdrive.com".into(),
                    "title \"Radware Bot Manager Block\"".into(),
                ],
            }
        );
    }

    #[test]
    fn http_error_without_challenge_signals() {
        let v = classify(Some(&resp(404, &[])), &probe("Page not found", 400, &[]));
        assert_eq!(
            v,
            PageValidity::Blocked {
                kind: BlockKind::HttpError,
                evidence: vec!["HTTP 404".into()],
            }
        );
        assert!(v.error_message().unwrap().contains("HTTP 404"));
    }

    #[test]
    fn ordinary_pages_and_file_urls_pass() {
        assert_eq!(classify(Some(&resp(200, &[])), &probe("Stripe", 12000, &[])), PageValidity::Ok);
        assert_eq!(classify(None, &probe("fixture", 10, &[])), PageValidity::Ok);
    }

    #[test]
    fn response_from_cdp_lowercases_headers() {
        let r = DocumentResponse::from_cdp(&json!({
            "url": "https://example.com/",
            "status": 405,
            "headers": { "X-Amzn-Waf-Action": "captcha", "Server": "CloudFront" },
        }))
        .unwrap();
        assert_eq!(r.status, 405);
        assert_eq!(r.header("x-amzn-waf-action"), Some("captcha"));
    }

    #[test]
    fn probe_js_embeds_every_marker() {
        let js = probe_js();
        for (selector, label) in CHALLENGE_MARKERS {
            assert!(js.contains(label));
            assert!(js.contains(&selector.replace('\'', "'")));
        }
    }
}
