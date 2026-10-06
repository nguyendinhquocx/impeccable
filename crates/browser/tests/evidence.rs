//! The validity gate, evidence scans, and replay, against an installed
//! browser. Skips cleanly when there is none.
//!
//! - A bot challenge or an HTTP error page is refused with an error by the
//!   CLI path and recorded (no findings, a screenshot) by the evidence path.
//! - An evidence scan reports the same findings as the CLI path, each named
//!   by its element.
//! - Replaying the recorded captures with no browser reproduces the
//!   deterministic passes' findings exactly, with no unanswered hit tests.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use impeccable_browser::{
    detect_url_evidence, origin, replay_url_scan, BrowserEngine, EvidenceRequest,
};
use impeccable_detect::engines::{ScanOptions, UrlEngine};

const CHALLENGE: &str = "<!doctype html><html><head><title>Human Verification</title></head><body><div id=\"captcha-container\">Please verify you are human.</div></body></html>";
const NOT_FOUND: &str = "<!doctype html><html><head><title>Not found</title></head><body><h1>Nothing here</h1></body></html>";

/// Fixtures that exercise the scan pass, hit tests (text-occlusion), and the
/// post-reveal content-hidden measure.
const REPLAY_FIXTURES: &[&str] = &[
    "should-flag.html",
    "text-occlusion.html",
    "reveal-working.html",
    "typography-should-flag.html",
    "quality.html",
    "layout.html",
];

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/antipatterns")
}

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || handle(stream));
        }
    });
    port
}

fn respond(stream: &mut TcpStream, status: &str, extra_headers: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.0 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle(mut stream: TcpStream) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    match path.as_str() {
        "/blocked" => respond(
            &mut stream,
            "405 Method Not Allowed",
            "x-amzn-waf-action: captcha\r\n",
            "text/html; charset=utf-8",
            CHALLENGE.as_bytes(),
        ),
        "/missing" => respond(&mut stream, "404 Not Found", "", "text/html; charset=utf-8", NOT_FOUND.as_bytes()),
        _ => {
            let rel = path.trim_start_matches('/');
            let file = fixtures_dir().join(rel);
            match std::fs::read(&file) {
                Ok(body) => {
                    let ct = if rel.ends_with(".css") { "text/css" } else { "text/html; charset=utf-8" };
                    respond(&mut stream, "200 OK", "", ct, &body)
                }
                Err(_) => respond(&mut stream, "404 Not Found", "", "text/plain", b"missing"),
            }
        }
    }
}

fn engine() -> Option<BrowserEngine> {
    let env: HashMap<String, String> = std::env::vars().collect();
    if impeccable_browser::discovery::find_browser(&env).is_err() {
        eprintln!("skip: no installed browser found");
        return None;
    }
    Some(BrowserEngine::new(env))
}

#[test]
fn blocked_pages_are_refused_by_the_cli_path_and_recorded_by_evidence() {
    let Some(engine) = engine() else { return };
    let port = serve();
    let options = ScanOptions::default();

    let blocked = format!("http://127.0.0.1:{port}/blocked");
    let err = engine.detect_url(&blocked, &options).expect_err("challenge page must not scan");
    assert!(err.message.contains("bot challenge"), "{}", err.message);
    assert!(err.message.contains("HTTP 405"), "{}", err.message);
    assert!(err.message.contains("x-amzn-waf-action: captcha"), "{}", err.message);

    let missing = format!("http://127.0.0.1:{port}/missing");
    let err = engine.detect_url(&missing, &options).expect_err("error page must not scan");
    assert!(err.message.contains("HTTP 404"), "{}", err.message);

    let mut browser = engine.launch().expect("launch");
    let (findings, evidence) =
        detect_url_evidence(&mut browser, &blocked, &options, "load", 100, &EvidenceRequest::default())
            .expect("evidence scan of a blocked page is Ok");
    browser.close();
    assert!(findings.is_empty());
    assert!(evidence.validity.as_ref().unwrap().is_blocked());
    assert_eq!(evidence.response.as_ref().unwrap().status, 405);
    assert!(evidence.scan_snapshot.is_none());
    assert!(evidence.screenshot.is_some(), "{:?}", evidence.screenshot_error);
}

#[test]
fn evidence_matches_the_cli_path_and_replay_matches_live() {
    let Some(engine) = engine() else { return };
    let port = serve();
    let options = ScanOptions::default();
    let mut browser = engine.launch().expect("launch");

    for name in REPLAY_FIXTURES {
        if !fixtures_dir().join(name).exists() {
            eprintln!("skip fixture {name}: not present");
            continue;
        }
        let url = format!("http://127.0.0.1:{port}/{name}");
        let cli = engine.detect_url(&url, &options).expect("cli scan");
        let (live, evidence) =
            detect_url_evidence(&mut browser, &url, &options, "networkidle0", 0, &EvidenceRequest::default())
                .expect("evidence scan");

        let strip = |f: &impeccable_core::findings::Finding| {
            (f.antipattern.clone(), f.snippet.clone())
        };
        // The visual-contrast pass samples pixels, so compare the passes that
        // do not: everything but visual-contrast must match the CLI path.
        let non_visual = |fs: &[impeccable_core::findings::Finding], origins: Option<&[&str]>| -> Vec<(String, String)> {
            fs.iter()
                .enumerate()
                .filter(|(i, f)| match origins {
                    Some(o) => o[*i] != origin::VISUAL_CONTRAST,
                    None => f.antipattern != "low-contrast" || f.extras.get("selector").is_some(),
                })
                .map(|(_, f)| strip(f))
                .collect()
        };
        assert_eq!(evidence.origins.len(), live.len());
        let live_scan: Vec<(String, String)> = non_visual(&live, Some(&evidence.origins));
        let cli_all: Vec<(String, String)> = cli.iter().map(strip).collect();
        for item in &live_scan {
            assert!(cli_all.contains(item), "{name}: evidence finding {item:?} missing from the CLI path");
        }

        let scan_findings = live.iter().zip(&evidence.origins).filter(|(_, o)| **o == origin::SCAN);
        for (f, _) in scan_findings {
            assert!(f.extras.get("selector").is_some(), "{name}: {} has no selector", f.antipattern);
        }
        assert!(evidence.screenshot.is_some(), "{name}: {:?}", evidence.screenshot_error);
        if live.iter().any(|f| f.extras.get("selector").is_some()) {
            assert!(!evidence.element_rects.is_empty(), "{name}: no element rects");
        }

        let replay = replay_url_scan(
            &url,
            evidence.scan_snapshot.as_deref().expect("scan snapshot"),
            &evidence.scan_facts,
            evidence
                .reveal_snapshot
                .as_deref()
                .map(|s| (s, &evidence.reveal_facts)),
            &options,
        )
        .expect("replay");
        let replayable: Vec<&impeccable_core::findings::Finding> = live
            .iter()
            .zip(&evidence.origins)
            .filter(|(_, o)| **o == origin::SCAN || **o == origin::CONTENT_HIDDEN)
            .map(|(f, _)| f)
            .collect();
        let replayed: Vec<&impeccable_core::findings::Finding> = replay.findings.iter().collect();
        assert_eq!(replayed, replayable, "{name}: replay differs from the live scan");
        assert_eq!(replay.unanswered_hit_tests, 0, "{name}: unanswered hit tests");
    }
    browser.close();
}
