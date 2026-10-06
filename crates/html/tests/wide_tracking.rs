//! `wide-tracking` in the static engine: short capital labels are the
//! standard treatment for wide tracking, running text is not.

use impeccable_html::{detect_html_source, DetectHtmlOptions};
use std::path::Path;

fn tracking_hits(body: &str) -> usize {
    let html = format!(
        "<!DOCTYPE html>\n<html><head><style>\n\
         .run {{ font-size: 16px; line-height: 26px; width: 520px; }}\n\
         </style></head><body>{body}</body></html>\n"
    );
    detect_html_source(&html, Path::new("/tmp/wide-tracking.html"), &DetectHtmlOptions::default())
        .iter()
        .filter(|f| f.antipattern == "wide-tracking")
        .count()
}

fn repo_root() -> std::path::PathBuf {
    std::env::var("IMPECCABLE_PUBLIC_REPO")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

#[test]
fn short_capital_label_passes() {
    assert_eq!(
        tracking_hits(
            r#"<span class="run" style="letter-spacing: 0.18em">LIMITED EDITION RELEASE 2026</span>"#
        ),
        0
    );
    assert_eq!(
        tracking_hits(
            r#"<span class="run" style="letter-spacing: 0.18em; text-transform: uppercase">Fall 2026 technology preview</span>"#
        ),
        0
    );
}

#[test]
fn mixed_case_label_still_flags() {
    assert_eq!(
        tracking_hits(
            r#"<span class="run" style="letter-spacing: 0.18em">Fall 2026 technology preview</span>"#
        ),
        1
    );
}

#[test]
fn typed_capitals_past_label_length_still_flag() {
    assert_eq!(
        tracking_hits(
            r#"<p class="run" style="letter-spacing: 0.12em">SUPPORT HOURS RUN MONDAY TO FRIDAY, FROM NINE UNTIL SIX.</p>"#
        ),
        1
    );
}

#[test]
fn declared_uppercase_stays_exempt() {
    // `text-transform: uppercase` is the author saying the run is set in
    // capitals at any length; `all-caps-body` owns a reading block of it.
    assert_eq!(
        tracking_hits(
            r#"<p class="run" style="letter-spacing: 0.12em; text-transform: uppercase">Every booking is confirmed by email within one working day of the request.</p>"#
        ),
        0
    );
}

#[test]
fn fixture_flag_and_pass_cases() {
    let fixture = repo_root().join("tests/fixtures/antipatterns/wide-tracking.html");
    assert!(fixture.is_file(), "missing fixture at {}", fixture.display());
    let html = std::fs::read_to_string(&fixture).unwrap();
    let findings = detect_html_source(&html, &fixture, &DetectHtmlOptions::default());
    let tracked = findings
        .iter()
        .filter(|f| f.antipattern == "wide-tracking")
        .count();
    assert_eq!(
        tracked, 3,
        "expected the three flag-column runs and no pass-column label, got {findings:?}"
    );
}
