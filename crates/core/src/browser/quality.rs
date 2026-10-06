//! `checkQuality` and its browser adapters from `checks.mjs` Section 5:
//! `checkQuality` (every branch, including the rect-gated ones the static
//! engine never reaches), `checkElementQualityDOM`,
//! `hasVisibleBackgroundBoundary`, `hasMeaningfulDirectText`,
//! `textDescendantsFlushSides`, `isVisuallyHidden`, `isNonRenderedText`,
//! `checkPageQualityFromDoc`, `checkPageQualityDOM`.

#![allow(unused_imports)]
use super::dom::{
    closest_or_none, direct_text, has_direct_text_longer_than, matches_or_false, pf0, safe_id,
    renders_no_text, style_px, tag_lower, Dom, DomChild, ElId, Rect,
};
use super::{BrowserConfig, BrowserFinding};
use crate::checks::measures::{colors_nearly_match, css_color_is_transparent, resolve_length_px};
use crate::checks::rules::RuleHit;
use crate::checks::text_rules::{
    NON_RENDERED_TAGS, QUALITY_TEXT_TAGS, SR_ONLY_SELECTOR, TEXT_EDGE_TAGS,
};
use crate::js::{self, math_round, number_to_string, parse_float, to_fixed};
use crate::js_ext_b::{slice_utf16_prefix, utf16_len};
use once_cell::sync::Lazy;
use regex::Regex;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new(&$pat).expect(stringify!($name)));
    };
}

re!(WS_RE, format!("{}+", js::WS));
// JS `/url\(/i` in checkQuality's buried-raster branch.
re!(QUALITY_RASTER_URL_RE, format!(r"{}\(", js::ci("url")));
re!(CLIP_RECT_RE, format!(r"rect\({}*0", js::WS));
re!(
    CLIP_INSET_RE,
    format!(r"inset\({}*(?:50%|99|100%)", js::WS)
);
re!(OUTLINE_W_RE, r"([0-9]+(?:\.[0-9]+)?)\s*px");
re!(
    OUTLINE_STYLE_RE,
    r"(?-u:\b)(solid|dashed|dotted|double|groove|ridge|inset|outset)(?-u:\b)"
);
re!(
    OUTLINE_COLOR_RE,
    format!(r"(rgba?\([^)]+\)|#[0-9a-fA-F]{{3,8}}|[a-zA-Z]+){}*$", js::WS)
);

/// JS `s.replace(/\s+/g, ' ')`.
pub fn collapse_ws(s: &str) -> String {
    WS_RE.replace_all(s, " ").into_owned()
}

const FLUSH_SKIP_TAGS: &[&str] = &[
    "HTML", "BODY", "MAIN", "HEADER", "FOOTER", "NAV", "ARTICLE", "ASIDE", "BUTTON", "A", "LABEL",
    "SUMMARY", "CODE", "PRE", "INPUT", "TEXTAREA", "SELECT", "FORM", "FIGURE", "TABLE", "TBODY",
    "THEAD", "TR", "TD", "TH",
];

const TINY_TEXT_UI_CONTEXT: &str = "button, a, label, summary, pre, [role=\"button\"], [role=\"link\"], [role=\"tab\"], [role=\"menuitem\"], [role=\"option\"], nav, footer, [aria-hidden=\"true\"], [class*=\"badge\" i], [class*=\"caption\" i], [class*=\"chip\" i], [class*=\"code\" i], [class*=\"console\" i], [class*=\"diff\" i], [class*=\"label\" i], [class*=\"meta\" i], [class*=\"mock\" i], [class*=\"pill\" i], [class*=\"preview\" i], [class*=\"tag\" i], [class*=\"terminal\" i], [class*=\"writes\" i]";
const EXEMPT_CONTEXT: &str = "pre, code, kbd, samp, var, svg, [aria-hidden=\"true\"], [class*=\"terminal\" i], [class*=\"console\" i], [class*=\"code\" i], [class*=\"mock\" i], [class*=\"editor\" i], [class*=\"syntax\" i], [class*=\"diff\" i]";
const INTERACTIVE: &str = "a[href], button, summary, label, select, textarea, [role=\"button\"], [role=\"link\"], [role=\"tab\"], [role=\"menuitem\"], [role=\"menuitemcheckbox\"], [role=\"menuitemradio\"], [role=\"option\"], [role=\"checkbox\"], [role=\"radio\"], [role=\"switch\"], [role=\"treeitem\"], [tabindex]";
const FURNITURE: &str = "nav, [role=\"navigation\"], td, th, [role=\"gridcell\"], [role=\"cell\"], caption, figcaption, dt, dd, footer, [class*=\"meta\" i], [class*=\"label\" i], [class*=\"badge\" i], [class*=\"chip\" i], [class*=\"pill\" i], [class*=\"tag\" i], [class*=\"kicker\" i], [class*=\"eyebrow\" i], [class*=\"breadcrumb\" i], [class*=\"timestamp\" i], [class*=\"category\" i], [class*=\"caption\" i], [class*=\"nav\" i]";
const SMALLPRINT: &str = "small, footer, [class*=\"legal\" i], [class*=\"copyright\" i], [class*=\"fineprint\" i], [class*=\"fine-print\" i], [class*=\"smallprint\" i], [class*=\"small-print\" i], [class*=\"disclaimer\" i], [class*=\"disclosure\" i], [class*=\"footnote\" i]";
const TEXT_EDGE_QUERY: &str =
    "a, button, code, dd, dt, figcaption, h1, h2, h3, h4, h5, h6, li, p, pre, span, td, th";

/// JS `(el.matches && el.matches(sel)) || (el.closest && el.closest(sel))`.
fn matches_or_closest(dom: &dyn Dom, el: ElId, sel: &str) -> bool {
    matches_or_false(dom, el, sel) || closest_or_none(dom, el, sel).is_some()
}

/// JS: checks.mjs#hasVisibleBackgroundBoundary(style, el, win) — browser:
/// `style` is `el`'s own computed style, `win` the live window.
pub fn has_visible_background_boundary(dom: &dyn Dom, el: ElId) -> bool {
    let bg = dom.style(el, "backgroundColor");
    if css_color_is_transparent(Some(&bg)) {
        return false;
    }
    let mut parent = dom.parent(el);
    while let Some(p) = parent {
        let parent_bg = dom.style(p, "backgroundColor");
        if !css_color_is_transparent(Some(&parent_bg)) {
            return !colors_nearly_match(Some(&bg), Some(&parent_bg));
        }
        parent = dom.parent(p);
    }
    true
}

/// JS: checks.mjs#hasMeaningfulDirectText(node)
pub fn has_meaningful_direct_text(dom: &dyn Dom, el: ElId) -> bool {
    has_direct_text_longer_than(dom, el, 4)
}

/// The width of every line the element's text rendered on, or `None` when
/// the DOM cannot say where the lines are.
///
/// `Dom::text_line_rects` has already merged the fragments of a line back
/// together, so each rect here is one line box and nothing is divided by
/// anything: a leading tighter than the glyph box used to turn one rect into
/// two identical "lines" and charge a single long line twice.
fn rendered_line_widths(dom: &dyn Dom, el: ElId) -> Option<Vec<f64>> {
    Some(
        dom.text_line_rects(el)?
            .into_iter()
            .filter(|r| r.width > 0.0 && r.height > 0.0)
            .map(|r| r.width)
            .collect(),
    )
}

static COMBINING_OR_FORMAT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\p{M}\p{Cf}]").expect("COMBINING_OR_FORMAT_RE"));

/// The running count of [`rendered_text_len`], fed one text node at a time.
///
/// White space is held back until a character that is not white space
/// follows it, so a leading run is dropped and a trailing run never counts:
/// the ends are trimmed as `String.prototype.trim` trims them, wherever the
/// node boundaries fall. A run of collapsible white space counts once, and it
/// runs on across node boundaries, the way `a <b> b</b>` renders one space.
#[derive(Default)]
struct RenderedTextCount {
    count: usize,
    /// White space seen since the last counted character.
    pending: usize,
    /// The last white space seen was collapsible, so more of it joins that run.
    in_collapsible_run: bool,
    /// Count white space that cannot collapse (preserved, or a no-break
    /// space) where it stands, edges included. Set for an atomic inline's
    /// contents, whose edges trim only collapsible white space.
    keep_fixed_spaces: bool,
}

impl RenderedTextCount {
    fn feed(&mut self, text: &str, preserved: bool) {
        let collapsible = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{c}');
        let mut buf = [0u8; 4];
        for c in text.chars() {
            if collapsible(c) && !preserved {
                if !self.in_collapsible_run {
                    self.pending += 1;
                    self.in_collapsible_run = true;
                }
                continue;
            }
            if js::is_js_whitespace(c) && !self.keep_fixed_spaces {
                self.pending += 1;
                self.in_collapsible_run = false;
                continue;
            }
            // A mark is not on the line; it neither ends a run of white space
            // nor counts as a character.
            if COMBINING_OR_FORMAT_RE.is_match(c.encode_utf8(&mut buf)) {
                continue;
            }
            if self.count > 0 {
                self.count += self.pending;
            }
            self.pending = 0;
            self.in_collapsible_run = false;
            self.count += 1;
        }
    }

    /// Takes in an atomic inline (an image, an inline-block) whose own
    /// contents counted `inner` characters. The box sits in the line like a
    /// character, so a collapsible space on each side of it renders: the run
    /// ends at the box. Its contents were counted in a count of their own,
    /// because they are laid out in their own formatting context: their edge
    /// collapsible white space is trimmed there and never joins the outer
    /// run, while preserved and no-break spaces at the edges still render.
    fn add_atomic_inline(&mut self, inner: usize) {
        self.in_collapsible_run = false;
        if inner == 0 {
            return;
        }
        if self.count > 0 {
            self.count += self.pending;
        }
        self.pending = 0;
        self.count += inner;
    }
}

/// Replaced elements, which lay out as atomic inlines in a line of text.
const REPLACED_TAGS: [&str; 11] =
    ["img", "svg", "video", "canvas", "iframe", "object", "embed", "input", "select", "textarea", "button"];

/// An atomic inline box: a replaced element or an `inline-*` display.
fn is_atomic_inline(dom: &dyn Dom, el: ElId) -> bool {
    REPLACED_TAGS.contains(&tag_lower(dom, el).as_str())
        || js::to_lower_case(&dom.style(el, "display")).trim().starts_with("inline-")
}

/// Feeds the text nodes under `el` in document order, each under its own
/// parent's `white-space`, skipping every descendant that renders no text
/// ([`renders_no_text`]: unrendered tags, `display: none`, and the contents
/// of a `content-visibility: hidden` box). `Dom::text_line_rects` skips the
/// same subtrees, so the count and the line widths it is divided among
/// always describe the same text.
fn feed_rendered_text(dom: &dyn Dom, el: ElId, out: &mut RenderedTextCount) {
    let mut preserved: Option<bool> = None;
    for child in dom.child_nodes(el) {
        match child {
            DomChild::Text(text) => {
                let preserved = *preserved.get_or_insert_with(|| {
                    let white_space = dom.style(el, "whiteSpace");
                    white_space == "pre" || white_space == "pre-wrap" || white_space == "break-spaces"
                });
                out.feed(&text, preserved);
            }
            DomChild::Element(child) => {
                if renders_no_text(dom, child) {
                    continue;
                }
                if is_atomic_inline(dom, child) {
                    let mut inner = RenderedTextCount { keep_fixed_spaces: true, ..Default::default() };
                    feed_rendered_text(dom, child, &mut inner);
                    out.add_atomic_inline(inner.count);
                } else {
                    feed_rendered_text(dom, child, out);
                }
            }
        }
    }
}

/// How many characters of `el`'s text reached its rendered lines, which is
/// the count the line rects have to be divided among.
///
/// `textContent` is the source, not the rendering, and it runs over in three
/// ways. It includes the text of an inline `<style>` or `<script>` child and
/// of a `display: none` one, none of which is on any line. It keeps the
/// source's indentation and newlines, which `white-space: normal` collapses
/// to a single space. And it counts code units, so a combining mark, which
/// sits on its base and advances nothing, is charged as a character of its
/// own: a third of a Devanagari paragraph is marks.
///
/// So the count is built from the text nodes themselves, in order: the
/// unrendered descendants are never visited, each node's collapsible white
/// space is folded to one space unless the element it sits in preserves it
/// (a `pre-wrap` span inside a normal paragraph keeps its spaces, which are
/// on the line), and combining marks and format characters (zero-width
/// joiners, soft hyphens) are left out.
fn rendered_text_len(dom: &dyn Dom, el: ElId) -> usize {
    let mut count = RenderedTextCount::default();
    feed_rendered_text(dom, el, &mut count);
    count.count
}

/// JS: checks.mjs#textDescendantsFlushSides(el, rect) → [top, right, bottom, left]
///
/// The side is flush when the *text* lands on it, not when a text-bearing box
/// does. A `<td>` fills its table edge to edge and insets its own text by the
/// cell padding; reading the cell's border box called that flush and charged a
/// framed table for having no inset, when the reader sees the padding the
/// cells declare (REN-403).
pub fn text_descendants_flush_sides(dom: &dyn Dom, el: ElId, rect: &Rect) -> [bool; 4] {
    let mut flush = [false; 4];
    const TEXT_EDGE_THRESHOLD: f64 = 4.0;
    let candidates = dom.query_all(Some(el), TEXT_EDGE_QUERY).unwrap_or_default();
    for node in candidates {
        let tag_name = dom.tag_name(node);
        if !TEXT_EDGE_TAGS.contains(&tag_name.as_str()) || !has_meaningful_direct_text(dom, node) {
            continue;
        }
        let nr = dom.direct_text_rect(node).unwrap_or_else(|| dom.rect(node));
        if nr.width <= 0.0 || nr.height <= 0.0 {
            continue;
        }
        if nr.bottom < rect.top || nr.top > rect.bottom || nr.right < rect.left || nr.left > rect.right {
            continue;
        }
        if nr.top - rect.top <= TEXT_EDGE_THRESHOLD {
            flush[0] = true;
        }
        if rect.right - nr.right <= TEXT_EDGE_THRESHOLD {
            flush[1] = true;
        }
        if rect.bottom - nr.bottom <= TEXT_EDGE_THRESHOLD {
            flush[2] = true;
        }
        if nr.left - rect.left <= TEXT_EDGE_THRESHOLD {
            flush[3] = true;
        }
    }
    flush
}

/// JS: checks.mjs#isVisuallyHidden(el, style)
pub fn is_visually_hidden(dom: &dyn Dom, el: ElId) -> bool {
    if matches_or_closest(dom, el, SR_ONLY_SELECTOR) {
        return true;
    }
    let pos = dom.style(el, "position");
    if pos == "absolute" || pos == "fixed" {
        let clip = dom.style(el, "clip");
        let clip_path = {
            let a = dom.style(el, "clipPath");
            if !a.is_empty() {
                a
            } else {
                let b = dom.style(el, "webkitClipPath");
                if !b.is_empty() {
                    b
                } else {
                    dom.style(el, "clip-path")
                }
            }
        };
        if CLIP_RECT_RE.is_match(&clip) || CLIP_INSET_RE.is_match(&clip_path) {
            return true;
        }
        let w = parse_float(&dom.style(el, "width"));
        let h = parse_float(&dom.style(el, "height"));
        let overflow = dom.style(el, "overflow");
        if (w == 1.0 || h == 1.0) && (overflow == "hidden" || overflow == "clip") {
            return true;
        }
    }
    false
}

/// JS: checks.mjs#isNonRenderedText(el, tag, style)
pub fn is_non_rendered_text(dom: &dyn Dom, el: ElId, tag: &str) -> bool {
    let t = js::to_lower_case(tag);
    if NON_RENDERED_TAGS.contains(&t.as_str()) {
        return true;
    }
    if closest_or_none(dom, el, "head").is_some() {
        return true;
    }
    if dom.style(el, "display") == "none" {
        return true;
    }
    let vis = dom.style(el, "visibility");
    if vis == "hidden" || vis == "collapse" {
        return true;
    }
    false
}

/// Inputs of `checkQuality` as the browser adapter builds them.
pub struct QualityInput {
    pub el: ElId,
    pub tag: String,
    pub has_direct_text: bool,
    pub text_len: usize,
    pub font_size: f64,
    pub line_height_px: Option<f64>,
    pub letter_spacing_px: Option<f64>,
    pub rect: Rect,
    pub line_max: f64,
    pub viewport_width: f64,
}

/// JS: checks.mjs#checkQuality(opts), browser adapter inputs (`rect` set,
/// `win` = window).
pub fn check_quality(dom: &dyn Dom, q: &QualityInput) -> Vec<RuleHit> {
    let el = q.el;
    let tag = q.tag.as_str();
    let font_size = q.font_size;
    let text_len = q.text_len;
    let rect = &q.rect;
    let line_max = q.line_max;
    let viewport_width = q.viewport_width;
    let has_direct_text = q.has_direct_text;
    let mut findings: Vec<RuleHit> = Vec::new();

    let el_id = safe_id(dom, el);
    if el_id.starts_with("claude-") || el_id.starts_with("cic-") {
        return findings;
    }

    let st = |k: &str| dom.style(el, k);
    let spx = |k: &str| style_px(dom, el, k);

    // A raster (<img>, or an element with a background url) at near-zero
    // opacity never reaches the screen: the produced material ships as a
    // compliance token. The CSS-text scan catches the stylesheet form; this
    // catches computed opacity on the element itself (both engines).
    {
        let op = parse_float(&st("opacity"));
        if op.is_finite() && op < 0.15 && op >= 0.0 {
            let bg = st("backgroundImage");
            if tag == "img" || QUALITY_RASTER_URL_RE.is_match(&bg) {
                let label = if tag == "img" {
                    dom.attr(el, "alt").unwrap_or_default()
                } else {
                    slice_utf16_prefix(js::trim(&dom.text_content(el)), 40)
                };
                findings.push(RuleHit::new(
                    "buried-raster",
                    format!(
                        "{} at opacity {}{}",
                        if tag == "img" { "<img>" } else { "raster background" },
                        number_to_string(op),
                        if label.is_empty() {
                            String::new()
                        } else {
                            format!(" \"{label}\"")
                        }
                    ),
                ));
            }
        }
    }

    // --- Line length too long ---
    //
    // The measure is the line that rendered, not the box that could have held
    // it. `rect.width / (fontSize * 0.5)` is the box's capacity: a paragraph
    // sitting in a 1022px column whose text stops at 571px was charged with
    // 142 characters a line it never rendered (REN-402). What the reader sees
    // is `text_line_rects`, one rect per line box with the fragments of a
    // line merged back together, and the characters divide between the lines
    // in proportion to the ink each carries — one element's text is one font
    // at one size, so the average advance is the same on every line of it.
    //
    // The rects cover the element's whole rendered text, descendants and all,
    // so the characters divided among them are the rendered ones too
    // (`rendered_text_len`): measuring the direct text alone and then
    // charging it with the characters of an inline `<strong>` inflated every
    // paragraph that had one, and so does charging the lines with an inline
    // `<style>` child, the source's indentation, or a script's combining
    // marks, none of which takes up any of a line.
    //
    // A DOM that cannot say where the lines are gets no finding. The union of
    // a long first line and a short tail is the same union as two even lines,
    // so there is nothing in it to read a line off, and a rule that guesses
    // there is charging noise.
    //
    // Charged when at least two rendered lines run past the maximum. The harm
    // this rule names is the eye losing its place tracking back to the start
    // of the next line, so it takes a column of long lines to do the damage;
    // one long line and a short tail is a sentence that wrapped once.
    if has_direct_text
        && QUALITY_TEXT_TAGS.contains(&tag)
        && rect.width > 0.0
        && (text_len as f64) > line_max
    {
        if let Some(widths) = rendered_line_widths(dom, el) {
            let total: f64 = widths.iter().sum();
            if total > 0.0 {
                let over = line_max + 5.0;
                let rendered_len = rendered_text_len(dom, el) as f64;
                let chars = |w: f64| rendered_len * w / total;
                let long = widths.iter().filter(|w| chars(**w) > over).count();
                if long >= 2 {
                    let longest = widths.iter().copied().fold(0.0, js::math_max);
                    findings.push(RuleHit::new(
                        "line-length",
                        format!(
                            "~{} chars on {} of {} rendered lines (aim for <{})",
                            number_to_string(math_round(chars(longest))),
                            number_to_string(long as f64),
                            number_to_string(widths.len() as f64),
                            number_to_string(line_max)
                        ),
                    ));
                }
            }
        }
    }

    // --- Cramped padding ---
    let is_inline_code = tag == "code" && closest_or_none(dom, el, "pre").is_none();
    if !is_inline_code && has_direct_text && text_len > 20 && rect.width > 100.0 && rect.height > 30.0 {
        let borders = [
            spx("borderTopWidth"),
            spx("borderRightWidth"),
            spx("borderBottomWidth"),
            spx("borderLeftWidth"),
        ];
        let border_count = borders.iter().filter(|w| **w > 0.0).count();
        let has_bg = has_visible_background_boundary(dom, el);
        // The space the reader sees, not the space the stylesheet declares:
        // the inset between the rendered text and the inside of the border
        // box. A 44px control with `padding: 0 16px` whose label a flex box
        // centres has 12px of air above the label and was charged with "0px
        // vertical padding" (REN-403). Nothing to measure the text with is
        // nothing to charge on, and the text is measured only for the
        // elements that got this far: the probe builds a Range per call, and
        // a page has a great many boxes that are not bounded at all.
        if let Some(text_rect) = (border_count >= 2 || has_bg)
            .then(|| dom.direct_text_rect(el))
            .flatten()
        {
            let mut v_pads: Vec<f64> = Vec::new();
            let mut h_pads: Vec<f64> = Vec::new();
            if has_bg || borders[0] > 0.0 {
                v_pads.push(text_rect.top - (rect.top + borders[0]));
            }
            if has_bg || borders[2] > 0.0 {
                v_pads.push((rect.bottom - borders[2]) - text_rect.bottom);
            }
            if has_bg || borders[3] > 0.0 {
                h_pads.push(text_rect.left - (rect.left + borders[3]));
            }
            if has_bg || borders[1] > 0.0 {
                h_pads.push((rect.right - borders[1]) - text_rect.right);
            }
            let v_min = v_pads.iter().copied().fold(f64::INFINITY, js::math_min);
            let h_min = h_pads.iter().copied().fold(f64::INFINITY, js::math_min);
            let v_thresh = js::math_max(4.0, font_size * 0.3);
            let h_thresh = js::math_max(8.0, font_size * 0.5);
            let px = |v: f64| number_to_string(math_round(v * 10.0) / 10.0);
            if v_min < v_thresh {
                findings.push(RuleHit::new(
                    "cramped-padding",
                    format!(
                        "{}px of space above and below the text (need ≥{}px for {}px text)",
                        px(v_min),
                        to_fixed(v_thresh, 1),
                        number_to_string(font_size)
                    ),
                ));
            } else if h_min < h_thresh {
                findings.push(RuleHit::new(
                    "cramped-padding",
                    format!(
                        "{}px of space beside the text (need ≥{}px for {}px text)",
                        px(h_min),
                        to_fixed(h_thresh, 1),
                        number_to_string(font_size)
                    ),
                ));
            }
        }
    }

    // --- Flush against a visible boundary ---
    {
        let upper_tag = js::to_upper_case(tag);
        let el_position = st("position");
        let children = dom.children(el);
        if !FLUSH_SKIP_TAGS.contains(&upper_tag.as_str())
            && !has_direct_text
            && el_position != "fixed"
            && el_position != "absolute"
            && !children.is_empty()
        {
            let border_w = [
                spx("borderTopWidth"),
                spx("borderRightWidth"),
                spx("borderBottomWidth"),
                spx("borderLeftWidth"),
            ];
            let bc = |k: &str| css_color_is_transparent(Some(&st(k)));
            let border_visible = [
                border_w[0] > 0.0 && !bc("borderTopColor"),
                border_w[1] > 0.0 && !bc("borderRightColor"),
                border_w[2] > 0.0 && !bc("borderBottomColor"),
                border_w[3] > 0.0 && !bc("borderLeftColor"),
            ];
            let mut outline_w = spx("outlineWidth");
            let mut outline_style_val = st("outlineStyle");
            let mut outline_color_val = st("outlineColor");
            let outline_short = st("outline");
            if outline_w == 0.0 && !outline_short.is_empty() {
                if let Some(m) = OUTLINE_W_RE.captures(&outline_short) {
                    outline_w = pf0(m.get(1).map(|x| x.as_str()).unwrap_or(""));
                }
                if outline_style_val.is_empty() {
                    outline_style_val = if OUTLINE_STYLE_RE.is_match(&outline_short) {
                        "solid".to_string()
                    } else {
                        String::new()
                    };
                }
                if outline_color_val.is_empty() {
                    if let Some(m) = OUTLINE_COLOR_RE.captures(&outline_short) {
                        outline_color_val = m.get(1).map(|x| x.as_str()).unwrap_or("").to_string();
                    }
                }
            }
            let outline_visible = outline_w > 0.0
                && !css_color_is_transparent(Some(&outline_color_val))
                && !outline_style_val.is_empty()
                && outline_style_val != "none";
            let bg_visible = has_visible_background_boundary(dom, el);
            let any_visible = border_visible.iter().any(|b| *b) || outline_visible || bg_visible;
            if any_visible {
                let len = |e: ElId, k: &str| {
                    resolve_length_px(Some(&dom.style(e, k)), font_size).unwrap_or(0.0)
                };
                let pad = [
                    len(el, "paddingTop"),
                    len(el, "paddingRight"),
                    len(el, "paddingBottom"),
                    len(el, "paddingLeft"),
                ];
                const PAD_THRESHOLD: f64 = 2.0;
                const CHILD_INSULATE_THRESHOLD: f64 = 4.0;
                // Content that runs past the box is clipped, not snug. A
                // table with a min-width inside an `overflow: hidden` frame
                // has its far column cut off, which is a defect
                // `clipped-overflow-container` is named for; calling it "no
                // inset" points at the wrong thing (REN-403).
                const OVERFLOW_TOLERANCE: f64 = 1.0;
                let mut children_overflow = [false; 4];
                let mut children_insulate = [false; 4];
                for &child in &children {
                    let child_pad = [
                        len(child, "paddingTop"),
                        len(child, "paddingRight"),
                        len(child, "paddingBottom"),
                        len(child, "paddingLeft"),
                    ];
                    let child_margin = [
                        len(child, "marginTop"),
                        len(child, "marginRight"),
                        len(child, "marginBottom"),
                        len(child, "marginLeft"),
                    ];
                    let cr = dom.rect(child);
                    if cr.width > 0.0 && cr.height > 0.0 {
                        if rect.top - cr.top > OVERFLOW_TOLERANCE {
                            children_overflow[0] = true;
                        }
                        if cr.right - rect.right > OVERFLOW_TOLERANCE {
                            children_overflow[1] = true;
                        }
                        if cr.bottom - rect.bottom > OVERFLOW_TOLERANCE {
                            children_overflow[2] = true;
                        }
                        if rect.left - cr.left > OVERFLOW_TOLERANCE {
                            children_overflow[3] = true;
                        }
                        if cr.top - rect.top >= CHILD_INSULATE_THRESHOLD {
                            children_insulate[0] = true;
                        }
                        if rect.right - cr.right >= CHILD_INSULATE_THRESHOLD {
                            children_insulate[1] = true;
                        }
                        if rect.bottom - cr.bottom >= CHILD_INSULATE_THRESHOLD {
                            children_insulate[2] = true;
                        }
                        if cr.left - rect.left >= CHILD_INSULATE_THRESHOLD {
                            children_insulate[3] = true;
                        }
                    }
                    for s in 0..4 {
                        if child_pad[s] >= CHILD_INSULATE_THRESHOLD
                            || child_margin[s] >= CHILD_INSULATE_THRESHOLD
                        {
                            children_insulate[s] = true;
                        }
                    }
                }

                let text_flush = text_descendants_flush_sides(dom, el, rect);
                let full_bleed_bg_band = viewport_width > 0.0
                    && rect.width >= viewport_width * 0.94
                    && bg_visible
                    && !outline_visible;
                let side_names = ["top", "right", "bottom", "left"];
                let mut flush_sides: Vec<&str> = Vec::new();
                for s in 0..4 {
                    let bg_bounds_side = bg_visible && !(full_bleed_bg_band && (s == 1 || s == 3));
                    let side_bounded = border_visible[s] || outline_visible || bg_bounds_side;
                    if side_bounded
                        && pad[s] <= PAD_THRESHOLD
                        && !children_insulate[s]
                        && !children_overflow[s]
                        && text_flush[s]
                    {
                        flush_sides.push(side_names[s]);
                    }
                }

                if !flush_sides.is_empty() {
                    let mut has_text_child = false;
                    for &child in &children {
                        let child_text = js::trim(&dom.text_content(child)).to_string();
                        if utf16_len(&child_text) > 4 {
                            has_text_child = true;
                            break;
                        }
                    }
                    if has_text_child {
                        let cls_all = dom.class_name_prop(el).unwrap_or_default();
                        let cls_all = js::trim(&cls_all).to_string();
                        let cls = if cls_all.is_empty() {
                            String::new()
                        } else {
                            WS_RE.split(&cls_all).next().unwrap_or("").to_string()
                        };
                        let mut boundary_parts: Vec<String> = Vec::new();
                        let border_sides_visible: Vec<&str> = (0..4)
                            .filter(|i| border_visible[*i])
                            .map(|i| side_names[i])
                            .collect();
                        if border_sides_visible.len() == 4 {
                            boundary_parts.push("border".to_string());
                        } else if !border_sides_visible.is_empty() {
                            boundary_parts.push(format!("border-{}", border_sides_visible.join("/")));
                        }
                        if outline_visible {
                            boundary_parts.push("outline".to_string());
                        }
                        if bg_visible {
                            boundary_parts.push("bg".to_string());
                        }
                        let sides_label = if flush_sides.len() == 4 {
                            "all sides".to_string()
                        } else {
                            flush_sides.join("/")
                        };
                        let tl = js::to_lower_case(tag);
                        let ident = if !cls.is_empty() {
                            format!("<{}> \"{}\"", tl, cls)
                        } else {
                            format!("<{}>", tl)
                        };
                        findings.push(RuleHit::new(
                            "cramped-padding",
                            format!(
                                "{}: children flush against {} on {} (no inset)",
                                ident,
                                boundary_parts.join("+"),
                                sides_label
                            ),
                        ));
                    }
                }
            }
        }
    }

    // --- Body text touching viewport edge ---
    if has_direct_text
        && text_len > 40
        && matches!(js::to_upper_case(tag).as_str(), "P" | "LI")
        && viewport_width > 0.0
    {
        let in_nav_header =
            closest_or_none(dom, el, "nav").is_some() || closest_or_none(dom, el, "header").is_some();
        let bg = st("backgroundColor");
        let has_own_bg = !bg.is_empty() && bg != "rgba(0, 0, 0, 0)" && bg != "transparent";
        let pos = st("position");
        let is_positioned = pos == "fixed" || pos == "absolute";
        let width_ratio = rect.width / viewport_width;
        let left_close = rect.left < 16.0;
        let right_close = rect.right > viewport_width - 16.0;
        if !in_nav_header && !has_own_bg && !is_positioned && width_ratio > 0.5 && (left_close || right_close) {
            let l = number_to_string(math_round(rect.left));
            let r = number_to_string(math_round(viewport_width - rect.right));
            let which = if left_close && right_close {
                format!("left {}px / right {}px", l, r)
            } else if left_close {
                format!("left {}px", l)
            } else {
                format!("right {}px", r)
            };
            findings.push(RuleHit::new(
                "body-text-viewport-edge",
                format!(
                    "<{}> with {}-char body bleeds to viewport edge ({})",
                    js::to_lower_case(tag),
                    text_len,
                    which
                ),
            ));
        }
    }

    let is_heading = matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6");

    // --- Tight line height ---
    if has_direct_text && text_len > 50 && !is_heading {
        if let Some(lh) = q.line_height_px {
            if font_size > 0.0 {
                let ratio = lh / font_size;
                if ratio > 0.0 && ratio < 1.3 {
                    findings.push(RuleHit::new(
                        "tight-leading",
                        format!("line-height {}x (need >=1.3)", to_fixed(ratio, 2)),
                    ));
                }
            }
        }
    }

    // --- Justified text (without hyphens) ---
    if has_direct_text && st("textAlign") == "justify" {
        let hyphens = {
            let a = st("hyphens");
            if !a.is_empty() {
                a
            } else {
                st("webkitHyphens")
            }
        };
        if hyphens != "auto" {
            findings.push(RuleHit::new(
                "justified-text",
                "text-align: justify without hyphens: auto".to_string(),
            ));
        }
    }

    // --- Tiny body text ---
    if has_direct_text && text_len > 20 && font_size < 12.0 {
        let skip_tags = ["sub", "sup", "code", "kbd", "samp", "var", "caption", "figcaption"];
        let in_ui_context = closest_or_none(dom, el, TINY_TEXT_UI_CONTEXT).is_some();
        let is_uppercase = st("textTransform") == "uppercase";
        if !skip_tags.contains(&tag)
            && !in_ui_context
            && !is_uppercase
            && !is_non_rendered_text(dom, el, tag)
        {
            findings.push(RuleHit::new(
                "tiny-text",
                format!("{}px body text", number_to_string(font_size)),
            ));
        }
    }

    // --- Undersized functional / UI text ---
    {
        let dt = js::trim(&collapse_ws(&direct_text(dom, el))).to_string();
        let dt_len = utf16_len(&dt);
        let ui_skip_tags = ["sub", "sup", "option"];
        if font_size > 0.0
            && font_size < 11.0
            && dt_len >= 2
            && !ui_skip_tags.contains(&tag)
            && !is_non_rendered_text(dom, el, tag)
        {
            let is_exempt_context = matches_or_closest(dom, el, EXEMPT_CONTEXT);
            if !is_exempt_context && !is_visually_hidden(dom, el) {
                let is_interactive = matches_or_closest(dom, el, INTERACTIVE);
                let is_furniture = matches_or_closest(dom, el, FURNITURE);
                let is_smallprint = matches_or_closest(dom, el, SMALLPRINT);
                let floor = if !is_interactive && is_smallprint { 10.0 } else { 11.0 };
                if font_size < floor && (is_interactive || is_furniture || dt_len <= 20) {
                    let excerpt = slice_utf16_prefix(&dt, 40);
                    findings.push(RuleHit::new(
                        "undersized-ui-text",
                        format!(
                            "{}px functional text \"{}\" (below {}px floor)",
                            number_to_string(font_size),
                            excerpt,
                            number_to_string(floor)
                        ),
                    ));
                }
            }
        }
    }

    // --- All-caps body text ---
    if has_direct_text && text_len > 30 && st("textTransform") == "uppercase" && !is_heading {
        findings.push(RuleHit::new(
            "all-caps-body",
            format!("text-transform: uppercase on {} chars of body text", text_len),
        ));
    }

    // --- Wide letter spacing on body text ---
    if has_direct_text && text_len > 20 && st("textTransform") != "uppercase" {
        if let Some(ls) = q.letter_spacing_px {
            if ls > 0.0 && font_size > 0.0 {
                let tracking_em = ls / font_size;
                if tracking_em > 0.05 {
                    findings.push(RuleHit::new(
                        "wide-tracking",
                        format!("letter-spacing: {}em on body text", to_fixed(tracking_em, 2)),
                    ));
                }
            }
        }
    }

    // --- Crushed letter spacing ---
    if has_direct_text && text_len > 20 && font_size > 0.0 {
        if let Some(ls) = q.letter_spacing_px {
            if ls < 0.0 {
                let tracking_em = ls / font_size;
                if tracking_em <= -0.05 {
                    let excerpt = slice_utf16_prefix(
                        &collapse_ws(js::trim(&dom.text_content(el))),
                        40,
                    );
                    findings.push(RuleHit::new(
                        "extreme-negative-tracking",
                        format!("letter-spacing: {}em — \"{}\"", to_fixed(tracking_em, 2), excerpt),
                    ));
                }
            }
        }
    }

    findings
}

/// JS: checks.mjs#checkElementQualityDOM(el)
pub fn check_element_quality_dom(dom: &dyn Dom, el: ElId, config: &BrowserConfig) -> Vec<RuleHit> {
    let tag = tag_lower(dom, el);
    let has_direct_text = has_direct_text_longer_than(dom, el, 10);
    let text_len = utf16_len(js::trim(&dom.text_content(el)));
    let font_size = {
        let n = parse_float(&dom.style(el, "fontSize"));
        if crate::js_ext_a::num_truthy(n) {
            n
        } else {
            16.0
        }
    };
    let line_height_px = resolve_length_px(Some(&dom.style(el, "lineHeight")), font_size);
    let letter_spacing_px = resolve_length_px(Some(&dom.style(el, "letterSpacing")), font_size);
    let rect = dom.rect(el);
    let line_max = config.line_max();
    let viewport_width = {
        let w = dom.inner_width();
        if crate::js_ext_a::num_truthy(w) {
            w
        } else {
            0.0
        }
    };
    check_quality(
        dom,
        &QualityInput {
            el,
            tag,
            has_direct_text,
            text_len,
            font_size,
            line_height_px,
            letter_spacing_px,
            rect,
            line_max,
            viewport_width,
        },
    )
}

/// JS: checks.mjs#checkPageQualityFromDoc(doc)
pub fn check_page_quality_from_doc(dom: &dyn Dom) -> Vec<RuleHit> {
    let mut findings = Vec::new();
    let mut prev_level: i64 = 0;
    let mut prev_text = String::new();
    for h in dom.query_all(None, "h1, h2, h3, h4, h5, h6").unwrap_or_default() {
        let tag = dom.tag_name(h);
        // JS `parseInt(h.tagName[1])`
        let level = js::parse_int(&tag.chars().nth(1).map(|c| c.to_string()).unwrap_or_default(), 10);
        let level = if level.is_nan() { 0 } else { level as i64 };
        let text = slice_utf16_prefix(&collapse_ws(js::trim(&dom.text_content(h))), 60);
        if prev_level > 0 && level > prev_level + 1 {
            findings.push(RuleHit::new(
                "skipped-heading",
                format!(
                    "<h{}> \"{}\" followed by <h{}> \"{}\" (missing h{})",
                    prev_level,
                    prev_text,
                    level,
                    text,
                    prev_level + 1
                ),
            ));
        }
        prev_level = level;
        prev_text = text;
    }
    findings
}

/// JS: checks.mjs#checkPageQualityDOM() — `{ type, detail }` shape.
pub fn check_page_quality_dom(dom: &dyn Dom) -> Vec<BrowserFinding> {
    check_page_quality_from_doc(dom)
        .iter()
        .map(BrowserFinding::from_hit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::fake_dom::FakeDom;

    fn text_el(d: &mut FakeDom, body: ElId, tag: &str, text: &str, font: &str) -> ElId {
        let p = d.add(Some(body), tag);
        d.add_text(p, text);
        d.set_styles(
            p,
            &[
                ("fontSize", font),
                ("lineHeight", "normal"),
                ("letterSpacing", "normal"),
                ("backgroundColor", "rgba(0, 0, 0, 0)"),
                ("position", "static"),
                ("textTransform", "none"),
                ("textAlign", "start"),
            ],
        );
        p
    }

    #[test]
    fn line_length_and_viewport_edge() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let long = "x".repeat(240);
        let p = text_el(&mut d, body, "p", &long, "16px");
        d.set_rect(p, 0.0, 100.0, 1200.0, 72.0);
        // Three rendered lines: two full ones and a tail.
        d.set_text_lines(p, &[(0.0, 100.0, 1180.0, 19.0), (0.0, 124.0, 1180.0, 19.0), (0.0, 148.0, 400.0, 19.0)]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert!(ids.contains(&"line-length"), "{ids:?}");
        assert_eq!(hits[0].snippet, "~103 chars on 2 of 3 rendered lines (aim for <80)");
        assert!(ids.contains(&"body-text-viewport-edge"));
        let edge = hits.iter().find(|h| h.id == "body-text-viewport-edge").unwrap();
        assert_eq!(edge.snippet, "<p> with 240-char body bleeds to viewport edge (left 0px)");
        // narrower, inset paragraph: neither fires
        d.set_rect(p, 40.0, 100.0, 600.0, 72.0);
        d.set_text_lines(p, &[(40.0, 100.0, 580.0, 19.0), (40.0, 124.0, 580.0, 19.0), (40.0, 148.0, 580.0, 19.0)]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        assert!(hits.is_empty(), "{hits:?}");
    }

    /// REN-402. Halfday's pricing copy: a 158-character paragraph in a 1022px
    /// card body, rendering 145 characters on its first line and 13 on its
    /// second. The old measurement charged the box (`1022 / (15 * 0.5)` = 136
    /// "chars/line") on every paragraph that shape, including the ones whose
    /// text stops well short of the box.
    #[test]
    fn line_length_reads_the_rendered_line_not_the_box() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let copy = "People are counted on the first of the month. Someone invited on the 3rd is free until the 1st, and someone removed mid-month is credited on the next invoice.";
        assert_eq!(copy.chars().count(), 158);
        let p = text_el(&mut d, body, "p", copy, "15px");
        d.set_style(p, "lineHeight", "24px");
        d.set_rect(p, 200.0, 971.0, 1022.0, 48.0);
        // One long line and a 13-character tail: the eye tracks back once.
        d.set_text_lines(p, &[(200.0, 974.0, 995.4, 18.0), (200.0, 998.0, 85.5, 18.0)]);
        assert_eq!(check_element_quality_dom(&d, p, &BrowserConfig::default()), vec![]);

        // The same box, text that stops at 571px: 89 characters on one line.
        let meta = text_el(&mut d, body, "p", &"y".repeat(89), "14px");
        d.set_style(meta, "lineHeight", "21.7px");
        d.set_rect(meta, 200.0, 122.0, 992.0, 21.7);
        d.set_text_lines(meta, &[(200.0, 124.2, 571.4, 17.0)]);
        assert_eq!(check_element_quality_dom(&d, meta, &BrowserConfig::default()), vec![]);

        // A column of long lines is the defect the rule is named for.
        let wall = text_el(&mut d, body, "p", &"z".repeat(500), "15px");
        d.set_style(wall, "lineHeight", "24px");
        d.set_rect(wall, 200.0, 100.0, 1022.0, 96.0);
        d.set_text_lines(
            wall,
            &[
                (200.0, 100.0, 1000.0, 18.0),
                (200.0, 124.0, 1000.0, 18.0),
                (200.0, 148.0, 1000.0, 18.0),
                (200.0, 172.0, 600.0, 18.0),
            ],
        );
        let hits = check_element_quality_dom(&d, wall, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].snippet, "~139 chars on 3 of 4 rendered lines (aim for <80)");
    }

    /// A line box split across text nodes is still one line. An inline
    /// `<strong>` or `<a>` in the middle of a sentence is its own text node,
    /// so `getClientRects()` hands back a rect per fragment; counting each
    /// fragment as a line divided the paragraph's characters among them and
    /// hid a genuinely long column.
    #[test]
    fn a_line_split_across_fragments_is_one_line() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        // 300 characters over three rendered lines, each interrupted mid-line
        // by an inline element and so measured in two pieces.
        let p = text_el(&mut d, body, "p", &"w".repeat(300), "16px");
        d.set_rect(p, 0.0, 100.0, 1020.0, 72.0);
        d.set_text_lines(
            p,
            &[
                (0.0, 100.0, 520.0, 19.0),
                (520.0, 100.0, 480.0, 19.0),
                (0.0, 124.0, 510.0, 19.0),
                (510.0, 124.0, 490.0, 19.0),
                (0.0, 148.0, 505.0, 19.0),
                (505.0, 148.0, 495.0, 19.0),
            ],
        );
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        let line = hits.iter().find(|h| h.id == "line-length").expect("charged");
        // Three lines of 1000px, not six of ~500: six would have put 50
        // characters on each and charged nothing at all.
        assert_eq!(line.snippet, "~100 chars on 3 of 3 rendered lines (aim for <80)");

        // The same merge the other way: one long line in two fragments plus a
        // short tail is two lines, and one long line is a sentence that
        // wrapped once.
        let q = text_el(&mut d, body, "p", &"w".repeat(190), "16px");
        d.set_rect(q, 0.0, 300.0, 1020.0, 48.0);
        d.set_text_lines(
            q,
            &[
                (0.0, 300.0, 600.0, 19.0),
                (600.0, 300.0, 400.0, 19.0),
                (0.0, 324.0, 120.0, 19.0),
            ],
        );
        let hits = check_element_quality_dom(&d, q, &BrowserConfig::default());
        assert!(!hits.iter().any(|h| h.id == "line-length"), "{hits:?}");
    }

    /// Two columns that happen to sit on the same rows are two flows, not one
    /// page-wide line. Fragments join a row only when they run on from it —
    /// a gap no wider than the row's own line box — so a gutter keeps them
    /// apart and the characters stay where the reader sees them.
    #[test]
    fn columns_on_the_same_rows_are_separate_lines() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = text_el(&mut d, body, "p", &"w".repeat(240), "16px");
        d.set_rect(p, 0.0, 100.0, 1020.0, 72.0);
        // Two 300px columns with a 100px gutter, three rows each.
        d.set_text_lines(
            p,
            &[
                (0.0, 100.0, 300.0, 19.0),
                (400.0, 100.0, 300.0, 19.0),
                (0.0, 124.0, 300.0, 19.0),
                (400.0, 124.0, 300.0, 19.0),
                (0.0, 148.0, 300.0, 19.0),
                (400.0, 148.0, 300.0, 19.0),
            ],
        );
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        // Six short lines of 40 characters each, not three of 700px.
        assert!(!hits.iter().any(|h| h.id == "line-length"), "{hits:?}");
    }

    /// A rect that is already one line is one line, whatever the leading is.
    /// Dividing every rect by the line box turned a paragraph whose leading
    /// is tighter than its glyph box into two copies of the same line, and
    /// two copies of one long line satisfied "at least two long lines".
    #[test]
    fn tight_leading_does_not_double_count_a_line() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = text_el(&mut d, body, "p", &"w".repeat(200), "15px");
        // 10px of leading under an 19px glyph box: `round(19 / 10)` is 2.
        d.set_style(p, "lineHeight", "10px");
        d.set_rect(p, 0.0, 100.0, 1020.0, 19.0);
        d.set_text_lines(p, &[(0.0, 100.0, 1000.0, 19.0)]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        assert!(!hits.iter().any(|h| h.id == "line-length"), "{hits:?}");
    }

    /// A DOM that kept only the union of its text rects cannot say where the
    /// lines are, and the rule stands down rather than inventing them. A
    /// snapshot captured before the lines were recorded is that DOM: the
    /// union of a long first line and a short tail is the same union as two
    /// even lines, so any width read off it is a width nothing rendered.
    #[test]
    fn a_dom_without_lines_does_not_charge_line_length() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = text_el(&mut d, body, "p", &"w".repeat(300), "16px");
        d.set_rect(p, 0.0, 100.0, 1020.0, 72.0);
        // The same paragraph the merge test charges, measured once.
        d.set_text_rect(p, 0.0, 100.0, 1000.0, 67.0);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        assert!(!hits.iter().any(|h| h.id == "line-length"), "{hits:?}");
    }

    #[test]
    fn cramped_padding_vertical() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        d.set_style(body, "backgroundColor", "rgb(255, 255, 255)");
        let p = text_el(&mut d, body, "div", &"word ".repeat(10), "16px");
        d.set_rect(p, 40.0, 100.0, 300.0, 60.0);
        d.set_styles(
            p,
            &[
                ("backgroundColor", "rgb(240, 240, 240)"),
                ("borderTopWidth", "0px"),
                ("borderRightWidth", "0px"),
                ("borderBottomWidth", "0px"),
                ("borderLeftWidth", "0px"),
                ("paddingTop", "2px"),
                ("paddingBottom", "12px"),
                ("paddingLeft", "12px"),
                ("paddingRight", "12px"),
            ],
        );
        // The text lands 2px under the top edge, which is what the reader sees
        // and what the declared padding happens to say here.
        d.set_text_lines(p, &[(52.0, 102.0, 276.0, 19.0)]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].snippet,
            "2px of space above and below the text (need ≥4.8px for 16px text)"
        );
    }

    /// REN-403. Halfday's plan button: 44px tall because the design system
    /// says every control is, `padding: 0 16px`, and the label optically
    /// centred by a flex box. The declared vertical padding is zero and the
    /// space above the label is 12px, which is what the reader sees.
    #[test]
    fn cramped_padding_measures_the_space_around_the_text() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        d.set_style(body, "backgroundColor", "rgb(255, 255, 255)");
        let btn = text_el(&mut d, body, "a", "Talk to us about Studio", "15px");
        d.set_rect(btn, 0.0, 778.7, 296.7, 44.0);
        d.set_styles(
            btn,
            &[
                ("backgroundColor", "rgb(255, 255, 255)"),
                ("borderTopWidth", "1px"),
                ("borderRightWidth", "1px"),
                ("borderBottomWidth", "1px"),
                ("borderLeftWidth", "1px"),
                ("paddingTop", "0px"),
                ("paddingBottom", "0px"),
                ("paddingLeft", "16px"),
                ("paddingRight", "16px"),
                ("display", "flex"),
            ],
        );
        d.set_text_lines(btn, &[(68.0, 791.2, 160.0, 18.0)]);
        assert_eq!(check_element_quality_dom(&d, btn, &BrowserConfig::default()), vec![]);

        // The same control with the label actually against the edge: charged.
        d.set_text_lines(btn, &[(68.0, 780.2, 160.0, 18.0)]);
        let hits = check_element_quality_dom(&d, btn, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].snippet,
            "0.5px of space above and below the text (need ≥4.5px for 15px text)"
        );
    }

    #[test]
    fn flush_children_against_border() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let card = d.add(Some(body), "section");
        d.set_attr(card, "class", "card-frame extra");
        d.set_rect(card, 0.0, 0.0, 400.0, 200.0);
        d.set_styles(
            card,
            &[
                ("position", "static"),
                ("borderTopWidth", "1px"),
                ("borderRightWidth", "1px"),
                ("borderBottomWidth", "1px"),
                ("borderLeftWidth", "1px"),
                ("borderTopColor", "rgb(0, 0, 0)"),
                ("borderRightColor", "rgb(0, 0, 0)"),
                ("borderBottomColor", "rgb(0, 0, 0)"),
                ("borderLeftColor", "rgb(0, 0, 0)"),
                ("outlineWidth", "0px"),
                ("backgroundColor", "rgba(0, 0, 0, 0)"),
                ("paddingTop", "28px"),
                ("paddingRight", "0px"),
                ("paddingBottom", "0px"),
                ("paddingLeft", "0px"),
                ("fontSize", "16px"),
            ],
        );
        let p = text_el(&mut d, card, "p", "Hello there friend", "16px");
        d.set_rect(p, 0.0, 28.0, 400.0, 20.0);
        d.set_styles(p, &[("paddingTop", "0px"), ("paddingRight", "0px"), ("paddingBottom", "0px"), ("paddingLeft", "0px"), ("marginTop", "0px"), ("marginRight", "0px"), ("marginBottom", "0px"), ("marginLeft", "0px")]);
        let hits = check_element_quality_dom(&d, card, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].snippet,
            "<section> \"card-frame\": children flush against border on right/left (no inset)"
        );
    }

    /// REN-403, the wrapper half of the same rule. Crewline's framed table:
    /// the `<table>` fills the frame edge to edge, and every cell insets its
    /// own text by the padding the stylesheet gives it. Reading the cell's
    /// border box called all four sides flush.
    #[test]
    fn flush_reads_the_text_not_the_cell_that_holds_it() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        d.set_style(body, "backgroundColor", "rgb(255, 255, 255)");
        let frame = d.add(Some(body), "div");
        d.set_attr(frame, "class", "table-frame");
        d.set_rect(frame, 0.0, 0.0, 860.0, 300.0);
        d.set_styles(
            frame,
            &[
                ("position", "static"),
                ("borderTopWidth", "1px"),
                ("borderRightWidth", "1px"),
                ("borderBottomWidth", "1px"),
                ("borderLeftWidth", "1px"),
                ("borderTopColor", "rgb(220, 220, 220)"),
                ("borderRightColor", "rgb(220, 220, 220)"),
                ("borderBottomColor", "rgb(220, 220, 220)"),
                ("borderLeftColor", "rgb(220, 220, 220)"),
                ("outlineWidth", "0px"),
                ("backgroundColor", "rgb(250, 250, 250)"),
                ("paddingTop", "0px"),
                ("paddingRight", "0px"),
                ("paddingBottom", "0px"),
                ("paddingLeft", "0px"),
                ("fontSize", "15px"),
            ],
        );
        let table = d.add(Some(frame), "table");
        d.set_rect(table, 0.0, 0.0, 860.0, 300.0);
        for (i, (x, y, w)) in [(0.0, 0.0, 430.0), (430.0, 0.0, 430.0), (0.0, 260.0, 430.0)]
            .into_iter()
            .enumerate()
        {
            let cell = d.add(Some(table), "td");
            d.add_text(cell, "Wednesday afternoon");
            d.set_rect(cell, x, y, w, 20.0);
            // Cell padding: 10px down, 16px across, which is where the text is.
            d.set_text_lines(cell, &[(x + 16.0, y + 10.0, w - 32.0, 17.0)]);
            let _ = i;
        }
        assert_eq!(check_element_quality_dom(&d, frame, &BrowserConfig::default()), vec![]);

        // A cell that really does put its text on the frame line is charged.
        let tight = d.add(Some(table), "td");
        d.add_text(tight, "Wednesday afternoon");
        d.set_rect(tight, 0.0, 140.0, 860.0, 20.0);
        d.set_text_lines(tight, &[(1.0, 140.0, 858.0, 17.0)]);
        let hits = check_element_quality_dom(&d, frame, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].snippet,
            "<div> \"table-frame\": children flush against border+bg on right/left (no inset)"
        );

        // The same frame at 390px, where the table keeps its min-width and the
        // frame hides what does not fit: the right side is clipped, not snug,
        // and that is `clipped-overflow-container`'s business (REN-403).
        d.set_rect(table, 0.0, 0.0, 1400.0, 300.0);
        let hits = check_element_quality_dom(&d, frame, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].snippet,
            "<div> \"table-frame\": children flush against border+bg on left (no inset)"
        );
    }

    #[test]
    fn typography_rules() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let text = "a".repeat(60);
        let p = text_el(&mut d, body, "p", &text, "16px");
        d.set_rect(p, 40.0, 100.0, 300.0, 40.0);
        d.set_styles(p, &[("lineHeight", "16px"), ("textAlign", "justify"), ("hyphens", "manual"), ("letterSpacing", "2px")]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, vec!["tight-leading", "justified-text", "wide-tracking"], "{hits:?}");
        assert_eq!(hits[0].snippet, "line-height 1.00x (need >=1.3)");
        assert_eq!(hits[2].snippet, "letter-spacing: 0.13em on body text");
        d.set_styles(p, &[("lineHeight", "24px"), ("textAlign", "left"), ("letterSpacing", "-1px"), ("textTransform", "uppercase")]);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, vec!["all-caps-body", "extreme-negative-tracking"], "{hits:?}");
        assert_eq!(hits[1].snippet, format!("letter-spacing: -0.06em — \"{}\"", "a".repeat(40)));
    }

    #[test]
    fn tiny_and_undersized_text() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = text_el(&mut d, body, "p", "This is small body copy text", "10px");
        d.set_rect(p, 40.0, 100.0, 300.0, 40.0);
        let hits = check_element_quality_dom(&d, p, &BrowserConfig::default());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, vec!["tiny-text"], "{hits:?}");
        assert_eq!(hits[0].snippet, "10px body text");
        // short functional label under 11px
        let s = text_el(&mut d, body, "span", "Meta 12:00", "9px");
        d.set_rect(s, 40.0, 100.0, 60.0, 12.0);
        let hits = check_element_quality_dom(&d, s, &BrowserConfig::default());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].snippet, "9px functional text \"Meta 12:00\" (below 11px floor)");
        // smallprint context softens the floor to 10px
        d.add_selector(s, SMALLPRINT);
        d.set_style(s, "fontSize", "10px");
        assert!(check_element_quality_dom(&d, s, &BrowserConfig::default()).is_empty());
        // sr-only exempts
        d.set_style(s, "fontSize", "9px");
        d.add_selector(s, SR_ONLY_SELECTOR);
        assert!(check_element_quality_dom(&d, s, &BrowserConfig::default()).is_empty());
    }

    #[test]
    fn skipped_heading() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let h1 = d.add(Some(body), "h1");
        d.add_text(h1, "  Title   here ");
        let h3 = d.add(Some(body), "h3");
        d.add_text(h3, "Sub");
        let f = check_page_quality_dom(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].type_, "skipped-heading");
        assert_eq!(f[0].detail, "<h1> \"Title here\" followed by <h3> \"Sub\" (missing h2)");
    }

    #[test]
    fn visually_hidden_and_non_rendered() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let s = d.add(Some(body), "span");
        d.set_styles(s, &[("position", "absolute"), ("clip", "rect(0px, 0px, 0px, 0px)")]);
        assert!(is_visually_hidden(&d, s));
        d.set_styles(s, &[("clip", "auto"), ("width", "1px"), ("height", "20px"), ("overflow", "hidden")]);
        assert!(is_visually_hidden(&d, s));
        d.set_style(s, "overflow", "visible");
        assert!(!is_visually_hidden(&d, s));
        assert!(is_non_rendered_text(&d, s, "script"));
        d.set_style(s, "visibility", "collapse");
        assert!(is_non_rendered_text(&d, s, "span"));
    }
}

#[cfg(test)]
mod rendered_text_tests {
    use super::*;
    use crate::browser::fake_dom::FakeDom;

    /// A paragraph over two rendered lines of 640px and 260px, as
    /// directus.io's hero paragraph rendered.
    fn two_line_p(d: &mut FakeDom, body: ElId) -> ElId {
        let p = d.add(Some(body), "p");
        d.set_styles(
            p,
            &[
                ("fontSize", "18px"),
                ("lineHeight", "normal"),
                ("letterSpacing", "normal"),
                ("backgroundColor", "rgba(0, 0, 0, 0)"),
                ("position", "static"),
                ("textTransform", "none"),
                ("textAlign", "start"),
                ("whiteSpace", "normal"),
            ],
        );
        d.set_rect(p, 100.0, 270.0, 700.0, 56.0);
        d.set_text_lines(p, &[(100.0, 272.0, 640.0, 24.0), (100.0, 300.0, 260.0, 24.0)]);
        p
    }

    fn line_length(d: &FakeDom, el: ElId) -> Option<String> {
        check_element_quality_dom(d, el, &BrowserConfig::default())
            .into_iter()
            .find(|h| h.id == "line-length")
            .map(|h| h.snippet)
    }

    const SENTENCE: &str = "The collaborative backend that turns any database into an API your whole team can use today.";

    /// An inline `<style>` child is in `textContent` and on no line. Its 240
    /// characters were shared out between the two rendered lines and turned
    /// a 66-character line into a 240-character one.
    #[test]
    fn an_inline_style_child_is_not_counted() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        let style = d.add(Some(p), "style");
        d.set_style(style, "display", "none");
        d.add_text(style, &"@keyframes blink { 0%, 50% { opacity: 1; } } ".repeat(6));
        d.add_text(p, SENTENCE);
        assert_eq!(rendered_text_len(&d, p), SENTENCE.len());
        assert_eq!(line_length(&d, p), None);

        // The same lines with that many characters of prose do report.
        let q = two_line_p(&mut d, body);
        d.add_text(q, &"w".repeat(SENTENCE.len() + 270));
        assert_eq!(
            line_length(&d, q).as_deref(),
            Some("~257 chars on 2 of 2 rendered lines (aim for <80)")
        );
    }

    /// A `display: none` child and a `<script>` are cut the same way, and a
    /// rendered inline child stays in.
    #[test]
    fn hidden_and_script_children_are_cut_and_inline_children_kept() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.add_text(p, "Before ");
        let hidden = d.add(Some(p), "span");
        d.set_style(hidden, "display", "none");
        d.add_text(hidden, &"hidden ".repeat(40));
        let strong = d.add(Some(p), "strong");
        d.set_style(strong, "display", "inline");
        d.add_text(strong, "kept");
        let script = d.add(Some(p), "script");
        d.add_text(script, &"var x = 1; ".repeat(30));
        d.add_text(p, " after");
        assert_eq!(rendered_text_len(&d, p), "Before kept after".len());
    }

    /// Source indentation collapses to one space under `white-space: normal`
    /// and is kept under `pre-wrap`.
    #[test]
    fn source_indentation_collapses_unless_preserved() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.add_text(p, "\n        Copyright 2017, all rights reserved\n                with the Directorate.\n    ");
        assert_eq!(
            rendered_text_len(&d, p),
            "Copyright 2017, all rights reserved with the Directorate.".len()
        );
        d.set_style(p, "whiteSpace", "pre-wrap");
        assert_eq!(
            rendered_text_len(&d, p),
            "Copyright 2017, all rights reserved\n                with the Directorate.".len()
        );
    }

    /// A combining mark sits on its base and a zero-width joiner or soft
    /// hyphen draws nothing, so none of them is a character on the line.
    #[test]
    fn combining_marks_and_format_characters_are_not_counted() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        // "राजस्थान के": र ा ज स ् थ ा न, a space, क े.
        d.add_text(p, "\u{930}\u{93e}\u{91c}\u{938}\u{94d}\u{925}\u{93e}\u{928} \u{915}\u{947}");
        assert_eq!(rendered_text_len(&d, p), 7);
        let q = two_line_p(&mut d, body);
        d.add_text(q, "cafe\u{301} co\u{ad}operate\u{200b}s");
        assert_eq!(rendered_text_len(&d, q), "cafe cooperates".len());
    }

    /// Plain prose counts as before, so a long column still reports the same
    /// number.
    #[test]
    fn plain_prose_counts_every_character() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.set_text_lines(p, &[(100.0, 272.0, 640.0, 24.0), (100.0, 300.0, 640.0, 24.0)]);
        d.add_text(p, &"word ".repeat(40));
        assert_eq!(rendered_text_len(&d, p), 199);
        assert_eq!(
            line_length(&d, p).as_deref(),
            Some("~100 chars on 2 of 2 rendered lines (aim for <80)")
        );
    }

    /// Each text node keeps or folds its white space by the `white-space` it
    /// inherits, not the paragraph's. A `pre-wrap` span inside a normal
    /// paragraph keeps its runs of spaces on the line, so it counts the same
    /// as a `pre-wrap` paragraph and flags the same long lines.
    #[test]
    fn a_preserving_span_inside_a_normal_paragraph_keeps_its_spaces() {
        let text = "word    ".repeat(22);
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.set_text_lines(p, &[(100.0, 272.0, 640.0, 24.0), (100.0, 300.0, 640.0, 24.0)]);
        d.add_text(p, "An opening line ");
        let span = d.add(Some(p), "span");
        d.set_style(span, "display", "inline");
        d.set_style(span, "whiteSpace", "pre-wrap");
        d.add_text(span, &text);
        assert_eq!(rendered_text_len(&d, p), "An opening line ".len() + 22 * 8 - 4);

        let whole = two_line_p(&mut d, body);
        d.set_text_lines(whole, &[(100.0, 272.0, 640.0, 24.0), (100.0, 300.0, 640.0, 24.0)]);
        d.set_style(whole, "whiteSpace", "pre-wrap");
        d.add_text(whole, &format!("An opening line {text}"));
        assert_eq!(rendered_text_len(&d, whole), rendered_text_len(&d, p));
        assert_eq!(line_length(&d, p), line_length(&d, whole));
        assert_eq!(
            line_length(&d, p).as_deref(),
            Some("~94 chars on 2 of 2 rendered lines (aim for <80)")
        );

        // The reverse: a normal span inside a pre-wrap paragraph folds its
        // own runs, and a collapsible run carries on across the boundary of
        // an inline child the way `a <b> b</b>` renders one space.
        let q = two_line_p(&mut d, body);
        d.set_style(q, "whiteSpace", "pre-wrap");
        d.add_text(q, "a  b");
        let normal = d.add(Some(q), "span");
        d.set_style(normal, "display", "inline");
        d.set_style(normal, "whiteSpace", "normal");
        d.add_text(normal, "   c   d");
        assert_eq!(rendered_text_len(&d, q), "a  b c d".len());
        let r = two_line_p(&mut d, body);
        d.add_text(r, "a ");
        let b = d.add(Some(r), "b");
        d.set_style(b, "display", "inline");
        d.add_text(b, " b");
        assert_eq!(rendered_text_len(&d, r), "a b".len());
    }

    /// The text of a hidden child is skipped where it sits, so a hidden run
    /// of white space never takes a visible space with it.
    #[test]
    fn a_hidden_child_is_skipped_where_it_sits() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.add_text(p, "one two");
        let hidden = d.add(Some(p), "span");
        d.set_style(hidden, "display", "none");
        d.add_text(hidden, " ");
        assert_eq!(rendered_text_len(&d, p), "one two".len());

        let q = two_line_p(&mut d, body);
        d.add_text(q, "one two three four");
        for _ in 0..3 {
            let hidden = d.add(Some(q), "span");
            d.set_style(hidden, "display", "none");
            d.add_text(hidden, " ");
            d.add_text(q, "x");
        }
        assert_eq!(rendered_text_len(&d, q), "one two three fourxxx".len());
    }

    /// A `content-visibility: hidden` child lays out its box and renders none
    /// of its contents, so its text is on no line. A DOM that cannot say
    /// (no `contentVisibility` value) counts it.
    #[test]
    fn a_content_visibility_hidden_child_is_skipped() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        let p = two_line_p(&mut d, body);
        d.add_text(p, "Before ");
        let skipped = d.add(Some(p), "span");
        d.set_style(skipped, "display", "inline-block");
        d.set_style(skipped, "contentVisibility", "hidden");
        d.add_text(skipped, &"unrendered ".repeat(30));
        d.add_text(p, "after");
        assert_eq!(rendered_text_len(&d, p), "Before after".len());

        let q = two_line_p(&mut d, body);
        d.add_text(q, "Before ");
        let unknown = d.add(Some(q), "span");
        d.set_style(unknown, "display", "inline");
        d.add_text(unknown, "kept ");
        d.add_text(q, "after");
        assert_eq!(rendered_text_len(&d, q), "Before kept after".len());

        // content-visibility does not apply to a plain inline box or to
        // display: contents, so their text renders and counts.
        for display in ["inline", "contents"] {
            let r = two_line_p(&mut d, body);
            d.add_text(r, "Before ");
            let inline = d.add(Some(r), "span");
            d.set_style(inline, "display", display);
            d.set_style(inline, "contentVisibility", "hidden");
            d.add_text(inline, "shown ");
            d.add_text(r, "after");
            assert_eq!(rendered_text_len(&d, r), "Before shown after".len(), "{display}");
        }
    }

    /// An image or an inline-block is an atomic inline: the space on each
    /// side of it renders, so the pair does not fold into one, and a
    /// populated box's own edge white space is trimmed inside it.
    #[test]
    fn spaces_around_an_atomic_inline_both_count() {
        let mut d = FakeDom::new();
        let (_h, body) = d.with_page();
        for (tag, display) in [("img", "inline"), ("span", "inline-block")] {
            let r = two_line_p(&mut d, body);
            d.add_text(r, "word ");
            let boxed = d.add(Some(r), tag);
            d.set_style(boxed, "display", display);
            d.add_text(r, " word");
            assert_eq!(rendered_text_len(&d, r), "word  word".len(), "{tag}");
        }

        // A populated box trims its own edge white space in its own
        // formatting context: none of it joins the spaces outside.
        for (tag, display) in [("span", "inline-block"), ("button", "inline-block")] {
            let r = two_line_p(&mut d, body);
            d.add_text(r, "word ");
            let boxed = d.add(Some(r), tag);
            d.set_style(boxed, "display", display);
            d.add_text(boxed, "\n      word\n    ");
            d.add_text(r, " word");
            assert_eq!(rendered_text_len(&d, r), "word word word".len(), "{tag}");
        }

        // Edge spaces that cannot collapse render inside the box: preserved
        // ones under white-space: pre, and no-break spaces.
        let r = two_line_p(&mut d, body);
        d.add_text(r, "word ");
        let pre = d.add(Some(r), "span");
        d.set_style(pre, "display", "inline-block");
        d.set_style(pre, "whiteSpace", "pre");
        d.add_text(pre, " word ");
        d.add_text(r, " word");
        assert_eq!(rendered_text_len(&d, r), "word  word  word".len());

        let r = two_line_p(&mut d, body);
        d.add_text(r, "word ");
        let nbsp = d.add(Some(r), "span");
        d.set_style(nbsp, "display", "inline-block");
        d.add_text(nbsp, "\u{a0}word\u{a0}");
        d.add_text(r, " word");
        assert_eq!(rendered_text_len(&d, r), "word _word_ word".len());
    }
}
