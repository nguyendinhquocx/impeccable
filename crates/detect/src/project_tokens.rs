//! The custom properties a project declares across its stylesheets: what a
//! `var(--danger)` in one component holds when the token lives in another
//! file (a `tokens.css`, a theme sheet). The text engine reads one file at a
//! time, so the CLI collects these once per project and hands them to every
//! file it scans there.

use std::collections::HashMap;
use std::rc::Rc;

use impeccable_core::checks::css_scan::{collect_css_custom_props, CustomProps};

use crate::file_system::SKIP_DIRS;
use crate::jsp;
use crate::util::exists;

static COMMENT_RE: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"(?s)/\*.*?\*/").expect("COMMENT_RE"));

static LINE_COMMENT_RE: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r#"(?m)(^|[^:"'(\\])//[^\n]*"#).expect("LINE_COMMENT_RE"));

const SHEET_EXTS: &[&str] = &[".css", ".scss", ".sass", ".less"];
/// Bounds on the walk: a token sheet is small, and a project with more
/// sheets or entries than this has its tokens among the ones read first or
/// not at all.
const MAX_SHEETS: usize = 2000;
const MAX_ENTRIES: usize = 100_000;
const MAX_SHEET_BYTES: u64 = 512 * 1024;
/// Build output and dependencies the source walk keeps out of, beside the
/// ones `detect` skips.
const SKIP_TOO: &[&str] = &["target", "vendor", "coverage", "out"];

/// The project a file belongs to: the nearest enclosing git checkout, else
/// the nearest package, else the file's own directory.
pub fn project_root(file_path: &str) -> String {
    let start = jsp::dirname(&jsp::resolve(file_path, &[]));
    let nearest = |marker: &str| {
        let mut dir = start.clone();
        loop {
            if exists(&jsp::join(&[&dir, marker])) {
                return Some(dir);
            }
            let parent = jsp::dirname(&dir);
            if parent == dir {
                return None;
            }
            dir = parent;
        }
    };
    nearest(".git").or_else(|| nearest("package.json")).unwrap_or(start)
}

/// Every custom property declared in the stylesheets under `root`, first
/// declaration wins (a light theme before its dark override, as the scan
/// reads one file).
pub fn collect_project_tokens(root: &str) -> CustomProps {
    let mut tokens = CustomProps::new();
    for sheet in stylesheets(root) {
        let Some(text) = read_sheet(&sheet) else {
            continue;
        };
        if !text.contains("--") {
            continue;
        }
        // A commented-out declaration is not the token's value: `/* */`
        // everywhere, `//` lines in the preprocessor dialects.
        let mut text = COMMENT_RE.replace_all(&text, " ").into_owned();
        if !sheet.to_ascii_lowercase().ends_with(".css") {
            text = LINE_COMMENT_RE.replace_all(&text, "$1").into_owned();
        }
        for (name, value) in collect_css_custom_props(&text).iter() {
            if !tokens.has(name) {
                tokens.set(name, value.clone());
            }
        }
    }
    tokens
}

/// A sheet's text: a regular file (not a link to a device or elsewhere),
/// read no further than the size bound.
fn read_sheet(path: &str) -> Option<String> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SHEET_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(MAX_SHEET_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_SHEET_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// The stylesheets under `root`, breadth first so a shallow token sheet
/// comes before deep ones, within the walk's bounds.
fn stylesheets(root: &str) -> Vec<String> {
    let mut sheets = Vec::new();
    let mut queue = std::collections::VecDeque::from([root.to_string()]);
    let mut entries = 0usize;
    while let Some(dir) = queue.pop_front() {
        let Ok(read) = std::fs::read_dir(&dir) else { continue };
        let mut names: Vec<(String, bool)> = read
            .flatten()
            .map(|e| {
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                (e.file_name().to_string_lossy().into_owned(), is_dir)
            })
            .collect();
        names.sort();
        for (name, is_dir) in names {
            entries += 1;
            if entries > MAX_ENTRIES || sheets.len() >= MAX_SHEETS {
                return sheets;
            }
            if is_dir {
                if !name.starts_with('.')
                    && !SKIP_DIRS.contains(&name.as_str())
                    && !SKIP_TOO.contains(&name.as_str())
                {
                    queue.push_back(jsp::join(&[&dir, &name]));
                }
            } else if SHEET_EXTS.iter().any(|ext| name.to_ascii_lowercase().ends_with(ext)) {
                sheets.push(jsp::join(&[&dir, &name]));
            }
        }
    }
    sheets
}

/// Project tokens, collected once per project root.
#[derive(Default)]
pub struct ProjectTokens {
    by_root: HashMap<String, Rc<CustomProps>>,
}

impl ProjectTokens {
    pub fn for_file(&mut self, file_path: &str) -> Rc<CustomProps> {
        let root = project_root(file_path);
        self.by_root
            .entry(root)
            .or_insert_with_key(|root| Rc::new(collect_project_tokens(root)))
            .clone()
    }
}

/// Whether a file could hold a stripe whose colour is a token: the only
/// reader of project tokens, so files without one skip the walk.
pub fn may_need_tokens(content: &str) -> bool {
    content.contains("var(") && (content.contains("inset") || content.contains("border-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_come_from_every_sheet_in_the_project() {
        let dir = std::env::temp_dir().join(format!("impeccable-tokens-{}", std::process::id()));
        let root = dir.to_string_lossy().into_owned();
        std::fs::create_dir_all(dir.join("design-system")).unwrap();
        std::fs::create_dir_all(dir.join("app/src")).unwrap();
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        std::fs::write(
            dir.join("design-system/tokens.css"),
            "/* --mark-danger: #ddd; */\n:root { --mark-danger: oklch(63% .23 27); }\n[data-theme=dark] { --mark-danger: #f00; }\n",
        )
        .unwrap();
        std::fs::write(dir.join("design-system/theme.scss"), "// --mark-ok: #ddd;\n:root { --mark-ok: #16a34a; }\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/dev/zero", dir.join("design-system/zero.css")).unwrap();
        let file = dir.join("app/src/Table.svelte").to_string_lossy().into_owned();
        assert_eq!(project_root(&file), root);
        let tokens = ProjectTokens::default().for_file(&file);
        assert_eq!(tokens.get("--mark-danger").map(String::as_str), Some("oklch(63% .23 27)"));
        assert_eq!(tokens.get("--mark-ok").map(String::as_str), Some("#16a34a"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
