//! Git repository layout, read from disk. Nothing here spawns `git`: the hook
//! runs on every edit, and git may not be installed.

use crate::jsp;

/// The `info/exclude` git reads for the repository whose gitdir is the
/// absolute path `git_dir`. A linked worktree's gitdir names the shared
/// directory in a `commondir` file, relative to itself, and git then ignores
/// the worktree's own `info`.
pub fn info_exclude(git_dir: &str) -> String {
    let common = match std::fs::read_to_string(jsp::join(&[git_dir, "commondir"])) {
        Ok(raw) => jsp::resolve(git_dir, &[raw.trim()]),
        Err(_) => git_dir.to_string(),
    };
    jsp::join(&[&common, "info", "exclude"])
}

/// The header line of every `.gitignore` the engine writes into a runtime
/// directory of the user's project.
pub const RUNTIME_IGNORE_HEADER: &str = "# Written by Impeccable: local runtime state, never committed.";

/// Makes sure `<dir>/.gitignore` ignores each of `patterns`, creating the
/// directory and the file when missing and appending only the patterns it
/// lacks, so it is cheap to call on every write and leaves the user's own
/// lines alone. A directory whose files are all runtime state passes `*`,
/// which also ignores the `.gitignore` itself, so no new file in it, the
/// ignore file included, reaches a commit. Files git already tracks stay
/// tracked: see `serve_question::tracked_runtime_notice`.
/// Best effort: a failure never fails the write it guards.
pub fn ensure_dir_ignored(dir: &str, patterns: &[&str]) {
    let file = jsp::join(&[dir, ".gitignore"]);
    let current = std::fs::read_to_string(&file).unwrap_or_default();
    let have: Vec<&str> = current.lines().map(str::trim).collect();
    let missing: Vec<&str> = patterns.iter().copied().filter(|p| !have.contains(p)).collect();
    if missing.is_empty() {
        return;
    }
    let mut next = current.clone();
    if next.is_empty() {
        next.push_str(RUNTIME_IGNORE_HEADER);
        next.push('\n');
    } else if !next.ends_with('\n') {
        next.push('\n');
    }
    for p in missing {
        next.push_str(p);
        next.push('\n');
    }
    let _ = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&file, next));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_exclude_follows_a_linked_worktrees_commondir() {
        let base = std::env::temp_dir().join(format!("impeccable-common-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tmp = base.to_string_lossy().into_owned();

        let plain = jsp::join(&[&tmp, "plain", ".git"]);
        assert_eq!(info_exclude(&plain), jsp::join(&[&plain, "info", "exclude"]));

        let worktree_git = jsp::join(&[&tmp, "repo", ".git", "worktrees", "wt"]);
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::write(jsp::join(&[&worktree_git, "commondir"]), "../..\n").unwrap();
        assert_eq!(
            info_exclude(&worktree_git),
            jsp::join(&[&tmp, "repo", ".git", "info", "exclude"])
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ensure_dir_ignored_writes_once_and_keeps_user_lines() {
        let dir = std::env::temp_dir().join(format!("impeccable-ignore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.join("q").to_string_lossy().into_owned();
        ensure_dir_ignored(&d, &["*"]);
        let file = dir.join("q/.gitignore");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{}\n*\n", RUNTIME_IGNORE_HEADER));
        ensure_dir_ignored(&d, &["*"]);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{}\n*\n", RUNTIME_IGNORE_HEADER), "idempotent");
        std::fs::write(&file, "mine.txt").unwrap();
        ensure_dir_ignored(&d, &["state.json"]);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "mine.txt\nstate.json\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
