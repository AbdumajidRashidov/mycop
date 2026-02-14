use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::language::Language;

/// Discover files to scan, respecting .gitignore
pub fn discover_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() {
            if Language::from_extension(path).is_some() {
                files.push(path.clone());
            }
        } else if path.is_dir() {
            let walker = WalkBuilder::new(path)
                .hidden(true)
                .git_ignore(true)
                .git_global(true)
                .git_exclude(true)
                .build();

            for entry in walker {
                let entry = entry?;
                let entry_path = entry.path();
                if entry_path.is_file() && Language::from_extension(entry_path).is_some() {
                    files.push(entry_path.to_path_buf());
                }
            }
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

/// Discover only files changed in git diff (for --diff mode)
pub fn discover_diff_files(base: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", "HEAD"])
        .current_dir(base)
        .output()?;

    if !output.status.success() {
        // Try against empty tree (initial commit)
        let output = Command::new("git")
            .args(["diff", "--name-only", "--cached"])
            .current_dir(base)
            .output()?;

        if !output.status.success() {
            anyhow::bail!("Failed to get git diff. Are you in a git repository?");
        }

        return parse_git_output(&output.stdout, base);
    }

    // Also get staged files
    let staged_output = Command::new("git")
        .args(["diff", "--name-only", "--cached", "--diff-filter=ACMR"])
        .current_dir(base)
        .output()?;

    let mut files = parse_git_output(&output.stdout, base)?;
    if staged_output.status.success() {
        files.extend(parse_git_output(&staged_output.stdout, base)?);
    }

    files.sort();
    files.dedup();
    Ok(files)
}

fn parse_git_output(output: &[u8], base: &Path) -> Result<Vec<PathBuf>> {
    let text = String::from_utf8_lossy(output);
    let files: Vec<PathBuf> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| base.join(l))
        .filter(|p| Language::from_extension(p).is_some())
        .collect();
    Ok(files)
}
