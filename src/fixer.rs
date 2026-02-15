use colored::*;

/// Extract the fixed file content from AI response.
/// Looks for content between <FIXED_FILE> and </FIXED_FILE> tags.
/// Falls back to extracting from markdown code blocks if tags not found.
pub fn extract_fixed_file(response: &str) -> Option<String> {
    // Try XML tags first (preferred, reliable)
    if let Some(start) = response.find("<FIXED_FILE>") {
        let content_start = start + "<FIXED_FILE>".len();
        if let Some(end) = response[content_start..].find("</FIXED_FILE>") {
            let content = &response[content_start..content_start + end];
            let trimmed = content.strip_prefix('\n').unwrap_or(content);
            let trimmed = trimmed.strip_suffix('\n').unwrap_or(trimmed);
            return Some(trimmed.to_string());
        }
    }

    // Fallback: try markdown code block (```...```)
    let lines: Vec<&str> = response.lines().collect();
    let mut in_block = false;
    let mut code_lines = Vec::new();
    let mut found_block = false;

    for line in &lines {
        if line.trim().starts_with("```") {
            if in_block {
                found_block = true;
                break;
            }
            in_block = true;
            continue;
        }
        if in_block {
            code_lines.push(*line);
        }
    }

    if found_block && !code_lines.is_empty() {
        return Some(code_lines.join("\n"));
    }

    None
}

/// Generate a unified diff as a plain-text string (no colors)
#[allow(dead_code)]
pub fn diff_to_string(file_path: &str, old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let changes = compute_diff(&old_lines, &new_lines);

    if changes.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!("--- {}\n", file_path));
    out.push_str(&format!("+++ {}\n", file_path));

    for chunk in group_changes(&changes) {
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            chunk.old_start + 1,
            chunk.old_count,
            chunk.new_start + 1,
            chunk.new_count
        ));

        for change in &chunk.lines {
            match change {
                DiffLine::Context(line) => {
                    out.push_str(&format!(" {}\n", line));
                }
                DiffLine::Remove(line) => {
                    out.push_str(&format!("-{}\n", line));
                }
                DiffLine::Add(line) => {
                    out.push_str(&format!("+{}\n", line));
                }
            }
        }
    }

    out
}

/// Generate and print a colored unified diff between old and new content
pub fn print_diff(file_path: &str, old: &str, new: &str) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    // Simple line-by-line diff using longest common subsequence
    let changes = compute_diff(&old_lines, &new_lines);

    if changes.is_empty() {
        println!("  {} No changes detected", "=".dimmed());
        return;
    }

    println!("\n  {} {}", "---".red(), file_path);
    println!("  {} {}", "+++".green(), file_path);

    for chunk in group_changes(&changes) {
        // Print hunk header
        println!(
            "  {}",
            format!(
                "@@ -{},{} +{},{} @@",
                chunk.old_start + 1,
                chunk.old_count,
                chunk.new_start + 1,
                chunk.new_count
            )
            .cyan()
        );

        for change in &chunk.lines {
            match change {
                DiffLine::Context(line) => {
                    println!("   {}", line);
                }
                DiffLine::Remove(line) => {
                    println!("  {} {}", "-".red().bold(), line.red());
                }
                DiffLine::Add(line) => {
                    println!("  {} {}", "+".green().bold(), line.green());
                }
            }
        }
    }
    println!();
}

#[derive(Debug)]
enum DiffLine<'a> {
    Context(&'a str),
    Remove(&'a str),
    Add(&'a str),
}

struct DiffChunk<'a> {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<DiffLine<'a>>,
}

#[derive(Debug, Clone)]
enum Change<'a> {
    Equal(&'a str, usize, usize), // line, old_idx, new_idx
    Remove(&'a str, usize),       // line, old_idx
    Add(&'a str, usize),          // line, new_idx
}

fn compute_diff<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<Change<'a>> {
    let m = old.len();
    let n = new.len();

    // Build LCS table
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to find changes
    let mut changes = Vec::new();
    let mut i = m;
    let mut j = n;

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            changes.push(Change::Equal(old[i - 1], i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            changes.push(Change::Add(new[j - 1], j - 1));
            j -= 1;
        } else {
            changes.push(Change::Remove(old[i - 1], i - 1));
            i -= 1;
        }
    }

    changes.reverse();
    changes
}

fn group_changes<'a>(changes: &'a [Change<'a>]) -> Vec<DiffChunk<'a>> {
    let context_lines = 3;
    let mut chunks: Vec<DiffChunk<'a>> = Vec::new();

    // Find ranges of changes with context
    let mut i = 0;
    while i < changes.len() {
        // Skip equal lines until we find a change
        if let Change::Equal(_, _, _) = changes[i] {
            i += 1;
            continue;
        }

        // Found a change, build a chunk with context
        let chunk_start = i.saturating_sub(context_lines);
        let mut chunk_end = i;

        // Extend to include following changes and context
        let mut last_change = i;
        let mut j = i + 1;
        while j < changes.len() {
            match changes[j] {
                Change::Equal(_, _, _) => {
                    // If we've seen enough context lines since last change, stop
                    if j - last_change > context_lines * 2 {
                        chunk_end = last_change + context_lines;
                        break;
                    }
                }
                _ => {
                    last_change = j;
                }
            }
            j += 1;
        }
        if j >= changes.len() {
            chunk_end = (last_change + context_lines).min(changes.len() - 1);
        }

        // Build the chunk
        let mut lines = Vec::new();
        let mut old_start = usize::MAX;
        let mut new_start = usize::MAX;
        let mut old_count = 0;
        let mut new_count = 0;

        for change in changes
            .iter()
            .take(chunk_end.min(changes.len() - 1) + 1)
            .skip(chunk_start)
        {
            match change {
                Change::Equal(line, oi, ni) => {
                    if old_start == usize::MAX {
                        old_start = *oi;
                        new_start = *ni;
                    }
                    old_count += 1;
                    new_count += 1;
                    lines.push(DiffLine::Context(line));
                }
                Change::Remove(line, oi) => {
                    if old_start == usize::MAX {
                        old_start = *oi;
                        new_start = *oi; // approximate
                    }
                    old_count += 1;
                    lines.push(DiffLine::Remove(line));
                }
                Change::Add(line, ni) => {
                    if new_start == usize::MAX {
                        new_start = *ni;
                        old_start = *ni; // approximate
                    }
                    new_count += 1;
                    lines.push(DiffLine::Add(line));
                }
            }
        }

        if !lines.is_empty() {
            chunks.push(DiffChunk {
                old_start: if old_start == usize::MAX {
                    0
                } else {
                    old_start
                },
                old_count,
                new_start: if new_start == usize::MAX {
                    0
                } else {
                    new_start
                },
                new_count,
                lines,
            });
        }

        i = chunk_end + 1;
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_fixed_file_xml_tags() {
        let response = "Here is the fix:\n<FIXED_FILE>\nfn main() {\n    println!(\"safe\");\n}\n</FIXED_FILE>\nDone.";
        let result = extract_fixed_file(response);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "fn main() {\n    println!(\"safe\");\n}");
    }

    #[test]
    fn test_extract_fixed_file_markdown_fallback() {
        let response = "Here is the fix:\n```python\ndef safe():\n    pass\n```\nDone.";
        let result = extract_fixed_file(response);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "def safe():\n    pass");
    }

    #[test]
    fn test_extract_fixed_file_none_for_garbage() {
        let response = "I can't fix this. Please review manually.";
        assert!(extract_fixed_file(response).is_none());
    }

    #[test]
    fn test_extract_fixed_file_empty_tags() {
        let response = "<FIXED_FILE></FIXED_FILE>";
        let result = extract_fixed_file(response);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn compute_diff_equal() {
        let old = vec!["a", "b", "c"];
        let new = vec!["a", "b", "c"];
        let changes = compute_diff(&old, &new);
        assert!(changes.iter().all(|c| matches!(c, Change::Equal(_, _, _))));
    }

    #[test]
    fn compute_diff_additions() {
        let old = vec!["a", "c"];
        let new = vec!["a", "b", "c"];
        let changes = compute_diff(&old, &new);
        let adds: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Add(_, _)))
            .collect();
        assert_eq!(adds.len(), 1);
    }

    #[test]
    fn compute_diff_deletions() {
        let old = vec!["a", "b", "c"];
        let new = vec!["a", "c"];
        let changes = compute_diff(&old, &new);
        let removes: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Remove(_, _)))
            .collect();
        assert_eq!(removes.len(), 1);
    }
}
