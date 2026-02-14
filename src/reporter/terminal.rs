use colored::*;
use std::collections::HashMap;

use crate::reporter::Reporter;
use crate::rules::matcher::Finding;
use crate::rules::parser::Severity;

pub struct TerminalReporter;

impl TerminalReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Reporter for TerminalReporter {
    fn report(
        &self,
        findings: &[Finding],
        ai_results: &HashMap<usize, String>,
    ) -> anyhow::Result<String> {
        if findings.is_empty() {
            println!("\n  {} No security issues found!\n", "✓".green().bold());
            return Ok(String::new());
        }

        println!();

        for (idx, finding) in findings.iter().enumerate() {
            // File location
            println!(
                "  {}:{}",
                finding.file.display().to_string().white().bold(),
                finding.line.to_string().cyan()
            );

            // Severity + rule name + CWE
            let severity_str = format_severity(&finding.severity);
            let cwe_str = finding
                .cwe
                .as_ref()
                .map(|c| format!(" ({})", c))
                .unwrap_or_default();
            println!(
                "  {} {} {}{}",
                severity_str,
                finding.rule_name.replace('-', " ").bold(),
                cwe_str.dimmed(),
                ""
            );
            println!();

            // Context before
            let start_line = finding.line.saturating_sub(finding.context_before.len());
            for (i, line) in finding.context_before.iter().enumerate() {
                let line_num = start_line + i;
                println!(
                    "     {} {}",
                    format!("{:>4} │", line_num).dimmed(),
                    line
                );
            }

            // The matched line (highlighted)
            println!(
                "  {}  {} {}",
                "→".red().bold(),
                format!("{:>4} │", finding.line).dimmed(),
                highlight_match(
                    &get_line_from_finding(finding),
                    &finding.matched_text
                )
            );

            // Context after
            for (i, line) in finding.context_after.iter().enumerate() {
                let line_num = finding.line + i + 1;
                println!(
                    "     {} {}",
                    format!("{:>4} │", line_num).dimmed(),
                    line
                );
            }

            // Message
            println!();
            println!("     {}", finding.message.yellow());

            // AI explanation/fix if available
            if let Some(ai_text) = ai_results.get(&idx) {
                println!();
                println!("  {} {}", "💡 AI:".cyan().bold(), "");
                for line in ai_text.lines() {
                    println!("     {}", line);
                }
            } else if let Some(ref hint) = finding.fix_hint {
                println!("     {} {}", "Fix:".green().bold(), hint);
            }

            println!();
            println!("  {}", "─".repeat(50).dimmed());
            println!();
        }

        // Summary
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for f in findings {
            match f.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low | Severity::Info => low += 1,
            }
        }

        let total = findings.len();
        print!("  Found {} issue{}: ", total, if total == 1 { "" } else { "s" });

        let mut parts = Vec::new();
        if critical > 0 {
            parts.push(format!("{} critical", critical).red().bold().to_string());
        }
        if high > 0 {
            parts.push(format!("{} high", high).red().to_string());
        }
        if medium > 0 {
            parts.push(format!("{} medium", medium).yellow().to_string());
        }
        if low > 0 {
            parts.push(format!("{} low", low).dimmed().to_string());
        }
        println!("{}", parts.join(", "));
        println!();

        Ok(String::new())
    }
}

fn format_severity(severity: &Severity) -> ColoredString {
    match severity {
        Severity::Critical => "🔴 CRITICAL".red().bold(),
        Severity::High => "🟠 HIGH    ".red(),
        Severity::Medium => "🟡 MEDIUM  ".yellow(),
        Severity::Low => "🔵 LOW     ".blue(),
        Severity::Info => "ℹ  INFO    ".dimmed(),
    }
}

fn highlight_match(line: &str, matched: &str) -> String {
    if let Some(pos) = line.find(matched) {
        let before = &line[..pos];
        let after = &line[pos + matched.len()..];
        format!(
            "{}{}{}",
            before,
            matched.red().underline(),
            after
        )
    } else {
        line.to_string()
    }
}

fn get_line_from_finding(finding: &Finding) -> String {
    // Read the specific line from file
    if let Ok(content) = std::fs::read_to_string(&finding.file) {
        if let Some(line) = content.lines().nth(finding.line - 1) {
            return line.to_string();
        }
    }
    finding.matched_text.clone()
}
