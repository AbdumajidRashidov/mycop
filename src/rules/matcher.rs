use anyhow::Result;
use regex::Regex;
use std::path::{Path, PathBuf};
use streaming_iterator::StreamingIterator;

use crate::rules::parser::{PatternType, Rule, Severity};
use crate::scanner::language::Language;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub matched_text: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub message: String,
    pub fix_hint: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub description: String,
    pub references: Vec<String>,
}

/// Match a rule against file content and return findings
pub fn match_rule(
    rule: &Rule,
    content: &str,
    file_path: &Path,
    _language: &Language,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Try AST query first if available
    if rule.pattern.pattern_type == PatternType::Ast {
        if let Some(ref query_str) = rule.pattern.query {
            let ast_findings =
                match_ast_query(rule, content, file_path, _language, query_str, &lines);
            if let Ok(af) = ast_findings {
                findings.extend(af);
            }
        }
    }

    // Always try regex patterns (either as primary or as supplement to AST)
    for pattern_str in &rule.pattern.regex {
        match Regex::new(pattern_str) {
            Ok(re) => {
                for (line_idx, line) in lines.iter().enumerate() {
                    if let Some(m) = re.find(line) {
                        // Avoid duplicates if AST already found this line
                        let already_found = findings.iter().any(|f: &Finding| {
                            f.line == line_idx + 1 && f.rule_id == rule.id
                        });
                        if already_found {
                            continue;
                        }

                        let context_before = get_context_lines(&lines, line_idx, 2, true);
                        let context_after = get_context_lines(&lines, line_idx, 2, false);

                        findings.push(Finding {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity.clone(),
                            file: file_path.to_path_buf(),
                            line: line_idx + 1,
                            column: m.start() + 1,
                            matched_text: m.as_str().to_string(),
                            context_before,
                            context_after,
                            message: rule.message.clone(),
                            fix_hint: rule.fix_hint.clone(),
                            cwe: rule.cwe.clone(),
                            owasp: rule.owasp.clone(),
                            description: rule.description.clone(),
                            references: rule.references.clone(),
                        });
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: invalid regex pattern in rule {}: {}",
                    rule.id, e
                );
            }
        }
    }

    Ok(findings)
}

fn match_ast_query(
    rule: &Rule,
    content: &str,
    file_path: &Path,
    language: &Language,
    query_str: &str,
    lines: &[&str],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let ts_language = match language {
        Language::Python => tree_sitter_python::LANGUAGE,
        Language::JavaScript => tree_sitter_javascript::LANGUAGE,
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
    };

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_language.into())?;

    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse AST for {}", file_path.display()))?;

    let ts_lang: tree_sitter::Language = ts_language.into();
    match tree_sitter::Query::new(&ts_lang, query_str) {
        Ok(query) => {
            let mut cursor = tree_sitter::QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

            while let Some(m) = { matches.advance(); matches.get() } {
                if let Some(capture) = m.captures.first() {
                    let node = capture.node;
                    let start = node.start_position();
                    let line_idx = start.row;
                    let matched_text = node
                        .utf8_text(content.as_bytes())
                        .unwrap_or("")
                        .to_string();

                    let context_before = get_context_lines(lines, line_idx, 2, true);
                    let context_after = get_context_lines(lines, line_idx, 2, false);

                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        file: file_path.to_path_buf(),
                        line: line_idx + 1,
                        column: start.column + 1,
                        matched_text,
                        context_before,
                        context_after,
                        message: rule.message.clone(),
                        fix_hint: rule.fix_hint.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        description: rule.description.clone(),
                        references: rule.references.clone(),
                    });
                }
            }
        }
        Err(e) => {
            // AST query failed, will fall back to regex
            eprintln!(
                "Warning: AST query failed for rule {} ({}), using regex fallback: {}",
                rule.id, rule.name, e
            );
        }
    }

    Ok(findings)
}

fn get_context_lines(lines: &[&str], current: usize, count: usize, before: bool) -> Vec<String> {
    let mut result = Vec::new();
    if before {
        let start = current.saturating_sub(count);
        for i in start..current {
            result.push(lines[i].to_string());
        }
    } else {
        let end = (current + count + 1).min(lines.len());
        for i in (current + 1)..end {
            result.push(lines[i].to_string());
        }
    }
    result
}
