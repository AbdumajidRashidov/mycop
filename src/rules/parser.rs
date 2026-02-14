use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub language: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub owasp: Option<String>,
    pub description: String,
    pub pattern: Pattern,
    pub message: String,
    #[serde(default)]
    pub fix_hint: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn ordinal(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pattern {
    #[serde(rename = "type")]
    pub pattern_type: PatternType,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    Ast,
    Regex,
}

/// Parse a single YAML rule file
pub fn parse_rule_file(path: &Path) -> Result<Rule> {
    let content = std::fs::read_to_string(path)?;
    let rule: Rule = serde_yaml::from_str(&content)?;
    Ok(rule)
}

/// Parse all YAML rule files in a directory
pub fn parse_rules_dir(dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    if !dir.exists() {
        return Ok(rules);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml")
            || path.extension().and_then(|e| e.to_str()) == Some("yaml")
        {
            match parse_rule_file(&path) {
                Ok(rule) => rules.push(rule),
                Err(e) => eprintln!("Warning: failed to parse rule {}: {}", path.display(), e),
            }
        }
    }

    Ok(rules)
}
