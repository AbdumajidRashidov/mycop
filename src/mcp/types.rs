use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---- Scan Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// A single file or directory path to scan (use this OR paths, not both)
    #[serde(default)]
    pub path: Option<String>,
    /// Multiple files or directories to scan (use this OR path, not both)
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// Minimum severity to report: "critical", "high", "medium", "low", "info"
    #[serde(default)]
    pub severity: Option<String>,
    /// Only scan files changed in git diff
    #[serde(default)]
    pub diff: Option<bool>,
    /// Maximum number of findings to return (default: 50)
    #[serde(default)]
    pub max_results: Option<usize>,
}

impl ScanParams {
    /// Resolve path/paths into a single Vec<String>. Defaults to "." if neither is provided.
    pub fn resolved_paths(&self) -> Vec<String> {
        if let Some(p) = &self.path {
            return vec![p.clone()];
        }
        if let Some(ps) = &self.paths {
            if !ps.is_empty() {
                return ps.clone();
            }
        }
        vec![".".to_string()]
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub total_findings: usize,
    pub files_scanned: usize,
    pub rules_loaded: usize,
    pub findings: Vec<FindingOutput>,
}

#[derive(Debug, Serialize)]
pub struct FindingOutput {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub matched_text: String,
    pub message: String,
    pub description: String,
    pub fix_hint: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub references: Vec<String>,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

// ---- List Rules Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRulesParams {
    /// Filter by language: "python", "javascript"
    #[serde(default)]
    pub language: Option<String>,
    /// Filter by minimum severity: "critical", "high", "medium", "low"
    #[serde(default)]
    pub severity: Option<String>,
    /// Search term to filter rules by name, id, or description
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListRulesResult {
    pub total: usize,
    pub rules: Vec<RuleOutput>,
}

#[derive(Debug, Serialize)]
pub struct RuleOutput {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub language: String,
    pub description: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub fix_hint: Option<String>,
    pub references: Vec<String>,
}

// ---- Explain Finding Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainFindingParams {
    /// The absolute file path containing the vulnerability
    #[serde(
        alias = "file",
        alias = "filePath",
        alias = "file_path",
        alias = "target"
    )]
    pub path: String,
    /// The line number of the finding
    pub line: usize,
    /// The rule ID (e.g., "PY-SEC-001")
    pub rule_id: String,
    /// Override AI provider: "claude-cli", "anthropic", "openai", "ollama", "none"
    #[serde(default)]
    pub ai_provider: Option<String>,
}

// ---- Review Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReviewParams {
    /// The absolute file path to review for security vulnerabilities
    #[serde(
        alias = "file",
        alias = "filePath",
        alias = "file_path",
        alias = "target"
    )]
    pub path: String,
    /// Override AI provider
    #[serde(default)]
    pub ai_provider: Option<String>,
}

// ---- Check Deps Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDepsParams {
    /// Path to project directory, requirements.txt, or package.json (defaults to ".")
    #[serde(default = "default_dot")]
    pub path: String,
}

fn default_dot() -> String {
    ".".to_string()
}

#[derive(Debug, Serialize)]
pub struct CheckDepsResult {
    pub files_checked: Vec<String>,
    pub python_packages: Vec<String>,
    pub npm_packages: Vec<String>,
    pub npm_dev_packages: Vec<String>,
}
