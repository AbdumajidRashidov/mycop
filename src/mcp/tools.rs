use std::path::PathBuf;

use rmcp::{handler::server::tool::Parameters, model::*, tool, Error as McpError};

use crate::ai;
use crate::config::ScanConfig;
use crate::rules::RuleRegistry;
use crate::scanner::file_discovery;
use crate::scanner::{Language, Scanner};

use super::convert::{finding_to_output, rule_to_output};
use super::types::*;
use super::MycopMcpServer;

impl MycopMcpServer {
    #[tool(
        name = "scan",
        description = "Scan files or directories for security vulnerabilities in Python, JavaScript, and TypeScript code. Returns findings with severity, CWE/OWASP mappings, and fix hints. Uses 100 built-in rules covering OWASP Top 10 and CWE Top 25."
    )]
    pub async fn scan(&self, params: Parameters<ScanParams>) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let result = tokio::task::spawn_blocking(move || scan_impl(params))
            .await
            .map_err(|e| McpError::internal_error(format!("Task join error: {}", e), None))?
            .map_err(|e| McpError::internal_error(format!("Scan error: {}", e), None))?;

        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        name = "list_rules",
        description = "List available security rules. Filter by language (python, javascript), severity, or search term. Returns rule IDs, descriptions, CWE/OWASP mappings, and fix hints."
    )]
    pub async fn list_rules(
        &self,
        params: Parameters<ListRulesParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let result = tokio::task::spawn_blocking(move || list_rules_impl(params))
            .await
            .map_err(|e| McpError::internal_error(format!("Task join error: {}", e), None))?
            .map_err(|e| McpError::internal_error(format!("Error: {}", e), None))?;

        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        name = "explain_finding",
        description = "Get a detailed explanation of a specific security finding. Provides attack scenarios, impact analysis, and remediation guidance."
    )]
    pub async fn explain_finding(
        &self,
        params: Parameters<ExplainFindingParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let result = tokio::task::spawn_blocking(move || explain_finding_impl(params))
            .await
            .map_err(|e| McpError::internal_error(format!("Task join error: {}", e), None))?
            .map_err(|e| McpError::internal_error(format!("Error: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    #[tool(
        name = "review",
        description = "Deep AI-powered security review of a single file. Goes beyond rule-based scanning to find logic flaws, auth issues, and complex vulnerability patterns."
    )]
    pub async fn review(
        &self,
        params: Parameters<ReviewParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let result = tokio::task::spawn_blocking(move || review_impl(params))
            .await
            .map_err(|e| McpError::internal_error(format!("Task join error: {}", e), None))?
            .map_err(|e| McpError::internal_error(format!("Error: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    #[tool(
        name = "check_deps",
        description = "Check project dependencies for hallucinated or suspicious packages. Reads requirements.txt and package.json to list all dependencies."
    )]
    pub async fn check_deps(
        &self,
        params: Parameters<CheckDepsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let result = tokio::task::spawn_blocking(move || check_deps_impl(params))
            .await
            .map_err(|e| McpError::internal_error(format!("Task join error: {}", e), None))?
            .map_err(|e| McpError::internal_error(format!("Error: {}", e), None))?;

        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

// Register all tools in a static ToolBox (generates private fn _tool_box)
rmcp::tool_box!(MycopMcpServer {
    scan,
    list_rules,
    explain_finding,
    review,
    check_deps,
} _tool_box);

pub fn tool_box() -> &'static rmcp::handler::server::tool::ToolBox<MycopMcpServer> {
    _tool_box()
}

// ---- Implementation functions (sync, run inside spawn_blocking) ----

fn parse_severity_filter(s: &str) -> Option<u8> {
    match s.to_lowercase().as_str() {
        "critical" => Some(4),
        "high" => Some(3),
        "medium" => Some(2),
        "low" => Some(1),
        "info" => Some(0),
        _ => None,
    }
}

fn resolve_ai_provider(provider_name: Option<&str>) -> ai::AiProvider {
    match provider_name {
        Some(s) => match s.to_lowercase().as_str() {
            "claude-cli" => ai::AiProvider::ClaudeCli,
            "anthropic" => {
                let key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
                ai::AiProvider::AnthropicApi(key)
            }
            "openai" => {
                let key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
                ai::AiProvider::OpenAiApi(key)
            }
            "ollama" => ai::AiProvider::Ollama,
            _ => ai::AiProvider::RuleBasedOnly,
        },
        None => ai::detect_ai_provider(),
    }
}

fn scan_impl(params: ScanParams) -> anyhow::Result<ScanResult> {
    let config = ScanConfig::load(&std::env::current_dir()?)?;
    let ignore_patterns = config
        .as_ref()
        .map(|c| c.ignore.clone())
        .unwrap_or_default();

    let registry = RuleRegistry::load_default()?;
    let rules_loaded = registry.rule_count();

    let resolved = params.resolved_paths();
    let paths: Vec<PathBuf> = resolved.iter().map(PathBuf::from).collect();

    let files = if params.diff.unwrap_or(false) {
        file_discovery::discover_diff_files(&std::env::current_dir()?)?
    } else {
        file_discovery::discover_files(&paths, &ignore_patterns)?
    };

    let files_scanned = files.len();
    let scanner = Scanner::new(registry);
    let mut findings = scanner.scan_files(&files)?;

    // Filter by severity
    if let Some(ref sev) = params.severity {
        if let Some(min_ord) = parse_severity_filter(sev) {
            findings.retain(|f| f.severity.ordinal() >= min_ord);
        }
    }

    // Sort by severity (highest first)
    findings.sort_by(|a, b| b.severity.ordinal().cmp(&a.severity.ordinal()));

    // Limit results
    let max = params.max_results.unwrap_or(50);
    let total_findings = findings.len();
    findings.truncate(max);

    let finding_outputs: Vec<FindingOutput> = findings.iter().map(finding_to_output).collect();

    Ok(ScanResult {
        total_findings,
        files_scanned,
        rules_loaded,
        findings: finding_outputs,
    })
}

fn list_rules_impl(params: ListRulesParams) -> anyhow::Result<ListRulesResult> {
    let registry = RuleRegistry::load_default()?;
    let mut rules: Vec<_> = registry.all_rules().into_iter().collect();

    if let Some(ref lang) = params.language {
        let lang_lower = lang.to_lowercase();
        rules.retain(|r| r.language.to_lowercase() == lang_lower);
    }

    if let Some(ref sev) = params.severity {
        if let Some(min_ord) = parse_severity_filter(sev) {
            rules.retain(|r| r.severity.ordinal() >= min_ord);
        }
    }

    if let Some(ref search) = params.search {
        let s = search.to_lowercase();
        rules.retain(|r| {
            r.id.to_lowercase().contains(&s)
                || r.name.to_lowercase().contains(&s)
                || r.description.to_lowercase().contains(&s)
        });
    }

    let outputs: Vec<RuleOutput> = rules.iter().map(|r| rule_to_output(r)).collect();

    Ok(ListRulesResult {
        total: outputs.len(),
        rules: outputs,
    })
}

fn explain_finding_impl(params: ExplainFindingParams) -> anyhow::Result<String> {
    let file = params.path;
    let file_path = PathBuf::from(&file);
    if !file_path.exists() {
        anyhow::bail!("File not found: {}", file);
    }

    let registry = RuleRegistry::load_default()?;
    let scanner = Scanner::new(registry);
    let findings = scanner.scan_files(std::slice::from_ref(&file_path))?;

    let finding = findings
        .iter()
        .find(|f| f.rule_id == params.rule_id && f.line == params.line)
        .or_else(|| findings.iter().find(|f| f.rule_id == params.rule_id))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No finding with rule_id '{}' at line {} in {}",
                params.rule_id,
                params.line,
                file
            )
        })?;

    let content = std::fs::read_to_string(&file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = finding.line.saturating_sub(6);
    let end = (finding.line + 5).min(lines.len());
    let code_context = lines[start..end].join("\n");

    let provider = resolve_ai_provider(params.ai_provider.as_deref());
    let backend = ai::create_backend(&provider);

    backend.explain(finding, &code_context)
}

fn review_impl(params: ReviewParams) -> anyhow::Result<String> {
    let file = params.path;
    let file_path = PathBuf::from(&file);
    if !file_path.exists() {
        anyhow::bail!("File not found: {}", file);
    }

    let language = Language::from_extension(&file_path)
        .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {}", file))?;

    let content = std::fs::read_to_string(&file_path)?;

    let provider = resolve_ai_provider(params.ai_provider.as_deref());
    let backend = ai::create_backend(&provider);

    backend.deep_review(&content, language.name())
}

fn check_deps_impl(params: CheckDepsParams) -> anyhow::Result<CheckDepsResult> {
    let path = PathBuf::from(&params.path);
    let mut files_checked = Vec::new();
    let mut python_packages = Vec::new();
    let mut npm_packages = Vec::new();
    let mut npm_dev_packages = Vec::new();

    let req_path = if path.is_file()
        && path.file_name().and_then(|f| f.to_str()) == Some("requirements.txt")
    {
        path.clone()
    } else {
        path.join("requirements.txt")
    };

    if req_path.exists() {
        files_checked.push(req_path.display().to_string());
        let content = std::fs::read_to_string(&req_path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let pkg = line
                .split(['=', '>', '<', '!', ';', ' '])
                .next()
                .unwrap_or(line);
            if !pkg.is_empty() {
                python_packages.push(pkg.to_string());
            }
        }
    }

    let pkg_path =
        if path.is_file() && path.file_name().and_then(|f| f.to_str()) == Some("package.json") {
            path.clone()
        } else {
            path.join("package.json")
        };

    if pkg_path.exists() {
        files_checked.push(pkg_path.display().to_string());
        let content = std::fs::read_to_string(&pkg_path)?;
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                for (name, _) in deps {
                    npm_packages.push(name.clone());
                }
            }
            if let Some(deps) = json.get("devDependencies").and_then(|d| d.as_object()) {
                for (name, _) in deps {
                    npm_dev_packages.push(name.clone());
                }
            }
        }
    }

    Ok(CheckDepsResult {
        files_checked,
        python_packages,
        npm_packages,
        npm_dev_packages,
    })
}
