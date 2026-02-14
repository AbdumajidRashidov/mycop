use anyhow::Result;

use crate::rules::matcher::Finding;

/// Available AI providers in priority order
#[derive(Debug, Clone)]
pub enum AiProvider {
    ClaudeCli,
    AnthropicApi(String), // API key
    OpenAiApi(String),    // API key
    Ollama,
    RuleBasedOnly,
}

impl std::fmt::Display for AiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiProvider::ClaudeCli => write!(f, "Claude CLI"),
            AiProvider::AnthropicApi(_) => write!(f, "Anthropic API"),
            AiProvider::OpenAiApi(_) => write!(f, "OpenAI API"),
            AiProvider::Ollama => write!(f, "Ollama (local)"),
            AiProvider::RuleBasedOnly => write!(f, "Rule-based only (offline)"),
        }
    }
}

/// Trait for all AI backends
pub trait AiBackend: Send + Sync {
    /// Explain a vulnerability finding
    fn explain(&self, finding: &Finding, code_context: &str) -> Result<String>;

    /// Suggest a fix for a vulnerability finding
    fn suggest_fix(&self, finding: &Finding, code_context: &str) -> Result<String>;

    /// Deep review an entire file for security issues
    fn deep_review(&self, file_content: &str, language: &str) -> Result<String>;

    /// Fix an entire file: send full content + all findings, get back fixed file
    fn fix_file(
        &self,
        file_path: &str,
        language: &str,
        file_content: &str,
        findings: &[&Finding],
    ) -> Result<String>;
}

/// AI response for a finding
#[derive(Debug, Clone)]
pub struct AiExplanation {
    pub explanation: String,
}

/// AI response with fix suggestion
#[derive(Debug, Clone)]
pub struct AiFix {
    pub explanation: String,
    pub fixed_code: String,
}
