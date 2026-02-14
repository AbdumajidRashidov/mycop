use anyhow::Result;

use crate::ai::types::AiBackend;
use crate::rules::matcher::Finding;

/// Offline fallback: uses fix_hint from YAML rules, no LLM calls
pub struct RuleBasedBackend;

impl RuleBasedBackend {
    pub fn new() -> Self {
        Self
    }
}

impl AiBackend for RuleBasedBackend {
    fn explain(&self, finding: &Finding, _code_context: &str) -> Result<String> {
        let mut explanation = finding.description.clone();

        if let Some(ref cwe) = finding.cwe {
            explanation.push_str(&format!("\n\nCWE: {}", cwe));
        }
        if let Some(ref owasp) = finding.owasp {
            explanation.push_str(&format!("\nOWASP: {}", owasp));
        }
        if !finding.references.is_empty() {
            explanation.push_str("\n\nReferences:");
            for r in &finding.references {
                explanation.push_str(&format!("\n  - {}", r));
            }
        }

        Ok(explanation)
    }

    fn suggest_fix(&self, finding: &Finding, _code_context: &str) -> Result<String> {
        match &finding.fix_hint {
            Some(hint) => Ok(format!("Suggested fix:\n{}", hint)),
            None => Ok(format!(
                "No specific fix suggestion available for {}. Please review the vulnerability description and apply appropriate security measures.",
                finding.rule_name
            )),
        }
    }

    fn deep_review(&self, _file_content: &str, _language: &str) -> Result<String> {
        Ok("Deep review requires an AI provider (Claude CLI, Anthropic API, OpenAI, or Ollama).\n\
            Run with --ai-provider to specify a provider, or ensure one is available.\n\
            Without AI, use `mycop scan` for rule-based vulnerability detection."
            .to_string())
    }

    fn fix_file(
        &self,
        _file_path: &str,
        _language: &str,
        _file_content: &str,
        _findings: &[&Finding],
    ) -> Result<String> {
        anyhow::bail!(
            "Auto-fix requires an AI provider (Claude CLI, Anthropic API, OpenAI, or Ollama).\n\
             Install Claude CLI, set ANTHROPIC_API_KEY or OPENAI_API_KEY, or start Ollama."
        )
    }
}
