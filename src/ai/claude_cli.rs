use anyhow::Result;
use std::process::Command;

use crate::ai::prompt;
use crate::ai::types::AiBackend;
use crate::rules::matcher::Finding;

pub struct ClaudeCliBackend;

impl ClaudeCliBackend {
    pub fn new() -> Self {
        Self
    }

    fn call_claude(&self, prompt_text: &str) -> Result<String> {
        let output = Command::new("claude")
            .args(["-p", prompt_text])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Claude CLI failed: {}", stderr);
        }

        let response = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(response.trim().to_string())
    }
}

impl AiBackend for ClaudeCliBackend {
    fn explain(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::explain_prompt(finding, code_context);
        self.call_claude(&prompt_text)
    }

    fn suggest_fix(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::fix_prompt(finding, code_context);
        self.call_claude(&prompt_text)
    }

    fn deep_review(&self, file_content: &str, language: &str) -> Result<String> {
        let prompt_text = prompt::review_prompt(file_content, language);
        self.call_claude(&prompt_text)
    }

    fn fix_file(
        &self,
        file_path: &str,
        language: &str,
        file_content: &str,
        findings: &[&Finding],
    ) -> Result<String> {
        let prompt_text =
            prompt::fix_file_prompt(file_path, language, file_content, findings);
        self.call_claude(&prompt_text)
    }
}
