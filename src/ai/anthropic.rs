use anyhow::Result;
use serde_json::json;

use crate::ai::prompt;
use crate::ai::types::AiBackend;
use crate::rules::matcher::Finding;

pub struct AnthropicBackend {
    api_key: String,
    client: reqwest::blocking::Client,
}

impl AnthropicBackend {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn call_api(&self, prompt_text: &str, max_tokens: u32) -> Result<String> {
        let body = json!({
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt_text
                }
            ]
        });

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            anyhow::bail!("Anthropic API error ({}): {}", status, text);
        }

        let json: serde_json::Value = response.json()?;
        let text = json["content"][0]["text"]
            .as_str()
            .unwrap_or("No response")
            .to_string();

        Ok(text)
    }
}

impl AiBackend for AnthropicBackend {
    fn explain(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::explain_prompt(finding, code_context);
        self.call_api(&prompt_text, 1024)
    }

    fn suggest_fix(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::fix_prompt(finding, code_context);
        self.call_api(&prompt_text, 1024)
    }

    fn deep_review(&self, file_content: &str, language: &str) -> Result<String> {
        let prompt_text = prompt::review_prompt(file_content, language);
        self.call_api(&prompt_text, 4096)
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
        self.call_api(&prompt_text, 16384)
    }
}
