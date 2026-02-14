use anyhow::Result;
use serde_json::json;

use crate::ai::prompt;
use crate::ai::types::AiBackend;
use crate::rules::matcher::Finding;

pub struct OpenAiBackend {
    api_key: String,
    client: reqwest::blocking::Client,
}

impl OpenAiBackend {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn call_api(&self, prompt_text: &str, max_tokens: u32) -> Result<String> {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security expert helping developers fix vulnerabilities in their code."
                },
                {
                    "role": "user",
                    "content": prompt_text
                }
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            anyhow::bail!("OpenAI API error ({}): {}", status, text);
        }

        let json: serde_json::Value = response.json()?;
        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("No response")
            .to_string();

        Ok(text)
    }
}

impl AiBackend for OpenAiBackend {
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
