use anyhow::Result;
use serde_json::json;

use crate::ai::prompt;
use crate::ai::types::AiBackend;
use crate::rules::matcher::Finding;

pub struct OllamaBackend {
    base_url: String,
    model: String,
    client: reqwest::blocking::Client,
}

impl OllamaBackend {
    pub fn new() -> Self {
        Self {
            base_url: "http://127.0.0.1:11434".to_string(),
            model: "llama3.1".to_string(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }

    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        self
    }

    fn call_api(&self, prompt_text: &str) -> Result<String> {
        let body = json!({
            "model": self.model,
            "prompt": prompt_text,
            "stream": false,
            "options": {
                "temperature": 0.1
            }
        });

        let response = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&body)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            anyhow::bail!("Ollama API error ({}): {}", status, text);
        }

        let json: serde_json::Value = response.json()?;
        let text = json["response"]
            .as_str()
            .unwrap_or("No response")
            .to_string();

        Ok(text)
    }
}

impl AiBackend for OllamaBackend {
    fn explain(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::explain_prompt(finding, code_context);
        self.call_api(&prompt_text)
    }

    fn suggest_fix(&self, finding: &Finding, code_context: &str) -> Result<String> {
        let prompt_text = prompt::fix_prompt(finding, code_context);
        self.call_api(&prompt_text)
    }

    fn deep_review(&self, file_content: &str, language: &str) -> Result<String> {
        let prompt_text = prompt::review_prompt(file_content, language);
        self.call_api(&prompt_text)
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
        self.call_api(&prompt_text)
    }
}
