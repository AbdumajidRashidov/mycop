pub mod anthropic;
pub mod claude_cli;
pub mod ollama;
pub mod openai;
pub mod prompt;
pub mod rule_based;
pub mod types;

use std::net::TcpStream;
use std::process::Command;

use crate::cli::AiProviderChoice;
pub use types::{AiBackend, AiProvider};

/// Auto-detect the best available AI provider
pub fn detect_ai_provider() -> AiProvider {
    // 1. Check for claude CLI
    if Command::new("claude")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return AiProvider::ClaudeCli;
    }

    // 2. Check for Anthropic API key
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return AiProvider::AnthropicApi(key);
        }
    }

    // 3. Check for OpenAI API key
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return AiProvider::OpenAiApi(key);
        }
    }

    // 4. Check for Ollama running locally
    if TcpStream::connect("127.0.0.1:11434").is_ok() {
        return AiProvider::Ollama;
    }

    // 5. Fallback: rule-based hints only
    AiProvider::RuleBasedOnly
}

/// Create an AI backend from a provider choice override
pub fn provider_from_choice(choice: &AiProviderChoice) -> AiProvider {
    match choice {
        AiProviderChoice::ClaudeCli => AiProvider::ClaudeCli,
        AiProviderChoice::Anthropic => {
            let key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
            AiProvider::AnthropicApi(key)
        }
        AiProviderChoice::Openai => {
            let key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            AiProvider::OpenAiApi(key)
        }
        AiProviderChoice::Ollama => AiProvider::Ollama,
        AiProviderChoice::None => AiProvider::RuleBasedOnly,
    }
}

/// Create an AiBackend instance from a provider
pub fn create_backend(provider: &AiProvider) -> Box<dyn AiBackend> {
    match provider {
        AiProvider::ClaudeCli => Box::new(claude_cli::ClaudeCliBackend::new()),
        AiProvider::AnthropicApi(key) => Box::new(anthropic::AnthropicBackend::new(key.clone())),
        AiProvider::OpenAiApi(key) => Box::new(openai::OpenAiBackend::new(key.clone())),
        AiProvider::Ollama => Box::new(ollama::OllamaBackend::new()),
        AiProvider::RuleBasedOnly => Box::new(rule_based::RuleBasedBackend::new()),
    }
}
