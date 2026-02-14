use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanConfig {
    /// Additional rule directories
    #[serde(default)]
    pub rules_dirs: Vec<PathBuf>,

    /// File patterns to ignore
    #[serde(default)]
    pub ignore: Vec<String>,

    /// Minimum severity to report
    #[serde(default)]
    pub min_severity: Option<String>,

    /// AI provider override
    #[serde(default)]
    pub ai_provider: Option<String>,

    /// Custom rules inline
    #[serde(default)]
    pub custom_rules: Vec<serde_yaml::Value>,
}

impl ScanConfig {
    /// Load config from .scanrc.yml in the given directory
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let candidates = vec![
            dir.join(".scanrc.yml"),
            dir.join(".scanrc.yaml"),
            dir.join(".mycop.yml"),
        ];

        for path in candidates {
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                let config: ScanConfig = serde_yaml::from_str(&content)?;
                return Ok(Some(config));
            }
        }

        Ok(None)
    }

    /// Generate a default .scanrc.yml content
    pub fn default_content() -> &'static str {
        r#"# mycop configuration file
# See https://github.com/mycop/mycop for documentation

# Additional directories containing custom YAML rules
# rules_dirs:
#   - ./custom-rules

# File patterns to ignore (glob syntax)
ignore:
  - "**/*_test.py"
  - "**/test_*.py"
  - "**/*.test.js"
  - "**/*.spec.ts"
  - "**/node_modules/**"
  - "**/__pycache__/**"
  - "**/venv/**"

# Minimum severity level: critical, high, medium, low, info
# min_severity: medium

# AI provider override: claude-cli, anthropic, openai, ollama, none
# ai_provider: null  # auto-detect
"#
    }
}
