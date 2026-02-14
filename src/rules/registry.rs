use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use crate::rules::parser::{self, Rule, Severity};
use crate::scanner::language::Language;

/// Embedded rule YAML files compiled into the binary
static EMBEDDED_RULES: &[(&str, &str)] = &[
    // Python rules
    ("python", include_str!("../../rules/python/sql-injection.yml")),
    ("python", include_str!("../../rules/python/os-command-injection.yml")),
    ("python", include_str!("../../rules/python/hardcoded-secrets.yml")),
    ("python", include_str!("../../rules/python/insecure-random.yml")),
    ("python", include_str!("../../rules/python/eval-exec.yml")),
    ("python", include_str!("../../rules/python/path-traversal.yml")),
    ("python", include_str!("../../rules/python/insecure-deserialization.yml")),
    ("python", include_str!("../../rules/python/missing-auth.yml")),
    ("python", include_str!("../../rules/python/xss-template.yml")),
    ("python", include_str!("../../rules/python/log-injection.yml")),
    // JavaScript rules
    ("javascript", include_str!("../../rules/javascript/xss-innerhtml.yml")),
    ("javascript", include_str!("../../rules/javascript/eval-injection.yml")),
    ("javascript", include_str!("../../rules/javascript/prototype-pollution.yml")),
    ("javascript", include_str!("../../rules/javascript/hardcoded-secrets.yml")),
    ("javascript", include_str!("../../rules/javascript/insecure-random.yml")),
    ("javascript", include_str!("../../rules/javascript/path-traversal.yml")),
    ("javascript", include_str!("../../rules/javascript/ssrf.yml")),
    ("javascript", include_str!("../../rules/javascript/nosql-injection.yml")),
    ("javascript", include_str!("../../rules/javascript/insecure-deserialization.yml")),
    ("javascript", include_str!("../../rules/javascript/dangerouslysetinnerhtml.yml")),
];

pub struct RuleRegistry {
    rules: HashMap<String, Vec<Rule>>, // language -> rules
}

impl RuleRegistry {
    /// Load rules from a directory containing language subdirectories
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();

        if !rules_dir.exists() {
            return Ok(Self { rules });
        }

        for entry in std::fs::read_dir(rules_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let lang_name = entry.file_name().to_string_lossy().to_string();
                let lang_rules = parser::parse_rules_dir(&entry.path())?;
                if !lang_rules.is_empty() {
                    rules.insert(lang_name, lang_rules);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Load embedded rules (compiled into the binary) plus any external rules
    pub fn load_default() -> Result<Self> {
        let mut registry = Self::load_embedded()?;

        // Also check for additional rules on disk (project-local or user config)
        let extra_dirs = vec![
            std::env::current_dir().unwrap_or_default().join("rules"),
            std::env::current_dir().unwrap_or_default().join(".mycop-rules"),
            dirs_rules_path(),
        ];

        for dir in extra_dirs {
            if dir.exists() {
                if let Ok(extra) = Self::load(&dir) {
                    for (lang, rules) in extra.rules {
                        registry.rules.entry(lang).or_default().extend(rules);
                    }
                }
            }
        }

        Ok(registry)
    }

    /// Load only the embedded (compiled-in) rules
    fn load_embedded() -> Result<Self> {
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();

        for (lang, yaml_content) in EMBEDDED_RULES {
            match serde_yaml::from_str::<Rule>(yaml_content) {
                Ok(rule) => {
                    rules.entry(lang.to_string()).or_default().push(rule);
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse embedded rule for {}: {}", lang, e);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Get rules for a specific language
    pub fn rules_for_language(&self, language: &Language) -> Vec<&Rule> {
        let lang_key = language.rule_dir().to_string();
        self.rules
            .get(&lang_key)
            .map(|rules| rules.iter().collect())
            .unwrap_or_default()
    }

    /// Get all rules
    pub fn all_rules(&self) -> Vec<&Rule> {
        self.rules.values().flat_map(|rules| rules.iter()).collect()
    }

    /// Filter rules by severity
    pub fn rules_with_min_severity(&self, language: &Language, min: &Severity) -> Vec<&Rule> {
        self.rules_for_language(language)
            .into_iter()
            .filter(|r| r.severity.ordinal() >= min.ordinal())
            .collect()
    }

    /// Get count of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|r| r.len()).sum()
    }

    /// List available languages
    pub fn languages(&self) -> Vec<&str> {
        self.rules.keys().map(|k| k.as_str()).collect()
    }
}

fn dirs_rules_path() -> std::path::PathBuf {
    if let Some(config_dir) = dirs_config_path() {
        config_dir.join("rules")
    } else {
        std::path::PathBuf::from("rules")
    }
}

fn dirs_config_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| std::path::PathBuf::from(h).join(".config").join("mycop"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.config", h)))
            .ok()
            .map(|h| std::path::PathBuf::from(h).join("mycop"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|h| std::path::PathBuf::from(h).join("mycop"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}
