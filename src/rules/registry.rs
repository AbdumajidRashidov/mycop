use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use crate::rules::parser::{self, Rule};
use crate::scanner::language::Language;

/// Embedded rule YAML files compiled into the binary
static EMBEDDED_RULES: &[(&str, &str)] = &[
    // Python rules
    (
        "python",
        include_str!("../../rules/python/sql-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/os-command-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/hardcoded-secrets.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-random.yml"),
    ),
    ("python", include_str!("../../rules/python/eval-exec.yml")),
    (
        "python",
        include_str!("../../rules/python/path-traversal.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-deserialization.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/missing-auth.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/xss-template.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/log-injection.yml"),
    ),
    // Python rules (011-050)
    ("python", include_str!("../../rules/python/ssrf.yml")),
    (
        "python",
        include_str!("../../rules/python/xxe-parsing.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/ldap-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/template-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/header-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/xpath-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-hash-md5.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-hash-sha1.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-cipher.yml"),
    ),
    ("python", include_str!("../../rules/python/ecb-mode.yml")),
    (
        "python",
        include_str!("../../rules/python/hardcoded-iv.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-tls.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/jwt-none-algorithm.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-password-hash.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/session-fixation.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/missing-hsts.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/open-redirect.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/cors-misconfiguration.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/mass-assignment.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/idor-pattern.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/debug-mode-enabled.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/stack-trace-exposure.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/sensitive-data-logging.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/hardcoded-connection-string.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/arbitrary-file-upload.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/tempfile-insecure.yml"),
    ),
    ("python", include_str!("../../rules/python/zipslip.yml")),
    (
        "python",
        include_str!("../../rules/python/unencrypted-socket.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/dns-resolution-user-input.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/bare-except.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/assert-for-auth.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/django-raw-sql.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/flask-secret-key.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/django-safe-string.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/subprocess-user-input.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/timing-attack.yml"),
    ),
    ("python", include_str!("../../rules/python/redos.yml")),
    ("python", include_str!("../../rules/python/toctou.yml")),
    (
        "python",
        include_str!("../../rules/python/unsafe-import.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/shell-true-list.yml"),
    ),
    // JavaScript rules
    (
        "javascript",
        include_str!("../../rules/javascript/xss-innerhtml.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/eval-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/prototype-pollution.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/hardcoded-secrets.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-random.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/path-traversal.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ssrf.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/nosql-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-deserialization.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/dangerouslysetinnerhtml.yml"),
    ),
    // JavaScript rules (011-050)
    (
        "javascript",
        include_str!("../../rules/javascript/sql-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/xxe-parsing.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/template-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/header-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ldap-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/command-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-hash-md5.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-hash-sha1.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-cipher.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ecb-mode.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-tls.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/createcipher-deprecated.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/jwt-none-algorithm.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-cookie.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/session-secret-weak.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/missing-helmet.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/open-redirect.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/cors-misconfiguration.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/idor-pattern.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/mass-assignment.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/debug-mode-enabled.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/error-info-leak.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/sensitive-data-exposure.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/hardcoded-connection-string.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/arbitrary-file-upload.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/directory-listing.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/zipslip.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/unencrypted-request.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/websocket-no-origin.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/empty-catch.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/react-ref-dom-manipulation.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/express-no-rate-limit.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/express-trust-proxy.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/react-unsafe-lifecycle.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/nextjs-ssr-secrets.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/timing-attack.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/redos.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/toctou.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/dynamic-require.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/postmessage-no-origin.yml"),
    ),
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
            std::env::current_dir()
                .unwrap_or_default()
                .join(".mycop-rules"),
            dirs_rules_path(),
        ];

        // Collect existing rule IDs to avoid duplicates
        let existing_ids: std::collections::HashSet<String> = registry
            .rules
            .values()
            .flat_map(|rules| rules.iter().map(|r| r.id.clone()))
            .collect();

        for dir in extra_dirs {
            if dir.exists() {
                if let Ok(extra) = Self::load(&dir) {
                    for (lang, rules) in extra.rules {
                        let new_rules: Vec<Rule> = rules
                            .into_iter()
                            .filter(|r| !existing_ids.contains(&r.id))
                            .collect();
                        if !new_rules.is_empty() {
                            registry.rules.entry(lang).or_default().extend(new_rules);
                        }
                    }
                }
            }
        }

        Ok(registry)
    }

    /// Load only the embedded (compiled-in) rules
    pub(crate) fn load_embedded() -> Result<Self> {
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

    /// Get count of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|r| r.len()).sum()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        assert!(
            registry.rule_count() >= 100,
            "Expected at least 100 embedded rules, got {}",
            registry.rule_count()
        );
    }

    #[test]
    fn test_rules_for_language_python() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let py_rules = registry.rules_for_language(&Language::Python);
        assert!(
            py_rules.len() >= 50,
            "Expected at least 50 Python rules, got {}",
            py_rules.len()
        );
    }

    #[test]
    fn test_rules_for_language_javascript() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let js_rules = registry.rules_for_language(&Language::JavaScript);
        assert!(
            js_rules.len() >= 50,
            "Expected at least 50 JavaScript rules, got {}",
            js_rules.len()
        );
    }

    #[test]
    fn test_typescript_uses_javascript_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let ts_rules = registry.rules_for_language(&Language::TypeScript);
        let js_rules = registry.rules_for_language(&Language::JavaScript);
        assert_eq!(ts_rules.len(), js_rules.len());
    }

    #[test]
    fn test_all_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let all = registry.all_rules();
        assert_eq!(all.len(), registry.rule_count());
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let registry = RuleRegistry::load(Path::new("/nonexistent/path/12345")).unwrap();
        assert_eq!(registry.rule_count(), 0);
    }
}
