use anyhow::Result;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::rules::matcher::Finding;
use crate::rules::registry::RuleRegistry;
use crate::scanner::language::Language;

pub struct Scanner {
    registry: Arc<RuleRegistry>,
}

impl Scanner {
    pub fn new(registry: RuleRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }

    /// Scan a list of files and return all findings
    pub fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<Finding>> {
        let findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));

        files.par_iter().for_each(|file| {
            match self.scan_file(file) {
                Ok(file_findings) => {
                    let mut all = findings.lock().unwrap();
                    all.extend(file_findings);
                }
                Err(e) => {
                    eprintln!("Warning: failed to scan {}: {}", file.display(), e);
                }
            }
        });

        let mut results = Arc::try_unwrap(findings)
            .unwrap()
            .into_inner()
            .unwrap();

        // Sort by severity (critical first) then by file path
        results.sort_by(|a, b| {
            b.severity
                .ordinal()
                .cmp(&a.severity.ordinal())
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        Ok(results)
    }

    /// Scan a single file
    fn scan_file(&self, path: &PathBuf) -> Result<Vec<Finding>> {
        let language = Language::from_extension(path)
            .ok_or_else(|| anyhow::anyhow!("Unsupported language: {}", path.display()))?;

        let content = std::fs::read_to_string(path)?;
        let rules = self.registry.rules_for_language(&language);

        let mut findings = Vec::new();

        for rule in rules {
            let rule_findings =
                crate::rules::matcher::match_rule(rule, &content, path, &language)?;
            findings.extend(rule_findings);
        }

        Ok(findings)
    }
}
