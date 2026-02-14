use serde_json::json;
use std::collections::HashMap;

use crate::reporter::Reporter;
use crate::rules::matcher::Finding;

pub struct JsonReporter;

impl JsonReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Reporter for JsonReporter {
    fn report(
        &self,
        findings: &[Finding],
        ai_results: &HashMap<usize, String>,
    ) -> anyhow::Result<String> {
        let findings_json: Vec<serde_json::Value> = findings
            .iter()
            .enumerate()
            .map(|(idx, f)| {
                let mut obj = json!({
                    "ruleId": f.rule_id,
                    "ruleName": f.rule_name,
                    "severity": f.severity.label(),
                    "file": f.file.display().to_string(),
                    "line": f.line,
                    "column": f.column,
                    "matchedText": f.matched_text,
                    "message": f.message,
                    "description": f.description,
                });

                if let Some(ref cwe) = f.cwe {
                    obj["cwe"] = json!(cwe);
                }
                if let Some(ref owasp) = f.owasp {
                    obj["owasp"] = json!(owasp);
                }
                if let Some(ref hint) = f.fix_hint {
                    obj["fixHint"] = json!(hint);
                }
                if !f.references.is_empty() {
                    obj["references"] = json!(f.references);
                }
                if let Some(ai_text) = ai_results.get(&idx) {
                    obj["aiExplanation"] = json!(ai_text);
                }

                obj
            })
            .collect();

        let output = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "totalFindings": findings.len(),
            "findings": findings_json,
        });

        let json_str = serde_json::to_string_pretty(&output)?;
        println!("{}", json_str);
        Ok(json_str)
    }
}
