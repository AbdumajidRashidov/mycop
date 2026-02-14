use serde_json::json;
use std::collections::HashMap;

use crate::reporter::Reporter;
use crate::rules::matcher::Finding;
use crate::rules::parser::Severity;

pub struct SarifReporter;

impl SarifReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Reporter for SarifReporter {
    fn report(
        &self,
        findings: &[Finding],
        _ai_results: &HashMap<usize, String>,
    ) -> anyhow::Result<String> {
        let rules: Vec<serde_json::Value> = collect_unique_rules(findings);

        let results: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "ruleId": f.rule_id,
                    "level": severity_to_sarif_level(&f.severity),
                    "message": {
                        "text": f.message
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.file.display().to_string()
                                },
                                "region": {
                                    "startLine": f.line,
                                    "startColumn": f.column
                                }
                            }
                        }
                    ]
                })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mycop",
                            "version": env!("CARGO_PKG_VERSION"),
                            "informationUri": "https://github.com/mycop/mycop",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        });

        let json_str = serde_json::to_string_pretty(&sarif)?;
        println!("{}", json_str);
        Ok(json_str)
    }
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn collect_unique_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for f in findings {
        if seen.insert(f.rule_id.clone()) {
            let mut rule = json!({
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {
                    "text": f.message.clone()
                },
                "fullDescription": {
                    "text": f.description.clone()
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                }
            });

            if let Some(ref cwe) = f.cwe {
                rule["properties"] = json!({
                    "tags": [cwe]
                });
            }

            rules.push(rule);
        }
    }

    rules
}
