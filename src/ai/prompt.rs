use crate::rules::matcher::Finding;

/// Generate prompt for explaining a vulnerability
pub fn explain_prompt(finding: &Finding, code_context: &str) -> String {
    format!(
        r#"You are a security expert. Explain this vulnerability in plain English.

Vulnerability: {} ({})
Severity: {}
CWE: {}
File: {}:{}

Code:
```
{}
```

Matched pattern: {}

Provide:
1. A clear explanation of why this is dangerous (2-3 sentences)
2. A realistic attack scenario (1-2 sentences)
3. The potential impact

Keep your response concise and actionable. No markdown headers."#,
        finding.rule_name,
        finding.description,
        finding.severity,
        finding.cwe.as_deref().unwrap_or("N/A"),
        finding.file.display(),
        finding.line,
        code_context,
        finding.matched_text,
    )
}

/// Generate prompt for suggesting a fix
pub fn fix_prompt(finding: &Finding, code_context: &str) -> String {
    format!(
        r#"You are a security expert. Fix this vulnerability.

Vulnerability: {} ({})
Severity: {}
CWE: {}
File: {}:{}

Vulnerable code:
```
{}
```

Matched pattern: {}
{}

Provide:
1. A brief explanation of the fix (1-2 sentences)
2. The corrected code (just the fixed version, ready to use)

Format the fixed code in a code block. Keep explanation minimal."#,
        finding.rule_name,
        finding.description,
        finding.severity,
        finding.cwe.as_deref().unwrap_or("N/A"),
        finding.file.display(),
        finding.line,
        code_context,
        finding.matched_text,
        finding
            .fix_hint
            .as_ref()
            .map(|h| format!("\nHint: {}", h))
            .unwrap_or_default(),
    )
}

/// Generate prompt for fixing an entire file (agentic mode)
/// Groups all findings for a file into one prompt, asks AI to return the complete fixed file.
pub fn fix_file_prompt(
    file_path: &str,
    language: &str,
    file_content: &str,
    findings: &[&Finding],
) -> String {
    let mut vulns = String::new();
    for (i, f) in findings.iter().enumerate() {
        vulns.push_str(&format!(
            "{}. Line {}: {} ({}) -- {}\n",
            i + 1,
            f.line,
            f.rule_name.replace('-', " "),
            f.cwe.as_deref().unwrap_or("N/A"),
            f.message,
        ));
        if let Some(ref hint) = f.fix_hint {
            vulns.push_str(&format!("   Hint: {}\n", hint));
        }
    }

    format!(
        r#"You are a security engineer. Fix ALL the security vulnerabilities listed below in this file.

RULES:
- Return ONLY the complete fixed file content between <FIXED_FILE> and </FIXED_FILE> tags.
- Do NOT add explanatory comments about your changes.
- Do NOT remove or change any existing functionality.
- Preserve the original formatting, indentation, and code style.
- Fix ONLY the listed vulnerabilities, nothing else.

File: {file_path}
Language: {language}

VULNERABILITIES TO FIX:
{vulns}
FULL FILE CONTENT:
<FILE>
{file_content}
</FILE>

Return the complete fixed file between <FIXED_FILE> and </FIXED_FILE> tags. Nothing else."#
    )
}

/// Generate prompt for deep file review
pub fn review_prompt(file_content: &str, language: &str) -> String {
    format!(
        r#"You are a senior security engineer performing a deep security code review.

Language: {}

Review this code for security vulnerabilities, focusing on:
1. Authentication and authorization issues
2. Input validation and sanitization
3. Injection vulnerabilities (SQL, command, XSS, etc.)
4. Sensitive data exposure (hardcoded secrets, logging PII)
5. Race conditions and TOCTOU issues
6. Insecure cryptographic practices
7. Path traversal and file access issues
8. Deserialization vulnerabilities
9. Logic flaws that could be exploited
10. Missing security headers or configurations

Code:
```{}
{}
```

For each issue found, provide:
- Line number(s)
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Description of the vulnerability
- How it could be exploited
- Recommended fix

If no significant issues are found, say so clearly."#,
        language, language, file_content
    )
}
