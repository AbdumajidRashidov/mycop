#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rules_dir() -> PathBuf {
    project_root().join("rules")
}

fn fixtures_dir() -> PathBuf {
    project_root().join("tests").join("fixtures")
}

#[test]
fn test_python_vulnerable_file_has_findings() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();
    let scanner = mycop::scanner::Scanner::new(registry);

    let files = vec![fixtures_dir().join("python").join("vulnerable.py")];
    let findings = scanner.scan_files(&files).unwrap();

    assert!(
        !findings.is_empty(),
        "Expected findings in vulnerable.py but found none"
    );

    // Should detect SQL injection
    let sql_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.contains("SEC-001"))
        .collect();
    assert!(!sql_findings.is_empty(), "Expected SQL injection findings");

    // Should detect OS command injection
    let cmd_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.contains("SEC-002"))
        .collect();
    assert!(
        !cmd_findings.is_empty(),
        "Expected OS command injection findings"
    );

    // Should detect hardcoded secrets
    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.contains("SEC-003"))
        .collect();
    assert!(
        !secret_findings.is_empty(),
        "Expected hardcoded secret findings"
    );

    // Should detect eval/exec
    let eval_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.contains("SEC-005"))
        .collect();
    assert!(!eval_findings.is_empty(), "Expected eval/exec findings");
}

#[test]
fn test_python_safe_file_has_fewer_findings() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();
    let scanner = mycop::scanner::Scanner::new(registry);

    let vuln_files = vec![fixtures_dir().join("python").join("vulnerable.py")];
    let safe_files = vec![fixtures_dir().join("python").join("safe.py")];

    let vuln_findings = scanner.scan_files(&vuln_files).unwrap();
    let safe_findings = scanner.scan_files(&safe_files).unwrap();

    assert!(
        safe_findings.len() < vuln_findings.len(),
        "Safe file should have fewer findings ({}) than vulnerable file ({})",
        safe_findings.len(),
        vuln_findings.len()
    );
}

#[test]
fn test_javascript_vulnerable_file_has_findings() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();
    let scanner = mycop::scanner::Scanner::new(registry);

    let files = vec![fixtures_dir().join("javascript").join("vulnerable.js")];
    let findings = scanner.scan_files(&files).unwrap();

    assert!(
        !findings.is_empty(),
        "Expected findings in vulnerable.js but found none"
    );

    // Should detect XSS via innerHTML
    let xss_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name.contains("xss") || f.rule_name.contains("innerhtml"))
        .collect();
    assert!(!xss_findings.is_empty(), "Expected XSS findings");

    // Should detect eval injection
    let eval_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name.contains("eval"))
        .collect();
    assert!(
        !eval_findings.is_empty(),
        "Expected eval injection findings"
    );
}

#[test]
fn test_rule_loading() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();

    assert!(
        registry.rule_count() >= 100,
        "Expected at least 100 rules, got {}",
        registry.rule_count()
    );
}

#[test]
fn test_file_discovery() {
    let fixtures = fixtures_dir();
    let files = mycop::scanner::file_discovery::discover_files(&[fixtures], &[]).unwrap();

    assert!(
        files.len() >= 4,
        "Expected at least 4 fixture files, got {}",
        files.len()
    );

    // Should include Python files
    assert!(
        files
            .iter()
            .any(|f| f.extension().map(|e| e == "py").unwrap_or(false)),
        "Expected Python files in discovery"
    );

    // Should include JavaScript files
    assert!(
        files
            .iter()
            .any(|f| f.extension().map(|e| e == "js").unwrap_or(false)),
        "Expected JavaScript files in discovery"
    );
}

#[test]
fn test_language_detection() {
    use mycop::scanner::Language;
    use std::path::Path;

    assert_eq!(
        Language::from_extension(Path::new("test.py")),
        Some(Language::Python)
    );
    assert_eq!(
        Language::from_extension(Path::new("test.js")),
        Some(Language::JavaScript)
    );
    assert_eq!(
        Language::from_extension(Path::new("test.ts")),
        Some(Language::TypeScript)
    );
    assert_eq!(
        Language::from_extension(Path::new("test.tsx")),
        Some(Language::TypeScript)
    );
    assert_eq!(Language::from_extension(Path::new("test.rs")), None);
    assert_eq!(Language::from_extension(Path::new("test.txt")), None);
}

#[test]
fn test_severity_ordering() {
    use mycop::rules::parser::Severity;

    assert!(Severity::Critical.ordinal() > Severity::High.ordinal());
    assert!(Severity::High.ordinal() > Severity::Medium.ordinal());
    assert!(Severity::Medium.ordinal() > Severity::Low.ordinal());
    assert!(Severity::Low.ordinal() > Severity::Info.ordinal());
}

#[test]
fn test_findings_sorted_by_severity() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();
    let scanner = mycop::scanner::Scanner::new(registry);

    let files = vec![fixtures_dir().join("python").join("vulnerable.py")];
    let findings = scanner.scan_files(&files).unwrap();

    // Verify findings are sorted by severity (highest first)
    for window in findings.windows(2) {
        assert!(
            window[0].severity.ordinal() >= window[1].severity.ordinal()
                || window[0].file != window[1].file,
            "Findings should be sorted by severity"
        );
    }
}

// ============================================================
// Inline ignore tests
// ============================================================

#[test]
fn test_inline_ignore_suppresses_eval() {
    let registry = mycop::rules::RuleRegistry::load(&rules_dir()).unwrap();
    let scanner = mycop::scanner::Scanner::new(registry);

    let files = vec![fixtures_dir().join("python").join("with_ignores.py")];
    let findings = scanner.scan_files(&files).unwrap();

    // The eval on line 4 has "# mycop-ignore:PY-SEC-005" on line 3 — should be suppressed
    let eval_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.matched_text.contains("eval("))
        .collect();
    assert!(
        eval_findings.is_empty(),
        "eval should be suppressed by mycop-ignore, but found: {:?}",
        eval_findings
            .iter()
            .map(|f| &f.matched_text)
            .collect::<Vec<_>>()
    );

    // exec on line 6 has no ignore — should still be reported
    let exec_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.matched_text.contains("exec("))
        .collect();
    assert!(!exec_findings.is_empty(), "exec should still be reported");

    // os.system on line 8 has "# mycop-ignore" (blanket) on same line — should be suppressed
    let os_system_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.matched_text.contains("os.system"))
        .collect();
    assert!(
        os_system_findings.is_empty(),
        "os.system should be suppressed by blanket mycop-ignore"
    );
}

// ============================================================
// CLI integration tests
// ============================================================

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("mycop"));
}

#[test]
fn test_cli_scan_json_output() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("scan")
        .arg(fixtures_dir().join("python").join("vulnerable.py"))
        .arg("--format")
        .arg("json");
    cmd.assert()
        .stdout(predicate::str::contains("\"totalFindings\""))
        .stdout(predicate::str::contains("\"findings\""));
}

#[test]
fn test_cli_scan_sarif_output() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("scan")
        .arg(fixtures_dir().join("python").join("vulnerable.py"))
        .arg("--format")
        .arg("sarif");
    cmd.assert()
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""))
        .stdout(predicate::str::contains("\"driver\""));
}

#[test]
fn test_cli_scan_exits_one_on_vulnerable() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("scan")
        .arg(fixtures_dir().join("python").join("vulnerable.py"))
        .arg("--format")
        .arg("json");
    // vulnerable.py has critical findings → exit code 1
    cmd.assert().failure();
}

#[test]
fn test_cli_scan_fail_on_low_exits_one() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("scan")
        .arg(fixtures_dir().join("python").join("vulnerable.py"))
        .arg("--fail-on")
        .arg("low")
        .arg("--format")
        .arg("json");
    // Any finding at low+ should cause failure
    cmd.assert().failure();
}

#[test]
fn test_cli_rules_list() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("rules").arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PY-SEC-001"));
}

#[test]
fn test_cli_rules_list_filter_language() {
    let mut cmd = Command::cargo_bin("mycop").unwrap();
    cmd.arg("rules").arg("list").arg("--language").arg("python");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PY-SEC"));
}
