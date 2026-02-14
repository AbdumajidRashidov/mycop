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
    assert!(
        !sql_findings.is_empty(),
        "Expected SQL injection findings"
    );

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
    assert!(
        !eval_findings.is_empty(),
        "Expected eval/exec findings"
    );
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
    assert!(
        !xss_findings.is_empty(),
        "Expected XSS findings"
    );

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
        registry.rule_count() >= 20,
        "Expected at least 20 rules, got {}",
        registry.rule_count()
    );
}

#[test]
fn test_file_discovery() {
    let fixtures = fixtures_dir();
    let files = mycop::scanner::file_discovery::discover_files(&[fixtures]).unwrap();

    assert!(
        files.len() >= 4,
        "Expected at least 4 fixture files, got {}",
        files.len()
    );

    // Should include Python files
    assert!(
        files.iter().any(|f| f.extension().map(|e| e == "py").unwrap_or(false)),
        "Expected Python files in discovery"
    );

    // Should include JavaScript files
    assert!(
        files.iter().any(|f| f.extension().map(|e| e == "js").unwrap_or(false)),
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
