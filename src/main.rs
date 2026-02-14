mod ai;
mod ast;
mod cli;
mod config;
mod fixer;
mod reporter;
mod rules;
mod scanner;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Commands, OutputFormat, SeverityFilter};
use config::ScanConfig;
use reporter::Reporter;
use rules::RuleRegistry;
use scanner::Scanner;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            paths,
            explain,
            fix,
            apply: _,
            format,
            severity,
            diff,
            ai_provider,
            config,
        } => {
            if fix {
                // --fix now triggers the agentic auto-fix flow (same as `mycop fix`)
                cmd_fix(paths, severity, false, ai_provider, diff)?;
            } else {
                cmd_scan(
                    paths,
                    explain,
                    format,
                    severity,
                    diff,
                    ai_provider,
                    config,
                )?;
            }
        }
        Commands::Fix {
            paths,
            severity,
            dry_run,
            ai_provider,
            diff,
        } => {
            cmd_fix(paths, severity, dry_run, ai_provider, diff)?;
        }
        Commands::Review { file, ai_provider } => {
            cmd_review(file, ai_provider)?;
        }
        Commands::Init => {
            cmd_init()?;
        }
        Commands::Rules { action } => match action {
            cli::RulesAction::List { language, severity } => {
                cmd_rules_list(language, severity)?;
            }
        },
        Commands::Deps { action } => match action {
            cli::DepsAction::Check { path } => {
                cmd_deps_check(path)?;
            }
        },
    }

    Ok(())
}

fn cmd_scan(
    paths: Vec<PathBuf>,
    explain: bool,
    format: OutputFormat,
    severity: Option<SeverityFilter>,
    diff: bool,
    ai_provider_choice: Option<cli::AiProviderChoice>,
    _config_path: Option<PathBuf>,
) -> Result<()> {
    let start = Instant::now();

    // Load config
    let _config = ScanConfig::load(&std::env::current_dir()?)?;

    // Load rules
    let registry = RuleRegistry::load_default()?;
    let rule_count = registry.rule_count();

    if rule_count == 0 {
        eprintln!(
            "{}",
            "Warning: no rules loaded. Make sure the rules/ directory exists."
                .yellow()
        );
    }

    // Discover files
    let files = if diff {
        scanner::file_discovery::discover_diff_files(&std::env::current_dir()?)?
    } else {
        scanner::file_discovery::discover_files(&paths)?
    };

    if files.is_empty() {
        println!("\n  {} No supported files found to scan.\n", "i".blue());
        return Ok(());
    }

    // Show scanning progress
    if format == OutputFormat::Terminal {
        println!(
            "\n  {} Scanning {} file{} with {} rule{}...\n",
            ">".cyan(),
            files.len(),
            if files.len() == 1 { "" } else { "s" },
            rule_count,
            if rule_count == 1 { "" } else { "s" },
        );
    }

    // Scan
    let scanner = Scanner::new(registry);
    let mut findings = scanner.scan_files(&files)?;

    // Filter by severity
    if let Some(ref min_severity) = severity {
        let min_ord = match min_severity {
            SeverityFilter::Critical => 4,
            SeverityFilter::High => 3,
            SeverityFilter::Medium => 2,
            SeverityFilter::Low => 1,
        };
        findings.retain(|f| f.severity.ordinal() >= min_ord);
    }

    // AI processing (--explain)
    let mut ai_results: HashMap<usize, String> = HashMap::new();

    if explain && !findings.is_empty() {
        let provider = match ai_provider_choice {
            Some(ref choice) => ai::provider_from_choice(choice),
            None => ai::detect_ai_provider(),
        };

        if format == OutputFormat::Terminal {
            println!(
                "  [AI] Using provider: {}\n",
                provider.to_string().cyan()
            );
        }

        let backend = ai::create_backend(&provider);

        let pb = if format == OutputFormat::Terminal {
            let pb = ProgressBar::new(findings.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("  Processing findings [{bar:30}] {pos}/{len}")
                    .unwrap(),
            );
            Some(pb)
        } else {
            None
        };

        for (idx, finding) in findings.iter().enumerate() {
            let code_context = read_context(&finding.file, finding.line, 5)?;

            let result = backend.explain(finding, &code_context);

            match result {
                Ok(text) => {
                    ai_results.insert(idx, text);
                }
                Err(e) => {
                    if format == OutputFormat::Terminal {
                        eprintln!("  Warning: AI error for {}: {}", finding.rule_id, e);
                    }
                }
            }

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    }

    // Report
    let reporter: Box<dyn Reporter> = match format {
        OutputFormat::Terminal => Box::new(reporter::terminal::TerminalReporter::new()),
        OutputFormat::Json => Box::new(reporter::json::JsonReporter::new()),
        OutputFormat::Sarif => Box::new(reporter::sarif::SarifReporter::new()),
    };

    reporter.report(&findings, &ai_results)?;

    let elapsed = start.elapsed();
    if format == OutputFormat::Terminal {
        println!(
            "  Scan completed in {:.2}s\n",
            elapsed.as_secs_f64()
        );
    }

    // Exit with non-zero if critical/high findings
    if findings
        .iter()
        .any(|f| f.severity.ordinal() >= 3)
    {
        std::process::exit(1);
    }

    Ok(())
}

fn cmd_fix(
    paths: Vec<PathBuf>,
    severity: Option<SeverityFilter>,
    dry_run: bool,
    ai_provider_choice: Option<cli::AiProviderChoice>,
    diff: bool,
) -> Result<()> {
    let start = Instant::now();

    // Detect AI provider
    let provider = match ai_provider_choice {
        Some(ref choice) => ai::provider_from_choice(choice),
        None => ai::detect_ai_provider(),
    };

    println!(
        "\n  {} mycop fix — auto-fixing security vulnerabilities",
        ">".cyan().bold()
    );
    println!(
        "  {} AI provider: {}",
        ">".cyan(),
        provider.to_string().cyan()
    );
    if dry_run {
        println!("  {} Dry run mode — no files will be modified", ">".yellow());
    }
    println!();

    // Load rules and discover files
    let registry = RuleRegistry::load_default()?;
    let files = if diff {
        scanner::file_discovery::discover_diff_files(&std::env::current_dir()?)?
    } else {
        scanner::file_discovery::discover_files(&paths)?
    };

    if files.is_empty() {
        println!("  No supported files found.\n");
        return Ok(());
    }

    // Scan
    let scan = Scanner::new(registry);
    let mut findings = scan.scan_files(&files)?;

    // Filter by severity
    if let Some(ref min_severity) = severity {
        let min_ord = match min_severity {
            SeverityFilter::Critical => 4,
            SeverityFilter::High => 3,
            SeverityFilter::Medium => 2,
            SeverityFilter::Low => 1,
        };
        findings.retain(|f| f.severity.ordinal() >= min_ord);
    }

    if findings.is_empty() {
        println!("  {} No security issues found — nothing to fix.\n", "OK".green().bold());
        return Ok(());
    }

    let total_findings = findings.len();
    println!(
        "  Found {} vulnerabilit{} across {} file{}.\n",
        total_findings,
        if total_findings == 1 { "y" } else { "ies" },
        files.len(),
        if files.len() == 1 { "" } else { "s" }
    );

    // Group findings by file
    let mut by_file: std::collections::BTreeMap<PathBuf, Vec<&crate::rules::matcher::Finding>> =
        std::collections::BTreeMap::new();
    for f in &findings {
        by_file.entry(f.file.clone()).or_default().push(f);
    }

    let backend = ai::create_backend(&provider);
    let mut files_fixed = 0;
    let mut vulns_fixed = 0;

    for (file_path, file_findings) in &by_file {
        let file_display = file_path.display().to_string();
        let lang = scanner::Language::from_extension(file_path)
            .map(|l| l.name().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let count = file_findings.len();
        println!(
            "  {} {} — {} vulnerabilit{}",
            "Fixing".yellow().bold(),
            file_display.white().bold(),
            count,
            if count == 1 { "y" } else { "ies" }
        );

        // Read original file
        let original = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("    {} Could not read file: {}", "!".red(), e);
                continue;
            }
        };

        // Ask AI to fix the entire file
        let response = match backend.fix_file(&file_display, &lang, &original, file_findings) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("    {} AI error: {}", "!".red(), e);
                continue;
            }
        };

        // Extract fixed file content
        let fixed = match fixer::extract_fixed_file(&response) {
            Some(f) => f,
            None => {
                eprintln!(
                    "    {} Could not parse AI response (no <FIXED_FILE> tags found)",
                    "!".red()
                );
                continue;
            }
        };

        // Skip if no changes
        if fixed.trim() == original.trim() {
            println!("    {} No changes needed", "=".dimmed());
            continue;
        }

        // Show diff
        fixer::print_diff(&file_display, &original, &fixed);

        // Write file (unless dry run)
        if !dry_run {
            std::fs::write(file_path, &fixed)?;
            println!(
                "    {} Wrote {}",
                "OK".green().bold(),
                file_display
            );
        } else {
            println!(
                "    {} Would write {} (dry run)",
                "--".dimmed(),
                file_display
            );
        }

        files_fixed += 1;
        vulns_fixed += count;
        println!();
    }

    // Verification re-scan (only if we actually wrote files)
    if !dry_run && files_fixed > 0 {
        println!("  {} Re-scanning to verify fixes...", ">".cyan());

        let registry2 = RuleRegistry::load_default()?;
        let scan2 = Scanner::new(registry2);
        let fixed_files: Vec<PathBuf> = by_file.keys().cloned().collect();
        let remaining = scan2.scan_files(&fixed_files)?;

        let remaining_count = remaining.len();
        if remaining_count == 0 {
            println!(
                "  {} All {} vulnerabilities fixed!\n",
                "OK".green().bold(),
                total_findings
            );
        } else {
            println!(
                "  {} {} -> {} vulnerabilities remaining\n",
                ">".yellow(),
                total_findings,
                remaining_count
            );
        }
    }

    // Summary
    let elapsed = start.elapsed();
    println!(
        "  {} {} file{} fixed, {} vulnerabilit{} addressed in {:.1}s\n",
        if dry_run { "DRY RUN" } else { "Done:" },
        files_fixed,
        if files_fixed == 1 { "" } else { "s" },
        vulns_fixed,
        if vulns_fixed == 1 { "y" } else { "ies" },
        elapsed.as_secs_f64()
    );

    Ok(())
}

fn cmd_review(file: PathBuf, ai_provider_choice: Option<cli::AiProviderChoice>) -> Result<()> {
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }

    let language = scanner::Language::from_extension(&file)
        .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {}", file.display()))?;

    let content = std::fs::read_to_string(&file)?;

    let provider = match ai_provider_choice {
        Some(ref choice) => ai::provider_from_choice(choice),
        None => ai::detect_ai_provider(),
    };

    println!(
        "\n  [Review] Deep security review of {}",
        file.display().to_string().white().bold()
    );
    println!(
        "  [AI] Using provider: {}\n",
        provider.to_string().cyan()
    );

    let backend = ai::create_backend(&provider);

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  Analyzing file...")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let result = backend.deep_review(&content, language.name())?;

    pb.finish_and_clear();

    println!("{}", result);
    println!();

    Ok(())
}

fn cmd_init() -> Result<()> {
    let path = std::env::current_dir()?.join(".scanrc.yml");

    if path.exists() {
        println!("  .scanrc.yml already exists");
        return Ok(());
    }

    std::fs::write(&path, ScanConfig::default_content())?;
    println!(
        "  {} Created .scanrc.yml",
        "OK".green().bold()
    );

    Ok(())
}

fn cmd_rules_list(language: Option<String>, severity: Option<SeverityFilter>) -> Result<()> {
    let registry = RuleRegistry::load_default()?;
    let all_rules = registry.all_rules();

    if all_rules.is_empty() {
        println!("\n  No rules loaded.\n");
        return Ok(());
    }

    println!(
        "\n  Available rules ({} total):\n",
        all_rules.len()
    );

    for rule in &all_rules {
        // Filter by language
        if let Some(ref lang) = language {
            if &rule.language != lang {
                continue;
            }
        }

        // Filter by severity
        if let Some(ref min_sev) = severity {
            let min_ord = match min_sev {
                SeverityFilter::Critical => 4,
                SeverityFilter::High => 3,
                SeverityFilter::Medium => 2,
                SeverityFilter::Low => 1,
            };
            if rule.severity.ordinal() < min_ord {
                continue;
            }
        }

        let sev = match rule.severity.label() {
            "CRITICAL" => "CRIT".red().bold(),
            "HIGH" => "HIGH".red(),
            "MEDIUM" => "MED ".yellow(),
            "LOW" => "LOW ".blue(),
            _ => "INFO".dimmed(),
        };

        println!(
            "  {} [{:>10}] {} -- {}",
            sev,
            rule.language.dimmed(),
            rule.id.white().bold(),
            rule.name
        );
    }

    println!();
    Ok(())
}

fn cmd_deps_check(path: PathBuf) -> Result<()> {
    println!(
        "\n  Checking dependencies in {}...\n",
        path.display()
    );

    // Check for requirements.txt
    let req_path = if path.is_file() {
        path.clone()
    } else {
        path.join("requirements.txt")
    };

    if req_path.exists()
        && req_path
            .file_name()
            .and_then(|f| f.to_str())
            == Some("requirements.txt")
    {
        let content = std::fs::read_to_string(&req_path)?;
        println!("  Checking Python packages in {}:", req_path.display());
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let pkg = line
                .split(['=', '>', '<', '!', ';', ' '])
                .next()
                .unwrap_or(line);
            println!("    - {}", pkg);
        }
        println!();
        println!(
            "  Dependency hallucination check requires an AI provider."
        );
        println!("  Run with --ai-provider to enable deep package verification.\n");
    }

    // Check for package.json
    let pkg_path = if path.is_file()
        && path
            .file_name()
            .and_then(|f| f.to_str())
            == Some("package.json")
    {
        path.clone()
    } else {
        path.join("package.json")
    };

    if pkg_path.exists() {
        let content = std::fs::read_to_string(&pkg_path)?;
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            println!("  Checking npm packages in {}:", pkg_path.display());
            if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                for (name, _) in deps {
                    println!("    - {}", name);
                }
            }
            if let Some(deps) = json.get("devDependencies").and_then(|d| d.as_object()) {
                for (name, _) in deps {
                    println!("    - {} (dev)", name);
                }
            }
            println!();
        }
    }

    Ok(())
}

fn read_context(file: &PathBuf, line: usize, context: usize) -> Result<String> {
    let content = std::fs::read_to_string(file)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(context + 1);
    let end = (line + context).min(lines.len());
    Ok(lines[start..end].join("\n"))
}

