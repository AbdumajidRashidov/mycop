use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "mycop",
    version,
    about = "AI Code Security Scanner — detect vulnerabilities in AI-generated code",
    long_about = "mycop scans your codebase for security vulnerabilities using pattern matching,\n\
                  AST analysis, and optional AI-powered explanations and fix suggestions.\n\n\
                  Designed to catch the security issues that AI coding assistants commonly introduce."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan files or directories for security vulnerabilities
    Scan {
        /// Files or directories to scan (defaults to current directory)
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,

        /// Get AI-powered explanations for each finding
        #[arg(long)]
        explain: bool,

        /// Get AI-suggested fixes for each finding
        #[arg(long)]
        fix: bool,

        /// Auto-apply AI-suggested fixes to files (requires --fix)
        #[arg(long, requires = "fix")]
        apply: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "terminal")]
        format: OutputFormat,

        /// Minimum severity level to report
        #[arg(long, value_enum)]
        severity: Option<SeverityFilter>,

        /// Only scan files changed in git diff
        #[arg(long)]
        diff: bool,

        /// Override AI provider selection
        #[arg(long, value_enum)]
        ai_provider: Option<AiProviderChoice>,

        /// Path to config file
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Auto-fix security vulnerabilities using AI (rewrites files)
    Fix {
        /// Files or directories to fix (defaults to current directory)
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,

        /// Minimum severity level to fix
        #[arg(long, value_enum)]
        severity: Option<SeverityFilter>,

        /// Show what would change without writing files
        #[arg(long)]
        dry_run: bool,

        /// Override AI provider selection
        #[arg(long, value_enum)]
        ai_provider: Option<AiProviderChoice>,

        /// Only fix files changed in git diff
        #[arg(long)]
        diff: bool,
    },

    /// Deep AI security review of a file
    Review {
        /// File to review
        file: PathBuf,

        /// Override AI provider selection
        #[arg(long, value_enum)]
        ai_provider: Option<AiProviderChoice>,
    },

    /// Initialize a .scanrc.yml config file
    Init,

    /// Manage security rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Check dependencies for issues
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List all available security rules
    List {
        /// Filter by language
        #[arg(long)]
        language: Option<String>,

        /// Filter by severity
        #[arg(long, value_enum)]
        severity: Option<SeverityFilter>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DepsAction {
    /// Check for hallucinated or non-existent packages
    Check {
        /// Path to requirements.txt, package.json, etc.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, PartialOrd)]
pub enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum AiProviderChoice {
    ClaudeCli,
    Anthropic,
    Openai,
    Ollama,
    None,
}
