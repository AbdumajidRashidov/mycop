# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is mycop

mycop is an AI-powered code security scanner (SAST) written in Rust. It detects vulnerabilities in AI-generated code targeting Python, JavaScript, and TypeScript, with 100 built-in YAML security rules covering OWASP Top 10 and CWE Top 25.

## Build & Development Commands

```bash
cargo build                    # Debug build
cargo build --release          # Optimized release build
cargo test --verbose           # Run all tests
cargo test scanner_tests       # Run a specific test module
cargo fmt --all -- --check     # Check formatting (CI enforced)
cargo clippy --all-targets -- -D warnings  # Lint (CI enforced, warnings are errors)
```

CI runs on both Ubuntu and macOS with stable Rust. All PRs must pass fmt, clippy, build, and test.

## Architecture

### Data Flow

CLI parsing (clap) → Config loading (.scanrc.yml) → File discovery (walkdir + gitignore) → Rule loading (embedded YAML via `include_str!`) → Parallel scanning (Rayon) → Severity filtering → Optional AI processing → Output reporting

### Module Map (`src/`)

- **cli.rs** — Clap-derived CLI definitions. Subcommands: `scan`, `fix`, `review`, `init`, `rules list`, `deps check`, `mcp`
- **main.rs** — Command routing and orchestration for all subcommands
- **scanner/** — Core scanning engine
  - `engine.rs` — Parallel file scanning with Rayon (`scan_files` returns `Vec<Finding>`)
  - `language.rs` — Language detection from file extensions (Python, JS, TS)
  - `file_discovery.rs` — File globbing, gitignore-aware traversal, `--diff` mode via git
- **rules/** — Security rule system
  - `registry.rs` — Loads 100 YAML rules embedded at compile time via `include_str!` from `rules/python/` and `rules/javascript/`
  - `matcher.rs` — Pattern matching using tree-sitter AST queries + regex. Produces `Finding` structs
  - `parser.rs` — YAML rule deserialization
- **ai/** — Pluggable AI backends behind the `AiBackend` trait
  - `types.rs` — `AiBackend` trait with `explain()`, `deep_review()`, `fix_file()` methods
  - `mod.rs` — Auto-detection and factory (`detect_ai_provider`, `create_backend`). Priority: Claude CLI → Anthropic API → OpenAI API → Ollama → rule-based fallback
  - Provider impls: `claude_cli.rs`, `anthropic.rs`, `openai.rs`, `ollama.rs`, `rule_based.rs`
  - `prompt.rs` — Prompt templates for AI interactions
- **fixer.rs** — Auto-fix flow: groups findings per file, sends to AI, extracts `<FIXED_FILE>` tags from response, generates diffs, optionally writes back and re-scans for verification. Also provides `diff_to_string()` for generating plain-text diffs (used by MCP fix tool)
- **mcp/** — MCP (Model Context Protocol) server for agentic tool integration
  - `mod.rs` — `MycopMcpServer` struct implementing `ServerHandler` trait. Handles `list_tools`, `call_tool`, `list_resources`, `read_resource`. Starts STDIO transport via `MycopMcpServer::run()`
  - `tools.rs` — 6 MCP tools implemented on `MycopMcpServer` using `#[tool]` proc macro: `scan`, `list_rules`, `explain_finding`, `fix`, `review`, `check_deps`. Sync impl functions bridged to async via `tokio::task::spawn_blocking`. Tools registered via `rmcp::tool_box!` macro
  - `types.rs` — MCP-specific request/response schemas with `Deserialize + JsonSchema` (inputs) and `Serialize` (outputs). Separate from core types to isolate MCP concerns
  - `convert.rs` — Conversions between core types (`Finding`, `Rule`) and MCP output types (`FindingOutput`, `RuleOutput`)
- **reporter/** — Output formatters implementing the `Reporter` trait
  - `terminal.rs` (colored), `json.rs`, `sarif.rs` (for CI/IDE integration)
- **config/scanrc.rs** — Loads `.scanrc.yml` / `.mycop.yml` config (ignore patterns, min_severity, fail_on, ai_provider)

### Rules (`rules/`)

100 YAML files (50 Python in `rules/python/`, 50 JavaScript in `rules/javascript/`). Each rule has: id, name, severity, CWE/OWASP mappings, pattern (regex and/or AST query), message, fix_hint. Rules are embedded into the binary at compile time.

Inline suppression: `# mycop-ignore` or `# mycop-ignore:RULE-ID`

### Key Design Patterns

- **Embedded rules** — No external files needed at runtime; YAML rules compiled into the binary
- **AST + regex dual matching** — tree-sitter AST queries for structural analysis, regex for broader detection, with deduplication
- **AI provider chain** — Auto-detects available providers with graceful fallback
- **Parallel scanning** — Rayon parallel iterators with `Arc<Mutex>` for collecting findings
- **Severity ordinals** — Critical=4, High=3, Medium=2, Low=1, Info=0; default fail threshold is High
- **MCP sync-to-async bridge** — Core scanning uses Rayon (sync); MCP server uses tokio (async). Bridged with `tokio::task::spawn_blocking`. All stdout reserved for JSON-RPC in MCP mode; diagnostics go to stderr
- **Separate MCP types** — `FindingOutput`/`RuleOutput` instead of adding `Serialize`/`JsonSchema` to core `Finding`/`Rule`, keeping MCP concerns isolated

## Tests

Integration tests in `tests/scanner_tests.rs` with fixtures in `tests/fixtures/`. Tests cover file discovery, rule parsing, finding deduplication, config loading, and severity filtering.
