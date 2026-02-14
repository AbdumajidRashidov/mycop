# mycop

AI Code Security Scanner — detect and auto-fix vulnerabilities in AI-generated code.

[![CI](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml/badge.svg)](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

mycop scans Python, JavaScript, and TypeScript codebases for security vulnerabilities using pattern matching, AST analysis, and optional AI-powered explanations and auto-fix. It ships with 20 built-in security rules covering OWASP Top 10 categories.

## Installation

### Install script (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/AbdumajidRashidov/mycop/main/install.sh | sh
```

### Homebrew

```bash
brew install mycop/tap/mycop
```

### Cargo

```bash
cargo install mycop
```

### Docker

```bash
docker run --rm -v "$(pwd):/src" -w /src mycop scan .
```

### Build from source

```bash
git clone https://github.com/AbdumajidRashidov/mycop.git
cd mycop
cargo install --path .
```

## Quick Start

```bash
# Scan current directory
mycop scan .

# Auto-fix all vulnerabilities using AI
mycop fix .

# Deep AI security review of a single file
mycop review src/auth.py

# Initialize config for your project
mycop init

# List all security rules
mycop rules list
```

## Commands

### `mycop scan`

Scan files for security vulnerabilities.

```bash
mycop scan .                              # Scan current directory
mycop scan src/ lib/                      # Scan specific directories
mycop scan --severity high                # Only report high/critical
mycop scan --fail-on critical             # Exit 1 only on critical findings
mycop scan --format json                  # JSON output
mycop scan --format sarif                 # SARIF output (for IDE integration)
mycop scan --explain                      # AI-powered explanations
mycop scan --diff                         # Only scan git-changed files
mycop scan --fix                          # Auto-fix (same as `mycop fix`)
```

Exit code 1 when findings meet the `--fail-on` threshold (default: high).

### `mycop fix`

Auto-fix security vulnerabilities using AI. Groups all findings per file, sends the entire file to an AI provider, and writes back the fixed version.

```bash
mycop fix .                               # Fix all files
mycop fix src/auth.py                     # Fix specific file
mycop fix . --severity high               # Only fix high/critical
mycop fix . --dry-run                     # Show diffs without writing
mycop fix . --ai-provider anthropic       # Force specific AI provider
mycop fix . --diff                        # Only fix git-changed files
```

### `mycop review`

Deep AI-powered security review of a single file. Goes beyond rule matching to find logic flaws, race conditions, and architectural issues.

```bash
mycop review src/server.ts
mycop review app.py --ai-provider openai
```

### `mycop init`

Generate a `.scanrc.yml` configuration file. Automatically detects your project type (Python, JavaScript/TypeScript, Rust) and pre-populates language-specific ignore patterns.

```bash
mycop init
```

### `mycop rules list`

List all available security rules.

```bash
mycop rules list                          # All rules
mycop rules list --language python        # Python rules only
mycop rules list --severity high          # High/critical rules only
```

### `mycop deps check`

Check dependencies for issues (hallucinated packages).

```bash
mycop deps check .
mycop deps check requirements.txt
```

## Inline Ignore

Suppress specific findings with inline comments:

```python
eval(user_input)  # mycop-ignore

# mycop-ignore:PY-SEC-005
eval(user_input)

eval(user_input)  # mycop-ignore:PY-SEC-005,PY-SEC-001
```

Works with `#` (Python) and `//` (JavaScript/TypeScript) comment styles. Place the comment on the same line or the line above.

## AI Providers

mycop auto-detects available AI providers in this order:

1. **Claude CLI** — `claude` command installed
2. **Anthropic API** — `ANTHROPIC_API_KEY` environment variable
3. **OpenAI API** — `OPENAI_API_KEY` environment variable
4. **Ollama** — local Ollama server running on port 11434
5. **Rule-based** — offline fallback using fix hints from rules

Override with `--ai-provider`:

```bash
mycop scan . --explain --ai-provider anthropic
mycop fix . --ai-provider ollama
```

## Configuration

Create a `.scanrc.yml` (or `.mycop.yml`) in your project root, or run `mycop init` to generate one:

```yaml
# File patterns to ignore (glob syntax)
ignore:
  - "**/*_test.py"
  - "**/test_*.py"
  - "**/*.test.js"
  - "**/*.spec.ts"
  - "**/node_modules/**"
  - "**/venv/**"

# Minimum severity level: critical, high, medium, low
min_severity: medium

# Minimum severity to cause non-zero exit: critical, high, medium, low
fail_on: high

# AI provider override: claude-cli, anthropic, openai, ollama, none
# ai_provider: anthropic
```

CLI flags always take priority over config file values.

## Security Rules

20 built-in rules covering:

| Category | Python | JavaScript |
|----------|--------|------------|
| SQL Injection (CWE-89) | PY-SEC-001 | — |
| Command Injection (CWE-78) | PY-SEC-002 | — |
| Hardcoded Secrets (CWE-798) | PY-SEC-003 | JS-SEC-004 |
| Insecure Random (CWE-330) | PY-SEC-004 | JS-SEC-005 |
| Eval/Exec Injection (CWE-95) | PY-SEC-005 | JS-SEC-002 |
| Path Traversal (CWE-22) | PY-SEC-006 | JS-SEC-006 |
| Insecure Deserialization (CWE-502) | PY-SEC-007 | JS-SEC-009 |
| Missing Auth (CWE-862) | PY-SEC-008 | — |
| XSS (CWE-79) | PY-SEC-009 | JS-SEC-001, JS-SEC-010 |
| Log Injection (CWE-117) | PY-SEC-010 | — |
| Prototype Pollution (CWE-1321) | — | JS-SEC-003 |
| SSRF (CWE-918) | — | JS-SEC-007 |
| NoSQL Injection (CWE-943) | — | JS-SEC-008 |

## Output Formats

- **Terminal** — colored output with code context (default)
- **JSON** — structured JSON for tool integration
- **SARIF** — Static Analysis Results Interchange Format for IDE/CI integration

## Integrations

### GitHub Action

Add mycop to your CI pipeline with the official GitHub Action:

```yaml
- name: mycop Security Scan
  uses: AbdumajidRashidov/mycop/action@main
  with:
    paths: '.'
    fail-on: 'high'
    format: 'sarif'
```

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | `.` | Files or directories to scan |
| `severity` | | Minimum severity to report |
| `fail-on` | `high` | Minimum severity to fail the check |
| `format` | `terminal` | Output format (`terminal`, `json`, `sarif`) |
| `version` | `latest` | mycop version to install |
| `diff-only` | `false` | Only scan files changed in the PR |

Upload SARIF results to GitHub Code Scanning:

```yaml
- name: mycop Security Scan
  uses: AbdumajidRashidov/mycop/action@main
  with:
    format: 'sarif'

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mycop-results.sarif
```

### Pre-commit Hook

Add mycop as a [pre-commit](https://pre-commit.com/) hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/AbdumajidRashidov/mycop
    rev: main
    hooks:
      - id: mycop
```

### VS Code Extension

The `vscode-extension/` directory contains a VS Code extension that provides:

- Real-time scanning on file save
- Diagnostics in the Problems panel
- "Scan Current File" and "Scan Workspace" commands
- Configurable severity threshold

See [vscode-extension/README.md](vscode-extension/README.md) for setup instructions.

### Docker

```bash
# Scan current directory
docker run --rm -v "$(pwd):/src" -w /src mycop scan .

# Scan with specific options
docker run --rm -v "$(pwd):/src" -w /src mycop scan . --format json --severity high
```

## License

MIT
