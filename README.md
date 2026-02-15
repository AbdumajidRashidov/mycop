# mycop

AI Code Security Scanner — detect and auto-fix vulnerabilities in AI-generated code.

[![CI](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml/badge.svg)](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mycop.svg)](https://crates.io/crates/mycop)
[![Downloads](https://img.shields.io/crates/d/mycop.svg)](https://crates.io/crates/mycop)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/AbdumajidRashidov/mycop.svg?style=social)](https://github.com/AbdumajidRashidov/mycop)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

mycop scans Python, JavaScript, and TypeScript codebases for security vulnerabilities using pattern matching, AST analysis, and optional AI-powered explanations and auto-fix. It ships with 100 built-in security rules covering OWASP Top 10 and CWE Top 25 categories.

<p align="center">
  <img src="docs/demo.gif" alt="mycop demo — scanning Python code for security vulnerabilities" width="750">
</p>

## Why mycop?

**AI-generated code is fast, but it is not safe.** [Research from Veracode](https://www.veracode.com/) shows that **45% of AI-generated code contains security vulnerabilities**. Copilot, ChatGPT, and other AI assistants produce functional code that often includes SQL injection, hardcoded secrets, command injection, and other critical flaws.

mycop was built specifically to solve this problem:

- **First SAST tool designed for AI-generated code** -- 100 rules targeting the exact vulnerability patterns that LLMs produce most often, covering OWASP Top 10 and CWE Top 25.
- **AI-powered auto-fix, not just detection** -- mycop does not just find vulnerabilities, it fixes them. The `mycop fix` command rewrites insecure code using AI while preserving functionality.
- **Multi-language with a single tool** -- scan Python, JavaScript, and TypeScript codebases without juggling Bandit, ESLint, and separate configs.
- **Zero configuration** -- all 100 security rules are compiled into the binary. No rule downloads, no config files, no internet connection required. Just `mycop scan .` and go.
- **MCP server for agentic workflows** -- plug mycop directly into Claude Code, Cursor, Windsurf, and other AI coding assistants via the Model Context Protocol.
- **Free and open source** -- MIT licensed, forever.

## Installation

### Install script (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/AbdumajidRashidov/mycop/main/install.sh | sh
```

### Homebrew

```bash
brew install AbdumajidRashidov/tap/mycop
```

### Cargo

```bash
cargo install mycop
```

### Docker

```bash
docker run --rm -v "$(pwd):/src" -w /src ghcr.io/abdumajidrashidov/mycop scan .
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

### `mycop mcp`

Start an MCP (Model Context Protocol) server over STDIO for agentic tool integration. This lets AI coding assistants call mycop's scanning, fixing, and review capabilities directly.

```bash
mycop mcp
```

**Tools exposed:**

| Tool | Description |
|------|-------------|
| `scan` | Scan files/directories for vulnerabilities with severity filtering |
| `list_rules` | Browse/filter the 100 built-in security rules |
| `explain_finding` | Detailed explanation of a specific finding with CWE/OWASP info |
| `review` | Deep AI security review of a file |
| `check_deps` | Detect hallucinated packages in dependencies |

> **Note:** The CLI `mycop fix` command is still available for standalone use. In MCP mode, the agent reads scan findings (with `fix_hint`) and applies fixes directly — no redundant AI-to-AI call needed.

**Resources:** `mycop://rules/catalog` (full JSON catalog) and `mycop://config/schema` (config template).

**Configure in Claude Code** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "mycop": {
      "command": "mycop",
      "args": ["mcp"]
    }
  }
}
```

**Configure in Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "mycop": {
      "command": "mycop",
      "args": ["mcp"],
      "type": "stdio"
    }
  }
}
```

**Configure in Windsurf** (`.windsurf/mcp.json`):

```json
{
  "mcpServers": {
    "mycop": {
      "command": "mycop",
      "args": ["mcp"]
    }
  }
}
```

Works with any MCP-compatible client including Codex CLI, Gemini CLI, and other agentic IDEs.

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

100 built-in rules (50 Python + 50 JavaScript) covering OWASP Top 10, CWE Top 25, and more:

| Category | Python | JavaScript |
|----------|--------|------------|
| SQL Injection (CWE-89) | PY-SEC-001, PY-SEC-042 | JS-SEC-011 |
| Command Injection (CWE-78) | PY-SEC-002, PY-SEC-045, PY-SEC-050 | JS-SEC-016 |
| Hardcoded Secrets (CWE-798) | PY-SEC-003, PY-SEC-034, PY-SEC-043 | JS-SEC-004, JS-SEC-034 |
| Insecure Random (CWE-330) | PY-SEC-004 | JS-SEC-005 |
| Eval/Exec Injection (CWE-95) | PY-SEC-005 | JS-SEC-002, JS-SEC-049 |
| Path Traversal (CWE-22) | PY-SEC-006, PY-SEC-037 | JS-SEC-006, JS-SEC-037 |
| Insecure Deserialization (CWE-502) | PY-SEC-007 | JS-SEC-009 |
| Missing Auth (CWE-862) | PY-SEC-008 | — |
| XSS (CWE-79) | PY-SEC-009, PY-SEC-044 | JS-SEC-001, JS-SEC-010, JS-SEC-041 |
| Log Injection (CWE-117) | PY-SEC-010 | — |
| SSRF (CWE-918) | PY-SEC-011 | JS-SEC-007 |
| XXE (CWE-611) | PY-SEC-012 | JS-SEC-012 |
| LDAP Injection (CWE-90) | PY-SEC-013 | JS-SEC-015 |
| Template Injection (CWE-1336) | PY-SEC-014 | JS-SEC-013 |
| Header Injection (CWE-113) | PY-SEC-015 | JS-SEC-014 |
| XPath Injection (CWE-643) | PY-SEC-016 | — |
| Weak Hash MD5/SHA1 (CWE-328) | PY-SEC-017, PY-SEC-018 | JS-SEC-017, JS-SEC-018 |
| Weak Cipher (CWE-327) | PY-SEC-019, PY-SEC-020 | JS-SEC-019, JS-SEC-020, JS-SEC-022 |
| Hardcoded IV (CWE-329) | PY-SEC-021 | — |
| Insecure TLS (CWE-295) | PY-SEC-022 | JS-SEC-021 |
| JWT None Algorithm (CWE-345) | PY-SEC-023 | JS-SEC-023 |
| Weak Password Hash (CWE-916) | PY-SEC-024 | — |
| Session Fixation (CWE-384) | PY-SEC-025 | JS-SEC-024, JS-SEC-025 |
| Missing Security Headers (CWE-319) | PY-SEC-026 | JS-SEC-026 |
| Open Redirect (CWE-601) | PY-SEC-027 | JS-SEC-027 |
| CORS Misconfiguration (CWE-942) | PY-SEC-028 | JS-SEC-028 |
| Mass Assignment (CWE-915) | PY-SEC-029 | JS-SEC-030 |
| IDOR (CWE-639) | PY-SEC-030 | JS-SEC-029 |
| Debug Mode (CWE-215) | PY-SEC-031 | JS-SEC-031 |
| Error Info Leak (CWE-209) | PY-SEC-032 | JS-SEC-032 |
| Sensitive Data Logging (CWE-532) | PY-SEC-033 | JS-SEC-033 |
| Arbitrary File Upload (CWE-434) | PY-SEC-035 | JS-SEC-035 |
| Insecure Temp Files (CWE-377) | PY-SEC-036 | — |
| Zip Slip (CWE-22) | PY-SEC-037 | JS-SEC-037 |
| Unencrypted Transport (CWE-319) | PY-SEC-038 | JS-SEC-038 |
| Prototype Pollution (CWE-1321) | — | JS-SEC-003 |
| NoSQL Injection (CWE-943) | — | JS-SEC-008 |
| Timing Attack (CWE-208) | PY-SEC-046 | JS-SEC-046 |
| ReDoS (CWE-1333) | PY-SEC-047 | JS-SEC-047 |
| TOCTOU (CWE-367) | PY-SEC-048 | JS-SEC-048 |
| Bare/Empty Catch (CWE-390) | PY-SEC-040 | JS-SEC-040 |

Run `mycop rules list` to see all 100 rules with their severity levels.

## Comparison

How does mycop compare to other security tools?

| Feature | mycop | Semgrep | Snyk Code | Bandit | ESLint Security |
|---------|:-----:|:-------:|:---------:|:------:|:---------------:|
| AI code focus | Yes | No | No | No | No |
| Built-in rules (no download) | 100 | Requires registry | Cloud-based | ~100 (Python only) | ~30 (JS only) |
| AI auto-fix | Yes | No | Paid | No | No |
| Multi-language | Python, JS, TS | 30+ | 10+ | Python only | JS/TS only |
| MCP server | Yes | No | No | No | No |
| Zero config | Yes | Needs rules config | Needs project setup | Minimal | Needs .eslintrc |
| SARIF output | Yes | Yes | Yes | Yes | Via plugin |
| Price | Free (MIT) | Free tier / Paid | Paid | Free | Free |

mycop is purpose-built for the AI coding era. Other tools are general-purpose scanners that were designed before AI code generation became mainstream.

## Output Formats

- **Terminal** — colored output with code context (default)
- **JSON** — structured JSON for tool integration
- **SARIF** — Static Analysis Results Interchange Format for IDE/CI integration

## Integrations

### MCP Server (Agentic Tools)

mycop includes a built-in [MCP](https://modelcontextprotocol.io/) server that exposes all capabilities to agentic coding tools. Run `mycop mcp` and configure your tool — see the [`mycop mcp` section](#mycop-mcp) above for setup instructions.

Supported clients: Claude Code, Cursor, Windsurf, Codex CLI, Gemini CLI, and any MCP-compatible IDE or agent.

**Available on:**

- [Glama](https://glama.ai/mcp/servers) — Managed MCP registry
- [Smithery](https://smithery.ai/) — MCP server hosting and discovery
- [PulseMCP](https://pulsemcp.com/) — MCP server directory
- [MCP Servers](https://mcpservers.org/) — Curated community list

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

### VS Code Extension (Coming Soon)

The `vscode-extension/` directory contains a VS Code extension that provides:

- Real-time scanning on file save
- Diagnostics in the Problems panel
- "Scan Current File" and "Scan Workspace" commands
- Configurable severity threshold

See [vscode-extension/README.md](vscode-extension/README.md) for setup instructions.

### Docker

```bash
# Scan current directory
docker run --rm -v "$(pwd):/src" -w /src ghcr.io/abdumajidrashidov/mycop scan .

# Scan with specific options
docker run --rm -v "$(pwd):/src" -w /src ghcr.io/abdumajidrashidov/mycop scan . --format json --severity high
```

## Contributing

Contributions are welcome! Whether it is a bug report, a new security rule, a feature request, or a pull request, we appreciate your help in making mycop better.

To get started:

1. Fork the repository and create your branch from `main`.
2. Make your changes and ensure all checks pass:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --verbose
   ```
3. Open a pull request with a clear description of your changes.

Browse [open issues](https://github.com/AbdumajidRashidov/mycop/issues) to find something to work on, or open a new one to suggest an improvement.

If you find mycop useful, consider [sponsoring the project](https://github.com/sponsors/AbdumajidRashidov) to support ongoing development.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=AbdumajidRashidov/mycop&type=Date)](https://star-history.com/#AbdumajidRashidov/mycop&Date)

## License

MIT
