# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-02-15

### Fixed
- Fix invalid regex lookahead in JS-SEC-034 and PY-SEC-043 (Rust regex crate does not support lookahead)
- Fix install script permission denied on macOS (auto-elevate with sudo)
- Update Homebrew tap with correct formula

## [0.2.0] - 2026-02-15

### Added
- **80 new security rules** — scaled from 20 to 100 total (50 Python + 50 JavaScript)
  - Injection: SSRF, XXE, LDAP, template injection, header injection, XPath, SQL injection (JS), command injection (JS)
  - Cryptography: weak hashes (MD5/SHA1), weak ciphers (DES/RC4), ECB mode, hardcoded IVs, insecure TLS, deprecated createCipher
  - Auth & Session: JWT none algorithm, weak password hashing, session fixation, insecure cookies, weak session secrets
  - Access Control: open redirect, CORS misconfiguration, mass assignment, IDOR patterns
  - Data Exposure: debug mode detection, error info leak, sensitive data logging, hardcoded connection strings
  - File Operations: arbitrary file upload, insecure tempfiles, zip slip
  - Network: unencrypted transport, WebSocket origin validation, DNS resolution with user input
  - Error Handling: bare/empty catch blocks, assert-based auth checks
  - Framework-specific: Django raw SQL, Flask secret key, Django mark_safe, Express rate limiting, Express trust proxy, React ref DOM manipulation, React unsafe lifecycle, Next.js SSR secrets
  - Advanced: timing attacks, ReDoS, TOCTOU race conditions, dynamic require/import, postMessage origin checks
- Rule deduplication in registry to prevent double-counting embedded and on-disk rules
- Inline ignore comments (`# mycop-ignore:RULE-ID` / `// mycop-ignore:RULE-ID`)
- `--fail-on` flag for explicit exit code control
- Enhanced `mycop init` with project type detection
- GitHub Action for CI integration
- Pre-commit hook support
- Homebrew formula
- Docker image
- VS Code extension (preview)
- Comprehensive unit and integration test suite

## [0.1.0] - 2025-06-01

### Added
- Initial release
- 20 embedded security rules (10 Python, 10 JavaScript/TypeScript)
- OWASP Top 10 coverage with CWE mappings
- 5 AI backends: Claude CLI, Anthropic API, OpenAI API, Ollama, rule-based fallback
- AST (tree-sitter) + regex pattern matching
- Agentic auto-fix: AI rewrites entire files to fix all vulnerabilities
- Deep AI security review (`mycop review`)
- Terminal, JSON, and SARIF output formats
- Git diff scanning mode (`--diff`)
- `.scanrc.yml` / `.mycop.yml` configuration
- Severity filtering (`--severity`)
- Parallel file scanning with Rayon
