#!/usr/bin/env python3
"""Test all 6 mycop MCP tools via JSON-RPC over stdin/stdout."""

import json
import subprocess
import sys
import time

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"

FIXTURE = "tests/fixtures/python/vulnerable.py"
FIXTURE_JS = "tests/fixtures/javascript/vulnerable.js"
PASS_COUNT = 0
FAIL_COUNT = 0


def send_and_receive(proc, request):
    """Send a JSON-RPC request and read the response line."""
    line = json.dumps(request) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    response_line = proc.stdout.readline().strip()
    if not response_line:
        return None
    return json.loads(response_line)


def run_test(name, tool_name, arguments, expect_field=None):
    """Start an MCP server, initialize it, call one tool, and check the result."""
    global PASS_COUNT, FAIL_COUNT

    print(f"\n{CYAN}━━━ Testing: {name} ━━━{NC}")

    # Unset CLAUDECODE to allow nested Claude CLI calls (for AI tools)
    import os
    env = os.environ.copy()
    env.pop("CLAUDECODE", None)

    proc = subprocess.Popen(
        ["mycop", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        # Step 1: Initialize
        init_resp = send_and_receive(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1"},
            },
        })

        if not init_resp or "result" not in init_resp:
            print(f"  {RED}FAIL{NC} — Initialize failed: {init_resp}")
            FAIL_COUNT += 1
            return

        server_info = init_resp["result"].get("serverInfo", {})
        if PASS_COUNT == 0 and FAIL_COUNT == 0:
            print(f"  Server: {server_info.get('name')} v{server_info.get('version')}")

        # Step 2: Send initialized notification
        notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        proc.stdin.write(notif)
        proc.stdin.flush()
        time.sleep(0.1)

        # Step 3: Call the tool
        tool_resp = send_and_receive(proc, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        })

        if not tool_resp:
            print(f"  {RED}FAIL{NC} — No response for tool call")
            FAIL_COUNT += 1
            return

        if "error" in tool_resp:
            err = tool_resp["error"]
            msg = err.get("message", str(err))
            # Truncate long error messages
            if len(msg) > 120:
                msg = msg[:120] + "..."
            print(f"  {RED}FAIL{NC} — Error: {msg}")
            FAIL_COUNT += 1
            return

        # Extract content
        result = tool_resp.get("result", {})
        contents = result.get("content", [])
        text = ""
        for c in contents:
            if c.get("type") == "text":
                text = c["text"]
                break

        if not text:
            print(f"  {RED}FAIL{NC} — Empty content")
            FAIL_COUNT += 1
            return

        # Check expected field if given
        if expect_field:
            try:
                data = json.loads(text)
                if expect_field not in data:
                    print(f"  {RED}FAIL{NC} — Field '{expect_field}' not in response")
                    print(f"    Keys: {list(data.keys())}")
                    FAIL_COUNT += 1
                    return
            except json.JSONDecodeError:
                if expect_field not in text:
                    print(f"  {RED}FAIL{NC} — '{expect_field}' not found in text response")
                    FAIL_COUNT += 1
                    return

        print(f"  {GREEN}PASS{NC}")
        PASS_COUNT += 1

        # Preview (compact)
        preview_lines = text.split("\n")[:8]
        print(f"  {YELLOW}Preview:{NC}")
        for line in preview_lines:
            print(f"    {line}")
        if len(text.split("\n")) > 8:
            print("    ... (truncated)")

    except Exception as e:
        print(f"  {RED}FAIL{NC} — Exception: {e}")
        import traceback
        traceback.print_exc()
        FAIL_COUNT += 1
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)


def main():
    print(f"{CYAN}╔══════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║       mycop MCP Server — Full Tool Tests     ║{NC}")
    print(f"{CYAN}╚══════════════════════════════════════════════╝{NC}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SCAN TOOL (5 tests)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}▸ scan tool{NC}")

    run_test("scan — single file via 'path'", "scan",
             {"path": FIXTURE},
             expect_field="total_findings")

    run_test("scan — no args (defaults to '.')", "scan",
             {},
             expect_field="total_findings")

    run_test("scan — severity filter (high)", "scan",
             {"path": FIXTURE, "severity": "high"},
             expect_field="total_findings")

    run_test("scan — max_results=3", "scan",
             {"path": FIXTURE, "max_results": 3},
             expect_field="findings")

    run_test("scan — multiple paths via 'paths'", "scan",
             {"paths": [FIXTURE, FIXTURE_JS]},
             expect_field="files_scanned")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # LIST_RULES TOOL (4 tests)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}▸ list_rules tool{NC}")

    run_test("list_rules — no filter (all 100)", "list_rules",
             {},
             expect_field="total")

    run_test("list_rules — language=python", "list_rules",
             {"language": "python"},
             expect_field="total")

    run_test("list_rules — severity=critical", "list_rules",
             {"severity": "critical"},
             expect_field="rules")

    run_test("list_rules — search='sql'", "list_rules",
             {"search": "sql"},
             expect_field="total")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # EXPLAIN_FINDING TOOL (2 tests)
    # Uses ai_provider=none to avoid needing Claude CLI
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}▸ explain_finding tool{NC}")

    run_test("explain_finding — via 'path' (required)", "explain_finding",
             {"path": FIXTURE, "line": 9, "rule_id": "PY-SEC-001", "ai_provider": "none"})

    run_test("explain_finding — via 'file' alias", "explain_finding",
             {"file": FIXTURE, "line": 9, "rule_id": "PY-SEC-001", "ai_provider": "none"})

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # REVIEW TOOL (3 tests)
    # path is now REQUIRED in schema
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}▸ review tool{NC}")

    run_test("review — via 'path' (required)", "review",
             {"path": FIXTURE, "ai_provider": "none"})

    run_test("review — via 'file' alias", "review",
             {"file": FIXTURE, "ai_provider": "none"})

    run_test("review — via 'filePath' alias", "review",
             {"filePath": FIXTURE, "ai_provider": "none"})

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CHECK_DEPS TOOL (2 tests)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}▸ check_deps tool{NC}")

    run_test("check_deps — no args (defaults to '.')", "check_deps",
             {},
             expect_field="files_checked")

    run_test("check_deps — explicit path='.'", "check_deps",
             {"path": "."},
             expect_field="files_checked")

    # ── Summary ──
    total = PASS_COUNT + FAIL_COUNT
    print(f"\n{CYAN}{'━' * 48}{NC}")
    print(f"  Results: {GREEN}{PASS_COUNT} passed{NC}, {RED}{FAIL_COUNT} failed{NC} (total: {total})")
    print(f"{CYAN}{'━' * 48}{NC}")

    sys.exit(1 if FAIL_COUNT > 0 else 0)


if __name__ == "__main__":
    main()
