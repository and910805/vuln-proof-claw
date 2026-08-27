# Tool runtime and autonomy

[繁體中文](TOOL_RUNTIME.zh-TW.md) | **English**

Version 0.7.0 introduces one registry shared by REST, MCP, policy, and future Worker
adapters. A registry entry is not automatically considered executable:

| State | Meaning |
| --- | --- |
| `cataloged` | The capability, executable, risk, and intended adapter are known. Execution is rejected. |
| `contract_ready` | A strict request contract exists, but no default Worker runner is available. |
| `worker_ready` | A bounded argv builder exists for execution inside a disposable restricted Worker. |

The initial registry includes Shell, Python, Nmap, password testing, exploit/PoC,
httpx, Nuclei, Nikto, ffuf, Feroxbuster, Gobuster, Katana, sqlmap, Dalfox,
testssl.sh, OWASP ZAP, Wapiti, WhatWeb, WAFW00F, Subfinder, Amass, Semgrep, and
Trivy. New tools must declare an action type and risk before they can be planned.

## Execution contracts

- `shell_command` accepts an executable basename and argv array. It never accepts a
  shell command line; the Worker must allowlist the executable and run with `shell=False`.
- `python_execute` accepts bounded source and arguments for an isolated, network-restricted
  Worker. It uses isolated Python flags and is L2.
- `nmap` generates a TCP connect scan from typed ports, optional service detection, and
  registry script names. It does not accept raw flags.
- `password_test` accepts usernames and secret-store references, not raw passwords. It caps
  attempts at 100 and rate at 30/minute, and stops on success by default.
- `exploit_poc` requires a registry ID, artifact SHA-256, expected success signal, and no more
  than ten attempts. ProofClaw does not ship an exploit payload in the request.

Every accepted plan is normalized, hashed, converted into a Flow/Task/Action, checked against
engagement scope and maximum risk, and written to the audit log. L2 actions wait for an exact
Approval or a reusable Approval Preset. L1 actions may execute automatically only when the
engagement was created with `auto_execute_l1: true`.

## Agent loop

The autonomous controller selects `plan`, `operate`, `wait_for_approval`, `verify`, `complete`,
or `stop`. Approval always precedes operation, verification precedes completion, and any step,
tool-call, duration, or consecutive-failure limit stops the loop. Planner, Operator, and
Verifier decisions are exposed through REST and the local Codex/Claude Code MCP server.

Authorized testing may trigger EDR or other alerts. That is an operational coordination issue,
not a reason to remove useful testing behavior. ProofClaw does not implement alert evasion,
defensive-control tampering, or EDR disabling.
