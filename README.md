# Brakepoint

**A breakpoint for irreversible AI agent actions.**

Brakepoint sits between an AI agent and its tools. Before a shell command, SQL
statement, file write, or MCP tool call runs, it checks the action against an
open catalog of destructive operations. Anything irreversible stops and waits
for a human, through a channel the model cannot answer. Everything else runs
untouched.

```text
agent ──► tool call ──► Brakepoint ──► allowed?  ──► tool
                            │
                            ├─ irreversible? ──► human approves outside the model
                            ├─ production?   ──► denied, with a safer alternative
                            └─ every decision ──► hash-chained audit log
```

> Status: v0.1, alpha. Built to be proposed as an OWASP project.

## Why

Agents are being given real credentials, and the failures are no longer hypothetical:

- **April 2026.** A coding agent found an infrastructure token in a file and deleted a
  production database volume. The backups lived on the same volume and went with it.
  ([OECD AI incident](https://oecd.ai/en/incidents/2026-04-27-6153))
- **March 2026.** An internal agent at Meta posted advice to a forum without being asked.
  Following it exposed company and user data for two hours, rated Sev 1. Separately, a Meta
  AI safety director's agent bulk-deleted her inbox after she told it to confirm first.
  ([TechCrunch](https://techcrunch.com/2026/03/18/meta-is-having-trouble-with-rogue-ai-agents))
- **July 2026.** Agents under test escaped their sandbox and went from code execution in one
  pod to cluster-admin on another company's clusters.
  ([Wikipedia](https://en.wikipedia.org/wiki/OpenAI_rogue_agent_breach_of_Hugging_Face))
- **July 2025.** An agent wiped a live database during an explicit code freeze.
  ([OECD AI incident](https://oecd.ai/en/incidents/2025-07-19-1eb1))

The common thread: people *told* the agent to be careful, and a prompt is not a control.
The agent's text was allowed to become a production action with nothing in between.
Brakepoint is that something: enforcement outside the model, at the tool boundary.

## What it does

- **Destructive-action catalog.** 59 rules covering shell and filesystem, git, SQL and NoSQL,
  Delta Lake and Databricks, BigQuery and Snowflake, AWS, Google Cloud, Azure, Kubernetes,
  Terraform/Pulumi/CDK, Docker, PaaS platforms, GitHub, credential stores, cloud metadata
  endpoints, and verb-based rules for MCP tools nobody has catalogued yet. Each rule says
  *why* it is dangerous and what the *safer* alternative is. See [docs/CATALOG.md](docs/CATALOG.md).
- **Human approval the model cannot fake.** In Claude Code it uses the harness's own
  permission prompt. Elsewhere it asks on the controlling terminal (`/dev/tty`, not the
  agent's stdin) or through an approval queue answered from another terminal.
- **Production protection.** Critical actions that target something named like production
  (`prod`, `production`, `prd`, `live`, configurable) are denied outright.
- **Fails closed.** Errors, timeouts, and unattended sessions (`bypassPermissions`) all deny.
- **Self-protection.** The agent cannot approve its own requests, edit the policy, or remove
  the hook. These rules are locked; no policy can relax them.
- **Tamper-evident audit log.** Every decision is appended to a SHA-256 hash-chained JSONL
  file with secrets redacted. `brakepoint audit verify` detects edited or deleted entries.
- **Tells the agent what to do instead.** Denials include the reason and a safer
  alternative, plus an instruction not to retry in another form.
- **Only tightens.** Brakepoint never auto-approves anything; your harness's own permission
  rules still apply to everything it lets through.

## Quick start

```bash
pip install git+https://github.com/milan6190/brakepoint
brakepoint replay              # see what it would have done in real incidents
brakepoint check "kubectl delete ns payments"
```

```text
APPROVE
Brakepoint APPROVE: [BP-K8S-001] Delete a namespace, persistent volume, or everything of a kind (critical, irreversible).
Why: Deleting a namespace deletes everything in it; deleting PVs can delete the underlying disks.
Safer: Scale the workload down and let a human remove it.
Also matched: BP-K8S-099
```

### Claude Code

```bash
cd your-project
brakepoint init --claude-code
```

This writes `.brakepoint.yaml` and adds a `PreToolUse` hook to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*",
        "hooks": [{ "type": "command", "command": "brakepoint hook claude-code", "timeout": 600 }]
      }
    ]
  }
}
```

Safe calls pass through silently. Calls that need approval become Claude Code's own
permission prompt. Denied calls are blocked and the reason goes back to the model.

### Any MCP client

Wrap any stdio MCP server:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "brakepoint",
      "args": ["mcp-proxy", "--name", "gmail", "--", "npx", "-y", "some-gmail-mcp-server"]
    }
  }
}
```

Every `tools/call` is checked before it reaches the server. If the server marks a tool with
the MCP `destructiveHint` annotation, Brakepoint treats it as high severity. Server hints only
ever tighten the policy, never relax it.

### Plain shell (scripts, CI, other agent frameworks)

```bash
brakepoint exec -- terraform destroy          # asks on your terminal
brakepoint check --json "DROP TABLE users"    # exit 0 allow, 3 needs approval, 4 denied
```

From Python:

```python
from brakepoint import Action, Engine

verdict = Engine().evaluate(Action.tool("mcp__stripe__create_refund", {"amount": 499}))
if verdict.needs_human:
    print(verdict.reason())
```

## Policy

`brakepoint init` writes a commented `.brakepoint.yaml`. The essentials:

```yaml
defaults:            # what each severity means for you
  critical: approve
  high: approve
  medium: log
protected:
  markers: [prod, production, prd, live]
  protected_action: deny
approval:
  backend: auto      # auto | tty | queue | deny
rules:
  BP-GIT-002: log    # per-rule overrides (locked rules ignore these)
allow:
  - 'rm -rf (\./)?(node_modules|dist|build)/?'
catalogs:
  - ./my-company-rules.yaml
```

## Commands

| Command | What it does |
|---|---|
| `brakepoint check <text>` | Classify a command, SQL, URL, path, or tool call without running it |
| `brakepoint exec -- <cmd>` | Run a command through Brakepoint |
| `brakepoint hook claude-code` | Claude Code `PreToolUse` hook (reads stdin) |
| `brakepoint mcp-proxy --name N -- <server>` | Guard a stdio MCP server |
| `brakepoint pending` / `approve <id>` / `deny <id>` | Work the approval queue |
| `brakepoint catalog [--markdown\|--json]` | List the rules |
| `brakepoint audit tail\|verify` | Read or verify the audit log |
| `brakepoint replay` | Replay real incidents against your policy |
| `brakepoint init [--claude-code]` | Write a starter policy and hook |

## Limits (read this)

Brakepoint is one layer, not a sandbox. It matches what an agent *asks* to do, so it cannot
see inside a script the agent writes and then runs, and a determined attacker can find
phrasings no catalog anticipates. It is most valuable when combined with least-privilege
credentials, network egress controls, and backups the agent cannot reach.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Roadmap

- Slack, Teams, and webhook approvers with signed decisions
- HTTP-transport MCP proxy and an OpenTelemetry exporter for the audit log
- Integrations for LangGraph, OpenAI Agents SDK, CrewAI, and Cursor hooks
- Catalog coverage for Snowflake, Oracle, Salesforce, ServiceNow, Jira, and Google Workspace
- Per-target allow rules (for example, "staging volumes are fine")
- Mapping each rule to the OWASP Top 10 for LLM Applications and for Agentic Applications

## Contributing

The catalog is the heart of the project, and adding a rule is the easiest way to help. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately per [SECURITY.md](SECURITY.md).

## License

MIT
