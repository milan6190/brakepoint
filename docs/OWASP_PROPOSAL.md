# OWASP project proposal (draft)

**Project name:** OWASP Brakepoint
**Type:** Tool (with a community-maintained data asset: the destructive-action catalog)
**Requested level:** Incubator
**License:** MIT
**Leader:** Milankumar Rana (co-leader to be confirmed)

## Problem

AI agents now hold real credentials and call real tools. Public incidents in 2025–2026 show
the same failure again and again: an agent guesses, or ignores an instruction to ask first,
and a destructive call reaches production with nothing in between. Prompt instructions are
not controls, and most platforms let an API token delete data, backups, and whole
environments without confirmation.

## What the project delivers

1. **An open destructive-action catalog.** Machine-readable rules describing irreversible
   operations across shells, databases, lakehouses, clouds, Kubernetes, IaC, PaaS, source
   hosting, and agent tools, each with a reason and a safer alternative. Usable by any
   guardrail, not only this tool.
2. **A reference enforcement layer.** Hooks and proxies that apply the catalog at the tool
   boundary, require out-of-band human approval for irreversible actions, deny actions on
   production targets, fail closed, and keep a tamper-evident audit log.
3. **Incident replays.** Reconstructions of public incidents that act as regression tests
   and as teaching material.

## How it relates to existing OWASP work

- The OWASP Top 10 for LLM Applications and the Top 10 for Agentic Applications describe the
  risks of excessive agency and tool misuse; Brakepoint is a practical control for them.
- OWASP guidance on securing MCP servers covers server-side design; Brakepoint adds a
  client-side check that works with servers that do not follow it.
- The OWASP GenAI Security Project's agent control work defines what should be controlled;
  Brakepoint aims to be an open implementation of the "stop irreversible actions" control.
  Before submitting, read the current Agent Control Standard and map Brakepoint's features to it.

## 90-day plan

| Weeks | Milestone |
|---|---|
| 1–2 | Private alpha with Claude Code and MCP proxy; collect false-positive data |
| 3–4 | Public repo, PyPI release, OpenSSF Best Practices badge application |
| 5–8 | Slack/webhook approvers, LangGraph and OpenAI Agents SDK integrations, 100+ rules |
| 9–10 | Rule mapping to OWASP Top 10 for LLM and Agentic Applications |
| 11–12 | Submit Incubator application; talk proposal for an OWASP Global AppSec event |

## Success measures

- Catalog rules contributed by people outside the core team
- Zero known bypasses of locked rules
- False-positive rate under 1% on a corpus of everyday developer commands
