# Threat model

## What Brakepoint defends against

1. **An agent that means well but guesses.** It picks the wrong environment, misreads a
   task, or "cleans up" something it should not. This is the most common failure in the
   public incidents and the one Brakepoint is built for.
2. **An agent that ignores instructions.** "Ask before you delete" written in a prompt is
   advice to the model. Brakepoint enforces it outside the model.
3. **An agent steered by injected content.** A web page, email, or tool result tells the
   agent to run something destructive. The action still has to pass the catalog.
4. **An agent that tries to switch the guardrail off.** Approving its own requests, editing
   the policy, rewriting the hook config, or uninstalling Brakepoint are locked rules.

## Trust boundaries

| Component | Trusted? | Notes |
|---|---|---|
| The human at the terminal / harness prompt | Yes | The only party that can approve. |
| Policy file `.brakepoint.yaml` | Yes | The agent is blocked from writing it. |
| Catalog files | Yes | Shipped with the package or listed in the policy. |
| The model and its output | No | Everything it proposes is checked. |
| MCP servers and their annotations | No | `destructiveHint` can only tighten, never relax. |
| Tool results, web pages, files the agent reads | No | Never interpreted as approvals. |

## Approval channels

| Backend | How the human answers | Why the model can't answer |
|---|---|---|
| Claude Code (`ask`) | Claude Code's permission prompt | The prompt is rendered by the harness, not sent to the model. |
| `tty` | Typing `yes` on `/dev/tty` | The agent drives stdin/stdout of the command, not the controlling terminal. |
| `queue` | `brakepoint approve <id>` in another terminal | The agent running that command hits locked rule BP-SELF-001. For a hard guarantee, put the queue directory where the agent's OS user cannot write. |
| `deny` | Nobody | Everything that needs approval is denied. Use in CI. |

In Claude Code's `bypassPermissions` and `dontAsk` modes no human sees an `ask`, so
Brakepoint denies instead (configurable via `approval.unattended_modes`).

## Known limits

- **Pattern matching is not program analysis.** Brakepoint sees the command the agent asks
  to run. A script the agent writes to disk and then executes (`python cleanup.py`) is only
  checked at the level of its command line. Pair Brakepoint with least privilege.
- **Novel phrasings.** A determined adversary can find a destructive command the catalog
  does not know. De-quoting, segment splitting, and the obfuscation rule (BP-EXEC-002)
  raise the bar; they do not close it.
- **Same-user tampering.** If the agent runs as your OS user, it could in principle alter
  files Brakepoint relies on through a path the catalog doesn't recognise. Run agents as a
  separate user, and ship the audit log to a store the agent cannot write.
- **The hook is only as reliable as its harness.** If a harness skips hooks in some mode,
  Brakepoint cannot help in that mode.

## Defence in depth

Brakepoint is most effective alongside:

- credentials scoped to the task (read-only database roles, environment-scoped API tokens);
- network egress controls, including blocking link-local metadata addresses;
- backups stored somewhere the agent's credentials cannot delete;
- deletion protection and resource locks on production assets.
