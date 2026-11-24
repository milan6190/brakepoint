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

## Non-goals

Brakepoint deliberately does **not** do the following. A passing test suite says nothing
about them, and it is not evidence of conformance with AISVS, NIST AI RMF, or any other
standard. [COVERAGE.md](COVERAGE.md) shows what the tests do exercise, and
[CROSSWALK.md](CROSSWALK.md) shows, requirement by requirement, what is met, partly met,
or not addressed.

- **Not a sandbox.** Once an action runs, Brakepoint has no further control over it. It
  does not isolate processes, filesystems, or networks.
- **Not program analysis.** It sees the command line, not the program. A script the agent
  writes and then runs, and the content of files it writes, are not inspected.
- **Not a prompt-injection filter.** It does not screen what the model reads (web pages,
  emails, tool results). It checks what the model then tries to do.
- **Not an allow-list.** The default is a catalog of known-dangerous actions
  (`unmatched: allow`). Unknown dangerous actions pass unless you set `unmatched: approve`.
- **Not output safety.** Toxicity, PII in responses, and similar content concerns are out
  of scope.
- **Not agent identity.** No per-agent cryptographic identity, signed approvals, or
  single-use approval nonces (AISVS C9.2.8, C9.4.1).
- **Not budgets or a kill switch.** No rate limits, spend limits, recursion limits, or
  emergency stop (AISVS C9.1, C9.6.1).
- **Not data-loss prevention.** Data sent out through an allowed channel (for example an
  HTTP POST to an unlisted host) is not detected.
- **Not tamper-proof logging.** The audit log is tamper-evident. A party who can rewrite
  the whole file can rebuild a valid chain; ship entries to a store the agent cannot write.
- **Not a defence against the approver.** A human who approves a harmful action, or an
  attacker with the human's own access, is outside the model.
- **Only these integration points:** the Claude Code `PreToolUse` hook, the stdio MCP
  proxy, and `brakepoint exec`. HTTP/SSE MCP transports and other harnesses are not covered.

## The human approver

An approval step is only as strong as the person approving.

- **Approval fatigue.** People asked many times a day start approving by reflex. Reserve
  live prompts for the highest-impact actions, and let humans set policy and review the
  rest afterwards. [`examples/low-fatigue.brakepoint.yaml`](../examples/low-fatigue.brakepoint.yaml)
  prompts only for critical actions and a few high-risk ones, logs the rest, and still
  denies anything aimed at production. `brakepoint audit review` summarises decisions per
  rule: a rule that is always approved is a candidate for `log`, one that is always
  rejected a candidate for `deny`.
- **Persuasion by the agent.** A compromised or confused agent can write text meant to
  persuade the approver: a comment saying "already approved by security", a fake line
  that looks like Brakepoint's own, terminal escape codes that erase the warning, or a
  harmless first screen with the dangerous part far below. Brakepoint treats all agent
  text in a prompt as untrusted: every line of it is fenced with a `│` margin and labelled
  as written by the agent, control and invisible Unicode characters are shown as escapes,
  long text keeps both its start and end with the hidden length stated, and the exact
  text that triggered each rule is shown separately. Only the rule, why, and safer lines
  come from Brakepoint. In Claude Code the harness draws the prompt itself; Brakepoint
  adds a reminder to judge what the command does, not what text inside it claims.
- **What is recorded.** In the terminal and queue backends the audit log records the
  approver and their decision. In Claude Code it records that a human was asked; the
  answer is given in the harness and is not visible to Brakepoint.

## Trust boundaries

| Component | Trusted? | Notes |
|---|---|---|
| The human at the terminal / harness prompt | Yes | The only party that can approve. |
| Policy file `.brakepoint.yaml` | Yes | The agent is blocked from writing it. The hook looks it up from `CLAUDE_PROJECT_DIR`, so `cd` elsewhere does not escape it. Unknown keys and wrongly typed values are errors, so a typo cannot quietly weaken it. |
| Approval queue, audit log, user policy | Yes | Default locations are covered by BP-SELF-001; custom paths set in the policy are covered by BP-SELF-002. |
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

The MCP proxy refuses JSON-RPC batches that contain a `tools/call`, so a batch cannot carry
a call past the check.

## Known limits

- **Pattern matching is not program analysis.** Brakepoint sees the command the agent asks
  to run. A script the agent writes to disk and then executes (`python cleanup.py`) is only
  checked at the level of its command line. Pair Brakepoint with least privilege.
- **Novel phrasings.** A determined adversary can find a destructive command the catalog
  does not know. De-quoting, segment splitting, and the obfuscation rule (BP-EXEC-002)
  raise the bar; they do not close it. `$IFS` word splitting and SQL comments used as
  spaces (`DROP/**/TABLE`) are normalised away before matching.
- **Very long actions.** Text over 16,000 characters is matched on its first and last 8,000
  only, so that no input can make evaluation slow enough to time out the hook. Such actions
  always match BP-SIZE-001 (high, so approval by default) and go to a human.
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
