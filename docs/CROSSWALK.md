# Crosswalk: rules and tests to AISVS and NIST

How Brakepoint's rules, design, and tests relate to external standards. It is written for
auditors and assessors, so it says what is **not** met as plainly as what is.

**This is not a conformance claim.** A passing test suite shows that the cases in
[COVERAGE.md](COVERAGE.md) behave as expected. It does not show that Brakepoint satisfies
any standard. Brakepoint is one control at the tool boundary; most requirements below also
need controls elsewhere. See [THREAT_MODEL.md](THREAT_MODEL.md#non-goals) for what is out
of scope.

Status values:

- **Met**: Brakepoint does this, and a named test shows it.
- **Partial**: Brakepoint does part of it; the gap is stated.
- **Not addressed**: out of scope for Brakepoint; use another control.

Test names refer to functions in `tests/`. Rule ids refer to [CATALOG.md](CATALOG.md).

## OWASP AISVS 1.01

Requirement ids and levels were checked against the AISVS 1.01 chapter files in
[OWASP/AISVS](https://github.com/OWASP/AISVS/tree/main/1.01/en). Requirement text is
summarised here; read the source for the exact wording. Cite them versioned, for example
`v1.01-C9.2.1`.

### C9 Orchestration and agentic action

| Req | Level | Summary | Status | Evidence | Gap |
|---|---|---|---|---|---|
| C9.2.1 | L1 | Privileged or irreversible actions are blocked until a human explicitly approves | Partial | `approve` decisions for catalogued rules; `test_hook_asks_human_for_destructive_command`, `test_queue_approval_round_trip`, `test_tty_timeout_covers_a_half_typed_answer` | Only actions the catalog recognises. Unknown actions pass unless `unmatched: approve`. |
| C9.2.2 | L2 | The approval shows the complete action parameters | Partial | Claude Code shows the full command in its own prompt. Terminal and queue prompts show the start, the end, and each matching segment; `test_approval_prompt_fences_agent_text` | Terminal and queue prompts leave out the middle of text over 800 characters and say how much is hidden. |
| C9.2.3 | L2 | Each action has a reversibility classification | Met | Every rule declares `reversibility`, enforced when the catalog loads; `test_catalog_loads_and_ids_are_unique` | |
| C9.2.4 | L2 | The runtime enforces the reversibility classification | Partial | Decisions follow severity; most `irreversible` rules are high or critical | Policy is keyed by severity, not reversibility. Three irreversible rules are medium and only logged by default: BP-CRED-002, BP-SCM-003, BP-TOOL-005. Override them to `approve` if that matters to you. |
| C9.2.5 | L2 | The agent cannot modify its own prompts or tool lists | Partial | Locked BP-SELF-001 and BP-SELF-002 protect the policy, hook settings, queue, and audit log; `test_hook_blocks_settings_tampering`, `test_hook_normalises_paths_before_self_protection`, `test_agent_cannot_touch_custom_queue_audit_or_policy_paths` | Prompts and tool lists in general are not protected. |
| C9.2.8 to C9.2.11 | L3 | Approvals bound with nonces and isolated signing keys; re-approval for action chains | Not addressed | | Queue ids are random but not signed. No chain-level approval. |
| C9.3.1 | L1 | Each tool runs in a least-privilege sandbox | Not addressed | | Non-goal: Brakepoint is not a sandbox. |
| C9.3.7 | L2 | External resources are checked against an allow-list before use | Partial | BP-CRED-003 denies cloud metadata endpoints for shell, URL and tool actions | Deny-list for known endpoints, not an allow-list. |
| C9.5.1 | L2 | Actions are authorised against fine-grained policies on tools and parameter values | Partial | Rules match tool names and argument text, including commands nested in arguments; `test_tool_calls`, `test_hook_checks_mcp_tools` | Pattern rules, not schema-aware policy on each parameter. |
| C9.5.3 | L2 | Access decisions are made by application logic or a policy engine, never by the model | Met | The engine is deterministic and runs outside the model; the model cannot answer its own approval; `test_agent_cannot_self_approve`, `test_hook_denies_when_nobody_can_answer` | |
| C9.6.1 / C9.6.3 | L1 / L3 | A manual kill switch, out of band | Not addressed | | Non-goal. |
| C9.6.2 | L2 | If an approval is not given in time, the action is blocked | Met | Every backend fails closed on timeout or error; `test_queue_times_out_closed`, `test_tty_timeout_covers_a_half_typed_answer`, `test_hook_fails_closed_on_bad_input` | |
| C9.1.1 to C9.1.3 | L1 to L2 | Per-tool quotas, timeouts, and execution budgets | Not addressed | | Non-goal. |

### C5 Access control and identity

| Req | Level | Summary | Status | Evidence | Gap |
|---|---|---|---|---|---|
| C5.2.1 | L2 | Explicit allow-lists, default deny | Not addressed by default | `unmatched: approve` or `deny` makes unknown actions need a human | The shipped default is a deny-list (`unmatched: allow`). |
| C5.2.5 | L2 | The agent-authorisation decision point is isolated from the agent's execution environment | Partial | The decision runs in a hook or proxy process, not in the model; `test_hook_reads_policy_from_project_dir_not_cwd` | By default it runs as the same OS user as the agent. Run agents as a separate user for real isolation. |

### C10 MCP security

| Req | Level | Summary | Status | Evidence | Gap |
|---|---|---|---|---|---|
| C10.2.5 | L2 | Access control on every tool invocation, including argument values | Partial | The proxy checks every `tools/call`, refuses batches that contain one, and reads `destructiveHint`; `test_mcp_proxy_forwards_safe_calls_and_blocks_destructive_ones`, `test_mcp_proxy_refuses_batched_tool_calls`, `test_mcp_proxy_honours_destructive_hint` | Requirement is written for servers; Brakepoint is a client-side proxy. stdio transport only. |
| C10.4.8 | L3 | A changed tool definition is re-approved before use | Not addressed | | |

### C12 Monitoring, logging and anomaly detection

| Req | Level | Summary | Status | Evidence | Gap |
|---|---|---|---|---|---|
| C12.1.2 | L2 | Policy decisions are logged in enough detail for audit and forensics | Met | Each decision is logged with action, matched rules, decision, outcome, context, and secrets redacted; `test_hook_writes_audit_entries`, `test_secrets_are_redacted_in_audit` | |
| C12.4.2 | L2 | Logs of security-critical actions capture approver identity, time, parameters, and outcome | Partial | Terminal and queue: approver and decision recorded; `test_queue_approval_round_trip` | In Claude Code the log records that a human was asked, not their answer. |
| C12.5.3 | L2 | Changes produce immutable audit records | Partial | Hash-chained log; `test_audit_chain_detects_tampering`, `test_audit_chain_survives_entries_larger_than_the_read_block` | Tamper-evident, not immutable: a full rewrite can rebuild the chain. Ship it to a write-once store. |

### C2 Input validation

AISVS C2 is about input to the model. Brakepoint checks the model's output (the action), so
these are analogues, not direct matches.

| Req | Level | Summary | Status | Evidence | Gap |
|---|---|---|---|---|---|
| C2.1.1 / C2.1.2 | L1 | Input is normalised; encoding tricks are detected | Partial (analogue) | Actions are de-quoted, `$IFS` and SQL comments are normalised, paths are normalised; `test_obfuscated_spacing_is_seen_through`, `test_hook_normalises_paths_before_self_protection` | Not a full shell or SQL parser. |
| C2.1.4 | L1 | Over-long input is rejected, not truncated | Partial (analogue) | Over 16,000 characters: start and end are checked and BP-SIZE-001 requires a human; `test_long_actions_are_fast_and_go_to_a_human`, `test_padding_does_not_hide_a_destructive_command` | Not rejected by default. Set `rules: {BP-SIZE-001: deny}` to reject. |

## NIST SP 800-207 (Zero Trust Architecture)

> **Draft: not yet checked against the source text.** These mappings were written from
> knowledge of the standard; the NIST site could not be reached when this was drafted.
> Verify section numbers and wording against
> [SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) before relying on them.

| Concept | Brakepoint | Evidence |
|---|---|---|
| Policy Enforcement Point | The Claude Code hook, the MCP proxy, and `brakepoint exec`: every tool call passes through one before it runs | `test_hook_*`, `test_mcp_proxy_*`, `test_cli_exec_runs_safe_commands_and_blocks_locked_ones` |
| Policy Engine / Policy Administrator | `Engine` decides from the catalog and policy; the approver backends carry out approve or deny | `test_defaults_map_severity_to_decision`, `test_queue_approval_round_trip` |
| Access decided per request | Each action is evaluated on its own; an earlier approval grants nothing later | `test_hook_asks_human_for_destructive_command` |
| Dynamic policy | Decisions depend on the action, its target (production markers), and the session mode | `test_protected_marker_escalates_critical_to_deny`, `test_hook_denies_when_nobody_can_answer` |
| Strict enforcement before access | Decisions are made before the call runs, and errors deny | `test_hook_fails_closed_on_bad_input` |
| Collect information to improve posture | The audit log and `brakepoint audit review` feed policy changes | `test_audit_review_suggests_policy_changes` |

Not covered: identity, device posture, and network-level controls, which a full zero-trust
architecture also needs.

## NIST AI RMF 1.0 (NIST AI 100-1)

> **Draft: not yet checked against the source text**, for the same reason. Check each
> subcategory id and its wording in the
> [AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/) before relying on it.

| Subcategory | Brakepoint's contribution | Evidence |
|---|---|---|
| GOVERN 3.2 (human oversight of AI systems) | Humans set policy and approve high-impact actions; the model cannot approve | `test_agent_cannot_self_approve`, `test_locked_rule_cannot_be_overridden` |
| MANAGE 2.4 (mechanisms to supersede or deactivate) | Deny decisions and fail-closed behaviour stop actions | `test_hook_denies_production_wipe_and_tells_agent_not_to_retry` |
| MEASURE 2.7 (security and resilience evaluated and documented) | Tests, rule coverage, incident replay, and this crosswalk | `pytest --require-all-rules`, `brakepoint replay` |
| MANAGE 4.1 (post-deployment monitoring) | Hash-chained audit log and per-rule review | `test_hook_writes_audit_entries`, `test_audit_review_suggests_policy_changes` |

## Keeping this current

- A new rule must come with a test; CI runs `pytest --require-all-rules`.
- Regenerate coverage with `pytest --rule-coverage docs/COVERAGE.md`.
- When a status changes, update the row and its evidence in the same change.
