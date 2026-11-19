# Changelog

## 0.2.0

A security release. It closes several ways an agent could get past Brakepoint, and it
makes policy loading strict. **Read "Upgrading" first.**

### Upgrading from 0.1

- **Policies are validated strictly.** Unknown keys (for example `default:` instead of
  `defaults:`), wrongly typed values (a string where a list is expected), and overrides
  for rule ids that do not exist are now errors. While a policy is invalid, the Claude
  Code hook blocks every tool call. Run `brakepoint validate` before you upgrade.
- **Actions over 16,000 characters need approval** (new rule `BP-SIZE-001`, high). Large
  heredocs can hit this. To relax it: `rules: {BP-SIZE-001: log}`.
- **Agents can no longer read Brakepoint's own state** (approval queue, audit log, user
  policy), as well as no longer write it.
- **Add `Grep` to your hook matcher** if you wrote `.claude/settings.json` by hand:
  `Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch|mcp__.*`.
  `brakepoint init --claude-code` writes it for new projects.

### Security fixes

- File paths are normalised, so `.claude//settings.json` and `.claude/./settings.json`
  no longer get past `BP-SELF-001`.
- `BP-SELF-001` covers `~/.config/brakepoint/` and `~/.local/state/brakepoint/`. Before,
  an agent could approve its own request by writing a decision file into the queue. The
  new locked rule `BP-SELF-002` covers custom queue, audit, catalog and policy paths.
- The Claude Code hook checks `Grep`, which prints file contents (for example `.env`).
- The hook finds the policy from `CLAUDE_PROJECT_DIR`, so `cd /tmp` no longer escapes a
  stricter project policy.
- The MCP proxy refuses JSON-RPC batches that contain `tools/call`; they were forwarded
  unchecked.
- `$IFS` word splitting (`rm${IFS}-rf${IFS}/`) and SQL comments used as spaces
  (`DROP/**/TABLE`) are seen through.
- `approval.unattended_modes` given as a string was split into characters, which turned
  denials in `bypassPermissions` mode into asks.
- Terminal approval ignores keys typed before the prompt appeared, so a stray `yes` cannot
  approve an action nobody has seen.
- The URL-credential redaction regex and several catalog patterns were quadratic on long
  input (300 KB took about two minutes), enough to time out the hook. Evaluation is now
  linear: about a second for 1 MB.

### Fixes

- Terminal approval (`tty` backend, and `auto` outside a harness) never worked: opening
  `/dev/tty` in buffered read-write mode always fails, so every request was denied.
- The terminal approval timeout now covers the whole answer, not just the first key.
- The MCP proxy keeps serving pings, cancellations and other calls while one call waits
  for a human.
- The audit log no longer breaks its own hash chain after an entry over 64 KB.
- The MCP proxy reports the server's real exit code after it has to stop the server.

### Added

- `brakepoint validate [path]`: load a policy exactly as the hook would and report
  problems.

## 0.1.0

First release.
