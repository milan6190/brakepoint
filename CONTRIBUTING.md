# Contributing to Brakepoint

Thanks for helping. The catalog is the most valuable part of the project, so new and
improved rules are the best contribution.

## Set up

```bash
git clone https://github.com/milan6190/brakepoint && cd brakepoint
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q && ruff check src tests
```

## Adding a rule

1. Pick the catalog file in `src/brakepoint/catalog/` that fits, or add a new one.
2. Give the rule the next free id for its area (`BP-AWS-006`, `BP-SNOW-001`, ...). Ids are
   permanent; never renumber or reuse one.
3. Fill in every field. `why` explains the damage in one or two sentences; `safer` tells the
   agent and the human what to do instead. Both are shown at decision time, so write them for
   someone who has five seconds.
4. Choose severity by the worst realistic outcome:
   - **critical**: permanent loss of data, backups, keys, or whole environments; full-account
     privilege grants; sandbox escape.
   - **high**: destructive but scoped, or hard to reverse.
   - **medium**: risky enough to log.
5. Add at least one "must stop" and one "must allow" case to `tests/test_catalog.py`. A rule
   without a false-positive test will not be merged.
6. If the rule was motivated by a public incident, add the link to `refs`, and consider adding
   a replay to `src/brakepoint/incidents.py`.
7. Regenerate the reference: `brakepoint catalog --markdown > docs/CATALOG.md`.

## Pattern tips

- Rules see each command segment (split on `;`, `&&`, `||`, `|`, newlines, `$(`), the full
  command, and de-quoted versions of each. Use `[^|;&]*` to stay within one command.
- Prefer anchoring on the tool name (`\bkubectl\s+delete\b`) over bare verbs.
- Use `unless` for well-known safe variants instead of making the main pattern unreadable.
- For MCP tools, `field: name` rules match the normalised tool name
  (`mcp__gmail__batchDelete` becomes `mcp gmail batch_delete`).

## Ground rules

- Brakepoint must never loosen a harness's own permissions. Hooks either stay silent, ask,
  or deny.
- Fail closed. If you add a code path that can raise, make sure the integration denies.
- No telemetry, ever.

## Releasing (maintainers)

1. Bump `__version__` in `src/brakepoint/__init__.py` and merge to `main`.
2. Create a GitHub release with tag `vX.Y.Z` matching that version.
3. The `Release` workflow tests, builds, and publishes to PyPI via trusted publishing.

By contributing you agree to license your work under the MIT license.
