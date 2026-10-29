# Catalog schema

Catalog files are YAML with a top-level `rules` list. Brakepoint validates every file at
load time and refuses to start (failing closed) if one is malformed.

```yaml
rules:
  - id: BP-SQL-003               # required, BP-<AREA>-<NNN>, permanent
    title: DELETE without a WHERE clause
    category: data-destruction   # see list below
    platform: sql                # free text, used for grouping
    severity: critical           # critical | high | medium
    reversibility: irreversible  # irreversible | hard-to-reverse | reversible
    kinds: [shell, tool, sql]    # which actions the rule applies to (default: shell, tool)
    field: text                  # text (default) or name (tool name only)
    patterns:                    # Python regexes; any match triggers the rule
      - '(?i)\bdelete\s+from\s+[\w."`\[\]]+\s*(?:;|$)'
    unless:                      # optional; cancels a match in the same segment
      - '(?i)\bwhere\b'
    locked: false                # true = always deny; policies cannot relax it
    why: Deletes every row in the table.
    safer: Add a WHERE clause, and preview it with SELECT COUNT(*) first.
    refs:                        # optional links to incidents or documentation
      - https://example.com/incident
```

## Action kinds

| Kind | Text matched |
|---|---|
| `shell` | The command, each segment of it, and de-quoted forms |
| `sql` | The statement |
| `tool` | `<tool name> <JSON arguments>`; commands and SQL inside arguments are also checked as `shell` and `sql` |
| `file` | `read <path>` or `write <path>` |
| `url` | The URL |

## Categories

`data-destruction`, `backup-destruction`, `credential-access`, `privilege-escalation`,
`exposure`, `sandbox-escape`, `code-execution`, `outbound-action`, `financial`,
`self-tamper`, `history-rewrite`, `availability`.

## Using your own catalog

List extra files in your policy:

```yaml
catalogs:
  - ./rules/acme.yaml
```

Rule ids must be unique across all loaded files. Use your own area prefix (for example
`BP-ACME-001`) to avoid clashes with future built-in rules.
