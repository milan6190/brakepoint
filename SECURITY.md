# Security policy

Brakepoint is a security control, so a bypass is a vulnerability.

## Reporting

Please report bypasses and other vulnerabilities privately through GitHub's
**Report a vulnerability** button on the Security tab, not in a public issue. Include the
action that got through, the decision you expected, and the policy you used.

We aim to acknowledge reports within 3 business days.

## What counts

- A destructive action in a catalogued category that Brakepoint allows with the default policy.
- Any way for an agent to approve its own request, change the policy, or disable the hook.
- A crash or error path that allows an action instead of denying it.
- Secrets that reach the audit log unredacted.

Novel destructive commands in categories the catalog does not cover yet are welcome as
ordinary pull requests.

## Supported versions

Only the latest release receives fixes while the project is in alpha.
