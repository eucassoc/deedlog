# Security policy

deedlog exists to make evidence trustworthy, so we treat vulnerabilities
in it as high priority.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/eucassoc/deedlog/security/advisories/new).
Do not open a public issue.

We aim to acknowledge reports within 3 business days and to agree on a
disclosure timeline with the reporter.

## Supported versions

Until v1.0, only the latest release receives security fixes.

## Scope

Especially in scope:

- Ways to make `dlog verify` accept a chain that was edited, reordered or
  had records removed from the middle.
- Ways to recover personal data from records or checkpoints.
- Supply chain issues in our build and release process.
