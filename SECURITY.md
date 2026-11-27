# Security policy

## Supported versions

Security fixes are applied to the latest published minor version of `pylogcage`.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use the private security advisory form for this repository:

https://github.com/draarivpatel-ui/pylogcage/security/advisories/new

Include:

- A minimal reproducer.
- The affected version and Python version.
- Whether the issue concerns log injection, terminal control, secret leakage, redaction bypass, structured-record handling, JSON output size, or CLI file handling.
- Whether a public proof of concept is safe to disclose.

Do not include live credentials or private user data in a report. Use synthetic values.

## Response expectations

Reports are acknowledged within 3 business days. Initial triage is targeted within 14 days. A fix, mitigation, or documented resolution is targeted within 90 days. Fixes include regression tests, and disclosure is coordinated when needed. Security issues that can expose secrets or terminal control sequences are treated as high priority.

## Scope notes

`pylogcage` is a defensive logging library. Findings that require an application to deliberately log attacker-controlled secret values are still in scope when the library fails to redact a documented pattern. Application-specific secret formats not documented or supplied through configuration may be feature requests rather than vulnerabilities.
