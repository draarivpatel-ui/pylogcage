# Contributing

Thanks for helping improve `pylogcage`.

## Ground rules

- Keep the runtime dependency-free.
- Support Python 3.9 through 3.13.
- Preserve the security ordering: strip terminal sequences, redact, neutralize, then truncate.
- Do not add real credentials, realistic vendor-shaped placeholder credentials, private paths, or private contact details.
- Add regression tests for every security fix.
- Use `unittest` from the standard library unless a test dependency is explicitly accepted by maintainers.

## Local verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
```

Before sending a pull request, confirm that there are no tracked `__pycache__` directories or `.pyc` files.

## Reporting security issues

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.

## Pull requests

Keep changes focused. Explain the attacker model or user problem, the chosen invariant, and the tests that prove it. Performance-sensitive parsing changes should include a pathological-input test.
