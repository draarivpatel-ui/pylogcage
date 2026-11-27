# Good first issues

These are bounded starter specifications for new contributors. Each item should include tests and documentation.

1. **API reference examples**: Add small examples for every exported function in `README.md`, with one assertion-style expected output per example.
2. **Timezone object coverage**: Add tests for aware `datetime`, `date`, and `time` values in structured records.
3. **Custom truncation marker tests**: Add matrix coverage for marker lengths, marker validation failures, and interaction with visible escape tokens.
4. **Nested path wildcard tests**: Add tests for `redact_paths` patterns such as `users.*.token` and nested list indexes.
5. **CLI help snapshots**: Add tests that `pylogcage --help`, `sanitize --help`, and `audit --help` document exit behavior and safety properties.
6. **Audit count matrix**: Add tests for files containing several finding types on one line and repeated findings across many lines.
7. **Large binary input tests**: Add tests showing `bytes` and `bytearray` record values are decoded safely without throwing on invalid UTF-8.
8. **Formatter fallback tests**: Add tests for malformed percent templates, missing arguments, broken exception tuples, and custom `extra` key collisions.
9. **Performance regression fixture**: Add a deterministic benchmark-style unittest for repeated unterminated OSC and CSI input, with a generous CI-safe time bound.
10. **Typing smoke test**: Add a test that the distribution contains `py.typed` and that all public API names in `__all__` are importable.
