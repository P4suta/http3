# HTTP/1 handler guardian audit

This directory contains the checked-in static release gate for the HTTP/1 handler guardian.
Generated reports belong under `build/root-validation`.

Run the canonical gate with:

```text
mise run http1-guardian-audit
```

The v5 candidate uses `launcher.py` to write Running first, execute three bounded phases, preserve typed failure evidence, and publish through an independent strict consumer.
It binds each result to exact source, scanner,
checker, history, runtime, configuration, and launcher bytes.
The tracked manifest keeps Ready disabled until independent review and root-owned mise/CI integration are complete.
