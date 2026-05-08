# Plugin Development

The MVP contains the data model and folder layout for future non-destructive POC plugins. A plugin should expose metadata and a safe check function.

## Required Metadata

- `name`
- `cve`
- `product`
- `severity`
- `author`
- `references`
- `tags`
- `safe_check`

## Required Behavior

- `MatchFingerprint(target, fingerprints) bool`
- `Check(ctx, target) (Finding, bool, error)`
- `Evidence() string`

Plugins must verify existence only. They must not execute commands, write files, deploy web shells, read sensitive files, bypass logs, persist access, or alter target data.

## Result Contract

Plugins should emit `core.Finding` with target, type, severity, location, evidence, recommendation, and timestamp. Evidence should be concise and avoid secrets.

