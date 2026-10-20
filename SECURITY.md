# Release trust boundaries

Report security issues privately to the repository owner. Never put private keys, registry tokens, or production credentials in issues, commits, or artifacts.

Consumer build and smoke-test jobs have no repository release-write permission. Updater and OS signing credentials belong only at their existing consumer signing boundaries; strict inventory keys belong only in the protected inventory-signing step. Registry upload jobs consume already-built packages and use their registered publisher identity.

The publisher executes only the pinned toolkit. It reads consumer manifests, notes, public keys, and version fields as data, verifies every artifact and remote upload, binds tags to the captured source, and refuses published-release replacement. A compromised required-check bypass, environment configuration, signing key, toolkit commit, runner, or GitHub account remains outside that guarantee. Configure actual reviewers, rulesets, immutable releases, and key rotation deliberately.

This implementation does not claim independent review, a SLSA level, platform-signing coverage, or successful live consumer releases. Existing signed updaters must remain fail-closed. Standard and strict are distinct executable profiles; selecting standard does not satisfy strict-inventory requirements.
