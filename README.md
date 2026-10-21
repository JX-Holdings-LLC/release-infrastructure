# Unified release infrastructure

Shared version validation, manual release selection, artifact verification, and draft publication for personal and JX Holdings repositories. Application packaging, smoke tests, updater signatures, and registry identities stay in each application repository.

## Maintainer procedure

1. Change the app and advance its entry in `release.json`; use a patch by default. Synchronize embedded versions and write accurate release notes.
2. Pass CI and merge into `main`. Merging and pushing tags do not publish migrated applications.
3. Run **Actions → Release → Run workflow** from **main**, select **stable** or **preview**, and leave **dry_run** enabled for the first run.
4. Inspect all packages and smoke-test results. Dispatch again with dry run disabled when ready to publish, satisfying configured environment approvals.

Only apps ahead of their published version in their own tag namespace are selected. Equal versions are skipped; decreases fail. Preview versions use SemVer prerelease suffixes. Build metadata is unsupported. Builds, signatures, and tags refer to the single captured source SHA.

## Consumer files

```json
{
  "schemaVersion": 1,
  "apps": {
    "example": {"title": "Example", "version": "0.1.0"}
  }
}
```

`.release/config.json` holds `schemaVersion: 1`, `bumpPolicy: "every-main-change"`, and matching app entries:

```json
{
  "schemaVersion": 1,
  "bumpPolicy": "every-main-change",
  "apps": {
    "example": {
      "tagPrefix": "v",
      "paths": ["**"],
      "versionFiles": [{"path": "package.json", "format": "json", "key": "version"}],
      "notes": "CHANGELOG.md",
      "notesSection": true,
      "assets": ["Example-{version}-windows-x64.exe", "Example-{version}-linux-x64.tar.gz"],
      "security": "standard"
    }
  }
}
```

Keep published tag namespaces and filenames compatible with existing clients. JSON fields use dotted keys; text fields use `format: "text"` and a JavaScript `pattern` with one named `(?<version>...)` capture. Local tooling must handle specialized metadata and resource generation. `notesSection` extracts the version's level-two changelog section; otherwise the notes file is used in full. Notes paths can include `{app}` and `{version}`. Placeholder notes block release planning.

## Workflows and pins

- `validate.yml` checks configuration, embedded versions, and version advances on PRs and pushes. First adoption has no prior manifest to compare. Later changes use both base and proposed scopes and the base policy, so narrowing scopes cannot bypass a bump. Branch protections must actually require this check.
- `plan.yml` selects releases with read permissions and uploads `release-plan.json`; outputs are `selected`, `sha`, `apps`, and `matrix`.
- `finish.yml` signs strict inventories, verifies complete bundles with public keys, then optionally publishes. It consumes a consumer-produced flat artifact and the original plan. No consumer script executes in its write-permission job.

Every reusable workflow reference **and** its `toolkit-ref` input must use the same reviewed, full 40-character infrastructure commit. There is no mutable-main fallback. Consumer builds must check out the planner's `sha`, disable automatic publication, and collect every required platform before invoking the publisher. A matrix failure blocks publication for the selected group. Separate apps are separate GitHub releases; there is no cross-app transaction.

## Security and publication

`standard` requires nonempty regular assets, complete inventories, final SHA256 checksums, a source-bound draft, matching GitHub-recorded upload digests and sizes, and another tag-target check before exposing a release. Existing published versions are never overwritten. Existing drafts can be retried only with their original source and plan; unexpected draft assets require inspection. A later main SHA cannot retarget the old tag. All release pages are read, including pagination. Metadata/authentication errors fail rather than being treated as an empty release history.

`strict` additionally requires a checked-in PEM Ed25519 `publicKey`, and a matching `RELEASE_SIGNING_KEY_PEM` environment secret. A separate signing job produces `release-integrity.json` and `release-integrity.sig`, binding app, version, source SHA, and payload hashes. The publisher receives no private key. Payloads are streamed when hashing.

Existing updater signatures, OS code signing/notarization, package attestations, and registry identities remain consumer responsibilities. A strict inventory does not replace installed-client update authentication. A standard migration must not be described as achieving the optional strict profile.

Environment names in YAML do not establish reviewer or branch restrictions. Configure and verify the actual `release`, `release-strict`, and per-app signing environments before relying on them. Release/signing work belongs on disposable runners, separate from persistent QA runners. The toolkit does not configure rulesets, immutable releases, registry identities, or secrets.

## Compatibility extensions used by migrations

The handoff's initial implementation was unavailable (its remote contained only a README). This implementation is reconstructed from the design, with these explicit additions for existing distributions:

- `checksumFile` preserves names such as `checksums.txt` and `SHA256SUMS` consumed by existing installers.
- `legacyLatest: true` explicitly preserves the repository's existing stable latest-release alias for a designated primary app. The default remains `--latest=false`, and previews never become latest. This avoids breaking deployed clients using `releases/latest` during migration; auxiliary apps retain separate namespaces and never take over that alias.
- `optionalAssets` declares **bounded, anchored** filename rules for legitimate variants: a signed/unsigned installer choice, a complete optional pair of bundled-model installers, detached signing proofs, or a versioned incremental patch. Required platform deliverables remain exact `assets`. Bounds and `allOrNone` enforce completeness; unknown files, partial variant groups, directories, and symlinks still fail. `{version}` in a pattern is treated as a literal version.
- `preserveChecksum: true` retains an existing checksum file's bytes for detached GPG signatures, after checking its exact filename/hash coverage against the final bundle. `checksumExclusions` names detached signature/public-key files excluded from that checksum to avoid self-reference. GitHub upload digest checks still cover every attached file.

These are migration compatibility controls, not permission to omit a required platform or relax an existing updater signature.

## Local commands

With the pinned toolkit checked out at `.toolkit` in a consumer:

```sh
node .toolkit/src/release.mjs validate
node .toolkit/src/release.mjs bump --app example
node .toolkit/src/release.mjs bump --app example --kind minor
node .toolkit/src/release.mjs plan --channel stable
node .toolkit/src/release.mjs verify --app example --bundle release-bundle --sha SOURCE_SHA
```

The bump command updates configured fields and creates a notes placeholder for version-specific notes files. Replace it before release; for section-based changelogs, add the new section yourself. Never silently delete app IDs or change tag prefixes. Use a fresh version for rollback. There is no implemented Prepare-release-PR button.

Run `npm run check` and `npm test` on Node 24+. Tests include numeric/prerelease ordering, configuration, version consistency, real-Git bump enforcement, bundles, strict signatures/tampering, draft retries, and simulated publication failures. Local tests and workflow lint do not establish that a native package installs correctly or that hosted release credentials are configured.

`notesAsset` can name a required verified text artifact containing observed signing status. The publisher appends it to the source-controlled notes and refreshes that status on a same-source draft retry. Detached checksum exclusions must be explicit; uploaded SHA256 digests still cover these proof files.
