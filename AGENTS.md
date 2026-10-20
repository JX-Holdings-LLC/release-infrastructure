# Release infrastructure agent guidance

Keep `release.json` authoritative, use patch bumps by default, and preserve public tag namespaces, asset filenames, updater trust, and package identities. Treat consumer files/artifacts as data in the protected publisher. Never give consumer build scripts a release-write token or an inventory-signing key. Pin both the shared workflow and its toolkit checkout to the same reviewed full commit.

Default to every-main-change, using the base policy and both path scopes. Do not introduce exemptions silently. Do not overwrite public versions, move existing release tags, or make missing authentication look like an empty history. Preserve original-source retry restrictions.

Run syntax checks, the real-Git and publication/signature tests, and actionlint on changed workflows. Explain compatibility extensions and record hosted/native checks that have not run. Never claim that an environment name proves reviewers are configured. Do not issue a production release merely to test a migration.
