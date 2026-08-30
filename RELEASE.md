# Release Process

Releases are automated with [release-it](https://github.com/release-it/release-it/) and [lerna-changelog](https://github.com/lerna/lerna-changelog/). release-it updates the changelog and version, creates and pushes the Git tag, creates the GitHub release, and publishes the package to npm.

## Preparation

Before releasing, review every pull request merged since the previous release. Ensure each PR has an appropriate lerna-changelog label and a user-facing title suitable for release notes.

Use these labels:

- `breaking`: a breaking API or CLI contract change.
- `enhancement`: a new feature or enhancement.
- `bug`: a fix for behavior included in a previous release.
- `documentation`: documentation changes.
- `internal`: internal changes that should still appear in release notes.

Changelogs are for users, so edit titles and generated notes for clarity rather than preserving implementation-oriented wording.

## Release

1. Install the mise-managed toolchain and project dependencies, then run the full checks:

   ```bash
   mise install
   npm install
   npm run test:all
   npm run audit
   ```

2. Create a [GitHub personal access token][generate-token] with `repo` scope and expose it as `GITHUB_AUTH`:

   ```bash
   export GITHUB_AUTH=abc123def456
   ```

3. Start release-it through the package script:

   ```bash
   npm run release
   ```

release-it prompts for the version and opens the generated changelog for review. After confirmation, it commits the version and changelog, tags and pushes the release, creates the GitHub release, and publishes `@gleanwork/auth` to npm.

[generate-token]: https://github.com/settings/tokens/new?scopes=repo&description=GITHUB_AUTH+env+variable

## Verification

After release-it finishes:

1. Verify the published version with `npm view @gleanwork/auth@<version>`.
2. Install that exact version in a clean project.
3. Confirm tenant discovery, `login`, token retrieval, `status`, and `logout` against a test tenant without exposing credentials.
4. Confirm the npm artifact contains only the expected compiled output, package metadata, `CHANGELOG.md`, `LICENSE`, and `README.md`, with no `dist` source maps.

Do not update downstream consumers until the exact npm artifact passes these checks.

## Dev-only audit findings

An unscoped `npm audit` reports vulnerabilities in development-only release and test tooling, including the lerna-changelog dependency chain. These dependencies are not included in the published package. CI and `npm run audit` intentionally use `--omit=dev` to enforce a clean production dependency tree; Dependabot tracks updates to the development toolchain monthly.
