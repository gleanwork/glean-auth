# Contributing

## Setup

The repository toolchain is managed by [mise](https://mise.jdx.dev/).

```bash
mise install
npm ci
npm run test:all
npm run audit
```

Use caret ranges for dependencies. Authentication behavior is security-sensitive: changes to tenant trust boundaries, OAuth callbacks, credential storage, scope handling, or token refresh require focused tests and a packed-package smoke test.

## Target package boundaries

The approved public JavaScript API is intentionally limited to:

- `discoverGleanTenant(email)`
- `createGleanTokenProvider(options)`

The approved CLI commands are `login`, `status`, `token`, and `logout`.

Keep PKCE values, state storage, OAuth exchanges, client registration, refresh behavior, and locking behind the two public API entry points and four CLI commands. OAuth scope strings remain case-sensitive; advertised `scopes_supported` metadata is advisory, while the scope actually granted by the token endpoint is authoritative.

The CLI never reads or writes project `.env` files. Tenant resolution is limited to `--server-url`, `--email`, or `GLEAN_SERVER_URL`. OAuth state belongs only in the package state directory (`$XDG_STATE_HOME/glean-auth` when `XDG_STATE_HOME` is absolute, otherwise `~/.local/state/glean-auth`), never in project files. Only the explicit `token` command may print an OAuth credential.

## Quality checks

`npm run test:all` runs formatting checks, linting, type checking, tests, and a production build. Before requesting review, also run:

```bash
npm run audit
npm pack --dry-run
```

Do not commit generated `dist` source maps; the published package excludes them.

## Releases

Releases use release-it rather than a GitHub Actions release workflow. See [RELEASE.md](./RELEASE.md). Do not publish a version referenced by downstream recipes until the exact npm artifact has passed a clean installation and live test-tenant smoke test.
