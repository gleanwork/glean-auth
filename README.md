# @gleanwork/auth

[![Prerelease](https://img.shields.io/badge/-Prerelease-F6F3EB?style=flat-square)](https://github.com/gleanwork/.github/blob/main/docs/repository-stability.md#prerelease)
[![npm version](https://img.shields.io/npm/v/@gleanwork/auth.svg)](https://www.npmjs.com/package/@gleanwork/auth)
[![CI](https://github.com/gleanwork/glean-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/gleanwork/glean-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Authenticate with Glean from the command line or JavaScript, with tenant discovery, OAuth login, and automatic token refresh.

## Installation

Requires Node.js 22.12.0 or newer.

```bash
npm install @gleanwork/auth
```

The JavaScript API is ESM-only.

## Quick Start

Sign in with your work email and request the scopes your application needs:

```bash
npx glean-auth login --email you@example.com --scopes search
```

Print the current token for a shell command or non-JavaScript application:

```bash
export GLEAN_API_TOKEN="$(
  npx glean-auth token --email you@example.com --scopes search
)"
```

You can also run the CLI without installing it in a project:

```bash
npx -y @gleanwork/auth login --email you@example.com --scopes search
```

## CLI

| Command  | Description                                                    |
| -------- | -------------------------------------------------------------- |
| `login`  | Sign in with OAuth and save credentials.                       |
| `status` | Show local authentication status without printing credentials. |
| `token`  | Print the current access token.                                |
| `logout` | Remove the matching saved OAuth credentials.                   |

```bash
npx glean-auth status --email you@example.com --scopes search
npx glean-auth status --email you@example.com --scopes search --json
npx glean-auth token --email you@example.com --scopes search
npx glean-auth logout --email you@example.com --scopes search
```

`token` prints only the token and a trailing newline to stdout. It does not start an interactive login. Run `login` first or set `GLEAN_API_TOKEN`.

### Options

| Option                 | Description                                                         |
| ---------------------- | ------------------------------------------------------------------- |
| `--email <address>`    | Discover the Glean tenant associated with an email address.         |
| `--server-url <url>`   | Use an explicit Glean backend URL instead of tenant discovery.      |
| `--scopes <scope,...>` | Request OAuth scopes. This option is repeatable and case-sensitive. |

Use the lowercase scope names advertised by the Glean OAuth server, such as `search`, `chat`, or `mcp`.

Run `npx glean-auth --help` for shared options and the command list. Run `npx glean-auth <command> --help` for command-specific options.

## Authentication

OAuth is the recommended authentication method. `login` uses Authorization Code with PKCE and opens a browser for approval. If the tenant permits Dynamic Client Registration, the CLI registers a client automatically. Set `GLEAN_OAUTH_CLIENT_ID` when an administrator has provisioned a public OAuth client instead.

For CI or another non-interactive environment, set a user-scoped API token and the Glean backend URL:

```bash
export GLEAN_SERVER_URL=https://your-company-be.glean.com
export GLEAN_API_TOKEN=your-api-token
```

A non-empty `GLEAN_API_TOKEN` takes precedence when the package retrieves a token. The package does not validate the scopes or expiration of an API token.

The CLI chooses a tenant in this order:

1. `--server-url`
2. `--email`
3. `GLEAN_SERVER_URL`

OAuth always requests `openid` and `offline_access` in addition to the scopes passed through `--scopes`. A saved OAuth grant is reused only when it includes every requested scope.

## JavaScript API

The package exports two runtime functions and their supporting TypeScript types.

```ts
import { createGleanTokenProvider, discoverGleanTenant } from "@gleanwork/auth";

const tenant = await discoverGleanTenant("you@example.com");
const getAccessToken = createGleanTokenProvider({
  serverUrl: tenant.serverUrl,
  scopes: ["search"],
});

const token = await getAccessToken();
```

`discoverGleanTenant(email)` returns the canonical tenant instance and backend URL for an email address.

`createGleanTokenProvider(options)` returns a non-interactive `() => Promise<string>` callback. It uses `GLEAN_API_TOKEN` when set. Otherwise, it reuses or refreshes credentials created by `glean-auth login`.

The callback can be passed directly to the Glean TypeScript SDK:

```ts
import { Glean } from "@gleanwork/api-client";
import { createGleanTokenProvider } from "@gleanwork/auth";

const glean = new Glean({
  serverURL: "https://your-company-be.glean.com",
  apiToken: createGleanTokenProvider({
    serverUrl: "https://your-company-be.glean.com",
    scopes: ["search"],
  }),
});
```

## Credential Storage

The CLI stores OAuth credentials under `$XDG_STATE_HOME/glean-auth` when `XDG_STATE_HOME` is an absolute path. Otherwise, it uses `~/.local/state/glean-auth`.

On Unix, state directories use mode `0700` and credential files use mode `0600`. The package does not read or write project `.env` files. `status` never prints tokens; `token` intentionally writes a token to stdout for scripts and pipelines.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and quality checks.

## License

MIT, see [LICENSE](LICENSE).
