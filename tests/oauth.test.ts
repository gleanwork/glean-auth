import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGleanAuth,
  createGleanTokenProvider,
  type GleanAuthOptions,
} from "../src/oauth.js";
import { readState, writeState, type OAuthStateKey } from "../src/state.js";

const temporaryDirectories: string[] = [];
const servers: Server[] = [];
const originalFetch = globalThis.fetch;
const originalApiToken = process.env.GLEAN_API_TOKEN;
const originalOAuthClientId = process.env.GLEAN_OAUTH_CLIENT_ID;

afterEach(async () => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  if (originalApiToken === undefined) delete process.env.GLEAN_API_TOKEN;
  else process.env.GLEAN_API_TOKEN = originalApiToken;
  if (originalOAuthClientId === undefined) {
    delete process.env.GLEAN_OAUTH_CLIENT_ID;
  } else {
    process.env.GLEAN_OAUTH_CLIENT_ID = originalOAuthClientId;
  }
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function stateDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "glean-auth-oauth-"));
  temporaryDirectories.push(directory);
  return directory;
}

type MetadataOverrides = Partial<
  Record<
    "authorization_endpoint" | "token_endpoint" | "registration_endpoint",
    string
  >
>;

interface OAuthFixture {
  options: GleanAuthOptions;
  requests: Array<{ path: string; body: string }>;
  dispatchedUrls: string[];
  tokenRequests: () => number;
}

async function oauthFixture(
  advertisedScopes = ["openid", "offline_access", "SEARCH"],
  grantedScope = "openid offline_access SEARCH",
  metadataOverrides:
    MetadataOverrides | ((discoveryRequest: number) => MetadataOverrides) = {},
): Promise<OAuthFixture> {
  const requests: Array<{ path: string; body: string }> = [];
  const dispatchedUrls: string[] = [];
  let discoveryRequests = 0;
  let tokenRequests = 0;
  const server = createServer((request, response) => {
    void (async () => {
      const chunks: string[] = [];
      request.setEncoding("utf8");
      for await (const chunk of request) chunks.push(String(chunk));
      const body = chunks.join("");
      const path = request.url ?? "/";
      requests.push({ path, body });
      response.setHeader("content-type", "application/json");

      if (path === "/.well-known/oauth-authorization-server/oauth") {
        discoveryRequests += 1;
        const overrides =
          typeof metadataOverrides === "function"
            ? metadataOverrides(discoveryRequests)
            : metadataOverrides;
        response.end(
          JSON.stringify({
            issuer: "https://acme-be.glean.com/oauth",
            authorization_endpoint: "https://acme-be.glean.com/oauth/authorize",
            token_endpoint: "https://acme-be.glean.com/oauth/token",
            registration_endpoint: "https://acme-be.glean.com/oauth/register",
            code_challenge_methods_supported: ["S256"],
            scopes_supported: advertisedScopes,
            ...overrides,
          }),
        );
        return;
      }
      if (path === "/oauth/register") {
        response.statusCode = 201;
        response.end(
          JSON.stringify({
            client_id: "registered-client",
            redirect_uris: ["http://127.0.0.1:54321/oauth/callback"],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            token_endpoint_auth_method: "none",
          }),
        );
        return;
      }
      if (path === "/oauth/token") {
        tokenRequests += 1;
        const grantType = new URLSearchParams(body).get("grant_type");
        response.end(
          JSON.stringify(
            grantType === "authorization_code"
              ? {
                  access_token: "initial-access-token",
                  refresh_token: "initial-refresh-token",
                  token_type: "Bearer",
                  expires_in: 30,
                  scope: grantedScope,
                }
              : {
                  access_token: "refreshed-access-token",
                  refresh_token: "rotated-refresh-token",
                  token_type: "Bearer",
                  expires_in: 3600,
                  scope: grantedScope,
                },
          ),
        );
        return;
      }
      response.statusCode = 404;
      response.end("{}");
    })();
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Test OAuth server did not bind to a TCP port");
  }

  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (
        input: Parameters<typeof fetch>[0],
        init?: Parameters<typeof fetch>[1],
      ) => {
        const request =
          input instanceof Request ? input : new Request(input, init);
        const url = new URL(request.url);
        dispatchedUrls.push(url.href);
        if (url.hostname === "acme-be.glean.com") {
          url.protocol = "http:";
          url.hostname = "127.0.0.1";
          url.port = String(address.port);
        }
        return originalFetch(new Request(url, request));
      },
    ),
  );

  return {
    options: {
      serverUrl: "https://acme.glean.com",
      scopes: ["SEARCH"],
      callbackPort: 54_321,
      stateDir: await stateDirectory(),
    },
    requests,
    dispatchedUrls,
    tokenRequests: () => tokenRequests,
  };
}

function fixtureStateKey(
  fixture: OAuthFixture,
  registrationScope = "openid offline_access SEARCH",
): OAuthStateKey {
  return {
    profile: "default",
    issuer: "https://acme-be.glean.com/oauth",
    registrationScope,
  };
}

describe("Glean OAuth", () => {
  it("discovers the Glean OAuth issuer beneath the canonical backend", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth({
      ...fixture.options,
      clientId: "static-client",
    });

    await auth.login({
      authorize: (authorizationUrl) =>
        Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          ),
        ),
    });

    expect(fixture.dispatchedUrls).toContain(
      "https://acme-be.glean.com/.well-known/oauth-authorization-server/oauth",
    );
  });

  it("uses DCR and PKCE, rotates refresh tokens, and single-flights providers", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth(fixture.options);

    await auth.login({
      authorize: async (authorizationUrl) => {
        await expect(
          readState(fixtureStateKey(fixture), {
            stateDir: fixture.options.stateDir,
          }),
        ).resolves.toEqual({
          clientId: "registered-client",
          redirectUri: "http://127.0.0.1:54321/oauth/callback",
          registrationScope: "openid offline_access SEARCH",
        });
        expect(authorizationUrl.searchParams.get("scope")).toBe(
          "openid offline_access SEARCH",
        );
        expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe(
          "S256",
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge"),
        ).toBeTruthy();
        const state = authorizationUrl.searchParams.get("state");
        expect(state).toBeTruthy();
        return new URL(
          `http://127.0.0.1:54321/oauth/callback?code=local-code&state=${String(state)}`,
        );
      },
    });

    const firstProvider = createGleanTokenProvider(fixture.options);
    // This path resolves to the same state directory but intentionally gives the
    // providers different in-memory flight keys, exercising the file lock.
    const secondProvider = createGleanTokenProvider({
      ...fixture.options,
      stateDir: `${String(fixture.options.stateDir)}/.`,
    });
    await expect(
      Promise.all([firstProvider(), firstProvider(), secondProvider()]),
    ).resolves.toEqual([
      "refreshed-access-token",
      "refreshed-access-token",
      "refreshed-access-token",
    ]);
    expect(fixture.tokenRequests()).toBe(2);

    const persisted = await readState(
      {
        profile: "default",
        issuer: "https://acme-be.glean.com/oauth",
        registrationScope: "openid offline_access SEARCH",
      },
      { stateDir: fixture.options.stateDir },
    );
    expect(persisted?.refreshToken).toBe("rotated-refresh-token");
    expect(persisted?.accessToken).toBe("refreshed-access-token");

    const registration = fixture.requests.find(
      (request) => request.path === "/oauth/register",
    );
    expect(JSON.parse(registration?.body ?? "{}")).toEqual({
      client_name: "Glean developer tools",
      redirect_uris: ["http://127.0.0.1:54321/oauth/callback"],
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      scope: "openid offline_access SEARCH",
    });
    const tokenBodies = fixture.requests
      .filter((request) => request.path === "/oauth/token")
      .map((request) => new URLSearchParams(request.body));
    expect(tokenBodies.map((body) => body.get("grant_type"))).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(tokenBodies[0]?.get("code_verifier")).toBeTruthy();
  });

  it("adds exact base scopes while preserving and exactly deduplicating custom scopes", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const exactScope = "openid offline_access profile email OpenID";
    const fixture = await oauthFixture(
      ["openid", "offline_access", "profile", "email", "OpenID"],
      exactScope,
    );
    const auth = createGleanAuth({
      ...fixture.options,
      scopes: ["profile email", "profile", "OpenID", "offline_access"],
    });

    await auth.login({
      authorize: (authorizationUrl) => {
        expect(authorizationUrl.searchParams.get("scope")).toBe(exactScope);
        const state = authorizationUrl.searchParams.get("state");
        return Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(state)}`,
          ),
        );
      },
    });

    const registration = fixture.requests.find(
      (request) => request.path === "/oauth/register",
    );
    expect(JSON.parse(registration?.body ?? "{}")).toMatchObject({
      scope: exactScope,
    });
  });

  it("rejects a case-mismatched granted custom scope", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture(
      ["openid", "offline_access", "profile", "email"],
      "openid offline_access profile Email",
    );
    const auth = createGleanAuth({
      ...fixture.options,
      scopes: ["profile", "email"],
    });

    await expect(
      auth.login({
        authorize: (authorizationUrl) =>
          Promise.resolve(
            new URL(
              `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
            ),
          ),
      }),
    ).rejects.toThrow("OAuth grant is missing a requested scope");
  });

  it("uses a static client without dynamic registration", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth({
      ...fixture.options,
      clientId: "static-client",
      clientName: "Static test client",
      scopes: ["openid offline_access", "SEARCH"],
      profile: "static",
    });

    await auth.login({
      authorize: (authorizationUrl) =>
        Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          ),
        ),
    });

    expect(
      fixture.requests.some((request) => request.path === "/oauth/register"),
    ).toBe(false);
    const discovery = fixture.requests.find((request) =>
      request.path.startsWith("/.well-known/"),
    );
    expect(discovery).toBeDefined();
  });

  it.each([
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
  ] as const)(
    "rejects an off-issuer %s before browser or token exchange",
    async (endpoint) => {
      delete process.env.GLEAN_API_TOKEN;
      const fixture = await oauthFixture(
        ["openid", "offline_access", "SEARCH"],
        "openid offline_access SEARCH",
        { [endpoint]: `https://attacker.example/${endpoint}` },
      );
      const auth = createGleanAuth({
        ...fixture.options,
        clientId: "static-client",
      });
      const authorize = vi.fn();

      await expect(auth.login({ authorize })).rejects.toThrow(
        `OAuth ${endpoint} must be a valid HTTPS URL on the canonical issuer origin`,
      );
      expect(authorize).not.toHaveBeenCalled();
      expect(fixture.tokenRequests()).toBe(0);
    },
  );

  it("rejects an off-issuer registration endpoint before DCR", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture(
      ["openid", "offline_access", "SEARCH"],
      "openid offline_access SEARCH",
      { registration_endpoint: "https://attacker.example/register" },
    );
    const auth = createGleanAuth(fixture.options);
    const authorize = vi.fn();

    await expect(auth.login({ authorize })).rejects.toThrow(
      "OAuth registration_endpoint must be a valid HTTPS URL on the canonical issuer origin",
    );
    expect(authorize).not.toHaveBeenCalled();
    expect(
      fixture.requests.some((request) => request.path === "/oauth/register"),
    ).toBe(false);
  });

  it("blocks an off-issuer DCR endpoint advertised by second discovery", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture(
      ["openid", "offline_access", "SEARCH"],
      "openid offline_access SEARCH",
      (discoveryRequest) =>
        discoveryRequest === 1
          ? {}
          : { registration_endpoint: "https://attacker.example/register" },
    );
    const auth = createGleanAuth(fixture.options);
    const authorize = vi.fn();

    await expect(auth.login({ authorize })).rejects.toThrow(
      "OAuth client registration failed",
    );
    expect(fixture.dispatchedUrls).not.toContain(
      "https://attacker.example/register",
    );
    expect(authorize).not.toHaveBeenCalled();
    expect(
      fixture.requests.some((request) => request.path === "/oauth/register"),
    ).toBe(false);
  });

  it("does not overwrite a registration changed during browser interaction", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth(fixture.options);

    await expect(
      auth.login({
        authorize: async (authorizationUrl) => {
          await writeState(
            fixtureStateKey(fixture),
            {
              clientId: "replacement-client",
              redirectUri: "http://127.0.0.1:54321/oauth/callback",
              registrationScope: "openid offline_access SEARCH",
            },
            { stateDir: fixture.options.stateDir },
          );
          return new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          );
        },
      }),
    ).rejects.toThrow("OAuth client registration changed during sign-in");

    await expect(
      readState(fixtureStateKey(fixture), {
        stateDir: fixture.options.stateDir,
      }),
    ).resolves.toEqual({
      clientId: "replacement-client",
      redirectUri: "http://127.0.0.1:54321/oauth/callback",
      registrationScope: "openid offline_access SEARCH",
    });
  });

  it("uses GLEAN_OAUTH_CLIENT_ID and rejects a grant for another client", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    vi.stubEnv("GLEAN_OAUTH_CLIENT_ID", " environment-client ");
    const auth = createGleanAuth(fixture.options);

    await auth.login({
      authorize: (authorizationUrl) =>
        Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          ),
        ),
    });

    expect(
      fixture.requests.some((request) => request.path === "/oauth/register"),
    ).toBe(false);

    vi.stubEnv("GLEAN_OAUTH_CLIENT_ID", "different-client");
    const otherClient = createGleanAuth(fixture.options);
    await expect(otherClient.getAccessToken()).rejects.toThrow(
      "OAuth sign-in is required",
    );
    await expect(otherClient.status()).resolves.toMatchObject({
      authenticated: false,
      source: "oauth",
    });
    expect(fixture.tokenRequests()).toBe(1);
  });

  it("allows requested scopes omitted from advisory server metadata", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture(["openid", "offline_access"]);
    const auth = createGleanAuth(fixture.options);

    await expect(
      auth.login({
        authorize: (authorizationUrl) => {
          expect(authorizationUrl.searchParams.get("scope")).toBe(
            "openid offline_access SEARCH",
          );
          const state = authorizationUrl.searchParams.get("state");
          return Promise.resolve(
            new URL(
              `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(state)}`,
            ),
          );
        },
      }),
    ).resolves.toBeUndefined();
  });

  it("performs OAuth login even when GLEAN_API_TOKEN is configured", async () => {
    process.env.GLEAN_API_TOKEN = "environment-token";
    const fixture = await oauthFixture();
    const auth = createGleanAuth(fixture.options);

    await auth.login({
      authorize: (authorizationUrl) =>
        Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          ),
        ),
    });

    expect(fixture.tokenRequests()).toBe(1);
    expect(
      fixture.requests.some((request) => request.path === "/oauth/register"),
    ).toBe(true);
  });

  it("gives GLEAN_API_TOKEN precedence and never exposes it in status", async () => {
    const fixture = await oauthFixture();
    process.env.GLEAN_API_TOKEN = " environment-token ";
    const auth = createGleanAuth(fixture.options);

    await expect(auth.getAccessToken()).resolves.toBe("environment-token");
    await expect(createGleanTokenProvider(fixture.options)()).resolves.toBe(
      "environment-token",
    );
    const status = await auth.status();
    expect(status).toMatchObject({ authenticated: true, source: "api-token" });
    expect(JSON.stringify(status)).not.toContain("environment-token");
    expect(fixture.requests).toHaveLength(0);
  });

  it("uses complete nonblank state and expiry skew for authenticated status", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth(fixture.options);
    const completeState = {
      clientId: "registered-client",
      redirectUri: "http://127.0.0.1:54321/oauth/callback",
      registrationScope: "openid offline_access SEARCH",
      grantedScope: "openid offline_access SEARCH",
      accessToken: "access-token",
      expiresAt: Date.now() + 30_000,
    };

    await writeState(fixtureStateKey(fixture), completeState, {
      stateDir: fixture.options.stateDir,
    });
    await expect(auth.status()).resolves.toMatchObject({
      authenticated: false,
      refreshable: false,
    });
    await expect(auth.getAccessToken()).rejects.toThrow(
      "OAuth sign-in is required",
    );

    await writeState(
      fixtureStateKey(fixture),
      {
        ...completeState,
        redirectUri: " ",
        refreshToken: "refresh-token",
        expiresAt: Date.now() + 3_600_000,
      },
      { stateDir: fixture.options.stateDir },
    );
    await expect(auth.status()).resolves.toMatchObject({
      authenticated: false,
      refreshable: true,
    });
    await expect(auth.getAccessToken()).rejects.toThrow(
      "OAuth sign-in is required",
    );
  });

  it("reports safe OAuth status and clears only persisted state", async () => {
    delete process.env.GLEAN_API_TOKEN;
    const fixture = await oauthFixture();
    const auth = createGleanAuth(fixture.options);
    await auth.login({
      authorize: (authorizationUrl) =>
        Promise.resolve(
          new URL(
            `http://127.0.0.1:54321/oauth/callback?code=code&state=${String(authorizationUrl.searchParams.get("state"))}`,
          ),
        ),
    });

    const status = await auth.status();
    expect(status).toMatchObject({
      authenticated: true,
      source: "oauth",
      refreshable: true,
    });
    expect(JSON.stringify(status)).not.toMatch(
      /initial-(?:access|refresh)-token/u,
    );

    expect(Object.keys(auth).sort()).toEqual([
      "getAccessToken",
      "login",
      "logout",
      "status",
    ]);
    await auth.logout();
    await expect(auth.status()).resolves.toMatchObject({
      authenticated: false,
      source: "none",
    });
  });
});
