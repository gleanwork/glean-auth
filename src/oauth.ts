import * as oauth from "openid-client";
import {
  authorizeOnLoopback,
  DEFAULT_AUTHORIZATION_TIMEOUT,
  DEFAULT_CALLBACK_PORT,
  OAUTH_CALLBACK_PATH,
} from "./loopback.js";
import { parseServerUrl } from "./server-url.js";
import {
  readState,
  withStateTransaction,
  type OAuthState,
  type OAuthStateKey,
  type OAuthStateTransaction,
} from "./state.js";

const BASE_SCOPES = ["openid", "offline_access"] as const;
const DEFAULT_CLIENT_NAME = "Glean developer tools";
const DEFAULT_PROFILE = "default";
const EXPIRY_SKEW_MS = 60_000;
const REQUEST_TIMEOUT_SECONDS = 30;

export type GleanScopeInput = string | readonly string[];
export type GleanTokenProvider = () => Promise<string>;

export interface GleanAuthOptions {
  serverUrl: string;
  scopes?: GleanScopeInput;
  clientName?: string;
  clientId?: string;
  profile?: string;
  stateDir?: string;
  callbackPort?: number;
  /** Time to wait for the browser callback, in milliseconds. */
  timeout?: number;
}

export interface GleanLoginOptions {
  /** Set to false to prohibit launching a browser. Defaults to true. */
  interactive?: boolean;
  /** Test and embedding hook that replaces the loopback browser interaction. */
  authorize?: (authorizationUrl: URL) => Promise<URL>;
}

export interface GleanAccessTokenOptions {
  /** Allow an interactive login when no saved credential can supply a token. */
  interactive?: boolean;
}

export interface GleanAuthStatus {
  authenticated: boolean;
  source: "api-token" | "oauth" | "none";
  serverUrl: string;
  profile: string;
  scopes: readonly string[];
  expiresAt?: number;
  refreshable?: boolean;
}

export interface GleanAuth {
  login(options?: GleanLoginOptions): Promise<void>;
  getAccessToken(options?: GleanAccessTokenOptions): Promise<string>;
  status(): Promise<GleanAuthStatus>;
  logout(): Promise<void>;
}

interface NormalizedOptions {
  issuer: URL;
  serverUrl: string;
  scopes: string[];
  scope: string;
  clientName: string;
  clientId?: string;
  profile: string;
  stateDir?: string;
  callbackPort: number;
  timeout: number;
  redirectUri: URL;
  stateKey: OAuthStateKey;
  flightKey: string;
}

interface RegisteredOAuthState extends OAuthState {
  clientId: string;
  redirectUri: string;
  registrationScope: string;
}

interface CompleteOAuthState extends RegisteredOAuthState {
  grantedScope: string;
  accessToken: string;
  expiresAt: number;
}

type OAuthTokens = Awaited<ReturnType<typeof oauth.refreshTokenGrant>>;

const tokenFlights = new Map<string, Promise<string>>();

export function createGleanAuth(options: GleanAuthOptions): GleanAuth {
  const normalized = normalizeOptions(options);
  const provider = tokenProvider(normalized);

  const login = async (loginOptions: GleanLoginOptions = {}): Promise<void> => {
    if (
      loginOptions.interactive === false &&
      loginOptions.authorize === undefined
    ) {
      throw new Error("Interactive OAuth sign-in is disabled");
    }
    await loginWithOAuth(normalized, loginOptions.authorize);
  };

  const getAccessToken = async (
    tokenOptions: GleanAccessTokenOptions = {},
  ): Promise<string> => {
    try {
      return await provider();
    } catch (error: unknown) {
      if (tokenOptions.interactive !== true) throw error;
      await login({ interactive: true });
      return provider();
    }
  };

  const status = (): Promise<GleanAuthStatus> => authStatus(normalized);
  const logout = async (): Promise<void> => {
    const pending = tokenFlights.get(normalized.flightKey);
    if (pending !== undefined) await pending.catch(() => undefined);
    await withStateTransaction(
      normalized.stateKey,
      (transaction) => transaction.clear(),
      { stateDir: normalized.stateDir },
    );
  };

  return { login, getAccessToken, status, logout };
}

/** Returns an SDK-compatible, non-interactive token callback. */
export function createGleanTokenProvider(
  options: GleanAuthOptions,
): GleanTokenProvider {
  return tokenProvider(normalizeOptions(options));
}

async function loginWithOAuth(
  options: NormalizedOptions,
  authorize?: (authorizationUrl: URL) => Promise<URL>,
): Promise<void> {
  const { config, registration } = await withStateTransaction(
    options.stateKey,
    async (transaction) => {
      const previous = await transaction.read();
      return registerOrDiscoverClient(options, previous, transaction);
    },
    { stateDir: options.stateDir },
  );

  const codeVerifier = oauth.randomPKCECodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  const expectedState = oauth.randomState();
  const authorizationUrl = oauth.buildAuthorizationUrl(config, {
    redirect_uri: options.redirectUri.href,
    scope: options.scope,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: expectedState,
  });

  const callbackUrl = authorize
    ? await authorize(authorizationUrl)
    : await authorizeOnLoopback(authorizationUrl, {
        redirectUri: options.redirectUri,
        timeout: options.timeout,
      });
  assertCallbackUrl(callbackUrl, options.redirectUri, expectedState);

  let tokens: OAuthTokens;
  try {
    tokens = await oauth.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState,
    });
  } catch {
    throw new Error("OAuth authorization code exchange failed");
  }
  const nextState = stateWithTokens(registration, tokens, options, true);

  await withStateTransaction(
    options.stateKey,
    async (transaction) => {
      const current = await transaction.read();
      if (!registrationMatches(current, registration)) {
        throw new Error("OAuth client registration changed during sign-in");
      }
      await transaction.write(nextState);
    },
    { stateDir: options.stateDir },
  );
}

function tokenProvider(options: NormalizedOptions): GleanTokenProvider {
  return () => {
    const configuredToken = apiToken();
    if (configuredToken !== undefined) return Promise.resolve(configuredToken);

    const existing = tokenFlights.get(options.flightKey);
    if (existing !== undefined) return existing;

    const pending = freshAccessToken(options).finally(() => {
      if (tokenFlights.get(options.flightKey) === pending) {
        tokenFlights.delete(options.flightKey);
      }
    });
    tokenFlights.set(options.flightKey, pending);
    return pending;
  };
}

async function freshAccessToken(options: NormalizedOptions): Promise<string> {
  return withStateTransaction(
    options.stateKey,
    async (transaction) => {
      const state = await transaction.read();
      if (!isCompleteState(state)) throw signInRequired();
      if (
        options.clientId !== undefined &&
        state.clientId !== options.clientId
      ) {
        throw signInRequired();
      }
      assertGrantedScopes(state.grantedScope, options.scopes);

      if (state.expiresAt > Date.now() + EXPIRY_SKEW_MS) {
        return state.accessToken;
      }
      if (!nonBlankString(state.refreshToken)) throw signInRequired();

      const config = await discoverClient(options, state.clientId);
      let tokens: OAuthTokens;
      try {
        tokens = await oauth.refreshTokenGrant(config, state.refreshToken);
      } catch {
        throw new Error("OAuth token refresh failed");
      }
      const refreshed = stateWithTokens(state, tokens, options, false);
      await transaction.write(refreshed);
      return refreshed.accessToken;
    },
    { stateDir: options.stateDir },
  );
}

async function registerOrDiscoverClient(
  options: NormalizedOptions,
  state: OAuthState | undefined,
  transaction: OAuthStateTransaction,
): Promise<{
  config: oauth.Configuration;
  registration: RegisteredOAuthState;
}> {
  const reusableClientId =
    state !== undefined &&
    state.redirectUri === options.redirectUri.href &&
    typeof state.registrationScope === "string" &&
    sameScopes(state.registrationScope, options.scope)
      ? state.clientId
      : undefined;
  const clientId = options.clientId ?? reusableClientId;
  const metadata = clientMetadata(options);
  let config: oauth.Configuration;
  if (clientId) {
    try {
      config = await oauth.discovery(
        options.issuer,
        clientId,
        metadata,
        oauth.None(),
        requestOptions(options.issuer),
      );
    } catch {
      throw new Error("OAuth server discovery failed");
    }
  } else {
    // openid-client's DCR helper discovers metadata and immediately calls the
    // advertised registration endpoint. Preflight discovery lets us enforce
    // the issuer-origin trust boundary before that outbound request.
    let preflight: oauth.Configuration;
    try {
      preflight = await oauth.discovery(
        options.issuer,
        "glean-auth-preflight",
        metadata,
        oauth.None(),
        requestOptions(options.issuer),
      );
    } catch {
      throw new Error("OAuth server discovery failed");
    }
    assertOAuthCapabilities(preflight, options);
    if (!preflight.serverMetadata().registration_endpoint) {
      throw new Error(
        "The Glean OAuth server does not advertise dynamic client registration",
      );
    }
    try {
      config = await oauth.dynamicClientRegistration(
        options.issuer,
        metadata,
        oauth.None(),
        requestOptions(options.issuer),
      );
    } catch {
      throw new Error("OAuth client registration failed");
    }
  }
  assertOAuthCapabilities(config, options);

  const registeredClientId = config.clientMetadata().client_id;
  if (typeof registeredClientId !== "string" || registeredClientId === "") {
    throw new Error("OAuth client registration returned no client_id");
  }
  if (clientId !== undefined && registeredClientId !== clientId) {
    throw new Error("OAuth discovery returned an unexpected client_id");
  }

  const registration: RegisteredOAuthState = {
    clientId: registeredClientId,
    redirectUri: options.redirectUri.href,
    registrationScope: options.scope,
  };
  const registrationIsPersisted =
    state?.clientId === registration.clientId &&
    state.redirectUri === registration.redirectUri &&
    typeof state.registrationScope === "string" &&
    sameScopes(state.registrationScope, registration.registrationScope);
  if (!registrationIsPersisted) {
    await transaction.write(registration);
  }
  return { config, registration };
}

async function discoverClient(
  options: NormalizedOptions,
  clientId: string,
): Promise<oauth.Configuration> {
  let config: oauth.Configuration;
  try {
    config = await oauth.discovery(
      options.issuer,
      clientId,
      clientMetadata(options),
      oauth.None(),
      requestOptions(options.issuer),
    );
  } catch {
    throw new Error("OAuth server discovery failed");
  }
  assertOAuthCapabilities(config, options);
  return config;
}

function clientMetadata(
  options: NormalizedOptions,
): Partial<oauth.ClientMetadata> {
  return {
    client_name: options.clientName,
    redirect_uris: [options.redirectUri.href],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: options.scope,
  };
}

function requestOptions(issuer: URL): oauth.DiscoveryRequestOptions {
  const guardedFetch: oauth.CustomFetch = (url, options) => {
    let destination: URL;
    try {
      destination = new URL(url);
    } catch {
      return Promise.reject(invalidOAuthRequestUrl());
    }
    if (
      destination.protocol !== "https:" ||
      destination.origin !== issuer.origin ||
      destination.username !== "" ||
      destination.password !== ""
    ) {
      return Promise.reject(invalidOAuthRequestUrl());
    }
    return fetch(url, options);
  };

  return {
    algorithm: "oauth2",
    timeout: REQUEST_TIMEOUT_SECONDS,
    [oauth.customFetch]: guardedFetch,
  };
}

function invalidOAuthRequestUrl(): Error {
  return new Error(
    "OAuth requests must use a valid HTTPS URL on the canonical issuer origin",
  );
}

function assertOAuthCapabilities(
  config: oauth.Configuration,
  options: NormalizedOptions,
): void {
  const metadata = config.serverMetadata();
  for (const name of [
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
  ] as const) {
    const value = metadata[name];
    if (value === undefined) continue;

    let endpoint: URL;
    try {
      endpoint = new URL(value);
    } catch {
      throw invalidOAuthEndpoint(name);
    }
    if (
      endpoint.protocol !== "https:" ||
      endpoint.origin !== options.issuer.origin ||
      endpoint.username !== "" ||
      endpoint.password !== ""
    ) {
      throw invalidOAuthEndpoint(name);
    }
  }

  if (!metadata.supportsPKCE("S256")) {
    throw new Error("The Glean OAuth server must support PKCE with S256");
  }
}

function invalidOAuthEndpoint(name: string): Error {
  return new Error(
    `OAuth ${name} must be a valid HTTPS URL on the canonical issuer origin`,
  );
}

function stateWithTokens(
  state: RegisteredOAuthState,
  tokens: OAuthTokens,
  options: NormalizedOptions,
  requireRefreshToken: boolean,
): CompleteOAuthState {
  const expiresIn = tokens.expiresIn();
  if (
    expiresIn === undefined ||
    !Number.isFinite(expiresIn) ||
    expiresIn <= 0
  ) {
    throw new Error(
      "The OAuth token response did not include a valid expires_in",
    );
  }
  const expiresAt = Date.now() + expiresIn * 1000;
  if (!Number.isSafeInteger(expiresAt)) {
    throw new Error("The OAuth token expiry is outside the supported range");
  }

  const refreshToken = tokens.refresh_token ?? state.refreshToken;
  if (requireRefreshToken && !refreshToken) {
    throw new Error(
      "The OAuth server did not issue a refresh token for offline_access",
    );
  }
  const grantedScope = tokens.scope ?? state.grantedScope ?? options.scope;
  assertGrantedScopes(grantedScope, options.scopes);

  return {
    ...state,
    accessToken: tokens.access_token,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    expiresAt,
    grantedScope,
  };
}

async function authStatus(
  options: NormalizedOptions,
): Promise<GleanAuthStatus> {
  if (apiToken() !== undefined) {
    return {
      authenticated: true,
      source: "api-token",
      serverUrl: options.serverUrl,
      profile: options.profile,
      scopes: [...options.scopes],
    };
  }

  const state = await readState(options.stateKey, {
    stateDir: options.stateDir,
  });
  if (state === undefined) {
    return {
      authenticated: false,
      source: "none",
      serverUrl: options.serverUrl,
      profile: options.profile,
      scopes: [...options.scopes],
    };
  }

  const complete = isCompleteState(state);
  let scopesAreValid = false;
  if (complete) {
    try {
      assertGrantedScopes(state.grantedScope, options.scopes);
      scopesAreValid = true;
    } catch {
      // A narrowed or malformed grant is intentionally reported as unauthenticated.
    }
  }
  const clientMatches =
    options.clientId === undefined || state.clientId === options.clientId;
  const refreshable = nonBlankString(state.refreshToken);
  const expiresAt = state.expiresAt;
  return {
    authenticated:
      complete &&
      scopesAreValid &&
      clientMatches &&
      (state.expiresAt > Date.now() + EXPIRY_SKEW_MS || refreshable),
    source: "oauth",
    serverUrl: options.serverUrl,
    profile: options.profile,
    scopes: [...options.scopes],
    ...(expiresAt === undefined ? {} : { expiresAt }),
    refreshable,
  };
}

function normalizeOptions(options: GleanAuthOptions): NormalizedOptions {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("OAuth options must be an object");
  }
  const { serverUrl } = parseServerUrl(options.serverUrl);
  const issuer = new URL("/oauth", `${serverUrl}/`);
  const scopes = normalizeScopes([
    ...BASE_SCOPES,
    ...(options.scopes === undefined
      ? []
      : typeof options.scopes === "string"
        ? [options.scopes]
        : options.scopes),
  ]);
  const scope = scopes.join(" ");
  const clientName = nonEmpty(
    options.clientName ?? DEFAULT_CLIENT_NAME,
    "clientName",
  );
  const profile = nonEmpty(options.profile ?? DEFAULT_PROFILE, "profile");
  const clientId =
    options.clientId === undefined
      ? oauthClientIdFromEnvironment()
      : nonEmpty(options.clientId, "clientId");
  const callbackPort = options.callbackPort ?? DEFAULT_CALLBACK_PORT;
  if (
    !Number.isInteger(callbackPort) ||
    callbackPort < 1 ||
    callbackPort > 65_535
  ) {
    throw new TypeError("callbackPort must be an integer between 1 and 65535");
  }
  const timeout = options.timeout ?? DEFAULT_AUTHORIZATION_TIMEOUT;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new TypeError("timeout must be a positive number of milliseconds");
  }
  const redirectUri = new URL(
    `http://127.0.0.1:${String(callbackPort)}${OAUTH_CALLBACK_PATH}`,
  );
  const stateKey: OAuthStateKey = {
    profile,
    issuer: issuer.href,
    registrationScope: scope,
  };

  return {
    issuer,
    serverUrl,
    scopes,
    scope,
    clientName,
    clientId,
    profile,
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
    callbackPort,
    timeout,
    redirectUri,
    stateKey,
    flightKey: JSON.stringify({
      profile,
      issuer: issuer.href,
      registrationScope: [...scopes].sort().join(" "),
      stateDir: options.stateDir,
      clientId,
      redirectUri: redirectUri.href,
    }),
  };
}

function normalizeScopes(input: GleanScopeInput): string[] {
  const values = typeof input === "string" ? [input] : input;
  const scopes = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") {
      throw new TypeError("scopes must contain only strings");
    }
    for (const scope of value.trim().split(/\s+/u)) {
      if (scope !== "") scopes.add(scope);
    }
  }
  if (scopes.size === 0) {
    throw new TypeError("scopes must contain at least one scope");
  }
  return [...scopes];
}

function assertGrantedScopes(
  grantedScope: string,
  requestedScopes: readonly string[],
): void {
  const granted = new Set(normalizeScopes(grantedScope));
  const missing = requestedScopes.filter((scope) => !granted.has(scope));
  if (missing.length > 0) {
    throw new Error("The OAuth grant is missing a requested scope");
  }
}

function sameScopes(left: string, right: string): boolean {
  return (
    [...normalizeScopes(left)].sort().join(" ") ===
    [...normalizeScopes(right)].sort().join(" ")
  );
}

function assertCallbackUrl(
  callbackUrl: URL,
  redirectUri: URL,
  expectedState: string,
): void {
  if (
    callbackUrl.origin !== redirectUri.origin ||
    callbackUrl.username !== "" ||
    callbackUrl.password !== "" ||
    callbackUrl.pathname !== redirectUri.pathname ||
    callbackUrl.hash !== "" ||
    callbackUrl.searchParams.getAll("state").length !== 1 ||
    callbackUrl.searchParams.get("state") !== expectedState
  ) {
    throw new Error(
      "OAuth callback did not match the expected redirect or state",
    );
  }
  const codes = callbackUrl.searchParams.getAll("code");
  const errors = callbackUrl.searchParams.getAll("error");
  const hasCode = codes.length === 1 && codes[0] !== "" && errors.length === 0;
  const hasError =
    errors.length === 1 && errors[0] !== "" && codes.length === 0;
  if (!hasCode && !hasError) {
    throw new Error("OAuth callback must contain exactly one code or error");
  }
}

function isCompleteState(
  state: OAuthState | undefined,
): state is CompleteOAuthState {
  return (
    state !== undefined &&
    nonBlankString(state.clientId) &&
    nonBlankString(state.redirectUri) &&
    nonBlankString(state.registrationScope) &&
    nonBlankString(state.grantedScope) &&
    nonBlankString(state.accessToken) &&
    typeof state.expiresAt === "number"
  );
}

function registrationMatches(
  state: OAuthState | undefined,
  registration: RegisteredOAuthState,
): boolean {
  return (
    state !== undefined &&
    state.clientId === registration.clientId &&
    state.redirectUri === registration.redirectUri &&
    typeof state.registrationScope === "string" &&
    sameScopes(state.registrationScope, registration.registrationScope)
  );
}

function nonBlankString(value: string | undefined): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function apiToken(): string | undefined {
  const value = process.env.GLEAN_API_TOKEN?.trim();
  return value ? value : undefined;
}

function oauthClientIdFromEnvironment(): string | undefined {
  const value = process.env.GLEAN_OAUTH_CLIENT_ID?.trim();
  return value ? value : undefined;
}

function nonEmpty(value: string, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function signInRequired(): Error {
  return new Error("OAuth sign-in is required");
}
