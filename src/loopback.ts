import { createServer, type Server } from "node:http";
import open from "open";

export const DEFAULT_CALLBACK_PORT = 53_682;
export const OAUTH_CALLBACK_PATH = "/oauth/callback";
export const DEFAULT_AUTHORIZATION_TIMEOUT = 300_000;

export type OpenAuthorizationUrl = (url: string) => Promise<unknown>;

export interface LoopbackAuthorizationOptions {
  redirectUri: URL;
  timeout?: number;
  openUrl?: OpenAuthorizationUrl;
}

/**
 * Opens an authorization URL and waits for the exact OAuth redirect on a
 * loopback-only HTTP listener.
 */
export async function authorizeOnLoopback(
  authorizationUrl: URL,
  options: LoopbackAuthorizationOptions,
): Promise<URL> {
  const { redirectUri } = options;
  assertLoopbackRedirectUri(redirectUri);

  const expectedState = oneParameter(authorizationUrl, "state");
  if (expectedState === undefined || expectedState === "") {
    throw new Error("OAuth authorization URL is missing state");
  }

  const timeout = options.timeout ?? DEFAULT_AUTHORIZATION_TIMEOUT;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new TypeError("timeout must be a positive number of milliseconds");
  }

  let settleCallback: ((url: URL) => void) | undefined;
  let rejectCallback: ((error: Error) => void) | undefined;
  const callback = new Promise<URL>((resolve, reject) => {
    settleCallback = resolve;
    rejectCallback = reject;
  });

  const server = createServer((request, response) => {
    let requestUrl: URL;
    try {
      requestUrl = new URL(request.url ?? "/", redirectUri);
    } catch {
      response.writeHead(400).end();
      return;
    }

    if (
      request.method !== "GET" ||
      requestUrl.origin !== redirectUri.origin ||
      requestUrl.pathname !== redirectUri.pathname
    ) {
      response.writeHead(404).end();
      return;
    }

    const state = oneParameter(requestUrl, "state");
    const code = oneParameter(requestUrl, "code");
    const oauthError = oneParameter(requestUrl, "error");
    const validState = state !== undefined && state === expectedState;
    const validCode =
      code !== undefined && code !== "" && oauthError === undefined;
    const validError =
      oauthError !== undefined && oauthError !== "" && code === undefined;

    if (!validState || (!validCode && !validError)) {
      response.writeHead(400, responseHeaders());
      response.end("Invalid OAuth callback. You can close this tab.");
      return;
    }

    if (validError) {
      response.writeHead(400, responseHeaders());
      response.end("Authorization was not granted. Return to the terminal.");
    } else {
      response.writeHead(200, responseHeaders());
      response.end("Signed in. You can return to the terminal.");
    }
    settleCallback?.(requestUrl);
  });

  server.once("clientError", (_error, socket) => {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });

  await listen(server, redirectUri);
  const timer = setTimeout(() => {
    rejectCallback?.(new Error("Timed out waiting for Glean sign-in"));
  }, timeout);
  let active = true;
  const openUrl = options.openUrl ?? open;
  void Promise.resolve()
    .then(() => openUrl(authorizationUrl.href))
    .catch(() => {
      if (active) {
        console.error(
          `Unable to open a browser. Open this URL to continue:\n${authorizationUrl.href}`,
        );
      }
    });

  try {
    return await callback;
  } finally {
    active = false;
    clearTimeout(timer);
    await close(server);
  }
}

function oneParameter(url: URL, name: string): string | undefined {
  const values = url.searchParams.getAll(name);
  return values.length === 1 ? values[0] : undefined;
}

function assertLoopbackRedirectUri(redirectUri: URL): void {
  if (
    redirectUri.protocol !== "http:" ||
    redirectUri.hostname !== "127.0.0.1" ||
    redirectUri.username !== "" ||
    redirectUri.password !== "" ||
    redirectUri.pathname !== OAUTH_CALLBACK_PATH ||
    redirectUri.search !== "" ||
    redirectUri.hash !== "" ||
    redirectUri.port === ""
  ) {
    throw new TypeError(
      `redirectUri must be an http://127.0.0.1 callback at ${OAUTH_CALLBACK_PATH}`,
    );
  }
}

function responseHeaders(): Record<string, string> {
  return {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'",
    "X-Content-Type-Options": "nosniff",
  };
}

async function listen(server: Server, redirectUri: URL): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    server.once("listening", onListening);
    server.once("error", onError);
    server.listen(Number(redirectUri.port), redirectUri.hostname);
  });
}

async function close(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
