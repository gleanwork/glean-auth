import { isIP } from "node:net";

export interface GleanTenant {
  serverUrl: string;
  instance: string;
}

export interface ParseServerUrlOptions {
  /** Allow loopback origins for isolated tests and local development. */
  allowLocalhost?: boolean;
}

const INSTANCE_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const BACKEND_HOST = new RegExp(`^(${INSTANCE_LABEL})-be\\.glean\\.com$`, "u");
const LEGACY_ASKSCIO_HOST = /(?:^|\.)askscio\.com$/u;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const RESERVED_HOSTS = new Set(["app.glean.com", "glean.com"]);
const INVALID_SERVER_URL =
  "The server URL must be a valid Glean backend HTTPS origin";

/**
 * Parse and preserve a complete Glean backend origin. Canonical Glean backend
 * hosts expose their tenant label; custom backend hosts use the hostname as
 * their display identity.
 */
export function parseServerUrl(
  value: string,
  options: ParseServerUrlOptions = {},
): GleanTenant {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(INVALID_SERVER_URL);
  }

  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new TypeError(INVALID_SERVER_URL);
  }

  if (
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw new TypeError(INVALID_SERVER_URL);
  }

  const hostname = url.hostname.toLowerCase();
  if (hostname.endsWith(".")) {
    throw new TypeError(INVALID_SERVER_URL);
  }
  if (LOOPBACK_HOSTS.has(hostname)) {
    if (
      options.allowLocalhost !== true ||
      (url.protocol !== "http:" && url.protocol !== "https:")
    ) {
      throw new TypeError(INVALID_SERVER_URL);
    }
    return {
      serverUrl: url.origin,
      instance: "localhost",
    };
  }

  const address = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (isIP(address) !== 0) {
    throw new TypeError(INVALID_SERVER_URL);
  }

  if (url.protocol !== "https:" || url.port !== "") {
    throw new TypeError(INVALID_SERVER_URL);
  }

  if (RESERVED_HOSTS.has(hostname) || LEGACY_ASKSCIO_HOST.test(hostname)) {
    throw new TypeError(INVALID_SERVER_URL);
  }

  return {
    serverUrl: url.origin,
    instance: BACKEND_HOST.exec(hostname)?.[1] ?? hostname,
  };
}
