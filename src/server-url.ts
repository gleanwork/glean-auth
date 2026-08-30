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
const GLEAN_HOST = new RegExp(`^(${INSTANCE_LABEL})\\.glean\\.com$`, "u");
const ASKSCIO_HOST = new RegExp(`^(${INSTANCE_LABEL})\\.askscio\\.com$`, "u");
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const RESERVED_INSTANCES = new Set(["app"]);
const INVALID_SERVER_URL =
  "The server URL must be a valid trusted Glean HTTPS origin";

/**
 * Parse a server origin and map all supported customer host forms to the
 * canonical Glean backend origin.
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
  if (options.allowLocalhost === true && LOOPBACK_HOSTS.has(hostname)) {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new TypeError(INVALID_SERVER_URL);
    }
    return {
      serverUrl: url.origin,
      instance: "localhost",
    };
  }

  if (url.protocol !== "https:" || url.port !== "") {
    throw new TypeError(INVALID_SERVER_URL);
  }

  const match =
    BACKEND_HOST.exec(hostname) ??
    GLEAN_HOST.exec(hostname) ??
    ASKSCIO_HOST.exec(hostname);
  const instance = match?.[1];
  if (instance === undefined || RESERVED_INSTANCES.has(instance)) {
    throw new TypeError(INVALID_SERVER_URL);
  }

  return {
    serverUrl: `https://${instance}-be.glean.com`,
    instance,
  };
}
