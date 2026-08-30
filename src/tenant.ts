import { parseServerUrl, type GleanTenant } from "./server-url.js";

export const TENANT_DISCOVERY_URL = "https://app.glean.com/config/search";
export const TENANT_DISCOVERY_TIMEOUT_MS = 10_000;

const INVALID_EMAIL = "A valid email address is required for tenant discovery";
const DISCOVERY_FAILED = "Tenant discovery failed";
const DISCOVERY_TIMEOUT = "Tenant discovery timed out";
const INVALID_DISCOVERY_RESPONSE =
  "Tenant discovery returned an invalid response";

/** Normalize and validate an address before it is sent to tenant discovery. */
export function normalizeEmail(email: string): string {
  if (typeof email !== "string") throw new TypeError(INVALID_EMAIL);

  const normalized = email.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 254) {
    throw new TypeError(INVALID_EMAIL);
  }

  const separator = normalized.indexOf("@");
  if (separator <= 0 || separator !== normalized.lastIndexOf("@")) {
    throw new TypeError(INVALID_EMAIL);
  }

  const local = normalized.slice(0, separator);
  const domain = normalized.slice(separator + 1);
  if (
    local.length > 64 ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u.test(local) ||
    !isValidEmailDomain(domain)
  ) {
    throw new TypeError(INVALID_EMAIL);
  }

  return normalized;
}

/** Discover a customer's canonical Glean backend from their email address. */
export async function discoverGleanTenant(email: string): Promise<GleanTenant> {
  const normalizedEmail = normalizeEmail(email);
  const emailDomain = normalizedEmail.slice(normalizedEmail.indexOf("@") + 1);
  const controller = new AbortController();

  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new Error(DISCOVERY_TIMEOUT));
    }, TENANT_DISCOVERY_TIMEOUT_MS);
  });

  const request = async (): Promise<GleanTenant> => {
    let response: Response;
    try {
      response = await globalThis.fetch(TENANT_DISCOVERY_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: normalizedEmail,
          emailDomain,
          isGleanApp: true,
        }),
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) throw new Error(DISCOVERY_TIMEOUT);
      throw new Error(DISCOVERY_FAILED);
    }

    if (!response.ok) throw new Error(DISCOVERY_FAILED);

    let value: unknown;
    try {
      value = await response.json();
    } catch {
      throw new Error(INVALID_DISCOVERY_RESPONSE);
    }

    if (!isRecord(value) || !isRecord(value.search_config)) {
      throw new Error(INVALID_DISCOVERY_RESPONSE);
    }
    const queryUrl = value.search_config.queryURL;
    if (typeof queryUrl !== "string" || queryUrl.trim() === "") {
      throw new Error(INVALID_DISCOVERY_RESPONSE);
    }

    try {
      return parseServerUrl(queryUrl);
    } catch {
      throw new Error(INVALID_DISCOVERY_RESPONSE);
    }
  };

  try {
    return await Promise.race([request(), timeoutPromise]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function isValidEmailDomain(domain: string): boolean {
  if (domain.length === 0 || domain.length > 253 || !domain.includes(".")) {
    return false;
  }

  const labels = domain.split(".");
  if (
    labels.some(
      (label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label),
    )
  ) {
    return false;
  }

  return /^[a-z]{2,63}$/u.test(labels.at(-1) ?? "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
