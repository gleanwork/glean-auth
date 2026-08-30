import { createGleanTokenProvider as createInternalTokenProvider } from "./oauth.js";
import type { GleanTenant } from "./server-url.js";
import { discoverGleanTenant as discoverTenant } from "./tenant.js";

export type { GleanTenant } from "./server-url.js";

export interface GleanTokenProviderOptions {
  serverUrl: string;
  scopes: readonly string[];
}

export function discoverGleanTenant(email: string): Promise<GleanTenant> {
  return discoverTenant(email);
}

export function createGleanTokenProvider(
  options: GleanTokenProviderOptions,
): () => Promise<string> {
  const provider = createInternalTokenProvider(options);
  return async () => {
    try {
      return await provider();
    } catch {
      throw new Error("Unable to obtain a Glean access token");
    }
  };
}
