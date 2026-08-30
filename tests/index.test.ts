import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  createGleanTokenProvider,
  discoverGleanTenant,
  type GleanTenant,
  type GleanTokenProviderOptions,
} from "../src/index.js";
import * as publicApi from "../src/index.js";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("public API", () => {
  it("exports only the two public functions at runtime", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "createGleanTokenProvider",
      "discoverGleanTenant",
    ]);
  });

  it("has the exact approved public type signatures", () => {
    expectTypeOf<GleanTenant>().toEqualTypeOf<{
      serverUrl: string;
      instance: string;
    }>();
    expectTypeOf<GleanTokenProviderOptions>().toEqualTypeOf<{
      serverUrl: string;
      scopes: readonly string[];
    }>();
    expectTypeOf(discoverGleanTenant).toEqualTypeOf<
      (email: string) => Promise<GleanTenant>
    >();
    expectTypeOf(createGleanTokenProvider).toEqualTypeOf<
      (options: GleanTokenProviderOptions) => () => Promise<string>
    >();
  });

  it("uses GLEAN_API_TOKEN through the public provider", async () => {
    vi.stubEnv("GLEAN_API_TOKEN", " public-api-token ");
    const provider = createGleanTokenProvider({
      serverUrl: "https://acme.glean.com",
      scopes: ["SEARCH"],
    });

    await expect(provider()).resolves.toBe("public-api-token");
  });
});
