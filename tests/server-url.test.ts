import { describe, expect, it } from "vitest";
import { parseServerUrl } from "../src/server-url.js";

describe("parseServerUrl", () => {
  it.each(["https://acme-be.glean.com", " HTTPS://ACME-BE.GLEAN.COM/ "])(
    "preserves the canonical backend origin %s",
    (value) => {
      expect(parseServerUrl(value)).toEqual({
        serverUrl: "https://acme-be.glean.com",
        instance: "acme",
      });
    },
  );

  it.each([
    ["https://acmecorp-pl.glean.com", "acmecorp-pl.glean.com"],
    [" HTTPS://SEARCH.EXAMPLE.COM/ ", "search.example.com"],
  ])("preserves the custom backend origin %s", (value, instance) => {
    expect(parseServerUrl(value)).toEqual({
      serverUrl: new URL(value.trim()).origin,
      instance,
    });
  });

  it.each([
    "https://app.glean.com",
    "https://glean.com",
    "https://askscio.com",
    "https://acme.askscio.com",
    "https://north-america.askscio.com",
    "https://app.glean.com.",
    "https://acme.askscio.com.",
    "https://acme-be.glean.com.",
    "https://localhost",
    "https://127.0.0.1",
    "https://127.0.0.2",
    "https://127.255.255.254",
    "https://192.168.1.10",
    "https://[::1]",
    "https://[::ffff:127.0.0.1]",
    "acme.glean.com",
    "http://acme.glean.com",
    "ftp://acme.glean.com",
    "https://user@acme.glean.com",
    "https://acme.glean.com/path",
    "https://acme.glean.com?redirect=https://evil.test",
    "https://acme.glean.com#fragment",
    "https://acme.glean.com:8443",
    "",
  ])("rejects invalid caller input without echoing it: %s", (value) => {
    let thrown: unknown;
    try {
      parseServerUrl(value);
    } catch (error: unknown) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    if (value !== "") expect((thrown as Error).message).not.toContain(value);
  });

  it("allows loopback origins only when explicitly enabled", () => {
    expect(() => parseServerUrl("http://localhost:4317")).toThrow(TypeError);
    expect(
      parseServerUrl("http://localhost:4317/", { allowLocalhost: true }),
    ).toEqual({ serverUrl: "http://localhost:4317", instance: "localhost" });
    expect(
      parseServerUrl("http://127.0.0.1:4317", { allowLocalhost: true }),
    ).toEqual({ serverUrl: "http://127.0.0.1:4317", instance: "localhost" });
    expect(
      parseServerUrl("http://[::1]:4317", { allowLocalhost: true }),
    ).toEqual({ serverUrl: "http://[::1]:4317", instance: "localhost" });
  });

  it("does not let localhost mode permit arbitrary HTTP hosts", () => {
    expect(() =>
      parseServerUrl("http://acme.glean.com", { allowLocalhost: true }),
    ).toThrow(TypeError);
  });
});
