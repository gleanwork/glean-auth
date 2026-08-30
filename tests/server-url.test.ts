import { describe, expect, it } from "vitest";
import { parseServerUrl } from "../src/server-url.js";

describe("parseServerUrl", () => {
  it.each([
    "https://acme-be.glean.com",
    "https://acme.glean.com",
    "https://acme.askscio.com",
    " HTTPS://ACME.GLEAN.COM/ ",
  ])("canonicalizes the trusted host form %s", (value) => {
    expect(parseServerUrl(value)).toEqual({
      serverUrl: "https://acme-be.glean.com",
      instance: "acme",
    });
  });

  it("supports hyphenated instance names", () => {
    expect(parseServerUrl("https://north-america.askscio.com")).toEqual({
      serverUrl: "https://north-america-be.glean.com",
      instance: "north-america",
    });
  });

  it.each([
    "https://app.glean.com",
    "https://glean.com",
    "https://askscio.com",
    "https://acme.glean.com.example.org",
    "https://acme-be.glean.com.example.org",
    "https://acme.askscio.com.example.org",
    "https://evilacme.glean.com.evil.test",
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
