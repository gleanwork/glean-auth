import { afterEach, describe, expect, it, vi } from "vitest";
import {
  discoverGleanTenant,
  normalizeEmail,
  TENANT_DISCOVERY_TIMEOUT_MS,
  TENANT_DISCOVERY_URL,
} from "../src/tenant.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("normalizeEmail", () => {
  it("trims and lowercases a valid email address", () => {
    expect(normalizeEmail("  Person+Auth@Example.COM ")).toBe(
      "person+auth@example.com",
    );
  });

  it.each([
    "",
    "not-an-email",
    "@example.com",
    "person@",
    "person@@example.com",
    ".person@example.com",
    "person..name@example.com",
    "person@example",
    "person@-example.com",
    "person@example.com.evil-",
    "person name@example.com",
  ])("rejects malformed caller input without echoing it: %s", (email) => {
    let thrown: unknown;
    try {
      normalizeEmail(email);
    } catch (error: unknown) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(TypeError);
    if (email !== "") expect((thrown as Error).message).not.toContain(email);
  });
});

describe("discoverGleanTenant", () => {
  it("posts the normalized discovery payload to the fixed endpoint", async () => {
    const transport = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({
        search_config: { queryURL: "https://customer-be.glean.com/" },
      }),
    );
    vi.stubGlobal("fetch", transport);

    await expect(discoverGleanTenant(" Person@Example.COM ")).resolves.toEqual({
      serverUrl: "https://customer-be.glean.com",
      instance: "customer",
    });

    expect(transport).toHaveBeenCalledTimes(1);
    const [url, init] = transport.mock.calls[0] ?? [];
    expect(url).toBe(TENANT_DISCOVERY_URL);
    expect(init).toMatchObject({
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "person@example.com",
        emailDomain: "example.com",
        isGleanApp: true,
      }),
    });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([
    ["https://customer-be.glean.com", "customer"],
    ["https://customer.glean.com", "customer.glean.com"],
    ["https://search.example.com", "search.example.com"],
  ])("accepts trusted queryURL %s", async (queryURL, instance) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse({ search_config: { queryURL } })),
    );

    await expect(discoverGleanTenant("person@example.com")).resolves.toEqual({
      serverUrl: queryURL,
      instance,
    });
  });

  it.each([
    "https://app.glean.com",
    "https://customer.askscio.com",
    "not a URL",
  ])("sanitizes an invalid discovered queryURL: %s", async (queryURL) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse({ search_config: { queryURL } })),
    );

    const error = await discoverGleanTenant("person@example.com").catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(TypeError);
    expect((error as Error).message).toBe(
      "Tenant discovery returned an invalid response",
    );
    expect((error as Error).message).not.toContain(queryURL);
  });

  it.each([
    null,
    {},
    { search_config: null },
    { search_config: {} },
    { search_config: { queryURL: 42 } },
  ])("rejects an invalid discovery response: %j", async (payload) => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(payload)),
    );

    await expect(discoverGleanTenant("person@example.com")).rejects.toThrow(
      "Tenant discovery returned an invalid response",
    );
  });

  it("rejects invalid JSON as an invalid discovery response", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response("{", { status: 200 })),
    );

    await expect(discoverGleanTenant("person@example.com")).rejects.toThrow(
      "Tenant discovery returned an invalid response",
    );
  });

  it("returns a sanitized HTTP failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response("private upstream body", { status: 503 }),
        ),
    );

    const error = await discoverGleanTenant("person@example.com").catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("Tenant discovery failed");
    expect((error as Error).message).not.toContain("private upstream body");
    expect(error).not.toHaveProperty("status");
    expect(error).not.toHaveProperty("cause");
  });

  it("does not expose transport error details", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockRejectedValue(new Error("request included a private value")),
    );

    const error = await discoverGleanTenant("person@example.com").catch(
      (caught: unknown) => caught,
    );
    expect((error as Error).message).toBe("Tenant discovery failed");
    expect((error as Error).message).not.toContain("private value");
    expect(error).not.toHaveProperty("cause");
  });

  it("aborts and fails after exactly ten seconds", async () => {
    vi.useFakeTimers();
    const captured: { signal?: AbortSignal } = {};
    const transport = vi.fn<typeof fetch>((_input, init) => {
      captured.signal = init?.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    });
    vi.stubGlobal("fetch", transport);

    const discovery = discoverGleanTenant("person@example.com");
    const rejection = expect(discovery).rejects.toThrow(
      "Tenant discovery timed out",
    );

    await vi.advanceTimersByTimeAsync(TENANT_DISCOVERY_TIMEOUT_MS - 1);
    expect(captured.signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await rejection;
    expect(captured.signal?.aborted).toBe(true);
  });

  it("does not call discovery for an invalid email", async () => {
    const transport = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", transport);

    await expect(discoverGleanTenant("not-an-email")).rejects.toBeInstanceOf(
      TypeError,
    );
    expect(transport).not.toHaveBeenCalled();
  });

  it("restores the native fetch after tests", () => {
    expect(originalFetch).toBeTypeOf("function");
  });
});

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
