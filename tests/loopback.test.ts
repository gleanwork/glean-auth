import { once } from "node:events";
import { createServer } from "node:http";
import { describe, expect, it, vi } from "vitest";
import { authorizeOnLoopback } from "../src/loopback.js";

async function availablePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Test server did not bind to a TCP port");
  }
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

describe("authorizeOnLoopback", () => {
  it("accepts only the exact method, path, state, and one code", async () => {
    const port = await availablePort();
    const redirectUri = new URL(
      `http://127.0.0.1:${String(port)}/oauth/callback`,
    );
    const authorizationUrl = new URL(
      "https://acme-be.glean.com/oauth/authorize",
    );
    authorizationUrl.searchParams.set("state", "expected-state");
    const openUrl = vi.fn(async () => {
      await expect(
        fetch(`${redirectUri.href}?code=code&state=expected-state`, {
          method: "POST",
        }),
      ).resolves.toMatchObject({ status: 404 });
      await expect(
        fetch(
          `http://127.0.0.1:${String(port)}/wrong?code=code&state=expected-state`,
        ),
      ).resolves.toMatchObject({ status: 404 });
      await expect(
        fetch(`${redirectUri.href}?code=code&state=wrong-state`),
      ).resolves.toMatchObject({ status: 400 });
      await expect(
        fetch(
          `${redirectUri.href}?code=first&code=second&state=expected-state`,
        ),
      ).resolves.toMatchObject({ status: 400 });
      await expect(
        fetch(`${redirectUri.href}?code=accepted&state=expected-state`),
      ).resolves.toMatchObject({ status: 200 });
    });

    await expect(
      authorizeOnLoopback(authorizationUrl, {
        redirectUri,
        timeout: 2_000,
        openUrl,
      }),
    ).resolves.toEqual(
      new URL(`${redirectUri.href}?code=accepted&state=expected-state`),
    );
    expect(openUrl).toHaveBeenCalledWith(authorizationUrl.href);
  });

  it("returns a state-bound OAuth error callback for protocol handling", async () => {
    const port = await availablePort();
    const redirectUri = new URL(
      `http://127.0.0.1:${String(port)}/oauth/callback`,
    );
    const authorizationUrl = new URL(
      "https://acme-be.glean.com/oauth/authorize?state=expected-state",
    );

    const result = await authorizeOnLoopback(authorizationUrl, {
      redirectUri,
      timeout: 2_000,
      openUrl: async () => {
        const response = await fetch(
          `${redirectUri.href}?error=access_denied&error_description=Denied&state=expected-state`,
        );
        expect(response.status).toBe(400);
      },
    });

    expect(result.searchParams.get("error")).toBe("access_denied");
    expect(result.searchParams.get("state")).toBe("expected-state");
  });

  it("prints a handoff URL when browser launch fails", async () => {
    const port = await availablePort();
    const redirectUri = new URL(
      `http://127.0.0.1:${String(port)}/oauth/callback`,
    );
    const authorizationUrl = new URL(
      "https://acme-be.glean.com/oauth/authorize?state=expected-state",
    );
    const error = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);

    const result = await authorizeOnLoopback(authorizationUrl, {
      redirectUri,
      timeout: 2_000,
      openUrl: () => {
        setTimeout(() => {
          void fetch(`${redirectUri.href}?code=accepted&state=expected-state`);
        }, 0);
        return Promise.reject(new Error("no browser"));
      },
    });

    expect(result.searchParams.get("code")).toBe("accepted");
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining(authorizationUrl.href),
    );
    error.mockRestore();
  });

  it("times out a never-settling browser launch and closes the listener", async () => {
    const port = await availablePort();
    const redirectUri = new URL(
      `http://127.0.0.1:${String(port)}/oauth/callback`,
    );
    const authorizationUrl = new URL(
      "https://acme-be.glean.com/oauth/authorize?state=expected-state",
    );

    await expect(
      authorizeOnLoopback(authorizationUrl, {
        redirectUri,
        timeout: 10,
        openUrl: () => new Promise(() => undefined),
      }),
    ).rejects.toThrow("Timed out waiting for Glean sign-in");

    const replacement = createServer();
    replacement.listen(port, "127.0.0.1");
    await expect(once(replacement, "listening")).resolves.toBeDefined();
    await new Promise<void>((resolve) => replacement.close(() => resolve()));
  });

  it("rejects authorization URLs without exactly one state", async () => {
    const port = await availablePort();
    const redirectUri = new URL(
      `http://127.0.0.1:${String(port)}/oauth/callback`,
    );

    await expect(
      authorizeOnLoopback(
        new URL("https://acme-be.glean.com/oauth/authorize?state=a&state=b"),
        { redirectUri, openUrl: vi.fn() },
      ),
    ).rejects.toThrow("missing state");
  });
});
