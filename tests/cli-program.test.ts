import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createGleanAuth: vi.fn(),
}));

vi.mock("../src/oauth.js", () => ({
  createGleanAuth: mocks.createGleanAuth,
}));

import { createProgram } from "../src/cli.js";

const auth = {
  login: vi.fn(),
  getAccessToken: vi.fn(),
  status: vi.fn(),
  logout: vi.fn(),
};

let stdout: string[];

beforeEach(() => {
  vi.resetAllMocks();
  stdout = [];
  mocks.createGleanAuth.mockReturnValue(auth);
  vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("glean-auth command actions", () => {
  it("renders a concise login lifecycle", async () => {
    auth.login.mockResolvedValue(undefined);

    await createProgram().parseAsync([
      "node",
      "glean-auth",
      "login",
      "--server-url",
      "https://acme-be.glean.com",
    ]);

    expect(stdout.join("")).toBe("Signing in to acme...\nSigned in to acme.\n");
    expect(auth.login).toHaveBeenCalledWith({ interactive: true });
  });

  it("preserves a safe actionable OAuth failure", async () => {
    auth.login.mockRejectedValue(new Error("OAuth server discovery failed"));

    await expect(
      createProgram().parseAsync([
        "node",
        "glean-auth",
        "login",
        "--server-url",
        "https://acme-be.glean.com",
      ]),
    ).rejects.toThrow("OAuth server discovery failed");

    expect(stdout.join("")).toBe("Signing in to acme...\n");
  });

  it("preserves status read failures without writing partial output", async () => {
    auth.status.mockRejectedValue(new Error("Unable to read OAuth state"));

    await expect(
      createProgram().parseAsync([
        "node",
        "glean-auth",
        "status",
        "--server-url",
        "https://acme-be.glean.com",
      ]),
    ).rejects.toThrow("Unable to read OAuth state");

    expect(stdout).toEqual([]);
  });

  it("adds login remediation to token retrieval failures", async () => {
    auth.getAccessToken.mockRejectedValue(
      new Error("OAuth token refresh failed"),
    );

    await expect(
      createProgram().parseAsync([
        "node",
        "glean-auth",
        "token",
        "--server-url",
        "https://acme-be.glean.com",
      ]),
    ).rejects.toThrow(
      "OAuth token refresh failed. Run glean-auth login before requesting a token.",
    );

    expect(stdout).toEqual([]);
  });

  it("renders concise logout output and preserves failures", async () => {
    auth.logout.mockResolvedValueOnce(undefined);
    await createProgram().parseAsync([
      "node",
      "glean-auth",
      "logout",
      "--server-url",
      "https://acme-be.glean.com",
    ]);
    expect(stdout.join("")).toBe("Signed out of acme.\n");

    stdout = [];
    auth.logout.mockRejectedValueOnce(
      new Error("Unable to remove OAuth state"),
    );
    await expect(
      createProgram().parseAsync([
        "node",
        "glean-auth",
        "logout",
        "--server-url",
        "https://acme-be.glean.com",
      ]),
    ).rejects.toThrow("Unable to remove OAuth state");
    expect(stdout).toEqual([]);
  });
});
