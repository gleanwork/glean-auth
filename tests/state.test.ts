import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearState,
  readState,
  withStateTransaction,
  writeState,
  type OAuthState,
  type OAuthStateKey,
  type OAuthStateTransaction,
} from "../src/state.js";

const KEY: OAuthStateKey = {
  profile: "default",
  issuer: "https://issuer.example.com",
  registrationScope: ["search", "openid"],
};

const AUTHENTICATED_STATE: OAuthState = {
  clientId: "client-id",
  redirectUri: "http://127.0.0.1/callback",
  registrationScope: "openid search",
  grantedScope: "search openid",
  accessToken: "access-token",
  refreshToken: "refresh-token",
  expiresAt: 1_900_000_000_000,
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function temporaryStateDirectory(): Promise<{
  root: string;
  stateDir: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "glean-auth-state-"));
  temporaryDirectories.push(root);
  return { root, stateDir: join(root, "state") };
}

async function stateFile(stateDir: string): Promise<string> {
  const names = (await readdir(stateDir)).filter((name) =>
    name.endsWith(".json"),
  );
  expect(names).toHaveLength(1);
  return join(stateDir, names[0] ?? "missing-state-file");
}

describe("OAuth state identity and lifecycle", () => {
  it("round-trips authenticated state using canonical registration scopes", async () => {
    const { stateDir } = await temporaryStateDirectory();

    await writeState(KEY, AUTHENTICATED_STATE, { stateDir });

    await expect(
      readState(
        {
          ...KEY,
          registrationScope: ["openid search", "search"],
        },
        { stateDir },
      ),
    ).resolves.toEqual(AUTHENTICATED_STATE);
  });

  it("preserves scope casing in state identity and deduplicates exact values only", async () => {
    const { stateDir } = await temporaryStateDirectory();
    const key: OAuthStateKey = {
      ...KEY,
      registrationScope: ["profile email", "profile"],
    };
    const state: OAuthState = {
      clientId: "client-id",
      registrationScope: "email profile",
    };

    await writeState(key, state, { stateDir });
    await expect(
      readState(
        { ...key, registrationScope: ["email", "profile", "email"] },
        { stateDir },
      ),
    ).resolves.toEqual(state);
    await expect(
      readState(
        { ...key, registrationScope: ["email", "Profile"] },
        { stateDir },
      ),
    ).resolves.toBeUndefined();
    await expect(
      writeState(key, { registrationScope: "email Profile" }, { stateDir }),
    ).rejects.toThrow("registrationScope does not match");
  });

  it("supports empty and partial pre-login registration state", async () => {
    const { stateDir } = await temporaryStateDirectory();

    await writeState(KEY, {}, { stateDir });
    await expect(readState(KEY, { stateDir })).resolves.toEqual({});

    const registrationState: OAuthState = {
      clientId: "registered-client",
      redirectUri: "http://127.0.0.1/callback",
      registrationScope: "search openid",
    };
    await writeState(KEY, registrationState, { stateDir });
    await expect(readState(KEY, { stateDir })).resolves.toEqual(
      registrationState,
    );
  });

  it("isolates state by profile, issuer, and canonical scope set", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, { clientId: "correct" }, { stateDir });

    await expect(
      readState({ ...KEY, profile: "other" }, { stateDir }),
    ).resolves.toBeUndefined();
    await expect(
      readState({ ...KEY, issuer: "https://other.example.com" }, { stateDir }),
    ).resolves.toBeUndefined();
    await expect(
      readState({ ...KEY, registrationScope: "openid" }, { stateDir }),
    ).resolves.toBeUndefined();
    await expect(
      readState(
        { ...KEY, registrationScope: "openid search search" },
        { stateDir },
      ),
    ).resolves.toEqual({ clientId: "correct" });
  });

  it("uses only a SHA-256 digest in the state filename", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, {}, { stateDir });

    const names = (await readdir(stateDir)).filter((name) =>
      name.endsWith(".json"),
    );
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^[a-f0-9]{64}\.json$/u);
    expect(names[0]).not.toContain(KEY.profile);
    expect(names[0]).not.toContain("issuer");
  });

  it("clears state and is idempotent when no state exists", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, { clientId: "client-id" }, { stateDir });

    await clearState(KEY, { stateDir });
    await expect(readState(KEY, { stateDir })).resolves.toBeUndefined();
    await expect(clearState(KEY, { stateDir })).resolves.toBeUndefined();
    expect(
      (await readdir(stateDir)).filter((name) => name.endsWith(".json")),
    ).toEqual([]);
  });

  it("holds one lock across a transaction and rejects escaped access", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, { accessToken: "initial" }, { stateDir });

    let releaseFirst!: () => void;
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let markFirstEntered!: () => void;
    const firstEntered = new Promise<void>((resolve) => {
      markFirstEntered = resolve;
    });
    let escapedTransaction: OAuthStateTransaction | undefined;

    const first = withStateTransaction(
      KEY,
      async (transaction) => {
        escapedTransaction = transaction;
        await expect(transaction.read()).resolves.toEqual({
          accessToken: "initial",
        });
        await transaction.write({ accessToken: "intermediate" });
        markFirstEntered();
        await firstCanFinish;
        await transaction.write({ accessToken: "rotated" });
      },
      { stateDir },
    );
    await firstEntered;

    let secondEntered = false;
    const second = withStateTransaction(
      KEY,
      async (transaction) => {
        secondEntered = true;
        return transaction.read();
      },
      { stateDir },
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(secondEntered).toBe(false);

    releaseFirst();
    await first;
    await expect(second).resolves.toEqual({ accessToken: "rotated" });
    expect(() => escapedTransaction?.read()).toThrow(
      "OAuth state transaction is no longer active",
    );
  });
});

describe("state directory selection", () => {
  it("uses an explicit stateDir in preference to XDG_STATE_HOME", async () => {
    const { root, stateDir } = await temporaryStateDirectory();
    const xdgDirectory = join(root, "xdg");
    vi.stubEnv("XDG_STATE_HOME", xdgDirectory);

    await writeState(KEY, {}, { stateDir });

    await expect(stat(await stateFile(stateDir))).resolves.toBeDefined();
    await expect(stat(join(xdgDirectory, "glean-auth"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("falls back to XDG_STATE_HOME/glean-auth", async () => {
    const { root } = await temporaryStateDirectory();
    const xdgDirectory = join(root, "xdg");
    vi.stubEnv("XDG_STATE_HOME", xdgDirectory);

    await writeState(KEY, {});

    await expect(
      readState(KEY, { stateDir: join(xdgDirectory, "glean-auth") }),
    ).resolves.toEqual({});
  });

  it("ignores a relative XDG_STATE_HOME instead of writing under cwd", async () => {
    const { root } = await temporaryStateDirectory();
    const cwd = join(root, "cwd");
    const home = join(root, "home");
    const originalCwd = process.cwd();
    await mkdir(cwd);
    vi.stubEnv("HOME", home);
    vi.stubEnv("XDG_STATE_HOME", "relative-state");

    try {
      process.chdir(cwd);
      await writeState(KEY, {});

      await expect(
        readState(KEY, {
          stateDir: join(home, ".local", "state", "glean-auth"),
        }),
      ).resolves.toEqual({});
      await expect(
        stat(join(cwd, "relative-state", "glean-auth")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("falls back to ~/.local/state/glean-auth when XDG_STATE_HOME is empty", async () => {
    const { root } = await temporaryStateDirectory();
    const home = join(root, "home");
    vi.stubEnv("HOME", home);
    vi.stubEnv("XDG_STATE_HOME", "");

    await writeState(KEY, {});

    await expect(
      readState(KEY, { stateDir: join(home, ".local", "state", "glean-auth") }),
    ).resolves.toEqual({});
  });

  it("rejects an empty configured stateDir", async () => {
    await expect(readState(KEY, { stateDir: "  " })).rejects.toThrow(
      "stateDir must not be empty",
    );
  });
});

describe("validation", () => {
  it.each([
    ["invalid JSON", "{", /invalid JSON/u],
    ["a non-object", "[]", /must be a JSON object/u],
    ["an unknown field", '{"unknown":true}', /unknown field/u],
    ["a non-string field", '{"clientId":42}', /non-string string field/u],
    ["a negative expiry", '{"expiresAt":-1}', /non-negative safe integer/u],
    ["a fractional expiry", '{"expiresAt":1.5}', /non-negative safe integer/u],
    [
      "a mismatched registration scope",
      '{"registrationScope":"other"}',
      /registrationScope does not match/u,
    ],
  ])(
    "rejects persisted state containing %s",
    async (_name, contents, message) => {
      const { stateDir } = await temporaryStateDirectory();
      await writeState(KEY, {}, { stateDir });
      await writeFile(await stateFile(stateDir), contents, "utf8");

      await expect(readState(KEY, { stateDir })).rejects.toThrow(message);
    },
  );

  it("applies the same strict validation before writing", async () => {
    const { stateDir } = await temporaryStateDirectory();

    await expect(
      writeState(KEY, { clientId: 42 } as unknown as OAuthState, { stateDir }),
    ).rejects.toThrow("non-string string field");
    await expect(
      writeState(KEY, { registrationScope: "different" }, { stateDir }),
    ).rejects.toThrow("registrationScope does not match");
    await expect(
      writeState(KEY, { extra: true } as unknown as OAuthState, { stateDir }),
    ).rejects.toThrow("unknown field");
  });

  it("rejects state files larger than one MiB", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, {}, { stateDir });
    await writeFile(
      await stateFile(stateDir),
      "x".repeat(1024 * 1024 + 1),
      "utf8",
    );

    await expect(readState(KEY, { stateDir })).rejects.toThrow(
      "exceeds 1048576 bytes",
    );
  });

  it.each([
    [{ ...KEY, profile: "" }, /profile must be a non-empty string/u],
    [{ ...KEY, issuer: " " }, /issuer must be a non-empty string/u],
    [{ ...KEY, registrationScope: [] }, /at least one scope/u],
  ])("rejects an invalid state key", async (key, message) => {
    const { stateDir } = await temporaryStateDirectory();
    await expect(readState(key, { stateDir })).rejects.toThrow(message);
  });
});

describe("filesystem safety", () => {
  it("enforces directory mode 0700 and file mode 0600", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await mkdir(stateDir, { mode: 0o777 });
    await writeState(KEY, {}, { stateDir });
    const path = await stateFile(stateDir);

    expect((await stat(stateDir)).mode & 0o777).toBe(0o700);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    await chmod(stateDir, 0o755);
    await chmod(path, 0o644);
    await readState(KEY, { stateDir });

    expect((await stat(stateDir)).mode & 0o777).toBe(0o700);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    await writeState(KEY, { clientId: "replacement" }, { stateDir });
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("refuses a symbolic link used as the state directory", async () => {
    const { root } = await temporaryStateDirectory();
    const target = join(root, "target");
    const stateDir = join(root, "linked-state");
    await mkdir(target);
    await symlink(target, stateDir);

    await expect(readState(KEY, { stateDir })).rejects.toThrow(
      "Refusing to use a symbolic link as the state directory",
    );
  });

  it("refuses to read, replace, or clear a symbolic link state file", async () => {
    const { root, stateDir } = await temporaryStateDirectory();
    await writeState(KEY, {}, { stateDir });
    const path = await stateFile(stateDir);
    const target = join(root, "target.json");
    await rm(path);
    await writeFile(target, "{}", "utf8");
    await symlink(target, path);

    await expect(readState(KEY, { stateDir })).rejects.toThrow(
      "Refusing to access a symbolic link state file",
    );
    await expect(writeState(KEY, {}, { stateDir })).rejects.toThrow(
      "Refusing to access a symbolic link state file",
    );
    await expect(clearState(KEY, { stateDir })).rejects.toThrow(
      "Refusing to access a symbolic link state file",
    );
    await expect(readFile(target, "utf8")).resolves.toBe("{}");
  });

  it("serializes concurrent operations without partial files or leftover locks", async () => {
    const { stateDir } = await temporaryStateDirectory();
    await writeState(KEY, { accessToken: "initial" }, { stateDir });
    const tokens = Array.from({ length: 24 }, (_, index) => `token-${index}`);

    await Promise.all(
      tokens.flatMap((accessToken) => [
        writeState(KEY, { accessToken }, { stateDir }),
        readState(KEY, { stateDir }),
      ]),
    );

    const result = await readState(KEY, { stateDir });
    expect(tokens).toContain(result?.accessToken);
    const names = await readdir(stateDir);
    expect(names.filter((name) => name.endsWith(".json"))).toHaveLength(1);
    expect(names.filter((name) => name.endsWith(".tmp"))).toEqual([]);
    expect(names.filter((name) => name.endsWith(".lock"))).toEqual([]);
  });
});
