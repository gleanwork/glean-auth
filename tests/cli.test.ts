import { execFileSync } from "node:child_process";
import { readFileSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createBintastic, type BintasticProject } from "bintastic";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const { setupProject, teardownProject, runBin } = createBintastic({
  importMeta: import.meta,
  binPath: "../dist/cli.js",
});

const packageMetadata = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version: string };

let project: BintasticProject;

beforeEach(async () => {
  project = await setupProject();
  await project.write();
});

afterEach(() => {
  teardownProject();
});

describe("built glean-auth CLI", () => {
  it("runs through an installed package bin symlink", () => {
    const linkedBin = join(project.baseDir, "glean-auth");
    symlinkSync(
      fileURLToPath(new URL("../dist/cli.js", import.meta.url)),
      linkedBin,
    );

    expect(execFileSync(linkedBin, ["--version"], { encoding: "utf8" })).toBe(
      `${packageMetadata.version}\n`,
    );
  });

  it("prints the four-command help surface", async () => {
    const result = await runBin("--help", runOptions());

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Usage: glean-auth [options] [command]");
    for (const command of ["login", "status", "token", "logout"]) {
      expect(result.stdout).toMatch(new RegExp(`\\b${command}\\b`, "u"));
    }
    for (const removed of [
      "exec",
      "configure",
      "clear",
      "--profile",
      "--state-dir",
      "--env-file",
      "--login-if-needed",
    ]) {
      expect(result.stdout).not.toContain(removed);
    }
  });

  it("prints help and exits zero with no arguments", async () => {
    const result = await runBin(runOptions());

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Usage: glean-auth [options] [command]");
  });

  it("shows shared tenant and scope options in command help", async () => {
    const result = await runBin("login", "--help", runOptions());

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Global Options:");
    expect(result.stdout).toContain("--email <email>");
    expect(result.stdout).toContain("--server-url <url>");
    expect(result.stdout).toContain("--scopes <scopes>");
  });

  it("prints the package version", async () => {
    const result = await runBin("--version", runOptions());

    expect(result.exitCode).toBe(0);
    expect(outputText(result.stdout).trim()).toBe(packageMetadata.version);
  });

  it("rejects an unknown command", async () => {
    const result = await runBin("configure", runOptions());

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("unknown command");
  });

  it("reports unauthenticated JSON without configuration", async () => {
    const result = await runBin("status", "--json", runOptions());

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(outputText(result.stdout))).toEqual({
      configured: false,
      authenticated: false,
    });
  });

  it("reports API-token authentication without printing the token", async () => {
    const secret = "api-token-that-must-not-be-rendered";
    const result = await runBin(
      "--server-url",
      "https://acme.glean.com",
      "--scopes",
      "SEARCH",
      "status",
      "--json",
      runOptions({ GLEAN_API_TOKEN: secret }),
    );

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(outputText(result.stdout))).toMatchObject({
      configured: true,
      authenticated: true,
      source: "api-token",
      serverUrl: "https://acme-be.glean.com",
      instance: "acme",
      scopes: ["openid", "offline_access", "SEARCH"],
    });
    expect(outputText(result.stdout) + outputText(result.stderr)).not.toContain(
      secret,
    );
  });

  it("prints only the current token and a newline", async () => {
    const secret = "token-command-secret";
    const result = await runBin(
      "token",
      "--server-url",
      "https://acme.glean.com",
      "--scopes",
      "SEARCH",
      {
        ...runOptions({ GLEAN_API_TOKEN: secret }),
        stripFinalNewline: false,
      },
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe(`${secret}\n`);
    expect(result.stderr).toBe("");
  });

  it("keeps token retrieval noninteractive", async () => {
    const result = await runBin(
      "token",
      "--server-url",
      "https://acme.glean.com",
      "--scopes",
      "SEARCH",
      runOptions(),
    );

    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Run glean-auth login");
  });

  it("logs out using isolated XDG state", async () => {
    const result = await runBin(
      "--server-url",
      "https://acme.glean.com",
      "logout",
      runOptions(),
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("Signed out of acme.");
    expect(outputText(result.stdout) + outputText(result.stderr)).not.toMatch(
      /token|secret/iu,
    );
  });
});

function outputText(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("Expected CLI output to be text");
  }
  return value;
}

function runOptions(extraEnv: NodeJS.ProcessEnv = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: join(project.baseDir, "home"),
    XDG_STATE_HOME: join(project.baseDir, "state"),
    ...extraEnv,
  };
  delete env.GLEAN_API_TOKEN;
  delete env.GLEAN_OAUTH_CLIENT_ID;
  delete env.GLEAN_SERVER_URL;
  delete env.GLEAN_INSTANCE;
  Object.assign(env, extraEnv);

  return {
    cwd: project.baseDir,
    env,
    reject: false,
  };
}
