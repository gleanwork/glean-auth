#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { Command } from "commander";
import {
  createGleanAuth,
  type GleanAuthOptions,
  type GleanAuthStatus,
} from "./oauth.js";
import { parseServerUrl, type GleanTenant } from "./server-url.js";
import { discoverGleanTenant } from "./tenant.js";

interface CommonOptions {
  email?: string;
  serverUrl?: string;
  scopes?: string[];
}

interface PackageMetadata {
  version: string;
}

const PACKAGE_VERSION = packageMetadata().version;

export function createProgram(): Command {
  const program = new Command();

  program
    .name("glean-auth")
    .description("Authenticate developer tools with Glean")
    .version(PACKAGE_VERSION)
    .addHelpCommand(false)
    .showHelpAfterError()
    .configureHelp({ showGlobalOptions: true, sortOptions: true })
    .option("--email <email>", "discover the Glean tenant for an email address")
    .option("--server-url <url>", "use an explicit Glean server URL")
    .option(
      "--scopes <scopes>",
      "OAuth scopes (comma-separated or repeatable)",
      parseScopes,
    );

  const loginCommand = program
    .command("login")
    .description("sign in and save OAuth credentials")
    .action(async () => {
      const options = loginCommand.optsWithGlobals<CommonOptions>();
      const tenant = await resolveFromOptions(options);
      const auth = createGleanAuth(authOptions(tenant, options));
      process.stdout.write(`Signing in to ${tenant.instance}...\n`);
      await auth.login({ interactive: true });
      process.stdout.write(`Signed in to ${tenant.instance}.\n`);
    });

  const statusCommand = program
    .command("status")
    .description("show authentication status without revealing credentials")
    .option("--json", "print machine-readable JSON")
    .action(async () => {
      const options = statusCommand.optsWithGlobals<CommonOptions>();
      const statusOptions = statusCommand.opts<{ json?: boolean }>();
      let tenant: GleanTenant;
      try {
        tenant = await resolveFromOptions(options);
      } catch (error) {
        if (!isMissingTenantError(error)) throw error;
        printStatus(
          { configured: false, authenticated: false },
          Boolean(statusOptions.json),
        );
        return;
      }

      const auth = createGleanAuth(authOptions(tenant, options));
      const status: GleanAuthStatus = await auth.status();
      printStatus(
        {
          configured: true,
          instance: tenant.instance,
          ...safeStatus(status),
        },
        Boolean(statusOptions.json),
      );
    });

  const tokenCommand = program
    .command("token")
    .description("print the current access token")
    .action(async () => {
      const options = tokenCommand.optsWithGlobals<CommonOptions>();
      const tenant = await resolveFromOptions(options);
      const auth = createGleanAuth(authOptions(tenant, options));

      let token: string;
      try {
        token = await auth.getAccessToken();
      } catch (error: unknown) {
        throw new Error(
          `${errorMessage(error, "Credentials unavailable")}. ` +
            "Run glean-auth login before requesting a token.",
          { cause: error },
        );
      }
      process.stdout.write(`${token}\n`);
    });

  const logoutCommand = program
    .command("logout")
    .description("remove saved OAuth credentials")
    .action(async () => {
      const options = logoutCommand.optsWithGlobals<CommonOptions>();
      const tenant = await resolveFromOptions(options);
      const auth = createGleanAuth(authOptions(tenant, options));
      await auth.logout();
      process.stdout.write(`Signed out of ${tenant.instance}.\n`);
    });

  return program;
}

export async function run(
  argv: readonly string[] = process.argv,
): Promise<void> {
  const program = createProgram();
  if (argv.length <= 2) {
    program.outputHelp();
    return;
  }
  await program.parseAsync([...argv]);
}

async function resolveFromOptions(
  options: CommonOptions,
): Promise<GleanTenant> {
  if (options.serverUrl) return parseServerUrl(options.serverUrl);
  if (options.email) return discoverGleanTenant(options.email);
  if (process.env.GLEAN_SERVER_URL) {
    return parseServerUrl(process.env.GLEAN_SERVER_URL);
  }
  throw new Error(
    "No Glean tenant configured. Pass --server-url or --email, or set GLEAN_SERVER_URL.",
  );
}

function parseScopes(value: string, previous: string[] = []): string[] {
  const scopes = value
    .split(",")
    .map((scope) => scope.trim())
    .filter(Boolean);
  return [...new Set([...previous, ...scopes])];
}

function authOptions(
  tenant: GleanTenant,
  options: CommonOptions,
): GleanAuthOptions {
  return {
    serverUrl: tenant.serverUrl,
    scopes: options.scopes ?? [],
  };
}

function safeStatus(status: GleanAuthStatus): Record<string, unknown> {
  return {
    authenticated: status.authenticated,
    source: status.source,
    serverUrl: status.serverUrl,
    scopes: [...status.scopes],
    ...(status.expiresAt === undefined ? {} : { expiresAt: status.expiresAt }),
    ...(status.refreshable === undefined
      ? {}
      : { refreshable: status.refreshable }),
  };
}

function printStatus(status: Record<string, unknown>, json: boolean): void {
  if (json) {
    process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
    return;
  }

  const configured = status.configured === true;
  const authenticated = status.authenticated === true;
  process.stdout.write(`Configured: ${configured ? "yes" : "no"}\n`);
  if (configured && typeof status.instance === "string") {
    process.stdout.write(`Instance: ${status.instance}\n`);
  }
  process.stdout.write(`Authenticated: ${authenticated ? "yes" : "no"}\n`);
}

function isMissingTenantError(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.message ===
      "No Glean tenant configured. Pass --server-url or --email, or set GLEAN_SERVER_URL."
  );
}

function packageMetadata(): PackageMetadata {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as unknown;
  } catch {
    throw new Error("Unable to read package metadata");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("version" in parsed) ||
    typeof parsed.version !== "string" ||
    parsed.version === ""
  ) {
    throw new Error("Package metadata does not contain a valid version");
  }
  return { version: parsed.version };
}

const invokedPath = process.argv[1];
if (isEntrypoint(invokedPath)) {
  run().catch((error: unknown) => {
    const message =
      error instanceof Error ? error.message : "glean-auth failed";
    process.stderr.write(`Error: ${redactMessage(message)}\n`);
    process.exitCode = 1;
  });
}

function isEntrypoint(invokedPath: string | undefined): boolean {
  if (!invokedPath) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(invokedPath)).href;
  } catch {
    return false;
  }
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim() !== "") {
    return error.message.replace(/[.]+$/u, "");
  }
  return fallback;
}

function redactMessage(message: string): string {
  return message
    .replace(/(?:Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, "Bearer [redacted]")
    .replace(
      /((?:access[_-]?token|api[_-]?token|credential|secret)\s*[=:]\s*)\S+/giu,
      "$1[redacted]",
    );
}
