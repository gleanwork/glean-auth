import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import lockfile from "proper-lockfile";

export type ScopeInput = string | readonly string[];

export interface OAuthStateKey {
  profile: string;
  issuer: string;
  registrationScope: ScopeInput;
}

export interface OAuthState {
  clientId?: string;
  redirectUri?: string;
  registrationScope?: string;
  grantedScope?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
}

export interface StateOptions {
  stateDir?: string;
}

export interface OAuthStateTransaction {
  read(): Promise<OAuthState | undefined>;
  write(state: OAuthState): Promise<void>;
  clear(): Promise<void>;
}

const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const MAX_STATE_BYTES = 1024 * 1024;
const LOCK_ACQUISITION_TIMEOUT_MS = 60_000;
const LOCK_MAX_RETRY_INTERVAL_MS = 250;
const STRING_STATE_FIELDS = [
  "clientId",
  "redirectUri",
  "registrationScope",
  "grantedScope",
  "accessToken",
  "refreshToken",
] as const;
const ALLOWED_STATE_FIELDS = new Set<string>([
  ...STRING_STATE_FIELDS,
  "expiresAt",
]);

function stateDirectory(configuredDirectory?: string): string {
  if (configuredDirectory !== undefined) {
    if (configuredDirectory.trim() === "") {
      throw new TypeError("stateDir must not be empty");
    }
    return resolve(configuredDirectory);
  }

  const xdgStateHome = process.env.XDG_STATE_HOME;
  if (
    xdgStateHome !== undefined &&
    xdgStateHome.trim() !== "" &&
    isAbsolute(xdgStateHome)
  ) {
    return resolve(xdgStateHome, "glean-auth");
  }

  return join(homedir(), ".local", "state", "glean-auth");
}

function canonicalScope(scope: ScopeInput): string {
  const input = typeof scope === "string" ? [scope] : scope;
  const scopes = new Set<string>();

  for (const value of input) {
    if (typeof value !== "string") {
      throw new TypeError("registrationScope must contain only strings");
    }
    for (const token of value.trim().split(/\s+/u)) {
      if (token !== "") scopes.add(token);
    }
  }

  if (scopes.size === 0) {
    throw new TypeError("registrationScope must contain at least one scope");
  }

  return [...scopes].sort().join(" ");
}

function normalizedKey(key: OAuthStateKey): {
  profile: string;
  issuer: string;
  registrationScope: string;
} {
  if (typeof key !== "object" || key === null) {
    throw new TypeError("state key must be an object");
  }
  if (typeof key.profile !== "string" || key.profile.trim() === "") {
    throw new TypeError("profile must be a non-empty string");
  }
  if (typeof key.issuer !== "string" || key.issuer.trim() === "") {
    throw new TypeError("issuer must be a non-empty string");
  }

  return {
    profile: key.profile,
    issuer: key.issuer,
    registrationScope: canonicalScope(key.registrationScope),
  };
}

function statePath(key: OAuthStateKey, options: StateOptions): string {
  const identity = normalizedKey(key);
  const digest = createHash("sha256")
    .update(JSON.stringify(identity))
    .digest("hex");
  return join(stateDirectory(options.stateDir), `${digest}.json`);
}

async function ensureStateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: DIRECTORY_MODE });

  const stats = await lstat(directory);
  if (stats.isSymbolicLink()) {
    throw new Error("Refusing to use a symbolic link as the state directory");
  }
  if (!stats.isDirectory()) {
    throw new Error("The OAuth state directory is not a directory");
  }

  // mkdir's mode is affected by existing directories and process umask.
  await chmod(directory, DIRECTORY_MODE);
}

async function assertSafeStateFile(path: string): Promise<void> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      throw new Error("Refusing to access a symbolic link state file");
    }
    if (!stats.isFile()) {
      throw new Error("The OAuth state path is not a regular file");
    }
  } catch (error: unknown) {
    if (isNodeError(error, "ENOENT")) return;
    throw error;
  }
}

function isNodeError(
  error: unknown,
  code: string,
): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function parseState(value: string, expectedScope: string): OAuthState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("OAuth state contains invalid JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("OAuth state must be a JSON object");
  }

  const record = parsed as Record<string, unknown>;
  for (const field of Object.keys(record)) {
    if (!ALLOWED_STATE_FIELDS.has(field)) {
      throw new Error("OAuth state contains an unknown field");
    }
  }
  for (const field of STRING_STATE_FIELDS) {
    if (field in record && typeof record[field] !== "string") {
      throw new Error("OAuth state contains a non-string string field");
    }
  }
  if (
    "expiresAt" in record &&
    (typeof record.expiresAt !== "number" ||
      !Number.isSafeInteger(record.expiresAt) ||
      record.expiresAt < 0)
  ) {
    throw new Error(
      "OAuth state field must be a non-negative safe integer: expiresAt",
    );
  }
  if (
    typeof record.registrationScope === "string" &&
    canonicalScope(record.registrationScope) !== expectedScope
  ) {
    throw new Error(
      "OAuth state registrationScope does not match its state key",
    );
  }

  return parsed;
}

function validateState(state: OAuthState, expectedScope: string): void {
  // Use the same strict validation for writes and reads. JSON serialization also
  // gives the validator an object with exactly the persisted representation.
  const serialized = JSON.stringify(state);
  if (serialized === undefined) {
    throw new TypeError("OAuth state is not serializable");
  }
  parseState(serialized, expectedScope);
}

async function withStateLock<T>(
  path: string,
  operation: () => Promise<T>,
): Promise<T> {
  const release = await lockfile.lock(path, {
    realpath: false,
    stale: 10_000,
    update: 2_000,
    retries: {
      retries: Math.ceil(
        LOCK_ACQUISITION_TIMEOUT_MS / LOCK_MAX_RETRY_INTERVAL_MS,
      ),
      factor: 1.5,
      minTimeout: 10,
      maxTimeout: LOCK_MAX_RETRY_INTERVAL_MS,
      randomize: true,
    },
  });

  try {
    // proper-lockfile uses a sibling directory. Tighten its mode while held.
    await chmod(`${path}.lock`, DIRECTORY_MODE);
    return await operation();
  } finally {
    await release();
  }
}

async function readStateFile(
  path: string,
  expectedScope: string,
): Promise<OAuthState | undefined> {
  await assertSafeStateFile(path);

  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error: unknown) {
    if (isNodeError(error, "ENOENT")) return undefined;
    if (isNodeError(error, "ELOOP")) {
      throw new Error("Refusing to access a symbolic link state file", {
        cause: error,
      });
    }
    throw error;
  }

  try {
    const stats = await file.stat();
    if (!stats.isFile()) {
      throw new Error("The OAuth state path is not a regular file");
    }
    await file.chmod(FILE_MODE);
    if (stats.size > MAX_STATE_BYTES) {
      throw new Error(`OAuth state exceeds ${MAX_STATE_BYTES} bytes`);
    }
    return parseState(await file.readFile("utf8"), expectedScope);
  } finally {
    await file.close();
  }
}

async function writeStateFile(path: string, state: OAuthState): Promise<void> {
  await assertSafeStateFile(path);

  const temporaryPath = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let file;

  try {
    file = await open(
      temporaryPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      FILE_MODE,
    );
    await file.writeFile(`${JSON.stringify(state)}\n`, "utf8");
    await file.sync();
    await file.close();
    file = undefined;

    // Re-check under the lock so an existing symlink is refused, not replaced.
    await assertSafeStateFile(path);
    await rename(temporaryPath, path);
    await chmod(path, FILE_MODE);
  } catch (error: unknown) {
    if (file !== undefined) await file.close().catch(() => undefined);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function clearStateFile(path: string): Promise<void> {
  await assertSafeStateFile(path);
  try {
    await rm(path);
  } catch (error: unknown) {
    if (!isNodeError(error, "ENOENT")) throw error;
  }
}

/**
 * Runs an operation while exclusively holding the lock for one state key.
 * The transaction is callback-scoped and must not be retained after the
 * callback settles.
 */
export async function withStateTransaction<T>(
  key: OAuthStateKey,
  operation: (transaction: OAuthStateTransaction) => Promise<T>,
  options: StateOptions = {},
): Promise<T> {
  const identity = normalizedKey(key);
  const path = statePath(key, options);
  await ensureStateDirectory(dirname(path));

  return withStateLock(path, async () => {
    let active = true;
    const assertActive = (): void => {
      if (!active) {
        throw new Error("OAuth state transaction is no longer active");
      }
    };
    const transaction: OAuthStateTransaction = {
      read: () => {
        assertActive();
        return readStateFile(path, identity.registrationScope);
      },
      write: (state) => {
        assertActive();
        validateState(state, identity.registrationScope);
        return writeStateFile(path, state);
      },
      clear: () => {
        assertActive();
        return clearStateFile(path);
      },
    };

    try {
      return await operation(transaction);
    } finally {
      active = false;
    }
  });
}

export async function readState(
  key: OAuthStateKey,
  options: StateOptions = {},
): Promise<OAuthState | undefined> {
  return withStateTransaction(
    key,
    (transaction) => transaction.read(),
    options,
  );
}

export async function writeState(
  key: OAuthStateKey,
  state: OAuthState,
  options: StateOptions = {},
): Promise<void> {
  await withStateTransaction(
    key,
    (transaction) => transaction.write(state),
    options,
  );
}

export async function clearState(
  key: OAuthStateKey,
  options: StateOptions = {},
): Promise<void> {
  await withStateTransaction(
    key,
    (transaction) => transaction.clear(),
    options,
  );
}
