/**
 * The programmatic API.
 *
 * Designed from the outside in, as though written by the third party developer who
 * has to use it rather than by the person who wrote the internals. The faculties
 * are all individually importable, but almost nobody wants to assemble a
 * transport, a client, a capture and a grader by hand just to answer "is this
 * server still what I approved".
 *
 * ## Cancellation and progress
 *
 * Every operation that can take longer than an instant accepts an `AbortSignal`
 * and an optional progress callback. Cancellation is distinguished from a timeout
 * throughout: a `CancellationError` means the caller changed their mind, a
 * `TimeoutError` means this package gave up. A host embedding this is going to
 * report those differently.
 *
 * ## Resource safety
 *
 * `dispose` is idempotent and using a session after disposal throws a typed error
 * rather than hanging or silently doing nothing. Child processes are killed as a
 * tree, so nothing is left running.
 */

import { grade, type ConformanceReport } from './conformance/index.js';
import { TransportError } from './core/errors.js';
import { NOOP_LOGGER, type Logger } from './core/logger.js';
import type {
  DriftReport,
  LedgerEntry,
  ServerRef,
  ServerSurface,
  TrustPin,
} from './core/types.js';
import { discover, type DiscoveryOptions, type Inventory } from './discovery/index.js';
import { Ledger } from './ledger/index.js';
import { analyzeMigration, type AnalyzeOptions, type MigrationReport } from './migration/index.js';
import { checkPolicy, type PolicyInput, type PolicyResult } from './policy/index.js';
import type { Policy } from './core/types.js';
import { McpClient, type CaptureProgress, type CaptureResult } from './protocol/client.js';
import { HttpTransport } from './protocol/http-transport.js';
import { StdioTransport } from './protocol/stdio-transport.js';
import { createPin, diffAgainstPin, diffSurfaces, type DiffOptions } from './trust/index.js';

/** Options shared by every operation that talks to a server. */
export interface OperationOptions {
  /** Cancel the operation. Distinct from a timeout throughout. */
  readonly signal?: AbortSignal;
  /** Per request time budget in milliseconds. Defaults to 30000. */
  readonly timeoutMs?: number;
  readonly logger?: Logger;
  /** Called as each stage of a capture completes. */
  readonly onProgress?: (event: CaptureProgress) => void;
  /**
   * Environment variables to pass to a stdio server.
   *
   * Only what is named here reaches the child. The library never hands a server
   * the host process's whole environment, because that would leak every
   * credential the host happens to hold into a program it did not write.
   */
  readonly env?: Readonly<Record<string, string>>;
}

/**
 * A live connection to one server.
 *
 * Hold one of these to capture repeatedly without paying to start the server each
 * time. Always `dispose` it, ideally in a `finally`.
 */
export class ServerSession {
  private disposed = false;

  private constructor(
    private readonly client: McpClient,
    readonly server: ServerRef,
  ) {}

  /** Open a session against a server reference. */
  static open(server: ServerRef, options: OperationOptions = {}): ServerSession {
    const logger = options.logger ?? NOOP_LOGGER;
    const timeoutMs = options.timeoutMs ?? 30_000;

    if (server.endpoint.transport === 'stdio') {
      const transport = new StdioTransport({
        command: server.endpoint.command,
        args: server.endpoint.args,
        env: options.env ?? {},
        logger,
        ...(server.endpoint.cwd === undefined ? {} : { cwd: server.endpoint.cwd }),
      });

      transport.start();

      return new ServerSession(
        new McpClient(transport, {
          timeoutMs,
          logger,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
        }),
        server,
      );
    }

    return new ServerSession(
      new McpClient(new HttpTransport({ url: server.endpoint.url, logger }), {
        timeoutMs,
        logger,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
      }),
      server,
    );
  }

  private assertUsable(): void {
    if (this.disposed) {
      throw new TransportError(
        'This session has been disposed. Open a new one rather than reusing it.',
        { details: { serverId: this.server.id } },
      );
    }
  }

  /** Capture what the server currently advertises. */
  async capture(): Promise<ServerSurface> {
    this.assertUsable();
    return (await this.client.capture(this.server, this.server.endpoint.transport)).surface;
  }

  /** Capture, retaining the evidence a conformance grade needs. */
  async captureWithEvidence(): Promise<CaptureResult> {
    this.assertUsable();
    return await this.client.capture(this.server, this.server.endpoint.transport);
  }

  /** Capture and grade in one step. */
  async conform(): Promise<{ surface: ServerSurface; report: ConformanceReport }> {
    this.assertUsable();

    const captured = await this.client.capture(this.server, this.server.endpoint.transport);
    return { surface: captured.surface, report: grade(captured) };
  }

  /**
   * Release the server process or connection.
   *
   * Idempotent. Safe to call in a `finally` alongside an explicit call.
   */
  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    await this.client.dispose();
  }

  /** Whether this session has been disposed. */
  get isDisposed(): boolean {
    return this.disposed;
  }
}

/**
 * Run a function with a session, disposing it afterwards no matter what.
 *
 * The shape most callers want. It is very easy to write a `try` that leaks a
 * child process on the error path, and on Windows that process survives the test
 * run and breaks the next one.
 */
export async function withServer<T>(
  server: ServerRef,
  fn: (session: ServerSession) => Promise<T>,
  options: OperationOptions = {},
): Promise<T> {
  const session = ServerSession.open(server, options);

  try {
    return await fn(session);
  } finally {
    await session.dispose();
  }
}

/**
 * Inventory the MCP servers configured on this machine.
 *
 * Entirely offline. Connects to nothing, so it is safe on a machine you do not
 * fully trust and cannot itself start a server.
 */
export async function inventory(options: DiscoveryOptions = {}): Promise<Inventory> {
  return await discover(options);
}

/** Capture a server's surface, opening and closing a session around it. */
export async function captureServer(
  server: ServerRef,
  options: OperationOptions = {},
): Promise<ServerSurface> {
  return await withServer(server, async (session) => await session.capture(), options);
}

/** Capture and grade a server against the specification. */
export async function conformServer(
  server: ServerRef,
  options: OperationOptions = {},
): Promise<{ surface: ServerSurface; report: ConformanceReport }> {
  return await withServer(server, async (session) => await session.conform(), options);
}

/** Capture a server and pin what it advertises as approved. */
export async function trustServer(
  server: ServerRef,
  approvedBy: string,
  options: OperationOptions & { readonly note?: string } = {},
): Promise<TrustPin> {
  const surface = await captureServer(server, options);

  return createPin(surface, {
    approvedBy,
    ...(options.note === undefined ? {} : { note: options.note }),
  });
}

/** Capture a server and compare it against a pin. */
export async function diffServer(
  server: ServerRef,
  pin: TrustPin,
  options: OperationOptions & DiffOptions = {},
): Promise<{ surface: ServerSurface; report: DriftReport }> {
  const surface = await captureServer(server, options);
  return { surface, report: diffAgainstPin(surface, pin, options) };
}

/** Append a captured surface to a ledger. */
export async function recordCapture(
  ledgerPath: string,
  surface: ServerSurface,
  toolVersion: string,
): Promise<LedgerEntry> {
  return await new Ledger(ledgerPath).append({ surface, toolVersion });
}

/** Verify a ledger's hash chain. */
export async function verifyLedger(
  ledgerPath: string,
): Promise<ReturnType<Ledger['verify']>> {
  return await new Ledger(ledgerPath).verify();
}

/** Evaluate a policy against a machine's state. */
export function evaluatePolicy(policy: Policy, input: PolicyInput): PolicyResult {
  return checkPolicy(policy, input);
}

/** Analyse a source tree for patterns that break under 2026-07-28. */
export async function analyzeSourceTree(
  path: string,
  options: AnalyzeOptions = {},
): Promise<MigrationReport> {
  return await analyzeMigration(path, options);
}

export { diffSurfaces, createPin };

export type {
  CaptureProgress,
  CaptureResult,
  ConformanceReport,
  DiffOptions,
  DriftReport,
  Inventory,
  LedgerEntry,
  MigrationReport,
  Policy,
  PolicyResult,
  ServerRef,
  ServerSurface,
  TrustPin,
};
