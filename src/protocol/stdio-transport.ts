/**
 * stdio transport.
 *
 * Spawns a server as a child process and exchanges newline delimited JSON-RPC
 * over its standard streams (MW-STDIO-001).
 *
 * Three things here are easy to get wrong and are handled deliberately.
 *
 * **stderr is not an error channel.** The specification is explicit that a server
 * MAY write anything to stderr and that a client SHOULD NOT treat output there as
 * indicating a problem (MW-STDIO-003). It is captured separately, bounded, and
 * never merged into the message stream.
 *
 * **Shutdown is a sequence, not a kill.** Close stdin, wait for exit, force
 * terminate only if the server does not go (MW-STDIO-007). Servers are told to
 * exit when stdin closes, and honouring that is what keeps the common case clean.
 *
 * **On Windows, killing a process does not kill its descendants.** An MCP server
 * launched through `npx` or `cmd` is a shell that spawns the real server, so
 * killing the shell leaves the server running and holding its port or its file
 * locks. The whole tree is terminated explicitly.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { platform } from 'node:process';

import { CancellationError, TimeoutError, TransportError } from '../core/errors.js';
import { isJsonNumber, parseJsonPreservingNumbers, type JsonValue } from '../core/json-parse.js';
import { NOOP_LOGGER, type Logger } from '../core/logger.js';
import { serializeForStdio } from './messages.js';

/** How long to wait for a graceful exit before forcing termination. */
const GRACEFUL_EXIT_MS = 2_000;

/** Cap on retained stderr, so a chatty server cannot exhaust memory. */
const MAX_STDERR_BYTES = 64 * 1024;

/**
 * Cap on a single line from the server.
 *
 * Without this, a server that never emits a newline makes the reader buffer grow
 * without bound. The specification's own denial of service reasoning for schema
 * depth applies equally to the framing layer.
 */
const MAX_LINE_BYTES = 32 * 1024 * 1024;

export interface StdioTransportOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly cwd?: string;
  readonly logger?: Logger;
  readonly maxLineBytes?: number;
}

interface PendingRequest {
  readonly resolve: (value: JsonValue) => void;
  readonly reject: (error: Error) => void;
  timer?: NodeJS.Timeout;
}

export class StdioTransport {
  private child: ChildProcessWithoutNullStreams | undefined;
  private readonly pending = new Map<string, PendingRequest>();
  private buffer = '';
  private stderrChunks: string[] = [];
  private stderrBytes = 0;
  private disposed = false;
  private exited = false;
  private exitReason: string | undefined;
  private readonly logger: Logger;
  private readonly maxLineBytes: number;

  constructor(private readonly options: StdioTransportOptions) {
    this.logger = options.logger ?? NOOP_LOGGER;
    this.maxLineBytes = options.maxLineBytes ?? MAX_LINE_BYTES;
  }

  /** Everything the server wrote to stderr, capped. Never treated as an error. */
  get stderr(): string {
    return this.stderrChunks.join('');
  }

  get isRunning(): boolean {
    return this.child !== undefined && !this.exited;
  }

  start(): void {
    if (this.disposed) {
      throw new TransportError('Transport has been disposed');
    }
    if (this.child !== undefined) {
      throw new TransportError('Transport already started');
    }

    try {
      this.child = spawn(this.options.command, [...(this.options.args ?? [])], {
        stdio: ['pipe', 'pipe', 'pipe'],
        // Inheriting the parent environment wholesale would leak every
        // credential this process holds into an untrusted child. Only what the
        // caller named is passed.
        env: { ...this.options.env },
        ...(this.options.cwd === undefined ? {} : { cwd: this.options.cwd }),
        // Never route through a shell. The command and its arguments come from a
        // configuration file this package did not write, and a shell would turn
        // an argument containing a semicolon into arbitrary code execution.
        shell: false,
        windowsHide: true,
      });
    } catch (cause) {
      throw new TransportError(`Failed to spawn ${this.options.command}`, {
        details: { command: this.options.command },
        cause,
      });
    }

    this.child.stdout.setEncoding('utf8');
    this.child.stderr.setEncoding('utf8');

    this.child.stdout.on('data', (chunk: string) => {
      this.onStdout(chunk);
    });

    this.child.stderr.on('data', (chunk: string) => {
      this.onStderr(chunk);
    });

    this.child.on('error', (error) => {
      this.failAll(new TransportError(`Child process error: ${error.message}`, { cause: error }));
    });

    this.child.on('exit', (code, signal) => {
      this.exited = true;
      this.exitReason =
        signal === null ? `exited with code ${String(code)}` : `killed by signal ${signal}`;

      this.logger.debug('server process exited', { code, signal });

      // A server that dies mid capture must not leave a caller awaiting forever.
      this.failAll(
        new TransportError(`Server process ${this.exitReason} while requests were in flight`, {
          details: { code, signal, stderr: this.stderr.slice(-2000) },
        }),
      );
    });
  }

  private onStdout(chunk: string): void {
    this.buffer += chunk;

    for (;;) {
      const newline = this.buffer.indexOf('\n');

      if (newline === -1) {
        if (this.buffer.length > this.maxLineBytes) {
          this.failAll(
            new TransportError(
              `Server sent more than ${String(this.maxLineBytes)} bytes without a newline`,
            ),
          );
          this.buffer = '';
        }
        return;
      }

      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);

      if (line.length > 0) this.onMessage(line);
    }
  }

  private onMessage(line: string): void {
    let message: JsonValue;

    try {
      message = parseJsonPreservingNumbers(line);
    } catch (cause) {
      // A server that writes non JSON to stdout has violated MW-STDIO-002. That
      // is a finding the conformance engine reports, not a reason to tear down
      // the transport, so the line is dropped and recorded.
      this.logger.warn('server wrote a non JSON line to stdout', { length: line.length });
      void cause;
      return;
    }

    if (typeof message !== 'object' || message === null || Array.isArray(message)) {
      this.logger.warn('server wrote a JSON value that is not an object to stdout');
      return;
    }

    const record = message as Record<string, JsonValue>;
    const rawId = record['id'];

    if (rawId === undefined) {
      // A notification. Request scoped notifications are not needed for surface
      // capture, so they are logged and discarded rather than queued.
      this.logger.trace('notification received', { method: record['method'] });
      return;
    }

    const key = idKeyFromJson(rawId);

    if (key === undefined) {
      this.logger.warn('response carried an id that is neither a string nor a number');
      return;
    }

    const waiter = this.pending.get(key);

    if (waiter === undefined) {
      this.logger.warn('response for an unknown request id', { id: key });
      return;
    }

    this.pending.delete(key);
    if (waiter.timer !== undefined) clearTimeout(waiter.timer);
    waiter.resolve(message);
  }

  private onStderr(chunk: string): void {
    // Bounded, and never interpreted. MW-STDIO-003 is explicit that stderr
    // output does not indicate an error condition.
    if (this.stderrBytes >= MAX_STDERR_BYTES) return;

    this.stderrChunks.push(chunk);
    this.stderrBytes += chunk.length;
  }

  /**
   * Send a request and await its response.
   *
   * @param timeoutMs time budget for this request alone.
   * @param signal caller cancellation, distinct from a timeout.
   */
  async request(
    message: Record<string, unknown>,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    const child = this.child;

    if (child === undefined || this.exited) {
      throw new TransportError(
        this.exitReason === undefined
          ? 'Transport is not running'
          : `Transport is not running: server ${this.exitReason}`,
      );
    }

    const id = message['id'];
    if (id === undefined || (typeof id !== 'string' && typeof id !== 'number')) {
      throw new TransportError('A request must carry a string or number id');
    }

    const key = idKey(id);

    return new Promise<JsonValue>((resolve, reject) => {
      const settle = (fn: () => void): void => {
        this.pending.delete(key);
        if (signal !== undefined) signal.removeEventListener('abort', onAbort);
        fn();
      };

      const onAbort = (): void => {
        settle(() => {
          reject(new CancellationError('Request cancelled by the caller'));
        });
      };

      if (signal?.aborted === true) {
        reject(new CancellationError('Request cancelled before it was sent'));
        return;
      }

      const timer = setTimeout(() => {
        settle(() => {
          reject(
            new TimeoutError(`Request timed out after ${String(timeoutMs)}ms`, {
              details: { timeoutMs, method: message['method'] },
            }),
          );
        });
      }, timeoutMs);

      // Do not hold the event loop open on account of a pending timeout.
      timer.unref();

      this.pending.set(key, {
        resolve: (value) => {
          settle(() => {
            clearTimeout(timer);
            resolve(value);
          });
        },
        reject: (error) => {
          settle(() => {
            clearTimeout(timer);
            reject(error);
          });
        },
        timer,
      });

      if (signal !== undefined) signal.addEventListener('abort', onAbort, { once: true });

      try {
        child.stdin.write(serializeForStdio(message));
      } catch (cause) {
        settle(() => {
          clearTimeout(timer);
          reject(new TransportError('Failed to write to the server stdin', { cause }));
        });
      }
    });
  }

  private failAll(error: Error): void {
    const waiters = [...this.pending.values()];
    this.pending.clear();

    for (const waiter of waiters) {
      if (waiter.timer !== undefined) clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  /**
   * Shut down, leaving no orphaned processes.
   *
   * Idempotent: calling it twice is not an error, which matters because a
   * `finally` block and an explicit close frequently both run.
   */
  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;

    const child = this.child;
    if (child === undefined) return;

    this.failAll(new TransportError('Transport disposed while requests were in flight'));

    if (this.exited) return;

    // Step one: close stdin. Servers SHOULD exit on end of file, and this is the
    // only portable graceful signal (MW-STDIO-007).
    try {
      child.stdin.end();
    } catch {
      // Already closed. Nothing to do.
    }

    const exitedGracefully = await this.waitForExit(GRACEFUL_EXIT_MS);
    if (exitedGracefully) return;

    this.logger.debug('server did not exit on stdin close, terminating');
    this.killTree(child);

    await this.waitForExit(GRACEFUL_EXIT_MS);
  }

  private waitForExit(ms: number): Promise<boolean> {
    const child = this.child;
    /* c8 ignore next */
    if (child === undefined) return Promise.resolve(true);
    if (this.exited) return Promise.resolve(true);

    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        resolve(false);
      }, ms);
      timer.unref();

      child.once('exit', () => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }

  /**
   * Terminate the child and every descendant.
   *
   * On Windows this is not optional. An MCP server is commonly launched through
   * `npx` or `cmd`, which spawns the real server as a grandchild. Killing only
   * the direct child leaves that grandchild running, holding its port and its
   * file handles, and the next capture then fails for reasons that look nothing
   * like the actual cause. `taskkill /T` walks the tree.
   */
  private killTree(child: ChildProcessWithoutNullStreams): void {
    const pid = child.pid;

    if (pid === undefined) {
      child.kill('SIGKILL');
      return;
    }

    if (platform === 'win32') {
      try {
        // Synchronous and fire and forget: dispose must not hang on this, and a
        // failure here is already the exceptional path.
        const killer = spawn('taskkill', ['/pid', String(pid), '/t', '/f'], {
          stdio: 'ignore',
          windowsHide: true,
          shell: false,
        });
        killer.on('error', () => {
          child.kill('SIGKILL');
        });
      } catch {
        child.kill('SIGKILL');
      }
      return;
    }

    // POSIX: escalate. SIGTERM lets a well behaved server clean up; SIGKILL is
    // the backstop for one that ignores it.
    child.kill('SIGTERM');

    const escalation = setTimeout(() => {
      if (!this.exited) child.kill('SIGKILL');
    }, GRACEFUL_EXIT_MS);

    escalation.unref();
  }
}

function idKey(id: string | number): string {
  return typeof id === 'number' ? `n:${String(id)}` : `s:${id}`;
}

/**
 * Derive the correlation key from an id that came back off the wire.
 *
 * This cannot reuse {@link idKey} directly. Responses are parsed with
 * `parseJsonPreservingNumbers`, so a numeric id arrives as a `JsonNumber` carrying
 * its source token rather than as a JavaScript number. Passing that object to
 * `idKey` yields `s:[object Object]`, which matches nothing, and every request
 * silently times out despite the server answering correctly.
 *
 * The token is normalised through `Number` so that a server echoing `1.0` for a
 * request sent as `1` still correlates. Request ids are small integers, so there
 * is no precision concern here, unlike in the canonicalization path.
 */
function idKeyFromJson(id: JsonValue): string | undefined {
  if (typeof id === 'string') return `s:${id}`;

  if (isJsonNumber(id)) {
    const numeric = Number(id.token);
    return Number.isFinite(numeric) ? `n:${String(numeric)}` : undefined;
  }

  return undefined;
}
