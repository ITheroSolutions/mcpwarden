/**
 * Streamable HTTP transport.
 *
 * Every JSON-RPC message is its own POST to a single endpoint (MW-HTTP-001). The
 * server answers with either a single JSON object or an SSE stream scoped to that
 * request, and the client must support both (MW-HTTP-007).
 *
 * ## What this revision removed
 *
 * There is no session and no `Mcp-Session-Id` (MW-HTTP-012). There is no GET
 * stream endpoint. There is no `Last-Event-ID` resumability: a broken response
 * stream loses the in-flight request and the client re-issues it as a new request
 * with a new id. None of that machinery exists here, and its absence is the point
 * rather than an omission.
 *
 * ## Why there is a raw probe alongside the normal request path
 *
 * Most of the HTTP conformance rules are about the *envelope* rather than the
 * body: a `400` with `-32020` when headers disagree with the body, a `404` with
 * `-32601` for an unknown method, a `405` for a GET. A transport that only ever
 * returns a parsed JSON-RPC result throws that evidence away. {@link rawRequest}
 * keeps the status line and headers so the conformance engine can grade them.
 */

import { CancellationError, TimeoutError, TransportError } from '../core/errors.js';
import { parseJsonPreservingNumbers, type JsonValue } from '../core/json-parse.js';
import { NOOP_LOGGER, type Logger } from '../core/logger.js';
import type { ProtocolRevision } from '../core/revisions.js';
import {
  buildHttpHeaders,
  METHODS_REQUIRING_NAME_HEADER,
  serializeForStdio,
} from './messages.js';

/** Cap on a response body, so a hostile endpoint cannot exhaust memory. */
const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

export interface HttpTransportOptions {
  readonly url: string;
  /** Extra headers, typically authorization supplied by the caller. */
  readonly headers?: Readonly<Record<string, string>>;
  readonly logger?: Logger;
  readonly maxResponseBytes?: number;
  /** Overrides the revision read from the outgoing message. Only for probing. */
  readonly revision?: ProtocolRevision;
}

/** A complete HTTP exchange, kept intact so conformance rules can grade it. */
export interface RawHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly contentType: string;
  /** The raw body text. For an SSE response, the concatenated data payloads. */
  readonly bodyText: string;
  /** The parsed JSON-RPC message, when the body contained one. */
  readonly message: JsonValue | undefined;
  /** True when the server answered with `text/event-stream`. */
  readonly streamed: boolean;
}

export interface RawRequestOptions {
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  /** Override the HTTP method. Only for probing MW-HTTP-011. */
  readonly httpMethod?: string;
  /** Replace the computed headers wholesale. Only for probing. */
  readonly headers?: Readonly<Record<string, string>>;
  /** Send this body verbatim instead of serialising the message. Only for probing. */
  readonly rawBody?: string;
}

export class HttpTransport {
  private readonly logger: Logger;
  private readonly maxResponseBytes: number;
  private disposed = false;

  constructor(private readonly options: HttpTransportOptions) {
    this.logger = options.logger ?? NOOP_LOGGER;
    this.maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  }

  /**
   * Send a request and return the parsed JSON-RPC response.
   *
   * Satisfies the `Transport` interface the capture client depends on.
   */
  async request(
    message: Record<string, unknown>,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    const response = await this.rawRequest(message, { timeoutMs, ...(signal ? { signal } : {}) });

    if (response.message === undefined) {
      throw new TransportError(
        `Server returned HTTP ${String(response.status)} with no JSON-RPC message`,
        { details: { status: response.status, contentType: response.contentType } },
      );
    }

    return response.message;
  }

  /**
   * Send a request and return the whole exchange.
   *
   * A non `2xx` status is not an error here. Several conformance rules require a
   * specific error status paired with a specific JSON-RPC code, so a `400` with
   * `-32020` is a *correct* answer that the engine needs to see rather than a
   * failure to swallow.
   */
  async rawRequest(
    message: Record<string, unknown>,
    options: RawRequestOptions,
  ): Promise<RawHttpResponse> {
    if (this.disposed) throw new TransportError('Transport has been disposed');

    const method = typeof message['method'] === 'string' ? message['method'] : '';
    const headers = options.headers ?? this.headersFor(message, method);

    const controller = new AbortController();
    const onAbort = (): void => {
      controller.abort();
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(() => {
      controller.abort();
    }, options.timeoutMs);
    timer.unref();

    try {
      const body =
        options.rawBody ??
        // Reuse the stdio serialiser for its embedded newline assertion, then
        // drop the trailing newline HTTP does not want.
        serializeForStdio(message).slice(0, -1);

      const response = await fetch(this.options.url, {
        method: options.httpMethod ?? 'POST',
        headers: { ...headers, ...this.options.headers },
        ...(options.httpMethod === 'GET' || options.httpMethod === 'DELETE' ? {} : { body }),
        signal: controller.signal,
        redirect: 'manual',
      });

      return await this.readResponse(response);
    } catch (error) {
      if (options.signal?.aborted === true) {
        throw new CancellationError('Request cancelled by the caller');
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new TimeoutError(`Request timed out after ${String(options.timeoutMs)}ms`, {
          details: { timeoutMs: options.timeoutMs, method },
        });
      }

      throw new TransportError(
        `HTTP request failed: ${error instanceof Error ? error.message : 'unknown error'}`,
        { details: { method }, cause: error },
      );
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
    }
  }

  private headersFor(
    message: Record<string, unknown>,
    method: string,
  ): Record<string, string> {
    const revision = this.options.revision ?? this.revisionFromMessage(message);
    const params = message['params'];
    const name = readNameForHeader(params, method);

    return buildHttpHeaders({
      revision,
      method,
      ...(name === undefined ? {} : { name }),
    });
  }

  /**
   * Read the revision out of the outgoing message body.
   *
   * MW-HTTP-002 requires the `MCP-Protocol-Version` header to match the body's
   * `_meta` value, so taking it from anywhere else would risk sending a request
   * that is non conforming by construction.
   */
  private revisionFromMessage(message: Record<string, unknown>): ProtocolRevision {
    const params = message['params'];

    if (typeof params === 'object' && params !== null) {
      const meta = (params as Record<string, unknown>)['_meta'];
      if (typeof meta === 'object' && meta !== null) {
        const version = (meta as Record<string, unknown>)['io.modelcontextprotocol/protocolVersion'];
        if (typeof version === 'string') return version as ProtocolRevision;
      }
    }

    return '2026-07-28';
  }

  private async readResponse(response: Response): Promise<RawHttpResponse> {
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const contentType = headers['content-type'] ?? '';
    const streamed = contentType.includes('text/event-stream');

    const bodyText = await this.readBody(response);

    // A 202 Accepted for a notification carries no body by design (MW-HTTP-006).
    if (bodyText.length === 0) {
      return { status: response.status, headers, contentType, bodyText, message: undefined, streamed };
    }

    const payload = streamed ? lastSseData(bodyText) : bodyText;

    if (payload === undefined) {
      return { status: response.status, headers, contentType, bodyText, message: undefined, streamed };
    }

    let message: JsonValue | undefined;
    try {
      message = parseJsonPreservingNumbers(payload);
    } catch {
      // A body that is not JSON is itself a finding for the conformance engine.
      // The exchange is returned intact so the engine can grade it.
      this.logger.debug('response body was not valid JSON', { status: response.status });
      message = undefined;
    }

    return { status: response.status, headers, contentType, bodyText, message, streamed };
  }

  private async readBody(response: Response): Promise<string> {
    if (response.body === null) return '';

    // `response.body` is typed `ReadableStream<any>` by the bundled fetch types,
    // so the chunk type has to be stated. It is narrowed rather than widened: the
    // stream yields `Uint8Array` at runtime, and asserting that is what keeps the
    // byte counting below meaningful.
    //
    // The alternative was `response.arrayBuffer()`, which types cleanly but
    // downloads the whole body before the size cap can reject it, turning the
    // cap into an assertion rather than a defence.
    const body = response.body as ReadableStream<Uint8Array>;
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let bytes = 0;

    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;

      bytes += value.byteLength;
      if (bytes > this.maxResponseBytes) {
        await reader.cancel();
        throw new TransportError(
          `Response exceeded ${String(this.maxResponseBytes)} bytes`,
          { details: { limit: this.maxResponseBytes } },
        );
      }

      text += decoder.decode(value, { stream: true });
    }

    return text + decoder.decode();
  }

  dispose(): Promise<void> {
    this.disposed = true;
    return Promise.resolve();
  }
}

/**
 * Extract the final JSON-RPC message from an SSE body.
 *
 * The server may emit progress notifications before the response, and the final
 * response SHOULD terminate the stream, so the last data payload is the answer.
 * Comment lines beginning with a colon are keep-alives and carry no event data;
 * the SSE specification requires clients to ignore them rather than treat them as
 * malformed, which matters because servers are encouraged to send them on long
 * lived streams.
 */
export function lastSseData(body: string): string | undefined {
  const payloads: string[] = [];
  let current: string[] = [];

  for (const rawLine of body.split(/\r?\n/)) {
    if (rawLine.length === 0) {
      if (current.length > 0) {
        payloads.push(current.join('\n'));
        current = [];
      }
      continue;
    }

    // A keep-alive comment. Ignore it.
    if (rawLine.startsWith(':')) continue;

    if (rawLine.startsWith('data:')) {
      // A single optional space after the colon is part of the framing.
      const value = rawLine.slice('data:'.length);
      current.push(value.startsWith(' ') ? value.slice(1) : value);
    }
  }

  if (current.length > 0) payloads.push(current.join('\n'));

  return payloads.at(-1);
}

/**
 * Read the value the `Mcp-Name` header must carry.
 *
 * `params.name` for `tools/call` and `prompts/get`, `params.uri` for
 * `resources/read` (MW-HTTP-003).
 */
function readNameForHeader(params: unknown, method: string): string | undefined {
  if (!METHODS_REQUIRING_NAME_HEADER.has(method)) return undefined;
  if (typeof params !== 'object' || params === null) return undefined;

  const record = params as Record<string, unknown>;
  const name = record['name'];
  if (typeof name === 'string') return name;

  const uri = record['uri'];
  if (typeof uri === 'string') return uri;

  return undefined;
}
