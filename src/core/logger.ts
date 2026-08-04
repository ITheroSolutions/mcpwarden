/**
 * Logging.
 *
 * The library never writes to a stream on its own. The default logger discards
 * everything, and a host that wants output supplies one.
 *
 * This is not a style preference. **stdout is an MCP transport.** The self hosted
 * MCP server speaks JSON-RPC over stdio, so a single stray write to
 * stdout anywhere in the library corrupts the protocol stream, and the failure
 * surfaces as a parse error inside somebody else's client rather than as an
 * obvious bug here. ESLint forbids `console` across the source tree for the same
 * reason.
 *
 * Every message is redacted before it reaches a sink, because a log line is one of
 * the four places a secret must never reach, and the natural way to
 * log a connection failure is to interpolate the thing that failed.
 */

import { redact, redactDeep, type RedactionOptions } from './redaction.js';

/** Ordered from most severe to most verbose. */
export const LOG_LEVELS = ['silent', 'error', 'warn', 'info', 'debug', 'trace'] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];

/** Numeric severity, used only for threshold comparison. */
const LEVEL_RANK: Readonly<Record<LogLevel, number>> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
  trace: 5,
};

export interface LogRecord {
  readonly level: Exclude<LogLevel, 'silent'>;
  readonly message: string;
  readonly fields?: Readonly<Record<string, unknown>>;
}

export interface Logger {
  error(message: string, fields?: Readonly<Record<string, unknown>>): void;
  warn(message: string, fields?: Readonly<Record<string, unknown>>): void;
  info(message: string, fields?: Readonly<Record<string, unknown>>): void;
  debug(message: string, fields?: Readonly<Record<string, unknown>>): void;
  trace(message: string, fields?: Readonly<Record<string, unknown>>): void;
  /** A logger scoped with additional fields merged into every record. */
  child(fields: Readonly<Record<string, unknown>>): Logger;
}

/** Where records go. Supplied by the host, never by the library. */
export type LogSink = (record: LogRecord) => void;

export interface LoggerOptions {
  readonly level?: LogLevel;
  readonly sink?: LogSink;
  readonly redaction?: RedactionOptions;
  readonly fields?: Readonly<Record<string, unknown>>;
}

class StructuredLogger implements Logger {
  private readonly level: LogLevel;
  private readonly sink: LogSink | undefined;
  private readonly redaction: RedactionOptions;
  private readonly fields: Readonly<Record<string, unknown>>;

  constructor(options: LoggerOptions) {
    this.level = options.level ?? 'silent';
    this.sink = options.sink;
    this.redaction = options.redaction ?? {};
    this.fields = options.fields ?? {};
  }

  private emit(
    level: Exclude<LogLevel, 'silent'>,
    message: string,
    fields?: Readonly<Record<string, unknown>>,
  ): void {
    if (this.sink === undefined) return;
    if (LEVEL_RANK[level] > LEVEL_RANK[this.level]) return;

    const merged = { ...this.fields, ...fields };

    this.sink({
      level,
      message: redact(message, this.redaction),
      ...(Object.keys(merged).length === 0
        ? {}
        : { fields: redactDeep(merged, this.redaction) }),
    });
  }

  error(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.emit('error', message, fields);
  }

  warn(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.emit('warn', message, fields);
  }

  info(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.emit('info', message, fields);
  }

  debug(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.emit('debug', message, fields);
  }

  trace(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.emit('trace', message, fields);
  }

  child(fields: Readonly<Record<string, unknown>>): Logger {
    return new StructuredLogger({
      level: this.level,
      ...(this.sink === undefined ? {} : { sink: this.sink }),
      redaction: this.redaction,
      fields: { ...this.fields, ...fields },
    });
  }
}

/**
 * The default logger: discards everything.
 *
 * Exported as a singleton so that the common case of "no logging configured" costs
 * nothing per call site.
 */
export const NOOP_LOGGER: Logger = new StructuredLogger({ level: 'silent' });

export function createLogger(options: LoggerOptions = {}): Logger {
  return new StructuredLogger(options);
}

export function isLogLevel(value: string): value is LogLevel {
  return (LOG_LEVELS as readonly string[]).includes(value);
}
