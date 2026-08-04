/**
 * Types for the HTTP fixture server.
 *
 * The fixture itself is plain JavaScript so it stays outside the compiled package
 * and outside the type-aware lint project, matching the stdio fixture. This
 * declaration exists only so the tests that import it are still type checked.
 */

export interface HttpFixtureRequest {
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export interface HttpFixture {
  /** The MCP endpoint URL, on an ephemeral loopback port. */
  readonly url: string;
  /** Every request the fixture received, in order, for header assertions. */
  readonly received: HttpFixtureRequest[];
  close(): Promise<void>;
}

export interface HttpFixtureOptions {
  /**
   * Which behaviour to exhibit. `conforming` is correct; the others are each
   * broken in one specific, documented way.
   */
  readonly mode?: string;
}

export function startHttpFixture(options?: HttpFixtureOptions): Promise<HttpFixture>;
