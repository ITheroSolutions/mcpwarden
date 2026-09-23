/**
 * Types for the real world HTTP fixture. See http-realworld.mjs.
 */

import type { HttpFixtureRequest } from './http-server.mjs';

export type RealWorldMode =
  | 'auth-vendor-json'
  | 'auth-jsonrpc'
  | 'auth-forbidden'
  | 'legacy-session'
  | 'json-not-jsonrpc';

export interface RealWorldFixture {
  readonly url: string;
  readonly received: HttpFixtureRequest[];
  /** Legacy session mode only: whether the handshake completed, and the session was closed. */
  readonly state: { initialized: boolean; closed: boolean };
  close(): Promise<void>;
}

export function startRealWorldFixture(options: { mode: RealWorldMode }): Promise<RealWorldFixture>;
