/**
 * Recognising a credential by its name, in the naming conventions real
 * configurations use.
 *
 * The secret name pattern was written for environment variables, which are upper
 * snake case. A real server was configured with its token in a URL query as
 * `userToken`, camelCase, and was reported as carrying no credential. The token
 * was also an encrypted, five segment JWT, which the three segment shape check
 * missed.
 */

import { describe, expect, it } from 'vitest';

import { isSecretName } from '../../src/core/redaction.js';
import type { ClientDefinition } from '../../src/discovery/clients.js';
import { deduplicate, parseClientConfig } from '../../src/discovery/parse.js';

const CLIENT: ClientDefinition = {
  id: 'vscode',
  displayName: 'VS Code',
  shape: 'servers',
  confidence: 'confirmed',
  paths: [],
};

function postureOf(entry: Record<string, unknown>): string | undefined {
  const text = JSON.stringify({ servers: { srv: entry } });
  return deduplicate(parseClientConfig(text, CLIENT, '/cfg.json'))[0]?.authPosture;
}

const JWE =
  'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01.q1w2e3r4t5y6u7i8.' +
  'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F9e8D7c6B5a4Z3y2X1w0V9u8T7s6R5q4P3o2N1m0.Zz9Yy8Xx7Ww6Vv5Uu4Tt3S';

describe('isSecretName', () => {
  it('recognises secret names in every common convention', () => {
    for (const name of [
      'API_KEY',
      'GITHUB_TOKEN',
      'userToken',
      'apiKey',
      'accessToken',
      'clientSecret',
      'X-Api-Key',
      'x-auth-token',
      'Authorization',
      'db.password',
    ]) {
      expect(isSecretName(name), name).toBe(true);
    }
  });

  it('does not flag ordinary names', () => {
    for (const name of ['username', 'author', 'monkey', 'keyboardLayout', 'PATH', 'baseUrl', 'timeoutMs']) {
      expect(isSecretName(name), name).toBe(false);
    }
  });
});

describe('inline credentials in configuration', () => {
  it('finds an encrypted JWT in a URL query under a camelCase name', () => {
    expect(postureOf({ url: `https://design.example.com/mcp/stream?userToken=${JWE}` })).toBe('inline');
  });

  it('finds an encrypted JWT in a URL query under any name, by its shape', () => {
    expect(postureOf({ url: `https://example.com/mcp?t=${JWE}` })).toBe('inline');
  });

  it('finds a credential in a hyphenated header', () => {
    expect(postureOf({ url: 'https://example.com/mcp', headers: { 'X-Api-Key': 'k3y-abcdefghijklmnop' } })).toBe(
      'inline',
    );
  });

  it('does not flag a URL whose query holds nothing secret', () => {
    expect(postureOf({ url: 'https://example.com/mcp?region=eu-west-1&format=json' })).toBe('none');
  });
});
