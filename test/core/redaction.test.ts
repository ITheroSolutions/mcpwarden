import { describe, expect, it } from 'vitest';

import {
  collectEnvSecrets,
  findResidualSecret,
  redact,
  redactDeep,
  redactionFingerprint,
  SECRET_ENV_NAME_PATTERN,
} from '../../src/core/redaction.js';
import { MUST_SURVIVE, SECRET_FIXTURES } from '../fixtures/secrets.js';

describe('redact: every fixture shape', () => {
  for (const fixture of SECRET_FIXTURES) {
    describe(fixture.name, () => {
      it('removes the secret from its realistic context', () => {
        const output = redact(fixture.context);
        expect(output).not.toContain(fixture.secret);
      });

      // A contextual-only secret is one that is indistinguishable from ordinary
      // text on its own, such as a connection string password. What identifies it
      // is its position, not its content. Requiring isolated detection would mean
      // redacting every medium length word, which destroys reports.
      it.skipIf(fixture.contextualOnly)('removes the secret in isolation', () => {
        const output = redact(fixture.secret);
        expect(output).not.toContain(fixture.secret);
      });

      it('leaves no residual credential the probes can still find', () => {
        expect(findResidualSecret(redact(fixture.context))).toBeUndefined();
      });

      it('marks the removal visibly rather than deleting silently', () => {
        // A silent deletion is worse than a marked one: the reader cannot tell
        // whether something was removed or was never there.
        expect(redact(fixture.context)).toContain('REDACTED');
      });

      if (fixture.preserved !== undefined) {
        it('keeps the surrounding context readable', () => {
          expect(redact(fixture.context)).toContain(fixture.preserved);
        });
      }
    });
  }
});

describe('redact: over-redaction guard', () => {
  for (const value of MUST_SURVIVE) {
    it(`leaves ${JSON.stringify(value)} untouched`, () => {
      expect(redact(value)).toBe(value);
    });
  }

  it('leaves an ordinary sentence completely unchanged', () => {
    const prose =
      'This tool reads a file from disk and returns its contents as a string value.';
    expect(redact(prose)).toBe(prose);
  });

  it('leaves an empty string alone', () => {
    expect(redact('')).toBe('');
  });
});

describe('redact: our own content hashes survive', () => {
  // A surface merkle root is 64 hex characters. Without explicit protection the
  // high entropy hex heuristic would eat it and destroy the ledger's readability.
  const root = 'sha256:' + 'a'.repeat(64);
  const mixed = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  it('preserves a prefixed hash verbatim', () => {
    expect(redact(`merkle root ${root} captured`)).toContain(root);
  });

  it('preserves several hashes in one string', () => {
    const a = 'sha256:' + '1'.repeat(64);
    const b = 'sha256:' + '2'.repeat(64);
    const output = redact(`from ${a} to ${b}`);
    expect(output).toContain(a);
    expect(output).toContain(b);
  });

  it('still redacts an unprefixed hex blob of the same length', () => {
    // Only the prefixed form is trusted. A bare blob is treated as unknown.
    expect(redact(mixed)).not.toContain(mixed);
  });
});

describe('redact: fingerprints', () => {
  it('is stable for the same secret across calls', () => {
    const secret = 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH';
    expect(redact(secret)).toBe(redact(secret));
  });

  it('produces the same token for the same secret in different contexts', () => {
    const secret = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB';
    const first = redact(`token is ${secret}`);
    const second = redact(`different wording, same key: ${secret}`);

    const fingerprint = redactionFingerprint(secret);
    expect(first).toContain(fingerprint);
    expect(second).toContain(fingerprint);
  });

  it('produces different tokens for different secrets', () => {
    const a = redact('ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const b = redact('ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    expect(a).not.toBe(b);
  });

  it('never contains the secret it fingerprints', () => {
    const secret = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';
    expect(redactionFingerprint(secret)).not.toContain(secret);
    expect(secret).not.toContain(redactionFingerprint(secret));
  });
});

describe('redact: idempotence', () => {
  it('redacting twice equals redacting once, for every fixture', () => {
    for (const fixture of SECRET_FIXTURES) {
      const once = redact(fixture.context);
      const twice = redact(once);
      expect(twice).toBe(once);
    }
  });
});

describe('redact: environment derived secrets', () => {
  const env = {
    ANTHROPIC_API_KEY: 'notaprefixedkeyjustalongopaquevalue123',
    DATABASE_PASSWORD: 'hunter2hunter2hunter2',
    MY_SERVICE_TOKEN: 'opaque-token-value-here-1234',
    HOME: '/home/dev',
    PATH: '/usr/bin:/bin',
    AUTH_TYPE: 'oauth',
    LOG_LEVEL: 'debug',
    SHORT_SECRET: 'abc',
  };

  it('collects values only from secret shaped names', () => {
    const secrets = collectEnvSecrets(env);
    expect(secrets).toContain('notaprefixedkeyjustalongopaquevalue123');
    expect(secrets).toContain('hunter2hunter2hunter2');
    expect(secrets).toContain('opaque-token-value-here-1234');
  });

  it('ignores non secret names', () => {
    const secrets = collectEnvSecrets(env);
    expect(secrets).not.toContain('/home/dev');
    expect(secrets).not.toContain('/usr/bin:/bin');
    expect(secrets).not.toContain('debug');
  });

  it('ignores known non secret names that match the pattern', () => {
    expect(collectEnvSecrets(env)).not.toContain('oauth');
  });

  it('ignores values too short to redact safely', () => {
    // Redacting "abc" would strip that substring out of unrelated words.
    expect(collectEnvSecrets(env)).not.toContain('abc');
  });

  it('removes a collected value that no pattern would otherwise catch', () => {
    const opaque = 'notaprefixedkeyjustalongopaquevalue123';
    const output = redact(`the server was started with ${opaque} as its key`, {
      extraSecrets: collectEnvSecrets(env),
    });

    expect(output).not.toContain(opaque);
    expect(output).toContain('REDACTED');
    expect(output).toContain('the server was started with');
  });

  it('replaces the longest matching secret when one contains another', () => {
    const short = 'abcdefghijkl';
    const long = 'abcdefghijklmnopqrstuvwx';
    const output = redact(long, { extraSecrets: [short, long] });

    expect(output).not.toContain(long);
    expect(output).not.toContain(short);
    // One token, not a token nested inside the remains of another.
    expect(output.match(/REDACTED/g)).toHaveLength(1);
  });

  it('treats the variable name as public and only the value as secret', () => {
    const output = redact('DATABASE_PASSWORD=hunter2hunter2hunter2', {
      extraSecrets: collectEnvSecrets(env),
    });
    expect(output).toContain('DATABASE_PASSWORD');
    expect(output).not.toContain('hunter2hunter2hunter2');
  });
});

describe('SECRET_ENV_NAME_PATTERN', () => {
  const secretNames = [
    'API_KEY',
    'ANTHROPIC_API_KEY',
    'DATABASE_PASSWORD',
    'GITHUB_TOKEN',
    'CLIENT_SECRET',
    'AWS_SECRET_ACCESS_KEY',
    'PRIVATE_KEY',
    'REFRESH_TOKEN',
    'SESSION_COOKIE',
    'SENTRY_DSN',
  ];

  const publicNames = ['HOME', 'PATH', 'NODE_ENV', 'PORT', 'LOG_LEVEL', 'USER', 'LANG'];

  for (const name of secretNames) {
    it(`treats ${name} as secret`, () => {
      SECRET_ENV_NAME_PATTERN.lastIndex = 0;
      expect(SECRET_ENV_NAME_PATTERN.test(name)).toBe(true);
    });
  }

  for (const name of publicNames) {
    it(`treats ${name} as public`, () => {
      SECRET_ENV_NAME_PATTERN.lastIndex = 0;
      expect(SECRET_ENV_NAME_PATTERN.test(name)).toBe(false);
    });
  }
});

describe('redactDeep', () => {
  it('redacts strings at every depth while preserving structure', () => {
    const input = {
      name: 'get_weather',
      config: {
        headers: { Authorization: 'Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789AB' },
        retries: 3,
        enabled: true,
        hosts: ['https://example.com/mcp', 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'],
      },
      missing: null,
    };

    const output = redactDeep(input);

    expect(output.name).toBe('get_weather');
    expect(output.config.retries).toBe(3);
    expect(output.config.enabled).toBe(true);
    expect(output.missing).toBeNull();
    expect(output.config.hosts[0]).toBe('https://example.com/mcp');

    const serialized = JSON.stringify(output);
    expect(serialized).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz0123456789AB');
    expect(serialized).not.toContain('sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH');
  });

  it('redacts object keys, not only values', () => {
    // A config file can put a credential in a key name.
    const input = { 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH': 'value' };
    const serialized = JSON.stringify(redactDeep(input));
    expect(serialized).not.toContain('sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH');
  });

  it('leaves numbers untouched so cache and ledger fields stay intact', () => {
    const input = { ttlMs: 3_600_000, sequence: 9_007_199_254_740_991 };
    const output = redactDeep(input);
    expect(output.ttlMs).toBe(3_600_000);
    expect(output.sequence).toBe(9_007_199_254_740_991);
  });

  it('does not let a __proto__ key alter the result object', () => {
    const input = JSON.parse('{"__proto__": {"polluted": true}, "safe": "value"}') as Record<
      string,
      unknown
    >;
    const output = redactDeep(input);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(output['safe']).toBe('value');
  });

  it('handles an empty object and an empty array', () => {
    expect(redactDeep({})).toEqual({});
    expect(redactDeep([])).toEqual([]);
  });
});

describe('findResidualSecret', () => {
  it('finds an unredacted credential', () => {
    expect(findResidualSecret('key is ghp_abcdefghijklmnopqrstuvwxyz0123456789AB')).toBe(
      'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB',
    );
  });

  it('reports clean text as clean', () => {
    expect(findResidualSecret('tools/list returned 4 tools')).toBeUndefined();
  });

  it('is not confused by a redaction token', () => {
    expect(findResidualSecret(redact('ghp_abcdefghijklmnopqrstuvwxyz0123456789AB'))).toBeUndefined();
  });

  it('is repeatable, so a global regex lastIndex never leaks between calls', () => {
    const text = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB';
    expect(findResidualSecret(text)).toBe(findResidualSecret(text));
    expect(findResidualSecret(text)).toBe(findResidualSecret(text));
  });
});
