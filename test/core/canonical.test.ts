import { describe, expect, it } from 'vitest';

import {
  canonicalizeJsonText,
  canonicalizeNumberToken,
  canonicalizeString,
  canonicalizeValue,
  hashCanonicalForm,
  hashJsonText,
  hashValue,
  isContentHash,
} from '../../src/core/canonical.js';
import { parseJsonPreservingNumbers } from '../../src/core/json-parse.js';

describe('number canonicalization', () => {
  // These are the specific correctness requirements canonicalization exists for.
  describe('required cases', () => {
    it('treats 1.0 and 1 as the same number', () => {
      expect(canonicalizeNumberToken('1.0')).toBe(canonicalizeNumberToken('1'));
    });

    it('treats 1e2 and 100 as the same number', () => {
      expect(canonicalizeNumberToken('1e2')).toBe(canonicalizeNumberToken('100'));
    });

    it('treats negative zero and zero as the same number', () => {
      expect(canonicalizeNumberToken('-0')).toBe(canonicalizeNumberToken('0'));
      expect(canonicalizeNumberToken('-0')).toBe('0');
    });

    it('preserves an integer larger than Number.MAX_SAFE_INTEGER', () => {
      // These two differ by one and are indistinguishable as doubles. If the
      // canonicalizer ever routes through Number, this test fails, which is
      // exactly what it is for.
      const a = canonicalizeNumberToken('9007199254740993');
      const b = canonicalizeNumberToken('9007199254740992');
      expect(a).not.toBe(b);
    });

    it('proves the double round trip it avoids would have collided', () => {
      // Demonstrates the bug this design exists to prevent.
      expect(Number('9007199254740993')).toBe(Number('9007199254740992'));
    });
  });

  describe('canonical forms', () => {
    const cases: readonly (readonly [string, string])[] = [
      ['0', '0'],
      ['-0', '0'],
      ['0.0', '0'],
      ['0e100', '0'],
      ['1', '1e0'],
      ['1.0', '1e0'],
      ['1.000', '1e0'],
      ['-1', '-1e0'],
      ['100', '1e2'],
      ['1e2', '1e2'],
      ['1E2', '1e2'],
      ['1.0E+2', '1e2'],
      ['0.1', '1e-1'],
      ['1e-1', '1e-1'],
      ['1.5', '1.5e0'],
      ['1.50', '1.5e0'],
      ['15e-1', '1.5e0'],
      ['-1.5', '-1.5e0'],
      ['12345', '1.2345e4'],
      ['0.000123', '1.23e-4'],
      ['9007199254740993', '9.007199254740993e15'],
      ['123456789012345678901234567890', '1.2345678901234567890123456789e29'],
    ];

    for (const [input, expected] of cases) {
      it(`${input} canonicalizes to ${expected}`, () => {
        expect(canonicalizeNumberToken(input)).toBe(expected);
      });
    }
  });

  it('is idempotent on its own output for plain integers', () => {
    // The canonical form is itself a valid JSON number token.
    for (const input of ['1', '100', '0.1', '-1.5', '9007199254740993']) {
      const once = canonicalizeNumberToken(input);
      expect(canonicalizeNumberToken(once)).toBe(once);
    }
  });

  it('rejects a token that is not a valid JSON number', () => {
    expect(() => canonicalizeNumberToken('NaN')).toThrow(/valid JSON number/);
    expect(() => canonicalizeNumberToken('')).toThrow(/valid JSON number/);
  });
});

describe('string canonicalization', () => {
  const cases: readonly (readonly [string, string])[] = [
    ['', '""'],
    ['plain', '"plain"'],
    ['with "quotes"', '"with \\"quotes\\""'],
    ['back\\slash', '"back\\\\slash"'],
    ['tab\there', '"tab\\there"'],
    ['new\nline', '"new\\nline"'],
    ['carriage\rreturn', '"carriage\\rreturn"'],
    ['form\ffeed', '"form\\ffeed"'],
    ['back\bspace', '"back\\bspace"'],
    ['unitseparator', '"unit\\u0001separator"'],
  ];

  for (const [input, expected] of cases) {
    it(`escapes ${JSON.stringify(input)} minimally`, () => {
      expect(canonicalizeString(input)).toBe(expected);
    });
  }

  it('emits non ASCII literally rather than escaping it', () => {
    // RFC 8785 requires minimal escaping. Escaping would still be valid JSON but
    // would produce a different canonical form, and therefore a different hash,
    // than another conforming implementation.
    expect(canonicalizeString('世界')).toBe('"世界"');
    expect(canonicalizeString('café')).toBe('"café"');
  });

  it('does not escape the forward slash', () => {
    expect(canonicalizeString('a/b')).toBe('"a/b"');
  });

  it('preserves an emoji as a surrogate pair without corrupting it', () => {
    expect(canonicalizeString('flag \u{1F3F4}')).toBe('"flag \u{1F3F4}"');
  });
});

describe('key ordering', () => {
  it('sorts object keys', () => {
    expect(canonicalizeJsonText('{"b":1,"a":2}')).toBe('{"a":2e0,"b":1e0}');
  });

  it('produces the same canonical form regardless of source key order', () => {
    const a = canonicalizeJsonText('{"one":1,"two":2,"three":3}');
    const b = canonicalizeJsonText('{"three":3,"one":1,"two":2}');
    const c = canonicalizeJsonText('{"two":2,"three":3,"one":1}');
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('sorts by UTF-16 code unit, not by locale', () => {
    // A locale aware sort would order these differently on some machines, which
    // would make the hash depend on where it was computed.
    const canonical = canonicalizeJsonText('{"b":1,"B":2,"a":3,"A":4}');
    expect(canonical).toBe('{"A":4e0,"B":2e0,"a":3e0,"b":1e0}');
  });

  it('sorts nested objects too', () => {
    expect(canonicalizeJsonText('{"z":{"y":1,"x":2}}')).toBe('{"z":{"x":2e0,"y":1e0}}');
  });

  it('does not reorder arrays, where order is meaningful', () => {
    expect(canonicalizeJsonText('[3,1,2]')).toBe('[3e0,1e0,2e0]');
  });
});

describe('whitespace and structure', () => {
  it('removes insignificant whitespace', () => {
    const spaced = '{\n  "a" : 1 ,\n  "b" : [ 1 , 2 ]\n}';
    const tight = '{"a":1,"b":[1,2]}';
    expect(canonicalizeJsonText(spaced)).toBe(canonicalizeJsonText(tight));
  });

  it('handles empty containers', () => {
    expect(canonicalizeJsonText('{}')).toBe('{}');
    expect(canonicalizeJsonText('[]')).toBe('[]');
    expect(canonicalizeJsonText('{"a":{},"b":[]}')).toBe('{"a":{},"b":[]}');
  });

  it('handles deeply nested structures', () => {
    const nested = '{"a":{"b":{"c":{"d":{"e":[1,{"f":2}]}}}}}';
    expect(canonicalizeJsonText(nested)).toBe('{"a":{"b":{"c":{"d":{"e":[1e0,{"f":2e0}]}}}}}');
  });

  it('handles the literals', () => {
    expect(canonicalizeJsonText('[true,false,null]')).toBe('[true,false,null]');
  });
});

describe('golden vectors', () => {
  // A committed table of canonical input to expected hash. If a change to the
  // canonicalizer moves any of these, every previously written ledger entry
  // becomes unverifiable, so a diff here is a deliberate breaking change and
  // never an incidental one.
  const GOLDEN: readonly (readonly [string, string])[] = [
    ['{}', 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'],
    ['[]', 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'],
    ['null', 'sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b'],
    ['true', 'sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b'],
  ];

  for (const [input, expected] of GOLDEN) {
    it(`${input} hashes to a stable value`, () => {
      expect(hashJsonText(input)).toBe(expected);
    });
  }

  it('produces a well formed content hash', () => {
    const hash = hashJsonText('{"a":1}');
    expect(isContentHash(hash)).toBe(true);
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('rejects malformed content hashes', () => {
    expect(isContentHash('sha256:tooshort')).toBe(false);
    expect(isContentHash('a'.repeat(64))).toBe(false);
    expect(isContentHash('md5:' + 'a'.repeat(64))).toBe(false);
    expect(isContentHash('sha256:' + 'A'.repeat(64))).toBe(false);
  });
});

describe('hash equality reflects semantic equality', () => {
  it('reordering keys does not change the hash', () => {
    expect(hashJsonText('{"a":1,"b":2}')).toBe(hashJsonText('{"b":2,"a":1}'));
  });

  it('reformatting does not change the hash', () => {
    expect(hashJsonText('{"a":1}')).toBe(hashJsonText('{\n  "a": 1\n}'));
  });

  it('equivalent number spellings do not change the hash', () => {
    expect(hashJsonText('{"n":100}')).toBe(hashJsonText('{"n":1e2}'));
    expect(hashJsonText('{"n":1}')).toBe(hashJsonText('{"n":1.0}'));
  });

  it('any content change does change the hash', () => {
    const base = hashJsonText('{"name":"get_weather","required":["location"]}');

    const variants = [
      '{"name":"get_weather2","required":["location"]}',
      '{"name":"get_weather","required":["location","units"]}',
      '{"name":"get_weather","required":[]}',
      '{"name":"get_weather","required":["location"],"extra":1}',
      '{"name":"get_weather","required":"location"}',
    ];

    for (const variant of variants) {
      expect(hashJsonText(variant)).not.toBe(base);
    }
  });

  it('distinguishes a nested change deep in a schema', () => {
    const a = '{"inputSchema":{"properties":{"q":{"type":"string"}}}}';
    const b = '{"inputSchema":{"properties":{"q":{"type":"number"}}}}';
    expect(hashJsonText(a)).not.toBe(hashJsonText(b));
  });

  it('distinguishes a string from a number with the same digits', () => {
    expect(hashJsonText('{"v":1}')).not.toBe(hashJsonText('{"v":"1"}'));
  });

  it('distinguishes null from absent', () => {
    expect(hashJsonText('{"a":null}')).not.toBe(hashJsonText('{}'));
  });

  it('distinguishes an empty array from an empty object', () => {
    expect(hashJsonText('[]')).not.toBe(hashJsonText('{}'));
  });
});

describe('idempotence', () => {
  const samples = [
    '{"a":1,"b":[1,2,{"c":3}]}',
    '{"unicode":"世界","escape":"a\\nb"}',
    '{"nums":[0,-0,1.0,1e2,0.1,9007199254740993]}',
    '[]',
    '{}',
    'null',
  ];

  for (const sample of samples) {
    it(`canonicalizing twice equals canonicalizing once for ${sample.slice(0, 30)}`, () => {
      const once = canonicalizeJsonText(sample);
      const twice = canonicalizeJsonText(once);
      expect(twice).toBe(once);
    });
  }

  it('holds for randomly generated structures', () => {
    // Property: canonicalization is idempotent, and hash equality implies
    // canonical form equality, for arbitrary nested values.
    let seed = 0x2f6e2b1;
    const random = (): number => {
      // Deterministic xorshift, so a failure is reproducible rather than a
      // heisenbug that vanishes on the next run.
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return Math.abs(seed) / 0x7fffffff;
    };

    const build = (depth: number): unknown => {
      const roll = random();
      if (depth > 3 || roll < 0.3) {
        if (roll < 0.08) return null;
        if (roll < 0.14) return random() < 0.5;
        if (roll < 0.22) return Math.floor(random() * 1000);
        return `s${Math.floor(random() * 1000).toString()}`;
      }
      if (roll < 0.6) {
        return Array.from({ length: Math.floor(random() * 4) }, () => build(depth + 1));
      }
      const out: Record<string, unknown> = {};
      const count = Math.floor(random() * 5);
      for (let i = 0; i < count; i += 1) {
        out[`k${Math.floor(random() * 100).toString()}`] = build(depth + 1);
      }
      return out;
    };

    for (let i = 0; i < 200; i += 1) {
      const value = build(0);
      const text = JSON.stringify(value);
      const once = canonicalizeJsonText(text);
      expect(canonicalizeJsonText(once)).toBe(once);
      expect(hashCanonicalForm(once)).toBe(hashJsonText(text));
    }
  });
});

describe('canonicalizeValue for locally constructed values', () => {
  it('agrees with the text path for safe values', () => {
    const value = { b: 2, a: 'x', c: [1, true, null] };
    expect(canonicalizeValue(value)).toBe(canonicalizeJsonText(JSON.stringify(value)));
  });

  it('omits undefined members, matching JSON.stringify', () => {
    // An optional field must not change the hash merely by being present as
    // undefined, or every optional field would break drift detection.
    expect(canonicalizeValue({ a: 1, b: undefined })).toBe(canonicalizeValue({ a: 1 }));
  });

  it('accepts a bigint, preserving full precision', () => {
    expect(canonicalizeValue({ n: 9007199254740993n })).toBe('{"n":9.007199254740993e15}');
  });

  it('refuses an unsafe integer rather than silently rounding it', () => {
    // By this point the value has already lost precision. Throwing is the only
    // honest option: silently hashing the rounded value would mean the ledger
    // records something the server never sent.
    // The precision loss the linter warns about here is the entire point of the
    // test: this literal becomes 9007199254740992 at runtime, which is exactly
    // the corruption canonicalizeValue must refuse to hash.
    // eslint-disable-next-line no-loss-of-precision
    expect(() => canonicalizeValue({ n: 9007199254740993 })).toThrow(/safe range/);
  });

  it('refuses non finite numbers', () => {
    expect(() => canonicalizeValue({ n: NaN })).toThrow(/non finite/);
    expect(() => canonicalizeValue({ n: Infinity })).toThrow(/non finite/);
  });

  it('refuses values JSON cannot represent', () => {
    expect(() => canonicalizeValue({ fn: () => 1 })).toThrow(/Cannot canonicalize/);
    expect(() => canonicalizeValue({ sym: Symbol('x') })).toThrow(/Cannot canonicalize/);
  });

  it('names the path of the offending value', () => {
    expect(() => canonicalizeValue({ outer: { inner: [1, NaN] } })).toThrow(
      /\$\.outer\.inner\[1\]/,
    );
  });

  it('hashes consistently with the text path', () => {
    const value = { name: 'get_weather', ttlMs: 3600000 };
    expect(hashValue(value)).toBe(hashJsonText(JSON.stringify(value)));
  });
});

describe('parser strictness', () => {
  const invalid = [
    ['trailing comma in object', '{"a":1,}'],
    ['trailing comma in array', '[1,2,]'],
    ['single quotes', "{'a':1}"],
    ['unquoted key', '{a:1}'],
    ['leading zero', '{"a":01}'],
    ['leading plus', '{"a":+1}'],
    ['bare decimal point', '{"a":.5}'],
    ['trailing decimal point', '{"a":1.}'],
    ['NaN', '{"a":NaN}'],
    ['Infinity', '{"a":Infinity}'],
    ['comment', '{"a":1} // note'],
    ['unterminated string', '{"a":"x}'],
    ['unterminated object', '{"a":1'],
    ['empty input', ''],
    ['bare word', 'undefined'],
    ['duplicate key', '{"a":1,"a":2}'],
    ['raw control character in string', '{"a":"line\nbreak"}'],
    ['invalid escape', '{"a":"\\x"}'],
    ['bad unicode escape', '{"a":"\\u12"}'],
  ] as const;

  for (const [name, text] of invalid) {
    it(`rejects ${name}`, () => {
      expect(() => parseJsonPreservingNumbers(text)).toThrow();
    });
  }

  it('rejects a duplicate key rather than picking a winner', () => {
    // Last-wins and first-wins produce different hashes for identical bytes.
    // There is no honest way to choose, so this is refused.
    expect(() => parseJsonPreservingNumbers('{"a":1,"a":2}')).toThrow(/duplicate/);
  });

  it('rejects nesting beyond the depth limit rather than blowing the stack', () => {
    const deep = '['.repeat(600) + ']'.repeat(600);
    expect(() => parseJsonPreservingNumbers(deep)).toThrow(/nesting depth/);
  });

  it('accepts nesting within the depth limit', () => {
    const ok = '['.repeat(100) + ']'.repeat(100);
    expect(() => parseJsonPreservingNumbers(ok)).not.toThrow();
  });

  it('does not let a __proto__ key pollute the prototype', () => {
    parseJsonPreservingNumbers('{"__proto__":{"polluted":true}}');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('keeps a __proto__ key as ordinary data in the canonical form', () => {
    // Defusing prototype pollution must not mean dropping the key. A server
    // that advertises a tool named __proto__ has to be recorded faithfully,
    // or the ledger would not reflect what was actually served.
    const canonical = canonicalizeJsonText('{"__proto__":{"polluted":true}}');
    expect(canonical).toBe('{"__proto__":{"polluted":true}}');
  });
});
