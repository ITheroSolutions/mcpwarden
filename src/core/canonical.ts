/**
 * Deterministic JSON canonicalization and hashing.
 *
 * In the spirit of RFC 8785 (JSON Canonicalization Scheme): object keys sorted,
 * no insignificant whitespace, minimal string escaping, stable Unicode handling.
 * One deliberate and documented deviation, on numbers. See below.
 *
 * Everything the ledger and the drift diff rest on comes through here, so the
 * property that matters is narrow and absolute: two inputs hash the same if and
 * only if they are semantically the same JSON value.
 *
 * ## The number deviation, and why
 *
 * RFC 8785 serialises numbers using ECMAScript `Number::toString`, which means
 * round tripping through an IEEE 754 double. That is wrong for this package.
 * `9007199254740993` and `9007199254740992` are different integers that both
 * become `9007199254740992` as doubles, so a tool schema could change in a way a
 * double cannot represent and the hash would not move. A trust ledger that cannot
 * see a change is not a trust ledger.
 *
 * So numbers are normalised from their **source token** into a canonical
 * scientific form with no precision loss:
 *
 * | Input | Canonical form |
 * | --- | --- |
 * | `1`, `1.0`, `1.000` | `1e0` |
 * | `100`, `1e2`, `1.0E+2` | `1e2` |
 * | `0`, `-0`, `0.0` | `0` |
 * | `0.1` | `1e-1` |
 * | `9007199254740993` | `9.007199254740993e15` |
 *
 * Semantically identical values collapse to the same form. Semantically distinct
 * values never do, however many digits they carry.
 *
 * Negative zero canonicalises to `0`, matching RFC 8785. JSON has no way to
 * express a distinction between the two that any consumer could act on, and
 * treating them as different would make a hash change on a round trip through
 * almost any JSON library.
 */

import { createHash } from 'node:crypto';

import { InternalError } from './errors.js';
import {
  isJsonNumber,
  parseJsonPreservingNumbers,
  type JsonObject,
  type JsonValue,
} from './json-parse.js';

/**
 * A content hash, always rendered with its algorithm prefix.
 *
 * The prefix is not decoration. The redaction module recognises `sha256:` as a
 * trusted own-value and leaves it alone; a bare 64 character hex run would be
 * swept up by the high entropy heuristic and silently destroyed.
 */
export type ContentHash = `sha256:${string}`;

export function isContentHash(value: string): value is ContentHash {
  return /^sha256:[a-f0-9]{64}$/.test(value);
}

/**
 * Canonicalize a number token.
 *
 * Works entirely on the decimal string. No `Number` conversion happens anywhere in
 * this function, which is the whole point.
 */
export function canonicalizeNumberToken(token: string): string {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (match === null) {
    throw new InternalError(`Not a valid JSON number token: ${JSON.stringify(token)}`);
  }

  const sign = match[1] === '-' ? '-' : '';
  const integerPart = match[2] ?? '';
  const fractionPart = match[3] ?? '';
  const exponentPart = match[4] ?? '0';

  // All significant digits, with the decimal point removed. The exponent is
  // adjusted to compensate for the digits that were after the point.
  const digits = integerPart + fractionPart;
  let exponent = Number(exponentPart) - fractionPart.length;

  // Strip leading zeros. "000123" and "123" are the same digit string.
  const withoutLeadingZeros = digits.replace(/^0+/, '');

  // Every digit was a zero, so the value is zero. Negative zero collapses here
  // too, which is deliberate: JSON offers no distinction a consumer could use.
  if (withoutLeadingZeros === '') return '0';

  // Strip trailing zeros, moving them into the exponent. This is what makes
  // `100`, `1e2` and `1.00e2` land on the same canonical form.
  const trailingZeros = /0*$/.exec(withoutLeadingZeros)?.[0].length ?? 0;
  const mantissaDigits = withoutLeadingZeros.slice(
    0,
    withoutLeadingZeros.length - trailingZeros,
  );
  exponent += trailingZeros;

  // Normalised scientific form: exactly one digit before the point, and the
  // exponent counts from there.
  exponent += mantissaDigits.length - 1;

  const mantissa =
    mantissaDigits.length === 1
      ? mantissaDigits
      : `${mantissaDigits[0] ?? ''}.${mantissaDigits.slice(1)}`;

  return `${sign}${mantissa}e${String(exponent)}`;
}

/**
 * Escape a string per RFC 8785.
 *
 * Minimal escaping: only what JSON requires, using the two character forms where
 * they exist and `\u00xx` for the remaining control characters. Everything else,
 * including non ASCII, is emitted literally as UTF-8. Lone surrogates are passed
 * through unchanged rather than replaced, so canonicalization never alters the
 * content it is supposed to be measuring.
 */
export function canonicalizeString(value: string): string {
  let out = '"';

  for (const ch of value) {
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      default: {
        const code = ch.codePointAt(0) ?? 0;
        out += code < 0x20 ? `\\u${code.toString(16).padStart(4, '0')}` : ch;
      }
    }
  }

  return out + '"';
}

/**
 * Sort object keys by UTF-16 code unit, as RFC 8785 requires.
 *
 * `Array.prototype.sort` with the default comparator already orders by UTF-16 code
 * unit, but relying on that implicitly would leave the requirement invisible. The
 * comparator is written out so the intent survives a future refactor, and so it is
 * obvious that this is not a locale aware comparison. `localeCompare` here would
 * make hashes depend on the machine's locale.
 */
function compareKeys(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * Narrow a {@link JsonValue} to an array.
 *
 * `Array.isArray` alone does not remove `readonly JsonValue[]` from the union in
 * the negative branch, so the object branch below would still see an array in its
 * type. This guard states the intent explicitly and narrows both ways.
 */
function isJsonArray(value: JsonValue): value is readonly JsonValue[] {
  return Array.isArray(value);
}

/** Canonicalize a parsed JSON value into its canonical text form. */
export function canonicalizeJsonValue(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return canonicalizeString(value);

  if (isJsonNumber(value)) return canonicalizeNumberToken(value.token);

  if (isJsonArray(value)) {
    return `[${value.map(canonicalizeJsonValue).join(',')}]`;
  }

  const record: JsonObject = value;
  const keys = Object.keys(record).sort(compareKeys);

  const members: string[] = [];
  for (const key of keys) {
    const entry = record[key];
    /* c8 ignore next -- keys come from Object.keys, so this cannot be missing */
    if (entry === undefined) continue;
    members.push(`${canonicalizeString(key)}:${canonicalizeJsonValue(entry)}`);
  }

  return `{${members.join(',')}}`;
}

/**
 * Canonicalize raw JSON text.
 *
 * This is the entry point for anything that arrived over the wire, because it is
 * the only path that preserves number fidelity.
 */
export function canonicalizeJsonText(text: string): string {
  return canonicalizeJsonValue(parseJsonPreservingNumbers(text));
}

/**
 * Canonicalize a JavaScript value.
 *
 * Convenience for values this package constructs itself, such as ledger entries.
 *
 * **Lossy for numbers outside the safe integer range**, because the value has
 * already been through a double by the time it arrives here and the original
 * token no longer exists. Anything that came from a server must use
 * {@link canonicalizeJsonText} instead. To make that impossible to get wrong by
 * accident, an unsafe integer throws rather than being silently rounded.
 */
export function canonicalizeValue(value: unknown): string {
  return canonicalizeJsonValue(toJsonValue(value, '$'));
}

function toJsonValue(value: unknown, path: string): JsonValue {
  if (value === null) return null;

  switch (typeof value) {
    case 'boolean':
    case 'string':
      return value;

    case 'number': {
      if (!Number.isFinite(value)) {
        throw new InternalError(`Cannot canonicalize a non finite number at ${path}`, {
          details: { path },
        });
      }
      if (!Number.isSafeInteger(value) && Number.isInteger(value)) {
        throw new InternalError(
          `Integer at ${path} exceeds the safe range and has already lost precision. ` +
            'Canonicalize from the original JSON text instead.',
          { details: { path } },
        );
      }
      // Number::toString gives the shortest representation that round trips,
      // which the token normaliser then folds into canonical form.
      return { __jsonNumber: true, token: numberToJsonToken(value) };
    }

    case 'bigint':
      return { __jsonNumber: true, token: value.toString() };

    case 'object': {
      if (Array.isArray(value)) {
        return value.map((item, index) => toJsonValue(item, `${path}[${String(index)}]`));
      }

      const out: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
      for (const [key, entry] of Object.entries(value)) {
        // `undefined` members are omitted, matching JSON.stringify. A key whose
        // value is absent and a key that is not present must canonicalize the
        // same way, or an optional field would change the hash by existing.
        if (entry === undefined) continue;
        out[key] = toJsonValue(entry, `${path}.${key}`);
      }
      return out;
    }

    default:
      throw new InternalError(`Cannot canonicalize a ${typeof value} at ${path}`, {
        details: { path, type: typeof value },
      });
  }
}

/**
 * Render a JavaScript number as a JSON number token.
 *
 * `toString` produces `1e+21` style output for large magnitudes, which is valid
 * JSON, and plain decimal otherwise. Both are accepted by the token normaliser.
 */
function numberToJsonToken(value: number): string {
  return Object.is(value, -0) ? '-0' : value.toString();
}

/** SHA-256 of a canonical form, rendered with its algorithm prefix. */
export function hashCanonicalForm(canonical: string): ContentHash {
  const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

/** Canonicalize raw JSON text and hash it. */
export function hashJsonText(text: string): ContentHash {
  return hashCanonicalForm(canonicalizeJsonText(text));
}

/** Canonicalize a locally constructed value and hash it. */
export function hashValue(value: unknown): ContentHash {
  return hashCanonicalForm(canonicalizeValue(value));
}
