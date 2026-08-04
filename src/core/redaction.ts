/**
 * Redaction.
 *
 * Every string leaving this package toward a report, a log line, a ledger entry or
 * an error message passes through {@link redact} first. This is the highest
 * consequence module here: a miss writes somebody's credential into a file they
 * will commit, and a ledger is append-only, so a leaked secret cannot be recalled.
 *
 * Two properties are held deliberately in tension.
 *
 * **Never leak.** When in doubt, redact. A false positive costs a reader some
 * context. A false negative costs a user their credential.
 *
 * **Stay useful.** Output preserves the shape of what was removed and carries a
 * stable fingerprint, so the same secret is recognisable across two reports without
 * ever being exposed. `sk-REDACTED-4f2a1c9b` in Monday's report and in Friday's
 * report is the same key.
 *
 * ## What the fingerprint does and does not give you
 *
 * The fingerprint is the leading bytes of a SHA-256 digest of the secret. It lets a
 * reader correlate. It does not let a reader recover: inverting it means inverting
 * SHA-256.
 *
 * It does let somebody who already has a *candidate* secret confirm that candidate
 * against a report. That is an accepted and documented tradeoff, not an oversight.
 * Correlation across reports is the whole point of the fingerprint, and any
 * construction that provides it also provides confirmation. Anyone holding both a
 * report and a guessed credential already has the credential.
 */

import { createHash } from 'node:crypto';

/**
 * Length in hex characters of the fingerprint appended to a redaction token.
 *
 * Eight rather than four. Four is enough to look right in a single report but
 * collides at roughly even odds once a few hundred distinct secrets are in play,
 * and a colliding fingerprint actively misleads: it tells a reader two different
 * credentials are the same one. Eight pushes that far past any realistic report.
 */
const FINGERPRINT_LENGTH = 8;

/** Minimum length before an environment variable's value is treated as a secret. */
const MIN_ENV_SECRET_LENGTH = 8;

/** Minimum run length before an undifferentiated blob is treated as high entropy. */
const DEFAULT_MIN_BLOB_LENGTH = 32;

export interface RedactionOptions {
  /**
   * Literal values to remove wherever they appear, in addition to those detected
   * by pattern. Typically the values of environment variables whose names look
   * secret; see {@link collectEnvSecrets}.
   */
  readonly extraSecrets?: readonly string[];

  /**
   * Minimum length for the generic high entropy blob heuristics. Below this,
   * base64 and hex runs are left alone. Defaults to 32.
   */
  readonly minBlobLength?: number;

  /**
   * Whether to apply the generic high entropy heuristics at all. Defaults to true.
   * Turning this off keeps the targeted patterns (PEM blocks, known key prefixes,
   * bearer tokens, connection strings) and drops only the catch-all.
   *
   * There is no legitimate reason to disable this for untrusted input. It exists
   * for rendering text that is known to be locally generated.
   */
  readonly entropyHeuristics?: boolean;
}

/**
 * Environment variable names whose values are treated as secrets.
 *
 * Deliberately broad. The cost of treating a non secret environment value as a
 * secret is a redacted string in a report. The cost of the reverse is a leaked
 * credential.
 */
export const SECRET_ENV_NAME_PATTERN =
  /(^|_)(SECRET|TOKEN|PASSWORD|PASSWD|PWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH|CREDENTIAL|CREDENTIALS|SESSION|COOKIE|SIGNING_KEY|ENCRYPTION_KEY|PASSPHRASE|BEARER|OAUTH|REFRESH_TOKEN|SALT|DSN|CONNECTION_STRING)($|_)/i;

/**
 * Environment variable names that match {@link SECRET_ENV_NAME_PATTERN} but are
 * known to carry non secret values. Without these, common configuration ends up
 * redacted and reports become unreadable.
 */
const SECRET_ENV_NAME_EXCEPTIONS = new Set([
  'AUTH_TYPE',
  'AUTH_MODE',
  'AUTH_ENABLED',
  'AUTH_REQUIRED',
  'TOKEN_TYPE',
  'SESSION_TIMEOUT',
  'SESSION_TTL',
  'CREDENTIAL_PROCESS',
  'OAUTH_SCOPE',
  'OAUTH_SCOPES',
]);

/**
 * Stable fingerprint for a secret value.
 *
 * Deterministic across processes and machines, so the same credential produces the
 * same token in every report. See the module comment for what this does and does
 * not disclose.
 */
export function redactionFingerprint(secret: string): string {
  return createHash('sha256').update(secret, 'utf8').digest('hex').slice(0, FINGERPRINT_LENGTH);
}

/**
 * Build a redaction token that keeps the recognisable shape of what was removed.
 *
 * @param label short shape hint, for example `sk` for an OpenAI style key or
 * `PRIVATE-KEY` for a PEM block.
 * @param secret the value being removed, used only to derive the fingerprint.
 */
function token(label: string, secret: string): string {
  return `${label}-REDACTED-${redactionFingerprint(secret)}`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * True when a captured value has already been dealt with and must be left alone.
 *
 * Two cases. It is a token this pass already emitted, or it is a parked
 * placeholder standing in for one. Both matter because several patterns capture a
 * *positional* value rather than a recognisable one: the connection string rule
 * treats whatever sits between `:` and `@` as a password, and on a second pass
 * that is the token from the first pass. Without this guard the fingerprint
 * changes on every pass and cross-report correlation breaks.
 */
function alreadyHandled(value: string): boolean {
  return value.includes('REDACTED') || value.includes(PARK_SENTINEL);
}

/**
 * Known credential prefixes, longest first so that `sk-ant-` wins over `sk-`.
 *
 * Each entry is a literal prefix and the character class that may follow it. These
 * are matched ahead of the generic heuristics so the token keeps a useful label:
 * `sk-REDACTED-...` tells a reader which vendor's key leaked, which is exactly what
 * they need in order to rotate it.
 */
const PREFIXED_KEY_PATTERNS: readonly { readonly label: string; readonly pattern: RegExp }[] = [
  // Anthropic
  { label: 'sk-ant', pattern: /\bsk-ant-[A-Za-z0-9_-]{16,}/g },
  // OpenAI, including project and service account forms
  { label: 'sk-proj', pattern: /\bsk-proj-[A-Za-z0-9_-]{16,}/g },
  { label: 'sk', pattern: /\bsk-[A-Za-z0-9_-]{16,}/g },
  // GitHub
  { label: 'github_pat', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/g },
  { label: 'gh', pattern: /\bgh[pousr]_[A-Za-z0-9]{16,}/g },
  // Slack
  { label: 'xox', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  { label: 'xapp', pattern: /\bxapp-[A-Za-z0-9-]{10,}/g },
  // AWS access key ids. The matching secret key is caught by the blob heuristic.
  { label: 'AWS-KEY-ID', pattern: /\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b/g },
  // Google
  { label: 'AIza', pattern: /\bAIza[A-Za-z0-9_-]{20,}/g },
  { label: 'google-oauth', pattern: /\bya29\.[A-Za-z0-9_-]{20,}/g },
  // GitLab
  { label: 'glpat', pattern: /\bglpat-[A-Za-z0-9_-]{16,}/g },
  // Package registries
  { label: 'npm', pattern: /\bnpm_[A-Za-z0-9]{30,}/g },
  { label: 'pypi', pattern: /\bpypi-[A-Za-z0-9_-]{16,}/g },
  // Stripe
  { label: 'stripe', pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  // DigitalOcean
  { label: 'do', pattern: /\bdop_v1_[a-f0-9]{32,}/g },
  // Hugging Face, Replicate
  { label: 'hf', pattern: /\bhf_[A-Za-z0-9]{16,}/g },
  { label: 'r8', pattern: /\br8_[A-Za-z0-9]{16,}/g },
];

/** PEM encoded private key and certificate blocks, including the delimiters. */
const PEM_BLOCK =
  /-----BEGIN[ A-Z0-9]*(?:PRIVATE KEY|RSA PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK|ENCRYPTED PRIVATE KEY)-----[\s\S]*?-----END[ A-Z0-9]*(?:PRIVATE KEY|RSA PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK|ENCRYPTED PRIVATE KEY)-----/g;

/** JSON Web Tokens. Three base64url segments separated by dots. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

/**
 * Credentials embedded in a URL userinfo component, for example
 * `postgres://user:hunter2@db.internal:5432/app`.
 *
 * Only the password is removed. The scheme, user and host are the parts an operator
 * needs in order to identify which connection string this was.
 */
const CONNECTION_STRING_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;

/** `Authorization: Bearer <token>` and bare `Bearer <token>`. */
const BEARER = /\b(Bearer|Basic|Token|ApiKey)\s+([A-Za-z0-9._~+/=-]{12,})/gi;

/**
 * `key=value` and `"key": "value"` pairs whose key name looks secret.
 *
 * Covers query strings, `.env` lines, JSON config and CLI arguments in one pattern
 * by treating `=` and `:` as interchangeable separators.
 */
const SECRET_ASSIGNMENT =
  /\b([A-Za-z0-9_.-]*(?:secret|token|password|passwd|pwd|apikey|api_key|access_key|private_key|client_secret|credential|passphrase|auth)[A-Za-z0-9_.-]*)(\s*[=:]\s*"?)([^\s"'&,;}]{6,})/gi;

/**
 * Our own content hashes, which must survive redaction untouched.
 *
 * A surface merkle root is 64 hex characters and would otherwise be eaten by the
 * high entropy hex heuristic, silently destroying the ledger's readability. Hashes
 * are always rendered with this prefix so the redactor can recognise them.
 */
const OWN_HASH = /\bsha256:[a-f0-9]{64}\b/g;

/**
 * A redaction token this module already emitted.
 *
 * These must be immune to a second pass. Without this, `sk-REDACTED-41b69fc4` is
 * itself matched by the `sk-` vendor prefix pattern and gets redacted again,
 * producing a different fingerprint every time and breaking the one property the
 * whole design rests on: that the same secret yields the same token everywhere.
 */
const EXISTING_TOKEN = /\b[A-Za-z0-9_-]*REDACTED-[a-f0-9]{8}\b/g;

/**
 * Sentinel used to park text that later patterns must not touch.
 *
 * NUL is used because no legitimate protocol string or configuration value
 * contains it, and no pattern in this module matches it. Any NUL already present
 * in the input is stripped first so the sentinel cannot be forged by a hostile
 * server trying to smuggle text past redaction.
 */
const PARK_SENTINEL = '\u0000';

const HEX_BLOB = (min: number): RegExp => new RegExp(`\\b[a-f0-9]{${String(min)},}\\b`, 'gi');

/**
 * Base64 and base64url runs.
 *
 * Requires a mix of character classes so that ordinary long identifiers, which are
 * usually all lowercase or snake case, are not swept up. `getVeryLongToolNameHere`
 * stays readable; `dGhpcyBpcyBhIHNlY3JldA==` does not.
 */
const BASE64_BLOB = (min: number): RegExp =>
  new RegExp(`\\b(?=[A-Za-z0-9+/_-]*[A-Z])(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[0-9])[A-Za-z0-9+/_-]{${String(min)},}={0,2}`, 'g');

/**
 * Collect secret values from an environment.
 *
 * Returns the *values* of variables whose names look secret, filtered to those long
 * enough to be worth removing. Short values such as `1`, `true` or `dev` are
 * excluded: redacting them would strip those substrings out of unrelated text
 * everywhere and make reports nonsense.
 *
 * The names themselves are never treated as secret, only the values.
 */
export function collectEnvSecrets(env: Readonly<Record<string, string | undefined>>): string[] {
  const secrets: string[] = [];

  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (value.length < MIN_ENV_SECRET_LENGTH) continue;
    if (SECRET_ENV_NAME_EXCEPTIONS.has(name.toUpperCase())) continue;
    if (!SECRET_ENV_NAME_PATTERN.test(name)) continue;
    secrets.push(value);
  }

  return secrets;
}

/**
 * Redact a single string.
 *
 * Ordering is load bearing and runs from most specific to least:
 *
 * 1. Protect our own content hashes so later heuristics cannot eat them.
 * 2. Exact known secret values, longest first, so a longer secret containing a
 *    shorter one is replaced as a whole.
 * 3. PEM blocks, which span lines and would otherwise be shredded piecewise.
 * 4. Connection string credentials, keeping scheme, user and host.
 * 5. Bearer and similar authorization schemes.
 * 6. Known vendor key prefixes, which yield the most useful labels.
 * 7. JSON Web Tokens.
 * 8. Assignments whose key name looks secret.
 * 9. Generic high entropy blobs, the catch-all.
 */
export function redact(input: string, options: RedactionOptions = {}): string {
  if (input.length === 0) return input;

  const minBlob = options.minBlobLength ?? DEFAULT_MIN_BLOB_LENGTH;
  const useEntropy = options.entropyHeuristics ?? true;

  // Step 1. Park anything later steps must not touch, behind a sentinel that no
  // pattern here matches, and restore it at the end.
  //
  // Two kinds of text are parked. Our own content hashes, which the high entropy
  // hex heuristic would otherwise eat. And redaction tokens this module already
  // emitted, which the vendor prefix patterns would otherwise match: without this,
  // `sk-REDACTED-41b69fc4` is itself a valid `sk-` match, so a second pass yields a
  // different fingerprint and destroys the cross-report stability the whole design
  // rests on.
  //
  // Any NUL already present in the input is dropped first, so a hostile server
  // cannot forge a sentinel and smuggle text past the patterns below.
  const parked: string[] = [];
  const park = (match: string): string => {
    parked.push(match);
    return `${PARK_SENTINEL}${String(parked.length - 1)}${PARK_SENTINEL}`;
  };

  let text = input.split(PARK_SENTINEL).join('');
  text = text.replace(OWN_HASH, park);
  text = text.replace(EXISTING_TOKEN, park);

  // Step 2. Exact known values, longest first.
  const exact = [...(options.extraSecrets ?? [])]
    .filter((s) => s.length >= MIN_ENV_SECRET_LENGTH)
    .sort((a, b) => b.length - a.length);

  for (const secret of exact) {
    text = text.replace(new RegExp(escapeRegExp(secret), 'g'), token('ENV', secret));
  }

  // Step 3. PEM blocks.
  text = text.replace(PEM_BLOCK, (match) => `[${token('PRIVATE-KEY', match)}]`);

  // Step 4. Connection string credentials. Scheme, user and host survive.
  text = text.replace(
    CONNECTION_STRING_USERINFO,
    (match, scheme: string, user: string, password: string) =>
      alreadyHandled(password) ? match : `${scheme}${user}:${token('PW', password)}@`,
  );

  // Step 5. Authorization schemes.
  text = text.replace(BEARER, (match, scheme: string, value: string) =>
    alreadyHandled(value) ? match : `${scheme} ${token('AUTH', value)}`,
  );

  // Step 6. Known vendor prefixes.
  for (const { label, pattern } of PREFIXED_KEY_PATTERNS) {
    text = text.replace(pattern, (match) => (alreadyHandled(match) ? match : token(label, match)));
  }

  // Step 7. JSON Web Tokens.
  text = text.replace(JWT, (match) => (alreadyHandled(match) ? match : token('JWT', match)));

  // Step 8. Secret shaped assignments.
  text = text.replace(
    SECRET_ASSIGNMENT,
    (match, key: string, separator: string, value: string) =>
      alreadyHandled(value) ? match : `${key}${separator}${token('VALUE', value)}`,
  );

  // Step 9. Generic high entropy blobs.
  if (useEntropy) {
    text = text.replace(BASE64_BLOB(minBlob), (match) =>
      alreadyHandled(match) ? match : token('B64', match),
    );
    text = text.replace(HEX_BLOB(minBlob), (match) =>
      alreadyHandled(match) ? match : token('HEX', match),
    );
  }

  // Restore everything parked in step 1.
  //
  // The control character is the point: NUL is the one byte that cannot appear
  // in a protocol string or a configuration value, which is exactly what makes
  // it safe as a parking sentinel. Input NULs are stripped above so a hostile
  // server cannot forge one.
  // eslint-disable-next-line no-control-regex
  text = text.replace(/\u0000(\d+)\u0000/g, (_match, index: string) => {
    const restored = parked[Number(index)];
    /* c8 ignore next -- unreachable: indices come from our own parking pass */
    return restored ?? '';
  });

  return text;
}

/**
 * Recursively redact every string in a value, preserving structure.
 *
 * Object *keys* are redacted too. A configuration file can put a credential in a
 * key name, and a report that renders keys verbatim would leak it.
 *
 * Non string primitives pass through unchanged: a number cannot carry a credential
 * in any shape this package produces, and rewriting numbers would corrupt the
 * cache and ledger fields that carry them.
 */
export function redactDeep<T>(value: T, options: RedactionOptions = {}): T {
  return redactUnknown(value, options) as T;
}

function redactUnknown(value: unknown, options: RedactionOptions): unknown {
  if (typeof value === 'string') return redact(value, options);

  if (Array.isArray(value)) {
    return value.map((entry) => redactUnknown(entry, options));
  }

  if (value !== null && typeof value === 'object') {
    // Preserve the prototype-free shape of parsed JSON rather than inheriting
    // Object.prototype, so a key such as "__proto__" cannot alter behaviour.
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, entry] of Object.entries(value)) {
      out[redact(key, options)] = redactUnknown(entry, options);
    }
    return out;
  }

  return value;
}

/**
 * Assert that a string carries no recognisable credential.
 *
 * Used by tests and by the report renderers' own guard rails. Returns the offending
 * substring when the input still looks like it contains a secret, or `undefined`
 * when it is clean.
 */
export function findResidualSecret(input: string): string | undefined {
  const probes: readonly RegExp[] = [
    PEM_BLOCK,
    JWT,
    ...PREFIXED_KEY_PATTERNS.map((p) => p.pattern),
  ];

  for (const probe of probes) {
    // Regexes carry the global flag, so reset before reuse.
    probe.lastIndex = 0;
    const match = probe.exec(input);
    if (match && !match[0].includes('REDACTED')) return match[0];
  }

  return undefined;
}
