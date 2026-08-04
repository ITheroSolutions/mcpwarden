/**
 * Parsing client configuration into a normalised shape.
 *
 * Every client writes a slightly different file. The job here is to reduce all of
 * them to one `ServerRef` shape without losing the two things an operator
 * actually needs: which client registered a server, and whether a credential was
 * written into the file itself.
 *
 * ## The inline credential problem
 *
 * A server entry like `"env": { "GITHUB_TOKEN": "ghp_realtoken" }` puts a live
 * credential in a file that is frequently inside a synced directory and
 * occasionally inside a git repository. That is a finding in its own right, and
 * detecting it is one of the main reasons this package reads these files at all.
 *
 * It has to be distinguished from `"env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }`,
 * which is a reference and entirely fine. The distinction is made structurally,
 * on the shape of the value, never by connecting to anything.
 */

import { DiscoveryError } from '../core/errors.js';
import { redactionFingerprint, SECRET_ENV_NAME_PATTERN } from '../core/redaction.js';
import type { AuthPosture, RegistrationSite, ServerEndpoint, ServerRef } from '../core/types.js';
import type { ClientDefinition, ConfigShape } from './clients.js';

/** One server as it appeared in one file, before deduplication. */
export interface ParsedRegistration {
  readonly name: string;
  readonly endpoint: ServerEndpoint;
  readonly authPosture: AuthPosture;
  readonly site: RegistrationSite;
  /** Fingerprints of any credentials found inline, so two files can be compared. */
  readonly inlineCredentialFingerprints: readonly string[];
  /** Keys present in the entry that this parser did not recognise. */
  readonly unknownFields: readonly string[];
}

const SHAPE_KEYS: Readonly<Record<ConfigShape, string>> = {
  mcpServers: 'mcpServers',
  servers: 'servers',
  context_servers: 'context_servers',
};

const KNOWN_ENTRY_FIELDS = new Set([
  'command',
  'args',
  'env',
  'cwd',
  'url',
  'type',
  'transport',
  'headers',
  'disabled',
  'enabled',
  'autoApprove',
  'alwaysAllow',
  'timeout',
  'description',
  'source',
  'settings',
]);

/**
 * A value that references an environment variable rather than carrying a secret.
 *
 * Covers `${VAR}`, `$VAR`, `%VAR%` and the empty string, which clients use to mean
 * "inherit from the ambient environment".
 */
const ENV_REFERENCE = /^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%|)$/;

/**
 * Decide whether a configuration value is a literal credential.
 *
 * Structural, never semantic. A value is inline if its key looks secret and the
 * value is neither an environment reference nor obviously non secret. Short values
 * are excluded because a flag like `"1"` under a key named `AUTH_MODE` is not a
 * credential and reporting it as one would train people to ignore the finding.
 */
export function isInlineCredential(key: string, value: string): boolean {
  if (ENV_REFERENCE.test(value)) return false;
  if (value.length < 8) return false;

  SECRET_ENV_NAME_PATTERN.lastIndex = 0;
  if (SECRET_ENV_NAME_PATTERN.test(key)) return true;

  // An Authorization style header value carries a credential regardless of the
  // key naming convention in use.
  return /^(Bearer|Basic|Token)\s+\S+/i.test(value);
}

function parseEndpoint(
  name: string,
  entry: Record<string, unknown>,
  configPath: string,
): ServerEndpoint {
  const command = entry['command'];
  const url = entry['url'];

  if (typeof command === 'string' && command.length > 0) {
    const rawArgs = entry['args'];
    const args = Array.isArray(rawArgs)
      ? rawArgs.filter((a): a is string => typeof a === 'string')
      : [];

    const env = entry['env'];
    const envNames =
      typeof env === 'object' && env !== null && !Array.isArray(env) ? Object.keys(env) : [];

    const cwd = entry['cwd'];

    return {
      transport: 'stdio',
      command,
      args,
      envNames,
      ...(typeof cwd === 'string' ? { cwd } : {}),
    };
  }

  if (typeof url === 'string' && url.length > 0) {
    const headers = entry['headers'];
    const headerNames =
      typeof headers === 'object' && headers !== null && !Array.isArray(headers)
        ? Object.keys(headers)
        : [];

    return { transport: 'http', url, headerNames };
  }

  throw new DiscoveryError(
    `Server ${JSON.stringify(name)} has neither a command nor a url`,
    { details: { name, configPath } },
  );
}

/**
 * Classify how a server authenticates, from the configuration alone.
 *
 * `unknown` is a real answer and is used rather than guessing. A server with no
 * credentials visible in its configuration may still authenticate through an
 * ambient mechanism this cannot see, and claiming `none` would overstate what was
 * actually established.
 */
function classifyAuth(
  entry: Record<string, unknown>,
  inlineFound: boolean,
  envNames: readonly string[],
  headerNames: readonly string[],
): AuthPosture {
  if (inlineFound) return 'inline';

  const url = entry['url'];
  if (typeof url === 'string' && /\boauth\b/i.test(url)) return 'oauth';

  const secretNamed = [...envNames, ...headerNames].some((name) => {
    SECRET_ENV_NAME_PATTERN.lastIndex = 0;
    return SECRET_ENV_NAME_PATTERN.test(name);
  });

  if (secretNamed) return 'env';
  if (envNames.length === 0 && headerNames.length === 0) return 'none';

  return 'unknown';
}

/**
 * Parse one client configuration file.
 *
 * @param text the raw file contents.
 * @param client which client's format to expect.
 * @param configPath absolute path, recorded on every registration.
 */
export function parseClientConfig(
  text: string,
  client: ClientDefinition,
  configPath: string,
): readonly ParsedRegistration[] {
  let document: unknown;

  try {
    document = JSON.parse(text);
  } catch (cause) {
    throw new DiscoveryError(`${configPath} is not valid JSON`, {
      details: { configPath, client: client.id },
      cause,
    });
  }

  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    throw new DiscoveryError(`${configPath} does not contain a JSON object`, {
      details: { configPath, client: client.id },
    });
  }

  const servers = (document as Record<string, unknown>)[SHAPE_KEYS[client.shape]];

  // A configuration file with no server map is not an error. Claude Code's
  // .claude.json holds a great deal besides MCP configuration, and most of the
  // time there is simply nothing here to find.
  if (typeof servers !== 'object' || servers === null || Array.isArray(servers)) {
    return [];
  }

  const registrations: ParsedRegistration[] = [];

  for (const [name, rawEntry] of Object.entries(servers)) {
    if (typeof rawEntry !== 'object' || rawEntry === null || Array.isArray(rawEntry)) {
      throw new DiscoveryError(
        `Server ${JSON.stringify(name)} in ${configPath} is not an object`,
        { details: { name, configPath } },
      );
    }

    const entry = rawEntry as Record<string, unknown>;

    // A disabled server still counts. It is configured, it can be re-enabled
    // without review, and an inventory that hid it would understate the surface.
    const endpoint = parseEndpoint(name, entry, configPath);

    const fingerprints: string[] = [];
    const scanValues = (record: unknown): void => {
      if (typeof record !== 'object' || record === null || Array.isArray(record)) return;

      for (const [key, value] of Object.entries(record)) {
        if (typeof value !== 'string') continue;
        if (isInlineCredential(key, value)) {
          // Only the fingerprint is kept. The value itself is never stored, never
          // logged, and never reaches a report.
          fingerprints.push(redactionFingerprint(value));
        }
      }
    };

    scanValues(entry['env']);
    scanValues(entry['headers']);

    const envNames = endpoint.transport === 'stdio' ? endpoint.envNames : [];
    const headerNames = endpoint.transport === 'http' ? endpoint.headerNames : [];

    const unknownFields = Object.keys(entry).filter((key) => !KNOWN_ENTRY_FIELDS.has(key));

    registrations.push({
      name,
      endpoint,
      authPosture: classifyAuth(entry, fingerprints.length > 0, envNames, headerNames),
      site: {
        client: client.id,
        configPath,
        hasInlineCredential: fingerprints.length > 0,
      },
      inlineCredentialFingerprints: fingerprints,
      unknownFields,
    });
  }

  return registrations;
}

/**
 * The identity two registrations must share to be the same server.
 *
 * A stdio server is its command and arguments. An HTTP server is its URL. Name is
 * deliberately excluded: the same server is routinely registered under different
 * names in different clients, and treating those as different servers would
 * inflate the inventory and split its history across several pins.
 */
export function identityOf(endpoint: ServerEndpoint): string {
  if (endpoint.transport === 'stdio') {
    return `stdio:${endpoint.command} ${endpoint.args.join(' ')}`;
  }

  // Normalise the URL so a trailing slash does not split one server into two.
  try {
    const url = new URL(endpoint.url);
    const path = url.pathname.replace(/\/+$/, '');
    return `http:${url.protocol}//${url.host}${path}`;
  } catch {
    return `http:${endpoint.url}`;
  }
}

/** Merge registrations of the same server across clients into one `ServerRef`. */
export function deduplicate(registrations: readonly ParsedRegistration[]): readonly ServerRef[] {
  const byIdentity = new Map<string, ParsedRegistration[]>();

  for (const registration of registrations) {
    const identity = identityOf(registration.endpoint);
    const existing = byIdentity.get(identity);
    if (existing === undefined) byIdentity.set(identity, [registration]);
    else existing.push(registration);
  }

  const servers: ServerRef[] = [];

  for (const [identity, group] of byIdentity) {
    const first = group[0];
    /* c8 ignore next -- a map entry always has at least one member */
    if (first === undefined) continue;

    // The most alarming posture across all registrations wins. A server holding
    // an inline credential in one client is an inline credential problem, even
    // if three other clients reference it cleanly.
    const posture = group.some((r) => r.authPosture === 'inline')
      ? 'inline'
      : (first.authPosture satisfies AuthPosture);

    servers.push({
      id: shortId(identity),
      name: first.name,
      endpoint: first.endpoint,
      authPosture: posture,
      registrations: group.map((r) => r.site),
    });
  }

  return servers;
}

/** A short, stable, filesystem safe id derived from a server's identity. */
function shortId(identity: string): string {
  return redactionFingerprint(identity);
}
