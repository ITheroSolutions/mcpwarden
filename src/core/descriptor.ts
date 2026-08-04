/**
 * Building descriptors from what a server advertised.
 *
 * The important property here is that a descriptor's content hash is computed from
 * the server's own bytes, canonicalized, and never from a value that has been
 * through `JSON.parse`. Number fidelity is lost the moment that happens, and it
 * cannot be recovered afterwards.
 */

import { canonicalizeJsonValue, hashCanonicalForm } from './canonical.js';
import { ProtocolViolationError } from './errors.js';
import { isJsonNumber, type JsonObject, type JsonValue } from './json-parse.js';
import type { Descriptor, DescriptorCategory } from './types.js';

/**
 * Which field carries the stable identity for each category.
 *
 * Tools and prompts are named. Resources are identified by URI. Resource templates
 * are identified by their URI template, since a template has no concrete URI.
 */
const IDENTITY_FIELD: Readonly<Record<DescriptorCategory, readonly string[]>> = {
  tool: ['name'],
  prompt: ['name'],
  resource: ['uri'],
  resourceTemplate: ['uriTemplate'],
};

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !isJsonNumber(value);
}

/**
 * Read a descriptor's identity.
 *
 * A descriptor without one is a protocol violation rather than something to paper
 * over with a generated id: an unnamed tool cannot be pinned, cannot be diffed,
 * and cannot be referred to in a finding.
 */
export function readIdentity(category: DescriptorCategory, value: JsonObject): string {
  for (const field of IDENTITY_FIELD[category]) {
    const candidate = value[field];
    if (typeof candidate === 'string' && candidate.length > 0) return candidate;
  }

  throw new ProtocolViolationError(
    `A ${category} descriptor is missing its identity field ` +
      `(${IDENTITY_FIELD[category].join(' or ')})`,
    { details: { category, fields: IDENTITY_FIELD[category] } },
  );
}

/** Build one descriptor from a parsed value, computing its canonical form and hash. */
export function buildDescriptor(category: DescriptorCategory, value: JsonValue): Descriptor {
  if (!isJsonObject(value)) {
    throw new ProtocolViolationError(`A ${category} descriptor must be a JSON object`, {
      details: { category },
    });
  }

  const canonical = canonicalizeJsonValue(value);

  return {
    category,
    identity: readIdentity(category, value),
    value,
    canonical,
    hash: hashCanonicalForm(canonical),
  };
}

/** Build every descriptor in one category from a parsed list. */
export function buildDescriptors(
  category: DescriptorCategory,
  values: readonly JsonValue[],
): readonly Descriptor[] {
  return values.map((value) => buildDescriptor(category, value));
}

/**
 * Read a descriptor's description, when it has one.
 *
 * Separate from the generic accessor because a description change on an approved
 * tool is the single highest signal event this package looks for. Tool poisoning
 * works by changing the text the model reads, while the name and schema stay put.
 */
export function readDescription(descriptor: Descriptor): string | undefined {
  const value = descriptor.value['description'];
  return typeof value === 'string' ? value : undefined;
}

/** Read a tool's `inputSchema`, when it has one. */
export function readInputSchema(descriptor: Descriptor): JsonObject | undefined {
  const value = descriptor.value['inputSchema'];
  return value !== undefined && isJsonObject(value) ? value : undefined;
}

/**
 * Read the names a schema marks as required.
 *
 * Returns an empty array when the schema says nothing, which is the correct
 * reading: absent `required` means nothing is required.
 */
export function readRequiredParameters(schema: JsonObject | undefined): readonly string[] {
  if (schema === undefined) return [];

  const required = schema['required'];
  if (!Array.isArray(required)) return [];

  return required.filter((entry): entry is string => typeof entry === 'string');
}

/** Read the property names a schema declares. */
export function readSchemaProperties(schema: JsonObject | undefined): readonly string[] {
  if (schema === undefined) return [];

  const properties = schema['properties'];
  if (properties === undefined || !isJsonObject(properties)) return [];

  return Object.keys(properties);
}

export { isJsonObject };
