/**
 * No file in this repository contains invisible characters.
 *
 * A tool that flags hidden Unicode in MCP tool descriptions must not carry any in
 * its own source. It nearly did: an editor turned the `\u200B` style escapes in
 * the poisoning marker patterns into the literal characters, which render as
 * nothing, so the source a reviewer read was not the source that ran. Escapes are
 * visible; the characters are not. This scans every source, test and document with
 * the same pattern the product uses on tool descriptions.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { POISONING_MARKERS } from '../../src/trust/markers.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SCANNED_DIRECTORIES = ['src', 'test', 'docs', 'scripts', 'examples', '.github'];
const SCANNED_EXTENSIONS = /\.(ts|mts|mjs|js|json|md|yml|yaml|cmd)$/;

async function filesUnder(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  const files: string[] = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (SCANNED_EXTENSIONS.test(entry.name)) files.push(path);
  }

  return files;
}

describe('the repository itself', () => {
  it('contains no invisible or direction changing characters', async () => {
    const hidden = POISONING_MARKERS.find((marker) => marker.id === 'hidden-characters');
    expect(hidden).toBeDefined();

    const topLevel = (await readdir(ROOT)).filter((name) => /\.(md|json)$/.test(name) && name !== 'package-lock.json');
    const files = [
      ...topLevel.map((name) => join(ROOT, name)),
      ...(await Promise.all(SCANNED_DIRECTORIES.map((dir) => filesUnder(join(ROOT, dir))))).flat(),
    ];

    const offenders: string[] = [];
    for (const file of files) {
      const text = await readFile(file, 'utf8');
      if (hidden?.pattern.test(text) === true) offenders.push(relative(ROOT, file));
    }

    expect(files.length).toBeGreaterThan(50);
    expect(offenders, 'files containing invisible characters; use escapes instead').toEqual([]);
  });
});
