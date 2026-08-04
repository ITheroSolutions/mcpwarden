/**
 * Codemods for the mechanical transformations only.
 *
 * The governing constraint is the important part: never rewrite anything that
 * cannot be transformed safely. A codemod that silently mangles source is the
 * most damaging thing this package could do, because the damage lands in a
 * repository rather than in a report, and it lands in code the author will later
 * assume they wrote.
 *
 * So the bar here is deliberately high, and most detected patterns do not clear
 * it. Removing an `initialize` handler means understanding what state it set up.
 * Adding `ttlMs` means choosing a cache lifetime only the author knows. Those are
 * reported with a specific fix and left to a human.
 *
 * What is left is the renumbering of retired error codes, which is a pure literal
 * substitution with a one to one mapping the specification states outright.
 *
 * ## Safety
 *
 * Every transform is opt in, prints a unified diff, and requires confirmation
 * unless a write flag is passed. Substitution happens only on numeric literals
 * located through the TypeScript AST, so a comment mentioning `-32002` or a
 * version string that happens to contain the digits is never touched.
 */

import { readFile, writeFile } from 'node:fs/promises';

import { InternalError } from '../core/errors.js';

/**
 * Retired error codes and their replacements.
 *
 * `-32002` and `-32042` were retired outright. `-32001`, `-32003` and `-32004`
 * were renumbered into the range the specification reserves for itself.
 */
export const ERROR_CODE_REPLACEMENTS: Readonly<Record<number, { to: number; why: string }>> = {
  [-32002]: {
    to: -32602,
    why: 'resource not found is now Invalid Params, aligning with JSON-RPC',
  },
  [-32001]: { to: -32020, why: 'HeaderMismatch moved into the reserved MCP range' },
  [-32003]: {
    to: -32021,
    why: 'MissingRequiredClientCapability moved into the reserved MCP range',
  },
  [-32004]: {
    to: -32022,
    why: 'UnsupportedProtocolVersion moved into the reserved MCP range',
  },
};

/** A code that was retired with no replacement. */
export const RETIRED_WITHOUT_REPLACEMENT: Readonly<Record<number, string>> = {
  [-32042]: 'URL elicitation required was removed entirely, with no successor code',
};

export interface CodemodEdit {
  readonly line: number;
  readonly before: string;
  readonly after: string;
  readonly why: string;
}

export interface CodemodResult {
  readonly file: string;
  readonly edits: readonly CodemodEdit[];
  /** The rewritten source. Identical to the input when there are no edits. */
  readonly output: string;
  /** Unified diff, empty when there are no edits. */
  readonly diff: string;
  /** Patterns found that a human must handle, with the reason. */
  readonly manual: readonly { readonly line: number; readonly reason: string }[];
}

/** The narrow slice of the compiler API this module uses. */
interface TypeScriptApi {
  createSourceFile(
    fileName: string,
    sourceText: string,
    languageVersion: number,
    setParentNodes?: boolean,
  ): TsSourceFile;
  ScriptTarget: { Latest: number };
  SyntaxKind: Record<string, number>;
  forEachChild<T>(node: TsNode, cb: (node: TsNode) => T | undefined): T | undefined;
}

interface TsNode {
  kind: number;
  pos: number;
  end: number;
  getStart?: () => number;
}

interface TsSourceFile extends TsNode {
  getLineAndCharacterOfPosition(pos: number): { line: number; character: number };
  text: string;
}

async function loadTypeScript(): Promise<TypeScriptApi | undefined> {
  try {
    const module = (await import('typescript')) as unknown as { default?: TypeScriptApi };
    const api = module.default ?? (module as unknown as TypeScriptApi);
    return typeof api.createSourceFile === 'function' ? api : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Rewrite retired error codes in one source file.
 *
 * Returns the proposed output and a diff without writing anything. Writing is a
 * separate, explicit step.
 *
 * @throws {InternalError} when the TypeScript compiler is not available. A
 * regex based fallback is deliberately not offered here: a lower confidence
 * *report* is useful, but a lower confidence *rewrite* is not, and the whole
 * point of locating literals through the AST is that a comment or a version
 * string is never touched.
 */
export async function codemodErrorCodes(file: string, source: string): Promise<CodemodResult> {
  const ts = await loadTypeScript();

  if (ts === undefined) {
    throw new InternalError(
      'Rewriting error codes needs the TypeScript compiler, which is not installed. ' +
        'Install typescript, or apply the change by hand using the migrate report. ' +
        'A text based rewrite is not offered because it would edit comments and strings.',
      { details: { file } },
    );
  }

  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);

  interface Replacement {
    readonly start: number;
    readonly end: number;
    readonly text: string;
    readonly line: number;
    readonly why: string;
  }

  const replacements: Replacement[] = [];
  const manual: { line: number; reason: string }[] = [];

  const visit = (node: TsNode): undefined => {
    if (node.kind === ts.SyntaxKind['NumericLiteral']) {
      const start = node.getStart?.() ?? node.pos;
      const literal = source.slice(start, node.end);

      // The minus is a separate prefix operator, so the sign is recovered from
      // the character before the token rather than from the literal itself.
      const preceding = source.slice(0, start);
      const trimmed = preceding.trimEnd();

      if (trimmed.endsWith('-')) {
        const value = Number(`-${literal}`);
        const { line } = sourceFile.getLineAndCharacterOfPosition(start);

        const replacement = ERROR_CODE_REPLACEMENTS[value];
        if (replacement !== undefined) {
          // Replace the digits and the sign together, so `-32002` becomes
          // `-32602` rather than leaving a stray operator behind.
          const signStart = trimmed.length - 1;

          replacements.push({
            start: signStart,
            end: node.end,
            text: String(replacement.to),
            line: line + 1,
            why: replacement.why,
          });
        } else if (RETIRED_WITHOUT_REPLACEMENT[value] !== undefined) {
          manual.push({
            line: line + 1,
            reason: RETIRED_WITHOUT_REPLACEMENT[value] ?? 'retired',
          });
        }
      }
    }

    ts.forEachChild(node, visit);
    return undefined;
  };

  ts.forEachChild(sourceFile, visit);

  if (replacements.length === 0) {
    return { file, edits: [], output: source, diff: '', manual };
  }

  // Apply back to front so earlier offsets stay valid.
  const ordered = [...replacements].sort((a, b) => b.start - a.start);

  let output = source;
  for (const replacement of ordered) {
    output = output.slice(0, replacement.start) + replacement.text + output.slice(replacement.end);
  }

  const edits = [...replacements]
    .sort((a, b) => a.line - b.line)
    .map((replacement) => ({
      line: replacement.line,
      before: lineAt(source, replacement.line),
      after: lineAt(output, replacement.line),
      why: replacement.why,
    }));

  return { file, edits, output, diff: unifiedDiff(file, source, output), manual };
}

/**
 * Apply a codemod result to disk.
 *
 * Separate from computing it, so nothing can write as a side effect of being
 * asked what it would do.
 */
export async function applyCodemod(result: CodemodResult): Promise<void> {
  if (result.edits.length === 0) return;
  await writeFile(result.file, result.output, 'utf8');
}

/** Read a file and compute the codemod for it. */
export async function codemodFile(file: string): Promise<CodemodResult> {
  return await codemodErrorCodes(file, await readFile(file, 'utf8'));
}

function lineAt(text: string, oneBasedLine: number): string {
  return text.split(/\r?\n/)[oneBasedLine - 1] ?? '';
}

/**
 * A unified diff of the changed lines.
 *
 * Hand written rather than pulled from a dependency, and deliberately simple: it
 * emits one hunk per changed line with three lines of context. That is enough for
 * a human to see what would happen before agreeing to it, which is the only job
 * this has.
 */
export function unifiedDiff(file: string, before: string, after: string): string {
  const beforeLines = before.split(/\r?\n/);
  const afterLines = after.split(/\r?\n/);

  const changed: number[] = [];
  for (let i = 0; i < Math.max(beforeLines.length, afterLines.length); i += 1) {
    if (beforeLines[i] !== afterLines[i]) changed.push(i);
  }

  if (changed.length === 0) return '';

  const lines: string[] = [`--- a/${file}`, `+++ b/${file}`];

  for (const index of changed) {
    const from = Math.max(0, index - 3);
    const to = Math.min(beforeLines.length - 1, index + 3);

    lines.push(`@@ -${String(from + 1)},${String(to - from + 1)} +${String(from + 1)},${String(to - from + 1)} @@`);

    for (let i = from; i <= to; i += 1) {
      if (i === index) {
        lines.push(`-${beforeLines[i] ?? ''}`);
        lines.push(`+${afterLines[i] ?? ''}`);
      } else {
        lines.push(` ${beforeLines[i] ?? ''}`);
      }
    }
  }

  return lines.join('\n');
}
