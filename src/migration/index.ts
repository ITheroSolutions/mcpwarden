/**
 * The migration analyzer.
 *
 * Static analysis of an MCP server source tree for patterns that break under
 * 2026-07-28. Reads code and connects to nothing.
 *
 * ## Two passes, honestly labelled
 *
 * When the TypeScript compiler API is available, detection runs on a real AST, so
 * a match inside a comment or an unrelated string is not reported and the line
 * number is exact. Findings from that pass are `high` confidence.
 *
 * When it is not, a line oriented pass runs instead. It still skips obvious
 * comment lines, but it cannot tell a method name from a word in a docstring, so
 * its findings are labelled `low` confidence and say so in the report. A tool that
 * presented grep results as though they were type aware analysis would be lying
 * about what it knows.
 *
 * ## Why TypeScript is optional
 *
 * The compiler is around seven megabytes and the rest of this package has zero
 * runtime dependencies. Making every user of `discover` or `ledger verify` carry
 * a compiler so that `migrate` can exist would be a poor trade. It is declared as
 * an optional peer dependency: present in most MCP server repositories already,
 * and cleanly degraded to the line pass when absent.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, sep } from 'node:path';

import { NOOP_LOGGER, type Logger } from '../core/logger.js';
import { redact } from '../core/redaction.js';
import {
  MIGRATION_PATTERNS,
  PATTERN_SIGNALS,
  patternById,
  type DetectionConfidence,
  type MigrationPattern,
} from './patterns.js';

export * from './patterns.js';
export * from './codemod.js';

export interface MigrationFinding {
  readonly patternId: string;
  readonly title: string;
  readonly severity: MigrationPattern['severity'];
  /** Path relative to the scanned root, using forward slashes. */
  readonly file: string;
  readonly line: number;
  /** The matched source text, trimmed and redacted. */
  readonly snippet: string;
  readonly why: string;
  readonly fix: string;
  readonly confidence: DetectionConfidence;
  readonly rule: string;
}

export interface MigrationReport {
  readonly root: string;
  readonly filesScanned: number;
  readonly findings: readonly MigrationFinding[];
  /** Which analysis pass ran. */
  readonly analysis: 'typescript' | 'line-oriented';
  /** Why the line pass was used, when it was. */
  readonly degradedReason?: string;
  readonly summary: Readonly<Record<string, number>>;
}

export interface AnalyzeOptions {
  readonly logger?: Logger;
  /** File extensions to read. Defaults to common server languages. */
  readonly extensions?: readonly string[];
  /** Directory names never descended into. */
  readonly ignoreDirectories?: readonly string[];
  /** Force the line oriented pass even when the compiler is available. */
  readonly forceLinePass?: boolean;
  readonly maxFiles?: number;
}

const DEFAULT_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs', '.py', '.go', '.rs'];

const DEFAULT_IGNORES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  'vendor',
  '__pycache__',
  'target',
];

const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts']);

/** Analyse a source tree. */
export async function analyzeMigration(
  root: string,
  options: AnalyzeOptions = {},
): Promise<MigrationReport> {
  const logger = options.logger ?? NOOP_LOGGER;
  const extensions = new Set(options.extensions ?? DEFAULT_EXTENSIONS);
  const ignores = new Set(options.ignoreDirectories ?? DEFAULT_IGNORES);
  const maxFiles = options.maxFiles ?? 5_000;

  const files = await collectFiles(root, extensions, ignores, maxFiles);

  const ts = options.forceLinePass === true ? undefined : await loadTypeScript();
  const analysis = ts === undefined ? 'line-oriented' : 'typescript';

  const findings: MigrationFinding[] = [];

  for (const file of files) {
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch {
      continue;
    }

    const relativePath = relative(root, file).split(sep).join('/');

    if (ts !== undefined && TS_EXTENSIONS.has(extname(file))) {
      findings.push(...analyzeWithCompiler(ts, text, relativePath));
    } else {
      findings.push(...analyzeLines(text, relativePath, ts === undefined ? 'low' : 'medium'));
    }
  }

  logger.debug('migration analysis complete', { files: files.length, findings: findings.length });

  const summary: Record<string, number> = {};
  for (const finding of findings) {
    summary[finding.patternId] = (summary[finding.patternId] ?? 0) + 1;
  }

  return {
    root,
    filesScanned: files.length,
    findings: findings.sort(bySeverityThenLocation),
    analysis,
    ...(ts === undefined && options.forceLinePass !== true
      ? {
          degradedReason:
            'The TypeScript compiler was not resolvable, so a line oriented pass ran instead. ' +
            'Install typescript to get exact line numbers and to stop comments and unrelated ' +
            'strings being reported.',
        }
      : {}),
    summary,
  };
}

/**
 * Load the TypeScript compiler if it is installed.
 *
 * Returns undefined rather than throwing when it is not, because `migrate`
 * degrading to a labelled lower confidence pass is far better than the command
 * refusing to run at all.
 */
async function loadTypeScript(): Promise<TypeScriptApi | undefined> {
  try {
    const module = (await import('typescript')) as unknown as { default?: TypeScriptApi };
    const api = module.default ?? (module as unknown as TypeScriptApi);
    return typeof api.createSourceFile === 'function' ? api : undefined;
  } catch {
    return undefined;
  }
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
  isStringLiteralLike(node: TsNode): boolean;
  isIdentifier(node: TsNode): boolean;
  isPropertyAssignment(node: TsNode): boolean;
}

interface TsNode {
  kind: number;
  pos: number;
  end: number;
  getText?: () => string;
  getStart?: () => number;
}

interface TsSourceFile extends TsNode {
  getLineAndCharacterOfPosition(pos: number): { line: number; character: number };
  text: string;
}

/**
 * Detect patterns on a real AST.
 *
 * Only string literals and identifiers are inspected, which is what removes the
 * whole class of false positives a text search produces: a changelog entry in a
 * comment mentioning `Mcp-Session-Id`, or a variable named `pinging`.
 */
function analyzeWithCompiler(
  ts: TypeScriptApi,
  text: string,
  file: string,
): readonly MigrationFinding[] {
  const findings: MigrationFinding[] = [];

  let source: TsSourceFile;
  try {
    source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return analyzeLines(text, file, 'low');
  }

  const visit = (node: TsNode): undefined => {
    const isLiteral = ts.isStringLiteralLike(node);
    const isIdent = ts.isIdentifier(node);
    const isNumeric = node.kind === ts.SyntaxKind['NumericLiteral'];

    // Retired error codes are numeric literals, and the minus sign is a separate
    // prefix operator rather than part of the token. Reading the character just
    // before the literal recovers the sign without a text search over the file,
    // so a comment mentioning -32002 is still ignored.
    if (isNumeric) {
      const start = node.getStart?.() ?? node.pos;
      const literal = source.text.slice(start, node.end);
      const preceding = source.text.slice(0, start).trimEnd();
      const signed = preceding.endsWith('-') ? `-${literal}` : literal;

      for (const signal of PATTERN_SIGNALS['MIG-ERROR-CODE'] ?? []) {
        if (signed !== signal) continue;

        const pattern = patternById('MIG-ERROR-CODE');
        if (pattern === undefined) break;

        const { line } = source.getLineAndCharacterOfPosition(start);
        findings.push(toFinding(pattern, file, line + 1, signed, 'high'));
        break;
      }
    }

    if (isLiteral || isIdent) {
      const raw = node.getText?.() ?? '';
      const value = isLiteral ? raw.slice(1, -1) : raw;

      for (const [patternId, signals] of Object.entries(PATTERN_SIGNALS)) {
        for (const signal of signals) {
          if (!matchesSignal(value, signal, isLiteral)) continue;

          const pattern = patternById(patternId);
          if (pattern === undefined) continue;

          const { line } = source.getLineAndCharacterOfPosition(node.pos);
          findings.push(toFinding(pattern, file, line + 1, raw, 'high'));
          break;
        }
      }
    }

    ts.forEachChild(node, visit);
    return undefined;
  };

  ts.forEachChild(source, visit);
  return findings;
}

/**
 * Decide whether a source token matches a migration signal.
 *
 * String literals match exactly, because a method name is an exact string and a
 * substring match on `ping` would hit `mapping`, `shipping` and `stripping`.
 * Identifiers match case insensitively but still whole, for the same reason.
 */
function matchesSignal(value: string, signal: string, isLiteral: boolean): boolean {
  const cleaned = signal.replace(/^['"]|['"]$/g, '').replace(/:$/, '');

  if (isLiteral) return value === cleaned;
  return value.toLowerCase() === cleaned.toLowerCase();
}

/**
 * The fallback pass.
 *
 * Skips lines that are obviously comments, which removes the most common false
 * positive, but makes no claim beyond that. Findings are labelled so a reader
 * knows they are looking at a text match rather than an analysed reference.
 */
function analyzeLines(
  text: string,
  file: string,
  confidence: DetectionConfidence,
): readonly MigrationFinding[] {
  const findings: MigrationFinding[] = [];
  const lines = text.split(/\r?\n/);

  let inBlockComment = false;

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? '';
    const trimmed = raw.trim();

    if (inBlockComment) {
      if (trimmed.includes('*/')) inBlockComment = false;
      continue;
    }
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    for (const [patternId, signals] of Object.entries(PATTERN_SIGNALS)) {
      for (const signal of signals) {
        const needle = signal.replace(/^['"]|['"]$/g, '');
        if (!raw.includes(needle)) continue;

        const pattern = patternById(patternId);
        if (pattern === undefined) continue;

        findings.push(toFinding(pattern, file, index + 1, trimmed, confidence));
        break;
      }
    }
  }

  return findings;
}

function toFinding(
  pattern: MigrationPattern,
  file: string,
  line: number,
  snippet: string,
  confidence: DetectionConfidence,
): MigrationFinding {
  return {
    patternId: pattern.id,
    title: pattern.title,
    severity: pattern.severity,
    file,
    line,
    // Source can contain a hardcoded credential, and a migration report is an
    // outbound artifact like any other.
    snippet: redact(snippet.slice(0, 200)),
    why: pattern.why,
    fix: pattern.fix,
    confidence,
    rule: pattern.rule,
  };
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function bySeverityThenLocation(a: MigrationFinding, b: MigrationFinding): number {
  const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  if (bySeverity !== 0) return bySeverity;

  const byFile = a.file.localeCompare(b.file);
  return byFile !== 0 ? byFile : a.line - b.line;
}

/** Walk a directory tree, honouring the ignore list and the file cap. */
async function collectFiles(
  root: string,
  extensions: ReadonlySet<string>,
  ignores: ReadonlySet<string>,
  maxFiles: number,
): Promise<readonly string[]> {
  const files: string[] = [];

  const walk = async (directory: string): Promise<void> => {
    if (files.length >= maxFiles) return;

    let entries: string[];
    try {
      entries = await readdir(directory);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (ignores.has(entry)) continue;

      const full = join(directory, entry);

      let info;
      try {
        info = await stat(full);
      } catch {
        continue;
      }

      if (info.isDirectory()) {
        await walk(full);
      } else if (extensions.has(extname(entry))) {
        files.push(full);
      }
    }
  };

  await walk(root);
  return files;
}

/** Every pattern, for documentation generation. */
export function allMigrationPatterns(): readonly MigrationPattern[] {
  return MIGRATION_PATTERNS;
}
