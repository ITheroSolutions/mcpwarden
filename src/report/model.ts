/**
 * The report model.
 *
 * Every faculty produces the same shape, and every renderer consumes only this
 * shape. That is what keeps six output formats from drifting into six slightly
 * different truths about the same scan.
 *
 * ## Determinism
 *
 * Same input produces byte identical output, with exactly one exception: the
 * `generatedAt` timestamp. It is a single named field rather than being
 * interpolated into prose, so a caller diffing two reports can ignore one line
 * rather than writing a regex.
 *
 * ## Redaction
 *
 * Redaction happens once, here, when the model is built. Doing it in each renderer
 * would mean six chances to forget, and the one that forgot would be the one
 * somebody pasted into an issue.
 */

import { redact, type RedactionOptions } from '../core/redaction.js';
import type { Severity } from '../core/types.js';

export type ReportKind = 'inventory' | 'conformance' | 'drift' | 'policy' | 'migration';

/** A headline number, shown at the top of every format. */
export interface SummaryItem {
  readonly label: string;
  readonly value: string;
  /** Set when the value is itself a problem, so renderers can mark it. */
  readonly severity?: Severity;
}

/** One reported item: a finding, a violation, a drift event, an inventory row. */
export interface ReportItem {
  /** Stable identifier, for example a rule id or a pattern id. */
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  /** What is wrong, in one or two sentences. */
  readonly detail: string;
  /** What to do about it. */
  readonly remediation?: string;
  /** Where the problem is: a file, a server, a tool name. */
  readonly locus?: string;
  /** File path and line, when the item came from source analysis. */
  readonly location?: { readonly file: string; readonly line: number };
  /** Specification section or SEP backing the item. */
  readonly citation?: string;
  /** Extra structured context, rendered only by machine formats. */
  readonly evidence?: Readonly<Record<string, string>>;
}

export interface ReportSection {
  readonly title: string;
  /** Shown when the section has no items, so an empty section still says something. */
  readonly emptyMessage: string;
  readonly items: readonly ReportItem[];
}

export interface Report {
  readonly kind: ReportKind;
  readonly title: string;
  /** ISO 8601 UTC. The only field that varies between two runs on identical input. */
  readonly generatedAt: string;
  readonly toolVersion: string;
  /** The subject: a machine, a server name, a source tree. */
  readonly subject: string;
  readonly summary: readonly SummaryItem[];
  readonly sections: readonly ReportSection[];
  /**
   * Notes that are not findings: checks that could not run, degraded analysis,
   * unconfirmed paths. Rendered separately so they are not mistaken for problems.
   */
  readonly notes: readonly string[];
}

export interface BuildReportInput {
  readonly kind: ReportKind;
  readonly title: string;
  readonly subject: string;
  readonly toolVersion: string;
  readonly generatedAt?: string;
  readonly summary: readonly SummaryItem[];
  readonly sections: readonly ReportSection[];
  readonly notes?: readonly string[];
  readonly redaction?: RedactionOptions;
}

/**
 * Build a report, redacting every string in it.
 *
 * The single choke point. A renderer receives an already clean model, so no
 * renderer needs to remember to redact and none of them can forget.
 */
export function buildReport(input: BuildReportInput): Report {
  const options = input.redaction ?? {};
  const clean = (text: string): string => redact(text, options);

  return {
    kind: input.kind,
    title: clean(input.title),
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    toolVersion: input.toolVersion,
    subject: clean(input.subject),
    summary: input.summary.map((item) => ({
      label: clean(item.label),
      value: clean(item.value),
      ...(item.severity === undefined ? {} : { severity: item.severity }),
    })),
    sections: input.sections.map((section) => ({
      title: clean(section.title),
      emptyMessage: clean(section.emptyMessage),
      items: section.items.map((item) => cleanItem(item, clean)),
    })),
    notes: (input.notes ?? []).map(clean),
  };
}

function cleanItem(item: ReportItem, clean: (text: string) => string): ReportItem {
  return {
    id: item.id,
    title: clean(item.title),
    severity: item.severity,
    detail: clean(item.detail),
    ...(item.remediation === undefined ? {} : { remediation: clean(item.remediation) }),
    ...(item.locus === undefined ? {} : { locus: clean(item.locus) }),
    ...(item.location === undefined
      ? {}
      : { location: { file: clean(item.location.file), line: item.location.line } }),
    ...(item.citation === undefined ? {} : { citation: clean(item.citation) }),
    ...(item.evidence === undefined
      ? {}
      : {
          evidence: Object.fromEntries(
            Object.entries(item.evidence).map(([key, value]) => [clean(key), clean(value)]),
          ),
        }),
  };
}

/** Every item across every section, most severe first. */
export function allItems(report: Report): readonly ReportItem[] {
  const items = report.sections.flatMap((section) => section.items);
  return [...items].sort(bySeverity);
}

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function bySeverity(a: ReportItem, b: ReportItem): number {
  const rank = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  return rank !== 0 ? rank : a.id.localeCompare(b.id);
}

/** True when nothing was found. */
export function isClean(report: Report): boolean {
  return report.sections.every((section) => section.items.length === 0);
}
