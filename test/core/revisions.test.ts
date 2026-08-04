import { describe, expect, it } from 'vitest';

import {
  compareRevisions,
  eraOf,
  isKnownRevision,
  isSupportedRevision,
  KNOWN_UNSUPPORTED_REVISIONS,
  requiresInitializeHandshake,
  selectBestRevision,
  SUPPORTED_REVISIONS,
  TARGET_REVISION,
} from '../../src/core/revisions.js';

describe('revision identifiers', () => {
  it('grades against the stateless revision', () => {
    expect(TARGET_REVISION).toBe('2026-07-28');
  });

  it('lists supported revisions newest first', () => {
    const sorted = [...SUPPORTED_REVISIONS].sort((a, b) => compareRevisions(b, a));
    expect([...SUPPORTED_REVISIONS]).toEqual(sorted);
  });

  it('does not claim support for a revision it also lists as unsupported', () => {
    for (const revision of KNOWN_UNSUPPORTED_REVISIONS) {
      expect(isSupportedRevision(revision)).toBe(false);
      expect(isKnownRevision(revision)).toBe(true);
    }
  });

  it('rejects strings that merely look like revisions', () => {
    expect(isSupportedRevision('2026-07-29')).toBe(false);
    expect(isKnownRevision('2026-07-29')).toBe(false);
    expect(isKnownRevision('')).toBe(false);
    expect(isKnownRevision('latest')).toBe(false);
  });
});

describe('era classification', () => {
  it('classifies the stateless revision as modern', () => {
    expect(eraOf('2026-07-28')).toBe('modern');
    expect(requiresInitializeHandshake('2026-07-28')).toBe(false);
  });

  it('classifies the handshake revision as legacy', () => {
    expect(eraOf('2025-11-25')).toBe('legacy');
    expect(requiresInitializeHandshake('2025-11-25')).toBe(true);
  });

  it('assigns an era to every supported revision', () => {
    for (const revision of SUPPORTED_REVISIONS) {
      expect(['modern', 'legacy']).toContain(eraOf(revision));
    }
  });
});

describe('compareRevisions', () => {
  it('orders chronologically', () => {
    expect(compareRevisions('2025-11-25', '2026-07-28')).toBeLessThan(0);
    expect(compareRevisions('2026-07-28', '2025-11-25')).toBeGreaterThan(0);
    expect(compareRevisions('2026-07-28', '2026-07-28')).toBe(0);
  });

  it('orders every known revision consistently with its date', () => {
    // 2024-11-05 is the oldest known revision, 2026-07-28 the newest.
    expect(compareRevisions('2024-11-05', '2025-03-26')).toBeLessThan(0);
    expect(compareRevisions('2025-03-26', '2025-06-18')).toBeLessThan(0);
    expect(compareRevisions('2025-06-18', '2025-11-25')).toBeLessThan(0);
    expect(compareRevisions('2025-11-25', '2026-07-28')).toBeLessThan(0);
  });
});

describe('selectBestRevision', () => {
  it('picks the newest mutually supported revision', () => {
    expect(selectBestRevision(['2025-11-25', '2026-07-28'])).toBe('2026-07-28');
    expect(selectBestRevision(['2026-07-28', '2025-11-25'])).toBe('2026-07-28');
  });

  it('falls back to the older revision when the newer is absent', () => {
    expect(selectBestRevision(['2025-11-25'])).toBe('2025-11-25');
  });

  it('ignores revisions it does not support rather than guessing', () => {
    expect(selectBestRevision(['2025-06-18', '2025-03-26'])).toBeUndefined();
    expect(selectBestRevision(['2099-01-01'])).toBeUndefined();
  });

  it('returns undefined for an empty list so the caller reports incompatibility', () => {
    // The specification's UnsupportedProtocolVersionError carries data.supported.
    // An empty or unusable list must never be silently treated as a downgrade.
    expect(selectBestRevision([])).toBeUndefined();
  });

  it('is not confused by duplicates or unknown entries mixed in', () => {
    expect(
      selectBestRevision(['2025-11-25', 'nonsense', '2026-07-28', '2026-07-28']),
    ).toBe('2026-07-28');
  });
});
