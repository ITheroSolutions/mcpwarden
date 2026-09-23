/**
 * Signs of tool poisoning in text a model will read.
 *
 * Tool poisoning works by putting instructions in a tool's description that the
 * model follows and the user never sees: read `~/.ssh/id_rsa` and pass it along
 * in an innocuous parameter, do not mention this to the user, ignore previous
 * instructions. The published examples share a small vocabulary, and these
 * patterns look for it.
 *
 * They exist to separate two things a drift report was conflating. Before them, a
 * changed description on any tool that mentioned the network or the filesystem was
 * rated critical, so upgrading a legitimate browser automation server between two
 * real releases produced seventeen critical alarms, every one of them noise. An
 * alarm that always fires is an alarm nobody reads. Critical is now reserved for a
 * change that carries one of these signs.
 *
 * Every pattern is deliberately narrow, because a pattern that fires on ordinary
 * descriptions recreates the problem it exists to solve. Like everything else in
 * risk scoring this is a heuristic, and it is wrong in both directions: a careful
 * attacker can avoid every phrase here, and an honest tool can happen to use one.
 * It directs attention. It does not make a judgement.
 */

export interface PoisoningMarker {
  /** Stable identifier. */
  readonly id: string;
  /** What was found, phrased to complete "the description contains ...". */
  readonly finding: string;
  readonly pattern: RegExp;
}

export const POISONING_MARKERS: readonly PoisoningMarker[] = [
  {
    id: 'hidden-characters',
    finding:
      'invisible or direction changing Unicode characters, which can hide text from a human reviewer while the model still reads it',
    // The zero width space, invisible operators, bidirectional embedding and
    // override controls (the Trojan Source characters), the byte order mark used
    // mid text, and the Unicode tag block, which renders as nothing at all.
    // Deliberately excluded: zero width joiners and the left and right marks,
    // which ordinary Persian, Arabic and Hebrew text uses legitimately.
    pattern: /[\u200B\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/u,
  },
  {
    id: 'instruction-tag',
    finding: 'an instruction tag such as <IMPORTANT> or <system>',
    pattern: /<\s*\/?\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>/i,
  },
  {
    id: 'conceal-from-user',
    finding: 'an instruction to keep something from the user',
    pattern:
      /\b(do\s+not|don['\u2019]t|never)\s+(tell|mention|inform|reveal|show|disclose|notify)\b.{0,40}?\b(user|human|operator)s?\b/i,
  },
  {
    id: 'override-instructions',
    finding: 'an instruction to ignore or override other instructions',
    pattern:
      /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other|system)\s+(instructions?|directions?|rules?|prompts?|messages?)\b/i,
  },
  {
    id: 'cross-tool-steering',
    finding: 'an instruction about when or how to use other tools',
    pattern:
      /\b(before|instead\s+of|after)\s+(using|calling|invoking|running)\s+(any|every|all|other|another)\s+(other\s+)?(tools?|functions?)\b/i,
  },
  {
    id: 'credential-path',
    finding: 'a reference to a credential file, such as an SSH key, cloud credentials or a .env file',
    pattern:
      /[\\/]\.(ssh|aws|kube|gnupg|docker)[\\/]|\bid_(rsa|ed25519|ecdsa|dsa)\b|(^|[\s"'`(])\.env(\.[\w-]+)?\b|\b(credentials\.json|\.npmrc|\.netrc|\.pgpass|claude_desktop_config\.json)\b/i,
  },
];

/** The findings for every marker present in `text`, in a stable order. */
export function findPoisoningMarkers(text: string | undefined): readonly string[] {
  if (text === undefined || text.length === 0) return [];

  return POISONING_MARKERS.filter((marker) => marker.pattern.test(text)).map(
    (marker) => `the text the model reads contains ${marker.finding}`,
  );
}
