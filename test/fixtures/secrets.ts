/**
 * Realistic secret shapes for redaction tests.
 *
 * Every value here is synthetic. None is a real credential and none was ever
 * valid: the random-looking portions are keyboard mash and repeated filler chosen
 * to match each vendor's documented format and length. They exist so the redaction
 * tests exercise the shapes that actually appear in the wild rather than a
 * convenient toy string.
 *
 * If you add a case, add it to {@link SECRET_FIXTURES} so the sweep tests pick it
 * up automatically. Do not paste a real credential here, even an expired one.
 */

export interface SecretFixture {
  /** What this shape is, used as the test name. */
  readonly name: string;
  /** The synthetic secret in isolation. */
  readonly secret: string;
  /** The secret as it realistically appears, embedded in surrounding text. */
  readonly context: string;
  /**
   * A substring of `context` that must survive redaction, so the test proves the
   * output stays useful rather than being blanked wholesale.
   */
  readonly preserved?: string;

  /**
   * Set when the secret is only identifiable from its surroundings.
   *
   * A connection string password is the clear case: `sup3rs3cr3tpassw0rd` on its
   * own is indistinguishable from an ordinary word, and a redactor that removed
   * every such string would destroy far more legitimate text than it protected.
   * What makes it a credential is its position in `scheme://user:PASSWORD@host`.
   *
   * These fixtures are exempt from the isolation test and still required to be
   * removed from their realistic context.
   */
  readonly contextualOnly?: true;
}

export const SECRET_FIXTURES: readonly SecretFixture[] = [
  {
    name: 'Anthropic API key',
    secret: 'sk-ant-api03-QmxhaEJsYWhCbGFoTm90UmVhbEtleQAA-ZmFrZUtleVZhbHVl',
    context:
      'Set ANTHROPIC_API_KEY=sk-ant-api03-QmxhaEJsYWhCbGFoTm90UmVhbEtleQAA-ZmFrZUtleVZhbHVl before starting.',
    preserved: 'before starting',
  },
  {
    name: 'OpenAI project key',
    secret: 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
    context: 'openai.api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"',
    preserved: 'openai.api_key',
  },
  {
    name: 'OpenAI classic key',
    secret: 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH',
    context: 'Authorization header uses sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH here',
    preserved: 'Authorization header uses',
  },
  {
    name: 'GitHub fine grained PAT',
    secret: 'github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL',
    context:
      'git remote set-url origin https://github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL@github.com/acme/repo.git',
    preserved: 'github.com/acme/repo.git',
  },
  {
    name: 'GitHub classic PAT',
    secret: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB',
    context: 'GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB',
  },
  {
    name: 'Slack bot token',
    secret: 'xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
    context: 'slack: xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
    preserved: 'slack:',
  },
  {
    name: 'AWS access key id',
    secret: 'AKIAIOSFODNN7EXAMPLE',
    context: 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'AWS secret access key',
    secret: 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY',
    context: 'aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY',
  },
  {
    name: 'Google API key',
    secret: 'AIzaSyDaGmWKa4JsXZHjjjjjjjjjjjjjjjjjjjjjj',
    context: 'maps key AIzaSyDaGmWKa4JsXZHjjjjjjjjjjjjjjjjjjjjjj in config',
    preserved: 'in config',
  },
  {
    name: 'GitLab personal access token',
    secret: 'glpat-abcdefghijklmnopqrst',
    context: 'CI_JOB_TOKEN=glpat-abcdefghijklmnopqrst',
  },
  {
    name: 'Stripe live secret key',
    secret: 'sk_live_abcdefghijklmnopqrstuvwx',
    context: 'stripe.setApiKey("sk_live_abcdefghijklmnopqrstuvwx")',
    preserved: 'stripe.setApiKey',
  },
  {
    name: 'JSON Web Token',
    secret:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    context:
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    preserved: 'Authorization',
  },
  {
    name: 'Postgres connection string',
    secret: 'sup3rs3cr3tpassw0rd',
    context: 'DATABASE_URL=postgres://appuser:sup3rs3cr3tpassw0rd@db.internal:5432/production',
    preserved: 'db.internal:5432/production',
    contextualOnly: true,
  },
  {
    name: 'MongoDB connection string',
    secret: 'p%40ssw0rd-with-symbols',
    context: 'mongodb+srv://svc_account:p%40ssw0rd-with-symbols@cluster0.example.mongodb.net/app',
    preserved: 'cluster0.example.mongodb.net/app',
    contextualOnly: true,
  },
  {
    name: 'RSA private key block',
    secret: [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAxGgUxNotARealKeyAtAllJustFillerForTestingPurposes',
      'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP',
      'QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ0000111122223333444455==',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n'),
    context: [
      'The server config embedded a key:',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAxGgUxNotARealKeyAtAllJustFillerForTestingPurposes',
      'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP',
      'QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ0000111122223333444455==',
      '-----END RSA PRIVATE KEY-----',
      'and then continued.',
    ].join('\n'),
    preserved: 'and then continued.',
  },
  {
    name: 'OpenSSH private key block',
    secret: [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz',
      'c2gtcnNhAAAAAwEAAQAAAYEAxNotARealPrivateKeyJustTestFillerAAAAAAA',
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n'),
    context: [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz',
      'c2gtcnNhAAAAAwEAAQAAAYEAxNotARealPrivateKeyJustTestFillerAAAAAAA',
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n'),
  },
  {
    name: 'npm automation token',
    secret: 'npm_abcdefghijklmnopqrstuvwxyz0123456789AB',
    context: '//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789AB',
    preserved: 'registry.npmjs.org',
  },
  {
    name: 'Hugging Face token',
    secret: 'hf_abcdefghijklmnopqrstuvwxyzABCD',
    context: 'HUGGINGFACE_TOKEN=hf_abcdefghijklmnopqrstuvwxyzABCD',
  },
  {
    name: 'generic hex blob',
    secret: 'a3f5c9e1b7d2486013579bdf2468ace0135792468acef0246',
    context: 'signature=a3f5c9e1b7d2486013579bdf2468ace0135792468acef0246',
  },
  {
    name: 'generic base64 blob',
    secret: 'VGhpc0lzTm90QVJlYWxTZWNyZXQxMjM0NTY3ODkwQUJDREVG',
    context: 'payload VGhpc0lzTm90QVJlYWxTZWNyZXQxMjM0NTY3ODkwQUJDREVG end',
    preserved: 'end',
  },
];

/**
 * Strings that must survive redaction untouched.
 *
 * Over-redaction is a real failure mode: a redactor that eats ordinary identifiers
 * produces reports nobody can read, and a report nobody reads catches nothing.
 */
export const MUST_SURVIVE: readonly string[] = [
  'get_weather',
  'searchDocumentsByRelevanceScore',
  'file:///projects/myapp/config.json',
  'https://example.com/mcp',
  'The quick brown fox jumps over the lazy dog.',
  'tools/list',
  'resources/templates/list',
  'io.modelcontextprotocol/protocolVersion',
  '2026-07-28',
  'ttlMs',
  'cacheScope',
  '-32020',
  'application/json',
  'text/event-stream',
  'a_very_long_snake_case_identifier_that_goes_on_and_on_and_on_for_a_while',
  'AVeryLongCamelCaseIdentifierThatGoesOnAndOnAndOnForQuiteAWhileIndeed',
  'Mcp-Protocol-Version',
];
