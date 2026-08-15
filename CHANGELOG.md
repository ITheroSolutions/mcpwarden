# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `mcpwarden discover`: finds MCP servers configured across supported clients
  (Claude Desktop, Claude Code, Cursor, VS Code, Zed), deduplicates servers shared
  across clients, and reports inline credentials found in configuration, including
  credentials embedded in an HTTP endpoint's URL query string, never the credential
  value itself, only a fingerprint.
- `mcpwarden conform`: grades a server against the 2026-07-28 MCP specification,
  citing the specification section or SEP behind every finding, with a single MUST
  failure capping the letter grade regardless of score.
- `mcpwarden trust` and `mcpwarden diff`: captures a server's advertised surface,
  records it in a tamper evident append only ledger, and diffs it against a pinned
  baseline to detect drift, including tool poisoning, after the fact.
- `mcpwarden migrate`: analyses a source tree for patterns that break under the
  2026-07-28 specification revision (removed `initialize` handshake and sessions,
  removed `ping` and `logging/setLevel`, `resources/subscribe` replaced by
  `subscriptions/listen`) and reports what needs to change.
- Policy gate: marks servers unknown to an operator supplied allowlist.
- Project foundation: TypeScript strict configuration, ESLint, Prettier, Vitest with
  coverage thresholds, and cross platform continuous integration on Node 20 and 22
  across Ubuntu, Windows and macOS.
- `SPEC-NOTES.md`, a structured record of every normative requirement extracted from
  the 2026-07-28 specification, each classified MUST, SHOULD or MAY and carrying the
  specification section or SEP that justifies it.

### Fixed

- Credential detection now scans HTTP endpoint URL query strings, not just `env`
  and `headers`. A server configured with a live token in its URL (for example
  `?userToken=<jwt>`) was previously reported as carrying no credential at all.

[Unreleased]: https://github.com/ITheroSolutions/mcpwarden/compare/HEAD...HEAD
