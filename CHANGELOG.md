# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release.

### Added

- `mcpwarden discover`: an offline inventory of every MCP server configured on the
  machine, across Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline and
  Zed. A server registered in several clients is reported once, with every place it
  is registered. Credentials written inline into a configuration file, whether in
  `env`, in `headers` or in the endpoint URL's query string, are flagged with an
  eight character fingerprint. The credential itself never appears in any output.
- `mcpwarden capture`: connects to a server over stdio or HTTP and records what it
  advertises (tools, prompts, resources and resource templates), along with the
  protocol revision it actually spoke.
- `mcpwarden conform`: grades a server against the 2026-07-28 MCP specification
  with 17 rules, each citing the specification section or SEP that justifies it. A
  single MUST failure caps the letter grade regardless of score. A server that speaks
  a different revision is reported as not graded, and the command fails, rather than
  being scored against rules that do not apply to it.
- `mcpwarden trust` and `mcpwarden diff`: approve a server's current surface as a
  baseline, then detect later changes descriptor by descriptor, each with a risk
  tier. A changed description on an existing tool, the tool poisoning signal, is
  reported as a change to that tool rather than lost in general churn.
- `mcpwarden ledger log`, `ledger verify` and `ledger export`: an append only, hash
  chained record of every capture. `verify` names the exact entry where integrity
  fails. The format is specified in `docs/formats.md` precisely enough to write an
  independent verifier.
- `mcpwarden policy init`, `policy check` and `verify`: a policy gate for CI and
  pre commit hooks, covering allowlists and denylists, forbidden auth postures,
  inline credentials, unpinned servers, a minimum grade and a maximum drift risk.
  Exits nonzero on any violation.
- `mcpwarden migrate`: finds 12 patterns in server source code that break under
  2026-07-28. `--fix` applies the one change that is safely mechanical, renumbering
  retired error codes, prints the diff, and writes nothing without `--yes`.
- `mcpwarden doctor`: reports the environment, every configuration location
  checked, and the state of the ledger and policy.
- Reports in terminal, JSON, NDJSON, Markdown, SARIF and HTML formats. Secrets are
  redacted once, before any format is rendered.
- A programmatic API at `mcpwarden/api`, and a built in MCP server exposing six
  tools, so an agent can inspect its own tool surface.
- Zero runtime dependencies. No telemetry, no account, no cloud service, and no
  network access except to the servers you ask it to inspect.

[Unreleased]: https://github.com/ITheroSolutions/mcpwarden/compare/HEAD...HEAD
