# Release checklist

How to cut a release of `mcpwarden`, and what to settle before the first one.

---

## Before the first publish

### 1. Confirm the package name is still free

```bash
npm view mcpwarden
```

A `404` means it is available.

### 2. Decide on the unconfirmed client paths

`VERIFY.md` section 1 lists four configuration paths that are implemented but marked
`probable` rather than `confirmed`: Windsurf, Cline, Zed, and the generic project
`mcp.json` convention.

A wrong path means `discover` reports a clean machine when it simply looked in the
wrong place, which is the worst failure this component has. Confirming them needs
somebody who runs those clients.

Publishing without confirming is defensible. Each path is marked `probable` in the
code, `doctor` reports the uncertainty, and `absentPaths` lists every location checked
so a wrong path is visible rather than silent. But it should be a decision rather than
an oversight.

### 3. Settle the disclosure address

`SECURITY.md` points disclosure at GitHub private vulnerability reporting, with an
email fallback. Anything published there gets scraped. GitHub private vulnerability
reporting works without an address at all.

---

## Publishing

```bash
# 1. Confirm the working tree is clean and on the release commit.
git status --short

# 2. Full verification. prepublishOnly runs this again, but seeing it pass
#    before you start is worth the two minutes.
npm run verify

# 3. Regenerate the derived documentation and confirm it is in sync.
npm run build && npm run docs:rules && npm run docs:check

# 4. Inspect the tarball one more time.
mkdir -p ./.pack
npm pack --pack-destination ./.pack
tar -tzf .pack/mcpwarden-0.1.0.tgz | sort

# 5. Dry run.
npm publish --dry-run

# 6. Publish. This is the irreversible step.
npm publish --provenance --access public

# 7. Tag and push.
git tag -a v0.1.0 -m "mcpwarden 0.1.0"
git push origin v0.1.0
```

Alternatively use the `Release` GitHub Actions workflow, which is wired but
`workflow_dispatch` only and defaults to a dry run. It needs an `NPM_TOKEN` secret and
an `npm-publish` environment. There is deliberately no automatic path from a merge to a
published package.

---

## After publishing

```bash
# Confirm it installs from the registry rather than from disk.
cd $(mktemp -d) && npm init -y && npm install mcpwarden
node -e "import('mcpwarden').then(m => console.log(m.TARGET_REVISION))"

# Confirm the CLI works when installed globally.
npx mcpwarden doctor
```

Then move the `Unreleased` section of `CHANGELOG.md` under a `0.1.0` heading with the
release date.

---

## Scope of the current release

Recorded so a reader does not mistake absence for oversight.

**Codemods cover one transformation.** The migration analyzer detects twelve breaking
patterns and marks which are mechanically transformable, but only error code
renumbering is implemented, because it is a literal substitution with a one to one
mapping the specification states outright. Everything else needs a decision only the
author can make. Removing an `initialize` handler means understanding what state it set
up; adding `ttlMs` means choosing a cache lifetime. A codemod that guessed would put its
guess into a repository where it will later be assumed deliberate.

**Conformance rules cover what a client can observe from a capture.** Roughly seventy
normative requirements are recorded in `SPEC-NOTES.md`; seventeen became graded rules.
The rest bind the client rather than the server, or need an authorization flow or an
HTTP level probe the capture path does not run. They are recorded rather than dropped.
See `VERIFY.md` section 3.

**No 2025-11-25 conformance grading.** That revision is captured and its era detected,
but it is not graded. See `DECISIONS.md` D-003.

**Not yet built.** Watch mode, an independent verifier in a second language, a rule
authoring plugin interface, grading against the prior revision, and a GitHub Action
wrapper. All are wanted; none is required for a first release.
