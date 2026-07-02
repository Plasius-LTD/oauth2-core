# AGENTS.md

## Scope
- This repository is `@plasius/oauth2-core`, a standards-focused TypeScript package for OAuth 2.1, PKCE, metadata, bearer-token, and JWT claim primitives.
- Keep this package pure: no persistence, HTTP framework coupling, cookies, environment reads, Plasius admin logic, or secrets.

## Tooling
- Use Node.js 24, npm, TypeScript, Vitest, ESLint, and tsup.
- Install with `npm ci`.
- Common checks:
  - `npm run lint`
  - `npm run typecheck`
  - `npm run test:coverage`
  - `npm run build`
  - `npm run pack:check`

## Packaging
- Publish only through approved GitHub CD workflows. Do not run `npm publish` locally.
- Keep package dependencies registry-based; do not commit `file:` or workspace-local dependencies.
- Generated output in `dist/`, `coverage/`, and `node_modules/` must not be committed.

## Quality
- Add or update tests for changed behavior and keep coverage at or above 80%.
- Public API changes require README, CHANGELOG, and ADR updates where applicable.
- Never include secrets, real PII, tokens, authorization codes, refresh tokens, or private keys in examples, tests, logs, fixtures, or docs.
