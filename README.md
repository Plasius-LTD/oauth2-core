# @plasius/oauth2-core

Standards-focused OAuth 2.1, PKCE, metadata, and bearer-token primitives for
Plasius services.

## Boundary

This package contains pure OAuth helpers only:

- request and response types
- OAuth error contracts
- scope and resource validation
- redirect URI validation
- PKCE S256 helpers
- authorization-server metadata builders
- protected-resource metadata builders
- dynamic client metadata validation
- bearer challenge helpers
- JWT access-token claim validation
- RFC 9068 access-token JWT header validation (`typ` and asymmetric `alg`)
- standards conformance fixtures

It intentionally does not contain persistence, environment reads, cookies, HTTP
framework adapters, Plasius admin authorization, site routes, or secrets.

## Standards

- OAuth 2.1 draft-15
- PKCE RFC 7636
- Bearer tokens RFC 6750
- Token revocation RFC 7009
- Authorization server metadata RFC 8414
- OAuth Security BCP RFC 9700
- Protected resource metadata RFC 9728
- Dynamic client registration RFC 7591
- JWT access-token profile RFC 9068
- Resource indicators RFC 8707
- DPoP RFC 9449

`validateJwtAccessTokenHeader` must be applied to the decoded JOSE header before
claim validation. It accepts only `at+jwt` or `application/at+jwt` and rejects
unsigned or symmetric-algorithm access-token JWTs, as required by RFC 9068 §§2.1
and 4. Signature verification remains the caller's cryptographic boundary.

Runtime-visible adoption inherits
`governance.rfc-compliance-remediation.enabled`; consumers may use the disabled
state only for a documented migration window. Rollback disables the flag and
restores the prior verifier while affected tokens expire. The pure package does
not evaluate remote flags itself.

## Development

```bash
npm ci
npm run build
npm test
npm run test:coverage
npm run pack:check
```

## License

Apache-2.0

<!-- BEGIN PLASIUS RELEASE INTEGRITY -->
## Release integrity

CI keeps the administrative contributor registry outside Git and npm package
artifacts using exact, case-normalised path checks. Both CI jobs run only for pushes in this repository on the approved
`Public CI - Quarantined` group with explicit `[self-hosted, Linux, X64]`
labels. Pull-request, target, dispatch and reusable-call entry points are
absent. The group admits only selected repositories and reviewed workflow
refs; there is no hosted fallback or caller-controlled runner selector.
Checkout credentials are not persisted, package-manager cache finalization
is disabled, and jobs have 15/10 minute limits. Strict `npm ci`, lint, types,
audit, build, 80% LCOV, source/index admission and final package checks remain
mandatory.
Publication uses the GitHub-hosted `production` job with Node 24 and a pinned
npm 11.6.2 client. It is token-free and proceeds only while the prepared SHA
is the exact `main` head after successful push-triggered CI. Do not dispatch CD
until the npm trusted-publisher binding is verified.

Before pushing a source branch, review its workflow and temporarily admit only
that exact branch workflow ref in the existing restricted group. Remove the
temporary entry after its checks finish and it is merged. For a pipeline-created
release metadata PR, verify its App author, base, preparation run, head SHA and
version/lockfile/CHANGELOG-only diff, then admit that exact branch while it is
available. Preserve it until CI finishes. If required reviews/checks block merge,
complete them before allowing preparation to continue; never bypass protection.
Keep the group's selected repositories, public policy and other refs unchanged.

This recovery inherits `platform.public-artifact-integrity.enabled` from Feature
#1597: enabled permits verified staged promotion; disabled stops promotion;
rollback disables the affected workflow/distribution channel. The governed
platform store evaluates the flag, with no package-local flag or capability.
Source, index and package admission remain mandatory in all three states. Never
restore the administrative registry, introduce a token fallback or reuse a
removed npm version. See [ADR-0003](docs/adrs/adr-0003-quarantined-public-ci.md).
<!-- END PLASIUS RELEASE INTEGRITY -->
