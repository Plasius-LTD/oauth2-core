# ADR-0003: Quarantined public CI with hosted package publication

- Status: Accepted
- Date: 2026-10-21
- Project: oauth2-core#5; plasius-ltd-site#1626; Feature #1597
- Supersedes: ADR-0002's CI runner policy only

## Context

The public oauth2-core repository must satisfy its Project requirement for approved
self-hosted validation without allowing external-fork code onto organisation
capacity. Hosted OIDC publication is a separate, existing trust boundary.

## Decision

Accept only push events from the literal `Plasius-LTD/oauth2-core` repository.
Both CI jobs use the literal `Public CI - Quarantined` group and
`[self-hosted, Linux, X64]` labels. The group's selected repository/workflow
allowlist admits main and only specifically reviewed source branches while
needed. No pull-request/target/dispatch/call trigger, dynamic selector or hosted
fallback exists. Checkout does not persist credentials, package-manager cache
finalization is disabled, and validation is bounded to 15/10 minutes.

Use clean `npm ci` and keep lint, types, runtime audit, build, 80% LCOV,
source/index artifact admission and final package-manifest checks. Reuse the
existing validators rather than introducing a second admission implementation.
No package dependencies, runtime source or public API change.

Keep ADR-0002's hosted exact-main production OIDC publication unchanged. Before
release verify visibility, production, publisher identity and an unused patch
version, then use only main's approved two-phase cd.yml. The preparation
pipeline owns version/changelog metadata and tags; exact-main push CI gates
publication. Verify registry bytes, provenance, signatures and public release.

The inherited `platform.public-artifact-integrity.enabled` flag is evaluated
by the platform's governed store. Enabled permits staged verified promotion;
disabled stops it. Mandatory integrity gates remain active in either state.
This library needs no capability, runtime flag evaluation or env override.

## Alternatives

Hosted CI contradicts the tracked acceptance criteria. Public PR-head
execution, caller-selected runner inputs and automatic hosted fallbacks weaken
the intended admission boundary. A new shared package or runtime flag would
add an unnecessary package boundary for repository workflow configuration.

## Impact and tests

Workflow regressions first demonstrate failures for event admission, runner
isolation and reproducible quality/artifact gates, then enforce both jobs and
the unchanged hosted production OIDC/exact-SHA boundary. Run full package
validation and actionlint, source/main CI, and approved CD. Runtime source is
unchanged, so changed-runtime-file LCOV is N/A; retain overall 80% coverage.
No UI, browser, SEO, backend deployment or ACA secret-reference change applies.
Bounded jobs and explicit logs support reliability and observability.

## Rollback

Disable the affected CI/CD workflow or distribution channel and stop promotion;
remove temporary source-branch workflow admission after merge/checks. Retain
source, index and package admission; never restore the administrative registry,
fall back to a long-lived npm token, or reuse a removed version.
