# Changelog

## Unreleased

- **Added**
  - (placeholder)

- **Changed**
  - Bound npm publication to the exact prepared `main` commit after successful push-triggered CI.
  - (placeholder)

- **Fixed**
  - Added exact-commit CI dispatch and disabled package-manager cache finalization in both hosted validation jobs.
  - (placeholder)

- **Security**
  - Removed the npm write-token path, added a fail-closed npm 11.5.1-or-newer OIDC guard, and denied fork PR code access to reviewed CI.
  - Pinned patched transitive npm dependencies to clear the current audit baseline.
  - Moved reviewed CI to explicit GitHub-hosted runners while retaining the same-repository pull-request guard.
  - Added fail-closed source and npm-package admission for the administrative contributor registry and pinned the CI/CD runtime to Node.js 24.18.0 LTS.
  - Updated the release dependency lock to resolve the current npm audit findings.
  - (placeholder)

## [0.1.1] - 2026-07-12

- **Added**
  - Added RFC 9068 access-token JOSE header validation for `at+jwt` and
    asymmetric signature algorithms.

- **Changed**
  - Strengthened JWT access-token claim primitive validation and added the
    standard `unsupported_response_type` OAuth error code.

- **Fixed**
  - (placeholder)

- **Security**
  - (placeholder)

## [0.1.0] - 2026-07-02

- Added the initial OAuth 2.1/PKCE core standards primitives package.


[0.1.0]: https://github.com/Plasius-LTD/oauth2-core/releases/tag/v0.1.0
[0.1.1]: https://github.com/Plasius-LTD/oauth2-core/releases/tag/v0.1.1
