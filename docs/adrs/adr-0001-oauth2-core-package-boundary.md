# ADR 0001: OAuth 2 Core Package Boundary

## Status

Accepted.

## Context

Plasius needs reusable OAuth 2.1-aligned primitives for the ChatGPT MCP
connector without tying standards validation to one backend route, persistence
store, or admin product surface.

## Decision

Create `@plasius/oauth2-core` as a pure public package for OAuth metadata,
validation, PKCE, error, and bearer-challenge contracts.

The package must not read environment variables, store grants, issue tokens,
verify signatures, depend on HTTP frameworks, or know about Plasius admin
capabilities. Runtime issuer and resource-server behavior belongs in
`@plasius/oauth2-issuer` and consuming applications.

## Consequences

- Standards behavior is testable and reusable across Plasius services.
- Runtime integrations keep storage, key management, audit, and authorization
  decisions behind injected ports.
- Consumers must still enforce authentication, authorization, rollout gates,
  rate limits, and audit logging at their own boundary.
