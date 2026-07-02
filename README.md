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

## Development

```bash
npm install
npm run build
npm test
npm run test:coverage
npm run pack:check
```

## License

Apache-2.0
