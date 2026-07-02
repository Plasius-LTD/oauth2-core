import { describe, expect, it } from "vitest";
import {
  buildAuthorizationServerMetadata,
  buildBearerChallenge,
  buildProtectedResourceMetadata,
  buildTokenErrorResponse,
  createPkceS256Challenge,
  oauth2ConformanceFixtures,
  parseScopeString,
  scopesContainAll,
  validateClientMetadata,
  validateJwtAccessTokenClaims,
  validateRedirectUri,
  validateResourceIdentifier,
  verifyPkceS256Challenge,
} from "../src/index.js";

describe("@plasius/oauth2-core", () => {
  it("generates the RFC 7636 Appendix B PKCE S256 challenge", () => {
    expect(createPkceS256Challenge(oauth2ConformanceFixtures.pkceVerifier)).toBe(
      oauth2ConformanceFixtures.pkceS256Challenge,
    );
    expect(
      verifyPkceS256Challenge({
        verifier: oauth2ConformanceFixtures.pkceVerifier,
        challenge: oauth2ConformanceFixtures.pkceS256Challenge,
      }),
    ).toBe(true);
  });

  it("parses and validates OAuth scope strings", () => {
    expect(parseScopeString("mcp:access admin.flags.read")).toEqual([
      "mcp:access",
      "admin.flags.read",
    ]);
    expect(scopesContainAll("mcp:access admin.flags.read", ["mcp:access"])).toBe(true);
    expect(() => parseScopeString("mcp:access mcp:access")).toThrow(/Duplicate/);
    expect(() => parseScopeString("bad\"scope")).toThrow(/Invalid/);
  });

  it("rejects unsafe redirect and resource identifiers", () => {
    expect(validateRedirectUri("https://chat.openai.com/callback").valid).toBe(true);
    expect(validateRedirectUri("http://localhost:3000/callback").valid).toBe(true);
    expect(validateRedirectUri("https://example.com/callback#frag").valid).toBe(false);
    expect(validateRedirectUri("https://*.example.com/callback").valid).toBe(false);
    expect(validateResourceIdentifier("https://plasius.co.uk/api/mcp").valid).toBe(true);
    expect(validateResourceIdentifier("http://plasius.co.uk/api/mcp").valid).toBe(false);
  });

  it("builds RFC metadata responses with zero-trust defaults", () => {
    const auth = buildAuthorizationServerMetadata({
      issuer: oauth2ConformanceFixtures.issuer,
      authorizationEndpoint: `${oauth2ConformanceFixtures.issuer}/authorize`,
      tokenEndpoint: `${oauth2ConformanceFixtures.issuer}/token`,
      jwksUri: `${oauth2ConformanceFixtures.issuer}/jwks`,
      revocationEndpoint: `${oauth2ConformanceFixtures.issuer}/revoke`,
      registrationEndpoint: `${oauth2ConformanceFixtures.issuer}/register`,
      scopesSupported: oauth2ConformanceFixtures.scopes,
    });
    expect(auth.response_types_supported).toEqual(["code"]);
    expect(auth.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(auth.code_challenge_methods_supported).toEqual(["S256"]);
    expect(auth.resource_indicators_supported).toBe(true);

    const resource = buildProtectedResourceMetadata({
      resource: oauth2ConformanceFixtures.resource,
      authorizationServers: [oauth2ConformanceFixtures.issuer],
      scopesSupported: oauth2ConformanceFixtures.scopes,
      resourceName: "Plasius MCP",
    });
    expect(resource.bearer_methods_supported).toEqual(["header"]);
    expect(resource.authorization_servers).toEqual([oauth2ConformanceFixtures.issuer]);
  });

  it("validates DCR metadata and rejects implicit-style response types", () => {
    expect(
      validateClientMetadata({
        redirect_uris: [oauth2ConformanceFixtures.redirectUri],
        response_types: ["code"],
        grant_types: ["authorization_code", "refresh_token"],
        scope: "mcp:access",
      }).valid,
    ).toBe(true);

    expect(
      validateClientMetadata({
        redirect_uris: [oauth2ConformanceFixtures.redirectUri],
        response_types: ["token" as "code"],
      }).valid,
    ).toBe(false);
  });

  it("builds token errors and bearer challenges without leaking tokens", () => {
    expect(buildTokenErrorResponse({ error: "invalid_grant" })).toMatchObject({
      status: 400,
      body: { error: "invalid_grant" },
    });
    expect(
      buildBearerChallenge({
        resourceMetadataUrl: "https://plasius.co.uk/api/.well-known/oauth-protected-resource",
        error: "insufficient_scope",
        scope: ["mcp:access"],
      }),
    ).toContain("resource_metadata=");
  });

  it("validates JWT access-token claims for audience and scopes", () => {
    const now = 1_800_000_000;
    const result = validateJwtAccessTokenClaims(
      {
        iss: oauth2ConformanceFixtures.issuer,
        sub: "admin-1",
        aud: oauth2ConformanceFixtures.resource,
        exp: now + 60,
        iat: now,
        jti: "jti-1",
        client_id: "client-1",
        scope: "mcp:access admin.flags.read",
      },
      {
        issuer: oauth2ConformanceFixtures.issuer,
        audience: oauth2ConformanceFixtures.resource,
        requiredScopes: ["mcp:access"],
        nowEpochSeconds: now,
      },
    );
    expect(result.valid).toBe(true);
  });

  it("reports JWT access-token claim validation failures", () => {
    const now = 1_800_000_000;
    const result = validateJwtAccessTokenClaims(
      {
        iss: "https://issuer.example",
        sub: "admin-1",
        aud: ["https://other.example/api"],
        exp: now - 1,
        iat: now - 60,
        jti: "jti-1",
        client_id: "client-1",
        nbf: now + 60,
        scope: "mcp:access",
      },
      {
        issuer: oauth2ConformanceFixtures.issuer,
        audience: oauth2ConformanceFixtures.resource,
        requiredScopes: ["admin.flags.read"],
        nowEpochSeconds: now,
      },
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        "issuer mismatch",
        "audience mismatch",
        "token expired",
        "token not active yet",
        "insufficient scope",
      ]),
    );

    expect(validateJwtAccessTokenClaims(null).errors).toEqual(["claims must be an object"]);
    expect(validateJwtAccessTokenClaims({}, { nowEpochSeconds: now }).errors).toContain("iss is required");
  });
});
