import { createHash, randomBytes } from "node:crypto";

export const OAUTH2_CORE_PACKAGE = "@plasius/oauth2-core";
export const OAUTH2_DRAFT_VERSION = "draft-ietf-oauth-v2-1-15";

export const oauth2Standards = Object.freeze({
  oauth21: "draft-ietf-oauth-v2-1-15",
  pkce: "RFC7636",
  bearer: "RFC6750",
  revocation: "RFC7009",
  authorizationServerMetadata: "RFC8414",
  securityBcp: "RFC9700",
  protectedResourceMetadata: "RFC9728",
  dynamicClientRegistration: "RFC7591",
  jwtAccessTokenProfile: "RFC9068",
  resourceIndicators: "RFC8707",
  dpop: "RFC9449",
});

export type OAuth2TokenEndpointAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post";

export type OAuth2GrantType = "authorization_code" | "refresh_token" | "client_credentials";
export type OAuth2ResponseType = "code";
export type OAuth2CodeChallengeMethod = "S256";

export interface OAuth2AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  revocation_endpoint?: string;
  response_types_supported: OAuth2ResponseType[];
  grant_types_supported: OAuth2GrantType[];
  code_challenge_methods_supported: OAuth2CodeChallengeMethod[];
  token_endpoint_auth_methods_supported: OAuth2TokenEndpointAuthMethod[];
  scopes_supported?: string[];
  resource_indicators_supported?: boolean;
  dpop_signing_alg_values_supported?: string[];
  [key: string]: unknown;
}

export interface OAuth2ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  jwks_uri?: string;
  scopes_supported?: string[];
  bearer_methods_supported?: ("header" | "body" | "query")[];
  resource_name?: string;
  resource_documentation?: string;
  resource_policy_uri?: string;
  resource_tos_uri?: string;
  dpop_signing_alg_values_supported?: string[];
  dpop_bound_access_tokens_required?: boolean;
  [key: string]: unknown;
}

export interface OAuth2ClientMetadata {
  client_id?: string;
  client_name?: string;
  redirect_uris: string[];
  grant_types?: OAuth2GrantType[];
  response_types?: OAuth2ResponseType[];
  scope?: string;
  token_endpoint_auth_method?: OAuth2TokenEndpointAuthMethod;
  application_type?: "web" | "native";
  contacts?: string[];
  logo_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  jwks_uri?: string;
  [key: string]: unknown;
}

export type OAuth2ErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "access_denied"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable"
  | "invalid_token"
  | "insufficient_scope";

export interface OAuth2ErrorResponse {
  error: OAuth2ErrorCode;
  error_description?: string;
  error_uri?: string;
}

export interface OAuth2TokenErrorResponse {
  status: number;
  headers: Record<string, string>;
  body: OAuth2ErrorResponse;
}

export interface OAuth2JwtAccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  jti: string;
  client_id: string;
  scope?: string;
  nbf?: number;
  cnf?: {
    jkt?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface OAuth2ValidationResult {
  valid: boolean;
  errors: string[];
}

const SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/u;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u;

export function base64UrlEncode(input: Buffer | Uint8Array | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function generatePkceVerifier(byteLength = 32): string {
  if (!Number.isInteger(byteLength) || byteLength < 32 || byteLength > 96) {
    throw new Error("PKCE verifier entropy must be between 32 and 96 bytes.");
  }
  return base64UrlEncode(randomBytes(byteLength));
}

export function isValidPkceVerifier(value: unknown): value is string {
  return typeof value === "string" && PKCE_VERIFIER_PATTERN.test(value);
}

export function createPkceS256Challenge(verifier: string): string {
  if (!isValidPkceVerifier(verifier)) {
    throw new Error("Invalid PKCE code verifier.");
  }
  return base64UrlEncode(createHash("sha256").update(verifier).digest());
}

export function verifyPkceS256Challenge(input: {
  verifier: string;
  challenge: string;
}): boolean {
  if (!isValidPkceVerifier(input.verifier) || typeof input.challenge !== "string") {
    return false;
  }
  return createPkceS256Challenge(input.verifier) === input.challenge;
}

export function parseScopeString(scope: string | undefined | null): string[] {
  if (scope === undefined || scope === null || scope.trim() === "") {
    return [];
  }
  const scopes = scope.trim().split(/\s+/u);
  const seen = new Set<string>();
  for (const item of scopes) {
    if (!SCOPE_TOKEN_PATTERN.test(item)) {
      throw new Error(`Invalid OAuth scope token: ${item}`);
    }
    if (seen.has(item)) {
      throw new Error(`Duplicate OAuth scope token: ${item}`);
    }
    seen.add(item);
  }
  return scopes;
}

export function normalizeScopeString(scopes: readonly string[]): string {
  const parsed = parseScopeString(scopes.join(" "));
  return parsed.join(" ");
}

export function scopesContainAll(granted: string | readonly string[], required: readonly string[]): boolean {
  const grantedScopes = new Set(typeof granted === "string" ? parseScopeString(granted) : granted);
  return required.every((scope) => grantedScopes.has(scope));
}

export function validateResourceIdentifier(resource: unknown): OAuth2ValidationResult {
  const errors: string[] = [];
  if (typeof resource !== "string" || resource.trim().length === 0) {
    return { valid: false, errors: ["resource must be a non-empty string"] };
  }
  try {
    const url = new URL(resource);
    if (url.protocol !== "https:") {
      errors.push("resource must use https");
    }
    if (url.hash) {
      errors.push("resource must not include a fragment");
    }
    if (url.username || url.password) {
      errors.push("resource must not include credentials");
    }
  } catch {
    errors.push("resource must be an absolute URL");
  }
  return { valid: errors.length === 0, errors };
}

export function validateRedirectUri(
  redirectUri: unknown,
  options: { allowLoopbackHttp?: boolean } = {},
): OAuth2ValidationResult {
  const allowLoopbackHttp = options.allowLoopbackHttp ?? true;
  const errors: string[] = [];
  if (typeof redirectUri !== "string" || redirectUri.trim().length === 0) {
    return { valid: false, errors: ["redirect_uri must be a non-empty string"] };
  }
  if (redirectUri.includes("*")) {
    errors.push("redirect_uri must not contain wildcards");
  }
  try {
    const url = new URL(redirectUri);
    const isLoopback =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]" ||
      url.hostname === "::1";
    if (url.protocol !== "https:" && !(allowLoopbackHttp && url.protocol === "http:" && isLoopback)) {
      errors.push("redirect_uri must use https except loopback local development");
    }
    if (url.hash) {
      errors.push("redirect_uri must not include a fragment");
    }
    if (url.username || url.password) {
      errors.push("redirect_uri must not include credentials");
    }
  } catch {
    errors.push("redirect_uri must be an absolute URL");
  }
  return { valid: errors.length === 0, errors };
}

export function assertValidRedirectUri(redirectUri: string): void {
  const result = validateRedirectUri(redirectUri);
  if (!result.valid) {
    throw new Error(result.errors.join("; "));
  }
}

function assertHttpsUrl(name: string, value: string): void {
  const result = validateResourceIdentifier(value);
  if (!result.valid) {
    throw new Error(`${name}: ${result.errors.join("; ")}`);
  }
}

export function buildAuthorizationServerMetadata(input: {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  registrationEndpoint?: string;
  revocationEndpoint?: string;
  scopesSupported?: readonly string[];
  tokenEndpointAuthMethodsSupported?: readonly OAuth2TokenEndpointAuthMethod[];
  dpopSigningAlgValuesSupported?: readonly string[];
}): OAuth2AuthorizationServerMetadata {
  assertHttpsUrl("issuer", input.issuer);
  assertHttpsUrl("authorizationEndpoint", input.authorizationEndpoint);
  assertHttpsUrl("tokenEndpoint", input.tokenEndpoint);
  assertHttpsUrl("jwksUri", input.jwksUri);
  if (input.registrationEndpoint) assertHttpsUrl("registrationEndpoint", input.registrationEndpoint);
  if (input.revocationEndpoint) assertHttpsUrl("revocationEndpoint", input.revocationEndpoint);

  return {
    issuer: input.issuer,
    authorization_endpoint: input.authorizationEndpoint,
    token_endpoint: input.tokenEndpoint,
    jwks_uri: input.jwksUri,
    ...(input.registrationEndpoint ? { registration_endpoint: input.registrationEndpoint } : {}),
    ...(input.revocationEndpoint ? { revocation_endpoint: input.revocationEndpoint } : {}),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: [...(input.tokenEndpointAuthMethodsSupported ?? ["none"])],
    ...(input.scopesSupported ? { scopes_supported: [...input.scopesSupported] } : {}),
    resource_indicators_supported: true,
    ...(input.dpopSigningAlgValuesSupported
      ? { dpop_signing_alg_values_supported: [...input.dpopSigningAlgValuesSupported] }
      : {}),
  };
}

export function buildProtectedResourceMetadata(input: {
  resource: string;
  authorizationServers?: readonly string[];
  jwksUri?: string;
  scopesSupported?: readonly string[];
  resourceName?: string;
  resourceDocumentation?: string;
  resourcePolicyUri?: string;
  resourceTosUri?: string;
  dpopSigningAlgValuesSupported?: readonly string[];
  dpopBoundAccessTokensRequired?: boolean;
}): OAuth2ProtectedResourceMetadata {
  assertHttpsUrl("resource", input.resource);
  for (const issuer of input.authorizationServers ?? []) {
    assertHttpsUrl("authorizationServer", issuer);
  }
  if (input.jwksUri) assertHttpsUrl("jwksUri", input.jwksUri);

  return {
    resource: input.resource,
    ...(input.authorizationServers ? { authorization_servers: [...input.authorizationServers] } : {}),
    ...(input.jwksUri ? { jwks_uri: input.jwksUri } : {}),
    ...(input.scopesSupported ? { scopes_supported: [...input.scopesSupported] } : {}),
    bearer_methods_supported: ["header"],
    ...(input.resourceName ? { resource_name: input.resourceName } : {}),
    ...(input.resourceDocumentation ? { resource_documentation: input.resourceDocumentation } : {}),
    ...(input.resourcePolicyUri ? { resource_policy_uri: input.resourcePolicyUri } : {}),
    ...(input.resourceTosUri ? { resource_tos_uri: input.resourceTosUri } : {}),
    ...(input.dpopSigningAlgValuesSupported
      ? { dpop_signing_alg_values_supported: [...input.dpopSigningAlgValuesSupported] }
      : {}),
    ...(input.dpopBoundAccessTokensRequired === undefined
      ? {}
      : { dpop_bound_access_tokens_required: input.dpopBoundAccessTokensRequired }),
  };
}

export function validateClientMetadata(input: OAuth2ClientMetadata): OAuth2ValidationResult {
  const errors: string[] = [];
  if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length === 0) {
    errors.push("redirect_uris must include at least one URI");
  } else {
    for (const redirectUri of input.redirect_uris) {
      const result = validateRedirectUri(redirectUri);
      errors.push(...result.errors.map((error) => `${redirectUri}: ${error}`));
    }
  }
  for (const grantType of input.grant_types ?? ["authorization_code"]) {
    if (!["authorization_code", "refresh_token", "client_credentials"].includes(grantType)) {
      errors.push(`unsupported grant type: ${grantType}`);
    }
  }
  for (const responseType of input.response_types ?? ["code"]) {
    if (responseType !== "code") {
      errors.push(`unsupported response type: ${responseType}`);
    }
  }
  try {
    parseScopeString(input.scope);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "invalid scope");
  }
  return { valid: errors.length === 0, errors };
}

export function buildTokenErrorResponse(input: {
  error: OAuth2ErrorCode;
  status?: number;
  errorDescription?: string;
  errorUri?: string;
}): OAuth2TokenErrorResponse {
  const body: OAuth2ErrorResponse = {
    error: input.error,
    ...(input.errorDescription ? { error_description: input.errorDescription } : {}),
    ...(input.errorUri ? { error_uri: input.errorUri } : {}),
  };
  return {
    status: input.status ?? (input.error === "invalid_client" ? 401 : 400),
    headers: {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "Content-Type": "application/json; charset=utf-8",
    },
    body,
  };
}

export function buildRevocationResponse(): {
  status: 200;
  headers: Record<string, string>;
  body: "";
} {
  return {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
    body: "",
  };
}

export function buildBearerChallenge(input: {
  resourceMetadataUrl?: string;
  realm?: string;
  error?: OAuth2ErrorCode;
  errorDescription?: string;
  scope?: string | readonly string[];
}): string {
  const parameters: string[] = [];
  const add = (name: string, value: string | undefined): void => {
    if (value !== undefined && value.length > 0) {
      parameters.push(`${name}="${value.replace(/["\\]/g, "")}"`);
    }
  };
  add("realm", input.realm);
  add("resource_metadata", input.resourceMetadataUrl);
  add("error", input.error);
  add("error_description", input.errorDescription);
  add("scope", typeof input.scope === "string" ? input.scope : input.scope?.join(" "));
  return parameters.length ? `Bearer ${parameters.join(", ")}` : "Bearer";
}

export function validateJwtAccessTokenClaims(
  claims: unknown,
  options: {
    issuer?: string;
    audience?: string;
    requiredScopes?: readonly string[];
    nowEpochSeconds?: number;
  } = {},
): OAuth2ValidationResult {
  const errors: string[] = [];
  if (!claims || typeof claims !== "object") {
    return { valid: false, errors: ["claims must be an object"] };
  }
  const raw = claims as Record<string, unknown>;
  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  for (const key of ["iss", "sub", "aud", "exp", "iat", "jti", "client_id"]) {
    if (raw[key] === undefined || raw[key] === null) {
      errors.push(`${key} is required`);
    }
  }
  if (options.issuer && raw.iss !== options.issuer) {
    errors.push("issuer mismatch");
  }
  if (options.audience) {
    const audiences = Array.isArray(raw.aud) ? raw.aud : [raw.aud];
    if (!audiences.includes(options.audience)) {
      errors.push("audience mismatch");
    }
  }
  if (typeof raw.exp !== "number" || raw.exp <= now) {
    errors.push("token expired");
  }
  if (typeof raw.nbf === "number" && raw.nbf > now) {
    errors.push("token not active yet");
  }
  if (options.requiredScopes?.length && !scopesContainAll(String(raw.scope ?? ""), options.requiredScopes)) {
    errors.push("insufficient scope");
  }
  return { valid: errors.length === 0, errors };
}

export const oauth2ConformanceFixtures = Object.freeze({
  pkceVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  pkceS256Challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  issuer: "https://plasius.co.uk/api/oauth/mcp",
  resource: "https://plasius.co.uk/api/mcp",
  redirectUri: "https://chat.openai.com/aip/g-000000/oauth/callback",
  scopes: ["mcp:access", "admin.flags.read", "admin.flags.write"],
});

export const packageDescriptor = Object.freeze({
  name: OAUTH2_CORE_PACKAGE,
  version: "0.1.0",
  standards: oauth2Standards,
  summary:
    "Standards-focused OAuth 2.1, PKCE, metadata, and bearer-token primitives for Plasius services.",
});
