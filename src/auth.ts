import { SignJWT, jwtVerify, type JWTPayload } from "jose";

export const AUTH_SCOPES = ["diagram.private"] as const;
export const REQUIRED_AUTH_SCOPES = ["diagram.private"] as const;

export const PUBLIC_SECURITY_SCHEMES = [{ type: "noauth" }] as const;
export const PRIVATE_SECURITY_SCHEMES = [
  { type: "oauth2", scopes: [...AUTH_SCOPES] },
] as const;

type HeaderValue = string | string[] | undefined;
export type HeaderBag = Record<string, HeaderValue>;

export type AuthenticatedUser = {
  subject: string;
  email?: string;
  name?: string;
  scopes: string[];
  payload: JWTPayload;
};

type AuthResult =
  | { ok: true; user: AuthenticatedUser }
  | { ok: false; message: string; challenge: string };

function env(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function normalizeUrl(value: string): string {
  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const url = new URL(withProtocol);
  url.hash = "";
  url.search = "";
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return `${url.origin}${path}`;
}

function getHeader(headers: HeaderBag | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== target) continue;
    return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

export function getWorkOSIssuer(): string | undefined {
  return undefined;
}

export function getAuthorizationIssuer(headers?: HeaderBag): string {
  const issuer = env("MCP_OAUTH_ISSUER") ?? getResourceUrl(headers);
  return normalizeUrl(issuer);
}

export function getResourceUrl(headers?: HeaderBag): string {
  const explicit =
    env("MCP_RESOURCE_URL") ??
    env("PUBLIC_MCP_BASE_URL") ??
    env("MCP_PUBLIC_URL") ??
    env("VERCEL_PROJECT_PRODUCTION_URL") ??
    env("VERCEL_URL");
  if (explicit) return normalizeUrl(explicit);

  const forwardedHost = getHeader(headers, "x-forwarded-host")?.split(",")[0]?.trim();
  const forwardedProto = getHeader(headers, "x-forwarded-proto")?.split(",")[0]?.trim();
  const host = forwardedHost ?? getHeader(headers, "host") ?? "localhost:3001";
  const proto = forwardedProto ?? (host.startsWith("localhost") ? "http" : "https");
  return normalizeUrl(`${proto}://${host}`);
}

export function getProtectedResourceMetadataUrl(headers?: HeaderBag): string {
  return new URL("/.well-known/oauth-protected-resource", getResourceUrl(headers)).toString();
}

export function getAuthorizationServerMetadataUrl(): string | undefined {
  return undefined;
}

export function getJwksUrl(): string | undefined {
  return undefined;
}

export function protectedResourceMetadata(headers?: HeaderBag): Record<string, unknown> {
  const issuer = getAuthorizationIssuer(headers);
  return {
    resource: getResourceUrl(headers),
    authorization_servers: [issuer],
    scopes_supported: [...AUTH_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "Excalidraw MCP protected diagrams",
  };
}

export function metadataCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, Mcp-Session-Id",
  };
}

export function authorizationServerMetadata(headers?: HeaderBag): Record<string, unknown> {
  const issuer = getAuthorizationIssuer(headers);
  return {
    issuer,
    authorization_endpoint: new URL("/oauth2/authorize", issuer).toString(),
    token_endpoint: new URL("/oauth2/token", issuer).toString(),
    registration_endpoint: new URL("/oauth2/register", issuer).toString(),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...AUTH_SCOPES],
  };
}

export async function fetchAuthorizationServerMetadata(headers?: HeaderBag): Promise<unknown> {
  return authorizationServerMetadata(headers);
}

function quoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function authChallenge(
  headers?: HeaderBag,
  error = "unauthorized",
  errorDescription = "Authorization needed",
): string {
  return [
    `Bearer error="${quoted(error)}"`,
    `error_description="${quoted(errorDescription)}"`,
    `resource_metadata="${quoted(getProtectedResourceMetadataUrl(headers))}"`,
    `scope="${quoted(AUTH_SCOPES.join(" "))}"`,
  ].join(", ");
}

function getBearerToken(headers?: HeaderBag): string | undefined {
  const value = getHeader(headers, "authorization");
  const match = value?.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
}

function tokenScopes(payload: JWTPayload): string[] {
  const scope = payload.scope;
  if (typeof scope === "string") return scope.split(/\s+/).filter(Boolean);

  const scp = payload.scp;
  if (Array.isArray(scp)) return scp.filter((item): item is string => typeof item === "string");
  if (typeof scp === "string") return scp.split(/\s+/).filter(Boolean);

  return [];
}

function audienceMatches(payload: JWTPayload, headers?: HeaderBag): boolean {
  const expected =
    env("WORKOS_EXPECTED_AUDIENCE") ??
    env("MCP_EXPECTED_AUDIENCE") ??
    getResourceUrl(headers);
  const audiences =
    typeof payload.aud === "string" ? [payload.aud] : Array.isArray(payload.aud) ? payload.aud : [];

  return audiences.length === 0 || audiences.includes(expected) || audiences.includes(getResourceUrl(headers));
}

function getOAuthSigningKey(): Uint8Array {
  const secret =
    env("MCP_OAUTH_SIGNING_SECRET") ??
    env("AUTHKIT_SECRET") ??
    env("WORKOS_API_KEY") ??
    "excalidraw-mcp-local-oauth-demo-secret";
  return new TextEncoder().encode(secret);
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64url(new Uint8Array(digest));
}

export async function createAuthorizationCode({
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod,
  resource,
  scope,
  headers,
}: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
  scope: string;
  headers?: HeaderBag;
}): Promise<string> {
  return new SignJWT({
    typ: "authorization_code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    resource,
    scope,
    email: "vignesh@openai.com",
    name: "Vignesh Ramesh",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(getAuthorizationIssuer(headers))
    .setSubject("excalidraw-demo-user")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(getOAuthSigningKey());
}

export async function exchangeAuthorizationCode({
  code,
  codeVerifier,
  clientId,
  redirectUri,
  resource,
  headers,
}: {
  code: string;
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
  resource?: string;
  headers?: HeaderBag;
}): Promise<{
  accessToken: string;
  scope: string;
  expiresIn: number;
}> {
  const issuer = getAuthorizationIssuer(headers);
  const { payload } = await jwtVerify(code, getOAuthSigningKey(), { issuer });
  if (payload.typ !== "authorization_code") throw new Error("invalid authorization code");
  if (payload.client_id !== clientId) throw new Error("client_id does not match authorization code");
  if (payload.redirect_uri !== redirectUri) throw new Error("redirect_uri does not match authorization code");
  if (payload.code_challenge_method !== "S256") throw new Error("unsupported code challenge method");
  const expectedChallenge = typeof payload.code_challenge === "string" ? payload.code_challenge : "";
  const actualChallenge = await sha256Base64url(codeVerifier);
  if (expectedChallenge !== actualChallenge) throw new Error("PKCE verification failed");

  const tokenResource =
    resource ??
    (typeof payload.resource === "string" ? payload.resource : undefined) ??
    getResourceUrl(headers);
  const scope = typeof payload.scope === "string" && payload.scope ? payload.scope : AUTH_SCOPES.join(" ");
  const expiresIn = 60 * 60;
  const accessToken = await new SignJWT({
    scope,
    scp: scope.split(/\s+/).filter(Boolean),
    email: typeof payload.email === "string" ? payload.email : "vignesh@openai.com",
    name: typeof payload.name === "string" ? payload.name : "Vignesh Ramesh",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setAudience(tokenResource)
    .setSubject(payload.sub ?? "excalidraw-demo-user")
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .sign(getOAuthSigningKey());

  return { accessToken, scope, expiresIn };
}

export async function verifyWorkOSAuth(headers?: HeaderBag): Promise<AuthResult> {
  const issuer = getAuthorizationIssuer(headers);
  const token = getBearerToken(headers);
  if (!token) {
    return {
      ok: false,
      message: "Authentication required: no access token provided.",
      challenge: authChallenge(headers, "unauthorized", "Authorization needed"),
    };
  }

  try {
    const { payload } = await jwtVerify(token, getOAuthSigningKey(), { issuer });
    if (!audienceMatches(payload, headers)) {
      return {
        ok: false,
        message: "Authentication required: token audience does not match this MCP server.",
        challenge: authChallenge(headers, "invalid_token", "Token audience does not match this MCP server"),
      };
    }

    const scopes = tokenScopes(payload);
    const missingScopes = REQUIRED_AUTH_SCOPES.filter((scope) => !scopes.includes(scope));
    if (scopes.length > 0 && missingScopes.length > 0) {
      return {
        ok: false,
        message: `Authentication required: token is missing scope ${missingScopes.join(", ")}.`,
        challenge: authChallenge(headers, "insufficient_scope", "You need to login to continue"),
      };
    }

    const email = typeof payload.email === "string" ? payload.email : undefined;
    const name = typeof payload.name === "string" ? payload.name : undefined;
    return {
      ok: true,
      user: {
        subject: payload.sub ?? "unknown",
        email,
        name,
        scopes,
        payload,
      },
    };
  } catch {
    return {
      ok: false,
      message: "Authentication required: bearer token could not be verified.",
      challenge: authChallenge(headers, "invalid_token", "Bearer token could not be verified"),
    };
  }
}
