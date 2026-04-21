import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export const AUTH_SCOPES = ["openid", "profile", "email"] as const;
export const REQUIRED_AUTH_SCOPES = ["openid"] as const;

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

const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

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
  const issuer =
    env("WORKOS_AUTHKIT_ISSUER") ??
    env("WORKOS_AUTHKIT_DOMAIN") ??
    env("WORKOS_ISSUER") ??
    env("AUTHKIT_ISSUER");
  return issuer ? normalizeUrl(issuer) : undefined;
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
  const issuer = getWorkOSIssuer();
  return issuer ? new URL("/.well-known/oauth-authorization-server", issuer).toString() : undefined;
}

export function getJwksUrl(): string | undefined {
  const issuer = getWorkOSIssuer();
  return issuer ? new URL("/oauth2/jwks", issuer).toString() : undefined;
}

export function protectedResourceMetadata(headers?: HeaderBag): Record<string, unknown> {
  const issuer = getWorkOSIssuer();
  return {
    resource: getResourceUrl(headers),
    authorization_servers: issuer ? [issuer] : [],
    scopes_supported: [...AUTH_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "Excalidraw MCP mixed-auth reference",
  };
}

export function metadataCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, Mcp-Session-Id",
  };
}

export async function fetchAuthorizationServerMetadata(): Promise<unknown> {
  const metadataUrl = getAuthorizationServerMetadataUrl();
  if (!metadataUrl) {
    throw new Error("WORKOS_AUTHKIT_ISSUER or WORKOS_AUTHKIT_DOMAIN must be configured.");
  }
  const response = await fetch(metadataUrl);
  if (!response.ok) {
    throw new Error(`WorkOS authorization metadata fetch failed: ${response.status}`);
  }
  return response.json();
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

function getJwks(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL("/oauth2/jwks", issuer));
    jwksByIssuer.set(issuer, jwks);
  }
  return jwks;
}

export async function verifyWorkOSAuth(headers?: HeaderBag): Promise<AuthResult> {
  const issuer = getWorkOSIssuer();
  if (!issuer) {
    return {
      ok: false,
      message: "Authentication required, but WorkOS AuthKit is not configured on this deployment.",
      challenge: authChallenge(headers, "server_error", "WorkOS AuthKit issuer is not configured"),
    };
  }

  const token = getBearerToken(headers);
  if (!token) {
    return {
      ok: false,
      message: "Authentication required: no access token provided.",
      challenge: authChallenge(headers, "unauthorized", "Authorization needed"),
    };
  }

  try {
    const { payload } = await jwtVerify(token, getJwks(issuer), { issuer });
    if ((env("WORKOS_EXPECTED_AUDIENCE") || env("MCP_EXPECTED_AUDIENCE")) && !audienceMatches(payload, headers)) {
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
