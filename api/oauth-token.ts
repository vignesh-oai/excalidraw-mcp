import { exchangeAuthorizationCode, metadataCorsHeaders } from "../src/auth.js";

function headersFromRequest(request: Request): Record<string, string> {
  return Object.fromEntries(request.headers.entries());
}

async function parseTokenRequest(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(body).flatMap(([key, value]) => (typeof value === "string" ? [[key, value]] : [])),
    );
  }

  const text = await request.text();
  return Object.fromEntries(new URLSearchParams(text).entries());
}

function tokenError(error: string, description: string, status = 400): Response {
  return Response.json(
    { error, error_description: description },
    { status, headers: { ...metadataCorsHeaders(), "Cache-Control": "no-store" } },
  );
}

const handler = async (request: Request) => {
  const body = await parseTokenRequest(request);
  if (body.grant_type !== "authorization_code") {
    return tokenError("unsupported_grant_type", "Only authorization_code is supported.");
  }
  if (!body.code || !body.code_verifier || !body.client_id || !body.redirect_uri) {
    return tokenError("invalid_request", "Missing code, code_verifier, client_id, or redirect_uri.");
  }

  try {
    const exchanged = await exchangeAuthorizationCode({
      code: body.code,
      codeVerifier: body.code_verifier,
      clientId: body.client_id,
      redirectUri: body.redirect_uri,
      resource: body.resource,
      headers: headersFromRequest(request),
    });

    return Response.json(
      {
        access_token: exchanged.accessToken,
        token_type: "Bearer",
        expires_in: exchanged.expiresIn,
        scope: exchanged.scope,
      },
      { headers: { ...metadataCorsHeaders(), "Cache-Control": "no-store" } },
    );
  } catch (error) {
    return tokenError("invalid_grant", (error as Error).message);
  }
};

const options = async () => {
  return new Response(null, {
    status: 204,
    headers: metadataCorsHeaders(),
  });
};

export { handler as POST, options as OPTIONS };
