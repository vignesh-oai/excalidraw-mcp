import {
  AUTH_SCOPES,
  createAuthorizationCode,
  getResourceUrl,
  metadataCorsHeaders,
} from "../src/auth.js";

function headersFromRequest(request: Request): Record<string, string> {
  return Object.fromEntries(request.headers.entries());
}

function html(body: string): Response {
  return new Response(body, {
    headers: {
      ...metadataCorsHeaders(),
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function errorPage(message: string): Response {
  return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Excalidraw MCP OAuth</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; color: #222; background: #f7f7f8; }
      main { width: min(420px, calc(100vw - 32px)); background: white; border: 1px solid #ddd; border-radius: 8px; padding: 24px; box-shadow: 0 8px 30px rgb(0 0 0 / 0.08); }
      h1 { font-size: 20px; margin: 0 0 8px; }
      p { color: #555; line-height: 1.45; }
    </style>
  </head>
  <body><main><h1>Unable to connect</h1><p>${message}</p></main></body>
</html>`);
}

const handler = async (request: Request) => {
  const url = new URL(request.url);
  const headers = headersFromRequest(request);
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const clientId = url.searchParams.get("client_id");
  const responseType = url.searchParams.get("response_type");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "plain";
  const resource = url.searchParams.get("resource") ?? getResourceUrl(headers);
  const scope = url.searchParams.get("scope") ?? AUTH_SCOPES.join(" ");

  if (!redirectUri || !clientId || responseType !== "code" || !codeChallenge) {
    return errorPage("The OAuth request was missing required authorization-code or PKCE fields.");
  }
  if (codeChallengeMethod !== "S256") {
    return errorPage("This app requires PKCE with S256.");
  }

  if (url.searchParams.get("approve") === "1") {
    const code = await createAuthorizationCode({
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      resource,
      scope,
      headers,
    });
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", code);
    if (state) callback.searchParams.set("state", state);
    return Response.redirect(callback.toString(), 302);
  }

  const approveUrl = new URL(url);
  approveUrl.searchParams.set("approve", "1");
  return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Connect Excalidraw MCP</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; color: #202124; background: #f7f7f8; }
      main { width: min(440px, calc(100vw - 32px)); background: white; border: 1px solid #dedee3; border-radius: 8px; padding: 24px; box-shadow: 0 8px 30px rgb(0 0 0 / 0.08); }
      h1 { font-size: 21px; margin: 0 0 8px; letter-spacing: 0; }
      p { color: #5f6368; line-height: 1.45; margin: 0 0 18px; }
      ul { color: #3c4043; padding-left: 20px; margin: 0 0 20px; line-height: 1.5; }
      a { display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 0 14px; border-radius: 6px; background: #111; color: white; text-decoration: none; font-weight: 600; }
      small { display: block; color: #777; margin-top: 14px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Connect Excalidraw MCP</h1>
      <p>Authorize ChatGPT to call the protected Excalidraw diagram tool.</p>
      <ul>
        <li>Render private Excalidraw widgets</li>
        <li>Use OAuth token-gated MCP tools</li>
      </ul>
      <a href="${approveUrl.toString()}">Authorize</a>
      <small>Scope: ${scope}</small>
    </main>
  </body>
</html>`);
};

const options = async () => {
  return new Response(null, {
    status: 204,
    headers: metadataCorsHeaders(),
  });
};

export { handler as GET, options as OPTIONS };
