import { metadataCorsHeaders } from "../src/auth.js";

function randomId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${suffix}`;
}

const handler = async (request: Request) => {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((item): item is string => typeof item === "string")
    : [];

  return Response.json(
    {
      client_id: randomId("excalidraw_mcp_client"),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
    { headers: metadataCorsHeaders() },
  );
};

const options = async () => {
  return new Response(null, {
    status: 204,
    headers: metadataCorsHeaders(),
  });
};

export { handler as POST, options as OPTIONS };
