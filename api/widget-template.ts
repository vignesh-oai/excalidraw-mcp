import fs from "node:fs/promises";
import path from "node:path";

const WIDGET_MIME_TYPE = "text/html;profile=mcp-app";

async function handler(request: Request): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405, headers: corsHeaders() });
  }

  const html = await fs.readFile(path.join(process.cwd(), "dist", "mcp-app.html"), "utf-8");
  return new Response(request.method === "HEAD" ? null : html, {
    headers: {
      ...corsHeaders(),
      "content-type": WIDGET_MIME_TYPE,
      "cache-control": "no-store",
    },
  });
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "Content-Type, Accept, Authorization",
  };
}

export { handler as GET, handler as HEAD, handler as OPTIONS };
