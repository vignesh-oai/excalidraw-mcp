import { createMcpHandler } from "mcp-handler";
import path from "node:path";
import { createVercelStore } from "../src/checkpoint-store.js";
import { registerTools } from "../src/server.js";

const store = createVercelStore();

const mcpHandler = createMcpHandler(
  (server) => {
    const distDir = path.join(process.cwd(), "dist");
    registerTools(server, distDir, store);
  },
  { serverInfo: { name: "Excalidraw", version: "1.0.0" } },
  { basePath: "", maxDuration: 60, sessionIdGenerator: undefined },
);

function normalizeRequest(request: Request): Request {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/api/")) {
    url.pathname = url.pathname.replace("/api/", "/");
  }

  const headers = new Headers(request.headers);

  if (url.pathname === "/mcp" && request.method === "POST") {
    const accept = headers.get("accept") ?? "";
    const acceptsJson = accept.includes("application/json");
    const acceptsSse = accept.includes("text/event-stream");
    if (!acceptsJson || !acceptsSse) {
      headers.set("accept", "application/json, text/event-stream");
    }
  }

  const body = request.method === "GET" || request.method === "HEAD" ? undefined : request.body;
  const init: RequestInit & { duplex?: "half" } = {
    method: request.method,
    headers,
    body,
    redirect: request.redirect,
    signal: request.signal,
  };

  if (body) init.duplex = "half";
  return new Request(url.toString(), init);
}

// Wrap to support both /mcp and /api/mcp (backward compat)
const handler = async (request: Request) => {
  return mcpHandler(normalizeRequest(request));
};

export { handler as GET, handler as POST, handler as DELETE };
