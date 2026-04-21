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

  let normalized = url.toString() === request.url
    ? request
    : new Request(url.toString(), request);

  if (url.pathname === "/mcp" && request.method === "POST") {
    const accept = normalized.headers.get("accept") ?? "";
    const acceptsJson = accept.includes("application/json") || accept.includes("*/*");
    const acceptsSse = accept.includes("text/event-stream") || accept.includes("*/*");
    if (!acceptsJson || !acceptsSse) {
      const headers = new Headers(normalized.headers);
      headers.set("accept", "application/json, text/event-stream");
      normalized = new Request(normalized, { headers });
    }
  }

  return normalized;
}

// Wrap to support both /mcp and /api/mcp (backward compat)
const handler = async (request: Request) => {
  return mcpHandler(normalizeRequest(request));
};

export { handler as GET, handler as POST, handler as DELETE };
