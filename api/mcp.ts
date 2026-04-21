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

function patchToolSecuritySchemes(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;
  const result = (payload as { result?: unknown }).result;
  if (!result || typeof result !== "object") return false;
  const tools = (result as { tools?: unknown }).tools;
  if (!Array.isArray(tools)) return false;

  let changed = false;
  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const descriptor = tool as {
      securitySchemes?: unknown;
      _meta?: { securitySchemes?: unknown };
    };
    if (descriptor.securitySchemes) continue;
    const securitySchemes = descriptor._meta?.securitySchemes;
    if (!Array.isArray(securitySchemes)) continue;
    descriptor.securitySchemes = securitySchemes;
    changed = true;
  }
  return changed;
}

function patchJsonLine(value: string): string {
  try {
    const payload = JSON.parse(value);
    return patchToolSecuritySchemes(payload) ? JSON.stringify(payload) : value;
  } catch {
    return value;
  }
}

function patchSseText(text: string): string {
  return text
    .split("\n")
    .map((line) => {
      if (!line.startsWith("data:")) return line;
      const prefix = line.startsWith("data: ") ? "data: " : "data:";
      return `${prefix}${patchJsonLine(line.slice(prefix.length))}`;
    })
    .join("\n");
}

async function patchResponse(request: Request, response: Response): Promise<Response> {
  if (request.method !== "POST") return response;

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  const isSse = contentType.includes("text/event-stream");
  if (!isJson && !isSse) return response;

  const text = await response.text();
  const patched = isJson ? patchJsonLine(text) : patchSseText(text);
  if (patched === text) return new Response(text, response);

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(patched, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// Wrap to support both /mcp and /api/mcp (backward compat)
const handler = async (request: Request) => {
  const normalized = normalizeRequest(request);
  return patchResponse(normalized, await mcpHandler(normalized));
};

export { handler as GET, handler as POST, handler as DELETE };
