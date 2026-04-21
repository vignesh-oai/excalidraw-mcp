import {
  metadataCorsHeaders,
  protectedResourceMetadata,
} from "../src/auth.js";

function headersFromRequest(request: Request): Record<string, string> {
  return Object.fromEntries(request.headers.entries());
}

const handler = async (request: Request) => {
  return Response.json(protectedResourceMetadata(headersFromRequest(request)), {
    headers: metadataCorsHeaders(),
  });
};

const options = async () => {
  return new Response(null, {
    status: 204,
    headers: metadataCorsHeaders(),
  });
};

export { handler as GET, options as OPTIONS };
