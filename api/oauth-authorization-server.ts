import {
  fetchAuthorizationServerMetadata,
  metadataCorsHeaders,
} from "../src/auth.js";

function headersFromRequest(request: Request): Record<string, string> {
  return Object.fromEntries(request.headers.entries());
}

const handler = async (request: Request) => {
  try {
    return Response.json(await fetchAuthorizationServerMetadata(headersFromRequest(request)), {
      headers: metadataCorsHeaders(),
    });
  } catch (error) {
    return Response.json(
      { error: (error as Error).message },
      { status: 500, headers: metadataCorsHeaders() },
    );
  }
};

const options = async () => {
  return new Response(null, {
    status: 204,
    headers: metadataCorsHeaders(),
  });
};

export { handler as GET, options as OPTIONS };
