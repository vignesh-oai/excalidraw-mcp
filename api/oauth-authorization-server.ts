import {
  fetchAuthorizationServerMetadata,
  metadataCorsHeaders,
} from "../src/auth.js";

const handler = async () => {
  try {
    return Response.json(await fetchAuthorizationServerMetadata(), {
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
