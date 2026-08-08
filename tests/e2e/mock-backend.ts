import { serve } from "bun";

const server = serve({
  port: 8082,
  fetch(req) {
    const url = new URL(req.url);
    const headers = Object.fromEntries(req.headers.entries());
    
    return Response.json({
      message: "Hello from mock backend",
      path: url.pathname,
      method: req.method,
      headers: headers,
    });
  },
});

console.log(`Mock backend listening on http://localhost:${server.port}`);
