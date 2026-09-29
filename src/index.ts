export interface Env {
  AEVO_GATEWAY_NAME?: string;
  AEVO_APP_CODE?: string;
  AEVO_ENVIRONMENT?: string;
  AEVO_CORE_API_ORIGIN?: string;
  AEVO_GATEWAY_SIGNING_SECRET?: string;
  AEVO_ALLOWED_ORIGINS?: string;
}

const LOCAL_ALLOWED_ORIGINS = new Set([
  "http://localhost:4330",
  "http://127.0.0.1:4330"
]);

const ALLOWED_CORS_HEADERS = [
  "accept",
  "authorization",
  "content-type",
  "idempotency-key",
  "x-aevo-app",
  "x-csrf-token",
  "x-organization-id",
  "x-request-id",
  "x-store-id"
].join(", ");

function allowedOrigins(env: Env): Set<string> {
  const configured = env.AEVO_ALLOWED_ORIGINS
    ?.split(",")
    .map((origin) => origin.trim().replace(/\/$/u, ""))
    .filter(Boolean);
  if (configured?.length) return new Set(configured);
  if (["development", "local"].includes((env.AEVO_ENVIRONMENT ?? "").trim().toLowerCase())) {
    return LOCAL_ALLOWED_ORIGINS;
  }
  return new Set();
}

function withSecurityHeaders(response: Response, env: Env): Response {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  headers.set("cross-origin-resource-policy", "same-site");
  headers.set("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  if (["production", "staging"].includes((env.AEVO_ENVIRONMENT ?? "").trim().toLowerCase())) {
    headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function withCors(response: Response, request: Request, env: Env): Response {
  const securedResponse = withSecurityHeaders(response, env);
  const requestOrigin = request.headers.get("origin")?.trim().replace(/\/$/u, "");
  if (!requestOrigin || !allowedOrigins(env).has(requestOrigin)) return securedResponse;

  const headers = new Headers(securedResponse.headers);
  headers.set("access-control-allow-origin", requestOrigin);
  headers.set("access-control-allow-credentials", "true");
  headers.set("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
  headers.set("access-control-allow-headers", ALLOWED_CORS_HEADERS);
  headers.set("access-control-expose-headers", "x-request-id, x-aevo-contract-version");
  headers.set("access-control-max-age", "600");
  const vary = headers.get("vary");
  headers.set("vary", vary ? `${vary}, Origin` : "Origin");
  return new Response(securedResponse.body, { status: securedResponse.status, statusText: securedResponse.statusText, headers });
}

function requestIdFor(request: Request): string {
  const incoming = request.headers.get("x-request-id")?.trim();
  return incoming ? incoming.slice(0, 128) : crypto.randomUUID();
}

function json(requestId: string, body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-request-id": requestId
    }
  });
}

function error(requestId: string, code: string, message: string, status: number): Response {
  return json(requestId, { error: { code, message, requestId } }, status);
}

function base64Url(bytes: ArrayBuffer): string {
  const bytesView = new Uint8Array(bytes);
  let binary = "";
  for (const byte of bytesView) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function sign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64Url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
}

async function sha256(value: ArrayBuffer): Promise<string> {
  return base64Url(await crypto.subtle.digest("SHA-256", value));
}

async function proxy(request: Request, env: Env, requestId: string): Promise<Response> {
  const origin = env.AEVO_CORE_API_ORIGIN?.trim();
  const secret = env.AEVO_GATEWAY_SIGNING_SECRET?.trim();
  if (!origin || !secret) {
    return error(requestId, "EDGE_NOT_CONFIGURED", "Core API origin and gateway signing secret are required.", 503);
  }

  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(`${incomingUrl.pathname}${incomingUrl.search}`, `${origin.replace(/\/$/u, "")}/`);
  const body = await request.clone().arrayBuffer();
  const application = env.AEVO_APP_CODE?.trim().toUpperCase() || "EDGE";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = await sha256(body);
  // Bind the trusted app context to the origin signature. The Core API must
  // never accept an application header that was changed after the Edge hop.
  const signingPayload = [timestamp, request.method.toUpperCase(), `${targetUrl.pathname}${targetUrl.search}`, bodyHash, application].join("\n");
  const signature = await sign(secret, signingPayload);

  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("x-aevo-gateway");
  headers.delete("x-aevo-gateway-timestamp");
  headers.delete("x-aevo-gateway-signature");
  headers.set("x-aevo-gateway", env.AEVO_GATEWAY_NAME ?? "aevo-edge-gateway");
  headers.set("x-aevo-app", application);
  headers.set("x-aevo-gateway-timestamp", timestamp);
  headers.set("x-aevo-gateway-signature", signature);
  headers.set("x-request-id", requestId);

  const upstream = await fetch(new Request(targetUrl, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : body,
    redirect: "manual"
  }));
  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.set("cache-control", "no-store");
  responseHeaders.set("x-request-id", requestId);
  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
}

const worker: ExportedHandler<Env> = {
  async fetch(request, env): Promise<Response> {
    const requestId = requestIdFor(request);
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return withCors(json(requestId, {
        status: "healthy",
        service: "aevo-edge-gateway",
        environment: env.AEVO_ENVIRONMENT ?? "local"
      }), request, env);
    }
    if (url.pathname === "/ready") {
      return withCors(env.AEVO_CORE_API_ORIGIN?.trim() && env.AEVO_GATEWAY_SIGNING_SECRET?.trim()
        ? json(requestId, { status: "ready", service: "aevo-edge-gateway" })
        : error(requestId, "EDGE_NOT_CONFIGURED", "Gateway origin and signing secret are required.", 503), request, env);
    }
    if (!url.pathname.startsWith("/api/")) return withCors(error(requestId, "NOT_FOUND", "Route not found.", 404), request, env);
    if (request.method.toUpperCase() === "OPTIONS") {
      const origin = request.headers.get("origin")?.trim();
      if (origin && !allowedOrigins(env).has(origin.replace(/\/$/u, ""))) {
        return error(requestId, "CORS_ORIGIN_NOT_ALLOWED", "The request origin is not allowed.", 403);
      }
      return withCors(new Response(null, {
        status: 204,
        headers: { "cache-control": "no-store", "x-request-id": requestId }
      }), request, env);
    }
    return withCors(await proxy(request, env, requestId), request, env);
  }
};

export default worker;
