import { describe, expect, test } from "bun:test";
import type { ExecutionContext } from "@cloudflare/workers-types";
import worker from "../src/index";

function request(input: string, init: RequestInit = {}): Request {
  return new globalThis.Request(input, init) as unknown as Request;
}

function corsRequest(input: string, init: RequestInit): Request {
  return new globalThis.Request(input, {
    ...init,
    headers: {
      origin: "http://localhost:4330",
      ...(init.headers ?? {})
    }
  }) as unknown as Request;
}

function base64Url(bytes: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function hmac(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64Url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
}

const fetchWorker = worker.fetch! as unknown as (
  request: globalThis.Request,
  env: Record<string, string>,
  context: ExecutionContext
) => Promise<globalThis.Response>;

describe("aevo-edge-gateway", () => {
  test("keeps liveness available before Core API is connected", async () => {
    const response = await fetchWorker(request("https://edge.test/health") as unknown as globalThis.Request, {}, {} as ExecutionContext);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "healthy", service: "aevo-edge-gateway" });
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  test("does not proxy without the signing secret", async () => {
    const response = await fetchWorker(request("https://edge.test/api/v1/me") as unknown as globalThis.Request, {
      AEVO_CORE_API_ORIGIN: "https://api.example.test"
    }, {} as ExecutionContext);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: { code: "EDGE_NOT_CONFIGURED" } });
  });

  test("forwards the versioned Feed route to Core without making an auth decision", async () => {
    const originalFetch = globalThis.fetch;
    let forwardedUrl = "";
    let forwardedGateway = "";
    let forwardedApplication = "";
    let forwardedRequest: Request | null = null;
    const mockedFetch = Object.assign(async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      forwardedUrl = input instanceof Request ? input.url : String(input);
      forwardedGateway = input instanceof Request ? input.headers.get("x-aevo-gateway") ?? "" : "";
      forwardedApplication = input instanceof Request ? input.headers.get("x-aevo-app") ?? "" : "";
      forwardedRequest = input instanceof Request ? input : new Request(input, _init);
      return new Response(JSON.stringify({ forwarded: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }, { preconnect: originalFetch.preconnect });
    globalThis.fetch = mockedFetch as typeof globalThis.fetch;

    try {
      const response = await fetchWorker(
        request("https://edge.test/api/v1/public/feed?surface=explore&limit=24", { headers: { "x-aevo-app": "ADMIN" } }) as unknown as globalThis.Request,
        {
          AEVO_CORE_API_ORIGIN: "https://api.example.test",
          AEVO_GATEWAY_NAME: "edge-test",
          AEVO_GATEWAY_SIGNING_SECRET: "test-secret",
          AEVO_APP_CODE: "EDGE"
        },
        {} as ExecutionContext
      );

      expect(response.status).toBe(200);
      expect(await response.json() as { forwarded: boolean }).toEqual({ forwarded: true });
      expect(forwardedUrl).toBe("https://api.example.test/api/v1/public/feed?surface=explore&limit=24");
      expect(forwardedGateway).toBe("edge-test");
      expect(forwardedApplication).toBe("EDGE");
      expect(forwardedRequest).toBeTruthy();
      const forwardedBodyHash = base64Url(await crypto.subtle.digest("SHA-256", await forwardedRequest!.clone().arrayBuffer()));
      const timestamp = forwardedRequest!.headers.get("x-aevo-gateway-timestamp");
      const expectedPayload = [timestamp, "GET", "/api/v1/public/feed?surface=explore&limit=24", forwardedBodyHash, "EDGE"].join("\n");
      expect(forwardedRequest!.headers.get("x-aevo-gateway-signature")).toBe(await hmac("test-secret", expectedPayload));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("forwards the versioned public Place routes without rewriting their query shape", async () => {
    const originalFetch = globalThis.fetch;
    const forwardedUrls: string[] = [];
    const mockedFetch = Object.assign(async (input: RequestInfo | URL): Promise<Response> => {
      forwardedUrls.push(input instanceof Request ? input.url : String(input));
      return new Response(JSON.stringify({ forwarded: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }, { preconnect: originalFetch.preconnect });
    globalThis.fetch = mockedFetch as typeof globalThis.fetch;

    const env = {
      AEVO_CORE_API_ORIGIN: "https://api.example.test",
      AEVO_GATEWAY_NAME: "edge-test",
      AEVO_GATEWAY_SIGNING_SECRET: "test-secret",
      AEVO_APP_CODE: "EDGE"
    };
    const routes = [
      "/api/v1/public/places/map?west=100&south=13&east=101&north=14&zoom=12",
      "/api/v1/public/places/search?q=cafe&limit=24&savedOnly=true",
      "/api/v1/public/places/nearby?longitude=100.54&latitude=13.78&radiusMeters=1000",
      "/api/v1/public/places/123e4567-e89b-12d3-a456-426614174000"
    ];

    try {
      for (const route of routes) {
        const response = await fetchWorker(request(`https://edge.test${route}`) as unknown as globalThis.Request, env, {} as ExecutionContext);
        expect(response.status).toBe(200);
      }
      expect(forwardedUrls).toEqual(routes.map((route) => `https://api.example.test${route}`));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("forwards canonical Place save and unsave methods without making an auth decision", async () => {
    const originalFetch = globalThis.fetch;
    const forwarded: Array<{ method: string; url: string; idempotencyKey: string }> = [];
    const mockedFetch = Object.assign(async (input: RequestInfo | URL): Promise<Response> => {
      const forwardedRequest = input instanceof Request ? input : new Request(input);
      forwarded.push({
        method: forwardedRequest.method,
        url: forwardedRequest.url,
        idempotencyKey: forwardedRequest.headers.get("idempotency-key") ?? ""
      });
      return new Response(JSON.stringify({ forwarded: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }, { preconnect: originalFetch.preconnect });
    globalThis.fetch = mockedFetch as typeof globalThis.fetch;

    const env = {
      AEVO_CORE_API_ORIGIN: "https://api.example.test",
      AEVO_GATEWAY_NAME: "edge-test",
      AEVO_GATEWAY_SIGNING_SECRET: "test-secret",
      AEVO_APP_CODE: "EDGE"
    };
    const placeId = "123e4567-e89b-12d3-a456-426614174000";

    try {
      const saveResponse = await fetchWorker(
        request(`https://edge.test/api/v1/public/places/${placeId}/save`, {
          method: "POST",
          headers: { "idempotency-key": "edge-save-001", "content-type": "application/json" },
          body: "{}"
        }) as unknown as globalThis.Request,
        env,
        {} as ExecutionContext
      );
      const unsaveResponse = await fetchWorker(
        request(`https://edge.test/api/v1/public/places/${placeId}/save`, {
          method: "DELETE",
          headers: { "idempotency-key": "edge-unsave-001" }
        }) as unknown as globalThis.Request,
        env,
        {} as ExecutionContext
      );

      expect(saveResponse.status).toBe(200);
      expect(unsaveResponse.status).toBe(200);
      expect(forwarded).toEqual([
        {
          method: "POST",
          url: `https://api.example.test/api/v1/public/places/${placeId}/save`,
          idempotencyKey: "edge-save-001"
        },
        {
          method: "DELETE",
          url: `https://api.example.test/api/v1/public/places/${placeId}/save`,
          idempotencyKey: "edge-unsave-001"
        }
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("answers an allowed browser preflight without proxying to Core", async () => {
    const response = await fetchWorker(corsRequest("https://edge.test/api/v1/hub/bootstrap", {
      method: "OPTIONS",
      headers: {
        "access-control-request-method": "GET",
        "access-control-request-headers": "content-type,x-csrf-token"
      }
    }), { AEVO_ENVIRONMENT: "development" }, {} as ExecutionContext);

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("http://localhost:4330");
    expect(response.headers.get("access-control-allow-credentials")).toBe("true");
    expect(response.headers.get("access-control-allow-methods")).toContain("OPTIONS");
    expect(response.headers.get("access-control-allow-methods")).toContain("DELETE");
    expect(response.headers.get("access-control-allow-headers")).toContain("x-csrf-token");
  });

  test("rejects an origin outside the configured local allowlist", async () => {
    const response = await fetchWorker(new globalThis.Request("https://edge.test/api/v1/hub/bootstrap", {
      method: "OPTIONS",
      headers: { origin: "https://untrusted.example", "access-control-request-method": "GET" }
    }) as unknown as Request, { AEVO_ENVIRONMENT: "development" }, {} as ExecutionContext);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: "CORS_ORIGIN_NOT_ALLOWED" } });
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  test("rejects the removed legacy Hub origin", async () => {
    const response = await fetchWorker(new globalThis.Request("https://edge.test/api/v1/hub/bootstrap", {
      method: "OPTIONS",
      headers: { origin: "http://localhost:4321", "access-control-request-method": "GET" }
    }) as unknown as Request, { AEVO_ENVIRONMENT: "development" }, {} as ExecutionContext);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: "CORS_ORIGIN_NOT_ALLOWED" } });
  });
});
