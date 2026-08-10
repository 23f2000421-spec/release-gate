import { evaluateReleaseGate } from "./policy.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8"
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return jsonResponse({ service: "release-gate", version: "2026-08-10.2" });
    }

    if (!["/release-gate", "/release-gate/"].includes(url.pathname)) {
      return jsonResponse({ error: "not_found" }, 404);
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed" }, 405);
    }

    try {
      const payload = await request.json();
      return jsonResponse(evaluateReleaseGate(payload));
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }
  }
};
