import { NextResponse } from "next/server";
import { clientIp, handler } from "@/lib/http";
import { issueMachineToken, OAuthError } from "@/lib/auth/m2m";

const NO_STORE = { "cache-control": "no-store", pragma: "no-cache" };

/**
 * OAuth 2.0 token endpoint, client credentials grant only (RFC 6749 section 4.4). Credentials come from HTTP Basic or
 * the body (form or JSON). No CORS: this is for servers, never for browsers. Errors follow RFC 6749 section 5.2.
 */
export const POST = handler(async (req: Request) => {
  try {
    const text = (await req.text()).slice(0, 4096);
    const type = req.headers.get("content-type") ?? "";
    let body: Record<string, unknown> = {};
    if (type.includes("application/json")) {
      try { body = JSON.parse(text) ?? {}; } catch { throw new OAuthError(400, "invalid_request", "Invalid JSON"); }
    } else body = Object.fromEntries(new URLSearchParams(text));
    const str = (v: unknown) => (typeof v === "string" ? v : undefined);
    let clientId = str(body.client_id), clientSecret = str(body.client_secret);
    const basic = req.headers.get("authorization")?.match(/^Basic ([A-Za-z0-9+/=]+)$/)?.[1];
    if (basic) {
      const raw = Buffer.from(basic, "base64").toString("utf8");
      const i = raw.indexOf(":");
      if (i > 0) {
        try { clientId = decodeURIComponent(raw.slice(0, i)); clientSecret = decodeURIComponent(raw.slice(i + 1)); } catch { /* falls through to invalid_client */ }
      }
    }
    const r = await issueMachineToken({ clientId, clientSecret, grantType: str(body.grant_type), scope: str(body.scope) }, clientIp(req));
    return NextResponse.json(r, { headers: NO_STORE });
  } catch (e) {
    if (!(e instanceof OAuthError)) throw e;
    return NextResponse.json({ error: e.code, error_description: e.message }, { status: e.status, headers: { ...NO_STORE, ...(e.status === 401 ? { "www-authenticate": 'Basic realm="token"' } : {}) } });
  }
});
