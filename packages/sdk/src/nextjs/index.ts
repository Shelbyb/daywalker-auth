import { NextResponse, type NextRequest } from "next/server";
import { verifyToken, createBackendClient, has, protect, ForbiddenError, type SessionClaims } from "../server";
export { ForbiddenError };
import { SESSION_COOKIE, ACTIVE_COOKIE, instanceIdFromKey, type Config } from "../core/keys";
import { INLINE_PROOF_SOURCE } from "../core/dpop";

/**
 * Reads config from env:
 *   NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY, NEXT_PUBLIC_DAYWALKER_AUTH_URL, DAYWALKER_SECRET_KEY (server only)
 *   DAYWALKER_AUTHORIZED_PARTIES (optional, comma-separated origins)
 */
function config(): Config & { authorizedParties?: string[] } {
  const publishableKey = process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY;
  const frontendApi = process.env.NEXT_PUBLIC_DAYWALKER_AUTH_URL;
  if (!publishableKey || !frontendApi)
    throw new Error("Set NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY and NEXT_PUBLIC_DAYWALKER_AUTH_URL");
  const parties = process.env.DAYWALKER_AUTHORIZED_PARTIES?.split(",").map((s) => s.trim()).filter(Boolean);
  return { publishableKey, frontendApi, authorizedParties: parties };
}

function tokenFrom(headers: Headers, cookie: (name: string) => string | undefined) {
  const bearer = headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
  return bearer ?? cookie(SESSION_COOKIE);
}

type Check = { permission?: string; role?: string };
export type Auth =
  | (SessionClaims & { isSignedIn: true; /** True when the active organization role has this permission/role. */ has: (c: Check) => boolean; /** Throws ForbiddenError (403) unless `has`. */ protect: (c: Check) => void })
  | { isSignedIn: false; userId: null; sessionId: null; has: (c: Check) => false; protect: (c: Check) => never };
const signedOut: Auth = {
  isSignedIn: false, userId: null, sessionId: null, has: () => false,
  protect: () => { throw new ForbiddenError("Not signed in"); },
};

/**
 * Current session in Server Components, Route Handlers and Server Actions.
 * Verifies the JWT itself; never trusts headers set by a proxy.
 */
export async function auth(opts: { config?: Config & { authorizedParties?: string[] } } = {}): Promise<Auth> {
  const { headers, cookies } = await import("next/headers");
  const [h, c] = await Promise.all([headers(), cookies()]);
  const claims = await verifyToken(tokenFrom(h, (n) => c.get(n)?.value), opts.config ?? config());
  return claims ? { ...claims, isSignedIn: true, has: (c: Check) => has(claims, c), protect: (c: Check) => protect(claims, c) } : signedOut;
}

/** Backend API client configured from DAYWALKER_SECRET_KEY. */
export function backend() {
  const secretKey = process.env.DAYWALKER_SECRET_KEY;
  if (!secretKey) throw new Error("Set DAYWALKER_SECRET_KEY");
  return createBackendClient({ secretKey, apiUrl: config().frontendApi });
}

type Matcher = string | RegExp;
const matches = (path: string, m: Matcher) =>
  typeof m === "string" ? (m.endsWith("*") ? path.startsWith(m.slice(0, -1)) : path === m) : m.test(path);

/** Escape a value for embedding in an inline <script>. */
const js = (v: unknown) => JSON.stringify(v).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");

/**
 * Short page served when a returning user's 60s JWT has expired: it exchanges the refresh
 * cookie for a new token in the browser and reloads. Without it, every page load after a
 * minute of inactivity would bounce to sign-in.
 */
function refreshPage(cfg: Config, signInUrl: string, secure: boolean) {
  const flags = `Path=/; SameSite=Lax${secure ? "; Secure" : ""}`;
  return `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Loading…</title><script>
${INLINE_PROOF_SOURCE}
(async()=>{const k="dw_refresh_attempt";if(sessionStorage.getItem(k)){sessionStorage.removeItem(k);document.cookie=${js(`${ACTIVE_COOKIE}=; Max-Age=0; ${flags}`)};location.replace(${js(signInUrl)});return}
sessionStorage.setItem(k,"1");
try{const tu=${js(`${new URL(cfg.frontendApi).origin}/v1/client/session/token`)};const pf=await dwProof(${js(instanceIdFromKey(cfg.publishableKey))},"POST",tu);const r=await fetch(tu,{method:"POST",credentials:"include",headers:Object.assign({"x-publishable-key":${js(cfg.publishableKey)}},pf?{dpop:pf}:{})});
if(r.ok){const{jwt}=await r.json();const exp=JSON.parse(atob(jwt.split(".")[1].replace(/-/g,"+").replace(/_/g,"/"))).exp;document.cookie=${js(`${SESSION_COOKIE}=`)}+jwt+"; Max-Age="+Math.max(exp-Math.floor(Date.now()/1e3),0)+${js(`; ${flags}`)};location.reload();return}}catch(e){}
document.cookie=${js(`${ACTIVE_COOKIE}=; Max-Age=0; ${flags}`)};sessionStorage.removeItem(k);location.replace(${js(signInUrl)})})();
</script>`;
}

/**
 * Route protection for `proxy.ts` (Next 16) or `middleware.ts`.
 *
 *   export default authProxy({ protect: ["/dashboard*", "/api/private*"] });
 *
 * Page requests without a valid session go to the hosted sign-in page and come back after.
 * API requests (paths under /api or JSON requests) get a 401 instead of a redirect.
 */
export function authProxy(opts: { protect: Matcher[]; signInUrl?: string; /** Use instead of the NEXT_PUBLIC_DAYWALKER_* env vars */ config?: Config & { authorizedParties?: string[] } }) {
  return async function proxy(req: NextRequest) {
    const path = req.nextUrl.pathname;
    if (!opts.protect.some((m) => matches(path, m))) return NextResponse.next();

    const cfg = opts.config ?? config();
    const claims = await verifyToken(tokenFrom(req.headers, (n) => req.cookies.get(n)?.value), cfg);
    if (claims) return NextResponse.next();

    const isApi = path.startsWith("/api") || req.headers.get("accept")?.includes("application/json");
    if (isApi) return NextResponse.json({ error: { code: "unauthenticated", message: "Not signed in" } }, { status: 401 });

    const signIn = new URL(opts.signInUrl ?? `${new URL(cfg.hostedDomain ?? cfg.frontendApi).origin}/sign-in`);
    if (!cfg.hostedDomain || opts.signInUrl) signIn.searchParams.set("pk", cfg.publishableKey);
    signIn.searchParams.set("redirect_url", req.nextUrl.href);

    // A session probably exists but the short-lived token lapsed: refresh in the browser.
    if (req.cookies.get(ACTIVE_COOKIE) && req.method === "GET") {
      return new NextResponse(refreshPage(cfg, signIn.toString(), req.nextUrl.protocol === "https:"), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }
    return NextResponse.redirect(signIn);
  };
}
