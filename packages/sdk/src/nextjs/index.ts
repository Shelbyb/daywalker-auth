import { NextResponse, type NextRequest } from "next/server";
import { verifyToken, createBackendClient, has, protect, isRecentlyVerified, requireRecentAuth, reverificationResponse, ForbiddenError, ReverificationRequiredError, type RecentAuthCheck, type SessionClaims } from "../server";
export { ForbiddenError, ReverificationRequiredError, reverificationResponse, type RecentAuthCheck };
import { SESSION_COOKIE, ACTIVE_COOKIE, instanceIdFromKey, type Config } from "../core/keys";
import { INLINE_PROOF_SOURCE } from "../core/dpop";
import { SATELLITE_HANDSHAKE_PATH, SATELLITE_SIGNED_OUT_COOKIE, SATELLITE_SYNC_PATH, SATELLITE_TRY_COOKIE, SATELLITE_VERIFIER_COOKIE, assertSatelliteConfig, buildSyncUrl, createVerifier, safeReturnTarget } from "../core/satellite";

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
  const isSatellite = process.env.NEXT_PUBLIC_DAYWALKER_IS_SATELLITE === "true";
  const primaryDomain = process.env.NEXT_PUBLIC_DAYWALKER_PRIMARY_DOMAIN;
  const domain = process.env.NEXT_PUBLIC_DAYWALKER_DOMAIN;
  return { publishableKey, frontendApi, authorizedParties: parties, ...(isSatellite ? { isSatellite, primaryDomain, ...(domain ? { domain } : {}) } : {}) };
}

function tokenFrom(headers: Headers, cookie: (name: string) => string | undefined) {
  const bearer = headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
  return bearer ?? cookie(SESSION_COOKIE);
}

type Check = { permission?: string; role?: string };
export type Auth =
  | (SessionClaims & { isSignedIn: true; /** True when the active organization role has this permission/role. */ has: (c: Check) => boolean; /** Throws ForbiddenError (403) unless `has`. */ protect: (c: Check) => void; /** Has the person proved themselves in the last `maxAge` seconds (at `level`)? */ isRecentlyVerified: (c: RecentAuthCheck) => boolean; /** Throws ReverificationRequiredError (403) unless `isRecentlyVerified`. In a route handler: catch it and `return err.toResponse()`. */ requireRecentAuth: (c: RecentAuthCheck) => void })
  | { isSignedIn: false; userId: null; sessionId: null; has: (c: Check) => false; protect: (c: Check) => never; isRecentlyVerified: (c: RecentAuthCheck) => false; requireRecentAuth: (c: RecentAuthCheck) => never };
const signedOut: Auth = {
  isSignedIn: false, userId: null, sessionId: null, has: () => false,
  protect: () => { throw new ForbiddenError("Not signed in"); },
  isRecentlyVerified: () => false,
  requireRecentAuth: () => { throw new ForbiddenError("Not signed in"); },
};

/**
 * Current session in Server Components, Route Handlers and Server Actions.
 * Verifies the JWT itself; never trusts headers set by a proxy.
 */
export async function auth(opts: { config?: Config & { authorizedParties?: string[] } } = {}): Promise<Auth> {
  const { headers, cookies } = await import("next/headers");
  const [h, c] = await Promise.all([headers(), cookies()]);
  const claims = await verifyToken(tokenFrom(h, (n) => c.get(n)?.value), opts.config ?? config());
  return claims ? { ...claims, isSignedIn: true, has: (c: Check) => has(claims, c), protect: (c: Check) => protect(claims, c), isRecentlyVerified: (c: RecentAuthCheck) => isRecentlyVerified(claims, c), requireRecentAuth: (c: RecentAuthCheck) => requireRecentAuth(claims, c) } : signedOut;
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

const text = (status: number, body: string) => new NextResponse(body, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });

/**
 * Satellite domains. `/__daywalker/sync` starts the handshake (step 1): it keeps a secret in an httpOnly cookie and sends
 * the browser to the service, which comes back to `/__daywalker/handshake` with a one-time code. The code is traded for a
 * token by this server (step 3) and stored in the same cookies a primary-domain app uses. See the satellite domains guide.
 */
async function satelliteSync(req: NextRequest, cfg: Config, ownOrigin: string) {
  const to = safeReturnTarget(req.nextUrl.searchParams.get("to"), ownOrigin);
  const tries = Number(req.cookies.get(SATELLITE_TRY_COOKIE)?.value ?? 0);
  if (tries >= 4) return text(508, "Couldn't sync your session with the primary domain. Check that this domain is a verified satellite and the keys match, then try again.");
  const { verifier, challenge } = await createVerifier();
  const res = NextResponse.redirect(buildSyncUrl(cfg, { satelliteOrigin: ownOrigin, to: ownOrigin + to, challenge }), 302);
  const secure = ownOrigin.startsWith("https:");
  res.cookies.set(SATELLITE_VERIFIER_COOKIE, verifier, { httpOnly: true, secure, sameSite: "lax", path: SATELLITE_HANDSHAKE_PATH, maxAge: 300 });
  res.cookies.set(SATELLITE_TRY_COOKIE, String(tries + 1), { secure, sameSite: "lax", path: "/", maxAge: 60 });
  res.headers.set("cache-control", "no-store");
  return res;
}

async function satelliteHandshake(req: NextRequest, cfg: Config, ownOrigin: string) {
  const q = req.nextUrl.searchParams;
  const dest = new URL(safeReturnTarget(q.get("to"), ownOrigin), ownOrigin);
  const res = NextResponse.redirect(dest, 302);
  const secure = ownOrigin.startsWith("https:");
  res.headers.set("cache-control", "no-store");
  res.headers.set("referrer-policy", "no-referrer");
  res.cookies.set(SATELLITE_VERIFIER_COOKIE, "", { path: SATELLITE_HANDSHAKE_PATH, maxAge: 0 });
  const signedOut = () => {
    res.cookies.set(SATELLITE_SIGNED_OUT_COOKIE, "1", { secure, sameSite: "lax", path: "/", maxAge: 60 });
    res.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0 });
    res.cookies.set(ACTIVE_COOKIE, "", { path: "/", maxAge: 0 });
    return res;
  };
  const code = q.get("code");
  const verifier = req.cookies.get(SATELLITE_VERIFIER_COOKIE)?.value;
  if (!code || !verifier || q.get("status") === "signed_out") return signedOut();
  try {
    const r = await fetch(`${new URL(cfg.frontendApi).origin}/v1/client/satellite/exchange`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": cfg.publishableKey },
      body: JSON.stringify({ code, verifier }),
      cache: "no-store",
    });
    if (!r.ok) return signedOut();
    const { jwt } = (await r.json()) as { jwt: string };
    const exp = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).exp as number;
    res.cookies.set(SESSION_COOKIE, jwt, { secure, sameSite: "lax", path: "/", maxAge: Math.max(exp - Math.floor(Date.now() / 1000), 0) });
    res.cookies.set(ACTIVE_COOKIE, "1", { secure, sameSite: "lax", path: "/", maxAge: 60 * 60 * 24 * 30 });
    res.cookies.set(SATELLITE_SIGNED_OUT_COOKIE, "", { path: "/", maxAge: 0 });
    res.cookies.set(SATELLITE_TRY_COOKIE, "", { path: "/", maxAge: 0 });
    return res;
  } catch {
    return signedOut();
  }
}

const isPrefetch = (req: NextRequest) => !!req.headers.get("next-router-prefetch") || (req.headers.get("sec-purpose") ?? req.headers.get("purpose") ?? "").includes("prefetch");

/**
 * Route protection for `proxy.ts` (Next 16) or `middleware.ts`.
 *
 *   export default authProxy({ protect: ["/dashboard*", "/api/private*"] });
 *
 * Page requests without a valid session go to the hosted sign-in page and come back after.
 * API requests (paths under /api or JSON requests) get a 401 instead of a redirect.
 */
export function authProxy(opts: { protect: Matcher[]; signInUrl?: string; /** Satellite domains only: pages (besides the protected ones) where a signed-in visitor should be recognised, e.g. ["/"]. */ syncPaths?: Matcher[]; /** Use instead of the NEXT_PUBLIC_DAYWALKER_* env vars */ config?: Config & { authorizedParties?: string[] } }) {
  return async function proxy(req: NextRequest) {
    const path = req.nextUrl.pathname;
    const satelliteCfg = opts.config ?? (process.env.NEXT_PUBLIC_DAYWALKER_IS_SATELLITE === "true" ? config() : null);
    const sat = !!satelliteCfg?.isSatellite;
    const ownOrigin = sat ? new URL(satelliteCfg!.domain ?? req.nextUrl.origin).origin : "";
    if (sat) {
      assertSatelliteConfig(satelliteCfg!);
      if (req.method === "GET" && path === SATELLITE_SYNC_PATH) return satelliteSync(req, satelliteCfg!, ownOrigin);
      if (req.method === "GET" && path === SATELLITE_HANDSHAKE_PATH) return satelliteHandshake(req, satelliteCfg!, ownOrigin);
    }
    const protectedPath = opts.protect.some((m) => matches(path, m));
    const syncPath = sat && !!opts.syncPaths?.some((m) => matches(path, m));
    if (!protectedPath && !syncPath) return NextResponse.next();

    const cfg = opts.config ?? config();
    const claims = await verifyToken(tokenFrom(req.headers, (n) => req.cookies.get(n)?.value), cfg);
    if (claims) return NextResponse.next();
    if (!protectedPath) {
      // A page that only wants to recognise a signed-in visitor: sync quietly once, never block.
      if (req.method === "GET" && !isPrefetch(req) && !req.cookies.get(SATELLITE_SIGNED_OUT_COOKIE) && req.headers.get("accept")?.includes("text/html"))
        return NextResponse.redirect(new URL(`${SATELLITE_SYNC_PATH}?to=${encodeURIComponent(req.nextUrl.pathname + req.nextUrl.search)}`, ownOrigin), 302);
      return NextResponse.next();
    }

    const isApi = path.startsWith("/api") || req.headers.get("accept")?.includes("application/json");
    if (isApi) return NextResponse.json({ error: { code: "unauthenticated", message: "Not signed in" } }, { status: 401 });

    // Satellite: try the handshake first (the person may already be signed in on the primary domain).
    if (sat && req.method === "GET" && !isPrefetch(req) && !req.cookies.get(SATELLITE_SIGNED_OUT_COOKIE))
      return NextResponse.redirect(new URL(`${SATELLITE_SYNC_PATH}?to=${encodeURIComponent(req.nextUrl.pathname + req.nextUrl.search)}`, ownOrigin), 302);

    const signIn = new URL(opts.signInUrl ?? `${new URL(cfg.hostedDomain ?? cfg.frontendApi).origin}/sign-in`);
    if (!cfg.hostedDomain || opts.signInUrl) signIn.searchParams.set("pk", cfg.publishableKey);
    // After signing in a satellite comes back through the handshake, which picks the new session up.
    signIn.searchParams.set("redirect_url", sat ? `${ownOrigin}${SATELLITE_SYNC_PATH}?to=${encodeURIComponent(req.nextUrl.pathname + req.nextUrl.search)}` : req.nextUrl.href);

    // A session probably exists but the short-lived token lapsed: refresh in the browser.
    if (!sat && req.cookies.get(ACTIVE_COOKIE) && req.method === "GET") {
      return new NextResponse(refreshPage(cfg, signIn.toString(), req.nextUrl.protocol === "https:"), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }
    return NextResponse.redirect(signIn);
  };
}
