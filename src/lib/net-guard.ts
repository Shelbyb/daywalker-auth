/**
 * SSRF protection for every outbound request to a URL someone else chose (webhook endpoints,
 * OpenID Connect issuers, self-hosted GitLab). Only public addresses are allowed, and the
 * address that was checked is the one connected to (no DNS-rebinding window).
 */
import { lookup as dnsLookup, promises as dns } from "node:dns";
import https from "node:https";
import http from "node:http";
import { BlockList, isIP } from "node:net";

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["64:ff9b::", 96]] as const)
  blocked.addSubnet(net, prefix, "ipv6");

/**
 * Lets tests reach localhost. Needs BOTH flags, and ALLOW_INSECURE_TRANSPORT is already
 * refused by env validation outside of explicit local testing, so it can't be set by accident.
 */
export const allowPrivate = () => process.env.WEBHOOK_ALLOW_PRIVATE === "1" && process.env.ALLOW_INSECURE_TRANSPORT === "1";
const insecureOk = () => process.env.NODE_ENV !== "production" || process.env.ALLOW_INSECURE_TRANSPORT === "1";

export function isBlockedIp(ip: string) {
  const family = isIP(ip);
  if (!family) return true;
  const mapped = ip.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); // IPv4-mapped IPv6
  if (mapped) return blocked.check(mapped[1], "ipv4");
  return blocked.check(ip, family === 6 ? "ipv6" : "ipv4");
}

/** Used for the connection itself, so the address we checked is the address we connect to. */
export const safeLookup: typeof dnsLookup = ((host: string, opts: unknown, cb: (...a: unknown[]) => void) => {
  const options = typeof opts === "function" ? {} : (opts as object);
  const done = (typeof opts === "function" ? opts : cb) as (...a: unknown[]) => void;
  dnsLookup(host, { ...options, all: true }, (err, addrs) => {
    if (err) return done(err);
    const list = addrs as unknown as { address: string; family: number }[];
    if (!allowPrivate() && list.some((a) => isBlockedIp(a.address))) return done(new Error("blocked_address"));
    if ((options as { all?: boolean }).all) return done(null, list);
    done(null, list[0].address, list[0].family);
  });
}) as typeof dnsLookup;

export type UrlProblem = "invalid" | "insecure" | "credentials" | "too_long" | "unresolvable" | "private";

/** Returns the parsed URL, or the reason it isn't a public https URL. */
export async function checkPublicUrl(raw: string): Promise<{ ok: true; url: URL } | { ok: false; problem: UrlProblem }> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, problem: "invalid" };
  }
  if (raw.length > 2000) return { ok: false, problem: "too_long" };
  if (u.protocol !== "https:" && !(insecureOk() && u.protocol === "http:")) return { ok: false, problem: "insecure" };
  if (u.username || u.password) return { ok: false, problem: "credentials" };
  if (allowPrivate()) return { ok: true, url: u };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const addrs = isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true }).catch(() => []);
  if (!addrs.length) return { ok: false, problem: "unresolvable" };
  if (addrs.some((a) => isBlockedIp(a.address))) return { ok: false, problem: "private" };
  return { ok: true, url: u };
}

/**
 * A small fetch for untrusted hosts: public addresses only, no redirects, a timeout and a size
 * cap on the response body. Returns the status and the body as text.
 */
export async function guardedFetch(
  raw: string,
  init: { method?: "GET" | "POST" | "PUT"; headers?: Record<string, string>; body?: string; timeoutMs?: number; maxBytes?: number } = {},
): Promise<{ status: number; text: string }> {
  const c = await checkPublicUrl(raw);
  if (!c.ok) throw new Error(`blocked_url:${c.problem}`);
  const url = c.url;
  const max = init.maxBytes ?? 256 * 1024;
  return new Promise((resolve, reject) => {
    const mod = url.protocol === "https:" ? https : http;
    const headers = { ...(init.headers ?? {}), ...(init.body !== undefined ? { "content-length": String(Buffer.byteLength(init.body)) } : {}) };
    const req = mod.request(url, { method: init.method ?? "GET", headers, lookup: safeLookup, timeout: init.timeoutMs ?? 10_000 }, (res) => {
      let size = 0;
      const chunks: Buffer[] = [];
      res.on("data", (d: Buffer) => {
        size += d.length;
        if (size > max) return req.destroy(new Error("response_too_large"));
        chunks.push(d);
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(init.body);
  });
}
