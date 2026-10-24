// `daywalker listen`: receive a development instance's events over a server-sent-events stream and
// forward each one to your local server, signed with a temporary secret the CLI prints. No dependencies.
import { createHmac, randomBytes } from "node:crypto";

const MAX_EVENT_BYTES = 1_000_000;
const FORWARD_TIMEOUT_MS = 10_000;

export const newCliSecret = () => `whsec_${randomBytes(32).toString("base64")}`;

/** Standard Webhooks signature, the same scheme the service uses. */
export function sign(secret, msgId, timestamp, body) {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  return `v1,${createHmac("sha256", key).update(`${msgId}.${timestamp}.${body}`).digest("base64")}`;
}

const isLocalHost = (h) => h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost");

/** Validates options; throws an Error with a message fit to print. */
export function resolveOptions(o, env = process.env) {
  const key = o.key ?? env.DAYWALKER_SECRET_KEY;
  if (!key) throw new Error("Missing secret key. Set DAYWALKER_SECRET_KEY to your development instance's secret key (sk_test_...).");
  if (!/^sk_test_[A-Za-z0-9_-]+$/.test(key)) {
    throw new Error(key.startsWith("sk_live_") ? "Refusing to use a production key. `listen` only works with a development instance (sk_test_...)." : "That doesn't look like a development secret key (sk_test_...).");
  }
  let api;
  try { api = new URL(o.apiUrl ?? env.DAYWALKER_API_URL ?? "https://users.daywalker.dev"); } catch { throw new Error("--api-url isn't a valid URL"); }
  if (api.protocol !== "https:" && !(api.protocol === "http:" && isLocalHost(api.hostname))) {
    throw new Error("The API URL must use https (plain http is allowed only for localhost). Your secret key is sent with every request.");
  }
  if (api.username || api.password) throw new Error("Don't put credentials in the API URL.");
  if (!o.forwardTo) throw new Error("Missing --forward-to, for example --forward-to http://localhost:3000/api/webhooks");
  let target;
  try { target = new URL(o.forwardTo); } catch { throw new Error("--forward-to isn't a valid URL"); }
  if (target.protocol !== "http:" && target.protocol !== "https:") throw new Error("--forward-to must be an http(s) URL");
  const secret = o.secret ?? newCliSecret();
  if (!/^whsec_[A-Za-z0-9+/=]{20,}$/.test(secret)) throw new Error("--secret must look like whsec_ followed by base64 (leave it out to generate one)");
  return { key, api, target, secret, events: o.events ?? null, verbose: !!o.verbose };
}

/** Incremental server-sent-events parser. Feed it text chunks; it calls `onEvent({event, data})`. */
export function sseParser(onEvent) {
  let buf = "";
  let event = "message";
  let data = [];
  let size = 0;
  return (chunk) => {
    buf += chunk;
    if (buf.length > MAX_EVENT_BYTES * 2) throw new Error("Stream event too large");
    let i;
    while ((i = buf.search(/\r\n|\n|\r/)) !== -1) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + (buf.startsWith("\r\n", i) ? 2 : 1));
      if (line === "") {
        if (data.length) onEvent({ event, data: data.join("\n") });
        event = "message"; data = []; size = 0;
      } else if (line.startsWith(":")) {
        // comment / keepalive
      } else {
        const c = line.indexOf(":");
        const field = c === -1 ? line : line.slice(0, c);
        const value = c === -1 ? "" : line.slice(c + 1).replace(/^ /, "");
        if (field === "event") event = value;
        else if (field === "data") { size += value.length; if (size > MAX_EVENT_BYTES) throw new Error("Stream event too large"); data.push(value); }
      }
    }
  };
}

/** Signs `body` with the temporary secret and POSTs it. Never follows redirects. Returns { status, ms } or { error }. */
export async function forward(target, secret, id, body) {
  const ts = Math.floor(Date.now() / 1000);
  const t0 = Date.now();
  try {
    const res = await fetch(target, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        "user-agent": "Daywalker-CLI/0.1",
        "webhook-id": id,
        "webhook-timestamp": String(ts),
        "webhook-signature": sign(secret, id, ts, body),
        "webhook-source": "cli",
      },
      body,
    });
    await res.body?.cancel().catch(() => {});
    return { status: res.status, ms: Date.now() - t0 };
  } catch (e) {
    return { error: e?.name === "TimeoutError" ? "timed out" : (e?.cause?.code ?? e?.message ?? "failed") };
  }
}

const stamp = () => new Date().toTimeString().slice(0, 8);

/**
 * Connects and forwards until `signal` aborts. `out` is where status lines go (default console).
 * Resolves with an exit code: 0 on abort, 1 on a fatal error (bad key, production key, ...).
 */
export async function listen(options, { signal, out = (s) => console.log(s), err = (s) => console.error(s) } = {}) {
  let o;
  try { o = resolveOptions(options); } catch (e) { err(`Error: ${e.message}`); return 1; }
  const url = new URL("/v1/webhooks/stream", o.api);
  if (o.events) url.searchParams.set("events", o.events);
  out(`Forwarding events to ${o.target.origin}${o.target.pathname}`);
  out(`Signing secret for this session (use it as your webhook secret locally): ${o.secret}`);
  let delay = 1000;
  while (!signal?.aborted) {
    try {
      const res = await fetch(url, { headers: { authorization: `Bearer ${o.key}`, accept: "text/event-stream" }, redirect: "manual", signal });
      if (res.status === 401) { err("Error: the secret key was rejected."); return 1; }
      if (res.status === 403) { err("Error: this instance can't stream events (only development instances can)."); return 1; }
      if (res.status === 429) { err("Rate limited or too many listeners already connected. Retrying shortly."); delay = Math.max(delay, 15_000); throw new Error("rate_limited"); }
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      const parse = sseParser(({ event, data }) => {
        if (event === "ready") { out(`Connected. Waiting for events (Ctrl+C to stop).`); delay = 1000; return; }
        if (event !== "webhook") return;
        let id, type;
        try { ({ id, type } = JSON.parse(data)); } catch { return; }
        if (typeof id !== "string" || typeof type !== "string" || !/^[\w.:-]{1,100}$/.test(id)) return;
        void forward(o.target, o.secret, id, data).then((r) => {
          out(`${stamp()}  ${type}  ${id}  ${r.error ? `forward failed (${r.error})` : `${r.status} (${r.ms} ms)`}`);
          if (o.verbose) out(data);
        });
      });
      const dec = new TextDecoder();
      for await (const chunk of res.body) parse(dec.decode(chunk, { stream: true }));
    } catch (e) {
      if (signal?.aborted) break;
      if (e?.message !== "rate_limited") err(`Disconnected (${e?.cause?.code ?? e?.message}). Reconnecting...`);
    }
    if (signal?.aborted) break;
    await new Promise((r) => { const t = setTimeout(r, delay); signal?.addEventListener("abort", () => { clearTimeout(t); r(); }, { once: true }); });
    delay = Math.min(delay * 2, 30_000);
  }
  return 0;
}
